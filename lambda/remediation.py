import os


def remediate_public_ssh(incident, dry_run=True, ec2_client=None):
    """
    Remove a public SSH (TCP/22 from 0.0.0.0/0) ingress rule.

    Safety controls:
    - dry_run=True by default.
    - Live remediation requires ENABLE_LIVE_REMEDIATION=true.
    - An EC2 client is injected only when live remediation is authorized.
    """

    security_group = incident.get("security_group")

    if not security_group or security_group == "Unknown":
        return {
            "status": "FAILED",
            "reason": "Security group ID is missing."
        }

    action = {
        "action": "RevokeSecurityGroupIngress",
        "security_group": security_group,
        "protocol": "tcp",
        "port": 22,
        "cidr": "0.0.0.0/0"
    }

    if dry_run:
        return {
            "status": "DRY_RUN",
            **action,
            "message": "Dangerous SSH rule would be removed."
        }

    # Second safety gate.
    if os.environ.get("ENABLE_LIVE_REMEDIATION", "false").lower() != "true":
        return {
            "status": "BLOCKED",
            **action,
            "message": "Live remediation is disabled by safety control."
        }

    if ec2_client is None:
        import boto3
        ec2_client = boto3.client("ec2")

    ec2_client.revoke_security_group_ingress(
        GroupId=security_group,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ]
            }
        ]
    )

    return {
        "status": "REMEDIATED",
        **action,
        "message": "Dangerous public SSH rule removed."
    }