from rules import public_permissions


def verify_remediation(response, ec2_client=None):
    """
    Verify remediation.

    DRY_RUN:
        Validate that the proposed remediation matches the expected
        security control.

    LIVE:
        Query AWS and independently verify that TCP/22 is no longer
        exposed to 0.0.0.0/0.
    """

    if response.get("status") == "DRY_RUN":
        expected = (
            response.get("action") == "RevokeSecurityGroupIngress"
            and response.get("protocol") == "tcp"
            and response.get("port") == 22
            and response.get("cidr") == "0.0.0.0/0"
        )

        return {
            "status": "VERIFIED" if expected else "FAILED",
            "mode": "DRY_RUN",
            "message": (
                "Correct remediation action verified."
                if expected
                else "Remediation action did not match expected controls."
            ),
        }

    if response.get("status") not in {"REMEDIATED", "ALREADY_SECURE"}:
        return {
            "status": "NOT_VERIFIED",
            "mode": "LIVE",
            "message": "Remediation did not report successful execution.",
        }

    security_group = response.get("security_group")

    if not security_group:
        return {
            "status": "FAILED",
            "mode": "LIVE",
            "message": "Security group ID is missing.",
        }

    if ec2_client is None:
        import boto3
        ec2_client = boto3.client("ec2")

    result = ec2_client.describe_security_groups(
        GroupIds=[security_group]
    )

    groups = result.get("SecurityGroups", [])
    if len(groups) != 1 or groups[0].get("GroupId") != security_group:
        return {"status": "FAILED", "mode": "LIVE", "message": "Requested group was not returned."}
    if public_permissions(groups[0].get("IpPermissions")):
        return {"status": "FAILED", "mode": "LIVE", "message": "Public IPv4 or IPv6 SSH exposure still exists."}

    return {
        "status": "VERIFIED",
        "mode": "LIVE",
        "message": "AWS state verified: public SSH exposure removed.",
    }