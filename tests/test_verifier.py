import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "lambda"))

from verifier import verify_remediation


class FakeEC2Client:
    def __init__(self, permissions):
        self.permissions = permissions

    def describe_security_groups(self, GroupIds):
        return {
            "SecurityGroups": [
                {
                    "GroupId": GroupIds[0],
                    "IpPermissions": self.permissions,
                }
            ]
        }


def test_verifies_successful_live_remediation():
    response = {
        "status": "REMEDIATED",
        "security_group": "sg-test123",
    }

    ec2 = FakeEC2Client(permissions=[])

    result = verify_remediation(response, ec2_client=ec2)

    assert result["status"] == "VERIFIED"
    assert result["mode"] == "LIVE"


def test_detects_failed_live_remediation():
    response = {
        "status": "REMEDIATED",
        "security_group": "sg-test123",
    }

    ec2 = FakeEC2Client(
        permissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ]
    )

    result = verify_remediation(response, ec2_client=ec2)

    assert result["status"] == "FAILED"
    assert result["mode"] == "LIVE"


def test_verifies_correct_dry_run():
    response = {
        "status": "DRY_RUN",
        "action": "RevokeSecurityGroupIngress",
        "protocol": "tcp",
        "port": 22,
        "cidr": "0.0.0.0/0",
    }

    result = verify_remediation(response)

    assert result["status"] == "VERIFIED"
    assert result["mode"] == "DRY_RUN"


def test_does_not_verify_unsuccessful_remediation():
    response = {
        "status": "FAILED",
        "security_group": "sg-test123",
    }

    result = verify_remediation(response)

    assert result["status"] == "NOT_VERIFIED"
    assert result["mode"] == "LIVE"