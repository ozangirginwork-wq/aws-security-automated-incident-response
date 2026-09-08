import json
import sys
from pathlib import Path
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lambda'))
from detector import detect_public_ssh
from remediation import remediate_public_ssh
from verifier import verify_remediation
from handler import lambda_handler


def event():
    return json.loads((ROOT / 'sample-events/unsafe-security-group.json').read_text())


class EC2:
    def __init__(self, permissions):
        self.permissions = permissions
        self.revoked = []

    def describe_security_groups(self, GroupIds):
        return {'SecurityGroups': [{'GroupId': GroupIds[0], 'IpPermissions': self.permissions}]}

    def revoke_security_group_ingress(self, **kwargs):
        self.revoked.append(kwargs)
        self.permissions = []
        return {'Return': True}


@pytest.mark.parametrize('protocol,start,end', [('tcp', 20, 30), ('6', 22, 22), ('-1', None, None)])
@pytest.mark.parametrize('ipv6', [False, True])
def test_public_rule_shapes(protocol, start, end, ipv6):
    e = event()
    p = e['detail']['requestParameters']['ipPermissions']['items'][0]
    p.update(ipProtocol=protocol, fromPort=start, toPort=end)
    if ipv6:
        p.pop('ipRanges', None)
        p['ipv6Ranges'] = {'items': [{'cidrIpv6': '::/0'}]}
    assert detect_public_ssh(e)
    api = {'IpProtocol': protocol}
    if start is not None:
        api.update(FromPort=start, ToPort=end)
    api['Ipv6Ranges' if ipv6 else 'IpRanges'] = [{'CidrIpv6' if ipv6 else 'CidrIp': '::/0' if ipv6 else '0.0.0.0/0'}]
    assert verify_remediation({'status': 'REMEDIATED', 'security_group': 'sg-test'}, EC2([api]))['status'] == 'FAILED'


def test_failed_api_and_null_request_ignored():
    e = event()
    e['detail']['errorCode'] = 'UnauthorizedOperation'
    assert not detect_public_ssh(e)
    e['detail'].pop('errorCode')
    e['detail']['requestParameters'] = None
    assert not detect_public_ssh(e)


def test_exact_range_revoke_preserves_trusted_sources(monkeypatch):
    monkeypatch.setenv('ENABLE_LIVE_REMEDIATION', 'true')
    monkeypatch.setenv('PROTECTED_SECURITY_GROUP_ID', 'sg-test')
    ec2 = EC2([{'IpProtocol': 'tcp', 'FromPort': 20, 'ToPort': 30,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}, {'CidrIp': '10.0.0.0/24'}]}])
    response = remediate_public_ssh({'security_group': 'sg-test'}, False, ec2)
    assert response['status'] == 'REMEDIATED'
    assert ec2.revoked[0]['IpPermissions'] == [{'IpProtocol': 'tcp', 'FromPort': 20, 'ToPort': 30, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
    assert remediate_public_ssh({'security_group': 'sg-test'}, False, ec2)['status'] == 'ALREADY_SECURE'
    assert len(ec2.revoked) == 1


def test_safety_gates_make_no_calls(monkeypatch):
    class NoCalls:
        def describe_security_groups(self, **kwargs):
            raise AssertionError('Safety gate allowed an AWS call')
    monkeypatch.delenv('ENABLE_LIVE_REMEDIATION', raising=False)
    assert remediate_public_ssh({'security_group': 'sg-test'}, ec2_client=NoCalls())['status'] == 'DRY_RUN'
    assert remediate_public_ssh({'security_group': 'sg-test'}, False, NoCalls())['status'] == 'BLOCKED'
    monkeypatch.setenv('ENABLE_LIVE_REMEDIATION', 'true')
    monkeypatch.setenv('PROTECTED_SECURITY_GROUP_ID', 'sg-other')
    assert remediate_public_ssh({'security_group': 'sg-test'}, False, NoCalls())['status'] == 'BLOCKED'


def test_handler_never_claims_failed_verification_is_handled():
    with patch('handler.remediate_public_ssh', return_value={'status': 'REMEDIATED'}), patch('handler.verify_remediation', return_value={'status': 'FAILED'}):
        with pytest.raises(RuntimeError, match='unresolved'):
            lambda_handler(event())


def test_handler_reports_blocked(monkeypatch):
    monkeypatch.delenv('ENABLE_LIVE_REMEDIATION', raising=False)
    assert lambda_handler(event())['status'] == 'BLOCKED'
