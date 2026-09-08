"""Scope-gated, repeatable remediation using the current EC2 permission shape."""
import os
from rules import public_permissions


def remediate_public_ssh(incident, dry_run=True, ec2_client=None):
    group = incident.get('security_group')
    if not group or group == 'Unknown':
        return {'status': 'FAILED', 'reason': 'Security group ID is missing.'}
    action = {'action': 'RevokeSecurityGroupIngress', 'security_group': group,
              'protocol': 'tcp', 'port': 22, 'cidr': '0.0.0.0/0'}
    if dry_run:
        return {'status': 'DRY_RUN', **action,
                'message': 'Preview only: inspect and remove public SSH permissions; no AWS call made.'}
    if os.environ.get('ENABLE_LIVE_REMEDIATION', 'false').lower() != 'true':
        return {'status': 'BLOCKED', **action, 'message': 'Live remediation is disabled.'}
    if group != os.environ.get('PROTECTED_SECURITY_GROUP_ID'):
        return {'status': 'BLOCKED', **action, 'message': 'Target is outside the configured protected group.'}
    if ec2_client is None:
        import boto3
        ec2_client = boto3.client('ec2')
    groups = ec2_client.describe_security_groups(GroupIds=[group]).get('SecurityGroups', [])
    if len(groups) != 1 or groups[0].get('GroupId') != group:
        raise RuntimeError('EC2 did not return the requested security group.')
    permissions = public_permissions(groups[0].get('IpPermissions'))
    if not permissions:
        return {'status': 'ALREADY_SECURE', **action, 'message': 'No public SSH rule remains; verify state independently.'}
    try:
        result = ec2_client.revoke_security_group_ingress(GroupId=group, IpPermissions=permissions)
    except Exception as error:
        # A duplicate delivery may race another responder. The verifier still checks state.
        code = getattr(error, 'response', {}).get('Error', {}).get('Code')
        if code != 'InvalidPermission.NotFound':
            raise
        return {'status': 'ALREADY_SECURE', **action, 'message': 'Rule changed concurrently; independent verification required.'}
    if result.get('Return') is not True:
        raise RuntimeError('EC2 did not confirm the revoke operation.')
    return {'status': 'REMEDIATED', **action, 'removed_permissions': permissions,
            'message': 'Public sources removed using exact current rule bounds.'}
