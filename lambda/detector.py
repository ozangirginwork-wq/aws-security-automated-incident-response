"""Detect successful ingress changes exposing SSH to the IPv4 or IPv6 internet."""
from rules import public_permissions


def detect_public_ssh(event):
    detail = event.get('detail') or {}
    if detail.get('eventName') != 'AuthorizeSecurityGroupIngress':
        return False
    if detail.get('eventSource') != 'ec2.amazonaws.com':
        return False
    if detail.get('errorCode') or detail.get('errorMessage'):
        return False
    request = detail.get('requestParameters') or {}
    return bool(public_permissions(request.get('ipPermissions'), cloudtrail=True))
