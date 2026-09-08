"""Shared SSH rule matching for CloudTrail input and EC2 state verification."""


def items(value):
    if isinstance(value, dict):
        value = value.get('items', [])
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def exposes_ssh(protocol, start=None, end=None):
    protocol = str(protocol).lower()
    if protocol == '-1':
        return True
    if protocol not in {'tcp', '6'}:
        return False
    try:
        return int(start) <= 22 <= int(end)
    except (TypeError, ValueError):
        return False


def public_permissions(permissions, cloudtrail=False):
    """Keep exact protocol/port bounds but only public sources; preserve trusted CIDRs."""
    result = []
    for permission in items(permissions):
        protocol_key, start_key, end_key = ('ipProtocol', 'fromPort', 'toPort') if cloudtrail else ('IpProtocol', 'FromPort', 'ToPort')
        protocol = permission.get(protocol_key)
        if not exposes_ssh(protocol, permission.get(start_key), permission.get(end_key)):
            continue
        rule = {'IpProtocol': 'tcp' if str(protocol).lower() in {'tcp', '6'} else '-1'}
        if rule['IpProtocol'] != '-1':
            rule.update(FromPort=int(permission[start_key]), ToPort=int(permission[end_key]))
        for api_key, trail_key, api_cidr, trail_cidr, public in [
            ('IpRanges', 'ipRanges', 'CidrIp', 'cidrIp', '0.0.0.0/0'),
            ('Ipv6Ranges', 'ipv6Ranges', 'CidrIpv6', 'cidrIpv6', '::/0'),
        ]:
            ranges = items(permission.get(trail_key if cloudtrail else api_key))
            if any(value.get(trail_cidr if cloudtrail else api_cidr) == public for value in ranges):
                rule[api_key] = [{api_cidr: public}]
        if 'IpRanges' in rule or 'Ipv6Ranges' in rule:
            result.append(rule)
    return result
