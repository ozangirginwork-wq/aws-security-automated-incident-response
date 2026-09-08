def detect_public_ssh(event):
    """
    Detects whether an AWS CloudTrail event exposes SSH (TCP/22)
    to the entire IPv4 internet (0.0.0.0/0).
    """

    detail = event.get("detail", {})

    # Only inspect security-group ingress changes.
    if detail.get("eventName") != "AuthorizeSecurityGroupIngress":
        return False

    request_parameters = detail.get("requestParameters", {})
    permissions = request_parameters.get("ipPermissions", {}).get("items", [])

    for permission in permissions:
        protocol = permission.get("ipProtocol")
        from_port = permission.get("fromPort")
        to_port = permission.get("toPort")

        # Check whether TCP port 22 is included in the rule.
        ssh_exposed = (
            protocol == "tcp"
            and from_port is not None
            and to_port is not None
            and from_port <= 22 <= to_port
        )

        if not ssh_exposed:
            continue

        ip_ranges = permission.get("ipRanges", {}).get("items", [])

        for ip_range in ip_ranges:
            if ip_range.get("cidrIp") == "0.0.0.0/0":
                return True

    return False