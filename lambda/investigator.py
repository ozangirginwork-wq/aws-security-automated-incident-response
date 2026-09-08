def investigate_event(event):
    """
    Extract security-relevant information from a CloudTrail event.
    """

    detail = event.get("detail", {})
    identity = detail.get("userIdentity", {})
    request = detail.get("requestParameters", {})

    incident = {
        "event_name": detail.get("eventName", "Unknown"),
        "actor_type": identity.get("type", "Unknown"),
        "actor": identity.get("userName") or identity.get("arn") or identity.get("principalId", "Unknown"),
        "source_ip": detail.get("sourceIPAddress", "Unknown"),
        "security_group": request.get("groupId", "Unknown"),
        "region": event.get("region", "Unknown"),
        "timestamp": event.get("time", "Unknown"),
        "severity": "HIGH"
    }

    return incident