# Incident Report — Public SSH Exposure

## Executive Summary

This lab simulated an AWS security incident in which an EC2 security group was modified to allow SSH (TCP/22) from `0.0.0.0/0`.

The event-driven incident-response pipeline successfully detected the change, investigated the CloudTrail event, automatically revoked the dangerous ingress rule, and independently verified the resulting AWS security group state.

**Final Status:** REMEDIATED AND VERIFIED

---

## Incident Classification

| Field | Value |
|---|---|
| Incident Type | Public SSH Exposure |
| Severity | HIGH |
| AWS Service | Amazon EC2 |
| Detection Source | AWS CloudTrail |
| Detection/Routing | Amazon EventBridge |
| Response Engine | AWS Lambda |
| Infrastructure | Terraform |
| Remediation | Automated |
| Verification | Automated AWS state validation |

---

## Trigger

The simulated incident authorized the following ingress:

- Protocol: TCP
- Port: 22
- Source: `0.0.0.0/0`

The corresponding AWS API operation was:

`AuthorizeSecurityGroupIngress`

This configuration would expose SSH to the public IPv4 internet.

---

## Detection

CloudTrail recorded the security group modification.

An EventBridge rule matched the `AuthorizeSecurityGroupIngress` API event and invoked the incident-response Lambda function.

The detector inspected the event and classified it as dangerous only when the requested permission included TCP/22 exposed to `0.0.0.0/0`.

---

## Investigation

The Lambda investigation stage extracted structured incident context including:

- event name
- identity type
- actor
- source IP
- affected security group
- AWS region
- timestamp
- severity

The incident was classified as **HIGH severity**.

---

## Automated Response

The remediation stage executed:

`ec2:RevokeSecurityGroupIngress`

The Lambda IAM role permits this destructive operation only against the protected lab security group.

A separate `ENABLE_LIVE_REMEDIATION` safety gate controls whether live remediation is permitted.

---

## Verification

After the revoke operation succeeded, the workflow did not assume that the resource was secure.

The verification stage called:

`ec2:DescribeSecurityGroups`

It independently inspected the resulting ingress configuration and confirmed that TCP/22 was no longer exposed to `0.0.0.0/0`.

The workflow reported:

- Response: `REMEDIATED`
- Verification: `VERIFIED`
- Mode: `LIVE`

A separate AWS CLI query after execution also showed no remaining ingress permissions on the protected security group.

---

## Response Lifecycle

```text
AuthorizeSecurityGroupIngress
            ↓
        CloudTrail
            ↓
       EventBridge
            ↓
          Lambda
            ↓
          DETECT
            ↓
        INVESTIGATE
            ↓
         REMEDIATE
            ↓
          VERIFY
            ↓
      INCIDENT CLOSED
```
