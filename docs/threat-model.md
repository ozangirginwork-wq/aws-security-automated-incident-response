# Threat Model — AWS Automated Incident Response

## System Purpose

This project protects a designated AWS security group against accidental or unauthorized public SSH exposure.

The protected condition is:

`TCP/22 from 0.0.0.0/0`

The system uses CloudTrail, EventBridge, Lambda, IAM, and EC2 APIs to detect and remediate this condition.

---

## Protected Asset

The primary protected asset is an AWS EC2 security group managed by Terraform.

The security objective is to prevent SSH port 22 from remaining publicly accessible from the internet.

---

## Threat Scenario

An administrator, compromised identity, automation process, or configuration error authorizes an ingress rule that exposes:

- Protocol: TCP
- Port: 22
- Source: `0.0.0.0/0`

This creates unrestricted public SSH exposure.

---

## Detection

AWS CloudTrail records the `AuthorizeSecurityGroupIngress` API event.

Amazon EventBridge monitors CloudTrail events and forwards relevant security-group changes to the incident-response Lambda function.

The detector validates that the event represents public SSH exposure before remediation is attempted.

---

## Investigation

When a dangerous rule is detected, the Lambda pipeline extracts incident context including:

- Event name
- Identity type
- Actor
- Source IP
- Security group
- AWS Region
- Timestamp
- Severity

This information is written to CloudWatch Logs to provide an auditable incident trail.

---

## Automated Remediation

When live remediation is enabled, the Lambda function calls:

`ec2:RevokeSecurityGroupIngress`

The dangerous rule is removed automatically.

The IAM role follows least-privilege principles: the remediation permission is scoped to the designated protected security group.

---

## Verification

Successful execution of the revoke API is not treated as sufficient proof that the environment is secure.

After remediation, the verifier independently queries AWS using:

`ec2:DescribeSecurityGroups`

It confirms that TCP port 22 is no longer exposed to `0.0.0.0/0`.

The incident is marked verified only when the AWS resource state confirms that the exposure has been removed.

---

## Safety Controls

The project includes multiple safeguards:

1. Dry-run support for safe testing.
2. `ENABLE_LIVE_REMEDIATION` environment-variable safety gate.
3. Least-privilege IAM permissions.
4. Remediation restricted to the protected security group.
5. Independent post-remediation verification.
6. Infrastructure managed through Terraform.
7. CloudWatch logging for incident evidence.
8. Automated tests for detection and verification logic.

---

## Trust Boundaries

The primary trust boundaries are:

- AWS identity and IAM authorization
- CloudTrail event generation
- EventBridge event delivery
- Lambda execution environment
- EC2 security-group API
- Terraform deployment environment

Each component receives only the permissions required for its role in the response pipeline.

---

## Response Lifecycle

```text
Security Group Change
        |
        v
    CloudTrail
        |
        v
   EventBridge
        |
        v
      Lambda
        |
        v
      DETECT
        |
        v
    INVESTIGATE
        |
        v
     REMEDIATE
        |
        v
      VERIFY
        |
        v
  INCIDENT CLOSED
```
