# Controlled SSH exposure — sanitized transcript

This is a manually transcribed excerpt from the historical Lab 6 security-group event screenshot, not a new AWS test or an unmodified terminal capture. The screenshot was removed from the current repository because its earlier redaction left an AWS account ID and security-group rule ARN visible.

The visible response reported these rule properties:

```json
{
  "IsEgress": false,
  "IpProtocol": "tcp",
  "FromPort": 22,
  "ToPort": 22,
  "CidrIpv4": "0.0.0.0/0",
  "SecurityGroupRuleArn": "[REDACTED]"
}
```

This records the controlled public-SSH ingress rule. It does not independently prove EventBridge delivery or successful remediation; see the separate [remediation capture](03-lambda-remediation-verified-sanitized.png).

The source account ID, resource identifier and local user path are omitted. Earlier Git commits may still contain the original screenshot; this edit does not rewrite history.
