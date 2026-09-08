# Historical lab evidence

These artifacts document the original Lab 6 exercise. They do not represent a new deployment of the reviewed code or the current state of the AWS account.

1. [Terraform deployment capture](01-terraform-apply-sanitized.png).
2. [Controlled SSH exposure — sanitized transcript](02-security-group-event-sanitized.md).
3. [Lambda remediation and verification capture](03-lambda-remediation-verified-sanitized.png).

The two screenshots retain the original interface and include explanatory overlays added during the earlier sanitization. Overlays are annotations, not raw AWS output. Nonsecret local paths, timestamps and request identifiers may remain visible.

The previous security-group event screenshot still exposed an account ID and resource ARN despite its sanitization label. It has been replaced in the current repository with a clearly labeled text transcript. Older Git history may retain that screenshot. No history rewrite was performed.

The sample under `sample-events/` is synthetic test input, separate from this historical evidence. No contact-sheet file is included.
