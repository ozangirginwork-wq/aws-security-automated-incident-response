# Security Policy

## Scope

This repository is an educational AWS security engineering lab. It is not intended to be deployed as a production incident-response system without additional review and hardening.

## Reporting a security issue

Please do not publish credentials, private keys, account details, or other sensitive information in an issue or pull request.

If you discover a repository security problem, contact the repository owner privately through GitHub rather than posting sensitive details publicly.

## Repository safety controls

- Terraform state and local Terraform working directories are excluded from source control.
- Variable files, environment files, private keys, and generated archives are excluded.
- Sample events use synthetic identifiers and documentation-only IP addresses.
- CI performs Python tests and Terraform validation without requiring AWS credentials.
- Live AWS remediation should only be enabled deliberately in a controlled test account.
