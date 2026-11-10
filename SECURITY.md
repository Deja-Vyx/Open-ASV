# Security policy

## Reporting a vulnerability in OpenASV

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/Deja-Vyx/openasv/security/advisories/new) rather than public issues.
Include the version, deployment method and steps to reproduce. You will receive an acknowledgement within a few days.

## Hardening a deployment

- Publish the UI on `127.0.0.1` (the default Compose file does) or behind an authenticating reverse proxy with TLS.
- Set `OPENASV_ADMIN_PASSWORD`, `OPENASV_API_TOKEN` and a unique `ZAP_API_KEY`.
- Keep `config/target-policy.yaml` restrictive: list only systems you are authorized to test.
- Scan data (`/data`) contains vulnerability details and dispute evidence; restrict access and back it up like any
  other security record. OpenASV masks values that look like card numbers, but treat evidence uploads with care.
