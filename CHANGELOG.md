# Changelog

## 1.0.0 — 2026-11

First public release.

- Scopes with IPs, hostnames, CIDR ranges and web application URLs; scan customer details; load balancer flags.
- Engines: Nmap (all TCP, common UDP, OS detection), testssl.sh, OWASP ZAP (crawl, passive, active), Nuclei,
  HTTP checks, end-of-life detection (bundled endoflife.date data), NVD version correlation, DNS zone transfer
  and scope discovery.
- ASV scoring policy: CVSS ≥ 4.0, automatic failures, DoS exemption, special notes with customer declarations,
  discovered components, inconclusive scans with interference detection.
- Workflow: per-finding disputes with evidence and review, rescans of failing components, combined results,
  report finalisation with customer attestation, three-month cadence tracking, schedules and webhooks.
- Reports in the ASV layout (HTML, PDF, JSON, CSV, Markdown) with PCI DSS v4.0.1 mapping.
- Importers for Nessus, Greenbone/OpenVAS, ZAP, Nuclei, Nmap and testssl.sh results.
- REST API, CLI with CI exit codes, optional sign-in, audit trail, card-number masking.
- Black-box checks beyond the ASV minimum: SSH algorithm audit (ssh-audit), web application firewall detection
  (wafw00f), page script and security-header inventory with change detection between scans, SPF/DMARC checks,
  certificate and protocol inventory. Findings map to 29 PCI DSS v4.0.1 requirements.
- Interface and reports in English and Vietnamese; light, dark and system themes.
- Runs from source in an IDE (shared PyCharm run configurations, `.env` loading) or with Docker Compose.
