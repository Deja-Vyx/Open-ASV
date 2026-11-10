"""testssl.sh: protocols, cipher suites, certificate validity and TLS vulnerabilities."""
from __future__ import annotations

import json
from pathlib import Path

from .. import config, findings
from .base import Ctx, EngineError, run_cmd, plural

_SEV = {"DEBUG": 0, "INFO": 1, "OK": 1, "WARN": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5, "FATAL": 6}

# id -> (category, matcher). matcher(sev, finding_lower) -> bool
_OFFERED = lambda s, f: "not offered" not in f and "offered" in f  # noqa: E731
RULES = {
    "SSLv2": ("ssl_early_tls", _OFFERED),
    "SSLv3": ("ssl_early_tls", _OFFERED),
    "TLS1": ("ssl_early_tls", _OFFERED),
    "TLS1_1": ("deprecated_tls", _OFFERED),
    "cipherlist_NULL": ("weak_cipher", _OFFERED),
    "cipherlist_aNULL": ("anonymous_cipher", _OFFERED),
    "cipherlist_EXPORT": ("weak_cipher", _OFFERED),
    "cipherlist_LOW": ("weak_cipher", _OFFERED),
    "cipherlist_3DES_IDEA": ("weak_cipher", _OFFERED),
    "cipherlist_OBSOLETED": ("weak_cipher", lambda s, f: _OFFERED(s, f) and _SEV.get(s, 0) >= _SEV["MEDIUM"]),
    "RC4": ("weak_cipher", lambda s, f: _SEV.get(s, 0) >= _SEV["LOW"]),
    "cert_chain_of_trust": ("cert_untrusted", lambda s, f: _SEV.get(s, 0) >= _SEV["HIGH"]),
    "cert_trust": ("cert_untrusted", lambda s, f: _SEV.get(s, 0) >= _SEV["HIGH"] or "does not match" in f
                   or "mismatch" in f),
    "cert_expirationStatus": ("cert_expired", lambda s, f: "expired" in f),
    "cert_notAfter": (None, None),
    "secure_client_renego": ("dos_only", lambda s, f: _SEV.get(s, 0) >= _SEV["MEDIUM"]),
}
VULN_IDS = {"heartbleed", "CCS", "ticketbleed", "ROBOT", "secure_renego", "CRIME_TLS", "POODLE_SSL",
            "fallback_SCSV", "SWEET32", "FREAK", "DROWN", "DROWN_hint", "LOGJAM", "LOGJAM-common_primes",
            "BEAST", "LUCKY13", "winshock", "opossum", "BREACH"}
VULN_MIN = {"BEAST": "MEDIUM", "LUCKY13": "MEDIUM", "BREACH": "HIGH", "fallback_SCSV": "MEDIUM"}


def tls_ports(ctx: Ctx) -> list[int]:
    ports = [ctx.url_port(u) for u in ctx.target.web_urls if u.startswith("https://")]
    for s in ctx.state.get("services", []):
        if s["tls"] and s["proto"] == "tcp":
            ports.append(s["port"])
    return sorted(set(ports))


def run(ctx: Ctx) -> None:
    ports = tls_ports(ctx)
    if not ports:
        ctx.progress(100, "No TLS services")
        ctx.state["testssl_skipped"] = True
        return
    s = config.settings
    for i, port in enumerate(ports):
        ctx.check()
        out = ctx.run_dir / f"testssl_{ctx.component}_{port}.json".replace(":", "_")
        out.unlink(missing_ok=True)
        args = [s.testssl, "--jsonfile", str(out), "--warnings", "batch", "--quiet", "--color", "0",
                "--connect-timeout", "10", "--openssl-timeout", "10"]
        cas = [c for c in s.extra_ca if Path(c).is_file()]
        if cas:
            args += ["--add-ca", ",".join(cas)]
        args += list(ctx.profile.get("testssl") or [])
        args.append(f"{ctx.target.tool_host}:{port}")
        ctx.progress(5 + 90 * i // len(ports), f"TLS analysis of port {port}")
        rc = run_cmd(ctx, args, timeout=1800, label=f"testssl:{port}")
        if not out.exists():
            raise EngineError(f"testssl.sh produced no JSON for port {port} (exit {rc})")
        parse(out, ctx, port)
        ctx.state.setdefault("tls_tested", set()).add(port)
    ctx.progress(100, f"{plural(len(ports), 'TLS service')} analysed")


_PROTOCOLS = {"SSLv2": "SSL 2.0", "SSLv3": "SSL 3.0", "TLS1": "TLS 1.0", "TLS1_1": "TLS 1.1", "TLS1_2": "TLS 1.2",
              "TLS1_3": "TLS 1.3"}
_CERT_FIELDS = {"cert_commonName": "subject", "cert_caIssuers": "issuer", "cert_notAfter": "expires",
                "cert_keySize": "key", "cert_signatureAlgorithm": "signature", "cert_fingerprintSHA256": "sha256"}


def inventory(data: list[dict], ctx: Ctx, port: int, raw_name: str) -> None:
    """Protocols offered and the certificate presented: an inventory for PCI DSS 4.2.1.1 and 12.3.3."""
    protocols, cert = [], {}
    for d in data:
        rid = str(d.get("id", "")).split(" ")[0]
        fnd = str(d.get("finding", ""))
        if rid in _PROTOCOLS and "not offered" not in fnd.lower() and "offered" in fnd.lower():
            protocols.append(_PROTOCOLS[rid])
        elif rid in _CERT_FIELDS and _CERT_FIELDS[rid] not in cert:
            cert[_CERT_FIELDS[rid]] = fnd
    if not protocols and not cert:
        return
    ctx.state.setdefault("crypto_inventory", []).append({"port": port, "kind": "TLS", "protocols": protocols, "detail": cert})
    lines = [f"Protocols offered: {', '.join(protocols) or 'not determined'}"]
    lines += [f"Certificate {k}: {v}" for k, v in cert.items()]
    ctx.findings.append(findings.make(
        "testssl", "crypto_inventory", ctx.component, "TLS protocol and certificate inventory", port=port,
        service="tls", evidence="\n".join(lines), rule_id="tls-inventory", raw_ref=raw_name,
        description="Protocols and certificate in use on this service, for the inventory of trusted keys and "
                    "certificates and the annual review of cipher suites and protocols."))


def parse(path: Path, ctx: Ctx, port: int) -> None:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace") or "[]")
    if isinstance(data, dict):  # --jsonfile-pretty layout
        data = [x for sr in data.get("scanResult", []) for v in sr.values() if isinstance(v, list) for x in v]
    fatal = [d for d in data if d.get("id") == "scanProblem" and d.get("severity") == "FATAL"]
    if fatal:
        raise EngineError(f"testssl.sh could not test port {port}: {fatal[0].get('finding')}")
    inventory(data, ctx, port, path.name)
    for d in data:
        rid = str(d.get("id", ""))
        base = rid.split(" ")[0]
        sev = str(d.get("severity", "INFO")).upper()
        fnd = str(d.get("finding", ""))
        low = fnd.lower()
        if base == "cert_subjectAltName":
            for name in fnd.split():
                name = name.strip().lower().lstrip("*.")
                if "." in name and name != ctx.component:
                    ctx.state.setdefault("cert_names", set()).add(name)
            continue
        cat = None
        if base in RULES:
            cat, matcher = RULES[base]
            if cat and not matcher(sev, low):
                cat = None
        elif base in VULN_IDS and _SEV.get(sev, 0) >= _SEV[VULN_MIN.get(base, "MEDIUM")]:
            cat = "tls_vulnerability" if base != "SWEET32" else "weak_cipher"
        if not cat:
            continue
        cve = [c for c in str(d.get("cve", "")).split() if c.startswith("CVE-")]
        cwe = [c for c in str(d.get("cwe", "")).split() if c.startswith("CWE-")]
        hint = sev.lower() if sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else None
        title = {"ssl_early_tls": f"{base.replace('TLS1', 'TLS 1.0').replace('SSLv', 'SSL v')} offered",
                 "deprecated_tls": "TLS 1.1 offered"}.get(cat, f"{base}: {fnd}")
        ctx.findings.append(findings.make(
            "testssl", cat, ctx.component, title, port=port, service="tls", evidence=f"{rid}: {fnd}",
            description=f"testssl.sh check '{rid}' reported severity {sev}.", cve=cve, cwe=cwe,
            severity_hint=hint, rule_id=base, raw_ref=f"{path.name}#{rid}"))
        if cat == "anonymous_cipher":
            ctx.note("anonymous_key_agreement", f"Anonymous cipher suites offered on port {port}", port, "testssl")
