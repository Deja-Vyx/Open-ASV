"""SSH server configuration audit (ssh-audit): protocol version, key exchange, host keys, ciphers and MACs."""
from __future__ import annotations

import json
import re

from .. import config, findings
from .base import Ctx, EngineError, command, plural, run_cmd

# Algorithms with practical breaks or no remaining security margin: reported as a failing (Medium) finding.
# Everything else ssh-audit flags is reported once per service as a Low hardening finding.
_BROKEN = re.compile(
    r"^(arcfour.*|rc4.*|des-cbc.*|3des-cbc|blowfish-cbc|cast128-cbc|none|hmac-md5.*|hmac-ripemd.*|"
    r"diffie-hellman-group1-sha1|rsa1024-sha1|ssh-dss|ssh-rsa1)$")
_MIN_RSA_BITS = 2048


def ssh_services(ctx: Ctx) -> list[dict]:
    return [s for s in ctx.state.get("services", []) if s["proto"] == "tcp" and not s.get("tls")
            and (s["service"] == "ssh" or "ssh" in (s.get("product") or "").lower())]


def run(ctx: Ctx) -> None:
    svcs = ssh_services(ctx)
    if not svcs:
        ctx.state["ssh_skipped"] = True
        ctx.progress(100, "No SSH service found")
        return
    exe = config.settings.ssh_audit
    if not command(exe):
        raise EngineError(f"'{exe}' is not installed; SSH algorithms were not audited")
    for i, s in enumerate(svcs):
        ctx.check()
        port = s["port"]
        ctx.progress(5 + 90 * i // len(svcs), f"Auditing SSH on port {port}")
        lines: list[str] = []

        def keep(line: str, _lines=lines) -> bool:
            _lines.append(line)
            return True                       # JSON goes to the raw file, not the scan log
        run_cmd(ctx, [exe, "-j", "-n", "--skip-rate-test", "-t", "10", "-p", str(port), ctx.target.tool_host],
                timeout=180, label=f"ssh-audit:{port}", on_line=keep)
        raw = next((x for x in lines if x.lstrip().startswith("{")), "")
        if not raw:
            raise EngineError(f"ssh-audit could not negotiate with port {port}: {' '.join(lines)[:200]}")
        (ctx.run_dir / f"sshaudit_{ctx.target.host}_{port}.json").write_text(raw, encoding="utf-8")
        parse(json.loads(raw), ctx, port)
    ctx.progress(100, f"{plural(len(svcs), 'SSH service')} audited")


def parse(data: dict, ctx: Ctx, port: int) -> None:
    banner = data.get("banner") or {}
    broken, weak = [], []
    proto = str(banner.get("protocol", ""))
    if proto.startswith("1"):
        broken.append(f"protocol {proto} (SSH-1 accepted)")
    for group, label in (("kex", "key exchange"), ("key", "host key"), ("enc", "cipher"), ("mac", "MAC")):
        for a in data.get(group) or []:
            name = a.get("algorithm", "")
            notes = a.get("notes") or {}
            bits = a.get("keysize")
            small = group == "key" and name.startswith(("ssh-rsa", "rsa-sha2")) and bits and bits < _MIN_RSA_BITS
            if _BROKEN.match(name) or small:
                broken.append(f"{label} {name}" + (f" ({bits}-bit)" if small else ""))
            else:
                # post-quantum advisories apply to nearly every deployed server today and are not a weakness yet
                why = [n for n in (notes.get("fail") or []) + (notes.get("warn") or []) if "post-quantum" not in n]
                if why:
                    weak.append(f"{label} {name}: {why[0]}")
    raw = f"sshaudit_{ctx.target.host}_{port}.json"
    software = banner.get("raw", "")
    common = dict(port=port, service="ssh", raw_ref=raw,
                  references=["https://www.ssh-audit.com/hardening_guides.html"])
    if broken:
        ctx.findings.append(findings.make(
            "ssh-audit", "ssh_broken_crypto", ctx.component, "SSH server offers broken cryptographic algorithms",
            evidence=f"{software}\n" + "\n".join(sorted(set(broken))), rule_id="ssh-broken",
            description="The SSH service negotiates algorithms that no longer provide strong cryptography for "
                        "administrative access.", **common))
    if weak:
        ctx.findings.append(findings.make(
            "ssh-audit", "ssh_weak_crypto", ctx.component, "SSH server offers weak or deprecated algorithms",
            evidence=f"{software}\n" + "\n".join(sorted(set(weak))[:40]), rule_id="ssh-weak",
            description="ssh-audit flags these algorithms as weak or deprecated. They are hardening items, not "
                        "known practical breaks.", **common))
    algs = {g: [a.get("algorithm") for a in data.get(g) or []] for g in ("kex", "key", "enc", "mac")}
    ctx.findings.append(findings.make(
        "ssh-audit", "crypto_inventory", ctx.component, "SSH algorithm inventory", evidence=f"{software}\n" + "\n".join(
            f"{label}: {', '.join(algs[g]) or '-'}" for g, label in (("kex", "Key exchange"), ("key", "Host keys"),
                                                                  ("enc", "Ciphers"), ("mac", "MACs"))),
        rule_id="ssh-inventory", description="Algorithms offered by the SSH service, for the annual review of "
                                             "cryptographic cipher suites and protocols.", **common))
    ctx.state.setdefault("crypto_inventory", []).append({
        "port": port, "kind": "SSH", "software": software,
        "protocols": [f"SSH-{proto}"] if proto else [],
        "detail": algs})
