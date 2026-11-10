"""DNS: zone-transfer testing and ASV-style scope discovery (MX, NS, common hostnames)."""
from __future__ import annotations

import re

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from .. import config, findings
from .base import Ctx

COMMON_HOSTS = ["www", "mail", "webmail", "smtp", "mx", "vpn", "remote", "portal", "api", "shop", "store", "pay",
                "payment", "payments", "checkout", "secure", "admin", "ftp", "autodiscover", "owa", "m", "app"]


def _resolver_cfg() -> tuple[list[str] | None, int]:
    raw = config.settings.dns_resolver
    if not raw:
        return None, 53
    host, _, port = raw.partition(":")
    return [host], int(port or 53)


def resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    ns, port = _resolver_cfg()
    if ns:
        r.nameservers, r.port = ns, port
    r.lifetime, r.timeout = 8.0, 4.0
    return r


def _a(r, name: str) -> list[str]:
    out = []
    for t in ("A", "AAAA"):
        try:
            out += [x.to_text() for x in r.resolve(name, t)]
        except (dns.exception.DNSException, ValueError):
            pass
    return out


def try_axfr(domain: str, ns_ip: str) -> int:
    _, port = _resolver_cfg()
    try:
        z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, port=port, timeout=10, lifetime=25))
        return sum(1 for _ in z.iterate_rdatas())
    except Exception:  # noqa: BLE001  (refused / timeout / not authoritative are all "not vulnerable")
        return 0


def _txt(r, name: str) -> list[str]:
    try:
        return ["".join(p.decode("utf-8", "replace") for p in rr.strings) for rr in r.resolve(name, "TXT")]
    except dns.exception.DNSException:
        return []


def email_authentication(ctx: Ctx, r, domain: str, in_scope: set[str]) -> None:
    """SPF and DMARC of a domain that receives mail: anti-spoofing controls referenced by PCI DSS 5.4.1."""
    spf = [t for t in _txt(r, domain) if t.lower().startswith("v=spf1")]
    dmarc = [t for t in _txt(r, f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    problems = []
    if not spf:
        problems.append("No SPF record")
    elif "+all" in spf[0].lower() or spf[0].lower().rstrip().endswith(" all"):
        problems.append(f"SPF allows any sender: {spf[0]}")
    if not dmarc:
        problems.append("No DMARC record")
    else:
        m = re.search(r"\bp\s*=\s*(\w+)", dmarc[0], re.I)
        if not m or m.group(1).lower() == "none":
            problems.append(f"DMARC policy does not reject or quarantine spoofed mail: {dmarc[0]}")
    ctx.state.setdefault("email_auth", {})[domain] = {"spf": spf[:1], "dmarc": dmarc[:1], "problems": problems}
    if not problems:
        return
    comp = next((h for h in sorted(in_scope) if h == domain or h.endswith("." + domain)), domain)
    ctx.findings.append(findings.make(
        "dns", "email_spoofing", comp, f"Email anti-spoofing controls incomplete for {domain}", service="dns",
        evidence="\n".join(problems), rule_id=f"email-auth-{domain}",
        description="Without an enforcing SPF and DMARC policy, attackers can send phishing mail that appears to "
                    "come from this domain. DKIM selectors cannot be enumerated remotely and were not checked."))


def run(ctx: Ctx, domains: list[str], in_scope: set[str], dns_hosts: dict[str, str]) -> None:
    """ctx.target is a synthetic 'dns' target; findings are attached to the name server component.

    domains: registrable domains in scope; in_scope: names/IPs already in scope;
    dns_hosts: {component_name: ip} of in-scope hosts that expose a DNS service (port 53)."""
    r = resolver()
    for i, d in enumerate(domains):
        ctx.check()
        ctx.progress(5 + 85 * i // max(1, len(domains)), f"DNS checks for {d}")
        name_servers = {}
        try:
            for ns in r.resolve(d, "NS"):
                n = ns.target.to_text().rstrip(".").lower()
                name_servers[n] = _a(r, n)
        except dns.exception.DNSException as e:
            ctx.log(f"[dns] NS lookup for {d} failed: {e}")
        for comp, ip in dns_hosts.items():
            name_servers.setdefault(comp, [ip])
        for n, ips in name_servers.items():
            if ips:
                ctx.state.setdefault("dns_checked", set()).add(n)
            if n not in in_scope:
                ctx.discover(n, "host", f"authoritative name server for {d}")
            for ip in ips[:2]:
                count = try_axfr(d, ip)
                if count:
                    ctx.findings.append(findings.make(
                        "dns", "dns_zone_transfer", n, f"Zone transfer (AXFR) of {d} allowed",
                        port=53, service="domain", evidence=f"AXFR {d} @{ip} returned {count} records",
                        description="The name server returns the full zone to any requester.",
                        rule_id=f"axfr-{d}"))
                    break
        has_mx = False
        try:
            for mx in r.resolve(d, "MX"):
                n = mx.exchange.to_text().rstrip(".").lower()
                has_mx = has_mx or bool(n)
                if n and n not in in_scope:
                    ctx.discover(n, "host", f"MX record of {d}")
        except dns.exception.DNSException:
            pass
        if has_mx:
            email_authentication(ctx, r, d, in_scope)
        for h in COMMON_HOSTS:
            fq = f"{h}.{d}"
            if fq not in in_scope and _a(r, fq):
                ctx.discover(fq, "host", f"DNS lookup of common hostname in {d}")
        if d not in in_scope and _a(r, d):
            ctx.discover(d, "host", "apex domain of an in-scope host")
    ctx.progress(100, f"{len(domains)} domain(s) checked")
