"""Scope components: parsing, resolution and the target authorization policy."""
from __future__ import annotations

import fnmatch
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from . import config


class TargetError(ValueError):
    pass


PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "::1/128", "fc00::/7", "fe80::/10")]


@dataclass
class Component:
    kind: str                 # host | ip | url | cidr
    value: str                # normalised value as stored
    host: str                 # hostname or IP (for url: the URL host)
    port: int | None = None   # url port
    scheme: str | None = None
    url: str | None = None
    ips: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.host


def parse(raw: str) -> Component:
    raw = (raw or "").strip()
    if not raw:
        raise TargetError("Empty component")
    if "://" in raw:
        p = urlsplit(raw)
        if p.scheme not in ("http", "https"):
            raise TargetError(f"Unsupported scheme in {raw!r}; use http:// or https://")
        if not p.hostname:
            raise TargetError(f"URL without host: {raw!r}")
        if p.username or p.password:
            raise TargetError("Do not put credentials in component URLs")
        try:
            port = p.port or (443 if p.scheme == "https" else 80)
        except ValueError as e:
            raise TargetError(f"Invalid port in {raw!r}") from e
        host = p.hostname.lower()
        default = (p.scheme, port) in (("https", 443), ("http", 80))
        hn = f"[{host}]" if ":" in host else host
        netloc = hn if default else f"{hn}:{port}"
        url = urlunsplit((p.scheme, netloc, p.path or "/", p.query, ""))
        return Component("url", url, host, port, p.scheme, url)
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as e:
            raise TargetError(f"Invalid CIDR {raw!r}") from e
        return Component("cidr", str(net), str(net))
    try:
        ip = ipaddress.ip_address(raw.strip("[]"))
        return Component("ip", str(ip), str(ip), ips=[str(ip)])
    except ValueError:
        pass
    host = raw.lower().rstrip(".")
    if not all(part and len(part) < 64 for part in host.split(".")) or any(c in host for c in " _/\\@"):
        raise TargetError(f"Invalid hostname {raw!r}")
    return Component("host", host, host)


def resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise TargetError(f"Cannot resolve {host}: {e.strerror}") from e
    return sorted({i[4][0].split("%")[0] for i in infos})


def is_private(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return any(a.version == n.version and a in n for n in PRIVATE_NETS)


def expand(c: Component) -> list[str]:
    """IP addresses covered by a cidr component."""
    net = ipaddress.ip_network(c.value)
    limit = int(config.target_policy().get("max_cidr_hosts", 256))
    if net.num_addresses > limit:
        raise TargetError(f"{c.value} has {net.num_addresses} addresses (limit {limit}, see target-policy.yaml)")
    hosts = list(net.hosts()) or [net.network_address]
    return [str(h) for h in hosts]


def _match_host(host: str, patterns) -> str | None:
    for p in patterns or []:
        if fnmatch.fnmatchcase(host, str(p).lower()):
            return str(p)
    return None


def _in_cidrs(ip: str, cidrs) -> str | None:
    a = ipaddress.ip_address(ip)
    for c in cidrs or []:
        try:
            n = ipaddress.ip_network(str(c), strict=False)
        except ValueError:
            continue
        if a.version == n.version and a in n:
            return str(c)
    return None


def authorize(c: Component, resolver=resolve) -> str:
    """Return a human-readable reason the component is allowed, or raise TargetError."""
    pol = config.target_policy()
    if c.kind == "cidr":
        ips = expand(c)
    elif c.kind == "ip":
        ips = [c.host]
    else:
        tool_host = tool_host_for(c.host)
        ips = resolver(tool_host)
    c.ips = ips
    if _match_host(c.host, pol.get("deny_hosts")):
        raise TargetError(f"{c.host} is denied by target-policy.yaml")
    for ip in ips:
        if _in_cidrs(ip, pol.get("deny_cidrs")):
            raise TargetError(f"{ip} is denied by target-policy.yaml")
    if c.kind in ("host", "url"):
        m = _match_host(c.host, pol.get("allow_hosts"))
        if m:
            return f"hostname matches allow_hosts ({m})"
    reasons = []
    for ip in ips:
        m = _in_cidrs(ip, pol.get("allow_cidrs"))
        if m:
            reasons.append(m)
        elif pol.get("allow_private_networks", True) and is_private(ip):
            reasons.append("private network")
        else:
            raise TargetError(
                f"{c.host} resolves to {ip}, which is not permitted by config/target-policy.yaml. "
                "Add the host or range only if you own it or have written authorization to test it.")
    return "all addresses permitted (" + ", ".join(sorted(set(reasons))) + ")"


def tool_host_for(host: str) -> str:
    alias = config.settings.localhost_alias
    if alias and host in ("localhost", "127.0.0.1", "::1"):
        return alias
    return host


def tcp_probe(host: str, port: int, timeout: float = 4.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "TCP connection established"
    except OSError as e:
        return False, f"connection failed: {e}"


def registrable_domain(host: str) -> str | None:
    """Best-effort registrable domain without the public suffix list (handles common 2-level ccTLDs)."""
    if not host or "/" in host or ":" in host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    labels = host.split(".")
    if labels[-1].isdigit():
        return None
    if len(labels) < 2 or labels[-1] in ("local", "localhost", "internal", "lan", "test", "example", "invalid"):
        return None
    second = {"com", "net", "org", "edu", "gov", "co", "ac", "or", "ne", "go", "mil", "int", "info", "biz"}
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in second:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
