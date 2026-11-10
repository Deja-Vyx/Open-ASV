"""Nmap: port and service discovery (TCP + common UDP), OS fingerprinting."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .. import config, findings
from .base import Ctx, EngineError, run_cmd, plural

WEB_SERVICES = {"http", "https", "http-alt", "http-proxy", "https-alt", "http-mgmt", "ssl/http", "ssl/https", "www"}


def build_args(ctx: Ctx, out: Path) -> list[str]:
    s = config.settings
    p = ctx.profile["nmap"]
    tcp = str(p.get("tcp_ports") or "url")
    udp = str(p.get("udp_ports") or "")
    privileged = s.privileged
    args = [s.nmap, "-Pn", "-n", "-sV", "--version-intensity", str(p.get("version_intensity", 5)),
            "-T4", "--max-retries", "2", "--open", "--reason", "--stats-every", "15s", "-oX", str(out)]
    args.append("-sS" if privileged else "-sT")
    if privileged and udp:
        args.append("-sU")
    if privileged and p.get("os_detection"):
        args += ["-O", "--osscan-limit"]
    if tcp == "url":
        tcp_spec = ",".join(str(x) for x in sorted(set(ctx.target.ports))) or "80,443"
    elif tcp == "top1000":
        tcp_spec = None
    else:
        tcp_spec = tcp
    if tcp_spec is None:
        args += ["--top-ports", "1000"] if not (privileged and udp) else ["-p", f"T:{_top1000()},U:{udp}"]
    else:
        args += ["-p", f"T:{tcp_spec}" + (f",U:{udp}" if privileged and udp else "")]
    args.append(ctx.target.tool_host)
    return args


def _top1000() -> str:
    # Used only when UDP is combined with a top-1000 TCP selection; nmap cannot mix --top-ports with U: lists.
    return "1-1024,1080,1194,1433,1521,1723,2049,2082,2083,2086,2087,2375,2376,3000,3306,3389,5000,5432,5601," \
           "5900,5985,5986,6379,7001,8000,8008,8080,8081,8088,8443,8888,9000,9090,9200,9443,10000,11211,27017"


def run(ctx: Ctx) -> None:
    out = ctx.run_dir / f"nmap_{_safe(ctx.component)}.xml"
    args = build_args(ctx, out)
    ctx.state.setdefault("coverage", {})["udp"] = bool(config.settings.privileged and ctx.profile["nmap"].get("udp_ports"))
    ctx.state["coverage"]["tcp"] = str(ctx.profile["nmap"].get("tcp_ports"))
    ctx.progress(5, "Port and service discovery")

    def stats(line: str) -> bool:
        m = re.search(r"^(.+?) Timing: About ([\d.]+)% done", line)
        if m:
            ctx.progress(5 + int(float(m.group(2)) * 0.9), f"{m.group(1).strip()}: {float(m.group(2)):.0f}%")
            return True
        if line.startswith("Stats:"):
            return True
        return False

    rc = run_cmd(ctx, args, timeout=4 * 3600, label="nmap", on_line=stats)
    if rc != 0 or not out.exists():
        raise EngineError(f"nmap exited with code {rc}")
    parse(out, ctx)
    ctx.progress(100, plural(len(ctx.state.get('services', [])), "open service"))


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)


def parse(path: Path, ctx: Ctx) -> None:
    pol = config.policy()["services"]
    dbn, dbp = {x.lower() for x in pol["database_names"]}, set(pol["database_ports"])
    ran, rap = {x.lower() for x in pol["remote_access_names"]}, set(pol["remote_access_ports"])
    insecure = {x.lower() for x in pol["insecure_names"]}
    unknown = {x.lower() for x in pol["unknown_names"]}
    pos_kw = [x.lower() for x in pol["pos_keywords"]]

    root = ET.parse(path).getroot()
    services, banners, oses = [], [], []
    for host in root.findall("host"):
        for osm in host.findall("os/osmatch")[:3]:
            cpes = [c.text for c in osm.findall("osclass/cpe") if c.text]
            oses.append({"name": osm.get("name", ""), "accuracy": int(osm.get("accuracy", "0")), "cpe": cpes})
        for p in host.findall("ports/port"):
            st = p.find("state")
            if st is None or not st.get("state", "").startswith("open"):
                continue
            if st.get("state") == "open|filtered":
                continue  # UDP without a response is not evidence of a listening service
            svc = p.find("service")
            g = (lambda k, _s=svc: (_s.get(k) or "") if _s is not None else "")
            name, tunnel, product, version = (g("name") or "unknown").lower(), g("tunnel"), g("product"), g("version")
            extrainfo = g("extrainfo")
            cpes = [c.text for c in svc.findall("cpe") if c.text] if svc is not None else []
            port, proto = int(p.get("portid")), p.get("protocol", "tcp")
            tls = tunnel == "ssl" or name in ("https", "ssl", "https-alt") or name.startswith("ssl/")
            web = proto == "tcp" and (name in WEB_SERVICES or name.startswith("http") or (tls and name in ("ssl", "unknown")))
            rec = {"port": port, "proto": proto, "service": name, "tunnel": tunnel, "product": product,
                   "version": version, "extrainfo": extrainfo, "cpe": cpes, "tls": tls, "web": web}
            services.append(rec)
            if product:
                banners.append({"product": product, "version": version, "cpe": cpes, "port": port, "source": "nmap"})
            label = f"{'ssl/' if tunnel == 'ssl' else ''}{name}"
            banner = " ".join(x for x in (product, version, extrainfo and f"({extrainfo})") if x) or name
            ev = f"{port}/{proto} open {label} {banner}".strip()
            comp = ctx.component
            ctx.findings.append(findings.make(
                "nmap", "open_port", comp, f"{port}/{proto} {label}" + (f" — {banner}" if banner != name else ""),
                port=port, protocol=proto, service=name, evidence=ev, rule_id=f"port-{proto}-{port}",
                description="Service detected by Nmap. ASV reports list exposed services so the scan customer can confirm each has a business need.",
                raw_ref=path.name, extra={"cpe": cpes}))
            if not web and (name in dbn or port in dbp):
                ctx.findings.append(findings.make(
                    "nmap", "database_exposed", comp, f"Database service reachable: {name} ({banner})",
                    port=port, protocol=proto, service=name, evidence=ev, rule_id=f"db-{port}", raw_ref=path.name,
                    description="A database listener accepts connections from the scanning network. Open access to databases from the Internet is an automatic failure."))
            if name in ran or (port in rap and name in ("unknown", "tcpwrapped")):
                ctx.note("remote_access", f"{label} on {port}/{proto} ({banner})", port, "nmap")
            if name in insecure or (name == "ftp" and tls is False):
                ctx.note("insecure_service", f"{label} on {port}/{proto} ({banner})", port, "nmap")
            if name in unknown:
                ctx.note("unknown_service", f"Unidentified service on {port}/{proto}", port, "nmap")
            if any(k in f"{product} {extrainfo}".lower() for k in pos_kw):
                ctx.note("pos_software", f"{banner} on {port}/{proto}", port, "nmap")
    ctx.state["services"] = services
    ctx.state.setdefault("banners", []).extend(banners)
    ctx.state["os"] = oses
