"""Import results from other scanners and score them with the OpenASV ASV policy.

Supported: Tenable Nessus (.nessus v2), Greenbone/OpenVAS (GVM XML report), OWASP ZAP (traditional JSON report),
Nuclei (JSONL), Nmap (XML), testssl.sh (JSON)."""
from __future__ import annotations

import json
import re
import threading
import xml.etree.ElementTree as ET
from pathlib import Path

from .. import db, findings, redact, scoring, targets
from ..engines import nmap as nmap_e, nuclei as nuclei_e, testssl as testssl_e, zap as zap_e
from ..engines.base import Ctx, HostTarget

FORMATS = {
    "nessus": "Tenable Nessus (.nessus)",
    "gvm": "Greenbone / OpenVAS (XML report)",
    "zap": "OWASP ZAP (JSON report)",
    "nuclei": "Nuclei (JSONL)",
    "nmap": "Nmap (XML)",
    "testssl": "testssl.sh (JSON)",
}


class ImportErrorX(ValueError):
    pass


def detect(path: Path) -> str:
    head = path.read_bytes()[:4096].decode("utf-8", "replace").lstrip()
    if "<NessusClientData_v2" in head:
        return "nessus"
    if head.startswith("<?xml") or head.startswith("<"):
        if "<nmaprun" in head:
            return "nmap"
        if "<report" in head:
            return "gvm"
    if head.startswith("{") and '"site"' in path.read_text(encoding="utf-8", errors="replace")[:200000]:
        return "zap"
    if head.startswith("["):
        return "testssl"
    if head.startswith("{") and '"template-id"' in head:
        return "nuclei"
    raise ImportErrorX("Unrecognised file format")


def _ctx(sid: int, host: str, run_dir: Path) -> Ctx:
    return Ctx(scan_id=sid, run_dir=run_dir, target=HostTarget(host, host, []), profile={}, scope_domains=[],
               log=lambda s: None, progress=lambda *a: None, cancel=threading.Event())


def _sev_hint(n: int) -> str:
    return {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}.get(n, "info")


SCANNER_PLUGINS = {"11219", "34277", "10335", "14272", "22964", "25220"}  # port scanners / service detection


def _service_effects(ctx: Ctx, port: int, proto: str, svc: str, title: str, engine: str):
    from .. import config
    pol = config.policy()["services"]
    svc = (svc or "").lower().rstrip("?")
    if svc in {x.lower() for x in pol["remote_access_names"]} or svc in ("rdp", "msrdp"):
        ctx.note("remote_access", f"{svc} on {port}/{proto}", port, engine)
    if svc in {x.lower() for x in pol["insecure_names"]}:
        ctx.note("insecure_service", f"{svc} on {port}/{proto}", port, engine)
    if svc in {x.lower() for x in pol["database_names"]} or port in set(pol["database_ports"]):
        ctx.findings.append(findings.make(engine, "database_exposed", ctx.component, f"Database service reachable: {svc or port}",
                                          port=port, protocol=proto, service=svc, evidence=title, rule_id=f"db-{port}"))


def parse_nessus(path: Path, sid: int, run_dir: Path) -> list[Ctx]:
    root = ET.parse(path).getroot()
    ctxs = []
    for rh in root.iter("ReportHost"):
        props = {t.get("name"): (t.text or "") for t in rh.findall("HostProperties/tag")}
        host = (props.get("host-fqdn") or rh.get("name") or props.get("host-ip") or "").lower()
        ctx = _ctx(sid, host, run_dir)
        ctx.target.ips = [props.get("host-ip", host)]
        ports_seen = set()
        for it in rh.findall("ReportItem"):
            port, proto = int(it.get("port", "0")), it.get("protocol", "tcp")
            sev, pid, name = int(it.get("severity", "0")), it.get("pluginID", ""), it.get("pluginName", "")
            svc, family = it.get("svc_name", ""), it.get("pluginFamily", "")
            g = lambda tag, _it=it: (_it.findtext(tag) or "").strip()  # noqa: E731
            if port and (port, proto) not in ports_seen and (pid in SCANNER_PLUGINS or "service detection" in name.lower()):
                ports_seen.add((port, proto))
                ctx.findings.append(findings.make("nessus", "open_port", host, f"{port}/{proto} {svc}", port=port,
                                                  protocol=proto, service=svc, evidence=name, rule_id=f"port-{proto}-{port}"))
                _service_effects(ctx, port, proto, svc, name, "nessus")
            if sev == 0:
                continue
            cves = [c.text for c in it.findall("cve") if c.text]
            cwes = [c.text for c in it.findall("cwe") if c.text] + re.findall(r"CWE:(\d+)", " ".join(x.text or "" for x in it.findall("xref")))
            score3, vec3 = g("cvss3_base_score"), g("cvss3_vector")
            score2, vec2 = g("cvss_base_score"), g("cvss_vector")
            score = float(score3) if score3 else (float(score2) if score2 else None)
            vector = vec3 or vec2 or None
            default = "other_web" if family in ("CGI abuses", "CGI abuses : XSS", "Web Servers") else "other_network"
            cat = findings.classify(cwe=cwes, title=name, default=default)
            ctx.findings.append(findings.make(
                "nessus", cat, host, name, port=port or None, protocol=proto, service=svc,
                description=g("description") or g("synopsis"), evidence=g("plugin_output")[:1500],
                cvss_score=score, cvss_vector=vector, cvss_source="imported" if score is not None else None,
                severity_hint=_sev_hint(sev), cve=cves, cwe=cwes, references=g("see_also").split(),
                engine_solution=g("solution"), rule_id=f"nessus-{pid}", raw_ref=f"{path.name}#{pid}"))
            if cat == "directory_listing":
                ctx.note("directory_browsing", name, port, "nessus")
            if cat == "anonymous_cipher":
                ctx.note("anonymous_key_agreement", name, port, "nessus")
        ctxs.append(ctx)
    return ctxs


def parse_gvm(path: Path, sid: int, run_dir: Path) -> list[Ctx]:
    root = ET.parse(path).getroot()
    by_host: dict[str, Ctx] = {}
    for r in root.iter("result"):
        host_el = r.find("host")
        if host_el is None:
            continue
        ip = (host_el.text or "").strip()
        hostname = (host_el.findtext("hostname") or "").strip().lower()
        host = hostname or ip
        ctx = by_host.setdefault(host, _ctx(sid, host, run_dir))
        port_s = (r.findtext("port") or "general/tcp").strip()
        pnum, _, proto = port_s.partition("/")
        port = int(pnum) if pnum.isdigit() else None
        nvt = r.find("nvt")
        name = (r.findtext("name") or (nvt.findtext("name") if nvt is not None else "") or "").strip()
        sev = float(r.findtext("severity") or 0)
        threat = (r.findtext("threat") or "").lower()
        if sev <= 0 or threat in ("log", "debug", "false positive"):
            continue
        tags = dict(x.split("=", 1) for x in (nvt.findtext("tags") or "").split("|") if "=" in x) if nvt is not None else {}
        vector = None
        if nvt is not None:
            for s in nvt.findall("severities/severity"):
                if (s.get("type") or "").startswith("cvss_base_v3"):
                    vector = (s.findtext("value") or "").strip() or vector
        vector = vector or tags.get("cvss_base_vector")
        refs = nvt.findall("refs/ref") if nvt is not None else []
        cves = [x.get("id") for x in refs if x.get("type") == "cve"]
        cwes = [x.get("id") for x in refs if x.get("type") == "cwe"]
        urls = [x.get("id") for x in refs if x.get("type") == "url"]
        cat = findings.classify(cwe=cwes, title=name, default="other_network")
        ctx.findings.append(findings.make(
            "openvas", cat, host, name, port=port, protocol=proto or "tcp",
            description=tags.get("summary", "") + ("\n" + tags.get("insight", "") if tags.get("insight") else ""),
            evidence=(r.findtext("description") or "")[:1500], cvss_score=sev, cvss_vector=vector,
            cvss_source="imported", severity_hint=threat or None, cve=cves, cwe=cwes, references=urls,
            engine_solution=(nvt.findtext("solution") if nvt is not None else "") or tags.get("solution", ""),
            rule_id=f"gvm-{nvt.get('oid') if nvt is not None else name}", raw_ref=path.name))
        if cat == "directory_listing":
            ctx.note("directory_browsing", name, port, "openvas")
    return list(by_host.values())


def parse_zap_report(path: Path, sid: int, run_dir: Path) -> list[Ctx]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    out = []
    risk = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High"}
    for site in data.get("site", []):
        host = (site.get("@host") or "").lower()
        ctx = _ctx(sid, host, run_dir)
        alerts = []
        for a in site.get("alerts", []):
            for inst in a.get("instances", []) or [{}]:
                alerts.append({"pluginId": a.get("pluginid"), "alert": a.get("alert") or a.get("name"),
                               "risk": risk.get(str(a.get("riskcode")), "Low"), "cweid": a.get("cweid"),
                               "url": inst.get("uri", ""), "method": inst.get("method", ""),
                               "param": inst.get("param", ""), "attack": inst.get("attack", ""),
                               "evidence": inst.get("evidence", ""), "description": re.sub("<[^>]+>", "", a.get("desc", "")),
                               "solution": re.sub("<[^>]+>", "", a.get("solution", "")),
                               "reference": re.sub("<[^>]+>", "\n", a.get("reference", "")),
                               "confidence": a.get("confidence", ""), "other": a.get("otherinfo", "")})
        zap_e.parse(alerts, ctx, path.name)
        out.append(ctx)
    return out


def parse_single(fmt: str, path: Path, sid: int, run_dir: Path, host_hint: str = "") -> list[Ctx]:
    if fmt == "nmap":
        root = ET.parse(path).getroot()
        h = root.find("host/hostnames/hostname")
        a = root.find("host/address")
        host = (h.get("name") if h is not None else None) or (a.get("addr") if a is not None else host_hint)
        ctx = _ctx(sid, host.lower(), run_dir)
        nmap_e.parse(path, ctx)
        return [ctx]
    if fmt == "testssl":
        data = json.loads(path.read_text())
        ipf = (data[0].get("ip") if data else "") or host_hint
        host = ipf.split("/")[0].lower()
        port = int(data[0].get("port", 443)) if data else 443
        ctx = _ctx(sid, host, run_dir)
        testssl_e.parse(path, ctx, port)
        return [ctx]
    if fmt == "nuclei":
        by: dict[str, Ctx] = {}
        lines = path.read_text().splitlines()
        for line in lines:
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            m = r.get("matched-at") or r.get("host") or ""
            h = (re.sub(r"^\w+://", "", m).split("/")[0].rsplit(":", 1)[0] or host_hint).lower()
            by.setdefault(h, _ctx(sid, h, run_dir))
        for h, ctx in by.items():
            tmp = run_dir / f"_import_{h}.jsonl"
            tmp.write_text("\n".join(ln for ln in lines if h in ln.lower()))
            nuclei_e.parse(tmp, ctx)
        return list(by.values())
    raise ImportErrorX(f"Unsupported format {fmt}")


def import_file(scope_id: int, path: Path, actor: str, fmt: str | None = None, label: str = "") -> int:
    from .. import worker  # local import to avoid a cycle
    fmt = fmt or detect(path)
    if fmt not in FORMATS:
        raise ImportErrorX("Unsupported format")
    sid = db.x("INSERT INTO scans (scope_id,created_at,started_at,profile,report_type,label,components,authorized_by,"
               "authorization,status) VALUES (?,?,?,?,?,?,?,?,?,?)",
               (scope_id, db.now(), db.now(), "import", "imported", label or f"Imported {FORMATS[fmt]}", "[]", actor,
                f"Results imported from {FORMATS[fmt]} by {actor}", "running"))
    rd = worker.run_dir(sid)
    dest = rd / f"import_{path.name}"
    dest.write_bytes(path.read_bytes())
    try:
        if fmt == "nessus":
            ctxs = parse_nessus(dest, sid, rd)
        elif fmt == "gvm":
            ctxs = parse_gvm(dest, sid, rd)
        elif fmt == "zap":
            ctxs = parse_zap_report(dest, sid, rd)
        else:
            ctxs = parse_single(fmt, dest, sid, rd)
    except (ET.ParseError, json.JSONDecodeError, KeyError, ValueError) as e:
        db.update_scan(sid, status="failed", error=f"Could not parse file: {e}", finished_at=db.now())
        raise ImportErrorX(f"Could not parse file: {e}") from e
    comps, all_f, all_n = [], [], []
    for c in ctxs:
        if not c.component:
            continue
        kind = "ip" if re.match(r"^[\d.:]+$", c.component) else "host"
        db.upsert_component(scope_id, kind, c.component, status="in_scope", source="imported")
        comps.append({"value": c.component, "kind": kind, "host": c.component, "label": "", "load_balanced": False,
                      "lb_synchronized": False})
        all_f += c.findings
        all_n += c.notes
    merged = findings.consolidate(all_f)
    db.save_findings(sid, merged)
    db.save_notes(sid, all_n)
    redact.mask_files(rd)
    meta = {"imported_format": fmt, "imported_file": path.name, "versions": {FORMATS[fmt]: "imported"},
            "limitations": ["Results were produced by an external scanner; OpenASV applied its ASV scoring policy, "
                            "special-note rules and PCI DSS mapping to the imported findings."]}
    db.update_scan(sid, components=comps, meta=meta, status="completed", finished_at=db.now())
    res = scoring.evaluate(db.scan(sid))
    db.update_scan(sid, result=res["overall"])
    db.audit(actor, "scan.imported", f"scan:{sid}", f"{fmt} {path.name} -> {res['overall']}")
    return sid


__all__ = ["FORMATS", "detect", "import_file", "ImportErrorX", "targets"]
