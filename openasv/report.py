"""Report assembly (ASV report layout) and exports: HTML, PDF, JSON, CSV, Markdown."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from . import DISCLAIMER, __version__, compliance, config, db, scoring

COVERAGE = [
    ("Service discovery", "Nmap", "All TCP ports (ASV profile), common UDP ports in privileged mode, service and version detection, OS fingerprinting."),
    ("SSL/TLS", "testssl.sh", "Protocol versions, cipher suites, forward secrecy, certificate trust, expiry and hostname match, TLS vulnerabilities."),
    ("Web applications", "OWASP ZAP", "Crawling, passive analysis, active testing for SQL injection, XSS, directory traversal, header injection and more."),
    ("Known vulnerabilities", "Nuclei", "Template-based detection of CVEs, misconfigurations, exposures, default logins and backdoors."),
    ("Unsupported software", "endoflife.date", "End-of-life status of detected products and operating systems."),
    ("Version-based CVEs", "NVD API 2.0", "CVE correlation for detected product versions (potential vulnerabilities)."),
    ("DNS", "dnspython", "Zone-transfer testing; MX, NS and common-hostname discovery for scope review."),
    ("HTTP", "OpenASV", "Redirects, cleartext credential forms, embedded content from out-of-scope domains, version banners."),
    ("SSH", "ssh-audit", "Protocol version, key exchange, host keys, ciphers and MACs offered by SSH services."),
    ("Web application firewall", "wafw00f", "Fingerprinting of a web application firewall in front of each web application."),
    ("Scripts and headers", "OpenASV", "Inventory of page scripts, Subresource Integrity and security headers; differences from the previous scan."),
    ("Email anti-spoofing", "dnspython", "SPF and DMARC policy of in-scope domains that receive mail."),
    ("Change detection", "OpenASV", "Services, scripts and headers that changed since the previous scan of the scope."),
]


def _dt(s):
    try:
        return datetime.fromisoformat(s) if s else None
    except ValueError:
        return None


def pci_titles() -> dict:
    return {k: (v or {}).get("title", "") for k, v in (config.pci().get("requirements") or {}).items()}


def build(scan_id: int) -> dict | None:
    s = db.scan(scan_id)
    if not s:
        return None
    scope = db.scope(s["scope_id"])
    ev = scoring.evaluate(s)
    titles = pci_titles()
    reqs: dict[str, dict] = {}
    for f in ev["scored"] + ev["evidence"] + ev["services"]:
        for p in f["pci"]:
            r = reqs.setdefault(p["req"], {"req": p["req"], "title": titles.get(p["req"], ""), "fail": 0, "pass": 0,
                                           "info": 0, "direct": False, "categories": set()})
            r["fail" if f["status"] == "Fail" else ("info" if f["status"] == "Info" else "pass")] += 1
            r["direct"] = r["direct"] or p.get("rel") == "direct"
            r["categories"].add(f["category_title"])
    for r in reqs.values():
        r["categories"] = sorted(r["categories"])
    req_rows = sorted(reqs.values(), key=lambda r: [int(x) for x in r["req"].split(".")])
    sc = config.settings
    scanner = {"company": sc.scanner_company or (scope["customer"].get("company") if scope else "") or "—",
               "contact": sc.scanner_contact, "email": sc.scanner_email, "website": sc.scanner_website}
    comp_count = len(ev["components"])
    return {
        "scan": s, "scope": scope, "ev": ev, "meta": s["meta"], "requirements": req_rows, "pci_titles": titles,
        "completed": _dt(s["finished_at"]), "expiry": ev["expiry"], "scanner": scanner,
        "coverage": COVERAGE, "disclaimer": DISCLAIMER, "version": __version__, "policy_hash": config.policy_hash(),
        "profile": config.profiles().get(s["profile"], {"label": "Imported results", "summary": ""}),
        "report_type": {"full": "Full scan", "rescan": "Partial scan or rescan", "imported": "Imported results"}.get(
            s["report_type"], s["report_type"]),
        "special_note_defs": config.policy()["special_notes"], "dispute_kinds": scoring.DISPUTE_KINDS,
        "component_count": comp_count, "standard": config.pci().get("standard", "PCI DSS v4.0.1"),
        "generated": datetime.now().astimezone(),
    }


def build_combined(scan_ids: list[int]) -> dict:
    c = compliance.combine(scan_ids)
    scope = db.scope(c["scans"][0]["scope_id"])
    return {"c": c, "scope": scope, "disclaimer": DISCLAIMER, "version": __version__,
            "generated": datetime.now().astimezone(), "scanner": build(c["scans"][-1]["id"])["scanner"]}


# ----------------------------------------------------------------- machine-readable exports
def _finding_row(f: dict) -> dict:
    d = f.get("dispute") or {}
    return {
        "key": f["key"], "component": f["component"], "port": f["port"], "protocol": f["protocol"],
        "title": f["title"], "category": f["category"], "engine": f["engine"], "severity": f["severity"],
        "cvss": f["cvss_score"], "cvss_vector": f["cvss_vector"], "cvss_source": f["cvss_source"],
        "status": f["status"], "status_reason": f["status_reason"], "automatic_failure": f["auto_fail"],
        "potential": f["potential"], "cve": f["cve"], "cwe": f["cwe"], "url": f["url"], "param": f["param"],
        "instances": len(f["instances"]) or 1, "evidence": f["evidence"], "remediation": f["remediation"],
        "pci_dss": [p["req"] for p in f["pci"]], "exception": f["exception_label"],
        "dispute_status": d.get("status"), "dispute_type": d.get("kind"),
    }


def to_json(r: dict) -> str:
    s, ev = r["scan"], r["ev"]
    out = {
        "tool": {"name": "OpenASV", "version": r["version"], "policy": r["policy_hash"]},
        "disclaimer": r["disclaimer"],
        "scan": {"id": s["id"], "scope": r["scope"]["name"] if r["scope"] else None, "profile": s["profile"],
                 "report_type": r["report_type"], "started": s["started_at"], "completed": s["finished_at"],
                 "expires": ev["expiry"].isoformat() if ev["expiry"] else None, "final": bool(s["finalized_at"])},
        "result": {"status": ev["overall"], "reasons": ev["reasons"], "counts": ev["counts"],
                   "inconclusive": ev["inconclusive"]},
        "components": ev["components"],
        "special_notes": [{k: n.get(k) for k in ("type", "title", "component", "port", "detail")} |
                          {"declared": bool(n.get("declaration"))} for n in ev["notes"]],
        "discovered_components": ev["discovered"],
        "findings": [_finding_row(f) for f in ev["findings"]],
        "pci_dss": [{k: v for k, v in q.items()} for q in r["requirements"]],
    }
    return json.dumps(out, ensure_ascii=False, indent=2, default=str)


def to_csv(r: dict) -> str:
    buf = io.StringIO()
    cols = ["component", "port", "protocol", "title", "category", "severity", "cvss", "status", "automatic_failure",
            "exception", "dispute_status", "cve", "cwe", "pci_dss", "url", "param", "engine", "evidence", "remediation"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for f in r["ev"]["findings"]:
        row = _finding_row(f)
        for k in ("cve", "cwe", "pci_dss"):
            row[k] = " ".join(row[k])
        w.writerow(row)
    return buf.getvalue()


def to_markdown(r: dict) -> str:
    s, ev = r["scan"], r["ev"]
    icon = "✅" if ev["overall"] == "PASS" else "❌"
    lines = [f"## {icon} OpenASV scan #{s['id']} — {ev['overall']}", "",
             f"**Scope:** {r['scope']['name'] if r['scope'] else '-'} · **Profile:** {r['profile']['label']} · "
             f"**Completed:** {s['finished_at']}", ""]
    for reason in ev["reasons"]:
        lines.append(f"- {reason}")
    lines += ["", "| Component | High | Medium | Low | Status |", "|---|---:|---:|---:|---|"]
    for c in ev["components"]:
        lines.append(f"| `{c['component']}` | {c['high']} | {c['medium']} | {c['low']} | {c['status']} |")
    if ev["failing"]:
        lines += ["", "### Failing vulnerabilities", "", "| Severity | CVSS | Component | Finding | PCI DSS |",
                  "|---|---:|---|---|---|"]
        for f in sorted(ev["failing"], key=lambda x: (-x["cvss_score"], x["component"]))[:50]:
            af = " (automatic failure)" if f["auto_fail"] else ""
            lines.append(f"| {f['severity']} | {f['cvss_score']:.1f} | `{f['component']}:{f['port'] or '-'}` | "
                         f"{f['title']}{af} | {', '.join(p['req'] for p in f['pci'])} |")
    lines += ["", f"<sub>{r['disclaimer']}</sub>", ""]
    return "\n".join(lines)
