"""ASV-style compliance determination for one scan."""
from __future__ import annotations

from datetime import datetime, timedelta

from . import config, cvss, db

DISPUTE_KINDS = {
    "false_positive": "False positive",
    "compensating_control": "Compensating control",
    "exception": "Exception",
    "cvss": "Disputed CVSS score",
    "inconclusive": "Inconclusive scan",
}
SCAN_VALIDITY_DAYS = 90
SCAN_DISPUTE_KEY = "__scan__"


def _expiry(scan: dict) -> datetime | None:
    try:
        return datetime.fromisoformat(scan["finished_at"]) + timedelta(days=SCAN_VALIDITY_DAYS)
    except (TypeError, ValueError):
        return None


def evaluate(scan: dict, fs: list[dict] | None = None, notes: list[dict] | None = None,
             declarations: dict | None = None, disputes: dict | None = None) -> dict:
    sid = scan["id"]
    fs = db.findings(sid) if fs is None else fs
    notes = db.notes(sid) if notes is None else notes
    declarations = db.declarations(sid) if declarations is None else declarations
    disputes = db.disputes(sid) if disputes is None else disputes
    meta = scan.get("meta") or {}
    in_scope = {c["host"] for c in scan.get("components", []) if c.get("host")}
    in_scope |= set(meta.get("expanded_hosts", []))
    out_of_scope_now = set(meta.get("out_of_scope", []))

    # ---- load balancer special notes are derived from the declared scope
    notes = list(notes)
    for c in scan.get("components", []):
        if c.get("load_balanced") and not c.get("lb_synchronized"):
            key = f"lb-{c['host']}"
            if not any(n["key"] == key for n in notes):
                notes.append({"key": key, "type": "load_balancer", "component": c["host"], "port": None,
                              "detail": "Component declared as load balanced without synchronisation assurance",
                              "source": "scope"})

    evaluated, excluded = [], []
    for f in fs:
        f = dict(f)
        if f["component"] not in in_scope and f["component"] in out_of_scope_now:
            excluded.append(f)
            continue
        d = disputes.get(f["key"])
        score = f["cvss_score"]
        if d and d["status"] == "accepted" and d["kind"] == "cvss" and d.get("proposed_score") is not None:
            f["original_cvss"] = score
            score = float(d["proposed_score"])
            f["cvss_score"], f["severity"] = score, cvss.asv_severity(score)
        if f["informational"]:
            status = "Info"
            why = ("Informational — service inventory" if f["category"] == "open_port"
                   else "Informational — supporting evidence, not scored")
        elif f["dos_exempt"]:
            status, why = "Pass", "Purely denial-of-service vulnerabilities are not ranked as failures"
        elif f["auto_fail"]:
            status, why = "Fail", "Automatic failure (ASV Program Guide)"
        elif score >= 4.0:
            status, why = "Fail", f"CVSS {score:.1f} ≥ 4.0"
        else:
            status, why = "Pass", f"CVSS {score:.1f} < 4.0"
        f["raw_status"] = status
        f["dispute"] = d
        f["exception_label"] = ""
        if d and d["status"] == "accepted" and status == "Fail" and d["kind"] in ("false_positive", "compensating_control", "exception"):
            status = "Pass"
            f["exception_label"] = DISPUTE_KINDS[d["kind"]]
            why = f"{DISPUTE_KINDS[d['kind']]} accepted by {d.get('reviewer') or 'reviewer'}"
        elif d and d["status"] == "accepted" and d["kind"] == "cvss":
            f["exception_label"] = f"CVSS adjusted from {f.get('original_cvss')}"
        f["status"], f["status_reason"] = status, why
        evaluated.append(f)

    # ---- components
    comps: dict[str, dict] = {}
    for h in sorted(in_scope):
        comps[h] = {"component": h, "high": 0, "medium": 0, "low": 0, "fail": 0, "exceptions": 0, "notes": 0,
                    "services": 0, "status": "PASS", "solutions": set()}
    for f in evaluated:
        c = comps.setdefault(f["component"], {"component": f["component"], "high": 0, "medium": 0, "low": 0,
                                              "fail": 0, "exceptions": 0, "notes": 0, "services": 0,
                                              "status": "PASS", "solutions": set()})
        if f["status"] == "Info":
            c["services"] += f["category"] == "open_port"
            continue
        c[f["severity"].lower()] += 1
        if f["status"] == "Fail":
            c["fail"] += 1
            c["status"] = "FAIL"
            c["solutions"].add(_solution(f))
        if f["exception_label"]:
            c["exceptions"] += 1

    # ---- special notes and declarations
    pending_notes = []
    for n in notes:
        n["declaration"] = declarations.get(n["key"])
        n["title"] = config.policy()["special_notes"].get(n["type"], {}).get("title", n["type"])
        if n["component"] in comps:
            comps[n["component"]]["notes"] += 1
        if not n["declaration"]:
            pending_notes.append(n)

    # ---- scope review
    discovered = [d for d in meta.get("discovered", []) if d.get("status", "discovered") == "discovered"]

    # ---- inconclusive
    inconclusive = list(meta.get("inconclusive", []))
    scan_dispute = disputes.get(SCAN_DISPUTE_KEY)
    inconclusive_resolved = bool(scan_dispute and scan_dispute["status"] == "accepted")

    reasons = []
    failing = [f for f in evaluated if f["status"] == "Fail"]
    if failing:
        reasons.append(f"{len(failing)} failing vulnerabilit{'y' if len(failing) == 1 else 'ies'} on "
                       f"{sum(1 for c in comps.values() if c['status'] == 'FAIL')} component(s)")
    if inconclusive and not inconclusive_resolved:
        reasons.append("Scan is inconclusive: " + "; ".join(inconclusive))
    if pending_notes:
        reasons.append(f"{len(pending_notes)} special note(s) awaiting scan customer declaration")
    if discovered:
        reasons.append(f"{len(discovered)} discovered component(s) must be scanned or declared out of scope")
    overall = "FAIL" if reasons else "PASS"

    expiry = _expiry(scan)
    order = {"Fail": 0, "Pass": 1, "Info": 2}
    sev_order = {"High": 0, "Medium": 1, "Low": 2}
    evaluated.sort(key=lambda f: (order[f["status"]], sev_order.get(f["severity"], 3), -f["cvss_score"],
                                  f["component"], f["port"] or 0, f["title"]))
    for c in comps.values():
        c["solutions"] = sorted({x.rstrip(". ") for x in c["solutions"] if x})
    pending_disputes = [d for d in disputes.values() if d["status"] == "pending"]
    checklist = [
        ("No unresolved failing vulnerabilities", not failing),
        ("Special notes declared by the scan customer", not pending_notes),
        ("Discovered components scanned or declared out of scope", not discovered),
        ("Scan not inconclusive (or inconclusive dispute accepted)", not inconclusive or inconclusive_resolved),
        ("All disputes reviewed", not pending_disputes),
        ("Scan results less than 90 days old", bool(expiry and expiry > datetime.now(expiry.tzinfo))),
    ]
    return {
        "overall": overall, "reasons": reasons, "findings": evaluated, "excluded": excluded,
        "scored": [f for f in evaluated if f["status"] != "Info"],
        "services": [f for f in evaluated if f["status"] == "Info" and f["category"] == "open_port"],
        "evidence": [f for f in evaluated if f["status"] == "Info" and f["category"] != "open_port"],
        "failing": failing, "components": sorted(comps.values(), key=lambda c: (c["status"] != "FAIL", c["component"])),
        "notes": notes, "pending_notes": pending_notes, "discovered": discovered,
        "inconclusive": inconclusive, "inconclusive_resolved": inconclusive_resolved,
        "pending_disputes": pending_disputes, "checklist": checklist, "expiry": expiry,
        "counts": {
            "fail": len(failing), "high": sum(f["severity"] == "High" for f in evaluated if f["status"] != "Info"),
            "medium": sum(f["severity"] == "Medium" for f in evaluated if f["status"] != "Info"),
            "low": sum(f["severity"] == "Low" for f in evaluated if f["status"] != "Info"),
            "auto_fail": sum(1 for f in failing if f["auto_fail"]),
            "exceptions": sum(1 for f in evaluated if f["exception_label"]),
            "services": sum(1 for f in evaluated if f["status"] == "Info" and f["category"] == "open_port"),
            "components": len(comps), "notes": len(notes),
            "out_of_scope": len(out_of_scope_now),
        },
    }


def _solution(f: dict) -> str:
    cat = f["category"]
    if cat in ("known_cve", "vulnerable_component", "tls_vulnerability", "unsupported_software"):
        return "Apply vendor security updates / upgrade unsupported software"
    if cat in ("ssl_early_tls", "deprecated_tls", "weak_cipher", "anonymous_cipher", "cert_untrusted", "cert_expired"):
        return "Harden TLS configuration and certificates"
    if cat in ("sql_injection", "xss", "path_traversal", "header_injection", "csrf"):
        return "Fix input handling in the web application"
    if cat == "database_exposed":
        return "Remove Internet exposure of database services"
    if cat == "default_account":
        return "Change or disable default accounts"
    return config.category(cat).get("remediation", "Remediate per finding details")
