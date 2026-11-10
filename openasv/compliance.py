"""Scan cadence (PCI DSS 11.3.2: at least once every three months) and combined (multi-scan) results."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from . import db, scoring, targets

CADENCE_DAYS = 90
DUE_SOON_DAYS = 14


def _dt(s):
    try:
        return datetime.fromisoformat(s) if s else None
    except ValueError:
        return None


def effective_result(scan: dict) -> str:
    """A rescan covers only the components that failed, so on its own it passes the scope only when combined with the
    scan it re-tests (ASV Program Guide, combining scan reports)."""
    res = scan["result"]
    if res != "PASS" or scan["report_type"] != "rescan" or not scan.get("parent_scan_id"):
        return res
    try:
        return combine([scan["parent_scan_id"], scan["id"]])["overall"]
    except ValueError:
        return "FAIL"


def scope_status(scope_id: int) -> dict:
    scans = db.q("SELECT * FROM scans WHERE scope_id=? AND status='completed' ORDER BY finished_at DESC", (scope_id,))
    passes, latest = [], None
    for s in scans:
        full = db.scan(s["id"])
        res = effective_result(full)
        if latest is None:
            latest = full
        if res == "PASS":
            passes.append(full)
    now = datetime.now(timezone.utc).astimezone()
    last_pass = _dt(passes[0]["finished_at"]) if passes else None
    due = last_pass + timedelta(days=CADENCE_DAYS) if last_pass else None
    if not last_pass:
        state, label = "never", "No passing scan"
    elif due < now:
        state, label = "overdue", f"Overdue since {due:%d %b %Y}"
    elif due - now <= timedelta(days=DUE_SOON_DAYS):
        state, label = "due", f"Due {due:%d %b %Y}"
    else:
        state, label = "current", f"Current until {due:%d %b %Y}"

    # last four three-month windows, newest first
    windows = []
    for i in range(4):
        end = now - timedelta(days=CADENCE_DAYS * i)
        start = end - timedelta(days=CADENCE_DAYS)
        hit = next((p for p in passes if start < _dt(p["finished_at"]) <= end), None)
        windows.append({"start": start, "end": end, "pass_scan": hit["id"] if hit else None})
    return {"state": state, "label": label, "last_pass": last_pass, "due": due, "latest": latest,
            "passes": len([w for w in windows if w["pass_scan"]]), "windows": list(reversed(windows))}


def combine(scan_ids: list[int]) -> dict:
    """Aggregate several scans of one scope into a single result (ASV Program Guide: combining failing scans).

    Each component takes the result of the most recent scan that covered it. Failures from earlier scans that are
    absent from the later scan of the same component are reported as remediated and validated by rescan."""
    scans = [db.scan(i) for i in scan_ids]
    if any(s is None for s in scans):
        raise ValueError("Unknown scan id")
    if len({s["scope_id"] for s in scans}) != 1:
        raise ValueError("All scans must belong to the same scope")
    if any(s["status"] != "completed" for s in scans):
        raise ValueError("All scans must be completed")
    scans.sort(key=lambda s: (s["finished_at"], s["id"]))
    rank = {s["id"]: i for i, s in enumerate(scans)}
    first, last = _dt(scans[0]["finished_at"]), _dt(scans[-1]["finished_at"])
    if (last - first).days > CADENCE_DAYS:
        raise ValueError("Scans to combine must complete within 90 days of each other")

    evals = {s["id"]: scoring.evaluate(s) for s in scans}
    latest_for: dict[str, int] = {}
    for s in scans:
        # name servers tested for zone transfer count as covered by the scan that tested them
        hosts = ({c["host"] for c in s["components"]} | set(s["meta"].get("expanded_hosts", []))
                 | set(s["meta"].get("dns_checked", [])) | {c["component"] for c in evals[s["id"]]["components"]})
        for h in hosts:
            latest_for[h] = s["id"]
    out_of_scope = {targets.parse(c["value"]).host for c in db.components(scans[0]["scope_id"], "out_of_scope")}
    components, remediated, failing, pending_notes = [], [], [], []
    for host, sid in sorted(latest_for.items()):
        if host in out_of_scope:
            continue
        ev = evals[sid]
        comp = next((c for c in ev["components"] if c["component"] == host), None)
        status = comp["status"] if comp else "PASS"
        components.append({"component": host, "status": status, "scan_id": sid})
        failing += [f | {"scan_id": sid} for f in ev["failing"] if f["component"] == host]
        pending_notes += [n | {"scan_id": sid} for n in ev["pending_notes"] if n["component"] == host]
        later_keys = {f["key"] for f in ev["findings"] if f["component"] == host}
        for s in scans:
            if s["id"] == sid:
                continue
            for f in evals[s["id"]]["failing"]:
                if f["component"] == host and f["key"] not in later_keys and rank[s["id"]] < rank[sid]:
                    remediated.append(f | {"scan_id": s["id"], "validated_by": sid})
    inconclusive = [r for s in scans if latest_for and s["id"] in set(latest_for.values())
                    for r in (evals[s["id"]]["inconclusive"] if not evals[s["id"]]["inconclusive_resolved"] else [])]
    discovered = [d for s in scans[-1:] for d in evals[s["id"]]["discovered"]]
    reasons = []
    if failing:
        reasons.append(f"{len(failing)} failing vulnerabilities remain in the most recent scan of their component")
    if pending_notes:
        reasons.append(f"{len(pending_notes)} special note(s) awaiting declaration")
    if inconclusive:
        reasons.append("A contributing scan is inconclusive")
    if discovered:
        reasons.append(f"{len(discovered)} discovered component(s) unresolved")
    remediated.sort(key=lambda f: (-(f.get("cvss_score") or 0), f["component"], f.get("port") or 0, f["title"]))
    return {"scans": scans, "evals": evals, "components": components, "remediated": remediated,
            "failing": failing, "pending_notes": pending_notes, "overall": "FAIL" if reasons else "PASS",
            "reasons": reasons, "first": first, "last": last,
            "expiry": first + timedelta(days=scoring.SCAN_VALIDITY_DAYS)}
