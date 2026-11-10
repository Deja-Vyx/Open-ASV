"""Application operations shared by the web UI, REST API, CLI and scheduler."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from . import config, db, scoring, targets, worker

AUTHORIZATION_TEXT = ("I confirm that I own, or have written authorization to test, every component in this scan, "
                      "and I accept that the scan sends attack payloads (e.g. SQL injection and XSS probes) that may "
                      "create data on the targets.")
SCHEDULES = {"none": None, "monthly": 30, "quarterly": 90}


class ServiceError(ValueError):
    pass


# ----------------------------------------------------------------- scopes
def create_scope(name: str, customer: dict, actor: str, components: list[str] | None = None) -> int:
    name = (name or "").strip()
    if not name:
        raise ServiceError("Scope name is required")
    sid = db.x("INSERT INTO scopes (name, customer, created_at) VALUES (?,?,?)",
               (name[:120], json.dumps(_clean_customer(customer)), db.now()))
    for c in components or []:
        add_component(sid, c, actor)
    db.audit(actor, "scope.created", f"scope:{sid}", name)
    return sid


def _clean_customer(c: dict) -> dict:
    keys = ("company", "contact", "title", "phone", "email", "address", "city", "state", "postal", "country", "website")
    return {k: str(c.get(k, "") or "").strip()[:200] for k in keys}


def update_scope(sid: int, actor: str, **f) -> None:
    sc = db.scope(sid)
    if not sc:
        raise ServiceError("Unknown scope")
    if "customer" in f:
        db.x("UPDATE scopes SET customer=? WHERE id=?", (json.dumps(_clean_customer(f["customer"])), sid))
    if "name" in f and f["name"].strip():
        db.x("UPDATE scopes SET name=? WHERE id=?", (f["name"].strip()[:120], sid))
    if "schedule" in f:
        if f["schedule"] not in SCHEDULES:
            raise ServiceError("Invalid schedule")
        prof = f.get("schedule_profile") or sc["schedule_profile"]
        if prof not in config.profiles():
            raise ServiceError("Invalid profile")
        nxt = None
        if SCHEDULES[f["schedule"]]:
            nxt = (datetime.now(timezone.utc) + timedelta(days=SCHEDULES[f["schedule"]])).astimezone().isoformat(timespec="seconds")
            if f.get("next_run"):
                nxt = f["next_run"]
        db.x("UPDATE scopes SET schedule=?, schedule_profile=?, next_run=? WHERE id=?", (f["schedule"], prof, nxt, sid))
    if "notes" in f:
        db.x("UPDATE scopes SET notes=? WHERE id=?", (f["notes"][:4000], sid))
    db.audit(actor, "scope.updated", f"scope:{sid}", ", ".join(f))


def add_component(scope_id: int, raw: str, actor: str, label: str = "") -> dict:
    c = targets.parse(raw)
    db.upsert_component(scope_id, c.kind, c.value, status="in_scope", source="declared", label=label)
    db.audit(actor, "component.added", f"scope:{scope_id}", c.value)
    return {"kind": c.kind, "value": c.value}


def set_component(scope_id: int, comp_id: int, actor: str, *, status: str | None = None, reason: str = "",
                  load_balanced: bool | None = None, lb_synchronized: bool | None = None) -> None:
    c = db.one("SELECT * FROM components WHERE id=? AND scope_id=?", (comp_id, scope_id))
    if not c:
        raise ServiceError("Unknown component")
    if status:
        if status not in ("in_scope", "out_of_scope", "removed"):
            raise ServiceError("Invalid status")
        if status == "out_of_scope" and len(reason.strip()) < 10:
            raise ServiceError("Explain why the component is out of scope (segmented from the CDE)")
        db.x("UPDATE components SET status=?, reason=?, updated_at=? WHERE id=?",
             (status, reason.strip()[:500] or c["reason"], db.now(), comp_id))
        _refresh_discovered(scope_id, c["value"], status)
    if load_balanced is not None:
        db.x("UPDATE components SET load_balanced=?, lb_synchronized=?, updated_at=? WHERE id=?",
             (int(load_balanced), int(bool(lb_synchronized) and load_balanced), db.now(), comp_id))
    db.audit(actor, "component.updated", f"scope:{scope_id}", f"{c['value']} -> {status or 'lb'} {reason}")


def _refresh_discovered(scope_id: int, value: str, status: str) -> None:
    """Classifying a discovered component updates the open scans of that scope."""
    for s in db.q("SELECT id FROM scans WHERE scope_id=? AND status='completed' AND finalized_at IS NULL", (scope_id,)):
        scan = db.scan(s["id"])
        meta = scan["meta"]
        changed = False
        for d in meta.get("discovered", []):
            if d["value"] == value:
                d["status"] = status
                changed = True
        if status == "out_of_scope" and value not in meta.get("out_of_scope", []):
            meta.setdefault("out_of_scope", []).append(value)
            changed = True
        if changed:
            db.update_scan(s["id"], meta=meta)
            refresh_result(s["id"])


# ----------------------------------------------------------------- scans
def launch_scan(scope_id: int, profile: str, actor: str, *, authorized: bool, label: str = "",
                only: list[str] | None = None, report_type: str = "full", parent: int | None = None) -> int:
    if not authorized:
        raise ServiceError("You must confirm that you are authorized to scan these components")
    if profile not in config.profiles():
        raise ServiceError("Unknown profile")
    if not db.scope(scope_id):
        raise ServiceError("Unknown scope")
    comps = db.components(scope_id, "in_scope")
    if only is not None:
        comps = [c for c in comps if targets.parse(c["value"]).host in only or c["value"] in only]
    if not comps:
        raise ServiceError("The scope has no in-scope components")
    snapshot = []
    for c in comps:
        p = targets.parse(c["value"])
        try:
            targets.authorize(p)
        except targets.TargetError as e:
            raise ServiceError(str(e)) from e
        snapshot.append({"value": c["value"], "kind": c["kind"], "host": p.host, "label": c["label"],
                         "load_balanced": bool(c["load_balanced"]), "lb_synchronized": bool(c["lb_synchronized"])})
    sid = db.x("INSERT INTO scans (scope_id,created_at,profile,report_type,parent_scan_id,label,components,"
               "authorized_by,authorization) VALUES (?,?,?,?,?,?,?,?,?)",
               (scope_id, db.now(), profile, report_type, parent, label[:80], json.dumps(snapshot), actor,
                f"{AUTHORIZATION_TEXT} — confirmed by {actor} at {db.now()}"))
    db.audit(actor, "scan.launched", f"scan:{sid}", f"scope {scope_id}, profile {profile}, {len(snapshot)} component(s)")
    worker.enqueue(sid)
    return sid


def rescan_failed(scan_id: int, actor: str, authorized: bool) -> int:
    s = db.scan(scan_id)
    res = scoring.evaluate(s)
    failing = {c["component"] for c in res["components"] if c["status"] == "FAIL"}
    if not failing:
        raise ServiceError("No failing components to rescan")
    scanned = {c["host"] for c in s["components"]}
    hosts = sorted(failing & scanned)
    if failing - scanned and not hosts:
        # findings on name servers (zone transfer) are re-tested by the DNS stage of any scan of the scope domains
        hosts = sorted(scanned)[:1]
    return launch_scan(s["scope_id"], s["profile"], actor, authorized=authorized, label=f"Rescan of #{scan_id}",
                       only=hosts, report_type="rescan", parent=scan_id)


def refresh_result(scan_id: int) -> str:
    s = db.scan(scan_id)
    if s["status"] != "completed":
        return s.get("result") or ""
    res = scoring.evaluate(s)
    db.update_scan(scan_id, result=res["overall"])
    return res["overall"]


def _editable(scan_id: int) -> dict:
    s = db.scan(scan_id)
    if not s:
        raise ServiceError("Unknown scan")
    if s["status"] != "completed":
        raise ServiceError("The scan is not completed")
    if s["finalized_at"]:
        raise ServiceError("The report is final and can no longer be changed")
    return s


# ----------------------------------------------------------------- declarations (special notes)
def declare(scan_id: int, nkey: str, option: str, statement: str, actor: str) -> None:
    _editable(scan_id)
    note = next((n for n in scoring.evaluate(db.scan(scan_id))["notes"] if n["key"] == nkey), None)
    if not note:
        raise ServiceError("Unknown special note")
    opts = config.policy()["special_notes"][note["type"]]["options"]
    if option not in opts:
        raise ServiceError("Invalid declaration option")
    if len(statement.strip()) < 15:
        raise ServiceError("Describe the business justification or the action taken (at least 15 characters)")
    db.x("INSERT OR REPLACE INTO declarations VALUES (?,?,?,?,?,?)",
         (scan_id, nkey, option, statement.strip()[:2000], actor, db.now()))
    db.audit(actor, "note.declared", f"scan:{scan_id}", f"{note['type']}: {option}")
    refresh_result(scan_id)


# ----------------------------------------------------------------- disputes
def submit_dispute(scan_id: int, fkey: str, kind: str, justification: str, actor: str, *, attested: bool,
                   evidence: list[dict] | None = None, proposed_score: float | None = None) -> int:
    _editable(scan_id)
    if kind not in scoring.DISPUTE_KINDS:
        raise ServiceError("Invalid dispute type")
    if not attested:
        raise ServiceError("The scan customer must attest that the evidence is accurate and complete")
    if len(justification.strip()) < 30:
        raise ServiceError("Provide a justification of at least 30 characters describing the evidence")
    if fkey != scoring.SCAN_DISPUTE_KEY and fkey not in {f["key"] for f in db.findings(scan_id)}:
        raise ServiceError("Unknown finding")
    if kind == "inconclusive" and fkey != scoring.SCAN_DISPUTE_KEY:
        raise ServiceError("Inconclusive-scan disputes apply to the whole scan")
    if kind == "cvss":
        if proposed_score is None or not 0 <= proposed_score <= 10:
            raise ServiceError("Provide the proposed CVSS base score (0.0–10.0)")
    did = db.x("INSERT OR REPLACE INTO disputes (scan_id,fkey,kind,justification,evidence,proposed_score,submitted_by,"
               "submitted_at,status) VALUES (?,?,?,?,?,?,?,?, 'pending')",
               (scan_id, fkey, kind, justification.strip()[:4000], json.dumps(evidence or []), proposed_score,
                actor, db.now()))
    db.audit(actor, "dispute.submitted", f"scan:{scan_id}", f"{fkey} {kind}")
    return did


def review_dispute(dispute_id: int, decision: str, reviewer: str, notes: str) -> None:
    d = db.one("SELECT * FROM disputes WHERE id=?", (dispute_id,))
    if not d:
        raise ServiceError("Unknown dispute")
    _editable(d["scan_id"])
    if decision not in ("accepted", "rejected"):
        raise ServiceError("Invalid decision")
    if not reviewer.strip() or len(notes.strip()) < 10:
        raise ServiceError("Record the reviewer name and the conclusion (at least 10 characters)")
    if reviewer.strip() == d["submitted_by"] and decision == "accepted":
        # separation of duties is recommended; allowed, but recorded explicitly
        notes = notes.strip() + " [reviewed by the submitter]"
    db.x("UPDATE disputes SET status=?, reviewer=?, review_notes=?, reviewed_at=? WHERE id=?",
         (decision, reviewer.strip()[:120], notes.strip()[:2000], db.now(), dispute_id))
    db.audit(reviewer, f"dispute.{decision}", f"scan:{d['scan_id']}", d["fkey"])
    refresh_result(d["scan_id"])


def withdraw_dispute(dispute_id: int, actor: str) -> None:
    d = db.one("SELECT * FROM disputes WHERE id=?", (dispute_id,))
    if not d:
        raise ServiceError("Unknown dispute")
    _editable(d["scan_id"])
    db.x("DELETE FROM disputes WHERE id=?", (dispute_id,))
    db.audit(actor, "dispute.withdrawn", f"scan:{d['scan_id']}", d["fkey"])
    refresh_result(d["scan_id"])


def carry_forward(scan_id: int, from_scan: int, actor: str) -> int:
    """Re-submit disputes from a previous scan. They return to 'pending': ASV disputes must be re-verified each period."""
    _editable(scan_id)
    keys = {f["key"] for f in db.findings(scan_id)}
    n = 0
    for d in db.disputes(from_scan).values():
        if d["fkey"] in keys and d["status"] == "accepted" and d["fkey"] not in db.disputes(scan_id):
            db.x("INSERT INTO disputes (scan_id,fkey,kind,justification,evidence,proposed_score,submitted_by,"
                 "submitted_at,status,carried_from) VALUES (?,?,?,?,?,?,?,?,'pending',?)",
                 (scan_id, d["fkey"], d["kind"], d["justification"], json.dumps(d["evidence"]), d["proposed_score"],
                  actor, db.now(), from_scan))
            n += 1
    db.audit(actor, "dispute.carried", f"scan:{scan_id}", f"{n} from scan {from_scan}")
    return n


# ----------------------------------------------------------------- finalisation
def finalize(scan_id: int, actor: str, attestation: dict) -> None:
    s = _editable(scan_id)
    res = scoring.evaluate(s)
    if res["pending_disputes"]:
        raise ServiceError("Review all pending disputes before finalising")
    for k in ("name", "title", "date"):
        if not str(attestation.get(k, "")).strip():
            raise ServiceError("Customer attestation requires name, title and date")
    if not attestation.get("scope_complete") or not attestation.get("evidence_accurate"):
        raise ServiceError("Both customer attestation statements must be confirmed")
    if not str(attestation.get("reviewer", "")).strip():
        raise ServiceError("Record the name of the scan reviewer")
    db.update_scan(scan_id, finalized_at=db.now(), finalized_by=actor, attestation=attestation, result=res["overall"])
    db.audit(actor, "report.finalized", f"scan:{scan_id}", res["overall"])


# ----------------------------------------------------------------- scheduler
def due_scopes() -> list[dict]:
    now = db.now()
    return db.q("SELECT * FROM scopes WHERE archived=0 AND schedule!='none' AND next_run IS NOT NULL AND next_run<=?",
                (now,))


def run_scheduled() -> list[int]:
    out = []
    for sc in due_scopes():
        try:
            sid = launch_scan(sc["id"], sc["schedule_profile"], "scheduler", authorized=True,
                              label=f"Scheduled ({sc['schedule']})")
            out.append(sid)
        except ServiceError as e:
            db.audit("scheduler", "scan.skipped", f"scope:{sc['id']}", str(e))
        days = SCHEDULES.get(sc["schedule"]) or 90
        nxt = (datetime.now(timezone.utc) + timedelta(days=days)).astimezone().isoformat(timespec="seconds")
        db.x("UPDATE scopes SET next_run=? WHERE id=?", (nxt, sc["id"]))
    return out
