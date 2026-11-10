"""SQLite persistence."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from .config import settings

_LOCK = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS scopes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  customer TEXT NOT NULL DEFAULT '{}',          -- A.1 scan customer information (JSON)
  schedule TEXT NOT NULL DEFAULT 'none',        -- none | monthly | quarterly
  schedule_profile TEXT NOT NULL DEFAULT 'asv',
  next_run TEXT,
  notes TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  archived INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS components (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope_id INTEGER NOT NULL REFERENCES scopes(id),
  kind TEXT NOT NULL, value TEXT NOT NULL, label TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'in_scope',      -- in_scope | out_of_scope | discovered | removed
  source TEXT NOT NULL DEFAULT 'declared',      -- declared | discovered | imported
  discovered_by TEXT DEFAULT '', reason TEXT DEFAULT '',
  load_balanced INTEGER NOT NULL DEFAULT 0, lb_synchronized INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (scope_id, value)
);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope_id INTEGER NOT NULL REFERENCES scopes(id),
  created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  status TEXT NOT NULL DEFAULT 'queued',        -- queued | running | completed | failed | cancelled
  profile TEXT NOT NULL, report_type TEXT NOT NULL DEFAULT 'full',   -- full | rescan | imported
  parent_scan_id INTEGER, label TEXT DEFAULT '',
  components TEXT NOT NULL DEFAULT '[]',        -- snapshot of in-scope components at launch
  authorized_by TEXT NOT NULL, authorization TEXT NOT NULL,
  result TEXT, inconclusive INTEGER NOT NULL DEFAULT 0, error TEXT,
  finalized_at TEXT, finalized_by TEXT, attestation TEXT,
  meta TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS stages (
  scan_id INTEGER NOT NULL, ord INTEGER NOT NULL, name TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending', progress INTEGER NOT NULL DEFAULT 0, message TEXT DEFAULT '',
  started_at TEXT, finished_at TEXT,
  PRIMARY KEY (scan_id, ord)
);
CREATE TABLE IF NOT EXISTS findings (
  scan_id INTEGER NOT NULL, fkey TEXT NOT NULL, data TEXT NOT NULL,
  PRIMARY KEY (scan_id, fkey)
);
CREATE TABLE IF NOT EXISTS notes (
  scan_id INTEGER NOT NULL, nkey TEXT NOT NULL, data TEXT NOT NULL,
  PRIMARY KEY (scan_id, nkey)
);
CREATE TABLE IF NOT EXISTS declarations (
  scan_id INTEGER NOT NULL, nkey TEXT NOT NULL, option TEXT NOT NULL, statement TEXT NOT NULL,
  declared_by TEXT NOT NULL, declared_at TEXT NOT NULL,
  PRIMARY KEY (scan_id, nkey)
);
CREATE TABLE IF NOT EXISTS disputes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL, fkey TEXT NOT NULL,
  kind TEXT NOT NULL,                           -- false_positive | compensating_control | exception | cvss | inconclusive
  justification TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '[]',
  proposed_score REAL,
  submitted_by TEXT NOT NULL, submitted_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',       -- pending | accepted | rejected | withdrawn
  reviewer TEXT, review_notes TEXT, reviewed_at TEXT,
  carried_from INTEGER,
  UNIQUE (scan_id, fkey)
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, object TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
);
"""


def now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _connect() -> sqlite3.Connection:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(settings.data_dir / "openasv.db", timeout=30, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


@contextmanager
def conn():
    with _LOCK:
        c = _connect()
        try:
            yield c
            c.commit()
        finally:
            c.close()


def init() -> None:
    with conn() as c:
        c.executescript(SCHEMA)     # interrupted scans are handled by worker.recover() when the server starts


def q(sql: str, args=()) -> list[dict]:
    with conn() as c:
        return [dict(r) for r in c.execute(sql, args)]


def one(sql: str, args=()) -> dict | None:
    r = q(sql, args)
    return r[0] if r else None


def x(sql: str, args=()) -> int:
    with conn() as c:
        cur = c.execute(sql, args)
        return cur.lastrowid


def audit(actor: str, action: str, obj: str, detail: str = "") -> None:
    x("INSERT INTO audit (at,actor,action,object,detail) VALUES (?,?,?,?,?)", (now(), actor, action, obj, detail[:2000]))


# ------------------------------------------------------------------ scopes & components
def scope(sid: int) -> dict | None:
    s = one("SELECT * FROM scopes WHERE id=?", (sid,))
    if s:
        s["customer"] = json.loads(s["customer"] or "{}")
    return s


def scopes(include_archived=False) -> list[dict]:
    rows = q("SELECT * FROM scopes " + ("" if include_archived else "WHERE archived=0 ") + "ORDER BY name")
    for r in rows:
        r["customer"] = json.loads(r["customer"] or "{}")
    return rows


def components(scope_id: int, status: str | None = None) -> list[dict]:
    if status:
        return q("SELECT * FROM components WHERE scope_id=? AND status=? ORDER BY value", (scope_id, status))
    return q("SELECT * FROM components WHERE scope_id=? ORDER BY status, value", (scope_id,))


def upsert_component(scope_id: int, kind: str, value: str, *, status="in_scope", source="declared",
                     discovered_by="", reason="", label="") -> None:
    t = now()
    existing = one("SELECT * FROM components WHERE scope_id=? AND value=?", (scope_id, value))
    if existing:
        if source == "discovered":
            return  # never override an operator decision with a discovery result
        x("UPDATE components SET status=?, kind=?, label=?, updated_at=? WHERE id=?",
          (status, kind, label or existing["label"], t, existing["id"]))
        return
    x("INSERT INTO components (scope_id,kind,value,label,status,source,discovered_by,reason,created_at,updated_at) "
      "VALUES (?,?,?,?,?,?,?,?,?,?)", (scope_id, kind, value, label, status, source, discovered_by, reason, t, t))


# ------------------------------------------------------------------ scans
def scan(sid: int) -> dict | None:
    s = one("SELECT * FROM scans WHERE id=?", (sid,))
    if not s:
        return None
    s["meta"] = json.loads(s["meta"] or "{}")
    s["components"] = json.loads(s["components"] or "[]")
    s["attestation"] = json.loads(s["attestation"]) if s.get("attestation") else None
    s["stages"] = q("SELECT * FROM stages WHERE scan_id=? ORDER BY ord", (sid,))
    return s


def update_scan(sid: int, **fields) -> None:
    for k in ("meta", "components", "attestation"):
        if k in fields and not isinstance(fields[k], str):
            fields[k] = json.dumps(fields[k], ensure_ascii=False, default=str)
    cols = ", ".join(f"{k}=?" for k in fields)
    x(f"UPDATE scans SET {cols} WHERE id=?", (*fields.values(), sid))


def add_stage(sid: int, name: str, target: str = "") -> int:
    with conn() as c:
        n = c.execute("SELECT COALESCE(MAX(ord),-1)+1 FROM stages WHERE scan_id=?", (sid,)).fetchone()[0]
        c.execute("INSERT INTO stages (scan_id,ord,name,target) VALUES (?,?,?,?)", (sid, n, name, target))
        return n


def update_stage(sid: int, ord_: int, **fields) -> None:
    cols = ", ".join(f"{k}=?" for k in fields)
    x(f"UPDATE stages SET {cols} WHERE scan_id=? AND ord=?", (*fields.values(), sid, ord_))


def save_findings(sid: int, findings: list[dict]) -> None:
    with conn() as c:
        c.execute("DELETE FROM findings WHERE scan_id=?", (sid,))
        c.executemany("INSERT OR REPLACE INTO findings VALUES (?,?,?)",
                      [(sid, f["key"], json.dumps(f, ensure_ascii=False)) for f in findings])


def findings(sid: int) -> list[dict]:
    return [json.loads(r["data"]) for r in q("SELECT data FROM findings WHERE scan_id=?", (sid,))]


def save_notes(sid: int, notes: list[dict]) -> None:
    with conn() as c:
        c.execute("DELETE FROM notes WHERE scan_id=?", (sid,))
        c.executemany("INSERT OR REPLACE INTO notes VALUES (?,?,?)",
                      [(sid, n["key"], json.dumps(n, ensure_ascii=False)) for n in notes])


def notes(sid: int) -> list[dict]:
    return [json.loads(r["data"]) for r in q("SELECT data FROM notes WHERE scan_id=?", (sid,))]


def declarations(sid: int) -> dict[str, dict]:
    return {r["nkey"]: r for r in q("SELECT * FROM declarations WHERE scan_id=?", (sid,))}


def disputes(sid: int) -> dict[str, dict]:
    out = {}
    for r in q("SELECT * FROM disputes WHERE scan_id=?", (sid,)):
        r["evidence"] = json.loads(r["evidence"] or "[]")
        out[r["fkey"]] = r
    return out
