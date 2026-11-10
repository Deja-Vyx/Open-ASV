"""Optional webhook notifications (Slack / Microsoft Teams / generic JSON)."""
from __future__ import annotations

import threading

import requests

from . import config, db


def _post(url: str, payload: dict) -> None:
    try:
        requests.post(url, json=payload, timeout=10)
    except requests.RequestException:
        pass


def scan_finished(sid: int, res: dict) -> None:
    url = config.settings.webhook_url
    if not url:
        return
    scan = db.scan(sid)
    scope = db.scope(scan["scope_id"]) or {}
    link = f"{config.settings.base_url}/scans/{sid}/report"
    text = (f"OpenASV scan #{sid} of {scope.get('name', 'scope')} finished: {res['overall']} — "
            f"{res['counts']['fail']} failing vulnerabilities, {len(res['pending_notes'])} special note(s) to declare. {link}")
    payload = {"text": text, "event": "scan.completed", "scan_id": sid, "scope": scope.get("name"),
               "result": res["overall"], "failing": res["counts"]["fail"], "report": link}
    threading.Thread(target=_post, args=(url, payload), daemon=True).start()
