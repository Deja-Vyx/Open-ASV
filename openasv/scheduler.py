"""Background scheduler for recurring scans (monthly / every three months)."""
from __future__ import annotations

import threading

from . import config, db, service

_started = False


def _loop(interval: int):
    ev = threading.Event()
    while True:
        try:
            service.run_scheduled()
        except Exception as e:  # noqa: BLE001
            db.audit("scheduler", "error", "scheduler", str(e))
        ev.wait(interval)


def start(interval: int = 60) -> None:
    global _started
    if _started or not config.settings.scheduler:
        return
    threading.Thread(target=_loop, args=(interval,), name="openasv-scheduler", daemon=True).start()
    _started = True
