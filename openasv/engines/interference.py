"""Scan interference detection (ASV Program Guide: active protection systems must not block the scan)."""
from __future__ import annotations

import threading

from ..targets import tcp_probe


class Monitor:
    """Probe a known-open port during the scan; consistent failures after earlier success suggest shunning."""

    def __init__(self, host: str, port: int, interval: float = 15.0):
        self.host, self.port, self.interval = host, port, interval
        self.samples: list[bool] = []
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._t.start()
        return self

    def stop(self):
        self._stop.set()
        self._t.join(timeout=self.interval + 5)

    def _loop(self):
        while not self._stop.is_set():
            ok, _ = tcp_probe(self.host, self.port, timeout=5)
            self.samples.append(ok)
            self._stop.wait(self.interval)


def assess(samples: list[bool], services: list[dict], reachable_port: int | None, zap_stats: dict) -> list[str]:
    reasons = []
    if samples and any(samples):
        first_ok = samples.index(True)
        tail = samples[first_ok:]
        streak = 0
        for s in reversed(tail):
            if s:
                break
            streak += 1
        if streak >= 3:
            reasons.append(f"Target stopped answering on port {reachable_port} for the last {streak} liveness probes "
                           "after responding earlier (possible IPS/firewall shunning).")
    if reachable_port and not any(s["port"] == reachable_port for s in services) and services is not None:
        reasons.append(f"Port {reachable_port} answered the pre-scan check but the port scan reported it closed or "
                       "filtered (possible rate-based blocking).")
    for url, st in (zap_stats or {}).items():
        if st.get("sampled", 0) >= 50 and st.get("blocked_ratio", 0) >= 0.6:
            reasons.append(f"{int(st['blocked_ratio'] * 100)}% of sampled responses from {url} were blocked "
                           "(403/429/no response) — a WAF may have interfered with web testing.")
    return reasons
