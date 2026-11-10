"""Engine plumbing shared by every scanner integration."""
from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .. import redact


class Cancelled(Exception):
    pass


class EngineError(Exception):
    """An engine could not complete. The scan continues but is marked inconclusive."""


@dataclass
class HostTarget:
    host: str                      # as declared (component name in reports)
    tool_host: str                 # what tools connect to
    ips: list[str]
    web_urls: list[str] = field(default_factory=list)     # declared web application URLs (display form)
    ports: list[int] = field(default_factory=list)         # ports implied by declared URLs
    load_balanced: bool = False
    lb_synchronized: bool = False


@dataclass
class Ctx:
    scan_id: int
    run_dir: Path
    target: HostTarget
    profile: dict
    scope_domains: list[str]
    log: Callable[[str], None]
    progress: Callable[[int, str], None]
    cancel: threading.Event
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    discovered: list = field(default_factory=list)     # (value, kind, reason)
    state: dict = field(default_factory=dict)          # services, banners, web_urls, ...

    def check(self):
        if self.cancel.is_set():
            raise Cancelled()

    # --- naming helpers -------------------------------------------------------
    @property
    def component(self) -> str:
        return self.target.host

    def to_tool_url(self, url: str) -> str:
        t = self.target
        if t.tool_host != t.host:
            return url.replace(f"//{t.host}", f"//{t.tool_host}", 1)
        return url

    def to_display_url(self, url: str) -> str:
        t = self.target
        if t.tool_host != t.host:
            return url.replace(f"//{t.tool_host}", f"//{t.host}", 1)
        return url

    def url_port(self, url: str) -> int:
        p = urlsplit(url)
        return p.port or (443 if p.scheme == "https" else 80)

    # --- outputs --------------------------------------------------------------
    def note(self, kind: str, detail: str, port: int | None = None, source: str = "", ref: str = "") -> None:
        key = hashlib.sha1(f"{kind}|{self.component}|{port}|{ref or detail}".encode()).hexdigest()[:14]
        if any(n["key"] == key for n in self.notes):
            return
        self.notes.append({"key": key, "type": kind, "component": self.component, "port": port,
                           "detail": redact.mask(detail)[:600], "source": source})

    def discover(self, value: str, kind: str, reason: str) -> None:
        if (value, kind) not in {(d[0], d[1]) for d in self.discovered}:
            self.discovered.append((value, kind, reason))


def which(binary: str) -> str | None:
    if os.path.isfile(binary) and os.access(binary, os.X_OK):
        return binary
    return shutil.which(binary)


def command(binary: str) -> list[str] | None:
    """Executable plus interpreter prefix. Shell scripts such as testssl.sh need bash on Windows (Git Bash or WSL)."""
    exe = which(binary)
    if not exe and os.path.isfile(binary):
        exe = binary
    if not exe:
        return None
    if os.name == "nt" and exe.lower().endswith(".sh"):
        bash = shutil.which("bash")
        return [bash, exe] if bash else None
    return [exe]


def run_cmd(ctx: Ctx, args: list[str], timeout: int, label: str, env: dict | None = None,
            on_line: Callable[[str], bool] | None = None) -> int:
    """Run a command, stream its output into the scan log, honour cancellation and timeout."""
    exe = command(args[0])
    if not exe:
        raise EngineError(f"'{args[0]}' is not installed or not on PATH")
    ctx.log(f"$ {' '.join(args)}")
    proc = subprocess.Popen([*exe, *args[1:]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            errors="replace", cwd=ctx.run_dir, start_new_session=True,
                            env={**os.environ, **(env or {})})

    def pump():
        for line in proc.stdout:  # type: ignore[union-attr]
            line = strip_ansi(line.rstrip())
            if line and not (on_line and on_line(line)):
                ctx.log(f"[{label}] {line[:400]}")

    t = threading.Thread(target=pump, daemon=True)
    t.start()
    start = time.time()
    try:
        while proc.poll() is None:
            if ctx.cancel.is_set():
                raise Cancelled()
            if time.time() - start > timeout:
                raise EngineError(f"{label} exceeded {timeout}s")
            time.sleep(0.5)
    except BaseException:
        try:
            if hasattr(os, "killpg"):
                os.killpg(proc.pid, signal.SIGTERM)
            else:                      # Windows
                proc.terminate()
        except (ProcessLookupError, OSError):
            pass
        raise
    finally:
        t.join(timeout=5)
    return proc.returncode


_ANSI = __import__("re").compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(s: str) -> str:
    return _ANSI.sub("", s)


def first_line(cmd: list[str], timeout: int = 30) -> str:
    exe = which(cmd[0])
    if not exe:
        return "not installed"
    try:
        p = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, timeout=timeout)
        for line in strip_ansi(p.stdout + "\n" + p.stderr).splitlines():
            s = line.strip()
            if s and not s.startswith("Picked up JAVA_TOOL_OPTIONS") and "PDCP Directory" not in s:
                return s[:160]
        return "unknown"
    except Exception as e:  # noqa: BLE001
        return f"error: {e}"[:160]


def plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"
