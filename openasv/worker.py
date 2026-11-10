"""Scan execution: one scan at a time, each component through the engine pipeline."""
from __future__ import annotations

import json
import queue
import threading
import traceback
from pathlib import Path

from . import changes, config, db, findings, notify, redact, scoring, targets
from .engines import (base, dns as dns_engine, eol, interference, nmap, nuclei, nvd, pages, sshaudit, testssl, waf,
                      web, zap)
from .engines.base import Cancelled, Ctx, EngineError, HostTarget

_Q: "queue.Queue[int]" = queue.Queue()
_CANCEL: dict[int, threading.Event] = {}
_started = False
_lock = threading.Lock()

STAGE_LABELS = {
    "preflight": "Preflight", "nmap": "Port & service discovery", "testssl": "TLS / SSL",
    "web": "HTTP analysis", "zap": "Web application testing", "nuclei": "Known vulnerabilities & misconfiguration",
    "ssh": "SSH configuration audit", "waf": "Web application firewall detection",
    "pages": "Script and header inventory",
    "eol": "End-of-life analysis", "nvd": "Version-based CVE correlation", "dns": "DNS & scope discovery",
    "scoring": "Compliance determination",
}


def run_dir(sid: int) -> Path:
    d = config.settings.data_dir / "scans" / str(sid)
    d.mkdir(parents=True, exist_ok=True)
    return d


def log_path(sid: int) -> Path:
    return run_dir(sid) / "scan.log"


def enqueue(sid: int) -> None:
    _CANCEL[sid] = threading.Event()
    _Q.put(sid)
    ensure_started()


def cancel(sid: int) -> bool:
    ev = _CANCEL.get(sid)
    if ev:
        ev.set()
    return bool(ev)


def recover() -> list[int]:
    """At server start: scans left 'running' by a previous process cannot be resumed; queued ones are re-queued."""
    for s in db.q("SELECT id FROM scans WHERE status='running'"):
        db.update_scan(s["id"], status="failed", error="Interrupted: the OpenASV server stopped while this scan was running",
                       finished_at=db.now())
        _close_stages(s["id"], "error", "interrupted")
    queued = [s["id"] for s in db.q("SELECT id FROM scans WHERE status='queued' ORDER BY id")]
    for sid in queued:
        enqueue(sid)
    return queued


def ensure_started() -> None:
    global _started
    with _lock:
        if not _started:
            threading.Thread(target=_loop, name="openasv-worker", daemon=True).start()
            _started = True


def _loop():
    while True:
        sid = _Q.get()
        try:
            execute(sid)
        except Exception:  # noqa: BLE001
            db.update_scan(sid, status="failed", error=traceback.format_exc()[-2000:], finished_at=db.now())


def _version_of(cmd: list[str], marker: str) -> str:
    exe = base.command(cmd[0])
    if not exe:
        return "not installed"
    try:
        import subprocess
        out = subprocess.run([*exe, *cmd[1:]], capture_output=True, text=True, timeout=30)
        text = base.strip_ansi(out.stdout + out.stderr)
        line = next((x for x in text.splitlines() if marker.lower() in x.lower()), "")
        return " ".join(line.strip("# ").split())[:80] or "installed"
    except Exception:  # noqa: BLE001
        return "installed"


def tool_versions() -> dict:
    s = config.settings
    v = {"nmap": base.first_line([s.nmap, "--version"]),
         "nuclei": base.first_line([s.nuclei, "-version"]).replace("[INF] ", "")}
    v["ssh-audit"] = _version_of([s.ssh_audit, "--help"], "ssh-audit v")
    v["wafw00f"] = _version_of([s.wafw00f, "--version"], "WAFW00F")
    t = base.strip_ansi(base.first_line([s.testssl, "--version"], timeout=60))
    v["testssl.sh"] = t
    try:
        exe = base.which(s.testssl)
        if exe:
            import subprocess
            out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=60).stdout
            line = next((x for x in out.splitlines() if "testssl.sh" in x and "version" in x), "")
            v["testssl.sh"] = " ".join(base.strip_ansi(line).split()) or t
    except Exception:  # noqa: BLE001
        pass
    try:
        v["zap"] = zap.client().version()
    except Exception:  # noqa: BLE001
        v["zap"] = "not reachable"
    d = eol.data()
    v["eol data"] = f"endoflife.date snapshot {d.get('generated', '?')}"
    return v


class _Stage:
    def __init__(self, sid: int, name: str, target: str = ""):
        self.sid, self.name = sid, name
        self.ord = db.add_stage(sid, name, target)
        db.update_stage(sid, self.ord, status="running", started_at=db.now(), progress=1)

    def progress(self, pct: int, msg: str):
        db.update_stage(self.sid, self.ord, progress=max(1, min(100, int(pct))), message=msg[:300])

    def done(self, status="done", msg=None):
        f = {"status": status, "finished_at": db.now()}
        if status == "done":
            f["progress"] = 100
        if msg is not None:
            f["message"] = msg[:300]
        db.update_stage(self.sid, self.ord, **f)


TLS_CATEGORIES = {"ssl_early_tls", "deprecated_tls", "weak_cipher", "anonymous_cipher", "cert_untrusted",
                  "cert_expired", "tls_vulnerability"}


def prefer_testssl(fs: list[dict], tested_ports: set) -> list[dict]:
    """testssl.sh is the authoritative TLS engine (it honours extra trusted CAs). Drop overlapping TLS findings
    from template engines on ports testssl.sh analysed; keep them where testssl.sh could not run."""
    return [f for f in fs if not (f["engine"] == "nuclei" and f["port"] in tested_ports
                                  and (f["category"] in TLS_CATEGORIES or "ssl" in f["extra"].get("tags", [])))]


def host_pipeline(profile: dict) -> list[str]:
    web_on = profile.get("web", True)
    names = (["nmap", "testssl"] + (["ssh"] if profile.get("ssh", True) else [])
             + (["web"] if web_on else []) + (["waf"] if web_on and profile.get("waf", True) else [])
             + ["zap"] + (["pages"] if web_on and profile.get("pages", True) else []) + ["nuclei"])
    if profile.get("eol", True):
        names.append("eol")
    if profile.get("nvd") and config.settings.nvd_enabled:
        names.append("nvd")
    return names


def upcoming(scan: dict) -> list[dict]:
    """Stages still to come for a queued or running scan (for the progress view)."""
    if scan["status"] not in ("queued", "running"):
        return []
    profile = config.profiles().get(scan["profile"], {})
    plan = host_pipeline(profile)
    done = [s["name"] for s in scan["stages"]]
    rest = (["preflight"] + plan) if not done else (plan[plan.index(done[-1]) + 1:] if done[-1] in plan else
                                                    (plan if done[-1] == "preflight" else []))
    if profile.get("dns") and "dns" not in done:
        rest.append("dns")
    rest.append("scoring")
    return [{"name": n, "label": STAGE_LABELS[n]} for n in rest if n not in ("scoring",) or "scoring" not in done]


def build_hosts(components: list[dict], log) -> tuple[list[HostTarget], list[str]]:
    hosts: dict[str, HostTarget] = {}
    problems = []
    for c in components:
        try:
            comp = targets.parse(c["value"])
            targets.authorize(comp)
        except targets.TargetError as e:
            problems.append(str(e))
            continue
        names = targets.expand(comp) if comp.kind == "cidr" else [comp.host]
        for h in names:
            t = hosts.get(h)
            if not t:
                t = HostTarget(host=h, tool_host=targets.tool_host_for(h), ips=comp.ips if comp.kind != "cidr" else [h],
                               load_balanced=bool(c.get("load_balanced")), lb_synchronized=bool(c.get("lb_synchronized")))
                hosts[h] = t
            if comp.kind == "url":
                t.web_urls.append(comp.url)
                t.ports.append(comp.port)
    for p in problems:
        log(f"[preflight] {p}")
    return list(hosts.values()), problems


def execute(sid: int) -> None:
    scan = db.scan(sid)
    profile = config.profiles()[scan["profile"]]
    cancel_ev = _CANCEL.setdefault(sid, threading.Event())
    rd = run_dir(sid)
    lf = open(log_path(sid), "a", encoding="utf-8")

    def log(line: str):
        lf.write(f"{db.now()[11:19]} {redact.mask(line)}\n")
        lf.flush()

    meta = dict(scan["meta"])
    meta["policy_hash"] = config.policy_hash()
    db.update_scan(sid, status="running", started_at=db.now())
    inconclusive: list[str] = []
    all_f, all_n, discovered = [], [], []
    try:
        st = _Stage(sid, "preflight")
        hosts, problems = build_hosts(scan["components"], log)
        if problems:
            inconclusive += [f"Component not scanned: {p}" for p in problems]
        if not hosts:
            raise EngineError("No component passed the target authorization policy")
        meta["expanded_hosts"] = [h.host for h in hosts]
        meta["versions"] = tool_versions()
        meta["privileged"] = config.settings.privileged
        reach = {}
        for h in hosts:
            ports = h.ports or [443, 80]
            reach[h.host] = None
            for p in ports:
                ok, msg = targets.tcp_probe(h.tool_host, p)
                log(f"[preflight] {h.host} ({h.tool_host}) port {p}: {msg}")
                if ok:
                    reach[h.host] = p
                    break
        scope_domains = sorted({d for c in scan["components"] for d in [targets.registrable_domain(
            targets.parse(c["value"]).host)] if d})
        meta["scope_domains"] = scope_domains
        db.update_scan(sid, meta=meta)
        st.done(msg=f"{base.plural(len(hosts), 'component')} authorized")

        dns_hosts = {}
        for h in hosts:
            ctx = Ctx(scan_id=sid, run_dir=rd, target=h, profile=profile, scope_domains=scope_domains, log=log,
                      progress=lambda *_: None, cancel=cancel_ev)
            mon = interference.Monitor(h.tool_host, reach[h.host]).start() if reach[h.host] else None
            runners = {"nmap": nmap.run, "testssl": testssl.run, "ssh": sshaudit.run, "web": web.run, "waf": waf.run,
                       "zap": None, "pages": pages.run, "nuclei": nuclei.run, "eol": eol.run, "nvd": nvd.run}
            for name in host_pipeline(profile):
                fn = runners[name]
                ctx.check()
                if name == "zap":
                    urls = ctx.state.get("all_web_urls") or web.web_urls(ctx)
                    for u in urls:
                        ctx.check()
                        s2 = _Stage(sid, "zap", u)
                        ctx.progress = s2.progress
                        try:
                            zap.scan_url(ctx, u)
                            s2.done()
                        except Cancelled:
                            raise
                        except Exception as e:  # noqa: BLE001
                            inconclusive.append(f"Web application testing of {u} did not complete: {e}")
                            log(f"[zap] ERROR {e}")
                            s2.done("error", str(e))
                    continue
                s2 = _Stage(sid, name, h.host)
                ctx.progress = s2.progress
                try:
                    fn(ctx)
                    s2.done("skipped" if ctx.state.pop(f"{name}_skipped", False) else "done")
                except Cancelled:
                    raise
                except Exception as e:  # noqa: BLE001  (one engine failing must not hide other results)
                    if name in ("nmap", "testssl", "nuclei"):
                        inconclusive.append(f"{STAGE_LABELS[name]} did not complete on {h.host}: {e}")
                    else:
                        meta.setdefault("limitations", []).append(f"{STAGE_LABELS[name]} on {h.host}: {e}")
                    log(f"[{name}] ERROR {e}")
                    s2.done("error", str(e))
            if mon:
                mon.stop()
            inconclusive += [f"{h.host}: {r}" for r in interference.assess(
                mon.samples if mon else [], ctx.state.get("services", []), reach[h.host],
                ctx.state.get("interference", {}))]
            for s in ctx.state.get("services", []):
                if s["service"] == "domain" and s["proto"] in ("tcp", "udp"):
                    dns_hosts[h.host] = h.tool_host
            for n in sorted(ctx.state.get("cert_names", set())):
                if targets.registrable_domain(n) in scope_domains:
                    ctx.discover(n, "host", f"TLS certificate subjectAltName on {h.host}")
            for n in sorted(ctx.state.get("linked_hosts", set())):
                if targets.registrable_domain(n) in scope_domains:
                    ctx.discover(n, "host", f"linked from crawled pages of {h.host}")
            meta.setdefault("coverage", {})[h.host] = ctx.state.get("coverage", {})
            meta.setdefault("banners", {})[h.host] = [
                {k: v for k, v in b.items() if k in ("product", "version", "port", "source")}
                for b in ctx.state.get("banners", [])][:40]
            meta.setdefault("crawled", {}).update(ctx.state.get("crawled", {}))
            inv = meta.setdefault("inventory", {"services": {}, "pages": {}})
            if "services" in ctx.state:
                inv["services"][h.host] = sorted(
                    f"{x['port']}/{x['proto']} {x['service']}" + (f" ({x['product']})" if x.get("product") else "")
                    for x in ctx.state["services"])     # compared by port/protocol; the rest is a label
            inv["pages"].update(ctx.state.get("page_inventory", {}))
            meta.setdefault("waf", {}).update(ctx.state.get("waf", {}))
            meta.setdefault("limitations", []).extend(ctx.state.get("limitations", []))
            meta.setdefault("versions", {}).update(ctx.state.get("versions", {}))
            all_f += prefer_testssl(ctx.findings, ctx.state.get("tls_tested", set()))
            all_n += ctx.notes
            discovered += ctx.discovered

        if profile.get("dns") and (scope_domains or dns_hosts):
            dctx = Ctx(scan_id=sid, run_dir=rd, target=HostTarget("dns", "dns", []), profile=profile,
                       scope_domains=scope_domains, log=log, progress=lambda *_: None, cancel=cancel_ev)
            s2 = _Stage(sid, "dns", ", ".join(scope_domains) or "in-scope DNS servers")
            dctx.progress = s2.progress
            in_scope = {h.host for h in hosts} | {ip for h in hosts for ip in h.ips}
            try:
                dns_engine.run(dctx, scope_domains, in_scope, dns_hosts)
                s2.done()
            except Cancelled:
                raise
            except Exception as e:  # noqa: BLE001
                meta.setdefault("limitations", []).append(f"DNS checks: {e}")
                s2.done("error", str(e))
            all_f += dctx.findings
            discovered += dctx.discovered
            meta["dns_checked"] = sorted(dctx.state.get("dns_checked", set()))
            meta["email_auth"] = dctx.state.get("email_auth", {})

        st = _Stage(sid, "scoring")
        hostset = {h.host for h in hosts}
        disc = []
        existing = {c["value"]: c for c in db.components(scan["scope_id"])}
        for value, kind, reason in discovered:
            if value in hostset:
                continue
            ex = existing.get(value)
            status = ex["status"] if ex else "discovered"
            if status in ("in_scope",):
                continue
            db.upsert_component(scan["scope_id"], kind, value, status="discovered", source="discovered",
                                discovered_by=f"scan #{sid}", reason=reason)
            disc.append({"value": value, "kind": kind, "reason": reason, "status": status})
        meta["discovered"] = disc
        meta["out_of_scope"] = [c["value"] for c in db.components(scan["scope_id"], "out_of_scope")]
        meta["inconclusive"] = inconclusive
        prev = changes.previous_scan(scan)
        if prev:
            diff = changes.compare(prev["meta"].get("inventory") or {}, meta.get("inventory") or {})
            meta["changes"] = {"since_scan": prev["id"], "since": prev["finished_at"], **diff}
            all_f += changes.to_findings(diff, prev["id"])
        merged = findings.consolidate(all_f)
        db.save_findings(sid, merged)
        db.save_notes(sid, all_n)
        redact.mask_files(rd)
        (rd / "findings.json").write_text(json.dumps(merged, ensure_ascii=False, indent=1), encoding="utf-8")
        db.update_scan(sid, meta=meta, finished_at=db.now(), status="completed", inconclusive=int(bool(inconclusive)))
        res = scoring.evaluate(db.scan(sid))
        db.update_scan(sid, result=res["overall"])
        st.done(msg=f"{res['overall']} — {res['counts']['fail']} failing, {len(res['pending_notes'])} note(s) to declare")
        log(f"[scoring] result {res['overall']}")
        db.audit("system", "scan.completed", f"scan:{sid}", res["overall"])
        notify.scan_finished(sid, res)
    except Cancelled:
        log("Cancelled by operator")
        db.update_scan(sid, status="cancelled", finished_at=db.now(), meta=meta)
        _close_stages(sid, "cancelled")
    except EngineError as e:
        log(f"Stopped: {e}")
        db.update_scan(sid, status="failed", error=str(e), finished_at=db.now(), meta=meta)
        _close_stages(sid, "error", str(e))
    finally:
        lf.close()
        _CANCEL.pop(sid, None)


def _close_stages(sid: int, status: str, msg: str = ""):
    for s in db.scan(sid)["stages"]:
        if s["status"] == "running":
            db.update_stage(sid, s["ord"], status=status, message=msg[:300], finished_at=db.now())
