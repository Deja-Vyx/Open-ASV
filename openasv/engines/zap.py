"""OWASP ZAP (daemon) via its JSON API: crawl, passive and active web application testing."""
from __future__ import annotations

import json
import re
import time
from urllib.parse import urlsplit

import requests

from .. import config, findings
from .base import Ctx, EngineError, plural

_RISK = {"informational": 0, "low": 1, "medium": 2, "high": 3}
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")


class Zap:
    def __init__(self, base: str, key: str = ""):
        self.base, self.key = base, key
        self.s = requests.Session()
        self.s.trust_env = False

    def call(self, comp: str, kind: str, name: str, **params):
        if self.key:
            params["apikey"] = self.key
        r = self.s.get(f"{self.base}/JSON/{comp}/{kind}/{name}/", params=params, timeout=120)
        if r.status_code != 200:
            raise EngineError(f"ZAP {comp}/{name}: HTTP {r.status_code} {r.text[:200]}")
        return r.json()

    def version(self) -> str:
        return self.call("core", "view", "version")["version"]


def client() -> Zap:
    return Zap(config.settings.zap_api, config.settings.zap_api_key)


def wait_ready(ctx: Ctx, zap: Zap, seconds: int = 240) -> str:
    end, last = time.time() + seconds, ""
    while time.time() < end:
        ctx.check()
        try:
            return zap.version()
        except Exception as e:  # noqa: BLE001
            last = str(e)
            ctx.progress(2, "Waiting for the ZAP daemon")
            time.sleep(3)
    raise EngineError(f"ZAP is not reachable at {config.settings.zap_api}: {last[:200]}")


def _poll(ctx: Ctx, status, minutes: float, lo: int, hi: int, msg: str, stop) -> None:
    end = time.time() + minutes * 60
    while True:
        ctx.check()
        pct = int(status())
        ctx.progress(lo + (hi - lo) * pct // 100, f"{msg} {pct}%")
        if pct >= 100:
            return
        if time.time() > end:
            stop()
            ctx.log(f"[zap] {msg}: time limit of {minutes} min reached, collecting results so far")
            return
        time.sleep(3)


def scan_url(ctx: Ctx, url_display: str) -> None:
    zap = client()
    ver = wait_ready(ctx, zap)
    ctx.state.setdefault("versions", {})["zap"] = ver
    url = ctx.to_tool_url(url_display)
    cfg = ctx.profile.get("zap") or {}
    p = urlsplit(url)
    ctx.log(f"[zap] ZAP {ver} — target {url}")

    zap.call("core", "action", "newSession", overwrite="true")
    cname = f"openasv-{ctx.scan_id}"
    cid = zap.call("context", "action", "newContext", contextName=cname)["contextId"]
    zap.call("context", "action", "includeInContext", contextName=cname,
             regex=f"^{re.escape(p.scheme)}://{re.escape(p.netloc)}(/.*)?$")
    zap.call("spider", "action", "setOptionMaxDuration", Integer=str(cfg.get("spider_minutes", 3)))
    zap.call("ascan", "action", "setOptionMaxScanDurationInMins", Integer=str(cfg.get("active_minutes", 10)))
    try:
        zap.call("core", "action", "accessUrl", url=url, followRedirects="true")
    except EngineError as e:
        raise EngineError(f"ZAP cannot reach {url_display}: {e}") from e

    sid = zap.call("spider", "action", "scan", url=url, contextName=cname, recurse="true")["scan"]
    _poll(ctx, lambda: zap.call("spider", "view", "status", scanId=sid)["status"],
          cfg.get("spider_minutes", 3) + 1, 5, 30, "Crawling", lambda: zap.call("spider", "action", "stop", scanId=sid))
    urls = zap.call("spider", "view", "results", scanId=sid).get("results", [])
    if cfg.get("ajax_spider"):
        zap.call("ajaxSpider", "action", "scan", url=url, contextName=cname)
        end = time.time() + 60 * cfg.get("spider_minutes", 3)
        while time.time() < end and zap.call("ajaxSpider", "view", "status")["status"] == "running":
            ctx.check()
            time.sleep(3)
        zap.call("ajaxSpider", "action", "stop")
    ctx.log(f"[zap] crawl found {len(urls)} URLs")

    end = time.time() + 240
    while time.time() < end:
        ctx.check()
        left = int(zap.call("pscan", "view", "recordsToScan")["recordsToScan"])
        ctx.progress(35, f"Passive analysis ({left} records left)")
        if left == 0:
            break
        time.sleep(2)

    if cfg.get("active"):
        aid = zap.call("ascan", "action", "scan", url=url, recurse="true", inScopeOnly="false", contextId=cid)["scan"]
        _poll(ctx, lambda: zap.call("ascan", "view", "status", scanId=aid)["status"],
              cfg.get("active_minutes", 10) + 2, 40, 92, "Active testing",
              lambda: zap.call("ascan", "action", "stop", scanId=aid))

    base = f"{p.scheme}://{p.netloc}"
    alerts, start = [], 0
    while True:
        page = zap.call("core", "view", "alerts", baseurl=base, start=str(start), count="500").get("alerts", [])
        alerts += page
        if len(page) < 500:
            break
        start += 500
    ctx.state.setdefault("interference", {})[url_display] = response_stats(zap, base)
    raw = ctx.run_dir / f"zap_{p.hostname}_{p.port or ''}.json"
    raw.write_text(json.dumps({"zap_version": ver, "target": url_display, "crawled": urls, "alerts": alerts},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    ctx.state.setdefault("crawled", {})[url_display] = len(urls)
    ctx.state.setdefault("crawled_urls", {})[url_display] = urls[:2000]
    for u in urls:
        h = urlsplit(u).hostname
        if h and h not in (p.hostname, ctx.target.tool_host):
            ctx.state.setdefault("linked_hosts", set()).add(h)
    parse(alerts, ctx, raw.name)
    ctx.progress(100, plural(len(alerts), "alert"))


def response_stats(zap: Zap, base: str) -> dict:
    """Sample responses to spot active blocking (WAF / IPS) during the scan."""
    try:
        n = int(zap.call("core", "view", "numberOfMessages", baseurl=base)["numberOfMessages"])
        start = max(0, n - 400)
        msgs = zap.call("core", "view", "messages", baseurl=base, start=str(start), count="400").get("messages", [])
    except Exception:  # noqa: BLE001
        return {"sampled": 0}
    codes: dict[str, int] = {}
    for m in msgs:
        mm = re.match(r"HTTP/\S+\s+(\d{3})", m.get("responseHeader", "") or "")
        c = mm.group(1) if mm else "none"
        codes[c] = codes.get(c, 0) + 1
    total = sum(codes.values())
    blocked = codes.get("403", 0) + codes.get("429", 0) + codes.get("none", 0)
    return {"sampled": total, "codes": codes, "blocked_ratio": round(blocked / total, 3) if total else 0.0}


def parse(alerts: list[dict], ctx: Ctx, raw_name: str = "zap.json") -> None:
    cls = config.policy()["classification"]
    plugin_map = {str(k): v for k, v in cls["zap_plugins"].items()}
    for a in alerts:
        risk = str(a.get("risk", "Informational")).lower()
        if _RISK.get(risk, 0) < 1:
            continue
        pid = str(a.get("pluginId", ""))
        cwe = [str(a.get("cweid"))] if str(a.get("cweid", "")) not in ("", "-1", "0") else []
        name = a.get("alert") or a.get("name", "ZAP alert")
        cat = findings.classify(rule_map=plugin_map, rule_id=pid, cwe=cwe, title=name)
        url = ctx.to_display_url(a.get("url", ""))
        port = ctx.url_port(url) if url else None
        if cat == "embedded_external":
            m = re.search(r"src=[\"']?([^\"' >]+)", str(a.get("evidence", "")))
            dom = (urlsplit(m.group(1)).hostname if m else "") or "external domain"
            ctx.note("embedded_external_content", f"Pages on port {port} load script from {dom}", port, "zap",
                     ref=f"ext-{dom}")
            continue
        refs = [r.strip() for r in str(a.get("reference", "")).splitlines() if r.strip().startswith("http")]
        cves = sorted(set(_CVE.findall(f"{a.get('other', '')} {a.get('reference', '')}")))
        ctx.findings.append(findings.make(
            "zap", cat, ctx.component, name, port=port, service="http", url=url, method=a.get("method", ""),
            param=a.get("param", ""), attack=str(a.get("attack", "")), evidence=str(a.get("evidence", "")),
            description=str(a.get("description", "")), severity_hint=risk, cve=cves, cwe=cwe, references=refs,
            engine_solution=str(a.get("solution", "")), rule_id=f"zap-{pid}", raw_ref=f"{raw_name}#{pid}",
            confidence=str(a.get("confidence", "")), extra={"zap_risk": a.get("risk"), "plugin": pid}))
        if cat == "directory_listing":
            ctx.note("directory_browsing", f"Directory browsing at {url}", port, "zap", ref=f"dir-{urlsplit(url).path}")
