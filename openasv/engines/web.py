"""Lightweight HTTP checks: redirects, cleartext credentials, out-of-scope embedded content, version banners."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import requests
import urllib3

from .. import findings
from ..targets import registrable_domain
from .base import Ctx, plural

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")
_PRODUCT_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.+-]*?)[/ ]v?(\d+(?:\.\d+){0,3}[a-z0-9]*)")


class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts, self.frames, self.forms, self.passwords, self.generator = [], [], [], 0, ""
        self.card_fields = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag in ("iframe", "frame") and a.get("src"):
            self.frames.append(a["src"])
        elif tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag == "input":
            if a.get("type", "").lower() == "password":
                self.passwords += 1
            if re.search(r"card|pan|cc-?num|cvv|cvc", a.get("name", "") + a.get("autocomplete", ""), re.I):
                self.card_fields += 1
        elif tag == "meta" and a.get("name", "").lower() == "generator":
            self.generator = a.get("content", "")


def parse_banners(value: str) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in _PRODUCT_RE.finditer(value or "")]


def _session() -> requests.Session:
    s = requests.Session()
    s.trust_env = False
    s.verify = False
    s.headers["User-Agent"] = "OpenASV/1.0 (+https://github.com/Deja-Vyx/Open-ASV)"
    return s


def web_urls(ctx: Ctx) -> list[str]:
    urls = list(ctx.target.web_urls)
    have = {(urlsplit(u).scheme, ctx.url_port(u)) for u in urls}
    for s in ctx.state.get("services", []):
        if s["web"]:
            scheme = "https" if s["tls"] else "http"
            if (scheme, s["port"]) not in have:
                default = (scheme, s["port"]) in (("https", 443), ("http", 80))
                urls.append(f"{scheme}://{ctx.component}{'' if default else ':' + str(s['port'])}/")
                have.add((scheme, s["port"]))
    return urls


def in_scope_host(ctx: Ctx, host: str) -> bool:
    if not host:
        return True
    host = host.lower()
    if host in (ctx.component, ctx.target.tool_host):
        return True
    rd = registrable_domain(host)
    return bool(rd) and rd in ctx.scope_domains


def run(ctx: Ctx) -> None:
    urls = web_urls(ctx)
    ctx.state["all_web_urls"] = urls
    s = _session()
    for i, display in enumerate(urls):
        ctx.check()
        ctx.progress(5 + 90 * i // max(1, len(urls)), f"HTTP analysis of {display}")
        try:
            check_url(ctx, s, display)
        except requests.RequestException as e:
            ctx.log(f"[web] {display}: {e}")
    ctx.progress(100, f"{plural(len(urls), 'web endpoint')} analysed")


def check_url(ctx: Ctx, s: requests.Session, display: str) -> None:
    url = ctx.to_tool_url(display)
    chain, resp = [], None
    for _ in range(6):
        resp = s.get(url, timeout=12, allow_redirects=False)
        if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
            nxt = urljoin(url, resp.headers["location"])
            chain.append(nxt)
            host = urlsplit(nxt).hostname or ""
            if not in_scope_host(ctx, host):
                ctx.discover(host, "host", f"HTTP redirect from {display}")
                break
            url = nxt
            continue
        break
    if resp is None:
        return
    final = ctx.to_display_url(url)
    port = ctx.url_port(final)

    for h in BANNER_HEADERS:
        v = resp.headers.get(h)
        if v:
            for prod, ver in parse_banners(v):
                ctx.state.setdefault("banners", []).append({"product": prod, "version": ver, "cpe": [], "port": port,
                                                           "source": f"http header {h}"})
    ctype = resp.headers.get("content-type", "")
    if "html" not in ctype.lower():
        return
    page = _Page()
    try:
        page.feed(resp.text[:2_000_000])
    except Exception:  # noqa: BLE001
        return
    if page.generator:
        for prod, ver in parse_banners(page.generator):
            ctx.state.setdefault("banners", []).append({"product": prod, "version": ver, "cpe": [], "port": port,
                                                       "source": "html generator"})
    for src in page.scripts:
        m = re.search(r"jquery[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", src, re.I)
        if m:
            ctx.state.setdefault("banners", []).append({"product": "jquery", "version": m.group(1), "cpe": [],
                                                       "port": port, "source": f"script {src[:120]}"})

    external = {}
    for kind, items in (("script", page.scripts), ("frame", page.frames), ("form", page.forms)):
        for ref in items:
            host = urlsplit(urljoin(url, ref)).hostname or ""
            if host and not in_scope_host(ctx, host):
                external.setdefault(host, set()).add(kind)
    for host, kinds in sorted(external.items()):
        what = "script" if "script" in kinds else ("frame" if "frame" in kinds else "form target")
        ctx.note("embedded_external_content", f"Pages on port {port} load {what} from {host}", port, "web",
                 ref=f"ext-{host}")

    if urlsplit(final).scheme == "http" and (page.passwords or page.card_fields):
        what = "password" if page.passwords else "payment card"
        ctx.findings.append(findings.make(
            "web", "cleartext_credentials", ctx.component, f"{what.capitalize()} form served over HTTP",
            port=port, url=final, evidence=f"{page.passwords} password / {page.card_fields} card field(s) on an http:// page",
            description="A form that collects credentials or card data is delivered without TLS.", rule_id="web-cleartext-form"))
        ctx.note("insecure_service", f"Cleartext HTTP form at {final}", port, "web", ref=f"clear-{final}")
