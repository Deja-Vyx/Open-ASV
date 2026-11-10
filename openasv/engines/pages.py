"""Page script and security-header inventory.

Records which scripts every sampled page loads (source, Subresource Integrity, content hash for same-site and
inline scripts) and the security-relevant response headers, so that the next scan can report what changed.
Supports PCI DSS 6.4.3 (script inventory and integrity) and 11.6.1 (change and tamper detection). External
script files are never fetched: they belong to hosts outside the authorized scope."""
from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import requests

from .. import findings
from . import web
from .base import Ctx, plural

HEADERS = ("content-security-policy", "content-security-policy-report-only", "strict-transport-security",
           "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy")
MAX_PAGES = 12
_PRIORITY = re.compile(r"pay|checkout|cart|order|card|billing|login|signin|account|admin", re.I)
_CARD = re.compile(r"card|pan|cc-?num|cvv|cvc", re.I)
_SKIP_EXT = re.compile(r"\.(png|jpe?g|gif|svg|ico|css|js|woff2?|ttf|pdf|zip|xml|txt|json)(\?|$)", re.I)


class _Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.external, self.inline, self.card_fields, self.password_fields = [], [], 0, 0
        self._buf = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            if a.get("src"):
                self.external.append({"src": a["src"], "integrity": a.get("integrity", "")})
            elif a.get("type", "text/javascript").lower() in ("", "text/javascript", "module", "application/javascript"):
                self._buf = []
        elif tag == "input":
            if _CARD.search(a.get("name", "") + a.get("autocomplete", "") + a.get("id", "")):
                self.card_fields += 1
            if a.get("type", "").lower() == "password":
                self.password_fields += 1

    def handle_data(self, data):
        if self._buf is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._buf is not None:
            body = "".join(self._buf).strip()
            if body:
                self.inline.append(hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16])
            self._buf = None


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def candidates(ctx: Ctx, entry: str) -> list[str]:
    base = urlsplit(entry)
    seen, out = set(), [entry]
    crawled = [ctx.to_display_url(u) for u in ctx.state.get("crawled_urls", {}).get(entry, [])]
    crawled.sort(key=lambda u: (not _PRIORITY.search(u), len(u)))
    for u in crawled:
        p = urlsplit(u)
        key = p.path.rstrip("/")
        if (p.scheme, p.netloc) != (base.scheme, base.netloc) or _SKIP_EXT.search(p.path) or key in seen \
                or key == base.path.rstrip("/"):
            continue
        seen.add(key)
        out.append(f"{p.scheme}://{p.netloc}{p.path}")
        if len(out) >= MAX_PAGES:
            break
    return out


def inventory_page(ctx: Ctx, s: requests.Session, display: str) -> dict | None:
    url = ctx.to_tool_url(display)
    r = s.get(url, timeout=12, allow_redirects=True)
    if "html" not in r.headers.get("content-type", "").lower():
        return None
    p = _Scripts()
    try:
        p.feed(r.text[:2_000_000])
    except Exception:  # noqa: BLE001
        return None
    scripts = {}
    for sc in p.external:
        full = urljoin(r.url, sc["src"])
        host = urlsplit(full).hostname or ""
        same = web.in_scope_host(ctx, host)
        digest = ""
        if same:
            try:
                digest = _sha(s.get(full, timeout=12).content)
            except requests.RequestException:
                digest = "unreachable"
        scripts[ctx.to_display_url(full)] = {"external": not same, "integrity": bool(sc["integrity"]), "sha256": digest}
    return {"status": r.status_code, "scripts": scripts, "inline": sorted(p.inline),
            "headers": {h: r.headers[h] for h in HEADERS if h in r.headers},
            "payment": bool(p.card_fields), "login": bool(p.password_fields)}


def run(ctx: Ctx) -> None:
    entries = ctx.state.get("all_web_urls") or web.web_urls(ctx)
    if not entries:
        ctx.state["pages_skipped"] = True
        ctx.progress(100, "No web application found")
        return
    s = web._session()
    inv: dict[str, dict] = {}
    for i, entry in enumerate(entries):
        ctx.check()
        ctx.progress(5 + 90 * i // len(entries), f"Recording scripts and headers of {entry}")
        for display in candidates(ctx, entry):
            ctx.check()
            try:
                page = inventory_page(ctx, s, display)
            except requests.RequestException as e:
                ctx.log(f"[pages] {display}: {e}")
                continue
            if page:
                inv[display] = page
    ctx.state["page_inventory"] = inv
    report(ctx, inv)
    ctx.progress(100, f"{plural(len(inv), 'page')} inventoried")


def report(ctx: Ctx, inv: dict[str, dict]) -> None:
    by_port: dict[int, list] = {}
    for url, page in inv.items():
        by_port.setdefault(ctx.url_port(url), []).append((url, page))
    for port, pages in sorted(by_port.items()):
        scripts = {src: meta for _, pg in pages for src, meta in pg["scripts"].items()}
        lines = [f"{len(pages)} page(s) sampled, {len(scripts)} script file(s), "
                 f"{sum(len(pg['inline']) for _, pg in pages)} inline script block(s)"]
        lines += [f"{'external' if m['external'] else 'same-site'}  {'SRI' if m['integrity'] else 'no-SRI'}  {src}"
                  for src, m in sorted(scripts.items())][:60]
        ctx.findings.append(findings.make(
            "pages", "script_inventory", ctx.component, "Script inventory of sampled pages", port=port, service="http",
            evidence="\n".join(lines), rule_id="script-inventory",
            description="Scripts loaded by the sampled pages. Compare with the authorized script inventory; "
                        "OpenASV reports differences on the next scan."))
        for url, pg in pages:
            missing = sorted(src for src, m in pg["scripts"].items() if m["external"] and not m["integrity"])
            if missing:
                where = "payment page" if pg["payment"] else "page"
                ctx.findings.append(findings.make(
                    "pages", "script_no_integrity_payment" if pg["payment"] else "script_no_integrity", ctx.component,
                    f"External script without Subresource Integrity on a {where}", port=port, url=url, service="http",
                    evidence="\n".join(missing[:20]), rule_id="script-no-sri",
                    description="Scripts loaded from another origin carry no integrity attribute, so a change at the "
                                "source would run unnoticed in the consumer's browser."))
            if pg["login"] and urlsplit(url).scheme == "https":
                ctx.findings.append(findings.make(
                    "pages", "auth_interface", ctx.component, "Login form reachable from the Internet", port=port,
                    url=url, service="http", evidence="Password field present", rule_id="login-exposed",
                    description="If personnel or administrators sign in here, confirm that multi-factor "
                                "authentication and account lockout are enforced. Consumer accounts are outside "
                                "PCI DSS Requirement 8."))
