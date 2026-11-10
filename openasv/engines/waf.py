"""Web application firewall detection (wafw00f). Presence is evidence for PCI DSS 6.4.1 / 6.4.2; absence of a
fingerprint is only an indicator, because a well-tuned WAF may not reveal itself."""
from __future__ import annotations

import json

from .. import config, findings
from . import web
from .base import Ctx, EngineError, command, plural, run_cmd


def run(ctx: Ctx) -> None:
    urls = ctx.state.get("all_web_urls") or web.web_urls(ctx)
    if not urls:
        ctx.state["waf_skipped"] = True
        ctx.progress(100, "No web application found")
        return
    exe = config.settings.wafw00f
    if not command(exe):
        raise EngineError(f"'{exe}' is not installed; web application firewall detection was skipped")
    for i, display in enumerate(urls):
        ctx.check()
        ctx.progress(5 + 90 * i // len(urls), f"Looking for a web application firewall at {display}")
        out = ctx.run_dir / f"wafw00f_{ctx.target.host}_{ctx.url_port(display)}.json"
        out.unlink(missing_ok=True)
        run_cmd(ctx, [exe, "-a", "-T", "10", "--no-colors", "-f", "json", "-o", str(out), ctx.to_tool_url(display)],
                timeout=240, label="wafw00f", env={"HTTP_PROXY": "", "HTTPS_PROXY": "", "http_proxy": "", "https_proxy": ""})
        rows = json.loads(out.read_text(encoding="utf-8") or "[]") if out.exists() else []
        parse(rows, ctx, display, out.name)
    ctx.progress(100, f"{plural(len(urls), 'web endpoint')} checked")


def parse(rows: list[dict], ctx: Ctx, display: str, raw_name: str = "wafw00f.json") -> None:
    port = ctx.url_port(display)
    names = sorted({f"{r.get('firewall')} ({r.get('manufacturer')})" if r.get("manufacturer") else str(r.get("firewall"))
                    for r in rows if r.get("detected") and r.get("firewall") not in (None, "", "None")})
    ctx.state.setdefault("waf", {})[display] = names
    if names:
        ctx.findings.append(findings.make(
            "wafw00f", "waf_presence", ctx.component, "Web application firewall detected", port=port, url=display,
            service="http", evidence="; ".join(names), rule_id="waf-detected", raw_ref=raw_name,
            description="An automated technical solution appears to be deployed in front of the web application. "
                        "Confirm that it is in blocking mode, kept up to date and generating audit logs."))
    else:
        ctx.findings.append(findings.make(
            "wafw00f", "waf_presence", ctx.component, "No web application firewall detected", port=port, url=display,
            service="http", evidence="No known WAF fingerprint and no generic blocking behaviour observed.",
            rule_id="waf-not-detected", raw_ref=raw_name, potential=True,
            description="No web application firewall was identified in front of this public-facing web application. "
                        "This is an indicator only: confirm how web-based attacks are continually detected and "
                        "prevented."))
