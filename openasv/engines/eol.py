"""End-of-life detection from service banners and OS fingerprints (endoflife.date data)."""
from __future__ import annotations

import datetime as dt
import json
import re
from functools import lru_cache
from pathlib import Path

from .. import config, findings
from .base import Ctx

SNAPSHOT = Path(__file__).resolve().parent.parent / "data" / "eol.json"

# banner product (lowercase, regex) -> endoflife.date product key
ALIASES = [
    (r"^nginx$", "nginx"), (r"^apache( httpd)?$|^apache-http-server$|^httpd$", "apache-http-server"),
    (r"tomcat|coyote", "tomcat"), (r"^php$", "php"), (r"^python$|^cpython$", "python"),
    (r"^node(\.js|js)?$|^express$", "nodejs"), (r"^openssl$", "openssl"), (r"^mysql$", "mysql"),
    (r"^mariadb$", "mariadb"), (r"^postgresql( db)?$", "postgresql"), (r"^mongodb$", "mongodb"),
    (r"^redis( key-value store)?$", "redis"), (r"^elasticsearch", "elasticsearch"), (r"^haproxy", "haproxy"),
    (r"^exim", "exim"), (r"^postfix", "postfix"), (r"^wordpress$", "wordpress"), (r"^drupal$", "drupal"),
    (r"^joomla", "joomla"), (r"^jquery$", "jquery"), (r"^jenkins$", "jenkins"), (r"^grafana$", "grafana"),
    (r"^kibana$", "kibana"), (r"^rabbitmq", "rabbitmq"), (r"^memcached$", "memcached"), (r"^squid", "squid"),
    (r"^jetty$", "eclipse-jetty"), (r"^magento$", "magento"), (r"^openvpn", "openvpn"), (r"^zabbix", "zabbix"),
    (r"^gitlab", "gitlab"), (r"^asp\.net$", "dotnet"), (r"^django$", "django"), (r"^ruby$", "ruby"),
]
IIS_TO_WINDOWS = {"7.0": "2008", "7.5": "2008-r2", "8.0": "2012", "8.5": "2012-r2"}


@lru_cache(maxsize=1)
def data() -> dict:
    p = config.settings.data_dir / "eol.json"
    src = p if p.exists() else SNAPSHOT
    return json.loads(src.read_text(encoding="utf-8"))


def product_key(product: str, cpes: list[str] | None = None) -> str | None:
    prods = data()["products"]
    for c in cpes or []:
        vp = ":".join(c.replace("cpe:2.3:", "cpe:/").split(":")[1:4])  # e.g. /a:apache:http_server
        for k, p in prods.items():
            for pc in p.get("cpes", []):
                if ":".join(pc.replace("cpe:2.3:", "cpe:/").split(":")[1:4]) == vp:
                    return k
    low = (product or "").strip().lower()
    for rx, key in ALIASES:
        if re.search(rx, low):
            return key
    return None


def match_cycle(key: str, version: str) -> dict | None:
    cycles = data()["products"].get(key, {}).get("cycles", [])
    best = None
    for c in cycles:
        cyc = c["cycle"]
        if version == cyc or version.startswith(cyc + ".") or (re.match(r"^\d+$", cyc) and version.split(".")[0] == cyc):
            if best is None or len(cyc) > len(best["cycle"]):
                best = c
    return best


def is_eol(cycle: dict, today: dt.date | None = None) -> tuple[bool, str]:
    today = today or dt.date.today()
    eol = cycle.get("eol")
    if eol is True:
        return True, "end of life"
    if isinstance(eol, str):
        try:
            d = dt.date.fromisoformat(eol[:10])
            return d <= today, f"end of life since {d.isoformat()}" if d <= today else f"supported until {d.isoformat()}"
        except ValueError:
            return False, eol
    return False, "supported"


def evaluate_banner(product: str, version: str, cpes=None) -> dict | None:
    if product.lower().startswith("microsoft-iis") or product.lower() in ("iis", "microsoft iis httpd"):
        win = IIS_TO_WINDOWS.get(".".join(version.split(".")[:2]))
        if not win:
            return None
        key, cyc = "windows-server", next((c for c in data()["products"]["windows-server"]["cycles"]
                                            if c["cycle"] == win), None)
        version = f"IIS {version} (Windows Server {win})"
    else:
        key = product_key(product, cpes)
        if not key or not version:
            return None
        cyc = match_cycle(key, version)
    if not cyc:
        return None
    eol, why = is_eol(cyc)
    return {"key": key, "title": data()["products"][key]["title"], "version": version, "cycle": cyc["cycle"],
            "eol": eol, "why": why, "latest": cyc.get("latest"), "supported": supported_cycles(key)}


def supported_cycles(key: str, limit: int = 3) -> list[str]:
    return [c["cycle"] for c in data()["products"][key]["cycles"] if not is_eol(c)[0]][:limit]


def run(ctx: Ctx) -> None:
    seen = set()
    items = list(ctx.state.get("banners", []))
    for o in ctx.state.get("os", []):
        if o["accuracy"] >= 95:
            for c in o["cpe"]:
                parts = c.split(":")
                if len(parts) >= 4 and parts[1] == "/o":
                    items.append({"product": parts[3], "version": parts[4] if len(parts) > 4 else "", "cpe": [c],
                                  "port": None, "source": f"OS fingerprint {o['name']}"})
    for b in items:
        version = (b.get("version") or "").strip()
        r = evaluate_banner(b.get("product", ""), version, b.get("cpe"))
        if not r:
            continue
        b["eol_key"] = r["key"]
        sig = (r["key"], r["cycle"], b.get("port"))
        if sig in seen or not r["eol"]:
            continue
        seen.add(sig)
        ctx.findings.append(findings.make(
            "eol", "unsupported_software", ctx.component, f"Unsupported {r['title']} {r['cycle']} ({r['why']})",
            port=b.get("port"), evidence=f"{b.get('product')} {version} — detected via {b.get('source')}",
            description=f"{r['title']} {r['cycle']} no longer receives security updates. Data: endoflife.date "
                        f"(snapshot {data().get('generated', '?')}).",
            remediation=f"Upgrade {r['title']} {r['cycle']} to a supported release line"
                        + (f" (currently supported: {', '.join(r['supported'])})" if r.get("supported") else "") + "."
                        + (f" {r['latest']}, the final {r['cycle']} release, is also unsupported." if r.get("latest") else ""),
            rule_id=f"eol-{r['key']}-{r['cycle']}", potential=True, references=[f"https://endoflife.date/{r['key']}"]))
    ctx.progress(100, "End-of-life analysis complete")
