"""Version-based CVE correlation through the NVD CVE API 2.0 (optional, cached)."""
from __future__ import annotations

import hashlib
import json
import re
import time

import requests

from .. import config, findings
from . import eol
from .base import Ctx

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DAYS = 7
MAX_PER_PRODUCT = 25
_last_call = [0.0]


def cpe_for(banner: dict) -> str | None:
    m = re.match(r"\d+(?:\.\d+)*", (banner.get("version") or "").strip())
    if not m:
        return None
    version = m.group(0)
    key = banner.get("eol_key") or eol.product_key(banner.get("product", ""), banner.get("cpe"))
    if key:
        for c in eol.data()["products"].get(key, {}).get("cpes", []):
            if c.startswith("cpe:2.3:"):
                part, vendor, product = c.split(":")[2:5]
                return f"cpe:2.3:{part}:{vendor}:{product}:{version}"
    for c in banner.get("cpe") or []:
        if c.startswith("cpe:/"):
            parts = c[5:].split(":")
            if len(parts) >= 3:
                return f"cpe:2.3:{parts[0]}:{parts[1]}:{parts[2]}:{parts[3] if len(parts) > 3 else version}"
    return None


def _cached_get(params: dict) -> dict:
    d = config.settings.data_dir / "cache" / "nvd"
    d.mkdir(parents=True, exist_ok=True)
    p = d / (hashlib.sha1(json.dumps(params, sort_keys=True).encode()).hexdigest() + ".json")
    if p.exists() and time.time() - p.stat().st_mtime < CACHE_DAYS * 86400:
        return json.loads(p.read_text())
    key = config.settings.nvd_api_key
    gap = 0.7 if key else 6.5
    wait = _last_call[0] + gap - time.time()
    if wait > 0:
        time.sleep(wait)
    s = requests.Session()
    s.headers["User-Agent"] = "OpenASV"
    if key:
        s.headers["apiKey"] = key
    r = s.get(API, params=params, timeout=40)
    _last_call[0] = time.time()
    r.raise_for_status()
    data = r.json()
    p.write_text(json.dumps(data))
    return data


def metric(cve: dict) -> tuple[float | None, str | None]:
    m = cve.get("metrics") or {}
    for k in ("cvssMetricV31", "cvssMetricV30"):
        rows = m.get(k) or []
        rows = sorted(rows, key=lambda r: r.get("type") != "Primary")
        if rows:
            d = rows[0]["cvssData"]
            return float(d["baseScore"]), d.get("vectorString")
    rows = m.get("cvssMetricV2") or []
    if rows:
        return float(rows[0]["cvssData"]["baseScore"]), rows[0]["cvssData"].get("vectorString")
    return None, None


def to_findings(ctx: Ctx, banner: dict, cpe: str, data: dict) -> int:
    rows = []
    for v in data.get("vulnerabilities", []):
        c = v.get("cve") or {}
        if c.get("vulnStatus") in ("Rejected",):
            continue
        score, vector = metric(c)
        if score is None:
            continue
        rows.append((score, vector, c))
    rows.sort(key=lambda r: -r[0])
    for score, vector, c in rows[:MAX_PER_PRODUCT]:
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        cwes = [d["value"] for w in c.get("weaknesses", []) for d in w.get("description", []) if d.get("value")]
        dos = vector and "/C:N/I:N/A:" in vector and "/A:N" not in vector
        cat = "dos_only" if dos else "vulnerable_component"
        ctx.findings.append(findings.make(
            "nvd", cat, ctx.component, f"{c['id']} in {banner.get('product')} {banner.get('version')}",
            port=banner.get("port"), cvss_score=score, cvss_vector=vector, cve=[c["id"]], cwe=cwes,
            description=desc, evidence=f"{banner.get('product')} {banner.get('version')} via {banner.get('source')}; {cpe}",
            references=[r["url"] for r in c.get("references", [])][:5], rule_id=f"nvd-{c['id']}",
            potential=True, extra={"cpe": cpe}))
    return min(len(rows), MAX_PER_PRODUCT)


def run(ctx: Ctx) -> None:
    if not config.settings.nvd_enabled:
        ctx.progress(100, "NVD correlation disabled")
        return
    seen, total = set(), 0
    banners = [b for b in ctx.state.get("banners", []) if b.get("version")]
    for i, b in enumerate(banners):
        ctx.check()
        cpe = cpe_for(b)
        if not cpe or cpe in seen:
            continue
        seen.add(cpe)
        ctx.progress(5 + 90 * i // max(1, len(banners)), f"NVD lookup {cpe}")
        try:
            data = _cached_get({"virtualMatchString": cpe, "resultsPerPage": 200})
        except requests.HTTPError as e:
            ctx.log(f"[nvd] {cpe}: {e}")
            continue
        except Exception as e:  # noqa: BLE001  network unreachable: stop instead of retrying every product
            pending = [x for x in banners[i:] if cpe_for(x)]
            ctx.state.setdefault("limitations", []).append(
                f"NVD API unreachable; version-based CVE correlation skipped for {len({cpe_for(x) for x in pending})} product(s)")
            ctx.log(f"[nvd] {e}")
            break
        total += to_findings(ctx, b, cpe, data)
    ctx.progress(100, f"{total} version-based CVE(s)")
