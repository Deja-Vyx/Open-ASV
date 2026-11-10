"""Nuclei: template-based detection of known CVEs, misconfigurations, exposures and default logins."""
from __future__ import annotations

import json
from pathlib import Path

from .. import config, findings
from .base import Ctx, EngineError, run_cmd

TAG_CATEGORIES = [
    ("default-login", "default_account"), ("backdoor", "backdoor"), ("webshell", "backdoor"),
    ("sqli", "sql_injection"), ("xss", "xss"), ("lfi", "path_traversal"), ("traversal", "path_traversal"),
    ("crlf", "header_injection"), ("eol", "unsupported_software"), ("zone-transfer", "dns_zone_transfer"),
    ("axfr", "dns_zone_transfer"), ("pan", "pan_in_response"), ("dos", "dos_only"),
    ("listing", "directory_listing"), ("cve", "known_cve"), ("exposure", "sensitive_exposure"),
    ("misconfig", "sensitive_exposure"), ("config", "sensitive_exposure"),
]


def luhn(d: str) -> bool:
    digits = [int(c) for c in d if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    s = 0
    for i, n in enumerate(reversed(digits)):
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        s += n
    return s % 10 == 0


def targets(ctx: Ctx) -> list[str]:
    out = [ctx.to_tool_url(u) for u in ctx.target.web_urls]
    seen = {ctx.url_port(u) for u in ctx.target.web_urls}
    for s in ctx.state.get("services", []):
        if s["proto"] != "tcp" or s["port"] in seen:
            continue
        if s["web"]:
            out.append(f"{'https' if s['tls'] else 'http'}://{ctx.target.tool_host}:{s['port']}/")
        else:
            out.append(f"{ctx.target.tool_host}:{s['port']}")
    return out


def run(ctx: Ctx) -> None:
    s = config.settings
    cfg = ctx.profile.get("nuclei") or {}
    tl = targets(ctx)
    if not tl:
        ctx.progress(100, "No services to test")
        return
    lst = ctx.run_dir / f"nuclei_targets_{ctx.component}.txt".replace(":", "_")
    lst.write_text("\n".join(tl) + "\n", encoding="utf-8")
    out = ctx.run_dir / f"nuclei_{ctx.component}.jsonl".replace(":", "_")
    out.unlink(missing_ok=True)
    args = [s.nuclei, "-l", str(lst), "-jsonl", "-o", str(out), "-nc", "-duc", "-silent", "-rl", str(cfg.get("rate_limit", 100)), "-c", str(cfg.get("concurrency", 25)),
            "-timeout", "10", "-retries", "1", "-mhe", "15",
            "-severity", ",".join(cfg.get("severity") or ["low", "medium", "high", "critical"])]
    if cfg.get("exclude_tags"):
        args += ["-etags", ",".join(cfg["exclude_tags"])]
    if cfg.get("tags"):
        args += ["-tags", ",".join(cfg["tags"])]
    if not s.nuclei_interactsh:
        args.append("-ni")
    custom = s.config_dir / "nuclei"
    has_custom = custom.is_dir() and any(custom.glob("*.yaml"))
    if s.nuclei_templates or has_custom:
        # an explicit -t replaces nuclei's default template set, so name it whenever custom templates are added
        args += ["-t", s.nuclei_templates or str(Path.home() / "nuclei-templates")]
    if has_custom:
        args += ["-t", str(custom)]
    args += ["-stats", "-sj", "-si", "10"]
    ctx.progress(5, f"Running templates against {len(tl)} service(s)")

    def stats(line: str) -> bool:
        if not line.startswith("{") or '"percent"' not in line:
            return False
        try:
            st = json.loads(line)
            pct = int(float(st.get("percent", 0)))
            ctx.progress(5 + pct * 9 // 10, f"{pct}% of {st.get('total', '?')} requests, "
                                            f"{st.get('templates', '?')} templates, {st.get('matched', 0)} matched")
        except (ValueError, TypeError):
            return False
        return True

    rc = run_cmd(ctx, args, timeout=3 * 3600, label="nuclei", on_line=stats)
    if rc not in (0, 1) and not out.exists():
        raise EngineError(f"nuclei exited with code {rc}")
    if out.exists():
        parse(out, ctx)
    ctx.progress(100, "Templates complete")


def _list(v) -> list[str]:
    if not v:
        return []
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    return [str(x) for x in v]


def parse(path: Path, ctx: Ctx) -> None:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = r.get("info") or {}
        sev = str(info.get("severity", "info")).lower()
        tags = [t.lower() for t in _list(info.get("tags"))]
        cl = info.get("classification") or {}
        cves = [c.upper() for c in _list(cl.get("cve-id"))]
        cwes = _list(cl.get("cwe-id"))
        score = cl.get("cvss-score")
        name = info.get("name") or r.get("template-id", "Nuclei finding")
        cat = next((c for t, c in TAG_CATEGORIES if t in tags), None)
        if cat in (None, "sensitive_exposure", "known_cve", "directory_listing"):
            c2 = findings.classify(cwe=cwes, title=name, default="")
            if c2 and c2 not in ("other_web", "info_disclosure"):
                cat = c2
        if cat is None:
            if sev == "info" and not cves:
                if "tech" in tags:
                    _tech(ctx, r, info)
                continue
            cat = "known_cve" if cves else "other_web"
        extracted = [str(x) for x in r.get("extracted-results") or []]
        if cat == "pan_in_response":
            extracted = [x[:6] + "*" * (len(x) - 10) + x[-4:] for x in extracted if luhn(x)]
            if not extracted:
                continue
        matched = r.get("matched-at") or r.get("host") or ""
        url = ctx.to_display_url(matched) if "://" in matched else ""
        port = ctx.url_port(url) if url else _port(matched)
        refs = _list(info.get("reference"))
        ctx.findings.append(findings.make(
            "nuclei", cat, ctx.component, name, port=port, url=url,
            description=str(info.get("description", "")),
            evidence=", ".join(extracted)[:500] if extracted else str(r.get("matcher-name", "") or matched),
            cvss_score=float(score) if score not in (None, "", 0, 0.0) else None, cvss_vector=cl.get("cvss-metrics"),
            severity_hint=sev, cve=cves, cwe=cwes, references=refs, remediation=str(info.get("remediation", "") or ""),
            rule_id=f"nuclei-{r.get('template-id', '')}", raw_ref=f"{path.name}#{r.get('template-id', '')}",
            extra={"template": r.get("template-id"), "tags": tags, "nuclei_severity": sev}))
        if cat == "directory_listing":
            ctx.note("directory_browsing", f"{name} at {url or matched}", port, "nuclei")


def _port(hostport: str) -> int | None:
    try:
        return int(hostport.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return None


def _tech(ctx: Ctx, r: dict, info: dict) -> None:
    """Keep technology fingerprints (with versions) for EOL / NVD analysis."""
    for x in r.get("extracted-results") or []:
        s = str(x)
        if "/" in s:
            prod, _, ver = s.partition("/")
            ctx.state.setdefault("banners", []).append({"product": prod, "version": ver.split()[0], "cpe": [],
                                                       "port": None, "source": "nuclei"})
