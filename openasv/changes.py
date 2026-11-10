"""What changed on the external attack surface since the previous scan of the same scope.

Compares the service inventory and the page script / header inventory of two scans. Only hosts and pages present
in both scans are compared, so a partial rescan never reports the untested remainder as removed."""
from __future__ import annotations

from urllib.parse import urlsplit

from . import db, findings


def previous_scan(scan: dict) -> dict | None:
    rows = db.q("SELECT id FROM scans WHERE scope_id=? AND id<? AND status='completed' AND report_type!='imported' "
                "ORDER BY id DESC LIMIT 10", (scan["scope_id"], scan["id"]))
    for r in rows:
        s = db.scan(r["id"])
        if (s["meta"].get("inventory") or {}).get("services"):
            return s
    return None


def compare(old: dict, new: dict) -> dict:
    services, pages = [], []
    for host, now in sorted((new.get("services") or {}).items()):
        before = (old.get("services") or {}).get(host)
        if before is None:
            continue
        a, b = {x.split(" ")[0]: x for x in before}, {x.split(" ")[0]: x for x in now}   # key: "443/tcp"
        added, removed = sorted(b[k] for k in set(b) - set(a)), sorted(a[k] for k in set(a) - set(b))
        if added or removed:
            services.append({"host": host, "added": added, "removed": removed})
    for url, now in sorted((new.get("pages") or {}).items()):
        before = (old.get("pages") or {}).get(url)
        if before is None:
            continue
        a, b = before.get("scripts", {}), now.get("scripts", {})
        d = {"url": url,
             "scripts_added": sorted(set(b) - set(a)), "scripts_removed": sorted(set(a) - set(b)),
             "scripts_changed": sorted(k for k in set(a) & set(b) if (a[k].get("sha256"), a[k].get("integrity"))
                                       != (b[k].get("sha256"), b[k].get("integrity"))),
             "inline_added": len(set(now.get("inline", [])) - set(before.get("inline", []))),
             "inline_removed": len(set(before.get("inline", [])) - set(now.get("inline", []))),
             "headers_changed": sorted(h for h in set(before.get("headers", {})) | set(now.get("headers", {}))
                                       if before.get("headers", {}).get(h) != now.get("headers", {}).get(h)),
             "payment": bool(now.get("payment"))}
        if any(d[k] for k in d if k not in ("url", "payment")):
            pages.append(d)
    return {"services": services, "pages": pages}


def to_findings(diff: dict, since: int) -> list[dict]:
    out = []
    for s in diff["services"]:
        lines = [f"+ {x}" for x in s["added"]] + [f"- {x}" for x in s["removed"]]
        out.append(findings.make(
            "changes", "service_change", s["host"], f"Exposed services changed since scan #{since}",
            evidence="\n".join(lines), rule_id="service-change",
            description="The set of services reachable from the Internet differs from the previous scan. Confirm that "
                        "each new service is approved and has a business need."))
    for p in diff["pages"]:
        lines = ([f"+ script {x}" for x in p["scripts_added"]] + [f"- script {x}" for x in p["scripts_removed"]]
                 + [f"~ script content or integrity changed: {x}" for x in p["scripts_changed"]]
                 + ([f"+ {p['inline_added']} inline script block(s)"] if p["inline_added"] else [])
                 + ([f"- {p['inline_removed']} inline script block(s)"] if p["inline_removed"] else [])
                 + [f"~ header {h}" for h in p["headers_changed"]])
        u = urlsplit(p["url"])
        out.append(findings.make(
            "changes", "page_change", u.hostname or p["url"],
            f"{'Payment page' if p['payment'] else 'Page'} scripts or security headers changed since scan #{since}",
            port=u.port or (443 if u.scheme == "https" else 80), url=p["url"], service="http",
            evidence="\n".join(lines[:60]), rule_id="page-change",
            description="Scripts or security-impacting HTTP headers differ from the previous scan. Confirm that every "
                        "change was authorized."))
    return out
