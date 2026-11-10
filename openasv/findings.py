"""Normalised finding model, classification and CVSS resolution."""
from __future__ import annotations

import hashlib
import re
from functools import lru_cache
from urllib.parse import urlsplit

from . import config, cvss, redact


@lru_cache(maxsize=1)
def _keyword_rules():
    return [(re.compile(rx, re.I), cat) for rx, cat in config.policy()["classification"]["keywords"]]


def classify(*, rule_map: dict | None = None, rule_id: str = "", cwe: list[str] | None = None,
             title: str = "", default: str = "other_web") -> str:
    """Rule id -> CWE -> keyword -> default."""
    if rule_map and str(rule_id) in rule_map:
        return rule_map[str(rule_id)]
    cmap = config.policy()["classification"]["cwe"]
    for c in cwe or []:
        n = str(c).upper().replace("CWE-", "")
        if n in cmap:
            return cmap[n]
    for rx, cat in _keyword_rules():
        if rx.search(title or ""):
            return cat
    return default


def _key(*parts) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:14]


def _norm_cwe(items) -> list[str]:
    out = []
    for c in items or []:
        s = str(c).strip().upper()
        if not s or s in ("-1", "0", "CWE-0", "CWE--1", "NVD-CWE-OTHER", "NVD-CWE-NOINFO"):
            continue
        out.append(s if s.startswith("CWE-") else f"CWE-{s}")
    return sorted(set(out))


def make(engine: str, category: str, component: str, title: str, *, port: int | None = None,
         protocol: str = "tcp", service: str = "", description: str = "", evidence: str = "",
         url: str = "", method: str = "", param: str = "", attack: str = "",
         cvss_score: float | None = None, cvss_vector: str | None = None, severity_hint: str | None = None,
         cve: list[str] | None = None, cwe: list[str] | None = None, references: list[str] | None = None,
         remediation: str = "", engine_solution: str = "", rule_id: str = "", raw_ref: str = "",
         confidence: str = "", potential: bool | None = None, extra: dict | None = None,
         cvss_source: str | None = None) -> dict:
    cats = config.policy()["categories"]
    if category not in cats:
        category = "other_web"
    cat = cats[category]

    source, vector, score = None, None, 0.0
    if cvss_score is not None:
        score, vector, source = float(cvss_score), cvss_vector, cvss_source or "nvd"
    elif cat.get("vector"):
        vector, source = cat["vector"], "policy"
        score = cvss.base_score(vector)
    elif severity_hint and config.policy()["risk_fallback"].get(severity_hint.lower()):
        vector, source = config.policy()["risk_fallback"][severity_hint.lower()], "engine"
        score = cvss.base_score(vector)
    elif cat.get("informational"):
        source = "n/a"
    else:
        source = "engine"

    path = urlsplit(url).path if url else ""
    return {
        "key": _key(engine, category, component, port, rule_id or title, path, param),
        "group_key": _key(engine, category, component, port, rule_id or title),
        "engine": engine,
        "category": category,
        "category_title": cat.get("title", category),
        "component": component,
        "port": port,
        "protocol": protocol,
        "service": service,
        "title": redact.mask(title),
        "description": redact.mask(description or "")[:2500],
        "evidence": redact.mask(evidence or "")[:2000],
        "url": redact.mask(url or ""),
        "method": method,
        "param": redact.mask(param or ""),
        "attack": redact.mask(attack or "")[:400],
        "instances": [],
        "cvss_score": round(score, 1),
        "cvss_vector": vector,
        "cvss_source": source,
        "severity": cvss.asv_severity(score),
        "auto_fail": bool(cat.get("auto_fail")),
        "dos_exempt": bool(cat.get("dos_exempt")),
        "informational": bool(cat.get("informational")),
        "potential": bool(cat.get("potential")) if potential is None else potential,
        "special_note": cat.get("special_note"),
        "cve": sorted({c.upper() for c in cve or [] if c}),
        "cwe": _norm_cwe(cwe),
        "references": [r for r in (references or []) if isinstance(r, str)][:8],
        "remediation": remediation or cat.get("remediation", ""),
        "engine_solution": redact.mask(engine_solution or "")[:1200],
        "pci": [dict(x) for x in cat.get("pci") or []],
        "rule_id": str(rule_id),
        "raw_ref": raw_ref,
        "confidence": confidence,
        "extra": extra or {},
    }


def _fails(f: dict) -> bool:
    if f["informational"] or f["dos_exempt"]:
        return False
    return f["auto_fail"] or f["cvss_score"] >= 4.0


def consolidate(findings: list[dict]) -> list[dict]:
    """De-duplicate. Failing findings stay one-per-instance (disputes are per URL/parameter, as ASVs require);
    passing web findings of the same rule are grouped with an instance list to keep reports readable."""
    gcfg = config.policy().get("grouping", {})
    group = gcfg.get("group_passing_web_findings", True)
    merge = set(gcfg.get("merge_across_engines") or [])
    out: dict[str, dict] = {}
    for f in findings:
        if f["category"] in merge:
            k = _key("merged", f["category"], f["component"], f["port"])
        else:
            k = f["group_key"] if (group and f["url"] and not _fails(f)) else f["key"]
        inst = {"url": f["url"], "method": f["method"], "param": f["param"], "attack": f["attack"],
                "evidence": f["evidence"][:300]}
        if k not in out:
            f = dict(f)
            f["key"] = k
            f["instances"] = [inst] if f["url"] else []
            out[k] = f
            continue
        cur = out[k]
        if f["engine"] not in cur["engine"].split(" + "):
            cur["engine"] = f"{cur['engine']} + {f['engine']}"
            if f["evidence"] and f["evidence"] not in cur["evidence"]:
                cur["evidence"] = (cur["evidence"] + "\n" + f["evidence"])[:2000]
        if f["url"] and len(cur["instances"]) < 50 and inst not in cur["instances"]:
            cur["instances"].append(inst)
        if f["cvss_score"] > cur["cvss_score"]:
            for fld in ("cvss_score", "cvss_vector", "cvss_source", "severity"):
                cur[fld] = f[fld]
        cur["cve"] = sorted(set(cur["cve"]) | set(f["cve"]))
    return list(out.values())
