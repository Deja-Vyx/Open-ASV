"""CVSS v3.1 base score calculator (FIRST specification, section 7.1 + Appendix A roundup)."""
from __future__ import annotations

import math

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if parts and parts[0].startswith("CVSS:"):
        parts = parts[1:]
    m = {}
    for p in parts:
        if ":" not in p:
            raise ValueError(f"bad CVSS component {p!r}")
        k, v = p.split(":", 1)
        m[k] = v
    missing = [k for k in _REQUIRED if k not in m]
    if missing:
        raise ValueError(f"CVSS vector missing {missing}")
    return m


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    scope = m["S"]
    iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[scope][m["PR"]] * _W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + expl, 10))
    return _roundup(min(1.08 * (impact + expl), 10))


def asv_severity(score: float) -> str:
    """Severity bands used in ASV scan reports: Low 0.0-3.9, Medium 4.0-6.9, High 7.0-10.0."""
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"
