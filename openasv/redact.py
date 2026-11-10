"""Mask anything that looks like a valid PAN (Luhn) so the scanner never stores cardholder data (Req 3.3/3.4 spirit)."""
from __future__ import annotations

import re
from pathlib import Path

_CAND = re.compile(r"(?<!\d)(\d[ -]?){12,18}\d(?!\d)")


def _luhn(d: str) -> bool:
    s = 0
    for i, n in enumerate(int(c) for c in reversed(d)):
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        s += n
    return s % 10 == 0


def mask(text: str) -> str:
    def rep(m):
        raw = m.group(0)
        d = re.sub(r"\D", "", raw)
        if 13 <= len(d) <= 19 and _luhn(d):
            return d[:6] + "*" * (len(d) - 10) + d[-4:]
        return raw
    return _CAND.sub(rep, text)


def mask_files(folder: Path, suffixes=(".json", ".jsonl", ".xml", ".txt")) -> int:
    n = 0
    for p in folder.iterdir():
        if p.is_file() and p.suffix in suffixes:
            t = p.read_text(encoding="utf-8", errors="replace")
            m = mask(t)
            if m != t:
                p.write_text(m, encoding="utf-8")
                n += 1
    return n
