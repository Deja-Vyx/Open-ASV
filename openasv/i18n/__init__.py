"""Interface translation.

English is the source language. Templates are written in plain English; the :class:`AutoTranslate` Jinja extension
wraps every static text node (and a few attributes) in ``_()`` when a template is compiled, and pipes every
expression printed as page text through the catalogue, so labels that come from Python or the policy files are translated
too. A catalogue is a JSON object ``{"English text": "translation"}``; keys may contain ``{0}``, ``{1}`` … for
variable parts. Text without a catalogue entry is shown in English.
"""
from __future__ import annotations

import html
import json
import re
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path

from jinja2.ext import Extension

LANGUAGES = {"en": "English", "vi": "Tiếng Việt"}
DEFAULT = "en"
_lang: ContextVar[str] = ContextVar("openasv_lang", default=DEFAULT)
_DIR = Path(__file__).resolve().parent


class Translated(str):
    """A string that already went through the catalogue."""


def set_lang(code: str | None) -> str:
    code = code if code in LANGUAGES else DEFAULT
    _lang.set(code)
    return code


def get_lang() -> str:
    return _lang.get()


@lru_cache(maxsize=None)
def catalogue(lang: str) -> tuple[dict, list]:
    p = _DIR / f"{lang}.json"
    exact = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    patterns = []
    for k, v in exact.items():
        if re.search(r"\{\d\}", k):
            rx = re.escape(k)
            rx = re.sub(r"\\\{(\d)\\\}", lambda m: f"(?P<g{m.group(1)}>.+?)", rx)
            patterns.append((re.compile(f"^{rx}$", re.S), v))
    return exact, patterns


@lru_cache(maxsize=8192)
def _lookup(text: str, lang: str) -> str:
    exact, patterns = catalogue(lang)
    hit = exact.get(text)
    if hit is not None:
        return hit
    if len(text) < 300 and (" " in text or any(c.isdigit() for c in text)):
        for rx, tpl in patterns:
            m = rx.match(text)
            if m:
                return _fill(tpl, m.groupdict(), lang)
    return text


def _fill(tpl: str, groups: dict, lang: str) -> str:
    return re.sub(r"\{(\d)\}", lambda g: _lookup(groups.get("g" + g.group(1), ""), lang), tpl)


def translate(text: str, *args) -> Translated:
    lang = get_lang()
    out = text if lang == DEFAULT else _lookup(text, lang)
    if args:
        out = out.format(*args)
    return Translated(out)


def translate_value(value):
    """Jinja filter applied to every expression printed as page text (never inside tags or attributes), so labels
    that come from Python or the policy files are translated as well."""
    if type(value) is str and value and get_lang() != DEFAULT and len(value) < 700:
        return _lookup(value, get_lang())
    return value


# ---------------------------------------------------------------------------- template preprocessing
_ATTRS = re.compile(r'\b(placeholder|title|aria-label|data-confirm|alt)="([^"{}<>]*[A-Za-z]{2}[^"{}<>]*)"')
_HAS_WORD = re.compile(r"[^\W\d_]{2}")
_SKIP_CONTENT = ("script", "style", "textarea")
_EXPR = re.compile(r"^\{\{(-?)(.*?)(-?)\}\}$", re.S)


def _literal(s: str) -> str:
    return json.dumps(s, ensure_ascii=True)


def _tokens(src: str):
    """Yield (kind, text) with kind in {'jinja', 'tag', 'text'}."""
    i, n, buf = 0, len(src), []
    closers = {"{{": "}}", "{%": "%}", "{#": "#}"}
    while i < n:
        two = src[i:i + 2]
        if two in closers:
            if buf:
                yield "text", "".join(buf)
                buf = []
            j = src.find(closers[two], i + 2)
            j = n if j < 0 else j + 2
            yield "jinja", src[i:j]
            i = j
        elif src[i] == "<" and i + 1 < n and (src[i + 1].isalpha() or src[i + 1] in "/!"):
            if buf:
                yield "text", "".join(buf)
                buf = []
            j = i + 1
            while j < n and src[j] != ">":
                if src[j:j + 2] in closers:
                    k = src.find(closers[src[j:j + 2]], j + 2)
                    j = n if k < 0 else k + 2
                else:
                    j += 1
            yield "tag", src[i:j + 1]
            i = j + 1
        else:
            buf.append(src[i])
            i += 1
    if buf:
        yield "text", "".join(buf)


def wrap_source(src: str, collect: set | None = None) -> str:
    out, skip = [], None
    for kind, tok in _tokens(src):
        if kind == "tag":
            name = re.match(r"</?\s*([a-zA-Z0-9]+)", tok)
            name = name.group(1).lower() if name else ""
            if skip:
                if tok.startswith("</") and name == skip:
                    skip = None
            elif (name in _SKIP_CONTENT or 'translate="no"' in tok) and not tok.startswith("</") and not tok.endswith("/>"):
                skip = name

            def attr(m):
                val = html.unescape(m.group(2))
                if collect is not None:
                    collect.add(val)
                return f'{m.group(1)}="{{{{ _({_literal(val)}) }}}}"'
            out.append(_ATTRS.sub(attr, tok))
        elif kind == "text" and not skip and _HAS_WORD.search(tok):
            core = tok.strip()
            lead, trail = tok[:len(tok) - len(tok.lstrip())], tok[len(tok.rstrip()):]
            key = html.unescape(" ".join(core.split()))
            if collect is not None:
                collect.add(key)
            out.append(f"{lead}{{{{ _({_literal(key)}) }}}}{trail}")
        elif kind == "jinja" and not skip and tok.startswith("{{"):
            m = _EXPR.match(tok)
            out.append(f"{{{{{m.group(1)} ({m.group(2).strip()})|tr {m.group(3)}}}}}" if m else tok)
        else:
            out.append(tok)
    return "".join(out)


class AutoTranslate(Extension):
    def preprocess(self, source, name, filename=None):
        return wrap_source(source) if (name or "").endswith(".html") else source


def template_strings(template_dir: Path) -> dict[str, set]:
    found: dict[str, set] = {}
    for p in sorted(template_dir.glob("*.html")):
        keys: set = set()
        wrap_source(p.read_text(encoding="utf-8"), keys)
        found[p.name] = keys
    return found
