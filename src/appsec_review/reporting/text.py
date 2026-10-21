"""Bounding and escaping of untrusted text for the report renderers.

Everything that came from a model, a target or a tool is data. It is cleaned (control and format
characters removed), bounded, and then escaped for exactly one output language here; no renderer
writes a raw string from the run into its output.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import unicodedata
from typing import Any

from .model import Truncation

_NEWLINE = re.compile(r"\r\n|\r| | |\x0b|\x0c")
_SPACE_RUN = re.compile(r"[ \t\xa0]+")
_SAFE_TOKEN = re.compile(r"[^A-Za-z0-9._:-]+")
_TEX_SPECIAL = {
    "\\": r"\textbackslash{}", "{": r"\{", "}": r"\}", "$": r"\$", "&": r"\&", "#": r"\#",
    "^": r"\textasciicircum{}", "_": r"\_", "%": r"\%", "~": r"\textasciitilde{}",
    "<": r"\textless{}", ">": r"\textgreater{}", "|": r"\textbar{}", '"': r"\textquotedbl{}",
    "[": r"{[}", "]": r"{]}",
    "-": r"{-}",
}
# Break opportunities for long identifiers in the monospace face.
_BREAK_AFTER = set("/._:-=,;)]}>&?#@+")
_FONT_LIMIT = 0x2E80  # beyond this the bundled fonts have no glyphs; show the code point instead


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def sha256_value(value: Any) -> str:
    return sha256_text(canonical(value))


def clean(value: Any, *, keep_newlines: bool = False, code: bool = False) -> str:
    """Printable text only: control, format, surrogate and private-use characters are dropped.

    ``code`` keeps runs of spaces (indentation) and expands tabs to four spaces.
    """
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    text = _NEWLINE.sub("\n", text)
    out: list[str] = []
    for char in text:
        if char == "\n":
            out.append("\n" if keep_newlines else " ")
        elif char == "\t":
            out.append("    " if code else " ")
        else:
            category = unicodedata.category(char)
            if category[0] == "C" or category in {"Zl", "Zp"}:
                continue
            out.append(char)
    text = "".join(out)
    if keep_newlines:
        squeeze = (lambda line: line.rstrip()) if code else (lambda line: _SPACE_RUN.sub(" ", line).rstrip())
        return "\n".join(squeeze(line) for line in text.split("\n")).strip("\n")
    return _SPACE_RUN.sub(" ", text).strip()


def bound(value: Any, limit: int, *, keep_newlines: bool = False) -> tuple[str, Truncation | None]:
    """Clean and cut at ``limit`` characters; the cut records how much was omitted and its hash."""
    text = clean(value, keep_newlines=keep_newlines)
    if len(text) <= limit:
        return text, None
    kept, rest = text[:limit], text[limit:]
    return kept, Truncation(omitted=len(rest), unit="chars", sha256=sha256_text(text))


def bound_lines(value: Any, max_lines: int, max_chars: int) -> tuple[str, Truncation | None]:
    text = clean(value, keep_newlines=True, code=True)
    lines = text.split("\n") if text else []
    cut_lines = lines[:max_lines]
    kept = "\n".join(line[:240] for line in cut_lines)
    if len(kept) > max_chars:
        kept = kept[:max_chars]
    if kept == text:
        return kept, None
    omitted = max(len(lines) - len(kept.split("\n")), 0)
    unit = "lines"
    if omitted == 0:
        omitted, unit = max(len(text) - len(kept), 1), "chars"
    return kept, Truncation(omitted=omitted, unit=unit, sha256=sha256_text(text))


def token(value: Any, default: str = "unknown") -> str:
    """A conservative identifier (state names, enums): ASCII word characters only."""
    text = _SAFE_TOKEN.sub("_", clean(value))[:96].strip("_")
    return text or default


def anchor(*parts: str) -> str:
    return "a-" + sha256_text("|".join(parts))[:16]


def tex(text: str) -> str:
    """Escape for ordinary (sans) text. Total: every character is mapped, none can start a command."""
    cleaned = clean(text, keep_newlines=True).replace("\n", " ")
    return "".join(" " if part.startswith(" ") else _tex_run(part) for part in re.split(r"( +)", cleaned) if part)


def _tex_run(run: str) -> str:
    """One unbroken run of prose: ordinary words stay whole, identifiers and hashes may break."""
    out: list[str] = []
    since = 0
    long_run = len(run) > 22
    for char in run:
        out.append(_tex_char(char))
        since += 1
        if char in "_/" or (long_run and (char in _BREAK_AFTER or since >= 14)):
            out.append(r"\allowbreak{}")
            since = 0
    return "".join(out)


def _tex_char(char: str) -> str:
    if char in _TEX_SPECIAL:
        return _TEX_SPECIAL[char]
    if ord(char) >= _FONT_LIMIT:
        return rf"\textless{{}}U+{ord(char):04X}\textgreater{{}}"
    return char


def tex_mono(text: str) -> str:
    """Escape for the monospace face, with break opportunities in long unbroken runs."""
    cleaned = clean(text)
    out: list[str] = []
    run = 0
    for char in cleaned:
        if char == " ":
            out.append(r"\ ")
            run = 0
            continue
        out.append(_tex_char(char))
        run += 1
        if char in _BREAK_AFTER or run >= 14:
            out.append(r"\allowbreak{}")
            run = 0
    return "".join(out)


def tex_code_line(line: str) -> str:
    """One source line: leading indentation kept, long tokens breakable, never a TeX command."""
    cleaned = clean(line, code=True)
    stripped = cleaned.lstrip(" ")
    indent = len(cleaned) - len(stripped)
    prefix = rf"\hspace*{{{min(indent, 40)}\codewidth}}" if indent else ""
    return prefix + tex_mono(stripped)


def esc(text: Any) -> str:
    """HTML-escape cleaned text (attribute-safe)."""
    return html.escape(clean(text, keep_newlines=True), quote=True)


def esc_line(text: Any) -> str:
    return html.escape(clean(text), quote=True)
