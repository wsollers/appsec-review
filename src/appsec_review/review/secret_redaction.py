"""Redaction of credential literals in model-facing text (``secret-redaction/1``).

A ``secret`` lead says where a scanner found a credential; the reviewing model needs to reason about where
that credential is used, never to see it. Secret scanners run with ``--redact`` and the intake keeps no raw
match, so the only place a literal can still reach a model is the source excerpt of the package view, which
reads the target file. :func:`redact_source_line` replaces the literal on the lead's line(s) with
``<redacted:n chars>`` and keeps everything else on the line (names, operators, call structure).

The scanner does not report the literal's column, so the rule is deliberately conservative on the flagged line:
every quoted string body, every unquoted value after ``=`` or ``:``, and every remaining long token that mixes
digits with other characters is replaced. A flagged multi-line span (a private key block) is replaced line by
line. Over-redaction on a flagged line is accepted; a literal that survives is not.
"""
from __future__ import annotations

import re

REDACTION_RULE = "appsec-review/secret-redaction/1"
_MARK = "<redacted:"
_QUOTED = re.compile(r"""(?P<open>["'`])(?P<body>(?:\\.|(?!(?P=open)).)+)(?P=open)""")
_ASSIGNED = re.compile(r"""(?P<head>[=:]\s*)(?P<value>[^\s,;"'`<>()\[\]{}]{6,})""")
_TOKEN = re.compile(r"[A-Za-z0-9+/_\-=.]{20,}")


def placeholder(length: int) -> str:
    return f"{_MARK}{length} chars>"


def _already(value: str) -> bool:
    return value.startswith(_MARK)


def redact_source_line(text: str, *, whole_line: bool = False, assignments: bool = True) -> str:
    """``text`` with credential literals replaced by ``<redacted:n chars>``; indentation is kept."""
    stripped = text.lstrip()
    indent = text[:len(text) - len(stripped)]
    body = stripped.rstrip()
    if not body:
        return text
    if whole_line:
        return indent + placeholder(len(body))

    def quoted(match: re.Match[str]) -> str:
        inner = match.group("body")
        return match.group(0) if _already(inner) else f"{match.group('open')}{placeholder(len(inner))}{match.group('open')}"

    def assigned(match: re.Match[str]) -> str:
        value = match.group("value")
        return match.group(0) if _already(value) else f"{match.group('head')}{placeholder(len(value))}"

    def token(match: re.Match[str]) -> str:
        value = match.group(0)
        mixed = any(char.isdigit() for char in value) and not value.isdigit()
        return placeholder(len(value)) if mixed and not _already(value) else value

    redacted = _QUOTED.sub(quoted, body)
    if assignments:
        redacted = _ASSIGNED.sub(assigned, redacted)
    redacted = _TOKEN.sub(token, redacted)
    return indent + redacted


def redact_message(text: str | None, *, bound: int = 240) -> str | None:
    """A scanner message with any literal-looking token removed; bounded (messages describe rules, not matches)."""
    if text is None:
        return None
    return redact_source_line(text.replace("\n", " "))[:bound]


__all__ = ["REDACTION_RULE", "placeholder", "redact_message", "redact_source_line"]
