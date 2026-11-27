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
_QUOTED_NO_BACKTICK = re.compile(r"""(?P<open>["'])(?P<body>(?:\\.|(?!(?P=open)).)+)(?P=open)""")
_PROSE_QUOTED = re.compile(
    r"""(?P<dq>"(?P<dbody>(?:\\.|[^"\n])+)")|(?<![A-Za-z0-9_])(?P<sq>'(?P<sbody>(?:\\.|[^'\n])+)')(?![A-Za-z0-9_])"""
)
_INLINE_BACKTICK = re.compile(r"`(?P<code>[^`\n]+)`")
_ASSIGNED = re.compile(r"""(?P<head>(?<!:)[=:](?!:)\s*)(?P<value>[^\s,;"'`<>()\[\]{}]{6,})""")
_SECRET_KEY_TERM = re.compile(
    r"(?i)(?:secret|password|passwd|pwd|token|api[_-]?key|private[_-]?key|access[_-]?key|"
    r"client[_-]?secret|credential|authorization|oauth|bearer|cookie|session[_-]?key|"
    r"(?:^|(?<=[_.-]))auth(?:$|(?=[_.-])))"
)
_SECRET_NAME_ASSIGNED = re.compile(
    r"""(?i)(?P<head>\b(?:[A-Za-z0-9_.-]*(?:secret|password|passwd|pwd|token|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret|credential|authorization|oauth|bearer|cookie|session[_-]?key)[A-Za-z0-9_.-]*|(?:[A-Za-z0-9_.-]+[_.-])?auth(?:[_.-][A-Za-z0-9_.-]+)?)\s*(?P<op>=|:|=>|:=)\s*)(?:(?P<q>["'])(?P<qval>(?:\\.|(?!(?P=q)).)+)(?P=q)|(?P<uval>[^\s,;"'`<>()\[\]{}]+))"""
)
_BEARER = re.compile(r"(?i)\b(?P<head>(?:bearer|basic|token)\s+)(?P<value>[A-Za-z0-9._~+/=-]{4,512})")
_BASIC_AUTH_URL = re.compile(r"(?P<head>https?://[^/\s:@]+:)(?P<value>[^@\s/]+)(?=@)")
_KNOWN_SECRET_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{6,}|github_pat_[A-Za-z0-9_]{12,}|"
    r"sk_(?:live|test)_[A-Za-z0-9_]{6,}|sk-[A-Za-z0-9_-]{8,}|"
    r"AKIA[0-9A-Z]{8,}|ASIA[0-9A-Z]{8,}|AIza[0-9A-Za-z_-]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?)\b"
)
_STRING_SECRET_INNER = re.compile(
    r"(?i)(?:secret|password|passwd|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret|"
    r"session[_-]?key|credential|authorization\s*:|bearer\s+|BEGIN [A-Z0-9 ]*PRIVATE KEY)"
)
_TOKEN = re.compile(r"[A-Za-z0-9+/_\-=.]{20,}")
_CANONICAL_ID_TOKEN = re.compile(
    r"^(?:(?:gap|claim|finding|finding_package|finding_lead|hunt|dossier|score|evrel|adjudication|decision|"
    r"verdict|judge|chain|cell|pkg|unit|basis|verification)-[0-9a-f]{16,64}|[0-9a-f]{40,64})$"
)
_CANONICAL_FULL_REF = re.compile(
    r"^(?:asr:[a-z0-9_]+:[0-9a-f]{16,64}|(?:sha256:)?[0-9a-f]{40,64}|(?:appsec-review/)?[a-z0-9_.-]+/[0-9]+)$"
)
_PROSE_COLON_STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "can", "cannot", "could", "does",
    "for", "from", "has", "have", "if", "in", "into", "is", "it", "its", "may", "must", "neither",
    "no", "none", "nor", "not", "null", "nullptr", "of", "on", "only", "or", "see", "should",
    "so", "that", "the", "their", "then", "there", "these", "this", "those", "to", "true", "false",
    "unassessed", "unknown", "was", "were", "when", "where", "which", "while", "with", "without",
})
_PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_PRIVATE_KEY_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----")


def placeholder(length: int) -> str:
    return f"{_MARK}{length} chars>"


def _already(value: str) -> bool:
    return value.startswith(_MARK)


def assignments_safe_prose_token(core: str) -> bool:
    return bool(_CANONICAL_FULL_REF.fullmatch(core))


def _is_benign_prose_kv(core: str) -> bool:
    if "=" not in core:
        return False
    lhs, sep, rhs = core.partition("=")
    if sep != "=" or not lhs or not rhs:
        return False
    if not re.fullmatch(r"[a-z_][a-z0-9_.-]{0,63}", lhs) or _SECRET_KEY_TERM.search(lhs):
        return False
    if _KNOWN_SECRET_TOKEN.search(rhs) or _STRING_SECRET_INNER.search(rhs):
        return False
    return bool(
        rhs.isdigit()
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", rhs)
        or re.fullmatch(r"[0-9a-f]{40,64}", rhs)
        or assignments_safe_prose_token(rhs)
        or (
            re.fullmatch(r"[a-z_][a-z0-9_.-]{0,63}", rhs)
            and not _SECRET_KEY_TERM.search(rhs)
            and not re.search(r"[0-9a-f]{16,}", rhs)
        )
    )


def _preserve_non_secret_token(full_text: str, start: int, end: int, value: str) -> bool:
    core = value.rstrip(".")
    if not core:
        return True
    if assignments_safe_prose_token(core):
        return True
    if _is_benign_prose_kv(core):
        return True
    if _CANONICAL_ID_TOKEN.fullmatch(core):
        if re.fullmatch(r"[0-9a-f]{40,64}", core):
            prefix = full_text[max(0, start - 32):start]
            if prefix.endswith(":") and (
                "asr:" in prefix or prefix.lower().endswith("sha256:")
            ):
                return True
            if start == 0 or full_text[start - 1] not in ("=", ":"):
                return True
            return False
        return True
    return False


def redact_source_line(
    text: str, *, whole_line: bool = False, assignments: bool = True, backticks: bool | None = None
) -> str:
    """``text`` with credential literals replaced by ``<redacted:n chars>``; indentation is kept.

    When ``assignments=False`` (narrative prose, gap strings, schema/policy labels), Markdown inline-code
    backticks are preserved unless ``backticks=True`` is explicitly requested; tokens inside backticks are
    still checked by ``_TOKEN``.
    """
    stripped = text.lstrip()
    indent = text[:len(text) - len(stripped)]
    body = stripped.rstrip()
    if not body:
        return text
    if whole_line:
        return indent + placeholder(len(body))
    redact_backticks = assignments if backticks is None else backticks

    def quoted(match: re.Match[str]) -> str:
        inner = match.group("body")
        if _already(inner):
            return match.group(0)
        if not assignments and _CANONICAL_FULL_REF.fullmatch(inner):
            return match.group(0)
        return f"{match.group('open')}{placeholder(len(inner))}{match.group('open')}"

    def assigned(match: re.Match[str]) -> str:
        value = match.group("value")
        return match.group(0) if _already(value) else f"{match.group('head')}{placeholder(len(value))}"

    quote_re = _QUOTED if redact_backticks else _QUOTED_NO_BACKTICK
    redacted = quote_re.sub(quoted, body)
    if assignments:
        redacted = _ASSIGNED.sub(assigned, redacted)

    def token(match: re.Match[str]) -> str:
        value = match.group(0)
        if _already(value):
            return value
        if not assignments and _preserve_non_secret_token(redacted, match.start(), match.end(), value):
            return value
        core = value.rstrip(".")
        trailing = value[len(core):]
        mixed = any(char.isdigit() for char in core) and not core.isdigit()
        if not mixed:
            return value
        if assignments and re.fullmatch(r"[0-9a-f]{64}", core) and redacted[max(0, match.start() - 32):match.start()].endswith(":") and "asr:" in redacted[max(0, match.start() - 32):match.start()]:
            return value
        return placeholder(len(core)) + trailing

    redacted = _TOKEN.sub(token, redacted)
    return indent + redacted


_ALPHABET_SEQUENCES = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789abcdef",
    "0123456789ABCDEF",
)


def _is_charset_table(value: str) -> bool:
    if _SECRET_KEY_TERM.search(value) or _KNOWN_SECRET_TOKEN.search(value):
        return False
    if value in {"0123456789abcdef", "0123456789ABCDEF"}:
        return True
    return any(seq in value for seq in ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))


def _is_safe_snake_identifier(core: str) -> bool:
    return bool(
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", core)
        and "_" in core
        and not _KNOWN_SECRET_TOKEN.search(core)
        and not _SECRET_KEY_TERM.search(core)
        and not re.search(r"[0-9a-fA-F]{16,}", core)
    )


def redact_code_secrets(text: str, *, secret_context: bool = False) -> str:
    """Redact credential literals in non-secret code/patches without corrupting C/C++ syntax."""
    if "\n" in text:
        return "\n".join(redact_code_secrets(part, secret_context=secret_context) for part in text.split("\n"))
    if secret_context:
        return redact_source_line(text, assignments=True, backticks=True)
    stripped = text.lstrip()
    indent = text[:len(text) - len(stripped)]
    body = stripped.rstrip()
    if not body:
        return text
    if "PRIVATE KEY" in body.upper():
        return indent + placeholder(len(body))

    out = _BEARER.sub(lambda m: m.group("head") + placeholder(len(m.group("value"))), body)

    def secret_assign(match: re.Match[str]) -> str:
        head = match.group("head")
        if match.group("q") is not None:
            q = match.group("q")
            qval = match.group("qval")
            return match.group(0) if _already(qval) else f"{head}{q}{placeholder(len(qval))}{q}"
        uval = match.group("uval")
        if (
            _already(uval)
            or uval in {"true", "false", "null", "nullptr", "None", "True", "False"}
            or uval.isdigit()
            or len(uval) < 4
        ):
            return match.group(0)
        return f"{head}{placeholder(len(uval))}"

    out = _SECRET_NAME_ASSIGNED.sub(secret_assign, out)
    out = _KNOWN_SECRET_TOKEN.sub(lambda m: m.group(0) if _already(m.group(0)) else placeholder(len(m.group(0))), out)

    def secret_quoted(match: re.Match[str]) -> str:
        inner = match.group("body")
        if _already(inner):
            return match.group(0)
        if _STRING_SECRET_INNER.search(inner) or _KNOWN_SECRET_TOKEN.search(inner):
            return f"{match.group('open')}{placeholder(len(inner))}{match.group('open')}"
        if len(inner) >= 24 and re.fullmatch(r"[A-Za-z0-9+/=_-]{24,}", inner):
            has_digit = any(c.isdigit() for c in inner)
            has_alpha = any(c.isalpha() for c in inner)
            if has_digit and has_alpha and not _CANONICAL_ID_TOKEN.fullmatch(inner) and not _is_charset_table(inner):
                return f"{match.group('open')}{placeholder(len(inner))}{match.group('open')}"
        return match.group(0)

    out = _QUOTED_NO_BACKTICK.sub(secret_quoted, out)

    def bare_token(match: re.Match[str]) -> str:
        value = match.group(0)
        if _already(value):
            return value
        core = value.rstrip(".")
        trailing = value[len(core):]
        if not (any(c.isdigit() for c in core) and any(c.isalpha() for c in core)):
            return value
        if _is_charset_table(core) or _preserve_non_secret_token(out, match.start(), match.end(), value):
            return value
        if _is_safe_snake_identifier(core):
            return value
        return placeholder(len(core)) + trailing

    out = _TOKEN.sub(bare_token, out)
    return indent + out


def _redact_prose_segment(segment: str) -> str:
    if not segment:
        return segment
    out = _BASIC_AUTH_URL.sub(
        lambda m: m.group(0) if _already(m.group("value")) else m.group("head") + placeholder(len(m.group("value"))),
        segment,
    )

    def prose_bearer(match: re.Match[str]) -> str:
        head = match.group("head")
        value = match.group("value")
        if _already(value):
            return match.group(0)
        core = value.rstrip(".,;:")
        trailing = value[len(core):]
        if not core:
            return match.group(0)
        prefix = out[max(0, match.start() - 24):match.start()].lower()
        auth_header = bool(re.search(r"authorization\s*:\s*$", prefix))
        scheme = head.strip().lower()
        is_secret = (
            auth_header
            or bool(_KNOWN_SECRET_TOKEN.search(core))
            or bool(_STRING_SECRET_INNER.search(core))
            or (
                scheme == "bearer"
                and (not core.isalpha() or core != core.lower() or len(core) >= 16)
                and core.lower() not in _PROSE_COLON_STOPWORDS
            )
            or (
                len(core) >= 8
                and not _preserve_non_secret_token(out, match.start("value"), match.end("value"), core)
                and not _is_safe_snake_identifier(core)
                and (
                    (any(c.isdigit() for c in core) and any(c.isalpha() for c in core))
                    or (any(c.isupper() for c in core) and any(c.islower() for c in core) and len(core) >= 12)
                    or any(c in "+/=" for c in core)
                )
            )
        )
        return f"{head}{placeholder(len(core))}{trailing}" if is_secret else match.group(0)

    out = _BEARER.sub(prose_bearer, out)

    def prose_secret_assign(match: re.Match[str]) -> str:
        head = match.group("head")
        op = match.group("op")
        if match.group("q") is not None:
            q = match.group("q")
            qval = match.group("qval")
            return match.group(0) if _already(qval) else f"{head}{q}{placeholder(len(qval))}{q}"
        uval = match.group("uval")
        core = uval.rstrip(".,;:")
        trailing = uval[len(core):]
        if not core or _already(core):
            return match.group(0)
        if core.lower() in {"true", "false", "null", "nullptr", "none"}:
            return match.group(0)
        if op == ":" and core.lower() in _PROSE_COLON_STOPWORDS:
            return match.group(0)
        if op == ":" and core.isalpha() and core == core.lower() and len(core) < 12 and not _STRING_SECRET_INNER.search(core):
            lhs = head.split(":", 1)[0].strip().lower()
            if lhs in {"token", "cookie", "auth"}:
                return match.group(0)
        return f"{head}{placeholder(len(core))}{trailing}"

    out = _SECRET_NAME_ASSIGNED.sub(prose_secret_assign, out)

    def prose_quoted(match: re.Match[str]) -> str:
        if match.group("dq") is not None:
            quote = '"'
            inner = match.group("dbody")
        else:
            quote = "'"
            inner = match.group("sbody")
        if _already(inner):
            return match.group(0)
        if _STRING_SECRET_INNER.search(inner) or _KNOWN_SECRET_TOKEN.search(inner):
            return f"{quote}{placeholder(len(inner))}{quote}"
        if len(inner) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=_-]{16,}", inner):
            has_digit = any(c.isdigit() for c in inner)
            has_alpha = any(c.isalpha() for c in inner)
            if (
                has_digit
                and has_alpha
                and not _is_charset_table(inner)
                and not _preserve_non_secret_token(inner, 0, len(inner), inner)
                and not _is_safe_snake_identifier(inner)
            ):
                return f"{quote}{placeholder(len(inner))}{quote}"
        return match.group(0)

    out = _PROSE_QUOTED.sub(prose_quoted, out)
    out = _KNOWN_SECRET_TOKEN.sub(lambda m: m.group(0) if _already(m.group(0)) else placeholder(len(m.group(0))), out)

    def prose_bare_token(match: re.Match[str]) -> str:
        value = match.group(0)
        if _already(value):
            return value
        core = value.rstrip(".")
        trailing = value[len(core):]
        if not (any(c.isdigit() for c in core) and any(c.isalpha() for c in core)):
            return value
        if _is_charset_table(core) or _preserve_non_secret_token(out, match.start(), match.end(), value):
            return value
        if _is_safe_snake_identifier(core):
            return value
        return placeholder(len(core)) + trailing

    return _TOKEN.sub(prose_bare_token, out)


def redact_prose_secrets(text: str, *, secret_context: bool = False) -> str:
    """Redact credential literals in narrative prose without corrupting apostrophes, char literals, or IDs."""
    if not text:
        return text
    lines = text.split("\n")
    out_lines: list[str] = []
    in_private_key = False
    for line in lines:
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]
        body = stripped.rstrip()
        if not body:
            out_lines.append(line)
            continue
        if _PRIVATE_KEY_BEGIN.search(body):
            in_private_key = True
        if in_private_key or ("PRIVATE KEY-----" in body.upper()):
            out_lines.append(indent + placeholder(len(body)))
            if _PRIVATE_KEY_END.search(body):
                in_private_key = False
            continue
        if secret_context:
            out_lines.append(redact_source_line(line, assignments=True, backticks=False))
            continue
        parts: list[str] = []
        cursor = 0
        for match in _INLINE_BACKTICK.finditer(body):
            parts.append(_redact_prose_segment(body[cursor:match.start()]))
            parts.append(f"`{redact_code_secrets(match.group('code'), secret_context=False)}`")
            cursor = match.end()
        parts.append(_redact_prose_segment(body[cursor:]))
        out_lines.append(indent + "".join(parts))
    return "\n".join(out_lines)


def redact_message(text: str | None, *, bound: int = 240) -> str | None:
    """A scanner or audit message with any credential literal removed; bounded."""
    if text is None:
        return None
    return redact_prose_secrets(text, secret_context=False).replace("\n", " ")[:bound]


__all__ = [
    "REDACTION_RULE",
    "assignments_safe_prose_token",
    "placeholder",
    "redact_code_secrets",
    "redact_message",
    "redact_prose_secrets",
    "redact_source_line",
]
