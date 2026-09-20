#!/usr/bin/env python3
"""Deterministic evidence redactor and redaction receipt (ADR-0010 Decision G9-A, task V06).

One shared redactor that every scanner-backed producer calls at its OWN publication boundary:
`redact_tree(attempt_private_dir, to_be_published_dir, on_unhandled=..., limits=...)`. Nothing in
this module is wired into a worker, the common publication runtime or `02-evidence-index`; V10-V13
adopt it. See `docs/evidence-redaction.md`.

Contract in one paragraph: the source directory is never modified; every file is either published
byte-identical (`unchanged`), published with stable `[REDACTED:<kind>:<n>]` markers (`redacted`),
or not published at all (`withheld`, with a named reason). There is no fourth state. A marker
carries a kind and an ordinal within its file -- never a hash, prefix, suffix or length of the
value. No function here logs, prints or raises text taken from file content; exceptions name a
(safe) relative path and a reason only.

Behaviour ported from the legacy `scripts/scrub_evidence.py` (two passes: secret-name-aware and
entropy/shape), not its code.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from dataclasses import asdict, dataclass, fields, replace
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterator

from execution_state import atomic_bytes, beneath, digest
from schema_validate import validate_document

MODULE_VERSION = "1.1.0"
REDACTOR_NAME = "appsec-review-process/evidence_redaction"
RECEIPT_SCHEMA = "redaction-receipt.schema.json"
RECEIPT_FILENAME = "redaction-receipt.json"
POLICIES = ("refuse", "withhold")
PARSER_MODES = ("json", "sarif", "text", "fallback-text")

# Kinds, highest merge priority first: when two detections overlap the merged span takes the
# earliest kind listed here. "fingerprint" is structural (SARIF fingerprints) and never merges.
KINDS = (
    "private-key-block",
    "named-secret",
    "url-credential",
    "bearer-token",
    "provider-token",
    "jwt",
    "high-entropy",
    "fingerprint",
)
WITHHELD_REASONS = (
    "binary-content",
    "file-size-limit",
    "internal-error",
    "json-depth-limit",
    "line-length-limit",
    "not-converged",
    "not-regular-file",
    "not-utf8",
    "read-error",
    "reserved-name",
    "symlink",
    "total-bytes-limit",
    "unsafe-path",
    "unstable-output",
    "unsupported-type",
)

_KEYWORD = (
    r"(?:passw(?:or)?d|passphrase|(?<![A-Za-z])pass(?![A-Za-z])|(?<![A-Za-z])pwd(?![A-Za-z])"
    r"|secret|token|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|signing[_-]?key"
    r"|encryption[_-]?key|shared[_-]?access[_-]?(?:key|signature)|conn(?:ection)?[_-]?str(?:ing)?"
    r"|credential|bearer|authorization)"
)
_BEGIN = "-----BEGIN "  # kept apart from the label so no scannable key header exists in this repo
_END = "-----END "

# Everything that decides what is redacted lives in RULESET; its digest is the receipt's
# ruleset_sha256. A logic change that RULESET cannot express must bump MODULE_VERSION.
RULESET: dict[str, Any] = {
    "marker": "[REDACTED:<kind>:<ordinal-within-file>]",
    "kinds": list(KINDS),
    "keyword": _KEYWORD,
    # Rules anchored on a keyword are evaluated AT each keyword match (bounded look-behind and
    # look-ahead), so cost stays linear in the input whatever the input is made of.
    "named_tail": (
        r"(?i)[A-Za-z0-9_.\-]{0,64}(?:\\?[\"'])?\]?[ \t]{0,8}"
        r"(?P<op>:[ \t]{0,8}(?:Optional\[)?(?:str|string|bytes|SecretStr|&str)\]?[ \t]{0,8}=(?!=)"
        r"|[=!]==?|=>|:=|[:=(])[ \t]{0,8}"
        r"(?:(?:basic|bearer|digest|negotiate|token)[ \t]+)?"
    ),
    "keyword_lookbehind_chars": 66,
    "flag_prefix": r"(?<![A-Za-z0-9])--?[A-Za-z0-9_\-]{0,64}\Z",
    "flag_tail": r"[A-Za-z0-9_\-]{0,64}[ \t]+",
    # `ENV API_KEY value` / `ARG NPM_TOKEN value` / `export DB_PASSWORD value`: a directive, a
    # secret-ish NAME, whitespace, then the value with no operator at all. Dockerfiles still accept
    # this legacy ENV form, and hadolint/trivy output quotes such lines verbatim.
    "directive_prefix": r"(?i)(?:^|\n)[ \t]{0,16}(?:ENV|ARG|LABEL|export|setenv|setx|set|declare(?:[ \t]+-[A-Za-z]{1,4})?)[ \t]{1,8}[A-Za-z0-9_.\-]{0,64}\Z",
    "directive_tail": r"[A-Za-z0-9_.\-]{0,64}[ \t]{1,8}(?![=:])",
    # Credentials passed positionally to well-known clients, where no secret-ish name exists to
    # anchor on. Each pattern is bounded, so cost stays linear.
    "cli_credentials": {
        "mysql-family-short-password": r"(?i)\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlcheck|mysqlshow|mariadb|mariadb-dump|mariadb-admin)\b[^\n]{0,512}?[ \t]-p(?P<v>[^\s\-][^\s]{0,255})",
        "sshpass-password": r"(?i)\bsshpass[ \t]{1,8}-p[ \t]{0,8}(?P<v>[^\s]{1,256})",
        "user-colon-password": r"(?i)\b(?:curl|wget|http|https)\b[^\n]{0,512}?[ \t](?:-u|--user|--proxy-user)[ \t=]{1,8}[\"']?[^\s:\"']{1,128}:(?P<v>[^\s\"']{1,256})",
    },
    "flag_only": r"(?i)^--?[A-Za-z0-9_\-]{0,64}?" + _KEYWORD + r"[A-Za-z0-9_\-]{0,64}$",
    "xml_prefix": r"<[A-Za-z0-9_:.\-]{0,64}\Z",
    "xml_tail": r"[A-Za-z0-9_:.\-]{0,64}(?:\s[^<>]{0,512})?>(?P<v>[^<]{1,4096})<",
    "unquoted_value": r"[^\s\"',;]{1,4096}",
    "unquoted_literals": ["false", "nil", "none", "null", "true", "undefined"],
    "bearer": r"(?i)\bbearer[ \t]+(?P<v>[A-Za-z0-9._~+/=\-]{16,})",
    "url_credential": r"://[^/\s:@]{1,256}:(?P<v>[^/\s@]{1,256})@",
    "jwt": r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
    "provider": {
        "aws-access-key-id": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        "github-token": r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b",
        "gitlab-token": r"\bglpat-[A-Za-z0-9_\-]{20,}",
        "google-api-key": r"\bAIza[0-9A-Za-z_\-]{35}",
        "npm-token": r"\bnpm_[A-Za-z0-9]{36}\b",
        "sk-api-key": r"\bsk-[A-Za-z0-9_\-]{20,}",
        "slack-token": r"\bxox[abeprs]-[A-Za-z0-9\-]{10,}",
        "stripe-key": r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}",
    },
    "private_key_begin": _BEGIN + r"(?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----",
    "private_key_end": _END + r"(?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----",
    "public_pem": _BEGIN + r"(?P<label>(?:[A-Z0-9]+ ){0,4}(?:CERTIFICATE|PUBLIC KEY|CERTIFICATE REQUEST|X509 CRL))-----",
    "ssh_public_key": r"\b(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com)[ \t]+(?P<v>AAAA[A-Za-z0-9+/=]{16,})",
    "entropy": {
        "candidate": r"[A-Za-z0-9+/_=\-]{20,}",
        "segment_min_length": 20,
        "segment_min_entropy": 3.5,
        "letters_only_min_length": 24,
        "letters_only_min_entropy": 4.2,
        "whole_run_min_length": 40,
        "whole_run_min_entropy": 4.5,
        "exempt_hex_digest_lengths": [32, 40, 56, 64, 96, 128],
        # An identifier such as `source_snapshot_sha256` is words plus the NAME of an algorithm or
        # format. Without this, the redactor rewrote the structural keys of this repository's own
        # evidence documents (tool-results, coverage, probe receipts, wave manifests), which made
        # them schema-invalid and unpublishable. The list is closed and only ever applies to a
        # PIECE of an identifier that is otherwise made of plain words (see _wordy); a string that
        # merely contains one of these tokens is still judged on its entropy.
        "wordy_technical_pieces": ["base16", "base32", "base58", "base64", "blake2b", "blake2s", "blake3", "crc32",
                                   "ed25519", "hmac", "ipv4", "ipv6", "md5", "oauth2", "p256", "p384", "p521",
                                   "rsa2048", "rsa4096", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3",
                                   "utf8", "utf16", "x509"],
        "wordy_min_plain_words": 2,
        "wordy_counter_max_length": 8,
        # `20260919T123919Z-0b9e70`: this repository's run-id shape (UTC stamp plus a short hex
        # suffix). About a third of real run ids were being flagged, which mangled the header of
        # every published document. The suffix carries at most 48 bits and is an identifier.
        "exempt_patterns": {"utc-stamp-id": r"[0-9]{8}T[0-9]{6}Z(?:-[0-9a-f]{4,12})?\Z"},
        "exempt": ["all-digits", "uuid", "hex-digest-length", "wordy-kebab-or-snake", "utc-stamp-id", "public-pem-body", "ssh-public-key"],
    },
    "json_extensions": [".json", ".sarif"],
    "text_extensions": [".csv", ".err", ".jsonl", ".log", ".md", ".ndjson", ".out", ".tsv", ".txt", ".xml", ".yaml", ".yml"],
    "sarif_wholesale_objects": {"environmentVariables": "named-secret", "fingerprints": "fingerprint", "partialFingerprints": "fingerprint"},
    "fixed_point_iterations": 4,
}
RULESET_SHA256 = digest({"module_version": MODULE_VERSION, "ruleset": RULESET})

MARKER_RE = re.compile(r"\[REDACTED:(" + "|".join(re.escape(kind) for kind in KINDS) + r"):([1-9][0-9]{0,8})\]")
PLACEHOLDER_PATH_RE = re.compile(r"\[WITHHELD-PATH:([1-9][0-9]{0,8})\]\Z")
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_KEYWORD_RE = re.compile("(?i)" + _KEYWORD)
_NAMED_TAIL_RE = re.compile(RULESET["named_tail"])
_FLAG_PREFIX_RE = re.compile(RULESET["flag_prefix"])
_FLAG_TAIL_RE = re.compile(RULESET["flag_tail"])
_XML_PREFIX_RE = re.compile(RULESET["xml_prefix"])
_XML_TAIL_RE = re.compile(RULESET["xml_tail"])
_FLAG_ONLY_RE = re.compile(RULESET["flag_only"])
_DIRECTIVE_PREFIX_RE = re.compile(RULESET["directive_prefix"])
_DIRECTIVE_TAIL_RE = re.compile(RULESET["directive_tail"])
_CLI_CREDENTIAL_RES = tuple(re.compile(pattern) for _, pattern in sorted(RULESET["cli_credentials"].items()))
_UNQUOTED_RE = re.compile(RULESET["unquoted_value"])
_DQ_RE = re.compile(r'(?:\\.|[^"\\\n])*')
_SQ_RE = re.compile(r"(?:\\.|[^'\\\n])*")
_BEARER_RE = re.compile(RULESET["bearer"])
_URL_RE = re.compile(RULESET["url_credential"])
_JWT_RE = re.compile(RULESET["jwt"])
_PROVIDER_RES = tuple(re.compile(RULESET["provider"][name]) for name in sorted(RULESET["provider"]))
_KEY_BEGIN_RE = re.compile(RULESET["private_key_begin"])
_KEY_END_RE = re.compile(RULESET["private_key_end"])
_PUBLIC_PEM_RE = re.compile(RULESET["public_pem"])
_SSH_PUBLIC_RE = re.compile(RULESET["ssh_public_key"])
_CANDIDATE_RE = re.compile(RULESET["entropy"]["candidate"])
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_HEX_RE = re.compile(r"[0-9a-fA-F]+\Z")
_SEGMENT_RE = re.compile(r"[^/=]+")
_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
_JSON_DEPTH_RE = re.compile(r'"(?:[^"\\]|\\.)*"|[\[\]{}]')
_ALNUM_RE = re.compile(r"[A-Za-z0-9]")
_PRIORITY = {kind: index for index, kind in enumerate(KINDS)}
_LITERALS = frozenset(RULESET["unquoted_literals"])
_ENTROPY = RULESET["entropy"]
_TECHNICAL_PIECES = frozenset(RULESET["entropy"]["wordy_technical_pieces"])
_EXEMPT_PATTERN_RES = tuple(re.compile(pattern) for _, pattern in sorted(RULESET["entropy"]["exempt_patterns"].items()))


class RedactionError(ValueError):
    """Misuse or an environment failure. The message never contains file content."""


class PublicationRefused(RedactionError):
    """Nothing was published. `reasons` is a list of (safe relative path, reason) pairs."""

    def __init__(self, summary: str, reasons: list[tuple[str, str]]):
        self.reasons = list(reasons)
        shown = ", ".join(f"{path} ({reason})" for path, reason in self.reasons[:20])
        more = f" and {len(self.reasons) - 20} more" if len(self.reasons) > 20 else ""
        super().__init__(f"{summary}: {shown}{more}")


class ReceiptVerificationError(RedactionError):
    """The receipt does not describe the published directory. `errors` lists every violation."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("redaction receipt verification failed: " + "; ".join(self.errors))


@dataclass(frozen=True)
class Limits:
    """Bounds in force. Every field is required: there is no implicit 'unbounded'."""

    max_file_bytes: int
    max_line_length: int
    max_files: int
    max_total_bytes: int
    max_json_depth: int
    max_path_length: int

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise RedactionError(f"limit {field.name} must be a positive integer")
        if self.max_json_depth > 200:
            raise RedactionError("limit max_json_depth must not exceed 200 (parser recursion bound)")


DEFAULT_LIMITS = Limits(
    max_file_bytes=16 * 1024 * 1024,
    max_line_length=128 * 1024,
    max_files=2000,
    max_total_bytes=128 * 1024 * 1024,
    max_json_depth=64,
    max_path_length=512,
)


class _Withhold(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _Tally:
    def __init__(self) -> None:
        self.ordinal = 0
        self.counts = {kind: 0 for kind in KINDS}

    def marker(self, kind: str) -> str:
        self.ordinal += 1
        self.counts[kind] += 1
        return f"[REDACTED:{kind}:{self.ordinal}]"

    @property
    def total(self) -> int:
        return self.ordinal


@dataclass(frozen=True)
class _Outcome:
    disposition: str
    data: bytes | None
    parser_mode: str | None
    withheld_reason: str | None
    counts: dict[str, int]


# ---------------------------------------------------------------------------------------------
# Detection: every rule yields (start, end, kind) over the text it was given. Nothing is replaced
# until all rules have run, so one rule's marker is never rescanned by another in the same round.
# ---------------------------------------------------------------------------------------------

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    size = len(text)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def _value_span(text: str, pos: int, require_quoted: bool) -> tuple[int, int] | None:
    size = len(text)
    if pos >= size:
        return None
    char = text[pos]
    if char == "\\" and pos + 1 < size and text[pos + 1] in "\"'":
        # A quote that is itself JSON-escaped (a snippet seen through the text passes). The value
        # ends at the next escaped quote, or at end of line when it never closes.
        quote, start = text[pos + 1], pos + 2
        eol = text.find("\n", start)
        eol = size if eol < 0 else eol
        end = text.find("\\" + quote, start, eol)
        return start, (eol if end < 0 else end)
    if char in "\"'":
        if text.startswith(char * 3, pos):
            start = pos + 3
            end = text.find(char * 3, start)
            if end < 0:
                end = text.find("\n", start)
                end = size if end < 0 else end
            return start, end
        match = (_DQ_RE if char == '"' else _SQ_RE).match(text, pos + 1)
        return pos + 1, match.end()  # unterminated: runs to end of line, which is the safe side
    if require_quoted:
        return None
    match = _UNQUOTED_RE.match(text, pos)
    if not match or match.group(0).lower() in _LITERALS:
        return None
    return match.span()


def _named_spans(text: str) -> Iterator[tuple[int, int, str]]:
    behind = RULESET["keyword_lookbehind_chars"]
    for keyword in _KEYWORD_RE.finditer(text):
        tail = _NAMED_TAIL_RE.match(text, keyword.end())
        if tail:
            span = _value_span(text, tail.end(), require_quoted=tail.group("op") == "(")
            if span:
                yield span[0], span[1], "named-secret"
        before = text[max(0, keyword.start() - behind):keyword.start()]
        tail = _FLAG_PREFIX_RE.search(before) and _FLAG_TAIL_RE.match(text, keyword.end())
        if tail and not text.startswith("-", tail.end()):
            span = _value_span(text, tail.end(), require_quoted=False)
            if span:
                yield span[0], span[1], "named-secret"
        tail = _DIRECTIVE_PREFIX_RE.search(before) and _DIRECTIVE_TAIL_RE.match(text, keyword.end())
        if tail:
            span = _value_span(text, tail.end(), require_quoted=False)
            if span:
                yield span[0], span[1], "named-secret"
        tail = _XML_PREFIX_RE.search(before) and _XML_TAIL_RE.match(text, keyword.end())
        if tail and tail.group("v").strip():
            yield tail.start("v"), tail.end("v"), "named-secret"
    for pattern in _CLI_CREDENTIAL_RES:
        for match in pattern.finditer(text):
            yield match.start("v"), match.end("v"), "named-secret"
    for match in _BEARER_RE.finditer(text):
        yield match.start("v"), match.end("v"), "bearer-token"
    for match in _URL_RE.finditer(text):
        yield match.start("v"), match.end("v"), "url-credential"


def _private_key_spans(text: str) -> Iterator[tuple[int, int, str]]:
    pos = 0
    while True:
        begin = _KEY_BEGIN_RE.search(text, pos)
        if not begin:
            return
        end = _KEY_END_RE.search(text, begin.end())
        stop = end.end() if end else len(text)  # a truncated block redacts to the end: fail closed
        yield begin.start(), stop, "private-key-block"
        pos = stop


def _public_material_spans(text: str) -> list[tuple[int, int]]:
    """Spans the ENTROPY pass must not touch. Every other rule still applies inside them."""
    spans = []
    for match in _PUBLIC_PEM_RE.finditer(text):
        close = text.find(_END + match.group("label") + "-----", match.end())
        if close >= 0:
            spans.append((match.end(), close))
    spans.extend(match.span("v") for match in _SSH_PUBLIC_RE.finditer(text))
    return spans


def _wordy(run: str) -> bool:
    """A kebab/snake identifier made of plain words. Besides words, a piece may be the closed-list
    NAME of an algorithm or format (`sha256`), or a short digit counter (`0001`); anything else is
    "odd" and stays tightly bounded. At least two plain words are always required, so a string
    built only from technical tokens and counters is not an identifier."""
    pieces = [piece for piece in re.split(r"[-_]", run) if piece]
    if len(pieces) < 3:
        return False
    words = [piece for piece in pieces if piece.isalpha() and (piece.islower() or piece.isupper() or piece.istitle())]
    if len(words) < _ENTROPY["wordy_min_plain_words"]:
        return False
    odd = [piece for piece in pieces if piece not in words
           and piece.lower() not in _TECHNICAL_PIECES
           and not (piece.isdigit() and len(piece) <= _ENTROPY["wordy_counter_max_length"])]
    return all(len(piece) <= 4 for piece in odd) and len(odd) * 3 <= len(pieces)


def _exempt(run: str) -> bool:
    if run.isdigit() or _UUID_RE.match(run):
        return True
    if _HEX_RE.match(run) and len(run) in _ENTROPY["exempt_hex_digest_lengths"]:
        return True
    if any(pattern.match(run) for pattern in _EXEMPT_PATTERN_RES):
        return True
    return _wordy(run)


def _segment_is_secret(segment: str) -> bool:
    if len(segment) < _ENTROPY["segment_min_length"] or _exempt(segment):
        return False
    entropy = shannon_entropy(segment)
    has_digit = any(char.isdigit() for char in segment)
    has_alpha = any(char.isalpha() for char in segment)
    if has_digit and has_alpha and entropy >= _ENTROPY["segment_min_entropy"]:
        return True
    mixed = any(char.islower() for char in segment) and any(char.isupper() for char in segment)
    return (mixed and len(segment) >= _ENTROPY["letters_only_min_length"]
            and entropy >= _ENTROPY["letters_only_min_entropy"])


def _entropy_spans(text: str) -> Iterator[tuple[int, int, str]]:
    protected = _public_material_spans(text)
    for match in _CANDIDATE_RE.finditer(text):
        start, end = match.span()
        if any(low <= start and end <= high for low, high in protected):
            continue
        run = match.group(0)
        if _exempt(run):
            continue
        if (len(run) >= _ENTROPY["whole_run_min_length"]
                and any(char.isdigit() for char in run) and any(char.islower() for char in run)
                and any(char.isupper() for char in run)
                and shannon_entropy(run) >= _ENTROPY["whole_run_min_entropy"]):
            yield start, end, "high-entropy"
            continue
        for segment in _SEGMENT_RE.finditer(run):
            if _segment_is_secret(segment.group(0)):
                yield start + segment.start(), start + segment.end(), "high-entropy"


def _shape_spans(text: str) -> Iterator[tuple[int, int, str]]:
    yield from _private_key_spans(text)
    for pattern in _PROVIDER_RES:
        for match in pattern.finditer(text):
            yield match.start(), match.end(), "provider-token"
    for match in _JWT_RE.finditer(text):
        yield match.start(), match.end(), "jwt"
    yield from _entropy_spans(text)


def _escape_view(text: str) -> tuple[str, list[tuple[int, int, int]]]:
    r"""`\uXXXX` escapes decoded for DETECTION ONLY, with a map back to the original offsets, so a
    value spelled with escapes in a file that reaches the text passes is still found."""
    pieces, segments, pos, view = [], [], 0, 0
    for match in _UNICODE_ESCAPE_RE.finditer(text):
        if match.start() > pos:
            segments.append((view, pos, 1))
            pieces.append(text[pos:match.start()])
            view += match.start() - pos
        segments.append((view, match.start(), 6))
        pieces.append(chr(int(match.group(1), 16)))
        view += 1
        pos = match.end()
    if pos < len(text):
        segments.append((view, pos, 1))
        pieces.append(text[pos:])
    return "".join(pieces), segments


def _all_spans(text: str) -> list[tuple[int, int, str]]:
    # Existing markers are opaque to detection: mask them (same length, so offsets hold) or the
    # words inside a marker would themselves read as `secret:<value>`.
    text = MARKER_RE.sub(lambda match: "\x00" * len(match.group(0)), text)
    spans = list(_named_spans(text)) + list(_shape_spans(text))
    if _UNICODE_ESCAPE_RE.search(text):
        view, segments = _escape_view(text)
        starts = [segment[0] for segment in segments]
        for low, high, kind in list(_named_spans(view)) + list(_shape_spans(view)):
            if high <= low:
                continue
            first = segments[bisect_right(starts, low) - 1]
            last = segments[bisect_right(starts, high - 1) - 1]
            spans.append((first[1] + (low - first[0]) * (1 if first[2] == 1 else 0),
                          last[1] + ((high - 1 - last[0]) if last[2] == 1 else 0) + last[2], kind))
    return spans


def _merged_spans(text: str) -> list[tuple[int, int, str]]:
    spans = sorted((low, high, kind) for low, high, kind in _all_spans(text) if high > low)
    merged: list[list[Any]] = []
    for low, high, kind in spans:
        if merged and low < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], high)
            if _PRIORITY[kind] < _PRIORITY[merged[-1][2]]:
                merged[-1][2] = kind
        else:
            merged.append([low, high, kind])
    # Never rewrite an existing marker: cut markers out of each span and keep only remainders that
    # still hold an alphanumeric character. This is what makes redaction idempotent.
    markers = [match.span() for match in MARKER_RE.finditer(text)]
    marker_starts = [span[0] for span in markers]
    result = []
    for low, high, kind in merged:
        cursor = low
        for marker_low, marker_high in markers[max(0, bisect_right(marker_starts, low) - 1):]:
            if marker_low >= high:
                break
            if marker_high <= cursor:
                continue
            if marker_low > cursor:
                result.append((cursor, marker_low, kind))
            cursor = max(cursor, marker_high)
        if cursor < high:
            result.append((cursor, high, kind))
    return [(low, high, kind) for low, high, kind in result if _ALNUM_RE.search(text, low, high)]


def _redact_text(text: str, tally: _Tally) -> str:
    """Both passes to a fixed point. Raises _Withhold('not-converged') rather than emit text that a
    second run would change."""
    for _ in range(RULESET["fixed_point_iterations"]):
        spans = _merged_spans(text)
        if not spans:
            return text
        pieces, cursor = [], 0
        for low, high, kind in spans:
            pieces.append(text[cursor:low])
            pieces.append(tally.marker(kind))
            cursor = high
        pieces.append(text[cursor:])
        text = "".join(pieces)
    if _merged_spans(text):
        raise _Withhold("not-converged")
    return text


# ---------------------------------------------------------------------------------------------
# Structured (JSON / SARIF) walk
# ---------------------------------------------------------------------------------------------

def _is_marker(value: str) -> bool:
    return bool(MARKER_RE.fullmatch(value))


def _walk(node: Any, wholesale: str | None, sarif: bool, limits: Limits, tally: _Tally) -> Any:
    if isinstance(node, str):
        if len(node) > limits.max_line_length:
            raise _Withhold("line-length-limit")
        if wholesale and node.strip() and not _is_marker(node):
            return tally.marker(wholesale)
        return _redact_text(node, tally)
    if isinstance(node, bool) or node is None:
        return node
    if isinstance(node, (int, float)):
        return tally.marker(wholesale) if wholesale else node
    if isinstance(node, list):
        result, flagged = [], False
        for item in node:
            forced = wholesale
            if flagged and isinstance(item, str) and not item.startswith("-"):
                forced = wholesale or "named-secret"
            flagged = isinstance(item, str) and bool(_FLAG_ONLY_RE.match(item))
            result.append(_walk(item, forced, sarif, limits, tally))
        return result
    result = {}
    for key, value in node.items():
        if len(key) > limits.max_line_length:
            raise _Withhold("line-length-limit")
        child = wholesale
        if child is None and sarif and key in RULESET["sarif_wholesale_objects"]:
            child = RULESET["sarif_wholesale_objects"][key]
        if child is None and _KEYWORD_RE.search(MARKER_RE.sub("", key)):  # a marker's own words are not a name
            child = "named-secret"
        safe_key = _redact_text(key, tally)
        if safe_key in result:
            raise _Withhold("internal-error")
        result[safe_key] = _walk(value, child, sarif, limits, tally)
    return result


def _reject_constant(_name: str) -> Any:
    raise ValueError("non-standard JSON constant")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate object key")  # never silently keep one and drop the other
    return result


def _json_depth(text: str) -> int:
    depth = deepest = 0
    for match in _JSON_DEPTH_RE.finditer(text):
        token = match.group(0)
        if token in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif token in "]}":
            depth -= 1
    return deepest


def _file_kind(relative_path: str) -> str | None:
    suffix = os.path.splitext(relative_path)[1].lower()
    if suffix in RULESET["json_extensions"]:
        return "json"
    if suffix in RULESET["text_extensions"]:
        return "text"
    return None


def _process_once(data: bytes, relative_path: str, limits: Limits) -> _Outcome:
    tally = _Tally()
    kind = _file_kind(relative_path)
    if kind is None:
        raise _Withhold("unsupported-type")
    if len(data) > limits.max_file_bytes:
        raise _Withhold("file-size-limit")
    if b"\x00" in data:
        raise _Withhold("binary-content")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _Withhold("not-utf8") from None
    mode = "text"
    if kind == "json":
        bom = "﻿" if text.startswith("﻿") else ""
        body = text[len(bom):]
        if _json_depth(body) > limits.max_json_depth:
            raise _Withhold("json-depth-limit")
        try:
            document = json.loads(body, parse_constant=_reject_constant, object_pairs_hook=_unique_pairs)
        except RecursionError:
            raise _Withhold("json-depth-limit") from None
        except ValueError:
            mode = "fallback-text"  # malformed input is never repaired; it gets the text passes
        else:
            sarif = (isinstance(document, dict) and isinstance(document.get("runs"), list)
                     and isinstance(document.get("version"), str))
            mode = "sarif" if sarif else "json"
            redacted = _walk(document, None, sarif, limits, tally)
            if not tally.total:
                return _Outcome("unchanged", data, mode, None, tally.counts)
            output = (bom + json.dumps(redacted, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode("utf-8")
            return _Outcome("redacted", output, mode, None, tally.counts)
    if max(len(line) for line in data.split(b"\n")) > limits.max_line_length:
        raise _Withhold("line-length-limit")
    redacted_text = _redact_text(text, tally)
    if not tally.total:
        return _Outcome("unchanged", data, mode, None, tally.counts)
    # Bytes in, bytes out: no newline translation, so CRLF and LF inputs are each stable everywhere.
    return _Outcome("redacted", redacted_text.encode("utf-8"), mode, None, tally.counts)


def _withheld(reason: str) -> _Outcome:
    return _Outcome("withheld", None, None, reason, {kind: 0 for kind in KINDS})


def _process(data: bytes, relative_path: str, limits: Limits) -> _Outcome:
    """Total function: any failure becomes a `withheld` outcome with a reason and no content."""
    try:
        outcome = _process_once(data, relative_path, limits)
        if outcome.disposition == "redacted":
            # Prove the bytes about to be published are a fixed point within every limit, because
            # that is exactly what verify_receipt() will demand of them.
            try:
                again = _process_once(outcome.data, relative_path, limits)
            except _Withhold:
                return _withheld("unstable-output")  # e.g. a marker pushed a line past max_line_length
            if again.disposition != "unchanged" or again.parser_mode != outcome.parser_mode:
                return _withheld("unstable-output")
        return outcome
    except _Withhold as held:
        return _withheld(held.reason)
    except Exception:  # noqa: BLE001 -- deliberately total; the cause may quote file content
        return _withheld("internal-error")


# ---------------------------------------------------------------------------------------------
# Publication boundary
# ---------------------------------------------------------------------------------------------

def _path_is_safe(relative_path: str, limits: Limits) -> bool:
    """A path is published in the receipt, so it must pass the same detector as file content."""
    if not relative_path or len(relative_path) > limits.max_path_length:
        return False
    try:
        relative_path.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if any(ord(char) < 0x20 or char in "\\\x7f" for char in relative_path):
        return False
    parts = relative_path.split("/")
    if any(part in ("", ".", "..") for part in parts) or (len(parts[0]) == 2 and parts[0][1] == ":"):
        return False
    if MARKER_RE.search(relative_path) or relative_path.startswith("[WITHHELD-PATH:"):
        return False
    return not _merged_spans(relative_path)


def _safe_label(relative_path: str, limits: Limits) -> str:
    return relative_path if _path_is_safe(relative_path, limits) else "[UNSAFE-PATH]"


def _enumerate(root: Path, limits: Limits) -> list[tuple[str, Path, str]]:
    """(relative posix path, absolute path, 'file'|'symlink'|'special'), sorted by relative path.
    Links are recorded and never followed or descended."""
    found, stack = [], [(root, "")]
    while stack:
        directory, prefix = stack.pop()
        try:
            with os.scandir(directory) as entries:
                listing = sorted(entries, key=lambda entry: entry.name)
        except OSError:
            raise RedactionError("source directory could not be listed") from None
        for entry in listing:
            relative = prefix + entry.name
            path = Path(entry.path)
            junction = getattr(path, "is_junction", None)
            if entry.is_symlink() or (junction is not None and junction()):
                found.append((relative, path, "symlink"))
            elif entry.is_dir(follow_symlinks=False):
                stack.append((path, relative + "/"))
                continue
            elif entry.is_file(follow_symlinks=False):
                found.append((relative, path, "file"))
            else:
                found.append((relative, path, "special"))
            if len(found) > limits.max_files:
                raise PublicationRefused(
                    "publication refused under every policy: the source holds more entries than max_files",
                    [(".", "file-count-limit")])
    return sorted(found)


def _read_bounded(root: Path, path: Path, limits: Limits) -> bytes:
    beneath(root, path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _Withhold("not-regular-file")
        chunks, remaining = [], limits.max_file_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if len(data) > limits.max_file_bytes:
        raise _Withhold("file-size-limit")
    return data


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record(path: str, outcome: _Outcome, preexisting: int) -> dict:
    published = outcome.data is not None
    digest_value = _sha256(outcome.data) if published else None
    return {
        "path": path,
        "disposition": outcome.disposition,
        "withheld_reason": outcome.withheld_reason,
        "parser_mode": outcome.parser_mode,
        # Only an unchanged file has a source hash: for a redacted or withheld file the hash of the
        # source bytes would be an offline oracle for the very value that was removed.
        "source_sha256": digest_value if outcome.disposition == "unchanged" else None,
        "published_sha256": digest_value,
        "published_bytes": len(outcome.data) if published else None,
        "redactions": dict(outcome.counts),
        "preexisting_markers": preexisting,
    }


def _totals(records: list[dict]) -> dict:
    return {
        "files_total": len(records),
        "files_unchanged": sum(record["disposition"] == "unchanged" for record in records),
        "files_redacted": sum(record["disposition"] == "redacted" for record in records),
        "files_withheld": sum(record["disposition"] == "withheld" for record in records),
        "published_bytes": sum(record["published_bytes"] or 0 for record in records),
        "redactions": {kind: sum(record["redactions"][kind] for record in records) for kind in KINDS},
        "redactions_total": sum(sum(record["redactions"].values()) for record in records),
        "preexisting_markers": sum(record["preexisting_markers"] for record in records),
    }


def _seal(receipt: dict) -> dict:
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    return {**body, "receipt_sha256": digest(body)}


def _check_arguments(on_unhandled: Any, limits: Any) -> None:
    if on_unhandled not in POLICIES:
        raise RedactionError("on_unhandled must be exactly 'refuse' or 'withhold'")
    if not isinstance(limits, Limits):
        raise RedactionError("limits must be an evidence_redaction.Limits instance")


def redact_tree(source_dir: Any, published_dir: Any, *, on_unhandled: str, limits: Limits) -> dict:
    """Redact every file beneath `source_dir` into `published_dir` and return the sealed receipt,
    which is also written to `published_dir/redaction-receipt.json` LAST.

    `on_unhandled` and `limits` are required. 'refuse' publishes nothing unless every file was
    handled; 'withhold' publishes the handled files and lists the rest. Neither copies a file it
    could not prove handled. More than `limits.max_files` entries is refused under both.
    """
    _check_arguments(on_unhandled, limits)
    source, target = Path(source_dir).absolute(), Path(published_dir).absolute()
    try:
        beneath(source, source)
        beneath(target.parent, target)
    except ValueError:
        raise RedactionError("source and published directories must not be or traverse a link") from None
    if not source.is_dir():
        raise RedactionError("source directory does not exist or is not a directory")
    real_source, real_target = source.resolve(), target.resolve()
    if real_source == real_target or real_source in real_target.parents or real_target in real_source.parents:
        raise RedactionError("source and published directories must not contain one another")
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise RedactionError("published directory must be absent or empty")

    records, outputs, consumed, placeholders = [], [], 0, 0
    for relative, path, entry_kind in _enumerate(source, limits):
        outcome = None
        if entry_kind != "file":
            outcome = _withheld("symlink" if entry_kind == "symlink" else "not-regular-file")
        elif relative == RECEIPT_FILENAME:
            outcome = _withheld("reserved-name")
        if not _path_is_safe(relative, limits):
            placeholders += 1
            label, outcome = f"[WITHHELD-PATH:{placeholders}]", _withheld("unsafe-path")
        else:
            label = relative
        if outcome is None:
            try:
                data = _read_bounded(source, path, limits)
            except _Withhold as held:
                outcome = _withheld(held.reason)
            except ValueError:
                outcome = _withheld("symlink")
            except OSError:
                outcome = _withheld("read-error")
            else:
                consumed += len(data)
                outcome = _withheld("total-bytes-limit") if consumed > limits.max_total_bytes else _process(data, relative, limits)
        preexisting = 0
        if outcome.data is not None:
            markers = sum(1 for _ in MARKER_RE.finditer(outcome.data.decode("utf-8")))
            preexisting = markers - sum(outcome.counts.values())
            if preexisting < 0:
                outcome, preexisting = _withheld("unstable-output"), 0
        records.append(_record(label, outcome, preexisting))
        if outcome.data is not None:
            outputs.append((relative, outcome.data))

    unhandled = [(record["path"], record["withheld_reason"]) for record in records if record["disposition"] == "withheld"]
    if unhandled and on_unhandled == "refuse":
        raise PublicationRefused(
            f"publication refused under on_unhandled='refuse': {len(unhandled)} file(s) could not be proven handled",
            unhandled)

    receipt = _seal({
        "schema_version": "1.0",
        "receipt_type": "redaction-receipt",
        "redactor": {"name": REDACTOR_NAME, "module_version": MODULE_VERSION, "ruleset_sha256": RULESET_SHA256},
        "policy": {"on_unhandled": on_unhandled},
        "limits": asdict(limits),
        "files": records,
        "totals": _totals(records),
        "unredacted_file_in_published_set": False,
    })
    try:
        target.mkdir(parents=True, exist_ok=True)
        for relative, data in outputs:
            atomic_bytes(beneath(target, target / relative), data)
        atomic_bytes(beneath(target, target / RECEIPT_FILENAME), receipt_bytes(receipt))
    except (OSError, ValueError):
        raise RedactionError(
            "published directory could not be written; it holds no receipt and must be treated as absent") from None
    return receipt


def receipt_bytes(receipt: dict) -> bytes:
    return (json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


# ---------------------------------------------------------------------------------------------
# Verification: re-derive every claim about the published bytes from the published bytes.
# ---------------------------------------------------------------------------------------------

def _schema_errors(receipt: Any) -> list[str]:
    # schema_validate echoes offending instance values; keep only the location and the rule.
    rules = ("missing required property", "unexpected property", "expected type", "not in enum",
             "does not match pattern", "expected const", "minItems")
    errors = []
    for message in validate_document(receipt, RECEIPT_SCHEMA):
        location, _, detail = message.partition(": ")
        rule = next((rule for rule in rules if rule in detail), "schema rule")
        if not re.fullmatch(r"\$[A-Za-z0-9_.\[\]\-]*", location):
            location = "$"
        errors.append(f"{location}: violates {RECEIPT_SCHEMA} ({rule})")
    return sorted(set(errors))


def _record_errors(index: int, record: dict, limits: Limits) -> list[str]:
    where, errors = f"files[{index}]", []
    counts = record["redactions"]
    total = sum(counts.values())
    if any(isinstance(value, bool) or value < 0 for value in [*counts.values(), record["preexisting_markers"]]):
        errors.append(f"{where}: redaction and marker counts must be non-negative integers")
    placeholder = bool(PLACEHOLDER_PATH_RE.match(record["path"]))
    if not placeholder and not _path_is_safe(record["path"], limits):
        errors.append(f"{where}: path must be a normalized relative path that itself passes the redactor")
    if record["disposition"] == "withheld":
        if record["withheld_reason"] is None:
            errors.append(f"{where}: a withheld file must name its withheld_reason")
        if any(record[key] is not None for key in ("parser_mode", "source_sha256", "published_sha256", "published_bytes")):
            errors.append(f"{where}: a withheld file must have null parser_mode, source_sha256, published_sha256 and published_bytes")
        if total or record["preexisting_markers"]:
            errors.append(f"{where}: a withheld file must have zero redactions and zero preexisting_markers")
        if placeholder != (record["withheld_reason"] == "unsafe-path"):
            errors.append(f"{where}: a placeholder path is used exactly when withheld_reason is 'unsafe-path'")
        return errors
    if placeholder:
        errors.append(f"{where}: only a withheld file may use a placeholder path")
    if record["withheld_reason"] is not None:
        errors.append(f"{where}: only a withheld file may carry a withheld_reason")
    if any(record[key] is None for key in ("parser_mode", "published_sha256", "published_bytes")):
        errors.append(f"{where}: a published file must have parser_mode, published_sha256 and published_bytes")
    if record["disposition"] == "unchanged":
        if total:
            errors.append(f"{where}: an unchanged file must have zero redactions")
        if record["source_sha256"] is None or record["source_sha256"] != record["published_sha256"]:
            errors.append(f"{where}: an unchanged file must have source_sha256 equal to published_sha256")
    else:
        if not total:
            errors.append(f"{where}: a redacted file must have at least one redaction")
        if record["source_sha256"] is not None:
            errors.append(f"{where}: a redacted file must have null source_sha256 (a source hash is an oracle for the removed value)")
    return errors


def _published_errors(index: int, record: dict, path: Path, root: Path, limits: Limits) -> list[str]:
    where = f"files[{index}] ({record['path']})"
    try:
        data = _read_bounded(root, path, limits)
    except (_Withhold, ValueError, OSError):
        return [f"{where}: published file is not a readable regular file within max_file_bytes"]
    errors = []
    if _sha256(data) != record["published_sha256"]:
        errors.append(f"{where}: published_sha256 does not match the published bytes")
    if len(data) != record["published_bytes"]:
        errors.append(f"{where}: published_bytes does not match the published file size")
    outcome = _process(data, record["path"], limits)
    if outcome.disposition != "unchanged":
        errors.append(f"{where}: published bytes are not a fixed point of this redactor under the receipt's limits "
                      "(re-running it would redact or withhold the file)")
        return errors
    if outcome.parser_mode != record["parser_mode"]:
        errors.append(f"{where}: parser_mode does not match the mode re-derived from the published bytes")
    found = {kind: 0 for kind in KINDS}
    ordinals = []
    for match in MARKER_RE.finditer(data.decode("utf-8")):
        found[match.group(1)] += 1
        ordinals.append(int(match.group(2)))
    counts, preexisting = record["redactions"], record["preexisting_markers"]
    if len(ordinals) != sum(counts.values()) + preexisting:
        errors.append(f"{where}: markers in the published bytes must equal redactions plus preexisting_markers")
    elif preexisting == 0 and (found != counts or sorted(ordinals) != list(range(1, len(ordinals) + 1))):
        errors.append(f"{where}: per-kind redaction counts and ordinals 1..n must match the markers in the published bytes")
    elif any(found[kind] < counts[kind] for kind in KINDS):
        errors.append(f"{where}: per-kind redaction counts exceed the markers in the published bytes")
    return errors


def verify_receipt(receipt: Any, published_dir: Any, *, on_unhandled: str, limits: Limits) -> None:
    """Raise ReceiptVerificationError unless `receipt` exactly describes `published_dir`.

    `published_dir`, `on_unhandled` and `limits` are all required: the consumer states the policy
    and bounds it demands, and every statement about published bytes is recomputed from them.
    `receipt_sha256` is an integrity check, not an authenticator -- whoever can rewrite the receipt
    can rehash it -- which is why nothing here trusts a field the bytes can contradict.
    """
    _check_arguments(on_unhandled, limits)
    root = Path(published_dir).absolute()
    errors = _schema_errors(receipt)
    if errors:
        raise ReceiptVerificationError(errors)
    if receipt["receipt_sha256"] != digest({key: value for key, value in receipt.items() if key != "receipt_sha256"}):
        errors.append("receipt_sha256 does not match the canonical digest of every other field")
    identity = {"name": REDACTOR_NAME, "module_version": MODULE_VERSION, "ruleset_sha256": RULESET_SHA256}
    if receipt["redactor"] != identity:
        errors.append("redactor identity must equal this module's name, module_version and ruleset_sha256; "
                      "a different ruleset cannot be re-derived here")
    if receipt["limits"] != asdict(limits):
        errors.append("limits must equal the limits the verifier requires")
    if receipt["policy"]["on_unhandled"] != on_unhandled:
        errors.append("policy.on_unhandled must equal the policy the verifier requires")
    records = receipt["files"]
    for index, record in enumerate(records):
        errors.extend(_record_errors(index, record, limits))
    if errors:
        raise ReceiptVerificationError(errors)

    if receipt["policy"]["on_unhandled"] == "refuse" and any(record["disposition"] == "withheld" for record in records):
        errors.append("policy.on_unhandled 'refuse' cannot coexist with a withheld file")
    if len(records) > limits.max_files:
        errors.append("files must not exceed limits.max_files")
    real = [record["path"] for record in records if not PLACEHOLDER_PATH_RE.match(record["path"])]
    if real != sorted(set(real)):
        errors.append("files must list each real path once, in ascending order")
    held = [int(PLACEHOLDER_PATH_RE.match(record["path"]).group(1)) for record in records if PLACEHOLDER_PATH_RE.match(record["path"])]
    if held != list(range(1, len(held) + 1)):
        errors.append("placeholder paths must be numbered 1..n in order")
    if receipt["totals"] != _totals(records):
        errors.append("totals must equal the sums of the per-file records")

    expected = {record["path"]: (index, record) for index, record in enumerate(records) if record["disposition"] != "withheld"}
    try:
        beneath(root, root)
        if not root.is_dir():
            raise ValueError
        # The published set is the receipt's files plus the receipt itself.
        present = {relative: (path, kind) for relative, path, kind
                   in _enumerate(root, replace(limits, max_files=limits.max_files + 1))}
    except (RedactionError, ValueError):
        raise ReceiptVerificationError(errors + ["published directory must be a real, listable directory within max_files"]) from None
    receipt_entry = present.pop(RECEIPT_FILENAME, None)
    for relative in sorted(set(present) - set(expected)):
        errors.append(f"published directory holds a file the receipt does not list: {_safe_label(relative, limits)}")
    for relative in sorted(set(expected) - set(present)):
        errors.append(f"published directory is missing a file the receipt lists: {relative}")
    try:
        if receipt_entry is None or receipt_entry[1] != "file":
            raise ValueError
        on_disk = json.loads(_read_bounded(root, receipt_entry[0], limits).decode("utf-8"))
    except (_Withhold, ValueError, OSError):
        on_disk = None
    if on_disk != receipt:
        errors.append(f"published directory must contain {RECEIPT_FILENAME} equal to the receipt being verified")
    for relative in sorted(set(expected) & set(present)):
        index, record = expected[relative]
        path, kind = present[relative]
        if kind != "file":
            errors.append(f"files[{index}] ({relative}): published entry must be a regular file, not a link or special file")
            continue
        errors.extend(_published_errors(index, record, path, root, limits))
    if errors:
        raise ReceiptVerificationError(errors)


# ---------------------------------------------------------------------------------------------
# CLI (prints counts, paths already proven safe, and reasons -- never content)
# ---------------------------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Redact a directory at a publication boundary, or verify a receipt.")
    commands = parser.add_subparsers(dest="command", required=True)
    redact = commands.add_parser("redact", help="redact <src> into an empty <dst> and write the receipt")
    redact.add_argument("src")
    redact.add_argument("dst")
    redact.add_argument("--policy", required=True, choices=POLICIES)
    verify = commands.add_parser("verify", help="verify <receipt> against the published directory <dst>")
    verify.add_argument("receipt")
    verify.add_argument("dst")
    verify.add_argument("--policy", required=True, choices=POLICIES)
    args = parser.parse_args(argv)
    try:
        if args.command == "redact":
            receipt = redact_tree(args.src, args.dst, on_unhandled=args.policy, limits=DEFAULT_LIMITS)
            print(json.dumps({"receipt_sha256": receipt["receipt_sha256"], "totals": receipt["totals"]}, sort_keys=True))
            return 0
        try:
            receipt = json.loads(Path(args.receipt).read_bytes().decode("utf-8"))
        except (OSError, ValueError):
            print("receipt file is not readable UTF-8 JSON", file=sys.stderr)
            return 1
        verify_receipt(receipt, args.dst, on_unhandled=args.policy, limits=DEFAULT_LIMITS)
        print(json.dumps({"verified": True, "receipt_sha256": receipt["receipt_sha256"]}, sort_keys=True))
        return 0
    except PublicationRefused as refused:
        print(str(refused), file=sys.stderr)
        return 2
    except RedactionError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
