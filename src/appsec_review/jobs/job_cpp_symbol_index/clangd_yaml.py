r"""Strict parser for the YAML subset clangd-indexer emits with ``--format=yaml``.

clangd writes a stream of ``--- !Tag`` documents terminated by ``...``. Each document uses
block mappings, block sequences of mappings, and plain, single-quoted or double-quoted scalars.
clangd 23 writes ``Documentation`` as a one-line double-quoted scalar with YAML escapes (``\n``,
``\"``, ``\\``, ``\t``, ``\xXX``, ``\uXXXX``); the parser decodes exactly the YAML 1.2 escape set
and raises ``ValueError`` on anything else, rather than guessing.
A trailing document without its ``...`` terminator (for example after output truncation) is
reported, not parsed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator


@dataclass(frozen=True, slots=True)
class Document:
    tag: str
    value: dict[str, Any]


def _scalar(text: str) -> str:
    text = text.strip()
    if text.startswith("'"):
        if len(text) < 2 or not text.endswith("'"):
            raise ValueError("unterminated single-quoted scalar")
        return text[1:-1].replace("''", "'")
    if text.startswith('"'):
        return _double_quoted(text)
    return text


_SIMPLE_ESCAPES = {
    "0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v", "f": "\f",
    "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0",
    "L": "\u2028", "P": "\u2029",
}
_HEX_ESCAPE_WIDTHS = {"x": 2, "u": 4, "U": 8}
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _double_quoted(text: str) -> str:
    """Decode one single-line double-quoted scalar (``text`` starts with ``"``).

    Only the YAML 1.2 escape set is accepted; an unknown escape, a malformed hexadecimal escape, a
    surrogate or out-of-range code point, content after the closing quote, or a missing closing
    quote raises ``ValueError``. The scan is a single bounded pass over ``text``.
    """
    out: list[str] = []
    index = 1
    while index < len(text):
        char = text[index]
        if char == '"':
            if index != len(text) - 1:
                raise ValueError("content after the closing double quote")
            return "".join(out)
        if char != "\\":
            out.append(char)
            index += 1
            continue
        index += 1
        if index >= len(text):
            break
        escape = text[index]
        if escape in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[escape])
            index += 1
            continue
        width = _HEX_ESCAPE_WIDTHS.get(escape)
        if width is None:
            raise ValueError(f"unsupported escape in double-quoted scalar: \\{escape}")
        digits = text[index + 1:index + 1 + width]
        if len(digits) != width or any(digit not in _HEX_DIGITS for digit in digits):
            raise ValueError(f"malformed \\{escape} escape in double-quoted scalar")
        code = int(digits, 16)
        if code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
            raise ValueError(f"invalid code point in double-quoted scalar: U+{code:X}")
        out.append(chr(code))
        index += 1 + width
    raise ValueError("unterminated double-quoted scalar")


def _quote_open(text: str) -> bool:
    """True when a single-quoted scalar starts in ``text`` but does not close on this line."""
    stripped = text.strip()
    if not stripped.startswith("'"):
        return False
    body = stripped[1:]
    index = 0
    while index < len(body):
        if body[index] == "'":
            if index + 1 < len(body) and body[index + 1] == "'":
                index += 2
                continue
            return False
        index += 1
    return True


def _logical_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Return (indent, content) pairs, folding multi-line single-quoted scalars into one line."""
    result: list[tuple[int, str]] = []
    pending: list[str] | None = None
    indent = 0
    for raw in lines:
        if pending is not None:
            pending.append(raw.strip())
            joined = " ".join(pending)
            if not _quote_open(joined.split(":", 1)[1] if ":" in joined and not joined.startswith("- ")
                               else joined):
                result.append((indent, joined))
                pending = None
            continue
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        content = raw.strip()
        _key, separator, value = content.partition(": ")
        if separator and _quote_open(value):
            pending = [content]
            continue
        result.append((indent, content))
    if pending is not None:
        raise ValueError("unterminated multi-line scalar")
    return result


def _block(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    if index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
        items = []
        while index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
            # "- key: value" opens a mapping item whose keys sit two columns deeper.
            first = (indent + 2, lines[index][1][2:])
            item_lines = [first]
            index += 1
            while index < len(lines) and lines[index][0] > indent:
                item_lines.append(lines[index])
                index += 1
            value, consumed = _block(item_lines, 0, indent + 2)
            if consumed != len(item_lines):
                raise ValueError("sequence item has inconsistent indentation")
            items.append(value)
        return items, index
    mapping: dict[str, Any] = {}
    while index < len(lines) and lines[index][0] == indent:
        content = lines[index][1]
        if content.startswith("- "):
            break
        key, separator, rest = content.partition(":")
        if not separator or not key or key != key.strip():
            raise ValueError(f"expected a mapping key: {content[:80]!r}")
        if key in mapping:
            raise ValueError(f"duplicate mapping key: {key}")
        index += 1
        if rest.strip():
            mapping[key] = _scalar(rest)
        elif index < len(lines) and lines[index][0] > indent:
            mapping[key], index = _block(lines, index, lines[index][0])
        elif index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
            mapping[key], index = _block(lines, index, indent)
        else:
            mapping[key] = ""
    if index < len(lines) and lines[index][0] > indent:
        raise ValueError("unexpected indentation")
    return mapping, index


def parse_documents(text: str, *, document_limit: int) -> tuple[list[Document], bool, bool]:
    """Parse clangd YAML; return (documents, truncated_tail, capped)."""
    documents: list[Document] = []
    tag: str | None = None
    body: list[str] = []
    capped = False
    for raw in text.splitlines():
        if raw.startswith("--- "):
            if tag is not None:
                raise ValueError("document started before the previous one ended")
            tag = raw[4:].strip()
            if not tag.startswith("!") or len(tag) > 64:
                raise ValueError(f"unexpected document tag: {tag[:64]!r}")
            body = []
        elif raw == "...":
            if tag is None:
                raise ValueError("document end without a start")
            if len(documents) >= document_limit:
                capped = True
                tag = None
                break
            lines = _logical_lines(body)
            value, consumed = _block(lines, 0, 0) if lines else ({}, 0)
            if consumed != len(lines) or not isinstance(value, dict):
                raise ValueError(f"malformed {tag} document")
            documents.append(Document(tag[1:], value))
            tag = None
        elif tag is None:
            if raw.strip():
                raise ValueError("content outside a document")
        else:
            body.append(raw)
    return documents, tag is not None, capped


def iter_tagged(documents: list[Document], tag: str) -> Iterator[dict[str, Any]]:
    return (document.value for document in documents if document.tag == tag)
