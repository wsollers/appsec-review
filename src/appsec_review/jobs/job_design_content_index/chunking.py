"""Deterministic structure-aware chunking of design-artifact text.

Chunks are inclusive 1-based line ranges with exact byte offsets into the exact bytes that were
read, so every chunk resolves to source lines (or to converted-text characters). Content is data:
it is split by fixed syntax markers only and is never interpreted.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
import re
from typing import Any


CHUNKER_IDENTITY = "design-content-chunker/1"
_MD_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_ADOC_HEADING = re.compile(r"^(={1,6})\s+(.+?)\s*$")
_ORG_HEADING = re.compile(r"^(\*{1,6})\s+(.+?)\s*$")
_RST_UNDERLINE = re.compile(r"^([=\-~^\"'`#*+])\1{2,}\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")
_BLOCK = re.compile(r"^\s*(?:extend\s+)?(service|message|enum|struct|union|exception|interface|"
                    r"protocol|record|table|type|input|scalar|schema|resource|operation|structure)\s+"
                    r"([A-Za-z_][\w.]*)?")
_HTTP_SEPARATOR = re.compile(r"^###")


@dataclass(frozen=True, slots=True)
class Chunk:
    start_line: int
    end_line: int
    kind: str
    heading: str
    heading_path: tuple[str, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)


class Lines:
    """Line table over decoded text that maps line ranges back to exact byte offsets."""

    def __init__(self, text: str):
        self.text = text
        self.lines = text.splitlines(keepends=True) or [""]
        self.byte_offsets = [0]
        self.char_offsets = [0]
        for line in self.lines:
            self.byte_offsets.append(self.byte_offsets[-1] + len(line.encode("utf-8")))
            self.char_offsets.append(self.char_offsets[-1] + len(line))

    def __len__(self) -> int:
        return len(self.lines)

    def line(self, number: int) -> str:
        return self.lines[number - 1].rstrip("\r\n")

    def span_text(self, start: int, end: int) -> str:
        return "".join(self.lines[start - 1:end])

    def bytes_span(self, start: int, end: int) -> tuple[int, int]:
        return self.byte_offsets[start - 1], self.byte_offsets[end]

    def chars_span(self, start: int, end: int) -> tuple[int, int]:
        return self.char_offsets[start - 1], self.char_offsets[end]


def _sections(lines: Lines, headings: list[tuple[int, int, str]], kind: str = "section") -> list[Chunk]:
    """Turn (line, level, title) headings into contiguous sections with breadcrumb paths."""
    chunks: list[Chunk] = []
    if not headings or headings[0][0] > 1:
        first = headings[0][0] - 1 if headings else len(lines)
        if first >= 1 and lines.span_text(1, first).strip():
            chunks.append(Chunk(1, first, "preamble", "(preamble)"))
    stack: list[tuple[int, str]] = []
    for index, (line, level, title) in enumerate(headings):
        end = headings[index + 1][0] - 1 if index + 1 < len(headings) else len(lines)
        while stack and stack[-1][0] >= level:
            stack.pop()
        stack.append((level, title))
        chunks.append(Chunk(line, max(line, end), kind, title, tuple(item[1] for item in stack)))
    return chunks


def markdown(lines: Lines) -> list[Chunk]:
    headings: list[tuple[int, int, str]] = []
    fenced = False
    for number in range(1, len(lines) + 1):
        text = lines.line(number)
        if _FENCE.match(text):
            fenced = not fenced
            continue
        match = None if fenced else _MD_HEADING.match(text)
        if match:
            headings.append((number, len(match.group(1)), match.group(2)[:200]))
    return _sections(lines, headings)


def asciidoc(lines: Lines) -> list[Chunk]:
    headings = [(number, len(match.group(1)), match.group(2)[:200])
                for number in range(1, len(lines) + 1)
                if (match := _ADOC_HEADING.match(lines.line(number)))]
    return _sections(lines, headings)


def org(lines: Lines) -> list[Chunk]:
    headings = [(number, len(match.group(1)), match.group(2)[:200])
                for number in range(1, len(lines) + 1)
                if (match := _ORG_HEADING.match(lines.line(number)))]
    return _sections(lines, headings)


def rst(lines: Lines) -> list[Chunk]:
    levels: dict[str, int] = {}
    headings: list[tuple[int, int, str]] = []
    for number in range(2, len(lines) + 1):
        title, underline = lines.line(number - 1), lines.line(number)
        match = _RST_UNDERLINE.match(underline)
        if match and title.strip() and len(underline.strip()) >= len(title.strip()) and \
                not _RST_UNDERLINE.match(title):
            level = levels.setdefault(match.group(1), len(levels) + 1)
            headings.append((number - 1, level, title.strip()[:200]))
    return _sections(lines, headings)


def brace_blocks(lines: Lines) -> list[Chunk]:
    """Top-level `keyword Name {...}` blocks for IDL-like syntaxes, ignoring comments and strings.

    Lines outside any block (package, import, option, syntax) become `declarations` chunks so that
    every non-blank line stays searchable.
    """
    code: list[str] = []
    in_block_comment = False
    for number in range(1, len(lines) + 1):
        text, in_block_comment = _strip_code(lines.line(number), in_block_comment)
        code.append(text)
    blocks: list[Chunk] = []
    depth = 0
    start: tuple[int, str, str] | None = None
    opened = False
    for number, text in enumerate(code, 1):
        if depth == 0 and start is None:
            match = _BLOCK.match(text)
            if match:
                start, opened = (number, match.group(1), match.group(2) or match.group(1)), False
        if "{" in text:
            opened = True
        depth = max(0, depth + text.count("{") - text.count("}"))
        if start is None or depth != 0:
            continue
        upcoming = next((value.strip() for value in code[number:] if value.strip()), "")
        if opened or not upcoming.startswith("{"):
            blocks.append(Chunk(start[0], number, start[1], f"{start[1]} {start[2]}"[:200]))
            start = None
    covered = {line for chunk in blocks for line in range(chunk.start_line, chunk.end_line + 1)}
    run_start = None
    declarations: list[Chunk] = []
    for number in range(1, len(lines) + 2):
        free = number <= len(lines) and number not in covered
        if free and run_start is None:
            run_start = number
        elif not free and run_start is not None:
            if lines.span_text(run_start, number - 1).strip():
                declarations.append(Chunk(run_start, number - 1, "declarations", "declarations"))
            run_start = None
    return sorted([*blocks, *declarations], key=lambda chunk: chunk.start_line)


def _strip_code(line: str, in_block_comment: bool) -> tuple[str, bool]:
    result: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(line):
        pair = line[index:index + 2]
        if in_block_comment:
            if pair == "*/":
                in_block_comment = False
                index += 2
                continue
            index += 1
            continue
        character = line[index]
        if quote:
            if character == "\\":
                index += 2
                continue
            if character == quote:
                quote = None
            index += 1
            continue
        if pair == "/*":
            in_block_comment = True
            index += 2
            continue
        if pair == "//" or character == "#":
            break
        if character in {'"', "'"}:
            quote = character
            index += 1
            continue
        result.append(character)
        index += 1
    return "".join(result), in_block_comment


def http_requests(lines: Lines) -> list[Chunk]:
    separators = [number for number in range(1, len(lines) + 1) if _HTTP_SEPARATOR.match(lines.line(number))]
    bounds = [1, *separators, len(lines) + 1]
    chunks = []
    for start, stop in zip(bounds, bounds[1:]):
        end = stop - 1
        if end >= start and lines.span_text(start, end).strip():
            title = lines.line(start).lstrip("#").strip() or lines.line(min(start + 1, end)).strip()
            chunks.append(Chunk(start, end, "request", title[:200] or "request"))
    return chunks


def windows(lines: Lines, *, max_lines: int, start: int = 1, end: int | None = None,
            kind: str = "window", heading: str = "", heading_path: tuple[str, ...] = (),
            attributes: Mapping[str, Any] | None = None) -> list[Chunk]:
    end = len(lines) if end is None else end
    chunks = []
    for first in range(start, end + 1, max_lines):
        last = min(end, first + max_lines - 1)
        if lines.span_text(first, last).strip():
            chunks.append(Chunk(first, last, kind, heading or f"lines {first}-{last}", heading_path,
                                dict(attributes or {})))
    return chunks


def split_oversized(lines: Lines, chunks: list[Chunk], *, max_lines: int, max_bytes: int) -> list[Chunk]:
    """Split any chunk above the line or byte bound into windows that keep its heading context."""
    result: list[Chunk] = []
    for chunk in chunks:
        start_byte, end_byte = lines.bytes_span(chunk.start_line, chunk.end_line)
        if chunk.end_line - chunk.start_line + 1 <= max_lines and end_byte - start_byte <= max_bytes:
            result.append(chunk)
            continue
        step = max_lines
        while step > 1:
            widest = max((lines.bytes_span(first, min(chunk.end_line, first + step - 1))[1] -
                          lines.bytes_span(first, min(chunk.end_line, first + step - 1))[0])
                         for first in range(chunk.start_line, chunk.end_line + 1, step))
            if widest <= max_bytes:
                break
            step = max(1, step // 2)
        for part in windows(lines, max_lines=step, start=chunk.start_line, end=chunk.end_line,
                            kind=chunk.kind, heading=chunk.heading, heading_path=chunk.heading_path,
                            attributes=chunk.attributes):
            result.append(part)
    return result


MARKUP_CHUNKERS = {".md": markdown, ".markdown": markdown, ".adoc": asciidoc, ".asciidoc": asciidoc,
                   ".rst": rst, ".org": org}
BLOCK_SUFFIXES = {".proto", ".thrift", ".avdl", ".fbs", ".capnp", ".smithy", ".idl", ".aidl",
                  ".graphql", ".graphqls", ".gql"}
SKIPPED_SUFFIXES = {".png", ".svg", ".drawio", ".tm7", ".pdf", ".docx", ".doc", ".odt", ".rtf", ".epub",
                    ".vsdx", ".vsd", ".pptx"}


def structural_chunks(path: str, lines: Lines, *, max_lines: int) -> tuple[list[Chunk], str]:
    """Return format-structural chunks and the method name used for them."""
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in MARKUP_CHUNKERS:
        return MARKUP_CHUNKERS[suffix](lines), f"{suffix.lstrip('.')}-sections"
    if suffix in BLOCK_SUFFIXES:
        chunks = brace_blocks(lines)
        if chunks:
            return chunks, "idl-blocks"
    if suffix in {".http", ".rest"}:
        return http_requests(lines), "http-requests"
    return windows(lines, max_lines=max_lines), "line-windows"
