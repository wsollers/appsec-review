"""Bounded, text-only parsers for accepted execution-profile exchange formats."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class ProfileRow:
    symbol: str
    count: int
    event: str = "samples"
    module: str | None = None
    source: str | None = None
    line: int | None = None


@dataclass(frozen=True, slots=True)
class ProfileDocument:
    format: str
    rows: tuple[ProfileRow, ...]
    gaps: tuple[str, ...] = ()


_INTEGER = re.compile(r"^[0-9]+$")
_PERF_HEADER = re.compile(r"^\s*.+?\s+\d+(?:/\d+)?\s+(?:\[\d+\]\s+)?[0-9.]+:\s+([^:]+):")
_PERF_FRAME = re.compile(r"^\s*(?:[0-9a-fA-F]+\s+)?(.+?)(?:\s+\(([^()]*)\))?\s*$")
_LLVM_HEADER = re.compile(r"^([^\s:#].*):([0-9]+):(?:[0-9]+)(?:\s+.*)?$")


def _text(data: bytes) -> str:
    if b"\x00" in data:
        raise ValueError("profile contains NUL bytes")
    try:
        return data.decode("utf-8-sig", errors="strict")
    except UnicodeError as exc:
        raise ValueError("profile is not UTF-8 text") from exc


def _bounded_lines(data: bytes, *, max_rows: int, max_line_bytes: int) -> tuple[list[str], list[str]]:
    if max_rows < 1 or max_line_bytes < 1:
        raise ValueError("profile parser bounds must be positive")
    lines = _text(data).splitlines()
    gaps: list[str] = []
    if len(lines) > max_rows:
        gaps.append(f"row_truncation: retained {max_rows} of {len(lines)} input lines")
        lines = lines[:max_rows]
    for line in lines:
        if len(line.encode("utf-8")) > max_line_bytes:
            raise ValueError(f"profile line exceeds {max_line_bytes} bytes")
    return lines, gaps


def _rows(values: dict[tuple[str, str, str | None, str | None, int | None], int]) -> tuple[ProfileRow, ...]:
    return tuple(ProfileRow(symbol, count, event, module, source, line)
                 for (symbol, event, module, source, line), count in sorted(
                     values.items(), key=lambda item: tuple("" if value is None else str(value)
                                                           for value in item[0])) if count >= 0)


def parse_folded_stacks(data: bytes, *, max_rows: int = 250_000,
                        max_line_bytes: int = 64 * 1024,
                        max_frames_per_sample: int = 256) -> ProfileDocument:
    lines, gaps = _bounded_lines(data, max_rows=max_rows, max_line_bytes=max_line_bytes)
    values: dict[tuple[str, str, str | None, str | None, int | None], int] = defaultdict(int)
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            stack, raw_count = line.rsplit(None, 1)
            count = int(raw_count)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"invalid folded-stack row {number}") from exc
        frames = [frame.strip() for frame in stack.split(";") if frame.strip()]
        if not frames or count < 0:
            raise ValueError(f"invalid folded-stack row {number}")
        if len(frames) > max_frames_per_sample:
            gaps.append(f"frame_truncation: row {number} retained {max_frames_per_sample} of {len(frames)} frames")
            frames = frames[-max_frames_per_sample:]
        for frame in frames:
            values[(frame, "samples", None, None, None)] += count
    if not values:
        raise ValueError("folded-stack profile contains no samples")
    return ProfileDocument("folded-stacks", _rows(values), tuple(gaps))


def parse_perf_script(data: bytes, *, max_rows: int = 250_000,
                      max_line_bytes: int = 64 * 1024,
                      max_frames_per_sample: int = 256) -> ProfileDocument:
    lines, gaps = _bounded_lines(data, max_rows=max_rows, max_line_bytes=max_line_bytes)
    values: dict[tuple[str, str, str | None, str | None, int | None], int] = defaultdict(int)
    event: str | None = None
    frames = 0
    saw_header = False
    for number, raw in enumerate([*lines, ""], 1):
        header = _PERF_HEADER.match(raw) if raw.strip() else None
        if header:
            event = header.group(1).strip()[:128]
            frames = 0
            saw_header = True
            continue
        if not raw.strip():
            event = None
            frames = 0
            continue
        if event is None or not raw[:1].isspace():
            continue
        match = _PERF_FRAME.match(raw)
        if not match:
            raise ValueError(f"invalid perf-script frame {number}")
        frames += 1
        if frames > max_frames_per_sample:
            if frames == max_frames_per_sample + 1:
                gaps.append(f"frame_truncation: sample ending near row {number} exceeded {max_frames_per_sample} frames")
            continue
        symbol = match.group(1).strip()
        module = (match.group(2) or "").strip() or None
        if symbol in {"[unknown]", "unknown"}:
            gaps.append(f"ambiguous_symbol: row {number} has no resolved symbol")
            continue
        values[(symbol, event, module, None, None)] += 1
    if not saw_header or not values:
        raise ValueError("perf-script profile contains no bounded samples")
    return ProfileDocument("perf-script", _rows(values), tuple(dict.fromkeys(gaps)))


def parse_callgrind(data: bytes, *, max_rows: int = 250_000,
                    max_line_bytes: int = 64 * 1024, **_: int) -> ProfileDocument:
    lines, gaps = _bounded_lines(data, max_rows=max_rows, max_line_bytes=max_line_bytes)
    events: list[str] = []
    source: str | None = None
    symbol: str | None = None
    source_refs: dict[str, str] = {}
    symbol_refs: dict[str, str] = {}
    current_line: int | None = None
    callee_symbol: str | None = None
    callee_source: str | None = None
    pending_call = False
    values: dict[tuple[str, str, str | None, str | None, int | None], int] = defaultdict(int)
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("events:"):
            events = line.split(":", 1)[1].split()
        elif line.startswith(("fl=", "fi=")):
            raw_value = line.split("=", 1)[1].strip()
            match = re.match(r"^\(([^)]+)\)(?:\s+(.*))?$", raw_value)
            if match and match.group(2):
                source = match.group(2).strip() or None
                if source:
                    source_refs[match.group(1)] = source
            elif match:
                source = source_refs.get(match.group(1))
                if source is None:
                    gaps.append(f"ambiguous_source: row {number} references unknown file id {match.group(1)}")
            else:
                source = raw_value or None
        elif line.startswith("cfl="):
            raw_value = line.split("=", 1)[1].strip()
            match = re.match(r"^\(([^)]+)\)(?:\s+(.*))?$", raw_value)
            if match and match.group(2):
                callee_source = match.group(2).strip() or None
                if callee_source:
                    source_refs[match.group(1)] = callee_source
            elif match:
                callee_source = source_refs.get(match.group(1))
            else:
                callee_source = raw_value or None
        elif line.startswith("fn="):
            raw_value = line[3:].strip()
            match = re.match(r"^\(([^)]+)\)(?:\s+(.*))?$", raw_value)
            selected: str | None
            if match and match.group(2):
                selected = match.group(2).strip() or None
                if selected:
                    symbol_refs[match.group(1)] = selected
            elif match:
                selected = symbol_refs.get(match.group(1))
                if selected is None:
                    gaps.append(f"ambiguous_symbol: row {number} references unknown function id {match.group(1)}")
            else:
                selected = raw_value or None
            if selected != symbol:
                current_line = None
            symbol = selected
        elif line.startswith("cfn="):
            raw_value = line[4:].strip()
            match = re.match(r"^\(([^)]+)\)(?:\s+(.*))?$", raw_value)
            if match and match.group(2):
                callee_symbol = match.group(2).strip() or None
                if callee_symbol:
                    symbol_refs[match.group(1)] = callee_symbol
            elif match:
                callee_symbol = symbol_refs.get(match.group(1))
            else:
                callee_symbol = raw_value or None
        elif line.startswith("calls="):
            pending_call = True
            if callee_symbol is None:
                gaps.append(f"ambiguous_symbol: row {number} call cost has no resolved callee")
        elif symbol and (line[0].isdigit() or line[0] in "+-*"):
            fields = line.split()
            if not events or len(fields) < 1 + len(events) or not all(_INTEGER.fullmatch(v) for v in fields[1:1 + len(events)]):
                raise ValueError(f"invalid Callgrind cost row {number}")
            position = fields[0]
            if _INTEGER.fullmatch(position):
                current_line = int(position)
            elif position == "*":
                pass
            elif re.fullmatch(r"[+-][0-9]+", position) and current_line is not None:
                current_line += int(position)
            else:
                gaps.append(f"ambiguous_line: row {number} has unresolved position {position}")
                current_line = None
            line_number = current_line if current_line and current_line > 0 else None
            active_symbol = callee_symbol if pending_call and callee_symbol else symbol
            active_source = callee_source if pending_call and callee_source else source
            for event, raw_count in zip(events, fields[1:], strict=True):
                values[(active_symbol, event[:128], None, active_source, line_number)] += int(raw_count)
            pending_call = False
    if not events or not values:
        raise ValueError("Callgrind profile contains no event costs")
    return ProfileDocument("callgrind", _rows(values), tuple(gaps))


def parse_llvm_sample_profile(data: bytes, *, max_rows: int = 250_000,
                              max_line_bytes: int = 64 * 1024, **_: int) -> ProfileDocument:
    lines, gaps = _bounded_lines(data, max_rows=max_rows, max_line_bytes=max_line_bytes)
    values: dict[tuple[str, str, str | None, str | None, int | None], int] = defaultdict(int)
    for raw in lines:
        if not raw or raw[:1].isspace() or raw.lstrip().startswith("#"):
            continue
        match = _LLVM_HEADER.match(raw.strip())
        if match:
            values[(match.group(1).strip(), "samples", None, None, None)] += int(match.group(2))
    if not values:
        raise ValueError("LLVM sample profile contains no function headers")
    return ProfileDocument("llvm-sample", _rows(values), tuple(gaps))


PARSERS = {
    "folded-stacks": parse_folded_stacks,
    "perf-script": parse_perf_script,
    "callgrind": parse_callgrind,
    "llvm-sample": parse_llvm_sample_profile,
}


def parse_profile(data: bytes, format_name: str, *, max_rows: int = 250_000,
                  max_line_bytes: int = 64 * 1024,
                  max_frames_per_sample: int = 256) -> ProfileDocument:
    """Parse one explicitly selected text format without executing or deserializing it."""
    parser = PARSERS.get(format_name)
    if parser is None:
        raise ValueError(f"unsupported profile format: {format_name}")
    return parser(data, max_rows=max_rows, max_line_bytes=max_line_bytes,
                  max_frames_per_sample=max_frames_per_sample)
