"""Bounded, text-only parsers for accepted execution-profile exchange formats."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import astuple, dataclass, replace
import re


@dataclass(frozen=True, slots=True)
class ProfileRow:
    symbol: str
    count: int
    event: str = "samples"
    module: str | None = None
    source: str | None = None
    line: int | None = None
    cost_kind: str | None = None
    callsite_symbol: str | None = None
    callsite_source: str | None = None
    callsite_line: int | None = None


@dataclass(frozen=True, slots=True)
class ProfileDocument:
    format: str
    rows: tuple[ProfileRow, ...]
    gaps: tuple[str, ...] = ()


_INTEGER = re.compile(r"^[0-9]+$")
_PERF_HEADER = re.compile(
    r"^\s*.+?\s+\d+(?:/\d+)?\s+(?:\[\d+\]\s+)?[0-9.]+:\s+"
    r"(?:[0-9]+\s+)?(?P<event>\S+):(?:\s|$)")
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


def _rows(values: dict[ProfileRow, int]) -> tuple[ProfileRow, ...]:
    return tuple(replace(row, count=count) for row, count in sorted(
        values.items(), key=lambda item: tuple("" if value is None else str(value)
                                              for value in astuple(item[0]))) if count >= 0)


def parse_folded_stacks(data: bytes, *, max_rows: int = 250_000,
                        max_line_bytes: int = 64 * 1024,
                        max_frames_per_sample: int = 256) -> ProfileDocument:
    lines, gaps = _bounded_lines(data, max_rows=max_rows, max_line_bytes=max_line_bytes)
    values: dict[ProfileRow, int] = defaultdict(int)
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
            values[ProfileRow(frame, 0)] += count
    if not values:
        raise ValueError("folded-stack profile contains no samples")
    return ProfileDocument("folded-stacks", _rows(values), tuple(gaps))


def parse_perf_script(data: bytes, *, max_rows: int = 250_000,
                      max_line_bytes: int = 64 * 1024,
                      max_frames_per_sample: int = 256) -> ProfileDocument:
    lines, gaps = _bounded_lines(data, max_rows=max_rows, max_line_bytes=max_line_bytes)
    values: dict[ProfileRow, int] = defaultdict(int)
    event: str | None = None
    frames = 0
    saw_header = False
    for number, raw in enumerate([*lines, ""], 1):
        header = _PERF_HEADER.match(raw) if raw.strip() else None
        if header:
            event = header.group("event")
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
        values[ProfileRow(symbol, 0, event, module)] += 1
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
    callee_source_explicit = False
    callee_line: int | None = None
    pending_call = False
    values: dict[ProfileRow, int] = defaultdict(int)

    def reference(raw_value: str, refs: dict[str, str], kind: str, number: int) -> str | None:
        match = re.fullmatch(r"\(([^)]+)\)(?:\s+(.*))?", raw_value)
        if match and match.group(2):
            refs[match.group(1)] = match.group(2).strip()
            value = refs[match.group(1)]
        elif match:
            value = refs.get(match.group(1))
            if value is None:
                gaps.append(f"ambiguous_{kind}: row {number} references unknown id {match.group(1)}")
        else:
            value = raw_value or None
        if kind == "source" and value == "???":
            gaps.append(f"ambiguous_source: row {number} reports unknown file marker ???")
            return None
        return value

    def position(raw_value: str, previous: int | None, number: int) -> int | None:
        if _INTEGER.fullmatch(raw_value):
            return int(raw_value)
        if raw_value == "*" and previous is not None:
            return previous
        if re.fullmatch(r"[+-][0-9]+", raw_value) and previous is not None:
            return previous + int(raw_value)
        gaps.append(f"ambiguous_line: row {number} has unresolved position {raw_value}")
        return None

    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("events:"):
            events = line.split(":", 1)[1].split()
        elif line.startswith("positions:"):
            if line.split(":", 1)[1].split() != ["line"]:
                raise ValueError("unsupported Callgrind positions: only line positions are parsed")
        elif line.startswith(("fl=", "fi=")):
            source = reference(line.split("=", 1)[1].strip(), source_refs, "source", number)
        elif line.startswith("cfl="):
            callee_source = reference(line[4:].strip(), source_refs, "source", number)
            callee_source_explicit = True
        elif line.startswith("fn="):
            selected = reference(line[3:].strip(), symbol_refs, "symbol", number)
            if selected != symbol:
                current_line = None
            symbol = selected
            if pending_call:
                gaps.append(f"missing_call_cost: row {number} starts a function before its preceding call cost")
            pending_call = False
            callee_symbol = callee_source = callee_line = None
            callee_source_explicit = False
        elif line.startswith("cfn="):
            selected = reference(line[4:].strip(), symbol_refs, "symbol", number)
            if selected != callee_symbol:
                callee_line = None
            callee_symbol = selected
        elif line.startswith("calls="):
            fields = line[6:].split()
            if not fields or not _INTEGER.fullmatch(fields[0]) or len(fields) > 2:
                raise ValueError(f"invalid Callgrind call row {number}")
            if pending_call:
                gaps.append(f"missing_call_cost: row {number} replaces a call without its cost")
            pending_call = True
            callee_line = position(fields[1] if len(fields) == 2 else "", callee_line, number)
            if callee_symbol is None:
                gaps.append(f"ambiguous_symbol: row {number} call cost has no resolved callee")
        elif symbol and (line[0].isdigit() or line[0] in "+-*"):
            fields = line.split()
            if not events or len(fields) != 1 + len(events) or not all(_INTEGER.fullmatch(v) for v in fields[1:]):
                raise ValueError(f"invalid Callgrind cost row {number}")
            current_line = position(fields[0], current_line, number)
            line_number = current_line if current_line and current_line > 0 else None
            for event, raw_count in zip(events, fields[1:], strict=True):
                if pending_call:
                    if callee_symbol is None:
                        continue
                    # The cost position is the caller's; calls= supplies the callee's position.
                    row = ProfileRow(
                        callee_symbol, 0, event, source=callee_source if callee_source_explicit else source,
                        line=callee_line if callee_line and callee_line > 0 else None,
                        cost_kind="call_inclusive", callsite_symbol=symbol,
                        callsite_source=source, callsite_line=line_number)
                else:
                    row = ProfileRow(symbol, 0, event, source=source, line=line_number, cost_kind="self")
                values[row] += int(raw_count)
            pending_call = False
    if pending_call:
        gaps.append("missing_call_cost: profile ends before its final call cost")
    if not events or not values:
        raise ValueError("Callgrind profile contains no event costs")
    return ProfileDocument("callgrind", _rows(values), tuple(gaps))


def parse_llvm_sample_profile(data: bytes, *, max_rows: int = 250_000,
                              max_line_bytes: int = 64 * 1024, **_: int) -> ProfileDocument:
    lines, gaps = _bounded_lines(data, max_rows=max_rows, max_line_bytes=max_line_bytes)
    values: dict[ProfileRow, int] = defaultdict(int)
    for number, raw in enumerate(lines, 1):
        if not raw or raw[:1].isspace() or raw.lstrip().startswith("#"):
            continue
        match = _LLVM_HEADER.match(raw.strip())
        if match:
            values[ProfileRow(match.group(1).strip(), 0)] += int(match.group(2))
        else:
            gaps.append(f"malformed_llvm_header: row {number} is not a supported function header")
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
