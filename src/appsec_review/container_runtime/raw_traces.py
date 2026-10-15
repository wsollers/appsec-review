"""Bounded debug retention of the build collector's raw per-process trace files."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
import re
from typing import Any


RAW_TRACE_DIRECTORY = "raw-traces"
REDACTED_VALUE = "<redacted: envp_redact_names>"
_UNPARSED_ROW = re.compile(r"^(?P<prefix>unparsed .+ row: )(?P<name>trace(?:\.[0-9]+)?):(?P<line>[0-9]+)$")


def _envp_redactor(names: Sequence[str]):
    if not names:
        return lambda line: line
    # strace renders each envp entry as a C string literal: "NAME=value" with escapes.
    pattern = re.compile(
        rb'"(' + b"|".join(re.escape(name.encode("ascii")) for name in names) +
        rb')=(?:[^"\\]|\\.)*("|(?=\.\.\.)|$)')
    replacement = b'"\\1=' + REDACTED_VALUE.encode("ascii") + b'\\2'
    return lambda line: pattern.sub(replacement, line)


def retain_raw_traces(capture_root: Path, trace_paths: Sequence[Path], *, bytes_limit: int,
                      envp_redact_names: Sequence[str] = ()) -> dict[str, Any]:
    """Copy raw traces beside the record, stopping at ``bytes_limit`` retained bytes in total.

    Values of configured ``envp_redact_names`` are redacted exactly as in normalized events. A
    file that crosses the bound keeps only whole lines below it. Every file the collector wrote is
    listed, so omission and truncation are explicit rather than inferred from absence.
    """
    if bytes_limit < 1:
        raise ValueError("raw trace byte limit must be positive")
    redact = _envp_redactor(tuple(envp_redact_names))
    root = capture_root / RAW_TRACE_DIRECTORY
    root.mkdir(mode=0o700, exist_ok=True)
    remaining = bytes_limit
    records: list[dict[str, Any]] = []
    observed_bytes = retained_bytes = 0
    for source in sorted(trace_paths, key=lambda item: item.name):
        if source.is_symlink() or not source.is_file():
            continue
        size = source.stat().st_size
        observed_bytes += size
        record: dict[str, Any] = {"source": source.name, "bytes": size}
        if remaining <= 0:
            records.append({**record, "retained": False, "retained_bytes": 0,
                            "retained_lines": 0, "truncated": True})
            continue
        target = root / source.name
        kept = lines = 0
        truncated = False
        with source.open("rb") as reader, target.open("wb") as writer:
            for raw in reader:
                line = redact(raw)
                if kept + len(line) > remaining:
                    truncated = True
                    break
                writer.write(line)
                kept += len(line)
                lines += 1
        if truncated:
            remaining = 0  # Later files are listed as omitted rather than partially retained.
        else:
            remaining -= kept
        if truncated and kept == 0:
            target.unlink()
            records.append({**record, "retained": False, "retained_bytes": 0,
                            "retained_lines": 0, "truncated": True})
            continue
        target.chmod(0o600)
        retained_bytes += kept
        records.append({**record, "retained": True,
                        "uri": f"{RAW_TRACE_DIRECTORY}/{source.name}",
                        "retained_bytes": kept, "retained_lines": lines,
                        "truncated": truncated})
    return {"enabled": True, "bytes_limit": bytes_limit, "observed_files": len(records),
            "observed_bytes": observed_bytes, "retained_bytes": retained_bytes,
            "truncated": any(item["truncated"] for item in records), "records": records}


def reference_raw_traces(errors: Sequence[str], raw_traces: Mapping[str, Any] | None) -> tuple[str, ...]:
    """Name the retained raw-trace file and line for each unparsed collector row."""
    by_source = {str(item["source"]): item for item in (raw_traces or {}).get("records", ())}
    result = []
    for error in errors:
        match = _UNPARSED_ROW.match(error)
        if match is None:
            result.append(error)
            continue
        line = int(match.group("line"))
        item = by_source.get(match.group("name"))
        if raw_traces is None:
            where = "raw trace not retained: build_capture.retain_raw_traces is disabled"
        elif item is None or not item.get("retained"):
            where = "raw trace not retained: raw_trace_bytes_limit reached"
        elif line > int(item["retained_lines"]):
            where = f"{item['uri']} was truncated before line {line}"
        else:
            where = f"retained as {item['uri']} line {line}"
        result.append(f"{error} ({where})")
    return tuple(result)
