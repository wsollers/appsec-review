#!/usr/bin/env python3
"""Bounded, hash-verified, redacted code snippets for report findings (ADR-0020).

Python, not the model, cuts the snippet: +-``CONTEXT`` lines around the cited flaw lines, read from
the run's projected source checkout only when the file's bytes match the ``source_sha256`` the tool
lead cited, passed through the evidence redactor (``evidence_redaction``), and bounded in lines and
characters.  A snippet that cannot be verified is withheld with a reason, never approximated.
"""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import evidence_redaction

CONTEXT = 5
MAX_LINES = 41
MAX_LINE_CHARS = 200
MAX_FILE_BYTES = 4 * 1024 * 1024


def source_roots(run_root: Path) -> list[Path]:
    """Projected source trees of a run (``data/automatic-inputs/source/*/tree``), sorted."""
    base = Path(run_root) / "data" / "automatic-inputs" / "source"
    if not base.is_dir():
        return []
    return sorted(path / "tree" for path in base.iterdir()
                  if (path / "tree").is_dir() and not path.is_symlink() and not (path / "tree").is_symlink())


def _safe_file(root: Path, relative: str) -> Path | None:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        return None
    cursor = Path(root)
    for part in pure.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            return None
    if not cursor.is_file():
        return None
    try:
        cursor.resolve(strict=True).relative_to(Path(root).resolve(strict=True))
    except (OSError, ValueError):
        return None
    return cursor


def redact_lines(lines: list[str]) -> tuple[list[str], int]:
    """Run the evidence redactor over the joined snippet; returns (lines, marker count)."""
    tally = evidence_redaction._Tally()
    try:
        text = evidence_redaction._redact_text("\n".join(lines), tally)
    except evidence_redaction._Withhold:
        return [], -1
    return text.split("\n"), tally.total


def extract(roots: Iterable[Path], path: str, source_sha256: str | None, flaw: list[int],
            context: int = CONTEXT, note: str | None = None) -> dict[str, Any]:
    flaw = sorted({int(line) for line in flaw if isinstance(line, int) and line > 0})
    base = {"path": path, "flaw": flaw, "note": note, "source_sha256": source_sha256}
    if not flaw or not source_sha256:
        return {**base, "status": "WITHHELD", "reason": "finding cites no line or no source hash"}
    for root in roots:
        file = _safe_file(Path(root), path)
        if file is None or file.stat().st_size > MAX_FILE_BYTES:
            continue
        data = file.read_bytes()
        if "sha256:" + hashlib.sha256(data).hexdigest() != source_sha256:
            continue
        text = data.decode("utf-8", errors="replace").expandtabs(4).splitlines()
        if flaw[-1] > len(text):
            return {**base, "status": "WITHHELD", "reason": "cited line is beyond the verified file"}
        start = max(1, flaw[0] - context)
        end = min(len(text), flaw[-1] + context, start + MAX_LINES - 1)
        lines = [line[:MAX_LINE_CHARS] for line in text[start - 1:end]]
        redacted, markers = redact_lines(lines)
        if markers < 0:
            return {**base, "status": "WITHHELD", "reason": "redactor did not converge on the snippet"}
        return {**base, "status": "VERIFIED", "start": start, "end": start + len(redacted) - 1,
                "source": redacted, "redaction_markers": markers,
                "flaw": [line for line in flaw if start <= line <= start + len(redacted) - 1]}
    return {**base, "status": "WITHHELD", "reason": "no projected checkout file matches the cited source hash"}
