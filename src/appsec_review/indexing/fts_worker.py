"""Offline validation of accepted-shard FTS5 content with the pinned ``tool-sqlite-fts`` image.

The in-process :class:`~appsec_review.retrieval.index.IndexBuilder` remains the only producer of
accepted retrieval shards; MCP reads nothing else. This worker exports the already-sanitized
``search_fts`` documents of shards this job published as bounded JSONL, rebuilds them with the
pinned image (network-less, read-only root), verifies the image's FTS5 capability and pinned image
ID, and cross-checks record count, input hash and deterministic probe terms against the in-process
shards. The image-built database is retained only as an ``artifact_only`` validation receipt.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
from typing import Any

from appsec_review.indexing.store import open_shard, shard_key
from appsec_review.storage import atomic_json, file_sha256


TOOL_ID = "tool-sqlite-fts"
EXECUTABLE = "/opt/tool/bin/sqlite-fts"
DOCUMENT_SCHEMA = "appsec-review/sqlite-fts-documents/1"
RECEIPT_SCHEMA = "appsec-review/sqlite-fts-validation/1"
MODES = ("disabled", "optional", "required")
_TERM = re.compile(r"[A-Za-z][A-Za-z0-9_]{3,31}")
_SENSITIVE_VALUE = re.compile(r"(?i)\b(?:password|passwd|token|secret|api[_-]?key|credential)\s*[:=]\s*\S+")


class FtsValidationError(RuntimeError):
    """The image-built FTS disagrees with the accepted in-process shards in ``required`` mode."""


def export_documents(run_root: Path, shards: Sequence[Mapping[str, Any]], destination: Path, *,
                     max_records: int, max_input_bytes: int, max_text_bytes: int) -> dict[str, Any]:
    """Write sanitized, bounded FTS documents in identity order; refuse instead of truncating."""
    rows: dict[str, tuple[str, str, str]] = {}
    input_bytes = 0
    for shard in shards:
        with open_shard(run_root, shard) as database:
            for row in database.execute("SELECT identity, name, path, text FROM search_fts"):
                identity = str(row[0])
                value = (str(row[1]), str(row[2] or ""), str(row[3]))
                if _SENSITIVE_VALUE.search(value[0]) or _SENSITIVE_VALUE.search(value[2]):
                    return {"status": "skipped", "reason": "accepted FTS text contains a sensitive key/value "
                            "pattern; image export refused"}
                if len(value[2].encode("utf-8")) > max_text_bytes:
                    return {"status": "skipped", "reason": f"document {identity} exceeds the text byte bound"}
                previous = rows.get(identity)
                if previous is not None:
                    if previous != value:
                        return {"status": "skipped", "reason": f"conflicting accepted FTS identity {identity}"}
                    continue
                if len(rows) >= max_records:
                    return {"status": "skipped", "reason": f"documents exceed the {max_records}-record bound"}
                encoded = json.dumps({"identity": identity, "name": value[0][:4096],
                                      "path": value[1][:4096], "text": value[2]},
                                     sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
                input_bytes += len(encoded)
                if input_bytes > max_input_bytes:
                    return {"status": "skipped", "reason": f"document stream exceeds the {max_input_bytes}-byte bound"}
                rows[identity] = value
    lines: list[bytes] = []
    for identity in sorted(rows):
        name, path, text = rows[identity]
        logical = PurePosixPath(path) if path else None
        if logical is not None and (logical.is_absolute() or ".." in logical.parts or "\\" in path):
            return {"status": "skipped", "reason": f"document {identity} has a non-logical path"}
        lines.append(json.dumps({"identity": identity, "name": name[:4096], "path": path[:4096], "text": text},
                                sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n")
    data = b"".join(lines)
    if len(data) > max_input_bytes:
        return {"status": "skipped", "reason": f"document stream exceeds the {max_input_bytes}-byte bound"}
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return {"status": "exported", "record_count": len(lines), "input_sha256": hashlib.sha256(data).hexdigest(),
            "terms": _probe_terms(rows)}


def _probe_terms(rows: Mapping[str, tuple[str, str, str]], count: int = 5) -> list[str]:
    seen: list[str] = []
    for identity in sorted(rows):
        for term in _TERM.findall(rows[identity][0] + " " + rows[identity][2]):
            lowered = term.lower()
            if lowered not in seen:
                seen.append(lowered)
            if len(seen) >= count:
                return seen
    return seen


def _matches(database: sqlite3.Connection, term: str) -> set[str]:
    return {str(row[0]) for row in database.execute(
        "SELECT identity FROM search_fts WHERE search_fts MATCH ?", ('"' + term.replace('"', '""') + '"',))}


def validate_shards(run_root: Path, scratch: Path, shards: Sequence[Mapping[str, Any]], *, mode: str,
                    expected_image_id: str | None, executor_factory: Callable[[], Any],
                    request_type: Any, max_records: int, max_input_bytes: int,
                    max_text_bytes: int) -> dict[str, Any]:
    """Return a validation receipt; never alters accepted shards."""
    if mode not in MODES:
        raise ValueError(f"invalid FTS image validation mode: {mode}")
    shard_refs = [{"name": key[0], "shard_id": key[1], "sha256": str(item["sha256"])}
                  for item, key in ((item, shard_key(item)) for item in shards)]
    receipt: dict[str, Any] = {"schema": RECEIPT_SCHEMA, "tool_id": TOOL_ID, "mode": mode,
                               "expected_image_id": expected_image_id, "shards": shard_refs, "gaps": []}

    def finish(status: str, gap: str | None = None, **values: Any) -> dict[str, Any]:
        receipt.update(status=status, **values)
        if gap:
            receipt["gaps"].append(gap)
        scratch.mkdir(parents=True, exist_ok=True)
        path = scratch / "receipt.json"
        atomic_json(path, receipt)
        receipt["receipt"] = {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path)}
        if status in {"mismatch", "unavailable", "skipped"} and mode == "required":
            raise FtsValidationError("; ".join(receipt["gaps"]) or "required FTS image validation did not complete")
        return receipt

    if mode == "disabled":
        return finish("disabled", "image-backed FTS validation disabled by configuration; in-process FTS5 only")
    if not shards:
        return finish("skipped", "no shard was published by this job to validate")
    documents = scratch / "input" / "documents.jsonl"
    exported = export_documents(run_root, shards, documents, max_records=max_records,
                                max_input_bytes=max_input_bytes, max_text_bytes=max_text_bytes)
    if exported["status"] != "exported":
        return finish("skipped", f"image-backed FTS validation skipped: {exported['reason']}")
    documents.chmod(0o444)
    steps: list[dict[str, Any]] = []
    try:
        executor = executor_factory()
        def run(name: str, argv: tuple[str, ...], target: Path) -> tuple[Any, str]:
            result = executor.execute(request_type(TOOL_ID, (EXECUTABLE, *argv), target, scratch / name,
                                                   working_directory="/scratch"))
            stdout = (run_root / result.stdout_path).read_text(encoding="utf-8", errors="replace").strip()
            steps.append({"step": name, "exit_code": result.exit_code, "timed_out": result.timed_out,
                          "image_id": result.image_id, "execution_receipt": result.receipt_path})
            if expected_image_id is not None and result.image_id != expected_image_id:
                raise ValueError(f"{TOOL_ID} image id {result.image_id} differs from the pinned catalog id")
            if result.exit_code != 0 or result.timed_out or result.oom_killed:
                raise RuntimeError(f"{TOOL_ID} {name} failed (exit {result.exit_code})")
            return result, stdout

        _, probe = run("probe", ("probe",), documents.parent)
        if not probe.startswith("FTS5 ready"):
            return finish("unavailable", "image FTS5 capability probe did not report readiness", steps=steps)
        limits = ("--max-records", str(max_records), "--max-input-bytes", str(max_input_bytes),
                  "--max-text-bytes", str(max_text_bytes + 16))
        _, built = run("build", ("build", "--input", "/target/documents.jsonl", "--input-root", "/target",
                                 "--output", "/scratch/search.sqlite", "--output-root", "/scratch", *limits),
                       documents.parent)
        _, verified = run("verify", ("verify", "--index", "/target/search.sqlite", "--input-root", "/target"),
                          scratch / "build")
    except (RuntimeError, ValueError, OSError) as exc:
        return finish("unavailable", f"image-backed FTS validation unavailable: {exc}", steps=steps)
    try:
        build_report = json.loads(built.splitlines()[-1])
        verify_report = json.loads(verified.splitlines()[-1])
        if not isinstance(build_report, dict) or not isinstance(verify_report, dict):
            raise ValueError("tool reports must be objects")
    except (IndexError, ValueError, TypeError) as exc:
        return finish("unavailable", f"image-backed FTS validation returned an invalid report "
                      f"({type(exc).__name__})", steps=steps)
    output = scratch / "build" / "search.sqlite"
    gaps: list[str] = []
    if build_report.get("record_count") != exported["record_count"] or \
            verify_report.get("record_count") != exported["record_count"]:
        gaps.append("image FTS record count differs from the accepted shard documents")
    if build_report.get("input_sha256") != exported["input_sha256"]:
        gaps.append("image FTS input hash differs from the exported document stream")
    probes: list[dict[str, Any]] = []
    try:
        with sqlite3.connect(f"file:{output.as_posix()}?mode=ro&immutable=1", uri=True) as image_db:
            for term in exported["terms"]:
                expected: set[str] = set()
                for shard in shards:
                    with open_shard(run_root, shard) as database:
                        expected |= _matches(database, term)
                actual = _matches(image_db, term)
                probes.append({"term": term, "expected": len(expected), "actual": len(actual),
                               "equal": expected == actual})
                if expected != actual:
                    gaps.append(f"probe term {term!r} returns different identities from the image FTS")
        output_sha256 = file_sha256(output)
    except (OSError, sqlite3.Error) as exc:
        return finish("unavailable", f"image-backed FTS validation output is unreadable "
                      f"({type(exc).__name__})", steps=steps)
    values = {"steps": steps, "image_id": steps[-1]["image_id"] if steps else None,
              "sqlite_version": build_report.get("sqlite_version"), "record_count": exported["record_count"],
              "input_sha256": exported["input_sha256"], "probes": probes,
              "secret_pattern_documents": 0,
              "output": {"path": output.relative_to(run_root).as_posix(), "sha256": output_sha256}}
    if gaps:
        receipt["gaps"].extend(gaps)
        return finish("mismatch", None, **values)
    return finish("verified", None, **values)


def receipt_summary(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {key: receipt.get(key) for key in ("status", "mode", "tool_id", "image_id", "expected_image_id",
                                               "sqlite_version", "record_count", "input_sha256", "gaps", "secret_pattern_documents")}


__all__ = ["FtsValidationError", "MODES", "TOOL_ID", "receipt_summary", "validate_shards"]
