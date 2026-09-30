"""Bounded, source-bound projection of Joern CPG records.

Joern output is untrusted tool evidence.  This module never treats a graph hit as a finding:
queries return immutable record locators which must be dereferenced against the accepted source
snapshot before use in a claim.
"""
from __future__ import annotations

import tunables
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import evidence_redaction as redaction
from execution_state import Blocked, digest, file_hash
import size_log
from schema_validate import validate_document

SCHEMA = "appsec-review/code-property-graph/1.0"
KINDS = frozenset(("call", "symbol", "type", "identifier", "memory-operation"))
QUERY_KINDS = frozenset(("calls", "symbols", "types", "flows", "memory-operations"))
LIMITS = {
    "max_input_bytes": tunables.value("02-code-property-graph", "cpg_input_bytes_logged"),   # logged
    "max_records": tunables.value("02-code-property-graph", "cpg_records_logged"),   # logged
    "max_field_chars": tunables.value("02-code-property-graph", "field_chars_max"),
    "max_search_chars": tunables.value("02-code-property-graph", "search_chars_max"),
    "max_query_results": tunables.value("02-code-property-graph", "query_results_max"),
    "max_citation_lines": tunables.value("02-code-property-graph", "citation_lines_max"),
}


def _sha(path: Path) -> str:
    return "sha256:" + file_hash(path)


def source_tree_sha256(target: Path) -> str:
    rows: list[tuple[str, str]] = []
    for path in sorted(target.rglob("*")):
        if ".git" in path.relative_to(target).parts or path.is_symlink():
            continue
        if path.is_file():
            rows.append((path.relative_to(target).as_posix(), _sha(path)))
    return "sha256:" + digest(rows)


def _field(value: Any, name: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) > LIMITS["max_field_chars"]:
        raise Blocked(f"Joern record has invalid {name}")
    return value


def _location(target: Path, raw: Any) -> tuple[str, Path]:
    value = _field(raw, "file")
    assert isinstance(value, str)
    normalized = value.replace("\\", "/")
    if normalized.startswith("/workspace/"):
        normalized = normalized[len("/workspace/"):]
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or not pure.parts or any(part in ("", ".", "..") for part in pure.parts):
        raise Blocked("Joern record source path is not normalized beneath the target")
    path = target.joinpath(*pure.parts)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(target.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Blocked("Joern record source path escapes or is missing from the target") from exc
    cursor = target
    for part in pure.parts:
        cursor /= part
        if cursor.is_symlink():
            raise Blocked("Joern record source path traverses a symbolic link")
    if not resolved.is_file():
        raise Blocked("Joern record source location is not a regular file")
    return pure.as_posix(), resolved


def _redact(value: str) -> tuple[str, str]:
    outcome = redaction._process(value.encode("utf-8"), "cpg-record.txt", redaction.DEFAULT_LIMITS)
    if outcome.data is None:
        return "", "withheld"
    rendered = outcome.data.decode("utf-8", errors="replace")[:LIMITS["max_search_chars"]]
    return rendered, "redacted" if outcome.disposition != "unchanged" else "unchanged"


def _frontends(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise Blocked("Joern frontend outcome file is missing or linked")
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise Blocked("Joern frontend outcome file contains a malformed line") from exc
        if not isinstance(row, dict) or set(row) != {"language", "unit", "status", "records", "detail"}:
            raise Blocked("Joern frontend outcome does not have the closed exporter shape")
        detail, _ = _redact(str(row["detail"]))
        rows.append(dict(row, detail=detail[:300]))
    return rows


def normalize_jsonl(raw: Path, *, target: Path, run_id: str, source_snapshot_sha256: str,
                    source_revision: str, image_id: str, image_digest: str,
                    exporter_sha256: str, build_identity_sha256: str,
                    frontends: Path | None = None) -> dict[str, Any]:
    """``frontends``: the exporter's per-frontend outcome file (one JSON object per line). A FAILED
    frontend is a coverage gap for that language, never a failed job (ADR-0013)."""
    if raw.is_symlink() or not raw.is_file():
        raise Blocked("Joern JSONL is missing or linked")
    outcomes = _frontends(frontends) if frontends is not None else None
    size_log.observe(run_id, "02-code-property-graph", "joern_jsonl_bytes", raw.stat().st_size,
                     LIMITS["max_input_bytes"])
    ordinal = 0
    records: list[dict[str, Any]] = []
    skipped = {"no_source_location": 0, "duplicate": 0}
    seen: set[str] = set()
    source_cache: dict[Path, tuple[str, int]] = {}
    with raw.open("r", encoding="utf-8") as stream:
        for ordinal, line in enumerate(stream, 1):
            try:
                item = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise Blocked("Joern JSONL contains a malformed record") from exc
            if not isinstance(item, dict) or set(item) != {
                    "kind", "label", "name", "full_name", "caller", "type_name", "file", "line", "column", "code",
            }:
                raise Blocked("Joern record does not have the closed exporter shape")
            kind = _field(item["kind"], "kind")
            if kind not in KINDS:
                raise Blocked("Joern record has an unsupported structural kind")
            line_number, column = item["line"], item["column"]
            if column == 0 and not isinstance(column, bool):
                # jssrc2cpg and csharpsrc2cpg number some columns from 0 (a file's :program method);
                # the column is locator detail only, so record it as unknown rather than reject the export.
                column = None
            if (item["file"] == "" or
                    (isinstance(item["file"], str) and item["file"].startswith("<") and item["file"].endswith(">")) or
                    line_number is None):
                skipped["no_source_location"] += 1
                continue
            if (not isinstance(line_number, int) or isinstance(line_number, bool) or line_number < 1 or
                    (column is not None and (not isinstance(column, int) or isinstance(column, bool) or column < 1))):
                raise Blocked("Joern record has an invalid source coordinate")
            try:
                relative, source = _location(target, item["file"])
            except (Blocked, OSError):
                # Joern names files it inferred (e.g. unresolved #include headers) that are not in
                # the checkout, or reached through a link (freeciv21). Skip and count.
                skipped["source_unavailable"] = skipped.get("source_unavailable", 0) + 1
                continue
            cached = source_cache.get(source)
            if cached is None:
                raw_source = source.read_bytes()
                total_lines = max(raw_source.count(b"\n"), len(raw_source.replace(b"\r\n", b"\n").replace(b"\r", b"\n").splitlines()))
                cached = (_sha(source), total_lines)
                source_cache[source] = cached
            source_sha256, total_lines = cached
            if line_number > max(total_lines, 1):
                # Joern counts lone CR as a line break; our count may be lower (doom3-bfg). Skip and count.
                skipped["line_beyond_file"] = skipped.get("line_beyond_file", 0) + 1
                continue
            fields = {name: _field(item[name], name) for name in
                      ("label", "name", "full_name", "caller", "type_name", "code")}
            search, disposition = _redact(" | ".join(str(fields[name]) for name in
                                                       ("name", "full_name", "type_name", "code")))
            identity = "cpg_" + digest((kind, relative, line_number, column, fields["label"],
                                         fields["name"], fields["full_name"], fields["caller"], fields["code"]))[:24]
            if identity in seen:
                skipped["duplicate"] += 1
                continue
            seen.add(identity)
            records.append({"record_id": identity, "kind": kind, **fields,
                "source_path": relative, "source_sha256": source_sha256, "start_line": line_number,
                "start_column": column, "end_line": line_number, "search_text": search,
                "redaction": disposition, "locator": {
                    "artifact": "code-property-graph.json", "record_id": identity,
                    "source_path": relative, "source_sha256": source_sha256, "line": line_number,
                }})
    size_log.observe(run_id, "02-code-property-graph", "joern_records", ordinal, LIMITS["max_records"],
                     kept=len(records))
    records.sort(key=lambda row: (row["source_path"], row["start_line"], row["kind"], row["record_id"]))
    failed = sum(1 for row in outcomes or [] if row["status"] == "FAILED")
    if failed:
        skipped["frontend_failed"] = failed
    result = {"schema": SCHEMA, "run_id": run_id, "source_revision": source_revision,
        "source_snapshot_sha256": source_snapshot_sha256, "source_tree_sha256": source_tree_sha256(target),
        "build_identity_sha256": build_identity_sha256, "image_id": image_id,
        "image_digest": image_digest, "exporter_sha256": exporter_sha256,
        "status": "OK_WITH_GAPS" if any(skipped.values()) else "OK", "record_count": len(records),
        "records": records, "coverage_gaps": [
            {"reason": reason.replace("_", "-"), "count": count}
            for reason, count in sorted(skipped.items()) if count
        ], "limits": LIMITS, "claim_boundary": "STRUCTURAL_RETRIEVAL_NOT_FINDING_OR_RUNTIME_PROOF"}
    if outcomes is not None:
        result["frontends"] = outcomes
    if validate_document(result, "code-property-graph.schema.json"):
        raise Blocked("normalized Joern CPG evidence fails its closed schema")
    return result


def structural_query(document: dict[str, Any], *, operation: str, text: str = "",
                     caller: str = "", callee: str = "", limit: int = 20) -> list[dict[str, Any]]:
    if operation not in QUERY_KINDS or not 1 <= limit <= LIMITS["max_query_results"]:
        raise ValueError("unsupported or unbounded structural query")
    if any(len(value) > LIMITS["max_search_chars"] for value in (text, caller, callee)):
        raise ValueError("structural query text exceeds its bound")
    accepted = {"calls": {"call", "memory-operation"}, "symbols": {"symbol", "identifier"},
                "types": {"type"}, "flows": {"call", "memory-operation"},
                "memory-operations": {"memory-operation"}}[operation]
    needle = text.casefold().strip()
    rows = []
    for item in document.get("records", []):
        if item.get("kind") not in accepted or (needle and needle not in item.get("search_text", "").casefold()):
            continue
        if operation == "flows":
            if caller and caller.casefold() not in item.get("caller", "").casefold():
                continue
            if callee and callee.casefold() not in item.get("name", "").casefold() and callee.casefold() not in item.get("full_name", "").casefold():
                continue
        rows.append({"record_id": item["record_id"], "kind": item["kind"],
                     "name": item["name"], "locator": item["locator"],
                     "authority": "candidate_locator_requires_dereference"})
        if len(rows) == limit:
            break
    return rows


def dereference(target: Path, locator: dict[str, Any], *, context_lines: int = 1) -> dict[str, Any]:
    if not 0 <= context_lines <= LIMITS["max_citation_lines"]:
        raise ValueError("citation context exceeds its bound")
    relative, source = _location(target, locator.get("source_path"))
    if _sha(source) != locator.get("source_sha256"):
        raise Blocked("structural locator names stale source bytes")
    line = locator.get("line")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise Blocked("structural locator has an invalid line")
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    if line > len(lines):
        raise Blocked("structural locator line no longer resolves")
    start, end = max(1, line - context_lines), min(len(lines), line + context_lines)
    excerpt, disposition = _redact("\n".join(lines[start - 1:end]))
    return {"source_path": relative, "source_sha256": locator["source_sha256"],
            "start_line": start, "end_line": end, "excerpt": excerpt,
            "redaction": disposition, "authority": "dereferenced_source_evidence"}


def project_ir_facts(document: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Project accepted IR facts as locators; null debug locations remain explicit gaps."""
    locations = {item.get("debug_location_id"): item for item in document.get("debug_locations", [])
                 if isinstance(item, dict) and item.get("debug_location_id")}
    for fact in document.get("facts", []):
        location = locations.get(fact.get("debug_location_id"))
        if fact.get("source_path") and fact.get("source_sha256") and location:
            yield {"record_id": fact["fact_id"], "kind": "memory-operation",
                   "name": fact["kind"], "function": fact.get("function"),
                   "search_text": " | ".join(str(x) for x in (fact["kind"], fact.get("function"),
                                                                 fact.get("source_path")) if x),
                   "locator": {"artifact": "ir-facts.json", "record_id": fact["fact_id"],
                               "source_path": fact["source_path"],
                               "source_sha256": fact["source_sha256"],
                               "line": location["source_line"],
                               "column": location["source_column"],
                               "debug_location_id": fact.get("debug_location_id")},
                   "authority": "candidate_locator_requires_dereference"}
