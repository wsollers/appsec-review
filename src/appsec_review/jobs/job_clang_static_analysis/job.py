"""Bounded Clang-Tidy and Clang Static Analyzer job over accepted native scopes.

Only source material and compilation databases already accepted by
``job_cpp_compiled_analysis`` are mounted.  The target itself is never executed.  Each engine is
an independent action so one failure cannot erase the other's observations; all failures are
retained as scope-specific coverage gaps.
"""

from __future__ import annotations

from appsec_review.storage.shared import PublicationThreadPoolExecutor as ThreadPoolExecutor
from collections import defaultdict
from dataclasses import asdict
import re
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from appsec_review import seeding
from appsec_review.jobs.cpp_index_scopes import (
    SOURCE_MOUNT, CheckpointIntegrityError, IndexScope, project_prefix, accepted_cpp_scopes, artifact, checkpoint_identity, execute_scope_tool,
    publish_scope_indexes, save_scope_checkpoint, scope_checkpoint, tool_identity,
)
from appsec_review.jobs.engineering_contracts import CLANG_STATIC_HANDOFF_SCHEMA
from appsec_review.provenance import common_metadata, json_selector, retain_native_output, select_native, verify_native_reference
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint,
)
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from appsec_review.storage.shared import current as current_owner
from . import seeded
from .datasets import CONTRACT, DATASETS


JOB_ID = "job_clang_static_analysis"
TOOL_ID = "tool-clang-static-analysis"
OUTPUT_SCHEMA = "appsec-review/clang-static-output/1"
ADAPTER = "clang-static-adapter/9"
ENGINES = ("clang-tidy", "clang-static-analyzer")
_CHECKER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*")


def _validated_settings(settings: Mapping[str, Any]) -> dict[str, Any]:
    checks = settings.get("clang_tidy_checks", ())
    checkers = settings.get("clang_analyzer_checkers", ())
    if not isinstance(checks, (list, tuple)) or not checks or not all(isinstance(v, str) and v for v in checks):
        raise ValueError("clang_tidy_checks must be a non-empty string list")
    if not isinstance(checkers, (list, tuple)) or not checkers or not all(isinstance(v, str) and v for v in checkers):
        raise ValueError("clang_analyzer_checkers must be a non-empty string list")
    patterns = [value for value in checkers if not _CHECKER_NAME.fullmatch(value)]
    if patterns:
        # ``clang --analyze`` rejects a pattern with "no analyzer checkers or packages are associated with",
        # which fails every translation unit; clang-tidy checks, not these, accept wildcards.
        raise ValueError("clang_analyzer_checkers entries must be Static Analyzer checker or package names, "
                         f"not patterns: {', '.join(patterns)}")
    values = {
        "workers": int(settings["workers"]),
        "max_output_bytes": int(settings["max_output_bytes"]),
        "max_diagnostics_per_scope": int(settings["max_diagnostics_per_scope"]),
        "clang_tidy_checks": tuple(checks),
        "clang_analyzer_checkers": tuple(checkers),
    }
    if min(values["workers"], values["max_output_bytes"], values["max_diagnostics_per_scope"]) <= 0:
        raise ValueError("Clang static-analysis numeric bounds must be positive")
    if values["max_diagnostics_per_scope"] > 100000:
        raise ValueError("max_diagnostics_per_scope must not exceed the wrapper limit 100000")
    return values


def _settings(unit: UnitContext) -> dict[str, Any]:
    return _validated_settings(unit.job.config.settings)


def _valid_point(value: Any) -> bool:
    return isinstance(value, Mapping) and all(
        value.get(key) is None or
        (isinstance(value[key], str) and len(value[key]) <= 4096 if key == "path"
         else type(value[key]) is int and value[key] > 0)
        for key in ("path", "line", "column"))


def _valid_ranges(value: Any) -> bool:
    return isinstance(value, list) and len(value) <= 16 and all(
        isinstance(pair, list) and len(pair) == 2 and all(_valid_point(point) for point in pair)
        for pair in value)


def _valid_trace_piece(note: Any) -> bool:
    if not (_valid_point(note) and isinstance(note.get("message"), str) and len(note["message"]) <= 4096
            and _valid_ranges(note.get("ranges", []))):
        return False
    edges = note.get("edges", [])
    if not isinstance(edges, list) or len(edges) > 16 or not all(
            isinstance(edge, Mapping) and _valid_ranges([edge.get("start"), edge.get("end")]) for edge in edges):
        return False
    if "depth" in note and (type(note["depth"]) is not int or note["depth"] < 0):
        return False
    if "key_event" in note and type(note["key_event"]) is not bool:
        return False
    if "kind" in note and (not isinstance(note["kind"], str) or
                           note["kind"] not in {"note", "event", "control", "pop-up"}):
        return False
    if "origin" in note and (not isinstance(note["origin"], str) or note["origin"] not in {"notes", "path"}):
        return False
    return all(type(note.get(f"{key}_length", len(note.get(key, [])))) is int
               and note.get(f"{key}_length", len(note.get(key, []))) >= len(note.get(key, []))
               for key in ("message", "ranges", "edges"))


def _read_output(path: Path, *, engine: str, max_bytes: int, max_diagnostics: int) -> tuple[list[dict[str, Any]], list[str]]:
    """Read one strict, bounded wrapper result; malformed output is a gap, never clean."""
    from appsec_review.runtime import execution_safety as safety
    gaps: list[str] = []
    if not path.is_file() or path.is_symlink():
        safety.fail(f"{engine} omitted its result document", action="clang.output")
        return [], [f"{engine} produced no result document"]
    size = path.stat().st_size
    if size > max_bytes:
        safety.fail(f"{engine} exceeded its output bound", action="clang.output", expected=True)
        return [], [f"{engine} result exceeded the {max_bytes}-byte output bound"]
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        safety.fail(f"{engine} returned malformed JSON", action="clang.output")
        return [], [f"{engine} result was malformed JSON"]
    if not isinstance(document, Mapping) or document.get("schema") != OUTPUT_SCHEMA or document.get("engine") != engine:
        safety.fail(f"{engine} returned an invalid envelope", action="clang.output")
        return [], [f"{engine} result envelope was malformed"]
    raw = document.get("diagnostics")
    if not isinstance(raw, list):
        safety.fail(f"{engine} returned invalid diagnostics", action="clang.output")
        return [], [f"{engine} diagnostics were malformed"]
    if len(raw) > max_diagnostics:
        safety.fail(f"{engine} exceeded its diagnostic bound", action="clang.output", expected=True)
        return [], [f"{engine} exceeded the {max_diagnostics}-diagnostic bound"]
    if document.get("truncated") is True:
        safety.fail(f"{engine} output was truncated", action="clang.output", expected=True)
        gaps.append(f"{engine} output was truncated by its bounded wrapper")
    records: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            safety.fail(f"{engine} returned an invalid diagnostic", action="clang.output")
            return [], [f"{engine} diagnostic {index} was malformed"]
        required = ("rule_id", "message", "path", "line", "column")
        if any((not isinstance(item.get(key), str)) if key in {"rule_id", "message", "path"}
               else type(item.get(key)) is not int for key in required):
            safety.fail(f"{engine} returned invalid diagnostic fields", action="clang.output")
            return [], [f"{engine} diagnostic {index} was malformed"]
        if len(item["rule_id"]) > 512 or len(item["message"]) > 16384 or len(item["path"]) > 4096 \
                or int(item["line"]) < 1 or int(item["column"]) < 1:
            safety.fail(f"{engine} returned an out-of-contract diagnostic", action="clang.output")
            return [], [f"{engine} diagnostic {index} exceeded field bounds"]
        end_line, end_column = item.get("end_line", item["line"]), item.get("end_column", item["column"])
        if (type(end_line) is not int or type(end_column) is not int or end_line < 1 or end_column < 1
                or (end_line, end_column) < (item["line"], item["column"])):
            safety.fail(f"{engine} returned an invalid span", action="clang.output")
            return [], [f"{engine} diagnostic {index} had a malformed span"]
        notes = item.get("notes", [])
        if not isinstance(notes, list) or len(notes) > 256:
            safety.fail(f"{engine} returned an invalid trace", action="clang.output")
            return [], [f"{engine} diagnostic {index} had an unbounded trace"]
        if not all(_valid_trace_piece(note) for note in notes) or not _valid_ranges(item.get("ranges", [])):
            safety.fail(f"{engine} returned malformed trace coordinates", action="clang.output")
            return [], [f"{engine} diagnostic {index} had malformed trace/range fields"]
        trace_length = item.get("trace_length", len(notes))
        if type(trace_length) is not int or trace_length < len(notes) or (
                "trace_truncated" in item and type(item["trace_truncated"]) is not bool):
            safety.fail(f"{engine} returned malformed trace counts", action="clang.output")
            return [], [f"{engine} diagnostic {index} had malformed trace counts"]
        omissions = item.get("trace_omissions", {})
        expected_omissions = {
            "steps": trace_length - len(notes),
            **{name: sum(note.get(f"{key}_length", len(note.get(key, []))) - len(note.get(key, []))
                         for note in notes)
               for key, name in (("ranges", "ranges"), ("edges", "edges"), ("message", "message_characters"))},
        }
        if "trace_omissions" in item and (
                not isinstance(omissions, Mapping) or any(
                    key not in expected_omissions or type(count) is not int or count < 0
                    for key, count in omissions.items())
                or any(omissions.get(key, 0) != count for key, count in expected_omissions.items())):
            safety.fail(f"{engine} returned malformed trace omissions", action="clang.output")
            return [], [f"{engine} diagnostic {index} had malformed trace omissions"]
        trace_truncated = item.get("trace_truncated") is True or any(expected_omissions.values())
        if trace_truncated:
            safety.fail(f"{engine} trace was truncated", action="clang.output", expected=True)
            gaps.append(f"{engine} diagnostic {index} trace truncated: retained {len(notes)} of {trace_length} steps")
        records.append({
            "engine": engine, "rule_id": item["rule_id"], "message": item["message"],
            "severity": str(item.get("severity", "warning"))[:32], "path": item["path"],
            "line": int(item["line"]), "column": int(item["column"]),
            "end_line": end_line, "end_column": end_column,
            "notes": notes, "fix_it": item.get("fix_it") is True,
            "trace_length": trace_length, "trace_truncated": trace_truncated,
            "trace_omissions": {key: count for key, count in expected_omissions.items() if count},
            "ranges": item.get("ranges", []),
            # Underscore keys address the retained native output and never enter the evidence identity.
            "_native_selector": json_selector("diagnostics", index).as_dict(),
        })
    return records, gaps


def _retain_output(unit: UnitContext, output_path: Path, execution: Mapping[str, Any],
                   parsed: list[dict[str, Any]], parse_gaps: list[str]) -> dict[str, Any] | None:
    """Retain the bounded wrapper document so each observation's ``common`` record cites it.

    Outside a run-owned publication attempt (direct handler calls) there is no retention owner; the
    observation then carries ``provenance_unavailable`` in its common record instead of a reference.
    """
    owner = current_owner()
    if owner is None or owner.run_root != unit.job.run_root:
        return None
    receipt = execution.get("receipt")
    reference = retain_native_output(
        unit.job.run_root, output_path, parser_identity=ADAPTER,
        complete=not any("truncated" in gap for gap in parse_gaps), native_result_count=len(parsed),
        execution_reference=receipt if isinstance(receipt, Mapping) and {"path", "sha256"} <= set(receipt) else None,
        events=getattr(unit.job, "events", None), unit_id=unit.unit_id)
    return reference.as_dict()


def _location(scope: IndexScope, record: Mapping[str, Any], *,
              end_is_inclusive_byte: bool = False) -> tuple[SourceLocation | None, Mapping[str, Any] | None]:
    accepted = scope.accepted_file(str(record["path"]))
    if accepted is None:
        return None, None
    relative = str(accepted["scratch_path"])[len("source/"):]
    source = scope.case_root / "source" / Path(*relative.split("/"))
    data = source.read_bytes()
    offsets = [0]
    offsets.extend(index + 1 for index, value in enumerate(data) if value == 10)
    line, end_line = record["line"], record["end_line"]
    column, end_column = record["column"], record["end_column"]
    if any(type(value) is not int or value < 1 for value in (line, end_line, column, end_column)) \
            or (end_line, end_column) < (line, column) or end_line > len(offsets):
        return None, accepted

    def position(line: int, column: int, *, inclusive_end: bool = False) -> int | None:
        beginning = offsets[line - 1]
        limit = offsets[line] - 1 if line < len(offsets) else len(data)
        if limit > beginning and data[limit - 1:limit] == b"\r":
            limit -= 1
        offset = beginning + column - 1
        if inclusive_end and end_is_inclusive_byte:
            # LLVM plist EmitRange subtracts one byte from its exclusive end, not one
            # character. Validate the boundary after that byte, without relaxing start/point checks.
            if offset >= limit:
                return None
            offset += 1
            return None if offset < len(data) and data[offset] & 0xC0 == 0x80 else offset
        if offset > limit or (offset < len(data) and data[offset] & 0xC0 == 0x80):
            return None
        if inclusive_end and offset < limit:
            offset += 1
            while offset < limit and data[offset] & 0xC0 == 0x80:
                offset += 1
        return offset

    start, end = position(line, column), position(end_line, end_column, inclusive_end=True)
    if start is None or end is None:
        return None, accepted
    return SourceLocation(
        target_snapshot=scope.case_snapshot, path=str(accepted["target_path"]),
        file_sha256=str(accepted["sha256"]), start_byte=start, end_byte=max(start, end),
        start_line=line, end_line=end_line, start_column=int(record["column"]),
        end_column=int(record["end_column"]),
        producer_location={key: record[key] for key in
                           ("engine", "path", "line", "column", "end_line", "end_column")},
        mapping_method="accepted-cpp-source-map", confidence=1.0,
    ), accepted


def _resolved_ranges(scope: IndexScope, ranges: list[Any], engine: str) -> list[dict[str, Any]]:
    resolved = []
    for start, end in ranges:
        location = None
        if (all(point.get(key) is not None for point in (start, end) for key in ("path", "line", "column"))
                and start["path"] == end["path"]):
            location, _ = _location(scope, {**start, "engine": engine,
                                            "end_line": end.get("line"), "end_column": end.get("column")},
                                    end_is_inclusive_byte=True)
        resolved.append({"reported_start": dict(start), "reported_end": dict(end),
                         "location": {**asdict(location), "producer_location": {}} if location else None,
                         **({} if location else {"gap": "range did not resolve to accepted source bytes"})})
    return resolved


def _resolved_trace(scope: IndexScope, record: Mapping[str, Any], gaps: list[str]) -> tuple[list[Any], list[Any]]:
    notes = []
    for note in record["notes"]:
        location = None
        if note.get("path") is not None and note.get("line") is not None and note.get("column") is not None:
            location, _ = _location(scope, {**note, "engine": record["engine"],
                                            "end_line": note["line"], "end_column": note["column"]})
        resolved = {**note, "location": asdict(location) if location else None}
        if location is None and not (note.get("kind") == "control" and note.get("edges")):
            resolved["gap"] = "trace point did not resolve to accepted source bytes"
            gaps.append(f"{record['engine']} {resolved['gap']}")
        if "ranges" in note:
            resolved["ranges"] = _resolved_ranges(scope, note["ranges"], record["engine"])
        if "edges" in note:
            resolved["edges"] = []
            for edge in note["edges"]:
                projected = {}
                for key in ("start", "end"):
                    span = _resolved_ranges(scope, [edge[key]], record["engine"])[0]
                    # Keep edge spans within the existing payload-depth bound; original coordinates
                    # live beside the span instead of one extra nested producer_location object.
                    projected[key] = ({**span["location"], "producer_location": {}} if span["location"] else None)
                    projected[f"reported_{key}"] = {
                        f"{position}_{field}": point.get(field)
                        for position, point in (("start", span["reported_start"]), ("end", span["reported_end"]))
                        for field in ("path", "line", "column")}
                    if span.get("gap"):
                        projected[f"{key}_gap"] = span["gap"]
                        gaps.append(f"{record['engine']} control edge did not resolve to accepted source bytes")
                resolved["edges"].append(projected)
        notes.append(resolved)
    ranges = _resolved_ranges(scope, record["ranges"], record["engine"])
    if any(item.get("gap") for item in ranges) or any(
            item.get("gap") for note in notes for item in note.get("ranges", [])):
        gaps.append(f"{record['engine']} diagnostic range did not resolve to accepted source bytes")
    return notes, ranges


def _engine_argv(engine: str, settings: Mapping[str, Any]) -> tuple[str, ...]:
    action = "tidy" if engine == "clang-tidy" else "analyze"
    selection = settings["clang_tidy_checks"] if action == "tidy" else settings["clang_analyzer_checkers"]
    return ("/opt/appsec/clang-static.py", action, "/scratch/compile_commands.json",
            f"/scratch/{action}.json", str(settings["max_diagnostics_per_scope"]), ",".join(selection))


def _not_applicable_scope(scope: IndexScope) -> dict[str, Any]:
    """A scope whose compile units are all outside Clang support: SKIPPED_NA, never launched."""
    return {"scope_id": scope.scope_id, "case_id": scope.case_id, "project_id": scope.project_id,
            "terminal_status": "SKIPPED_NA", "gaps": [],
            "not_applicable_inputs": scope.not_applicable_inputs()}


def _skipped_scope_index(unit: UnitContext, skipped: Mapping[str, Any]) -> dict[str, Any]:
    """Keep applicability in the manifest without inventing measured analysis coverage."""
    shard = f"clang-static-{skipped['scope_id']}"
    fingerprint = checkpoint_identity({"adapter": ADAPTER, **skipped})
    path = unit.job.run_root / "data" / "indices" / "observations" / "attempts" / unit.job.config.job_id / unit.job.attempt_id / f"{fingerprint}.sqlite"
    builder = IndexBuilder(path, name="observations", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard)
    index = IndexIdentity("observations", "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                          path.relative_to(unit.job.run_root).as_posix(),
                          {"job": JOB_ID, "unit": unit.unit_id, **skipped}, (), shard)
    return {**skipped, "index_identity": asdict(index)}


def _read_units(path: Path, *, max_bytes: int) -> list[dict[str, Any]] | None:
    """The wrapper's per-translation-unit outcomes, or ``None`` when it did not report any."""
    if not path.is_file() or path.is_symlink() or path.stat().st_size > max_bytes:
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None
    units = document.get("units") if isinstance(document, Mapping) else None
    if not isinstance(units, list) or len(units) > 4096 or not all(
            isinstance(item, Mapping) and isinstance(item.get("file"), str) and len(item["file"]) <= 4096
            for item in units):
        return None
    return [{"file": item["file"],
             "compile_unit_id": item.get("compile_unit_id") if isinstance(item.get("compile_unit_id"), str)
             and re.fullmatch(r"[0-9a-f]{64}", item["compile_unit_id"]) else None,
             "exit_code": item.get("exit_code") if type(item.get("exit_code")) is int else None,
             "message": str(item.get("message") or "")[:512]}
            for item in units]


def _compile_unit_identity(row: Mapping[str, Any]) -> str:
    """Canonical wire identity also derived by the standalone wrapper from its selected row."""
    return checkpoint_identity({
        "schema": "appsec-review/clang-compile-unit/1",
        **{key: row[key] for key in ("directory", "file", "arguments", "source_sha256")},
    })


def _source_of(container_path: str) -> str:
    prefix = SOURCE_MOUNT + "/"
    return container_path[len(prefix):] if container_path.startswith(prefix) else container_path


def _analyze_scope(unit: UnitContext, scope: IndexScope, executor_factory: Any,
                   run: seeded.Run | None = None) -> dict[str, Any]:
    settings = _settings(unit)
    root = (unit.job.run_root / "data" / "clang-static" / scope.scope_id /
            "attempts" / unit.job.attempt_id)
    values: dict[str, Any] = {
        "schema": CLANG_STATIC_HANDOFF_SCHEMA, "adapter": ADAPTER, "scope": scope.as_dict(),
        "settings": settings, "tool": tool_identity(unit.job.repository_root, TOOL_ID)
        if executor_factory is None else {"tool_id": TOOL_ID, "injected_executor": True},
    }
    if run is not None:
        values.update(seeded.identity_values(run.settings, run.scope_seeds, run.hood, run.plan))
    identity = checkpoint_identity(values)
    reused = scope_checkpoint(root / "checkpoint.json", identity, unit.job.run_root, scope)
    if reused is not None:
        try:
            for native in reused.get("native_outputs", {}).values():
                verify_native_reference(unit.job.run_root, native)
        except (OSError, ValueError) as exc:
            raise CheckpointIntegrityError(f"{scope.scope_id}: invalid Clang native evidence: {exc}") from exc
        return dict(reused)

    generation = 1
    while True:
        evidence_root = root / identity / f"execution-{generation:04d}"
        try:
            evidence_root.mkdir(parents=True, exist_ok=False)
            break
        except FileExistsError:
            generation += 1
    records: list[dict[str, Any]] = []
    gaps: list[str] = []
    executions: dict[str, Any] = {}
    raw_artifacts: list[Mapping[str, Any]] = [dict(scope.compile_database)]
    selection = None
    rows: list[dict[str, Any]] | None = None
    engines = ENGINES
    if run is not None:
        if run.scope_seeds.seeds:
            selection = seeded.select(scope, run.scope_seeds, run.settings)
            gaps.extend(selection.gaps)
            rows = list(selection.container_rows)
            engines = ENGINES if rows else ()
        else:
            engines = ()
    engine_failed: set[str] = set()
    failed_units: dict[tuple[str, str], str] = {}
    incomplete_units: set[tuple[str, str]] = set()
    incomplete_engines: set[str] = set()
    successful_units: dict[str, set[str]] = {}
    expected_units: dict[str, dict[str, Any]] = {}
    selected_rows = (rows if rows is not None else scope.container_compile_database()) if engines else []
    for row in selected_rows:
        accepted = scope.accepted_file(row["file"])
        if accepted is None:
            raise ValueError(f"Clang compile unit did not resolve to accepted source: {row['file']}")
        row = {**row, "source_sha256": accepted["sha256"]}
        expected_units.setdefault(_compile_unit_identity(row), row)
    rows = list(expected_units.values())
    retained: dict[str, dict[str, Any]] = {}
    for engine in engines:
        scratch = evidence_root / ("tidy" if engine == "clang-tidy" else "analyze")
        try:
            execution = execute_scope_tool(
                unit, scope, TOOL_ID, _engine_argv(engine, settings), scratch, executor_factory,
                file_size_limit_bytes=settings["max_output_bytes"] + 1, compile_rows=rows,
            )
        except Exception as exc:
            from appsec_review.runtime import execution_safety as safety
            safety.fail(f"{engine} failed: {type(exc).__name__}", action="clang.execution")
            gaps.append(f"{engine} tool/image unavailable: {type(exc).__name__}: {exc}")
            engine_failed.add(engine)
            continue
        executions[engine] = execution
        raw_artifacts.extend((execution["receipt"], execution["compile_database"]))
        raw_artifacts.extend(artifact(unit.job.run_root, unit.job.run_root / execution[key])
                             for key in ("stdout_path", "stderr_path"))
        from appsec_review.runtime import execution_safety as safety
        safety.failed_result(
            execution["timed_out"] or execution["oom_killed"] or execution["file_size_limit_reached"]
            or execution["stdout_truncated"] or execution["stderr_truncated"]
            or execution["exit_code"] != 0,
            f"{engine} execution failed or exceeded its bounds", action="clang.execution")
        if execution["timed_out"]:
            gaps.append(f"{engine} timed out")
            engine_failed.add(engine)
            continue
        if execution["oom_killed"]:
            gaps.append(f"{engine} was OOM-killed")
            engine_failed.add(engine)
            continue
        if execution["file_size_limit_reached"] or execution["stdout_truncated"] or execution["stderr_truncated"]:
            gaps.append(f"{engine} output was truncated or exceeded its execution bound")
            engine_failed.add(engine)
            continue
        output_path = scratch / ("tidy.json" if engine == "clang-tidy" else "analyze.json")
        units = _read_units(output_path, max_bytes=settings["max_output_bytes"])
        bad = [item for item in units or () if item["exit_code"] is not None and item["exit_code"] != 0]
        from appsec_review.runtime import execution_safety as safety
        safety.failed_result(bool(bad) or execution["exit_code"] != 0,
                             f"{engine} failed on a translation unit", action="clang.execution")
        if execution["exit_code"] != 0 and not (run is not None and bad):
            gaps.append(f"{engine} exited with status {execution['exit_code']}")
            engine_failed.add(engine)
            continue
        by_identity: dict[str | None, list[dict[str, Any]]] = defaultdict(list)
        for item in units or ():
            by_identity[item["compile_unit_id"]].append(item)
        successful_units[engine] = set()
        for compile_id, row in sorted(expected_units.items()):
            path = row["file"]
            outcomes = by_identity.get(compile_id, [])
            if len(outcomes) != 1 or outcomes[0]["exit_code"] is None or outcomes[0]["file"] != path:
                incomplete_units.add((engine, _source_of(path)))
                gaps.append(f"{engine} incomplete compile-unit outcomes for {path} ({compile_id}): "
                            f"expected exactly one matching valid record, got {len(outcomes)}")
            elif outcomes[0]["exit_code"] == 0:
                successful_units[engine].add(compile_id)
            else:
                rel = _source_of(path)
                item = outcomes[0]
                failed_units[(engine, rel)] = item["message"] or f"exit {item['exit_code']}"
                gaps.append(f"{engine} failed on {project_prefix(scope.root)}{rel}: {failed_units[(engine, rel)]}")
        unexpected = set(by_identity) - set(expected_units)
        if unexpected:
            gaps.append(f"{engine} compile-unit outcomes included missing or unselected identities")
            incomplete_engines.add(engine)
            expected_files = {row["file"] for row in expected_units.values()}
            for compile_id in unexpected:
                for item in by_identity[compile_id]:
                    if item["file"] in expected_files:
                        incomplete_units.add((engine, _source_of(item["file"])))
        if units is None or any(item[0] == engine for item in incomplete_units):
            incomplete_engines.add(engine)
        if engine in incomplete_engines:
            safety.fail(f"{engine} compile-unit outcomes were incomplete or malformed", action="clang.output")
        parsed, parse_gaps = _read_output(output_path, engine=engine,
                                          max_bytes=settings["max_output_bytes"],
                                          max_diagnostics=settings["max_diagnostics_per_scope"])
        gaps.extend(parse_gaps)
        if parse_gaps and not parsed:
            engine_failed.add(engine)
        if output_path.is_file() and not output_path.is_symlink() and output_path.stat().st_size <= settings["max_output_bytes"]:
            raw_artifacts.append(artifact(unit.job.run_root, output_path))
            if parsed:
                native = _retain_output(unit, output_path, execution, parsed, parse_gaps)
                if native is not None:
                    retained[engine] = native
        records.extend(parsed)

    section = ledger = compact = None
    if run is not None:
        failed: dict[tuple[str, int, int], str] = {}
        for key, rels in (selection.by_seed if selection else {}).items():
            if engine_failed or any((engine, rel) in failed_units for engine in ENGINES for rel in rels):
                failed[key] = seeding.record.REASON_RUN_FAILED
            elif any((engine, rel) in incomplete_units for engine in ENGINES for rel in rels):
                failed[key] = seeding.record.REASON_NOT_RUN
        section = seeded.section_for(run, selection, failed)
        if not run.scope_seeds.seeds:
            section["gaps"] = [seeding.NO_SEEDS_GAP, *section["gaps"]]
        elif not run.hood.known:
            gaps.append(seeded.NEIGHBORHOOD_UNAVAILABLE)
        gaps.extend(gap for gap in section["gaps"] if gap not in gaps)
        ledger_path = evidence_root / "seeded-ledger.json"
        atomic_json(ledger_path, {"schema": seeding.record.RECORD_SCHEMA, "branch": "clang-static",
                                  "project": scope.case_id, "seeded": section})
        ledger = artifact(unit.job.run_root, ledger_path)
        compact = seeding.compact_record({**section, "gaps": list(dict.fromkeys(gaps))}, ledger=ledger,
                                         skipped=not run.scope_seeds.seeds)
        raw_artifacts.append(ledger)

    shard = f"clang-static-{scope.scope_id}"
    fingerprint = index_fingerprint(
        name="observations", target_snapshot=scope.case_snapshot, producer_artifacts=raw_artifacts,
        tool_identity={"tool": TOOL_ID, "executions": {key: value.get("image_digest") for key, value in executions.items()},
                       **({"seeded": values["seeded"]} if run is not None else {})},
        parser_identity=ADAPTER, normalizer_identity=ADAPTER, mapping_identity="accepted-cpp-source-map/1",
    )
    path = unit.job.run_root / "data" / "indices" / "observations" / "attempts" / unit.job.config.job_id / unit.job.attempt_id / f"{fingerprint}-{hashlib.sha256(shard.encode()).hexdigest()[:16]}.sqlite"
    builder = IndexBuilder(path, name="observations", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard)
    accepted_count = 0
    source_entities: set[str] = set()
    labels: dict[str, int] = {}
    # Evidence identities already written: a diagnostic one engine reports more than once (a header seen from
    # two translation units) is one observation whose common record cites the first report. Run 2026-11-17-0002
    # failed because each repeat cited its own native-output selector and the shard builder refused two payloads
    # for one identity; the underscore keys never enter the identity, so the repeats are identical evidence.
    seen_evidence: set[str] = set()
    collapsed_repeats = 0
    for record in records:
        location, accepted = _location(scope, record)
        if location is None or accepted is None:
            gaps.append(f"{record['engine']} diagnostic path did not resolve to accepted source: {record['path']}"
                        if accepted is None else
                        f"{record['engine']} diagnostic span did not resolve to accepted source bytes: "
                        f"{record['path']}:{record['line']}:{record['column']}-"
                        f"{record['end_line']}:{record['end_column']}")
            continue
        selector = record.get("_native_selector")
        hashed = {key: value for key, value in record.items() if not key.startswith("_")}
        evidence_id = hashlib.sha256(canonical_json({"scope": scope.scope_id, **hashed})).hexdigest()
        if evidence_id in seen_evidence:
            collapsed_repeats += 1
            continue
        seen_evidence.add(evidence_id)
        observation = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, scope.case_snapshot,
                                             {"producer": record["engine"], "evidence_id": evidence_id})
        source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, scope.case_snapshot,
                                           {"path": accepted["target_path"], "sha256": accepted["sha256"]})
        if source_id.value not in source_entities:
            builder.add_entity(EntityRecord(
                source_id, str(accepted["target_path"]), Path(str(accepted["target_path"])).name,
                str(accepted["target_path"]),
                {"sha256": accepted["sha256"], "scope_id": scope.scope_id}, location,
            ))
            source_entities.add(source_id.value)
        # ``native_severity`` is the key retrieval normalizes (clang ``warning`` -> medium, ``error`` -> high);
        # ``reported_severity`` stays for readers of the previous adapter's payloads.
        trace, ranges = _resolved_trace(scope, record, gaps)
        payload = {"tool_id": TOOL_ID, "scanner": record["engine"], "category": "source_sast",
                   "native_rule_id": record["rule_id"],
                   "message": record["message"], "native_severity": record["severity"],
                   "reported_severity": record["severity"],
                   "project_id": scope.project_id, "trace": trace, "ranges": ranges, "evidence_id": evidence_id,
                   "trace_length": record["trace_length"], "trace_retained_count": len(trace),
                   "trace_truncated": record["trace_truncated"], "trace_omissions": record["trace_omissions"],
                   "fix_it": bool(record.get("fix_it"))}
        native_output = retained.get(record["engine"])
        payload["common"] = common_metadata(
            payload,
            evidence_refs=((select_native(native_output, selector).as_dict(),)
                           if native_output is not None and selector is not None else ()),
            payload_schema=ADAPTER)
        if run is not None:
            relative = str(accepted["scratch_path"])[len("source/"):]
            placement = seeded.classify(relative, int(record["line"]), run.scope_seeds, run.hood)
            payload["seeded"] = placement
            labels[placement["label"]] = labels.get(placement["label"], 0) + 1
        builder.add_entity(EntityRecord(
            observation, evidence_id, str(record["rule_id"]),
            f"{record['rule_id']} {record['message']}", payload, location,
        ))
        builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT, observation.value,
                                            source_id.value, True, 1.0))
        accepted_count += 1
    gaps = list(dict.fromkeys(gaps))
    any_success = any(paths for engine, paths in successful_units.items() if engine not in engine_failed)
    coverage_status = "unavailable" if engines and not any_success else "partial"
    if run is None:
        coverage_status = coverage_status if gaps else "complete"
        coverage_text = None if not gaps else "; ".join(gaps)[:16384]
    else:
        coverage_text = "; ".join([seeding.coverage_gap(section), *gaps])[:16384]
    builder.add_coverage(f"clang-static:{scope.project_id}", coverage_status, coverage_text)
    sha = builder.build()
    producer: dict[str, Any] = {"job": JOB_ID, "unit": unit.unit_id, "scope_id": scope.scope_id,
                                "project_root": scope.root}
    if compact is not None:
        producer["seeded"] = compact
    index = IndexIdentity("observations", "appsec-review/retrieval-index/2", sha, fingerprint,
                          path.relative_to(unit.job.run_root).as_posix(), producer,
                          tuple(gaps), shard)
    status = "SUCCEEDED" if not gaps else "COMPLETED_WITH_GAPS"
    # Identical diagnostics collapse to one observation entity in the shard; the count is the entity count.
    collapsed = collapsed_repeats + builder.collapsed_identical_records
    result = {"scope_id": scope.scope_id, "case_id": scope.case_id, "project_id": scope.project_id,
              "accepted_compile_database": dict(scope.compile_database), "executions": executions,
              "evidence_artifacts": raw_artifacts, "native_outputs": retained,
              "observation_count": accepted_count - builder.collapsed_identical_records,
              "collapsed_identical_records": collapsed,
              "index_identity": asdict(index),
              "gaps": gaps, "terminal_status": status,
              "not_applicable_inputs": scope.not_applicable_inputs()}
    if run is not None:
        result.update(seeded=compact, ledger=ledger, diagnostic_labels=dict(sorted(labels.items())),
                      analyzed_units=[seeded.UNIT_PREFIX + _source_of(row["file"]) for row in (rows or ())])
    if not incomplete_engines and (run is None or not (engine_failed or failed_units)):
        save_scope_checkpoint(root / "checkpoint.json", identity, result)
    return result


def _validate(context: Any, _result: Any) -> None:
    if tuple(context.config.steps) != ("load", "analyze", "acceptance"):
        raise ValueError("Clang static-analysis topology does not match central configuration")
    for step, task in (("load", "accepted_cpp"), ("analyze", "scopes"),
                       ("acceptance", "publish_handoff")):
        if tuple(context.config.step(step).tasks) != (task,):
            raise ValueError(f"Clang static-analysis task configuration mismatch: {step}")
    _validated_settings(context.config.settings)


def build_job(*, executor_factory: Any = None) -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        accepted, scopes, unavailable = accepted_cpp_scopes(unit.job.run_root)
        if accepted["handoff"].get("source_fingerprint") != unit.job.source_fingerprint:
            raise ValueError("Clang static-analysis target snapshot differs from accepted C++ analysis")
        return {"upstream": {"handoff_sha256": accepted["handoff_sha256"],
                             "manifest": accepted["manifest"]},
                "scopes": [scope.as_dict() for scope in scopes], "unavailable": unavailable}

    def analyze(unit: UnitContext) -> Mapping[str, Any]:
        accepted, scopes, unavailable = accepted_cpp_scopes(unit.job.run_root)
        planned = {item["scope_id"] for item in unit.output("load.accepted_cpp")["scopes"]}
        if {scope.scope_id for scope in scopes} != planned:
            raise ValueError("accepted C++ scopes changed between load and analysis")
        runnable = [scope for scope in scopes if scope.container_compile_database()]
        skipped = [_not_applicable_scope(scope) for scope in scopes if not scope.container_compile_database()]
        seeded_settings = seeded.settings_of(unit)
        plan = seeded.plan_for(unit, runnable, seeded_settings) if seeded_settings.seeded and runnable else None

        def run_for(scope: IndexScope) -> seeded.Run | None:
            if plan is None:
                return None
            return seeded.Run(seeded_settings, plan, plan.for_scope(scope.case_id),
                              seeded.neighborhood_of(accepted, scope.case_id))

        with ThreadPoolExecutor(max_workers=max(1, _settings(unit)["workers"])) as pool:
            results = list(pool.map(lambda scope: _analyze_scope(unit, scope, executor_factory, run_for(scope)),
                                    runnable))
        gaps = [f"{item['case_id']}: {gap}" for item in results for gap in item["gaps"]]
        gaps.extend(f"{case_id}: {reason}" for case_id, reason in unavailable.items())
        status = "NOT_APPLICABLE" if not results and not unavailable else (
            "SUCCEEDED" if results and not gaps else "COMPLETED_WITH_GAPS")
        return {"scopes": results, "scope_count": len(results), "gaps": gaps,
                "not_applicable_scopes": skipped, "terminal_status": status}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded, analyzed = unit.output("load.accepted_cpp"), unit.output("analyze.scopes")
        skipped = analyzed.get("not_applicable_scopes", [])
        skipped_indexes = [_skipped_scope_index(unit, item) for item in skipped]
        manifest = publish_scope_indexes(
            unit, job_id=JOB_ID, index_name="observations", prefix="clang-static",
            results=[*analyzed["scopes"], *skipped_indexes], unavailable=loaded["unavailable"], gaps=analyzed["gaps"],
        )
        counts = {"scopes": len(analyzed["scopes"]) + len(skipped),
                  "analyzed_scopes": len(analyzed["scopes"]), "not_applicable_scopes": len(skipped),
                  "observations": sum(item["observation_count"] for item in analyzed["scopes"]),
                  "gap_count": len(analyzed["gaps"])}
        summary = unit.unit_root / "clang-static-analysis-summary.json"
        atomic_json(summary, {"schema": CLANG_STATIC_HANDOFF_SCHEMA, "upstream": loaded["upstream"],
                              "counts": counts, "scopes": analyzed["scopes"],
                              "not_applicable_scopes": skipped,
                              "unavailable": loaded["unavailable"], "gaps": analyzed["gaps"]})
        return {"schema": CLANG_STATIC_HANDOFF_SCHEMA, "artifact": artifact(unit.job.run_root, summary),
                "index_manifest": manifest, "item_count": counts["observations"], "counts": counts,
                "gaps": analyzed["gaps"], "terminal_status": analyzed["terminal_status"]}

    units = (
        Unit("load.accepted_cpp", load),
        Unit("analyze.scopes", analyze, ("load.accepted_cpp",)),
        Unit("acceptance.publish_handoff", publish, ("load.accepted_cpp", "analyze.scopes")),
    )
    implementation = None
    return Job(JOB_ID, "clang_static_analysis", UnitExecutor(units).execute,
               input_validators=(_validate,), schema_identity=CLANG_STATIC_HANDOFF_SCHEMA,
               implementation_identity=implementation, validation_identity=implementation,
               units=units, datasets=DATASETS, contract=CONTRACT)
