"""Bounded Clang-Tidy and Clang Static Analyzer job over accepted native scopes.

Only source material and compilation databases already accepted by
``job_cpp_compiled_analysis`` are mounted.  The target itself is never executed.  Each engine is
an independent action so one failure cannot erase the other's observations; all failures are
retained as scope-specific coverage gaps.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from appsec_review.jobs.cpp_index_scopes import (
    IndexScope, accepted_cpp_scopes, artifact, checkpoint_identity, execute_scope_tool,
    publish_scope_indexes, save_scope_checkpoint, scope_checkpoint, tool_identity,
)
from appsec_review.jobs.engineering_contracts import CLANG_STATIC_HANDOFF_SCHEMA
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint,
)
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from .datasets import CONSUMES, DATASETS


JOB_ID = "job_clang_static_analysis"
TOOL_ID = "tool-clang-static-analysis"
OUTPUT_SCHEMA = "appsec-review/clang-static-output/1"
ADAPTER = "clang-static-adapter/3"
ENGINES = ("clang-tidy", "clang-static-analyzer")


def _validated_settings(settings: Mapping[str, Any]) -> dict[str, Any]:
    checks = settings.get("clang_tidy_checks", ())
    checkers = settings.get("clang_analyzer_checkers", ())
    if not isinstance(checks, (list, tuple)) or not checks or not all(isinstance(v, str) and v for v in checks):
        raise ValueError("clang_tidy_checks must be a non-empty string list")
    if not isinstance(checkers, (list, tuple)) or not checkers or not all(isinstance(v, str) and v for v in checkers):
        raise ValueError("clang_analyzer_checkers must be a non-empty string list")
    values = {
        "workers": int(settings["workers"]),
        "max_output_bytes": int(settings["max_output_bytes"]),
        "max_diagnostics_per_scope": int(settings["max_diagnostics_per_scope"]),
        "clang_tidy_checks": tuple(checks),
        "clang_analyzer_checkers": tuple(checkers),
    }
    if min(values["workers"], values["max_output_bytes"], values["max_diagnostics_per_scope"]) <= 0:
        raise ValueError("Clang static-analysis numeric bounds must be positive")
    return values


def _settings(unit: UnitContext) -> dict[str, Any]:
    return _validated_settings(unit.job.config.settings)


def _read_output(path: Path, *, engine: str, max_bytes: int, max_diagnostics: int) -> tuple[list[dict[str, Any]], list[str]]:
    """Read one strict, bounded wrapper result; malformed output is a gap, never clean."""
    gaps: list[str] = []
    if not path.is_file() or path.is_symlink():
        return [], [f"{engine} produced no result document"]
    size = path.stat().st_size
    if size > max_bytes:
        return [], [f"{engine} result exceeded the {max_bytes}-byte output bound"]
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return [], [f"{engine} result was malformed JSON"]
    if not isinstance(document, Mapping) or document.get("schema") != OUTPUT_SCHEMA or document.get("engine") != engine:
        return [], [f"{engine} result envelope was malformed"]
    raw = document.get("diagnostics")
    if not isinstance(raw, list):
        return [], [f"{engine} diagnostics were malformed"]
    if len(raw) > max_diagnostics:
        return [], [f"{engine} exceeded the {max_diagnostics}-diagnostic bound"]
    if document.get("truncated") is True:
        gaps.append(f"{engine} output was truncated by its bounded wrapper")
    records: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            return [], [f"{engine} diagnostic {index} was malformed"]
        required = ("rule_id", "message", "path", "line", "column")
        if any((not isinstance(item.get(key), str)) if key in {"rule_id", "message", "path"}
               else type(item.get(key)) is not int for key in required):
            return [], [f"{engine} diagnostic {index} was malformed"]
        if len(item["rule_id"]) > 512 or len(item["message"]) > 16384 or len(item["path"]) > 4096 \
                or int(item["line"]) < 1 or int(item["column"]) < 1:
            return [], [f"{engine} diagnostic {index} exceeded field bounds"]
        notes = item.get("notes", [])
        if not isinstance(notes, list) or len(notes) > 256:
            return [], [f"{engine} diagnostic {index} had an unbounded trace"]
        records.append({
            "engine": engine, "rule_id": item["rule_id"], "message": item["message"],
            "severity": str(item.get("severity", "warning"))[:32], "path": item["path"],
            "line": int(item["line"]), "column": int(item["column"]),
            "end_line": max(int(item.get("end_line", item["line"])), int(item["line"])),
            "end_column": max(int(item.get("end_column", item["column"])), int(item["column"])),
            "notes": notes,
        })
    return records, gaps


def _location(scope: IndexScope, record: Mapping[str, Any]) -> tuple[SourceLocation | None, Mapping[str, Any] | None]:
    accepted = scope.accepted_file(str(record["path"]))
    if accepted is None:
        return None, None
    relative = str(accepted["scratch_path"])[len("source/"):]
    source = scope.case_root / "source" / Path(*relative.split("/"))
    data = source.read_bytes()
    offsets = [0]
    offsets.extend(index + 1 for index, value in enumerate(data) if value == 10)
    line = min(int(record["line"]), len(offsets))
    end_line = min(int(record["end_line"]), len(offsets))
    start = min(len(data), offsets[line - 1] + int(record["column"]) - 1)
    end = min(len(data), offsets[end_line - 1] + int(record["end_column"]))
    return SourceLocation(
        target_snapshot=scope.case_snapshot, path=str(accepted["target_path"]),
        file_sha256=str(accepted["sha256"]), start_byte=start, end_byte=max(start, end),
        start_line=line, end_line=end_line, start_column=int(record["column"]),
        end_column=int(record["end_column"]),
        producer_location={"engine": record["engine"], "path": record["path"]},
        mapping_method="accepted-cpp-source-map", confidence=1.0,
    ), accepted


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


def _analyze_scope(unit: UnitContext, scope: IndexScope, executor_factory: Any) -> dict[str, Any]:
    settings = _settings(unit)
    root = unit.job.run_root / "data" / "clang-static" / scope.scope_id
    identity = checkpoint_identity({
        "schema": CLANG_STATIC_HANDOFF_SCHEMA, "adapter": ADAPTER, "scope": scope.as_dict(),
        "settings": settings, "tool": tool_identity(unit.job.repository_root, TOOL_ID)
        if executor_factory is None else {"tool_id": TOOL_ID, "injected_executor": True},
    })
    reused = scope_checkpoint(root / "checkpoint.json", identity, unit.job.run_root, scope)
    if reused is not None:
        return dict(reused)

    records: list[dict[str, Any]] = []
    gaps: list[str] = []
    executions: dict[str, Any] = {}
    raw_artifacts: list[Mapping[str, Any]] = [dict(scope.compile_database)]
    for engine in ENGINES:
        scratch = root / ("tidy" if engine == "clang-tidy" else "analyze")
        try:
            execution = execute_scope_tool(
                unit, scope, TOOL_ID, _engine_argv(engine, settings), scratch, executor_factory,
                file_size_limit_bytes=settings["max_output_bytes"] + 1,
            )
        except Exception as exc:
            gaps.append(f"{engine} tool/image unavailable: {type(exc).__name__}: {exc}")
            continue
        executions[engine] = execution
        raw_artifacts.extend((execution["receipt"], execution["compile_database"]))
        if execution["timed_out"]:
            gaps.append(f"{engine} timed out")
            continue
        if execution["oom_killed"]:
            gaps.append(f"{engine} was OOM-killed")
            continue
        if execution["file_size_limit_reached"] or execution["stdout_truncated"] or execution["stderr_truncated"]:
            gaps.append(f"{engine} output was truncated or exceeded its execution bound")
            continue
        if execution["exit_code"] != 0:
            gaps.append(f"{engine} exited with status {execution['exit_code']}")
            continue
        output_path = scratch / ("tidy.json" if engine == "clang-tidy" else "analyze.json")
        parsed, parse_gaps = _read_output(output_path, engine=engine,
                                          max_bytes=settings["max_output_bytes"],
                                          max_diagnostics=settings["max_diagnostics_per_scope"])
        gaps.extend(parse_gaps)
        if output_path.is_file() and not output_path.is_symlink() and output_path.stat().st_size <= settings["max_output_bytes"]:
            raw_artifacts.append(artifact(unit.job.run_root, output_path))
        records.extend(parsed)

    shard = f"clang-static-{scope.scope_id}"
    fingerprint = index_fingerprint(
        name="observations", target_snapshot=scope.case_snapshot, producer_artifacts=raw_artifacts,
        tool_identity={"tool": TOOL_ID, "executions": {key: value.get("image_digest") for key, value in executions.items()}},
        parser_identity=ADAPTER, normalizer_identity=ADAPTER, mapping_identity="accepted-cpp-source-map/1",
    )
    path = unit.job.run_root / "data" / "indices" / "observations" / f"{fingerprint}-{hashlib.sha256(shard.encode()).hexdigest()[:16]}.sqlite"
    builder = IndexBuilder(path, name="observations", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard)
    accepted_count = 0
    source_entities: set[str] = set()
    for record in records:
        location, accepted = _location(scope, record)
        if location is None or accepted is None:
            gaps.append(f"{record['engine']} diagnostic path did not resolve to accepted source: {record['path']}")
            continue
        evidence_id = hashlib.sha256(canonical_json({"scope": scope.scope_id, **record})).hexdigest()
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
        builder.add_entity(EntityRecord(
            observation, evidence_id, str(record["rule_id"]),
            f"{record['rule_id']} {record['message']}",
            {"tool_id": TOOL_ID, "scanner": record["engine"], "category": "source_sast",
             "native_rule_id": record["rule_id"],
             "message": record["message"], "reported_severity": record["severity"],
             "project_id": scope.project_id, "trace": record["notes"], "evidence_id": evidence_id},
            location,
        ))
        builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT, observation.value,
                                            source_id.value, True, 1.0))
        accepted_count += 1
    coverage_status = "complete" if not gaps else "partial"
    builder.add_coverage(f"clang-static:{scope.project_id}", coverage_status,
                         None if not gaps else "; ".join(gaps)[:16384])
    sha = builder.build()
    index = IndexIdentity("observations", "appsec-review/retrieval-index/2", sha, fingerprint,
                          path.relative_to(unit.job.run_root).as_posix(),
                          {"job": JOB_ID, "unit": unit.unit_id, "scope_id": scope.scope_id},
                          tuple(dict.fromkeys(gaps)), shard)
    status = "SUCCEEDED" if not gaps else "COMPLETED_WITH_GAPS"
    result = {"scope_id": scope.scope_id, "case_id": scope.case_id, "project_id": scope.project_id,
              "accepted_compile_database": dict(scope.compile_database), "executions": executions,
              "observation_count": accepted_count, "index_identity": asdict(index),
              "gaps": list(dict.fromkeys(gaps)), "terminal_status": status,
              "not_applicable_inputs": scope.not_applicable_inputs()}
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
        _accepted, scopes, unavailable = accepted_cpp_scopes(unit.job.run_root)
        planned = {item["scope_id"] for item in unit.output("load.accepted_cpp")["scopes"]}
        if {scope.scope_id for scope in scopes} != planned:
            raise ValueError("accepted C++ scopes changed between load and analysis")
        runnable = [scope for scope in scopes if scope.container_compile_database()]
        skipped = [_not_applicable_scope(scope) for scope in scopes if not scope.container_compile_database()]
        with ThreadPoolExecutor(max_workers=max(1, _settings(unit)["workers"])) as pool:
            results = list(pool.map(lambda scope: _analyze_scope(unit, scope, executor_factory), runnable))
        gaps = [f"{item['case_id']}: {gap}" for item in results for gap in item["gaps"]]
        gaps.extend(f"{case_id}: {reason}" for case_id, reason in unavailable.items())
        status = "NOT_APPLICABLE" if not results and not unavailable else (
            "SUCCEEDED" if results and not gaps else "COMPLETED_WITH_GAPS")
        return {"scopes": results, "scope_count": len(results), "gaps": gaps,
                "not_applicable_scopes": skipped, "terminal_status": status}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded, analyzed = unit.output("load.accepted_cpp"), unit.output("analyze.scopes")
        manifest = publish_scope_indexes(
            unit, job_id=JOB_ID, index_name="observations", prefix="clang-static",
            results=analyzed["scopes"], unavailable=loaded["unavailable"], gaps=analyzed["gaps"],
        )
        counts = {"scopes": len(analyzed["scopes"]),
                  "observations": sum(item["observation_count"] for item in analyzed["scopes"]),
                  "gap_count": len(analyzed["gaps"])}
        summary = unit.unit_root / "clang-static-analysis-summary.json"
        atomic_json(summary, {"schema": CLANG_STATIC_HANDOFF_SCHEMA, "upstream": loaded["upstream"],
                              "counts": counts, "scopes": analyzed["scopes"],
                              "unavailable": loaded["unavailable"], "gaps": analyzed["gaps"]})
        return {"schema": CLANG_STATIC_HANDOFF_SCHEMA, "artifact": artifact(unit.job.run_root, summary),
                "index_manifest": manifest, "item_count": counts["observations"], "counts": counts,
                "gaps": analyzed["gaps"], "terminal_status": analyzed["terminal_status"]}

    units = (
        Unit("load.accepted_cpp", load),
        Unit("analyze.scopes", analyze, ("load.accepted_cpp",)),
        Unit("acceptance.publish_handoff", publish, ("load.accepted_cpp", "analyze.scopes")),
    )
    implementation = hashlib.sha256(
        b"".join(path.read_bytes() for path in sorted(Path(__file__).parent.glob("*.py"))) +
        (b"injected-executor" if executor_factory else b"container-executor")
    ).hexdigest()
    return Job(JOB_ID, "clang_static_analysis", UnitExecutor(units).execute,
               input_validators=(_validate,), schema_identity=CLANG_STATIC_HANDOFF_SCHEMA,
               implementation_identity=implementation, validation_identity=implementation,
               units=units, datasets=DATASETS, consumes=CONSUMES)
