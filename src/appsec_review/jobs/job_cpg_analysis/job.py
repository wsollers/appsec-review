"""Independent Joern/c2cpg code property graph job for accepted C/C++ scopes.

The job consumes only the accepted ``job_cpp_compiled_analysis`` handoff. For every accepted
project scope it runs ``tool-joern``'s c2cpg frontend over the accepted sources and compile
database and retains the resulting CPG as hash-identified, run-owned evidence. A whole-program scope
has no bounded export, source mapping or security acceptance yet, so it publishes a BLOCKED observation
shard with zero observations and ``unavailable`` coverage: generating a CPG is not CPG coverage.

A seeded scope additionally exports the CPG once (``joern-export``, neo4jcsv, in its own scratch so the
c2cpg receipt is untouched) and keeps a bounded per-function record (``export.read_export``): calls,
branches and reaching-definition counts. Those rows make the scope ``partial``, never ``complete``; an
export with no usable function stays ``unavailable``. Bounded subsets retain explicit gaps and
``partial`` coverage, never clean zeroes or complete coverage.

``max_cpg_bytes`` is enforced while c2cpg writes: the container runs under RLIMIT_FSIZE of
``max_cpg_bytes + 1``, so the kernel stops any file from growing past the bound on the run volume.
A CPG that reaches the bound is discarded and the scope publishes an explicit producer gap.
"""

from __future__ import annotations

from appsec_review.storage.shared import PublicationThreadPoolExecutor as ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any, Mapping

from appsec_review import seeding
from appsec_review.jobs import cpp_seeded
from appsec_review.jobs.job_cpg_analysis import export as cpg_export, seeded
from appsec_review.jobs.cpp_index_scopes import (
    CheckpointIntegrityError, IndexScope, accepted_cpp_scopes, artifact, checkpoint_identity, execute_scope_tool,
    publish_scope_indexes, save_scope_checkpoint, scope_checkpoint, tool_identity,
)
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, index_fingerprint,
)
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from appsec_review.jobs.job_cpg_analysis.datasets import CONTRACT, DATASETS


JOB_ID = "job_cpg_analysis"
SCHEMA = "appsec-review/cpg-analysis/1"
TOOL_ID = "tool-joern"
ADAPTER = "joern-c2cpg-adapter/8"
CPG_MANIFEST_SCHEMA = "appsec-review/cpg-manifest/1"
ARGV = ("/opt/joern/joern-cli/c2cpg.sh", "/target/source", "--output", "/scratch/cpg.bin",
        "--compilation-database", "/scratch/compile_commands.json")
JOERN_GAP = (
    "BLOCKED: Joern/c2cpg evidence, when produced, does not establish complete CPG/PDG coverage. "
    "Seeded function exports are partial; general graph export, source mapping and security "
    "acceptance are not complete."
)
JOERN_DISABLED = (
    "DISABLED: Joern is not run because jobs.job_cpg_analysis.settings.enabled is false (the default). "
    "No review fact depends on Joern; code-graph facts come from CodeQL with Clang/LLVM cross-checks "
    "(docs/architecture/code-graph-precomputation.md). No CPG coverage is claimed."
)
RETIREMENT_REASON = "retired_by_policy_oom_replaced_by_alternate_cpg"


def retirement_metadata() -> dict[str, Any]:
    """Return structured retirement metadata for Joern CPG analysis."""
    return {
        "retired": True,
        "reason": RETIREMENT_REASON,
        "tool_id": TOOL_ID,
        "manual_only": True,
        "replacement": "alternate_cpg",
    }


def _settings(unit: UnitContext) -> Mapping[str, int]:
    return {"workers": int(unit.job.config.settings["workers"]),
            "max_cpg_bytes": int(unit.job.config.settings["max_cpg_bytes"])}


def _enabled(unit: UnitContext) -> bool:
    value = unit.job.config.settings.get("enabled", False)
    if not isinstance(value, bool):
        raise ValueError("jobs.job_cpg_analysis.settings.enabled must be a boolean")
    return value


def _reuse(unit: UnitContext, root: Path, identity: str, scope: IndexScope) -> dict[str, Any] | None:
    _check_root(unit, scope, root)
    reused = scope_checkpoint(root / "checkpoint.json", identity, unit.job.run_root, scope,
                              required=("execution.receipt", "execution.compile_database", "cpg_manifest"))
    if reused is None:
        return None
    for field in ("execution_artifacts", "export_artifacts"):
        if not isinstance(reused.get(field), list) or not all(
                isinstance(item, Mapping) and isinstance(item.get("path"), str)
                and isinstance(item.get("sha256"), str) for item in reused[field]):
            raise CheckpointIntegrityError(f"{scope.scope_id}: checkpoint lacks {field} identities")
    manifest = json.loads((unit.job.run_root / reused["cpg_manifest"]["path"]).read_text(encoding="utf-8"))
    bound = {"schema": CPG_MANIFEST_SCHEMA, "checkpoint_identity": identity, "scope": scope.as_dict(),
             "cpg": reused["cpg"], "accepted_compile_database": dict(scope.compile_database),
             "resource_limit": reused["resource_limit"],
             "export_artifacts": reused["export_artifacts"]}
    execution_keys = ("receipt", "compile_database", "image_id", "exit_code", "timed_out", "oom_killed")
    executed = manifest.get("execution") if isinstance(manifest.get("execution"), dict) else {}
    if {key: manifest.get(key) for key in bound} != bound or \
            {key: executed.get(key) for key in execution_keys} != {key: reused["execution"][key] for key in execution_keys}:
        raise CheckpointIntegrityError(f"{scope.scope_id}: CPG manifest does not match its checkpoint")
    evidence_root = (unit.job.run_root / reused["cpg_manifest"]["path"]).parent
    _check_root(unit, scope, evidence_root)
    if reused["cpg"] is not None and reused["cpg"]["path"] != (
            evidence_root / "run" / "cpg.bin").relative_to(unit.job.run_root).as_posix():
        raise CheckpointIntegrityError(f"{scope.scope_id}: checkpointed CPG left its scope root")
    invocations = [("run", reused["execution_artifacts"])]
    if reused["cpg_export"] is not None:
        invocations.append(("export-run", reused["export_artifacts"]))
    for directory, artifacts in invocations:
        expected = {(evidence_root / directory / name).relative_to(unit.job.run_root).as_posix()
                    for name in ("execution.json", "compile_commands.json", "raw/stdout.bin", "raw/stderr.bin")}
        if not expected <= {item["path"] for item in artifacts}:
            raise CheckpointIntegrityError(f"{scope.scope_id}: checkpoint lacks {directory} execution evidence")
    return reused


def _check_root(unit: UnitContext, scope: IndexScope, root: Path) -> None:
    expected = unit.job.run_root / "data" / "code-index" / "joern" / scope.scope_id
    if root.resolve() != root.absolute() or not root.is_relative_to(expected):
        raise CheckpointIntegrityError(f"{scope.scope_id}: CPG evidence root is not its owned path")


def _evidence_root(unit: UnitContext, scope: IndexScope, root: Path, identity: str) -> Path:
    _check_root(unit, scope, root)
    generation = 1
    while True:
        path = root / identity / f"execution-{generation:04d}"
        _check_root(unit, scope, path)
        try:
            path.mkdir(parents=True, exist_ok=False)
            return path
        except FileExistsError:
            generation += 1


def _discard(scratch: Path, name: str, protected: tuple[Path, ...] = ()) -> None:
    """Delete only an owned disposable child, unlinking rather than following symlinks."""
    if name not in ("cpg.bin", "export") or scratch.resolve() != scratch.absolute():
        raise CheckpointIntegrityError("CPG cleanup path left its owned scratch")
    path = scratch / name
    if any(item == path or path in item.parents for item in protected):
        raise CheckpointIntegrityError("CPG disposable output overlaps retained execution evidence")
    if path.is_symlink() or not path.is_dir():
        path.unlink(missing_ok=True)
    else:
        shutil.rmtree(path)


def _execution_artifacts(unit: UnitContext, execution: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [execution["receipt"], execution["compile_database"],
            *(artifact(unit.job.run_root, unit.job.run_root / execution[key])
              for key in ("stdout_path", "stderr_path"))]


def _execution_paths(unit: UnitContext, execution: Mapping[str, Any]) -> tuple[Path, ...]:
    return tuple((unit.job.run_root / path).resolve() for path in (
        execution["receipt"]["path"], execution["compile_database"]["path"],
        execution["stdout_path"], execution["stderr_path"]))


def _not_applicable(unit: UnitContext, scope: IndexScope) -> dict[str, Any]:
    result = {"scope_id": scope.scope_id, "case_id": scope.case_id, "project_id": scope.project_id,
              "terminal_status": "NOT_APPLICABLE", "gaps": [], "cpg": None, "execution": None,
              "observation_count": 0, "not_applicable_inputs": scope.not_applicable_inputs()}
    fingerprint = checkpoint_identity({"adapter": ADAPTER, "scope": scope.as_dict(), **result})
    shard = f"joern-{scope.scope_id}"
    path = unit.job.run_root / "data" / "indices" / "observations" / f"{fingerprint}.sqlite"
    builder = IndexBuilder(path, name="observations", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard)
    index = IndexIdentity("observations", "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                          path.relative_to(unit.job.run_root).as_posix(),
                          {"job": JOB_ID, "unit": unit.unit_id, **result}, (), shard)
    return {**result, "index_identity": asdict(index)}


def _generate(unit: UnitContext, scope: IndexScope, executor_factory: Any,
              run: seeded.Run | None = None) -> dict[str, Any]:
    if run is None and not scope.container_compile_database():
        return _not_applicable(unit, scope)
    limits = _settings(unit)
    limit = limits["max_cpg_bytes"]
    root = (unit.job.run_root / "data" / "code-index" / "joern" / scope.scope_id /
            "attempts" / unit.job.attempt_id)
    values: dict[str, Any] = {
        "schema": SCHEMA, "adapter": ADAPTER, "manifest_schema": CPG_MANIFEST_SCHEMA, "argv": list(ARGV),
        "scope": scope.as_dict(), "gap": JOERN_GAP,
        "container_compile_database": hashlib.sha256(canonical_json(scope.container_compile_database())).hexdigest(),
        "tool": tool_identity(unit.job.repository_root, TOOL_ID) if executor_factory is None
        else {"tool_id": TOOL_ID, "injected_executor": True},
        "max_cpg_bytes": limit, "limit_mechanism": "RLIMIT_FSIZE"}
    if run is not None:
        values.update(seeded.identity_values(run.settings, run.scope_seeds, run.plan))
    identity = checkpoint_identity(values)
    if run is not None and not run.scope_seeds.seeds:
        # Nothing to build: no container runs and nothing is checkpointed.
        return _skipped(unit, scope, run, identity)
    reused = _reuse(unit, root, identity, scope)
    if reused is not None:
        return reused
    selection = argv = rows = None
    if run is not None:
        selection = cpp_seeded.select(scope, run.scope_seeds, run.settings)
        rows = list(selection.container_rows)
        if not rows:
            return _skipped(unit, scope, run, identity, selection=selection)
        argv = seeded.argv_for(ARGV, seeded.selected_files(selection))
    evidence_root = _evidence_root(unit, scope, root, identity)
    scratch = evidence_root / "run"
    execution = execute_scope_tool(unit, scope, TOOL_ID, argv or ARGV, scratch, executor_factory,
                                   file_size_limit_bytes=limit + 1, compile_rows=rows)
    gaps: list[str] = list(selection.gaps) if selection else []
    cpg_path = scratch / "cpg.bin"
    cpg = None
    regular = cpg_path.is_file() and not cpg_path.is_symlink()
    observed = cpg_path.lstat().st_size if regular else None
    limited = execution["file_size_limit_reached"] or (observed is not None and observed > limit)
    disposition = "LIMIT_REACHED" if limited else "WITHIN_LIMIT" if observed else "NOT_PRODUCED"
    if limited:
        # The kernel stopped the write at limit + 1 bytes; whatever exists is partial and is never evidence.
        gaps.append(f"Joern c2cpg reached the {limit}-byte CPG limit while writing; "
                    "the partial CPG was discarded")
    elif execution["timed_out"]:
        gaps.append("Joern c2cpg timed out before a CPG was produced")
    elif execution["oom_killed"]:
        gaps.append("Joern c2cpg was OOM-killed before a CPG was produced")
    elif execution["exit_code"] != 0:
        gaps.append(f"Joern c2cpg exited with status {execution['exit_code']}")
    elif not regular or observed == 0:
        gaps.append("Joern c2cpg produced no CPG")
    else:
        cpg = artifact(unit.job.run_root, cpg_path)
    if cpg is None and (cpg_path.exists() or cpg_path.is_symlink()):
        _discard(scratch, "cpg.bin", _execution_paths(unit, execution))
    gaps.append(JOERN_GAP)
    exported: dict[str, Any] | None = None
    export_artifacts: list[Any] = []
    if run is not None and cpg is not None:
        exported, export_artifacts, export_gaps = _export(
            unit, scope, evidence_root, scratch / "cpg.bin", executor_factory)
        gaps.extend(export_gaps)
    resource_limit = {"mechanism": "RLIMIT_FSIZE", "max_cpg_bytes": limit, "enforced_bytes": limit + 1,
                      "disposition": disposition, "observed_bytes": observed}
    ledger = compact = None
    if run is not None:
        gaps.append(seeded.EXPORT_SCOPE_GAP if exported else seeded.NO_EXPORT_GAP)
        ledger, compact, gaps = _seeded_record(unit, scope, evidence_root, run, selection, cpg is not None, gaps)
    manifest_path = evidence_root / "cpg-manifest.json"
    atomic_json(manifest_path, {
        "schema": CPG_MANIFEST_SCHEMA, "checkpoint_identity": identity, "scope": scope.as_dict(), "cpg": cpg,
        "accepted_compile_database": dict(scope.compile_database), "resource_limit": resource_limit,
        "export_artifacts": export_artifacts,
        "execution": {key: execution[key] for key in ("receipt", "compile_database", "image_id", "image_digest",
                                                     "argv_identity", "exit_code", "timed_out", "oom_killed")}})
    cpg_manifest = artifact(unit.job.run_root, manifest_path)
    execution_artifacts = _execution_artifacts(unit, execution)
    artifacts = [*execution_artifacts, dict(scope.compile_database), cpg_manifest]
    if cpg is not None:
        artifacts.append(cpg)
    artifacts.extend(export_artifacts)
    if ledger is not None:
        artifacts.append(ledger)
    index = _publish_shard(unit, scope, artifacts=artifacts,
                           tool={"tool": TOOL_ID, "image": execution["image_id"],
                                 "image_digest": execution["image_digest"]},
                           gaps=gaps, cpg=cpg, cpg_manifest=cpg_manifest, resource_limit=resource_limit,
                           compact=compact, seeded_identity=values.get("seeded"), exported=exported)
    result = {"scope_id": scope.scope_id, "case_id": scope.case_id, "project_id": scope.project_id,
              "execution": execution, "execution_artifacts": execution_artifacts, "export_artifacts": export_artifacts,
              "accepted_compile_database": dict(scope.compile_database), "resource_limit": resource_limit,
              "cpg": cpg, "cpg_manifest": cpg_manifest, "observation_count": 0, "index_identity": asdict(index),
              "gaps": gaps, "cpg_export": exported["artifact"] if exported else None,
              "cpg_export_function_count": len(exported["functions"]) if exported else 0,
              "terminal_status": "COMPLETED_WITH_GAPS"}
    result["not_applicable_inputs"] = scope.not_applicable_inputs()
    if run is not None:
        result.update(seeded=compact, ledger=ledger,
                      analyzed_files=seeded.selected_files(selection), exclude_regex=seeded.exclude_regex(
                          seeded.selected_files(selection)))
    if run is None or exported is not None:
        save_scope_checkpoint(root / "checkpoint.json", identity, result)
    return result


def _export(unit: UnitContext, scope: IndexScope, root: Path, cpg_path: Path,
            executor_factory: Any) -> tuple[dict[str, Any] | None, list[Any], list[str]]:
    """Run ``joern-export`` over the scope's CPG in a separate scratch and keep its bounded per-function record.

    Returns (record or ``None``, run-owned artifacts, gaps). Failed execution outcomes publish no
    functions; engine/integrity exceptions propagate. Disposable CSVs and the staged input are cleaned
    on every outcome, never at the expense of retained execution evidence.
    """
    _check_root(unit, scope, root)
    scratch = root / "export-run"
    _check_root(unit, scope, scratch)
    protected: tuple[Path, ...] = ()
    try:
        execution = execute_scope_tool(unit, scope, TOOL_ID, seeded.EXPORT_ARGV, scratch, executor_factory,
                                       file_size_limit_bytes=seeded.MAX_EXPORT_FILE_BYTES, compile_rows=[],
                                       inputs={"cpg.bin": cpg_path})
        protected = _execution_paths(unit, execution)
        artifacts = _execution_artifacts(unit, execution)
        directory = scratch / "export"
        if execution["file_size_limit_reached"]:
            gaps = [f"Joern export reached the {seeded.MAX_EXPORT_FILE_BYTES}-byte per-file limit; it was discarded"]
        elif execution["timed_out"]:
            gaps = ["Joern export timed out; no seeded CPG fact is published"]
        elif execution["oom_killed"]:
            gaps = ["Joern export was OOM-killed; no seeded CPG fact is published"]
        elif execution["exit_code"] != 0:
            gaps = [f"Joern export exited with status {execution['exit_code']}"]
        elif not directory.is_dir() or directory.is_symlink():
            gaps = ["Joern export produced no output directory"]
        else:
            parsed = cpg_export.read_export(directory)
            gaps = list(parsed.gaps)
            if parsed.functions:
                record_path = root / "cpg-export.json"
                atomic_json(record_path, parsed.as_dict())
                record = artifact(unit.job.run_root, record_path)
                return ({"artifact": record, **parsed.as_dict()}, [*artifacts, record], gaps)
        return None, artifacts, gaps
    finally:
        _discard(scratch, "export", protected)
        _discard(scratch, "cpg.bin", protected)


def _seeded_record(unit: UnitContext, scope: IndexScope, root: Path, run: seeded.Run, selection: Any,
                   produced: bool, gaps: list[str]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Write the scope's seeded ledger and return (ledger artifact, compact record, gaps incl. the ledger's)."""
    section = cpp_seeded.section_for(run.settings, run.plan, run.scope_seeds, selection,
                                     seeded.reasons(selection, produced))
    if not run.scope_seeds.seeds:
        section["gaps"] = [seeding.NO_SEEDS_GAP, *section["gaps"]]
    gaps = list(dict.fromkeys([*gaps, *section["gaps"]]))
    root.mkdir(parents=True, exist_ok=True)
    ledger_path = root / "seeded-ledger.json"
    atomic_json(ledger_path, {"schema": seeding.record.RECORD_SCHEMA, "branch": "joern-cpg",
                              "project": scope.case_id, "seeded": section})
    ledger = artifact(unit.job.run_root, ledger_path)
    compact = seeding.compact_record({**section, "gaps": gaps}, ledger=ledger, skipped=not run.scope_seeds.seeds)
    return ledger, compact, gaps


def _publish_shard(unit: UnitContext, scope: IndexScope, *, artifacts: list[Any], tool: Mapping[str, Any],
                   gaps: list[str], cpg: Any, cpg_manifest: Any, resource_limit: Any,
                   compact: Mapping[str, Any] | None, seeded_identity: Any,
                   exported: Mapping[str, Any] | None = None) -> IndexIdentity:
    shard = f"joern-{scope.scope_id}"
    fingerprint = index_fingerprint(
        name="observations", target_snapshot=scope.case_snapshot, producer_artifacts=artifacts,
        tool_identity={**tool, **({"seeded": seeded_identity} if seeded_identity else {})},
        parser_identity=ADAPTER, normalizer_identity=ADAPTER, mapping_identity="cpp-source-mapping/3")
    path = (unit.job.run_root / "data" / "indices" / "observations" /
            f"{fingerprint}-{hashlib.sha256(shard.encode()).hexdigest()[:16]}.sqlite")
    builder = IndexBuilder(path, name="observations", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard)
    evidence = LogicalIdentity.derive(EntityKind.EVIDENCE_ARTIFACT, scope.case_snapshot,
                                      {"project_id": scope.project_id, "producer": "joern",
                                       "status": "BLOCKED"})
    builder.add_entity(EntityRecord(evidence, f"joern:{scope.case_id}", "joern",
                                    "; ".join(gaps)[:16384],
                                    {"status": "BLOCKED", "observation_count": 0, "cpg": cpg,
                                     "cpg_manifest": cpg_manifest, "resource_limit": resource_limit,
                                     "project_id": scope.project_id, "shard_id": shard}))
    for function in (exported or {}).get("functions", ()):
        function_key = {"function_id": function["function_id"]} if function["function_id"] is not None else {
            "export_sha256": exported["artifact"]["sha256"], "export_node_id": function["export_node_id"]}
        identity = LogicalIdentity.derive(EntityKind.AST_NODE, scope.case_snapshot, {
            "project_id": scope.project_id, "scope_id": scope.scope_id,
            "producer": "joern-cpg", **function_key})
        builder.add_entity(EntityRecord(identity, function["full_name"], function["name"], f"cpg {function['name']}",
                                        {"fact": "cpg", "producer": "joern-cpg", "scope_id": scope.scope_id,
                                         "project_id": scope.project_id, "shard_id": shard, **function}))
    text = "; ".join([seeding.coverage_gap(compact), *gaps] if compact else gaps)
    builder.add_coverage(f"joern:{scope.project_id}"[:256], "partial" if exported else "unavailable", text[:16384])
    sha, _ = builder.build_or_reuse()
    producer: dict[str, Any] = {"job": JOB_ID, "unit": unit.unit_id, "scope_id": scope.scope_id,
                                "project_root": scope.root}
    if compact is not None:
        producer["seeded"] = dict(compact)
    return IndexIdentity("observations", "appsec-review/retrieval-index/2", sha, fingerprint,
                         path.relative_to(unit.job.run_root).as_posix(), producer, tuple(gaps), shard)


def _skipped(unit: UnitContext, scope: IndexScope, run: seeded.Run, identity: str,
             selection: Any = None) -> dict[str, Any]:
    """A seeded scope with nothing to build (no seeds, or no supported unit holds one): no container runs."""
    root = unit.job.run_root / "data" / "code-index" / "joern" / scope.scope_id
    root = _evidence_root(unit, scope, root, identity)
    gaps = [JOERN_GAP, seeded.NO_EXPORT_GAP, *(selection.gaps if selection else ())]
    ledger, compact, gaps = _seeded_record(unit, scope, root, run, selection, False, gaps)
    index = _publish_shard(unit, scope, artifacts=[dict(scope.compile_database), ledger],
                           tool={"tool": TOOL_ID, "image": None, "image_digest": None}, gaps=gaps, cpg=None,
                           cpg_manifest=None, resource_limit=None, compact=compact,
                           seeded_identity=run.settings.identity())
    return {"scope_id": scope.scope_id, "case_id": scope.case_id, "project_id": scope.project_id,
            "execution": None, "accepted_compile_database": dict(scope.compile_database),
            "resource_limit": None, "cpg": None, "cpg_manifest": None, "observation_count": 0,
            "index_identity": asdict(index), "gaps": gaps, "seeded": compact, "ledger": ledger,
            "analyzed_files": [], "terminal_status": "COMPLETED_WITH_GAPS"}


def _validate(context, _result) -> None:
    if tuple(context.config.steps) != ("load", "generate", "acceptance"):
        raise ValueError("CPG-analysis topology does not match central configuration")
    for step, task in (("load", "accepted_cpp"), ("generate", "scopes"), ("acceptance", "publish_handoff")):
        if tuple(context.config.step(step).tasks) != (task,):
            raise ValueError(f"CPG-analysis task configuration mismatch: {step}")


def build_job(*, executor_factory=None) -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        accepted, scopes, unavailable = accepted_cpp_scopes(unit.job.run_root)
        if accepted["handoff"].get("source_fingerprint") != unit.job.source_fingerprint:
            raise ValueError("CPG target snapshot differs from the accepted C++ build")
        unit.job.events.write("CPG_SCOPES_LOADED", scope_count=len(scopes),
                              unavailable_count=len(unavailable))
        return {"upstream": {"handoff_sha256": accepted["handoff_sha256"], "manifest": accepted["manifest"]},
                "scopes": [scope.as_dict() for scope in scopes], "unavailable": unavailable}

    def generate(unit: UnitContext) -> Mapping[str, Any]:
        _accepted, scopes, unavailable = accepted_cpp_scopes(unit.job.run_root)
        planned = {item["scope_id"] for item in unit.output("load.accepted_cpp")["scopes"]}
        if {scope.scope_id for scope in scopes} != planned:
            raise ValueError("accepted C++ scopes changed between load and generate")
        if not _enabled(unit):
            # Deliberately not run: every scope is an explicit unavailable row, never clean coverage.
            disabled = {scope.case_id: JOERN_DISABLED for scope in scopes}
            unit.job.events.write("CPG_ANALYSIS_DISABLED", scope_count=len(scopes))
            gaps = [f"{case_id}: {reason}" for case_id, reason in {**unavailable, **disabled}.items()]
            return {"scopes": [], "scope_count": 0, "gaps": gaps, "disabled": sorted(disabled),
                    "terminal_status": "NOT_APPLICABLE" if not scopes and not unavailable else "COMPLETED_WITH_GAPS"}
        seeded_settings = cpp_seeded.settings_of(unit)
        plan = cpp_seeded.plan_for(unit, scopes, seeded_settings) if seeded_settings.seeded and scopes else None

        def run_for(scope: IndexScope) -> seeded.Run | None:
            if plan is None:
                return None
            return seeded.Run(seeded_settings, plan, plan.for_scope(scope.case_id))

        with ThreadPoolExecutor(max_workers=max(1, _settings(unit)["workers"])) as pool:
            results = list(pool.map(lambda scope: _generate(unit, scope, executor_factory, run_for(scope)), scopes))
        gaps = list(dict.fromkeys(f"{item['case_id']}: {gap}" for item in results for gap in item["gaps"]))
        gaps.extend(f"{case_id}: {reason}" for case_id, reason in unavailable.items())
        status = "NOT_APPLICABLE" if not unavailable and all(
            item["terminal_status"] == "NOT_APPLICABLE" for item in results) else "COMPLETED_WITH_GAPS"
        return {"scopes": results, "scope_count": len(results), "gaps": gaps, "disabled": [],
                "terminal_status": status}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded, generated = unit.output("load.accepted_cpp"), unit.output("generate.scopes")
        unavailable = {**loaded["unavailable"], **{case_id: JOERN_DISABLED for case_id in generated["disabled"]}}
        manifest = publish_scope_indexes(unit, job_id=JOB_ID, index_name="observations", prefix="joern",
                                         results=generated["scopes"], unavailable=unavailable,
                                         gaps=generated["gaps"])
        counts = {"scopes": len(generated["scopes"]), "disabled_scopes": len(generated["disabled"]),
                  "cpgs_generated": sum(item["cpg"] is not None for item in generated["scopes"]),
                  "observations": 0}
        summary_path = unit.unit_root / "cpg-analysis-summary.json"
        atomic_json(summary_path, {"schema": SCHEMA, "upstream": loaded["upstream"], "counts": counts,
                                   "retirement": retirement_metadata(),
                                   "scopes": generated["scopes"], "unavailable": unavailable,
                                   "gaps": generated["gaps"]})
        unit.job.events.write("CPG_ANALYSIS_COMPLETED", **counts, gap_count=len(generated["gaps"]))
        return {"schema": SCHEMA, "artifact": artifact(unit.job.run_root, summary_path),
                "index_manifest": manifest, "item_count": 0, "counts": counts,
                "gaps": generated["gaps"], "terminal_status": generated["terminal_status"]}

    units = (
        Unit("load.accepted_cpp", load),
        Unit("generate.scopes", generate, ("load.accepted_cpp",)),
        Unit("acceptance.publish_handoff", publish, ("load.accepted_cpp", "generate.scopes")),
    )
    implementation = None
    return Job(JOB_ID, "cpg_analysis", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=SCHEMA, implementation_identity=implementation, units=units,
               datasets=DATASETS, contract=CONTRACT)
