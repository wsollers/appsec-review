"""Finding-seeded CBMC evidence; no native target execution or claim-state changes."""

from collections import Counter
from collections.abc import Mapping
from collections.abc import Mapping
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review import seeding
from appsec_review.config.cbmc import CbmcSettings
from appsec_review.config.seeding import SeededSettings
from appsec_review.interchange import GapCode, ProducerStatus, producer_gap
from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.cpp_index_scopes import (
    IndexScope, accepted_cpp_scopes, container_compile_database, partition_compile_commands, project_prefix,
)
from appsec_review.provenance import common_metadata, json_selector, retain_native_output, select_native
from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, write_manifest
from appsec_review.retrieval.core import resolve_context_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.retrieval.observations import classify
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.runtime.consume import accepted_upstream
from appsec_review.runtime.handoff import collect_artifacts
from appsec_review.runtime.inputs import input_shard_owner, observe_output
from appsec_review.seeding import units as unit_selection
from appsec_review.storage import atomic_json, canonical_json, file_sha256, run_artifact, verify_run_artifact
from .analysis import Analysis, stage_source
from .datasets import CONTRACT, DATASETS, JOB_ID, SUMMARY_SCHEMA
from .protocol import CompileRejected, IMPLEMENTATION, compile_argv

TOPOLOGY = {"load": ("accepted_inputs",), "analyze": ("bounded_checks",),
            "acceptance": ("publish_handoff",)}
SEED_PRODUCERS = {"job_evidence_collection", "job_codeql_analysis", "job_clang_static_analysis"}
SEED_DATASETS = {(item.producer, item.output_kind) for item in CONTRACT.inputs
                 if item.producer in SEED_PRODUCERS and item.output_kind != "handoff"}


def _snapshot(context: Any) -> str:
    value = context.evidence_target_snapshot or context.source_fingerprint
    if not value or value == "none":
        raise ValueError("CBMC requires an admitted target evidence identity")
    return value


def _gap(reason: str, *, scope: str | None = None, code: GapCode = GapCode.PRODUCER_REPORTED_GAP):
    return producer_gap(code, reason, scope_id=scope)


def _write(unit: UnitContext, path: Path, document: Mapping[str, Any]) -> dict[str, Any]:
    atomic_json(path, document)
    return run_artifact(unit.job.run_root, path)


def _read(unit: UnitContext, reference: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(verify_run_artifact(unit.job.run_root, reference).read_text(encoding="utf-8"))


def _inputs(context: Any):
    manifest_path, manifest_sha = resolve_context_manifest(context)
    manifest, _ = load_verified_manifest(context.run_root, manifest_path, manifest_sha)
    snapshot = _snapshot(context)
    if manifest["target_snapshot"] != snapshot:
        raise ValueError("CBMC input manifest belongs to a different target snapshot")
    bound = {"path": manifest_path.relative_to(context.run_root).as_posix(), "sha256": manifest_sha}
    cpp = accepted_upstream(context.run_root, "job_cpp_compiled_analysis", required=False)
    if cpp is None:
        catalog = accepted_upstream(context.run_root, "job_target_catalog", required=False)
        if catalog is None:
            return bound, [], {"catalog": "accepted target source inventory is unavailable"}, []
        source_shards = [item for item in manifest["indexes"] if item["name"] == "source"
                         and item.get("producer", {}).get("job") == "job_target_catalog"]
        if not source_shards:
            return bound, [], {"catalog": "accepted target source shard is unavailable"}, []
        source_store = ShardSet(context.run_root, source_shards)
        native = any(str((row.get("location") or {}).get("path") or row["native_id"]).lower().endswith(
            (".c", ".cc", ".cpp", ".cxx", ".c++"))
                     for row in source_store.entities(source_store.shards, kinds=("source_file",)))
        return bound, [], ({"compiled": "accepted native compilation is unavailable"} if native else {}), []
    summary_ref = cpp.handoff.get("outputs", {}).get("acceptance.publish_handoff", {}).get("artifact")
    if not isinstance(summary_ref, Mapping) or not any(
        ref["path"] == summary_ref["path"] and ref["sha256"] == summary_ref["sha256"]
        for ref in cpp.handoff.get("artifacts", ())
    ):
        raise ValueError("accepted C/C++ summary is not bound to its handoff")
    summary = json.loads(verify_run_artifact(context.run_root, summary_ref).read_text(encoding="utf-8"))
    if summary.get("schema") != "appsec-review/cpp-compiled-analysis/2":
        raise ValueError("unsupported accepted C/C++ summary")
    observe_output(context.run_root, "job_cpp_compiled_analysis", "cpp_plan_and_summary", summary_ref)
    accepted, scopes, unavailable = accepted_cpp_scopes(context.run_root)
    if accepted["handoff"].get("source_fingerprint") != snapshot:
        raise ValueError("CBMC accepted C/C++ input belongs to a different target")
    admitted = {name for name in sorted(SEED_PRODUCERS)
                if accepted_upstream(context.run_root, name, required=False) is not None}
    shards = []
    for item in manifest["indexes"]:
        producer = item.get("producer", {}).get("job")
        if item["name"] != "observations" or producer not in admitted:
            continue
        owner = input_shard_owner(context.run_root, item)
        if (producer, owner.output_kind) in SEED_DATASETS:
            shards.append(item)
    source_hashes: dict[str, set[str]] = {}
    for scope in scopes:
        observe_output(context.run_root, "job_cpp_compiled_analysis", "cpp_case_material", scope.compile_database)
        for source in scope.files:
            source_hashes.setdefault(source["target_path"], set()).add(source["sha256"])
    store = ShardSet(context.run_root, shards)
    unmapped_native = set()
    for row in store.entities(store.shards, kinds=("tool_observation",)):
        location = row.get("location") or {}
        expected = source_hashes.get(location.get("path"))
        if expected is not None and location.get("file_sha256") not in expected:
            raise ValueError("CBMC scanner seed and accepted build source identities differ")
        if (expected is None and classify(row["payload"]) == "source_sast"
                and str(location.get("path", "")).lower().endswith((".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh"))):
            unmapped_native.add((location["path"], location["start_line"], location["end_line"]))
    if unmapped_native:
        unavailable = {**unavailable, "unmapped_native_seeds":
                       f"{len(unmapped_native)} native scanner seed locations have no accepted compiled source scope"}
    if scopes and not shards:
        unavailable = {**unavailable, "scanner_seeds": "no admitted source scanner observation shard"}
    return bound, scopes, unavailable, shards


@dataclass(frozen=True, slots=True)
class _ScopeCompilePartition:
    admissible_rows: tuple[dict[str, Any], ...]
    admissible_container_rows: tuple[dict[str, Any], ...]
    rejected_rows: tuple[dict[str, Any], ...]
    rejected_only_reasons: Mapping[str, str]
    clang_unsupported_rels: frozenset[str]
    admissible_project: seeding.ProjectScope
    rejected_project: seeding.ProjectScope | None


def _partition_scope(scope: IndexScope) -> _ScopeCompilePartition:
    prefix = project_prefix(scope.root)
    clang_supported, clang_unsupported = partition_compile_commands(scope.compile_commands)
    container_rows = container_compile_database(scope.root, clang_supported)
    admissible_rows: list[dict[str, Any]] = []
    admissible_container_rows: list[dict[str, Any]] = []
    admissible_rels: set[str] = set()
    rejected_rows: list[dict[str, Any]] = []
    rejected_reasons: dict[str, str] = {}
    for cmd, container_row in zip(clang_supported, container_rows, strict=True):
        rel = str(cmd["target_path"])[len(prefix):]
        scratch_row = dict(cmd, file=f"/scratch/source/{rel}")
        try:
            compile_argv(container_row)
        except CompileRejected as exc:
            rejected_rows.append(scratch_row)
            rejected_reasons.setdefault(rel, str(exc))
        else:
            admissible_rows.append(scratch_row)
            admissible_container_rows.append(container_row)
            admissible_rels.add(rel)
    rejected_only = {rel: reason for rel, reason in sorted(rejected_reasons.items()) if rel not in admissible_rels}
    clang_unsupported_rels = (
        frozenset(str(item.path)[len(prefix):] for item in clang_unsupported)
        - admissible_rels
        - set(rejected_only)
    )
    rejected_targets = {f"{prefix}{rel}" for rel in rejected_only}
    admissible_files = tuple(
        {"path": str(item["target_path"])}
        for item in scope.files
        if str(item["target_path"]) not in rejected_targets
    )
    rejected_files = tuple(
        {"path": str(item["target_path"])}
        for item in scope.files
        if str(item["target_path"]) in rejected_targets
    )
    return _ScopeCompilePartition(
        admissible_rows=tuple(admissible_rows),
        admissible_container_rows=tuple(admissible_container_rows),
        rejected_rows=tuple(rejected_rows),
        rejected_only_reasons=rejected_only,
        clang_unsupported_rels=clang_unsupported_rels,
        admissible_project=seeding.ProjectScope(scope.case_id, scope.root, admissible_files),
        rejected_project=seeding.ProjectScope(scope.case_id, scope.root, rejected_files) if rejected_files else None,
    )


def plan(context: Any, settings: CbmcSettings) -> dict[str, Any]:
    manifest, scopes, unavailable, shards = _inputs(context)
    partitions = {scope.case_id: _partition_scope(scope) for scope in scopes}
    seeds = seeding.extract_seeds(
        context.run_root, [], [partitions[scope.case_id].admissible_project for scope in scopes],
        seed_limit=settings.max_seeds_per_scope, extra_observation_shards=shards,
    )
    rejected_projects = [
        part.rejected_project for scope in scopes
        if (part := partitions[scope.case_id]).rejected_project is not None
    ]
    rejected_seeds = (
        seeding.extract_seeds(
            context.run_root, [], rejected_projects,
            seed_limit=max(settings.max_seeds_per_scope, 4096), extra_observation_shards=shards,
        )
        if rejected_projects else seeding.SeedPlan()
    )
    bounds = SeededSettings(mode="seeded", seed_limit=settings.max_seeds_per_scope,
                            unit_limit=settings.max_translation_units, include_scan_files=settings.max_source_files)
    work = []
    gaps = [_gap(reason, scope=scope, code=GapCode.INPUT_UNAVAILABLE) for scope, reason in sorted(unavailable.items())]
    omitted = {"scopes": 0, "translation_units": 0, "seeds": 0}
    selected_scopes = sorted(
        (
            scope for scope in scopes
            if seeds.for_scope(scope.case_id).seeds or rejected_seeds.for_scope(scope.case_id).seeds
        ),
        key=lambda scope: (
            min(
                seed.rank for seed in (
                    *seeds.for_scope(scope.case_id).seeds,
                    *rejected_seeds.for_scope(scope.case_id).seeds,
                )
            ),
            scope.scope_id,
        ),
    )
    omitted["scopes"] = max(0, len(selected_scopes) - settings.max_scopes)
    for scope in selected_scopes[:settings.max_scopes]:
        part = partitions[scope.case_id]
        scope_seeds = seeds.for_scope(scope.case_id)
        omitted["seeds"] += scope_seeds.dropped
        seeded_rejected = {
            seed.path for seed in rejected_seeds.for_scope(scope.case_id).seeds
            if seed.path in part.rejected_only_reasons
        }
        selection_gaps: list[str] = []
        if scope_seeds.seeds:
            reader = seeding.source_reader(scope.case_root / "source")
            chosen = unit_selection.select_units(
                part.admissible_rows, scope_seeds.seeds,
                unit_limit=bounds.unit_limit, include_scan_files=bounds.include_scan_files, read_text=reader,
            )
            rejected_covered: set[tuple[str, int, int]] = set()
            if chosen.uncovered and part.rejected_rows:
                uncovered_keys = set(chosen.uncovered)
                uncovered_seeds = [seed for seed in scope_seeds.seeds if seed.key in uncovered_keys]
                rej_chosen = unit_selection.select_units(
                    part.rejected_rows, uncovered_seeds,
                    unit_limit=len(part.rejected_rows), include_scan_files=bounds.include_scan_files, read_text=reader,
                )
                for key, indexes in rej_chosen.by_seed.items():
                    rejected_covered.add(key)
                    for idx in indexes:
                        rel = unit_selection.relative_source(part.rejected_rows[idx])
                        if rel in part.rejected_only_reasons:
                            seeded_rejected.add(rel)
            selection_gaps = list(chosen.gaps)
            non_missing = {
                key for key in chosen.uncovered
                if key in rejected_covered or key[0] in part.clang_unsupported_rels
            }
            if non_missing:
                selection_gaps = [g for g in selection_gaps if not g.startswith(unit_selection.NO_UNIT_FOR_SEED)]
                missing = len(chosen.uncovered) - len(non_missing)
                if missing:
                    selection_gaps.append(
                        f"{unit_selection.NO_UNIT_FOR_SEED}: {missing} seed location(s) lie in no analyzed "
                        "translation unit; their diagnostics are not covered"
                    )
            by_seed = {
                key: tuple(unit_selection.relative_source(part.admissible_rows[idx]) for idx in indexes)
                for key, indexes in chosen.by_seed.items()
            }
            for idx in chosen.selected:
                raw = part.admissible_rows[idx]
                row = part.admissible_container_rows[idx]
                relative = str(raw["file"]).removeprefix("/scratch/source/")
                selected = [
                    {"path": seed.path, "start_line": seed.start_line, "end_line": seed.end_line,
                     "rank": seed.rank, "observation_ids": sorted(source.observation_id for source in seed.sources)}
                    for seed in scope_seeds.seeds if relative in by_seed.get(seed.key, ())
                ]
                if selected:
                    work.append({"scope_id": scope.scope_id, "case_id": scope.case_id,
                                 "compile_database": dict(scope.compile_database), "row": row, "seeds": selected})
        for rel in sorted(seeded_rejected):
            gaps.append(_gap(f"CompileRejected ({rel}): {part.rejected_only_reasons[rel]}", scope=scope.scope_id))
        gaps.extend(_gap(reason, scope=scope.scope_id) for reason in selection_gaps)
    unique = {}
    for item in work:
        key = (item["scope_id"], canonical_json(item["row"]))
        unique.setdefault(key, item)
    work = list(unique.values())
    work.sort(key=lambda item: (min(seed["rank"] for seed in item["seeds"]), item["row"]["file"], item["scope_id"]))
    omitted["translation_units"] = max(0, len(work) - settings.max_translation_units)
    if any(omitted.values()):
        gaps.append(_gap(f"selection budget omitted {omitted}", code=GapCode.TRUNCATED))
    return {"schema": "appsec-review/cbmc-plan/1", "target_snapshot": _snapshot(context),
            "input_manifest": manifest, "work": work[:settings.max_translation_units],
            "omitted": omitted, "gaps": gaps, "eligible_scopes": len(selected_scopes)}


def analyze(unit: UnitContext, document: Mapping[str, Any], settings: CbmcSettings,
            executor_factory=None) -> dict[str, Any]:
    manifest, scopes, _, _ = _inputs(unit.job)
    if manifest != document["input_manifest"] or _snapshot(unit.job) != document["target_snapshot"]:
        raise ValueError("CBMC admitted inputs changed between selection and execution")
    by_id = {scope.scope_id: scope for scope in scopes}
    engine = Analysis(unit, settings, executor_factory=executor_factory)
    staged: dict[str, Path] = {}
    source_artifacts = []
    refused: dict[str, str] = {}
    results = []
    for item in document["work"]:
        scope = by_id[item["scope_id"]]
        if dict(scope.compile_database) != item["compile_database"]:
            raise ValueError("CBMC compile database changed after selection")
        if engine.clock() >= engine.deadline:
            results.append(engine.record(scope, item["seeds"], "not_attempted", "analysis budget exhausted",
                                         gaps=["analysis_budget"]))
            continue
        if scope.scope_id not in staged and scope.scope_id not in refused:
            target = engine.root / "source" / scope.scope_id
            try:
                stage_source(scope, target, settings)
                staged[scope.scope_id] = target
                source_artifacts.extend(run_artifact(unit.job.run_root, target / source["scratch_path"])
                                        for source in scope.files)
            except CompileRejected as exc:
                refused[scope.scope_id] = str(exc)
        if scope.scope_id in refused:
            results.append(engine.record(scope, item["seeds"], "not_attempted", refused[scope.scope_id],
                                         gaps=["source_staging_bound"]))
            continue
        results.extend(engine.translation_unit(scope, item["row"], item["seeds"], staged[scope.scope_id]))
    gaps = list(document["gaps"])
    for result in results:
        if result["gaps"]:
            gaps.append(_gap("; ".join(result["gaps"]) + ": " + result["reason"], scope=result["scope_id"]))
    return {"schema": "appsec-review/cbmc-analysis/1", "target_snapshot": document["target_snapshot"],
            "settings": asdict(settings), "results": results, "gaps": gaps,
            "omitted": document["omitted"], "executions": engine.calls, "source_artifacts": source_artifacts,
            "counts": dict(sorted(Counter(result["judgment"] for result in results).items()))}


def _location(snapshot: str, seed: Mapping[str, Any], scopes: Mapping[str, Any], scope_id: str) -> SourceLocation:
    scope = scopes[scope_id]
    accepted = next(item for item in scope.files if item["target_path"] == seed["path"])
    data = (scope.case_root / accepted["scratch_path"]).read_bytes()
    if hashlib.sha256(data).hexdigest() != seed["file_sha256"]:
        raise ValueError("CBMC seed source changed before publication")
    lines = data.splitlines(keepends=True)
    if not 1 <= seed["start_line"] <= seed["end_line"] <= len(lines):
        raise ValueError("CBMC seed line is outside the accepted source file")
    return SourceLocation(snapshot, seed["path"], seed["file_sha256"],
                          sum(map(len, lines[:seed["start_line"] - 1])), sum(map(len, lines[:seed["end_line"]])),
                          seed["start_line"], seed["end_line"], 1, 1,
                          producer_location={"producer": JOB_ID}, mapping_method="accepted-cpp-source-map",
                          confidence=1.0)


def publish(unit: UnitContext, document: Mapping[str, Any], plan_ref: Mapping[str, Any],
            analysis_ref: Mapping[str, Any]) -> dict[str, Any]:
    snapshot = _snapshot(unit.job)
    artifacts = collect_artifacts(unit.job.run_root, document, plan_ref, analysis_ref)
    settings = CbmcSettings.from_mapping(unit.job.config.settings)
    _, scopes, _, _ = _inputs(unit.job)
    by_id = {scope.scope_id: scope for scope in scopes}
    indexes = []
    counts = dict(document["counts"])
    for label in ("results", "coverage"):
        shard_id = f"cbmc-{label}-{unit.job.attempt_id}"
        fingerprint = hashlib.sha256(canonical_json({"implementation": IMPLEMENTATION, "label": label,
                                                     "analysis": analysis_ref["sha256"]})).hexdigest()
        path = unit.job.run_root / "data" / "indices" / "observations" / "attempts" / getattr(unit.job.config, "job_id", JOB_ID) / unit.job.attempt_id / f"{shard_id}.sqlite"
        builder = IndexBuilder(path, name="observations", fingerprint=fingerprint,
                               target_snapshot=snapshot, shard_id=shard_id)
        if label == "results":
            for ordinal, result in enumerate(document["results"]):
                seed = result["seed_locations"][0]
                location = _location(snapshot, seed, by_id, result["scope_id"])
                properties = result["properties"]
                payload = {key: value for key, value in result.items() if key not in {
                    "properties", "executions", "normalized_compile_arguments", "admitted_compile_arguments"}}
                payload.update(schema="appsec-review/cbmc-result/1", tool_id="tool-cbmc", scanner="cbmc",
                               category="bounded_model_check", native_severity="info",
                               properties=properties[:settings.max_property_summaries],
                               omitted_properties=result["omitted_properties"],
                               analysis=analysis_ref, result_ordinal=ordinal)
                native = result.get("native_output")
                refs = ()
                if native is not None:
                    retained = retain_native_output(
                        unit.job.run_root, verify_run_artifact(unit.job.run_root, native),
                        parser_identity=IMPLEMENTATION, complete=True, native_result_count=result["property_count"],
                        execution_reference=result["native_execution"],
                        events=unit.job.events, unit_id=unit.unit_id)
                    refs = (select_native(retained.as_dict(), json_selector()).as_dict(),)
                payload["common"] = common_metadata(payload, evidence_refs=refs, payload_schema=IMPLEMENTATION,
                                                    record_kind="observation")
                identity = LogicalIdentity.derive(EntityKind.REVIEW_SIGNAL, snapshot, {
                    "producer": JOB_ID, "analysis": analysis_ref["sha256"], "ordinal": ordinal})
                builder.add_entity(EntityRecord(
                    identity, identity.value, result["function"] or result["scope_id"],
                    f"CBMC {result['judgment']}: {result['reason']}", payload, location))
        # A selected function analysis is never whole-project coverage, even when every property passed.
        status = "partial" if any(item["property_count"] for item in document["results"]) else "unavailable"
        reason = "Finding-seeded function-entry models only; no whole-program or caller-reachability conclusion."
        if not document["results"]:
            reason = "No eligible seeded C/C++ work was attempted; this is not clean coverage."
        elif status == "unavailable":
            reason = "No CBMC property results were accepted; failed or omitted work is not clean coverage."
        if label == "coverage":
            builder.add_coverage("cbmc", status, reason)
            for gap in document["gaps"]:
                builder.add_coverage("cbmc:" + gap["gap_id"], "unavailable", gap["reason"])
        digest = builder.build()
        indexes.append(IndexIdentity("observations", "appsec-review/retrieval-index/2", digest, fingerprint,
                                     path.relative_to(unit.job.run_root).as_posix(),
                                     {"job": JOB_ID, "unit": unit.unit_id},
                                     tuple(gap["reason"] for gap in document["gaps"]), shard_id))
    upstream_path, upstream_sha = resolve_context_manifest(unit.job)
    upstream, _ = load_verified_manifest(unit.job.run_root, upstream_path, upstream_sha)
    inherited = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
                 for item in upstream["indexes"] if item.get("producer", {}).get("job") != JOB_ID]
    manifest = unit.job.run_root / "data" / "indices" / "manifests" / f"cbmc-{unit.job.attempt_id}.json"
    write_manifest(manifest, run_id=unit.job.run_id, target_snapshot=snapshot,
                   target_root=Path(upstream["target_root"]), indexes=[*inherited, *indexes],
                   upstream_manifests=({"path": upstream_path.relative_to(unit.job.run_root).as_posix(),
                                        "sha256": upstream_sha},))
    load_verified_manifest(unit.job.run_root, manifest, file_sha256(manifest))
    status = (ProducerStatus.COMPLETED_WITH_GAPS if document["gaps"] else
              ProducerStatus.SUCCEEDED if document["results"] else ProducerStatus.NOT_APPLICABLE)
    summary = {"schema": SUMMARY_SCHEMA, "target_snapshot": snapshot, "plan": plan_ref,
               "analysis": analysis_ref, "counts": counts, "omitted": document["omitted"],
               "image_id": document["settings"]["image_id"], "gaps": document["gaps"],
               "terminal_status": status}
    reference = _write(unit, unit.unit_root / "summary.json", summary)
    return {"schema": SUMMARY_SCHEMA, "artifact": reference, "artifacts": artifacts,
            "index_manifest": run_artifact(unit.job.run_root, manifest),
            "item_count": len(document["results"]), "gaps": document["gaps"], "terminal_status": status}


def _validate(context: Any, result: Mapping[str, Any] | None) -> None:
    settings = CbmcSettings.from_mapping(context.config.settings)
    if tuple(context.config.steps) != tuple(TOPOLOGY) or any(
        tuple(context.config.step(step).tasks) != tasks for step, tasks in TOPOLOGY.items()
    ):
        raise ValueError("CBMC task topology differs from central configuration")
    if result is not None:
        output = result["outputs"]["acceptance.publish_handoff"]
        summary = json.loads(verify_run_artifact(context.run_root, output["artifact"]).read_text())
        if (set(summary) != {"schema", "target_snapshot", "plan", "analysis", "counts", "omitted",
                            "image_id", "gaps", "terminal_status"}
                or summary["schema"] != SUMMARY_SCHEMA or summary["target_snapshot"] != _snapshot(context)):
            raise ValueError("invalid CBMC summary contract")
        plan = json.loads(verify_run_artifact(context.run_root, summary["plan"]).read_text())
        analysis = json.loads(verify_run_artifact(context.run_root, summary["analysis"]).read_text())
        collect_artifacts(context.run_root, plan, analysis)
        expected = dict(sorted(Counter(item["judgment"] for item in analysis["results"]).items()))
        if (summary["image_id"] != settings.image_id or summary["counts"] != expected
                or output["item_count"] != len(analysis["results"])
                or summary["gaps"] != analysis["gaps"]):
            raise ValueError("CBMC summary counts, gaps or image identity contradict its analysis")


def build_job(*, executor_factory=None) -> Job:
    def load(unit: UnitContext):
        document = plan(unit.job, CbmcSettings.from_mapping(unit.job.config.settings))
        reference = _write(unit, unit.unit_root / "plan.json", document)
        return {"artifact": reference, "artifacts": collect_artifacts(unit.job.run_root, document),
                "gaps": document["gaps"], "terminal_status":
                ProducerStatus.COMPLETED_WITH_GAPS if document["gaps"] else ProducerStatus.SUCCEEDED}

    def run(unit: UnitContext):
        source = _read(unit, unit.output("load.accepted_inputs")["artifact"])
        document = analyze(unit, source, CbmcSettings.from_mapping(unit.job.config.settings), executor_factory)
        reference = _write(unit, unit.job.attempt_root / "artifacts" / "cbmc" / "analysis.json", document)
        unit.job.events.write("CBMC_ANALYSIS_COMPLETED", unit_id=unit.unit_id,
                              counts=document["counts"], execution_count=len(document["executions"]),
                              gap_count=len(document["gaps"]))
        return {"artifact": reference, "artifacts": collect_artifacts(unit.job.run_root, document),
                "gaps": document["gaps"], "terminal_status":
                ProducerStatus.COMPLETED_WITH_GAPS if document["gaps"] else ProducerStatus.SUCCEEDED}

    def accept(unit: UnitContext):
        reference = unit.output("analyze.bounded_checks")["artifact"]
        return publish(unit, _read(unit, reference), unit.output("load.accepted_inputs")["artifact"], reference)

    units = (Unit("load.accepted_inputs", load),
             Unit("analyze.bounded_checks", run, ("load.accepted_inputs",)),
             Unit("acceptance.publish_handoff", accept, ("load.accepted_inputs", "analyze.bounded_checks")))
    return Job(JOB_ID, "cbmc_analysis", UnitExecutor(units).execute, units=units,
               input_validators=(_validate,), output_validators=(_validate,), schema_identity=SUMMARY_SCHEMA,
               datasets=DATASETS, contract=CONTRACT, strict_gaps=True)
