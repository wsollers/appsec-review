"""Finding-seeded CBMC evidence; no native target execution or claim-state changes."""

from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review import seeding
from appsec_review.config.cbmc import CbmcSettings
from appsec_review.config.seeding import SeededSettings
from appsec_review.interchange import GapCode, ProducerStatus, producer_gap
from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.cpp_index_scopes import accepted_cpp_scopes
from appsec_review.jobs.cpp_seeded import project_of, select
from appsec_review.provenance import common_metadata, json_selector, retain_native_output, select_native
from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, write_manifest
from appsec_review.retrieval.core import resolve_context_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.retrieval.observations import classify
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.runtime.consume import accepted_upstream
from appsec_review.runtime.inputs import observe_output
from appsec_review.storage import atomic_json, canonical_json, file_sha256, run_artifact, verify_run_artifact
from appsec_review.storage.shared import current as current_owner
from .analysis import Analysis, stage_source
from .datasets import CONTRACT, DATASETS, JOB_ID, SUMMARY_SCHEMA
from .protocol import CompileRejected, IMPLEMENTATION

TOPOLOGY = {"load": ("accepted_inputs",), "analyze": ("bounded_checks",),
            "acceptance": ("publish_handoff",)}
SEED_PRODUCERS = {"job_evidence_collection", "job_codeql_analysis", "job_clang_static_analysis"}


def _snapshot(context: Any) -> str:
    value = context.evidence_target_snapshot or context.source_fingerprint
    if not value or value == "none":
        raise ValueError("CBMC requires an admitted target evidence identity")
    return value


def _gap(reason: str, *, scope: str | None = None, code: GapCode = GapCode.PRODUCER_REPORTED_GAP):
    return producer_gap(code, reason, scope_id=scope, unit_id="analyze.bounded_checks")


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
    shards = [item for item in manifest["indexes"] if item["name"] == "observations"
              and item.get("producer", {}).get("job") in admitted]
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


def plan(context: Any, settings: CbmcSettings) -> dict[str, Any]:
    manifest, scopes, unavailable, shards = _inputs(context)
    seeds = seeding.extract_seeds(context.run_root, [], [project_of(scope) for scope in scopes],
                                 seed_limit=settings.max_seeds_per_scope, extra_observation_shards=shards)
    bounds = SeededSettings(mode="seeded", seed_limit=settings.max_seeds_per_scope,
                            unit_limit=settings.max_translation_units, include_scan_files=settings.max_source_files)
    work = []
    gaps = [_gap(reason, scope=scope, code=GapCode.INPUT_UNAVAILABLE) for scope, reason in sorted(unavailable.items())]
    omitted = {"scopes": 0, "translation_units": 0, "seeds": 0}
    selected_scopes = sorted(
        (scope for scope in scopes if seeds.for_scope(scope.case_id).seeds),
        key=lambda scope: (min(seed.rank for seed in seeds.for_scope(scope.case_id).seeds), scope.scope_id),
    )
    omitted["scopes"] = max(0, len(selected_scopes) - settings.max_scopes)
    for scope in selected_scopes[:settings.max_scopes]:
        scope_seeds = seeds.for_scope(scope.case_id)
        omitted["seeds"] += scope_seeds.dropped
        selection = select(scope, scope_seeds, bounds)
        gaps.extend(_gap(reason, scope=scope.scope_id) for reason in selection.gaps)
        for raw, row in zip(selection.rows, selection.container_rows, strict=True):
            relative = str(raw["file"]).removeprefix("/scratch/source/")
            selected = [
                {"path": seed.path, "start_line": seed.start_line, "end_line": seed.end_line,
                 "rank": seed.rank, "observation_ids": sorted(source.observation_id for source in seed.sources)}
                for seed in scope_seeds.seeds if relative in selection.by_seed.get(seed.key, ())
            ]
            if selected:
                work.append({"scope_id": scope.scope_id, "case_id": scope.case_id,
                             "compile_database": dict(scope.compile_database), "row": row, "seeds": selected})
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
            "omitted": document["omitted"], "executions": engine.calls,
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
    settings = CbmcSettings.from_mapping(unit.job.config.settings)
    _, scopes, _, _ = _inputs(unit.job)
    by_id = {scope.scope_id: scope for scope in scopes}
    indexes = []
    counts = dict(document["counts"])
    for label in ("results", "coverage"):
        shard_id = f"cbmc-{label}-{unit.job.attempt_id}"
        fingerprint = hashlib.sha256(canonical_json({"implementation": IMPLEMENTATION, "label": label,
                                                     "analysis": analysis_ref["sha256"]})).hexdigest()
        path = unit.job.run_root / "data" / "indices" / "observations" / f"{shard_id}.sqlite"
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
                if native is not None and current_owner() is not None:
                    retained = retain_native_output(
                        unit.job.run_root, verify_run_artifact(unit.job.run_root, native),
                        parser_identity=IMPLEMENTATION, complete=True, native_result_count=result["property_count"],
                        execution_reference=result["executions"][-1]["receipt"],
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
    return {"schema": SUMMARY_SCHEMA, "artifact": reference,
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
        for name in ("plan", "analysis"):
            verify_run_artifact(context.run_root, summary[name])
        analysis = json.loads(verify_run_artifact(context.run_root, summary["analysis"]).read_text())
        expected = dict(sorted(Counter(item["judgment"] for item in analysis["results"]).items()))
        if (summary["image_id"] != settings.image_id or summary["counts"] != expected
                or output["item_count"] != len(analysis["results"])
                or summary["gaps"] != analysis["gaps"]):
            raise ValueError("CBMC summary counts, gaps or image identity contradict its analysis")


def build_job(*, executor_factory=None) -> Job:
    def load(unit: UnitContext):
        document = plan(unit.job, CbmcSettings.from_mapping(unit.job.config.settings))
        reference = _write(unit, unit.unit_root / "plan.json", document)
        return {"artifact": reference, "gaps": document["gaps"], "terminal_status":
                ProducerStatus.COMPLETED_WITH_GAPS if document["gaps"] else ProducerStatus.SUCCEEDED}

    def run(unit: UnitContext):
        source = _read(unit, unit.output("load.accepted_inputs")["artifact"])
        document = analyze(unit, source, CbmcSettings.from_mapping(unit.job.config.settings), executor_factory)
        reference = _write(unit, unit.job.attempt_root / "artifacts" / "cbmc" / "analysis.json", document)
        unit.job.events.write("CBMC_ANALYSIS_COMPLETED", unit_id=unit.unit_id,
                              counts=document["counts"], execution_count=len(document["executions"]),
                              gap_count=len(document["gaps"]))
        return {"artifact": reference, "gaps": document["gaps"], "terminal_status":
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
