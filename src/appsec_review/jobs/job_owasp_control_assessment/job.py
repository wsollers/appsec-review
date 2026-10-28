from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review.config.owasp import AssessmentMode, parse_settings
from appsec_review.applicability import resolved_configuration_identity
from appsec_review.inference import Infer
from appsec_review.observability import PipelineLog
from appsec_review.retrieval.core import RetrievalCore, resolve_context_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.owasp_workbench import (
    assess_batch, build_applicability, build_finding_packages, characterize_components,
    compose, control_records, deterministic_join, fingerprint_inputs, load_catalogs,
    partition_work, pin_bundle, publish_manifest, publish_shard, select_profiles,
    standards_manifest, verify_results,
)
from appsec_review.jobs.job_owasp_control_assessment.datasets import CONSUMES, DATASETS
from appsec_review.owasp_workbench.assessment import run_batch
from appsec_review.owasp_workbench.evidence import EvidenceResolver, accepted_inputs
from appsec_review.review.scope import accept_manifest


SCHEMA = "appsec-review/owasp-workbench-result/1"
CELLS = ("cell_01", "cell_02", "cell_03", "cell_04")
TOPOLOGY = {
    "standards_selection": ("ingest_catalogs", "select_profiles"),
    "characterization": ("load_inputs", "classify_components"),
    "applicability": ("build_matrix",),
    "batching": ("partition_work", "build_packages"),
    "validation": CELLS,
    "verification": ("independent_review",),
    "join": ("deterministic_join",),
    "publication": ("publish_indexes", "publish_handoff"),
}


def _artifact(unit: UnitContext, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    path = unit.job.attempt_root / "artifacts" / "owasp-workbench" / name
    atomic_json(path, dict(value))
    return {"path": path.relative_to(unit.job.run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _sources(settings: Mapping[str, Any]) -> Mapping[str, Any]:
    value = settings.get("standards")
    if not isinstance(value, Mapping):
        raise ValueError("OWASP standards source settings are required")
    return value


def _catalogs(unit: UnitContext):
    return load_catalogs(unit.job.repository_root, _sources(unit.job.config.settings))


def _validate_config(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("OWASP workbench topology does not match central configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"OWASP workbench task order mismatch: {step}")
    settings = context.config.settings
    typed = parse_settings(settings)
    if not typed.enabled:
        raise ValueError("OWASP job is disabled by settings.enabled")
    catalogs = load_catalogs(context.repository_root, _sources(settings))
    if typed.mode is AssessmentMode.ASSESSMENT:
        from appsec_review.inference import PROVIDERS
        if any(catalog.fixture for catalog in catalogs.values()):
            raise ValueError("assessment requires complete acquired catalogs, not qualification fixtures")
        for model in (settings["model"], settings["models"][typed.reviewer_profile]):
            if model["provider"] not in PROVIDERS:
                raise ValueError(f"unsupported OWASP inference transport: {model['provider']}")


def _fixture_or_accepted_inputs(unit: UnitContext) -> dict[str, Any]:
    typed = parse_settings(unit.job.config.settings)
    fixture = unit.job.run_root / "data" / "inputs" / "owasp-workbench.json"
    if typed.mode is AssessmentMode.QUALIFICATION:
        if not fixture.is_file():
            raise ValueError("explicit qualification mode requires the run-owned qualification input")
        document = json.loads(fixture.read_text(encoding="utf-8"))
        if document.get("schema") != "appsec-review/owasp-workbench-input/1":
            raise ValueError("OWASP fixture input schema is unsupported")
        return {"components": document.get("components", []), "evidence": document.get("evidence", []),
                "retrieval_manifest": document.get("retrieval_manifest", {"fixture": file_sha256(fixture)}),
                "input_mode": "run_owned_fixture", "assessment_mode": "qualification",
                "limitations": ["qualification input is synthetic and cannot establish customer target safety"]}
    if fixture.exists():
        raise ValueError("qualification input is not accepted in assessment mode")
    core, path = _core(unit)
    expected = unit.job.evidence_target_snapshot
    if expected is not None and core.manifest["target_snapshot"] != expected:
        raise ValueError("OWASP accepted evidence target differs from the job's authenticated target")
    return {**accepted_inputs(core, typed, manifest_path=path), "assessment_mode": "assessment"}


def _core(unit: UnitContext) -> tuple[RetrievalCore, Path]:
    path, sha256 = resolve_context_manifest(unit.job)
    return RetrievalCore(unit.job.run_root.parent, unit.job.run_id, manifest_path=path,
                         manifest_sha256=sha256), path


def _resolver(unit: UnitContext) -> EvidenceResolver:
    core, path = _core(unit)
    return EvidenceResolver(core, accept_manifest(unit.job.run_root, manifest_path=path,
                                                  manifest_sha256=core.manifest_sha256),
                            max_source_lines=parse_settings(unit.job.config.settings).max_source_lines)


def build_job(*, fail_cell: str | None = None, infer: Infer | None = None) -> Job:
    def transport():
        from appsec_review.inference import infer as default_infer
        return infer or default_infer

    def ingest(unit: UnitContext) -> Mapping[str, Any]:
        manifest = standards_manifest(_catalogs(unit))
        return {"manifest": manifest, "artifact": _artifact(unit, "standards-manifest.json", manifest),
                "gaps": manifest["gaps"],
                "terminal_status": "COMPLETED_WITH_GAPS" if manifest["gaps"] else "SUCCEEDED"}

    def select(unit: UnitContext) -> Mapping[str, Any]:
        settings = unit.job.config.settings
        selection = select_profiles(_catalogs(unit), asvs_level=int(settings["asvs_level"]),
                                    masvs_profile=str(settings["masvs_profile"]))
        return {"selection": selection, "artifact": _artifact(unit, "selection.json", selection)}

    def load_inputs(unit: UnitContext) -> Mapping[str, Any]:
        value = _fixture_or_accepted_inputs(unit)
        return {**value, "component_count": len(value["components"]),
                "evidence_count": len(value["evidence"])}

    def classify(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("characterization.load_inputs")
        values = characterize_components(loaded["components"],
            max_components=int(unit.job.config.settings["max_components"]),
            assessment_mode=loaded["assessment_mode"])
        artifact = _artifact(unit, "component-classifications.json", {
            "schema": "appsec-review/component-classification-set/1", "components": values})
        return {"classifications": values, "artifact": artifact,
                "gap_count": sum(len(value["gaps"]) for value in values)}

    def applicability(unit: UnitContext) -> Mapping[str, Any]:
        rows = build_applicability(_catalogs(unit),
            unit.output("characterization.classify_components")["classifications"],
            unit.output("standards_selection.select_profiles")["selection"],
            dynamic_authorized=bool(unit.job.config.settings["dynamic_authorized"]),
            assessment_mode=parse_settings(unit.job.config.settings).mode.value)
        artifact = _artifact(unit, "applicability.json", {
            "schema": "appsec-review/control-applicability-set/1", "rows": rows})
        counts = {outcome: sum(row["outcome"] == outcome for row in rows)
                  for outcome in sorted({row["outcome"] for row in rows})}
        return {"rows": rows, "artifact": artifact, "outcome_counts": counts}

    def partition(unit: UnitContext) -> Mapping[str, Any]:
        settings = unit.job.config.settings
        work = partition_work(unit.output("applicability.build_matrix")["rows"],
            unit.job.repository_root, max_batch_size=int(settings["max_batch_size"]),
            max_components=int(settings["max_components_per_batch"]))
        return {"work": work, "artifact": _artifact(unit, "validation-work.json", work),
                "batch_count": len(work["batches"])}

    def packages(unit: UnitContext) -> Mapping[str, Any]:
        catalogs = _catalogs(unit)
        selection = unit.output("standards_selection.select_profiles")["selection"]
        controls = control_records(catalogs, asvs_level=int(selection["policy"]["asvs_level"]),
                                   masvs_profile=str(selection["policy"]["masvs_profile"]))
        loaded = unit.output("characterization.load_inputs")
        classifications = unit.output("characterization.classify_components")["classifications"]
        rows = unit.output("applicability.build_matrix")["rows"]
        output = {}
        for batch in unit.output("batching.partition_work")["work"]["batches"]:
            values = list(build_finding_packages(batch, rows, controls, classifications,
                loaded["evidence"], retrieval_manifest=loaded["retrieval_manifest"],
                assessment_mode=loaded["assessment_mode"],
                max_subjects=parse_settings(unit.job.config.settings).max_subjects_per_control))
            task = {"task_id": batch["batch_id"],
                    "question": "Assess only the supplied control-component proof obligations.",
                    "proof_obligations": [item["proof_obligations"] for item in values],
                    "prohibited_claims": values[0]["prohibited_claims"] if values else []}
            bundle = compose(unit.job.repository_root, role=batch["assignment"]["role"],
                             persona=batch["assignment"]["persona"], task=task)
            guidance = pin_bundle(unit.job.run_root, bundle)
            for value in values:
                value["guidance"] = guidance
            output[batch["batch_id"]] = values
        value = {"schema": "appsec-review/finding-package-set/1", "batches": output}
        return {"packages": output, "artifact": _artifact(unit, "finding-packages.json", value),
                "package_count": sum(len(items) for items in output.values())}

    def make_cell(cell_id: str):
        def cell(unit: UnitContext) -> Mapping[str, Any]:
            settings = unit.job.config.settings
            typed = parse_settings(settings)
            work = unit.output("batching.partition_work")["work"]
            packages_by_batch = unit.output("batching.build_packages")["packages"]
            index = CELLS.index(cell_id)
            assigned = [batch for position, batch in enumerate(work["batches"])
                        if position % len(CELLS) == index]
            admitted = {batch["batch_id"] for batch in work["batches"][:typed.max_batches]}
            resolver = _resolver(unit) if typed.mode is AssessmentMode.ASSESSMENT else None
            results = []
            log = PipelineLog(unit.job.run_root)
            for batch in assigned:
                log.write("OWASP_WORKER_STARTED", run_id=unit.job.run_id,
                    job_id="job_owasp_control_assessment", attempt_id=unit.job.attempt_id,
                    step_id="validation", task_id=cell_id, details={"batch_id": batch["batch_id"],
                    "model": dict(unit.job.config.settings["model"]), "cell": cell_id})
                result = assess_batch(batch, packages_by_batch[batch["batch_id"]],
                    fail=fail_cell == cell_id or batch["batch_id"] not in admitted,
                    assessment_mode=typed.mode.value,
                    worker=(lambda request: run_batch(repository_root=unit.job.repository_root,
                        run_root=unit.job.run_root, batch=request["batch"], packages=request["packages"],
                        settings=typed, worker_profile=settings["model"],
                        reviewer_profile=settings["models"][typed.reviewer_profile],
                        resolver=resolver, infer=transport(), independent=False,
                        attempt_id=unit.job.attempt_id, unit_id=unit.unit_id))
                    if resolver is not None else None)
                if batch["batch_id"] not in admitted:
                    for row in result["results"]:
                        row["gaps"] = ["batch not launched: max_batches cap; row remains accounted and unresolved"]
                results.append(result)
                evidence_used = sorted({citation["source_identity"] for item in result["results"]
                                        for citation in item.get("evidence_used", ())})
                log.write("OWASP_WORKER_COMPLETED", run_id=unit.job.run_id,
                    job_id="job_owasp_control_assessment", attempt_id=unit.job.attempt_id,
                    step_id="validation", task_id=cell_id, details={"batch_id": batch["batch_id"],
                    "terminal_status": result["terminal_state"],
                    "evidence_used": evidence_used[:100],
                    "proposed_observation_count": sum(len(item.get("observations", ()))
                                                      for item in result["results"]),
                    "gap_count": sum(len(item.get("gaps", ())) for item in result["results"]),
                    "dispositions": [item["status"] for item in result["results"]],
                    **result["metrics"]})
            failed = sum(result["terminal_state"] == "failed" for result in results)
            return {"cell": cell_id, "batch_results": results, "assigned_batch_count": len(assigned),
                    "failed_batch_count": failed, "terminal_status":
                    "COMPLETED_WITH_GAPS" if failed else "SUCCEEDED"}
        return cell

    def verify(unit: UnitContext) -> Mapping[str, Any]:
        settings = unit.job.config.settings
        typed = parse_settings(settings)
        batches = [batch for cell in CELLS for batch in unit.output(f"validation.{cell}")["batch_results"]]
        reviewed_batches = []

        def review(batch):
            if "worker" not in batch:
                reviewed_batches.append(batch)
                return batch
            bid = batch["batch_id"]
            original = next(item for item in unit.output("batching.partition_work")["work"]["batches"]
                            if item["batch_id"] == bid)
            value = run_batch(repository_root=unit.job.repository_root, run_root=unit.job.run_root,
                batch=original, packages=unit.output("batching.build_packages")["packages"][bid],
                settings=typed, worker_profile=settings["model"],
                reviewer_profile=settings["models"][typed.reviewer_profile], resolver=_resolver(unit),
                infer=transport(), worker_result=batch["worker"],
                validation_retrieval=batch["metrics"].get("retrieval"),
                attempt_id=unit.job.attempt_id, unit_id=unit.unit_id)
            reviewed_batches.append(value)
            return value

        verified = verify_results(batches, assessment_mode=typed.mode.value, reviewer=review)
        gap_count = sum(len(value.get("gaps", ())) for value in verified)
        states = [observation.get("state") for value in verified
                  for observation in value.get("observations", ())]
        PipelineLog(unit.job.run_root).write("OWASP_VERIFICATION_COMPLETED",
            run_id=unit.job.run_id, job_id="job_owasp_control_assessment",
            attempt_id=unit.job.attempt_id, step_id="verification",
            task_id="independent_review", details={"result_count": len(verified),
            "confirmed_observation_count": states.count("confirmed"),
            "refuted_observation_count": states.count("refuted"),
            "pending_independent_verification_count": states.count("awaiting_independent_verification"),
            "gap_count": gap_count})
        value = {"schema": "appsec-review/verified-control-results/1", "results": verified}
        return {"verified_results": verified, "artifact": _artifact(unit, "verified-results.json", value),
                "batch_results": reviewed_batches,
                "gap_count": gap_count, "terminal_status": "COMPLETED_WITH_GAPS" if gap_count else "SUCCEEDED"}

    def join(unit: UnitContext) -> Mapping[str, Any]:
        joined = deterministic_join(unit.output("applicability.build_matrix")["rows"],
                                    unit.output("verification.independent_review")["verified_results"])
        return {"joined": joined, "artifact": _artifact(unit, "control-results.json", joined),
                "result_count": len(joined["results"]), "terminal_status":
                "COMPLETED_WITH_GAPS" if any(item["gaps"] for item in joined["results"]) else "SUCCEEDED"}

    def publish_indexes(unit: UnitContext) -> Mapping[str, Any]:
        standards = unit.output("standards_selection.ingest_catalogs")["manifest"]
        selection = unit.output("standards_selection.select_profiles")["selection"]
        classifications = unit.output("characterization.classify_components")["classifications"]
        rows = unit.output("applicability.build_matrix")["rows"]
        work = unit.output("batching.partition_work")["work"]
        packages_by_batch = unit.output("batching.build_packages")["packages"]
        joined = unit.output("join.deterministic_join")["joined"]
        guidance_ids = sorted({item["guidance"]["bundle_sha256"]
            for values in packages_by_batch.values() for item in values})
        guidance_hash = hashlib.sha256("\n".join(guidance_ids).encode()).hexdigest()
        fingerprints = fingerprint_inputs(standards=standards, selection=selection,
            classifications=classifications, rows=rows, batches=work["batches"],
            retrieval_manifest=unit.output("characterization.load_inputs")["retrieval_manifest"],
            configuration_sha256=resolved_configuration_identity(unit.job.run_root),
            guidance_bundle_sha256=guidance_hash, model_identity=unit.job.config.settings["model"],
            parser_versions=unit.job.config.settings["parser_versions"])
        shards = [publish_shard(unit.job.run_root, family="standards", shard_id="selected",
            records=standards["sources"], fingerprint_inputs=fingerprints["global_inputs"], gaps=standards["gaps"])]
        for component in classifications:
            cid = component["component_id"]
            fp = fingerprints["components"][cid]
            shards.append(publish_shard(unit.job.run_root, family="component-classification", shard_id=cid,
                records=[component], fingerprint_inputs={"component": fp["classification"]}, gaps=component["gaps"]))
            component_rows = [row for row in rows if row["component_id"] == cid]
            shards.append(publish_shard(unit.job.run_root, family="applicability", shard_id=cid,
                records=component_rows, fingerprint_inputs={"applicability": fp["applicability"]},
                gaps=[gap for row in component_rows for gap in row["gaps"]]))
            component_results = [result for result in joined["results"] if result["component_id"] == cid]
            shards.append(publish_shard(unit.job.run_root, family="control-result", shard_id=cid,
                records=component_results, fingerprint_inputs={"join": fp["validation_work"],
                "global": fingerprints["global"]}, gaps=[gap for result in component_results for gap in result["gaps"]]))
        for batch in work["batches"]:
            bid = batch["batch_id"]
            shards.append(publish_shard(unit.job.run_root, family="validation-work", shard_id=bid,
                records=[batch], fingerprint_inputs={"batch": batch["fingerprint"]}))
            shards.append(publish_shard(unit.job.run_root, family="finding-package", shard_id=bid,
                records=packages_by_batch[bid], fingerprint_inputs={"batch": batch["fingerprint"],
                "guidance": guidance_hash}))
        accepted = unit.output("characterization.load_inputs")["retrieval_manifest"]
        manifest = publish_manifest(unit.job.run_root, run_id=unit.job.run_id, shards=shards,
            accepted_upstream_manifest=accepted,
            configuration_sha256=resolved_configuration_identity(unit.job.run_root),
            assessment_bounds={"max_source_lines": parse_settings(unit.job.config.settings).max_source_lines},
            assessment_mode=parse_settings(unit.job.config.settings).mode.value)
        return {"manifest": manifest, "fingerprints": fingerprints, "shard_count": len(shards)}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        joined = unit.output("join.deterministic_join")["joined"]
        validation = {cell: unit.output(f"validation.{cell}")["failed_batch_count"] for cell in CELLS}
        value = {"schema": SCHEMA, "selection": unit.output("standards_selection.select_profiles")["selection"],
                 "assessment_mode": parse_settings(unit.job.config.settings).mode.value,
                 "control_results": unit.output("join.deterministic_join")["artifact"],
                 "index_manifest": unit.output("publication.publish_indexes")["manifest"],
                 "accounting": joined["accounting"], "failed_batches_by_cell": validation,
                 "gaps": sorted({gap for result in joined["results"] for gap in result["gaps"]})}
        results = joined["results"]
        value["coverage"] = {
            "catalog_controls": sum(len(catalog.records) for family, catalog in _catalogs(unit).items()
                                    if family in {"ASVS", "MASVS"}),
            "selected_controls": value["selection"]["control_count"], "selected_rows": len(results),
            "applicable_rows": sum(row["applicability"] in {"applicable", "conditional"} for row in results),
            "dispatched_rows": sum(row["worker_attempt_count"] > 0 for row in results),
            "reused_rows": sum(row["execution_completion"] == "reused" for row in results),
            "assessed_rows": sum(row["assessment_mode"] == "assessment" and row["control_status"] in {
                "satisfied", "not_satisfied"} for row in results),
            "independent_review_attempted_rows": sum(row["reviewer_attempt_count"] > 0 for row in results),
            "independently_reviewed_rows": sum(row["verification_status"] in {
                "independently_assessed", "dissent"} for row in results),
            "unresolved_rows": sum(row["coverage_completeness"] == "unresolved"
                                    or row["control_status"] == "cannot_verify" for row in results),
            "lead_producing_rows": sum(row["lead_eligible"] for row in results),
        }
        value["limitations"] = [
            *unit.output("standards_selection.ingest_catalogs")["manifest"]["gaps"],
            *unit.output("characterization.load_inputs").get("limitations", []),
            "Source procedures establish only their named subjects, not complete control or component safety.",
            "Runtime/manual evidence ingestion and live-model efficacy are separate, unpassed gates.",
        ]
        value["telemetry"] = [batch["metrics"] for batch in unit.output(
            "verification.independent_review").get("batch_results", [])]
        value["input_retrieval"] = unit.output("characterization.load_inputs").get("retrieval_metrics", {})
        value["gaps"] = sorted(set([*value["gaps"], *value["limitations"]]))
        artifact = _artifact(unit, "owasp-workbench-result.json", value)
        unit.job.events.write("OWASP_ASSESSMENT_RECORDED", unit_id=unit.unit_id,
                              metrics_receipt=artifact)
        return {"artifact": artifact,
                "index_manifest": value["index_manifest"], "accounting": value["accounting"],
                "gap_count": len(value["gaps"]), "terminal_status":
                "COMPLETED_WITH_GAPS" if value["gaps"] or any(validation.values()) else "SUCCEEDED"}

    u = Unit
    units = (
        u("standards_selection.ingest_catalogs", ingest),
        u("standards_selection.select_profiles", select, ("standards_selection.ingest_catalogs",)),
        u("characterization.load_inputs", load_inputs),
        u("characterization.classify_components", classify, ("characterization.load_inputs",)),
        u("applicability.build_matrix", applicability,
          ("standards_selection.select_profiles", "characterization.classify_components")),
        u("batching.partition_work", partition, ("applicability.build_matrix",)),
        u("batching.build_packages", packages,
          ("batching.partition_work", "standards_selection.select_profiles",
           "characterization.load_inputs", "characterization.classify_components", "applicability.build_matrix")),
        *(u(f"validation.{cell}", make_cell(cell), ("batching.partition_work", "batching.build_packages"))
          for cell in CELLS),
        u("verification.independent_review", verify, tuple(f"validation.{cell}" for cell in CELLS)),
        u("join.deterministic_join", join,
          ("applicability.build_matrix", "verification.independent_review")),
        u("publication.publish_indexes", publish_indexes,
          ("standards_selection.ingest_catalogs", "standards_selection.select_profiles",
           "characterization.load_inputs", "characterization.classify_components",
           "applicability.build_matrix", "batching.partition_work", "batching.build_packages",
           "join.deterministic_join")),
        u("publication.publish_handoff", publish,
          ("standards_selection.select_profiles", "join.deterministic_join", "publication.publish_indexes",
           *tuple(f"validation.{cell}" for cell in CELLS))),
    )
    identity = None
    return Job("job_owasp_control_assessment", "owasp_control_assessment", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=identity, validation_identity=identity, units=units,
               datasets=DATASETS, consumes=CONSUMES)
