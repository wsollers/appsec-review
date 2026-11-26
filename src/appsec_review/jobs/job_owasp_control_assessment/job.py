from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review.config.owasp import AssessmentMode, parse_settings
from appsec_review.applicability import resolved_configuration_identity
from appsec_review.inference import Infer
from appsec_review.interchange import CoverageDisposition, GapCode, ProducerStatus, producer_gap
from appsec_review.observability import PipelineLog
from appsec_review.retrieval.core import RetrievalCore, resolve_context_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.owasp_workbench import (
    assess_batch, build_applicability, build_finding_packages, classify_components,
    control_records, deterministic_join, fingerprint_inputs, load_catalogs,
    partition_work, publish_manifest, publish_shard, select_profiles,
    standards_manifest, target_class_ledger, verify_results,
)
from appsec_review.jobs.job_owasp_control_assessment.datasets import CONTRACT, DATASETS, SOURCE_SELECTION
from appsec_review.runtime.inputs import feed_input_identity
from appsec_review.owasp_workbench.assessment import prepare_guidance, run_batch
from appsec_review.owasp_workbench.engine import UNRESOLVED_OUTCOMES
from appsec_review.owasp_workbench.evidence import EvidenceResolver, accepted_inputs
from appsec_review.owasp_workbench.versions import implemented_parser_versions
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


def coverage_disposition(results, *, gaps: bool = False, failed: bool = False) -> str:
    """D5: the typed coverage disposition published beside ``terminal_status``.

    ``partial`` when any row is unresolved (``cannot_determine``, ``unsupported_missing_evidence``,
    unresolved coverage or ``cannot_verify``), when gaps are declared or a cell failed; ``complete``
    otherwise. Declared gaps always make it partial, so it never contradicts the producer status.
    """
    unresolved = any(row["applicability"] in UNRESOLVED_OUTCOMES
                     or row["coverage_completeness"] in {"unresolved", "partial"}
                     or row["control_status"] == "cannot_verify" for row in results)
    return (CoverageDisposition.PARTIAL if unresolved or gaps or failed else CoverageDisposition.COMPLETE).value


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
    declared = settings.get("parser_versions")
    expected = implemented_parser_versions()
    if not isinstance(declared, Mapping) or dict(declared) != expected:
        raise ValueError(f"OWASP parser_versions must declare the implemented rule versions {expected}; "
                         f"declared {dict(declared) if isinstance(declared, Mapping) else declared}")
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
    if (getattr(unit.job, "input_manifest_path", None) is None
            or getattr(unit.job, "input_manifest_sha256", None) is None):
        raise ValueError("OWASP source view requires the attempt's explicit admitted manifest pin")
    from appsec_review.storage.shared import safe_path
    safe_path(unit.job.run_root, Path(unit.job.input_manifest_path).relative_to(unit.job.run_root).as_posix())
    path, sha256 = resolve_context_manifest(unit.job)
    return RetrievalCore(unit.job.run_root.parent, unit.job.run_id, manifest_path=path,
                         manifest_sha256=sha256, selection=SOURCE_SELECTION), path


def _resolver(unit: UnitContext) -> EvidenceResolver:
    core, path = _core(unit)
    typed = parse_settings(unit.job.config.settings)
    return EvidenceResolver(core, accept_manifest(unit.job.run_root, manifest_path=path,
                                                  manifest_sha256=core.manifest_sha256,
                                                  dispositions=typed.source_dispositions,
                                                  selection=core.selection),
                            max_source_lines=typed.max_source_lines)


def _characterization_gaps(unit: UnitContext) -> list[str]:
    return sorted({
        *(gap["reason"] for gap in unit.output("characterization.load_inputs").get("gaps", ())),
        *(gap for component in unit.output("characterization.classify_components")["classifications"]
          for gap in component.get("gaps", ())),
    })


def _control_gaps(unit: UnitContext, reasons) -> list[dict[str, Any]]:
    return [producer_gap(GapCode.PRODUCER_REPORTED_GAP, reason, unit_id=unit.unit_id)
            for reason in sorted(set(reasons))]


def _status(gapped: bool) -> ProducerStatus:
    return ProducerStatus.COMPLETED_WITH_GAPS if gapped else ProducerStatus.SUCCEEDED


def build_job(*, fail_cell: str | None = None, infer: Infer | None = None) -> Job:
    def transport():
        from appsec_review.inference import infer as default_infer
        return infer or default_infer

    def ingest(unit: UnitContext) -> Mapping[str, Any]:
        manifest = standards_manifest(_catalogs(unit))
        return {"manifest": manifest, "artifact": _artifact(unit, "standards-manifest.json", manifest),
                "gaps": _control_gaps(unit, manifest["gaps"]),
                "terminal_status": _status(bool(manifest["gaps"]))}

    def select(unit: UnitContext) -> Mapping[str, Any]:
        settings = unit.job.config.settings
        selection = select_profiles(_catalogs(unit), asvs_level=int(settings["asvs_level"]),
                                    masvs_profile=str(settings["masvs_profile"]))
        return {"selection": selection, "artifact": _artifact(unit, "selection.json", selection)}

    def load_inputs(unit: UnitContext) -> Mapping[str, Any]:
        value = _fixture_or_accepted_inputs(unit)
        gaps = list(value.get("gaps", ()))
        return {**value, "component_count": len(value["components"]),
                "evidence_count": len(value["evidence"]), "gaps": _control_gaps(unit, gaps),
                "terminal_status": _status(bool(gaps))}

    def classify(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("characterization.load_inputs")
        # T-5008: classes and roles come from the accepted collation tags; the workbench has no classifier.
        values = classify_components(loaded["components"],
            max_components=int(unit.job.config.settings["max_components"]),
            assessment_mode=loaded["assessment_mode"])
        artifact = _artifact(unit, "component-classifications.json", {
            "schema": "appsec-review/component-classification-set/2", "components": values})
        return {"classifications": values, "artifact": artifact,
                "target_classes": {value["component_id"]: value["target_classes"] for value in values},
                "gaps": _control_gaps(unit, (gap for value in values for gap in value["gaps"])),
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
        ledger = target_class_ledger(unit.output("characterization.classify_components")["classifications"], rows)
        return {"rows": rows, "artifact": artifact, "outcome_counts": counts,
                "ledger": ledger, "ledger_artifact": _artifact(unit, "target-class-ledger.json", ledger),
                "dispatchable_rows": sum(row["outcome"] in {"applicable", "conditional"} for row in rows)}

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
        nondispatch = []
        # T-5013: half the worker's input budget (4 bytes per token) is shared by the batch's packages' evidence;
        # the obligations' own records come first and the rest stays reachable through expansion.
        input_bytes = int(unit.job.config.settings["model"]["max_input_tokens"]) * 4
        for batch in unit.output("batching.partition_work")["work"]["batches"]:
            values = list(build_finding_packages(batch, rows, controls, classifications,
                loaded["evidence"], retrieval_manifest=loaded["retrieval_manifest"],
                assessment_mode=loaded["assessment_mode"],
                max_subjects=parse_settings(unit.job.config.settings).max_subjects_per_control,
                max_evidence=parse_settings(unit.job.config.settings).max_evidence_per_component,
                max_evidence_bytes=max(1, input_bytes // 2 // max(1, len(batch["row_ids"])))))
            guidance = prepare_guidance(unit.job.repository_root, unit.job.run_root, batch)
            for value in values:
                value["guidance"] = guidance["control_assessor"]
                value["guidance_by_role"] = guidance
                if loaded["assessment_mode"] == "assessment" and not any(
                        obligation.get("supported") for obligation in value["proof_obligations"]):
                    nondispatch.append({"row_id": value["row_id"], "batch_id": batch["batch_id"],
                        "reason": "; ".join(sorted({obligation.get("reason", "no supported subject")
                            for obligation in value["proof_obligations"]})) or "no supported subject"})
            output[batch["batch_id"]] = values
        value = {"schema": "appsec-review/finding-package-set/1", "batches": output}
        return {"packages": output, "artifact": _artifact(unit, "finding-packages.json", value),
                "non_dispatch_dispositions": sorted(nondispatch, key=lambda item: item["row_id"]),
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
            ready_batches = [batch for batch in work["batches"]
                if typed.mode is AssessmentMode.QUALIFICATION or any(
                    obligation.get("supported") for package in packages_by_batch[batch["batch_id"]]
                    for obligation in package["proof_obligations"])]
            admitted = {batch["batch_id"] for batch in ready_batches[:typed.max_batches]}
            resolver = None
            results = []
            log = PipelineLog(unit.job.run_root)
            for batch in assigned:
                ready = batch in ready_batches
                launched = ready and batch["batch_id"] in admitted and fail_cell != cell_id
                if launched and typed.mode is AssessmentMode.ASSESSMENT and resolver is None:
                    resolver = _resolver(unit)
                log.write("OWASP_WORKER_STARTED" if launched else "OWASP_WORKER_NOT_DISPATCHED", run_id=unit.job.run_id,
                    job_id="job_owasp_control_assessment", attempt_id=unit.job.attempt_id,
                    step_id="validation", task_id=cell_id, details={"batch_id": batch["batch_id"],
                    "model": dict(unit.job.config.settings["model"]), "cell": cell_id})
                result = assess_batch(batch, packages_by_batch[batch["batch_id"]],
                    fail=fail_cell == cell_id or ready and batch["batch_id"] not in admitted,
                    assessment_mode=typed.mode.value,
                    worker=(lambda request: run_batch(repository_root=unit.job.repository_root,
                        run_root=unit.job.run_root, batch=request["batch"], packages=request["packages"],
                        settings=typed, worker_profile=settings["model"],
                        reviewer_profile=settings["models"][typed.reviewer_profile],
                        resolver=resolver, infer=transport(), independent=False,
                        attempt_id=unit.job.attempt_id, unit_id=unit.unit_id))
                    if typed.mode is AssessmentMode.ASSESSMENT else None)
                if ready and batch["batch_id"] not in admitted:
                    result["terminal_state"] = "not_dispatched"
                    for row in result["results"]:
                        row["gaps"] = ["batch not launched: max_batches cap; row remains accounted and unresolved"]
                        row["execution_completion"] = "not_dispatched"
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
            gapped = failed or any(row.get("gaps") for result in results for row in result["results"])
            return {"cell": cell_id, "batch_results": results, "assigned_batch_count": len(assigned),
                    "gaps": _control_gaps(unit, (gap for result in results for row in result["results"]
                                                for gap in row.get("gaps", ()))),
                    "failed_batch_count": failed, "terminal_status":
                    _status(bool(gapped))}
        return cell

    def verify(unit: UnitContext) -> Mapping[str, Any]:
        settings = unit.job.config.settings
        typed = parse_settings(settings)
        batches = [batch for cell in CELLS for batch in unit.output(f"validation.{cell}")["batch_results"]]
        reviewed_batches = []
        resolver = None

        def review(batch):
            nonlocal resolver
            if "worker" not in batch or batch["worker"]["status"] == "not_dispatched":
                reviewed_batches.append(batch)
                return batch
            if resolver is None:
                resolver = _resolver(unit)
            bid = batch["batch_id"]
            original = next(item for item in unit.output("batching.partition_work")["work"]["batches"]
                            if item["batch_id"] == bid)
            value = run_batch(repository_root=unit.job.repository_root, run_root=unit.job.run_root,
                batch=original, packages=unit.output("batching.build_packages")["packages"][bid],
                settings=typed, worker_profile=settings["model"],
                reviewer_profile=settings["models"][typed.reviewer_profile], resolver=resolver,
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
                "gaps": _control_gaps(unit, (gap for result in verified for gap in result.get("gaps", ()))),
                "gap_count": gap_count, "terminal_status": _status(bool(gap_count))}

    def join(unit: UnitContext) -> Mapping[str, Any]:
        joined = deterministic_join(unit.output("applicability.build_matrix")["rows"],
                                    unit.output("verification.independent_review")["verified_results"])
        gaps = _characterization_gaps(unit)
        gapped = bool(gaps) or any(item["gaps"] for item in joined["results"])
        disposition = coverage_disposition(joined["results"], gaps=gapped)
        return {"joined": joined, "artifact": _artifact(unit, "control-results.json", joined),
                "result_count": len(joined["results"]),
                "gaps": _control_gaps(unit, [*gaps, *(gap for row in joined["results"] for gap in row["gaps"])]),
                "coverage_disposition": disposition,
                "terminal_status": _status(disposition == "partial")}

    def publish_indexes(unit: UnitContext) -> Mapping[str, Any]:
        standards = unit.output("standards_selection.ingest_catalogs")["manifest"]
        selection = unit.output("standards_selection.select_profiles")["selection"]
        classifications = unit.output("characterization.classify_components")["classifications"]
        rows = unit.output("applicability.build_matrix")["rows"]
        work = unit.output("batching.partition_work")["work"]
        packages_by_batch = unit.output("batching.build_packages")["packages"]
        joined = unit.output("join.deterministic_join")["joined"]
        invocation_guidance = {}
        for batch in unit.output("verification.independent_review")["batch_results"]:
            roles = {}
            for key, role in (("worker", "control_assessor"), ("independent_review", "independent_reviewer")):
                result = batch.get(key, {})
                if result.get("status") == "reused" or any(
                        part["status"] == "reused" for part in result.get("parts", ())) or any(
                        attempt.get("dispatched") for attempt in result.get("attempts", ())):
                    roles[role] = result["guidance"]
            if roles:
                invocation_guidance[batch["batch_id"]] = roles
        guidance_ids = sorted({pin["bundle_sha256"]
            for roles in invocation_guidance.values() for pin in roles.values()})
        guidance_hash = hashlib.sha256("\n".join(guidance_ids).encode()).hexdigest()
        fingerprints = fingerprint_inputs(standards=standards, selection=selection,
            classifications=classifications, rows=rows, batches=work["batches"],
            retrieval_manifest=unit.output("characterization.load_inputs")["retrieval_manifest"],
            configuration_sha256=resolved_configuration_identity(unit.job.run_root),
            guidance_bundle_sha256=guidance_hash, model_identity=unit.job.config.settings["model"],
            parser_versions=unit.job.config.settings["parser_versions"])
        attempt_id = getattr(unit.job, "attempt_id", None)
        shards = [publish_shard(unit.job.run_root, family="standards", shard_id="selected",
            records=standards["sources"], fingerprint_inputs=fingerprints["global_inputs"], gaps=standards["gaps"],
            attempt_id=attempt_id)]
        for component in classifications:
            cid = component["component_id"]
            fp = fingerprints["components"][cid]
            shards.append(publish_shard(unit.job.run_root, family="component-classification", shard_id=cid,
                records=[component], fingerprint_inputs={"component": fp["classification"]}, gaps=component["gaps"],
                attempt_id=attempt_id))
            component_rows = [row for row in rows if row["component_id"] == cid]
            shards.append(publish_shard(unit.job.run_root, family="applicability", shard_id=cid,
                records=component_rows, fingerprint_inputs={"applicability": fp["applicability"]},
                gaps=[gap for row in component_rows for gap in row["gaps"]], attempt_id=attempt_id))
            component_results = [result for result in joined["results"] if result["component_id"] == cid]
            shards.append(publish_shard(unit.job.run_root, family="control-result", shard_id=cid,
                records=component_results, fingerprint_inputs={"join": fp["validation_work"],
                "global": fingerprints["global"]}, gaps=[gap for result in component_results for gap in result["gaps"]],
                attempt_id=attempt_id))
        for batch in work["batches"]:
            bid = batch["batch_id"]
            shards.append(publish_shard(unit.job.run_root, family="validation-work", shard_id=bid,
                records=[batch], fingerprint_inputs={"batch": batch["fingerprint"]}, attempt_id=attempt_id))
            shards.append(publish_shard(unit.job.run_root, family="finding-package", shard_id=bid,
                records=packages_by_batch[bid], fingerprint_inputs={"batch": batch["fingerprint"],
                "guidance": invocation_guidance.get(bid, {})}, attempt_id=attempt_id))
        accepted = unit.output("characterization.load_inputs")["retrieval_manifest"]
        manifest = publish_manifest(unit.job.run_root, run_id=unit.job.run_id, shards=shards,
            accepted_upstream_manifest=accepted,
            configuration_sha256=resolved_configuration_identity(unit.job.run_root),
            assessment_bounds={"max_source_lines": parse_settings(unit.job.config.settings).max_source_lines},
            assessment_mode=parse_settings(unit.job.config.settings).mode.value, attempt_id=attempt_id)
        return {"manifest": manifest, "fingerprints": fingerprints, "shard_count": len(shards),
                "invocation_guidance": invocation_guidance}

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
            "unresolved_rows": sum(row["coverage_completeness"] in {"unresolved", "partial"}
                                    or row["applicability"] in UNRESOLVED_OUTCOMES
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
        value["non_dispatch_dispositions"] = unit.output("batching.build_packages")["non_dispatch_dispositions"]
        value["input_retrieval"] = unit.output("characterization.load_inputs").get("retrieval_metrics", {})
        # Limitations describe the method; gaps are missing coverage. A target whose class admits no
        # family ends with a not-applicable ledger and no gap (T-5008).
        value["target_class_ledger"] = unit.output("applicability.build_matrix")["ledger"]
        value["gaps"] = sorted(set([*value["gaps"],
                                    *_characterization_gaps(unit),
                                    *unit.output("standards_selection.ingest_catalogs")["manifest"]["gaps"]]))
        # D5: the typed coverage disposition is part of the recorded result and of its receipt.
        disposition = coverage_disposition(results, gaps=bool(value["gaps"]), failed=any(validation.values()))
        value["coverage_disposition"] = disposition
        from jsonschema import Draft202012Validator
        from appsec_review.application_paths import application_asset
        from appsec_review.owasp_workbench.engine import extract_verified_control_gaps, verified_control_gap_candidate
        gap_summary = extract_verified_control_gaps(
            unit.job.run_id,
            parse_settings(unit.job.config.settings).mode.value,
            results,
            resolver=_resolver(unit) if value["assessment_mode"] == "assessment"
            and any(verified_control_gap_candidate(row) for row in results) else None,
        )
        gap_schema = json.loads(
            application_asset("docs/schemas/owasp-workbench/owasp-control-gap.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator(gap_schema).validate(gap_summary)
        value["gaps"] = sorted(set([*value["gaps"], *(
            f"{gap['row_id']}: {gap['code']}: {gap['summary']}" for gap in gap_summary["coverage_gaps"])]))
        disposition = coverage_disposition(results, gaps=bool(value["gaps"]), failed=any(validation.values()))
        value["coverage_disposition"] = disposition
        gap_path = unit.job.attempt_root / "artifacts" / "owasp-control-gaps" / "owasp-control-gaps.json"
        atomic_json(gap_path, gap_summary)
        gap_artifact = {
            "path": gap_path.relative_to(unit.job.run_root).as_posix(),
            "sha256": file_sha256(gap_path),
            "size_bytes": gap_path.stat().st_size,
        }
        value["control_gap_summary"] = {
            "controls_assessed": gap_summary["controls_assessed"],
            "verified_gaps_indexed": gap_summary["verified_gaps_indexed"],
            "gaps_by_verdict": gap_summary["gaps_by_verdict"],
            "artifact": gap_artifact,
        }
        artifact = _artifact(unit, "owasp-workbench-result.json", value)
        unit.job.events.write("OWASP_ASSESSMENT_RECORDED", unit_id=unit.unit_id,
                              metrics_receipt=artifact)
        unit.job.events.write(
            "OWASP_CONTROL_GAPS_INDEXED",
            unit_id=unit.unit_id,
            controls_assessed=gap_summary["controls_assessed"],
            verified_gaps_indexed=gap_summary["verified_gaps_indexed"],
            telemetry=gap_summary["telemetry"],
        )
        return {"artifact": artifact, "gap_summary_artifact": gap_artifact,
                "telemetry": gap_summary["telemetry"],
                "index_manifest": value["index_manifest"], "accounting": value["accounting"],
                "gaps": _control_gaps(unit, value["gaps"]),
                "gap_count": len(value["gaps"]), "coverage_disposition": disposition, "terminal_status":
                _status(disposition == "partial")}

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
           "join.deterministic_join", "verification.independent_review")),
        u("publication.publish_handoff", publish,
          ("standards_selection.select_profiles", "standards_selection.ingest_catalogs",
           "applicability.build_matrix", "join.deterministic_join", "publication.publish_indexes",
           "batching.build_packages", "verification.independent_review",
           *tuple(f"validation.{cell}" for cell in CELLS))),
    )
    identity = None
    return Job("job_owasp_control_assessment", "owasp_control_assessment", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=identity, validation_identity=identity, units=units,
               datasets=DATASETS, contract=CONTRACT, external_input_identity=feed_input_identity,
               strict_gaps=True)
