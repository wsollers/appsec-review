from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review.jobs.job_target_analysis_plan import load_accepted_plan
from appsec_review.observability import PipelineLog
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.owasp_workbench import (
    assess_batch, build_applicability, build_finding_packages, characterize_components,
    compose, control_records, deterministic_join, fingerprint_inputs, load_catalogs,
    partition_work, pin_bundle, publish_manifest, publish_shard, select_profiles,
    standards_manifest, verify_results,
)


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
    required = {"asvs_level", "masvs_profile", "max_batch_size", "max_components_per_batch",
                "max_components", "dynamic_authorized", "model", "standards", "parser_versions"}
    if not required <= set(settings):
        raise ValueError("OWASP workbench central settings are incomplete")
    if settings["asvs_level"] not in {1, 2, 3} or settings["masvs_profile"] not in {"L1", "L2"}:
        raise ValueError("OWASP profile selection is invalid")
    for key, maximum in (("max_batch_size", 64), ("max_components_per_batch", 16),
                         ("max_components", 128)):
        if type(settings[key]) is not int or not 1 <= settings[key] <= maximum:
            raise ValueError(f"OWASP configured bound is invalid: {key}")
    model = settings["model"]
    model_required = {"provider", "model", "reasoning", "max_input_tokens", "max_output_tokens",
                      "timeout_seconds", "retries"}
    if not isinstance(model, Mapping) or not model_required <= set(model):
        raise ValueError("OWASP worker model configuration is incomplete")
    if type(settings["dynamic_authorized"]) is not bool:
        raise ValueError("OWASP dynamic authorization setting must be a boolean")
    load_catalogs(context.repository_root, _sources(settings))


def _fixture_or_accepted_inputs(unit: UnitContext) -> dict[str, Any]:
    fixture = unit.job.run_root / "data" / "inputs" / "owasp-workbench.json"
    if fixture.is_file():
        document = json.loads(fixture.read_text(encoding="utf-8"))
        if document.get("schema") != "appsec-review/owasp-workbench-input/1":
            raise ValueError("OWASP fixture input schema is unsupported")
        return {"components": document.get("components", []), "evidence": document.get("evidence", []),
                "retrieval_manifest": document.get("retrieval_manifest", {"fixture": file_sha256(fixture)}),
                "input_mode": "run_owned_fixture"}
    plan = load_accepted_plan(unit.job.run_root)
    components = []
    for raw in plan.get("components", ()):
        paths = [str(item.get("path", "")) for item in raw.get("scope", ())]
        lower = [path.lower() for path in paths]
        tags = []
        languages = []
        if any("androidmanifest.xml" in path for path in lower):
            tags.append("android")
            languages.append("kotlin")
        if any(path.endswith("info.plist") for path in lower):
            tags.append("ios")
            languages.append("swift")
        if any(path.endswith(("package.json", ".tsx", ".jsx")) for path in lower):
            tags.append("frontend")
            languages.append("typescript")
        if not tags and paths:
            tags.append("application")
        root_hash = hashlib.sha256("\n".join(paths).encode()).hexdigest()
        components.append({"target_id": "accepted-target", "project_id": "accepted-project",
            "component_id": str(raw["component_id"]), "paths": paths, "languages": languages,
            "frameworks": [], "tags": tags, "evidence": [{"source_identity":
            f"accepted-plan:{raw['component_id']}", "artifact_sha256": root_hash,
            "lines": [1, 1]}]})
    manifest_path, manifest_sha = resolve_accepted_manifest(unit.job.run_root)
    return {"components": components, "evidence": [],
            "retrieval_manifest": {"path": manifest_path.relative_to(unit.job.run_root).as_posix(),
                                   "sha256": manifest_sha}, "input_mode": "accepted_indexes"}


def build_job(*, fail_cell: str | None = None) -> Job:
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
                                         max_components=int(unit.job.config.settings["max_components"]))
        artifact = _artifact(unit, "component-classifications.json", {
            "schema": "appsec-review/component-classification-set/1", "components": values})
        return {"classifications": values, "artifact": artifact,
                "gap_count": sum(len(value["gaps"]) for value in values)}

    def applicability(unit: UnitContext) -> Mapping[str, Any]:
        rows = build_applicability(_catalogs(unit),
            unit.output("characterization.classify_components")["classifications"],
            unit.output("standards_selection.select_profiles")["selection"],
            dynamic_authorized=bool(unit.job.config.settings["dynamic_authorized"]))
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
                loaded["evidence"], retrieval_manifest=loaded["retrieval_manifest"]))
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
            work = unit.output("batching.partition_work")["work"]
            packages_by_batch = unit.output("batching.build_packages")["packages"]
            index = CELLS.index(cell_id)
            assigned = [batch for position, batch in enumerate(work["batches"])
                        if position % len(CELLS) == index]
            results = []
            log = PipelineLog(unit.job.run_root)
            for batch in assigned:
                log.write("OWASP_WORKER_STARTED", run_id=unit.job.run_id,
                    job_id="job_owasp_control_assessment", attempt_id=unit.job.attempt_id,
                    step_id="validation", task_id=cell_id, details={"batch_id": batch["batch_id"],
                    "model": dict(unit.job.config.settings["model"]), "cell": cell_id})
                result = assess_batch(batch, packages_by_batch[batch["batch_id"]],
                                      fail=fail_cell == cell_id)
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
        batches = [batch for cell in CELLS for batch in unit.output(f"validation.{cell}")["batch_results"]]
        verified = verify_results(batches)
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
            configuration_sha256=unit.job.config.settings.get("configuration_sha256", unit.job.source_fingerprint),
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
            accepted_upstream_manifest=accepted, configuration_sha256=str(
            unit.job.config.settings.get("configuration_sha256", unit.job.source_fingerprint)))
        return {"manifest": manifest, "fingerprints": fingerprints, "shard_count": len(shards)}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        joined = unit.output("join.deterministic_join")["joined"]
        validation = {cell: unit.output(f"validation.{cell}")["failed_batch_count"] for cell in CELLS}
        value = {"schema": SCHEMA, "selection": unit.output("standards_selection.select_profiles")["selection"],
                 "control_results": unit.output("join.deterministic_join")["artifact"],
                 "index_manifest": unit.output("publication.publish_indexes")["manifest"],
                 "accounting": joined["accounting"], "failed_batches_by_cell": validation,
                 "gaps": sorted({gap for result in joined["results"] for gap in result["gaps"]})}
        return {"artifact": _artifact(unit, "owasp-workbench-result.json", value),
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
    identity = hashlib.sha256(Path(__file__).read_bytes() + str(fail_cell).encode()).hexdigest()
    return Job("job_owasp_control_assessment", "owasp_control_assessment", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=identity, validation_identity=identity, units=units)
