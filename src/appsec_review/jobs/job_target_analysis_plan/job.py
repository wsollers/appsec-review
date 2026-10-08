from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import time
from typing import Any

from appsec_review.jobs.cataloging import write_json
from appsec_review.observability import PipelineLog, emit_model_event
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256

from .planning import (
    BUILD_SYSTEMS, PLAN_SCHEMA, PROPOSAL_SCHEMA, SCANNERS, ModelClient, ModelRequest,
    ambiguity_reasons, deterministic_plan, merge_proposal, summarize_catalog,
    validate_plan, validate_proposal,
)


TOPOLOGY = {
    "catalog_summary": ("load_accepted_catalog", "summarize_components"),
    "analysis_decisions": ("apply_deterministic_rules", "resolve_ambiguity"),
    "plan_acceptance": ("validate_plan", "index_plan", "publish_handoff"),
}


def _artifact(unit: UnitContext, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    path = unit.job.attempt_root / "artifacts" / "analysis-plan" / name
    identity = write_json(path, value)
    identity["path"] = path.relative_to(unit.job.run_root).as_posix()
    return identity


def _read_artifact(run_root: Path, identity: Mapping[str, Any]) -> Mapping[str, Any]:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file():
        raise ValueError("accepted upstream artifact is unavailable or outside the run")
    if file_sha256(path) != identity.get("sha256"):
        raise ValueError("accepted upstream artifact identity changed")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("accepted upstream artifact must be a JSON object")
    return value


def _accepted_catalog(run_root: Path) -> dict[str, Any]:
    pointer_path = run_root / "data" / "jobs" / "job_target_catalog" / "latest.json"
    if not pointer_path.is_file():
        raise ValueError("accepted job_target_catalog handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = _read_artifact(run_root, {"path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]})
    if handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED":
        raise ValueError("target catalog handoff is not accepted")
    published = handoff.get("outputs", {}).get("publish_catalog.publish_handoff", {})
    catalog = _read_artifact(run_root, published.get("artifact", {}))
    if catalog.get("schema") != "appsec-review/target-catalog/1":
        raise ValueError("target catalog schema is unsupported")
    artifacts = catalog.get("artifacts", {})
    partition = _read_artifact(run_root, artifacts["repository_discovery.partition_repository"])
    projects = _read_artifact(run_root, artifacts["repository_discovery.discover_projects"])
    components = _read_artifact(run_root, artifacts["component_discovery.catalog_components"])
    builds = _read_artifact(run_root, artifacts["build_discovery.discover_build_systems"])
    compile_databases = _read_artifact(run_root, artifacts["build_discovery.discover_compile_commands"])
    targets = _read_artifact(run_root, artifacts["build_discovery.catalog_build_targets"])
    recognized_names = {
        "CMakeLists.txt", "Makefile", "configure.ac", "configure.in", "Makefile.am", "meson.build",
        "BUILD", "WORKSPACE", "MODULE.bazel", "pom.xml", "build.gradle", "build.gradle.kts",
        "package.json", "tsconfig.json", "Cargo.toml", "go.mod", "pyproject.toml", "Dockerfile",
    }
    files = tuple(partition.get("files", ()))
    extra_builds = [item for item in files if Path(str(item["path"])).name in recognized_names or
                    Path(str(item["path"])).suffix.lower() in {".csproj", ".sln", ".vcxproj"}]
    by_path = {str(item["path"]): item for item in (*builds.get("systems", ()), *extra_builds)}
    gaps = [*partition.get("gaps", ()), *projects.get("gaps", ()), *components.get("gaps", ()),
            *builds.get("gaps", ()), *compile_databases.get("gaps", ()), *targets.get("gaps", ())]
    return {
        "source_fingerprint": catalog["source_fingerprint"],
        "catalog_handoff_sha256": pointer["handoff_sha256"],
        "files": files, "projects": tuple(projects.get("projects", ())),
        "components": tuple(components.get("components", ())),
        "build_files": tuple(by_path[key] for key in sorted(by_path)),
        "compile_databases": tuple(compile_databases.get("files", ())),
        "accepted_artifacts": tuple(item for item in targets.get("targets", ()) if item.get("artifact_kind") == "built"),
        "gaps": tuple(gaps),
    }


def load_accepted_plan(run_root: Path) -> Mapping[str, Any]:
    pointer_path = Path(run_root) / "data" / "jobs" / "job_target_analysis_plan" / "latest.json"
    if not pointer_path.is_file():
        raise ValueError("accepted job_target_analysis_plan handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = _read_artifact(Path(run_root), {"path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]})
    if handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED":
        raise ValueError("analysis plan handoff is not accepted")
    identity = handoff.get("outputs", {}).get("plan_acceptance.publish_handoff", {}).get("artifact")
    plan = _read_artifact(Path(run_root), identity or {})
    if plan.get("schema") != PLAN_SCHEMA:
        raise ValueError("accepted analysis plan schema is unsupported")
    return plan


def _validate_config(context, result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("target analysis plan topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"target analysis plan task order mismatch: {step}")
    settings = context.config.settings
    for key in ("summary_max_items", "summary_max_bytes", "summary_sample_per_prefix"):
        if type(settings.get(key)) is not int or int(settings[key]) < 1:
            raise ValueError(f"target analysis plan setting is invalid: {key}")
    if settings["summary_max_bytes"] < 1024 or settings["summary_sample_per_prefix"] > settings["summary_max_items"]:
        raise ValueError("target analysis plan summary bounds are inconsistent")
    model = settings.get("model")
    if not isinstance(model, Mapping):
        raise ValueError("target analysis plan model settings are required")
    required = {"enabled", "provider", "model", "reasoning", "max_input_tokens", "max_output_tokens",
                "timeout_seconds", "retries"}
    if not required <= set(model):
        raise ValueError("target analysis plan model settings are incomplete")
    if type(model["enabled"]) is not bool:
        raise ValueError("target analysis plan model enabled setting must be a boolean")
    for key in ("provider", "model", "reasoning"):
        if not isinstance(model[key], str) or not model[key].strip():
            raise ValueError(f"target analysis plan model setting is invalid: {key}")
    for key in ("max_input_tokens", "max_output_tokens", "timeout_seconds"):
        if type(model[key]) is not int or model[key] < 1:
            raise ValueError(f"target analysis plan model setting is invalid: {key}")
    if type(model["retries"]) is not int or not 0 <= model["retries"] <= 5:
        raise ValueError("target analysis plan model retries must be between zero and five")


def _base_indexes(run_root: Path) -> tuple[list[IndexIdentity], Path, str]:
    manifest_path, manifest_sha = resolve_accepted_manifest(run_root)
    manifest, _ = load_verified_manifest(run_root, manifest_path, manifest_sha)
    while any(item["name"] == "observations" for item in manifest["indexes"]):
        upstream = manifest.get("upstream_manifests", [])
        if not upstream:
            raise ValueError("accepted observations have no stable upstream index set")
        manifest_path = (run_root / upstream[0]["path"]).resolve()
        manifest_sha = str(upstream[0]["sha256"])
        manifest, _ = load_verified_manifest(run_root, manifest_path, manifest_sha)
    indexes = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
               for item in manifest["indexes"]
               if not (item["name"] == "analysis" and item.get("shard_id") == "target-analysis-plan")]
    return indexes, manifest_path, manifest_sha


def build_job(*, model_client: ModelClient | None = None, fail_task: str | None = None) -> Job:
    def maybe_fail(unit: UnitContext) -> None:
        if unit.unit_id == fail_task:
            raise RuntimeError(f"injected bounded failure: {fail_task}")

    def load_catalog(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        catalog = _accepted_catalog(unit.job.run_root)
        if catalog["source_fingerprint"] != unit.job.source_fingerprint:
            raise ValueError("graph target fingerprint does not match the accepted catalog")
        unit.job.events.write("ANALYSIS_PLAN_STARTED", catalog_handoff_sha256=catalog["catalog_handoff_sha256"])
        return {"catalog": catalog, "catalog_handoff_sha256": catalog["catalog_handoff_sha256"]}

    def summarize(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        catalog = unit.output("catalog_summary.load_accepted_catalog")["catalog"]
        settings = unit.job.config.settings
        value = summarize_catalog(catalog, max_items=int(settings["summary_max_items"]),
                                  max_bytes=int(settings["summary_max_bytes"]),
                                  sample_per_prefix=int(settings["summary_sample_per_prefix"]))
        return {"schema": value["schema"], "artifact": _artifact(unit, "catalog-summary.json", value),
                "summary": value, "gaps": (["analysis summary was truncated by configured bounds"]
                                              if value["bounds"]["truncated"] else [])}

    def deterministic(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        catalog = unit.output("catalog_summary.load_accepted_catalog")["catalog"]
        summary = unit.output("catalog_summary.summarize_components")["summary"]
        value = deterministic_plan(catalog, summary)
        unit.job.events.write("ANALYSIS_PLAN_DETERMINISTIC_DECISIONS",
                              selected_scanner_count=len(value["scanner_selections"]),
                              skipped_scanner_count=len(value["scanner_non_selections"]),
                              build_system_count=len(value["build_topology"]["build_systems"]),
                              gap_count=len(value["coverage_gaps"]))
        return {"plan": value, "ambiguities": ambiguity_reasons(summary)}

    def resolve(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        base = unit.output("analysis_decisions.apply_deterministic_rules")
        plan = dict(base["plan"])
        ambiguities = list(base["ambiguities"])
        model = unit.job.config.settings["model"]
        if not ambiguities:
            return {"plan": plan, "gaps": [], "model_calls": 0, "validation_rejections": 0,
                    "terminal_status": "SUCCEEDED"}
        if not bool(model["enabled"]):
            gap = "analysis planning ambiguity was not model-assisted because the configured model is disabled"
            plan["coverage_gaps"] = [*plan["coverage_gaps"], gap]
            plan["model"] = {"status": "DISABLED", "proposal_sha256": None}
            return {"plan": plan, "gaps": [gap], "model_calls": 0, "validation_rejections": 0,
                    "terminal_status": "COMPLETED_WITH_GAPS"}
        if model_client is None:
            gap = "analysis planning model is unavailable; deterministic safe plan published"
            plan["coverage_gaps"] = [*plan["coverage_gaps"], gap]
            plan["model"] = {"status": "UNAVAILABLE", "proposal_sha256": None}
            return {"plan": plan, "gaps": [gap], "model_calls": 0, "validation_rejections": 0,
                    "terminal_status": "COMPLETED_WITH_GAPS"}
        catalog = unit.output("catalog_summary.load_accepted_catalog")["catalog"]
        summary = unit.output("catalog_summary.summarize_components")["summary"]
        guidance_path = unit.job.repository_root / "skills" / "target-analysis-planning" / "SKILL.md"
        if not guidance_path.is_file():
            guidance_path = Path(__file__).parents[4] / "skills" / "target-analysis-planning" / "SKILL.md"
        guidance = guidance_path.read_text(encoding="utf-8")
        guidance_sha = hashlib.sha256(guidance.encode("utf-8")).hexdigest()
        bundle_root = unit.job.run_root / "data" / "guidance" / guidance_sha
        atomic_bytes(bundle_root / "SKILL.md", guidance.encode("utf-8"))
        identity = {"provider": str(model["provider"]), "model": str(model["model"]),
                    "reasoning": str(model["reasoning"]), "guidance_sha256": guidance_sha}
        atomic_json(bundle_root / "model-identity.json", identity)
        bounded_paths = sorted({
            str(item["path"])
            for prefix in summary["prefixes"] for item in prefix["sample"]
        } | {
            str(item["path"])
            for key in ("recognized_build_files", "compile_databases", "accepted_artifacts")
            for item in summary[key]
        })
        request = ModelRequest(PROPOSAL_SCHEMA, guidance, summary, SCANNERS, tuple(sorted(BUILD_SYSTEMS)),
                               tuple(str(item["component_id"]) for item in summary["components"]),
                               tuple(bounded_paths),
                               int(model["max_input_tokens"]), int(model["max_output_tokens"]))
        request_identity = {
            "schema": request.schema, "summary": request.summary,
            "allowed_scanners": request.allowed_scanners, "allowed_build_systems": request.allowed_build_systems,
            "allowed_components": request.allowed_components, "allowed_paths": request.allowed_paths,
            "max_input_tokens": request.max_input_tokens, "max_output_tokens": request.max_output_tokens,
            "guidance_sha256": guidance_sha,
        }
        encoded_request_bytes = len(canonical_json(request_identity)) + len(guidance.encode("utf-8"))
        request_sha = hashlib.sha256(canonical_json(request_identity)).hexdigest()
        if encoded_request_bytes > request.max_input_tokens * 4:
            gap = "analysis planning summary exceeded the configured model input budget; deterministic safe plan published"
            plan["coverage_gaps"] = [*plan["coverage_gaps"], gap]
            plan["model"] = {"status": "BUDGET_EXCEEDED", "proposal_sha256": None}
            return {"plan": plan, "gaps": [gap], "model_calls": 0, "validation_rejections": 0,
                    "terminal_status": "COMPLETED_WITH_GAPS"}
        calls = 0
        last_error: Exception | None = None
        for retry in range(int(model["retries"]) + 1):
            calls += 1
            invocation = hashlib.sha256(f"{unit.job.run_id}:{unit.job.attempt_id}:{retry}:{request_sha}".encode()).hexdigest()
            log = PipelineLog(unit.job.run_root)
            emit_model_event(log, event_type="MODEL_CALL_STARTED", run_id=unit.job.run_id,
                             invocation_id=invocation, provider=str(model["provider"]), model=str(model["model"]),
                             reasoning_level=str(model["reasoning"]), guidance_bundle_sha256=guidance_sha,
                             request_sha256=request_sha, retry_count=retry, job_id="job_target_analysis_plan",
                             attempt_id=unit.job.attempt_id)
            started = time.monotonic()
            try:
                result = model_client.complete(request, timeout_seconds=int(model["timeout_seconds"]))
                duration = int((time.monotonic() - started) * 1000)
                errors = validate_proposal(result.proposal, catalog=catalog,
                                           allowed_components=request.allowed_components,
                                           allowed_paths=request.allowed_paths)
                emit_model_event(log, event_type="MODEL_CALL_COMPLETED", run_id=unit.job.run_id,
                    invocation_id=invocation, provider=str(model["provider"]), model=str(model["model"]),
                    reasoning_level=str(model["reasoning"]), guidance_bundle_sha256=guidance_sha,
                    request_sha256=request_sha, terminal_status="REJECTED" if errors else "ACCEPTED",
                    duration_ms=duration, retry_count=retry, input_tokens=result.input_tokens,
                    output_tokens=result.output_tokens, cache_tokens=result.cache_tokens,
                    job_id="job_target_analysis_plan", attempt_id=unit.job.attempt_id)
                if errors:
                    unit.job.events.write("ANALYSIS_PLAN_VALIDATION_REJECTED", rejection_count=len(errors),
                                          proposal_sha256=hashlib.sha256(canonical_json(result.proposal)).hexdigest())
                    gap = "analysis planning model proposal was rejected; deterministic safe plan published"
                    plan["coverage_gaps"] = [*plan["coverage_gaps"], gap]
                    plan["contradictions"] = errors[:20]
                    plan["model"] = {"status": "REJECTED", "proposal_sha256": hashlib.sha256(canonical_json(result.proposal)).hexdigest()}
                    return {"plan": plan, "gaps": [gap], "model_calls": calls,
                            "validation_rejections": len(errors), "terminal_status": "COMPLETED_WITH_GAPS"}
                accepted = merge_proposal(plan, result.proposal, catalog)
                return {"plan": accepted, "gaps": [], "model_calls": calls,
                        "validation_rejections": 0, "terminal_status": "SUCCEEDED"}
            except Exception as exc:  # model/provider failures are planning gaps, never clean coverage
                last_error = exc
                duration = int((time.monotonic() - started) * 1000)
                emit_model_event(log, event_type="MODEL_CALL_COMPLETED", run_id=unit.job.run_id,
                    invocation_id=invocation, provider=str(model["provider"]), model=str(model["model"]),
                    reasoning_level=str(model["reasoning"]), guidance_bundle_sha256=guidance_sha,
                    request_sha256=request_sha, terminal_status="FAILED", duration_ms=duration,
                    retry_count=retry, error_class=type(exc).__name__, job_id="job_target_analysis_plan",
                    attempt_id=unit.job.attempt_id)
        gap = f"analysis planning model failed after bounded retries ({type(last_error).__name__}); deterministic safe plan published"
        plan["coverage_gaps"] = [*plan["coverage_gaps"], gap]
        plan["model"] = {"status": "FAILED", "proposal_sha256": None}
        return {"plan": plan, "gaps": [gap], "model_calls": calls, "validation_rejections": 0,
                "terminal_status": "COMPLETED_WITH_GAPS"}

    def validate(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        plan = unit.output("analysis_decisions.resolve_ambiguity")["plan"]
        catalog = unit.output("catalog_summary.load_accepted_catalog")["catalog"]
        validate_plan(plan, catalog)
        artifact = _artifact(unit, "accepted-analysis-plan.json", plan)
        return {"status": "VALID", "artifact": artifact, "plan": plan,
                "gaps": list(plan["coverage_gaps"]),
                "terminal_status": unit.output("analysis_decisions.resolve_ambiguity")["terminal_status"]}

    def index_plan(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        accepted = unit.output("plan_acceptance.validate_plan")
        plan = accepted["plan"]
        fingerprint = index_fingerprint(name="analysis", target_snapshot=unit.job.source_fingerprint,
            producer_artifacts=[accepted["artifact"]], tool_identity={"producer": "job_target_analysis_plan"},
            parser_identity="analysis-plan-parser/1", normalizer_identity="analysis-plan-normalizer/1",
            mapping_identity="catalog-identity/1")
        path = unit.job.run_root / "data" / "indices" / "analysis" / f"{fingerprint}-target-analysis-plan.sqlite"
        reused = path.exists()
        if not reused:
            builder = IndexBuilder(path, name="analysis", fingerprint=fingerprint,
                                   target_snapshot=unit.job.source_fingerprint, shard_id="target-analysis-plan")
            component_ids: dict[str, str] = {}
            for component in plan["components"]:
                identity = LogicalIdentity.derive(EntityKind.COMPONENT, unit.job.source_fingerprint,
                    {"component_id": component["component_id"], "manifest": component.get("manifest")})
                component_ids[component["component_id"]] = identity.value
                builder.add_entity(EntityRecord(identity, component["component_id"], component["component_id"],
                    " ".join([component["component_id"], component["root"], *component["scanner_ids"]]), component))
            for selection in plan["scanner_selections"]:
                identity = LogicalIdentity.derive(EntityKind.EVIDENCE_ARTIFACT, unit.job.source_fingerprint,
                                                   {"analysis_plan_scanner": selection["scanner_id"]})
                builder.add_entity(EntityRecord(identity, selection["scanner_id"], selection["scanner_id"],
                    selection["reason"], selection))
                for component in plan["components"]:
                    if selection["scanner_id"] in component["scanner_ids"]:
                        builder.add_relation(RelationRecord(RelationKind.SUPPORTS, identity.value,
                            component_ids[component["component_id"]], True, 1.0))
                for scope in selection["scope"]:
                    source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, unit.job.source_fingerprint,
                                                       {"path": scope["path"], "sha256": scope["sha256"]})
                    builder.add_relation(RelationRecord(RelationKind.SUPPORTS, identity.value,
                                                        source_id.value, True, 1.0,
                                                        payload={"scope_path": scope["path"]}))
            for index, action in enumerate(plan["build_topology"]["build_actions"], 1):
                identity = LogicalIdentity.derive(EntityKind.BUILD_ACTION, unit.job.source_fingerprint,
                                                   {"analysis_plan_action": index, **action})
                builder.add_entity(EntityRecord(identity, f"planned-build:{index:04d}",
                                                 action["build_system"], action["root"], action))
                system = plan["build_topology"]["build_systems"][index - 1]
                manifest = system.get("manifest")
                if isinstance(manifest, Mapping):
                    source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, unit.job.source_fingerprint,
                        {"path": manifest["path"], "sha256": manifest["sha256"]})
                    builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, identity.value,
                                                        source_id.value, True, 1.0))
            builder.add_coverage("analysis-plan", "complete" if not plan["coverage_gaps"] else "partial",
                                 None if not plan["coverage_gaps"] else "; ".join(plan["coverage_gaps"][:10]))
            sha256 = builder.build()
        else:
            sha256 = file_sha256(path)
        identity = IndexIdentity("analysis", "appsec-review/retrieval-index/1", sha256, fingerprint,
            path.relative_to(unit.job.run_root).as_posix(),
            {"job": "job_target_analysis_plan", "unit": unit.unit_id}, tuple(plan["coverage_gaps"]),
            "target-analysis-plan")
        existing, upstream_path, upstream_sha = _base_indexes(unit.job.run_root)
        manifest_path = unit.job.run_root / "data" / "indices" / "manifests" / f"analysis-plan-{unit.job.attempt_id}.json"
        write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
            target_root=unit.job.target_root or Path(), indexes=[*existing, identity],
            upstream_manifests=({"path": upstream_path.relative_to(unit.job.run_root).as_posix(),
                                 "sha256": upstream_sha},))
        load_verified_manifest(unit.job.run_root, manifest_path, file_sha256(manifest_path))
        return {"artifact": {"path": path.relative_to(unit.job.run_root).as_posix(), "sha256": sha256,
                             "size_bytes": path.stat().st_size},
                "index_identity": asdict(identity),
                "index_manifest": {"path": manifest_path.relative_to(unit.job.run_root).as_posix(),
                                   "sha256": file_sha256(manifest_path), "size_bytes": manifest_path.stat().st_size},
                "item_count": len(plan["components"]) + len(plan["scanner_selections"]) + len(plan["build_topology"]["build_actions"]),
                "gaps": list(plan["coverage_gaps"]), "index_reused": reused}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        accepted = unit.output("plan_acceptance.validate_plan")
        indexed = unit.output("plan_acceptance.index_plan")
        resolution = unit.output("analysis_decisions.resolve_ambiguity")
        plan = accepted["plan"]
        unit.job.events.write("ANALYSIS_PLAN_COMPLETED",
            selected_scanner_count=len(plan["scanner_selections"]),
            skipped_scanner_count=len(plan["scanner_non_selections"]),
            build_system_count=len(plan["build_topology"]["build_systems"]),
            gap_count=len(plan["coverage_gaps"]), model_calls=resolution["model_calls"],
            validation_rejections=resolution["validation_rejections"],
            plan_sha256=accepted["artifact"]["sha256"], index_sha256=indexed["index_identity"]["sha256"])
        return {"schema": PLAN_SCHEMA, "artifact": accepted["artifact"],
                "index_manifest": indexed["index_manifest"], "index_identity": indexed["index_identity"],
                "item_count": indexed["item_count"], "gaps": list(plan["coverage_gaps"]),
                "terminal_status": resolution["terminal_status"],
                "dispositions": {"selected_scanners": len(plan["scanner_selections"]),
                                 "skipped_scanners": len(plan["scanner_non_selections"]),
                                 "model_calls": resolution["model_calls"]}}

    u = Unit
    units = (
        u("catalog_summary.load_accepted_catalog", load_catalog),
        u("catalog_summary.summarize_components", summarize, ("catalog_summary.load_accepted_catalog",)),
        u("analysis_decisions.apply_deterministic_rules", deterministic,
          ("catalog_summary.load_accepted_catalog", "catalog_summary.summarize_components")),
        u("analysis_decisions.resolve_ambiguity", resolve,
          ("analysis_decisions.apply_deterministic_rules", "catalog_summary.load_accepted_catalog",
           "catalog_summary.summarize_components")),
        u("plan_acceptance.validate_plan", validate,
          ("analysis_decisions.resolve_ambiguity", "catalog_summary.load_accepted_catalog")),
        u("plan_acceptance.index_plan", index_plan, ("plan_acceptance.validate_plan",)),
        u("plan_acceptance.publish_handoff", publish,
          ("plan_acceptance.validate_plan", "plan_acceptance.index_plan", "analysis_decisions.resolve_ambiguity")),
    )
    implementation = hashlib.sha256(Path(__file__).read_bytes() + Path(__file__).with_name("planning.py").read_bytes() +
                                    str(fail_task).encode() + (b"model-client" if model_client else b"no-model-client")).hexdigest()
    return Job("job_target_analysis_plan", "target_analysis_plan", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=PLAN_SCHEMA,
               implementation_identity=implementation,
               validation_identity=hashlib.sha256(Path(__file__).read_bytes() + b"validation").hexdigest(),
               units=units)
