from __future__ import annotations

from appsec_review.interchange import decode_handoff

from collections.abc import Mapping
from appsec_review.storage.shared import PublicationThreadPoolExecutor as ThreadPoolExecutor
from dataclasses import replace
from dataclasses import asdict
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import time
from typing import Any

from appsec_review.application_paths import application_root
from appsec_review.jobs.build_discovery import (
    build_recipe_inference_policy, normalize_build_recipe, required_image_profile,
)
from appsec_review.jobs.build_topology import validate_build_topology
from appsec_review.jobs.cataloging import write_json
from appsec_review.observability import PipelineLog, emit_model_event
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_context_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256
from appsec_review.swift_policy import (
    SWIFT_KNOWN_GAP, contains_swift_derived, filter_swift_files, reject_swift_derived,
    swift_enabled_from_run, swift_inventory_count,
)

from appsec_review.inference import Infer, ModelRequest
from appsec_review.jobs.job_source_history_analysis import load_accepted_history

from .planning import (
    BUILD_SYSTEMS, PLAN_SCHEMA, PROPOSAL_SCHEMA, SCANNERS,
    ambiguity_reasons, deterministic_plan, merge_proposal, summarize_catalog,
    validate_plan, validate_proposal, bounded_feedback, evidence_catalog, _publish_build_graph, model_safe,
)
from appsec_review.jobs.job_target_analysis_plan.datasets import CONSUMES, DATASETS
from appsec_review.guidance.skills import load_runtime_skill


TOPOLOGY = {
    "catalog_summary": ("load_accepted_catalog", "summarize_components"),
    "analysis_decisions": ("apply_deterministic_rules", "resolve_ambiguity"),
    "plan_acceptance": ("validate_plan", "index_plan", "publish_handoff"),
}


def publish_guidance_bundle(run_root: Path, *, persona: str, role: str, guidance: str,
                            model: Mapping[str, Any], family: str, build_system: str,
                            repository_root: Path | None = None) -> str:
    """Write one immutable bundle per model and recipe group before inference uses it."""
    from appsec_review.guidance.workers import publish_worker_guidance
    root = repository_root or application_root("pipeline/guidance/registry.json")
    return publish_worker_guidance(root, run_root, "build_planning", family=family, model=model, build_system=build_system,
        texts={"persona": persona, "role": role, "procedure": guidance})[1]


def _artifact(unit: UnitContext, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    if len(canonical_json(value)) > 32 * 1024 * 1024:
        raise ValueError("planning artifact exceeds its 32 MiB reader bound")
    path = unit.job.attempt_root / "artifacts" / "analysis-plan" / name
    identity = write_json(path, value)
    identity["path"] = path.relative_to(unit.job.run_root).as_posix()
    return identity


def _read_artifact(run_root: Path, identity: Mapping[str, Any], *,
                   byte_limit: int = 16 * 1024 * 1024) -> Mapping[str, Any]:
    from appsec_review.storage.shared import safe_path
    if byte_limit not in {16 * 1024 * 1024, 32 * 1024 * 1024}:
        raise ValueError("unsupported accepted-artifact byte limit")
    path = safe_path(run_root, str(identity.get("path", "")))
    if run_root.resolve() not in path.parents or not path.is_file():
        raise ValueError("accepted upstream artifact is unavailable or outside the run")
    size = path.stat().st_size
    if size > byte_limit:
        raise ValueError("accepted upstream artifact exceeds its byte bound")
    data = path.read_bytes()
    if (len(data) != size or len(data) > byte_limit or identity.get("size_bytes", size) != size
            or hashlib.sha256(data).hexdigest() != identity.get("sha256")):
        raise ValueError("accepted upstream artifact identity changed")
    value = json.loads(data)
    if not isinstance(value, Mapping):
        raise ValueError("accepted upstream artifact must be a JSON object")
    return value


def _accepted_catalog(run_root: Path) -> dict[str, Any]:
    from appsec_review.storage.shared import safe_path
    pointer_path = safe_path(run_root, "data/jobs/job_target_catalog/latest.json")
    if not pointer_path.is_file():
        raise ValueError("accepted job_target_catalog handoff is required")
    if pointer_path.stat().st_size > 65536:
        raise ValueError("accepted catalog pointer exceeds its byte bound")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = _read_artifact(run_root, {"path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]},
                             byte_limit=32 * 1024 * 1024)
    handoff = decode_handoff(handoff, run_id=run_root.name, job_id="job_target_catalog")
    published = handoff.get("outputs", {}).get("publish_catalog.publish_handoff", {})
    catalog = _read_artifact(run_root, published.get("artifact", {}), byte_limit=32 * 1024 * 1024)
    if catalog.get("schema") != "appsec-review/target-catalog/1":
        raise ValueError("target catalog schema is unsupported")
    if catalog.get("source_fingerprint") != handoff["source_fingerprint"]:
        raise ValueError("accepted catalog and handoff source identities differ")
    artifacts = catalog.get("artifacts", {})
    partition = _read_artifact(run_root, artifacts["repository_discovery.partition_repository"],
                               byte_limit=32 * 1024 * 1024)
    projects = _read_artifact(run_root, artifacts["repository_discovery.discover_projects"])
    components = _read_artifact(run_root, artifacts["component_discovery.catalog_components"])
    builds = _read_artifact(run_root, artifacts["build_discovery.discover_build_systems"])
    compile_databases = _read_artifact(run_root, artifacts["build_discovery.discover_compile_commands"])
    targets = _read_artifact(run_root, artifacts["build_discovery.catalog_build_targets"])
    expected_schemas = (
        (partition, "repository-partition/1"), (projects, "project-catalog/1"),
        (components, "component-catalog/1"), (builds, "build-systems/2"),
        (compile_databases, "compile-commands/1"), (targets, "build-targets/2"),
    )
    if any(value.get("schema") != "appsec-review/" + schema for value, schema in expected_schemas):
        raise ValueError("accepted catalog child artifact schema is unsupported")
    if partition.get("source_fingerprint") != catalog["source_fingerprint"]:
        raise ValueError("accepted catalog partition source identity differs")
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
        "build_units": tuple(targets.get("targets", ())),
        "source_only_scopes": tuple(builds.get("source_only_scopes", ())),
        "compile_databases": tuple(compile_databases.get("files", ())),
        "accepted_artifacts": tuple(item for item in targets.get("targets", ()) if item.get("artifact_kind") == "built"),
        "gaps": tuple(gaps),
    }


@lru_cache(maxsize=2)
def _verify_source_topology(plan_bytes: bytes) -> None:
    from appsec_review.jobs.build_topology import (
        compile_build_topology, topology_evidence_bundle, refine_build_topology,
    )
    plan = json.loads(plan_bytes)
    topology = plan["build_topology"]
    graph, actions, bundle = topology["executable_graph"], topology["build_actions"], topology["evidence_bundle"]
    if (bundle["environment"] != plan.get("build_environment")
            or compile_build_topology(actions, source_fingerprint=plan["source_fingerprint"],
                               environment=bundle["environment"], profiles=bundle["profiles"]) != graph
            or bundle != topology_evidence_bundle(actions, source_fingerprint=plan["source_fingerprint"],
                                                 environment=bundle["environment"], profiles=bundle["profiles"])
            or topology["planning_refinement"] != refine_build_topology(
                graph, actions, environment=bundle["environment"], profiles=bundle["profiles"])):
        raise ValueError("accepted graph/refinement does not reproduce from its whole evidence bundle")


def load_accepted_plan(run_root: Path) -> Mapping[str, Any]:
    from appsec_review.storage.shared import safe_path
    pointer_path = safe_path(Path(run_root), "data/jobs/job_target_analysis_plan/latest.json")
    if not pointer_path.is_file():
        raise ValueError("accepted job_target_analysis_plan handoff is required")
    if pointer_path.stat().st_size > 65536:
        raise ValueError("accepted planning pointer exceeds its byte bound")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = _read_artifact(Path(run_root), {"path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]},
                             byte_limit=32 * 1024 * 1024)
    handoff = decode_handoff(handoff, run_id=Path(run_root).name, job_id="job_target_analysis_plan")
    identity = handoff.get("outputs", {}).get("plan_acceptance.publish_handoff", {}).get("artifact")
    plan = _read_artifact(Path(run_root), identity or {}, byte_limit=32 * 1024 * 1024)
    if plan.get("schema") != PLAN_SCHEMA:
        raise ValueError("accepted analysis plan schema is unsupported")
    graph = plan.get("build_topology", {}).get("executable_graph")
    if not isinstance(graph, Mapping) or graph.get("source_fingerprint") != plan.get("source_fingerprint"):
        raise ValueError("accepted analysis plan has no source-bound executable build graph")
    validate_build_topology(graph)
    if graph["schema"] == "appsec-review/build-topology/2":
        environment = plan.get("build_environment")
        if environment is not None:
            from appsec_review.jobs.job_build_environment_analysis.job import load_environment
            contract = {key: environment[key] for key in
                        ("schema", "workflow", "expected_producer", "mode", "reference", "reason")}
            current = load_environment(Path(run_root), plan["source_fingerprint"], contract)
            # Availability reason is a persisted outcome, not the launch reason.
            if any(environment[key] != current[key] for key in
                   ("availability", "artifact", "evidence", "reference", "mode", "workflow", "expected_producer")):
                raise ValueError("accepted planning environment identity changed")
        _verify_source_topology(canonical_json(plan))
    reject_swift_derived(
        plan, enabled=swift_enabled_from_run(Path(run_root)),
        context="accepted target analysis plan")
    return plan


def _validate_config(context, result) -> None:
    from appsec_review.config import PlanningFeedbackSettings, parse_bounded_settings
    parse_bounded_settings(context.config.settings.get("feedback", {}), PlanningFeedbackSettings)
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
                "timeout_seconds", "retries", "workers"}
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
    if type(model["workers"]) is not int or not 1 <= model["workers"] <= 16:
        raise ValueError("target analysis plan model workers must be between one and sixteen")


def _base_indexes(context) -> tuple[list[IndexIdentity], Path, str]:
    run_root = context.run_root
    manifest_path, manifest_sha = resolve_context_manifest(context)
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


def apply_swift_catalog_policy(catalog: Mapping[str, Any], *, enabled: bool) -> dict[str, Any]:
    """Keep Swift inventory upstream while removing it from every executable planning input."""
    if enabled:
        return dict(catalog)
    files = tuple(catalog.get("files", ()))
    return {
        **dict(catalog),
        "files": filter_swift_files(files, enabled=False),
        "accepted_artifacts": tuple(item for item in catalog.get("accepted_artifacts", ())
                                    if not contains_swift_derived(item)),
        "build_units": tuple(item for item in catalog.get("build_units", ())
                             if not contains_swift_derived(item)),
        "gaps": (*catalog.get("gaps", ()), *([SWIFT_KNOWN_GAP]
                 if swift_inventory_count(files) else [])),
    }


def build_job(*, infer: Infer | None = None, fail_task: str | None = None) -> Job:
    def maybe_fail(unit: UnitContext) -> None:
        if unit.unit_id == fail_task:
            raise RuntimeError(f"injected bounded failure: {fail_task}")

    def load_catalog(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        catalog = _accepted_catalog(unit.job.run_root)
        if catalog["source_fingerprint"] != unit.job.source_fingerprint:
            raise ValueError("graph target fingerprint does not match the accepted catalog")
        history = load_accepted_history(unit.job.run_root)
        if history is not None and history.get("target_snapshot") != catalog["source_fingerprint"]:
            history = {"stale_reason": "accepted source history describes a different target snapshot"}
        unit.job.events.write("ANALYSIS_PLAN_STARTED", catalog_handoff_sha256=catalog["catalog_handoff_sha256"])
        from appsec_review.jobs.job_build_environment_analysis.job import load_environment
        contract = json.loads(unit.job.orchestration["build_environment_contract"])
        environment = load_environment(unit.job.run_root, catalog["source_fingerprint"], contract)
        return {"catalog": catalog, "catalog_handoff_sha256": catalog["catalog_handoff_sha256"],
                "history": history, "environment": environment}

    def summarize(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        catalog = apply_swift_catalog_policy(
            unit.output("catalog_summary.load_accepted_catalog")["catalog"],
            enabled=unit.job.tools.enable_swift)
        settings = unit.job.config.settings
        value = summarize_catalog(catalog, max_items=int(settings["summary_max_items"]),
                                  max_bytes=int(settings["summary_max_bytes"]),
                                  sample_per_prefix=int(settings["summary_sample_per_prefix"]))
        return {"schema": value["schema"], "artifact": _artifact(unit, "catalog-summary.json", value),
                "summary": value, "gaps": (["analysis summary was truncated by configured bounds"]
                                              if value["bounds"]["truncated"] else [])}

    def deterministic(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        catalog = apply_swift_catalog_policy(
            unit.output("catalog_summary.load_accepted_catalog")["catalog"],
            enabled=unit.job.tools.enable_swift)
        summary = unit.output("catalog_summary.summarize_components")["summary"]
        value = deterministic_plan(catalog, summary,
                                   unit.output("catalog_summary.load_accepted_catalog").get("history"))
        value["build_environment"] = unit.output("catalog_summary.load_accepted_catalog")["environment"]
        environment = value["build_environment"]
        environment_gaps = environment["evidence"]["gaps"] if environment["evidence"] is not None else []
        if environment["availability"] == "UNAVAILABLE":
            environment_gaps = [*environment_gaps, environment["reason"]]
        value["coverage_gaps"] = [*value["coverage_gaps"],
                                  *("build environment: " + gap for gap in environment_gaps)]
        _publish_build_graph(value)
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
        environment_gaps = [gap for gap in plan["coverage_gaps"] if gap.startswith("build environment: ")]
        ambiguities = list(base["ambiguities"])
        model = unit.job.config.settings["model"]
        if not ambiguities:
            return {"plan": plan, "gaps": environment_gaps, "model_calls": 0, "validation_rejections": 0,
                    "terminal_status": "COMPLETED_WITH_GAPS" if environment_gaps else "SUCCEEDED"}
        if not bool(model["enabled"]):
            gap = "analysis planning ambiguity was not model-assisted because the configured model is disabled"
            plan["coverage_gaps"] = [*plan["coverage_gaps"], gap]
            plan["model"] = {"status": "DISABLED", "proposal_sha256": None}
            return {"plan": plan, "gaps": [gap], "model_calls": 0, "validation_rejections": 0,
                    "terminal_status": "COMPLETED_WITH_GAPS"}
        if infer is None:
            gap = "analysis planning model is unavailable; deterministic safe plan published"
            plan["coverage_gaps"] = [*plan["coverage_gaps"], gap]
            plan["model"] = {"status": "UNAVAILABLE", "proposal_sha256": None}
            return {"plan": plan, "gaps": [gap], "model_calls": 0, "validation_rejections": 0,
                    "terminal_status": "COMPLETED_WITH_GAPS"}
        catalog = apply_swift_catalog_policy(
            unit.output("catalog_summary.load_accepted_catalog")["catalog"],
            enabled=unit.job.tools.enable_swift)
        summary = unit.output("catalog_summary.summarize_components")["summary"]
        catalog_units = {str(value["build_unit_id"]): value for value in catalog.get("build_units", ())}
        from appsec_review.config import PlanningFeedbackSettings, parse_bounded_settings
        limits = parse_bounded_settings(unit.job.config.settings.get("feedback", {}), PlanningFeedbackSettings)
        from dataclasses import replace
        limits = replace(limits, max_calls=min(limits.max_calls, 1 + model["retries"]))
        guidance = load_runtime_skill(unit.job.repository_root, "target-analysis-planning",
                                      job_id="job_target_analysis_plan").text
        prompt_root = unit.job.repository_root / "pipeline" / "prompt-fragments"
        if not prompt_root.is_dir():
            prompt_root = (application_root("pipeline/prompt-fragments/personas/devops-engineer.md") /
                           "pipeline" / "prompt-fragments")
        persona_path = prompt_root / "personas" / "devops-engineer.md"
        persona = persona_path.read_text(encoding="utf-8")
        grouped: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
        for raw_unit in summary.get("build_units", ()):
            if raw_unit.get("build_system") == "unity":
                continue
            image_profile = required_image_profile(raw_unit)
            build_unit = {**dict(raw_unit), "required_image_profile": image_profile,
                          "command_policy": build_recipe_inference_policy(raw_unit)}
            grouped.setdefault((str(build_unit["family"]), str(build_unit["build_system"]),
                                image_profile), []).append(build_unit)

        if not grouped:
            plan["model"] = {"status": "NOT_NEEDED", "proposal_sha256": None}
            return {"plan": plan, "gaps": environment_gaps, "model_calls": 0, "validation_rejections": 0,
                    "terminal_status": "COMPLETED_WITH_GAPS" if environment_gaps else "SUCCEEDED"}

        partitions = []
        for key, values in sorted(grouped.items()):
            ordered = sorted(values, key=lambda value: value["build_unit_id"])
            partitions.extend((key, ordered[offset:offset + limits.units_per_scope])
                              for offset in range(0, len(ordered), limits.units_per_scope))
        omitted = max(0, len(partitions) - limits.max_scopes)
        partitions = partitions[:limits.max_scopes]

        def infer_group(item: tuple[tuple[str, str, str], list[Mapping[str, Any]]]) -> dict[str, Any]:
            (family, build_system, image_profile), build_units = item
            role_path = prompt_root / "roles" / f"build-engineer-{family}.md"
            role = role_path.read_text(encoding="utf-8")
            from appsec_review.guidance.workers import publish_worker_guidance
            governed, guidance_sha = publish_worker_guidance(
                unit.job.repository_root, unit.job.run_root, "build_planning", family=family, model=model,
                build_system=build_system,
                texts={"persona": persona, "role": role, "procedure": guidance})
            guidance_bytes = persona.encode() + b"\0" + role.encode() + b"\0" + governed.encode()
            paths = sorted({str(value["path"]) for build_unit in build_units
                            for value in (*build_unit.get("markers", ()),
                                          *build_unit.get("descriptor_package", {}).get("documents", ()))})
            compact_summary = {**summary, "components": [], "prefixes": [],
                               "recognized_build_files": [value for value in summary["recognized_build_files"]
                                                          if str(value["path"]) in paths],
                               "compile_databases": [value for value in summary["compile_databases"]
                                                     if str(value["path"]) in paths],
                               "accepted_artifacts": [], "build_units": build_units,
                               "build_environment": plan["build_environment"],
                               "feedback_limits": asdict(limits),
                               "guidance_bundle_sha256": guidance_sha}
            request = ModelRequest(
                schema=PROPOSAL_SCHEMA, persona=persona, role=role, guidance=governed,
                summary=compact_summary, allowed_scanners=(), allowed_build_systems=(build_system,),
                allowed_components=(), allowed_paths=tuple(paths),
                allowed_build_units=tuple(str(value["build_unit_id"]) for value in build_units),
                allowed_image_profiles=(image_profile,),
                provider=str(model["provider"]), model=str(model["model"]),
                reasoning=str(model["reasoning"]), max_input_tokens=int(model["max_input_tokens"]),
                max_output_tokens=int(model["max_output_tokens"]),
            )
            request_identity = {
                "schema": request.schema, "summary": request.summary, "persona_sha256": hashlib.sha256(persona.encode()).hexdigest(),
                "role_sha256": hashlib.sha256(role.encode()).hexdigest(), "allowed_paths": request.allowed_paths,
                "allowed_build_units": request.allowed_build_units, "provider": request.provider,
                "allowed_image_profiles": request.allowed_image_profiles,
                "model": request.model, "reasoning": request.reasoning,
                "max_input_tokens": request.max_input_tokens, "max_output_tokens": request.max_output_tokens,
                "guidance_sha256": guidance_sha,
                "source_fingerprint": catalog["source_fingerprint"],
                "whole_bundle": plan["build_topology"]["evidence_bundle"],
                "environment": plan["build_environment"],
                "profiles": plan["build_topology"]["evidence_bundle"]["profiles"],
                "rules": plan["build_topology"]["executable_graph"]["rules"],
            }
            accepted_units = [catalog_units[str(value["build_unit_id"])] for value in build_units]
            group_catalog = {**catalog, "build_units": accepted_units}
            from .planning import feedback_request
            request = feedback_request(request, group_catalog, limits)
            from appsec_review.storage.shared import safe_path

            def read_document(item, bound):
                if unit.job.target_root is None:
                    raise ValueError("planning evidence source custody is missing")
                path = safe_path(unit.job.target_root, item["path"])
                with path.open("rb") as stream:
                    return stream.read(bound + 1)

            call_starts = {}
            def on_call(event, call, key, error, result=None):
                if event == "STARTED":
                    call_starts[call] = time.monotonic()
                duration = (None if event == "STARTED" else
                            max(0, int((time.monotonic() - call_starts.pop(call)) * 1000)))
                invocation = hashlib.sha256(
                    f"{unit.job.run_id}:{unit.job.attempt_id}:{key}:{call}".encode()).hexdigest()
                emit_model_event(PipelineLog(unit.job.run_root),
                    event_type="MODEL_CALL_STARTED" if event == "STARTED" else "MODEL_CALL_COMPLETED",
                    run_id=unit.job.run_id, invocation_id=invocation,
                    provider=str(model["provider"]), model=str(model["model"]),
                    reasoning_level=str(model["reasoning"]), guidance_bundle_sha256=guidance_sha,
                    request_sha256=key, retry_count=call - 1, job_id="job_target_analysis_plan",
                    attempt_id=unit.job.attempt_id, build_family=family, build_system=build_system,
                    duration_ms=duration,
                    input_tokens=result.input_tokens if result is not None else None,
                    output_tokens=result.output_tokens if result is not None else None,
                    cache_tokens=result.cache_tokens if result is not None else None,
                    terminal_status=event if event != "STARTED" else None, error_class=error)

            return bounded_feedback(infer, request, catalog=group_catalog, limits=limits,
                read_document=read_document,
                cache_root=unit.job.run_root / "data" / "planning-feedback",
                identity=request_identity, on_call=on_call,
                call_timeout_seconds=int(model["timeout_seconds"]))

        workers = max(1, min(int(model.get("workers", 4)), len(partitions)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(infer_group, partitions))
        accepted_recipes = [recipe for value in results if value["proposal"] is not None
                            for recipe in value["proposal"]["build_recipes"]]
        gaps = [*environment_gaps, *(str(value["gap"]) for value in results if value["gap"])]
        if omitted:
            gaps.append(f"feedback_scope_bound: {omitted} deterministic partitions were not inferred")
        captured = {document["path"]: document for value in results for document in value["documents"]}
        plan["planning_evidence"] = [captured[path] for path in sorted(captured)]
        catalog = evidence_catalog(catalog, plan["planning_evidence"])
        for action in plan["build_topology"]["build_actions"]:
            accepted = next(item for item in catalog["build_units"]
                            if item["build_unit_id"] == action["build_unit_id"])
            action["descriptor_package"] = accepted["descriptor_package"]
        errors = [error for value in results for error in value["errors"]]
        if accepted_recipes:
            proposal = {"schema": PROPOSAL_SCHEMA, "action": "final", "component_proposals": [],
                        "build_recipes": accepted_recipes, "hints": [], "abstentions": []}
            plan = merge_proposal(plan, proposal, catalog)
            plan["model"] = {"status": "ACCEPTED" if not gaps else "PARTIAL",
                             "proposal_sha256": hashlib.sha256(canonical_json(proposal)).hexdigest(),
                             "groups": [{"status": value["status"]} for value in results]}
        else:
            terminal_model = "PARTIAL" if any(value["status"] == "PARTIAL" for value in results) else "FAILED"
            plan["model"] = {"status": terminal_model, "proposal_sha256": None,
                             "groups": [{"status": value["status"]} for value in results]}
        plan["coverage_gaps"] = [*plan["coverage_gaps"], *gaps]
        _publish_build_graph(plan)
        plan["feedback"] = [{"cache_key": value["cache_key"], "cache_hit": value["cache_hit"],
                             "calls": value["calls"], "status": value["status"], "metrics": value["metrics"]}
                            for value in results]
        plan["contradictions"] = [*plan.get("contradictions", []), *errors[:20]]
        return {"plan": plan, "gaps": gaps, "model_calls": sum(value["calls"] for value in results),
                "validation_rejections": len(errors),
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    def validate(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        plan = unit.output("analysis_decisions.resolve_ambiguity")["plan"]
        catalog = apply_swift_catalog_policy(
            unit.output("catalog_summary.load_accepted_catalog")["catalog"],
            enabled=unit.job.tools.enable_swift)
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
            parser_identity="analysis-plan-parser/2", normalizer_identity="analysis-plan-normalizer/2",
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
            graph = plan["build_topology"]["executable_graph"]
            bindings_by_fact = {}
            for binding in graph.get("bindings", []):
                bindings_by_fact.setdefault(binding["fact_id"], []).append({
                    key: binding[key] for key in ("binding_id", "build_unit_id", "subject", "stage", "scope_rule")})
            for fact in graph.get("facts", []):
                identity = LogicalIdentity.derive(EntityKind.EVIDENCE_ARTIFACT, unit.job.source_fingerprint,
                                                   {"topology": graph["topology_id"], "fact": fact["fact_id"]})
                payload = {key: fact[key] for key in ("fact_id", "predicate", "path", "sha256", "span", "rule")}
                payload["bindings"] = bindings_by_fact.get(fact["fact_id"], [])
                builder.add_entity(EntityRecord(identity, "build-fact:" + fact["fact_id"][:16],
                                                 fact["predicate"], fact["path"], payload))
                source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, unit.job.source_fingerprint,
                                                    {"path": fact["path"], "sha256": fact["sha256"]})
                builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, identity.value,
                                                    source_id.value, True, 1.0,
                                                    payload={"span": fact["span"]}))
            builder.add_coverage("analysis-plan", "complete" if not plan["coverage_gaps"] else "partial",
                                 None if not plan["coverage_gaps"] else "; ".join(plan["coverage_gaps"][:10]))
            sha256 = builder.build()
        else:
            sha256 = file_sha256(path)
        identity = IndexIdentity("analysis", "appsec-review/retrieval-index/2", sha256, fingerprint,
            path.relative_to(unit.job.run_root).as_posix(),
            {"job": "job_target_analysis_plan", "unit": unit.unit_id}, tuple(plan["coverage_gaps"]),
            "target-analysis-plan")
        existing, upstream_path, upstream_sha = _base_indexes(unit.job)
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
                "item_count": len(plan["components"]) + len(plan["scanner_selections"])
                              + len(plan["build_topology"]["build_actions"])
                              + len(plan["build_topology"]["executable_graph"].get("facts", [])),
                "gaps": list(plan["coverage_gaps"]), "index_reused": reused}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        accepted = unit.output("plan_acceptance.validate_plan")
        indexed = unit.output("plan_acceptance.index_plan")
        resolution = unit.output("analysis_decisions.resolve_ambiguity")
        plan = accepted["plan"]
        build_graph = plan["build_topology"]["executable_graph"]
        unit.job.events.write("ANALYSIS_PLAN_COMPLETED",
            selected_scanner_count=len(plan["scanner_selections"]),
            skipped_scanner_count=len(plan["scanner_non_selections"]),
            build_system_count=len(plan["build_topology"]["build_systems"]),
            gap_count=len(plan["coverage_gaps"]), model_calls=resolution["model_calls"],
            validation_rejections=resolution["validation_rejections"],
            plan_sha256=accepted["artifact"]["sha256"], index_sha256=indexed["index_identity"]["sha256"])
        return {"schema": PLAN_SCHEMA, "artifact": accepted["artifact"],
                 "build_topology_id": build_graph["topology_id"], "build_topology_schema": build_graph["schema"],
                "index_manifest": indexed["index_manifest"], "index_identity": indexed["index_identity"],
                "item_count": indexed["item_count"], "gaps": list(plan["coverage_gaps"]),
                "terminal_status": resolution["terminal_status"],
                "disposition_counts": {"selected_scanners": len(plan["scanner_selections"]),
                                       "skipped_scanners": len(plan["scanner_non_selections"]),
                                       "model_calls": resolution["model_calls"],
                                       **{f"build_units_{disposition}": sum(
                                           node["disposition"] == disposition for node in build_graph["nodes"])
                                          for disposition in ("independent", "contained", "unsupported", "unresolved")}}}

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
    implementation = None
    return Job("job_target_analysis_plan", "target_analysis_plan", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=PLAN_SCHEMA,
               implementation_identity=implementation,
               validation_identity=None,
               units=units,
               datasets=DATASETS, consumes=CONSUMES)
