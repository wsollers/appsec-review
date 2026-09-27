#!/usr/bin/env python3
"""Zero-config graph lifecycle for the intake-derived persona/tool review pool."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import claude_cli_invoker as cli
import claim_reviewer_pool  # registers the closed pool-candidate builder with the strict invoker
import container_execution
import control_lane_orchestration
import deterministic_pool_merge
import model_version_registry as model_versions
import persona_dispatch
import persona_invocation
import persona_prompt_assembly
import phase1
import pool_launcher
import pool_rendezvous
import pool_specification
import resource_pools
import review_cli
from execution_state import (Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash,
                             read_json, run_path)
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
from schema_validate import SchemaStore, validate_document

JOB = "persona-tool-pool-dispatch"
CONTRACT = JOB
RESULT = "persona-tool-pool-dispatch.json"
CELL_TEMPLATES = ("intake-review-pool-cell", "intake-review-pool-independent-cell")
ROOT_ID = "accepted-intake"
PERMISSIONS = ["read-run-data", "write-run-data"]
VIEW_REQUEST = "downstream/deterministic-pool-merge-request.json"
VIEW_CONTEXT = "downstream/pool-context.json"


def _permission_timestamp(value: str) -> str:
    """Normalize accepted-pointer timestamps to the permission model's UTC-seconds format."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise Blocked("persona/tool pool: accepted intake publication time is malformed") from exc
    if parsed.tzinfo is None:
        raise Blocked("persona/tool pool: accepted intake publication time has no timezone")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB, "whole")


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _code_hashes() -> dict[str, str]:
    names = ["persona_tool_pool_lifecycle.py", "claim_reviewer_pool.py", "pool_launcher.py",
             "pool_rendezvous.py", "pool_specification.py", "deterministic_pool_merge.py",
             "claude_cli_invoker.py", "persona_invocation.py", "control_lane_orchestration.py",
             "intake-review-pool-task.md", "registry/job-templates/intake-review-pool-cell.json",
             "registry/job-templates/intake-review-pool-independent-cell.json",
             "registry/job-templates/persona-tool-pool-dispatch.json",
             "registry/output-contracts/persona-tool-pool-dispatch.json"]
    result = {name: file_hash(ROOT / name) for name in names}
    for name in ("persona-tool-pool-dispatch.schema.json", "graph-pool-context.schema.json",
                 "claim-review-pool-candidates.schema.json"):
        result["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return result


def _load_intake(run_id: str) -> tuple[dict, dict, Path, str, str]:
    pointer = phase1.accepted(run_id, fresh=True)
    if pointer is None or pointer.get("status") != "OK" or pointer.get("run_id") != run_id:
        raise Blocked("persona/tool pool: newest accepted intake is unavailable")
    pointer_path = data_path(run_id, "jobs", "00-intake", "whole", "accepted.json")
    attempt = pointer_path.parent / "attempts" / pointer["attempt_id"]
    artifact = attempt / "outputs" / "intake.json"
    intake = read_json(artifact)
    source = "sha256:" + intake["source_fingerprint"]
    # Staged run inputs live beside data/, not beneath it.  Bind the pool's control generation to
    # the same manifest Phase 1 validated.
    manifest = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if manifest.is_symlink() or not manifest.is_file():
        raise Blocked("persona/tool pool: run artifact manifest is unavailable")
    control_generation = "sha256:" + file_hash(manifest)
    binding = {"job_id": "00-intake", "attempt_id": pointer["attempt_id"],
        "pointer_path": str(pointer_path.absolute()), "pointer_sha256": "sha256:" + file_hash(pointer_path),
        "artifact_path": "outputs/intake.json", "artifact_sha256": "sha256:" + file_hash(artifact),
        "source_snapshot_sha256": source}
    return intake, binding, attempt, control_generation, _permission_timestamp(pointer["published_at"])


def _request(run_id: str, template_id: str, prompt_name: str, intake_path: Path,
             source_generation: str, evaluated_at: str) -> tuple[dict, dict, str]:
    store = SchemaStore()
    prompt, template = persona_prompt_assembly.assemble_prompt_text(template_id, store)
    prompt_bytes = prompt.encode("utf-8")
    composition = persona_dispatch._composition_block(template_id, template, store)
    records = persona_invocation.load_composition(persona_invocation.REGISTRY_DIR, composition, store)
    ceiling = persona_invocation.claim_ceiling(records["role"], records["tooling_profile"])
    if "candidate_only" not in ceiling["allowed"]:
        raise Blocked("persona/tool pool: reviewer composition cannot emit candidate-only work")
    resolved = review_cli.resolve_model(template_id, template["budget_default"])
    model = model_versions.model_identity_for(run_id, resolved["model"])
    data = intake_path.read_bytes()
    request = {"invocation_role": "produce", "invoker_id": "claude-cli",
        "outer_prompt": {"path": prompt_name, "sha256": persona_invocation._bytes_sha(prompt_bytes),
                         "bytes": len(prompt_bytes)},
        "persona": composition, "model": model, "tools": [],
        "budget": dict(persona_dispatch.PERSONA_BUDGETS[template["budget_default"]]),
        "readable_inputs": [{"root": ROOT_ID, "path": "outputs/intake.json",
            "sha256": persona_invocation._bytes_sha(data), "bytes": len(data), "role": "evidence",
            "producer_request_sha256": None}],
        "allowed_claim_classes": ["candidate_only"],
        "prohibited_claim_classes": sorted(set(ceiling["prohibited"]) |
                                             (set(ceiling["allowed"]) - {"candidate_only"})),
        "producers": []}
    permission = persona_dispatch._permission_block(JOB, run_id=run_id,
        source_snapshot_sha256=source_generation, now=evaluated_at)
    return request, permission, prompt


def _current_inputs(run_id: str) -> dict[str, Any]:
    # Pin the run's model identities first, as every other persona worker does; this job can be
    # scheduled before discovery has created model-versions.json.
    model_versions.resolve_run_model_versions(run_id)
    intake, binding, intake_attempt, source, accepted_at = _load_intake(run_id)
    intake_path = intake_attempt / "outputs" / "intake.json"
    requests, prompts = [], {}
    for index, template_id in enumerate(CELL_TEMPLATES, 1):
        prompt_name = f"reviewer-{index}.md"
        request, permission, prompt = _request(
            run_id, template_id, prompt_name, intake_path, source, accepted_at)
        requests.append((template_id, request, permission))
        prompts[prompt_name] = prompt
    paths = intake.get("scope", {}).get("all_paths")
    if not isinstance(paths, list):
        raise Blocked("persona/tool pool: accepted intake scope is invalid")
    applicable = bool(paths)
    groups = [{"group_id": f"reviewer-{index}", "worker_kind": pool_specification.PERSONA,
        "count": 1 if applicable else 0, "memory_heavy": False, "permission": permission,
        "persona_request": request, "tool_request": None}
        for index, (_template, request, permission) in enumerate(requests, 1)]
    spec = {"schema": pool_specification.SPEC_ID, "pool_id": "full-review-intake-pool",
        "lane": "07-red-team-adversarial", "run_id": run_id, "job_id": JOB,
        "attempt_id": "pool-" + digest(binding)[:24], "budget_class": "standard",
        "pool_budget": {"max_instances": 2, "max_persona_input_units": 1_600_000,
                        "max_persona_output_units": 400_000, "max_total_timeout_seconds": 7200},
        "resource_pool_policy": {"allowed_pools": [resource_pools.PERSONA_LLM]},
        "wait_all": True, "rendezvous_timeout_seconds": 2400,
        "empty_pool_reason": None if applicable else "upstream_produced_no_work",
        "worker_groups": groups}
    return {"run_id": run_id, "source_generation": source, "accepted_at": accepted_at,
        "intake": intake, "intake_binding": binding, "intake_attempt": str(intake_attempt.absolute()),
        "prompts": prompts, "spec": spec,
        "applicability": "APPLICABLE" if applicable else "SKIPPED_NA_EMPTY_SCOPE",
        "code": _code_hashes()}


def _expected_candidates(intake: dict[str, Any], evidence_sha256: str) -> list[dict[str, Any]]:
    paths = sorted(intake["scope"]["all_paths"])
    if not paths:
        return []
    native = [path for path in paths if Path(path).suffix.lower() in
              {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}]
    scope = native or paths
    surface = "native source and build" if native else "accepted repository"
    assertion = {"hypothesis": f"The {surface} scope requires evidence-qualified security review.",
        "rationale": "Accepted intake identifies these paths as in scope but records no completed security verification.",
        "scope_paths": scope, "source_revision": intake["source_revision"],
        "limitations": list(intake.get("limitations", []))}
    return [{"candidate_id": "review_accepted_scope", "subject_id": "accepted-intake-scope",
        "assertion": json.dumps(assertion, sort_keys=True, separators=(",", ":")),
        "evidence_sha256": evidence_sha256, "claim_class": "candidate_only"}]


def _graph_instructions(package: Any) -> str:
    intake = json.loads(package.inputs[0].data)
    expected = _expected_candidates(intake, package.inputs[0].sha256)
    return "\n\n## Trusted graph-pool runtime (not target data)\n\n" + json.dumps({
        "required_claim_class": "candidate_only",
        "evidence_sha256": package.inputs[0].sha256,
        "candidate_id_format": "review_<letters-digits-underscore-hyphen>",
        "subject_id_rule": "stable review subject derived from an intake fact",
        "assertion_exact_fields": ["hypothesis", "rationale", "scope_paths", "source_revision",
                                   "limitations"],
        "candidate_rule": "return exactly the canonical candidates below; no findings or verdicts",
        "canonical_candidates": expected
    }, indent=2, sort_keys=True)


class GraphReviewInvoker:
    invoker_id = "claude-cli"

    def __init__(self, *, effort: str = "high", budget_usd: float | None = None,
                 timeout_seconds: int = cli.DEFAULT_TIMEOUT_SECONDS, dispatch_fn=None) -> None:
        self.effort, self.budget_usd, self.timeout_seconds = effort, budget_usd, timeout_seconds
        self.dispatch_fn = dispatch_fn or review_cli._dispatch_streaming

    def invoke(self, package: Any, *, output_root: Path, cancel: Any) -> None:
        suffix = _graph_instructions(package)

        def dispatch(argv: list[str], prompt: str, timeout: int, transcript: Path) -> dict[str, Any]:
            return self.dispatch_fn(argv, prompt + suffix, timeout, transcript)

        intake = json.loads(package.inputs[0].data)
        expected = _expected_candidates(intake, package.inputs[0].sha256)

        def fill(envelope: dict[str, Any], result_field: str) -> None:
            # The canonical candidates are fully determined by accepted intake; supply them
            # rather than depending on the model echoing them exactly (ADR-0013).
            envelope[result_field] = {"candidates": expected}

        cli.ClaudeCliInvoker(effort=self.effort, budget_usd=self.budget_usd,
            timeout_seconds=self.timeout_seconds, dispatch_fn=dispatch, fill_result=fill).invoke(
                package, output_root=output_root, cancel=cancel)


def _materialize_context(inputs: dict[str, Any], attempt: Path) -> tuple[pool_specification.PoolContext, Path]:
    context_root = attempt / "pool-context"
    pool_parent, prompt_root, rendezvous = (context_root / name for name in
                                            ("pools", "prompts", "rendezvous"))
    pool_parent.mkdir(parents=True); prompt_root.mkdir(); rendezvous.mkdir()
    for name, prompt in inputs["prompts"].items():
        atomic_bytes(prompt_root / name, prompt.encode("utf-8"))
    models = []
    for group in inputs["spec"]["worker_groups"]:
        model = group["persona_request"]["model"]
        if model not in models:
            models.append(model)
    context = pool_specification.PoolContext(pool_parent=pool_parent,
        registry_dir=persona_invocation.REGISTRY_DIR, prompt_root=prompt_root,
        readable_roots={ROOT_ID: Path(inputs["intake_attempt"])}, allowed_models=tuple(models),
        invoker_id="claude-cli", images_dir=container_execution.IMAGES_DIR,
        host_flavor="windows" if os.name == "nt" else "posix", docker_host=None,
        docker_executable=None, container_user=None, mount_roots={},
        source_snapshot_sha256=inputs["source_generation"], registry_ceiling=None)
    return context, rendezvous


def _validate_candidates(inputs: dict[str, Any], merge: dict[str, Any]) -> None:
    if validate_document(merge, "deterministic-pool-merge.schema.json"):
        raise Blocked("persona/tool pool: verified candidate merge is invalid")
    candidates = merge["candidates"]
    applicable = inputs["applicability"] == "APPLICABLE"
    if applicable and not candidates:
        raise Blocked("persona/tool pool: non-empty intake produced no review candidate")
    if not applicable and candidates:
        raise Blocked("persona/tool pool: empty intake produced review candidates")
    expected_hash = inputs["intake_binding"]["artifact_sha256"]
    expected = {item["candidate_id"]: item for item in _expected_candidates(inputs["intake"], expected_hash)}
    seen: set[str] = set()
    for candidate in candidates:
        if (candidate["candidate_id"] in seen or candidate["claim_class"] != "candidate_only" or
                candidate["evidence_sha256"] != expected_hash):
            raise Blocked("persona/tool pool: candidate identity, class, or evidence binding is invalid")
        seen.add(candidate["candidate_id"])
        raw = {key: candidate[key] for key in
               ("candidate_id", "subject_id", "assertion", "evidence_sha256", "claim_class")}
        if raw != expected.get(candidate["candidate_id"]):
            raise Blocked("persona/tool pool: candidate differs from the canonical intake derivation")
        if applicable and len(set(candidate["producer_ids"])) < 2:
            raise Blocked("persona/tool pool: candidate lacks two independent producers for quorum")
    if set(seen) != set(expected):
        raise Blocked("persona/tool pool: canonical intake candidates are incomplete")


def _context_record(inputs: dict[str, Any], context: pool_specification.PoolContext,
                    rendezvous: Path, launched: pool_launcher.LaunchedPool) -> dict[str, Any]:
    return {"schema": "appsec-review/graph-pool-context/1.0", "run_id": inputs["run_id"],
        "job_id": JOB, "source_generation": inputs["source_generation"],
        "intake_binding": inputs["intake_binding"],
        "spec_sha256": pool_specification.spec_sha256(inputs["spec"]),
        "pool_directory": launched.pool_directory, "pool_parent": str(context.pool_parent.absolute()),
        "prompt_root": str(context.prompt_root.absolute()),
        "readable_roots": {key: str(path.absolute()) for key, path in context.readable_roots.items()},
        "allowed_models": [dict(item) for item in context.allowed_models],
        "invoker_id": context.invoker_id, "host_flavor": context.host_flavor,
        "docker_executable": None, "container_user": None, "mount_roots": {},
        "registry_ceiling": None, "rendezvous_parent": str(rendezvous.absolute()),
        "terminal_manifest_sha256": launched.terminal_manifest_sha256}


def _control_context(record: dict[str, Any]) -> dict[str, Any]:
    return {key: record[key] for key in ("pool_parent", "prompt_root", "readable_roots",
        "allowed_models", "invoker_id", "host_flavor", "docker_executable", "container_user",
        "mount_roots", "registry_ceiling")}


def _handoff(inputs: dict[str, Any], attempt: Path, record: dict[str, Any]) -> dict[str, Any]:
    spec_path = Path(record["pool_parent"]) / record["pool_directory"] / pool_specification.SPEC_FILE
    return {"schema": control_lane_orchestration.SCHEMA, "run_id": inputs["run_id"],
        "job_id": "deterministic-pool-merge", "source_generation": inputs["source_generation"],
        "generated_at": inputs["accepted_at"], "payload": {"spec_path": str(spec_path.absolute()),
            "context": _control_context(record), "runtime": {"effort": "high", "budget_usd": None,
                "stop_grace_seconds": 5, "max_parallel": 1, "wait_limit_seconds": 2400,
                "drain_seconds": 10, "rendezvous_parent": record["rendezvous_parent"]}}}


def _receipts(inputs: dict[str, Any], record: dict[str, Any]) -> tuple[dict, dict, dict]:
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0",
        "run_id": inputs["run_id"], "job_id": JOB,
        "source_snapshot_sha256": inputs["source_generation"], "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0",
        "run_id": inputs["run_id"], "job_id": JOB,
        "source_snapshot_sha256": inputs["source_generation"],
        "build_lineage_sha256": _sha({"intake": inputs["intake_binding"],
            "spec": record["spec_sha256"], "manifest": record["terminal_manifest_sha256"]})}
    applicability = {"schema": "appsec-review/graph-pool-applicability/1.0",
        "run_id": inputs["run_id"], "job_id": JOB,
        "decision": "APPLICABLE" if inputs["applicability"] == "APPLICABLE" else "SKIPPED_NA",
        "reason": ("Accepted intake contains target paths requiring review." if
                   inputs["applicability"] == "APPLICABLE" else
                   "Accepted intake scope is genuinely empty."),
        "intake_path_count": len(inputs["intake"]["scope"]["all_paths"])}
    return permission, lineage, applicability


def _load_retained_context(record: dict[str, Any]) -> pool_specification.PoolContext:
    return pool_specification.PoolContext(pool_parent=Path(record["pool_parent"]),
        registry_dir=persona_invocation.REGISTRY_DIR, prompt_root=Path(record["prompt_root"]),
        readable_roots={key: Path(value) for key, value in record["readable_roots"].items()},
        allowed_models=tuple(record["allowed_models"]), invoker_id=record["invoker_id"],
        images_dir=container_execution.IMAGES_DIR, host_flavor=record["host_flavor"], docker_host=None,
        docker_executable=None, container_user=None, mount_roots={},
        source_snapshot_sha256=record["source_generation"], registry_ceiling=None)


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs or inputs["code"] != _code_hashes():
        raise Blocked("persona/tool pool: immutable inputs or implementation changed")
    if _current_inputs(run_id) != inputs:
        raise Blocked("persona/tool pool: accepted intake or model context changed")
    result, record = read_json(attempt / RESULT), read_json(attempt / "pool-context.json")
    if (validate_document(result, "persona-tool-pool-dispatch.schema.json") or
            validate_document(record, "graph-pool-context.schema.json")):
        raise Blocked("persona/tool pool: retained result or context is invalid")
    context = _load_retained_context(record)
    spec_path = context.pool_parent / record["pool_directory"] / pool_specification.SPEC_FILE
    spec = read_json(spec_path)
    if spec != inputs["spec"]:
        raise Blocked("persona/tool pool: retained C01 specification changed")
    verified = pool_rendezvous.load_verified_manifest(context.pool_parent / record["pool_directory"],
        expected_spec=spec, context=context, rendezvous_parent=Path(record["rendezvous_parent"]))
    manifest = verified.manifest
    if (result["pool_directory"] != record["pool_directory"] or
            result["expansion_sha256"] != pool_specification.plan_expansion(spec, context=context).manifest["expansion_sha256"] or
            result["terminal_manifest_sha256"] != manifest["manifest_sha256"] or
            result["outcome"] != manifest["outcome"] or result["instance_count"] != len(verified.instances)):
        raise Blocked("persona/tool pool: retained C01/C02 identity changed")
    merge = deterministic_pool_merge.merge_verified_manifest(
        verified, pool_root=context.pool_parent / record["pool_directory"], run_id=run_id)
    _validate_candidates(inputs, merge)
    if read_json(attempt / "deterministic-merge-request.json") != _handoff(inputs, attempt, record):
        raise Blocked("persona/tool pool: downstream deterministic-merge handoff changed")
    permission, lineage, applicability = _receipts(inputs, record)
    if (read_json(attempt / "permission.json") != permission or
            read_json(attempt / "lineage.json") != lineage or
            read_json(attempt / "applicability.json") != applicability):
        raise Blocked("persona/tool pool: retained receipts changed")


def _publish_views(base: Path, pointer: dict[str, Any], run_id: str) -> None:
    attempt = base / "attempts" / pointer["attempt_id"]
    inputs = read_json(attempt / "inputs.json")
    _validate_attempt(run_id, attempt, inputs)
    atomic_json(base / VIEW_REQUEST, read_json(attempt / "deterministic-merge-request.json"))
    atomic_json(base / VIEW_CONTEXT, read_json(attempt / "pool-context.json"))


def _tombstone_views(base: Path, exc: BaseException) -> None:
    value = {"schema": "appsec-review/noncurrent-control-input/1.0", "status": "NONCURRENT",
             "cause": type(exc).__name__}
    atomic_json(base / VIEW_REQUEST, value)
    atomic_json(base / VIEW_CONTEXT, value)


def run(run_id: str, dagster_run_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        context, rendezvous = _materialize_context(inputs, attempt)
        runtime = pool_rendezvous.RendezvousRuntime(rendezvous_parent=rendezvous,
            invoker=GraphReviewInvoker(), clock=lambda: inputs["accepted_at"], stop_grace_seconds=5,
            cancel=pool_rendezvous.PoolCancel(), max_parallel=1, wait_limit_seconds=2400,
            drain_seconds=10)
        launched = pool_launcher.launch(inputs["spec"], context=context, runtime=runtime)
        if launched.outcome not in {pool_rendezvous.COMPLETE, pool_rendezvous.DEGRADED,
                                    pool_rendezvous.EMPTY}:
            raise Blocked("persona/tool pool: C02 did not retain a publishable outcome")
        if inputs["applicability"] == "APPLICABLE" and launched.outcome == pool_rendezvous.EMPTY:
            raise Blocked("persona/tool pool: non-empty intake produced an empty pool")
        verified = pool_rendezvous.load_verified_manifest(context.pool_parent / launched.pool_directory,
            expected_spec=inputs["spec"], context=context, rendezvous_parent=rendezvous)
        merge = deterministic_pool_merge.merge_verified_manifest(
            verified, pool_root=context.pool_parent / launched.pool_directory, run_id=run_id)
        _validate_candidates(inputs, merge)
        result = {"schema": "appsec-review/persona-tool-pool-dispatch/1.0", "run_id": run_id,
            "pool_directory": launched.pool_directory, "expansion_sha256": launched.expansion_sha256,
            "terminal_manifest_sha256": launched.terminal_manifest_sha256,
            "outcome": launched.outcome, "instance_count": launched.instance_count}
        record = _context_record(inputs, context, rendezvous, launched)
        permission, lineage, applicability = _receipts(inputs, record)
        atomic_json(attempt / RESULT, result); atomic_json(attempt / "pool-context.json", record)
        atomic_json(attempt / "deterministic-merge-request.json", _handoff(inputs, attempt, record))
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        atomic_json(attempt / "applicability.json", applicability)
        skipped = inputs["applicability"] != "APPLICABLE"
        gaps = (["SKIPPED_NA: accepted intake scope is empty; C01/C02 retained a zero-instance pool."]
                if skipped else (["C02 pool completed with a degraded terminal population."]
                                 if launched.outcome == pool_rendezvous.DEGRADED else None))
        execution_status = "OK_WITH_GAPS" if gaps else "OK"
        status = {"process": JOB, "status": execution_status, "result": RESULT,
                  "claim_limit": "CANDIDATE_ONLY", "applicability": inputs["applicability"],
                  "pool_outcome": launched.outcome}
        pool_root = context.pool_parent / launched.pool_directory
        manifest_path = pool_rendezvous.rendezvous_root(
            pool_specification.plan_expansion(inputs["spec"], context=context), rendezvous) / pool_rendezvous.MANIFEST_FILE
        dynamic = [str((pool_root / pool_specification.SPEC_FILE).relative_to(attempt)).replace("\\", "/"),
                   str((pool_root / pool_specification.EXPANSION_FILE).relative_to(attempt)).replace("\\", "/"),
                   str(manifest_path.relative_to(attempt)).replace("\\", "/")]
        pointer = record_terminal_current(base, attempt, run_id=run_id, job_id=JOB,
            dagster_run_id=dagster_run_id, worker_kind="pool_coordinator", output_contract=CONTRACT,
            input_fingerprint=fingerprint, started_at=allocation["started_at"],
            execution_status=execution_status,
            summary=("Retained an evidence-supported empty reviewer pool." if skipped else
                     "Published the C01/C02-verified intake-derived reviewer pool."),
            status_record=status, artifact_paths=[RESULT, "pool-context.json",
                "deterministic-merge-request.json", "permission.json", "lineage.json",
                "applicability.json", "status.json", *dynamic], gaps=gaps,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))
        _publish_views(base, pointer, run_id)
        return pointer

    try:
        return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB,
            dagster_run_id=dagster_run_id, worker_kind="pool_coordinator", output_contract=CONTRACT,
            resume_command=f"python -B appsec-review-process/persona_tool_pool_lifecycle.py --run-id {run_id}",
            derive_inputs=lambda: _current_inputs(run_id), fingerprint_inputs=lambda value: _sha(value),
            execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id,
                "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}, force=force,
            post_validate=lambda attempt, _envelope, inputs: _validate_attempt(run_id, attempt, inputs),
            on_reuse=lambda admitted: _publish_views(base, admitted["pointer"], run_id),
            blocked_summary="Newest accepted intake or trusted graph-pool context was unavailable.",
            failed_summary="Graph-level persona/tool pool did not publish a verified terminal population.")
    except BaseException as exc:
        _tombstone_views(base, exc)
        raise


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-persona-tool-pool")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.run_id, args.dagster_run_id, args.force), indent=2))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
