#!/usr/bin/env python3
"""Validate the Mythos design-parity inventory without importing target-controlled code."""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import re
import sys
from typing import Any

from execution_state import ROOT, read_json
from job_graph import composition
import resource_pools
from schema_validate import validate_document
from worker_result import validate_worker_result

REPO = ROOT.parent
MANIFEST = ROOT / "design-parity-manifest.json"
WORKER_RESULT_CONTRACT = ROOT / "worker-result-contract.json"
READINESS = {
    "implemented_and_qualified", "implemented_not_qualified", "standalone_only",
    "supplied_artifact_gate", "registered_planned_not_executable", "missing_prerequisites",
    "decision_blocked", "not_applicable_design_decision",
}
QUALIFIED = "implemented_and_qualified"


def resolve_repo_path(relative: str | Path, repo: Path = REPO) -> Path:
    """Resolve host checkout paths and the code-server's split read-only mounts."""
    relative = Path(relative)
    normal = repo / relative
    if normal.exists() or (repo / "appsec-review-process").exists():
        return normal
    parts = relative.parts
    if parts and parts[0] == "appsec-review-process":
        return ROOT.joinpath(*parts[1:])
    if parts and parts[0] == "schemas":
        return ROOT.parent.joinpath(*parts)
    if parts[:2] == ("orchestrator", "dagster"):
        return ROOT.parent.joinpath("build-contract", *parts[2:])
    return normal


def _unique(records: list[dict[str, Any]], label: str) -> list[str]:
    seen: set[str] = set()
    errors: list[str] = []
    for record in records:
        identity = record.get("id")
        if identity in seen:
            errors.append(f"duplicate {label} id: {identity}")
        seen.add(identity)
    return errors


def _function_exists(reference: str | None, repo: Path) -> bool:
    if not reference or ":" not in reference:
        return False
    relative, function = reference.split(":", 1)
    path = resolve_repo_path(relative, repo)
    if not path.is_file():
        return False
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeError):
        return False
    return any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function
               for node in ast.walk(tree))


def _decorator_name(decorator: ast.expr) -> str | None:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return target.id if isinstance(target, ast.Name) else None


def _dagster_inventory(repo: Path) -> dict[str, Any]:
    definitions = resolve_repo_path("orchestrator/dagster/definitions.py", repo)
    workflow = resolve_repo_path("appsec-review-process/dagster_workflow.py", repo)
    launch = resolve_repo_path("appsec-review-process/launch_job.py", repo)
    names: set[str] = set()
    for path in (definitions, workflow):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                    _decorator_name(d) == "job" for d in node.decorator_list):
                names.add(node.name)
    launch_tree = ast.parse(launch.read_text(encoding="utf-8"))
    launcher: set[str] = set()
    for node in ast.walk(launch_tree):
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            values = [item.value for item in node.elts if isinstance(item, ast.Constant) and isinstance(item.value, str)]
            if "engagement_workflow" in values and "full_review" in values:
                launcher.update(values)
    text = workflow.read_text(encoding="utf-8")
    sensors: dict[str, list[str]] = {}
    tree = ast.parse(text)
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or _decorator_name(decorator) not in {"run_failure_sensor", "run_status_sensor"}:
                continue
            keyword = next((k.value for k in decorator.keywords if k.arg == "monitored_jobs"), None)
            if isinstance(keyword, ast.List):
                sensors[node.name] = [item.id for item in keyword.elts if isinstance(item, ast.Name)]
    return {"standalone_jobs": sorted(names), "launcher_jobs": sorted(launcher), "sensors": sensors, "workflow_text": text}


def _registry_for(node: dict[str, Any], repo: Path) -> dict[str, str] | None:
    template_id = node.get("template")
    if not template_id:
        return None
    registry = resolve_repo_path("appsec-review-process/registry", repo)
    template = read_json(registry / "job-templates" / f"{template_id}.json")
    composition(template, registry)
    value = template["composition"]
    return {"template": template_id, "persona": value["persona_id"], "role": value["role_id"],
            "domain": value["domain_id"], "tooling_profile": value["tooling_profile_id"],
            "output_contract": value["output_contract_id"]}


def _duplicates(values: list[str]) -> set[str]:
    return {value for value in values if values.count(value) > 1}


def _validate_worker_result_contract(manifest: dict[str, Any], repo: Path) -> list[str]:
    errors: list[str] = []
    reference = manifest.get("worker_result_contract", {})
    definition_path = resolve_repo_path(reference.get("definition_file", ""), repo)
    schema_path = resolve_repo_path(reference.get("schema_file", ""), repo)
    if not definition_path.is_file():
        return [f"missing worker-result contract: {reference.get('definition_file')}"]
    if not schema_path.is_file():
        return [f"missing worker-result schema: {reference.get('schema_file')}"]
    contract = read_json(definition_path)
    schema = read_json(schema_path)
    if contract.get("schema") != "appsec-review/worker-result-contract/1.0":
        errors.append("worker-result contract version mismatch")
    if contract.get("envelope_schema") != reference.get("schema_file"):
        errors.append("worker-result envelope schema reference mismatch")
    properties = schema.get("properties", {})
    if properties.get("schema", {}).get("const") != "appsec-review/worker-result-envelope/1.0":
        errors.append("worker-result envelope version mismatch")
    schema_kinds = properties.get("worker_kind", {}).get("enum", [])
    worker_kinds = contract.get("worker_kinds", [])
    if worker_kinds != schema_kinds or _duplicates(worker_kinds):
        errors.append("worker-result worker-kind set does not match envelope schema")
    execution = contract.get("execution_states", {})
    transient = execution.get("transient", [])
    terminal = execution.get("terminal", [])
    if execution.get("initial") not in transient:
        errors.append("worker-result initial execution state is not transient")
    if set(transient) & set(terminal) or _duplicates(transient + terminal):
        errors.append("worker-result execution states overlap or contain duplicates")
    if terminal != properties.get("execution_status", {}).get("enum", []):
        errors.append("worker-result terminal states do not match envelope schema")
    execution_transitions = execution.get("transitions", {})
    known_execution = set(transient + terminal)
    if set(execution_transitions) != known_execution:
        errors.append("worker-result execution transition sources are incomplete")
    for state, targets in execution_transitions.items():
        if _duplicates(targets) or set(targets) - known_execution:
            errors.append(f"worker-result execution transition from {state} has invalid targets")
        if state in terminal and targets:
            errors.append(f"worker-result terminal state {state} has outgoing transitions")
    acceptance = contract.get("acceptance_states", {})
    acceptance_states = acceptance.get("terminal", [])
    if acceptance_states != properties.get("acceptance_status", {}).get("enum", []):
        errors.append("worker-result acceptance states do not match envelope schema")
    acceptance_transitions = acceptance.get("transitions", {})
    if set(acceptance_transitions) != set(acceptance_states):
        errors.append("worker-result acceptance transition sources are incomplete")
    for state, targets in acceptance_transitions.items():
        if _duplicates(targets) or set(targets) - set(acceptance_states):
            errors.append(f"worker-result acceptance transition from {state} has invalid targets")
    if acceptance_transitions.get("SUPERSEDED"):
        errors.append("worker-result SUPERSEDED acceptance state must be immutable")
    if "SUPERSEDED" in terminal:
        errors.append("SUPERSEDED must be an acceptance disposition, not an execution status")
    skip_reasons = contract.get("skip_reasons", [])
    if not skip_reasons or _duplicates(skip_reasons):
        errors.append("worker-result skip-reason registry is empty or contains duplicates")
    required = set(schema.get("required", []))
    envelope_fields = {"execution_status", "acceptance_status", "skip_reason", "cause",
                       "retry", "superseded_by_attempt_id", "artifacts", "gaps"}
    missing_fields = sorted(envelope_fields - required)
    if missing_fields:
        errors.append("worker-result envelope omits required semantic fields: " + ", ".join(missing_fields))
    return errors


def _validate_graph(graph: dict[str, Any], manifest: dict[str, Any], repo: Path) -> list[str]:
    errors: list[str] = []
    jobs = graph.get("jobs", {})
    graph_contract = manifest.get("graph_contract", {})
    roots = graph_contract.get("roots", [])
    allowed_kinds = set(graph_contract.get("dependency_kinds", []))
    worker_definition = read_json(resolve_repo_path(
        manifest.get("worker_result_contract", {}).get("definition_file", ""), repo))
    allowed_skips = set(worker_definition.get("skip_reasons", []))
    namespaces = [node.get("namespace") for node in jobs.values()]
    for namespace in sorted(value for value in _duplicates(namespaces) if value):
        errors.append(f"graph namespace collision: {namespace}")
    for root in roots:
        if root not in jobs:
            errors.append(f"graph root is missing: {root}")
        elif jobs[root].get("dependencies"):
            errors.append(f"graph root has dependencies: {root}")
    adjacency: dict[str, list[str]] = {job_id: [] for job_id in jobs}
    for consumer, node in jobs.items():
        dependencies = node.get("dependencies", [])
        producers = [dep.get("job") for dep in dependencies]
        for duplicate in sorted(value for value in _duplicates(producers) if value):
            errors.append(f"{consumer}: duplicate dependency on {duplicate}")
        for dependency in dependencies:
            producer = dependency.get("job")
            kind = dependency.get("kind")
            skip_reasons = dependency.get("allowed_skip_reasons")
            if producer not in jobs:
                errors.append(f"{consumer}: unknown dependency {producer}")
                continue
            adjacency[producer].append(consumer)
            if kind not in allowed_kinds:
                errors.append(f"{consumer}: invalid dependency kind {kind!r} for {producer}")
            if not isinstance(skip_reasons, list):
                errors.append(f"{consumer}: dependency {producer} has no explicit skip-reason list")
                skip_reasons = []
            if kind == "optional" and not skip_reasons:
                errors.append(f"{consumer}: optional dependency {producer} has no allowed skip reason")
            unknown_skips = sorted(set(skip_reasons) - allowed_skips)
            if unknown_skips:
                errors.append(f"{consumer}: dependency {producer} has unknown skip reasons: {', '.join(unknown_skips)}")
            if _duplicates(skip_reasons):
                errors.append(f"{consumer}: dependency {producer} repeats a skip reason")
            expected = dependency.get("contract")
            actual = jobs[producer].get("contract")
            if expected != actual:
                errors.append(f"{consumer}: dependency contract mismatch for {producer}: expected {expected!r}, producer emits {actual!r}")
    reachable: set[str] = set()
    pending = list(roots)
    while pending:
        current = pending.pop()
        if current in reachable or current not in jobs:
            continue
        reachable.add(current)
        pending.extend(adjacency[current])
    unreachable = sorted(set(jobs) - reachable)
    if unreachable:
        errors.append("graph nodes unreachable from declared roots: " + ", ".join(unreachable))
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(job_id: str, trail: list[str]) -> None:
        if job_id in visiting:
            start = trail.index(job_id)
            errors.append("graph dependency cycle: " + " -> ".join(trail[start:] + [job_id]))
            return
        if job_id in visited:
            return
        visiting.add(job_id)
        for dependency in jobs[job_id].get("dependencies", []):
            producer = dependency.get("job")
            if producer in jobs:
                visit(producer, trail + [producer])
        visiting.remove(job_id)
        visited.add(job_id)

    for job_id in jobs:
        visit(job_id, [job_id])
    return errors


def validate_manifest(manifest: dict[str, Any], repo: Path = REPO) -> dict[str, Any]:
    errors = validate_document(manifest, "design-parity-manifest.schema.json")
    errors += _unique(manifest.get("jobs", []), "job")
    errors += _unique(manifest.get("capabilities", []), "capability")
    errors += _validate_worker_result_contract(manifest, repo)
    gaps: list[str] = []
    graph = read_json(resolve_repo_path("appsec-review-process/job-graph.json", repo))
    errors += _validate_graph(graph, manifest, repo)
    graph_jobs = graph["jobs"]
    records = {record.get("id"): record for record in manifest.get("jobs", []) if isinstance(record, dict)}
    missing = sorted(set(graph_jobs) - set(records))
    extra = sorted(set(records) - set(graph_jobs))
    if missing:
        errors.append("manifest missing graph jobs: " + ", ".join(missing))
    if extra:
        errors.append("manifest has jobs absent from graph: " + ", ".join(extra))
    actual = _dagster_inventory(repo)
    inventory = manifest.get("dagster_inventory", {})
    expected_jobs = sorted(set(actual["standalone_jobs"]) - {"orchestration_smoke"})
    if sorted(inventory.get("standalone_jobs", [])) != expected_jobs:
        errors.append(f"Dagster standalone job mismatch: manifest={sorted(inventory.get('standalone_jobs', []))} actual={expected_jobs}")
    relationships = inventory.get("standalone_relationships", [])
    errors += _unique([{"id": item.get("job")} for item in relationships], "standalone relationship")
    related_jobs = {item.get("job") for item in relationships}
    if related_jobs != set(expected_jobs):
        errors.append("standalone lifecycle relationship mismatch")
    for item in relationships:
        unknown = sorted(set(item.get("lifecycle_jobs", [])) - set(graph_jobs))
        if unknown:
            errors.append(f"{item.get('job')}: unknown related lifecycle jobs: {', '.join(unknown)}")
    if sorted(inventory.get("launcher_jobs", [])) != actual["launcher_jobs"]:
        errors.append("launcher job mismatch")
    sensor_map = {"failure_sensor_jobs": actual["sensors"].get("reconcile_workflow_failure", []),
                  "cancellation_sensor_jobs": actual["sensors"].get("reconcile_workflow_cancellation", [])}
    for field, values in sensor_map.items():
        if sorted(inventory.get(field, [])) != sorted(values):
            errors.append(f"{field} mismatch")
    pools = inventory.get("resource_pools", [])
    workflow_text = actual["workflow_text"]
    if not pools:
        gaps.append("resource_pools: no dedicated Dagster resource pools are configured")
    dagster_yaml = resolve_repo_path("orchestrator/dagster/dagster.yaml", repo).read_text(encoding="utf-8")
    global_match = re.search(r"max_concurrent_runs:\s*(\d+)", dagster_yaml)
    tag_match = re.search(r"applyLimitPerUniqueValue:\s*true\s*\n\s*limit:\s*(\d+)", dagster_yaml)
    queue = inventory.get("queue", {})
    if not global_match or int(global_match.group(1)) != queue.get("max_concurrent_runs"):
        errors.append("global Dagster queue limit mismatch")
    if not tag_match or int(tag_match.group(1)) != queue.get("per_engagement_limit"):
        errors.append("per-engagement Dagster queue limit mismatch")
    workflow_plan = read_json(resolve_repo_path("appsec-review-process/workflow-plan.json", repo))
    if workflow_plan.get("max_concurrent_steps") != queue.get("workflow_max_concurrent_steps"):
        errors.append("workflow concurrent-step limit mismatch")
    if pools and "pool=" not in workflow_text:
        errors.append("manifest declares resource pools but Dagster ops have no pool assignments")
    # B15: the pool vocabulary has one source of truth; the manifest may not invent or omit a pool.
    if pools and (len(set(pools)) != len(pools) or sorted(pools) != sorted(resource_pools.POOL_IDS)):
        errors.append("manifest resource pools do not match resource_pools.POOL_IDS")
    for job_id in sorted(set(records) & set(graph_jobs)):
        record = records[job_id]
        node = graph_jobs[job_id]
        if record.get("readiness") not in READINESS:
            errors.append(f"{job_id}: invalid readiness")
        if record.get("graph", {}).get("node") != job_id:
            errors.append(f"{job_id}: graph node identity mismatch")
        if record.get("graph", {}).get("implemented") != bool(node.get("implemented")):
            errors.append(f"{job_id}: graph implemented value mismatch")
        expected_deps = [dep["job"] for dep in node["dependencies"]]
        if record.get("graph", {}).get("dependencies") != expected_deps:
            errors.append(f"{job_id}: graph dependency mismatch")
        try:
            expected_registry = _registry_for(node, repo)
        except (FileNotFoundError, KeyError, ValueError) as exc:
            errors.append(f"{job_id}: broken registry composition: {exc}")
            expected_registry = None
        if record.get("registry") != expected_registry:
            errors.append(f"{job_id}: registry composition mismatch")
        if expected_registry:
            template = read_json(resolve_repo_path("appsec-review-process/registry/job-templates", repo) /
                                 f"{expected_registry['template']}.json")
            expected_permissions = template.get("permissions", [])
            if record.get("permissions") != expected_permissions:
                errors.append(f"{job_id}: registry permission mismatch")
        output = record.get("output", {})
        if output.get("contract") != node["contract"]:
            errors.append(f"{job_id}: output contract identity mismatch")
        for field in ("contract_file", "schema_file"):
            relative = output.get(field)
            if relative and not resolve_repo_path(relative, repo).is_file():
                errors.append(f"{job_id}: missing declared {field}: {relative}")
        if expected_registry:
            expected_contract = f"appsec-review-process/registry/output-contracts/{node['contract']}.json"
            if output.get("contract_file") != expected_contract:
                errors.append(f"{job_id}: registry output-contract file mismatch")
            contract_record = read_json(resolve_repo_path(expected_contract, repo))
            result_schema = contract_record.get("result_schema")
            if result_schema is not None:
                expected_schema = f"schemas/{result_schema.get('schema_file')}"
                if output.get("schema_file") != expected_schema:
                    errors.append(f"{job_id}: registry result-schema identity mismatch")
                if result_schema.get("artifact") not in contract_record.get("required_files", []):
                    errors.append(f"{job_id}: registry result artifact is not a required file")
            claim_class = contract_record.get("claim_class")
            if claim_class is not None:
                if output.get("claim_class") != claim_class.get("claim_class_id"):
                    errors.append(f"{job_id}: registry claim-class identity mismatch")
                for field in ("allowed_assertions", "forbidden_promotions"):
                    values = claim_class.get(field, [])
                    if len(values) != len(set(values)):
                        errors.append(f"{job_id}: registry claim-class {field} contains duplicates")
            elif output.get("claim_class") in {
                    "supply_chain_posture_evidence", "supplied_partition_map",
                    "supplied_project_discovery"}:
                errors.append(f"{job_id}: registry claim-class declaration is missing")
        execution = record.get("execution", {})
        for field in ("worker", "validator"):
            reference = execution.get(field)
            if reference and not _function_exists(reference, repo):
                errors.append(f"{job_id}: missing {field} entrypoint: {reference}")
        binding = record.get("dagster", {}).get("lifecycle_binding", {})
        entrypoint = binding.get("entrypoint")
        if not _function_exists(entrypoint, repo):
            errors.append(f"{job_id}: missing lifecycle entrypoint: {entrypoint}")
        kind = binding.get("kind")
        if kind == "blocked_op" and record.get("readiness") in {QUALIFIED, "implemented_not_qualified"}:
            errors.append(f"{job_id}: blocked_op cannot be classified as an implemented worker")
        if record.get("readiness") == "standalone_only" and kind != "blocked_op":
            errors.append(f"{job_id}: standalone_only conflicts with a lifecycle worker binding")
        if kind != "blocked_op" and job_id not in {"00-intake", "02-evidence-index"} and job_id not in workflow_text:
            errors.append(f"{job_id}: lifecycle binding is not referenced by the full-review source")
        if execution.get("mode") == "supplied_artifact" and record.get("readiness") != "supplied_artifact_gate":
            errors.append(f"{job_id}: supplied-artifact gate misclassified as automatic dispatch")
        if record.get("readiness") == "supplied_artifact_gate" and execution.get("mode") != "supplied_artifact":
            errors.append(f"{job_id}: supplied-artifact readiness requires supplied_artifact mode")
        if record.get("resource_pool") == "unassigned":
            gaps.append(f"{job_id}: resource pool unassigned")
        elif record.get("resource_pool") not in pools:
            errors.append(f"{job_id}: unknown resource pool {record.get('resource_pool')}")
        qualification = record.get("qualification", {})
        for reference in qualification.get("references", []):
            if not resolve_repo_path(reference, repo).exists():
                errors.append(f"{job_id}: missing qualification reference: {reference}")
        if qualification.get("levels") == ["none"] or not qualification.get("references"):
            gaps.append(f"{job_id}: no qualification evidence")
        if record.get("readiness") == QUALIFIED:
            required = {"worker": execution.get("worker"), "validator": execution.get("validator"),
                        "contract": output.get("contract_file"), "binding": entrypoint,
                        "qualification": qualification.get("references")}
            absent = [name for name, value in required.items() if not value]
            if absent:
                errors.append(f"{job_id}: false implemented_and_qualified claim; missing {', '.join(absent)}")
            if kind in {"blocked_op", "supplied_gate"}:
                errors.append(f"{job_id}: {kind} cannot be implemented_and_qualified")
            if not node.get("implemented"):
                errors.append(f"{job_id}: graph does not mark the qualified job implemented")
        for gap in record.get("gaps", []):
            gaps.append(f"{job_id}: {gap}")
    job_ids = set(graph_jobs)
    for capability in manifest.get("capabilities", []):
        unknown = sorted(set(capability.get("jobs", [])) - job_ids)
        if unknown:
            errors.append(f"{capability.get('id')}: unknown capability jobs: {', '.join(unknown)}")
        if capability.get("resource_pool") == "unassigned":
            gaps.append(f"{capability.get('id')}: resource pool unassigned")
        for reference in capability.get("qualification", {}).get("references", []):
            if not resolve_repo_path(reference, repo).exists():
                errors.append(f"{capability.get('id')}: missing qualification reference: {reference}")
        if capability.get("readiness") in {"decision_blocked", "missing_prerequisites"} and not capability.get("gaps"):
            errors.append(f"{capability.get('id')}: blocked/missing capability must declare gaps")
        for gap in capability.get("gaps", []):
            gaps.append(f"{capability.get('id')}: {gap}")
    # The code-server deliberately mounts /opt/process and /opt/schemas but not repository docs.
    # Enforce checked-in view freshness on full checkouts; split mounts still exercise both pure
    # renderers and every graph/contract check through the focused Linux suite.
    if (repo / "appsec-review-process").is_dir():
        generated = manifest.get("generated_views", {})
        expected_views = {
            "lifecycle_mermaid": render_mermaid(manifest),
            "readiness_table": render_readiness(manifest),
        }
        for field, expected in expected_views.items():
            relative = generated.get(field)
            path = resolve_repo_path(relative, repo) if relative else None
            if not path or not path.is_file():
                errors.append(f"missing generated {field}: {relative}")
            elif path.read_text(encoding="utf-8") != expected:
                errors.append(f"stale generated {field}: {relative}")
    return {"status": "PASS" if not errors else "FAIL", "errors": sorted(set(errors)),
            "gaps": sorted(set(gaps)), "job_count": len(records),
            "capability_count": len(manifest.get("capabilities", []))}


def _mermaid_id(job_id: str) -> str:
    return "j_" + re.sub(r"[^0-9A-Za-z_]", "_", job_id)


def render_mermaid(manifest: dict[str, Any]) -> str:
    lines = ["%% Generated by appsec-review-process/validate_design_parity.py; do not edit.",
             "flowchart TD"]
    for record in manifest.get("jobs", []):
        job_id = record["id"]
        readiness = record["readiness"]
        lines.append(f'  {_mermaid_id(job_id)}["{job_id}<br/>{readiness}"]')
    for record in manifest.get("jobs", []):
        consumer = _mermaid_id(record["id"])
        for producer_id in record.get("graph", {}).get("dependencies", []):
            lines.append(f"  {_mermaid_id(producer_id)} --> {consumer}")
    return "\n".join(lines) + "\n"


def render_readiness(manifest: dict[str, Any]) -> str:
    lines = ["# Lifecycle readiness", "",
             "Generated by `appsec-review-process/validate_design_parity.py`; do not edit.", "",
             "| Job | Execution mode | Binding | Readiness | Next prerequisite |",
             "|---|---|---|---|---|"]
    for record in manifest.get("jobs", []):
        prerequisite = (record.get("next_prerequisite") or "—").replace("|", "\\|")
        lines.append(f"| `{record['id']}` | `{record['execution']['mode']}` | "
                     f"`{record['dagster']['lifecycle_binding']['kind']}` | "
                     f"`{record['readiness']}` | {prerequisite} |")
    return "\n".join(lines) + "\n"


def render_report(manifest: dict[str, Any], result: dict[str, Any]) -> str:
    lines = ["# Mythos design-parity report", "", f"Status: **{result['status']}**",
             "", f"Manifest schema: `{manifest.get('schema')}`", f"Lifecycle jobs: **{result['job_count']}**",
             f"Design capabilities: **{result['capability_count']}**", "",
             "## Readiness summary", "", "| State | Jobs |", "|---|---:|"]
    counts: dict[str, int] = {}
    for record in manifest.get("jobs", []):
        counts[record["readiness"]] = counts.get(record["readiness"], 0) + 1
    lines += [f"| `{state}` | {counts[state]} |" for state in sorted(counts)]
    lines += ["", "## Lifecycle inventory", "", "| Job | Graph implemented | Binding | Readiness | Pool |",
              "|---|---:|---|---|---|"]
    for record in manifest.get("jobs", []):
        lines.append(f"| `{record['id']}` | {str(record['graph']['implemented']).lower()} | "
                     f"`{record['dagster']['lifecycle_binding']['kind']}` | `{record['readiness']}` | "
                     f"`{record['resource_pool']}` |")
    lines += ["", "## Explicit gaps", ""]
    lines += [f"- {gap}" for gap in result["gaps"]] or ["- None."]
    lines += ["", "## Validation errors", ""]
    lines += [f"- {error}" for error in result["errors"]] or ["- None."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--write-report", type=Path)
    parser.add_argument("--write-generated-views", action="store_true")
    args = parser.parse_args(argv)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    result = validate_manifest(manifest)
    report = render_report(manifest, result)
    if args.write_report:
        target = args.write_report if args.write_report.is_absolute() else REPO / args.write_report
        target.write_text(report, encoding="utf-8", newline="\n")
    if args.write_generated_views:
        generated = manifest["generated_views"]
        outputs = {"lifecycle_mermaid": render_mermaid(manifest),
                   "readiness_table": render_readiness(manifest)}
        for field, content in outputs.items():
            target = resolve_repo_path(generated[field])
            target.write_text(content, encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
