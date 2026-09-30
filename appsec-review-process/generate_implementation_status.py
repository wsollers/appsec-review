#!/usr/bin/env python3
"""Generate an evidence-based lifecycle implementation inventory.

This report is intentionally derived from the graph, design-parity manifest and
generated job catalog.  It does not turn qualification records into execution
claims for a new engagement.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import subprocess
from typing import Any
import registry_paths


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROCESS = ROOT / "appsec-review-process"


def load(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def retained_execution(run_root: pathlib.Path, job_id: str, downstream: list[str]) -> dict[str, Any]:
    """Return only facts retained by one run; absence never becomes a clean result."""
    base = run_root / "data" / "jobs" / job_id
    pointer_path = base / "accepted.json"
    empty = {"actual_run_attempt_id": None, "dagster_run_id": None,
        "accepted_pointer": None, "result_envelope": None, "execution_status": None,
        "applicability_decision": None, "skip_reason": None, "artifact_links": [],
        "hashes": {}, "lineage": None, "coverage": None, "gaps": ["no-retained-run-result"],
        "downstream_consumer": downstream, "appears_in_report": False}
    if not pointer_path.is_file():
        latest = base / "latest.json"
        if latest.is_file():
            try:
                attempt_id = load(latest).get("attempt_id")
                envelope_path = base / "attempts" / str(attempt_id) / "result.json"
                if envelope_path.is_file():
                    envelope = load(envelope_path)
                    empty.update(actual_run_attempt_id=attempt_id,
                        dagster_run_id=envelope.get("dagster_run_id"),
                        result_envelope=str(envelope_path), execution_status=envelope.get("execution_status"),
                        skip_reason=envelope.get("skip_reason"), gaps=envelope.get("gaps", []))
            except (OSError, ValueError, AttributeError):
                pass
        return empty
    try:
        pointer = load(pointer_path)
        attempt_id = pointer["attempt_id"]
        attempt = base / "attempts" / attempt_id
        envelope_path = attempt / pointer.get("envelope_path", "result.json")
        envelope = load(envelope_path)
        artifacts = [{"path": str(attempt / row["path"]), "sha256": row["sha256"]}
                     for row in envelope.get("artifacts", []) if isinstance(row, dict) and row.get("path")]
        applicability_path = attempt / "applicability.json"
        applicability = load(applicability_path) if applicability_path.is_file() else None
        lineage_path = attempt / "lineage.json"
        coverage = None
        status_path = attempt / "status.json"
        if status_path.is_file():
            status_record = load(status_path)
            coverage = status_record.get("coverage", status_record.get("coverage_summary"))
        report_trace = run_root / "data" / "jobs" / "10-synthesis-report" / "accepted.json"
        appears = False
        if report_trace.is_file():
            report_pointer = load(report_trace)
            trace_path = (run_root / "data" / "jobs" / "10-synthesis-report" / "attempts" /
                          report_pointer["attempt_id"] / "evidence-trace-index.json")
            if trace_path.is_file():
                trace = load(trace_path)
                appears = any(row.get("job_id") == job_id for row in trace.get("upstream", [])) or any(
                    row.get("producer_job_id") == job_id for row in trace.get("citations", []))
        return {"actual_run_attempt_id": attempt_id, "dagster_run_id": envelope.get("dagster_run_id"),
            "accepted_pointer": str(pointer_path), "result_envelope": str(envelope_path),
            "execution_status": envelope.get("execution_status"),
            "applicability_decision": applicability, "skip_reason": envelope.get("skip_reason"),
            "artifact_links": artifacts, "hashes": {"accepted_pointer_sha256": "sha256:" + sha256(pointer_path),
                "result_envelope_sha256": "sha256:" + sha256(envelope_path)},
            "lineage": ({"path": str(lineage_path), "sha256": "sha256:" + sha256(lineage_path)}
                        if lineage_path.is_file() else None),
            "coverage": coverage, "gaps": envelope.get("gaps", []),
            "downstream_consumer": downstream, "appears_in_report": appears}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {**empty, "gaps": ["retained-result-invalid:" + type(exc).__name__]}


def execution_status(value: str | None) -> str:
    return {"OK": "EXECUTED_OK", "OK_WITH_GAPS": "EXECUTED_WITH_GAPS",
            "SKIPPED": "SKIPPED_NA", "BLOCKED": "BLOCKED", "FAILED": "FAILED"}.get(
                value or "", "BLOCKED")


def status_for(readiness: str, binding: str, worker: str | None) -> str:
    if readiness == "implemented_and_qualified":
        return "INTEGRATED_QUALIFIED"
    if readiness in {"implemented_not_qualified", "supplied_artifact_gate"}:
        return "INTEGRATED_UNQUALIFIED"
    if readiness == "standalone_only":
        return "STANDALONE_ONLY"
    if not worker or worker == "none" or readiness == "missing_prerequisites":
        return "NOT_IMPLEMENTED"
    if binding == "blocked_op":
        return "CORE_ONLY"
    return "CORE_ONLY"


def automatic_input_state(binding: str, mode: str, worker: str | None) -> str:
    if binding == "blocked_op":
        return "NOT_CONSTRUCTED_FOR_FULL_REVIEW"
    if binding == "supplied_gate" or mode == "supplied_artifact":
        return "SUPPLIED_ARTIFACT_REQUIRED"
    if worker and worker != "none":
        return "LIFECYCLE_CONSTRUCTED"
    return "NOT_IMPLEMENTED"


def intended(job: dict[str, Any], catalog: dict[str, Any] | None) -> str:
    lane = (catalog or {}).get("lane") or "design capability"
    contract = (catalog or {}).get("contract") or job.get("output", {}).get("contract") or job["id"]
    consumes = ", ".join((catalog or {}).get("consumes", [])) or "declared upstream evidence"
    produces = ", ".join((catalog or {}).get("produces", [])) or "declared lifecycle output"
    return f"Execute {contract} in {lane}; consume {consumes}; publish {produces}."


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=("initial", "before-run", "after-run"))
    parser.add_argument("--output-dir", type=pathlib.Path, default=PROCESS)
    parser.add_argument("--validator-results", type=pathlib.Path)
    parser.add_argument("--run-root", type=pathlib.Path)
    args = parser.parse_args()

    graph_path = registry_paths.JOB_GRAPH
    parity_path = PROCESS / "design-parity-manifest.json"
    catalog_path = ROOT / "docs/processes/job-catalog.json"
    graph = load(graph_path)
    parity = load(parity_path)
    catalog = load(catalog_path)
    catalog_jobs = {item["id"]: item for item in catalog["lifecycle_jobs"]}
    parity_jobs = {item["id"]: item for item in parity["jobs"]}
    downstream: dict[str, list[str]] = {job_id: [] for job_id in graph["jobs"]}
    for job_id, record in graph["jobs"].items():
        for dep in record.get("dependencies", []):
            dep_id = dep if isinstance(dep, str) else dep.get("job") or dep.get("id")
            if dep_id in downstream:
                downstream[dep_id].append(job_id)

    features: list[dict[str, Any]] = []
    for job_id, graph_job in graph["jobs"].items():
        job = parity_jobs[job_id]
        cat = catalog_jobs.get(job_id)
        execution = job.get("execution", {})
        dagster = job.get("dagster", {})
        binding = dagster.get("lifecycle_binding", {})
        binding_kind = binding.get("kind", "none") if isinstance(binding, dict) else str(binding)
        worker = execution.get("worker")
        readiness = job.get("readiness", "missing_prerequisites")
        dependencies = graph_job.get("dependencies", [])
        upstream = [d if isinstance(d, str) else d.get("job") or d.get("id") for d in dependencies]
        implementation_files = [
            value
            for value in (
                worker,
                execution.get("validator"),
                job.get("output", {}).get("contract_file"),
                job.get("output", {}).get("schema_file"),
            )
            if value
        ]
        next_work = job.get("next_prerequisite") or "; ".join(job.get("gaps", [])) or "None recorded."
        common = "SUPPORTED"
        combined_gap = " ".join([next_work, *job.get("gaps", [])]).lower()
        if not worker or execution.get("mode") == "none":
            common = "NOT_IMPLEMENTED"
        elif "common-envelope" in combined_gap or "common envelope" in combined_gap or "migration" in combined_gap:
            common = "PARTIAL_OR_UNQUALIFIED"
        feature = {
                "feature_type": "lifecycle_job",
                "feature_job_id": job_id,
                "intended_design_behavior": intended(job, cat),
                "design_references": job.get("design_refs", []),
                "graph_implemented": bool(graph_job.get("implemented")),
                "implementation_files": implementation_files,
                "worker_type": execution.get("mode", "none"),
                "dagster_binding": {"kind": binding_kind, "entrypoint": binding.get("entrypoint") if isinstance(binding, dict) else None, "standalone_jobs": dagster.get("standalone_jobs", [])},
                "still_blocked_op": binding_kind == "blocked_op",
                "automatic_input_construction_status": automatic_input_state(binding_kind, execution.get("mode", "none"), worker),
                "upstream_bindings": upstream,
                "downstream_bindings": sorted(downstream[job_id]),
                "common_envelope_support": common,
                "permission_handling": job.get("permissions", []),
                "resource_pool": job.get("resource_pool", "unassigned"),
                "qualification_evidence": job.get("qualification", {}),
                "retained_live_run_evidence": {
                    "live_dagster_declared": "live_dagster" in job.get("qualification", {}).get("levels", []),
                    "references": job.get("qualification", {}).get("references", []),
                    "note": "Qualification references are not evidence that this fresh Hello engagement executed the feature.",
                },
                "current_honest_status": status_for(readiness, binding_kind, worker),
                "manifest_readiness": readiness,
                "exact_remaining_work": next_work,
                "implemented": bool(graph_job.get("implemented") and worker and worker != "none"),
                "integrated": bool(graph_job.get("implemented") and binding_kind not in {"none", "blocked_op"}),
                "automatically_supplied": automatic_input_state(binding_kind, execution.get("mode", "none"), worker) == "LIFECYCLE_CONSTRUCTED",
                "qualified": readiness == "implemented_and_qualified",
                "still_blocked": binding_kind == "blocked_op",
                "expected_to_execute_for_hello": True,
                "expected_to_publish_skipped_na": None,
            }
        if args.phase == "after-run":
            if args.run_root is None:
                parser.error("--run-root is required for --phase after-run")
            retained = retained_execution(args.run_root.resolve(), job_id, sorted(downstream[job_id]))
            feature["run_evidence"] = retained
            feature["current_honest_status"] = execution_status(retained["execution_status"])
            feature["exact_remaining_work"] = ("None recorded." if feature["current_honest_status"] == "EXECUTED_OK"
                                                else "; ".join(retained["gaps"]) or "Inspect retained result.")
        features.append(feature)

    for capability in parity.get("capabilities", []):
        readiness = capability.get("readiness", "missing_prerequisites")
        features.append(
            {
                "feature_type": "design_capability",
                "feature_job_id": capability["id"],
                "intended_design_behavior": f"Provide the {capability['id']} cross-cutting design capability for its declared lifecycle jobs.",
                "design_references": capability.get("design_refs", []),
                "graph_implemented": None,
                "implementation_files": capability.get("qualification", {}).get("references", []),
                "worker_type": capability.get("execution_mode", "none"),
                "dagster_binding": {"kind": "capability", "jobs": capability.get("jobs", [])},
                "still_blocked_op": readiness not in {"implemented_and_qualified", "implemented_not_qualified"},
                "automatic_input_construction_status": "CAPABILITY_DEPENDENT",
                "upstream_bindings": [],
                "downstream_bindings": capability.get("jobs", []),
                "common_envelope_support": "NOT_APPLICABLE" if capability["id"] != "common-worker-result-envelope" else "PARTIAL_OR_UNQUALIFIED",
                "permission_handling": [],
                "resource_pool": capability.get("resource_pool", "unassigned"),
                "qualification_evidence": capability.get("qualification", {}),
                "retained_live_run_evidence": {"references": capability.get("qualification", {}).get("references", []), "note": "No fresh Hello execution is claimed."},
                "current_honest_status": status_for(readiness, "capability", capability.get("execution_mode")),
                "manifest_readiness": readiness,
                "exact_remaining_work": capability.get("next_prerequisite") or "; ".join(capability.get("gaps", [])) or "None recorded.",
                "implemented": readiness != "missing_prerequisites",
                "integrated": readiness in {"implemented_and_qualified", "implemented_not_qualified"},
                "automatically_supplied": False,
                "qualified": readiness == "implemented_and_qualified",
                "still_blocked": readiness not in {"implemented_and_qualified", "implemented_not_qualified"},
                "expected_to_execute_for_hello": True,
                "expected_to_publish_skipped_na": None,
            }
        )

    validator_results = load(args.validator_results) if args.validator_results else []
    report = {
        "schema": "appsec-review/implementation-status/1.0",
        "phase": args.phase,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": {
            "branch": git("branch", "--show-current"),
            "head": git("rev-parse", "HEAD"),
            "status_porcelain": git("status", "--short"),
            "job_graph_sha256": sha256(graph_path),
            "design_parity_manifest_sha256": sha256(parity_path),
            "job_catalog_sha256": sha256(catalog_path),
        },
        "status_vocabulary": ["NOT_IMPLEMENTED", "CORE_ONLY", "STANDALONE_ONLY", "INTEGRATED_UNQUALIFIED", "INTEGRATED_QUALIFIED", "EXECUTED_OK", "EXECUTED_WITH_GAPS", "SKIPPED_NA", "BLOCKED", "FAILED"],
        "summary": {
            "lifecycle_jobs": len(graph["jobs"]),
            "design_capabilities": len(parity.get("capabilities", [])),
            "blocked_op_bindings": sorted(item["feature_job_id"] for item in features if item["feature_type"] == "lifecycle_job" and item["still_blocked_op"]),
        },
        "validator_results": validator_results,
        "features": features,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / f"implementation-status-{args.phase}.json"
    md_path = args.output_dir / f"implementation-status-{args.phase}.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = [
        f"# Implementation status: {args.phase}", "",
        f"Generated: `{report['generated_at']}`", "",
        f"Source: `{report['source']['branch']}` at `{report['source']['head']}`", "",
        f"Inventory: {report['summary']['lifecycle_jobs']} lifecycle jobs and {report['summary']['design_capabilities']} design capabilities.", "",
        f"Remaining `blocked_op` bindings: {len(report['summary']['blocked_op_bindings'])}.", "",
        "## Validator results", "",
    ]
    for result in validator_results:
        lines.append(f"- `{result['command']}`: **{result['status']}** (exit {result['exit_code']}) — {result.get('summary', '')}")
    lines.extend(["", "## Complete feature inventory", "", "| Feature | Type | Graph | Binding | Automatic inputs | Pool | Status | Exact remaining work |", "|---|---|---:|---|---|---|---|---|"])
    for item in features:
        remaining = str(item["exact_remaining_work"]).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{item['feature_job_id']}` | {item['feature_type']} | {item['graph_implemented']} | {item['dagster_binding']['kind']} | {item['automatic_input_construction_status']} | {item['resource_pool']} | **{item['current_honest_status']}** | {remaining} |")
    lines.extend(["", "The JSON companion contains implementation files, upstream/downstream bindings, envelope, permissions, qualification and retained-evidence fields for every row.", ""])
    md_path.write_text("\n".join(lines), encoding="utf-8")
    if args.phase == "after-run":
        initial_path = args.output_dir / "implementation-status-initial.json"
        before_path = args.output_dir / "implementation-status-before-run.json"
        if initial_path.is_file() and before_path.is_file():
            initial = {row["feature_job_id"]: row["current_honest_status"] for row in load(initial_path)["features"]}
            before = {row["feature_job_id"]: row["current_honest_status"] for row in load(before_path)["features"]}
            delta = ["# Implementation and execution status delta", "",
                "| Feature | Initial | Before run | After run |", "|---|---|---|---|"]
            for row in features:
                feature_id = row["feature_job_id"]
                delta.append(f"| `{feature_id}` | {initial.get(feature_id, 'NOT_IMPLEMENTED')} | {before.get(feature_id, 'NOT_IMPLEMENTED')} | {row['current_honest_status']} |")
            delta.extend(["", "Every after-run state above is derived from retained run evidence; absence is BLOCKED, never success.", ""])
            (args.output_dir / "implementation-status-delta.md").write_text("\n".join(delta), encoding="utf-8")
    print(json_path)
    print(md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
