#!/usr/bin/env python3
"""Publish one immutable, accepted 10-synthesis-report draft and presentation package."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
import tempfile
from typing import Any

from execution_state import Blocked, ROOT, atomic_json, digest, file_hash, read_json
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
import attack_chain_report as chain_report
import dependency_reachability_report as dep_report
import finding_enrichment as enrichment_core
import poc_fix_report as poc_report
import report_input_assembly as assembly
from schema_validate import validate_document
import synthesis_report as synthesis
import synthesis_report_presentation as presentation
import registry_paths

JOB = synthesis.JOB
CONTRACT = "synthesis-report-publication"
STANDALONE_REGISTRY = registry_paths.REGISTRY
STANDALONE_GRAPH = registry_paths.JOB_GRAPH
PERMISSIONS = ["read-run-data", "write-run-data"]
ARTIFACTS = [assembly.RESULT, synthesis.REPORT_JSON, synthesis.REPORT_MD, synthesis.APPENDIX,
    synthesis.TRACE, synthesis.PUBLICATION, enrichment_core.RESULT, chain_report.RESULT, poc_report.RESULT, dep_report.RESULT,
    presentation.RENDER_INPUT,
    presentation.RENDER_MANIFEST,
    *(f"presentation/{name}" for name in presentation.RENDERED),
    "permission.json", "lineage.json", "status.json"]
CODE_FILES = ("synthesis_report_worker.py", "synthesis_report_presentation.py", "synthesis_report.py",
    "report_input_assembly.py", "publish_job_output.py", "finding_enrichment.py", "reachability.py", "entry_exports.py",
    "cvss4.py", "cwe_catalog.py", "mitre_feed.py", "code_snippets.py", "epss_kev_snapshot.py",
    "attack_chain_report.py", "attack_chain_refute.py", "attack_chain_derive.py",
    "poc_fix_report.py", "poc_fix_denylist.py", "dependency_reachability_report.py",
    registry_paths.contract_rel("synthesis-report-publication"),
    registry_paths.template_rel("10-synthesis-report"), registry_paths.GRAPH_REL)
RENDER_FILES = ("pipeline/report/render.py", "pipeline/report/templates/report.tex.j2",
    "pipeline/report/templates/report.html.j2", "pipeline/report/templates/workbench.html.j2",
    "pipeline/report/templates/vendor/katex-0.16.11.css", "pipeline/report/templates/vendor/purify-3.4.16.min.js",
    "pipeline/report/latex/appsec-house.sty")


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def root(run_root: Path) -> Path:
    return Path(run_root) / "data" / "jobs" / JOB


def pointers(jobs_root: Path) -> dict[str, Path]:
    return {name: Path(jobs_root) / spec[0] / "accepted.json" for name, spec in assembly.SPECS.items()}


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    values.update({name: file_hash(ROOT.parent / name) for name in RENDER_FILES})
    return values


def current_inputs(run_id: str, jobs_root: Path) -> dict[str, Any]:
    accepted = {}
    for name, pointer in sorted(pointers(jobs_root).items()):
        loaded = assembly.load_accepted(pointer, run_id=run_id, name=name)
        accepted[name] = loaded["reference"]
    return {"run_id": run_id, "accepted": accepted, "implementation": _code_hashes(),
            "enrichment": enrichment_core.input_bindings(Path(jobs_root).parents[1]),
            "attack_chains": chain_report.input_binding(Path(jobs_root).parents[1]),
            "poc_fix": poc_report.input_binding(Path(jobs_root).parents[1]),
            "dependency_reachability": dep_report.input_binding(Path(jobs_root).parents[1])}


def _generator_sha256() -> str:
    return _sha(_code_hashes())


def _receipts(inputs: dict[str, Any], attempt: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    source = read_json(attempt / assembly.RESULT)["source_generation"]
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0",
        "run_id": inputs["run_id"], "job_id": JOB, "source_snapshot_sha256": source,
        "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0",
        "run_id": inputs["run_id"], "job_id": JOB, "source_snapshot_sha256": source,
        "build_lineage_sha256": _sha({"accepted": inputs["accepted"],
            "synthesis_input": "sha256:" + file_hash(attempt / assembly.RESULT),
            "report": "sha256:" + file_hash(attempt / synthesis.REPORT_JSON),
            "render": "sha256:" + file_hash(attempt / presentation.RENDER_MANIFEST)})}
    return permission, lineage


def _validate_attempt(attempt: Path, inputs: dict[str, Any], jobs_root: Path) -> None:
    if read_json(attempt / "inputs.json") != inputs or inputs["implementation"] != _code_hashes():
        raise Blocked(f"{JOB}: immutable inputs or implementation changed")
    if current_inputs(inputs["run_id"], jobs_root) != inputs:
        raise Blocked(f"{JOB}: accepted synthesis inputs changed")
    manifest = read_json(attempt / assembly.RESULT)
    errors = validate_document(manifest, "synthesis-input.schema.json")
    if errors:
        raise Blocked(f"{JOB}: retained synthesis input is invalid ({errors[0]})")
    loaded = synthesis.load_inputs(Path(jobs_root).parents[1], attempt / assembly.RESULT)
    report, trace = synthesis.build_report(loaded)
    if read_json(attempt / synthesis.REPORT_JSON) != report or read_json(attempt / synthesis.TRACE) != trace:
        raise Blocked(f"{JOB}: retained report differs from deterministic synthesis")
    expected_enrichment = enrichment_core.build(report, Path(jobs_root).parents[1])
    if read_json(attempt / enrichment_core.RESULT) != expected_enrichment:
        raise Blocked(f"{JOB}: retained finding enrichment differs from deterministic enrichment")
    expected_chains = chain_report.build(report, Path(jobs_root).parents[1])
    if read_json(attempt / chain_report.RESULT) != expected_chains:
        raise Blocked(f"{JOB}: retained attack-chain section differs from the accepted lane-14 ledger")
    expected_poc = poc_report.build(report, expected_enrichment, Path(jobs_root).parents[1])
    if read_json(attempt / poc_report.RESULT) != expected_poc:
        raise Blocked(f"{JOB}: retained PoC-and-fix section differs from the accepted lane-12b result")
    expected_reach = dep_report.build(report, Path(jobs_root).parents[1])
    if read_json(attempt / dep_report.RESULT) != expected_reach:
        raise Blocked(f"{JOB}: retained dependency-reachability section differs from the accepted 06 summary")
    expected_review = presentation.build_review(report, trace, expected_enrichment, expected_chains, expected_poc,
                                                expected_reach)
    if read_json(attempt / presentation.RENDER_INPUT) != expected_review:
        raise Blocked(f"{JOB}: retained renderer input differs from deterministic projection")
    render_manifest = read_json(attempt / presentation.RENDER_MANIFEST)
    errors = validate_document(render_manifest, "report-render-publication.schema.json")
    if errors:
        raise Blocked(f"{JOB}: render publication manifest is invalid ({errors[0]})")
    expected_render_bindings = {"run_id": report["run_id"], "status": synthesis.STATUS,
        "report_sha256": "sha256:" + file_hash(attempt / synthesis.REPORT_JSON),
        "trace_sha256": "sha256:" + file_hash(attempt / synthesis.TRACE),
        "render_input_sha256": "sha256:" + file_hash(attempt / presentation.RENDER_INPUT),
        "generator_sha256": _generator_sha256(), "final": False, "human_signoff": False}
    if any(render_manifest.get(key) != value for key, value in expected_render_bindings.items()):
        raise Blocked(f"{JOB}: render publication binding differs from the exact draft")
    if any("sha256:" + file_hash(attempt / item["path"]) != item["sha256"]
           for item in render_manifest["artifacts"]):
        raise Blocked(f"{JOB}: rendered presentation hash changed")
    with tempfile.TemporaryDirectory() as directory:
        check = Path(directory); atomic_json(check / presentation.RENDER_INPUT, expected_review)
        presentation._renderer().render(check / presentation.RENDER_INPUT, check / "presentation")
        presentation._compile_pdf(check / "presentation")
        if any(file_hash(check / "presentation" / name) !=
               file_hash(attempt / "presentation" / name) for name in presentation.RENDERED):
            raise Blocked(f"{JOB}: rendered presentation differs from the pinned templates")
    permission, lineage = _receipts(inputs, attempt)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: canonical receipts changed")


def _resume(run_root: Path, run_id: str, dagster_run_id: str) -> str:
    return shlex.join(["python", "-B", "appsec-review-process/synthesis_report_worker.py",
        "--run-root", str(Path(run_root).resolve()), "--run-id", run_id,
        "--dagster-run-id", dagster_run_id])


def run(run_root: Path, run_id: str, dagster_run_id: str, force: bool = False,
        attempt_id_factory=None) -> dict[str, Any]:
    run_root = Path(run_root); jobs_root = run_root / "data" / "jobs"; base = root(run_root)
    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        assembly.run(run_id, pointers(jobs_root), jobs_root, attempt / assembly.RESULT)
        synthesis.run(run_root, attempt / assembly.RESULT, attempt)
        report, trace = read_json(attempt / synthesis.REPORT_JSON), read_json(attempt / synthesis.TRACE)
        enrichment = enrichment_core.build(report, run_root)
        atomic_json(attempt / enrichment_core.RESULT, enrichment)
        chains = chain_report.build(report, run_root)
        atomic_json(attempt / chain_report.RESULT, chains)
        poc = poc_report.build(report, enrichment, run_root)
        atomic_json(attempt / poc_report.RESULT, poc)
        reach = dep_report.build(report, run_root)
        atomic_json(attempt / dep_report.RESULT, reach)
        presentation.render(report, trace, attempt, _generator_sha256(), enrichment, chains, poc, reach)
        permission, lineage = _receipts(inputs, attempt)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        gaps = sorted(set(report["limitations"]) | set(chains["gaps"]) | set(poc["gaps"]) | set(reach["gaps"]))
        status_name = "OK_WITH_GAPS" if gaps or report["unresolved_candidates"] else "OK"
        status = {"process": JOB, "status": status_name,
            "verified_findings": len(report["verified_findings"]),
            "unresolved_candidates": len(report["unresolved_candidates"]),
            "limitations": len(gaps), "attack_chains": len(chains["chains"]) + len(chains["appendix"]),
            "poc_fix_blocks": len(poc["by_claim"]),
            "dependency_reachability": reach["counts"],
            "final": False, "presentation": "HTML_LATEX_AND_PDF_RENDERED"}
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB,
            dagster_run_id=dagster_run_id, worker_kind="deterministic_python", output_contract=CONTRACT,
            input_fingerprint=fingerprint, started_at=allocation["started_at"],
            execution_status=status_name, summary="Evidence-backed draft report and bounded presentation published.",
            status_record=status, artifact_paths=ARTIFACTS, gaps=gaps,
            registry_root=STANDALONE_REGISTRY, graph_path=STANDALONE_GRAPH,
            pre_envelope_validate=lambda path, _status: _validate_attempt(path, inputs, jobs_root))
    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB,
        dagster_run_id=dagster_run_id, worker_kind="deterministic_python", output_contract=CONTRACT,
        resume_command=_resume(run_root, run_id, dagster_run_id),
        registry_root=STANDALONE_REGISTRY, graph_path=STANDALONE_GRAPH,
        derive_inputs=lambda: current_inputs(run_id, jobs_root), fingerprint_inputs=_sha,
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id,
            "preflight_error": f"{type(exc).__name__}: {exc}", "implementation": _code_hashes()},
        force=force, post_validate=lambda attempt, _envelope, inputs:
            _validate_attempt(attempt, inputs, jobs_root),
        blocked_summary="Exact accepted report inputs were unavailable or invalid.",
        failed_summary="Draft synthesis or bounded presentation failed.",
        attempt_id_factory=attempt_id_factory)


def validate(run_root: Path, run_id: str) -> Path:
    jobs_root = Path(run_root) / "data" / "jobs"; inputs = current_inputs(run_id, jobs_root)
    attempt, _ = validate_published(root(run_root), read_json(root(run_root) / "accepted.json"),
        _sha(inputs), expected_run_id=run_id, expected_job_id=JOB,
        registry_root=STANDALONE_REGISTRY, graph_path=STANDALONE_GRAPH)
    _validate_attempt(attempt, inputs, jobs_root)
    return attempt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True); parser.add_argument("--dagster-run-id", default="standalone-synthesis-report")
    parser.add_argument("--force", action="store_true"); args = parser.parse_args()
    print(json.dumps(run(args.run_root, args.run_id, args.dagster_run_id, args.force), indent=2))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
