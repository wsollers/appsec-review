"""Orchestration adapter for the independently qualified bounded transforms.

The transform facades intentionally do not discover or assemble lifecycle inputs.  This adapter
therefore accepts one explicit, run-owned request, re-verifies every named accepted upstream through
the facade seam, and publishes only beneath the named job's canonical run-owned output root.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from execution_state import Blocked, beneath, data_path, file_hash, identifier, now, read_json, run_path
import deployment_hardening
import fuzz_target_triage
import native_memory_analysis
import owasp_validation_worklist
import stig_srg_validation_worklist

REQUEST_SCHEMA = "appsec-review/bounded-transform-request/1.0"
FACADES = {
    native_memory_analysis.JOB: (native_memory_analysis, "analyze", "units"),
    fuzz_target_triage.JOB: (fuzz_target_triage, "analyze", "targets"),
    owasp_validation_worklist.JOB: (owasp_validation_worklist, "build", "controls"),
    stig_srg_validation_worklist.JOB: (stig_srg_validation_worklist, "build", "controls"),
    deployment_hardening.JOB: (deployment_hardening, "analyze", "targets"),
}
_REQUEST_KEYS = {"schema", "run_id", "job_id", "source_generation", "upstream", "payload"}
_UPSTREAM_KEYS = {"pointer_path", "job_id", "contract", "artifact", "schema"}


def _run_owned(path_value: str, owner: Path, label: str) -> Path:
    if not isinstance(path_value, str) or not path_value:
        raise Blocked(f"bounded transform: {label} path is required")
    path = Path(path_value).absolute()
    try:
        return beneath(owner, path)
    except ValueError as exc:
        raise Blocked(f"bounded transform: {label} path is not run-owned") from exc


def execute(*, job_id: str, run_id: str, input_path: str, output_root: str,
            attempt_id: str) -> dict[str, Any]:
    """Execute one facade from an explicit request; no upstream facts are inferred."""
    if job_id not in FACADES:
        raise Blocked("bounded transform: unknown lifecycle job")
    run_id = identifier(run_id)
    attempt_id = identifier(attempt_id)
    owner = run_path(run_id).absolute()
    request_path = _run_owned(input_path, owner, "input")
    expected_output = data_path(run_id, "jobs", job_id).absolute()
    selected_output = _run_owned(output_root, owner, "output")
    if selected_output != expected_output:
        raise Blocked("bounded transform: output root is not the canonical job output root")
    if request_path.is_symlink() or not request_path.is_file():
        raise Blocked("bounded transform: input request is missing or linked")

    request = read_json(request_path)
    if not isinstance(request, dict) or set(request) != _REQUEST_KEYS:
        raise Blocked("bounded transform: request shape is not closed")
    if (request.get("schema") != REQUEST_SCHEMA or request.get("run_id") != run_id or
            request.get("job_id") != job_id):
        raise Blocked("bounded transform: request identity is invalid")
    manifest = owner / "inputs" / "artifact-manifest.json"
    if manifest.is_symlink() or not manifest.is_file():
        raise Blocked("bounded transform: run artifact manifest is unavailable")
    generation = "sha256:" + file_hash(manifest)
    if request.get("source_generation") != generation:
        raise Blocked("bounded transform: request source generation is stale")

    facade, function_name, payload_name = FACADES[job_id]
    upstream = request.get("upstream")
    if not isinstance(upstream, list) or not upstream:
        raise Blocked("bounded transform: at least one accepted upstream is required")
    bindings = []
    for item in upstream:
        if not isinstance(item, dict) or set(item) != _UPSTREAM_KEYS:
            raise Blocked("bounded transform: upstream request shape is not closed")
        pointer = _run_owned(item["pointer_path"], owner, "upstream")
        _, binding = facade.load_upstream(
            pointer, run_id=run_id, job_id=item["job_id"], contract=item["contract"],
            artifact=item["artifact"], schema=item["schema"])
        bindings.append(binding)

    payload = request.get("payload")
    # Standards worklists may also carry worklist-level summary gaps beside their controls.
    optional = {"gaps"} if payload_name == "controls" else set()
    if (not isinstance(payload, dict) or not {payload_name} <= set(payload) <= {payload_name} | optional or
            not all(isinstance(value, list) for value in payload.values())):
        raise Blocked(f"bounded transform: payload must contain only {payload_name}")
    started = now()
    result = getattr(facade, function_name)(
        run_id=run_id, attempt_id=attempt_id, source_generation=generation,
        bindings=bindings, **payload)
    return facade.publish_attempt(expected_output, result, started_at=started, finished_at=now())
