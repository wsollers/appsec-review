#!/usr/bin/env python3
"""Compose accepted fixture producers into one immutable DRAFT_EVIDENCE_BACKED attempt."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import tempfile
from typing import Any

from execution_state import Blocked, atomic_json, digest, file_hash
import report_input_assembly as assembly
import synthesis_report as synthesis
from worker_result import artifact_records, terminal_envelope, validate_worker_result

ARTIFACTS = [assembly.RESULT, synthesis.REPORT_JSON, synthesis.REPORT_MD, synthesis.APPENDIX,
             synthesis.TRACE, synthesis.PUBLICATION, "permission.json", "lineage.json", "status.json"]


def _pointers(run_root: Path) -> dict[str, Path]:
    jobs = Path(run_root) / "data" / "jobs"
    return {name: jobs / spec[0] / "accepted.json" for name, spec in assembly.SPECS.items()}


def run_fixture(run_root: Path, run_id: str, attempt_id: str) -> dict[str, Any]:
    """Run the nominal composition once; an existing attempt is immutable and never reused."""
    run_root = Path(run_root)
    attempts = run_root / "data" / "jobs" / synthesis.JOB / "attempts"
    attempt = attempts / attempt_id
    if attempt.exists():
        raise Blocked(f"draft fixture: immutable attempt already exists: {attempt_id}")
    attempts.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".staging-{attempt_id}-", dir=attempts))
    pointers = _pointers(run_root)
    try:
        manifest_path = staging / assembly.RESULT
        assembly.run(run_id, pointers, run_root / "data" / "jobs", manifest_path)
        publication = synthesis.run(run_root, manifest_path, staging)
        if publication.get("status") != synthesis.STATUS or publication.get("final") is not False:
            raise Blocked("draft fixture: synthesis did not produce the required non-final draft")
        fingerprint = "sha256:" + digest({name: "sha256:" + file_hash(path)
                                          for name, path in sorted(pointers.items())})
        envelope = terminal_envelope(run_id=run_id, job_id=synthesis.JOB, attempt_id=attempt_id,
            worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
            input_fingerprint=fingerprint, output_contract=synthesis.CONTRACT,
            started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z",
            summary="Deterministic accepted-fixture DRAFT_EVIDENCE_BACKED report package.",
            artifacts=artifact_records(staging, ARTIFACTS))
        errors = validate_worker_result(envelope)
        if errors:
            raise Blocked(f"draft fixture: report attempt fails its common envelope ({errors[0]})")
        atomic_json(staging / "result.json", envelope)
        staging.rename(attempt)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    manifest_path = attempt / assembly.RESULT
    return {"run_id": run_id, "attempt_id": attempt_id, "status": synthesis.STATUS,
            "attempt_path": str(attempt), "input_manifest_sha256": "sha256:" + file_hash(manifest_path),
            "publication_manifest_sha256": "sha256:" + file_hash(attempt / synthesis.PUBLICATION),
            "result_envelope_sha256": "sha256:" + file_hash(attempt / "result.json"),
            "artifacts": ARTIFACTS + ["result.json"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt-id", required=True)
    args = parser.parse_args()
    print(json.dumps(run_fixture(args.run_root, args.run_id, args.attempt_id), indent=2))
