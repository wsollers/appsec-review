#!/usr/bin/env python3
"""Create a retained report-lifecycle demo, optionally through DEMO final approval.

This is a contract demonstration, not a target assessment.  The generated fixture finding and
family qualification index must never be represented as production security conclusions.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any

import completeness_audit
import control_process_worker
import demo_report_fixture
import draft_report_fixture_runner
from execution_state import Blocked, atomic_json, file_hash, tree_hashes
import final_publication
import synthetic_hypothesis_resynthesis

STAMP = "2026-01-01T00:00:00Z"
SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
FAMILIES = {
    "analysis": {
        "jobs": ["05-native-memory", "13-fuzz-target-triage", "04-owasp-validation-worklist",
                 "15-stig-srg-validation-worklist", "15-deployment-hardening"],
        "artifacts": ["bounded_analysis_workers.py", "bounded_transform_orchestration.py",
                      "tests/test_bounded_analysis_workers.py", "tests/test_bounded_transform_orchestration.py"]},
    "dependency": {
        "jobs": ["02-sbom-inventory", "02-sca-vulnerability-match", "02-license-scan",
                 "02-dependency-lifecycle", "06-cve-reachability"],
        "artifacts": ["dependency_workers.py", "dependency_b13_adapters.py", "dependency_orchestration.py",
                      "tests/test_dependency_workers.py", "tests/test_dependency_orchestration.py"]},
    "vendor": {
        "jobs": ["02-secrets-inventory", "02-iac-config-scan", "02-container-image-inventory",
                 "02-binary-hardening", "02-mobile-sast"],
        "artifacts": ["vendor_evidence_orchestration.py", "tests/test_vendor_evidence_workers.py",
                      "tests/test_vendor_evidence_b13.py", "tests/test_vendor_evidence_orchestration.py"]},
}


def _accepted(run_root: Path, run_id: str, job: str, attempt_id: str,
              contract: str, result_name: str) -> dict[str, str]:
    base, attempt = run_root / "data/jobs" / job, run_root / "data/jobs" / job / "attempts" / attempt_id
    envelope = json.loads((attempt / "result.json").read_text(encoding="utf-8"))
    pointer = {"schema": "appsec-review/accepted-worker-result/1.0", "status": "OK",
        "run_id": run_id, "job": job, "attempt_id": attempt_id,
        "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
        "envelope_sha256": file_hash(attempt / "result.json"), "hashes": tree_hashes(attempt),
        "accepted_at": "2026-01-01T00:00:02Z"}
    atomic_json(base / "accepted.json", pointer)
    atomic_json(base / "latest.json", {"attempt_id": attempt_id,
        "updated_at": "2026-01-01T00:00:02Z"})
    return {"job_id": job, "attempt_id": attempt_id, "contract_id": contract,
        "artifact_path": f"data/jobs/{job}/attempts/{attempt_id}/{result_name}",
        "artifact_sha256": "sha256:" + file_hash(attempt / result_name),
        "accepted_pointer_sha256": "sha256:" + file_hash(base / "accepted.json"),
        "permission_receipt_sha256": "sha256:" + file_hash(attempt / "permission.json"),
        "lineage_receipt_sha256": "sha256:" + file_hash(attempt / "lineage.json")}


def _supplemental_index(root: Path, run_id: str) -> dict[str, Any]:
    source = Path(__file__).resolve().parent
    families = []
    for family, record in FAMILIES.items():
        artifacts = [{"path": path, "sha256": "sha256:" + file_hash(source / path)}
                     for path in record["artifacts"]]
        families.append({"family": family, "jobs": record["jobs"], "qualification_artifacts": artifacts,
            "classification": "SUPPLEMENTAL_IMPLEMENTATION_AND_TEST_COVERAGE_ONLY",
            "report_effect": "NOT_A_FINDING_AND_NOT_VERIFIED_TARGET_EVIDENCE"})
    return {"schema": "appsec-review/demo-supplemental-family-qualification/1.0", "run_id": run_id,
        "demo": True, "families": families,
        "notice": "Hashes index qualification surfaces only; this demo does not execute scanners or promote them to findings."}


def _build(root: Path, run_id: str, *, authorization_key: bytes | None,
           ledger_anchor: str | None, reviewer_id: str | None) -> dict[str, Any]:
    demo_report_fixture.materialize(root, run_id)
    supplemental = _supplemental_index(root, run_id)
    atomic_json(root / "supplemental-family-qualification.json", supplemental)
    draft = draft_report_fixture_runner.run_fixture(root, run_id, "draft-1")
    result: dict[str, Any] = {"schema": "appsec-review/retained-happy-path-demo/1.0",
        "run_id": run_id, "demo": True, "status": "DRAFT_EVIDENCE_BACKED",
        "draft_path": "data/jobs/10-synthesis-report/attempts/draft-1",
        "supplemental_qualification_path": "supplemental-family-qualification.json",
        "final_path": None, "notice": "DEMO fixture lifecycle; not a production target assessment."}
    if authorization_key is None:
        atomic_json(root / "demo-index.json", result)
        return result

    assert ledger_anchor is not None and reviewer_id is not None
    draft_path = Path(draft["attempt_path"])
    report_sha = "sha256:" + file_hash(draft_path / "report.json")
    inputs = root / "demo-control-inputs"; inputs.mkdir()
    audit_input = inputs / "completeness-audit.json"
    atomic_json(audit_input, {"run_id": run_id, "subject_sha256": report_sha,
        "expected": [], "observed": [], "declared_gaps": []})
    audit_attempt = root / "data/jobs/completeness-audit/attempts/audit-1"
    completeness_audit.run_attempt(audit_input, audit_attempt, attempt_id="audit-1",
        source_snapshot_sha256=demo_report_fixture.SOURCE, started_at=STAMP,
        finished_at="2026-01-01T00:00:01Z")
    audit_ref = _accepted(root, run_id, "completeness-audit", "audit-1",
        "completeness-audit", "completeness-audit.json")
    audit = json.loads((audit_attempt / "completeness-audit.json").read_text(encoding="utf-8"))
    resynthesis_input = inputs / "synthetic-hypothesis-resynthesis.json"
    atomic_json(resynthesis_input, {"run_id": run_id, "audit": audit, "routes": {},
        "max_iterations": 1})
    feedback_attempt = root / "data/jobs/synthetic-hypothesis-resynthesis/attempts/feedback-1"
    synthetic_hypothesis_resynthesis.run_attempt(resynthesis_input, feedback_attempt,
        attempt_id="feedback-1", source_snapshot_sha256=demo_report_fixture.SOURCE,
        started_at=STAMP, finished_at="2026-01-01T00:00:01Z")
    feedback_ref = _accepted(root, run_id, "synthetic-hypothesis-resynthesis", "feedback-1",
        "synthetic-hypothesis-resynthesis", "synthetic-hypothesis-resynthesis.json")
    atomic_json(root / "completeness-ref.json", audit_ref)
    atomic_json(root / "feedback-ref.json", feedback_ref)

    demo_reviewer = "DEMO-OPERATOR:" + reviewer_id
    authorization = final_publication.sign_authorization(run_id=run_id, reviewer_id=demo_reviewer,
        report_sha256=report_sha, decision="APPROVED", issued_at="2026-01-01T00:59:00Z",
        authorization_id="DEMO-AUTHORIZATION-1", key=authorization_key)
    ledger = final_publication.append_signoff(None, run_id=run_id, reviewer_id=demo_reviewer,
        report_sha256=report_sha, decision="APPROVED", signed_at="2026-01-01T01:00:00Z",
        rationale="DEMO ONLY: operator authorized the retained fixture lifecycle demonstration.",
        authorization=authorization, authorization_key=authorization_key,
        expected_prior_head=ledger_anchor)
    atomic_json(root / "demo-human-signoff-ledger.json", ledger)
    final_publication.publish(draft_path, ledger, root / "final", run_root=root,
        completeness_ref=audit_ref, feedback_ref=feedback_ref, authorization_key=authorization_key,
        expected_ledger_anchor=ledger_anchor, expected_ledger_head=ledger["head_hash"])
    result.update(status="FINAL_APPROVED", final_path="final",
        signoff_path="demo-human-signoff-ledger.json", signoff_head=ledger["head_hash"])
    atomic_json(root / "demo-index.json", result)
    return result


def run(output_root: Path, run_id: str, *, authorization_key: bytes | None = None,
        ledger_anchor: str | None = None, reviewer_id: str | None = None) -> dict[str, Any]:
    """Build atomically and refuse any existing output root."""
    output_root = Path(output_root).absolute()
    if output_root.exists() or output_root.is_symlink():
        raise Blocked("retained demo: output root already exists")
    signing = (authorization_key is not None, ledger_anchor is not None, reviewer_id is not None)
    if any(signing) and not all(signing):
        raise Blocked("retained demo: key, ledger anchor, and reviewer are required together")
    if authorization_key is not None and len(authorization_key) < 32:
        raise Blocked("retained demo: operator-supplied authorization key must be at least 32 bytes")
    if ledger_anchor is not None and not SHA.fullmatch(ledger_anchor):
        raise Blocked("retained demo: supplied ledger anchor is not a sha256 value")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".retained-demo-", dir=output_root.parent))
    try:
        result = _build(staging, run_id, authorization_key=authorization_key,
                        ledger_anchor=ledger_anchor, reviewer_id=reviewer_id)
        os.replace(staging, output_root)
        return {**result, "output_root": str(output_root),
            "draft_path": str(output_root / result["draft_path"]),
            "supplemental_qualification_path": str(output_root / result["supplemental_qualification_path"]),
            "final_path": str(output_root / result["final_path"]) if result["final_path"] else None}
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--run-id", default="retained-demo")
    parser.add_argument("--authorization-key", type=Path,
        help="operator-supplied DEMO HMAC key file (>=32 bytes); omit to stop at draft")
    parser.add_argument("--ledger-anchor",
        help="operator-supplied trusted DEMO ledger anchor; required with --authorization-key")
    parser.add_argument("--demo-reviewer-id",
        help="operator identity, stored with a DEMO-OPERATOR prefix; required for final demo")
    args = parser.parse_args()
    key = args.authorization_key.read_bytes() if args.authorization_key else None
    result = run(args.output_root, args.run_id, authorization_key=key,
        ledger_anchor=args.ledger_anchor, reviewer_id=args.demo_reviewer_id)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
