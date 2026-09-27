#!/usr/bin/env python3
"""Run the retained SBOM -> offline SCA -> CVE reachability happy path.

This qualification entry point does not synchronize vulnerability databases.  It consumes an
already registered Grype/OSV snapshot registry and a small run-owned target, then exercises the
same orchestration, B13 container, immutable publication, and accepted-upstream checks used by
the standalone dependency jobs.  Reachability defaults to ``unknown`` because a version match is
not reachability evidence.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _binding(jobs: Path, job: str, output: str) -> dict[str, str]:
    accepted_path = jobs / job / "accepted.json"
    accepted = _json(accepted_path)
    result = jobs / job / "attempts" / accepted["attempt_id"] / output
    return {"attempt_id": accepted["attempt_id"], "path": str(result), "sha256": _sha(result),
            "accepted_path": str(accepted_path)}


def _request(path: Path, *, run_id: str, job_id: str, generation: str, generated_at: str,
             payload: dict[str, Any], tool: dict[str, Any]) -> None:
    _write(path, {"schema": "appsec-review/dependency-orchestration-request/1.0",
                  "run_id": run_id, "job_id": job_id, "source_generation": generation,
                  "generated_at": generated_at, "payload": payload, "tool": tool})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--snapshot-registry", type=Path, required=True)
    parser.add_argument("--max-database-age-seconds", type=int, required=True)
    args = parser.parse_args()

    runs_root = args.runs_root.resolve()
    registry = args.snapshot_registry.resolve()
    run = runs_root / args.run_id
    target = run / "inputs" / "target"
    manifest = run / "inputs" / "artifact-manifest.json"
    if not target.is_dir() or target.is_symlink() or not manifest.is_file() or manifest.is_symlink():
        raise RuntimeError("qualification requires a run-owned target and artifact manifest")
    if not registry.is_dir() or registry.is_symlink():
        raise RuntimeError("qualification requires an existing offline snapshot registry")

    os.environ["APPSEC_RUNS_ROOT"] = str(runs_root)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import dependency_orchestration as orchestration

    generation = _sha(manifest)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    jobs = run / "data" / "jobs"
    source_files = {path.relative_to(target).as_posix(): _sha(path)
                    for path in sorted(target.rglob("*")) if path.is_file() and not path.is_symlink()}
    request_dir = run / "inputs" / "dependency-qualification"

    sbom_request = request_dir / "02-sbom-inventory.json"
    _request(sbom_request, run_id=args.run_id, job_id="02-sbom-inventory", generation=generation,
             generated_at=generated_at, payload={"source_files": source_files},
             tool={"target_path": str(target)})
    sbom_orchestration = jobs / "02-sbom-inventory" / "orchestration-attempts" / "live-1"
    orchestration.execute(job_id="02-sbom-inventory", run_id=args.run_id,
        input_path=str(sbom_request), output_root=str(jobs), attempt_root=str(sbom_orchestration))
    sbom = _binding(jobs, "02-sbom-inventory", "outputs/sbom-manifest.json")
    sbom_root = Path(sbom["path"]).parent

    sca_request = request_dir / "02-sca-vulnerability-match.json"
    _request(sca_request, run_id=args.run_id, job_id="02-sca-vulnerability-match", generation=generation,
             generated_at=generated_at, payload={"sbom": sbom},
             tool={"sbom_root": str(sbom_root), "snapshot_registry": str(registry),
                   "max_database_age_seconds": args.max_database_age_seconds})
    sca_orchestration = jobs / "02-sca-vulnerability-match" / "orchestration-attempts" / "live-1"
    orchestration.execute(job_id="02-sca-vulnerability-match", run_id=args.run_id,
        input_path=str(sca_request), output_root=str(jobs), attempt_root=str(sca_orchestration))
    sca = _binding(jobs, "02-sca-vulnerability-match", "outputs/sca-vulnerability-match.json")
    sca_document = _json(Path(sca["path"]))

    evidence_path = request_dir / "reachability-evidence.json"
    _write(evidence_path, {"assessments": [{"match_ref": row["match_id"],
        "classification": "unknown", "evidence": []} for row in sca_document["matches"]]})
    reachability_request = request_dir / "06-cve-reachability.json"
    _request(reachability_request, run_id=args.run_id, job_id="06-cve-reachability", generation=generation,
             generated_at=generated_at, payload={"sca": sca,
                 "reachability_evidence": str(evidence_path),
                 "reachability_evidence_sha256": _sha(evidence_path)}, tool={})
    reachability_orchestration = jobs / "06-cve-reachability" / "orchestration-attempts" / "live-1"
    orchestration.execute(job_id="06-cve-reachability", run_id=args.run_id,
        input_path=str(reachability_request), output_root=str(jobs), attempt_root=str(reachability_orchestration))
    reachability = _binding(jobs, "06-cve-reachability", "outputs/cve-reachability.json")
    reachability_document = _json(Path(reachability["path"]))
    sbom_document = _json(Path(sbom["path"]))
    database_document = _json(Path(sca["path"]).with_name("vulnerability-database-identities.json"))

    summary = {"schema": "appsec-review/dependency-offline-live-qualification/1.0",
        "run_id": args.run_id, "source_snapshot_sha256": generation, "generated_at": generated_at,
        "accepted": {"sbom": sbom, "sca": sca, "reachability": reachability},
        "counts": {"components": len(sbom_document["components"]),
                   "vulnerability_matches": len(sca_document["matches"]),
                   "reachability_assessments": len(reachability_document["assessments"]),
                   "reachability_gaps": len(reachability_document["coverage_gaps"])},
        "database_identities": database_document["databases"],
        "claim_ceiling": reachability_document["claim_ceiling"]}
    summary_path = run / "qualification" / "dependency-offline-live.json"
    _write(summary_path, summary)
    print(json.dumps({**summary, "summary_path": str(summary_path),
                      "summary_sha256": _sha(summary_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
