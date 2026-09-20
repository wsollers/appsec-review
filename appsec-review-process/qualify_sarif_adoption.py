#!/usr/bin/env python3
"""Actual-service qualification for the adopted critical-findings SARIF worker envelope.

Batch B09 changes this worker's executable identity: it now runs through the common lifecycle
coordinator, the v1.0 worker-result envelope, the read-only validation/publication boundary and
the ``appsec-review/deterministic-child/1.0`` sub-contract. That requires one bounded live Dagster
success, reuse, publication-recovery, interrupted-attempt, newer-failure and recovery sequence.

Host entry point (run from the repository root, with the Dagster stack healthy and no active run):

```text
python -B appsec-review-process/qualify_sarif_adoption.py --run-id <owner_run_id>
```

The ``prepare``/``set-input``/``interrupt``/``make-pending-publication`` subcommands are executed
inside the Linux code-server by the host sequence; they are not operator entry points.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import uuid

from execution_state import (ROOT, atomic_bytes, atomic_json, data_path, execute, file_hash, now,
                             read_json, run_path, tree_hashes)
from publish_job_output import ACCEPTED_SCHEMA, NONCURRENT_SCHEMA

JOB_ID = "10-critical-findings-sarif"
DAGSTER_JOB = "critical_findings_sarif"
INPUT_NAME = "critical-findings.md"

FIXTURE = """---
id: CRIT-QUALIFY-001
title: Qualification fixture finding
severity: High
status: Open
component: qualification
location: CMakeLists.txt:1
category: appsec-review
cwe: CWE-862
asvs: null
data_classes: []
regulatory: []
cve: []
confidence: Confirmed
discovered_by: independent-verification
---
### Description
Synthetic qualification finding; it is not a verified product finding.

### Evidence
- Origin lane: qualification fixture for the common SARIF runtime adoption

### Impact
None. This record exists only to exercise the bounded transform.

### Remediation
No remediation is implied by this fixture.
"""
INVALID_FIXTURE = FIXTURE.replace("severity: High", "severity: Catastrophic")


def job_base(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB_ID, "whole")


def stage_input(run_id: str, valid: bool = True) -> Path:
    path = run_path(run_id) / "inputs" / INPUT_NAME
    atomic_bytes(path, (FIXTURE if valid else INVALID_FIXTURE).encode("utf-8"))
    return path


def prepare(owner_run: str) -> int:
    """Run inside code-server so the staged run retains Linux ownership."""
    import phase1
    import run_process

    sarif_run = "b09-sarif-" + uuid.uuid4().hex[:10]
    run_process.init_run(sarif_run)
    phase1.stage(sarif_run, Path("/targets/freeciv21"), "freeciv21",
                 "Qualify common critical-findings SARIF worker envelope", ["Linux"],
                 budget="probe", permissions=["read-source"],
                 execution_environment="dagster-read-only-linux")
    source = stage_input(sarif_run)
    print(json.dumps({"owner_run_id": owner_run, "sarif_run_id": sarif_run,
                      "source_sha256": file_hash(source)}))
    return 0


def set_input(run_id: str, valid: bool) -> int:
    source = stage_input(run_id, valid)
    print(json.dumps({"run_id": run_id, "valid": valid, "source_sha256": file_hash(source)}))
    return 0


def interrupt(run_id: str) -> int:
    """Leave a real adopted-path allocation pending so the next launch must recover it."""
    import critical_findings_sarif as sarif
    from publish_job_output import allocate_attempt

    record = sarif.current_inputs(run_id)
    allocation = allocate_attempt(
        job_base(run_id), run_id=run_id, job_id=JOB_ID,
        dagster_run_id="qualification-interrupted-allocation",
        worker_kind=sarif.WORKER_KIND, output_contract=sarif.OUTPUT_CONTRACT,
        input_record=record, input_fingerprint=sarif.input_fingerprint(record),
        resume_command=(f"python -B appsec-review-process/launch_job.py --run-id {run_id} "
                        f"--job {DAGSTER_JOB} --wait"))
    print(json.dumps({"attempt_id": allocation["attempt_id"]}))
    return 0


def make_pending_publication(run_id: str) -> int:
    """Fault-inject the durable-envelope/pre-pointer window without changing attempt bytes."""
    base = job_base(run_id)
    pointer = read_json(base / "accepted.json")
    if pointer.get("schema") != ACCEPTED_SCHEMA:
        raise RuntimeError("fault injection requires a current common accepted pointer")
    atomic_json(base / "accepted.json", {
        "schema": NONCURRENT_SCHEMA, "status": "PENDING", "attempt_id": pointer["attempt_id"],
        "fingerprint": pointer["fingerprint"], "updated_at": now(),
    })
    print(json.dumps({"attempt_id": pointer["attempt_id"], "job": JOB_ID}))
    return 0


def qualify(owner_run: str) -> int:
    """Host sequence: one bounded live success, reuse, recovery, failure and recovery."""
    from launch_job import launch

    out = data_path(owner_run, "qualification", "sarif-adoption-" + uuid.uuid4().hex[:8])
    out.mkdir(parents=True)
    report: dict = {"status": "RUNNING", "owner_run_id": owner_run, "job": JOB_ID,
                    "evidence": str(out)}
    atomic_json(out / "report.json", report)

    def command(label: str, command_argv: list[str]) -> str:
        result = execute(command_argv, ROOT.parent, out / label, 600)
        if result.get("error") or result.get("exit_code") != 0:
            raise RuntimeError(f"{label}: {result}")
        return (out / label / "stdout.log").read_text(encoding="utf-8")

    docker = ["docker", "compose", "-f", "orchestrator/dagster/compose.yaml", "exec", "-T",
              "-e", "PYTHONDONTWRITEBYTECODE=1", "code-server", "python", "-B",
              "/opt/process/qualify_sarif_adoption.py"]
    try:
        prepared = json.loads(command("prepare", docker + ["prepare", "--owner-run", owner_run]))
        sarif_run = prepared["sarif_run_id"]
        report.update(prepared)
        atomic_json(out / "prepared.json", prepared)
        base = job_base(sarif_run)

        first = launch(sarif_run, job=DAGSTER_JOB, wait=True, timeout=600)
        atomic_json(out / "sarif-first.json", first)
        assert first["status"] == "SUCCESS", first
        pointer = read_json(base / "accepted.json")
        assert pointer["schema"] == ACCEPTED_SCHEMA and pointer["status"] == "OK", pointer
        attempt = base / "attempts" / pointer["attempt_id"]
        envelope = read_json(attempt / "result.json")
        assert envelope["acceptance_status"] == "CURRENT"
        assert envelope["output_contract"] == "critical-findings-sarif"
        assert envelope["worker_kind"] == "deterministic_python"
        child = read_json(attempt / "command.json")
        assert child["schema"] == "appsec-review/deterministic-child/1.0", child
        assert child["exit_code"] == 0 and not child.get("error"), child
        assert child["argv"][:4] == child["argv_prefix"], child
        assert child["streams"]["stdout"]["observed_bytes"] > 0
        assert child["streams"]["stdout"]["truncated"] is False
        assert child["streams"]["stderr"]["observed_bytes"] == 0
        manifest = read_json(attempt / "manifest.json")
        assert manifest["sarif_sha256"] == file_hash(
            attempt / "outputs" / "critical-findings.sarif")
        hashes = tree_hashes(attempt)

        reuse = launch(sarif_run, job=DAGSTER_JOB, wait=True, timeout=600)
        atomic_json(out / "sarif-reuse.json", reuse)
        assert reuse["status"] == "SUCCESS"
        assert read_json(base / "accepted.json") == pointer
        assert tree_hashes(attempt) == hashes

        command("pending-publication", docker + ["make-pending-publication",
                                                "--run-id", sarif_run])
        publish_recovery = launch(sarif_run, job=DAGSTER_JOB, wait=True, timeout=600)
        atomic_json(out / "sarif-publish-recovery.json", publish_recovery)
        assert publish_recovery["status"] == "SUCCESS"
        recovered_pointer = read_json(base / "accepted.json")
        assert recovered_pointer["attempt_id"] == pointer["attempt_id"]
        assert tree_hashes(attempt) == hashes
        receipt = read_json(data_path(sarif_run, "orchestration", "dagster",
                                      publish_recovery["dagster_run_id"],
                                      "critical-findings-sarif-reuse.json"))
        assert receipt["publication_recovered"] is True, receipt

        interrupted = json.loads(command("interrupt", docker + ["interrupt",
                                                                "--run-id", sarif_run]))
        assert read_json(base / "accepted.json")["status"] == "PENDING"
        after_interrupt = launch(sarif_run, job=DAGSTER_JOB, force=True, wait=True, timeout=600)
        atomic_json(out / "sarif-after-interrupt.json", after_interrupt)
        assert after_interrupt["status"] == "SUCCESS"
        interrupted_envelope = read_json(
            base / "attempts" / interrupted["attempt_id"] / "result.json")
        assert interrupted_envelope["execution_status"] == "FAILED"
        assert interrupted_envelope["cause"] == "INTERRUPTED_WORKER"
        after_pointer = read_json(base / "accepted.json")
        assert after_pointer["schema"] == ACCEPTED_SCHEMA
        assert after_pointer["attempt_id"] not in {pointer["attempt_id"],
                                                   interrupted["attempt_id"]}

        command("set-invalid", docker + ["set-input", "--run-id", sarif_run, "--invalid"])
        failed_launch = launch(sarif_run, job=DAGSTER_JOB, force=True, wait=True, timeout=600)
        atomic_json(out / "sarif-failed.json", failed_launch)
        assert failed_launch["status"] == "FAILURE", failed_launch
        failed_pointer = read_json(base / "accepted.json")
        assert failed_pointer["schema"] == NONCURRENT_SCHEMA
        assert failed_pointer["status"] in {"BLOCKED", "FAILED"}, failed_pointer
        assert failed_pointer["attempt_id"] != after_pointer["attempt_id"]

        command("restore-valid", docker + ["set-input", "--run-id", sarif_run])
        recovery = launch(sarif_run, job=DAGSTER_JOB, force=True, wait=True, timeout=600)
        atomic_json(out / "sarif-recovery.json", recovery)
        assert recovery["status"] == "SUCCESS"
        final_pointer = read_json(base / "accepted.json")
        assert final_pointer["schema"] == ACCEPTED_SCHEMA and final_pointer["status"] == "OK"
        assert final_pointer["attempt_id"] not in {pointer["attempt_id"],
                                                   after_pointer["attempt_id"],
                                                   failed_pointer["attempt_id"]}

        identity_files = [
            ROOT / "qualify_sarif_adoption.py", ROOT / "critical_findings_sarif.py",
            ROOT / "deterministic_child.py", ROOT / "publish_job_output.py",
            ROOT / "validate_job_output.py", ROOT / "worker_result.py",
            ROOT / "worker-result-contract.json", ROOT / "execution_state.py",
            ROOT / "process_gate.py", ROOT / "dagster_workflow.py",
            ROOT / "tests/test_critical_findings_sarif.py",
            ROOT / "tests/test_worker_adoption.py", ROOT / "tests/test_deterministic_child.py",
            ROOT / "registry/job-templates/10-critical-findings-sarif.json",
            ROOT / "registry/output-contracts/critical-findings-sarif.json",
            ROOT.parent / "schemas/critical-findings-sarif.schema.json",
            ROOT.parent / "schemas/worker-result-envelope.schema.json",
        ]
        report.update(
            status="PASS",
            sarif_run_id=sarif_run,
            tested_identity={str(path.relative_to(ROOT.parent)).replace("\\", "/"): file_hash(path)
                             for path in identity_files},
            dagster_run_ids=[first["dagster_run_id"], reuse["dagster_run_id"],
                             publish_recovery["dagster_run_id"],
                             after_interrupt["dagster_run_id"], failed_launch["dagster_run_id"],
                             recovery["dagster_run_id"]],
            attempts={"initial": pointer["attempt_id"],
                      "interrupted": interrupted["attempt_id"],
                      "after_interrupt": after_pointer["attempt_id"],
                      "failed": failed_pointer["attempt_id"],
                      "recovered": final_pointer["attempt_id"]},
            source_sha256=manifest["source_sha256"],
            sarif_sha256=manifest["sarif_sha256"],
            checks=["live common-envelope publication of the standalone SARIF transform",
                    "live argv-only deterministic-child execution with separate bounded streams",
                    "immutable reuse of the accepted attempt",
                    "pending publication recovers the same immutable attempt",
                    "interrupted pending allocation becomes an immutable FAILED envelope",
                    "newer invalid attempt blocks the older accepted success",
                    "fresh recovery attempt publishes a new immutable attempt",
                    "no synthesis binding: the standalone job remains independent"])
    except BaseException as exc:
        report.update(status="FAILED", error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        atomic_json(out / "report.json", report)
        print(json.dumps(report, indent=2))
    # Refresh the latest pointer only after the final report bytes are durable.
    atomic_json(data_path(owner_run, "qualification", "sarif-adoption-latest.json"), {
        "status": "PASS", "report": str(out / "report.json"),
        "sha256": file_hash(out / "report.json")})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    prep = sub.add_parser("prepare")
    prep.add_argument("--owner-run", required=True)
    change = sub.add_parser("set-input")
    change.add_argument("--run-id", required=True)
    change.add_argument("--invalid", action="store_true")
    interrupted = sub.add_parser("interrupt")
    interrupted.add_argument("--run-id", required=True)
    pending = sub.add_parser("make-pending-publication")
    pending.add_argument("--run-id", required=True)
    parser.add_argument("--run-id")
    args = parser.parse_args(argv)
    if args.command == "prepare":
        return prepare(args.owner_run)
    if args.command == "set-input":
        return set_input(args.run_id, not args.invalid)
    if args.command == "interrupt":
        return interrupt(args.run_id)
    if args.command == "make-pending-publication":
        return make_pending_publication(args.run_id)
    if not args.run_id:
        parser.error("--run-id is required for host qualification")
    return qualify(args.run_id)


if __name__ == "__main__":
    raise SystemExit(main())
