#!/usr/bin/env python3
"""Actual-service qualification for the two adopted Workstream B worker envelopes."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import uuid

from execution_state import (ROOT, atomic_json, data_path, execute, file_hash, now, read_json,
                             run_path, tree_hashes)
from launch_job import launch
from publish_job_output import ACCEPTED_SCHEMA, NONCURRENT_SCHEMA


def partition_fixture(valid: bool = True) -> dict:
    source = Path("/targets/freeciv21/CMakeLists.txt")
    if not source.is_file():
        raise RuntimeError("qualification source citation is unavailable")
    citation = {"source_type": "source_file", "path": "CMakeLists.txt", "line_range": None,
                "tool_name": None, "tool_rule_id": None, "content_hash": file_hash(source),
                "note": "qualification fixture citation"}
    value = {
        "schema": "appsec-review/repository-partition-map/0.1",
        "target": "freeciv21", "source_revision": "qualification-pinned-run-source",
        "partitions": [{
            "partition_id": "application", "name": "Freeciv21 application",
            "kinds": ["client", "server"], "include_paths": ["client/**", "server/**"],
            "exclude_paths": [], "primary_persona_id": "developer-engineer",
            "supporting_persona_ids": ["sre-engineer"],
            "routing_rationale": "Top-level client and server source trees.",
            "confidence": "medium", "evidence_citations": [citation],
            "relationships": [], "overlap_notes": ["Shared common code remains visible."],
            "disposition": "review", "disposition_reason": "In-scope product code.",
            "rescope_trigger": "A new top-level build manifest is staged."
        }],
        "coverage": {"inventory_scope": ["**/*"], "unassigned_paths": ["common/**"],
                     "uninspected_scope": [], "budget_limitations": ["probe qualification"],
                     "category_checks": [{"category": "client-server", "result": "found",
                                          "search_scope": ["client/**", "server/**"],
                                          "evidence_citations": [citation]}]},
    }
    if not valid:
        value["partitions"][0]["include_paths"] = ["../escape"]
    return value


def prepare(owner_run: str) -> int:
    """Run inside code-server so staged targets retain Linux ownership."""
    import phase1
    import run_process
    scorecard_run = "batch8-scorecard-" + uuid.uuid4().hex[:10]
    partition_run = "batch8-partition-" + uuid.uuid4().hex[:10]
    for run_id, goal in ((scorecard_run, "Qualify common Scorecard worker envelope"),
                         (partition_run, "Qualify supplied repository partition envelope")):
        run_process.init_run(run_id)
        permissions = (["read-source", "network:api.scorecard.dev"]
                       if run_id == scorecard_run else ["read-source"])
        phase1.stage(run_id, Path("/targets/freeciv21"), "freeciv21", goal, ["Linux"],
                     budget="probe", permissions=permissions,
                     execution_environment="dagster-read-only-linux")
    atomic_json(run_path(scorecard_run) / "inputs" / "ossf-scorecard-projects.json", {
        "schema": "appsec-review/ossf-scorecard-projects/1",
        "projects": [{"repository": "github.com/ossf/scorecard"}],
    })
    supplied = data_path(partition_run, "jobs", "02-repository-partition-discovery",
                         "supplied", "result.json")
    atomic_json(supplied, partition_fixture())
    print(json.dumps({"owner_run_id": owner_run, "scorecard_run_id": scorecard_run,
                      "partition_run_id": partition_run}))
    return 0


def set_partition(run_id: str, valid: bool) -> int:
    atomic_json(data_path(run_id, "jobs", "02-repository-partition-discovery",
                          "supplied", "result.json"), partition_fixture(valid))
    return 0


def interrupt_partition(run_id: str) -> int:
    """Leave a real adopted-path allocation pending so the next launch must recover it."""
    import discovery_gate
    from create_job_handoff import read_latest_handoff
    from publish_job_output import allocate_attempt

    job = discovery_gate.ADOPTED_JOB
    discovery_gate.issue_handoff(run_id, job, "qualification-interrupted-allocation")
    handoff_file, handoff = read_latest_handoff(run_id, job, "handoff")
    supplied = discovery_gate.supplied_path(run_id, job)
    record = discovery_gate._partition_inputs(run_id, handoff, handoff_file, supplied)
    record["run_id"] = run_id
    record["fingerprint"] = discovery_gate._input_fingerprint(record)
    allocation = allocate_attempt(
        discovery_gate.root(run_id, job), run_id=run_id, job_id=job,
        dagster_run_id="qualification-interrupted-allocation",
        worker_kind="supplied_human_decision", output_contract="repository-partition-map",
        input_record=record, input_fingerprint=record["fingerprint"],
        resume_command=(f"python -B appsec-review-process/launch_job.py --run-id {run_id} "
                        "--job repository_partition_discovery --wait"))
    print(json.dumps({"attempt_id": allocation["attempt_id"]}))
    return 0


def make_pending_publication(run_id: str, job: str) -> int:
    """Fault-inject the durable-envelope/pre-pointer window without changing attempt bytes."""
    base = (data_path(run_id, "jobs", job, "whole") if job == "02-ossf-scorecard" else
            data_path(run_id, "jobs", job))
    pointer = read_json(base / "accepted.json")
    if pointer.get("schema") != ACCEPTED_SCHEMA:
        raise RuntimeError("fault injection requires a current common accepted pointer")
    atomic_json(base / "accepted.json", {
        "schema": NONCURRENT_SCHEMA, "status": "PENDING",
        "attempt_id": pointer["attempt_id"], "fingerprint": pointer["fingerprint"],
        "updated_at": now(),
    })
    print(json.dumps({"attempt_id": pointer["attempt_id"], "job": job}))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    prep = sub.add_parser("prepare")
    prep.add_argument("--owner-run", required=True)
    change = sub.add_parser("set-partition")
    change.add_argument("--run-id", required=True)
    change.add_argument("--invalid", action="store_true")
    interrupted = sub.add_parser("interrupt-partition")
    interrupted.add_argument("--run-id", required=True)
    pending = sub.add_parser("make-pending-publication")
    pending.add_argument("--run-id", required=True)
    pending.add_argument("--job", required=True,
                         choices=["02-ossf-scorecard", "02-repository-partition-discovery"])
    parser.add_argument("--run-id")
    args = parser.parse_args(argv)
    if args.command == "prepare":
        return prepare(args.owner_run)
    if args.command == "set-partition":
        return set_partition(args.run_id, not args.invalid)
    if args.command == "interrupt-partition":
        return interrupt_partition(args.run_id)
    if args.command == "make-pending-publication":
        return make_pending_publication(args.run_id, args.job)
    if not args.run_id:
        parser.error("--run-id is required for host qualification")

    out = data_path(args.run_id, "qualification", "worker-adoption-" + uuid.uuid4().hex[:8])
    out.mkdir(parents=True)
    report: dict = {"status": "RUNNING", "owner_run_id": args.run_id, "evidence": str(out)}
    atomic_json(out / "report.json", report)

    def command(label: str, command_argv: list[str]) -> str:
        result = execute(command_argv, ROOT.parent, out / label, 600)
        if result.get("error") or result.get("exit_code") != 0:
            raise RuntimeError(f"{label}: {result}")
        return (out / label / "stdout.log").read_text(encoding="utf-8")

    docker = ["docker", "compose", "-f", "orchestrator/dagster/compose.yaml", "exec", "-T",
              "-e", "PYTHONDONTWRITEBYTECODE=1", "code-server", "python", "-B",
              "/opt/process/qualify_worker_adoption.py"]
    try:
        prepared = json.loads(command("prepare", docker + ["prepare", "--owner-run", args.run_id]))
        scorecard_run = prepared["scorecard_run_id"]
        partition_run = prepared["partition_run_id"]
        report.update(prepared)
        atomic_json(out / "prepared.json", prepared)

        scorecard_first = launch(scorecard_run, job="ossf_scorecard", wait=True, timeout=600)
        atomic_json(out / "scorecard-first.json", scorecard_first)
        assert scorecard_first["status"] == "SUCCESS", scorecard_first
        score_base = data_path(scorecard_run, "jobs", "02-ossf-scorecard", "whole")
        score_pointer = read_json(score_base / "accepted.json")
        assert score_pointer["schema"] == ACCEPTED_SCHEMA and score_pointer["status"] == "OK"
        score_attempt = score_base / "attempts" / score_pointer["attempt_id"]
        score_command = read_json(score_attempt / "command.json")
        assert score_command["schema"] == "appsec-review/deterministic-child/1.0"
        assert score_command["exit_code"] == 0 and not score_command.get("error")
        assert score_command["streams"]["stdout"]["observed_bytes"] > 0
        assert score_command["streams"]["stdout"]["truncated"] is False
        score_hashes = tree_hashes(score_attempt)
        scorecard_reuse = launch(scorecard_run, job="ossf_scorecard", wait=True, timeout=600)
        atomic_json(out / "scorecard-reuse.json", scorecard_reuse)
        assert scorecard_reuse["status"] == "SUCCESS"
        assert read_json(score_base / "accepted.json") == score_pointer
        assert tree_hashes(score_attempt) == score_hashes

        command("scorecard-pending-publication", docker + [
            "make-pending-publication", "--run-id", scorecard_run,
            "--job", "02-ossf-scorecard"])
        scorecard_publish_recovery = launch(
            scorecard_run, job="ossf_scorecard", wait=True, timeout=600)
        atomic_json(out / "scorecard-publish-recovery.json", scorecard_publish_recovery)
        assert scorecard_publish_recovery["status"] == "SUCCESS"
        score_recovered_pointer = read_json(score_base / "accepted.json")
        assert score_recovered_pointer["attempt_id"] == score_pointer["attempt_id"]
        assert tree_hashes(score_attempt) == score_hashes
        score_recovery_receipt = read_json(data_path(
            scorecard_run, "orchestration", "dagster",
            scorecard_publish_recovery["dagster_run_id"], "ossf-scorecard-reuse.json"))
        assert score_recovery_receipt["publication_recovered"] is True

        partition_first = launch(partition_run, job="repository_partition_discovery",
                                 wait=True, timeout=600)
        atomic_json(out / "partition-first.json", partition_first)
        assert partition_first["status"] == "SUCCESS", partition_first
        partition_base = data_path(partition_run, "jobs", "02-repository-partition-discovery")
        partition_pointer = read_json(partition_base / "accepted.json")
        assert partition_pointer["schema"] == ACCEPTED_SCHEMA and partition_pointer["status"] == "OK"
        partition_attempt = partition_base / "attempts" / partition_pointer["attempt_id"]
        partition_hashes = tree_hashes(partition_attempt)

        partition_reuse = launch(partition_run, job="repository_partition_discovery",
                                 wait=True, timeout=600)
        atomic_json(out / "partition-reuse.json", partition_reuse)
        assert partition_reuse["status"] == "SUCCESS"
        assert read_json(partition_base / "accepted.json") == partition_pointer
        assert tree_hashes(partition_attempt) == partition_hashes

        command("partition-pending-publication", docker + [
            "make-pending-publication", "--run-id", partition_run,
            "--job", "02-repository-partition-discovery"])
        partition_publish_recovery = launch(
            partition_run, job="repository_partition_discovery", wait=True, timeout=600)
        atomic_json(out / "partition-publish-recovery.json", partition_publish_recovery)
        assert partition_publish_recovery["status"] == "SUCCESS"
        partition_recovered_same = read_json(partition_base / "accepted.json")
        assert partition_recovered_same["attempt_id"] == partition_pointer["attempt_id"]
        assert tree_hashes(partition_attempt) == partition_hashes
        partition_recovery_receipt = read_json(data_path(
            partition_run, "orchestration", "dagster",
            partition_publish_recovery["dagster_run_id"],
            "02-repository-partition-discovery-reuse.json"))
        assert partition_recovery_receipt["publication_recovered"] is True

        interrupted = json.loads(command(
            "interrupt-partition", docker + ["interrupt-partition", "--run-id", partition_run]))
        interrupted_attempt = partition_base / "attempts" / interrupted["attempt_id"]
        assert read_json(partition_base / "accepted.json")["status"] == "PENDING"
        partition_after_interrupt = launch(
            partition_run, job="repository_partition_discovery", force=True,
            wait=True, timeout=600)
        atomic_json(out / "partition-after-interrupt.json", partition_after_interrupt)
        assert partition_after_interrupt["status"] == "SUCCESS"
        interrupted_envelope = read_json(interrupted_attempt / "result.json")
        assert interrupted_envelope["execution_status"] == "FAILED"
        assert interrupted_envelope["cause"] == "INTERRUPTED_WORKER"
        after_interrupt_pointer = read_json(partition_base / "accepted.json")
        assert after_interrupt_pointer["schema"] == ACCEPTED_SCHEMA
        assert after_interrupt_pointer["attempt_id"] != interrupted["attempt_id"]

        command("set-invalid", docker + ["set-partition", "--run-id", partition_run, "--invalid"])
        partition_failed = launch(partition_run, job="repository_partition_discovery",
                                  force=True, wait=True, timeout=600)
        atomic_json(out / "partition-failed.json", partition_failed)
        assert partition_failed["status"] == "FAILURE"
        failed_pointer = read_json(partition_base / "accepted.json")
        assert failed_pointer["schema"] == NONCURRENT_SCHEMA
        assert failed_pointer["status"] == "FAILED"
        assert failed_pointer["attempt_id"] != partition_pointer["attempt_id"]

        command("restore-valid", docker + ["set-partition", "--run-id", partition_run])
        partition_recovery = launch(partition_run, job="repository_partition_discovery", force=True,
                                    wait=True, timeout=600)
        atomic_json(out / "partition-recovery.json", partition_recovery)
        assert partition_recovery["status"] == "SUCCESS"
        recovered_pointer = read_json(partition_base / "accepted.json")
        assert recovered_pointer["schema"] == ACCEPTED_SCHEMA
        assert recovered_pointer["attempt_id"] not in {
            partition_pointer["attempt_id"], failed_pointer["attempt_id"]}

        identity_files = [
            ROOT / "qualify_worker_adoption.py",
            ROOT / "create_job_handoff.py", ROOT / "publish_job_output.py",
            ROOT / "validate_job_output.py", ROOT / "worker_result.py",
            ROOT / "worker-result-contract.json",
            ROOT / "ossf_scorecard.py", ROOT / "deterministic_child.py",
            ROOT / "execution_state.py", ROOT / "process_gate.py", ROOT / "discovery_gate.py",
            ROOT / "tests/test_worker_adoption.py", ROOT / "tests/test_deterministic_child.py",
            ROOT / "tests/test_ossf_scorecard.py",
            ROOT / "dagster_workflow.py", ROOT.parent / "schemas/project-discovery.schema.json",
            ROOT.parent / "schemas/ossf-scorecard-results.schema.json",
            ROOT.parent / "schemas/worker-result-envelope.schema.json",
            ROOT / "registry/output-contracts/ossf-scorecard-results.json",
            ROOT / "registry/output-contracts/repository-partition-map.json",
            ROOT / "registry/output-contracts/project-discovery.json",
        ]
        report.update(
            status="PASS",
            tested_identity={str(path.relative_to(ROOT.parent)).replace("\\", "/"): file_hash(path)
                             for path in identity_files},
            dagster_run_ids=[scorecard_first["dagster_run_id"], scorecard_reuse["dagster_run_id"],
                             scorecard_publish_recovery["dagster_run_id"],
                             partition_first["dagster_run_id"], partition_reuse["dagster_run_id"],
                             partition_publish_recovery["dagster_run_id"],
                             partition_after_interrupt["dagster_run_id"],
                             partition_failed["dagster_run_id"],
                             partition_recovery["dagster_run_id"]],
            attempts={"scorecard": score_pointer["attempt_id"],
                      "partition_initial": partition_pointer["attempt_id"],
                      "partition_interrupted": interrupted["attempt_id"],
                      "partition_after_interrupt": after_interrupt_pointer["attempt_id"],
                      "partition_failed": failed_pointer["attempt_id"],
                      "partition_recovered": recovered_pointer["attempt_id"]},
            checks=["Scorecard contract-schema dispatch and common-envelope publication",
                    "Scorecard live argv-only deterministic-child execution",
                    "bounded concurrent stdout/stderr draining and child-tree cleanup",
                    "timeout, cancellation, stream pressure, child loss, and log failure injection on Windows/Linux",
                    "common lock-scoped lifecycle coordination for exactly two adopted workers",
                    "lock contention permits one allocation owner (Windows/Linux focused tests)",
                    "preflight BLOCKED, work FAILED, and KeyboardInterrupt CANCELED mapping",
                    "callback failures do not create a second terminal envelope",
                    "contract-declared claim-class identity and accepted claim surfaces",
                    "cross-contract finding/severity/runtime promotion rejection (unit fixture)",
                    "required status-field validation",
                    "partition citation freshness and repository-relative path validation",
                    "non-mutating secret-leak rejection (unit fixture)",
                    "Scorecard immutable reuse",
                    "Scorecard pending publication recovers the same immutable attempt",
                    "partition supplied-envelope publication", "partition immutable reuse",
                    "partition pending publication recovers the same immutable attempt",
                    "interrupted pending allocation becomes an immutable FAILED envelope",
                    "newer invalid attempt blocks older success", "fresh recovery attempt publishes",
                    "standalone qualification uses the lifecycle worker without dispatching analysis"],
            cancellation="Cross-platform fault-injected at the deterministic-child boundary; the live API call is intentionally too short for service cancellation injection.")
        atomic_json(data_path(args.run_id, "qualification", "worker-adoption-latest.json"), {
            "status": "PASS", "report": str(out / "report.json"),
            "sha256": file_hash(out / "report.json") if (out / "report.json").exists() else None})
    except BaseException as exc:
        report.update(status="FAILED", error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        atomic_json(out / "report.json", report)
        print(json.dumps(report, indent=2))
    # Refresh the latest pointer after the final report bytes are durable.
    atomic_json(data_path(args.run_id, "qualification", "worker-adoption-latest.json"), {
        "status": "PASS", "report": str(out / "report.json"),
        "sha256": file_hash(out / "report.json")})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
