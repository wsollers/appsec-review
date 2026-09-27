"""Focused nominal tests for the F02 evidence-assembly core."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import evidence_assembly as worker  # noqa: E402
from execution_state import Blocked, atomic_json, file_hash, read_json, tree_hashes  # noqa: E402
from worker_result import artifact_records, terminal_envelope  # noqa: E402

PLAN = read_json(ROOT / "tests" / "fixtures" / "evidence-assembly" / "complete-plan.json")


def instance_id(job):
    return hashlib.sha256(job.encode()).hexdigest()[:32]


def terminal_manifest(run_id, jobs):
    instances = []
    for ordinal, job in enumerate(jobs):
        iid = instance_id(job)
        instances.append({"instance_id": iid, "group_id": job[3:][:40], "ordinal": ordinal,
            "worker_kind": "pinned_container", "attempt_root": "instances/" + iid,
            "resource_pool": "tool_pool", "request_sha256": "sha256:" + "1" * 64,
            "input_fingerprint": "sha256:" + hashlib.sha256((job + "-input").encode()).hexdigest(),
            "state": "succeeded", "state_reason": "verified_adapter_result",
            "adapter_status": "OK", "adapter_cause": None,
            "result_file": {"path": f"instances/{iid}/logs/container/container-result.json",
                            "sha256": "sha256:" + hashlib.sha256(job.encode()).hexdigest(), "bytes": 100},
            "adapter_result_sha256": "sha256:" + hashlib.sha256((job + "-result").encode()).hexdigest(),
            "invoker_stopped": None, "container_removed": True, "worker_stopped": None})
    states = ["succeeded", "failed", "blocked", "canceled", "instance_timed_out",
              "rendezvous_timed_out", "crashed", "invalid", "not_launched_canceled",
              "not_launched_rendezvous_timeout", "missing"]
    value = {"schema": "appsec-review/pool-rendezvous-manifest/1.0",
        "classification": "appsec-review/pool-instance-classification/1.0",
        "expansion": "appsec-review/pool-expansion/1.0",
        "expansion_sha256": "sha256:" + "2" * 64, "spec_sha256": "sha256:" + "3" * 64,
        "pool_directory": "4" * 32, "pool_id": "evidence-assembly", "lane": "pregather",
        "run_id": run_id, "job_id": worker.JOB, "attempt_id": "terminal-generation-1",
        "wait_all": True, "rendezvous_timeout_seconds": 300, "empty_pool_reason": None,
        "expansion_state": "POPULATED", "outcome": "COMPLETE",
        "counts": {"instances": len(instances), **{state: len(instances) if state == "succeeded" else 0
                                                    for state in states}}, "instances": instances}
    value["manifest_sha256"] = worker.manifest_sha256(value)
    return value


def make_supply(folder, *, omit=(), duplicate=None, source_override=None, build_override=None,
                stale=None, corrupt=None):
    supply_root = Path(folder, "supply"); supply_root.mkdir()
    graph = read_json(worker.GRAPH)
    dependencies = graph["jobs"][worker.JOB]["dependencies"]
    jobs = [edge["job"] for edge in dependencies]
    atomic_json(supply_root / worker.TERMINAL, terminal_manifest(PLAN["run_id"], jobs))
    bindings = []
    for edge in dependencies:
        job = edge["job"]
        if job in omit:
            continue
        attempt_id = "attempt-" + hashlib.sha256(job.encode()).hexdigest()[:12]
        attempt = supply_root / "producers" / job / "attempts" / attempt_id
        permission = {"schema": worker.PERMISSION_SCHEMA, "run_id": PLAN["run_id"], "job_id": job,
            "source_snapshot_sha256": PLAN["source_snapshot_sha256"],
            "permissions": PLAN["permissions"]}
        atomic_json(attempt / "permission.json", permission)
        atomic_json(attempt / "lineage.json", {"schema": worker.LINEAGE_SCHEMA,
            "run_id": PLAN["run_id"], "job_id": job,
            "source_snapshot_sha256": PLAN["source_snapshot_sha256"],
            "build_lineage_sha256": PLAN["build_lineage_sha256"]})
        atomic_json(attempt / "evidence.json", {"producer": job, "evidence": "fixture-only"})
        status, skip_reason, gaps = "OK", None, []
        if job == PLAN["authorized_skip"]["job_id"]:
            status, skip_reason = "SKIPPED", PLAN["authorized_skip"]["reason"]
        if job == PLAN["gapped_job"]:
            status, gaps = "OK_WITH_GAPS", [PLAN["gap"]]
        artifacts = artifact_records(attempt, ["permission.json", "lineage.json", "evidence.json"])
        envelope = terminal_envelope(run_id=PLAN["run_id"], job_id=job, attempt_id=attempt_id,
            worker_kind="deterministic_python", execution_status=status, acceptance_status="CURRENT",
            input_fingerprint="sha256:" + hashlib.sha256((job + "-fingerprint").encode()).hexdigest(),
            output_contract=edge["contract"], started_at="2026-09-27T00:00:00Z",
            finished_at="2026-09-27T00:00:01Z", summary="fixture producer", artifacts=artifacts,
            gaps=gaps, skip_reason=skip_reason)
        atomic_json(attempt / "result.json", envelope)
        producer_root = supply_root / "producers" / job
        pointer = {"schema": "appsec-review/accepted-worker-result/1.0", "status": status,
            "run_id": PLAN["run_id"], "job": job, "attempt_id": attempt_id,
            "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
            "envelope_sha256": file_hash(attempt / "result.json"), "hashes": tree_hashes(attempt),
            "accepted_at": "2026-09-27T00:00:02Z"}
        atomic_json(producer_root / "accepted.json", pointer)
        atomic_json(producer_root / "latest.json", {"attempt_id": "stale-attempt" if stale == job else attempt_id})
        binding_source = source_override if source_override and source_override[0] == job else None
        binding_build = build_override if build_override and build_override[0] == job else None
        bindings.append({"job_id": job,
            "source_snapshot_sha256": binding_source[1] if binding_source else PLAN["source_snapshot_sha256"],
            "build_lineage_sha256": binding_build[1] if binding_build else PLAN["build_lineage_sha256"],
            "permissions": PLAN["permissions"], "terminal_instance_ids": [instance_id(job)]})
    if duplicate:
        bindings.append(copy.deepcopy(next(item for item in bindings if item["job_id"] == duplicate)))
    supply = {"schema": worker.SUPPLY_SCHEMA, "run_id": PLAN["run_id"],
              "source_snapshot_sha256": PLAN["source_snapshot_sha256"], "producers": bindings}
    atomic_json(supply_root / worker.SUPPLY, supply)
    if corrupt:
        path = supply_root / "producers" / corrupt / "attempts"
        attempt = next(path.iterdir())
        (attempt / "evidence.json").write_text('{"changed":true}\n')
    return supply_root


def reseal_producer(supply_root, job):
    producer = Path(supply_root, "producers", job)
    pointer = read_json(producer / "accepted.json")
    attempt = producer / "attempts" / pointer["attempt_id"]
    pointer["envelope_sha256"] = file_hash(attempt / "result.json")
    pointer["hashes"] = tree_hashes(attempt)
    atomic_json(producer / "accepted.json", pointer)


class EvidenceAssemblyTests(unittest.TestCase):
    def inspect(self, supply):
        return worker.inspect_supply(supply, run_id=PLAN["run_id"],
                                     source_snapshot_sha256=PLAN["source_snapshot_sha256"])

    def test_complete_manifest_is_deterministic_hash_bound_and_preserves_citation_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder)
            first, copies = self.inspect(supply)
            second, _ = self.inspect(supply)
            self.assertEqual(first, second)
            self.assertEqual(first["assembly_status"], "COMPLETE")
            self.assertEqual(first["manifest_sha256"], worker.manifest_sha256(first))
            self.assertEqual(len(first["producers"]), 25)
            self.assertEqual(len(copies), 76)
            artifact = first["producers"][0]["artifacts"][0]
            self.assertEqual(set(artifact), {"producer_job_id", "producer_attempt_id", "producer_path",
                                              "path", "sha256", "media_type"})
            skipped = next(item for item in first["producers"] if item["disposition"] == "authorized-skip")
            self.assertEqual(skipped["skip_reason"], PLAN["authorized_skip"]["reason"])
            self.assertTrue(any(gap["kind"] == "producer-gap" for gap in first["coverage_gaps"]))

    def test_missing_producer_is_explicit_but_incomplete_and_cannot_publish(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder, omit={"02-source-sast"})
            manifest, _ = self.inspect(supply)
            missing = next(item for item in manifest["producers"] if item["job_id"] == "02-source-sast")
            self.assertEqual(missing["disposition"], "missing")
            self.assertEqual(manifest["assembly_status"], "INCOMPLETE")
            job_root = Path(folder, "job")
            with mock.patch.object(worker, "root", return_value=job_root):
                with self.assertRaises(Blocked):
                    worker.run(PLAN["run_id"], "dagster-fixture", supply_root=supply,
                               source_snapshot_sha256=PLAN["source_snapshot_sha256"])
            pointer = read_json(job_root / "accepted.json")
            self.assertEqual(pointer["status"], "BLOCKED")
            self.assertFalse(any(job_root.glob("attempts/*/intel-manifest.json")))

    def test_complete_generation_publishes_common_envelope_and_copied_artifacts(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder)
            job_root = Path(folder, "job")
            with mock.patch.object(worker, "root", return_value=job_root):
                pointer = worker.run(PLAN["run_id"], "dagster-fixture", supply_root=supply,
                                     source_snapshot_sha256=PLAN["source_snapshot_sha256"])
            self.assertEqual(pointer["status"], "OK_WITH_GAPS")
            attempt = job_root / "attempts" / pointer["attempt_id"]
            manifest = read_json(attempt / worker.RESULT)
            self.assertEqual(manifest["assembly_status"], "COMPLETE")
            self.assertEqual(pointer["hashes"], tree_hashes(attempt))
            for producer in manifest["producers"]:
                for artifact in producer["artifacts"]:
                    self.assertEqual("sha256:" + file_hash(attempt / artifact["path"]), artifact["sha256"])

    def test_corrupt_artifact_and_stale_pointer_fail_closed(self):
        for variant in ("corrupt", "stale"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as folder:
                kwargs = {variant: "02-source-sast"}
                supply = make_supply(folder, **kwargs)
                with self.assertRaises(Blocked):
                    self.inspect(supply)

    def test_mixed_source_or_build_generation_fails_closed(self):
        cases = (
            {"source_override": ("02-source-sast", "sha256:" + "c" * 64)},
            {"build_override": ("02-source-sast", "sha256:" + "d" * 64)},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as folder:
                supply = make_supply(folder, **kwargs)
                with self.assertRaises(Blocked):
                    self.inspect(supply)

    def test_duplicate_producer_binding_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder, duplicate="02-source-sast")
            with self.assertRaises(Blocked):
                self.inspect(supply)

    def test_unauthorized_skip_and_permission_mismatch_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder)
            job = PLAN["authorized_skip"]["job_id"]
            producer = supply / "producers" / job
            pointer = read_json(producer / "accepted.json")
            envelope_path = producer / "attempts" / pointer["attempt_id"] / "result.json"
            envelope = read_json(envelope_path); envelope["skip_reason"] = "not-requested"
            atomic_json(envelope_path, envelope); reseal_producer(supply, job)
            with self.assertRaises(Blocked):
                self.inspect(supply)
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder)
            config = read_json(supply / worker.SUPPLY)
            config["producers"][0]["permissions"] = ["network"]
            atomic_json(supply / worker.SUPPLY, config)
            with self.assertRaises(Blocked):
                self.inspect(supply)

    def test_terminal_manifest_hash_and_unclaimed_instance_prevent_complete_publication(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder)
            terminal = read_json(supply / worker.TERMINAL)
            terminal["counts"]["succeeded"] -= 1
            atomic_json(supply / worker.TERMINAL, terminal)
            with self.assertRaises(Blocked):
                self.inspect(supply)
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder)
            terminal = read_json(supply / worker.TERMINAL)
            terminal["instances"][0].update(state="failed", adapter_status="FAILED",
                                               adapter_cause="CONTAINER_EXIT_NONZERO")
            terminal["counts"]["succeeded"] -= 1; terminal["counts"]["failed"] += 1
            terminal["outcome"] = "DEGRADED"
            terminal["manifest_sha256"] = worker.manifest_sha256(terminal)
            atomic_json(supply / worker.TERMINAL, terminal)
            with self.assertRaises(Blocked):
                self.inspect(supply)
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder)
            config = read_json(supply / worker.SUPPLY)
            config["producers"][0]["terminal_instance_ids"] = [config["producers"][1]["terminal_instance_ids"][0]]
            atomic_json(supply / worker.SUPPLY, config)
            with self.assertRaises(Blocked):
                self.inspect(supply)


if __name__ == "__main__":
    unittest.main()
