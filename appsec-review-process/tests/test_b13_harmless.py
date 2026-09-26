"""Phase 3: the real Dagster-facing harmless B13 worker and its fail-closed lifecycle."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import b13_harmless as worker  # noqa: E402
import container_execution as ce  # noqa: E402
import execution_state as state  # noqa: E402
from publish_job_output import ACCEPTED_SCHEMA, NONCURRENT_SCHEMA  # noqa: E402
from test_container_execution import ScriptedDocker  # noqa: E402


class HarmlessWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.owner = Path(self.temp.name)
        self.old_runs = state.RUNS
        state.RUNS = self.owner / "runs"
        self.run_id = "phase3-harmless"
        inputs = state.RUNS / self.run_id / "inputs"
        inputs.mkdir(parents=True)
        state.atomic_json(inputs / "artifact-manifest.json", {
            "schema": "appsec-review-process/artifact-manifest/0.1",
            "orchestration_version": 1, "run_id": self.run_id,
            "intake_config": {"executor_platform": "posix"},
            "target": {"repo_path": str(self.owner / "unused-target")},
        })
        worker.stage_control(self.run_id)
        self.clock = mock.patch.object(worker, "_utc_now", return_value="2026-09-20T12:00:00Z")
        self.clock.start()

    def tearDown(self):
        self.clock.stop()
        state.RUNS = self.old_runs
        self.temp.cleanup()

    def run_scripted(self, dagster="dagster-1", scripted=None, **kwargs):
        scripted = scripted or ScriptedDocker()
        first, second = scripted.patches()
        with first, second:
            return worker.run(self.run_id, dagster, **kwargs)

    def test_success_publishes_verified_envelope_and_reuses_immutably(self):
        first = self.run_scripted()
        self.assertEqual(first["schema"], ACCEPTED_SCHEMA)
        attempt = worker.validate(self.run_id, first)
        receipt = state.read_json(attempt / worker.RECEIPT_FILE)
        adapter_result = state.read_json(attempt / "logs/container/container-result.json")
        self.assertEqual(receipt["expected_result_sha256"], adapter_result["result_sha256"])
        self.assertEqual(receipt["image_reference"], worker.current_inputs(self.run_id)["image"]["reference"])
        self.assertEqual(state.read_json(attempt / "result.json")["worker_kind"], "pinned_container")
        second = worker.run(self.run_id, "dagster-reuse")
        self.assertEqual(first, second)
        self.assertEqual(len(list((worker.root(self.run_id) / "attempts").iterdir())), 1)

    def test_caller_hash_rejects_a_self_consistently_resealed_adapter_result(self):
        def tamper(attempt, _request, _expected):
            path = attempt / "logs/container/container-result.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["finished_at"] = "2026-09-20T12:00:01Z"
            value["result_sha256"] = ce.result_sha256(value)
            path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        with self.assertRaises(ce.ContainerRequestError):
            self.run_scripted(after_container=tamper)
        pointer = state.read_json(worker.root(self.run_id) / "accepted.json")
        self.assertEqual((pointer["schema"], pointer["status"]), (NONCURRENT_SCHEMA, "FAILED"))

    def test_image_digest_mismatch_is_rejected_before_docker_or_attempt_files(self):
        record = worker.current_inputs(self.run_id)
        attempt = self.owner / "standalone-attempt"
        attempt.mkdir()
        request = worker._request(self.run_id, "attempt-x", record)
        request["image"]["digest"] = "sha256:" + "0" * 64
        runtime = worker._runtime(record["source_snapshot_sha256"])
        with mock.patch.object(ce, "_docker", side_effect=AssertionError("docker called")):
            with self.assertRaisesRegex(ce.ContainerRequestError, "not the digest registered"):
                ce.run_container(runtime, run_id=self.run_id, job_id=worker.JOB,
                                 attempt_id="attempt-x", attempt_root=attempt, request=request)
        self.assertEqual(list(attempt.iterdir()), [])

    def test_missing_permission_or_grant_list_fails_closed(self):
        control = state.read_json(worker.control_path(self.run_id))
        for mutation in (lambda v: v.pop("permission"),
                         lambda v: v["permission"].pop("grants")):
            value = json.loads(json.dumps(control))
            mutation(value)
            with self.subTest(value=value), self.assertRaises(state.Blocked):
                worker._permission(value, self.run_id, "sha256:" + "a" * 64,
                                   "2026-09-20T12:00:00Z")

    def test_lifecycle_failure_blocks_old_success_then_recovery_and_reuse(self):
        first = self.run_scripted(dagster="dagster-success")
        worker.stage_control(self.run_id, "exit-nonzero")
        with self.assertRaises(RuntimeError):
            self.run_scripted(dagster="dagster-failure", scripted=ScriptedDocker(client_exit=1))
        failed = state.read_json(worker.root(self.run_id) / "accepted.json")
        self.assertEqual((failed["schema"], failed["status"]), (NONCURRENT_SCHEMA, "FAILED"))
        self.assertNotEqual(failed["attempt_id"], first["attempt_id"])
        worker.stage_control(self.run_id, "success")
        recovered = self.run_scripted(dagster="dagster-recovery")
        self.assertEqual(recovered["schema"], ACCEPTED_SCHEMA)
        self.assertNotEqual(recovered["attempt_id"], first["attempt_id"])
        self.assertEqual(worker.run(self.run_id, "dagster-reuse"), recovered)

    def test_tampered_accepted_attempt_is_never_repaired_or_reused(self):
        first = self.run_scripted()
        attempt = worker.root(self.run_id) / "attempts" / first["attempt_id"]
        receipt = state.read_json(attempt / worker.RECEIPT_FILE)
        receipt["verified_at"] = "tampered"
        state.atomic_json(attempt / worker.RECEIPT_FILE, receipt)
        with self.assertRaises(state.Blocked):
            worker.run(self.run_id, "dagster-after-tamper")
        pointer = state.read_json(worker.root(self.run_id) / "accepted.json")
        self.assertEqual((pointer["schema"], pointer["status"]), (NONCURRENT_SCHEMA, "BLOCKED"))
        self.assertNotEqual(pointer["attempt_id"], first["attempt_id"])

    def test_abandoned_attempt_is_recovered_before_new_success(self):
        from publish_job_output import allocate_attempt
        record = worker.current_inputs(self.run_id)
        fingerprint = "sha256:" + state.digest(record)
        abandoned = allocate_attempt(
            worker.root(self.run_id), run_id=self.run_id, job_id=worker.JOB,
            dagster_run_id="dagster-lost", worker_kind=worker.WORKER_KIND,
            output_contract=worker.CONTRACT, input_record=record,
            input_fingerprint=fingerprint, resume_command="retry",
            attempt_id_factory=lambda: "abandoned")
        result = self.run_scripted(dagster="dagster-recovered")
        recovery = state.read_json(abandoned["attempt"] / "result.json")
        self.assertEqual((recovery["execution_status"], recovery["cause"]),
                         ("FAILED", "INTERRUPTED_WORKER"))
        self.assertNotEqual(result["attempt_id"], "abandoned")


if __name__ == "__main__":
    unittest.main()
