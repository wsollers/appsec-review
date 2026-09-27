from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))

import execution_state
import vendor_evidence_orchestration as orchestration


class VendorEvidenceOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get("PHASE1_TEST_DATA")
        os.environ["PHASE1_TEST_DATA"] = self.temp.name
        execution_state.RUNS = Path(self.temp.name)
        self.run_id = "vendor-orchestration-test"
        self.owner = execution_state.run_path(self.run_id)
        self.source = self.owner / "inputs" / "target"
        self.source.mkdir(parents=True)
        (self.source / "README.md").write_text("fixture\n")
        self.manifest = self.owner / "inputs" / "artifact-manifest.json"
        self.manifest.write_text(json.dumps({"target": {"repo_path": str(self.source)}}))
        self.generation = "sha256:" + hashlib.sha256(self.manifest.read_bytes()).hexdigest()

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("PHASE1_TEST_DATA", None)
        else:
            os.environ["PHASE1_TEST_DATA"] = self.previous
        self.temp.cleanup()

    def request(self, job: str, source: Path | None = None) -> Path:
        path = self.owner / "inputs" / (job + ".json")
        path.write_text(json.dumps({"schema": orchestration.REQUEST_SCHEMA, "run_id": self.run_id,
            "job_id": job, "source_generation": self.generation,
            "generated_at": "2026-09-27T12:00:00Z", "source_root": str(source or self.source)}))
        return path

    def paths(self, job: str, attempt_id: str):
        base = self.owner / "data" / "jobs" / job / "whole"
        return base, base / "attempts" / attempt_id, base / "executions" / attempt_id

    @staticmethod
    def materialize(documents, attempt, **kwargs):
        attempt.mkdir(parents=True)
        envelope = {"schema": "appsec-review/worker-result-envelope/1.0", "run_id": documents["run_id"],
            "job_id": documents["job_id"], "attempt_id": attempt.name, "worker_kind": "pinned_container",
            "execution_status": documents["status"],
            "acceptance_status": "NOT_ACCEPTED" if documents["status"] == "BLOCKED" else "CURRENT",
            "input_fingerprint": "sha256:" + "a" * 64, "output_contract": documents["contract"],
            "started_at": kwargs["started_at"], "finished_at": kwargs["finished_at"],
            "summary": "fixture", "artifacts": [], "gaps": documents.get("gaps", []),
            "skip_reason": None, "cause": "unavailable" if documents["status"] == "BLOCKED" else None,
            "retry": {"allowed": False, "reason": None, "resume_command": None},
            "superseded_by_attempt_id": None}
        (attempt / "result.json").write_text(json.dumps(envelope))

    def test_each_job_calls_its_public_build_and_materialize_seams(self):
        for number, (job, worker) in enumerate(orchestration.WORKERS.items(), 1):
            with self.subTest(job=job):
                source = self.owner / "inputs" if job == "02-container-image-inventory" else self.source
                request = self.request(job, source)
                base, attempt, execution = self.paths(job, f"attempt-{number}")
                documents = {"run_id": self.run_id, "job_id": job, "status": "OK_WITH_GAPS",
                             "contract": "fixture", "gaps": ["gap-tool-a", "gap-tool-b"]}
                with patch.object(worker, "build", return_value=documents) as build, \
                     patch.object(worker, "materialize_attempt", side_effect=self.materialize) as materialize, \
                     patch.object(orchestration.binary_hardening_input, "validate", return_value={}), \
                     patch.object(orchestration, "publish_validated", return_value={"attempt_id": attempt.name}) as publish:
                    result = orchestration.execute(job_id=job, run_id=self.run_id, dagster_run_id="dagster-run-1",
                        input_path=str(request), output_root=str(base), attempt_root=str(attempt),
                        execution_root=str(execution))
                self.assertEqual(result["attempt_id"], attempt.name)
                self.assertEqual(build.call_args.args[0], source)
                self.assertEqual(build.call_args.kwargs["execution_root"], execution)
                self.assertEqual(materialize.call_args.args[1], attempt)
                self.assertEqual(publish.call_args.kwargs["orchestration"].source_snapshot_sha256, self.generation)
                self.assertEqual(documents["gaps"], ["gap-tool-a", "gap-tool-b"])

    def test_missing_stale_or_noncanonical_paths_fail_closed(self):
        job = "02-secrets-inventory"
        request = self.request(job)
        base, attempt, execution = self.paths(job, "attempt-x")
        outside = Path(self.temp.name) / "outside.json"
        outside.write_text("{}")
        with self.assertRaisesRegex(execution_state.Blocked, "not run-owned"):
            orchestration.execute(job_id=job, run_id=self.run_id, dagster_run_id="dagster-run-1",
                input_path=str(outside), output_root=str(base), attempt_root=str(attempt), execution_root=str(execution))
        value = json.loads(request.read_text()); value["source_generation"] = "sha256:" + "0" * 64
        request.write_text(json.dumps(value))
        with self.assertRaisesRegex(execution_state.Blocked, "stale"):
            orchestration.execute(job_id=job, run_id=self.run_id, dagster_run_id="dagster-run-1",
                input_path=str(request), output_root=str(base), attempt_root=str(attempt), execution_root=str(execution))

    def test_blocked_worker_result_is_noncurrent_and_raises(self):
        job = "02-secrets-inventory"
        request = self.request(job)
        base, attempt, execution = self.paths(job, "blocked")
        documents = {"run_id": self.run_id, "job_id": job, "status": "BLOCKED", "contract": "fixture"}
        worker = orchestration.WORKERS[job]
        with patch.object(worker, "build", return_value=documents), \
             patch.object(worker, "materialize_attempt", side_effect=self.materialize), \
             patch.object(orchestration, "record_noncurrent", return_value={"status": "BLOCKED"}) as record, \
             self.assertRaisesRegex(execution_state.Blocked, "did not produce current evidence"):
            orchestration.execute(job_id=job, run_id=self.run_id, dagster_run_id="dagster-run-1",
                input_path=str(request), output_root=str(base), attempt_root=str(attempt), execution_root=str(execution))
        record.assert_called_once()

    def test_binary_auto_route_uses_native_projection_and_canonical_attempt(self):
        request = self.owner / "data/jobs/02-binary-hardening/requests/dagster-auto.json"
        with patch.object(orchestration.binary_hardening_input, "stage_request", return_value=request), \
             patch.object(orchestration, "execute", return_value={"attempt_id": "native-dagster-auto"}) as execute:
            result = orchestration.execute_binary_from_native(
                run_id=self.run_id, dagster_run_id="dagster-auto")
        base = self.owner / "data/jobs/02-binary-hardening/whole"
        self.assertEqual(result["attempt_id"], "native-dagster-auto")
        execute.assert_called_once_with(job_id="02-binary-hardening", run_id=self.run_id,
            dagster_run_id="dagster-auto", input_path=str(request), output_root=str(base),
            attempt_root=str(base / "attempts/native-dagster-auto"),
            execution_root=str(base / "executions/native-dagster-auto"))


if __name__ == "__main__":
    unittest.main()
