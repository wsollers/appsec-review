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
        self.source_binding = {key: "fixture" for key in orchestration.automatic_inputs.SOURCE_BINDING_KEYS}
        self.source_patch = patch.object(orchestration.automatic_inputs, "source_projection",
            return_value=(self.source, self.source_binding, {}))
        self.validate_patch = patch.object(orchestration.automatic_inputs, "validate_source_projection",
            return_value={"binding": self.source_binding, "files": {}})
        self.source_patch.start(); self.validate_patch.start()

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("PHASE1_TEST_DATA", None)
        else:
            os.environ["PHASE1_TEST_DATA"] = self.previous
        self.source_patch.stop(); self.validate_patch.stop()
        self.temp.cleanup()

    def request(self, job: str, source: Path | None = None, generated_at: str = "2026-09-27T12:00:00Z") -> Path:
        selected = source or self.source
        probe = orchestration.vendor_workers.probe(job, selected)
        applicable = any(probe["candidates"].values()) or job == "02-secrets-inventory"
        path = self.owner / "data" / "controls" / "tests" / (job + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"schema": orchestration.REQUEST_SCHEMA, "run_id": self.run_id,
            "job_id": job, "source_generation": self.generation,
            "generated_at": generated_at, "source_root": str(selected),
            "source_binding": self.source_binding,
            "applicability": {"decision": "EXECUTE" if applicable else "SKIPPED_NA",
                "skip_reason": None if applicable else orchestration.vendor_workers.SKIP,
                "probe_sha256": "sha256:" + orchestration.digest(probe), "probe": probe}}))
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
        (attempt / "status.json").write_text(json.dumps({"status": documents["status"],
            "attempt_id": attempt.name, "dagster_run_id": kwargs["dagster_run_id"]}))
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
                self.assertEqual(publish.call_args.kwargs["consumer_job_id"], "02-evidence-assembly")
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
             patch.object(orchestration, "execute", return_value={"attempt_id": "native-fixture"}) as execute:
            result = orchestration.execute_binary_from_native(
                run_id=self.run_id, dagster_run_id="dagster-auto")
        base = self.owner / "data/jobs/02-binary-hardening/whole"
        self.assertEqual(result["attempt_id"], "native-fixture")
        kwargs = execute.call_args.kwargs
        attempt_id = Path(kwargs.pop("attempt_root")).name
        # Resume reuse: a fresh attempt id, never the Dagster run id (that stays an orchestration fact).
        self.assertRegex(attempt_id, r"^native-[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
        self.assertNotIn("dagster-auto", attempt_id)
        self.assertEqual(kwargs.pop("execution_root"), str(base / "executions" / attempt_id))
        self.assertEqual(kwargs, {"job_id": "02-binary-hardening", "run_id": self.run_id,
            "dagster_run_id": "dagster-auto", "input_path": str(request), "output_root": str(base)})

    # --- resume reuse (run 20261004T054551Z-357581) ----------------------------------------------

    def test_fresh_attempt_ids_keep_the_shapes_the_publication_redactor_exempts(self):
        import evidence_redaction
        for prefix in ("auto", "native"):
            attempt_id = orchestration.fresh_attempt_id(prefix)
            self.assertEqual(execution_state.identifier(attempt_id), attempt_id)
            self.assertTrue(evidence_redaction._exempt(attempt_id), attempt_id)

    @staticmethod
    def publish(base, attempt, envelope_path, fingerprint, **kwargs):
        """Stands in for the validated publication: the real common pointer, no vendor verifier."""
        envelope = json.loads(Path(envelope_path).read_text())
        pointer = {"schema": "appsec-review/accepted-worker-result/1.0", "status": envelope["execution_status"],
            "run_id": kwargs["expected_run_id"], "job": kwargs["expected_job_id"], "attempt_id": attempt.name,
            "fingerprint": fingerprint, "envelope_path": "result.json",
            "envelope_sha256": execution_state.file_hash(envelope_path),
            "hashes": execution_state.tree_hashes(attempt), "accepted_at": "2026-09-27T12:00:01Z"}
        execution_state.atomic_json(Path(base) / "accepted.json", pointer)
        return pointer

    def launch(self, job, dagster_run_id, generated_at, *, validated=None):
        """One launch as the full review drives it: a new request, a fresh attempt id, a new run id."""
        source = self.owner / "inputs" if job == "02-container-image-inventory" else self.source
        request = self.request(job, source, generated_at)
        attempt_id = orchestration.fresh_attempt_id("auto")
        base, attempt, execution = self.paths(job, attempt_id)
        documents = {"run_id": self.run_id, "job_id": job, "status": "OK", "contract": "fixture", "gaps": []}
        worker = orchestration.WORKERS[job]
        with patch.object(worker, "build", return_value=documents) as build, \
             patch.object(worker, "materialize_attempt", side_effect=self.materialize), \
             patch.object(orchestration.binary_hardening_input, "validate", return_value={}), \
             patch.object(orchestration, "publish_validated", side_effect=self.publish), \
             patch.object(orchestration, "validate_published", side_effect=validated) as reverify:
            pointer = orchestration.execute(job_id=job, run_id=self.run_id, dagster_run_id=dagster_run_id,
                input_path=str(request), output_root=str(base), attempt_root=str(attempt),
                execution_root=str(execution))
        return pointer, build.call_count, reverify

    def test_unchanged_request_reuses_the_accepted_attempt_without_a_container_call(self):
        for job in orchestration.WORKERS:
            with self.subTest(job=job):
                first, built, _ = self.launch(job, "dagster-run-1", "2026-09-27T12:00:00Z")
                self.assertEqual(built, 1)
                second, built, reverify = self.launch(job, "dagster-run-2", "2026-10-04T05:45:51Z")
                self.assertEqual(built, 0)
                self.assertEqual(second, first)
                # Re-validated with the facts of the run that PRODUCED the attempt.
                facts = reverify.call_args.kwargs["orchestration"]
                self.assertEqual(facts.dagster_run_id, "dagster-run-1")
                self.assertTrue(reverify.call_args.kwargs["reuse"])
                base = self.paths(job, "x")[0]
                self.assertEqual([path.name for path in (base / "attempts").iterdir()], [first["attempt_id"]])
                record = json.loads((base / "reuse.json").read_text())
                self.assertNotIn("dagster-run-1", json.dumps(record["inputs"]))
                self.assertNotIn("2026-09-27T12:00:00Z", json.dumps(record["inputs"]))

    def test_changed_content_or_failed_reverification_re_executes(self):
        job = "02-secrets-inventory"
        first, _, _ = self.launch(job, "dagster-run-1", "2026-09-27T12:00:00Z")
        (self.source / "README.md").write_text("changed\n")
        second, built, _ = self.launch(job, "dagster-run-2", "2026-09-27T12:00:00Z")
        self.assertEqual(built, 1)
        self.assertNotEqual(second["attempt_id"], first["attempt_id"])
        third, built, _ = self.launch(job, "dagster-run-3", "2026-09-27T12:00:00Z",
                                      validated=execution_state.Blocked("accepted attempt changed"))
        self.assertEqual(built, 1)
        self.assertNotEqual(third["attempt_id"], second["attempt_id"])


if __name__ == "__main__":
    unittest.main()
