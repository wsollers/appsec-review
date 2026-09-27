from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import control_lane_orchestration as orchestration
import execution_state


class ControlLaneOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get("PHASE1_TEST_DATA")
        os.environ["PHASE1_TEST_DATA"] = self.temp.name
        execution_state.RUNS = Path(self.temp.name)
        self.run_id = "control-orchestration-test"
        self.owner = execution_state.run_path(self.run_id)
        (self.owner / "inputs").mkdir(parents=True)
        self.manifest = self.owner / "inputs" / "artifact-manifest.json"
        self.manifest.write_text("{}\n")
        self.generation = "sha256:" + hashlib.sha256(self.manifest.read_bytes()).hexdigest()

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("PHASE1_TEST_DATA", None)
        else:
            os.environ["PHASE1_TEST_DATA"] = self.previous
        self.temp.cleanup()

    def request(self, job, payload):
        path = self.owner / "inputs" / f"{job}.json"
        path.write_text(json.dumps({"schema": orchestration.SCHEMA, "run_id": self.run_id,
            "job_id": job, "source_generation": self.generation,
            "generated_at": "2026-09-27T12:00:00Z", "payload": payload}))
        return path

    def paths(self, job, attempt_id="attempt-one"):
        base = self.owner / "data" / "jobs" / job / "whole"
        return base, base / "attempts" / attempt_id

    def test_each_deterministic_control_calls_its_public_attempt_seam(self):
        source = self.owner / "inputs" / "source.json"
        source.write_text("{}\n")
        jobs = {"evidence-qualified-quorum": orchestration.evidence_quorum, **orchestration.SIMPLE}
        for job, module in jobs.items():
            with self.subTest(job=job):
                request = self.request(job, {"source_path": str(source)})
                base, attempt = self.paths(job)
                with patch.object(module, "run_verified_attempt" if job == "evidence-qualified-quorum" else "run_attempt") as run, \
                     patch.object(orchestration, "_publish", return_value={"attempt_id": attempt.name}):
                    result = orchestration.execute(job_id=job, run_id=self.run_id,
                        dagster_run_id="dagster-run", input_path=str(request), output_root=str(base),
                        attempt_root=str(attempt))
                self.assertEqual(result["attempt_id"], attempt.name)
                run.assert_called_once()

    def test_deterministic_merge_accepts_only_verified_c02_manifest(self):
        spec = self.owner / "inputs" / "pool.json"
        spec.write_text("{}\n")
        pool_parent = self.owner / "data" / "pools"; pool_parent.mkdir(parents=True)
        rendezvous = self.owner / "data" / "rendezvous"; rendezvous.mkdir(parents=True)
        prompt_root = self.owner / "inputs" / "prompts"; prompt_root.mkdir()
        payload = {"spec_path": str(spec), "context": {"pool_parent": str(pool_parent),
            "prompt_root": str(prompt_root), "readable_roots": {}, "allowed_models": [],
            "invoker_id": "test", "host_flavor": "linux", "docker_executable": "",
            "container_user": "65532:65532", "mount_roots": {}, "registry_ceiling": "2026-09-27T12:00:00Z"},
            "runtime": {"effort": "medium", "budget_usd": 1, "stop_grace_seconds": 1,
                "max_parallel": 1, "wait_limit_seconds": 1, "drain_seconds": 1,
                "rendezvous_parent": str(rendezvous)}}
        request = self.request("deterministic-pool-merge", payload)
        base, attempt = self.paths("deterministic-pool-merge")
        context = SimpleNamespace(pool_parent=pool_parent); verified = object()
        with patch.object(orchestration, "_pool_context", return_value=context), \
             patch.object(orchestration.pool_specification, "spec_sha256", return_value="a" * 64), \
             patch.object(orchestration.pool_specification, "pool_directory", return_value="pool-a"), \
             patch.object(orchestration.pool_rendezvous, "load_verified_manifest", return_value=verified) as load, \
             patch.object(orchestration.deterministic_pool_merge, "run_verified_attempt") as merge, \
             patch.object(orchestration, "_publish", return_value={"attempt_id": attempt.name}):
            orchestration.execute_pool(job_id="deterministic-pool-merge", run_id=self.run_id,
                dagster_run_id="dagster-run", input_path=str(request), output_root=str(base),
                attempt_root=str(attempt))
        load.assert_called_once()
        self.assertIs(merge.call_args.args[0], verified)

    def test_paths_and_generation_fail_closed(self):
        source = self.owner / "inputs" / "source.json"; source.write_text("{}\n")
        request = self.request("dynamic-rescope", {"source_path": str(source)})
        base, attempt = self.paths("dynamic-rescope")
        value = json.loads(request.read_text()); value["source_generation"] = "sha256:" + "0" * 64
        request.write_text(json.dumps(value))
        with self.assertRaisesRegex(execution_state.Blocked, "stale"):
            orchestration.execute(job_id="dynamic-rescope", run_id=self.run_id,
                dagster_run_id="dagster-run", input_path=str(request), output_root=str(base),
                attempt_root=str(attempt))
        outside = Path(self.temp.name) / "outside.json"; outside.write_text("{}")
        with self.assertRaisesRegex(execution_state.Blocked, "not run-owned"):
            orchestration.execute(job_id="dynamic-rescope", run_id=self.run_id,
                dagster_run_id="dagster-run", input_path=str(outside), output_root=str(base),
                attempt_root=str(attempt))


if __name__ == "__main__":
    unittest.main()
