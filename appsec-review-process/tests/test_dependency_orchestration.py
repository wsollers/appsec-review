from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import dependency_orchestration as orchestration
import dependency_b13_adapters as adapters
import execution_state
import validate_job_output


class DependencyOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get("PHASE1_TEST_DATA")
        os.environ["PHASE1_TEST_DATA"] = self.temp.name
        execution_state.RUNS = Path(self.temp.name)
        self.run_id = "dependency-orchestration-test"
        self.owner = execution_state.run_path(self.run_id)
        (self.owner / "inputs" / "target").mkdir(parents=True)
        manifest = self.owner / "inputs" / "artifact-manifest.json"
        manifest.write_text("{}\n")
        self.generation = "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest()
        self.jobs = self.owner / "data" / "jobs"

    def tearDown(self):
        if self.previous is None: os.environ.pop("PHASE1_TEST_DATA", None)
        else: os.environ["PHASE1_TEST_DATA"] = self.previous
        self.temp.cleanup()

    def request(self, job, payload, tool):
        path = self.owner / "inputs" / (job + ".json")
        path.write_text(json.dumps({"schema": orchestration.REQUEST_SCHEMA, "run_id": self.run_id,
            "job_id": job, "source_generation": self.generation, "generated_at": "2026-09-27T12:00:00Z",
            "payload": payload, "tool": tool}))
        return path

    def execute(self, job, request, suffix="one"):
        return orchestration.execute(job_id=job, run_id=self.run_id, input_path=str(request),
            output_root=str(self.jobs), attempt_root=str(self.jobs / job / "orchestration-attempts" / suffix))

    def test_sbom_calls_public_b13_then_worker_seam(self):
        request = self.request("02-sbom-inventory", {"source_files": {}},
                               {"target_path": str(self.owner / "inputs" / "target")})
        binding = {"verified": True}
        with patch.object(orchestration.b13, "execute", return_value={"b13_attempt": binding}) as execute, \
             patch.object(orchestration.workers, "run", return_value={"attempt_id": "worker"}) as run:
            self.assertEqual(self.execute("02-sbom-inventory", request)["attempt_id"], "worker")
        self.assertEqual(execute.call_args.args[0], "syft")
        resolved = Path(run.call_args.args[1])
        self.assertEqual(json.loads(resolved.read_text())["b13_attempt"], binding)

    def test_sca_resolves_both_supplied_offline_snapshots(self):
        outputs = self.jobs / "02-sbom-inventory" / "attempts" / "a" / "outputs"
        outputs.mkdir(parents=True); manifest = outputs / "sbom-manifest.json"; manifest.write_text("{}")
        accepted = self.jobs / "02-sbom-inventory" / "accepted.json"; accepted.parent.mkdir(exist_ok=True); accepted.write_text("{}")
        registry = Path(self.temp.name) / "offline-registry"; registry.mkdir()
        payload = {"sbom": {"attempt_id": "a", "path": str(manifest), "sha256": "sha256:" + "1" * 64,
                            "accepted_path": str(accepted)}}
        request = self.request("02-sca-vulnerability-match", payload,
            {"sbom_root": str(outputs), "snapshot_registry": str(registry), "max_database_age_seconds": 3600})
        def registered(kind, **kwargs):
            return {"b13_attempt": {"kind": kind}, "database": {"database_kind": "grype-db" if kind == "grype" else "osv"}}
        with patch.object(orchestration.b13, "execute_registered", side_effect=registered) as execute, \
             patch.object(orchestration.workers, "run", return_value={"attempt_id": "worker"}) as run:
            self.execute("02-sca-vulnerability-match", request)
        self.assertEqual([call.args[0] for call in execute.call_args_list], ["grype", "osv"])
        resolved = json.loads(Path(run.call_args.args[1]).read_text())
        self.assertEqual({row["database_kind"] for row in resolved["databases"]}, {"grype-db", "osv"})
        self.assertEqual(resolved["max_database_age_seconds"], 3600)

    def test_absent_or_stale_snapshot_fails_closed(self):
        outputs = self.jobs / "02-sbom-inventory" / "attempts" / "a" / "outputs"
        outputs.mkdir(parents=True); manifest = outputs / "sbom-manifest.json"; manifest.write_text("{}")
        accepted = self.jobs / "02-sbom-inventory" / "accepted.json"; accepted.parent.mkdir(exist_ok=True); accepted.write_text("{}")
        registry = Path(self.temp.name) / "offline-registry"; registry.mkdir()
        request = self.request("02-sca-vulnerability-match", {"sbom": {"attempt_id": "a", "path": str(manifest),
            "sha256": "sha256:" + "1" * 64, "accepted_path": str(accepted)}},
            {"sbom_root": str(outputs), "snapshot_registry": str(registry), "max_database_age_seconds": 1})
        with patch.object(orchestration.b13, "execute_registered",
                          side_effect=adapters.AdapterBlocked("snapshot stale")), \
             self.assertRaisesRegex(execution_state.Blocked, "snapshot stale"):
            self.execute("02-sca-vulnerability-match", request)

    def test_cross_run_input_and_noncanonical_output_are_rejected(self):
        outside = Path(self.temp.name) / "outside.json"; outside.write_text("{}")
        with self.assertRaisesRegex(execution_state.Blocked, "not run-owned"):
            orchestration.execute(job_id="02-sbom-inventory", run_id=self.run_id,
                input_path=str(outside), output_root=str(self.jobs),
                attempt_root=str(self.jobs / "02-sbom-inventory" / "orchestration-attempts" / "x"))
        request = self.request("02-sbom-inventory", {"source_files": {}},
                               {"target_path": str(self.owner / "inputs" / "target")})
        with self.assertRaisesRegex(execution_state.Blocked, "canonical jobs root"):
            orchestration.execute(job_id="02-sbom-inventory", run_id=self.run_id,
                input_path=str(request), output_root=str(self.owner / "data"),
                attempt_root=str(self.jobs / "02-sbom-inventory" / "orchestration-attempts" / "x"))

    def test_shared_claim_policies_keep_dependency_outputs_bounded(self):
        expected = {
            "sbom-inventory": "dependency_inventory_evidence",
            "sca-vulnerability-match": "known_vulnerability_match_lead",
            "license-inventory": "license_detection_evidence",
            "dependency-lifecycle": "dependency_lifecycle_evidence",
            "cve-reachability": "cve_reachability_evidence_lead",
        }
        for contract, claim_class in expected.items():
            self.assertEqual(validate_job_output.CLAIM_CLASS_POLICIES[contract]["claim_class_id"], claim_class)


if __name__ == "__main__": unittest.main()
