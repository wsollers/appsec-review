from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))

import automatic_evidence_inputs as automatic
import dependency_orchestration
import execution_state as state
import intake
from worker_result import artifact_records, terminal_envelope


class AutomaticEvidenceInputsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get("PHASE1_TEST_DATA")
        os.environ["PHASE1_TEST_DATA"] = self.temp.name
        state.RUNS = Path(self.temp.name) / "runs"
        self.run_id = "automatic-input-test"
        self.run = state.run_path(self.run_id)
        self.target = Path(self.temp.name) / "target"
        self.target.mkdir()
        (self.target / "src").mkdir()
        (self.target / "src" / "hello.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
        (self.target / "README.md").write_text("fixture\n", encoding="utf-8")
        self.permissions = ["read-source", "read-run-data", "read-offline-snapshots", "write-run-data"]
        self.manifest = self.run / "inputs" / "artifact-manifest.json"
        state.atomic_json(self.manifest, {"run_id": self.run_id, "target": {"repo_path": str(self.target)},
            "intake_config": {"permissions": self.permissions}})
        self.source = intake.source_identity(self.target)
        self.intake_attempt = self.run / "data/jobs/00-intake/whole/attempts/intake-one"
        self.intake_attempt.joinpath("evidence").mkdir(parents=True)
        state.atomic_json(self.intake_attempt / "evidence/source.json", self.source)
        self.pointer_path = self.run / "data/jobs/00-intake/whole/accepted.json"
        self.pointer = {"status": "OK", "attempt_id": "intake-one"}
        state.atomic_json(self.pointer_path, self.pointer)
        self.accepted_patch = patch.object(automatic.phase1, "accepted", return_value=self.pointer)
        self.accepted_patch.start()
        self.reference = Path(self.temp.name) / "lifecycle.json"
        state.atomic_json(self.reference, {"schema": "appsec-review/dependency-lifecycle-reference-table/1.0",
            "table_id": "fixture", "version": "1", "as_of": "2026-09-27",
            "rows": [{"row_id": "generic-hello", "ecosystem": "generic", "name": "hello",
                      "cycle": "1", "status": "supported", "eol_date": None}]})
        self.registry = Path(self.temp.name) / "snapshot-registry"; self.registry.mkdir()
        control = self.run / "data/controls" / automatic.CONTROL
        state.atomic_json(control, {"schema": automatic.CONTROL_SCHEMA,
            "offline_snapshots": {"registry_path": str(self.registry), "max_database_age_seconds": 86400},
            "dependency_lifecycle": {"reference_table_path": str(self.reference), "max_reference_age_days": 30}})

    def tearDown(self):
        self.accepted_patch.stop()
        if self.previous is None: os.environ.pop("PHASE1_TEST_DATA", None)
        else: os.environ["PHASE1_TEST_DATA"] = self.previous
        self.temp.cleanup()

    def publish(self, job: str, result_relative: str) -> None:
        base = self.run / "data/jobs" / job
        attempt_id = job.replace("02-", "") + "-one"
        attempt = base / "attempts" / attempt_id
        result = attempt.joinpath(*result_relative.split("/")); result.parent.mkdir(parents=True)
        state.atomic_json(result, {"job_id": job, "attempt_id": attempt_id,
                                   "source_snapshot_sha256": "sha256:" + state.file_hash(self.manifest)})
        envelope = terminal_envelope(run_id=self.run_id, job_id=job, attempt_id=attempt_id,
            worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
            input_fingerprint="sha256:" + "a" * 64, output_contract="fixture",
            started_at="2026-09-27T12:00:00Z", finished_at="2026-09-27T12:00:00Z",
            summary="fixture", artifacts=artifact_records(attempt, [result_relative]))
        state.atomic_json(attempt / "result.json", envelope)
        state.atomic_json(base / "accepted.json", {"schema": "appsec-review/accepted-worker-result/1.0",
            "run_id": self.run_id, "job": job, "attempt_id": attempt_id, "status": "OK",
            "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
            "envelope_sha256": state.file_hash(attempt / "result.json")})

    def test_projection_is_content_addressed_run_owned_and_revalidated(self):
        tree, binding, files = automatic.source_projection(self.run_id)
        self.assertTrue(tree.is_relative_to(self.run / "data"))
        self.assertEqual((tree / "src/hello.c").read_bytes(), (self.target / "src/hello.c").read_bytes())
        self.assertEqual(files["src/hello.c"], "sha256:" + state.file_hash(self.target / "src/hello.c"))
        self.assertEqual(automatic.validate_source_projection(self.run_id, tree, binding)["files"], files)
        forged = dict(binding); forged["source_revision"] = "forged"
        with self.assertRaisesRegex(state.Blocked, "lineage is stale"):
            automatic.validate_source_projection(self.run_id, tree, forged)
        (self.target / "src/hello.c").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(state.Blocked, "checkout changed"):
            automatic.source_projection(self.run_id)

    def test_vendor_requests_use_projection_and_container_inputs_with_closed_receipts(self):
        for job in sorted(automatic.VENDOR_JOBS):
            with self.subTest(job=job):
                config = automatic.prepare(self.run_id, job, "dagster-one", generated_at="2026-09-27T12:00:00Z")
                request = state.read_json(Path(config["input_path"]))
                self.assertEqual(request["schema"], "appsec-review/vendor-evidence-orchestration-request/1.1")
                self.assertEqual(set(request["source_binding"]), automatic.SOURCE_BINDING_KEYS)
                if job != "02-secrets-inventory":
                    self.assertEqual(request["applicability"]["decision"], "SKIPPED_NA")
                    self.assertEqual(request["applicability"]["skip_reason"],
                                     automatic.vendor_workers.SKIP)
                expected = self.run / "inputs" if job == "02-container-image-inventory" else Path(
                    automatic.source_projection(self.run_id)[0])
                self.assertEqual(Path(request["source_root"]), expected)
                receipt = state.read_json(Path(config["input_path"]).with_suffix(".receipt.json"))
                self.assertEqual(receipt["request_sha256"], "sha256:" + state.file_hash(Path(config["input_path"])))
                self.assertEqual(automatic.prepare(self.run_id, job, "dagster-one"), config)

    def test_dependency_chain_is_automatic_and_binds_current_upstreams_and_controls(self):
        sbom = automatic.prepare(self.run_id, "02-sbom-inventory", "dagster-sbom",
                                 generated_at="2026-09-27T12:00:00Z")
        sbom_request = state.read_json(Path(sbom["input_path"]))
        self.assertEqual(sbom_request["payload"]["source_files"]["README.md"],
                         "sha256:" + state.file_hash(self.target / "README.md"))
        self.publish("02-sbom-inventory", automatic.RESULTS["02-sbom-inventory"])
        license_config = automatic.prepare(self.run_id, "02-license-scan", "dagster-license",
                                           generated_at="2026-09-27T12:00:00Z")
        license_request = state.read_json(Path(license_config["input_path"]))
        self.assertEqual(license_request["payload"]["sbom"]["attempt_id"], "sbom-inventory-one")
        self.publish("02-license-scan", automatic.RESULTS["02-license-scan"])
        def resolved(kind, *_args, **_kwargs):
            return {"database_kind": kind, "vendor_build": "fixture", "schema_version": "1",
                    "snapshot_id": kind + "-one", "sha256": "sha256:" + "b" * 64,
                    "data_timestamp": "2026-09-27T11:00:00Z", "freshness": "fresh"}
        with patch.object(automatic.snapshots, "resolve", side_effect=resolved) as resolve:
            sca = automatic.prepare(self.run_id, "02-sca-vulnerability-match", "dagster-sca",
                                    generated_at="2026-09-27T12:00:00Z")
        self.assertEqual(resolve.call_count, 2)
        sca_request = state.read_json(Path(sca["input_path"]))
        self.assertEqual(sca_request["tool"]["snapshot_registry"], str(self.registry.resolve()))
        lifecycle = automatic.prepare(self.run_id, "02-dependency-lifecycle", "dagster-lifecycle",
                                      generated_at="2026-09-27T12:00:00Z")
        lifecycle_request = state.read_json(Path(lifecycle["input_path"]))
        table = Path(lifecycle_request["payload"]["reference_table"])
        self.assertTrue(table.is_relative_to(self.run / "data"))
        self.assertEqual(lifecycle_request["payload"]["reference_table_sha256"],
                         "sha256:" + state.file_hash(table))

    def test_prepare_result_invokes_dependency_orchestration_without_manual_config(self):
        config = automatic.prepare(self.run_id, "02-sbom-inventory", "dagster-direct",
                                   generated_at="2026-09-27T12:00:00Z")
        with patch.object(dependency_orchestration.b13, "execute",
                          return_value={"b13_attempt": {"verified": True}}) as execute, \
             patch.object(dependency_orchestration.workers, "run",
                          return_value={"attempt_id": "worker"}) as run:
            result = dependency_orchestration.execute(job_id="02-sbom-inventory",
                                                       run_id=self.run_id, **config)
        self.assertEqual(result["attempt_id"], "worker")
        projected = Path(execute.call_args.kwargs["target"])
        self.assertTrue(projected.is_relative_to(self.run / "data/automatic-inputs/source"))
        self.assertEqual(Path(run.call_args.args[1]).name, "worker-request.json")

    def test_standards_binding_is_automatic_target_derived_and_immutable(self):
        path = automatic.prepare_standards_binding(self.run_id)
        binding = state.read_json(path)
        selected = {item["family"] for item in binding["selected_snapshots"]}
        unselected = {item["family"] for item in binding["unselected_families"]}
        self.assertIn("disa_asd_stig", selected)
        self.assertIn("owasp_asvs", selected)
        self.assertIn("disa_gpos_srg", unselected)
        self.assertIn("owasp_masvs", unselected)
        self.assertNotIn("approved", " ".join(item["selection_basis"] for item in binding["selected_snapshots"]).lower())
        self.assertEqual(automatic.prepare_standards_binding(self.run_id), path)
        changed = state.read_json(path)
        changed["unselected_families"][0]["reason"] = "changed"
        state.atomic_json(path, changed)
        with self.assertRaisesRegex(state.Blocked, "differs from accepted source"):
            automatic.prepare_standards_binding(self.run_id)

    def test_missing_permission_stale_upstream_and_changed_request_fail_closed(self):
        value = state.read_json(self.manifest); value["intake_config"]["permissions"].remove("write-run-data")
        state.atomic_json(self.manifest, value)
        with self.assertRaisesRegex(state.Blocked, "missing staged permission"):
            automatic.prepare(self.run_id, "02-secrets-inventory", "dagster-denied",
                              generated_at="2026-09-27T12:00:00Z")
        value["intake_config"]["permissions"].append("write-run-data"); state.atomic_json(self.manifest, value)
        with self.assertRaisesRegex(state.Blocked, "accepted 02-sbom-inventory is required"):
            automatic.prepare(self.run_id, "02-license-scan", "dagster-stale",
                              generated_at="2026-09-27T12:00:00Z")
        config = automatic.prepare(self.run_id, "02-secrets-inventory", "dagster-fixed",
                                   generated_at="2026-09-27T12:00:00Z")
        request = Path(config["input_path"]); changed = state.read_json(request); changed["generated_at"] = "2026-09-27T12:00:01Z"
        state.atomic_json(request, changed)
        with self.assertRaisesRegex(state.Blocked, "existing request has different inputs"):
            automatic.prepare(self.run_id, "02-secrets-inventory", "dagster-fixed",
                              generated_at="2026-09-27T12:00:00Z")


if __name__ == "__main__": unittest.main()
