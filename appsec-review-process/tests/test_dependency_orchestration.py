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
        build_root = self.jobs / "02-build-index"
        build_output = build_root / "attempts" / "build-one" / "build-index.json"
        build_output.parent.mkdir(parents=True)
        build_output.write_text("{}\n")
        build_pointer = build_root / "accepted.json"; build_pointer.write_text("{}\n")
        self.build_index = {"attempt_id": "build-one", "path": str(build_output),
            "sha256": "sha256:" + hashlib.sha256(build_output.read_bytes()).hexdigest(),
            "accepted_path": str(build_pointer)}
        self.source_binding = {key: "fixture" for key in orchestration.automatic_inputs.SOURCE_BINDING_KEYS}
        self.source_patch = patch.object(orchestration.automatic_inputs, "source_projection",
            return_value=(self.owner / "inputs" / "target", self.source_binding, {}))
        self.validate_patch = patch.object(orchestration.automatic_inputs, "validate_source_projection",
            return_value={"binding": self.source_binding, "files": {}})
        self.source_patch.start(); self.validate_patch.start()

    def tearDown(self):
        if self.previous is None: os.environ.pop("PHASE1_TEST_DATA", None)
        else: os.environ["PHASE1_TEST_DATA"] = self.previous
        self.source_patch.stop(); self.validate_patch.stop()
        self.temp.cleanup()

    def request(self, job, payload, tool, generated_at="2026-09-27T12:00:00Z"):
        path = self.owner / "inputs" / (job + ".json")
        path.write_text(json.dumps({"schema": orchestration.REQUEST_SCHEMA, "run_id": self.run_id,
            "job_id": job, "source_generation": self.generation, "generated_at": generated_at,
            "source_binding": self.source_binding, "payload": payload, "tool": tool}))
        return path

    def execute(self, job, request, suffix="one"):
        return orchestration.execute(job_id=job, run_id=self.run_id, input_path=str(request),
            output_root=str(self.jobs), attempt_root=str(self.jobs / job / "orchestration-attempts" / suffix))

    def test_sbom_calls_public_b13_then_worker_seam(self):
        request = self.request("02-sbom-inventory", {"source_files": {}, "build_index": self.build_index},
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
        outputs.mkdir(parents=True); manifest = outputs / "sbom-manifest.json"; manifest.write_text(json.dumps({
            "components": [{"component_id": "SC-000001", "purl": "pkg:npm/example@1.0.0"}]}))
        accepted = self.jobs / "02-sbom-inventory" / "accepted.json"; accepted.parent.mkdir(exist_ok=True); accepted.write_text("{}")
        registry = Path(self.temp.name) / "offline-registry"; registry.mkdir()
        payload = {"sbom": {"attempt_id": "a", "path": str(manifest),
                            "sha256": "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest(),
                            "accepted_path": str(accepted)}}
        identities = [{"database_kind": kind, "vendor_build": "v", "schema_version": "1",
                       "snapshot_id": kind + "-one", "sha256": "sha256:" + "2" * 64,
                       "data_timestamp": "2026-09-27T11:00:00Z"} for kind in ("grype-db", "osv")]
        request = self.request("02-sca-vulnerability-match", payload,
            {"sbom_root": str(outputs), "snapshot_registry": str(registry), "max_database_age_seconds": 3600,
             "snapshot_identities": identities})
        def registered(kind, **kwargs):
            database_kind = "grype-db" if kind == "grype" else "osv"
            return {"b13_attempt": {"kind": kind},
                    "database": next(row for row in identities if row["database_kind"] == database_kind)}
        with patch.object(orchestration.b13, "execute_registered", side_effect=registered) as execute, \
             patch.object(orchestration.workers, "run", return_value={"attempt_id": "worker"}) as run:
            self.execute("02-sca-vulnerability-match", request)
        self.assertEqual([call.args[0] for call in execute.call_args_list], ["grype", "osv"])
        resolved = json.loads(Path(run.call_args.args[1]).read_text())
        self.assertEqual({row["database_kind"] for row in resolved["databases"]}, {"grype-db", "osv"})
        self.assertEqual(resolved["max_database_age_seconds"], 3600)
        self.assertEqual(resolved["osv_applicability"]["decision"], "EXECUTE")

    def test_sca_skips_only_osv_for_an_sbom_without_purls_and_retains_both_snapshots(self):
        outputs = self.jobs / "02-sbom-inventory" / "attempts" / "a" / "outputs"
        outputs.mkdir(parents=True); manifest = outputs / "sbom-manifest.json"; manifest.write_text(json.dumps({
            "components": [{"component_id": "SC-000001", "purl": None}]}))
        accepted = self.jobs / "02-sbom-inventory" / "accepted.json"; accepted.parent.mkdir(exist_ok=True); accepted.write_text("{}")
        registry = Path(self.temp.name) / "offline-registry"; registry.mkdir()
        payload = {"sbom": {"attempt_id": "a", "path": str(manifest),
            "sha256": "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest(), "accepted_path": str(accepted)}}
        identities = [{"database_kind": kind, "vendor_build": "v", "schema_version": "1",
            "snapshot_id": kind + "-one", "sha256": "sha256:" + "2" * 64,
            "data_timestamp": "2026-09-27T11:00:00Z"} for kind in ("grype-db", "osv")]
        request = self.request("02-sca-vulnerability-match", payload,
            {"sbom_root": str(outputs), "snapshot_registry": str(registry), "max_database_age_seconds": 3600,
             "snapshot_identities": identities})
        with patch.object(orchestration.b13, "execute_registered", return_value={
                "b13_attempt": {"kind": "grype"}, "database": identities[0]}) as execute, \
             patch.object(orchestration.b13, "resolve_registered_snapshot", return_value={
                "database": identities[1], "database_freshness": {}}) as resolve, \
             patch.object(orchestration.workers, "run", return_value={"attempt_id": "worker"}) as run:
            self.execute("02-sca-vulnerability-match", request)
        self.assertEqual([call.args[0] for call in execute.call_args_list], ["grype"])
        resolve.assert_called_once()
        resolved = json.loads(Path(run.call_args.args[1]).read_text())
        self.assertEqual(resolved["osv_applicability"], {"decision": "SKIPPED_NA",
            "reason": "no-purl-bearing-components", "examined_component_count": 1,
            "purl_component_count": 0, "purl_component_refs": []})
        self.assertNotIn("osv_b13_attempt", resolved)

    def test_absent_or_stale_snapshot_fails_closed(self):
        outputs = self.jobs / "02-sbom-inventory" / "attempts" / "a" / "outputs"
        outputs.mkdir(parents=True); manifest = outputs / "sbom-manifest.json"; manifest.write_text('{"components": []}')
        accepted = self.jobs / "02-sbom-inventory" / "accepted.json"; accepted.parent.mkdir(exist_ok=True); accepted.write_text("{}")
        registry = Path(self.temp.name) / "offline-registry"; registry.mkdir()
        request = self.request("02-sca-vulnerability-match", {"sbom": {"attempt_id": "a", "path": str(manifest),
            "sha256": "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest(), "accepted_path": str(accepted)}},
            {"sbom_root": str(outputs), "snapshot_registry": str(registry), "max_database_age_seconds": 1,
             "snapshot_identities": [{"database_kind": kind} for kind in ("grype-db", "osv")]})
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
        request = self.request("02-sbom-inventory", {"source_files": {}, "build_index": self.build_index},
                               {"target_path": str(self.owner / "inputs" / "target")})
        with self.assertRaisesRegex(execution_state.Blocked, "canonical jobs root"):
            orchestration.execute(job_id="02-sbom-inventory", run_id=self.run_id,
                input_path=str(request), output_root=str(self.owner / "data"),
                attempt_root=str(self.jobs / "02-sbom-inventory" / "orchestration-attempts" / "x"))

    # --- resume reuse (run 20261004T054551Z-357581) ----------------------------------------------

    def publishing_worker(self, kind, resolved):
        """Stands in for dependency_workers.run: one immutable attempt and the common pointer."""
        request = json.loads(Path(resolved).read_text())
        job = orchestration.workers.JOBS[kind][0]
        root = self.jobs / job
        attempt_id = job + "-" + hashlib.sha256(Path(resolved).read_bytes()).hexdigest()[:20]
        attempt = root / "attempts" / attempt_id
        attempt.mkdir(parents=True)
        envelope = {"attempt_id": attempt_id, "acceptance_status": "CURRENT", "execution_status": "OK",
                    "started_at": request["generated_at"]}
        execution_state.atomic_json(attempt / "result.json", envelope)
        execution_state.atomic_json(root / "latest.json", {"attempt_id": attempt_id})
        execution_state.atomic_json(root / "accepted.json", {
            "schema": "appsec-review/accepted-worker-result/1.0", "run_id": self.run_id, "job": job,
            "attempt_id": attempt_id, "status": "OK", "fingerprint": "sha256:" + "f" * 64,
            "envelope_path": "result.json", "envelope_sha256": execution_state.file_hash(attempt / "result.json"),
            "hashes": execution_state.tree_hashes(attempt), "accepted_at": request["generated_at"]})
        return envelope

    def launch_sbom(self, generated_at, suffix):
        request = self.request("02-sbom-inventory", {"source_files": {"a.c": "sha256:" + "1" * 64},
            "build_index": self.build_index}, {"target_path": str(self.owner / "inputs" / "target")}, generated_at)
        with patch.object(orchestration.b13, "execute", return_value={"b13_attempt": {"verified": True}}) as container, \
             patch.object(orchestration.workers, "run", side_effect=self.publishing_worker):
            envelope = self.execute("02-sbom-inventory", request, suffix)
        return envelope, container.call_count

    def test_unchanged_request_reuses_the_accepted_attempt_without_a_container_call(self):
        first, ran = self.launch_sbom("2026-09-27T12:00:00Z", "auto-launch-1")
        self.assertEqual(ran, 1)
        second, ran = self.launch_sbom("2026-10-04T05:45:51Z", "auto-launch-2")
        self.assertEqual(ran, 0)
        self.assertEqual(second, first)
        self.assertFalse((self.jobs / "02-sbom-inventory" / "orchestration-attempts" / "auto-launch-2").exists())
        record = json.loads((self.jobs / "02-sbom-inventory" / "reuse.json").read_text())
        self.assertEqual(record["inputs"]["payload"]["build_index"],
                         {"sha256": self.build_index["sha256"]})

    def test_changed_upstream_content_re_executes(self):
        first, _ = self.launch_sbom("2026-09-27T12:00:00Z", "auto-launch-1")
        Path(self.build_index["path"]).write_text('{"changed": true}\n')
        self.build_index["sha256"] = "sha256:" + hashlib.sha256(Path(self.build_index["path"]).read_bytes()).hexdigest()
        second, ran = self.launch_sbom("2026-09-27T12:00:00Z", "auto-launch-2")
        self.assertEqual(ran, 1)
        self.assertNotEqual(second["attempt_id"], first["attempt_id"])

    def test_reuse_past_the_database_age_ceiling_re_executes(self):
        outputs = self.jobs / "02-sbom-inventory" / "attempts" / "a" / "outputs"
        outputs.mkdir(parents=True); manifest = outputs / "sbom-manifest.json"; manifest.write_text(json.dumps({
            "components": [{"component_id": "SC-000001", "purl": "pkg:npm/example@1.0.0"}]}))
        accepted = self.jobs / "02-sbom-inventory" / "accepted.json"; accepted.write_text("{}")
        registry = Path(self.temp.name) / "offline-registry"; registry.mkdir()
        payload = {"sbom": {"attempt_id": "a", "path": str(manifest),
                            "sha256": "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest(),
                            "accepted_path": str(accepted)}}
        identities = [{"database_kind": kind, "vendor_build": "v", "schema_version": "1",
                       "snapshot_id": kind + "-one", "sha256": "sha256:" + "2" * 64,
                       "data_timestamp": "2026-09-27T11:00:00Z"} for kind in ("grype-db", "osv")]
        def registered(kind, **kwargs):
            database_kind = "grype-db" if kind == "grype" else "osv"
            return {"b13_attempt": {"kind": kind},
                    "database": next(row for row in identities if row["database_kind"] == database_kind)}
        calls = []
        for generated_at, suffix in (("2026-09-27T11:30:00Z", "one"), ("2026-09-27T11:40:00Z", "two"),
                                     ("2026-09-27T13:00:00Z", "three")):
            request = self.request("02-sca-vulnerability-match", payload,
                {"sbom_root": str(outputs), "snapshot_registry": str(registry), "max_database_age_seconds": 3600,
                 "snapshot_identities": identities}, generated_at)
            with patch.object(orchestration.b13, "execute_registered", side_effect=registered) as execute, \
                 patch.object(orchestration.workers, "run", side_effect=self.publishing_worker):
                self.execute("02-sca-vulnerability-match", request, suffix)
            calls.append(execute.call_count)
        # Reused inside the ceiling; past it the job re-executes (and its worker then refuses the stale DB).
        self.assertEqual(calls, [2, 0, 2])

    def register(self, registry, kind, snapshot_id, data_timestamp, content):
        snapshots = orchestration.snapshots
        source = Path(self.temp.name) / "mirrors" / snapshot_id
        source.mkdir(parents=True)
        (source / "db.bin").write_bytes(content)
        metadata = source.parent / (snapshot_id + ".meta.json")
        metadata.write_text(json.dumps({"database_kind": kind, "vendor_build": "v", "schema_version": "1",
                                        "snapshot_id": snapshot_id, "data_timestamp": data_timestamp}))
        snapshots.register(kind, source, metadata, registry)
        resolved = snapshots.resolve(kind, registry, max_age_seconds=86400,
                                     now=orchestration.datetime.fromisoformat("2026-09-27T12:00:00+00:00"))
        return {key: resolved[key] for key in orchestration._IDENTITY_KEYS}

    def test_a_registry_advance_reuses_the_bound_snapshots_while_they_verify(self):
        outputs = self.jobs / "02-sbom-inventory" / "attempts" / "a" / "outputs"
        outputs.mkdir(parents=True); manifest = outputs / "sbom-manifest.json"; manifest.write_text(json.dumps({
            "components": [{"component_id": "SC-000001", "purl": "pkg:npm/example@1.0.0"}]}))
        accepted = self.jobs / "02-sbom-inventory" / "accepted.json"; accepted.write_text("{}")
        registry = Path(self.temp.name) / "offline-registry"; registry.mkdir()
        payload = {"sbom": {"attempt_id": "a", "path": str(manifest),
                            "sha256": "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest(),
                            "accepted_path": str(accepted)}}
        grype = self.register(registry, "grype-db", "grype-one", "2026-09-27T10:00:00Z", b"grype")
        current = {"grype-db": grype, "osv": self.register(registry, "osv", "osv-one", "2026-09-27T10:00:00Z", b"osv")}
        def registered(kind, **kwargs):
            return {"b13_attempt": {"kind": kind}, "database": current["grype-db" if kind == "grype" else "osv"]}
        def launch(generated_at, suffix):
            request = self.request("02-sca-vulnerability-match", payload,
                {"sbom_root": str(outputs), "snapshot_registry": str(registry), "max_database_age_seconds": 86400,
                 "snapshot_identities": [current["grype-db"], current["osv"]]}, generated_at)
            with patch.object(orchestration.b13, "execute_registered", side_effect=registered) as execute, \
                 patch.object(orchestration.workers, "run", side_effect=self.publishing_worker):
                self.execute("02-sca-vulnerability-match", request, suffix)
            return execute.call_count, json.loads(request.read_text())
        self.assertEqual(launch("2026-09-27T11:00:00Z", "one")[0], 2)
        bound = current["osv"]
        current["osv"] = self.register(registry, "osv", "osv-two", "2026-09-27T12:00:00Z", b"osv")   # 2-hourly sync
        job_root = self.jobs / "02-sca-vulnerability-match"
        record = json.loads((job_root / "reuse.json").read_text())
        calls, request = launch("2026-09-27T13:00:00Z", "two")
        self.assertNotEqual(orchestration.producer_reuse.key(orchestration.reuse_inputs(
            "sca", "02-sca-vulnerability-match", self.run_id, request, self.generation)),
            record["reuse_key"])                         # the request's identities were the false rerun
        self.assertEqual(calls, 0)                       # bound snapshots still verify: reused
        self.assertEqual(orchestration.bound_identities(job_root, request)[1], bound)
        data = registry / "snapshots" / "osv" / "osv-one" / "data" / "db.bin"
        data.write_bytes(b"tampered")                    # a real change: the bound bytes differ
        self.assertIsNone(orchestration.bound_identities(job_root, request))
        self.assertEqual(launch("2026-09-27T13:10:00Z", "three")[0], 2)
        record = json.loads((job_root / "reuse.json").read_text())
        self.assertEqual(record["inputs"]["tool"]["snapshot_identities"][1]["snapshot_id"], "osv-two")

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
