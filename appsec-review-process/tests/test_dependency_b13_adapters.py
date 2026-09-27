from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_execution as ce
import container_execution_support as support
import dependency_b13_adapters as adapters
import dependency_workers as workers
import dependency_snapshot_registry as snapshots
from test_container_execution import ScriptedDocker


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.target = self.root / "target"; self.target.mkdir(); (self.target / "package.json").write_text("{}\n")
        self.sbom = self.root / "sbom"; self.sbom.mkdir(); (self.sbom / "sbom.cdx.json").write_text("{}\n")
        self.database = self.root / "database"; self.database.mkdir(); (self.database / "snapshot").write_text("db\n")
        self.images = self.root / "images"; self.images.mkdir()
        base = support.fixture_record()
        for spec in adapters.SPECS.values():
            record = {**base, "image_id": spec["image"], "repository": "docker.io/library/" + spec["image"]}
            (self.images / (spec["image"] + ".json")).write_text(json.dumps(record))
        self.source = "sha256:" + "a" * 64

    def tearDown(self):
        self.temporary.cleanup()

    def runtime(self):
        defaults = ce.host_defaults()
        return ce.ContainerRuntime(docker_executable=defaults["docker_executable"] or Path(sys.executable).resolve(),
            docker_host=None, images_dir=self.images, host_flavor=defaults["host_flavor"],
            container_user=defaults["container_user"] if ce._USER_RE.match(defaults["container_user"]) else "10001:10001",
            source_snapshot_sha256=self.source, registry_ceiling=[], clock=lambda: support.NOW,
            cancel=threading.Event())

    def execute(self, kind, scripted, output):
        attempt = self.root / ("attempt-" + kind); attempt.mkdir()
        original_child = scripted.child
        def child(spec, **kwargs):
            result = original_child(spec, **kwargs)
            scratch = Path(spec.owner_root) / "scratch"
            scratch.mkdir(exist_ok=True)
            (scratch / adapters.SPECS[kind]["output"]).write_bytes(output)
            return result
        scripted.child = child
        first, second = scripted.patches()
        kwargs = {"target": self.target} if kind in {"syft", "scancode"} else {
            "sbom_root": self.sbom, "database_root": self.database}
        with first, second:
            return adapters.execute(kind, run_id="run-dependency", adapter_attempt_id="tool-attempt",
                source_snapshot_sha256=self.source, attempt_root=attempt,
                supplied_runtime=self.runtime(), **kwargs), attempt

    def write_json(self, name, value):
        path = self.root / name; path.write_text(json.dumps(value, sort_keys=True) + "\n"); return path

    def test_all_requests_are_fixed_offline_read_only_b13_requests(self):
        for kind, spec in adapters.SPECS.items():
            image = {"image_id": spec["image"], "digest": "sha256:" + "b" * 64}
            kwargs = {"target": self.target} if kind in {"syft", "scancode"} else {
                "sbom_root": self.sbom, "database_root": self.database}
            req = adapters.request(kind, run_id="run", adapter_attempt_id="attempt",
                source_snapshot_sha256=self.source, image=image, at=support.NOW, **kwargs)
            self.assertEqual(req["network"], {"mode": "none", "destinations": []})
            self.assertEqual(req["image"]["image_id"], spec["image"])
            self.assertEqual(req["argv"], spec["argv"])
            self.assertTrue(all(mount["container_path"] == "/workspace" or mount["container_path"].startswith("/inputs/")
                                for mount in req["target_mounts"]))
            self.assertEqual(ce.request_errors(req, run_id="run", job_id=spec["job"], attempt_id="attempt"), [])

    def test_scripted_clean_and_hit_outputs_are_reverified_and_receipted(self):
        for label, document in (("clean", {"bomFormat": "CycloneDX", "components": []}),
                                ("hit", {"bomFormat": "CycloneDX", "components": [{"name": "lodash"}]})):
            with self.subTest(label=label):
                result, attempt = self.execute("syft", ScriptedDocker(),
                    (json.dumps(document, sort_keys=True) + "\n").encode())
                receipt = json.loads(Path(result["tool_receipt"]).read_text())
                self.assertEqual(receipt["result_sha256"], adapters._hash_file(Path(result["tool_output"])))
                self.assertEqual(receipt["network_mode"], "none")
                self.assertTrue(receipt["target_read_only"] and receipt["scratch_writable"])
                self.assertEqual(ce.verify_container_result(attempt, run_id="run-dependency",
                    job_id="02-sbom-inventory", attempt_id="tool-attempt", request=result["request"],
                    images_dir=self.images, expected_result_sha256=result["expected_result_sha256"],
                    host_flavor=self.runtime().host_flavor, docker_host=None,
                    docker_executable=self.runtime().docker_executable,
                    container_user=self.runtime().container_user), [])
                shutil.rmtree(attempt)

    def test_scripted_error_and_timeout_are_terminal_blocked_paths(self):
        cases = [ScriptedDocker(client_exit=3),
                 ScriptedDocker(client_exit=-9, metadata={"timed_out": True, "error": "TimeoutError: bounded"})]
        for index, scripted in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaisesRegex(adapters.AdapterBlocked, "pinned tool ended"):
                    self.execute("syft", scripted, b"{}\n")
                shutil.rmtree(self.root / "attempt-syft")

    def test_tampered_b13_log_is_rejected_before_receipt(self):
        scripted = ScriptedDocker()
        real = ce.load_verified_result
        def tamper(attempt_root, **kwargs):
            (Path(attempt_root) / "logs/container/stdout.log").write_bytes(b"tampered\n")
            return real(attempt_root, **kwargs)
        with mock.patch.object(ce, "load_verified_result", side_effect=tamper):
            with self.assertRaisesRegex(adapters.AdapterBlocked, "re-verification"):
                self.execute("syft", scripted, b"{}\n")

    def test_verified_raw_tool_outputs_feed_the_closed_worker_contracts(self):
        source_sha = "sha256:" + "c" * 64
        syft_raw = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{
            "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20",
            "properties": [{"name": "syft:location:0:path", "value": "package-lock.json"}]}]}
        syft, _ = self.execute("syft", ScriptedDocker(), (json.dumps(syft_raw) + "\n").encode())
        common = {"run_id": "run-dependency", "source_snapshot_sha256": self.source,
                  "generated_at": support.NOW, "output_root": str(self.root / "worker-output")}
        sbom_request = self.write_json("sbom-request.json", {**common, "b13_attempt": syft["b13_attempt"],
            "source_files": {"package-lock.json": source_sha}})
        sbom = workers.run("sbom", sbom_request)
        sbom_path = self.root / "worker-output/02-sbom-inventory/attempts" / sbom["attempt_id"] / "outputs/sbom-manifest.json"
        sbom_doc = json.loads(sbom_path.read_text()); component = sbom_doc["components"][0]
        accepted = self.root / "worker-output/02-sbom-inventory/accepted.json"
        sbom_binding = {"attempt_id": sbom["attempt_id"], "path": str(sbom_path),
                        "sha256": workers._hash_file(sbom_path), "accepted_path": str(accepted)}

        grype_raw = {"matches": [{"artifact": {"purl": component["purl"], "cpes": []},
            "vulnerability": {"id": "CVE-2021-23337", "relatedVulnerabilities": [{"id": "GHSA-35jh-r3h4-6jhm"}]}}]}
        osv_raw = {"results": [{"packages": [{"package": {"purl": component["purl"]},
            "vulnerabilities": [{"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"]}]}]}]}
        grype, _ = self.execute("grype", ScriptedDocker(), (json.dumps(grype_raw) + "\n").encode())
        osv, _ = self.execute("osv", ScriptedDocker(), (json.dumps(osv_raw) + "\n").encode())
        databases = [{"database_kind": kind, "vendor_build": "build-1", "schema_version": "1.0",
            "snapshot_id": kind + "-20260927", "sha256": "sha256:" + ("d" if kind == "grype-db" else "e") * 64,
            "data_timestamp": "2026-09-20T11:00:00Z"} for kind in ("grype-db", "osv")]
        sca_request = self.write_json("sca-request.json", {**common, "sbom": sbom_binding,
            "b13_attempt": grype["b13_attempt"], "osv_b13_attempt": osv["b13_attempt"],
            "databases": databases, "max_database_age_seconds": 700000})
        sca = workers.run("sca", sca_request)
        sca_path = self.root / "worker-output/02-sca-vulnerability-match/attempts" / sca["attempt_id"] / "outputs/sca-vulnerability-match.json"
        self.assertEqual(len(json.loads(sca_path.read_text())["matches"]), 1, "Grype and OSV aliases must collapse")

        scan_raw = {"files": [{"path": "LICENSE", "license_detections": [{
            "license_expression_spdx": "MIT", "start_line": 1, "end_line": 1}]}]}
        scan, _ = self.execute("scancode", ScriptedDocker(), (json.dumps(scan_raw) + "\n").encode())
        license_request = self.write_json("license-request.json", {**common, "sbom": sbom_binding,
            "b13_attempt": scan["b13_attempt"],
            "source_files": {"LICENSE": source_sha}})
        license_result = workers.run("license", license_request)
        license_path = self.root / "worker-output/02-license-scan/attempts" / license_result["attempt_id"] / "outputs/license-inventory.json"
        self.assertEqual(json.loads(license_path.read_text())["records"][0]["license_expression"], "MIT")

    def test_registered_grype_and_osv_snapshots_drive_positive_b13_paths(self):
        registry = self.root / "snapshot-registry"
        for kind, database_kind, document in (("grype", "grype-db", {"matches": []}),
                                               ("osv", "osv", {"results": []})):
            supplied = self.root / (database_kind + "-supplied"); supplied.mkdir(); (supplied / "database.bin").write_bytes(b"fixture")
            metadata = self.write_json(database_kind + "-metadata.json", {"database_kind": database_kind,
                "vendor_build": "vendor-1", "schema_version": "1.0", "snapshot_id": database_kind + "-fixture",
                "data_timestamp": "2026-09-20T11:00:00Z"})
            snapshots.register(database_kind, supplied, metadata, registry)
            attempt = self.root / ("registered-" + kind); attempt.mkdir(); scripted = ScriptedDocker()
            original = scripted.child
            def child(spec, **kwargs):
                result = original(spec, **kwargs); scratch = Path(spec.owner_root) / "scratch"; scratch.mkdir(exist_ok=True)
                (scratch / adapters.SPECS[kind]["output"]).write_text(json.dumps(document) + "\n"); return result
            scripted.child = child; first, second = scripted.patches()
            with first, second:
                result = adapters.execute_registered(kind, snapshot_registry=registry, max_age_seconds=700000,
                    run_id="run-dependency", adapter_attempt_id=kind + "-registered", source_snapshot_sha256=self.source,
                    attempt_root=attempt, sbom_root=self.sbom, supplied_runtime=self.runtime())
            self.assertEqual(result["database"]["database_kind"], database_kind)

    def test_registered_snapshot_absent_and_stale_remain_distinct_blockers(self):
        registry = self.root / "snapshot-registry"
        attempt = self.root / "registered-absent"; attempt.mkdir()
        with self.assertRaisesRegex(adapters.AdapterBlocked, "snapshot absent"):
            adapters.execute_registered("grype", snapshot_registry=registry, max_age_seconds=60,
                run_id="run-dependency", adapter_attempt_id="absent", source_snapshot_sha256=self.source,
                attempt_root=attempt, sbom_root=self.sbom, supplied_runtime=self.runtime())
        supplied = self.root / "old-supplied"; supplied.mkdir(); (supplied / "database.bin").write_bytes(b"fixture")
        metadata = self.write_json("old.json", {"database_kind": "grype-db", "vendor_build": "vendor-1",
            "schema_version": "1.0", "snapshot_id": "old", "data_timestamp": "2026-01-01T00:00:00Z"})
        snapshots.register("grype-db", supplied, metadata, registry)
        with self.assertRaisesRegex(adapters.AdapterBlocked, "snapshot stale"):
            adapters.execute_registered("grype", snapshot_registry=registry, max_age_seconds=60,
                run_id="run-dependency", adapter_attempt_id="stale", source_snapshot_sha256=self.source,
                attempt_root=attempt, sbom_root=self.sbom, supplied_runtime=self.runtime())

    def test_live_syft_and_scancode_smoke_when_registry_and_images_are_present(self):
        registry_dir = Path(os.environ.get("APPSEC_TEST_B16_REGISTRY", str(ce.IMAGES_DIR)))
        try:
            registry = ce.load_image_registry(registry_dir)
            defaults = ce.host_defaults()
        except ce.ContainerRequestError:
            self.skipTest("host B16 registry is unavailable")
        if not {"tool-syft", "scancode-toolkit"}.issubset(registry) or defaults["docker_executable"] is None:
            self.skipTest("Syft/ScanCode B16 records or Docker are unavailable")
        import subprocess
        for image_id in ("tool-syft", "scancode-toolkit"):
            reference = ce.image_reference(registry[image_id])
            if subprocess.run([str(defaults["docker_executable"]), "image", "inspect", reference],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode:
                self.skipTest(f"pinned {image_id} image is not provisioned")
        attempt = self.root / "live-attempt"; attempt.mkdir()
        live_runtime = ce.ContainerRuntime(docker_executable=defaults["docker_executable"], docker_host=None,
            images_dir=registry_dir, host_flavor=defaults["host_flavor"],
            container_user=defaults["container_user"] if ce._USER_RE.match(defaults["container_user"]) else "10001:10001",
            source_snapshot_sha256=self.source, registry_ceiling=[], clock=adapters._clock,
            cancel=threading.Event())
        result = adapters.execute("syft", run_id="live-dependency-smoke", adapter_attempt_id="syft-live",
            source_snapshot_sha256=self.source, attempt_root=attempt, target=self.target,
            supplied_runtime=live_runtime)
        self.assertTrue(Path(result["tool_output"]).is_file())
        scan_attempt = self.root / "live-scan-attempt"; scan_attempt.mkdir()
        scan = adapters.execute("scancode", run_id="live-dependency-smoke", adapter_attempt_id="scancode-live",
            source_snapshot_sha256=self.source, attempt_root=scan_attempt, target=self.target,
            supplied_runtime=live_runtime)
        self.assertTrue(Path(scan["tool_output"]).is_file())

    def test_live_osv_registry_record_resolves_to_the_pinned_local_image(self):
        registry_dir = Path(os.environ.get("APPSEC_TEST_B16_REGISTRY", str(ce.IMAGES_DIR)))
        try:
            registry = ce.load_image_registry(registry_dir); defaults = ce.host_defaults()
        except ce.ContainerRequestError:
            self.skipTest("host B16 registry is unavailable")
        if "tool-osv-scanner" not in registry or defaults["docker_executable"] is None:
            self.skipTest("OSV Scanner B16 record or Docker is unavailable")
        record = registry["tool-osv-scanner"]
        self.assertEqual(record["image_id"], adapters.SPECS["osv"]["image"])
        import subprocess
        completed = subprocess.run([str(defaults["docker_executable"]), "image", "inspect",
                                    ce.image_reference(record)], capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, "B16 OSV record must resolve to its pinned local image")


if __name__ == "__main__":
    unittest.main()
