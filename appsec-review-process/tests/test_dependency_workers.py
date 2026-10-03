from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import registry_paths
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dependency_workers as workers
import sbom_family_contracts as sbom_contracts
import dependency_b13_adapters as adapters
import container_execution as ce
import container_execution_support as support
from test_container_execution import ScriptedDocker
from schema_validate import validate_document
from worker_result import artifact_records, terminal_envelope


def payload(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha_bytes(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


class DependencyWorkersTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.out = self.root / "runs"
        self.source = "sha256:" + "1" * 64
        self.run_id = "run-dependency-fixture"
        self.when = "2026-09-27T12:00:00Z"
        self.target = self.root / "target"; self.target.mkdir(); (self.target / "package.json").write_text("{}\n")
        self.sbom_input = self.root / "sbom-input"; self.sbom_input.mkdir(); (self.sbom_input / "sbom.cdx.json").write_text("{}\n")
        self.database = self.root / "database"; self.database.mkdir(); (self.database / "db").write_text("fixture\n")
        self.images = self.root / "images"; self.images.mkdir(); self.tool_counter = 0
        base = support.fixture_record()
        for spec in adapters.SPECS.values():
            record = {**base, "image_id": spec["image"], "repository": "docker.io/library/" + spec["image"]}
            (self.images / (spec["image"] + ".json")).write_text(json.dumps(record))
        build_root = self.out / "02-build-index"; build_attempt = build_root / "attempts" / "build-one"
        build_attempt.mkdir(parents=True)
        self.build_index_path = build_attempt / "build-index.json"
        self.build_index_path.write_bytes(payload({"schema": "appsec-review/build-index/1", "units": []}))
        envelope = terminal_envelope(run_id=self.run_id, job_id="02-build-index", attempt_id="build-one",
            worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
            input_fingerprint="sha256:" + "9" * 64, output_contract="build-index",
            started_at=self.when, finished_at=self.when, summary="fixture",
            artifacts=artifact_records(build_attempt, ["build-index.json"]))
        (build_attempt / "result.json").write_bytes(payload(envelope))
        build_root.mkdir(parents=True, exist_ok=True)
        self.build_pointer = build_root / "accepted.json"
        self.build_pointer.write_bytes(payload({"schema": "appsec-review/accepted-worker-result/1.0",
            "run_id": self.run_id, "job": "02-build-index", "attempt_id": "build-one", "status": "OK",
            "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
            "envelope_sha256": workers._hash_file(build_attempt / "result.json").split(":", 1)[1]}))
        self.build_index = {"attempt_id": "build-one", "path": str(self.build_index_path),
            "sha256": workers._hash_file(self.build_index_path), "accepted_path": str(self.build_pointer)}

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload(value))
        return path

    def tool(self, job, name, value):
        kinds = {"syft": "syft", "syft-directory": "syft", "grype": "grype",
                 "osv-scanner": "osv", "scancode": "scancode", "scancode-toolkit": "scancode"}
        kind = kinds[name]; self.tool_counter += 1
        attempt = self.root / f"b13-{kind}-{self.tool_counter}"; attempt.mkdir()
        scripted = ScriptedDocker(); original = scripted.child
        def child(spec, **kwargs):
            result = original(spec, **kwargs); scratch = Path(spec.owner_root) / "scratch"; scratch.mkdir(exist_ok=True)
            (scratch / adapters.SPECS[kind]["output"]).write_bytes(payload(value)); return result
        scripted.child = child; first, second = scripted.patches()
        defaults = ce.host_defaults()
        runtime = ce.ContainerRuntime(docker_executable=defaults["docker_executable"] or Path(sys.executable).resolve(),
            docker_host=None, images_dir=self.images, host_flavor=defaults["host_flavor"],
            container_user=defaults["container_user"] if ce._USER_RE.match(defaults["container_user"]) else "10001:10001",
            source_snapshot_sha256=self.source, registry_ceiling=[], clock=lambda: self.when,
            cancel=threading.Event())
        kwargs = {"target": self.target} if kind in {"syft", "scancode"} else {
            "sbom_root": self.sbom_input, "database_root": self.database}
        with first, second:
            result = adapters.execute(kind, run_id=self.run_id, adapter_attempt_id=f"{kind}-{self.tool_counter}",
                source_snapshot_sha256=self.source, attempt_root=attempt, supplied_runtime=runtime, **kwargs)
        return Path(result["tool_output"]), Path(result["tool_receipt"]), result["b13_attempt"]

    def request(self, **extra):
        if isinstance(extra.get("expected_tool"), dict) and "attempt_root" in extra["expected_tool"]:
            extra["b13_attempt"] = extra.pop("expected_tool"); extra.pop("tool_output", None); extra.pop("tool_receipt", None)
        if isinstance(extra.get("osv_expected_tool"), dict) and "attempt_root" in extra["osv_expected_tool"]:
            extra["osv_b13_attempt"] = extra.pop("osv_expected_tool"); extra.pop("osv_tool_output", None); extra.pop("osv_tool_receipt", None)
        b13 = extra.get("b13_attempt")
        if isinstance(b13, dict) and b13.get("request", {}).get("job_id") == "02-sbom-inventory":
            extra.setdefault("build_index", self.build_index)
            extra.setdefault("source_files", {
                "package-lock.json": "sha256:" + "2" * 64,
                "vendor/cJSON-1.7.18/cJSON.c": "sha256:" + "3" * 64,
                "vendor/cJSON-1.7.18/cJSON.h": "sha256:" + "4" * 64,
            })
        if "databases" in extra and isinstance(extra.get("sbom"), dict):
            sbom = json.loads(Path(extra["sbom"]["path"]).read_text())
            refs = sorted(row["component_id"] for row in sbom["components"] if row.get("purl"))
            extra.setdefault("osv_applicability", {"decision": "EXECUTE" if refs else "SKIPPED_NA",
                "reason": None if refs else "no-purl-bearing-components",
                "examined_component_count": len(sbom["components"]), "purl_component_count": len(refs),
                "purl_component_refs": refs})
        return {"run_id": self.run_id, "source_snapshot_sha256": self.source,
                "generated_at": self.when, "output_root": str(self.out), **extra}

    def osv(self):
        output, receipt, expected = self.tool("02-sca-vulnerability-match", "osv-scanner", {"results": []})
        return {"osv_tool_output": str(output), "osv_tool_receipt": str(receipt), "osv_expected_tool": expected}

    def run_request(self, kind, name, request):
        path = self.write(name + "-request.json", request)
        return workers.run(kind, path)

    def result_path(self, envelope, relative):
        return self.out / envelope["job_id"] / "attempts" / envelope["attempt_id"] / relative

    def binding(self, envelope, relative):
        path = self.result_path(envelope, relative)
        accepted = self.out / envelope["job_id"] / "accepted.json"
        return {"attempt_id": envelope["attempt_id"], "path": str(path), "sha256": workers._hash_file(path),
                "accepted_path": str(accepted)}

    def happy_chain(self):
        source_hash = "sha256:" + "2" * 64
        sbom_tool, sbom_receipt, sbom_expected = self.tool("02-sbom-inventory", "syft-directory", {"components": [{
            "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20", "cpe": None,
            "ecosystem": "npm", "declaration": "declared",
            "source": {"path": "package-lock.json", "sha256": source_hash},
        }]})
        sbom = self.run_request("sbom", "sbom", self.request(tool_output=str(sbom_tool),
            tool_receipt=str(sbom_receipt), expected_tool=sbom_expected))
        databases = [{"database_kind": kind, "vendor_build": "build-1", "schema_version": "1.0",
            "snapshot_id": kind + "-20260927", "sha256": "sha256:" + hashlib.sha256(kind.encode()).hexdigest(),
            "data_timestamp": "2026-09-27T11:00:00Z"} for kind in ("grype-db", "osv")]
        sca_tool, sca_receipt, sca_expected = self.tool("02-sca-vulnerability-match", "grype", {"matches": [{
            "component_ref": json.loads(self.result_path(sbom, "outputs/sbom-manifest.json").read_text())["components"][0]["component_id"],
            "aliases": ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"], "database": "grype-db",
            "advisory_id": "CVE-2021-23337", "match_basis": "purl",
        }]})
        sca = self.run_request("sca", "sca", self.request(sbom=self.binding(sbom, "outputs/sbom-manifest.json"),
            tool_output=str(sca_tool), tool_receipt=str(sca_receipt), expected_tool=sca_expected,
            databases=databases, max_database_age_seconds=7200, **self.osv()))
        license_tool, license_receipt, license_expected = self.tool("02-license-scan", "scancode-toolkit", {"records": [{
            "assertion": "license-text-detected", "component_ref": json.loads(self.result_path(sbom, "outputs/sbom-manifest.json").read_text())["components"][0]["component_id"],
            "license_expression": "MIT", "expression_state": "spdx-expression",
            "claim_source": {"kind": "found-in-file", "path": "LICENSE", "sha256": source_hash,
                             "start_line": 1, "end_line": 1},
        }]})
        license_result = self.run_request("license", "license", self.request(
            sbom=self.binding(sbom, "outputs/sbom-manifest.json"), tool_output=str(license_tool),
            tool_receipt=str(license_receipt), expected_tool=license_expected))
        table = self.write("lifecycle.json", {"schema": "appsec-review/dependency-lifecycle-reference-table/1.0",
            "table_id": "fixture-eol", "version": "2026.09", "as_of": "2026-09-26", "rows": [{
                "row_id": "lodash-4", "ecosystem": "npm", "name": "lodash", "cycle": "4",
                "status": "supported", "eol_date": None}]})
        lifecycle = self.run_request("lifecycle", "lifecycle", self.request(
            sbom=self.binding(sbom, "outputs/sbom-manifest.json"),
            license=self.binding(license_result, "outputs/license-inventory.json"),
            reference_table=str(table), reference_table_sha256=workers._hash_file(table), max_reference_age_days=7))
        match = json.loads(self.result_path(sca, "outputs/sca-vulnerability-match.json").read_text())["matches"][0]
        evidence = self.write("reachability.json", {"assessments": [{"match_ref": match["match_id"],
            "classification": "reachable", "evidence": [{"kind": "call", "path": "src/index.js",
                "sha256": source_hash, "locator": "line:12 lodash.merge"}]}]})
        reachability = self.run_request("reachability", "reachability", self.request(
            sca=self.binding(sca, "outputs/sca-vulnerability-match.json"), reachability_evidence=str(evidence),
            reachability_evidence_sha256=workers._hash_file(evidence)))
        return sbom, sca, license_result, lifecycle, reachability

    def test_complete_chain_is_schema_valid_and_reusable(self):
        results = self.happy_chain()
        schema_by_job = {"02-sbom-inventory": ("outputs/sbom-manifest.json", "sbom-inventory.schema.json"),
            "02-sca-vulnerability-match": ("outputs/sca-vulnerability-match.json", "sca-vulnerability-match.schema.json"),
            "02-license-scan": ("outputs/license-inventory.json", "license-inventory.schema.json"),
            "02-dependency-lifecycle": ("outputs/dependency-lifecycle.json", "dependency-lifecycle.schema.json"),
            "06-cve-reachability": ("outputs/cve-reachability.json", "cve-reachability.schema.json")}
        for envelope in results:
            relative, schema = schema_by_job[envelope["job_id"]]
            self.assertEqual(validate_document(json.loads(self.result_path(envelope, relative).read_text()), schema), [])
            self.assertEqual(envelope["acceptance_status"], "CURRENT")
            attempt = self.out / envelope["job_id"] / "attempts" / envelope["attempt_id"]
            permission = json.loads((attempt / "permission.json").read_text())
            lineage = json.loads((attempt / "lineage.json").read_text())
            template = json.loads((registry_paths.JOB_TEMPLATES_DIR /
                                   f"{envelope['job_id']}.json").read_text())
            self.assertEqual(permission, {"schema": workers.PERMISSION_SCHEMA, "run_id": self.run_id,
                "job_id": envelope["job_id"], "source_snapshot_sha256": self.source,
                "permissions": template["permissions"]})
            self.assertEqual(lineage["source_snapshot_sha256"], self.source)
            self.assertRegex(lineage["build_lineage_sha256"], r"^sha256:[0-9a-f]{64}$")
            self.assertTrue({"permission.json", "lineage.json"}.issubset(
                {item["path"] for item in envelope["artifacts"]}))
        request_path = self.root / "reachability-request.json"
        self.assertEqual(workers.run("reachability", request_path), results[-1])

    def test_immutable_reuse_rehashes_every_artifact(self):
        results = self.happy_chain()
        request_path = self.root / "reachability-request.json"
        evidence_identity = self.result_path(results[-1], "outputs/reachability-evidence-identity.json")
        evidence_identity.write_bytes(payload({"tampered": True}))
        with self.assertRaisesRegex(workers.WorkerBlocked, "artifact changed"):
            workers.run("reachability", request_path)

    def test_immutable_reuse_rejects_changed_producer_receipt(self):
        result = self.happy_chain()[-1]
        request_path = self.root / "reachability-request.json"
        receipt = self.out / result["job_id"] / "attempts" / result["attempt_id"] / "permission.json"
        changed = json.loads(receipt.read_text()); changed["permissions"] = []
        receipt.write_bytes(payload(changed))
        with self.assertRaisesRegex(workers.WorkerBlocked, "artifact changed"):
            workers.run("reachability", request_path)

    def test_implementation_version_prevents_reuse_of_receiptless_v1_attempt(self):
        request = self.request()
        old = workers._hash_bytes(workers._canonical(
            {"kind": "sbom", "request": request, "implementation": "dependency-workers-v1"}))
        new = workers._hash_bytes(workers._canonical(
            {"kind": "sbom", "request": request, "implementation": workers.IMPLEMENTATION}))
        self.assertNotEqual(old, new)

    def test_producer_lineage_binds_request_upstreams_but_not_publication_root(self):
        request = self.request(upstream={"attempt_id": "one", "sha256": "sha256:" + "a" * 64})
        first = workers._producer_receipts(request, "02-sbom-inventory")[1]["build_lineage_sha256"]
        relocated = {**request, "output_root": str(self.root / "elsewhere")}
        self.assertEqual(first, workers._producer_receipts(relocated, "02-sbom-inventory")[1]["build_lineage_sha256"])
        changed = {**request, "upstream": {"attempt_id": "two", "sha256": "sha256:" + "b" * 64}}
        self.assertNotEqual(first, workers._producer_receipts(changed, "02-sbom-inventory")[1]["build_lineage_sha256"])

    def test_receipt_only_bundle_cannot_substitute_for_a_b13_attempt(self):
        output = self.write("syft.json", {"components": []})
        request = self.request(tool_output=str(output), tool_receipt=str(self.root / "missing.json"),
                               expected_tool={"tool_id": "syft", "image_id": "tool-syft", "image_digest": "sha256:" + "3" * 64,
                                              "boundary_sha256": "sha256:" + "4" * 64})
        with self.assertRaisesRegex(workers.WorkerBlocked, "immutable B13 attempt binding"):
            self.run_request("sbom", "missing", request)
        self.assertFalse((self.out / "02-sbom-inventory").exists())

    def test_valid_cyclonedx_without_components_is_accepted_with_bounded_gap(self):
        output, receipt, expected = self.tool("02-sbom-inventory", "syft", {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "file", "name": "/workspace"}}})
        envelope = self.run_request("sbom", "empty-cyclonedx", self.request(
            tool_output=str(output), tool_receipt=str(receipt), expected_tool=expected))
        result = json.loads(self.result_path(envelope, "outputs/sbom-manifest.json").read_text())
        self.assertEqual(result["components"], [])
        self.assertEqual(envelope["execution_status"], "OK_WITH_GAPS")
        self.assertEqual(envelope["gaps"], ["no-dependency-components-detected"])

    def test_hello_build_index_enriches_empty_syft_with_cjson_purl_and_cpe(self):
        self.build_index_path.write_bytes(payload({"schema": "appsec-review/build-index/1", "units": [{
            "unit_id": "dir:.", "members": [{"path": "vendor/cJSON-1.7.18",
                "reason": "referenced-by-parent-build", "signal_ids": ["s0005"], "manifests": []}]}]}))
        build_attempt = self.build_index_path.parent
        envelope = terminal_envelope(run_id=self.run_id, job_id="02-build-index", attempt_id="build-one",
            worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
            input_fingerprint="sha256:" + "8" * 64, output_contract="build-index",
            started_at=self.when, finished_at=self.when, summary="hello build index",
            artifacts=artifact_records(build_attempt, ["build-index.json"]))
        (build_attempt / "result.json").write_bytes(payload(envelope))
        self.build_pointer.write_bytes(payload({"schema": "appsec-review/accepted-worker-result/1.0",
            "run_id": self.run_id, "job": "02-build-index", "attempt_id": "build-one", "status": "OK",
            "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
            "envelope_sha256": workers._hash_file(build_attempt / "result.json").split(":", 1)[1]}))
        self.build_index["sha256"] = workers._hash_file(self.build_index_path)
        output, receipt, expected = self.tool("02-sbom-inventory", "syft", {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": []})
        result_envelope = self.run_request("sbom", "hello-cjson", self.request(
            tool_output=str(output), tool_receipt=str(receipt), expected_tool=expected))
        result = json.loads(self.result_path(result_envelope, "outputs/sbom-manifest.json").read_text())
        self.assertEqual([(row["name"], row["version"]) for row in result["components"]], [("cJSON", "1.7.18")])
        component = result["components"][0]
        self.assertEqual(component["declaration"], "inferred-vendored")
        # No cJSON.h bytes under the target match the fixture hash, so the version is the directory's.
        self.assertEqual((component["purl"], component["cpe"]), ("pkg:github/davegamble/cjson@v1.7.18",
                         "cpe:2.3:a:cjson_project:cjson:1.7.18:*:*:*:*:*:*:*"))
        self.assertEqual(component["tool_id"], "build-index-vendored-member")
        self.assertEqual(result_envelope["gaps"], [])
        enrichment = json.loads(self.result_path(
            result_envelope, "outputs/build-index-vendored-members.json").read_text())
        self.assertEqual(enrichment["build_index_binding"]["attempt_id"], "build-one")
        self.assertEqual(enrichment["members"][0]["version_source"], "directory-name")
        self.assertEqual([error for error in sbom_contracts._component_errors(result["components"])
                          if error.startswith("purl-mismatch")], [])
        cdx_path = self.result_path(result_envelope, "outputs/sbom.cdx.json")
        self.assertEqual(sbom_contracts._cdx_errors(cdx_path.read_bytes(), result), [])
        enrichment_path = self.result_path(result_envelope, "outputs/build-index-vendored-members.json")
        self.assertEqual(sbom_contracts.build_index_enrichment_errors(result, enrichment_path.read_bytes()), [])
        self.assertEqual(component["citation"]["path"], "outputs/build-index-vendored-members.json")

        grype_output, grype_receipt, grype_expected = self.tool(
            "02-sca-vulnerability-match", "grype", {"matches": []})
        databases = [{"database_kind": kind, "vendor_build": "build-1", "schema_version": "1.0",
            "snapshot_id": kind + "-20260927", "sha256": "sha256:" + hashlib.sha256(kind.encode()).hexdigest(),
            "data_timestamp": "2026-09-27T11:00:00Z"} for kind in ("grype-db", "osv")]
        sca_request = self.request(sbom=self.binding(result_envelope, "outputs/sbom-manifest.json"),
            tool_output=str(grype_output), tool_receipt=str(grype_receipt), expected_tool=grype_expected,
            databases=databases, max_database_age_seconds=7200, **self.osv())
        sca_envelope = self.run_request("sca", "hello-cjson-sca", sca_request)
        self.assertNotIn("OSV_SKIPPED_NA_NO_PURL_COMPONENTS", sca_envelope["gaps"])
        self.assertNotIn("SCA_COMPONENT_GAPS", sca_envelope["gaps"])
        receipt = json.loads(self.result_path(
            sca_envelope, "outputs/osv-applicability-receipt.json").read_text())
        self.assertEqual((receipt["decision"], receipt["reason"]), ("EXECUTE", None))
        self.assertEqual(receipt["purl_component_refs"], [component["component_id"]])

    def test_sbom_rejects_stale_build_index_pointer(self):
        output, receipt, expected = self.tool("02-sbom-inventory", "syft", {"components": []})
        pointer = json.loads(self.build_pointer.read_text()); pointer["attempt_id"] = "newer-build"
        self.build_pointer.write_bytes(payload(pointer))
        with self.assertRaisesRegex(workers.WorkerBlocked, "accepted"):
            self.run_request("sbom", "stale-build-index", self.request(
                tool_output=str(output), tool_receipt=str(receipt), expected_tool=expected))

    def test_new_verified_generation_atomically_supersedes_the_pointer(self):
        output, receipt, expected = self.tool("02-sbom-inventory", "syft", {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "file", "name": "/workspace"}}})
        first = self.run_request("sbom", "first", self.request(
            tool_output=str(output), tool_receipt=str(receipt), expected_tool=expected))
        second_request = self.request(
            tool_output=str(output), tool_receipt=str(receipt), expected_tool=expected)
        second_request["generated_at"] = "2026-09-27T12:01:00Z"
        second = self.run_request("sbom", "second", second_request)
        self.assertNotEqual(first["attempt_id"], second["attempt_id"])
        accepted = json.loads((self.out / "02-sbom-inventory" / "accepted.json").read_text())
        self.assertEqual(accepted["attempt_id"], second["attempt_id"])

    def test_mutated_receipt_from_real_attempt_is_rejected(self):
        _output, receipt, binding = self.tool("02-sbom-inventory", "syft", {"components": []})
        forged = json.loads(receipt.read_text()); forged["tool_id"] = "caller-selected-tool"
        receipt.write_bytes(payload(forged))
        with self.assertRaisesRegex(workers.WorkerBlocked, "not derived from the verified B13 attempt"):
            self.run_request("sbom", "forged-receipt", self.request(b13_attempt=binding))
        self.assertFalse((self.out / "02-sbom-inventory").exists())

    def test_cross_matched_output_and_receipt_mutation_is_rejected_by_b13(self):
        output, receipt, binding = self.tool("02-sbom-inventory", "syft", {"components": []})
        output.write_bytes(payload({"components": [{"name": "fabricated"}]}))
        forged = json.loads(receipt.read_text()); forged["result_sha256"] = workers._hash_file(output)
        receipt.write_bytes(payload(forged))
        with self.assertRaisesRegex(workers.WorkerBlocked, "externally retained hash"):
            self.run_request("sbom", "cross-matched-forgery", self.request(b13_attempt=binding))
        self.assertFalse((self.out / "02-sbom-inventory").exists())

    def test_stale_database_blocks(self):
        sbom_tool, receipt, expected = self.tool("02-sbom-inventory", "syft", {"components": []})
        sbom = self.run_request("sbom", "sbom", self.request(tool_output=str(sbom_tool), tool_receipt=str(receipt), expected_tool=expected))
        tool, receipt, expected = self.tool("02-sca-vulnerability-match", "grype", {"matches": []})
        databases = [{"database_kind": kind, "vendor_build": "b", "schema_version": "1", "snapshot_id": "s",
            "sha256": "sha256:" + "4" * 64, "data_timestamp": "2026-09-01T00:00:00Z"} for kind in ("grype-db", "osv")]
        request = self.request(sbom=self.binding(sbom, "outputs/sbom-manifest.json"), tool_output=str(tool),
            tool_receipt=str(receipt), expected_tool=expected, databases=databases, max_database_age_seconds=60,
            **self.osv())
        with self.assertRaisesRegex(workers.WorkerBlocked, "stale"):
            self.run_request("sca", "stale", request)

    def test_version_match_cannot_be_promoted_to_reachable(self):
        _sbom, sca, _license, _lifecycle, _reachability = self.happy_chain()
        match = json.loads(self.result_path(sca, "outputs/sca-vulnerability-match.json").read_text())["matches"][0]
        evidence = self.write("bad-evidence.json", {"assessments": [{"match_ref": match["match_id"],
            "classification": "reachable", "evidence": []}]})
        request = self.request(sca=self.binding(sca, "outputs/sca-vulnerability-match.json"),
            reachability_evidence=str(evidence), reachability_evidence_sha256=workers._hash_file(evidence))
        with self.assertRaisesRegex(workers.WorkerBlocked, "version match alone"):
            self.run_request("reachability", "bad-reachability", request)

    def test_upstream_result_must_be_the_accepted_generation(self):
        sbom_tool, receipt, expected = self.tool("02-sbom-inventory", "syft", {"components": []})
        sbom = self.run_request("sbom", "sbom", self.request(tool_output=str(sbom_tool), tool_receipt=str(receipt), expected_tool=expected))
        binding = self.binding(sbom, "outputs/sbom-manifest.json")
        accepted = Path(binding["accepted_path"])
        pointer = json.loads(accepted.read_text())
        pointer["attempt_id"] = "forged-generation"
        accepted.write_bytes(payload(pointer))
        tool, receipt, expected = self.tool("02-license-scan", "scancode", {"records": []})
        request = self.request(sbom=binding, tool_output=str(tool), tool_receipt=str(receipt), expected_tool=expected)
        with self.assertRaisesRegex(workers.WorkerBlocked, "exact accepted"):
            self.run_request("license", "forged", request)

    def test_osv_cannot_assert_a_cpe_match(self):
        source_hash = "sha256:" + "2" * 64
        sbom_tool, receipt, expected = self.tool("02-sbom-inventory", "syft", {"components": [{
            "name": "widget", "version": "1.2.3", "purl": "pkg:generic/widget@1.2.3",
            "cpe": "cpe:2.3:a:vendor:widget:1.2.3:*:*:*:*:*:*:*", "ecosystem": "generic",
            "declaration": "inferred-vendored", "source": {"path": "vendor/widget.c", "sha256": source_hash}}]})
        sbom = self.run_request("sbom", "sbom", self.request(tool_output=str(sbom_tool), tool_receipt=str(receipt), expected_tool=expected))
        component = json.loads(self.result_path(sbom, "outputs/sbom-manifest.json").read_text())["components"][0]
        tool, receipt, expected = self.tool("02-sca-vulnerability-match", "grype", {"matches": [{
            "component_ref": component["component_id"], "aliases": ["CVE-2026-12345"], "database": "osv",
            "advisory_id": "CVE-2026-12345", "match_basis": "cpe"}]})
        databases = [{"database_kind": kind, "vendor_build": "build-1", "schema_version": "1.0",
            "snapshot_id": kind + "-20260927", "sha256": "sha256:" + hashlib.sha256(kind.encode()).hexdigest(),
            "data_timestamp": "2026-09-27T11:00:00Z"} for kind in ("grype-db", "osv")]
        request = self.request(sbom=self.binding(sbom, "outputs/sbom-manifest.json"), tool_output=str(tool),
            tool_receipt=str(receipt), expected_tool=expected, databases=databases, max_database_age_seconds=7200,
            **self.osv())
        with self.assertRaisesRegex(workers.WorkerBlocked, "basis"):
            self.run_request("sca", "bad-basis", request)


if __name__ == "__main__":
    unittest.main()


class OsvCoverageTests(unittest.TestCase):
    """Run 20261001T032047Z-fd64eb: osv-scanner exited 127 with no PyPI/Maven database (accepted as a
    coverage gap), yet every component was listed as evaluated by OSV and no gap was recorded."""

    STDERR = ("Scanned /inputs/sbom/sbom.cdx.json as CycloneDX SBOM and found 16 packages\n"
              "could not find local databases for ecosystems: Maven, PyPI, github:actions, github:dtolnay\n")

    def test_missing_ecosystems_are_parsed(self):
        import dependency_workers as workers
        self.assertEqual(workers.osv_missing_ecosystems(self.STDERR),
                         ["Maven", "PyPI", "github:actions", "github:dtolnay"])
        self.assertEqual(workers.osv_missing_ecosystems("Scanned 3 packages\n"), [])

    def test_only_components_with_a_database_count_as_osv_evaluated(self):
        import dependency_workers as workers
        missing = workers.osv_missing_ecosystems(self.STDERR)
        self.assertFalse(workers.osv_covers("pkg:pypi/pyyaml@5.3.1", missing))
        self.assertFalse(workers.osv_covers("pkg:maven/commons-collections/commons-collections@3.2.1", missing))
        self.assertFalse(workers.osv_covers("pkg:github/actions/checkout@v4", missing))
        self.assertTrue(workers.osv_covers("pkg:npm/lodash@4.17.15", missing))
        self.assertFalse(workers.osv_covers("pkg:unknowntype/x@1", []))


class ManifestCoverageTests(unittest.TestCase):
    def test_manifests_without_components_are_gaps_per_ecosystem(self):
        import dependency_workers as workers
        paths = ["projects/javascript/case-031/package.json", "projects/python/case-078/requirements.txt",
                 "projects/rust/case-033/Cargo.toml", "projects/dotnet/case-035/app.csproj",
                 "projects/cpp/case-045/third_party/x/package.json", "README.md"]
        components = [{"source": {"path": "projects/python/case-078/requirements.txt"}}]
        gaps = workers.uninventoried_manifests(paths, components)
        self.assertEqual([g.split(":")[1].strip() for g in gaps], ["cargo", "npm", "nuget"])
        self.assertIn("projects/javascript/case-031/package.json", gaps[1])
        self.assertNotIn("third_party", " ".join(gaps))
        self.assertEqual(workers.uninventoried_manifests({}, []), [])
