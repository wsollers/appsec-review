from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dependency_workers as workers
from schema_validate import validate_document


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

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload(value))
        return path

    def tool(self, job, name, value):
        output = self.write(name + ".json", value)
        expected = {"tool_id": name, "image_id": "tool-" + name,
                    "image_digest": "sha256:" + hashlib.sha256(("image:" + name).encode()).hexdigest()}
        receipt = self.write(name + "-receipt.json", {
            "schema": workers.PINNED_RECEIPT_SCHEMA, "run_id": self.run_id, "job_id": job,
            "attempt_id": name + "-b13-attempt", **expected, "result_sha256": workers._hash_file(output),
            "source_snapshot_sha256": self.source, "completed_at": self.when,
        })
        return output, receipt, expected

    def request(self, **extra):
        return {"run_id": self.run_id, "source_snapshot_sha256": self.source,
                "generated_at": self.when, "output_root": str(self.out), **extra}

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
            databases=databases, max_database_age_seconds=7200))
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
        request_path = self.root / "reachability-request.json"
        self.assertEqual(workers.run("reachability", request_path), results[-1])

    def test_immutable_reuse_rehashes_every_artifact(self):
        results = self.happy_chain()
        request_path = self.root / "reachability-request.json"
        evidence_identity = self.result_path(results[-1], "outputs/reachability-evidence-identity.json")
        evidence_identity.write_bytes(payload({"tampered": True}))
        with self.assertRaisesRegex(workers.WorkerBlocked, "artifact changed"):
            workers.run("reachability", request_path)

    def test_absent_tool_receipt_blocks_without_attempt(self):
        output = self.write("syft.json", {"components": []})
        request = self.request(tool_output=str(output), tool_receipt=str(self.root / "missing.json"),
                               expected_tool={"tool_id": "syft", "image_id": "tool-syft", "image_digest": "sha256:" + "3" * 64})
        with self.assertRaisesRegex(workers.WorkerBlocked, "regular file"):
            self.run_request("sbom", "missing", request)
        self.assertFalse((self.out / "02-sbom-inventory").exists())

    def test_stale_database_blocks(self):
        sbom_tool, receipt, expected = self.tool("02-sbom-inventory", "syft", {"components": []})
        sbom = self.run_request("sbom", "sbom", self.request(tool_output=str(sbom_tool), tool_receipt=str(receipt), expected_tool=expected))
        tool, receipt, expected = self.tool("02-sca-vulnerability-match", "grype", {"matches": []})
        databases = [{"database_kind": kind, "vendor_build": "b", "schema_version": "1", "snapshot_id": "s",
            "sha256": "sha256:" + "4" * 64, "data_timestamp": "2026-09-01T00:00:00Z"} for kind in ("grype-db", "osv")]
        request = self.request(sbom=self.binding(sbom, "outputs/sbom-manifest.json"), tool_output=str(tool),
            tool_receipt=str(receipt), expected_tool=expected, databases=databases, max_database_age_seconds=60)
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
            tool_receipt=str(receipt), expected_tool=expected, databases=databases, max_database_age_seconds=7200)
        with self.assertRaisesRegex(workers.WorkerBlocked, "basis"):
            self.run_request("sca", "bad-basis", request)


if __name__ == "__main__":
    unittest.main()
