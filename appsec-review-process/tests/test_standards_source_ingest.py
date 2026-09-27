from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import evidence_assembly
import execution_state as state
from execution_state import Blocked, atomic_json, digest, file_hash
from schema_validate import validate_document
import standards_source_ingest as worker


class StandardsSourceIngestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.owner = Path(self.temporary.name)
        self.fixture = json.loads((ROOT / "tests/fixtures/standards-source-ingest/hello-autotools-binding.json").read_text())

    def tearDown(self):
        self.temporary.cleanup()

    def inputs(self):
        snapshots = []
        for item in self.fixture["selected_snapshots"]:
            path = worker._snapshot_path(item["family"], item["snapshot_id"])
            manifest = json.loads((path / "manifest.json").read_text())
            snapshots.append({"family": item["family"], "path": str(path.resolve()),
                              "manifest_sha256": item["manifest_sha256"],
                              "expected_record_count": manifest["record_counts"]["records"]})
        return {"run_id": self.fixture["run_id"], "job_id": worker.JOB,
                "binding": self.fixture, "binding_sha256": "sha256:" + "a" * 64,
                "intake": {"job_id": "00-intake", "attempt_id": "intake-1", "fingerprint": "sha256:" + "b" * 64,
                           "source_fingerprint": "c" * 64, "pointer_sha256": "sha256:" + "d" * 64},
                "source_lock_sha256": "sha256:" + file_hash(worker.SOURCE_LOCK),
                "snapshots": snapshots, "code": worker._code_hashes()}

    @staticmethod
    def reseal(root: Path, catalog: dict) -> str:
        catalog_path = root / "normalized/catalog.json"
        atomic_json(catalog_path, catalog)
        manifest = json.loads((root / "manifest.json").read_text())
        record = next(item for item in manifest["normalized_files"] if item["path"] == "normalized/catalog.json")
        record["sha256"] = file_hash(catalog_path)
        record["bytes"] = catalog_path.stat().st_size
        manifest["record_counts"]["records"] = len(catalog["records"])
        manifest["content_digest"] = digest({
            "raw_files": manifest["raw_files"], "normalized_files": manifest["normalized_files"],
            "license_sha256": manifest["license"]["sha256"],
            "extractor": {"name": manifest["extractor"]["name"], "version": manifest["extractor"]["version"]},
        })
        atomic_json(root / "manifest.json", manifest)
        return "sha256:" + file_hash(root / "manifest.json")

    def copied_asvs(self, case: str = "copy") -> Path:
        source = worker._snapshot_path("owasp_asvs", "sha256-e48ca4caa6619973")
        destination = self.owner / case / source.name
        destination.parent.mkdir()
        shutil.copytree(source, destination)
        return destination

    def test_binding_and_owned_registry_records_are_closed_and_non_executable(self):
        self.assertEqual(validate_document(self.fixture, "standards-source-binding.schema.json"), [])
        template = json.loads((ROOT / "registry/job-templates/02-standards-source-ingest.json").read_text())
        contract = json.loads((ROOT / "registry/output-contracts/standards-source-extract.json").read_text())
        self.assertFalse(template["implemented"])
        self.assertEqual(template["permissions"], worker._permissions())
        self.assertEqual(contract["result_schema"], {"artifact": worker.RESULT,
                                                     "schema_file": "standards-source-extract.schema.json"})
        self.assertIn("never compliance proof", " ".join(contract["validation_rules"]))

    def test_first_fixture_materializes_exact_records_manifests_licenses_and_gaps(self):
        attempt = self.owner / "attempt"
        result, artifacts = worker.materialize(run_id=self.fixture["run_id"], attempt_id="attempt-1",
                                               attempt=attempt, inputs=self.inputs())
        self.assertEqual(validate_document(result, "standards-source-extract.schema.json"), [])
        self.assertEqual(result["status"], "OK_WITH_GAPS")
        self.assertEqual([(item["family"], item["record_count"]) for item in result["snapshots"]],
                         [("opencre", 522), ("owasp_asvs", 345), ("owasp_top_10", 10)])
        self.assertEqual(len(result["records"]), 877)
        self.assertEqual(len(result["coverage_gaps"]), 4)
        self.assertEqual(len(artifacts), 883)
        sample = json.loads((attempt / result["records"][0]["path"]).read_text())
        self.assertEqual(validate_document(sample, "standards-source-record.schema.json"), [])
        self.assertEqual(sample["claim_boundary"] if "claim_boundary" in sample else None, None)
        self.assertTrue(all((attempt / item["manifest_path"]).is_file() and
                            (attempt / item["license_path"]).is_file() for item in result["snapshots"]))

    def test_changed_snapshot_bytes_and_manifest_hash_are_rejected(self):
        copied = self.copied_asvs("changed")
        raw = next((copied / "raw").rglob("*.json"))
        raw.write_bytes(raw.read_bytes() + b" ")
        with self.assertRaises(Blocked):
            worker._load_snapshot(copied, "sha256:" + file_hash(copied / "manifest.json"), 345)
        copied = self.copied_asvs("changed-license")
        license_file = copied / "LICENSE-or-usage.txt"
        license_file.write_bytes(license_file.read_bytes() + b"changed")
        with self.assertRaises(Blocked):
            worker._load_snapshot(copied, "sha256:" + file_hash(copied / "manifest.json"), 345)
        copied = self.copied_asvs("wrong-manifest")
        with self.assertRaises(Blocked):
            worker._load_snapshot(copied, "sha256:" + "0" * 64, 345)

    def test_missing_record_text_duplicate_ids_and_mixed_snapshot_are_rejected_even_when_resealed(self):
        mutators = []
        def missing_record(catalog): catalog["records"].pop()
        def missing(catalog): catalog["records"][0]["text"] = ""
        def duplicate(catalog): catalog["records"].append(deepcopy(catalog["records"][0]))
        def mixed(catalog): catalog["snapshot_id"] = "sha256-0000000000000000"
        mutators.extend((missing_record, missing, duplicate, mixed))
        for index, mutate in enumerate(mutators):
            root = self.owner / f"case-{index}" / "sha256-e48ca4caa6619973"
            root.parent.mkdir()
            shutil.copytree(worker._snapshot_path("owasp_asvs", "sha256-e48ca4caa6619973"), root)
            catalog = json.loads((root / "normalized/catalog.json").read_text())
            mutate(catalog)
            expected = self.reseal(root, catalog)
            with self.subTest(index=index), self.assertRaises(Blocked):
                worker._load_snapshot(root, expected, 346 if index == 2 else 345)

    def test_receipts_match_f02_canonical_shapes_and_template_permissions(self):
        permission, lineage = worker._receipts(self.fixture["run_id"], self.inputs())
        self.assertEqual(permission, {"schema": evidence_assembly.PERMISSION_SCHEMA,
            "run_id": self.fixture["run_id"], "job_id": worker.JOB,
            "source_snapshot_sha256": "sha256:" + "c" * 64,
            "permissions": worker._permissions()})
        self.assertEqual(lineage, {"schema": evidence_assembly.LINEAGE_SCHEMA,
            "run_id": self.fixture["run_id"], "job_id": worker.JOB,
            "source_snapshot_sha256": "sha256:" + "c" * 64, "build_lineage_sha256": None})

    def test_materialization_is_deterministic(self):
        inputs = self.inputs()
        first, _ = worker.materialize(run_id=self.fixture["run_id"], attempt_id="same",
                                      attempt=self.owner / "one", inputs=inputs)
        second, _ = worker.materialize(run_id=self.fixture["run_id"], attempt_id="same",
                                       attempt=self.owner / "two", inputs=inputs)
        self.assertEqual(first, second)
        self.assertEqual([(item["path"], item["sha256"]) for item in first["records"]],
                         [(item["path"], item["sha256"]) for item in second["records"]])

    def test_common_envelope_publication_and_read_only_validation(self):
        inputs = self.inputs()
        old_runs = state.RUNS
        state.RUNS = self.owner / "runs"
        try:
            with patch.object(worker, "current_inputs", return_value=inputs):
                pointer = worker.run(self.fixture["run_id"], "dagster-s01")
                attempt = worker.validate(self.fixture["run_id"], pointer)
                envelope = json.loads((attempt / "result.json").read_text())
                self.assertEqual((envelope["worker_kind"], envelope["output_contract"],
                                  envelope["execution_status"], envelope["acceptance_status"]),
                                 ("deterministic_python", worker.CONTRACT, "OK_WITH_GAPS", "CURRENT"))
                self.assertEqual(len(envelope["artifacts"]), 887)
                before = {path.relative_to(attempt).as_posix(): file_hash(path)
                          for path in attempt.rglob("*") if path.is_file()}
                worker.validate(self.fixture["run_id"], pointer)
                after = {path.relative_to(attempt).as_posix(): file_hash(path)
                         for path in attempt.rglob("*") if path.is_file()}
                self.assertEqual(before, after)
                supply = self.owner / "supply"
                producer = supply / "producers" / worker.JOB
                producer.parent.mkdir(parents=True)
                shutil.copytree(worker.root(self.fixture["run_id"]), producer)
                instance_id = worker.JOB + "/whole/one"
                entry, copies = evidence_assembly._producer(
                    supply, self.fixture["run_id"], "sha256:" + "c" * 64,
                    {"job": worker.JOB, "contract": worker.CONTRACT, "allowed_skip_reasons": []},
                    {"source_snapshot_sha256": "sha256:" + "c" * 64,
                     "terminal_instance_ids": [instance_id], "permissions": worker._permissions(),
                     "build_lineage_sha256": None},
                    {instance_id: {"state": "succeeded", "group_id": "standards-source-ingest"}})
                self.assertEqual((entry["job_id"], entry["contract"], entry["disposition"]),
                                 (worker.JOB, worker.CONTRACT, "accepted"))
                self.assertEqual(len(copies), len(envelope["artifacts"]))
                record = attempt / json.loads((attempt / worker.RESULT).read_text())["records"][0]["path"]
                record.write_bytes(record.read_bytes() + b" ")
                with self.assertRaises(Blocked): worker.validate(self.fixture["run_id"], pointer)
        finally:
            state.RUNS = old_runs

    def test_selection_must_explicitly_partition_pinned_families(self):
        invalid = deepcopy(self.fixture)
        invalid["unselected_families"].pop()
        with patch.object(worker, "data_path", return_value=self.owner / worker.BINDING_NAME):
            atomic_json(self.owner / worker.BINDING_NAME, invalid)
            with self.assertRaises(Blocked): worker._binding(self.fixture["run_id"])


if __name__ == "__main__":
    unittest.main()
