"""Offline qualification for immutable OWASP/OpenCRE/DISA reference snapshots."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


PROCESS = Path(__file__).resolve().parents[1]
ROOT = PROCESS.parent
sys.path.insert(0, str(PROCESS))

import reference_snapshots as snapshots
import disa_reference_stage
from schema_validate import validate_document


class CommittedSnapshotTests(unittest.TestCase):
    def test_all_committed_snapshots_verify_offline(self):
        verified = snapshots.verify_tree(ROOT / "data/reference")
        manifests = [snapshots.load_json(path / "manifest.json") for path in verified]
        actual = {manifest["family"]: manifest["record_counts"]["records"] for manifest in manifests}
        self.assertEqual(actual, {
            "disa_asd_stig": 286,
            "disa_gpos_srg": 203,
            "opencre": 522,
            "owasp_api_security_top_10": 10,
            "owasp_asvs": 345,
            "owasp_llm_top_10": 10,
            "owasp_mastg": 292,
            "owasp_masvs": 24,
            "owasp_top_10": 10,
        })

    def test_disa_snapshots_bind_official_artifact_hash_and_xccdf_identity(self):
        lock = snapshots.load_json(ROOT / "data/reference/source-lock.json")
        sources = {item["family"]: item for item in lock["sources"]}
        for family in ("disa_asd_stig", "disa_gpos_srg"):
            source = sources[family]
            self.assertEqual(source["source_kind"], "disa_xccdf")
            self.assertIsNone(source["resolved_commit"])
            self.assertRegex(source["artifact_sha256"], r"^[0-9a-f]{64}$")
            manifest = next((ROOT / "data/reference/disa" / family).glob("**/manifest.json"))
            value = snapshots.load_json(manifest)
            self.assertEqual(value["upstream"]["url"], source["upstream_url"])
            self.assertEqual(value["upstream"]["artifact_sha256"], source["artifact_sha256"])

    def test_disa_stage_rejects_unlocked_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            bad = Path(temporary) / "not-official.zip"
            bad.write_bytes(b"not the official DISA package")
            with self.assertRaisesRegex(snapshots.SnapshotError, "package hash differs"):
                disa_reference_stage.stage(retrieved_at="2026-09-27T16:00:00Z",
                    family="disa_asd_stig", download=bad, output=Path(temporary) / "output")

    def test_disa_provenance_cannot_be_recast_as_git_or_redirected_to_a_mirror(self):
        lock = snapshots.load_json(ROOT / "data/reference/source-lock.json")
        disa = next(item for item in lock["sources"] if item["family"] == "disa_asd_stig")
        disa["upstream_url"] = "https://example.invalid/U_ASD_V6R4_STIG.zip"
        with self.assertRaisesRegex(snapshots.SnapshotError, "official DISA HTTPS artifact"):
            snapshots.validate_source_lock_semantics(lock)

    def test_hash_tamper_fails_closed(self):
        source = next((ROOT / "data/reference/owasp/owasp_masvs/2.1.0").iterdir())
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / source.name
            shutil.copytree(source, copied)
            catalog = copied / "normalized/catalog.json"
            catalog.write_text(catalog.read_text(encoding="utf-8") + " ", encoding="utf-8")
            with self.assertRaisesRegex(snapshots.SnapshotError, "snapshot file mismatch"):
                snapshots.verify_snapshot(copied)

    def test_source_lock_and_selection_contracts(self):
        lock = json.loads((ROOT / "data/reference/source-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(validate_document(lock, "reference-source-lock.schema.json"), [])
        selection = {
            "schema": "appsec-review/standard-selection/1.0",
            "selection_id": "selection-1",
            "engagement_id": "engagement-1",
            "selections": [{
                "family": "owasp_asvs",
                "snapshot_id": "sha256-e48ca4caa6619973",
                "manifest_sha256": "a" * 64,
                "edition": "5.0.0",
                "enabled_scope": ["server"],
                "profile_or_level": "L2",
                "tailoring": [],
            }],
            "approver": "engagement-lead",
            "approved_at": "2026-09-20T00:00:00Z",
        }
        self.assertEqual(validate_document(selection, "standard-selection.schema.json"), [])
        del selection["approver"]
        self.assertTrue(validate_document(selection, "standard-selection.schema.json"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
