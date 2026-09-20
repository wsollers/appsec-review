"""Offline qualification for the OWASP workbench accepted-intelligence lane-in."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


PROCESS = Path(__file__).resolve().parents[1]
ROOT = PROCESS.parent
sys.path.insert(0, str(PROCESS))

import execution_state
import owasp_lane_in
from schema_validate import validate_document


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OwaspLaneInTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.old_runs = execution_state.RUNS
        execution_state.RUNS = Path(self.temporary.name) / "runs"
        self.addCleanup(setattr, execution_state, "RUNS", self.old_runs)
        self.run_id = "lane-in-fixture"
        self.run = execution_state.RUNS / self.run_id
        write_json(self.run / "run-status.json", {"run_id": self.run_id, "status": "READY"})
        self.data = self.run / "data"

        raw = self.data / "imports" / "import-1" / "config.json"
        write_json(raw, {"setting": "declared"})
        write_json(self.data / "imports" / "import-1.json",
                   {"path": "imports/import-1", "origin": "fixture",
                    "hashes": {"config.json": sha(raw)}, "imported_at": "2026-09-20T00:00:00Z"})
        index = self.data / "jobs" / "02-evidence-index" / "whole" / "attempts" / "attempt-1" / "outputs" / "index.json"
        write_json(index, {"records": [{"path": "imports/import-1/config.json"}]})
        pointer = self.data / "jobs" / "02-evidence-index" / "whole" / "accepted.json"
        write_json(pointer, {"status": "OK", "run_id": self.run_id,
                             "attempt_id": "attempt-1", "job_id": "02-evidence-index",
                             "artifacts": {"outputs/index.json": sha(index)}})
        self.raw, self.index, self.pointer = raw, index, pointer

        asvs_root = next((ROOT / "data" / "reference" / "owasp" / "owasp_asvs" / "5.0.0").iterdir())
        manifest = asvs_root / "manifest.json"
        self.selection = {
            "schema": "appsec-review/standard-selection/1.0",
            "selection_id": "selection-1", "engagement_id": self.run_id,
            "selections": [{
                "family": "owasp_asvs", "snapshot_id": asvs_root.name,
                "manifest_sha256": sha(manifest), "edition": "5.0.0",
                "enabled_scope": ["server"], "profile_or_level": "L2", "tailoring": [],
            }],
            "approver": "engagement-lead", "approved_at": "2026-09-20T00:00:00Z",
        }
        self.request = {
            "schema": "appsec-review/owasp-intel-lane-in-request/1.0",
            "run_id": self.run_id, "selection": self.selection,
            "permissions": {"static_inspection": True, "dynamic_execution": False,
                            "manual_observation": False, "network_access": False,
                            "target_mutation": False},
            "entries": [
                {
                    "input_id": "raw-config", "evidence_class": "raw_evidence",
                    "kind": "configuration", "admission": "explicit_import",
                    "artifact": {"path": "imports/import-1/config.json", "sha256": sha(raw)},
                    "producer": None, "source_artifacts": [], "source_snapshot": None,
                    "derivation_status": None,
                    "freshness": {"assessed_at": "2026-09-20T00:00:00Z", "status": "not_time_sensitive"},
                    "redaction_status": "not_required", "caveats": [], "use": "canonical_evidence",
                },
                {
                    "input_id": "source-index", "evidence_class": "derived_intelligence",
                    "kind": "evidence_index", "admission": "accepted_run_output",
                    "artifact": {"path": "jobs/02-evidence-index/whole/attempts/attempt-1/outputs/index.json",
                                 "sha256": sha(index)},
                    "producer": {"job_id": "02-evidence-index", "attempt_id": "attempt-1",
                                 "accepted_pointer_path": "jobs/02-evidence-index/whole/accepted.json",
                                 "accepted_pointer_sha256": sha(pointer)},
                    "source_artifacts": [{"path": "imports/import-1/config.json", "sha256": sha(raw)}],
                    "source_snapshot": {"snapshot_id": "source-1", "captured_at": "2026-09-20T00:00:00Z"},
                    "derivation_status": "complete",
                    "freshness": {"assessed_at": "2026-09-20T00:00:00Z", "status": "current"},
                    "redaction_status": "reviewed",
                    "caveats": ["Locator only; dereference before status use."], "use": "locator_only",
                },
            ],
            "nvd": {"requested": False, "snapshot_id": None, "manifest_sha256": None,
                    "advisory_freshness_seconds": 86400},
            "completeness_gaps": [],
        }
        self.request_path = self.run / "inputs" / "owasp-lane-in-request.json"

    def write_request(self):
        write_json(self.request_path, self.request)

    def add_stale_nvd(self):
        root = Path(self.temporary.name) / "nvd"
        blob = root / "blobs" / "fixture.json.gz"
        blob.parent.mkdir(parents=True, exist_ok=True)
        blob.write_bytes(b"fixture")
        unsigned = {
            "schema": "appsec-review/nvd-snapshot-manifest/1", "feed_id": "nvd",
            "feed_schema": "NVD_CVE/2.0", "mode": "bootstrap", "parent_snapshot_id": None,
            "captured_at": "2026-09-18T00:00:00+00:00", "coverage": {"first_year": 2002, "last_year": 2026},
            "cursor": "2026-09-18T00:00:00+00:00", "record_count": 0,
            "layers": [{"kind": "year", "blob": {"path": "blobs/fixture.json.gz",
                                                       "sha256": sha(blob), "size_bytes": blob.stat().st_size}}],
            "limitations": ["Fixture enrichment only."],
        }
        snapshot_id = owasp_lane_in._nvd_identity(unsigned)
        manifest = {**unsigned, "snapshot_id": snapshot_id}
        path = root / "snapshots" / snapshot_id / "manifest.json"
        write_json(path, manifest)
        self.request["nvd"] = {"requested": True, "snapshot_id": snapshot_id,
                               "manifest_sha256": sha(path), "advisory_freshness_seconds": 60}
        return root

    def test_schemas_and_successful_reuse(self):
        self.write_request()
        self.assertEqual(validate_document(self.request, "owasp-intel-lane-in-request.schema.json"), [])
        first = owasp_lane_in.admit(self.run_id, self.request_path)
        self.assertEqual(first["status"], "OK")
        self.assertFalse(first["reused"])
        second = owasp_lane_in.admit(self.run_id, self.request_path)
        self.assertTrue(second["reused"])
        output = self.data / "jobs" / owasp_lane_in.JOB_ID / "whole" / "attempts" / first["attempt_id"] / "outputs" / "owasp-input-manifest.json"
        self.assertTrue((output.parents[1] / "logs" / "events.jsonl").is_file())
        self.assertEqual((output.parents[1] / "logs" / "stdout.log").read_bytes(), b"")
        manifest = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(validate_document(manifest, "owasp-input-manifest.schema.json"), [])
        self.assertEqual(manifest["selection"]["approver"], "engagement-lead")
        self.assertEqual(manifest["reference_snapshots"][0]["manifest"]["snapshot_id"],
                         self.selection["selections"][0]["snapshot_id"])
        self.assertFalse(manifest["entries"][1]["may_support_control_status"])

    def test_stale_nvd_is_gap_not_blocker(self):
        nvd_root = self.add_stale_nvd()
        self.write_request()
        result = owasp_lane_in.admit(
            self.run_id, self.request_path, nvd_root=nvd_root,
            clock=lambda: datetime(2026, 9, 20, tzinfo=timezone.utc),
        )
        self.assertEqual(result["status"], "OK_WITH_GAPS")
        output = self.data / "jobs" / owasp_lane_in.JOB_ID / "whole" / "attempts" / result["attempt_id"] / "outputs" / "owasp-input-manifest.json"
        manifest = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(manifest["nvd"]["freshness_status"], "stale_accepted")
        self.assertEqual(manifest["nvd"]["manifest"]["snapshot_id"], self.request["nvd"]["snapshot_id"])
        self.assertIn("nvd-stale-accepted", {gap["gap_id"] for gap in manifest["gaps"]})

    def test_dynamic_permission_and_non_l2_fail_before_attempt(self):
        self.request["permissions"]["dynamic_execution"] = True
        self.write_request()
        with self.assertRaisesRegex(ValueError, "dynamic_execution"):
            owasp_lane_in.admit(self.run_id, self.request_path)
        self.request["permissions"]["dynamic_execution"] = False
        self.request["selection"]["selections"][0]["profile_or_level"] = "L3"
        self.write_request()
        with self.assertRaisesRegex(execution_state.Blocked, "baseline L2"):
            owasp_lane_in.admit(self.run_id, self.request_path)
        self.assertFalse((self.data / "jobs" / owasp_lane_in.JOB_ID).exists())

    def test_stale_index_and_missing_derived_lineage_fail(self):
        self.request["entries"][1]["freshness"]["status"] = "stale_accepted"
        self.write_request()
        with self.assertRaisesRegex(execution_state.Blocked, "stale index"):
            owasp_lane_in.admit(self.run_id, self.request_path)
        self.request["entries"][1]["freshness"]["status"] = "current"
        self.request["entries"][1]["source_artifacts"] = []
        self.write_request()
        with self.assertRaisesRegex(ValueError, "source artifacts"):
            owasp_lane_in.admit(self.run_id, self.request_path)

    def test_hash_tamper_and_accepted_pointer_tamper_fail(self):
        self.raw.write_text("tampered", encoding="utf-8")
        self.write_request()
        with self.assertRaisesRegex(execution_state.Blocked, "hash mismatch"):
            owasp_lane_in.admit(self.run_id, self.request_path)
        write_json(self.raw, {"setting": "declared"})
        write_json(self.data / "imports" / "import-1.json",
                   {"path": "imports/import-1", "origin": "fixture",
                    "hashes": {"config.json": sha(self.raw)}, "imported_at": "2026-09-20T00:00:00Z"})
        self.request["entries"][0]["artifact"]["sha256"] = sha(self.raw)
        self.request["entries"][1]["source_artifacts"][0]["sha256"] = sha(self.raw)
        write_json(self.pointer, {"status": "FAILED", "run_id": self.run_id,
                                  "attempt_id": "attempt-1", "job_id": "02-evidence-index"})
        self.request["entries"][1]["producer"]["accepted_pointer_sha256"] = sha(self.pointer)
        self.write_request()
        with self.assertRaisesRegex(execution_state.Blocked, "producer is not accepted"):
            owasp_lane_in.admit(self.run_id, self.request_path)

    def test_unpublished_file_beneath_accepted_attempt_is_rejected(self):
        unpublished = self.index.parent / "unpublished.json"
        write_json(unpublished, {"records": []})
        self.request["entries"][1]["artifact"] = {
            "path": "jobs/02-evidence-index/whole/attempts/attempt-1/outputs/unpublished.json",
            "sha256": sha(unpublished),
        }
        self.write_request()
        with self.assertRaisesRegex(execution_state.Blocked, "does not publish the requested artifact/hash"):
            owasp_lane_in.admit(self.run_id, self.request_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
