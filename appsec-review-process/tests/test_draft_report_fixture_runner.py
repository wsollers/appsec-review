from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import draft_report_fixture_runner as runner
from execution_state import Blocked, file_hash
import synthesis_report as synthesis
import test_report_input_assembly as report_fixture_tests
import test_owasp_join_publisher as owasp_publisher_tests


class DraftReportFixtureRunnerTests(unittest.TestCase):
    def setUp(self):
        self.owasp_fixture = owasp_publisher_tests.OwaspJoinPublisherTests(
            "test_exact_verified_join_publishes_one_common_envelope_and_canonical_receipts")
        self.owasp_fixture.setUp()
        self.owasp_fixture.publish()
        self._fixture_globals = (report_fixture_tests.RUN_ID, report_fixture_tests.SOURCE,
                                 report_fixture_tests.CLAIM)
        report_fixture_tests.RUN_ID = self.owasp_fixture.run_id
        report_fixture_tests.SOURCE = self.owasp_fixture.facts().source_snapshot_sha256
        report_fixture_tests.CLAIM = "claim-" + report_fixture_tests.digest({
            "route_id": "route-1", "producer": "03-threat-model-dfd-stride",
            "attempt": "threat-1", "artifact": "sha256:" + "c" * 64,
            "source_generation": report_fixture_tests.SOURCE,
            "component_generation": report_fixture_tests.COMPONENT_ATTEMPT})[:24]
        self.fixture = report_fixture_tests.ReportInputAssemblyTests(
            "test_nominal_manifest_is_deterministic_hash_bound_and_prose_free")
        original = self.fixture._documents

        def documents():
            value = original()
            # This runner fixture has one lifecycle claim and therefore selects no threat routes.
            value["threat"]["integrated-threat-model.json"]["stride_hypotheses"] = []
            return value

        self.fixture._documents = documents
        self.fixture.setUp()
        self.run_root = self.owasp_fixture.run
        target_jobs = self.run_root / "data" / "jobs"
        for source in self.fixture.jobs.iterdir():
            if source.name != "04-owasp-join-report":
                shutil.copytree(source, target_jobs / source.name, dirs_exist_ok=True)
        self.fixture.jobs = target_jobs
        self.fixture.schema_patcher.stop()

    def tearDown(self):
        self.fixture.temp.cleanup()
        (report_fixture_tests.RUN_ID, report_fixture_tests.SOURCE,
         report_fixture_tests.CLAIM) = self._fixture_globals
        self.owasp_fixture.tearDown()

    def test_exact_cli_real_assembler_to_synthesis_emits_immutable_draft(self):
        completed = subprocess.run([sys.executable, str(ROOT / "draft_report_fixture_runner.py"),
            "--run-root", str(self.run_root), "--run-id", self.owasp_fixture.run_id,
            "--attempt-id", "draft-1"], cwd=ROOT.parent, text=True, capture_output=True, check=True)
        result = json.loads(completed.stdout)
        attempt = Path(result["attempt_path"])
        self.assertEqual(result["status"], "DRAFT_EVIDENCE_BACKED")
        self.assertFalse(json.loads((attempt / synthesis.PUBLICATION).read_text())["final"])
        manifest = json.loads((attempt / "synthesis-input.json").read_text())
        self.assertNotEqual(manifest["ledger_head_sha256"], manifest["lifecycle_origin_head_sha256"])
        self.assertEqual(result["input_manifest_sha256"], "sha256:" + file_hash(attempt / "synthesis-input.json"))
        self.assertEqual(set(result["artifacts"]), {item.name for item in attempt.iterdir()})
        with self.assertRaises(Blocked):
            runner.run_fixture(self.run_root, self.owasp_fixture.run_id, "draft-1")

    def test_failed_staging_does_not_reserve_attempt_and_same_id_retries(self):
        pointer = self.run_root / "data/jobs/01-component-characterization/accepted.json"
        parked = pointer.with_suffix(".parked")
        pointer.rename(parked)
        with self.assertRaises(Blocked):
            runner.run_fixture(self.run_root, self.owasp_fixture.run_id, "retry-1")
        attempts = self.run_root / "data/jobs/10-synthesis-report/attempts"
        self.assertFalse((attempts / "retry-1").exists())
        self.assertEqual(list(attempts.glob(".staging-retry-1-*")), [])
        parked.rename(pointer)
        result = runner.run_fixture(self.run_root, self.owasp_fixture.run_id, "retry-1")
        self.assertEqual(result["status"], synthesis.STATUS)
        self.assertTrue((attempts / "retry-1/result.json").is_file())


if __name__ == "__main__":
    unittest.main()
