from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import draft_report_fixture_runner as runner
from execution_state import Blocked, file_hash
import synthesis_report as synthesis
from schema_validate import validate_document as validate_schema
import test_report_input_assembly as report_fixture_tests


class DraftReportFixtureRunnerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = report_fixture_tests.ReportInputAssemblyTests(
            "test_nominal_manifest_is_deterministic_hash_bound_and_prose_free")
        original = self.fixture._documents

        def documents():
            value = original()
            # This runner fixture has one lifecycle claim and therefore selects no threat routes.
            value["threat"]["integrated-threat-model.json"]["stride_hypotheses"] = []
            matrix = value["owasp"]["owasp-control-status-matrix.json"]
            matrix["applicability_counts"] = {"applicable": 1, "conditional": 0,
                "not_applicable": 0, "cannot_determine": 0, "out_of_scope": 0}
            matrix["assessment_counts"] = {"satisfied": 1, "partially_satisfied": 0,
                "not_satisfied": 0, "cannot_verify": 0, "dynamic_test_required": 0,
                "human_decision_required": 0, "not_assessed": 0, "not_applicable": 0,
                "cannot_determine": 0, "out_of_scope": 0}
            value["owasp"]["owasp-coverage-gaps.json"]["gaps"][0]["statement"] = \
                "Fixture coverage gap remains visible."
            return value

        self.fixture._documents = documents
        self.fixture.setUp()
        self.run_root = Path(self.fixture.temp.name)
        (self.run_root / "data").mkdir()
        self.fixture.jobs.rename(self.run_root / "data" / "jobs")
        self.fixture.jobs = self.run_root / "data" / "jobs"

    def tearDown(self):
        self.fixture.tearDown()

    @staticmethod
    def _synthesis_validation(document, schema):
        if schema.startswith("owasp-") or schema in {
                "09-independent-verification.schema.json", "scoring-prioritization.schema.json"}:
            return []
        return validate_schema(document, schema)

    def test_real_assembler_to_synthesis_handoff_emits_immutable_draft(self):
        with patch.object(synthesis, "validate_document", side_effect=self._synthesis_validation):
            result = runner.run_fixture(self.run_root, "report-run", "draft-1")
        attempt = Path(result["attempt_path"])
        self.assertEqual(result["status"], "DRAFT_EVIDENCE_BACKED")
        self.assertFalse(json.loads((attempt / synthesis.PUBLICATION).read_text())["final"])
        manifest = json.loads((attempt / "synthesis-input.json").read_text())
        self.assertNotEqual(manifest["ledger_head_sha256"], manifest["lifecycle_origin_head_sha256"])
        self.assertEqual(result["input_manifest_sha256"], "sha256:" + file_hash(attempt / "synthesis-input.json"))
        self.assertEqual(set(result["artifacts"]), {item.name for item in attempt.iterdir()})
        with self.assertRaises(Blocked):
            runner.run_fixture(self.run_root, "report-run", "draft-1")


if __name__ == "__main__":
    unittest.main()
