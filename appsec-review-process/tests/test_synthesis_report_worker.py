from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import demo_report_fixture
from execution_state import Blocked, file_hash
from schema_validate import validate_document
import synthesis_report as synthesis
import synthesis_report_presentation as presentation
import synthesis_report_worker as worker


class SynthesisReportWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.run_root = Path(self.temp.name) / "report-run"
        self.run_id = "synthesis-worker-fixture"
        demo_report_fixture.materialize(self.run_root, self.run_id)

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_accepted_inputs_publish_and_revalidate_html_and_latex(self):
        ids = iter(("report-attempt-1", "report-attempt-2"))
        first = worker.run(self.run_root, self.run_id, "test-run", attempt_id_factory=lambda: next(ids))
        self.assertEqual(first["status"], "OK_WITH_GAPS")
        attempt = worker.validate(self.run_root, self.run_id)
        report = json.loads((attempt / synthesis.REPORT_JSON).read_text())
        manifest = json.loads((attempt / presentation.RENDER_MANIFEST).read_text())
        self.assertEqual(report["status"], "DRAFT_EVIDENCE_BACKED")
        self.assertFalse(report["claim_limits"]["final"])
        self.assertEqual(len(report["verified_findings"]), 1)
        self.assertGreater(len(report["limitations"]), 0)
        self.assertEqual(validate_document(manifest, "report-render-publication.schema.json"), [])
        self.assertFalse(manifest["final"]); self.assertFalse(manifest["human_signoff"])
        for relative in ("presentation/report.tex", "presentation/report.html", presentation.RENDER_INPUT):
            self.assertTrue((attempt / relative).is_file(), relative)
        hashes = {name: file_hash(attempt / name) for name in
            (synthesis.REPORT_JSON, synthesis.TRACE, presentation.RENDER_INPUT,
             "presentation/report.tex", "presentation/report.html")}
        second = worker.run(self.run_root, self.run_id, "test-run-2", force=True,
                            attempt_id_factory=lambda: next(ids))
        self.assertEqual(second["status"], "OK_WITH_GAPS")
        replacement = worker.validate(self.run_root, self.run_id)
        self.assertEqual(hashes, {name: file_hash(replacement / name) for name in hashes})

    def test_upstream_pointer_tampering_and_presentation_promotion_fail_closed(self):
        worker.run(self.run_root, self.run_id, "test-run", attempt_id_factory=lambda: "report-attempt")
        pointer_path = self.run_root / "data/jobs/01-component-characterization/accepted.json"
        pointer = json.loads(pointer_path.read_text()); pointer["accepted_at"] = "forged"
        pointer_path.write_text(json.dumps(pointer))
        with self.assertRaises(Blocked):
            worker.validate(self.run_root, self.run_id)
        report = {"schema": "appsec-review/synthesis-report/1.0", "status": "FINAL",
                  "claim_limits": {"final": True}}
        with self.assertRaisesRegex(Blocked, "exact draft"):
            presentation.build_review(report, {})

    def test_standalone_contract_and_template_are_schema_valid(self):
        registry = ROOT / "registry"
        records = ((registry / "output-contracts/synthesis-report-publication.json",
                    "output-contract.schema.json"),
                   (registry / "job-templates/10-synthesis-report.json", "job-template.schema.json"))
        for path, schema in records:
            self.assertEqual(validate_document(json.loads(path.read_text()), schema), [], path.name)


if __name__ == "__main__":
    unittest.main()
