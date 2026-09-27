from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PROCESS = REPO / "appsec-review-process"
sys.path[:0] = [str(HERE), str(PROCESS)]

import final_publication_adapter as adapter
import render
import retained_happy_path_demo as demo


class FinalPublicationAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name) / "retained"
        demo.run(cls.root, "presentation-demo",
            authorization_key=b"presentation-demo-key-at-least-32-bytes",
            ledger_anchor="sha256:" + "9" * 64, reviewer_id="presentation-reviewer")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_retained_final_package_renders_html_and_tex_authoritatively(self):
        review = adapter.convert(self.root / "final", self.root / "supplemental-family-qualification.json")
        self.assertEqual(review["finding_scoring"], "authoritative_retained_publication")
        self.assertEqual(review["process_assurance"], "not_asserted")
        self.assertTrue(review["report"]["sample"])
        self.assertEqual(len(review["findings"]), 1)
        finding = review["findings"][0]
        self.assertEqual((finding["severity_override"], finding["authoritative_score"],
                          finding["priority_label"]), ("Critical", 16, "P0"))
        self.assertIsNone(finding["cvss"])
        supplemental_jobs = {job for family in review["supplemental_qualification"]["families"]
                             for job in family["jobs"]}
        self.assertTrue(supplemental_jobs.isdisjoint({row["id"] for row in review["findings"]}))
        self.assertTrue(supplemental_jobs.isdisjoint({row["producer"] for row in review["evidence"]}))
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "retained.review.json"
            data.write_text(json.dumps(review))
            output = Path(directory) / "rendered"
            rendered = render.render(data, output)
            self.assertEqual(rendered["model"]["rating"], "Critical")
            self.assertIsNone(rendered["model"]["assurance_pct"])
            for name in ("report.html", "report.fragment.html", "report.tex",
                         "workbench.html", "workbench.fragment.html"):
                self.assertTrue((output / name).is_file(), name)
            self.assertIn("DEMO data", (output / "report.tex").read_text())
            self.assertIn(r"priority = \text{P0}", (output / "report.tex").read_text())

    def test_package_hash_tampering_and_promotional_supplement_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "final"
            shutil.copytree(self.root / "final", copied)
            report = json.loads((copied / "report.json").read_text())
            report["scope"]["target"] = "forged"
            (copied / "report.json").write_text(json.dumps(report))
            with self.assertRaisesRegex(adapter.AdapterError, "hash mismatch"):
                adapter.convert(copied)
            supplemental = json.loads((self.root / "supplemental-family-qualification.json").read_text())
            supplemental["families"][0]["report_effect"] = "VERIFIED_TARGET_EVIDENCE"
            path = Path(directory) / "supplemental.json"
            path.write_text(json.dumps(supplemental))
            with self.assertRaisesRegex(adapter.AdapterError, "non-promotional"):
                adapter.convert(self.root / "final", path)


if __name__ == "__main__":
    unittest.main()
