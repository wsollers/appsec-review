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


class StructuralCitationTests(unittest.TestCase):
    """ADR-0035: a tev: citation is shown by its Python summary, not by artifact#locator JSON."""

    def test_structural_citation_renders_its_observed_fact(self):
        fact = "code_path(copy_field -> strcpy) -> 1 path(s): copy_field -> strcpy (app/parse.c:22) [complete]"
        citation = {"citation_id": "tev:" + "a" * 32, "producer_job_id": "09-independent-verification",
                    "producer_attempt_id": "verify-1",
                    "artifact_path": "tool-evidence/09-independent-verification/verify-1/" + "a" * 32 + ".json",
                    "artifact_sha256": "sha256:" + "b" * 64,
                    "locator_json": '{"arguments":{"from":"copy_field","to":"strcpy"},"complete":true,"tool":"code_path"}',
                    "observed_fact": fact}
        rows, identifiers = adapter._evidence({"citations": [citation]})
        self.assertEqual(rows[0]["kind"], "structural query record (re-run verified)")
        (structural,) = adapter._findings({"verified_findings": [{
            "claim_id": "claim-structural", "title": "Unbounded copy reachable from copy_field",
            "component_ids": ["component-1"], "score": 16, "priority": "P0", "severity": "CRITICAL",
            "verification_citations": [citation]}]}, identifiers)
        self.assertEqual(structural["location"], "structural query: " + fact)
        self.assertEqual(structural["summary"], fact)
        import importlib.util
        if importlib.util.find_spec("cvss") is None:
            self.skipTest("render.py needs the cvss package")
        review = json.loads((HERE / "examples" / "hello-autotools.review.json").read_text())
        review["evidence"].append({**rows[0], "id": "E-900"})
        review["findings"][0].update(location=structural["location"], summary=structural["summary"],
                                     evidence=["E-900"])
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "structural.review.json"
            data.write_text(json.dumps(review))
            render.render(data, Path(directory) / "rendered")
            html = (Path(directory) / "rendered" / "report.html").read_text()
        self.assertIn("structural query: code_path(copy_field -&gt; strcpy)", html)


if __name__ == "__main__":
    unittest.main()
