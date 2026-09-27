from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from execution_state import Blocked
import retained_happy_path_demo as demo


class RetainedHappyPathDemoTests(unittest.TestCase):
    ANCHOR = "sha256:" + "9" * 64
    KEY = b"retained-demo-operator-key-32bytes-minimum"

    def test_retains_draft_and_supplemental_family_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "retained"
            result = demo.run(output, "demo-draft")
            self.assertEqual(result["status"], "DRAFT_EVIDENCE_BACKED")
            self.assertIsNone(result["final_path"])
            self.assertTrue(Path(result["draft_path"], "publication-manifest.json").is_file())
            supplemental = json.loads(Path(result["supplemental_qualification_path"]).read_text())
            self.assertEqual({row["family"] for row in supplemental["families"]},
                             {"analysis", "dependency", "vendor"})
            self.assertTrue(all(row["report_effect"] == "NOT_A_FINDING_AND_NOT_VERIFIED_TARGET_EVIDENCE"
                                for row in supplemental["families"]))

    def test_explicit_demo_signoff_retains_final_package(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "retained"
            result = demo.run(output, "demo-final", authorization_key=self.KEY,
                ledger_anchor=self.ANCHOR, reviewer_id="reviewer-1")
            self.assertEqual(result["status"], "FINAL_APPROVED")
            final_root = Path(result["final_path"])
            manifest = json.loads((final_root / "final-publication.json").read_text())
            self.assertTrue(manifest["final"])
            ledger = json.loads((output / "demo-human-signoff-ledger.json").read_text())
            self.assertEqual(ledger["entries"][-1]["reviewer_id"], "DEMO-OPERATOR:reviewer-1")
            self.assertIn("DEMO ONLY", ledger["entries"][-1]["rationale"])
            self.assertTrue((final_root / "completion/completeness-audit.json").is_file())

    def test_existing_output_and_incomplete_signoff_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "retained"
            demo.run(output, "demo-once")
            with self.assertRaisesRegex(Blocked, "already exists"):
                demo.run(output, "demo-twice")
            incomplete = Path(directory) / "incomplete"
            with self.assertRaisesRegex(Blocked, "required together"):
                demo.run(incomplete, "demo-incomplete", authorization_key=self.KEY)
            self.assertFalse(incomplete.exists())


if __name__ == "__main__":
    unittest.main()
