from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from execution_state import Blocked, atomic_json, file_hash
import final_publication as final
from .test_synthesis_sarif import SynthesisSarifTests


class FinalPublicationTests(unittest.TestCase):
    KEY = b"fixture-final-publication-key-32bytes-minimum"
    ANCHOR = "sha256:" + "9" * 64
    def fixture(self, root: Path):
        draft = root / "draft"; draft.mkdir()
        report, trace = SynthesisSarifTests().values()
        atomic_json(draft / "report.json", report)
        atomic_json(draft / "evidence-trace-index.json", trace)
        artifacts = [{"path": name, "sha256": "sha256:" + file_hash(draft / name)}
                     for name in ("report.json", "evidence-trace-index.json")]
        atomic_json(draft / "publication-manifest.json", {"schema": "appsec-review/report-publication-manifest/1.0",
            "run_id": "run-1", "status": "DRAFT_EVIDENCE_BACKED", "artifacts": artifacts,
            "final": False, "human_signoff": False})
        report_sha = "sha256:" + file_hash(draft / "report.json")
        authorization = final.sign_authorization(run_id="run-1", reviewer_id="human-1",
            report_sha256=report_sha, decision="APPROVED", issued_at="2026-09-27T00:59:00Z",
            authorization_id="auth-1", key=self.KEY)
        ledger = final.append_signoff(None, run_id="run-1", reviewer_id="human-1",
            report_sha256=report_sha, decision="APPROVED", signed_at="2026-09-27T01:00:00Z",
            rationale="Reviewed the exact evidence-backed draft and trace index.",
            authorization=authorization, authorization_key=self.KEY, expected_prior_head=self.ANCHOR)
        return draft, ledger

    def test_exact_human_approval_publishes_immutable_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); draft, ledger = self.fixture(root); output = root / "final"
            manifest = final.publish(draft, ledger, output, authorization_key=self.KEY,
                                     expected_ledger_anchor=self.ANCHOR)
            self.assertTrue(manifest["final"]); self.assertTrue(manifest["human_signoff"])
            self.assertEqual(json.loads((output / "final-publication.json").read_text()), manifest)
            self.assertTrue((output / "human-signoff-ledger.json").is_file())
            sarif = json.loads((output / "critical-findings.sarif").read_text())
            self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "claim-1")
            with self.assertRaisesRegex(Blocked, "already exists"):
                final.publish(draft, ledger, output, authorization_key=self.KEY,
                              expected_ledger_anchor=self.ANCHOR)

    def test_missing_rejected_or_wrong_report_signoff_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); draft, ledger = self.fixture(root)
            for mutation in (lambda value: value["entries"][-1].update(decision="REJECTED"),
                             lambda value: value["entries"][-1].update(report_sha256="sha256:" + "0" * 64)):
                forged = deepcopy(ledger); mutation(forged)
                entry = forged["entries"][-1]
                entry["entry_hash"] = final._sha({key: value for key, value in entry.items() if key != "entry_hash"})
                forged["head_hash"] = entry["entry_hash"]
                with self.assertRaises(Blocked): final.publish(draft, forged, root / ("out-" + entry["decision"]),
                    authorization_key=self.KEY, expected_ledger_anchor=self.ANCHOR)

    def test_tampered_draft_and_symlink_are_rejected_without_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); draft, ledger = self.fixture(root); output = root / "final"
            atomic_json(draft / "report.json", {"tampered": True})
            with self.assertRaisesRegex(Blocked, "changed"): final.publish(draft, ledger, output,
                authorization_key=self.KEY, expected_ledger_anchor=self.ANCHOR)
            self.assertFalse(output.exists())

    def test_append_only_ledger_rejects_chain_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            draft, ledger = self.fixture(Path(directory)); forged = deepcopy(ledger)
            forged["entries"][0]["reviewer_id"] = "other"
            with self.assertRaisesRegex(Blocked, "chain"):
                final.validate_signoff(forged, run_id="run-1",
                    report_sha256="sha256:" + file_hash(draft / "report.json"),
                    authorization_key=self.KEY, expected_anchor=self.ANCHOR)

    def test_forged_authorization_or_untrusted_anchor_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); draft, ledger=self.fixture(root)
            forged=deepcopy(ledger); forged["entries"][0]["authorization"]["reviewer_id"]="attacker"
            entry=forged["entries"][0]
            entry["entry_hash"]=final._sha({k:v for k,v in entry.items() if k!="entry_hash"})
            forged["head_hash"]=entry["entry_hash"]
            with self.assertRaises(Blocked):
                final.publish(draft,forged,root/"forged",authorization_key=self.KEY,
                              expected_ledger_anchor=self.ANCHOR)
            with self.assertRaisesRegex(Blocked,"anchor"):
                final.publish(draft,ledger,root/"wrong-anchor",authorization_key=self.KEY,
                              expected_ledger_anchor="sha256:"+"8"*64)

    def test_draft_cannot_claim_publisher_owned_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); draft,ledger=self.fixture(root)
            atomic_json(draft/"human-signoff-ledger.json",{"attacker":True})
            publication=json.loads((draft/"publication-manifest.json").read_text())
            publication["artifacts"].append({"path":"human-signoff-ledger.json",
                "sha256":"sha256:"+file_hash(draft/"human-signoff-ledger.json")})
            atomic_json(draft/"publication-manifest.json",publication)
            with self.assertRaisesRegex(Blocked,"publisher-owned"):
                final.publish(draft,ledger,root/"final",authorization_key=self.KEY,
                              expected_ledger_anchor=self.ANCHOR)


if __name__ == "__main__":
    unittest.main()
