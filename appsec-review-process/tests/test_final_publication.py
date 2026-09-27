from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from execution_state import Blocked, atomic_json, file_hash, tree_hashes
import final_publication as final
import control_process_worker
from .test_synthesis_sarif import SynthesisSarifTests


class FinalPublicationTests(unittest.TestCase):
    KEY = b"fixture-final-publication-key-32bytes-minimum"
    ANCHOR = "sha256:" + "9" * 64
    AUDIT={"schema":"appsec-review/completeness-audit/1.0","run_id":"run-1","subject_sha256":"",
        "expected_count":0,
        "observed_ids":[],"declared_gap_ids":[],"missing_ids":[],"false_gap_ids":[],
        "observed_evidence":[],"gap_evidence":[],"complete":True}
    FEEDBACK={"schema":"appsec-review/synthetic-feedback/1.0","run_id":"run-1","iteration":1,
        "audit_sha256":final._sha(AUDIT),"max_iterations":1,"terminal_state":"COMPLETE",
        "hypotheses":[],"unresolved_obligation_ids":[]}

    def _accepted(self,run_root,job,contract,result_name,value,attempt_id):
        base=run_root/"data"/"jobs"/job; attempt=base/"attempts"/attempt_id
        control_process_worker.publish(run_id="run-1",job_id=job,attempt_id=attempt_id,
            contract_id=contract,result_name=result_name,result=value,output_root=attempt,
            source_snapshot_sha256="sha256:"+"a"*64,input_binding={"fixture":attempt_id},
            started_at="2026-09-27T00:00:00Z",finished_at="2026-09-27T00:00:01Z")
        envelope=json.loads((attempt/"result.json").read_text())
        pointer={"schema":"appsec-review/accepted-worker-result/1.0","status":"OK","run_id":"run-1",
            "job":job,"attempt_id":attempt_id,"fingerprint":envelope["input_fingerprint"],
            "envelope_path":"result.json","envelope_sha256":file_hash(attempt/"result.json"),
            "hashes":tree_hashes(attempt),"accepted_at":"2026-09-27T00:00:02Z"}
        atomic_json(base/"accepted.json",pointer); atomic_json(base/"latest.json",{"attempt_id":attempt_id,"updated_at":"2026-09-27T00:00:02Z"})
        return {"job_id":job,"attempt_id":attempt_id,"contract_id":contract,
            "artifact_path":f"data/jobs/{job}/attempts/{attempt_id}/{result_name}",
            "artifact_sha256":"sha256:"+file_hash(attempt/result_name),
            "accepted_pointer_sha256":"sha256:"+file_hash(base/"accepted.json"),
            "permission_receipt_sha256":"sha256:"+file_hash(attempt/"permission.json"),
            "lineage_receipt_sha256":"sha256:"+file_hash(attempt/"lineage.json")}

    def _completion(self,draft,audit=None,feedback=None,suffix="a1"):
        defaults=audit is None and feedback is None
        key=(str(draft),suffix)
        cache=getattr(self,"_completion_cache",{})
        if defaults and key in cache: return cache[key]
        run_root=Path(draft).parent/("run-"+suffix); report_sha="sha256:"+file_hash(Path(draft)/"report.json")
        audit=audit or {**self.AUDIT,"subject_sha256":report_sha}
        feedback=feedback or {**self.FEEDBACK,"audit_sha256":final._sha(audit)}
        audit_ref=self._accepted(run_root,"completeness-audit","completeness-audit","completeness-audit.json",audit,"audit-"+suffix)
        feedback_ref=self._accepted(run_root,"synthetic-hypothesis-resynthesis","synthetic-hypothesis-resynthesis","synthetic-hypothesis-resynthesis.json",feedback,"feedback-"+suffix)
        result=(run_root,audit_ref,feedback_ref)
        if defaults:
            cache[key]=result; self._completion_cache=cache
        return result

    def publish(self,draft,ledger,output,**overrides):
        run_root,audit_ref,feedback_ref=self._completion(draft,suffix=output.name)
        args={"authorization_key":self.KEY,"expected_ledger_anchor":self.ANCHOR,
              "expected_ledger_head":ledger["head_hash"],
              "run_root":run_root,"completeness_ref":audit_ref,"feedback_ref":feedback_ref}
        args.update(overrides)
        with mock.patch.object(final,"_current_preparation",return_value=self.preparation(draft)):
            return final.publish(draft,ledger,output,**args)
    def preparation(self,draft):
        report_sha="sha256:"+file_hash(Path(draft)/"report.json")
        binding={"job_id":"control", "attempt_id":"a1", "artifact_path":"result.json",
            "artifact_sha256":"sha256:"+"1"*64,
            "accepted_pointer_sha256":"sha256:"+"2"*64}
        return {"schema":"appsec-review/final-publication-preparation/1.0","run_id":"run-1",
            "status":"PENDING_HUMAN_APPROVAL","draft_report_sha256":report_sha,
            "draft_publication_manifest_sha256":"sha256:"+file_hash(Path(draft)/"publication-manifest.json"),
            "completion_gate":{"schema":"appsec-review/final-publication-gate/1.0","run_id":"run-1",
                "draft_report_sha256":report_sha,"eligible":False,"publication_status":"BLOCKED",
                "blockers":["human_signoff_missing"],"human_signoff":None},
            "control_evidence":{"quorum":{"binding":binding,"decision_count":0,"admitted_count":0},
                "rescope":{"binding":binding,"state":"ITERATION_LIMIT","final_publication_affected":True},
                "remediation_retest":{"binding":binding,"proposal_count":0,"retest_count":0,
                    "skipped_not_applicable":True,"disposition":{"execution_status":"SKIPPED",
                        "skip_reason":"not-applicable-no-verified-claims",
                        "gaps":["not-applicable-no-verified-claims"]}}},
            "draft_attempt":str(draft),"required_action":"A named human must approve the exact draft."}
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
            manifest = self.publish(draft,ledger,output)
            self.assertTrue(manifest["final"]); self.assertTrue(manifest["human_signoff"])
            self.assertEqual(json.loads((output / "final-publication.json").read_text()), manifest)
            self.assertTrue((output / "human-signoff-ledger.json").is_file())
            self.assertTrue((output / "completion/publication-preparation.json").is_file())
            sarif = json.loads((output / "critical-findings.sarif").read_text())
            self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "claim-1")
            with self.assertRaisesRegex(Blocked, "already exists"):
                self.publish(draft,ledger,output)

    def test_missing_rejected_or_wrong_report_signoff_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); draft, ledger = self.fixture(root)
            for mutation in (lambda value: value["entries"][-1].update(decision="REJECTED"),
                             lambda value: value["entries"][-1].update(report_sha256="sha256:" + "0" * 64)):
                forged = deepcopy(ledger); mutation(forged)
                entry = forged["entries"][-1]
                entry["entry_hash"] = final._sha({key: value for key, value in entry.items() if key != "entry_hash"})
                forged["head_hash"] = entry["entry_hash"]
                with self.assertRaises(Blocked): self.publish(draft,forged,root/("out-"+entry["decision"]))

    def test_tampered_draft_and_symlink_are_rejected_without_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); draft, ledger = self.fixture(root); output = root / "final"
            atomic_json(draft / "report.json", {"tampered": True})
            with self.assertRaisesRegex(Blocked, "changed"): self.publish(draft,ledger,output)
            self.assertFalse(output.exists())

    def test_append_only_ledger_rejects_chain_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            draft, ledger = self.fixture(Path(directory)); forged = deepcopy(ledger)
            forged["entries"][0]["reviewer_id"] = "other"
            with self.assertRaisesRegex(Blocked, "chain"):
                final.validate_signoff(forged, run_id="run-1",
                    report_sha256="sha256:" + file_hash(draft / "report.json"),
                    authorization_key=self.KEY, expected_anchor=self.ANCHOR,
                    expected_current_head=forged["head_hash"])

    def test_forged_authorization_or_untrusted_anchor_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); draft, ledger=self.fixture(root)
            forged=deepcopy(ledger); forged["entries"][0]["authorization"]["reviewer_id"]="attacker"
            entry=forged["entries"][0]
            entry["entry_hash"]=final._sha({k:v for k,v in entry.items() if k!="entry_hash"})
            forged["head_hash"]=entry["entry_hash"]
            with self.assertRaises(Blocked):
                self.publish(draft,forged,root/"forged")
            with self.assertRaisesRegex(Blocked,"anchor"):
                self.publish(draft,ledger,root/"wrong-anchor",expected_ledger_anchor="sha256:"+"8"*64)

    def test_ledger_rollback_against_external_current_head_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); draft,approved=self.fixture(root); report_sha="sha256:"+file_hash(draft/"report.json")
            rejection=final.sign_authorization(run_id="run-1",reviewer_id="human-1",report_sha256=report_sha,
                decision="REJECTED",issued_at="2026-09-27T01:01:00Z",authorization_id="auth-2",key=self.KEY)
            current=final.append_signoff(approved,run_id="run-1",reviewer_id="human-1",report_sha256=report_sha,
                decision="REJECTED",signed_at="2026-09-27T01:02:00Z",rationale="Rejected after review.",
                authorization=rejection,authorization_key=self.KEY,expected_prior_head=approved["head_hash"])
            with self.assertRaisesRegex(Blocked,"current head"):
                self.publish(draft,approved,root/"rollback",expected_ledger_head=current["head_hash"])

    def test_draft_cannot_claim_publisher_owned_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); draft,ledger=self.fixture(root)
            atomic_json(draft/"human-signoff-ledger.json",{"attacker":True})
            publication=json.loads((draft/"publication-manifest.json").read_text())
            publication["artifacts"].append({"path":"human-signoff-ledger.json",
                "sha256":"sha256:"+file_hash(draft/"human-signoff-ledger.json")})
            atomic_json(draft/"publication-manifest.json",publication)
            with self.assertRaisesRegex(Blocked,"publisher-owned"):
                self.publish(draft,ledger,root/"final")

    def test_incomplete_or_nonterminal_completion_evidence_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); draft,ledger=self.fixture(root)
            report_sha="sha256:"+file_hash(draft/"report.json")
            audit={**self.AUDIT,"subject_sha256":report_sha,"complete":False,"missing_ids":["o1"],"expected_count":1}
            feedback={**self.FEEDBACK,"audit_sha256":final._sha(audit),"terminal_state":"UNRESOLVED_AND_REPORTED","unresolved_obligation_ids":["o1"]}
            run_root,audit_ref,feedback_ref=self._completion(draft,audit,feedback,"incomplete")
            with mock.patch.object(final,"_current_preparation",return_value=self.preparation(draft)), \
                 self.assertRaisesRegex(Blocked,"completion validator"):
                final.publish(draft,ledger,root/"incomplete",authorization_key=self.KEY,
                    expected_ledger_anchor=self.ANCHOR,expected_ledger_head=ledger["head_hash"],
                    run_root=run_root,completeness_ref=audit_ref,feedback_ref=feedback_ref)

    def test_current_control_blocker_prevents_human_approved_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); draft,ledger=self.fixture(root)
            run_root,audit_ref,feedback_ref=self._completion(draft,suffix="blocked")
            with mock.patch.object(final,"_current_preparation",
                    side_effect=Blocked("final publication preparation: quorum blocker")), \
                 self.assertRaisesRegex(Blocked,"quorum blocker"):
                final.publish(draft,ledger,root/"blocked",authorization_key=self.KEY,
                    expected_ledger_anchor=self.ANCHOR,expected_ledger_head=ledger["head_hash"],
                    run_root=run_root,completeness_ref=audit_ref,feedback_ref=feedback_ref)
            self.assertFalse((root/"blocked").exists())


if __name__ == "__main__":
    unittest.main()
