from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import control_feature_lifecycle as life  # noqa: E402
from execution_state import Blocked, atomic_json  # noqa: E402
from schema_validate import validate_document  # noqa: E402

SHA = "sha256:" + "1" * 64
BINDING = {"job_id":"upstream", "attempt_id":"a1", "artifact_path":"result.json",
           "artifact_sha256":SHA, "accepted_pointer_sha256":"sha256:" + "2" * 64}


class ControlFeatureLifecycleTests(unittest.TestCase):
    def fake_coordinate(self, base, **kwargs):
        attempt = Path(base) / "attempts" / "new"
        attempt.mkdir(parents=True)
        inputs = kwargs["derive_inputs"]()
        atomic_json(attempt / "inputs.json", inputs)
        return kwargs["execute_attempt"](
            {"attempt":attempt, "attempt_id":"new", "started_at":"2026-09-27T00:00:00Z"},
            inputs, kwargs["fingerprint_inputs"](inputs))

    @staticmethod
    def fake_record(_base, attempt, **kwargs):
        kwargs["pre_envelope_validate"](attempt, {"status":kwargs["execution_status"]})
        return {"status":kwargs["execution_status"], "skip_reason":kwargs.get("skip_reason")}

    def test_quorum_runs_from_current_merge(self):
        merge = {"schema":"appsec-review/deterministic-pool-merge/1.0", "run_id":"run",
            "expected_worker_ids":["w1","w2"], "observed_worker_ids":["w1","w2"],
            "missing_worker_ids":[], "candidates":[{"candidate_id":"c1", "subject_id":"s1",
            "assertion":"bounded", "evidence_sha256":SHA, "claim_class":"candidate_only",
            "semantic_sha256":SHA, "worker_ids":["w1","w2"], "producer_ids":["p1","p2"]}],
            "conflicts":[]}
        merge["merge_sha256"] = life._sha(merge)
        inputs = {"run_id":"run", "job_id":"evidence-qualified-quorum", "source_generation":SHA,
                  "code":{}, "merge":BINDING, "minimum_producers":2, "require_complete_pool":True}
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch.object(life, "current_inputs", return_value=inputs), \
             mock.patch.object(life, "data_path", side_effect=lambda _run,*parts:Path(folder).joinpath(*parts)), \
             mock.patch.object(life, "_current", return_value=(merge,BINDING,Path(folder))), \
             mock.patch.object(life, "coordinate_worker_lifecycle", side_effect=self.fake_coordinate), \
             mock.patch.object(life, "record_terminal_current", side_effect=self.fake_record):
            result = life.run("run", "dag", "evidence-qualified-quorum")
        self.assertEqual(result["status"], "OK")

    def test_remediation_without_verified_claims_is_evidence_supported_skip(self):
        verification = {"verifications":[]}
        inputs = {"run_id":"run", "job_id":"remediation-retest-feedback", "source_generation":SHA,
                  "code":{}, "verification":BINDING, "verified_claim_ids":[], "proposal":None}
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch.object(life, "current_inputs", return_value=inputs), \
             mock.patch.object(life, "data_path", side_effect=lambda _run,*parts:Path(folder).joinpath(*parts)), \
             mock.patch.object(life, "_current", return_value=(verification,BINDING,Path(folder))), \
             mock.patch.object(life, "_optional_current", return_value=None), \
             mock.patch.object(life, "coordinate_worker_lifecycle", side_effect=self.fake_coordinate), \
             mock.patch.object(life, "record_terminal_current", side_effect=self.fake_record):
            result = life.run("run", "dag", "remediation-retest-feedback")
        self.assertEqual(result, {"status":"SKIPPED", "skip_reason":"not-applicable-no-verified-claims"})

    def test_completeness_accounts_for_unresolved_obligations_as_declared_gaps(self):
        report = {"verified_findings":[], "unresolved_candidates":[{"claim_id":"c1",
            "proof_obligations":[{"obligation_id":"o1", "statement":"Needs runtime proof."}]}],
            "limitations":["Runtime execution was not authorized."]}
        expected, observed, gaps = life._completeness_inputs(report)
        result = life.completeness_audit.completeness_audit("run", expected, observed, gaps,
                                                            subject_sha256=SHA)
        self.assertTrue(result["complete"])
        self.assertEqual(result["missing_ids"], [])
        self.assertEqual(len(result["declared_gap_ids"]), 2)

    def test_final_preparation_is_pending_and_schema_valid(self):
        report = {"status":"DRAFT_EVIDENCE_BACKED"}
        audit = {"complete":True, "subject_sha256":life._sha(report)}
        feedback = {"terminal_state":"COMPLETE", "audit_sha256":life._sha(audit)}
        inputs = {"run_id":"run", "job_id":"final-publication-preparation", "source_generation":SHA,
            "code":{}, "report":BINDING, "audit":BINDING, "feedback":BINDING,
            "report_sha256":life._sha(report), "publication_manifest_sha256":SHA,
            "draft_attempt":"/run/data/jobs/10-synthesis-report/attempts/a1"}
        rows = [(report,BINDING,Path("draft")), (audit,BINDING,Path("audit")),
                (feedback,BINDING,Path("feedback"))]
        with mock.patch.object(life, "_current", side_effect=rows):
            result, status, gaps, skip = life._produce("run", "final-publication-preparation", inputs)
        self.assertEqual(status, "OK_WITH_GAPS")
        self.assertEqual(gaps, ["human-signoff-required"])
        self.assertIsNone(skip)
        self.assertEqual(result["status"], "PENDING_HUMAN_APPROVAL")
        self.assertEqual(validate_document(result, "final-publication-preparation.schema.json"), [])

    def test_pending_preparation_publishes_a_real_common_envelope(self):
        inputs = {"run_id":"run", "job_id":"final-publication-preparation",
                  "source_generation":SHA, "code":{}}
        gate = {"schema":"appsec-review/final-publication-gate/1.0", "run_id":"run",
                "draft_report_sha256":SHA, "eligible":False, "publication_status":"BLOCKED",
                "blockers":["human_signoff_missing"], "human_signoff":None}
        result = {"schema":"appsec-review/final-publication-preparation/1.0", "run_id":"run",
            "status":"PENDING_HUMAN_APPROVAL", "draft_report_sha256":SHA,
            "draft_publication_manifest_sha256":SHA, "completion_gate":gate,
            "draft_attempt":"/run/draft", "required_action":"A named human must approve the exact draft."}
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch.object(life, "current_inputs", return_value=inputs), \
             mock.patch.object(life, "data_path", side_effect=lambda _run,*parts:Path(folder).joinpath(*parts)), \
             mock.patch.object(life, "_produce", return_value=(result,"OK_WITH_GAPS",["human-signoff-required"],None)), \
             mock.patch.object(life, "_validate_attempt", return_value=None):
            pointer = life.run("run", "dag", "final-publication-preparation")
            attempt = Path(folder) / "jobs" / "final-publication-preparation" / "attempts" / pointer["attempt_id"]
            self.assertTrue((attempt / "result.json").is_file())
            self.assertEqual(pointer["status"], "OK_WITH_GAPS")

    def test_stale_inputs_fail_post_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            attempt = Path(folder)
            inputs = {"run_id":"run", "job_id":"completeness-audit"}
            atomic_json(attempt / "inputs.json", inputs)
            with mock.patch.object(life, "current_inputs", return_value={**inputs, "changed":True}):
                with self.assertRaisesRegex(Blocked, "stale"):
                    life._validate_attempt("run", "completeness-audit", attempt, inputs)

    def test_newest_failure_from_upstream_is_not_downgraded(self):
        with mock.patch.object(life.bounded, "load_accepted", side_effect=Blocked("accepted pointer is stale")), \
             mock.patch.object(life, "_accepted_base", return_value=Path("job")):
            with self.assertRaisesRegex(Blocked, "stale"):
                life._current("run", "10-synthesis-report")


if __name__ == "__main__":
    unittest.main()
