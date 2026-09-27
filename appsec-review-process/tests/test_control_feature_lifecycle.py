from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import control_feature_lifecycle as life  # noqa: E402
from execution_state import Blocked, atomic_json, file_hash, tree_hashes  # noqa: E402
from schema_validate import validate_document  # noqa: E402
from worker_result import artifact_records, terminal_envelope  # noqa: E402

SHA = "sha256:" + "1" * 64
BINDING = {"job_id":"upstream", "attempt_id":"a1", "artifact_path":"result.json",
           "artifact_sha256":SHA, "accepted_pointer_sha256":"sha256:" + "2" * 64}
NA_DISPOSITION = {"execution_status":"SKIPPED", "skip_reason":"not-applicable-no-verified-claims",
                  "gaps":["not-applicable-no-verified-claims"]}


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
        quorum = {"run_id":"run", "decisions":[{"candidate_id":"c1", "decision":"ADMITTED"}]}
        rescope = {"run_id":"run", "state":"ITERATION_LIMIT",
                   "affected_nodes":["final-publication-gate"]}
        remediation = {"run_id":"run", "proposals":[], "retests":[]}
        inputs = {"run_id":"run", "job_id":"final-publication-preparation", "source_generation":SHA,
            "code":{}, "report":BINDING, "audit":BINDING, "feedback":BINDING,
            "quorum":BINDING, "rescope":BINDING, "remediation_retest":BINDING,
            "remediation_retest_disposition":NA_DISPOSITION,
            "report_sha256":life._sha(report), "publication_manifest_sha256":SHA,
            "render_publication_manifest_sha256":SHA,
            "draft_artifacts":{"presentation/report.html":SHA,"presentation/report.pdf":SHA},
            "draft_attempt":"/run/data/jobs/10-synthesis-report/attempts/a1"}
        rows = [(report,BINDING,Path("draft")), (audit,BINDING,Path("audit")),
                (feedback,BINDING,Path("feedback")), (quorum,BINDING,Path("quorum")),
                (rescope,BINDING,Path("rescope")), (remediation,BINDING,Path("remediation"))]
        with mock.patch.object(life, "_current", side_effect=rows):
            result, status, gaps, skip = life._produce("run", "final-publication-preparation", inputs)
        self.assertEqual(status, "OK_WITH_GAPS")
        self.assertEqual(gaps, ["human-signoff-required"])
        self.assertIsNone(skip)
        self.assertEqual(result["status"], "PENDING_HUMAN_APPROVAL")
        self.assertEqual(result["completion_gate"]["draft_report_sha256"], inputs["report_sha256"])
        self.assertEqual(result["control_evidence"]["quorum"]["admitted_count"], 1)
        self.assertTrue(result["control_evidence"]["remediation_retest"]["skipped_not_applicable"])
        self.assertEqual(validate_document(result, "final-publication-preparation.schema.json"), [])

    def test_final_preparation_retains_nonadmitted_quorum_as_reportable_state(self):
        report = {"status":"DRAFT_EVIDENCE_BACKED"}
        audit = {"complete":True, "subject_sha256":life._sha(report)}
        feedback = {"terminal_state":"COMPLETE", "audit_sha256":life._sha(audit)}
        quorum = {"run_id":"run", "decisions":[{
            "candidate_id":"c1", "decision":"INSUFFICIENT_DIVERSITY"}]}
        rescope = {"run_id":"run", "state":"ITERATION_LIMIT",
                   "affected_nodes":["final-publication-gate"]}
        remediation = {"run_id":"run", "proposals":[], "retests":[]}
        inputs = {"run_id":"run", "job_id":"final-publication-preparation", "source_generation":SHA,
            "code":{}, "report":BINDING, "audit":BINDING, "feedback":BINDING,
            "quorum":BINDING, "rescope":BINDING, "remediation_retest":BINDING,
            "remediation_retest_disposition":NA_DISPOSITION,
            "report_sha256":life._sha(report), "publication_manifest_sha256":SHA,
            "render_publication_manifest_sha256":SHA,
            "draft_artifacts":{"presentation/report.html":SHA,"presentation/report.pdf":SHA},
            "draft_attempt":"/run/data/jobs/10-synthesis-report/attempts/a1"}
        rows = [(report,BINDING,Path("draft")), (audit,BINDING,Path("audit")),
                (feedback,BINDING,Path("feedback")), (quorum,BINDING,Path("quorum")),
                (rescope,BINDING,Path("rescope")), (remediation,BINDING,Path("remediation"))]
        with mock.patch.object(life, "_current", side_effect=rows):
            result, status, gaps, skip = life._produce(
                "run", "final-publication-preparation", inputs)
        self.assertEqual(status, "OK_WITH_GAPS")
        self.assertEqual(gaps, ["human-signoff-required"])
        self.assertIsNone(skip)
        self.assertEqual(
            result["control_evidence"]["quorum"]["insufficient_diversity_count"], 1)

    def test_remediation_gap_cannot_masquerade_as_non_applicable(self):
        evidence, blockers = life._publication_controls("run",
            {"run_id":"run", "decisions":[]}, BINDING,
            {"run_id":"run", "state":"ITERATION_LIMIT",
             "affected_nodes":["final-publication-gate"]}, BINDING,
            {"run_id":"run", "proposals":[], "retests":[]}, BINDING,
            {"execution_status":"OK_WITH_GAPS", "skip_reason":None,
             "gaps":["verified-claims-have-no-retained-remediation-proposal"]})
        self.assertFalse(evidence["remediation_retest"]["skipped_not_applicable"])
        self.assertIn("remediation:empty-result-is-not-an-accepted-na-skip", blockers)

    def test_pending_preparation_publishes_a_real_common_envelope(self):
        inputs = {"run_id":"run", "job_id":"final-publication-preparation",
                  "source_generation":SHA, "code":{}}
        gate = {"schema":"appsec-review/final-publication-gate/1.0", "run_id":"run",
                "draft_report_sha256":SHA, "eligible":False, "publication_status":"BLOCKED",
                "blockers":["human_signoff_missing"], "human_signoff":None}
        result = {"schema":"appsec-review/final-publication-preparation/1.0", "run_id":"run",
            "status":"PENDING_HUMAN_APPROVAL", "draft_report_sha256":SHA,
            "draft_publication_manifest_sha256":SHA, "draft_render_manifest_sha256":SHA,
            "draft_artifacts":{"presentation/report.html":SHA,"presentation/report.pdf":SHA},
            "completion_gate":gate,
            "control_evidence":{"quorum":{"binding":BINDING,"decision_count":0,"admitted_count":0,
                                             "insufficient_diversity_count":0,
                                             "conflicting_evidence_count":0},
                "rescope":{"binding":BINDING,"state":"ITERATION_LIMIT",
                           "final_publication_affected":True},
                "remediation_retest":{"binding":BINDING,"proposal_count":0,"retest_count":0,
                                      "skipped_not_applicable":True,
                                      "disposition":NA_DISPOSITION}},
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

    def test_evidence_supported_remediation_skip_is_a_current_control_input(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); attempt = base / "attempts" / "skip-1"; attempt.mkdir(parents=True)
            result = {"schema":"appsec-review/remediation-retest-feedback/1.0",
                      "run_id":"run", "proposals":[], "retests":[]}
            atomic_json(attempt / "remediation-retest.json", result)
            atomic_json(attempt / "status.json", {"status":"SKIPPED"})
            envelope = terminal_envelope(run_id="run", job_id="remediation-retest-feedback",
                attempt_id="skip-1", worker_kind="deterministic_python", execution_status="SKIPPED",
                acceptance_status="CURRENT", input_fingerprint=SHA,
                output_contract="remediation-retest-feedback", started_at="2026-09-27T00:00:00Z",
                finished_at="2026-09-27T00:00:01Z", summary="No verified claims.",
                artifacts=artifact_records(attempt, ["remediation-retest.json", "status.json"]),
                gaps=["not-applicable-no-verified-claims"],
                skip_reason="not-applicable-no-verified-claims")
            atomic_json(attempt / "result.json", envelope)
            pointer = {"schema":"appsec-review/accepted-worker-result/1.0", "status":"SKIPPED",
                "run_id":"run", "job":"remediation-retest-feedback", "attempt_id":"skip-1",
                "fingerprint":SHA, "envelope_path":"result.json",
                "envelope_sha256":file_hash(attempt / "result.json"), "hashes":tree_hashes(attempt),
                "accepted_at":"2026-09-27T00:00:02Z", "reason":"not-applicable-no-verified-claims"}
            atomic_json(base / "accepted.json", pointer)
            atomic_json(base / "latest.json", {"attempt_id":"skip-1"})
            with mock.patch.object(life, "_accepted_base", return_value=base):
                value, binding, retained = life._current("run", "remediation-retest-feedback")
            self.assertEqual(value, result)
            self.assertEqual(binding["attempt_id"], "skip-1")
            self.assertEqual(retained, attempt)


if __name__ == "__main__":
    unittest.main()
