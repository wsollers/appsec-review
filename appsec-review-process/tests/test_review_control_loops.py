from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from execution_state import Blocked
import review_control_loops as controls


class ReviewControlLoopTests(unittest.TestCase):
    def workers(self):
        expected = [{"worker_id": "w1", "producer_id": "p1", "run_id":"run-1"},
                    {"worker_id": "w2", "producer_id": "p2", "run_id":"run-1"}]
        candidate = {"candidate_id": "c1", "subject_id": "component-1", "assertion": "bounded claim",
                     "evidence_sha256": "sha256:" + "a" * 64, "claim_class": "candidate_only"}
        results = [{"worker_id": "w1", "producer_id": "p1", "run_id":"run-1", "status": "OK", "candidates": [candidate]},
                   {"worker_id": "w2", "producer_id": "p2", "run_id":"run-1", "status": "OK", "candidates": [candidate]}]
        return expected, results

    def test_deterministic_merge_and_evidence_qualified_quorum(self):
        expected, results = self.workers()
        first = controls.deterministic_merge("run-1", expected, results)
        second = controls.deterministic_merge("run-1", list(reversed(expected)), list(reversed(results)))
        self.assertEqual(first, second)
        quorum = controls.evidence_qualified_quorum("run-1", first, minimum_producers=2)
        self.assertEqual(quorum["decisions"][0]["decision"], "ADMITTED")
        missing = controls.deterministic_merge("run-1", expected, results[:1])
        with self.assertRaisesRegex(Blocked, "missing workers"):
            controls.evidence_qualified_quorum("run-1", missing, minimum_producers=1)

    def test_conflicting_candidate_is_not_silently_merged(self):
        expected, results = self.workers(); results[1] = deepcopy(results[1])
        results[1]["candidates"][0]["assertion"] = "contradictory claim"
        merged = controls.deterministic_merge("run-1", expected, results)
        self.assertEqual(merged["candidates"], [])
        self.assertEqual(merged["conflicts"][0]["candidate_id"], "c1")

    def test_dependency_index_and_bounded_affected_only_rescope(self):
        index = controls.dependency_index("run-1", ["component", "threat", "owasp", "report"], [
            {"upstream": "component", "downstream": "threat"},
            {"upstream": "threat", "downstream": "owasp"},
            {"upstream": "owasp", "downstream": "report"}])
        plan = controls.bounded_rescope("run-1", index, ["threat"], iteration=1, max_iterations=3)
        self.assertEqual(plan["affected_nodes"], ["owasp", "report", "threat"])
        self.assertEqual(plan["preserved_nodes"], ["component"])
        stalled = controls.bounded_rescope("run-1", index, ["threat"], iteration=2,
                                           max_iterations=3, previous_plan=plan)
        self.assertEqual(stalled["state"], "NO_PROGRESS")
        with self.assertRaisesRegex(Blocked, "cycle"):
            controls.dependency_index("run-1", ["a", "b"], [
                {"upstream": "a", "downstream": "b"}, {"upstream": "b", "downstream": "a"}])

    def test_completeness_feedback_routes_and_terminates(self):
        expected = [{"obligation_id": "o1"}, {"obligation_id": "o2"}]
        audit = controls.completeness_audit("run-1", expected, [{"obligation_id": "o1",
            "evidence_sha256":"sha256:"+"1"*64}], [])
        self.assertFalse(audit["complete"])
        routed = controls.synthetic_feedback("run-1", audit, {"o2": "02-source-sast"},
                                             iteration=1, max_iterations=2)
        self.assertEqual(routed["terminal_state"], "TARGETED_ANALYSIS_REQUIRED")
        terminal = controls.synthetic_feedback("run-1", audit, {"o2": "02-source-sast"},
                                               iteration=2, max_iterations=2, previous_feedback=routed)
        self.assertEqual(terminal["terminal_state"], "UNRESOLVED_AND_REPORTED")

    def test_remediation_never_claims_fixed_without_same_environment_independent_retest(self):
        proposals = controls.remediation_proposals("run-1", [{"claim_id": "c1", "status": "VERIFIED"}],
            [{"proposal_id": "r1", "claim_id": "c1", "state": "AUTHORIZED", "author_id": "author",
              "change_ref": "patch-1", "rationale": "Bounded fix proposal.",
              "target_components": ["component-1"]}])
        proposal = proposals["proposals"][0]
        env = {"source_sha256":"sha256:"+"a"*64,"build_sha256": "sha256:" + "b" * 64,
               "target_sha256": "sha256:" + "c" * 64,"change_ref":"patch-1"}
        fixed = controls.same_environment_retest("run-1", proposal, env,
            {"proposal_id":"r1","environment": env, "result": "PASSED", "executor_id": "executor"},
            {"producer_id": "verifier", "decision": "VERIFIED"})
        self.assertEqual(fixed["state"], "FIXED")
        with self.assertRaisesRegex(Blocked, "differs"):
            controls.same_environment_retest("run-1", proposal, env,
                {"proposal_id":"r1","environment": {**env, "build_sha256": "sha256:" + "d" * 64}, "result": "PASSED",
                 "executor_id": "executor"}, {"producer_id": "verifier", "decision": "VERIFIED"})

    def test_final_gate_requires_complete_terminal_exact_human_signoff(self):
        draft = {"status": "DRAFT_EVIDENCE_BACKED", "verified_findings": []}
        audit = {"complete": True}; feedback = {"terminal_state": "COMPLETE"}
        blocked = controls.completion_gate("run-1", draft, audit, feedback, None)
        self.assertFalse(blocked["eligible"])
        signoff = {"signoff_id": "s1", "reviewer_id": "human-1",
                   "report_sha256": controls._sha(draft), "decision": "APPROVED",
                   "signed_at": "2026-09-27T00:00:00Z"}
        final = controls.completion_gate("run-1", draft, audit, feedback, signoff)
        self.assertTrue(final["eligible"]); self.assertEqual(final["publication_status"], "FINAL_APPROVED")
        forged = deepcopy(signoff); forged["report_sha256"] = "sha256:" + "0" * 64
        self.assertFalse(controls.completion_gate("run-1", draft, audit, feedback, forged)["eligible"])


if __name__ == "__main__":
    unittest.main()
