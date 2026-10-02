"""claim-ledger-decisions (ADR-0034 V1): the accepted 07/08/09 decisions become ledger transitions."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import claim_ledger as ledger
import claim_ledger_decisions as decisions
import execution_state
import test_claim_ledger

RED, BLUE, VERIFY = decisions.STAGES


class ClaimLedgerDecisionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_claim_ledger.ClaimLedgerTests()   # reuse its candidates and accepted-decision publisher
        self.fixture.setUp()

    def candidates(self):
        return self.fixture.candidates()

    def decision_schema_gate(self, value, schema):
        if schema in ledger.DECISION_SCHEMAS.values():
            value = {key: item for key, item in value.items() if key not in {"ledger_head_id", "ledger_head_sha256"}}
        return self.fixture.decision_schema_gate(value, schema)

    def publish(self, jobs: Path, stage: str, claim: str, status: str, prior: dict, head: tuple | None = None):
        base, attempt = self.fixture.publish_decision(jobs, stage, claim, status, prior["source_generation"],
                                              prior["component_generation"], stage.split("-")[0] + "-1")
        artifact = ledger.DECISION_PRODUCERS[stage][1]
        result = execution_state.read_json(attempt / artifact)
        result["ledger_head_id"], result["ledger_head_sha256"] = head or (prior["entries"][-1]["event_id"],
                                                                           prior["head_hash"])
        execution_state.atomic_json(attempt / artifact, result)
        self.fixture.reseal_decision(base, attempt, artifact)
        return {"attempt_id": attempt.name}

    def apply(self, prior: dict, jobs: Path, stages: dict) -> tuple[dict, list[str]]:
        requests, gaps = decisions.plan("run1", prior, jobs, stages)
        with mock.patch.object(ledger, "validate_document", side_effect=self.decision_schema_gate):
            value = ledger.build_ledger("run1", "decisions-1", [], prior=prior, decisions=requests,
                                        decision_jobs_root=jobs, job_id=decisions.JOB)
        return value, gaps

    def test_each_stage_verdict_becomes_one_transition_and_09_may_reopen_an_08_refutation(self):
        prior = ledger.build_ledger("run1", "routing-1", self.candidates()[:1])
        claim = prior["claim_states"][0]["claim_id"]
        with tempfile.TemporaryDirectory() as directory:
            jobs = Path(directory) / "jobs"
            stages = {RED: self.publish(jobs, RED, claim, "HYPOTHESIS", prior),
                      BLUE: self.publish(jobs, BLUE, claim, "REFUTED", prior),
                      VERIFY: self.publish(jobs, VERIFY, claim, "UNRESOLVED", prior)}
            value, gaps = self.apply(prior, jobs, stages)
        self.assertEqual(gaps, [])
        self.assertEqual(value["job_id"], decisions.JOB)
        steps = [(entry["from_status"], entry["status"], entry["decision_authority"]["job_id"])
                 for entry in value["entries"] if entry["event_type"] == "status_decision"]
        self.assertEqual(steps, [("candidate", "under_review", RED), ("under_review", "refuted", BLUE),
                                 ("refuted", "unresolved", VERIFY)])
        self.assertEqual(ledger.validate_ledger(value), [])

    def test_a_repeated_status_adds_no_event(self):
        prior = ledger.build_ledger("run1", "routing-1", self.candidates()[:1])
        claim = prior["claim_states"][0]["claim_id"]
        with tempfile.TemporaryDirectory() as directory:
            jobs = Path(directory) / "jobs"
            stages = {RED: self.publish(jobs, RED, claim, "HYPOTHESIS", prior),
                      BLUE: self.publish(jobs, BLUE, claim, "UNRESOLVED", prior),
                      VERIFY: self.publish(jobs, VERIFY, claim, "BLOCKED", prior)}
            value, gaps = self.apply(prior, jobs, stages)
        self.assertEqual(gaps, [])
        self.assertEqual([entry["status"] for entry in value["entries"]], ["candidate", "under_review", "unresolved"])

    def test_a_missing_or_stale_stage_is_a_gap_and_stops_later_stages(self):
        prior = ledger.build_ledger("run1", "routing-1", self.candidates()[:1])
        claim = prior["claim_states"][0]["claim_id"]
        with tempfile.TemporaryDirectory() as directory:
            jobs = Path(directory) / "jobs"
            red = self.publish(jobs, RED, claim, "HYPOTHESIS", prior)
            value, gaps = self.apply(prior, jobs, {RED: red, BLUE: None, VERIFY: None})
            self.assertEqual(value["claim_states"][0]["status"], "under_review")
            self.assertEqual(len(gaps), 1)
            self.assertIn("08-blue-team-refutation has no accepted result", gaps[0])
            blue = self.publish(jobs, BLUE, claim, "SURVIVING", prior, head=("event-other", "sha256:" + "0" * 64))
            verify = self.publish(jobs, VERIFY, claim, "VERIFIED", prior)
            value, gaps = self.apply(prior, jobs, {RED: red, BLUE: blue, VERIFY: verify})
        self.assertEqual(value["claim_states"][0]["status"], "under_review")
        self.assertEqual(len(gaps), 1)
        self.assertIn("reviewed a different ledger head", gaps[0])

    def test_the_transition_tables_agree(self):
        import claim_lifecycle_core
        self.assertEqual({key: set(value) for key, value in ledger.TRANSITIONS.items()},
                         claim_lifecycle_core.LEDGER_TRANSITIONS)
        self.assertIn("unresolved", ledger.TRANSITIONS["refuted"])
        self.assertNotIn("verified", ledger.TRANSITIONS["refuted"])


if __name__ == "__main__":
    unittest.main()
