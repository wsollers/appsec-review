import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import claim_lifecycle_core as core
import claim_review_lifecycle as lifecycle
from execution_state import Blocked, read_json
from schema_validate import validate_document

FIXTURES = ROOT / "tests/fixtures/claim-lifecycle"
RUN_ID = "claim-run"
SOURCE = "sha256:" + "2" * 64


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def binding(job="upstream", artifact="upstream.json"):
    return {"job_id": job, "attempt_id": job + "-1",
            "pointer_sha256": "sha256:" + "1" * 64,
            "artifact_path": artifact, "artifact_sha256": "sha256:" + "3" * 64}


def upstreams():
    ledger = fixture("claim-ledger.json")
    red = core.red_team(ledger, binding("claim-ledger-routing", "claim-decision-ledger.json"),
                        fixture("red-decisions.json"))
    blue = core.blue_team(red, binding("07-red-team-adversarial", "red-team-adversarial.json"),
                          fixture("blue-decisions.json"))
    verification = core.verify(blue, binding("08-blue-team-refutation", "blue-team-refutation.json"),
                               fixture("verification-decisions.json"),
                       verification_evidence=fixture("verification-evidence.json"))
    return {"07-red-team-adversarial": ledger, "08-blue-team-refutation": red,
            "09-independent-verification": blue, "12-scoring-prioritization": verification}


DECISIONS = {"07-red-team-adversarial": "red-decisions.json",
             "08-blue-team-refutation": "blue-decisions.json",
             "09-independent-verification": "verification-decisions.json",
             "12-scoring-prioritization": "scoring-decisions.json"}


def pool(stage, decisions=None):
    decisions = copy.deepcopy(decisions if decisions is not None else fixture(DECISIONS[stage])["decisions"])
    candidates = []
    for index, decision in enumerate(decisions):
        candidate = {"candidate_id": f"pool-{index}", "subject_id": decision["claim_id"],
            "assertion": json.dumps(decision, sort_keys=True, separators=(",", ":")),
            "evidence_sha256": "sha256:" + str(index + 4) * 64,
            "claim_class": lifecycle.POOL_CLASSES[stage]}
        candidate["semantic_sha256"] = lifecycle._sha({key: candidate[key] for key in
            ("subject_id", "assertion", "claim_class")})
        candidate.update(worker_ids=[f"worker-{index}"], producer_ids=[f"producer-{index}"])
        candidates.append(candidate)
    result = {"schema": "appsec-review/deterministic-pool-merge/1.0", "run_id": RUN_ID,
        "expected_worker_ids": [f"worker-{i}" for i in range(len(candidates))],
        "observed_worker_ids": [f"worker-{i}" for i in range(len(candidates))],
        "missing_worker_ids": [], "candidates": candidates, "conflicts": []}
    result["merge_sha256"] = lifecycle._sha(result)
    return result


def reseal_pool(value):
    for candidate in value["candidates"]:
        candidate["semantic_sha256"] = lifecycle._sha({key: candidate[key] for key in
            ("subject_id", "assertion", "claim_class")})
    value["merge_sha256"] = lifecycle._sha({key: item for key, item in value.items()
                                             if key != "merge_sha256"})
    return value


def inputs(stage):
    upstream = upstreams()[stage]
    merge = pool(stage)
    return {"run_id": RUN_ID, "stage": stage, "source_generation": SOURCE,
        "upstream": upstream, "upstream_binding": binding(core.STAGES[stage][0], core.STAGES[stage][1]),
        "pool": merge, "pool_binding": {"job_id": "deterministic-pool-merge",
            "attempt_id": "merge-1", "artifact_path": "deterministic-pool-merge.json",
            "artifact_sha256": "sha256:" + "4" * 64,
            "accepted_pointer_sha256": "sha256:" + "5" * 64},
        "decisions": lifecycle.decisions_from_pool(stage, upstream, merge),
        "applicability": "APPLICABLE", "code": lifecycle._code_hashes(stage),
        **({"verification_evidence": fixture("verification-evidence.json")}
           if stage == "09-independent-verification" else {})}


class ClaimReviewLifecycleTests(unittest.TestCase):
    def test_all_four_stages_construct_decisions_only_from_pool_assertions(self):
        expected_arrays = lifecycle.OUTPUT_ARRAYS
        for stage in lifecycle.STAGES:
            with self.subTest(stage=stage):
                value = inputs(stage)
                result = lifecycle.build_result(value, "attempt-1")
                self.assertEqual(len(result[expected_arrays[stage]]), 2)
                self.assertEqual(validate_document(result, core.STAGES[stage][3]), [])
                self.assertEqual({row["claim_id"] for row in result[expected_arrays[stage]]},
                                 {row["claim_id"] for row in value["upstream"][lifecycle.ARRAYS[stage]]})

    def test_incomplete_conflicting_extra_and_malformed_pool_decisions_fail_closed(self):
        stage = "07-red-team-adversarial"
        upstream = upstreams()[stage]
        honest = pool(stage)
        cases = []
        incomplete = copy.deepcopy(honest)
        incomplete["observed_worker_ids"] = ["worker-0"]
        incomplete["missing_worker_ids"] = ["worker-1"]
        cases.append(reseal_pool(incomplete))
        conflicting = copy.deepcopy(honest); conflicting["conflicts"] = [{"candidate_id": "x", "worker_ids": ["worker-0"]}]
        cases.append(reseal_pool(conflicting))
        extra = copy.deepcopy(honest); extra["candidates"][0]["subject_id"] = "claim-extra"
        cases.append(reseal_pool(extra))
        malformed = copy.deepcopy(honest); malformed["candidates"][0]["assertion"] = "not-json"
        cases.append(reseal_pool(malformed))
        for candidate in cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises(Blocked):
                    lifecycle.decisions_from_pool(stage, upstream, candidate)

    def test_empty_upstream_executes_as_no_op_without_a_pool(self):
        upstream = {"schema": "appsec-review/claim-ledger-input/0.1", "run_id": RUN_ID,
            "ledger_head_id": "empty", "ledger_head_sha256": "sha256:" + "d" * 64,
            "candidates": []}
        value = {"run_id": RUN_ID, "stage": "07-red-team-adversarial",
            "source_generation": SOURCE, "upstream": upstream,
            "upstream_binding": binding("claim-ledger-routing", "claim-decision-ledger.json"),
            "pool": None, "pool_binding": None, "decisions": {"decisions": []},
            "applicability": "SKIPPED_NA_NO_CANDIDATES",
            "code": lifecycle._code_hashes("07-red-team-adversarial")}
        result = lifecycle.build_result(value, "empty-1")
        self.assertEqual(result["hypotheses"], [])
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / "07-red-team-adversarial"
            with mock.patch.object(lifecycle, "root", return_value=base), \
                    mock.patch.object(lifecycle, "current_inputs", return_value=value):
                pointer = lifecycle.run(RUN_ID, "dagster-empty", "07-red-team-adversarial")
                attempt = base / "attempts" / pointer["attempt_id"]
                self.assertEqual(pointer["status"], "OK")
                self.assertEqual(read_json(attempt / "status.json")["applicability"],
                                 "SKIPPED_NA_NO_CANDIDATES")
                self.assertEqual(read_json(attempt / "applicability.json")["decision"], "SKIPPED_NA")
                self.assertTrue(read_json(attempt / "result.json")["gaps"])

    def test_lifecycle_publishes_reuses_and_blocks_after_tampering(self):
        stage = "09-independent-verification"
        value = inputs(stage)
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / stage
            with mock.patch.object(lifecycle, "root", return_value=base), \
                    mock.patch.object(lifecycle, "current_inputs", return_value=value):
                first = lifecycle.run(RUN_ID, "dagster-1", stage)
                second = lifecycle.run(RUN_ID, "dagster-2", stage)
                self.assertEqual(first["attempt_id"], second["attempt_id"])
                attempt = base / "attempts" / first["attempt_id"]
                self.assertEqual(read_json(attempt / "result.json")["output_contract"], stage)
                (attempt / core.STAGES[stage][4]).write_text("{}", encoding="utf-8")
                with self.assertRaises(Blocked):
                    lifecycle.run(RUN_ID, "dagster-3", stage)

    def test_cwe_judged_decisions_do_not_block_on_their_own_code_fingerprint(self):
        # Regression: _code_hashes(stage) was called with no cwe_judged argument at both the
        # execute() preflight and _validate_attempt()'s reuse check, so it never matched a
        # current_inputs() snapshot taken with cwe_judged=True (ADR-0020/brief O2: any decision
        # that carries "cwe" at 07/09/12). Every CWE-judged attempt blocked, even with no code
        # change and no fixture decision ever exercised this path.
        stage = "09-independent-verification"
        upstream = upstreams()[stage]
        raw_decisions = copy.deepcopy(fixture(DECISIONS[stage])["decisions"])
        raw_decisions[0]["cwe"] = {"cwe_id": "CWE-22", "rationale": "Path traversal weakness."}
        merge = pool(stage, decisions=raw_decisions)
        decisions = lifecycle.decisions_from_pool(stage, upstream, merge)
        self.assertTrue(lifecycle._cwe_judged(decisions))
        value = {"run_id": RUN_ID, "stage": stage, "source_generation": SOURCE,
            "upstream": upstream, "upstream_binding": binding(core.STAGES[stage][0], core.STAGES[stage][1]),
            "pool": merge, "pool_binding": {"job_id": "deterministic-pool-merge",
                "attempt_id": "merge-1", "artifact_path": "deterministic-pool-merge.json",
                "artifact_sha256": "sha256:" + "4" * 64,
                "accepted_pointer_sha256": "sha256:" + "5" * 64},
            "decisions": decisions, "applicability": "APPLICABLE",
            "code": lifecycle._code_hashes(stage, True),
            "verification_evidence": fixture("verification-evidence.json")}
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / stage
            with mock.patch.object(lifecycle, "root", return_value=base), \
                    mock.patch.object(lifecycle, "current_inputs", return_value=value):
                first = lifecycle.run(RUN_ID, "dagster-cwe-1", stage)
                self.assertEqual(first["status"], "OK")
                second = lifecycle.run(RUN_ID, "dagster-cwe-2", stage)
                self.assertEqual(first["attempt_id"], second["attempt_id"])

    def test_new_failure_blocks_old_success_and_a_new_attempt_recovers(self):
        stage = "08-blue-team-refutation"
        value = inputs(stage)
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / stage
            with mock.patch.object(lifecycle, "root", return_value=base), \
                    mock.patch.object(lifecycle, "current_inputs", return_value=value):
                first = lifecycle.run(RUN_ID, "dagster-success", stage)
                with mock.patch.object(lifecycle, "build_result", side_effect=RuntimeError("pool crashed")):
                    with self.assertRaises(RuntimeError):
                        lifecycle.run(RUN_ID, "dagster-failure", stage, force=True)
                failed = read_json(base / "accepted.json")
                self.assertEqual(failed["status"], "FAILED")
                self.assertNotEqual(failed["attempt_id"], first["attempt_id"])
                recovered = lifecycle.run(RUN_ID, "dagster-recovery", stage)
                self.assertEqual(recovered["status"], "OK")
                self.assertNotIn(recovered["attempt_id"], {first["attempt_id"], failed["attempt_id"]})

    def test_decision_schema_is_closed_and_scoring_is_bounded(self):
        for stage in lifecycle.STAGES:
            for decision in fixture(DECISIONS[stage])["decisions"]:
                self.assertEqual(validate_document({"stage": stage, "decision": decision},
                                                   "claim-review-decision.schema.json"), [])
        hostile = fixture("scoring-decisions.json")["decisions"][0]
        hostile["factors"]["impact"] = 5
        self.assertTrue(validate_document({"stage": "12-scoring-prioritization", "decision": hostile},
                                          "claim-review-decision.schema.json"))


if __name__ == "__main__":
    unittest.main()
