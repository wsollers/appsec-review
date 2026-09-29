"""12b-poc-and-fix lifecycle worker: publish, reuse, skip, failed cell and tamper, with canned pool
merges built from fake persona replies through the real derive step and deterministic merge (no
model, no Dagster, no container)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import execution_state
import poc_fix_derive as derive
import poc_fix_pool as fix_pool
import poc_fix_select as selector
import poc_fix_worker as worker
from execution_state import Blocked
from review_control_loops import deterministic_merge
from schema_validate import validate_document
from tests.test_poc_fix_derive import AUTHOR, HIGH, REACH, good_reply, priority, scoring
from tests.test_report_finding_enrichment import write_run

RUN = "r1"
BINDING = {"job_id": "12-scoring-prioritization", "attempt_id": "s1", "pointer_sha256": "sha256:" + "5" * 64,
           "artifact_path": "scoring-prioritization.json", "artifact_sha256": "sha256:" + "4" * 64}
LAUNCHED = SimpleNamespace(pool_directory="pool-1", outcome="COMPLETE", instance_count=1,
                           expansion_sha256="sha256:" + "6" * 64, terminal_manifest_sha256="sha256:" + "7" * 64)


def merge_for(records: list[dict]) -> dict:
    expected = [{"worker_id": f"w{n}", "producer_id": "poc-fix-author", "run_id": RUN} for n in range(len(records))]
    results = [{"worker_id": f"w{n}", "producer_id": "poc-fix-author", "run_id": RUN, "status": "OK",
                "candidates": derive.candidates(record, "sha256:" + "a" * 64)["candidates"]}
               for n, record in enumerate(records)]
    return deterministic_merge(RUN, expected, results)


class Harness(unittest.TestCase):
    """Temporary run root (write_run fixture), pool stubs and canned publications (no tests of its own)."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        base = Path(self.folder.name).resolve()
        self.patches = [mock.patch.object(execution_state, "RUNS", base / "runs"),
                        mock.patch.object(fix_pool.pool_specification, "spec_sha256", return_value="sha256:" + "8" * 64),
                        mock.patch.object(fix_pool, "context", return_value=SimpleNamespace()),
                        mock.patch.object(worker, "_budget_usd", return_value=2.0)]
        for patch in self.patches:
            patch.start()
        write_run(execution_state.run_path(RUN))

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.folder.cleanup()

    def inputs(self, *rows) -> dict:
        document = scoring(*rows)
        selected = selector.select(document, execution_state.run_path(RUN), findings_max=12, window=20)
        return {"run_id": RUN, "source_generation": "sha256:" + "2" * 64, "scoring": BINDING,
                "ledger_head_sha256": document["ledger_head_sha256"],
                "eligibility": {key: selected[key] for key in ("rule", "considered", "eligible", "excluded")},
                "selection_gaps": selected["gaps"], "enrichment_inputs": selected["enrichment_inputs"],
                "requests": selected["requests"], "spec": {"schema": "test-spec"},
                "accepted_at": "2026-09-29T00:00:00Z",
                "applicability": "APPLICABLE" if selected["requests"] else "SKIPPED_NA_NO_ELIGIBLE_FINDINGS",
                "code": worker._code_hashes()}

    def run_twice(self, inputs, merge):
        with mock.patch.object(worker, "prepare", return_value=inputs), \
                mock.patch.object(fix_pool, "dispatch", return_value=(merge, LAUNCHED)) as dispatch:
            first = worker.run(RUN, "dagster-1")
            second = worker.run(RUN, "dagster-2")
        return first, second, dispatch

    def result(self, published) -> dict:
        return json.loads((worker.root(RUN) / "attempts" / published["attempt_id"] / worker.RESULT).read_text())

class WorkerTests(Harness):
    def test_publishes_and_reuses_one_record_per_eligible_finding(self):
        inputs = self.inputs(priority(REACH, line=9), priority(HIGH, line=9, severity="HIGH"))
        record, _ = derive.derive(inputs["requests"][0], good_reply(), author=AUTHOR)
        first, second, dispatch = self.run_twice(inputs, merge_for([record]))
        self.assertEqual(first["status"], "OK")
        self.assertEqual(second["attempt_id"], first["attempt_id"])
        self.assertEqual(dispatch.call_count, 1)
        result = self.result(first)
        self.assertEqual(validate_document(result, worker.RESULT_SCHEMA), [])
        self.assertEqual([row["claim_id"] for row in result["records"]], [REACH])
        self.assertEqual(result["eligibility"]["selected"], 1)
        self.assertEqual(result["records"][0]["label"], "UNVALIDATED")
        self.assertFalse(any(result["claim_limits"].values()))
        attempt = worker.root(RUN) / "attempts" / first["attempt_id"]
        self.assertIn("never executed", (attempt / worker.SUMMARY).read_text())

    def test_no_eligible_finding_publishes_skipped_without_a_pool(self):
        inputs = self.inputs(priority(HIGH, line=9, severity="HIGH"))
        with mock.patch.object(worker, "prepare", return_value=inputs), \
                mock.patch.object(fix_pool, "dispatch") as dispatch:
            first = worker.run(RUN, "dagster-1")
        self.assertEqual(dispatch.call_count, 0)
        self.assertEqual((first["status"], first.get("reason")), ("SKIPPED", worker.SKIP_REASON))
        pointer = json.loads((worker.root(RUN) / "accepted.json").read_text())
        self.assertEqual((pointer["status"], pointer["reason"]), ("SKIPPED", worker.SKIP_REASON))
        self.assertEqual(self.result(first)["records"], [])

    def test_failed_cell_and_denylist_rejection_are_gaps(self):
        inputs = self.inputs(priority(REACH, line=9))
        empty = deterministic_merge(RUN, [{"worker_id": "w0", "producer_id": "poc-fix-author", "run_id": RUN}], [])
        first, _second, _dispatch = self.run_twice(inputs, empty)
        self.assertEqual(first["status"], "OK_WITH_GAPS")
        self.assertEqual([gap["reason"] for gap in self.result(first)["gaps"]], ["author-failed"])

    def test_denylisted_poc_publishes_withheld_with_a_gap(self):
        inputs = self.inputs(priority(REACH, line=9))
        hostile = good_reply()
        hostile["poc"]["text"] = "rm -rf build && helper(big);"
        record, _ = derive.derive(inputs["requests"][0], hostile, author=AUTHOR)
        first, _second, _dispatch = self.run_twice(inputs, merge_for([record]))
        result = self.result(first)
        self.assertEqual(first["status"], "OK_WITH_GAPS")
        self.assertEqual(result["records"][0]["poc"]["text"], None)
        self.assertEqual([gap["reason"] for gap in result["gaps"]], ["denylist-rejected"])
        self.assertNotIn("rm -rf", json.dumps(result))

    def test_tampered_result_fails_validation(self):
        inputs = self.inputs(priority(REACH, line=9))
        record, _ = derive.derive(inputs["requests"][0], good_reply(), author=AUTHOR)
        first, _second, _dispatch = self.run_twice(inputs, merge_for([record]))
        attempt = worker.root(RUN) / "attempts" / first["attempt_id"]
        value = json.loads((attempt / worker.RESULT).read_text())
        value["records"][0]["label"] = "VALIDATED"
        (attempt / worker.RESULT).write_text(json.dumps(value))
        with mock.patch.object(worker, "prepare", return_value=inputs), self.assertRaises(Blocked):
            worker._validate_attempt(attempt, inputs)


if __name__ == "__main__":
    unittest.main()
