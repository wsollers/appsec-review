"""Report projection of lane 12b (brief F): published, skipped, absent, stale and mismatched
records, the denylist re-scan at report time, and the renderer block under the finding labelled as
unvalidated static text."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import execution_state
import finding_enrichment
import poc_fix_derive as derive
import poc_fix_pool as fix_pool
import poc_fix_report as poc_report
import poc_fix_worker as worker
import synthesis_report_presentation as presentation
from tests.test_poc_fix_derive import AUTHOR, HIGH, REACH, good_reply, priority
from tests.test_poc_fix_worker import BINDING, LAUNCHED, RUN, Harness, merge_for

CITATION = {"citation_id": "citation-v", "producer_job_id": "09-independent-verification", "producer_attempt_id": "v1",
            "artifact_path": "requests/v1.json", "artifact_sha256": "sha256:" + "6" * 64,
            "locator_json": None, "observed_fact": "verifier read the line"}


def report_finding(row: dict) -> dict:
    return {"claim_id": row["claim_id"], "title": row["hypothesis"], "component_ids": row["component_ids"],
            "severity": row["severity"], "priority": "P0", "score": row["score"], "citations": row["citations"],
            "verification_citations": [CITATION]}


def report(*rows: dict) -> dict:
    return {"run_id": RUN, "ledger_head_sha256": "sha256:" + "7" * 64,
            "verified_findings": [report_finding(row) for row in rows], "unresolved_candidates": [], "limitations": []}


class ReportTests(Harness):
    def setUp(self):
        super().setUp()
        scoring = execution_state.data_path(RUN, "jobs", "12-scoring-prioritization")
        scoring.mkdir(parents=True)
        (scoring / "accepted.json").write_text(json.dumps({"attempt_id": BINDING["attempt_id"], "status": "OK"}))
        self.root = execution_state.run_path(RUN)

    def publish(self, reply=None, rows=None):
        rows = rows or (priority(REACH, line=9), priority(HIGH, line=9, severity="HIGH"))
        inputs = self.inputs(*rows)
        records = [derive.derive(inputs["requests"][0], reply or good_reply(), author=AUTHOR)[0]] if inputs["requests"] else []
        with mock.patch.object(worker, "prepare", return_value=inputs), \
                mock.patch.object(fix_pool, "dispatch", return_value=(merge_for(records), LAUNCHED)):
            return worker.run(RUN, "dagster-1")

    def section(self, *rows):
        value = report(*rows)
        enrichment = finding_enrichment.build(value, self.root)
        return value, enrichment, poc_report.build(value, enrichment, self.root)

    def test_published_record_renders_under_the_eligible_finding_only(self):
        self.publish()
        value, enrichment, section = self.section(priority(REACH, line=9), priority(HIGH, line=9, severity="HIGH"))
        self.assertEqual(poc_report.eligible_claims(enrichment), [REACH])
        self.assertEqual((section["status"], list(section["by_claim"])), ("PUBLISHED", [REACH]))
        self.assertEqual(section["gaps"], [])
        block = section["by_claim"][REACH]
        self.assertEqual((block["label"], block["poc"]["status"], block["fix"]["status"]),
                         ("UNVALIDATED", "PROPOSED_UNVALIDATED", "PATCH_PROPOSED_UNVALIDATED"))
        self.assertIn("never executed", block["label_text"])
        self.assertEqual(block["cited_lines"][1]["display"][:24], "sink: app/main.cpp:9 (sh")
        rows = presentation._findings(value, {"citation-v": "E-001"}, enrichment, section)
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(by_id[REACH]["poc_fix"]["poc"]["lines"][-1], "helper(big);")
        self.assertNotIn("poc_fix", by_id[HIGH])

    def test_absent_skipped_and_stale_lanes_are_gaps_under_the_finding(self):
        _value, _enrichment, section = self.section(priority(REACH, line=9))
        self.assertEqual(section["status"], "ABSENT")
        self.assertTrue(any("did not publish" in gap for gap in section["gaps"]))
        self.assertTrue(any(f"{REACH} is Critical and REACHABLE" in gap for gap in section["gaps"]))
        value = report(priority(REACH, line=9))
        enrichment = finding_enrichment.build(value, self.root)
        rows = presentation._findings(value, {"citation-v": "E-001"}, enrichment, section)
        self.assertIsNone(rows[0]["poc_fix"])
        self.assertIn("No light PoC or proposed fix", rows[0]["poc_fix_note"])

        self.publish(rows=(priority(HIGH, line=9, severity="HIGH"),))
        _value, _enrichment, skipped = self.section(priority(HIGH, line=9, severity="HIGH"))
        self.assertEqual((skipped["status"], skipped["reason"], skipped["gaps"]),
                         ("SKIPPED", worker.SKIP_REASON, []))

    def test_stale_lane_is_not_rendered(self):
        self.publish()
        pointer = execution_state.data_path(RUN, "jobs", "12-scoring-prioritization", "accepted.json")
        pointer.write_text(json.dumps({"attempt_id": "s2", "status": "OK"}))
        _value, _enrichment, section = self.section(priority(REACH, line=9))
        self.assertEqual((section["status"], section["by_claim"]), ("STALE", {}))

    def test_record_for_a_finding_the_report_does_not_hold_critical_is_dropped(self):
        self.publish()
        _value, _enrichment, section = self.section(priority(REACH, line=9, severity="HIGH"))
        self.assertEqual(section["by_claim"], {})
        self.assertTrue(any("does not hold verified, Critical and REACHABLE" in gap for gap in section["gaps"]))

    def test_denylist_rejection_shows_a_note_not_the_text(self):
        hostile = good_reply()
        hostile["poc"]["text"] = "helper(big); /* then */ system(\"id\");"
        self.publish(hostile)
        _value, _enrichment, section = self.section(priority(REACH, line=9))
        block = section["by_claim"][REACH]
        self.assertEqual((block["poc"]["text"], block["poc"]["lines"]), (None, []))
        self.assertIn("process-spawn", block["poc"]["note"])
        self.assertTrue(any("denylist" in gap for gap in section["gaps"]))
        self.assertNotIn("system(", json.dumps(section))

    def test_report_time_rescan_withholds_text_that_slipped_past(self):
        record, _ = derive.derive(self.inputs(priority(REACH, line=9))["requests"][0], good_reply(), author=AUTHOR)
        tampered = copy.deepcopy(record)
        tampered["poc"]["text"] = "cat input | sh"
        block, gaps = poc_report.project(tampered)
        self.assertIsNone(block["poc"]["text"])
        self.assertEqual(len(gaps), 1)


class WiringTests(unittest.TestCase):
    def test_worker_pins_the_lane_12b_report_module(self):
        import synthesis_report_worker as synthesis_worker
        self.assertIn("poc_fix_report.py", synthesis_worker.CODE_FILES)
        self.assertIn("poc_fix_denylist.py", synthesis_worker.CODE_FILES)
        self.assertIn(poc_report.RESULT, synthesis_worker.ARTIFACTS)
        contract = json.loads((ROOT / "registry/output-contracts/synthesis-report-publication.json").read_text())
        self.assertIn(poc_report.RESULT, contract["required_files"])


if __name__ == "__main__":
    unittest.main()
