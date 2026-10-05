"""Citable structural evidence (ADR-0035): records, re-run checks, derive resolution and the 09 rule.

Hello-autotools 20261004T054551Z-357581: every claim ended UNRESOLVED or REFUTED because 09 could cite no
new independent evidence, and 08/09 code_callers / code_path answers were "described in prose but never
captured as a citation_id". The real input server over the code-query fixture index writes the records.
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import claim_lifecycle_core as core
import claim_review_derive as derive
import claim_reviewer_pool as reviewer_pool
import code_query_fixture as fx
import input_mcp
import tool_evidence as te
from claude_cli_invoker import InvokerOutputError
from execution_state import Blocked, digest
import test_claim_review_derive as dt
from tests import test_lsp_xref as lx

RED, BLUE, VERIFY = "07-red-team-adversarial", "08-blue-team-refutation", "09-independent-verification"
ATTEMPT = dt.REQUEST["attempt_id"]
A, B = dt.A, dt.B
COMPLETE = ("code_path", {"to": "strcpy", "from": "copy_field"})
INCOMPLETE = ("code_callers", {"function": "copy_field"})   # an indirect call in main is an escape


class _Inputs:
    def __init__(self, jobs: Path, ref: str):
        self.jobs, self.ref = jobs, "supporting-evidence:" + ref
        data = (jobs / ref).read_bytes()
        import hashlib
        self.entries = [{"ref": self.ref}]
        self.by_ref = {self.ref: {"sha256": "sha256:" + hashlib.sha256(data).hexdigest()}}

    def text(self, ref):
        return (self.jobs / ref.split(":", 1)[1]).read_text()


class Case(unittest.TestCase):
    job, attempt = VERIFY, ATTEMPT

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.data = Path(tmp.name) / "data"
        self.jobs = self.data / "jobs"
        ref, _summary = fx.publish(self.jobs)
        self.inputs = _Inputs(self.jobs, ref)
        root = lambda _run, *parts: self.data.joinpath(*parts)   # noqa: E731
        for patch in (mock.patch.object(te, "data_path", side_effect=root),
                      mock.patch.object(input_mcp, "data_path", side_effect=root),
                      mock.patch.dict(input_mcp.CONTEXT, {"job_id": self.job, "attempt_id": self.attempt,
                                                          "output_root": "/cell/out"}, clear=True),
                      mock.patch.dict(input_mcp.USAGE, {}, clear=True),
                      mock.patch.dict(input_mcp.BUDGET, {"max": None}),
                      mock.patch.dict(te._INDEXES, {}, clear=True)):
            patch.start()
            self.addCleanup(patch.stop)
        input_mcp.grant(self.inputs.ref, ["code_callers", "code_path", "code_search", "code_calls_to"])
        self.addCleanup(input_mcp.grant, None, [])

    def ask(self, tool, args):
        reply = input_mcp.handle("claim-run", self.inputs, {"method": "tools/call",
                                                            "params": {"name": tool, "arguments": args}})
        self.assertFalse(reply["isError"], reply)
        return json.loads(reply["content"][0]["text"])

    def record_path(self, citation_id):
        return self.data / te.relative_path(self.job, self.attempt, citation_id)


class RecordTests(Case):
    def test_answer_carries_a_content_hash_citation_id_and_the_record_is_deterministic(self):
        first = self.ask(*COMPLETE)
        second = self.ask(*COMPLETE)
        self.assertEqual(first["citation_id"], second["citation_id"])
        record = json.loads(self.record_path(first["citation_id"]).read_text())
        self.assertEqual(record["citation_id"], "tev:" + digest(record["body"])[:32])
        self.assertEqual(record["content_sha256"], "sha256:" + digest(record["body"]))
        self.assertEqual((record["body"]["job_id"], record["body"]["attempt_id"]), (VERIFY, ATTEMPT))
        self.assertEqual(record["body"]["index"]["ref"], self.inputs.ref)
        self.assertTrue(record["body"]["complete"])
        self.assertEqual(record["cell"], "/cell/out")
        answer = {key: value for key, value in first.items() if key != "citation_id"}
        again = te.build("code_path", answer, index=record["body"]["index"], job_id=VERIFY, attempt_id=ATTEMPT,
                         cell="elsewhere", recorded_at="2000-01-01T00:00:00Z")
        self.assertEqual(again["citation_id"], record["citation_id"])        # cell and time are not hashed
        other = te.build("code_path", answer, index=record["body"]["index"], job_id=VERIFY, attempt_id="other")
        self.assertNotEqual(other["citation_id"], record["citation_id"])     # the producer is
        self.assertEqual(len(list(self.record_path(first["citation_id"]).parent.iterdir())), 1)

    def test_locator_tools_and_scoped_calls_get_a_gap_not_an_id(self):
        search = self.ask("code_search", {"text": "copy"})
        self.assertNotIn("citation_id", search)
        self.assertIn("locators only", search["citation_gap"])
        scoped = self.ask("code_calls_to", {"name": "strcpy", "partition_id": "p1"})
        self.assertNotIn("citation_id", scoped)
        self.assertIn("partition_id", scoped["citation_gap"])
        self.assertIn("citation_id", self.ask("code_calls_to", {"name": "strcpy"}))

    def test_no_job_attempt_means_a_gap(self):
        with mock.patch.dict(input_mcp.CONTEXT, {}, clear=True):
            answer = self.ask(*COMPLETE)
        self.assertIn("serves no job attempt", answer["citation_gap"])

    def test_resolver_builds_the_canonical_citation(self):
        answer = self.ask(*COMPLETE)
        citation = te.Resolver("claim-run", VERIFY, ATTEMPT).resolve(answer["citation_id"])
        self.assertEqual((citation["producer_job_id"], citation["producer_attempt_id"]), (VERIFY, ATTEMPT))
        self.assertEqual(citation["artifact_path"], te.relative_path(VERIFY, ATTEMPT, answer["citation_id"]))
        self.assertEqual(json.loads(citation["locator_json"]),
                         {"tool": "code_path", "arguments": {"to": "strcpy", "from": "copy_field"}, "complete": True})
        self.assertEqual(citation["observed_fact"], "code_path(copy_field -> strcpy) -> 1 path(s): copy_field -> strcpy (app/parse.c:22) [complete]")
        callers = self.ask(*INCOMPLETE)
        fact = te.Resolver("claim-run", VERIFY, ATTEMPT).resolve(callers["citation_id"])["observed_fact"]
        self.assertTrue(fact.startswith("code_callers(copy_field) -> app/net.c:4, app/parse.c:8 [incomplete: "), fact)
        self.assertEqual(te.verify_citation("claim-run", citation), citation)

    def test_tampered_record_is_refused(self):
        answer = self.ask(*COMPLETE)
        path = self.record_path(answer["citation_id"])
        record = json.loads(path.read_text())
        record["answer"]["rows"] = []
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "altered"):
            te.Resolver("claim-run", VERIFY, ATTEMPT).resolve(answer["citation_id"])

    def test_a_forged_but_self_consistent_record_fails_the_rerun(self):
        answer = self.ask(*COMPLETE)
        record = json.loads(self.record_path(answer["citation_id"]).read_text())
        forged_answer = copy.deepcopy(record["answer"])
        forged_answer["rows"][0]["steps"][0]["function"] = "attacker_entry"
        forged = te.build("code_path", forged_answer, index=record["body"]["index"], job_id=VERIFY, attempt_id=ATTEMPT)
        te.write("claim-run", forged)
        with self.assertRaisesRegex(ValueError, "different answer"):
            te.Resolver("claim-run", VERIFY, ATTEMPT).resolve(forged["citation_id"])

    def test_a_changed_index_summary_refuses_the_rerun(self):
        answer = self.ask(*COMPLETE)
        summary = self.jobs / self.inputs.ref.split(":", 1)[1]
        summary.write_text(summary.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "missing or changed"):
            te.Resolver("claim-run", VERIFY, ATTEMPT).resolve(answer["citation_id"])

    def test_unknown_foreign_and_edited_citations_are_refused(self):
        answer = self.ask(*COMPLETE)
        with self.assertRaisesRegex(ValueError, "not a citation_id"):
            te.Resolver("claim-run", VERIFY, "another-attempt").resolve(answer["citation_id"])
        with self.assertRaisesRegex(ValueError, "not a citation_id"):
            te.Resolver("claim-run", VERIFY, ATTEMPT).resolve("tev:" + "0" * 32)
        citation = te.Resolver("claim-run", VERIFY, ATTEMPT).resolve(answer["citation_id"])
        with self.assertRaisesRegex(ValueError, "differs from its record"):
            te.verify_citation("claim-run", {**citation, "observed_fact": "main reaches strcpy"})
        with self.assertRaisesRegex(ValueError, "differs from its record"):
            te.verify_decisions("claim-run", {"decisions": [{"citations": [{**citation, "locator_json": "{}"}]}]})


def _synthetic(tool, complete, job, attempt):
    answer = {"tool": tool, "query": {"function": "copy_field"}, "complete": complete,
              "reasons": [] if complete else ["1 escape row(s)"], "rows": [{"kind": "edge", "cite": "app/parse.c:8"}],
              "source": {}, "truncated": False, "total": 1, "gaps": []}
    record = te.build(tool, answer, index={"kind": "code-index"}, job_id=job, attempt_id=attempt)
    return te.citation(record, "sha256:" + "9" * 64)


class IndependenceRuleTests(unittest.TestCase):
    """core.verify: VERIFIED only on complete records the verifier itself produced, new relative to red/blue."""

    def setUp(self):
        self.blue = dt.upstream(VERIFY)
        self.verifier = json.loads(json.dumps(dt.fixture("verification-decisions.json")["decisions"][0]["verifier"]))

    def decide(self, disposition, citations, status="SATISFIED", blue=None):
        rows = []
        for record in (blue or self.blue)["reviews"]:
            mine = record["claim_id"] == A
            cited = citations if mine else record["citations"][:1]
            rows.append({"claim_id": record["claim_id"],
                         "verifier": {**self.verifier, "source_generation": record["source_generation"],
                                      "component_generation": record["component_generation"]},
                         "disposition": disposition if mine else "UNRESOLVED", "method": "re-ran code_path",
                         "proof_obligations": [{**item, "status": status if mine else "UNRESOLVED",
                                                "citations": cited} for item in record["proof_obligations"]],
                         "citations": cited, "dissent_ids": []})
        return core.verify(blue or self.blue, dt.binding(BLUE, "blue-team-refutation.json"), {"decisions": rows})

    def own(self, complete=True):
        return _synthetic("code_path", complete, VERIFY, self.verifier["attempt_id"])

    def test_verified_on_a_complete_own_new_record_is_accepted(self):
        result = self.decide("VERIFIED", [self.own()])
        row = next(item for item in result["verifications"] if item["claim_id"] == A)
        self.assertEqual(row["status"], "VERIFIED")
        self.assertTrue(row["verification_citations"][0]["citation_id"].startswith("tev:"))

    def test_verified_on_an_incomplete_record_is_refused_and_unresolved_is_allowed(self):
        with self.assertRaisesRegex(Blocked, "incomplete structural evidence"):
            self.decide("VERIFIED", [self.own(complete=False)])
        with self.assertRaisesRegex(Blocked, "incomplete structural evidence"):
            self.decide("REFUTED", [self.own(complete=False)], status="FAILED")
        result = self.decide("UNRESOLVED", [self.own(complete=False)], status="UNRESOLVED")
        self.assertEqual(next(r for r in result["verifications"] if r["claim_id"] == A)["status"], "UNRESOLVED")

    def test_verified_on_a_blue_record_is_refused(self):
        blue_record = _synthetic("code_path", True, BLUE, "blue-1")
        blue = copy.deepcopy(self.blue)
        review = next(item for item in blue["reviews"] if item["claim_id"] == A)
        review["refutation_citations"] = review["refutation_citations"] + [blue_record]
        with self.assertRaisesRegex(Blocked, "new independent evidence"):
            self.decide("VERIFIED", [blue_record], blue=blue)
        with self.assertRaisesRegex(Blocked, "identity does not match the verifier"):
            self.decide("VERIFIED", [blue_record, self.own()], blue=blue)

    def test_verified_on_a_record_that_is_not_new_is_refused(self):
        own = self.own()
        blue = copy.deepcopy(self.blue)
        next(item for item in blue["reviews"] if item["claim_id"] == A)["refutation_citations"].append(own)
        with self.assertRaisesRegex(Blocked, "new independent evidence"):
            self.decide("VERIFIED", [own], blue=blue)

    def test_blue_may_cite_its_own_records_but_not_anothers(self):
        red = dt.upstream(BLUE)
        decisions = dt.fixture("blue-decisions.json")
        row = next(item for item in decisions["decisions"] if item["claim_id"] == A)
        attempt = row["reviewer"]["attempt_id"]
        own = _synthetic("code_callers", True, BLUE, attempt)
        row["citations"] = row["citations"] + [own]
        core.blue_team(red, dt.binding(RED, "red-team-adversarial.json"), decisions)
        row["citations"][-1] = _synthetic("code_callers", True, BLUE, "someone-else")
        with self.assertRaisesRegex(Blocked, "does not resolve"):
            core.blue_team(red, dt.binding(RED, "red-team-adversarial.json"), decisions)


class PresentationTests(unittest.TestCase):
    """The 10-synthesis-report presentation shows a structural citation by its observed_fact."""

    def test_structural_citation_location_is_its_summary(self):
        import synthesis_report_presentation as presentation
        citation = _synthetic("code_path", True, VERIFY, "verify-1")
        rows, ids = presentation._evidence({"citations": [citation]})
        self.assertEqual(rows[0]["kind"], "structural query record (re-run verified)")
        (finding,) = presentation._findings({"verified_findings": [{
            "claim_id": A, "title": "Unbounded copy", "component_ids": ["component-1"], "score": 16,
            "priority": "P0", "severity": "CRITICAL", "verification_citations": [citation]}]}, ids)
        self.assertEqual(finding["location"], "structural query: " + citation["observed_fact"])
        self.assertEqual(finding["summary"], citation["observed_fact"])
        self.assertTrue(citation["observed_fact"].endswith("[complete]"))


class DeriveResolutionTests(Case):
    """claim_review_derive resolves tev: ids against the invocation's own records; unknown ones go back."""

    def reply(self, disposition, ids, status):
        return {"decisions": [
            {"claim_id": A, "disposition": disposition, "method": "re-ran code_path copy_field -> strcpy",
             "citation_ids": ids, "proof_obligations": [{"obligation_id": "po-a", "status": status,
                                                         "citation_ids": ids}]},
            {"claim_id": B, "disposition": "UNRESOLVED", "method": "static review", "citation_ids": ["citation-b"],
             "proof_obligations": [{"obligation_id": "po-b", "status": "UNRESOLVED", "citation_ids": ["citation-b"]}]}]}

    def test_verified_with_a_complete_own_record_derives_its_canonical_citation(self):
        cid = self.ask(*COMPLETE)["citation_id"]
        document, notes = dt.run(VERIFY, self.reply("VERIFIED", [cid], "SATISFIED"))
        decision = dt.decisions_of(document)[A]
        self.assertEqual(decision["disposition"], "VERIFIED")
        self.assertEqual([item["citation_id"] for item in decision["citations"]], [cid])
        self.assertEqual(decision["citations"][0], te.Resolver("claim-run", VERIFY, ATTEMPT).resolve(cid))
        self.assertEqual(decision["proof_obligations"][0]["citations"], decision["citations"])
        self.assertEqual(notes, [])
        merged = {"decisions": [dt.decisions_of(document)[key] for key in (A, B)]}
        self.assertEqual(te.verify_decisions("claim-run", merged), 1)

    def test_incomplete_record_cannot_verify_but_supports_unresolved(self):
        cid = self.ask(*INCOMPLETE)["citation_id"]
        with self.assertRaises(InvokerOutputError) as caught:
            dt.run(VERIFY, self.reply("VERIFIED", [cid], "SATISFIED"))
        self.assertIn("incomplete structural evidence", " ".join(caught.exception.details))
        document, _ = dt.run(VERIFY, self.reply("UNRESOLVED", [cid, "citation-a"], "UNRESOLVED"))
        self.assertEqual([item["citation_id"] for item in dt.decisions_of(document)[A]["citations"]],
                         ["citation-a", cid])

    def test_unknown_tool_evidence_id_goes_back_for_repair(self):
        with self.assertRaises(InvokerOutputError) as caught:
            dt.run(VERIFY, self.reply("UNRESOLVED", ["citation-a", "tev:" + "a" * 32], "UNRESOLVED"))
        details = " ".join(caught.exception.details)
        self.assertIn(f"claim {A}: decision cites 'tev:{'a' * 32}'", details)
        self.assertIn("not a citation_id any code_* answer of this invocation returned", details)

    def test_pool_validation_refuses_a_record_edited_after_derive(self):
        cid = self.ask(*COMPLETE)["citation_id"]
        document, _ = dt.run(VERIFY, self.reply("VERIFIED", [cid], "SATISFIED"))
        path = self.record_path(cid)
        record = json.loads(path.read_text())
        record["recorded_at"] = "edited"   # not hashed, but the file sha256 the citation binds changes
        path.write_text(json.dumps(record))
        merged = {"decisions": [dt.decisions_of(document)[key] for key in (A, B)]}
        with self.assertRaisesRegex(ValueError, "differs from its record"):
            te.verify_decisions("claim-run", merged)

    def test_runtime_instructions_offer_verified_only_under_the_rule(self):
        self.assertIn("VERIFIED", derive.STAGE_DISPOSITIONS[VERIFY])
        package = mock.Mock(request={"job_id": VERIFY, "attempt_id": ATTEMPT})
        text = reviewer_pool._runtime_instructions(package)
        self.assertIn("complete=true, no escapes", text)
        self.assertIn("never proves exploitability", text)


class LspEvidenceTests(lx.Case):
    """Precomputed 02-lsp-xref answers are citable and re-run without a server; broker answers are not."""
    publish = lx.Tools.publish

    def test_precomputed_answer_is_recorded_and_reruns_without_a_server(self):
        jobs, ref, document = self.publish()
        (jobs / ref).write_text(json.dumps(document))
        index = lx.code_query_mcp.LspIndex("run-1", jobs, ref, document, broker=self.broker())

        class Inputs:
            import hashlib
            entries = [{"ref": "supporting-evidence:" + ref}]
            by_ref = {"supporting-evidence:" + ref: {"sha256": "sha256:" + hashlib.sha256((jobs / ref).read_bytes()).hexdigest()}}
        root = lambda _run, *parts: jobs.parent.joinpath(*parts)   # noqa: E731
        with mock.patch.object(te, "data_path", side_effect=root), mock.patch.dict(te._INDEXES, {}, clear=True):
            context = {"job_id": BLUE, "attempt_id": "blue-1"}
            answer = lx.code_query_mcp.call(None, "code_definition", {"function": "main"}, lsp=index)
            cited = te.attach("run-1", Inputs(), None, context, "code_definition", answer)
            starts = self.launcher.starts
            citation = te.Resolver("run-1", BLUE, "blue-1").resolve(cited["citation_id"])
            self.assertEqual(self.launcher.starts, starts)   # the re-run never started a server
            self.assertEqual(citation["observed_fact"], "code_definition(main) -> main.py:5 [complete]")
            live = te.attach("run-1", Inputs(), None, context, "code_definition",
                             {**answer, "source": {**answer["source"], "answered_from": "broker"}})
            self.assertIn("precomputed", live["citation_gap"])


if __name__ == "__main__":
    unittest.main()
