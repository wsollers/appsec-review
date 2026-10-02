"""ADR-0034 V2: verification evidence, the VERIFIED rule and the certainty ladder."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import verification_evidence as ve
from claude_cli_invoker import InvokerOutputError
from schema_validate import validate_document
from test_claim_review_derive import A, B, VERIFY, decisions_of, run as derive_run, upstream

FIXTURE = json.loads((ROOT / "tests/fixtures/claim-lifecycle/verification-evidence.json").read_text())
REACH, UNKNOWN_ITEM = "ve-" + "a" * 24, "ve-" + "b" * 24


def stub_context(graph_state=None):
    """A finding_enrichment-like context: no CPG unless a state is given."""
    graph = None
    if graph_state:
        graph = SimpleNamespace(identity="graph-1")
    return SimpleNamespace(graph=graph, entry_points=[], extra=None, sca={}, gaps=[], bindings={"cpg": None})


class BuildTests(unittest.TestCase):
    def test_without_a_graph_every_code_claim_is_unknown_with_its_reason(self):
        record = {"claim_id": A, "citations": [{"locator_json": json.dumps({"path": "src/a.c", "start_line": 3})}]}
        document = ve.build("run", [record], "event-1", "sha256:" + "0" * 64, context=stub_context())
        self.assertEqual(validate_document(document, ve.SCHEMA), [])
        item = document["claims"][0]["items"][0]
        self.assertEqual((item["kind"], item["state"]), ("call_graph_reachability", "UNKNOWN"))
        self.assertIn("no accepted code property graph", item["reason"])
        self.assertEqual(ve.to_bytes(document), ve.to_bytes(json.loads(ve.to_bytes(document))))

    def test_a_dependency_claim_reads_06_and_says_so_when_absent(self):
        record = {"claim_id": B, "citations": [{"locator_json": json.dumps({"component_ref": "pkg:x", "lead_ref": "m1"})}]}
        document = ve.build("run", [record], "event-1", "sha256:" + "0" * 64, context=stub_context())
        item = document["claims"][0]["items"][0]
        self.assertEqual((item["kind"], item["state"]), ("dependency_reachability", "UNKNOWN"))
        self.assertIn("06-cve-reachability", item["reason"])


class RuleTests(unittest.TestCase):
    def decision(self, disposition, item_id, statuses=("SATISFIED",)):
        return {"claim_id": A, "disposition": disposition,
                "proof_obligations": [{"status": status} for status in statuses],
                "citations": [{"artifact_path": ve.FILE, "locator_json": json.dumps({"item_id": item_id})}]}

    def test_verified_needs_a_cited_reachable_item(self):
        self.assertEqual(ve.verified_errors(self.decision("VERIFIED", REACH), FIXTURE), [])
        missing = dict(self.decision("VERIFIED", REACH), claim_id=B)
        self.assertTrue(ve.verified_errors(missing, FIXTURE))
        self.assertTrue(ve.verified_errors(self.decision("VERIFIED", REACH), None))
        self.assertEqual(ve.verified_errors(self.decision("UNRESOLVED", REACH), None), [])

    def test_certainty_ladder(self):
        ladder = ve.certainty(self.decision("VERIFIED", REACH), FIXTURE)
        self.assertEqual([row["rung"] for row in ladder["rungs"]], list(ve.RUNGS))
        self.assertEqual(ladder["highest"], "inference_validated")
        states = {row["rung"]: row["state"] for row in ladder["rungs"]}
        self.assertEqual((states["reachable"], states["poc"]), ("established", "not_assessed"))
        open_ = ve.certainty(dict(self.decision("UNRESOLVED", UNKNOWN_ITEM, ("UNRESOLVED",)), claim_id=B), FIXTURE)
        self.assertEqual(open_["highest"], "finding")
        self.assertEqual({row["rung"]: row["state"] for row in open_["rungs"]}["reachable"], "uncertain")
        schema = {"$ref": "verification-evidence.schema.json#/$defs/certainty"}
        from schema_validate import SchemaStore, validate
        self.assertEqual(validate(ladder, schema, SchemaStore()), [])


class DeriveTests(unittest.TestCase):
    def reply(self, a_disposition, a_items, a_status="SATISFIED"):
        rows = []
        for record in upstream(VERIFY)["reviews"]:
            claim = record["claim_id"]
            own = [record["citations"][0]["citation_id"]]
            if claim == A:
                rows.append({"claim_id": A, "disposition": a_disposition, "method": "call graph and inference",
                             "citation_ids": own, "evidence_ids": a_items,
                             "proof_obligations": [{"obligation_id": item["obligation_id"], "status": a_status,
                                                    "citation_ids": ["verification-" + a_items[0]] if a_items else own}
                                                   for item in record["proof_obligations"]]})
            else:
                rows.append({"claim_id": claim, "disposition": "UNRESOLVED", "method": "no reachability",
                             "citation_ids": own, "proof_obligations": [
                                 {"obligation_id": item["obligation_id"], "status": "UNRESOLVED", "citation_ids": own}
                                 for item in record["proof_obligations"]]})
        return {"decisions": rows}

    def run09(self, reply):
        from test_claim_review_derive import REQUEST, REQUEST_SHA, EVIDENCE_SHA
        import claim_review_derive as derive
        return derive.derive(VERIFY, upstream(VERIFY), reply, request=dict(REQUEST, job_id=VERIFY),
                             request_sha256=REQUEST_SHA, evidence_sha256=EVIDENCE_SHA,
                             verification=(FIXTURE, ve.sha256(FIXTURE)))

    def test_a_cited_reachable_item_becomes_a_verifier_citation_and_verifies(self):
        document, _notes = self.run09(self.reply("VERIFIED", [REACH]))
        decision = decisions_of(document)[A]
        minted = [item for item in decision["citations"] if item["artifact_path"] == ve.FILE]
        self.assertEqual(len(minted), 1)
        self.assertEqual(minted[0]["producer_job_id"], VERIFY)
        self.assertEqual(minted[0]["artifact_sha256"], ve.sha256(FIXTURE))
        self.assertEqual(decision["disposition"], "VERIFIED")

    def test_verified_without_reachable_evidence_goes_back_for_repair(self):
        with self.assertRaises(InvokerOutputError) as caught:
            self.run09(self.reply("VERIFIED", []))
        self.assertTrue(any("new independent evidence" in detail or "REACHABLE" in detail
                            for detail in caught.exception.details))
        with self.assertRaises(InvokerOutputError) as caught:
            self.run09(self.reply("VERIFIED", ["ve-" + "c" * 24]))
        self.assertIn("not a verification-evidence item", " ".join(caught.exception.details))


class TaskExampleTests(unittest.TestCase):
    def test_the_task_prompt_09_example_derives_and_verifies(self):
        text = (ROOT / "claim-review-pool-task.md").read_text(encoding="utf-8")
        block = text.split("## Example", 1)[1].split("```json\n")[3].split("\n```", 1)[0]
        document, notes = DeriveTests.run09(None, json.loads(block))
        self.assertEqual(notes, [])
        decisions = decisions_of(document)
        self.assertEqual((decisions[A]["disposition"], decisions[B]["disposition"]), ("VERIFIED", "UNRESOLVED"))


class ReportTests(unittest.TestCase):
    def test_certainty_flows_through_l08_and_renders(self):
        import claim_lifecycle_core as core
        import synthesis_report
        from test_claim_review_derive import binding, fixture, BLUE
        verification = core.verify(upstream(VERIFY), binding(BLUE, "blue-team-refutation.json"),
                                   fixture("verification-decisions.json"), verification_evidence=FIXTURE)
        scoring = core.score(verification, binding(VERIFY, "independent-verification.json"),
                             fixture("scoring-decisions.json"))
        records = {row["claim_id"]: row for row in synthesis_report.l08_adapter("claim-run", verification, scoring)["records"]}
        self.assertEqual(records[A]["certainty"]["highest"], "inference_validated")
        report = {"verified_findings": [{"claim_id": A, "severity": "HIGH", "priority": "P1", "component_ids": ["parser"],
                                         "certainty": records[A]["certainty"]}],
                  "unresolved_candidates": [{"claim_id": B, "status": "unresolved", "hypothesis": "h",
                                             "certainty": records[B]["certainty"]}],
                  "decision": {"recommendation": "HUMAN_DECISION_REQUIRED", "basis": "draft"},
                  "owasp_coverage": {"denominators": {"selected": 0, "applicable": 0, "assessed": 0, "satisfied": 0}},
                  "threat_model": {}, "limitations": [], "dissent_ids": []}
        draft, appendix = synthesis_report.render_markdown(report)
        self.assertIn("| inference_validated | 1 |", draft)
        self.assertIn(f"| `{B}` | finding | established | uncertain |", appendix)
        self.assertIn("no accepted code property graph", appendix)


if __name__ == "__main__":
    unittest.main()
