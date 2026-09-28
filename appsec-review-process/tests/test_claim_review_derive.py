"""Derive step for the stage claim-review pool (model-bookkeeping audit item 1).

The replies below are shaped like the live multi-vuln be3585 07 pool output (2026-09-28 16:20):
no or partial reviewer identity, citations as bare ids, plus the error cases a model produces
(an unknown id, a duplicate id, a missing claim, a typed citation object with a miscopied hash).
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import claim_lifecycle_core as core
import claim_review_derive as derive
import claim_review_lifecycle as lifecycle
import claim_reviewer_pool as reviewer_pool
import claude_cli_invoker as cli
from claude_cli_invoker import InvokerOutputError
from schema_validate import validate_document

FIXTURES = ROOT / "tests/fixtures/claim-lifecycle"
RED, BLUE, VERIFY, SCORE = lifecycle.STAGES
REQUEST = {"run_id": "claim-run", "job_id": RED, "attempt_id": "bda6fe971aaa009f4c1d811383f58cb0"}
REQUEST_SHA = "sha256:" + "4" * 64
EVIDENCE_SHA = "sha256:" + "5" * 64
A, B = "claim-aaaaaaaaaaaaaaaaaaaaaaaa", "claim-bbbbbbbbbbbbbbbbbbbbbbbb"


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def binding(job="claim-ledger-routing", artifact="claim-decision-ledger.json"):
    return {"job_id": job, "attempt_id": job + "-1", "pointer_sha256": "sha256:" + "1" * 64,
            "artifact_path": artifact, "artifact_sha256": "sha256:" + "3" * 64}


def upstream(stage):
    ledger = fixture("claim-ledger.json")
    if stage == RED:
        return ledger
    red = core.red_team(ledger, binding(), fixture("red-decisions.json"))
    if stage == BLUE:
        return red
    blue = core.blue_team(red, binding(RED, "red-team-adversarial.json"), fixture("blue-decisions.json"))
    if stage == VERIFY:
        return blue
    return core.verify(blue, binding(BLUE, "blue-team-refutation.json"),
                       fixture("verification-decisions.json"))


def run(stage, reply):
    return derive.derive(stage, upstream(stage), reply, request=dict(REQUEST, job_id=stage),
                         request_sha256=REQUEST_SHA, evidence_sha256=EVIDENCE_SHA)


def decisions_of(document):
    return {c["subject_id"]: json.loads(c["assertion"]) for c in document["candidates"]}


class RedTeamDeriveTests(unittest.TestCase):
    def test_bare_ids_without_identity_become_full_strict_decisions(self):
        reply = {"decisions": [
            {"claim_id": B, "attacker_case": "Crafted header overflows the parser.",
             "citation_ids": ["citation-b", "citation-b"]},
            {"claim_id": A, "attacker_case": "Attacker bytes reach the parser.",
             "citation_ids": ["citation-a"], "dissent_ids": ["d-2", "d-1", "d-2"]}]}
        document, notes = run(RED, reply)
        self.assertEqual(notes, [])
        self.assertEqual(validate_document(document, "claim-review-pool-candidates.schema.json"), [])
        self.assertEqual([c["subject_id"] for c in document["candidates"]], [A, B])
        first = document["candidates"][0]
        self.assertEqual((first["candidate_id"], first["claim_class"], first["evidence_sha256"]),
                         ("decision-" + A, "candidate_only", EVIDENCE_SHA))
        decision = decisions_of(document)[A]
        self.assertEqual(first["assertion"], derive.canonical_assertion(decision))
        record = upstream(RED)["candidates"][0]
        self.assertEqual(decision["reviewer"], {
            "job_id": RED, "attempt_id": REQUEST["attempt_id"], "role_id": "red-team-adversary",
            "source_generation": record["source_generation"],
            "component_generation": record["component_generation"],
            "artifact_path": f"requests/{REQUEST['attempt_id']}.json", "artifact_sha256": REQUEST_SHA,
            "permission_receipt_path": f"requests/{REQUEST['attempt_id']}.json",
            "permission_receipt_sha256": REQUEST_SHA, "reason": derive.ACTOR_REASON})
        self.assertEqual(decision["citations"], record["citations"])
        self.assertEqual(decision["dissent_ids"], ["d-1", "d-2"])
        self.assertEqual(len(decisions_of(document)[B]["citations"]), 1)
        # the unchanged merge-side checks accept it
        for value in decisions_of(document).values():
            self.assertEqual(validate_document({"stage": RED, "decision": value},
                                               "claim-review-decision.schema.json"), [])
            self.assertEqual(set(value), lifecycle.DECISION_KEYS[RED])
        core.red_team(upstream(RED), binding(), {"decisions": list(decisions_of(document).values())})

    def test_legacy_full_reply_with_partial_identity_and_tampered_citation_is_canonicalized(self):
        # The live be3585 shape: assertion strings, 6 of 10 actor fields, and (here) one typed
        # citation object whose hash and fact were miscopied: only its id is trusted.
        record = upstream(RED)["candidates"][0]
        forged = dict(record["citations"][0], artifact_sha256="f" * 64, observed_fact="made up")
        legacy = []
        for claim_id, cites in ((A, [forged]), (B, ["citation-b"])):
            decision = {"claim_id": claim_id, "reviewer": {"job_id": RED, "attempt_id": "x",
                        "role_id": "red-team-adversary"}, "attacker_case": "case",
                        "citations": cites, "dissent_ids": []}
            legacy.append({"candidate_id": "decision-" + claim_id, "subject_id": claim_id,
                           "claim_class": "candidate_only", "evidence_sha256": "sha256:" + "0" * 64,
                           "assertion": json.dumps(decision)})
        document, _notes = run(RED, {"candidates": legacy})
        decision = decisions_of(document)[A]
        self.assertEqual(decision["citations"], [record["citations"][0]])
        self.assertEqual(decision["reviewer"]["attempt_id"], REQUEST["attempt_id"])
        self.assertTrue(all(c["evidence_sha256"] == EVIDENCE_SHA for c in document["candidates"]))

    def test_unknown_citation_id_is_dropped_and_reported_never_invented(self):
        reply = {"decisions": [
            {"claim_id": A, "attacker_case": "a", "citation_ids": ["citation-a", "citation-zzz"]},
            {"claim_id": B, "attacker_case": "b", "citation_ids": ["citation-b"]}]}
        document, notes = run(RED, reply)
        self.assertEqual([c["citation_id"] for c in decisions_of(document)[A]["citations"]], ["citation-a"])
        self.assertEqual(len(notes), 1)
        self.assertIn("citation-zzz", notes[0])
        # another claim's citation is not this claim's evidence either
        reply["decisions"][0]["citation_ids"] = ["citation-b"]
        with self.assertRaises(InvokerOutputError) as caught:
            run(RED, reply)
        self.assertTrue(any("at least one upstream citation" in d for d in caught.exception.details))

    def test_missing_unknown_and_conflicting_claims_are_rejected_for_repair(self):
        only_a = {"decisions": [{"claim_id": A, "attacker_case": "a", "citation_ids": ["citation-a"]}]}
        with self.assertRaises(InvokerOutputError) as caught:
            run(RED, only_a)
        self.assertTrue(any(B in d for d in caught.exception.details))
        extra = copy.deepcopy(only_a)
        extra["decisions"] += [{"claim_id": B, "attacker_case": "b", "citation_ids": ["citation-b"]},
                               {"claim_id": "claim-invented", "attacker_case": "c", "citation_ids": ["x"]}]
        with self.assertRaises(InvokerOutputError):
            run(RED, extra)
        dup = copy.deepcopy(only_a)
        dup["decisions"] += [{"claim_id": B, "attacker_case": "b", "citation_ids": ["citation-b"]},
                             {"claim_id": A, "attacker_case": "different", "citation_ids": ["citation-a"]}]
        with self.assertRaises(InvokerOutputError):
            run(RED, dup)
        same = copy.deepcopy(only_a)
        same["decisions"] += [{"claim_id": B, "attacker_case": "b", "citation_ids": ["citation-b"]},
                              copy.deepcopy(only_a["decisions"][0])]
        document, notes = run(RED, same)
        self.assertEqual(len(document["candidates"]), 2)
        self.assertTrue(any("duplicate" in n for n in notes))

    def test_stage_fields_are_closed(self):
        reply = {"decisions": [{"claim_id": A, "attacker_case": "a", "citation_ids": ["citation-a"],
                                "disposition": "REFUTED"},
                               {"claim_id": B, "attacker_case": "b", "citation_ids": ["citation-b"]}]}
        with self.assertRaises(InvokerOutputError):
            run(RED, reply)
        with self.assertRaises(InvokerOutputError):
            run(RED, "not an object")


class BlueVerifyScoreDeriveTests(unittest.TestCase):
    def blue_reply(self, status_a="SATISFIED", disposition_a="SURVIVING"):
        return {"decisions": [
            {"claim_id": A, "disposition": disposition_a, "rationale": "flow reaches the parser",
             "citation_ids": [], "proof_obligations": [
                 {"obligation_id": "po-a", "status": status_a, "citation_ids": ["citation-a"]}]},
            {"claim_id": B, "disposition": "UNRESOLVED", "rationale": "no bound evidence",
             "citation_ids": ["citation-b"], "proof_obligations": [
                 {"obligation_id": "po-b", "status": "UNRESOLVED"}]}]}

    def test_obligations_by_id_get_upstream_statements_and_canonical_citations(self):
        document, notes = run(BLUE, self.blue_reply())
        self.assertEqual(notes, [])
        decision = decisions_of(document)[A]
        record = upstream(BLUE)["hypotheses"][0]
        self.assertEqual(decision["reviewer"]["role_id"], "blue-team-refuter")
        self.assertEqual(decision["proof_obligations"][0]["statement"],
                         record["proof_obligations"][0]["statement"])
        # an obligation's citation is carried into the decision evidence it must sit inside
        self.assertEqual([c["citation_id"] for c in decision["citations"]], ["citation-a"])
        self.assertEqual(decisions_of(document)[B]["proof_obligations"][0]["citations"], [])
        self.assertEqual(document["candidates"][0]["claim_class"], "refutation")
        core.blue_team(upstream(BLUE), binding(RED, "red-team-adversarial.json"),
                       {"decisions": list(decisions_of(document).values())})

    def test_unknown_or_missing_obligation_and_inconsistent_disposition_are_rejected(self):
        reply = self.blue_reply()
        reply["decisions"][0]["proof_obligations"][0]["obligation_id"] = "po-zzz"
        with self.assertRaises(InvokerOutputError) as caught:
            run(BLUE, reply)
        self.assertTrue(any("po-zzz" in d for d in caught.exception.details))
        reply = self.blue_reply()
        reply["decisions"][0]["proof_obligations"] = []
        with self.assertRaises(InvokerOutputError):
            run(BLUE, reply)
        with self.assertRaises(InvokerOutputError) as caught:
            run(BLUE, self.blue_reply(status_a="FAILED", disposition_a="SURVIVING"))
        self.assertIn("surviving requires", str(caught.exception))

    def test_verification_derives_verifier_and_rejects_unsupported_verified(self):
        reply = {"decisions": [
            {"claim_id": claim, "disposition": "UNRESOLVED", "method": "static review of cited flow",
             "citation_ids": [cite], "proof_obligations": [{"obligation_id": ob, "status": "UNRESOLVED",
                                                            "citation_ids": [cite]}]}
            for claim, cite, ob in ((A, "citation-a", "po-a"), (B, "citation-b", "po-b"))]}
        document, _ = run(VERIFY, reply)
        decision = decisions_of(document)[A]
        self.assertEqual(set(decision), lifecycle.DECISION_KEYS[VERIFY])
        self.assertEqual(decision["verifier"]["role_id"], "independent-verifier")
        # An id list cannot carry the new independent evidence VERIFIED needs: rejected, not faked.
        reply["decisions"][0]["disposition"] = "VERIFIED"
        reply["decisions"][0]["proof_obligations"][0]["status"] = "SATISFIED"
        with self.assertRaises(InvokerOutputError) as caught:
            run(VERIFY, reply)
        self.assertIn("new independent evidence", str(caught.exception))

    def test_scoring_passes_judgment_through_and_wraps_it(self):
        records = upstream(SCORE)["verifications"]
        reply = {"decisions": [{"claim_id": r["claim_id"], "rationale": "not verified",
                                "factors": None} for r in records if r["status"] != "VERIFIED"] +
                 [{"claim_id": r["claim_id"], "rationale": "verified",
                   "factors": {"impact": 3, "exploitability": 2, "exposure": 2, "confidence": 3}}
                  for r in records if r["status"] == "VERIFIED"]}
        document, _ = run(SCORE, reply)
        for value in decisions_of(document).values():
            self.assertEqual(set(value), lifecycle.DECISION_KEYS[SCORE])


class InvokerIntegrationTests(unittest.TestCase):
    """ClaimReviewerInvoker end to end over the real ClaudeCliInvoker with a fake model."""

    def package(self):
        contract = json.loads((ROOT / "registry/output-contracts/claim-review-pool-candidates.json").read_text())
        data = json.dumps(upstream(RED)).encode()
        item = SimpleNamespace(root=reviewer_pool.ROOT_ID, path="claim-decision-ledger.json", data=data,
                               sha256=EVIDENCE_SHA)
        return SimpleNamespace(composition={"output_contract": contract}, prompt=b"OUTER",
            inputs=(item,), request={"model": {"family": "claude-sonnet-5"}, "run_id": "r",
                                     "job_id": RED, "attempt_id": REQUEST["attempt_id"],
                                     "budget": {"input_unit_limit": 10 ** 9}},
            request_sha256=REQUEST_SHA, allowed_claim_classes=("candidate_only",))

    def test_persona_schema_is_rendered_and_final_document_is_derived(self):
        replies = [json.dumps({"candidates": {"decisions": [
            {"claim_id": A, "attacker_case": "a", "citation_ids": ["citation-a", "citation-q"]},
            {"claim_id": B, "attacker_case": "b", "citation_ids": ["citation-b"]}]}})]
        prompts, written = [], {}

        def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
            prompts.append(prompt)
            return {"timed_out": False, "final_result": {"result": replies.pop(0)}}

        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(cli.cbr, "resolve_claude_binary", return_value="/usr/bin/claude"), \
                mock.patch.object(cli.rc, "load_model_config", return_value={"invocation": {"repair_attempts": 0}}), \
                mock.patch.object(cli.pi, "write_invoker_output",
                                  side_effect=lambda package, root, **kw: written.update(kw)):
            reviewer_pool.ClaimReviewerInvoker(effort="high", dispatch_fn=dispatch_fn).invoke(
                self.package(), output_root=Path(out), cancel=threading.Event())
            published = json.loads((Path(out) / "candidates.json").read_text())
        self.assertIn("claim-review-pool-persona.schema.json", prompts[0])
        self.assertNotIn("`claim-review-pool-candidates.schema.json` (required", prompts[0])
        self.assertNotIn("actor_identity", prompts[0])
        self.assertEqual(validate_document(published, "claim-review-pool-candidates.schema.json"), [])
        self.assertEqual(decisions_of(published)[A]["reviewer"]["artifact_path"],
                         f"requests/{REQUEST['attempt_id']}.json")
        self.assertTrue(any("citation-q" in text for text in written["limitations"]))
        self.assertEqual([c["citations"][0]["locator"] for c in written["claims"]], [A, B])

    def test_default_invoker_behaviour_is_unchanged(self):
        with self.assertRaises(ValueError):
            cli.ClaudeCliInvoker(effort="high", persona_schema=derive.PERSONA_SCHEMA)
        package = self.package()
        store = cli.SchemaStore()
        contract = package.composition["output_contract"]
        self.assertIn("`claim-review-pool-candidates.schema.json` (required",
                      cli.build_prompt_text(package, contract, store))


if __name__ == "__main__":
    unittest.main()
