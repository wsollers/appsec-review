"""Lane 14 refutation and merge rules (ADR-0016 decisions 4, 6, 7, 9): fake refuter replies only."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import attack_chain_derive as compose
import attack_chain_refute as refute
from claude_cli_invoker import InvokerOutputError
from execution_state import Blocked
from schema_validate import validate_document
from tests.test_attack_chain_derive import CLAIM, COMPOSER, METHOD, run, two_link_chain, workspace

REFUTER = {"job_id": "14-attack-chain-refutation", "attempt_id": "cell-r", "persona_id": "attack-chain-refuter",
           "request_sha256": "sha256:" + "8" * 64}
MENU = {"supporting-evidence:02-code-property-graph/attempts/c1/code-property-graph.records.jsonl": "sha256:" + "8" * 64}


def composed() -> tuple[dict, list[dict]]:
    ws = workspace()
    document, _ = run({"chains": [two_link_chain()]}, ws)
    return ws, document["chains"]


def batch_for(ws, chains, **bounds):
    facts = {fact["fact_id"]: fact for fact in ws["facts"]}
    claims = {claim["claim_id"]: claim for claim in ws["claims"]}
    limits = {"chains_refuted_max": 48, "chain_refutation_batch": 6, **bounds}
    return refute.batches("r1", chains, facts=facts, claims=claims, bounds=limits)


class RefuteDeriveTests(unittest.TestCase):
    def setUp(self):
        self.ws, self.chains = composed()
        batches, gaps = batch_for(self.ws, self.chains)
        self.assertEqual(gaps, [])
        self.batch = batches[0]
        self.chain_id = self.chains[0]["chain_id"]

    def outcome(self, reply, menu=MENU):
        return refute.derive(self.batch, reply, refuter=REFUTER, menu=menu)

    def test_holds_makes_the_case_001_chain_supported(self):
        document, _ = self.outcome({"chains": [{"chain_id": self.chain_id, "disposition": "holds"}]})
        published, dropped = refute.apply(self.chains, {row["chain_id"]: row for row in document["outcomes"]}, {})
        self.assertEqual(dropped, [])
        self.assertEqual(published[0]["state"], "supported")
        self.assertEqual(published[0]["refutation"]["refuter"], REFUTER)
        self.assertEqual(validate_document(published[0], compose.RECORD_SCHEMA), [])

    def test_broken_with_a_chain_citation_refutes_and_drops_with_the_reason(self):
        reply = {"chains": [{"chain_id": self.chain_id, "disposition": "Broken", "target": {"kind": "edge", "index": 0},
                             "reason": "argv is length-checked before the copy", "citation_ids": [METHOD, "nope"]}]}
        document, notes = self.outcome(reply)
        row = document["outcomes"][0]
        self.assertEqual((row["disposition"], row["target"]), ("broken", {"kind": "edge", "index": 0}))
        self.assertEqual(row["citations"][0]["fact_id"], METHOD)
        self.assertTrue(any("nope" in note for note in notes))
        published, dropped = refute.apply(self.chains, {self.chain_id: row}, {})
        self.assertEqual(published, [])
        self.assertIn("refuter broke edge 0", dropped[0]["reason"])
        self.assertIn("length-checked", dropped[0]["reason"])

    def test_narrowed_with_a_menu_citation_caps_at_plausible(self):
        ref = next(iter(MENU)) + "#cpg_a01"
        reply = {"chains": [{"chain_id": self.chain_id, "disposition": "narrowed", "target": {"kind": "link", "index": 1},
                             "mechanism": "only when built without the fortify flag", "citation_ids": [ref]}]}
        document, _ = self.outcome(reply)
        self.assertEqual(document["outcomes"][0]["citations"][0]["kind"], "menu-file")
        published, _ = refute.apply(self.chains, {self.chain_id: document["outcomes"][0]}, {})
        self.assertEqual(published[0]["state"], "plausible")
        self.assertEqual(published[0]["weakest"]["reason"], "refuter narrowed link 1")

    def test_cannot_assess_and_not_run_stay_plausible(self):
        document, notes = self.outcome({"chains": [{"chain_id": self.chain_id, "disposition": "cannot_assess",
                                                     "target": {"kind": "link", "index": 0}}]})
        self.assertIsNone(document["outcomes"][0]["target"])
        self.assertTrue(any("target ignored" in note for note in notes))
        published, _ = refute.apply(self.chains, {self.chain_id: document["outcomes"][0]}, {})
        self.assertEqual(published[0]["state"], "plausible")
        published, _ = refute.apply(self.chains, {}, {self.chain_id: "refuter cell failed; state capped"})
        self.assertEqual(published[0]["refutation"]["disposition"], "not_run")
        self.assertEqual(published[0]["state"], "plausible")
        self.assertIn("refuter cell failed", published[0]["weakest"]["reason"])

    def assertRepair(self, reply, fragment):
        with self.assertRaises(InvokerOutputError) as caught:
            self.outcome(reply)
        self.assertTrue(any(fragment in detail for detail in caught.exception.details), caught.exception.details)

    def test_repair_cases(self):
        self.assertRepair({"chains": [{"chain_id": self.chain_id, "disposition": "broken",
                                       "target": {"kind": "link", "index": 0}, "mechanism": "sink looks safe"}]},
                          "at least one resolvable citation")
        self.assertRepair({"chains": [{"chain_id": self.chain_id, "disposition": "broken", "mechanism": "x",
                                       "citation_ids": [METHOD]}]}, "names the link or edge")
        self.assertRepair({"chains": [{"chain_id": self.chain_id, "disposition": "broken", "mechanism": "x",
                                       "target": {"kind": "edge", "index": 3}, "citation_ids": [METHOD]}]},
                          "does not exist")
        self.assertRepair({"chains": [{"chain_id": "chain-" + "0" * 24, "disposition": "holds"}]},
                          "is not a chain of this batch")
        self.assertRepair({"chains": []}, "every chain of the batch needs one")
        self.assertRepair({"chains": [{"chain_id": self.chain_id, "disposition": "broken", "mechanism": "",
                                       "target": {"kind": "edge", "index": 0}, "citation_ids": [METHOD]}]},
                          "needs the mechanism")
        self.assertRepair({"chains": [{"chain_id": self.chain_id, "disposition": "broken",
                                       "mechanism": "send ```python``` first", "target": {"kind": "edge", "index": 0},
                                       "citation_ids": [METHOD]}]}, "do not include code")
        self.assertRepair({"chains": [{"chain_id": self.chain_id, "disposition": "refuted"}]}, "not in enum")

    def test_menu_citation_must_be_pinned(self):
        self.assertRepair({"chains": [{"chain_id": self.chain_id, "disposition": "broken", "mechanism": "x",
                                       "target": {"kind": "edge", "index": 0},
                                       "citation_ids": ["supporting-evidence:other/file.json"]}]},
                          "at least one resolvable citation")

    def test_candidates_validate(self):
        document, _ = self.outcome({"chains": [{"chain_id": self.chain_id, "disposition": "holds"}]})
        self.assertEqual(validate_document(refute.candidates(document, "sha256:" + "b" * 64),
                                           compose.CANDIDATES_SCHEMA), [])


class BatchRankLedgerTests(unittest.TestCase):
    def test_refutation_cap_and_batch_size(self):
        ws, chains = composed()
        extra = []
        for index in range(4):
            chain = copy.deepcopy(chains[0])
            chain["chain_id"] = f"chain-{index:024x}"
            chain["impact_kind"] = "denial_of_service"
            extra.append(chain)
        batches, gaps = batch_for(ws, chains + extra, chains_refuted_max=3, chain_refutation_batch=2)
        self.assertEqual([len(batch["chains"]) for batch in batches], [2, 1])
        self.assertEqual(batches[0]["chains"][0]["chain_id"], chains[0]["chain_id"])   # code_execution first
        self.assertEqual([gap["reason"] for gap in gaps], ["refutation-cap", "refutation-cap"])
        self.assertEqual({fact["fact_id"] for fact in batches[0]["facts"]} >= set(chains[0]["fact_refs"]), True)

    def test_rank_orders_state_impact_severity_boundaries_length(self):
        _ws, chains = composed()
        base = {**chains[0], "state": "plausible"}
        rows = [{**base, "chain_id": "chain-" + "3" * 24, "state": "hypothesis"},
                {**base, "chain_id": "chain-" + "2" * 24, "impact_kind": "data_disclosure"},
                {**base, "chain_id": "chain-" + "1" * 24},
                {**base, "chain_id": "chain-" + "0" * 24, "state": "supported", "impact_kind": "exfiltration"}]
        order = [row["chain_id"][-1] for row in refute.rank(rows)]
        self.assertEqual(order, ["0", "1", "2", "3"])
        severities = {CLAIM: "CRITICAL"}
        other = {**base, "chain_id": "chain-" + "4" * 24,
                 "links": [dict(link, claim_id="claim-other" if link["claim_id"] else None) for link in base["links"]]}
        self.assertEqual(refute.rank([other, base], severities=severities)[0]["chain_id"], base["chain_id"])

    def test_ledger_is_hash_linked_and_bound(self):
        ws, chains = composed()
        outcome = {"chain_id": chains[0]["chain_id"], "disposition": "holds", "target": None, "mechanism": None,
                   "refuter": REFUTER, "citations": []}
        published, dropped = refute.apply(chains, {chains[0]["chain_id"]: outcome}, {})
        document = refute.ledger("r1", claim_ledger_head_sha256="sha256:" + "7" * 64,
                                 verification_pointer_sha256="sha256:" + "6" * 64, link_candidates=[CLAIM],
                                 composed=chains, outcomes={chains[0]["chain_id"]: outcome}, published=published,
                                 dropped=dropped, gaps=[], coverage={"chains_composed": 1})
        self.assertEqual([entry["event_type"] for entry in document["entries"]],
                         ["chain_composed", "chain_refutation", "chain_state_derived"])
        self.assertEqual(document["chains"][0]["rank"], 1)
        self.assertEqual(document["chains"][0]["state"], "supported")
        refute.verify_ledger(document)
        tampered = copy.deepcopy(document)
        tampered["entries"][1]["payload"]["disposition"] = "broken"
        with self.assertRaises(Blocked):
            refute.verify_ledger(tampered)
        with self.assertRaises(Blocked):
            refute.ledger("r1", claim_ledger_head_sha256=None, verification_pointer_sha256="sha256:" + "6" * 64,
                          link_candidates=["claim-other"], composed=chains, outcomes={}, published=published,
                          dropped=dropped, gaps=[], coverage={})


if __name__ == "__main__":
    unittest.main()
