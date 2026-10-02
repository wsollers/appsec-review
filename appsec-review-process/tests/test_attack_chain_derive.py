"""Lane 14 composer derive (ADR-0016 decisions 3, 4, 5.3): persona reply -> strict chain records.

The fake replies are shaped like composer output: bookkeeping echoed (ids, states, severity), a
clusters wrapper, string prerequisites. No live model call.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import attack_chain_derive as derive
import attack_chain_seeds as seeds
from claude_cli_invoker import InvokerOutputError
from schema_validate import validate_document
from tests.test_attack_chain_seeds import FIXTURE, claim, verification

CLAIM = "claim-000000000000000000case01"
ARGV = "02-code-property-graph#cpg_a02000000000000000000000"
STRCPY = "02-code-property-graph#cpg_a03000000000000000000000"
METHOD = "02-code-property-graph#cpg_a01000000000000000000000"
COMPOSER = {"job_id": "14-attack-chain-composition", "attempt_id": "cell-1",
            "persona_id": "attack-chain-composer", "request_sha256": "sha256:" + "9" * 64}


def workspace(doc=None, **overrides) -> dict:
    document = seeds.build("r1", doc or FIXTURE["verification"], cpg_records=FIXTURE["cpg_records"],
                           ir_facts=FIXTURE["ir_facts"], threat_model=FIXTURE["threat_model"],
                           component_map=FIXTURE["component_map"], artifacts=FIXTURE["artifacts"], **overrides)
    return document["clusters"][0]


def case_001_chain(**changes) -> dict:
    chain = {"objective": "Run attacker-chosen code through the case-001 command line",
             "impact_kind": "code_execution",
             "narrative": f"argv[1] reaches the unbounded copy of {CLAIM} into a 16-byte stack buffer.",
             "links": [{"fact_ref": ARGV, "stage": "entry",
                        "prerequisites": ["the attacker controls the first program argument"]},
                       {"claim_id": CLAIM, "stage": "execution", "citation_ids": ["citation-case01a"],
                        "prerequisites": [{"text": "argument longer than 15 bytes", "requires_link_indexes": [0]}]},
                       {"fact_ref": STRCPY, "stage": "impact"}],
             "edges": [{"from": 0, "to": 1, "basis_claimed": "code_fact", "fact_ref": METHOD,
                        "rationale": "argv is read in main, which performs the copy"}],
             **changes}
    return chain


def two_link_chain(**changes) -> dict:
    chain = case_001_chain()
    chain["links"] = [chain["links"][0], {**chain["links"][1], "stage": "impact"}]
    chain.update(changes)
    return chain


def run(reply, ws=None):
    return derive.derive(ws or workspace(), reply, composer=COMPOSER)


class DeriveTests(unittest.TestCase):
    def test_case_001_argv_to_strcpy_is_one_plausible_code_fact_chain(self):
        document, notes = run({"chains": [two_link_chain()]})
        self.assertEqual(len(document["chains"]), 1)
        chain = document["chains"][0]
        self.assertEqual(validate_document(chain, derive.RECORD_SCHEMA), [])
        self.assertRegex(chain["chain_id"], r"^chain-[0-9a-f]{24}$")
        self.assertEqual([(l["stage"], l["link_state"]) for l in chain["links"]], [("entry", "verified"), ("impact", "verified")])
        self.assertEqual(chain["edges"][0]["basis"], "code_fact")
        self.assertIsNone(chain["edges"][0]["downgraded_from"])
        self.assertEqual(chain["causal_claim_ids"], [CLAIM])
        self.assertEqual(chain["fact_refs"], [ARGV])
        self.assertEqual(chain["state"], "plausible")          # refutation has not run
        self.assertEqual(chain["weakest"]["reason"], "refutation did not run")
        self.assertEqual(chain["links"][0]["citations"][0]["kind"], "fact")
        self.assertEqual(chain["links"][1]["citations"][0]["citation_id"], "citation-case01a")
        self.assertEqual(chain["links"][1]["citations"][0]["kind"], "claim-citation")
        self.assertEqual(chain["composer"], COMPOSER)
        self.assertEqual(chain["claim_limits"], {"finding_created": False, "severity_assigned": False})
        self.assertEqual(chain["links"][0]["prerequisites"][0]["requires_link_indexes"], [])

    def test_echoed_bookkeeping_and_clusters_wrapper_are_ignored(self):
        chain = two_link_chain(chain_id="chain-bogus", state="supported", severity="critical")
        chain["links"][0]["link_state"] = "verified"
        document, notes = run({"clusters": [{"cluster_id": "x", "chains": [chain]}]})
        self.assertEqual(document["chains"][0]["state"], "plausible")
        self.assertTrue(any("severity" in note for note in notes))
        self.assertEqual(document["chains"][0]["cluster_id"], workspace()["cluster_id"])

    def test_same_chain_twice_is_one_record_and_prerequisite_order_does_not_matter(self):
        first = two_link_chain()
        second = copy.deepcopy(first)
        second["links"][0]["prerequisites"] = ["a different wording"]
        document, notes = run({"chains": [first, second]})
        self.assertEqual(len(document["chains"]), 1)
        self.assertTrue(any("collapsed" in note for note in notes))

    def test_unresolvable_code_fact_ref_is_downgraded_to_synthetic_and_recorded(self):
        chain = two_link_chain()
        chain["edges"][0]["fact_ref"] = "02-code-property-graph#cpg_a01000000000000000000000"
        ws = workspace()
        ws["adjacency"] = [edge for edge in ws["adjacency"] if edge["basis"] != "code_fact"]
        document, notes = run({"chains": [chain]}, ws)
        edge = document["chains"][0]["edges"][0]
        self.assertEqual((edge["basis"], edge["downgraded_from"]), ("synthetic", "code_fact"))
        self.assertEqual(document["chains"][0]["state"], "hypothesis")
        self.assertEqual(document["chains"][0]["weakest"], {"kind": "edge", "index": 0,
                                                            "reason": "edge 0->1 is synthetic"})
        self.assertTrue(any("recorded as synthetic" in note for note in notes))

    def test_model_synthetic_edge_gives_hypothesis(self):
        chain = two_link_chain()
        chain["edges"][0].update(basis_claimed="synthetic", fact_ref=None)
        document, _ = run({"chains": [chain]})
        self.assertEqual(document["chains"][0]["edges"][0]["basis"], "synthetic")
        self.assertIsNone(document["chains"][0]["edges"][0]["downgraded_from"])
        self.assertEqual(document["chains"][0]["state"], "hypothesis")

    def test_open_link_gives_hypothesis_with_the_open_link_weakest(self):
        doc = verification(claim(CLAIM, status="UNRESOLVED"))
        chain = two_link_chain()
        chain["links"][1]["citation_ids"] = [f"citation-{CLAIM}"]
        document, _ = run({"chains": [chain]}, workspace(doc))
        chain = document["chains"][0]
        self.assertEqual(chain["state"], "hypothesis")
        self.assertEqual(chain["weakest"], {"kind": "link", "index": 1, "reason": "link 1 (impact) is open"})

    def test_no_chain_needs_a_reason(self):
        document, _ = run({"chains": [], "no_chain_reason": "argv never reaches the copy"})
        self.assertEqual((document["chains"], document["no_chain_reason"]), ([], "argv never reaches the copy"))
        with self.assertRaises(InvokerOutputError):
            run({"chains": []})

    def test_candidates_document_and_claim_builder(self):
        document, _ = run({"chains": [two_link_chain()]})
        value = derive.candidates(document, "sha256:" + "a" * 64)
        self.assertEqual(validate_document(value, derive.CANDIDATES_SCHEMA), [])
        self.assertEqual(json.loads(value["candidates"][0]["assertion"]), document["chains"][0])
        empty = derive.candidates({"cluster_id": document["cluster_id"], "no_chain_reason": "none", "chains": []},
                                  "sha256:" + "a" * 64)
        self.assertEqual(validate_document(empty, derive.CANDIDATES_SCHEMA), [])


class RepairTests(unittest.TestCase):
    def assertRepair(self, reply, fragment: str, ws=None):
        with self.assertRaises(InvokerOutputError) as caught:
            run(reply, ws)
        self.assertTrue(any(fragment in detail for detail in caught.exception.details), caught.exception.details)

    def test_unknown_claim_id(self):
        chain = two_link_chain()
        chain["links"][1]["claim_id"] = "claim-invented"
        self.assertRepair({"chains": [chain]}, "is not a claim of this workspace")

    def test_unknown_fact_ref_on_a_link_and_on_an_edge(self):
        chain = two_link_chain()
        chain["links"][0]["fact_ref"] = "02-code-property-graph#cpg_invented"
        self.assertRepair({"chains": [chain]}, "is not a fact of this workspace")
        chain = two_link_chain()
        chain["edges"][0]["fact_ref"] = "02-ir-facts#nowhere"
        self.assertRepair({"chains": [chain]}, "is not a fact of this workspace")

    def test_reordered_stages(self):
        chain = case_001_chain()
        chain["links"][1]["stage"], chain["links"][2]["stage"] = "impact", "execution"
        self.assertRepair({"chains": [chain]}, "the one 'impact'")

    def test_two_entries(self):
        chain = case_001_chain()
        chain["links"][1]["stage"] = "entry"
        self.assertRepair({"chains": [chain]}, "stage 'entry' appears 2 times")

    def test_privilege_gain_after_persistence_is_a_reorder(self):
        chain = case_001_chain()
        chain["links"] = [chain["links"][0], {**chain["links"][1], "stage": "persistence"},
                          chain["links"][2] | {"stage": "privilege_gain"}, {"fact_ref": METHOD, "stage": "impact"}]
        chain["edges"] = [{"from": i, "to": i + 1, "basis_claimed": "synthetic", "rationale": "hop"} for i in range(3)]
        self.assertRepair({"chains": [chain]}, "not reordered")

    def test_over_chain_links_max(self):
        ws = workspace(bound_values={"chain_links_max": 2})
        self.assertRepair({"chains": [case_001_chain()]}, "chain_links_max", ws)

    def test_over_chains_per_cluster_max(self):
        ws = workspace(bound_values={"chains_per_cluster_max": 1})
        self.assertRepair({"chains": [two_link_chain(), case_001_chain()]}, "chains_per_cluster_max", ws)

    def test_same_ref_twice_is_a_cycle(self):
        chain = case_001_chain()
        chain["links"][2] = {"claim_id": CLAIM, "stage": "impact", "citation_ids": ["citation-case01v"]}
        chain["edges"].append({"from": 1, "to": 2, "basis_claimed": "synthetic", "rationale": "same claim"})
        self.assertRepair({"chains": [chain]}, "appears twice in one chain")

    def test_missing_hop_and_wrong_hop(self):
        chain = two_link_chain(edges=[])
        self.assertRepair({"chains": [chain]}, "every hop needs an edge")
        chain = two_link_chain()
        chain["edges"][0]["to"] = 2
        self.assertRepair({"chains": [chain]}, "an edge joins link i to link i+1")

    def test_claim_link_needs_a_resolvable_citation(self):
        chain = two_link_chain()
        chain["links"][1]["citation_ids"] = ["citation-invented"]
        self.assertRepair({"chains": [chain]}, "must name at least one citation")

    def test_prerequisite_must_point_backwards(self):
        chain = two_link_chain()
        chain["links"][0]["prerequisites"] = [{"text": "later", "requires_link_indexes": [1]}]
        self.assertRepair({"chains": [chain]}, "requires_link_indexes must name earlier links")

    def test_fact_only_chain_and_narrative_rules(self):
        chain = two_link_chain()
        chain["links"][1] = {"fact_ref": STRCPY, "stage": "impact"}
        self.assertRepair({"chains": [chain]}, "at least one reviewed claim")
        self.assertRepair({"chains": [two_link_chain(narrative="argv reaches strcpy")]}, "must name at least one of its claim ids")
        payload = two_link_chain(narrative=f"{CLAIM}: send \\x41\\x41\\x41\\x41\\x90\\x90 then ```sh```")
        self.assertRepair({"chains": [payload]}, "do not include code")

    def test_link_needs_exactly_one_ref(self):
        chain = two_link_chain()
        chain["links"][0]["claim_id"] = CLAIM
        self.assertRepair({"chains": [chain]}, "no value is allowed here")   # schema oneOf (P4)
        chain = two_link_chain()
        del chain["links"][0]["fact_ref"]
        self.assertRepair({"chains": [chain]}, "matches none of oneOf")

    def test_verification_wording_goes_back_and_negation_passes(self):
        self.assertRepair({"chains": [two_link_chain(narrative=f"The chain through {CLAIM} is verified.")]},
                          "asserts verification")
        self.assertRepair({"chains": [two_link_chain(objective="Use a confirmed exploit of the copy")]},
                          "asserts verification")
        document, _notes = run({"chains": [two_link_chain(
            narrative=f"argv reaches {CLAIM}; the chain is not verified, only supported by the call graph.")]})
        self.assertEqual(len(document["chains"]), 1)

    def test_persona_schema_violation(self):
        chain = two_link_chain(impact_kind="world_domination")
        self.assertRepair({"chains": [chain]}, "not in enum")


class TaskExampleTests(unittest.TestCase):
    def test_the_task_prompt_example_derives_one_chain(self):
        text = (ROOT / "14-attack-chain/task-attack-chain-composition-cell.md").read_text(encoding="utf-8")
        example = json.loads(text.split("## Example", 1)[1].split("```json\n", 1)[1].split("\n```", 1)[0])
        document, notes = run(example)
        self.assertEqual(notes, [])
        self.assertEqual([chain["causal_claim_ids"] for chain in document["chains"]], [[CLAIM]])


class StateTests(unittest.TestCase):
    LINKS = [{"index": 0, "stage": "entry", "link_state": "verified"},
             {"index": 1, "stage": "impact", "link_state": "verified"}]
    CODE = [{"from": 0, "to": 1, "basis": "code_fact"}]

    def test_decision_4_table(self):
        state = derive.chain_state
        self.assertEqual(state(self.LINKS, self.CODE, {"disposition": "holds", "target": None})[0], "supported")
        self.assertEqual(state(self.LINKS, self.CODE, None)[0], "plausible")
        self.assertEqual(state(self.LINKS, self.CODE, {"disposition": "cannot_assess", "target": None})[0], "plausible")
        model = [{"from": 0, "to": 1, "basis": "model_flow"}]
        self.assertEqual(state(self.LINKS, model, {"disposition": "holds", "target": None}),
                         ("plausible", {"kind": "edge", "index": 0, "reason": "edge 0->1 is model_flow"}))
        narrowed = [self.LINKS[0], {**self.LINKS[1], "link_state": "narrowed"}]
        self.assertEqual(state(narrowed, self.CODE, {"disposition": "holds", "target": None})[0], "plausible")
        broken = {"disposition": "broken", "target": {"kind": "link", "index": 1}}
        self.assertEqual(state(self.LINKS, self.CODE, broken),
                         ("refuted", {"kind": "link", "index": 1, "reason": "refuter broke link 1"}))
        refuted = [self.LINKS[0], {**self.LINKS[1], "link_state": "refuted"}]
        self.assertEqual(state(refuted, self.CODE, None)[0], "refuted")
        narrowed_by_refuter = {"disposition": "narrowed", "target": {"kind": "edge", "index": 0}}
        self.assertEqual(state(self.LINKS, self.CODE, narrowed_by_refuter)[0], "plausible")

    def test_weakest_tie_breaks_by_stage_order(self):
        links = [{"index": 0, "stage": "entry", "link_state": "open"},
                 {"index": 1, "stage": "impact", "link_state": "open"}]
        edges = [{"from": 0, "to": 1, "basis": "synthetic"}]
        self.assertEqual(derive.chain_state(links, edges, None)[1]["index"], 0)
        self.assertEqual(derive.chain_state(links, edges, None)[1]["kind"], "link")


if __name__ == "__main__":
    unittest.main()
