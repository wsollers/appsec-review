from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import attack_chain_derive  # noqa: E402
import claim_review_derive  # noqa: E402
import contract_derive as cd  # noqa: E402
import execution_state as state  # noqa: E402
import hypothesis_hunt_derive  # noqa: E402
import poc_fix_derive  # noqa: E402

# (derive module, final schema, persona schema, (persona prefix, final prefix))
CONTRACTS = (
    (poc_fix_derive, "poc-fix-record.schema.json", "poc-fix-persona.schema.json", ((), ())),
    (attack_chain_derive, "attack-chain-record.schema.json",
     "attack-chain-composer-persona.schema.json", (("chains", "[]"), ())),
    (claim_review_derive, "claim-review-decision.schema.json",
     "claim-review-pool-persona.schema.json", (("decisions", "[]"), ("decision",))),
    (hypothesis_hunt_derive, "hunter-hypothesis.schema.json",
     "hypothesis-hunt-persona.schema.json", (("hypotheses", "[]"), ())),
)


class ContractDerive(unittest.TestCase):
    def test_poc_fix_orchestrator_fields_by_path(self):
        found = cd.orchestrator_fields("poc-fix-record.schema.json", "poc-fix-persona.schema.json")
        self.assertEqual({path: sorted(names) for path, names in found.items() if names}, {
            (): ["author", "claim_id", "claim_limits", "explanation_status", "label", "poc_fix_id",
                 "request_id"],
            ("cited_lines", "[]"): ["hash_basis", "source_sha256"],
            ("fix",): ["denylist_hits", "diff_sha256", "files", "status"],
            ("poc",): ["denylist_hits", "reason", "status", "text_sha256"],
        })

    def test_attack_chain_hand_list_is_exactly_the_schema_derived_set(self):
        found = cd.orchestrator_fields("attack-chain-record.schema.json",
                                       "attack-chain-composer-persona.schema.json",
                                       (("chains", "[]"), ()))
        self.assertEqual(set().union(*found.values()), attack_chain_derive._ORCHESTRATOR_KEYS)

    def test_every_schema_derived_field_is_in_its_derive_list(self):
        # A final-record field the persona schema does not declare is Python's (ADR-0013). If a
        # derive list misses one, a model echo of it costs a repair round instead of a note.
        for module, final, persona, anchor in CONTRACTS:
            for path, names in cd.orchestrator_fields(final, persona, anchor).items():
                with self.subTest(module=module.__name__, path=path):
                    self.assertEqual(names - module._ORCHESTRATOR_KEYS, set())
        _, final, persona, anchor = CONTRACTS[2]
        self.assertEqual(claim_review_derive._OBLIGATION_KEYS, cd.orchestrator_keys(
            final, persona, anchor, path=("decisions", "[]", "proof_obligations", "[]")))

    def test_brief_l2_fields_are_now_derived(self):
        self.assertLessEqual({"explanation_status", "reason"}, poc_fix_derive._ORCHESTRATOR_KEYS)
        self.assertIn("citations", claim_review_derive._ORCHESTRATOR_KEYS)
        self.assertIn("drop_reason", hypothesis_hunt_derive._ORCHESTRATOR_KEYS)

    def test_orchestrator_keys_is_the_union_or_one_path(self):
        final = {"properties": {"a": {}, "rows": {"items": {"properties": {"b": {}, "c": {}}}}}}
        persona = {"properties": {"rows": {"items": {"properties": {"c": {}}}}}}
        self.assertEqual(cd.orchestrator_keys(final, persona), {"a", "b"})
        self.assertEqual(cd.orchestrator_keys(final, persona, path=("rows", "[]")), {"b"})
        self.assertEqual(cd.orchestrator_keys(final, persona, path=("nope",)), set())

    def test_branches_refs_and_items_are_followed(self):
        schema = {"$defs": {"base": {"properties": {"a": {}}}},
                  "allOf": [{"$ref": "#/$defs/base"}],
                  "oneOf": [{"properties": {"b": {}}}, {"type": "null"}],
                  "if": {"properties": {"c": {}}}, "then": {"properties": {"d": {}}},
                  "properties": {"rows": {"type": "array", "items": {"properties": {"e": {}}}}}}
        self.assertEqual(cd.object_properties(schema), {"a", "b", "c", "d", "rows"})
        self.assertEqual(cd.object_paths(schema), [(), ("rows", "[]")])
        persona = {"properties": {"rows": {"items": {"properties": {}}}, "a": {}}}
        self.assertEqual(cd.orchestrator_fields(schema, persona),
                         {(): {"b", "c", "d"}, ("rows", "[]"): {"e"}})
        with self.assertRaises(KeyError):
            cd.at(schema, ("nope",))

    def test_primitives(self):
        notes: list[str] = []
        row = cd.strip_orchestrator_fields({"a": 1, "chain_id": "x", "state": 2}, {"chain_id", "state"},
                                           "reply", notes)
        self.assertEqual(row, {"a": 1})
        self.assertEqual(len(notes), 2)
        self.assertEqual(cd.strip_orchestrator_fields([1], {"a"}, "r", notes), [1])
        identity = {"k": [1, 2]}
        self.assertEqual(cd.content_id("chain", identity), "chain-" + state.digest(identity)[:24])
        self.assertEqual(cd.unwrap_single([{"a": 1}]), {"a": 1})
        self.assertEqual(cd.unwrap_single([1, 2]), [1, 2])


if __name__ == "__main__":
    unittest.main()
