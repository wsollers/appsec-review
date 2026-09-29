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
# Final-record fields the schemas mark orchestrator-owned that the module's hand-written
# _ORCHESTRATOR_KEYS does not strip (an echo of one costs a repair round instead of a note).
# Recorded in TODO "L formats"; the fix edits the derive module, which is part of its job's
# fingerprint, so it waits for owner approval. Shrink this table as modules adopt contract_derive.
KNOWN_DRIFT = {
    "poc_fix_derive": {"explanation_status", "reason"},
    "attack_chain_derive": set(),
    "claim_review_derive": {"citations"},
    "hypothesis_hunt_derive": {"drop_reason"},
}


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

    def test_hand_written_lists_drift_only_as_recorded(self):
        for module, final, persona, anchor in CONTRACTS:
            derived = set().union(*cd.orchestrator_fields(final, persona, anchor).values())
            missing = derived - module._ORCHESTRATOR_KEYS
            self.assertEqual(missing, KNOWN_DRIFT[module.__name__], module.__name__)

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
