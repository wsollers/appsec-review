"""Claim-review sharding and reviewer-persona assignment (ADR-0021)."""
from __future__ import annotations

import json
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import registry_paths

import catalog_personas
import claim_review_sharding as sharding
import persona_invocation as pi
import persona_prompt_assembly as ppa
from claim_review_lifecycle import POOL_CLASSES
from schema_validate import SchemaStore

STRIDE = ("spoofing", "tampering", "repudiation", "information-disclosure", "denial-of-service",
          "elevation-of-privilege")
TEMPLATE = json.loads((registry_paths.template("claim-review-pool-cell")).read_text())


def claim(claim_id, components, hypothesis="Candidate condition.", path=None, causal=(), producer="03-x"):
    locator = json.dumps({"path": path, "start_line": 1}) if path else None
    return {"claim_id": claim_id, "component_ids": list(components), "hypothesis": hypothesis,
            "route_id": "route-" + claim_id, "causal_claim_ids": list(causal), "supersedes_claim_id": None,
            "citations": [{"citation_id": "c-" + claim_id, "producer_job_id": producer,
                           "locator_json": locator, "observed_fact": "fact"}]}


def stride_ledger(components=10):
    return [claim(f"claim-{c:02d}-{s}", [f"comp-{c:02d}"], f"Candidate {s} condition at flow {c}")
            for c in range(components) for s in STRIDE]


class ShardPlanTests(unittest.TestCase):
    def test_deterministic_regardless_of_input_order(self):
        records = stride_ledger()
        first = sharding.plan_shards(records, 3)
        shuffled = list(records)
        random.Random(7).shuffle(shuffled)
        self.assertEqual(sharding.plan_shards(shuffled, 3), first)
        self.assertEqual(sorted(i for shard in first for i in shard), sorted(r["claim_id"] for r in records))

    def test_every_claim_once_and_balanced(self):
        records = stride_ledger()
        shards = sharding.plan_shards(records, 3)
        self.assertEqual(len(shards), 3)
        ids = [i for shard in shards for i in shard]
        self.assertEqual(len(ids), len(set(ids)))       # shard only: one review per claim
        sizes = [sharding.shard_units(records, shard) for shard in shards]
        chunk = max(sharding.shard_units(records, [r["claim_id"] for r in records[:6]]), 1)
        self.assertLessEqual(max(sizes) - min(sizes), chunk + 8)   # within one component group

    def test_same_component_and_same_file_stay_together(self):
        records = stride_ledger()
        for shard in sharding.plan_shards(records, 3):
            components = {i.split("-")[1] for i in shard}
            for component in components:
                self.assertEqual(sum(1 for i in shard if i.split("-")[1] == component), 6)
        by_file = [claim(f"f{i}", ["x"], path=f"src/{i % 2}.c") for i in range(8)]
        for shard in sharding.plan_shards(by_file, 2):
            self.assertEqual(len({int(i[1:]) % 2 for i in shard}), 1)

    def test_causally_linked_claims_are_never_split(self):
        records = [claim("a", ["one"]), claim("b", ["two"], causal=["a"]), claim("c", ["three"]),
                   claim("d", ["four"])]
        shards = sharding.plan_shards(records, 4)
        self.assertIn(["a", "b"], shards)
        self.assertEqual(len(shards), 3)

    def test_oversized_locus_is_split_and_fewer_claims_than_instances(self):
        records = [claim(f"claim-{i:02d}", ["one"]) for i in range(9)]
        self.assertEqual(len(sharding.plan_shards(records, 3)), 3)
        self.assertEqual(len(sharding.plan_shards(records[:2], 3)), 2)
        self.assertEqual(sharding.plan_shards([], 3), [])

    def test_instance_count_grows_until_each_shard_fits_the_unit_limit(self):
        records = stride_ledger(4)
        one = sharding.shard_units(records, [r["claim_id"] for r in records[:6]])
        shards = sharding.plan_within_limit(records, 1, units_max=one * 2, instances_max=32)
        self.assertGreaterEqual(len(shards), 2)
        self.assertTrue(all(sharding.shard_units(records, s) <= one * 2 for s in shards))
        with self.assertRaises(ValueError):
            sharding.plan_within_limit(records, 1, units_max=1, instances_max=2)

    def test_shard_document_keeps_every_other_field(self):
        upstream = {"schema": "s", "run_id": "r", "candidates": stride_ledger(2)}
        document = sharding.shard_document("candidates", upstream, ["claim-01-spoofing"])
        self.assertEqual([r["claim_id"] for r in document["candidates"]], ["claim-01-spoofing"])
        self.assertEqual({k: v for k, v in document.items() if k != "candidates"},
                         {"schema": "s", "run_id": "r"})


class PersonaAssignmentTests(unittest.TestCase):
    def personas(self, stage):
        ids = TEMPLATE["stage_personas"][stage]
        store = SchemaStore()
        return ids, {i: pi._load_record(pi.REGISTRY_DIR, "personas", "persona.schema.json", "persona_id", i, store)
                     for i in ids}

    def test_each_instance_gets_a_distinct_persona_deterministically(self):
        records = stride_ledger()
        for stage in TEMPLATE["stage_personas"]:
            ids, records_by_id = self.personas(stage)
            shards = sharding.plan_shards(records, 3)
            first = sharding.assign_personas(stage, shards, records, ids, records_by_id)
            again = sharding.assign_personas(stage, shards, records, ids, records_by_id)
            self.assertEqual(first, again)
            chosen = [row["persona_id"] for row in first]
            self.assertEqual(len(set(chosen)), len(chosen), stage)
            self.assertTrue(set(chosen) <= set(ids))

    def test_matching_prefers_the_persona_whose_focus_matches_the_claims(self):
        ids, by_id = self.personas("07-red-team-adversarial")
        records = [claim("n1", ["parser"], "Heap buffer overflow: integer overflow into allocation and "
                         "copy reaches the parser sink; bounds and lifetime failure", producer="02-native-sast"),
                   claim("s1", ["ci"], "Unpinned GitHub action and dependency confusion through the lockfile "
                         "drift; postinstall build script risk", path="ci/workflow.yml")]
        rows = sharding.assign_personas("07-red-team-adversarial", [["n1"], ["s1"]], records, ids, by_id)
        self.assertEqual(rows[0]["persona_id"], "native-exploitability-engineer")
        self.assertEqual(rows[1]["persona_id"], "supply-chain-attacker")

    def test_rotation_reuses_personas_only_after_the_list_is_exhausted(self):
        ids, by_id = self.personas("09-independent-verification")
        records = [claim(f"c{i}", [f"k{i}"]) for i in range(len(ids) + 1)]
        rows = sharding.assign_personas("09-independent-verification", [[f"c{i}"] for i in range(len(ids) + 1)],
                                        records, ids, by_id)
        self.assertEqual(len({row["persona_id"] for row in rows[:len(ids)]}), len(ids))


class RegistryTests(unittest.TestCase):
    def test_every_catalog_persona_has_a_current_registry_record(self):
        self.assertEqual(catalog_personas.check(), [])

    def test_stage_persona_pools_are_registry_variants_and_disjoint_by_stage(self):
        variants = set(TEMPLATE["persona_variants"]) | {TEMPLATE["composition"]["persona_id"]}
        seen = set()
        for stage, ids in TEMPLATE["stage_personas"].items():
            self.assertGreaterEqual(len(ids), 3, stage)
            self.assertTrue(set(ids) <= variants, stage)
            self.assertFalse(seen & set(ids), f"{stage} reuses a reviewer persona of an earlier stage")
            seen |= set(ids)
        categories = {"07-red-team-adversarial": {"attacker", "domain-specialist"},
                      "08-blue-team-refutation": {"defender", "domain-specialist"},
                      "09-independent-verification": {"verifier", "domain-specialist"},
                      "12-scoring-prioritization": {"synthesis", "stakeholder-output"}}
        for stage, ids in TEMPLATE["stage_personas"].items():
            for persona_id in ids:
                record = json.loads((ROOT / f"personas/personas/{persona_id}/persona.json").read_text())
                self.assertIn(record["category"], categories[stage], (stage, persona_id))

    def test_registry_survey_accepts_the_new_records_and_variants(self):
        errors = pi.validate_persona_registry(pi.REGISTRY_DIR)
        self.assertFalse([e for e in errors if e.startswith("personas/") or "claim-review-pool-cell" in e], errors)

    def test_variant_prompt_and_composition_are_registry_decided(self):
        store = SchemaStore()
        base, _ = ppa.assemble_prompt_text("claim-review-pool-cell", store)
        text, template = ppa.assemble_prompt_text("claim-review-pool-cell", store, "defensive-skeptic")
        self.assertIn("## Persona (defensive-skeptic)", text)
        self.assertNotEqual(text, base)
        self.assertEqual(template["composition"]["persona_id"], "claim-reviewer")
        with self.assertRaises(ppa.PromptAssemblyError):
            ppa.assemble_prompt_text("claim-review-pool-cell", store, "intake-coordinator")
        block = {"job_template_id": "claim-review-pool-cell", "job_template_sha256": pi._sha(TEMPLATE)}
        for name, directory, schema, field in pi.COMPOSITION_KINDS[1:]:
            record_id = TEMPLATE["composition"][name + "_id"]
            block[name + "_id"] = record_id
            block[name + "_sha256"] = pi._sha(pi._load_record(pi.REGISTRY_DIR, directory, schema, field, record_id, store))
        pi.load_composition(pi.REGISTRY_DIR, block, store)
        for persona_id, accepted in (("defensive-skeptic", True), ("intake-coordinator", False)):
            record = pi._load_record(pi.REGISTRY_DIR, "personas", "persona.schema.json", "persona_id", persona_id, store)
            changed = {**block, "persona_id": persona_id, "persona_sha256": pi._sha(record)}
            if accepted:
                pi.load_composition(pi.REGISTRY_DIR, changed, store)
            else:
                with self.assertRaises(pi.PersonaRequestError):
                    pi.load_composition(pi.REGISTRY_DIR, changed, store)

    def composition_block(self, store):
        block = {"job_template_id": "claim-review-pool-cell", "job_template_sha256": pi._sha(TEMPLATE)}
        for name, directory, schema, field in pi.COMPOSITION_KINDS[1:]:
            record_id = TEMPLATE["composition"][name + "_id"]
            block[name + "_id"] = record_id
            block[name + "_sha256"] = pi._sha(pi._load_record(pi.REGISTRY_DIR, directory, schema, field, record_id, store))
        return block

    def test_each_stage_runs_as_its_own_registry_role_with_the_stage_claim_class(self):
        store = SchemaStore()
        self.assertEqual(set(TEMPLATE["stage_roles"]), set(TEMPLATE["stage_personas"]))
        self.assertEqual(sorted(TEMPLATE["stage_roles"].values()), sorted(TEMPLATE["role_variants"]))
        block = self.composition_block(store)
        profile = pi._load_record(pi.REGISTRY_DIR, "tooling-profiles", "tooling-profile.schema.json",
                                  "tooling_profile_id", TEMPLATE["composition"]["tooling_profile_id"], store)
        for stage, role_id in TEMPLATE["stage_roles"].items():
            with self.subTest(stage=stage):
                role = pi._load_record(pi.REGISTRY_DIR, "roles", "role.schema.json", "role_id", role_id, store)
                self.assertEqual(pi.claim_ceiling(role, profile)["allowed"], (POOL_CLASSES[stage],))
                records = pi.load_composition(pi.REGISTRY_DIR, {**block, "role_id": role_id,
                                                                "role_sha256": pi._sha(role)}, store)
                self.assertEqual(records["role"]["role_id"], role_id)
        other = pi._load_record(pi.REGISTRY_DIR, "roles", "role.schema.json", "role_id", "evidence-indexer", store)
        with self.assertRaisesRegex(pi.PersonaRequestError, "role_id is not what the named job template composes"):
            pi.load_composition(pi.REGISTRY_DIR, {**block, "role_id": "evidence-indexer",
                                                  "role_sha256": pi._sha(other)}, store)
        with self.assertRaises(ppa.PromptAssemblyError):
            ppa.assemble_prompt_text("claim-review-pool-cell", store, role_id="evidence-indexer")

    def test_a_stage_role_changes_only_the_role_section_of_the_prompt(self):
        store = SchemaStore()

        def sections(text):
            return [part.split("\n", 1) for part in ("\n" + text).split("\n## ")[1:]]

        generic, _ = ppa.assemble_prompt_text("claim-review-pool-cell", store, "defensive-skeptic")
        staged, _ = ppa.assemble_prompt_text("claim-review-pool-cell", store, "defensive-skeptic",
                                             "blue-team-refuter")
        before, after = sections(generic), sections(staged)
        self.assertEqual([heading for heading, _ in before if heading != "Role (claim-reviewer)"],
                         [heading for heading, _ in after if heading != "Role (blue-team-refuter)"])
        changed = [(a[0], b[0]) for a, b in zip(before, after) if a != b]
        self.assertEqual(changed, [("Role (claim-reviewer)", "Role (blue-team-refuter)")])

if __name__ == "__main__":
    unittest.main()
