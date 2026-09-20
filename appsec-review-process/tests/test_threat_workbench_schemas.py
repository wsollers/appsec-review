"""Golden and mutation tests for the threat-workbench schema set (ADR-0008, task T02).

Structural only. Cross-record identity, the completeness invariant, OBSERVED_EXPOSURE rejection,
index-only citations and claim-limit prose are lane-validator (T08) responsibilities; the one
place this file touches them is to pin that the schema deliberately lets OBSERVED_EXPOSURE through
so T08 can reject it by name.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from schema_validate import SchemaStore, validate_document

FIXTURES = ROOT / "tests" / "fixtures" / "threat-workbench" / "schema"
SCHEMAS = ROOT.parent / "schemas"

MODEL = "integrated-threat-model.schema.json"
CELL = "threat-workbench-cell-result.schema.json"
INTERCOM = "threat-workbench-intercom-record.schema.json"
WAVE = "threat-workbench-wave-manifest.schema.json"
RECORD_SCHEMAS = [
    "threat-model-citation.schema.json",
    "threat-model-element.schema.json",
    "threat-model-flow.schema.json",
    "threat-model-trust-boundary.schema.json",
    "threat-model-data-class.schema.json",
    "threat-model-deployment-zone.schema.json",
    "threat-model-abuse-scenario.schema.json",
    "threat-model-attack-tree.schema.json",
    "threat-model-stride-hypothesis.schema.json",
    "threat-model-assumption.schema.json",
    "threat-model-gap.schema.json",
]
ALL_SCHEMAS = [MODEL, CELL, INTERCOM, WAVE, *RECORD_SCHEMAS]

# Concepts ADR-0008 forbids the workbench from publishing. No schema may offer a home for them.
FORBIDDEN_PROPERTY_NAMES = {
    "verified", "is_verified", "verification_status", "verified_finding",
    "severity", "final_severity", "cvss", "risk_rating",
    "exploitable", "exploitability", "confirmed_exposure", "observed_runtime",
    "compliance_status", "compliant", "pass_fail",
    "malicious", "malicious_intent", "intent",
    "remediation_status", "remediated", "fix_status",
    "updated_at", "edited",
}
TERMINAL = ["OK", "OK_WITH_GAPS", "SKIPPED", "BLOCKED", "FAILED", "CANCELED", "UNRESOLVED"]


def load(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def walk_schema(node, path="$"):
    """Yields (path, subschema) for every object-typed subschema that declares properties."""
    if isinstance(node, dict):
        if node.get("type") == "object" and "properties" in node:
            yield path, node
        for key, value in node.items():
            yield from walk_schema(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk_schema(value, f"{path}[{index}]")


class ThreatWorkbenchSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = SchemaStore()
        cls.model = load("integrated-threat-model.golden.json")
        cls.cell = load("cell-result.golden.json")
        cls.intercom = load("intercom-records.golden.json")
        cls.wave = load("wave-manifest.golden.json")

    def assertValid(self, instance, schema):
        errors = validate_document(instance, schema, self.store)
        self.assertEqual(errors, [], "\n".join(errors))

    def assertRejected(self, instance, schema, *needles):
        errors = validate_document(instance, schema, self.store)
        self.assertTrue(errors, f"expected {schema} to reject the mutation")
        joined = "\n".join(errors)
        for needle in needles:
            self.assertIn(needle, joined)

    # ---- schema-set hygiene -------------------------------------------------------------

    def test_every_schema_loads_and_is_closed(self):
        for name in ALL_SCHEMAS:
            schema = self.store.load(name)
            self.assertEqual(schema.get("$id"), name)
            for path, node in walk_schema(schema):
                if path.endswith(".payload"):
                    continue  # intercom payload is the one deliberately open object
                self.assertIs(node.get("additionalProperties"), False, f"{name} {path} is not closed")
                self.assertEqual(set(node.get("required", [])), set(node["properties"]),
                                 f"{name} {path}: every declared property must be required")

    def test_no_schema_offers_a_forbidden_field(self):
        for name in ALL_SCHEMAS:
            for path, node in walk_schema(self.store.load(name)):
                offenders = FORBIDDEN_PROPERTY_NAMES & set(node["properties"])
                self.assertFalse(offenders, f"{name} {path} declares forbidden fields {sorted(offenders)}")

    def test_terminal_status_enums_match_the_common_envelope(self):
        envelope = self.store.load("worker-result-envelope.schema.json")
        expected = envelope["properties"]["execution_status"]["enum"]
        self.assertEqual(expected, TERMINAL)
        self.assertEqual(self.store.load(CELL)["properties"]["terminal_status"]["enum"], expected)
        wave_items = self.store.load(WAVE)["properties"]["terminal_instances"]["items"]
        self.assertEqual(wave_items["properties"]["terminal_status"]["enum"], expected)
        coverage = self.store.load(MODEL)["properties"]["coverage"]["properties"]["workcells"]["items"]
        self.assertEqual([v for v in coverage["properties"]["terminal_status"]["enum"] if v], expected)

    def test_intercom_payload_is_the_only_open_object(self):
        schema = self.store.load(INTERCOM)
        payload = schema["properties"]["payload"]
        self.assertEqual(payload.get("type"), "object")
        self.assertNotIn("additionalProperties", payload)

    # ---- goldens -------------------------------------------------------------------------

    def test_goldens_validate(self):
        self.assertValid(self.model, MODEL)
        self.assertValid(self.cell, CELL)
        self.assertValid(self.wave, WAVE)
        for record in self.intercom:
            self.assertValid(record, INTERCOM)

    def test_golden_ids_are_internally_consistent(self):
        # Kept here as a smoke check that the fixture is usable by T08, not as the T08 rule set.
        model = self.model
        ids = {e["element_id"] for e in model["elements"]}
        for flow in model["flows"]:
            self.assertIn(flow["source_element_id"], ids)
            self.assertIn(flow["destination_element_id"], ids)
        threat_ids = {t["threat_id"] for t in model["stride_hypotheses"]}
        for tree in model["attack_trees"]:
            node_ids = {n["node_id"] for n in tree["nodes"]}
            self.assertIn(tree["root_node_id"], node_ids)
            for node in tree["nodes"]:
                self.assertTrue(set(node["child_node_ids"]) <= node_ids)
                self.assertTrue(set(node["verification_item_ids"]) <= threat_ids)
        record_ids = {r["record_id"] for r in self.intercom}
        for entry in model["dissent"]:
            self.assertIn(entry["challenge_record_id"], record_ids)

    # ---- mutations: one per closed enum or forbidden concept -----------------------------

    def mutated_model(self):
        return deepcopy(self.model)

    def test_rejects_verified_flag_on_threat(self):
        model = self.mutated_model()
        model["stride_hypotheses"][0]["verified"] = True
        self.assertRejected(model, MODEL, "stride_hypotheses[0]", "unexpected property 'verified'")

    def test_rejects_severity_on_threat(self):
        model = self.mutated_model()
        model["stride_hypotheses"][0]["severity"] = "high"
        self.assertRejected(model, MODEL, "unexpected property 'severity'")

    def test_rejects_compliance_status_on_data_class(self):
        model = self.mutated_model()
        model["data_classes"][1]["compliance_status"] = "pass"
        self.assertRejected(model, MODEL, "data_classes[1]", "compliance_status")

    def test_rejects_malicious_intent_on_abuse_scenario(self):
        model = self.mutated_model()
        model["abuse_scenarios"][0]["malicious_intent"] = "confirmed"
        self.assertRejected(model, MODEL, "abuse_scenarios[0]", "malicious_intent")

    def test_rejects_remediation_status_top_level(self):
        model = self.mutated_model()
        model["remediation_status"] = "fixed"
        self.assertRejected(model, MODEL, "$: unexpected property 'remediation_status'")

    def test_observed_exposure_is_schema_valid_so_t08_can_reject_it_by_name(self):
        model = self.mutated_model()
        model["deployment_zones"][1]["exposure_label"] = "OBSERVED_EXPOSURE"
        self.assertValid(model, MODEL)
        # and nothing outside the two labels is accepted
        model["deployment_zones"][1]["exposure_label"] = "PROBABLE_EXPOSURE"
        self.assertRejected(model, MODEL, "exposure_label", "not in enum")

    def test_rejects_unknown_stride_category(self):
        model = self.mutated_model()
        model["stride_hypotheses"][0]["stride_category"] = "S"
        self.assertRejected(model, MODEL, "stride_category")

    def test_rejects_stride_coverage_missing_a_category(self):
        model = self.mutated_model()
        del model["stride_coverage"][0]["decisions"]["repudiation"]
        self.assertRejected(model, MODEL, "missing required property 'repudiation'")

    def test_rejects_threat_without_proof_obligation(self):
        model = self.mutated_model()
        model["stride_hypotheses"][0]["proof_obligations"] = []
        self.assertRejected(model, MODEL, "proof_obligations", "minItems is 1")

    def test_rejects_threat_without_citation(self):
        model = self.mutated_model()
        model["stride_hypotheses"][0]["citations"] = []
        self.assertRejected(model, MODEL, "citations", "minItems is 1")

    def test_rejects_unknown_downstream_owner(self):
        model = self.mutated_model()
        model["stride_hypotheses"][0]["downstream_owner"] = "10-synthesis-report"
        self.assertRejected(model, MODEL, "downstream_owner")

    def test_rejects_unknown_evidence_class(self):
        model = self.mutated_model()
        model["elements"][0]["evidence_class"] = "VERIFIED"
        self.assertRejected(model, MODEL, "evidence_class", "not in enum")

    def test_rejects_unknown_leaf_support(self):
        model = self.mutated_model()
        model["attack_trees"][0]["nodes"][1]["leaf_support"] = "proven"
        self.assertRejected(model, MODEL, "leaf_support")

    def test_rejects_unknown_source_class(self):
        model = self.mutated_model()
        model["elements"][0]["citations"][0]["source_class"] = "chat"
        self.assertRejected(model, MODEL, "source_class", "not in enum")

    def test_rejects_citation_without_hash(self):
        model = self.mutated_model()
        del model["elements"][0]["citations"][0]["sha256"]
        self.assertRejected(model, MODEL, "missing required property 'sha256'")

    def test_rejects_malformed_hash(self):
        model = self.mutated_model()
        model["elements"][0]["citations"][0]["sha256"] = "sha256:abc"
        self.assertRejected(model, MODEL, "sha256", "does not match pattern")

    def test_rejects_design_v3_status_vocabulary_in_coverage(self):
        model = self.mutated_model()
        model["coverage"]["workcells"][0]["terminal_status"] = "COMPLETE"
        self.assertRejected(model, MODEL, "terminal_status", "not in enum")

    def test_rejects_empty_workcell_coverage(self):
        model = self.mutated_model()
        model["coverage"]["workcells"] = []
        self.assertRejected(model, MODEL, "workcells", "minItems is 1")

    def test_rejects_wrong_job_id(self):
        model = self.mutated_model()
        model["job_id"] = "03-threat-model"
        self.assertRejected(model, MODEL, "job_id", "expected const")

    # provenance is unavoidable on every record family (PR 4 review finding)

    def test_every_record_family_requires_citations_evidence_class_and_confidence(self):
        for name in RECORD_SCHEMAS:
            if name == "threat-model-citation.schema.json":
                continue
            schema = self.store.load(name)
            for field in ("citations", "evidence_class", "confidence"):
                self.assertIn(field, schema["required"], f"{name} does not require {field}")
            self.assertEqual(schema["properties"]["citations"].get("minItems"), 1, f"{name} allows empty citations")

    def test_rejects_assumption_without_provenance(self):
        for field in ("citations", "evidence_class", "confidence"):
            model = self.mutated_model()
            del model["assumptions"][0][field]
            self.assertRejected(model, MODEL, "assumptions[0]", f"missing required property '{field}'")
        model = self.mutated_model()
        model["assumptions"][0]["citations"] = []
        self.assertRejected(model, MODEL, "assumptions[0].citations", "minItems is 1")

    def test_rejects_gap_without_provenance(self):
        for field in ("citations", "evidence_class", "confidence"):
            model = self.mutated_model()
            del model["gaps"][0][field]
            self.assertRejected(model, MODEL, "gaps[0]", f"missing required property '{field}'")
        model = self.mutated_model()
        model["gaps"][0]["citations"] = []
        self.assertRejected(model, MODEL, "gaps[0].citations", "minItems is 1")

    def test_rejects_attack_tree_without_provenance(self):
        for field in ("citations", "evidence_class", "confidence"):
            model = self.mutated_model()
            del model["attack_trees"][0][field]
            self.assertRejected(model, MODEL, "attack_trees[0]", f"missing required property '{field}'")
        model = self.mutated_model()
        model["attack_trees"][0]["citations"] = []
        self.assertRejected(model, MODEL, "attack_trees[0].citations", "minItems is 1")

    def test_attack_tree_node_citations_may_be_empty_for_non_evidence_nodes(self):
        # Conditional rule (leaf_support == evidence => citations) belongs to T08; structurally an
        # OR node and an unresolved leaf carry no citations, as in the golden.
        tree = self.model["attack_trees"][0]
        self.assertEqual(tree["nodes"][0]["kind"], "OR")
        self.assertEqual(tree["nodes"][0]["citations"], [])
        self.assertEqual(tree["nodes"][2]["leaf_support"], "unresolved")
        self.assertEqual(tree["nodes"][2]["citations"], [])

    def test_cell_rejects_gap_without_provenance(self):
        cell = deepcopy(self.cell)
        del cell["model_delta"]["gaps"][0]["citations"]
        self.assertRejected(cell, CELL, "model_delta.gaps[0]", "missing required property 'citations'")

    def test_rejects_unknown_gap_kind(self):
        model = self.mutated_model()
        model["gaps"][0]["kind"] = "todo"
        self.assertRejected(model, MODEL, "gaps[0].kind")

    def test_rejects_unknown_wave_4_state(self):
        model = self.mutated_model()
        model["coverage"]["wave_4"] = "skipped"
        self.assertRejected(model, MODEL, "wave_4")

    # cell result

    def test_cell_rejects_unrecorded_model_identity(self):
        cell = deepcopy(self.cell)
        cell["model_identity_hash"] = None
        self.assertRejected(cell, CELL, "model_identity_hash")

    def test_cell_rejects_wave_outside_one_to_four(self):
        cell = deepcopy(self.cell)
        cell["wave"] = 5
        self.assertRejected(cell, CELL, "wave", "not in enum")
        cell["wave"] = "join"
        self.assertRejected(cell, CELL, "wave")

    def test_cell_rejects_verified_in_delta(self):
        cell = deepcopy(self.cell)
        cell["model_delta"]["stride_hypotheses"][0]["verified"] = True
        self.assertRejected(cell, CELL, "model_delta.stride_hypotheses[0]", "verified")

    def test_cell_rejects_missing_delta_family(self):
        cell = deepcopy(self.cell)
        del cell["model_delta"]["gaps"]
        self.assertRejected(cell, CELL, "model_delta", "missing required property 'gaps'")

    # intercom

    def test_intercom_rejects_edit_in_place_fields(self):
        record = deepcopy(self.intercom[0])
        record["updated_at"] = "2026-09-20T11:00:00Z"
        self.assertRejected(record, INTERCOM, "unexpected property 'updated_at'")

    def test_intercom_rejects_unknown_record_type_and_status(self):
        record = deepcopy(self.intercom[0])
        record["record_type"] = "chat"
        self.assertRejected(record, INTERCOM, "record_type", "not in enum")
        record = deepcopy(self.intercom[0])
        record["status"] = "resolved"
        self.assertRejected(record, INTERCOM, "status", "not in enum")

    def test_intercom_requires_resolution_and_hash_chain_fields(self):
        record = deepcopy(self.intercom[1])
        del record["resolution"]["resolving_record_id"]
        self.assertRejected(record, INTERCOM, "resolution", "resolving_record_id")
        record = deepcopy(self.intercom[1])
        del record["previous_hash"]
        self.assertRejected(record, INTERCOM, "missing required property 'previous_hash'")

    def test_intercom_payload_accepts_arbitrary_keys(self):
        record = deepcopy(self.intercom[0])
        record["payload"] = {"anything": {"nested": [1, 2, 3]}}
        self.assertValid(record, INTERCOM)

    # wave manifest

    def test_wave_manifest_rejects_unknown_terminal_status(self):
        manifest = deepcopy(self.wave)
        manifest["terminal_instances"][0]["terminal_status"] = "RUNNING"
        self.assertRejected(manifest, WAVE, "terminal_status", "not in enum")

    def test_wave_manifest_rejects_unhashed_cell_result(self):
        manifest = deepcopy(self.wave)
        del manifest["terminal_instances"][0]["cell_result_sha256"]
        self.assertRejected(manifest, WAVE, "missing required property 'cell_result_sha256'")

    def test_wave_manifest_rejects_wave_zero(self):
        manifest = deepcopy(self.wave)
        manifest["wave"] = 0
        self.assertRejected(manifest, WAVE, "wave", "not in enum")


if __name__ == "__main__":
    unittest.main()
