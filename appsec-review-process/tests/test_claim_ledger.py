from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import claim_ledger as ledger
import execution_state
from schema_validate import SchemaStore, validate_document
import threat_model_core
import validate_job_output


class ClaimLedgerTests(unittest.TestCase):
    def setUp(self):
        component = json.loads((ROOT / "tests/fixtures/component-characterization/hello-autotools.json").read_text())
        inputs = {"run_id": "run1", "source_snapshot_sha256": component["source_snapshot_sha256"],
            "component_attempt_id": "component-1", "component_pointer_sha256": "sha256:" + "1" * 64,
            "component_envelope_sha256": "sha256:" + "2" * 64,
            "component_map_path": "data/jobs/01-component-characterization/attempts/component-1/component-purpose-map.json",
            "component_map_sha256": "3" * 64, "evidence_attempt_id": "evidence-1",
            "evidence_manifest_sha256": "sha256:" + "4" * 64,
            "evidence_path": "data/jobs/02-evidence-assembly/attempts/evidence-1/evidence/index.json",
            "evidence_sha256": "5" * 64, "component_map": component, "code": {}}
        model = threat_model_core.build_model(inputs, "threat-attempt-1")
        self.threat_source = {"contract_id": "threat-model-core", "producer_job_id": threat_model_core.JOB,
            "producer_attempt_id": "threat-attempt-1", "artifact_path": "data/jobs/03-threat-model-dfd-stride/attempts/threat-attempt-1/integrated-threat-model.json",
            "artifact_sha256": "sha256:" + "6" * 64, "accepted_pointer_sha256": "sha256:" + "7" * 64,
            "source_generation": model["source_snapshot"], "component_generation": model["component_map_attempt_id"],
            "artifact": model}
        self.owasp_source = {"contract_id": "owasp-join-report", "producer_job_id": "04-owasp-join-report",
            "producer_attempt_id": "owasp-attempt-1", "artifact_path": "data/jobs/04-owasp-join-report/attempts/owasp-attempt-1/owasp-candidate-promotion-routes.json",
            "artifact_sha256": "sha256:" + "8" * 64, "accepted_pointer_sha256": "sha256:" + "9" * 64,
            "source_generation": model["source_snapshot"], "component_generation": model["component_map_attempt_id"],
            "artifact": json.loads((ROOT / "tests/fixtures/claim-ledger/owasp-routes.json").read_text())}

    def candidates(self):
        return ledger.threat_candidates(self.threat_source) + ledger.owasp_candidates(self.owasp_source)

    def test_deterministic_admission_preserves_lineage_and_emits_inert_routing(self):
        candidates = self.candidates()
        first = ledger.build_ledger("run1", "ledger-attempt-1", candidates)
        second = ledger.build_ledger("run1", "ledger-attempt-1", deepcopy(candidates))
        self.assertEqual(first, second); self.assertEqual(ledger.validate_ledger(first), [])
        self.assertEqual(first["head_hash"], first["entries"][-1]["entry_hash"])
        self.assertTrue(all(item["claim_class"] == "candidate_only" and item["status"] == "candidate"
                            for item in first["entries"]))
        threat = next(item for item in first["entries"] if item["producer"]["contract_id"] == "threat-model-core")
        self.assertEqual(threat["source_generation"], self.threat_source["source_generation"])
        self.assertEqual(threat["producer"]["artifact_sha256"], self.threat_source["artifact_sha256"])
        self.assertTrue(threat["citations"]); self.assertTrue(threat["proof_obligations"])
        routing = ledger.work_routing(first)
        self.assertEqual(len(routing["routes"]), len(first["claim_states"]))
        self.assertTrue(all(item["authorization"] == "not_authorized" and item["execution"] == "not_executed"
                            for item in routing["routes"]))

    def test_mixed_or_stale_generation_and_duplicate_route_fail_closed(self):
        candidates = self.candidates()
        mixed = deepcopy(candidates); mixed[-1]["source"]["component_generation"] = "component-stale"
        with self.assertRaisesRegex(execution_state.Blocked, "mixed"):
            ledger.build_ledger("run1", "attempt-1", mixed)
        with self.assertRaisesRegex(execution_state.Blocked, "duplicate/conflicting route"):
            ledger.build_ledger("run1", "attempt-1", [candidates[0], deepcopy(candidates[0])])
        prior = ledger.build_ledger("run1", "attempt-1", candidates[:1])
        with self.assertRaisesRegex(execution_state.Blocked, "duplicate/conflicting route"):
            ledger.build_ledger("run1", "attempt-2", [candidates[0]], prior)

    def test_broken_chain_conflicting_ids_and_cycle_are_rejected(self):
        value = ledger.build_ledger("run1", "attempt-1", self.candidates())
        broken = deepcopy(value); broken["entries"][1]["previous_entry_hash"] = "sha256:" + "0" * 64
        self.assertTrue(any("broken" in error or "hash differs" in error for error in ledger.validate_ledger(broken)))
        duplicate = deepcopy(value); duplicate["entries"][1]["event_id"] = duplicate["entries"][0]["event_id"]
        self.assertIn("duplicate event id", ledger.validate_ledger(duplicate))
        cyclic = deepcopy(value)
        first, second = cyclic["entries"][0], cyclic["entries"][1]
        first["causal_claim_ids"] = [second["claim_id"]]; second["causal_claim_ids"] = [first["claim_id"]]
        self.assertTrue(any("cycle" in error for error in ledger.validate_ledger(cyclic)))

    def test_authorized_decisions_append_and_illegal_or_self_verifying_decisions_fail(self):
        prior = ledger.build_ledger("run1", "attempt-1", self.candidates()[:1])
        claim = prior["claim_states"][0]["claim_id"]
        red = {"claim_id": claim, "to_status": "under_review", "authority": {
            "job_id": "07-red-team-adversarial", "attempt_id": "red-1", "role_id": "red-team",
            "source_generation": prior["source_generation"], "component_generation": prior["component_generation"],
            "artifact_path": "data/jobs/07-red-team-adversarial/attempts/red-1/result.json",
            "artifact_sha256": "sha256:" + "c" * 64, "permission_receipt_path": "permission.json",
            "permission_receipt_sha256": "sha256:" + "a" * 64, "reason": "Candidate selected for adversarial review."}}
        reviewed = ledger.build_ledger("run1", "attempt-2", [], prior, [red])
        self.assertEqual(reviewed["claim_states"][0]["status"], "under_review")
        verify = {"claim_id": claim, "to_status": "verified", "authority": {
            "job_id": "09-independent-verification", "attempt_id": "verify-1", "role_id": "independent-verifier",
            "source_generation": prior["source_generation"], "component_generation": prior["component_generation"],
            "artifact_path": "data/jobs/09-independent-verification/attempts/verify-1/result.json",
            "artifact_sha256": "sha256:" + "d" * 64, "permission_receipt_path": "permission.json",
            "permission_receipt_sha256": "sha256:" + "b" * 64, "reason": "Independent evidence satisfied obligations."}}
        verified = ledger.build_ledger("run1", "attempt-3", [], reviewed, [verify])
        self.assertEqual(verified["claim_states"][0]["status"], "verified")
        for status in ("narrowed", "refuted", "unresolved"):
            blue = deepcopy(verify); blue["to_status"] = status
            blue["authority"].update(job_id="08-blue-team-refutation", attempt_id="blue-" + status,
                                     role_id="blue-team")
            decided = ledger.build_ledger("run1", "attempt-blue-" + status, [], reviewed, [blue])
            self.assertEqual(decided["claim_states"][0]["status"], status)
        illegal = deepcopy(red); illegal["to_status"] = "verified"
        with self.assertRaisesRegex(execution_state.Blocked, "illegal decision transition|not authorized"):
            ledger.build_ledger("run1", "attempt-x", [], prior, [illegal])
        self_verify = deepcopy(verify); self_verify["authority"].update(
            job_id=prior["entries"][0]["producer"]["job_id"], attempt_id=prior["entries"][0]["producer"]["attempt_id"])
        with self.assertRaisesRegex(execution_state.Blocked, "not authorized|self-verify"):
            ledger.build_ledger("run1", "attempt-x", [], reviewed, [self_verify])
        stale = deepcopy(verify); stale["authority"]["component_generation"] = "component-stale"
        with self.assertRaisesRegex(execution_state.Blocked, "stale or mixed"):
            ledger.build_ledger("run1", "attempt-x", [], reviewed, [stale])
        two = ledger.build_ledger("run1", "attempt-two", self.candidates()[:2])
        old, replacement = [item["claim_id"] for item in two["claim_states"]]
        supersede = {"claim_id": old, "to_status": "superseded", "supersedes_claim_id": replacement,
            "causal_claim_ids": [replacement], "authority": {"job_id": ledger.JOB,
                "attempt_id": "ledger-decision-1", "role_id": "claim-ledger-custodian",
                "source_generation": two["source_generation"], "component_generation": two["component_generation"],
                "artifact_path": "data/jobs/claim-ledger-routing/decisions/supersede.json",
                "artifact_sha256": "sha256:" + "e" * 64, "permission_receipt_path": "permission.json",
                "permission_receipt_sha256": "sha256:" + "f" * 64, "reason": "A narrower replacement exists."}}
        superseded = ledger.build_ledger("run1", "attempt-super", [], two, [supersede])
        self.assertEqual({item["claim_id"]: item["status"] for item in superseded["claim_states"]}[old], "superseded")
        self.assertNotIn(old, {item["claim_id"] for item in ledger.work_routing(superseded)["routes"]})

    def test_promotion_text_fields_and_owasp_promotion_flags_fail_closed(self):
        candidate = self.candidates()[0]; candidate["hypothesis"] = "Verified finding with severity: high"
        with self.assertRaisesRegex(execution_state.Blocked, "promoted claim"):
            ledger.build_ledger("run1", "attempt-1", [candidate])
        source = deepcopy(self.owasp_source); source["artifact"]["routes"][0]["finding_created"] = True
        with self.assertRaisesRegex(execution_state.Blocked, "promotes|invalid OWASP route source"):
            ledger.owasp_candidates(source)

    def test_contract_policy_receipts_and_owned_records(self):
        contract = json.loads((ROOT / "registry/output-contracts/claim-ledger-core.json").read_text())
        policy = validate_job_output.CLAIM_CLASS_POLICIES["claim-ledger-core"]
        self.assertEqual(policy["claim_class_id"], contract["claim_class"]["claim_class_id"])
        self.assertEqual(policy["allowed_assertions"], set(contract["claim_class"]["allowed_assertions"]))
        value = ledger.build_ledger("run1", "attempt-1", self.candidates())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory); execution_state.atomic_json(path / ledger.LEDGER, value)
            self.assertEqual(validate_job_output.validate_contract_result(path, contract, run_id="run1"), [])
        inputs = {"run_id": "run1", "sources": [self.threat_source, self.owasp_source]}
        permission, lineage = ledger._receipts(inputs, value)
        self.assertEqual(permission["permissions"], ledger.PERMISSIONS)
        self.assertEqual(lineage["source_snapshot_sha256"], value["source_generation"])
        store = SchemaStore()
        records = (("job-templates/claim-ledger-routing.json", "job-template.schema.json"),
            ("roles/claim-ledger-custodian.json", "role.schema.json"),
            ("domains/claim-ledger-lifecycle.json", "domain.schema.json"),
            ("tooling-profiles/hash-linked-claim-ledger.json", "tooling-profile.schema.json"),
            ("output-contracts/claim-ledger-core.json", "output-contract.schema.json"))
        for relative, schema in records:
            record = json.loads((ROOT / "registry" / relative).read_text())
            self.assertEqual(validate_document(record, schema, store), [], relative)
        def assert_closed(value, path="$", parent=None):
            if isinstance(value, dict):
                if value.get("type") == "object" or "properties" in value:
                    self.assertFalse(value.get("additionalProperties", True), path)
                for key, item in value.items(): assert_closed(item, f"{path}.{key}", value)
            elif isinstance(value, list):
                for index, item in enumerate(value): assert_closed(item, f"{path}[{index}]", parent)
        for name in ("claim-ledger-citation.schema.json", "claim-ledger-entry.schema.json",
                     "claim-decision-ledger.schema.json", "claim-ledger-work-routing.schema.json"):
            assert_closed(store.load(name))

    def test_nominal_worker_publishes_common_envelope_and_canonical_receipts(self):
        inputs = {"run_id": "run1", "sources": [deepcopy(self.threat_source)], "code": ledger._code_hashes()}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "claim-ledger-routing"
            with mock.patch.object(ledger, "root", return_value=base), \
                 mock.patch.object(ledger, "current_inputs", return_value=deepcopy(inputs)):
                pointer = ledger.run("run1", "dagster-1")
                self.assertEqual(pointer["status"], "OK")
                attempt, envelope = ledger.validate_published(base, pointer,
                    "sha256:" + ledger.digest(inputs), expected_run_id="run1", expected_job_id=ledger.JOB)
                ledger._validate_attempt(attempt, inputs)
                self.assertEqual(envelope["output_contract"], ledger.CONTRACT)
                self.assertEqual(execution_state.read_json(attempt / "permission.json")["permissions"], ledger.PERMISSIONS)
                self.assertEqual(execution_state.read_json(attempt / ledger.ROUTING)["routes"][0]["authorization"],
                                 "not_authorized")


if __name__ == "__main__": unittest.main()
