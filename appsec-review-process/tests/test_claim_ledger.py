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
from publish_job_output import ACCEPTED_SCHEMA, artifact_records, terminal_envelope


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

    def publish_decision(self, jobs: Path, producer: str, claim_id: str, status: str,
                         source_generation: str, component_generation: str, attempt_id: str | None = None,
                         citations: list[dict] | None = None):
        attempt_id = attempt_id or producer.split("-")[0] + "-1"
        specifications = {
            "07-red-team-adversarial": ("red-team-adversarial.json", "hypotheses", "reviewer",
                                        "red-team-adversary"),
            "08-blue-team-refutation": ("blue-team-refutation.json", "reviews", "blue_reviewer",
                                       "blue-team-refuter"),
            "09-independent-verification": ("independent-verification.json", "verifications", "verifier",
                                            "independent-verifier"),
        }
        artifact, collection, actor_field, role = specifications[producer]
        base = jobs / producer; attempt = base / "attempts" / attempt_id
        attempt.mkdir(parents=True)
        actor = {"job_id": producer, "attempt_id": attempt_id, "role_id": role,
                 "source_generation": source_generation, "component_generation": component_generation}
        citation_field = {"07-red-team-adversarial": "review_citations",
                          "08-blue-team-refutation": "refutation_citations",
                          "09-independent-verification": "verification_citations"}[producer]
        result = {"schema": "fixture", "run_id": "run1", "stage": producer,
                  "claim_boundary": "DECISION_RECORD_NOT_RUNTIME_OR_COMPLIANCE_PROOF",
                  collection: [{"claim_id": claim_id, "status": status,
                                "source_generation": source_generation,
                                "component_generation": component_generation, actor_field: actor,
                                citation_field: deepcopy(citations or []), "dissent_ids": [], "causal_claim_ids": [],
                                "supersedes_claim_id": None, "confidence": "medium"}]}
        permission = {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": "run1",
                      "job_id": producer, "source_snapshot_sha256": source_generation,
                      "permissions": ["read-run-data", "write-run-data"]}
        execution_state.atomic_json(attempt / artifact, result)
        execution_state.atomic_json(attempt / "permission.json", permission)
        execution_state.atomic_json(attempt / "status.json", {"status": "OK"})
        envelope = terminal_envelope(run_id="run1", job_id=producer, attempt_id=attempt_id,
            worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
            input_fingerprint="sha256:" + "a" * 64, output_contract=producer,
            started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z",
            summary="fixture", artifacts=artifact_records(attempt, [artifact, "permission.json", "status.json"]), gaps=[])
        execution_state.atomic_json(attempt / "result.json", envelope)
        execution_state.atomic_json(base / "latest.json", {"attempt_id": attempt_id})
        pointer = {"schema": ACCEPTED_SCHEMA, "status": "OK", "run_id": "run1", "job": producer,
                   "attempt_id": attempt_id, "fingerprint": "sha256:" + "a" * 64,
                   "envelope_path": "result.json", "envelope_sha256": execution_state.file_hash(attempt / "result.json"),
                   "hashes": execution_state.tree_hashes(attempt), "accepted_at": "2026-01-01T00:00:02Z"}
        execution_state.atomic_json(base / "accepted.json", pointer)
        return base, attempt

    def decision_schema_gate(self, value, schema):
        if schema in ledger.DECISION_SCHEMAS.values():
            allowed = {"schema", "run_id", "stage", "claim_boundary", "hypotheses", "reviews", "verifications"}
            unknown = set(value) - allowed
            return ["unknown field: " + sorted(unknown)[0]] if unknown else []
        return validate_document(value, schema)

    def reseal_decision(self, base: Path, attempt: Path, changed_artifact: str):
        envelope = execution_state.read_json(attempt / "result.json")
        for item in envelope["artifacts"]:
            if item["path"] == changed_artifact:
                item["sha256"] = execution_state.file_hash(attempt / changed_artifact)
        execution_state.atomic_json(attempt / "result.json", envelope)
        pointer = execution_state.read_json(base / "accepted.json")
        pointer["envelope_sha256"] = execution_state.file_hash(attempt / "result.json")
        pointer["hashes"] = execution_state.tree_hashes(attempt)
        execution_state.atomic_json(base / "accepted.json", pointer)

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
        missing = deepcopy(value); missing["entries"][-1]["causal_claim_ids"] = ["claim-" + "f" * 24]
        missing["entries"][-1]["event_id"] = ledger._event_id(missing["entries"][-1])
        missing["entries"][-1]["entry_hash"] = ledger._entry_hash(missing["entries"][-1])
        self.assertTrue(any("does not resolve" in error for error in ledger.validate_ledger(missing)))

    def test_rehashed_route_claim_and_event_identity_forgeries_are_rejected(self):
        value = ledger.build_ledger("run1", "attempt-1", self.candidates()[:1])
        route = deepcopy(value); entry = route["entries"][0]; entry["route_id"] = "forged-route"
        entry["event_id"] = ledger._event_id(entry); entry["entry_hash"] = ledger._entry_hash(entry)
        route["head_hash"] = entry["entry_hash"]
        self.assertTrue(any("claim id differs" in error for error in ledger.validate_ledger(route)))
        event = deepcopy(value); event["entries"][0]["event_id"] = "event-" + "f" * 24
        event["entries"][0]["entry_hash"] = ledger._entry_hash(event["entries"][0])
        event["head_hash"] = event["entries"][0]["entry_hash"]
        self.assertIn("event id differs from canonical content", ledger.validate_ledger(event))

    def test_decision_loader_rejects_missing_traversal_symlink_and_resealed_forgery(self):
        prior = ledger.build_ledger("run1", "attempt-1", self.candidates()[:1])
        claim = prior["claim_states"][0]["claim_id"]
        request = {"claim_id": claim, "producer_job_id": "09-independent-verification"}
        attacker = {**request, "citations": [{"citation_id": "nonexistent"}],
                    "reason": "attacker supplied authority"}
        with self.assertRaisesRegex(execution_state.Blocked, "shape is not closed"):
            ledger.build_ledger("run1", "next", [], prior, [attacker], Path("/not-used"))
        with tempfile.TemporaryDirectory() as directory:
            jobs = Path(directory) / "jobs"
            base, attempt = self.publish_decision(jobs, "09-independent-verification", claim, "VERIFIED",
                prior["source_generation"], prior["component_generation"], "verify-1")
            (attempt / "permission.json").unlink()
            pointer = execution_state.read_json(base / "accepted.json")
            pointer["hashes"] = execution_state.tree_hashes(attempt)
            execution_state.atomic_json(base / "accepted.json", pointer)
            with self.assertRaisesRegex(execution_state.Blocked, "missing|changed"):
                ledger.build_ledger("run1", "next", [], prior, [request], jobs)
        with tempfile.TemporaryDirectory() as directory:
            jobs = Path(directory) / "jobs"
            base, _ = self.publish_decision(jobs, "09-independent-verification", claim, "VERIFIED",
                prior["source_generation"], prior["component_generation"], "verify-1")
            pointer = execution_state.read_json(base / "accepted.json"); pointer["attempt_id"] = "../escape"
            execution_state.atomic_json(base / "accepted.json", pointer)
            execution_state.atomic_json(base / "latest.json", {"attempt_id": "../escape"})
            with self.assertRaisesRegex(execution_state.Blocked, "escapes|canonical"):
                ledger.build_ledger("run1", "next", [], prior, [request], jobs)
        with tempfile.TemporaryDirectory() as directory:
            jobs = Path(directory) / "jobs"
            base, attempt = self.publish_decision(jobs, "09-independent-verification", claim, "VERIFIED",
                prior["source_generation"], prior["component_generation"], "verify-1")
            outside = Path(directory) / "outside.json"; outside.write_text("{}")
            (attempt / "permission.json").unlink(); (attempt / "permission.json").symlink_to(outside)
            with self.assertRaisesRegex(execution_state.Blocked, "unsafe|symbolic|changed"):
                ledger.build_ledger("run1", "next", [], prior, [request], jobs)
        with tempfile.TemporaryDirectory() as directory:
            jobs = Path(directory) / "jobs"
            base, attempt = self.publish_decision(jobs, "09-independent-verification", claim, "VERIFIED",
                prior["source_generation"], prior["component_generation"], "verify-1")
            result = execution_state.read_json(attempt / "independent-verification.json")
            result["verifications"][0]["verifier"]["attempt_id"] = "forged-resealed"
            execution_state.atomic_json(attempt / "independent-verification.json", result)
            self.reseal_decision(base, attempt, "independent-verification.json")
            with self.assertRaisesRegex(execution_state.Blocked, "actor"):
                with mock.patch.object(ledger, "validate_document", side_effect=self.decision_schema_gate):
                    ledger.build_ledger("run1", "next", [], prior, [request], jobs)
        with tempfile.TemporaryDirectory() as directory:
            jobs = Path(directory) / "jobs"
            base, attempt = self.publish_decision(jobs, "09-independent-verification", claim, "VERIFIED",
                prior["source_generation"], prior["component_generation"], "verify-1")
            permission = execution_state.read_json(attempt / "permission.json")
            permission["permissions"] = ["read-run-data", "write-run-data", "target-execution"]
            execution_state.atomic_json(attempt / "permission.json", permission)
            self.reseal_decision(base, attempt, "permission.json")
            with self.assertRaisesRegex(execution_state.Blocked, "permission"):
                with mock.patch.object(ledger, "validate_document", side_effect=self.decision_schema_gate):
                    ledger.build_ledger("run1", "next", [], prior, [request], jobs)
        with tempfile.TemporaryDirectory() as directory:
            jobs = Path(directory) / "jobs"
            base, attempt = self.publish_decision(jobs, "09-independent-verification", claim, "VERIFIED",
                prior["source_generation"], prior["component_generation"], "verify-1")
            result = execution_state.read_json(attempt / "independent-verification.json")
            result["severity"] = "CRITICAL"
            execution_state.atomic_json(attempt / "independent-verification.json", result)
            self.reseal_decision(base, attempt, "independent-verification.json")
            with self.assertRaisesRegex(execution_state.Blocked, "closed contract schema"):
                with mock.patch.object(ledger, "validate_document", side_effect=self.decision_schema_gate):
                    ledger.build_ledger("run1", "next", [], prior, [request], jobs)

    def test_authorized_decisions_append_and_illegal_or_self_verifying_decisions_fail(self):
        prior = ledger.build_ledger("run1", "attempt-1", self.candidates()[:1])
        claim = prior["claim_states"][0]["claim_id"]
        with tempfile.TemporaryDirectory() as directory:
            jobs = Path(directory) / "jobs"
            red_base, red_attempt = self.publish_decision(jobs, "07-red-team-adversarial", claim, "HYPOTHESIS",
                                  prior["source_generation"], prior["component_generation"], "red-1",
                                  prior["entries"][0]["citations"])
            red = {"claim_id": claim, "producer_job_id": "07-red-team-adversarial"}
            with mock.patch.object(ledger, "validate_document", side_effect=self.decision_schema_gate):
                reviewed = ledger.build_ledger("run1", "attempt-2", [], prior, [red], jobs)
            self.assertEqual(reviewed["claim_states"][0]["status"], "under_review")
            self.assertEqual(reviewed["entries"][-1]["citations"], prior["entries"][0]["citations"])
            forged = execution_state.read_json(red_attempt / "red-team-adversarial.json")
            forged["hypotheses"][0]["review_citations"][0]["observed_fact"] = "Contradictory reuse."
            execution_state.atomic_json(red_attempt / "red-team-adversarial.json", forged)
            self.reseal_decision(red_base, red_attempt, "red-team-adversarial.json")
            with self.assertRaisesRegex(execution_state.Blocked, "contradictory decision citation"):
                with mock.patch.object(ledger, "validate_document", side_effect=self.decision_schema_gate):
                    ledger.build_ledger("run1", "attempt-forged", [], prior, [red], jobs)
            self.publish_decision(jobs, "09-independent-verification", claim, "VERIFIED",
                                  prior["source_generation"], prior["component_generation"], "verify-1")
            verify = {"claim_id": claim, "producer_job_id": "09-independent-verification"}
            with mock.patch.object(ledger, "validate_document", side_effect=self.decision_schema_gate):
                verified = ledger.build_ledger("run1", "attempt-3", [], reviewed, [verify], jobs)
            self.assertEqual(verified["claim_states"][0]["status"], "verified")
            for upstream, expected in (("SURVIVING", "narrowed"), ("REFUTED", "refuted"),
                                       ("UNRESOLVED", "unresolved")):
                self.publish_decision(jobs, "08-blue-team-refutation", claim, upstream,
                                      prior["source_generation"], prior["component_generation"], "blue-" + expected)
                blue = {"claim_id": claim, "producer_job_id": "08-blue-team-refutation"}
                with mock.patch.object(ledger, "validate_document", side_effect=self.decision_schema_gate):
                    decided = ledger.build_ledger("run1", "attempt-blue-" + expected, [], reviewed, [blue], jobs)
                self.assertEqual(decided["claim_states"][0]["status"], expected)
            with self.assertRaisesRegex(execution_state.Blocked, "exact accepted"):
                ledger.build_ledger("run1", "attempt-x", [], reviewed, [verify])

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
