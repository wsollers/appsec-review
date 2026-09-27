import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import report_input_assembly as report
from execution_state import Blocked, atomic_json, file_hash, tree_hashes
from schema_validate import validate_document as validate_schema
from validate_job_output import NO_ORCHESTRATION_FACTS, validate_job_output
from worker_result import artifact_records, terminal_envelope

RUN_ID = "report-run"
SOURCE = "sha256:" + "a" * 64
COMPONENT_ATTEMPT = "component-1"
CLAIM = "claim-" + "b" * 24


class ReportInputAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.schema_patcher = patch.object(report, "validate_document", side_effect=self._validation)
        self.schema_patcher.start()
        self.jobs = Path(self.temp.name) / "jobs"
        evidence = self.jobs / "evidence-source" / "attempts" / "evidence-1"
        evidence.mkdir(parents=True)
        atomic_json(evidence / "evidence.json", {"observed": "bounded fixture"})
        self.evidence_hash = "sha256:" + file_hash(evidence / "evidence.json")
        self.documents = self._documents()
        self.pointers = {}
        ledger = self.documents["ledger"]["claim-decision-ledger.json"]
        origin = ledger["entries"][0]
        for name in ("verification", "scoring"):
            document = self.documents[name][report.SPECS[name][2]]
            document["ledger_head_id"] = origin["event_id"]
            document["ledger_head_sha256"] = origin["entry_hash"]
        actors = {
            "07-red-team-adversarial": ("red-team-adversarial.json", "hypotheses", "reviewer", "red-team-adversary", "red-1"),
            "08-blue-team-refutation": ("blue-team-refutation.json", "reviews", "blue_reviewer", "blue-team-refuter", "blue-1"),
            "09-independent-verification": ("independent-verification.json", "verifications", "verifier", "independent-verifier", "verification-1"),
        }
        stage_pointers = {}
        for job, (artifact, collection, actor_key, role, attempt_id) in actors.items():
            if job == "09-independent-verification":
                document = self.documents["verification"][artifact]
            else:
                actor = {"job_id": job, "attempt_id": attempt_id, "role_id": role,
                    "source_generation": SOURCE, "component_generation": COMPONENT_ATTEMPT}
                document = {"schema": "fixture", "run_id": RUN_ID, "stage": job,
                    "ledger_head_id": origin["event_id"], "ledger_head_sha256": origin["entry_hash"],
                    "upstream": {}, "claim_boundary": "DECISION_RECORD_NOT_RUNTIME_OR_COMPLIANCE_PROOF",
                    collection: [{"claim_id": CLAIM, actor_key: actor}]}
            stage_pointers[job] = self._publish_job(job, job, attempt_id, {artifact: document})
        ledger["entries"][1]["decision_authority"] = self._authority(
            stage_pointers["07-red-team-adversarial"], "red-team-adversarial.json", "red-team-adversary")
        ledger["entries"][2]["decision_authority"] = self._authority(
            stage_pointers["08-blue-team-refutation"], "blue-team-refutation.json", "blue-team-refuter")
        ledger["entries"][3]["decision_authority"] = self._authority(
            stage_pointers["09-independent-verification"], "independent-verification.json", "independent-verifier")
        ledger["head_hash"] = self._rehash_entries(ledger["entries"])
        for name, spec in report.SPECS.items():
            if name == "verification":
                self.pointers[name] = stage_pointers["09-independent-verification"]
                continue
            artifacts = {spec[2]: self.documents[name][spec[2]]}
            if name == "owasp":
                artifacts.update({item[0]: self.documents[name][item[0]] for item in spec[4]})
            self.pointers[name] = self._publish(name, artifacts)

    def tearDown(self):
        self.schema_patcher.stop()
        self.temp.cleanup()

    def _citation(self):
        return {"citation_id": "citation-1", "producer_job_id": "evidence-source",
                "producer_attempt_id": "evidence-1", "artifact_path": "evidence.json",
                "artifact_sha256": self.evidence_hash, "locator_json": "/observed",
                "observed_fact": "Bounded fixture evidence exists."}

    @staticmethod
    def _rehash_entries(entries):
        previous = None
        for sequence, entry in enumerate(entries):
            entry["sequence"] = sequence
            entry["previous_entry_hash"] = previous
            entry["entry_hash"] = report._sha({key: value for key, value in entry.items() if key != "entry_hash"})
            previous = entry["entry_hash"]
        return previous

    def _documents(self):
        component = json.loads((ROOT / "tests/fixtures/component-characterization/hello-autotools.json").read_text())
        component["source_snapshot_sha256"] = SOURCE
        threat = json.loads((ROOT / "tests/fixtures/threat-workbench/schema/integrated-threat-model.golden.json").read_text())
        threat.update(run_id=RUN_ID, attempt_id="threat-1", source_snapshot=SOURCE,
                      component_map_attempt_id=COMPONENT_ATTEMPT)
        matrix = {"schema": "appsec-review/owasp-control-status-matrix/1.0", "run_id": RUN_ID,
                  "selection_id": "selection-1", "denominators": {"selected": 1, "applicable": 1,
                  "assessed": 1, "satisfied": 1}, "rows": [{"row_index": 0,
                  "applicability_status": "applicable", "joined_status": "satisfied"}],
                  "claim_limits": {"finding_created": False, "severity_assigned": False,
                  "runtime_state_claimed": False, "compliance_certified": False,
                  "status_upgrade_permitted": False}}
        gaps = {"schema": "appsec-review/owasp-coverage-gaps-report/1.0", "run_id": RUN_ID,
                "selection_id": "selection-1", "gaps": [{"gap_id": "gap-1"}]}
        routes = {"schema": "appsec-review/owasp-candidate-promotion-routes/1.0", "run_id": RUN_ID,
                  "selection_id": "selection-1", "finding_promotion": "not_performed", "routes": []}
        producer = {"contract_id": "threat-model-core", "job_id": "03-threat-model-dfd-stride",
                    "attempt_id": "threat-1", "artifact_path": "integrated-threat-model.json",
                    "artifact_sha256": "sha256:" + "c" * 64,
                    "accepted_pointer_sha256": "sha256:" + "d" * 64}
        base = {"event_type": "candidate_admitted", "claim_id": CLAIM, "route_id": "route-1",
                "claim_class": "candidate_only", "hypothesis": "A bounded fixture hypothesis.",
                "status": "candidate", "confidence": "medium", "component_ids": ["component-1"],
                "source_generation": SOURCE, "component_generation": COMPONENT_ATTEMPT,
                "producer": producer, "citations": [self._citation()],
                "proof_obligations": [{"obligation_id": "obligation-1", "statement": "Verify fixture."}],
                "dissent_ids": ["dissent-1"], "causal_claim_ids": [], "supersedes_claim_id": None,
                "from_status": None, "decision_authority": None,
                "sequence": 0, "event_id": "event-" + "1" * 24, "previous_entry_hash": None,
                "entry_hash": ""}
        self._rehash_entries([base])
        review = copy.deepcopy(base); review.update(event_type="status_decision", status="under_review",
            from_status="candidate", event_id="event-" + "2" * 24,
            decision_authority=None)
        narrowed = copy.deepcopy(review); narrowed.update(status="narrowed", from_status="under_review",
            event_id="event-" + "3" * 24, decision_authority=None)
        verified = copy.deepcopy(narrowed); verified.update(status="verified", from_status="narrowed",
            event_id="event-" + "4" * 24, decision_authority=None)
        entries = [base, review, narrowed, verified]
        head = self._rehash_entries(entries)
        ledger = {"schema": "appsec-review/claim-decision-ledger/1.0", "run_id": RUN_ID,
                  "job_id": "claim-ledger-routing", "attempt_id": "ledger-1",
                  "source_generation": SOURCE, "component_generation": COMPONENT_ATTEMPT,
                  "entries": entries, "head_hash": head,
                  "claim_states": [{"claim_id": CLAIM, "latest_event_id": verified["event_id"], "status": "verified"}],
                  "claim_limits": {"candidate_only": True, "finding_created": False,
                  "severity_assigned": False, "runtime_claimed": False, "compliance_claimed": False}}
        verifier = {"job_id": "09-independent-verification", "attempt_id": "verification-1",
            "role_id": "independent-verifier", "source_generation": SOURCE,
            "component_generation": COMPONENT_ATTEMPT}
        inherited = {"claim_id": CLAIM, "route_id": "route-1", "claim_class": "candidate_only",
            "hypothesis": "A bounded fixture hypothesis.", "confidence": "medium",
            "component_ids": ["component-1"], "source_generation": SOURCE,
            "component_generation": COMPONENT_ATTEMPT, "producer": producer,
            "citations": [self._citation()],
            "proof_obligations": [{"obligation_id": "obligation-1", "statement": "Verify fixture.",
                                   "status": "SATISFIED", "citations": [self._citation()]}],
            "dissent_ids": ["dissent-1"], "causal_claim_ids": [], "supersedes_claim_id": None}
        verification_record = {**inherited, "hypothesis_id": "hyp_" + "4" * 20,
            "status": "VERIFIED", "red_reviewer": {"job_id": "07-red-team-adversarial", "attempt_id": "red-1",
                "role_id": "red-team-adversary", "source_generation": SOURCE,
                "component_generation": COMPONENT_ATTEMPT},
            "blue_reviewer": {"job_id": "08-blue-team-refutation", "attempt_id": "blue-1",
                "role_id": "blue-team-refuter", "source_generation": SOURCE,
                "component_generation": COMPONENT_ATTEMPT},
            "verifier": verifier, "verification_method": "Hash-bound fixture verification.",
            "verification_citations": [self._citation()]}
        upstream = {"job_id": "upstream", "attempt_id": "upstream-1",
            "pointer_sha256": "sha256:" + "1" * 64, "artifact_path": "upstream.json",
            "artifact_sha256": "sha256:" + "2" * 64}
        verification = {"schema": "appsec-review/independent-verification/1.0", "run_id": RUN_ID,
            "stage": "09-independent-verification", "ledger_head_id": verified["event_id"],
            "ledger_head_sha256": head, "upstream": upstream,
            "claim_boundary": "DECISION_RECORD_NOT_RUNTIME_OR_COMPLIANCE_PROOF",
            "verifications": [verification_record]}
        priority = {**inherited, "verification_status": "VERIFIED", "verifier": verifier,
            "verification_citations": [self._citation()], "score": 16, "severity": "CRITICAL",
            "priority": "P0", "factors": {"impact": 4, "exploitability": 4, "exposure": 4, "confidence": 4},
            "scoring_rationale": "Deterministic fixture score."}
        scoring = {"schema": "appsec-review/scoring-prioritization/1.0", "run_id": RUN_ID,
            "stage": "12-scoring-prioritization", "ledger_head_id": verified["event_id"],
            "ledger_head_sha256": head, "upstream": upstream,
            "claim_boundary": "DECISION_RECORD_NOT_RUNTIME_OR_COMPLIANCE_PROOF",
            "priorities": [priority]}
        return {"component": {"component-purpose-map.json": component},
            "threat": {"integrated-threat-model.json": threat},
            "owasp": {"owasp-control-status-matrix.json": matrix, "owasp-coverage-gaps.json": gaps,
                      "owasp-candidate-promotion-routes.json": routes},
            "ledger": {"claim-decision-ledger.json": ledger},
            "verification": {"independent-verification.json": verification},
            "scoring": {"scoring-prioritization.json": scoring}}

    def _publish(self, name, documents):
        job, contract, _primary, _schema, _supporting = report.SPECS[name]
        attempt_id = COMPONENT_ATTEMPT if name == "component" else name + "-1"
        return self._publish_job(job, contract, attempt_id, documents)

    def _publish_job(self, job, contract, attempt_id, documents):
        base = self.jobs / job
        attempt = base / "attempts" / attempt_id
        attempt.mkdir(parents=True)
        for relative, document in documents.items(): atomic_json(attempt / relative, document)
        permission = {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": RUN_ID,
            "job_id": job, "source_snapshot_sha256": SOURCE,
            "permissions": report.CANONICAL_PERMISSIONS[job]}
        lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": RUN_ID,
            "job_id": job, "source_snapshot_sha256": SOURCE, "build_lineage_sha256": "sha256:" + "e" * 64}
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        atomic_json(attempt / "status.json", {"status": "OK"})
        paths = [*documents, "permission.json", "lineage.json", "status.json"]
        envelope = terminal_envelope(run_id=RUN_ID, job_id=job, attempt_id=attempt_id,
            worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
            input_fingerprint="sha256:" + "f" * 64, output_contract=contract,
            started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z",
            summary="fixture", artifacts=artifact_records(attempt, paths))
        atomic_json(attempt / "result.json", envelope)
        atomic_json(base / "latest.json", {"attempt_id": attempt_id})
        pointer = {"schema": "appsec-review/accepted-worker-result/1.0", "status": "OK",
            "run_id": RUN_ID, "job": job, "attempt_id": attempt_id,
            "fingerprint": "sha256:" + "f" * 64, "envelope_path": "result.json",
            "envelope_sha256": file_hash(attempt / "result.json"), "hashes": tree_hashes(attempt),
            "accepted_at": "2026-01-01T00:00:02Z"}
        atomic_json(base / "accepted.json", pointer)
        return base / "accepted.json"

    def _authority(self, pointer_path, artifact, role):
        pointer = json.loads(pointer_path.read_text())
        attempt = pointer_path.parent / "attempts" / pointer["attempt_id"]
        return {"contract_id": pointer["job"], "job_id": pointer["job"],
            "attempt_id": pointer["attempt_id"], "role_id": role,
            "source_generation": SOURCE, "component_generation": COMPONENT_ATTEMPT,
            "accepted_pointer_sha256": "sha256:" + file_hash(pointer_path),
            "envelope_sha256": "sha256:" + file_hash(attempt / "result.json"),
            "artifact_path": artifact, "artifact_sha256": "sha256:" + file_hash(attempt / artifact),
            "permission_receipt_path": "permission.json",
            "permission_receipt_sha256": "sha256:" + file_hash(attempt / "permission.json"),
            "reason": "Accepted exact fixture decision."}

    @staticmethod
    def _validation(document, schema):
        if schema.startswith("owasp-") or schema in {"claim-decision-ledger.schema.json",
                "07-red-team-adversarial.schema.json", "08-blue-team-refutation.schema.json",
                "09-independent-verification.schema.json", "scoring-prioritization.schema.json"}:
            return []
        return validate_schema(document, schema)

    def load(self):
        return {name: report.load_accepted(path, run_id=RUN_ID, name=name)
                for name, path in self.pointers.items()}

    def test_nominal_manifest_is_deterministic_hash_bound_and_prose_free(self):
        loaded = self.load()
        first = report.assemble(RUN_ID, loaded, self.jobs)
        second = report.assemble(RUN_ID, loaded, self.jobs)
        self.assertEqual(first, second)
        expected = json.loads((ROOT / "tests/fixtures/report-input-assembly/expected-counts.json").read_text())
        self.assertEqual(first["counts"], expected)
        self.assertEqual(first["owasp_denominators"], {"selected": 1, "applicable": 1, "assessed": 1, "satisfied": 1})
        self.assertEqual(first["evidence_artifacts"], [{"producer_job_id": "evidence-source",
            "producer_attempt_id": "evidence-1", "artifact_path": "evidence.json",
            "artifact_sha256": self.evidence_hash}])
        self.assertNotIn("hypothesis", json.dumps(first))
        self.assertNotEqual(first["ledger_head_sha256"], first["lifecycle_origin_head_sha256"])
        self.assertEqual(first["lifecycle_origin_head_sha256"],
                         self.documents["ledger"]["claim-decision-ledger.json"]["entries"][0]["entry_hash"])
        self.assertEqual(validate_schema(first, "synthesis-input.schema.json"), [])

    def test_noncanonical_permission_and_tampered_decision_authority_reject(self):
        loaded = self.load()
        component = self.pointers["component"].parent
        attempt = component / "attempts" / COMPONENT_ATTEMPT
        permission = json.loads((attempt / "permission.json").read_text())
        permission["permissions"] = ["target-execution"]
        atomic_json(attempt / "permission.json", permission)
        envelope = json.loads((attempt / "result.json").read_text())
        next(item for item in envelope["artifacts"] if item["path"] == "permission.json")["sha256"] = file_hash(attempt / "permission.json")
        atomic_json(attempt / "result.json", envelope)
        pointer = json.loads(self.pointers["component"].read_text())
        pointer["envelope_sha256"] = file_hash(attempt / "result.json")
        pointer["hashes"] = tree_hashes(attempt)
        atomic_json(self.pointers["component"], pointer)
        with self.assertRaises(Blocked):
            report.load_accepted(self.pointers["component"], run_id=RUN_ID, name="component")

        ledger = loaded["ledger"]["documents"]["claim-decision-ledger.json"]
        ledger["entries"][1]["decision_authority"]["accepted_pointer_sha256"] = "sha256:" + "0" * 64
        ledger["head_hash"] = self._rehash_entries(ledger["entries"])
        with self.assertRaises(Blocked): report.assemble(RUN_ID, loaded, self.jobs)

    def test_stale_pointer_missing_receipt_and_external_attempt_symlink_reject(self):
        component_base = self.pointers["component"].parent
        atomic_json(component_base / "latest.json", {"attempt_id": "newer"})
        with self.assertRaises(Blocked): report.load_accepted(self.pointers["component"], run_id=RUN_ID, name="component")
        atomic_json(component_base / "latest.json", {"attempt_id": COMPONENT_ATTEMPT})
        (component_base / "attempts" / COMPONENT_ATTEMPT / "permission.json").unlink()
        with self.assertRaises(Blocked): report.load_accepted(self.pointers["component"], run_id=RUN_ID, name="component")
    def test_external_citation_attempt_symlink_rejects(self):
        loaded = self.load()
        attempts = self.jobs / "evidence-source/attempts"
        external = Path(self.temp.name) / "external-evidence-attempts"
        attempts.rename(external)
        attempts.symlink_to(external, target_is_directory=True)
        with self.assertRaises(Blocked): report.assemble(RUN_ID, loaded, self.jobs)

    def test_mixed_generation_changed_citation_and_self_verification_reject(self):
        loaded = self.load()
        mixed = copy.deepcopy(loaded); mixed["threat"]["source_generation"] = "sha256:" + "9" * 64
        with self.assertRaises(Blocked): report.assemble(RUN_ID, mixed, self.jobs)
        evidence = self.jobs / "evidence-source/attempts/evidence-1/evidence.json"
        atomic_json(evidence, {"observed": "changed"})
        with self.assertRaises(Blocked): report.assemble(RUN_ID, loaded, self.jobs)
        atomic_json(evidence, {"observed": "bounded fixture"})
        hostile = copy.deepcopy(loaded)
        row = hostile["verification"]["documents"]["independent-verification.json"]["verifications"][0]
        row["verifier"] = {"job_id": row["producer"]["job_id"], "attempt_id": row["producer"]["attempt_id"]}
        with self.assertRaises(Blocked): report.assemble(RUN_ID, hostile, self.jobs)

    def test_circular_claims_invalid_upgrade_and_promotion_reject(self):
        loaded = self.load()
        circular = copy.deepcopy(loaded)
        ledger = circular["ledger"]["documents"]["claim-decision-ledger.json"]
        for entry in ledger["entries"]: entry["causal_claim_ids"] = [CLAIM]
        ledger["head_hash"] = self._rehash_entries(ledger["entries"])
        with self.assertRaises(Blocked): report.assemble(RUN_ID, circular, self.jobs)
        invalid = copy.deepcopy(loaded)
        scoring = invalid["scoring"]["documents"]["scoring-prioritization.json"]
        scoring["priorities"][0].update(verification_status="UNRESOLVED", score=12, severity="HIGH")
        with self.assertRaises(Blocked): report.assemble(RUN_ID, invalid, self.jobs)
        promoted = copy.deepcopy(loaded)
        promoted["owasp"]["documents"]["owasp-control-status-matrix.json"]["findings"] = ["not allowed"]
        with self.assertRaises(Blocked): report.assemble(RUN_ID, promoted, self.jobs)

    def test_owned_contract_and_generic_worker_envelope_accept_manifest(self):
        result = report.assemble(RUN_ID, self.load(), self.jobs)
        attempt = Path(self.temp.name) / "assembly-1"
        attempt.mkdir()
        atomic_json(attempt / "synthesis-input.json", result)
        atomic_json(attempt / "status.json", {"process": report.JOB, "status": "OK", "inputs": 6,
                    "claims": 1, "coverage_gaps": 1, "qualification": "implemented_not_qualified"})
        envelope = terminal_envelope(run_id=RUN_ID, job_id=report.JOB, attempt_id="assembly-1",
            worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
            input_fingerprint="sha256:" + "7" * 64, output_contract=report.CONTRACT,
            started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z",
            summary="fixture", artifacts=artifact_records(attempt, ["synthesis-input.json", "status.json"]))
        self.assertEqual(validate_job_output(attempt, envelope, "sha256:" + "7" * 64,
            expected_run_id=RUN_ID, expected_job_id=report.JOB,
            orchestration=NO_ORCHESTRATION_FACTS), [])

    def test_synthesis_schema_is_recursively_closed(self):
        stack = [json.loads((ROOT.parent / "schemas/synthesis-input.schema.json").read_text())]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                if value.get("type") == "object": self.assertIs(value.get("additionalProperties"), False)
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)


if __name__ == "__main__": unittest.main()
