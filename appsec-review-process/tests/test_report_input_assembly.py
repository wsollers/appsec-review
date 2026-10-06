import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import demo_report_fixture
import report_input_assembly as report
import tool_evidence_fixture
from execution_state import Blocked, atomic_json, digest, file_hash, tree_hashes
from schema_validate import validate_document as validate_schema
from validate_job_output import NO_ORCHESTRATION_FACTS, validate_job_output
from worker_result import artifact_records, terminal_envelope

RUN_ID = "report-run"
SOURCE = "sha256:" + "a" * 64
COMPONENT_ATTEMPT = "component-1"
CLAIM = "claim-" + digest({"route_id": "route-1", "producer": "03-threat-model-dfd-stride",
    "attempt": "threat-1", "artifact": "sha256:" + "c" * 64,
    "source_generation": SOURCE, "component_generation": COMPONENT_ATTEMPT})[:24]


class SourceSnapshotCitationTests(unittest.TestCase):
    """Run 20261006T150309Z-fdd8d6: 03 cites target files as producer 00-intake, attempt source-snapshot."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.jobs = base / "run" / "data" / "jobs"
        (self.jobs / "00-intake" / "whole" / "attempts" / "intake-1").mkdir(parents=True)
        self.target = base / "target"
        (self.target / "src").mkdir(parents=True)
        (self.target / "src" / "store.h").write_text("char buf[8];\n")
        (base / "run" / "inputs").mkdir(parents=True)
        atomic_json(base / "run" / "inputs" / "artifact-manifest.json", {"target": {"repo_path": str(self.target)}})
        self.sha = "sha256:" + file_hash(self.target / "src" / "store.h")

    def tearDown(self):
        self.temp.cleanup()

    def verify(self, path, sha=None):
        return report._verify_citation(self.jobs, ("00-intake", "source-snapshot", path, sha or self.sha))

    def test_target_file_citation_resolves_against_the_staged_checkout(self):
        self.assertEqual(self.verify("src/store.h"), {"producer_job_id": "00-intake",
            "producer_attempt_id": "source-snapshot", "artifact_path": "src/store.h", "artifact_sha256": self.sha})

    def test_changed_missing_or_escaping_target_file_blocks(self):
        with self.assertRaisesRegex(Blocked, "bytes changed"):
            self.verify("src/store.h", "sha256:" + "0" * 64)
        for path in ("src/absent.h", "../run/inputs/artifact-manifest.json", "/etc/passwd", ".git/config"):
            with self.assertRaises(Blocked):
                self.verify(path)


class ReportInputAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.schema_patcher = patch.object(report, "validate_document", side_effect=self._validation)
        self.schema_patcher.start()
        self.jobs = Path(self.temp.name) / "data" / "jobs"
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
                verified = self.documents["verification"]["independent-verification.json"]["verifications"][0]
                common = ("claim_id", "route_id", "claim_class", "hypothesis", "confidence", "component_ids",
                    "component_generation", "source_generation", "producer", "citations", "proof_obligations",
                    "dissent_ids", "causal_claim_ids", "supersedes_claim_id", "hypothesis_id")
                keep = {key: copy.deepcopy(verified[key]) for key in common}
                if job == "07-red-team-adversarial":
                    row = {**keep, "status": "HYPOTHESIS", "attacker_case": "Bounded fixture attacker case.",
                           "reviewer": copy.deepcopy(verified["red_reviewer"]),
                           "review_citations": copy.deepcopy(verified["citations"])}
                    schema = "appsec-review/red-team-adversarial/1.0"
                else:
                    row = {**keep, "status": "SURVIVING", "attacker_case": "Bounded fixture attacker case.",
                           "red_reviewer": copy.deepcopy(verified["red_reviewer"]),
                           "blue_reviewer": copy.deepcopy(verified["blue_reviewer"]),
                           "refutation_rationale": "Fixture obligations survived refutation.",
                           "refutation_citations": copy.deepcopy(verified["citations"])}
                    schema = "appsec-review/blue-team-refutation/1.0"
                document = {"schema": schema, "run_id": RUN_ID, "stage": job,
                    "ledger_head_id": origin["event_id"], "ledger_head_sha256": origin["entry_hash"],
                    "upstream": {"job_id": "fixture-upstream", "attempt_id": "fixture-1",
                        "pointer_sha256": "sha256:" + "1" * 64, "artifact_path": "upstream.json",
                        "artifact_sha256": "sha256:" + "2" * 64},
                    "claim_boundary": "DECISION_RECORD_NOT_RUNTIME_OR_COMPLIANCE_PROOF",
                    collection: [row]}
            stage_pointers[job] = self._publish_job(job, job, attempt_id, {artifact: document},
                inputs=demo_report_fixture.stage_inputs(self.jobs, RUN_ID, job, SOURCE, document[collection],
                                                        document["upstream"]))
        ledger["entries"][1]["decision_authority"] = self._authority(
            stage_pointers["07-red-team-adversarial"], "red-team-adversarial.json", "red-team-adversary")
        ledger["entries"][2]["decision_authority"] = self._authority(
            stage_pointers["08-blue-team-refutation"], "blue-team-refutation.json", "blue-team-refuter")
        ledger["entries"][3]["decision_authority"] = self._authority(
            stage_pointers["09-independent-verification"], "independent-verification.json", "independent-verifier")
        ledger["head_hash"] = self._rehash_entries(ledger["entries"])
        ledger["claim_states"] = [{"claim_id": CLAIM,
            "latest_event_id": ledger["entries"][-1]["event_id"], "status": "verified"}]
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
            entry["event_id"] = "event-" + digest({key: value for key, value in entry.items()
                if key not in {"event_id", "entry_hash"}})[:24]
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
        # Real reviewer identities: the reviewer-pool request (claim_review_derive.actor).
        red_actor = demo_report_fixture.reviewer_actor(RUN_ID, "07-red-team-adversarial", SOURCE, COMPONENT_ATTEMPT)
        blue_actor = demo_report_fixture.reviewer_actor(RUN_ID, "08-blue-team-refutation", SOURCE, COMPONENT_ATTEMPT)
        verifier = demo_report_fixture.reviewer_actor(RUN_ID, "09-independent-verification", SOURCE,
                                                      COMPONENT_ATTEMPT)
        inherited = {"claim_id": CLAIM, "route_id": "route-1", "claim_class": "candidate_only",
            "hypothesis": "A bounded fixture hypothesis.", "confidence": "medium",
            "component_ids": ["component-1"], "source_generation": SOURCE,
            "component_generation": COMPONENT_ATTEMPT, "producer": producer,
            "citations": [self._citation()],
            "proof_obligations": [{"obligation_id": "obligation-1", "statement": "Verify fixture.",
                                   "status": "SATISFIED", "citations": [self._citation()]}],
            "dissent_ids": ["dissent-1"], "causal_claim_ids": [], "supersedes_claim_id": None}
        verification_record = {**inherited, "hypothesis_id": "hyp_" + "4" * 20,
            "status": "VERIFIED", "red_reviewer": red_actor, "blue_reviewer": blue_actor,
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

    def _publish_job(self, job, contract, attempt_id, documents, receipts=True, inputs=None):
        base = self.jobs / job
        attempt = base / "attempts" / attempt_id
        attempt.mkdir(parents=True)
        for relative, document in documents.items(): atomic_json(attempt / relative, document)
        if receipts:
            permission = {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": RUN_ID,
                "job_id": job, "source_snapshot_sha256": SOURCE,
                "permissions": report.CANONICAL_PERMISSIONS[job]}
            lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": RUN_ID,
                "job_id": job, "source_snapshot_sha256": SOURCE, "build_lineage_sha256": "sha256:" + "e" * 64}
            if inputs is not None and "pool_binding" in inputs:   # a 07/08/09 stage binds its reviewer pool
                lineage = demo_report_fixture.stage_lineage(inputs)
            atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        if inputs is not None: atomic_json(attempt / "inputs.json", inputs)
        atomic_json(attempt / "status.json", {"status": "OK"})
        paths = [*documents, *(report.RECEIPTS if receipts else ()), "status.json"]
        fingerprint = "sha256:" + "f" * 64 if inputs is None else report._sha(inputs)
        envelope = terminal_envelope(run_id=RUN_ID, job_id=job, attempt_id=attempt_id,
            worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
            input_fingerprint=fingerprint, output_contract=contract,
            started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z",
            summary="fixture", artifacts=artifact_records(attempt, paths))
        atomic_json(attempt / "result.json", envelope)
        atomic_json(base / "latest.json", {"attempt_id": attempt_id, "updated_at": "2026-01-01T00:00:02Z"})
        pointer = {"schema": "appsec-review/accepted-worker-result/1.0", "status": "OK",
            "run_id": RUN_ID, "job": job, "attempt_id": attempt_id,
            "fingerprint": fingerprint, "envelope_path": "result.json",
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

    def test_fully_resealed_stage_outcome_cannot_forge_ledger_status(self):
        loaded = self.load()
        base = self.jobs / "08-blue-team-refutation"
        attempt = base / "attempts" / "blue-1"
        artifact = attempt / "blue-team-refutation.json"
        document = json.loads(artifact.read_text())
        document["reviews"][0]["status"] = "REFUTED"
        atomic_json(artifact, document)
        envelope_path = attempt / "result.json"
        envelope = json.loads(envelope_path.read_text())
        next(item for item in envelope["artifacts"] if item["path"] == artifact.name)["sha256"] = file_hash(artifact)
        atomic_json(envelope_path, envelope)
        pointer_path = base / "accepted.json"
        pointer = json.loads(pointer_path.read_text())
        pointer["envelope_sha256"] = file_hash(envelope_path)
        pointer["hashes"] = tree_hashes(attempt)
        atomic_json(pointer_path, pointer)
        ledger = loaded["ledger"]["documents"]["claim-decision-ledger.json"]
        authority = ledger["entries"][2]["decision_authority"]
        authority["accepted_pointer_sha256"] = "sha256:" + file_hash(pointer_path)
        authority["envelope_sha256"] = "sha256:" + file_hash(envelope_path)
        authority["artifact_sha256"] = "sha256:" + file_hash(artifact)
        ledger["head_hash"] = self._rehash_entries(ledger["entries"])
        ledger["claim_states"][0]["latest_event_id"] = ledger["entries"][-1]["event_id"]
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

    def test_verified_finding_on_a_structural_record_assembles_and_a_tampered_record_blocks(self):
        """ADR-0035: a tev: verification citation resolves under the run's data/tool-evidence, re-run checked."""
        verifier = demo_report_fixture.reviewer_actor(RUN_ID, "09-independent-verification", SOURCE,
                                                      COMPONENT_ATTEMPT)["attempt_id"]
        citation, path = tool_evidence_fixture.record(self.jobs.parent, "09-independent-verification", verifier)
        loaded = self.load()
        for name, artifact, field in (("verification", "independent-verification.json", "verifications"),
                                      ("scoring", "scoring-prioritization.json", "priorities")):
            loaded[name]["documents"][artifact][field][0]["verification_citations"] = [citation]
        result = report.assemble(RUN_ID, loaded, self.jobs)
        self.assertIn({"producer_job_id": "09-independent-verification", "producer_attempt_id": verifier,
                       "artifact_path": citation["artifact_path"], "artifact_sha256": citation["artifact_sha256"]},
                      result["evidence_artifacts"])
        edited = copy.deepcopy(loaded)
        edited["verification"]["documents"]["independent-verification.json"]["verifications"][0][
            "verification_citations"] = [{**citation, "observed_fact": "main reaches strcpy"}]
        with self.assertRaisesRegex(Blocked, "tool evidence"):
            report.assemble(RUN_ID, edited, self.jobs)
        record = json.loads(path.read_text()); record["answer"]["rows"] = []
        atomic_json(path, record)
        with self.assertRaisesRegex(Blocked, "tool evidence"):
            report.assemble(RUN_ID, loaded, self.jobs)

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

    def _reseal(self, job, mutate):
        """Re-bind a mutated attempt so only the property under test can reject it."""
        base = self.jobs / job; pointer = json.loads((base / "accepted.json").read_text())
        attempt = base / "attempts" / pointer["attempt_id"]
        envelope = json.loads((attempt / "result.json").read_text())
        paths = mutate(attempt, [item["path"] for item in envelope["artifacts"]])
        envelope["artifacts"] = artifact_records(attempt, paths)
        atomic_json(attempt / "result.json", envelope)
        pointer.update(envelope_sha256=file_hash(attempt / "result.json"), hashes=tree_hashes(attempt))
        atomic_json(base / "accepted.json", pointer)

    def _paginate_owasp(self):
        """Republish 04 exactly as owasp_join_publisher splits it: a manifest plus one page per row."""
        import shutil
        import owasp_join_publisher as publisher
        matrix = copy.deepcopy(self.documents["owasp"]["owasp-control-status-matrix.json"])
        matrix["rows"].append({"row_index": 1, "applicability_status": "applicable", "joined_status": "satisfied"})
        matrix["denominators"] = {"selected": 2, "applicable": 2, "assessed": 2, "satisfied": 2}
        limit = max(len(publisher._json_bytes(publisher._page(matrix, 0, 0, [row]))) for row in matrix["rows"])
        with patch.object(publisher, "PAGE_BYTE_LIMIT", limit), \
                patch.object(publisher, "validate_document", return_value=[]):
            outputs = publisher._partition_matrix(matrix)
        self.assertEqual(len(outputs[publisher.MATRIX_MANIFEST]["pages"]), 2)
        shutil.rmtree(self.jobs / "04-owasp-join-report")
        documents = {**outputs, **{item[0]: self.documents["owasp"][item[0]] for item in report.SPECS["owasp"][4]}}
        self.pointers["owasp"] = self._publish_job("04-owasp-join-report", "owasp-join-report", "owasp-1", documents)
        return matrix

    def test_paginated_owasp_matrix_reassembles_exactly(self):
        matrix = self._paginate_owasp()
        loaded = self.load()
        self.assertEqual(loaded["owasp"]["documents"]["owasp-control-status-matrix.json"], matrix)
        self.assertEqual(loaded["owasp"]["reference"]["artifact_path"], report.MATRIX_MANIFEST)
        result = report.assemble(RUN_ID, loaded, self.jobs)
        self.assertEqual(result["counts"]["owasp_rows"], 2)
        self.assertEqual(result["owasp_denominators"], matrix["denominators"])
        self.assertEqual(validate_schema(result, "synthesis-input.schema.json"), [])
        import synthesis_report
        value, _binding = synthesis_report.load_reference(Path(self.temp.name), RUN_ID, result["inputs"]["owasp"])
        self.assertEqual(value, matrix)

    def test_paginated_owasp_tampered_missing_or_unlisted_page_rejects(self):
        page = report.PAGE_DIRECTORY + "/page-0001.json"
        def tamper(attempt, paths):
            value = json.loads((attempt / page).read_text()); value["rows"][0]["joined_status"] = "not_satisfied"
            atomic_json(attempt / page, value); return paths
        def remove(attempt, paths):
            (attempt / page).unlink(); return [path for path in paths if path != page]
        def unlisted(attempt, paths):
            extra = report.PAGE_DIRECTORY + "/page-0002.json"
            atomic_json(attempt / extra, json.loads((attempt / page).read_text())); return [*paths, extra]
        for mutate in (tamper, remove, unlisted):
            with self.subTest(mutate.__name__):
                self._paginate_owasp(); self._reseal("04-owasp-join-report", mutate)
                with self.assertRaises(Blocked):
                    report.load_accepted(self.pointers["owasp"], run_id=RUN_ID, name="owasp")

    def test_legacy_single_file_owasp_matrix_still_loads(self):
        loaded = report.load_accepted(self.pointers["owasp"], run_id=RUN_ID, name="owasp")
        self.assertEqual(loaded["reference"]["artifact_path"], "owasp-control-status-matrix.json")
        self.assertEqual(loaded["documents"]["owasp-control-status-matrix.json"],
                         self.documents["owasp"]["owasp-control-status-matrix.json"])

    def _receiptless_component(self, source=SOURCE, inputs_source=None):
        import shutil
        component = copy.deepcopy(self.documents["component"]["component-purpose-map.json"])
        component["source_snapshot_sha256"] = source
        lineage = component["evidence_manifest_lineage"]
        inputs = {"job": "01-component-characterization", "run_id": RUN_ID,
                  "source_snapshot_sha256": inputs_source or source,
                  "evidence": {"attempt_id": lineage["producer_attempt_id"],
                               "pointer_sha256": lineage["accepted_pointer_sha256"].removeprefix("sha256:")}}
        shutil.rmtree(self.jobs / "01-component-characterization")
        self.pointers["component"] = self._publish_job("01-component-characterization", "component-map",
            COMPONENT_ATTEMPT, {"component-purpose-map.json": component}, receipts=False, inputs=inputs)

    def test_receiptless_component_binds_generation_from_map_and_inputs(self):
        self._receiptless_component()
        loaded = self.load()
        self.assertEqual(loaded["component"]["source_generation"], SOURCE)
        reference = loaded["component"]["reference"]
        self.assertIsNone(reference["permission_receipt_sha256"]); self.assertIsNone(reference["lineage_receipt_sha256"])
        result = report.assemble(RUN_ID, loaded, self.jobs)
        self.assertEqual(result["source_generation"], SOURCE)
        self.assertEqual(validate_schema(result, "synthesis-input.schema.json"), [])
        import synthesis_report
        with self.assertRaises(Blocked):  # a null receipt never stands for a producer that has receipts
            bad = copy.deepcopy(result["inputs"]["threat"]); bad["permission_receipt_sha256"] = None
            synthesis_report.load_reference(Path(self.temp.name), RUN_ID, bad, receiptless=True)
        value, binding = synthesis_report.load_reference(Path(self.temp.name), RUN_ID,
                                                         result["inputs"]["component"], receiptless=True)
        self.assertEqual(value["source_snapshot_sha256"], SOURCE)
        self.assertIsNone(binding["permission_receipt_sha256"])
        self.assertEqual(validate_schema(binding, "synthesis-upstream-binding.schema.json"), [])
        atomic_json(Path(self.temp.name) / report.RESULT, result)
        with patch.object(synthesis_report, "validate_document", side_effect=self._validation):
            inputs = synthesis_report.load_inputs(Path(self.temp.name), Path(self.temp.name) / report.RESULT)
        self.assertEqual(inputs["limitations"], [report.RECEIPT_GAP])  # the absent receipts are a named gap

    def test_receiptless_component_mismatched_generation_blocks(self):
        other = "sha256:" + "9" * 64
        self._receiptless_component(inputs_source=other)  # map and its own attempt inputs disagree
        with self.assertRaises(Blocked):
            report.load_accepted(self.pointers["component"], run_id=RUN_ID, name="component")
        self._receiptless_component(source=other)  # self-consistent, but a different generation than the rest
        loaded = self.load()
        self.assertEqual(loaded["component"]["source_generation"], other)
        with self.assertRaises(Blocked): report.assemble(RUN_ID, loaded, self.jobs)
        threat = self.jobs / "03-threat-model-dfd-stride"
        self._reseal("03-threat-model-dfd-stride", lambda attempt, paths: [p for p in paths if p != "permission.json"])
        with self.assertRaises(Blocked):  # receiptless is per spec: other producers still need receipts
            report.load_accepted(threat / "accepted.json", run_id=RUN_ID, name="threat")

    def test_reviewer_judgment_fields_on_09_and_12_records_are_accepted(self):
        """ADR-0020/0026: 09 and 12 records may carry cwe_judgments/mitre_refs (and 12 cvss_v4,
        remediation_proposal); any other extra field still rejects."""
        judgment = {"stage": "12-scoring-prioritization", "cwe_id": "CWE-787", "cwe_name": "Out-of-bounds Write",
                    "rationale": "fixture", "cwe_catalog": "committed-curated"}
        def judged(extra):
            def mutate(attempt, paths):
                document = json.loads((attempt / "scoring-prioritization.json").read_text())
                for row in document["priorities"]: row.update(extra)
                atomic_json(attempt / "scoring-prioritization.json", document)
                return paths
            return mutate
        self._reseal("12-scoring-prioritization", judged({"cwe_judgments": [judgment], "remediation_proposal": None}))
        report.assemble(RUN_ID, self.load(), self.jobs)
        verification = copy.deepcopy(self.documents["verification"]["independent-verification.json"])
        keys = set(verification["verifications"][0])
        verification["verifications"][0]["cwe_judgments"] = [judgment]
        report._records(verification, "verifications", "09-independent-verification", keys,
                        report.JUDGMENT_KEYS & {"cwe_judgments", "mitre_refs"})
        verification["verifications"][0]["invented"] = True
        with self.assertRaises(Blocked):
            report._records(verification, "verifications", "09-independent-verification", keys,
                            report.JUDGMENT_KEYS & {"cwe_judgments", "mitre_refs"})
        self._reseal("12-scoring-prioritization", judged({"invented": True}))
        with self.assertRaises(Blocked):
            report.assemble(RUN_ID, self.load(), self.jobs)

    def test_specs_match_producer_output_contracts(self):
        """Static guard: every name a spec requires is one its producer's contract promises."""
        import owasp_join_publisher as publisher
        import registry_paths
        self.assertEqual((report.MATRIX_MANIFEST, report.PAGE_DIRECTORY, *report.PAGINATED["owasp"][1:]),
            (publisher.MATRIX_MANIFEST, publisher.PAGE_DIRECTORY, publisher.SCHEMAS[publisher.MATRIX_MANIFEST],
             publisher.SCHEMAS["matrix_page"]))
        self.assertLessEqual(report.RECEIPTLESS | set(report.PAGINATED), set(report.SPECS))
        for name, (job, contract, primary, _schema, supporting) in report.SPECS.items():
            with self.subTest(name):
                required = set(json.loads(registry_paths.contract(contract).read_text())["required_files"])
                published = report.PAGINATED[name][0] if name in report.PAGINATED else primary
                self.assertIn(published, required)
                self.assertLessEqual({item[0] for item in supporting}, required)
                receipts = set(report.RECEIPTS) <= required
                self.assertEqual(receipts, name not in report.RECEIPTLESS,
                                 f"{contract} receipts disagree with RECEIPTLESS")
                self.assertIn(job, report.CANONICAL_PERMISSIONS)

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
