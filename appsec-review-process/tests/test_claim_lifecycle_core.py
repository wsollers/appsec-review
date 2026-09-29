import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import registry_paths

import claim_lifecycle_core as core
from execution_state import Blocked, atomic_json, file_hash, tree_hashes
from schema_validate import validate_document
from validate_job_output import NO_ORCHESTRATION_FACTS, validate_job_output
from worker_result import artifact_records, terminal_envelope

FIXTURES = ROOT / "tests/fixtures/claim-lifecycle"
RUN_ID = "claim-run"


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def binding(job="upstream", artifact="upstream.json"):
    return {"job_id": job, "attempt_id": "upstream-1",
            "pointer_sha256": "sha256:" + "1" * 64, "artifact_path": artifact,
            "artifact_sha256": "sha256:" + "2" * 64}


def actual_ledger():
    source = fixture("claim-ledger.json")
    candidates = copy.deepcopy(source["candidates"])
    identities = {}
    for candidate in candidates:
        old = candidate["claim_id"]
        candidate["claim_id"] = core._admission_claim_id(candidate)
        identities[old] = candidate["claim_id"]
    entries, previous = [], None
    for sequence, candidate in enumerate(candidates):
        candidate["causal_claim_ids"] = [identities[item] for item in candidate["causal_claim_ids"]]
        if candidate["supersedes_claim_id"] is not None:
            candidate["supersedes_claim_id"] = identities[candidate["supersedes_claim_id"]]
        entry = {**candidate, "sequence": sequence, "event_id": "", "event_type": "candidate_admitted",
                 "from_status": None, "decision_authority": None, "previous_entry_hash": previous,
                 "entry_hash": ""}
        entry["event_id"] = core._event_id(entry)
        entry["entry_hash"] = core._sha({key: value for key, value in entry.items() if key != "entry_hash"})
        entries.append(entry); previous = entry["entry_hash"]
    return {"schema": "appsec-review/claim-decision-ledger/1.0", "run_id": RUN_ID,
        "job_id": "claim-ledger-routing", "attempt_id": "ledger-1",
        "source_generation": candidates[0]["source_generation"],
        "component_generation": candidates[0]["component_generation"], "entries": entries,
        "head_hash": previous, "claim_states": [{"claim_id": item["claim_id"],
            "latest_event_id": item["event_id"], "status": "candidate"} for item in entries],
        "claim_limits": {"candidate_only": True, "finding_created": False,
            "severity_assigned": False, "runtime_claimed": False, "compliance_claimed": False}}


def reseal_ledger_content(ledger, *, canonical_events=False):
    previous = None
    for sequence, entry in enumerate(ledger["entries"]):
        entry["sequence"] = sequence; entry["previous_entry_hash"] = previous
        if canonical_events: entry["event_id"] = core._event_id(entry)
        entry["entry_hash"] = core._sha({key: value for key, value in entry.items() if key != "entry_hash"})
        previous = entry["entry_hash"]
    latest = {entry["claim_id"]: entry for entry in ledger["entries"]}
    ledger["head_hash"] = previous
    ledger["claim_states"] = [{"claim_id": key, "latest_event_id": latest[key]["event_id"],
        "status": latest[key]["status"]} for key in sorted(latest)]


class ClaimLifecycleTests(unittest.TestCase):
    def chain(self):
        red = core.red_team(fixture("claim-ledger.json"), binding("claim-ledger-routing", "claim-decision-ledger.json"),
                            fixture("red-decisions.json"))
        blue = core.blue_team(red, binding("07-red-team-adversarial", "red-team-adversarial.json"),
                              fixture("blue-decisions.json"))
        verification = core.verify(blue, binding("08-blue-team-refutation", "blue-team-refutation.json"),
                                   fixture("verification-decisions.json"))
        scoring = core.score(verification,
                             binding("09-independent-verification", "independent-verification.json"),
                             fixture("scoring-decisions.json"))
        return red, blue, verification, scoring

    def test_nominal_chain_is_deterministic_closed_and_preserves_lineage_dissent(self):
        one = self.chain()
        two = self.chain()
        self.assertEqual(one, two)
        schemas = ("07-red-team-adversarial.schema.json", "08-blue-team-refutation.schema.json",
                   "09-independent-verification.schema.json", "scoring-prioritization.schema.json")
        for document, schema in zip(one, schemas):
            self.assertEqual(validate_document(document, schema), [], schema)
            self.assertEqual(document["ledger_head_id"], "entry-2")
            self.assertEqual(document["ledger_head_sha256"], "sha256:" + "d" * 64)
        red, blue, verification, scoring = one
        source = fixture("claim-ledger.json")["candidates"][0]
        for record in (red["hypotheses"][0], blue["reviews"][0],
                       verification["verifications"][0], scoring["priorities"][0]):
            self.assertEqual(record["source_generation"], source["source_generation"])
            self.assertEqual(record["component_generation"], source["component_generation"])
            self.assertEqual(record["citations"], source["citations"])
            self.assertIn(source["dissent_ids"][0], record["dissent_ids"])
        self.assertEqual(scoring["priorities"][0]["severity"], "CRITICAL")
        unresolved = scoring["priorities"][1]
        self.assertEqual((unresolved["verification_status"], unresolved["score"],
                          unresolved["severity"], unresolved["priority"]),
                         ("UNRESOLVED", None, None, "UNRESOLVED"))

    def test_self_review_circular_lineage_and_mixed_generations_fail_closed(self):
        ledger = fixture("claim-ledger.json")
        red = fixture("red-decisions.json")
        red["decisions"][0]["reviewer"] = {"job_id": "03-threat-model-dfd-stride", "attempt_id": "threat-1"}
        with self.assertRaises(Blocked):
            core.red_team(ledger, binding(), red)
        ledger = fixture("claim-ledger.json")
        ledger["candidates"][0]["causal_claim_ids"] = ["claim-bbbbbbbbbbbbbbbbbbbbbbbb"]
        with self.assertRaises(Blocked):
            core.red_team(ledger, binding(), fixture("red-decisions.json"))
        ledger = fixture("claim-ledger.json")
        ledger["candidates"][1]["source_generation"] = "sha256:" + "9" * 64
        with self.assertRaises(Blocked):
            core.red_team(ledger, binding(), fixture("red-decisions.json"))

    def test_missing_obligations_invalid_upgrades_and_nonindependent_verification_fail(self):
        red, blue, _verification, _scoring = self.chain()
        decisions = fixture("blue-decisions.json")
        decisions["decisions"][0]["proof_obligations"] = []
        with self.assertRaises(Blocked):
            core.blue_team(red, binding(), decisions)
        decisions = fixture("verification-decisions.json")
        decisions["decisions"][0]["verifier"] = blue["reviews"][0]["blue_reviewer"]
        with self.assertRaises(Blocked):
            core.verify(blue, binding(), decisions)
        decisions = fixture("verification-decisions.json")
        decisions["decisions"][0]["citations"] = blue["reviews"][0]["citations"]
        decisions["decisions"][0]["proof_obligations"][0]["citations"] = blue["reviews"][0]["citations"]
        with self.assertRaises(Blocked):
            core.verify(blue, binding(), decisions)
        refuted = copy.deepcopy(blue)
        refuted["reviews"][0]["status"] = "REFUTED"
        with self.assertRaises(Blocked):
            core.verify(refuted, binding(), fixture("verification-decisions.json"))

    def test_preverification_promotion_and_unverified_scoring_fail_closed(self):
        red_decisions = fixture("red-decisions.json")
        red_decisions["decisions"][0]["severity"] = "HIGH"
        with self.assertRaises(Blocked):
            core.red_team(fixture("claim-ledger.json"), binding(), red_decisions)
        _red, _blue, verification, _scoring = self.chain()
        scores = fixture("scoring-decisions.json")
        scores["decisions"][1]["factors"] = {"impact": 1, "exploitability": 1, "exposure": 1, "confidence": 1}
        with self.assertRaises(Blocked):
            core.score(verification, binding(), scores)

    def test_closed_contract_result_schemas_reject_promotions_before_verification(self):
        red, blue, verification, scoring = self.chain()
        documents = {
            "07-red-team-adversarial": red,
            "08-blue-team-refutation": blue,
            "09-independent-verification": verification,
            "12-scoring-prioritization": scoring,
        }
        for contract_id, document in documents.items():
            contract = json.loads((ROOT / registry_paths.contract_rel(contract_id)).read_text())
            schema = contract["result_schema"]["schema_file"]
            self.assertEqual(validate_document(document, schema), [])
            hostile = copy.deepcopy(document)
            if contract_id == "12-scoring-prioritization":
                hostile["priorities"][0]["runtime_state"] = "observed"
            else:
                next(value for value in hostile.values() if isinstance(value, list))[0]["severity"] = "HIGH"
            self.assertTrue(validate_document(hostile, schema))

    def test_generic_output_validator_accepts_each_distinct_contract(self):
        documents = self.chain()
        jobs = list(core.STAGES)
        with tempfile.TemporaryDirectory() as folder:
            for job, document in zip(jobs, documents):
                with self.subTest(job=job):
                    attempt = Path(folder) / job
                    attempt.mkdir()
                    result_name = core.STAGES[job][4]
                    atomic_json(attempt / result_name, document)
                    atomic_json(attempt / "permission.json", core.permission_receipt(job, document))
                    atomic_json(attempt / "lineage.json", {
                        "schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": RUN_ID,
                        "job_id": job, "source_snapshot_sha256": core.source_generation(document),
                        "build_lineage_sha256": "sha256:" + "b" * 64})
                    atomic_json(attempt / "status.json", {"process": job, "status": "OK",
                                "result": result_name, "claim_limit": "CONTROL_DECISION_ONLY"})
                    envelope = terminal_envelope(run_id=RUN_ID, job_id=job, attempt_id=job,
                        worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
                        input_fingerprint="sha256:" + "f" * 64, output_contract=job,
                        started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z",
                        summary="fixture", artifacts=artifact_records(
                            attempt, [result_name, "permission.json", "lineage.json", "status.json"]))
                    self.assertEqual(validate_job_output(attempt, envelope, "sha256:" + "f" * 64,
                        expected_run_id=RUN_ID, expected_job_id=job,
                        orchestration=NO_ORCHESTRATION_FACTS), [])

    def test_stable_l01_ledger_is_hash_chain_verified_and_projected(self):
        ledger = actual_ledger()
        projected = core._ledger_view(ledger)
        self.assertEqual([item["route_id"] for item in projected["candidates"]], ["route-a", "route-b"])
        forged = copy.deepcopy(ledger)
        forged["entries"][0]["hypothesis"] = "forged"
        with self.assertRaises(Blocked):
            core._ledger_view(forged)

    def test_fully_rehashed_noncanonical_event_and_duplicate_route_fail_closed(self):
        noncanonical = actual_ledger()
        noncanonical["entries"][0]["event_id"] = "event-" + "f" * 24
        reseal_ledger_content(noncanonical)
        with self.assertRaises(Blocked): core._ledger_view(noncanonical)
        duplicate = actual_ledger()
        duplicate["entries"][1]["route_id"] = duplicate["entries"][0]["route_id"]
        duplicate["entries"][1]["claim_id"] = core._admission_claim_id(duplicate["entries"][1])
        duplicate["entries"][1]["causal_claim_ids"] = []
        reseal_ledger_content(duplicate, canonical_events=True)
        with self.assertRaises(Blocked): core._ledger_view(duplicate)


class AcceptedLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name) / "ledger"
        self.attempt = self.base / "attempts" / "ledger-1"
        self.attempt.mkdir(parents=True)
        atomic_json(self.attempt / "claim-decision-ledger.json", actual_ledger())
        self.reseal()

    def tearDown(self):
        self.temp.cleanup()

    def reseal(self):
        envelope = terminal_envelope(run_id=RUN_ID, job_id="claim-ledger-routing",
            attempt_id="ledger-1", worker_kind="deterministic_python", execution_status="OK",
            acceptance_status="CURRENT", input_fingerprint="sha256:" + "f" * 64,
            output_contract="claim-ledger-core", started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z", summary="ledger",
            artifacts=artifact_records(self.attempt, ["claim-decision-ledger.json"]))
        atomic_json(self.attempt / "result.json", envelope)
        atomic_json(self.base / "latest.json", {"attempt_id": "ledger-1"})
        atomic_json(self.base / "accepted.json", {"schema":"appsec-review/accepted-worker-result/1.0",
            "status":"OK","run_id":RUN_ID,"job":"claim-ledger-routing","attempt_id":"ledger-1",
            "fingerprint":"sha256:" + "f" * 64,"envelope_path":"result.json",
            "envelope_sha256":file_hash(self.attempt / "result.json"),"hashes":tree_hashes(self.attempt),
            "accepted_at":"2026-01-01T00:00:02Z"})

    def test_exact_accepted_ledger_runs_red_stage(self):
        output = Path(self.temp.name) / "red.json"
        decisions = Path(self.temp.name) / "decisions.json"
        decision_value = fixture("red-decisions.json")
        route_claims = {item["route_id"]: item["claim_id"] for item in actual_ledger()["entries"]}
        for item, route_id in zip(decision_value["decisions"], ("route-a", "route-b")):
            item["claim_id"] = route_claims[route_id]
        atomic_json(decisions, decision_value)
        result = core.run_stage("07-red-team-adversarial", self.base / "accepted.json", decisions, output, RUN_ID)
        self.assertEqual(json.loads(output.read_text()), result)
        self.assertEqual(result["upstream"]["attempt_id"], "ledger-1")
        self.assertEqual(json.loads((output.parent / "permission.json").read_text()),
                         core.permission_receipt("07-red-team-adversarial", result))

    def test_exact_accepted_ledger_publishes_atomic_common_envelope_attempt(self):
        decisions = Path(self.temp.name) / "attempt-decisions.json"
        decision_value = fixture("red-decisions.json")
        route_claims = {item["route_id"]: item["claim_id"] for item in actual_ledger()["entries"]}
        for item, route_id in zip(decision_value["decisions"], ("route-a", "route-b")):
            item["claim_id"] = route_claims[route_id]
        atomic_json(decisions, decision_value)
        attempt = Path(self.temp.name) / "red-1"
        published = core.run_attempt("07-red-team-adversarial", self.base / "accepted.json",
            decisions, attempt, RUN_ID, "red-1", "2026-01-01T00:00:03Z",
            "2026-01-01T00:00:04Z")
        self.assertEqual(set(path.name for path in attempt.iterdir()), {
            "red-team-adversarial.json", "permission.json", "lineage.json", "status.json", "result.json"})
        envelope = json.loads((attempt / "result.json").read_text())
        self.assertEqual(envelope["job_id"], "07-red-team-adversarial")
        self.assertEqual(envelope["attempt_id"], "red-1")
        self.assertEqual(published["envelope_sha256"], "sha256:" + file_hash(attempt / "result.json"))
        self.assertEqual(validate_job_output(attempt, envelope, envelope["input_fingerprint"],
            expected_run_id=RUN_ID, expected_job_id="07-red-team-adversarial",
            orchestration=NO_ORCHESTRATION_FACTS), [])
        with self.assertRaises(Blocked):
            core.run_attempt("07-red-team-adversarial", self.base / "accepted.json",
                decisions, attempt, RUN_ID, "red-1", "2026-01-01T00:00:03Z",
                "2026-01-01T00:00:04Z")

    def test_all_four_stages_publish_a_hash_bound_accepted_chain(self):
        jobs_root = Path(self.temp.name) / "jobs"
        upstream_pointer = self.base / "accepted.json"
        stage_specs = [
            ("07-red-team-adversarial", "red-decisions.json", "hypotheses"),
            ("08-blue-team-refutation", "blue-decisions.json", "reviews"),
            ("09-independent-verification", "verification-decisions.json", "verifications"),
            ("12-scoring-prioritization", "scoring-decisions.json", "priorities"),
        ]
        for index, (job, decision_name, records_key) in enumerate(stage_specs, 1):
            decisions = fixture(decision_name)
            if index == 1:
                upstream_rows = actual_ledger()["entries"]
            else:
                prior_job = stage_specs[index - 2][0]
                prior_artifact = core.STAGES[prior_job][4]
                prior_attempt = jobs_root / prior_job / "attempts" / f"attempt-{index - 1}"
                upstream_rows = json.loads((prior_attempt / prior_artifact).read_text())[stage_specs[index - 2][2]]
            claim_ids = [row["claim_id"] for row in sorted(upstream_rows, key=lambda row: row["route_id"])]
            for decision, claim_id in zip(decisions["decisions"], claim_ids):
                decision["claim_id"] = claim_id
            decision_path = Path(self.temp.name) / f"{job}-decisions.json"
            atomic_json(decision_path, decisions)
            base = jobs_root / job
            attempt_id = f"attempt-{index}"
            attempt = base / "attempts" / attempt_id
            core.run_attempt(job, upstream_pointer, decision_path, attempt, RUN_ID, attempt_id,
                f"2026-01-01T00:00:0{index}Z", f"2026-01-01T00:00:1{index}Z")
            envelope = json.loads((attempt / "result.json").read_text())
            atomic_json(base / "latest.json", {"attempt_id": attempt_id})
            atomic_json(base / "accepted.json", {
                "schema": "appsec-review/accepted-worker-result/1.0", "status": "OK",
                "run_id": RUN_ID, "job": job, "attempt_id": attempt_id,
                "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
                "envelope_sha256": file_hash(attempt / "result.json"), "hashes": tree_hashes(attempt),
                "accepted_at": f"2026-01-01T00:00:2{index}Z"})
            upstream_pointer = base / "accepted.json"
        score_attempt = jobs_root / "12-scoring-prioritization" / "attempts" / "attempt-4"
        scoring = json.loads((score_attempt / "scoring-prioritization.json").read_text())
        self.assertEqual(scoring["priorities"][0]["severity"], "CRITICAL")
        self.assertEqual(json.loads((score_attempt / "lineage.json").read_text())["job_id"],
                         "12-scoring-prioritization")

    def test_stale_corrupt_and_resealed_wrong_pointer_fail_closed(self):
        atomic_json(self.base / "latest.json", {"attempt_id": "ledger-new"})
        with self.assertRaises(Blocked):
            core.load_accepted(self.base / "accepted.json", run_id=RUN_ID,
                job_id="claim-ledger-routing", contract="claim-ledger-core",
                artifact="claim-decision-ledger.json", schema=core.LEDGER_SCHEMA)
        atomic_json(self.base / "latest.json", {"attempt_id": "ledger-1"})
        pointer = json.loads((self.base / "accepted.json").read_text())
        pointer["envelope_path"] = "claim-decision-ledger.json"
        atomic_json(self.base / "accepted.json", pointer)
        with self.assertRaises(Blocked):
            core.load_accepted(self.base / "accepted.json", run_id=RUN_ID,
                job_id="claim-ledger-routing", contract="claim-ledger-core",
                artifact="claim-decision-ledger.json", schema=core.LEDGER_SCHEMA)

    def test_external_attempts_symlink_fails_closed(self):
        attempts = self.base / "attempts"
        external = Path(self.temp.name) / "external-attempts"
        attempts.rename(external)
        try:
            attempts.symlink_to(external, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"directory symlinks are unavailable: {exc}")
        with self.assertRaises(Blocked):
            core.load_accepted(self.base / "accepted.json", run_id=RUN_ID,
                job_id="claim-ledger-routing", contract="claim-ledger-core",
                artifact="claim-decision-ledger.json", schema=core.LEDGER_SCHEMA)


class RegistryAndSchemaTests(unittest.TestCase):
    def test_four_distinct_nominal_registry_contracts(self):
        for job, (_upstream_contract, _artifact, _upstream_schema, schema, result) in core.STAGES.items():
            template = json.loads((ROOT / registry_paths.template_rel(job)).read_text())
            contract = json.loads((ROOT / registry_paths.contract_rel(job)).read_text())
            self.assertTrue(template["implemented"])
            self.assertEqual(template["execution"], {
                "worker": "claim_review_lifecycle.py", "arguments": ["--stage", job]})
            self.assertEqual(template["composition"]["output_contract_id"], job)
            self.assertEqual(contract["result_schema"], {"artifact": result, "schema_file": schema})
            self.assertEqual(validate_document(template, "job-template.schema.json"), [])
            self.assertEqual(validate_document(contract, "output-contract.schema.json"), [])

    def test_every_new_object_schema_is_closed(self):
        for path in sorted((ROOT.parent / "schemas").glob("*claim-lifecycle*.schema.json")) + [
                ROOT.parent / "schemas/claim-ledger-input.schema.json",
                ROOT.parent / "schemas/red-team-hypothesis.schema.json",
                ROOT.parent / "schemas/07-red-team-adversarial.schema.json",
                ROOT.parent / "schemas/blue-team-review.schema.json",
                ROOT.parent / "schemas/08-blue-team-refutation.schema.json",
                ROOT.parent / "schemas/independent-verification-record.schema.json",
                ROOT.parent / "schemas/09-independent-verification.schema.json",
                ROOT.parent / "schemas/scored-priority-record.schema.json",
                ROOT.parent / "schemas/scoring-prioritization.schema.json"]:
            stack = [json.loads(path.read_text())]
            while stack:
                value = stack.pop()
                if isinstance(value, dict):
                    if value.get("type") == "object":
                        self.assertIs(value.get("additionalProperties"), False, path.name)
                    stack.extend(value.values())
                elif isinstance(value, list): stack.extend(value)


if __name__ == "__main__": unittest.main()
