import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import claim_lifecycle_core as core
import claim_ledger
import claim_ledger_final as final
import demo_report_fixture
import report_input_assembly as report
from execution_state import Blocked, atomic_json, digest, file_hash, read_json, tree_hashes
from worker_result import artifact_records, terminal_envelope
from test_claim_lifecycle_core import RUN_ID, actual_ledger, fixture
import tool_evidence_fixture

STAGES = (("07-red-team-adversarial", "red-decisions.json", "red-1"),
          ("08-blue-team-refutation", "blue-decisions.json", "blue-1"),
          ("09-independent-verification", "verification-decisions.json", "verify-1"),
          ("12-scoring-prioritization", "scoring-decisions.json", "score-1"))


def accept(base: Path, attempt_id: str) -> Path:
    attempt = base / "attempts" / attempt_id
    envelope = read_json(attempt / "result.json")
    atomic_json(base / "latest.json", {"attempt_id": attempt_id})
    atomic_json(base / "accepted.json", {"schema": "appsec-review/accepted-worker-result/1.0", "status": "OK",
        "run_id": RUN_ID, "job": base.name, "attempt_id": attempt_id, "fingerprint": envelope["input_fingerprint"],
        "envelope_path": "result.json", "envelope_sha256": file_hash(attempt / "result.json"),
        "hashes": tree_hashes(attempt), "accepted_at": "2026-01-01T00:00:09Z"})
    return base / "accepted.json"


def binding(jobs: Path, job: str) -> dict:
    pointer = read_json(jobs / job / "accepted.json")
    artifact = final.SOURCES[job][1]
    return {"job_id": job, "attempt_id": pointer["attempt_id"],
            "pointer_sha256": "sha256:" + file_hash(jobs / job / "accepted.json"), "artifact_path": artifact,
            "artifact_sha256": "sha256:" + file_hash(jobs / job / "attempts" / pointer["attempt_id"] / artifact)}


class FinalLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.jobs = Path(self.temp.name) / "data" / "jobs"
        base = self.jobs / claim_ledger.JOB
        attempt = base / "attempts" / "ledger-1"
        attempt.mkdir(parents=True)
        atomic_json(attempt / claim_ledger.LEDGER, actual_ledger())
        atomic_json(attempt / "result.json", terminal_envelope(run_id=RUN_ID, job_id=claim_ledger.JOB,
            attempt_id="ledger-1", worker_kind="deterministic_python", execution_status="OK",
            acceptance_status="CURRENT", input_fingerprint="sha256:" + "f" * 64,
            output_contract=claim_ledger.CONTRACT, started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z", summary="ledger",
            artifacts=artifact_records(attempt, [claim_ledger.LEDGER])))
        upstream = accept(base, "ledger-1")
        claims = [row["claim_id"] for row in sorted(actual_ledger()["entries"], key=lambda row: row["route_id"])]
        previous = claim_ledger.JOB
        for index, (job, decisions_name, attempt_id) in enumerate(STAGES):
            decisions = fixture(decisions_name)
            field = demo_report_fixture.POOL_ACTOR_KEYS.get(job)
            for index_, (decision, claim_id) in enumerate(zip(decisions["decisions"], claims)):
                decision["claim_id"] = claim_id
                if field:   # the real actor: the reviewer-pool request (claim_review_derive.actor),
                    old = decision[field]   # and the reviewer's own records produced under that id
                    new = demo_report_fixture.reviewer_actor(RUN_ID, job, old["source_generation"],
                                                             old["component_generation"])
                    decision = json.loads(json.dumps(decision).replace(
                        json.dumps(old["attempt_id"]), json.dumps(new["attempt_id"])))
                    decision[field] = new
                    decisions["decisions"][index_] = decision
            atomic_json(Path(self.temp.name) / f"{job}.json", decisions)
            core.run_attempt(job, upstream, Path(self.temp.name) / f"{job}.json",
                             self.jobs / job / "attempts" / attempt_id, RUN_ID, attempt_id,
                             f"2026-01-01T00:00:0{index}Z", f"2026-01-01T00:00:1{index}Z")
            if job in demo_report_fixture.POOL_ACTOR_KEYS:
                self.bind_pool(job, attempt_id, binding(self.jobs, previous))
            upstream = accept(self.jobs / job, attempt_id)
            previous = job
        self.origin = actual_ledger()

    def bind_pool(self, job: str, attempt_id: str, upstream_binding: dict) -> None:
        """Lay the stage attempt out as claim_review_lifecycle publishes it: inputs.json (its digest is
        the fingerprint) and lineage.json bind the accepted reviewer pool whose merge decided the rows."""
        attempt = self.jobs / job / "attempts" / attempt_id
        rows = read_json(attempt / final.SOURCES[job][1])[final.SOURCES[job][3]]
        inputs = demo_report_fixture.stage_inputs(self.jobs, RUN_ID, job, rows[0]["source_generation"],
                                                  rows, upstream_binding)
        atomic_json(attempt / "inputs.json", inputs)
        atomic_json(attempt / "lineage.json", demo_report_fixture.stage_lineage(inputs))
        envelope = read_json(attempt / "result.json")
        envelope["input_fingerprint"] = "sha256:" + digest(inputs)
        envelope["artifacts"] = artifact_records(attempt, [item["path"] for item in envelope["artifacts"]])
        atomic_json(attempt / "result.json", envelope)

    def tearDown(self):
        self.temp.cleanup()

    def republish(self, job: str, mutate) -> None:
        """Rewrite one accepted stage result and re-chain every later stage to it (upstream binding)."""
        names = [item[0] for item in STAGES]
        for index in range(names.index(job), len(names)):
            name, attempt_id = names[index], STAGES[index][2]
            attempt = self.jobs / name / "attempts" / attempt_id
            artifact = final.SOURCES[name][1]
            document = read_json(attempt / artifact)
            if name == job:
                mutate(document)
            else:
                document["upstream"] = binding(self.jobs, names[index - 1])
            atomic_json(attempt / artifact, document)
            envelope = read_json(attempt / "result.json")
            envelope["artifacts"] = artifact_records(attempt, [item["path"] for item in envelope["artifacts"]])
            atomic_json(attempt / "result.json", envelope)
            accept(self.jobs / name, attempt_id)

    def derive(self):
        return final.derive(RUN_ID, "final-1", final.current_inputs(RUN_ID, self.jobs), self.jobs)

    def assert_report_accepts(self, ledger):
        latest = report._validate_ledger(ledger)
        origin = report._lifecycle_origin(ledger)
        self.assertEqual(origin, (self.origin["entries"][-1]["event_id"], self.origin["head_hash"]))
        previous = {}
        for entry in ledger["entries"]:
            if entry["event_type"] == "status_decision":
                report._verify_decision_authority(self.jobs, RUN_ID, entry, ledger["source_generation"],
                                                  ledger["component_generation"], previous[entry["claim_id"]])
            previous[entry["claim_id"]] = entry
        return latest

    def test_l01_plus_07_08_09_12_decisions_form_a_final_ledger_the_report_accepts(self):
        ledger, steps = self.derive()
        count = len(self.origin["entries"])
        self.assertEqual(ledger["entries"][:count], self.origin["entries"])  # L01 bytes and head preserved
        self.assertEqual(ledger["entries"][count]["previous_entry_hash"], self.origin["head_hash"])
        self.assertEqual(claim_ledger.validate_ledger(ledger), [])
        decisions = ledger["entries"][count:]
        self.assertEqual([(entry["decision_authority"]["job_id"], entry["from_status"], entry["status"])
                          for entry in decisions],
                         [("07-red-team-adversarial", "candidate", "under_review")] * 2 +
                         [("08-blue-team-refutation", "under_review", "narrowed"),
                          ("08-blue-team-refutation", "under_review", "unresolved"),
                          ("09-independent-verification", "narrowed", "verified")])
        self.assertEqual(steps["gaps"], [])
        self.assertEqual(steps["concurred"]["09-independent-verification"], 1)  # 09 UNRESOLVED on unresolved
        latest = self.assert_report_accepts(ledger)
        verified = [key for key, entry in latest.items() if entry["status"] == "verified"]
        self.assertEqual(len(verified), 1)
        # 09's new independent citation is merged into the appended entry, and the report accepts it.
        self.assertIn("citation-c", [item["citation_id"] for item in latest[verified[0]]["citations"]])
        self.assertEqual(self.derive(), (ledger, steps))

    def test_claim_a_stage_did_not_decide_is_a_named_gap(self):
        claims = sorted(item["claim_id"] for item in self.origin["claim_states"])
        def drop(collection):
            return lambda document: document.update({collection: [row for row in document[collection]
                                                                  if row["claim_id"] != claims[1]]})
        self.republish("09-independent-verification", drop("verifications"))
        self.republish("12-scoring-prioritization", drop("priorities"))
        ledger, steps = self.derive()
        self.assertEqual(len(steps["gaps"]), 1)
        self.assertIn("09-independent-verification-undecided", steps["gaps"][0])
        self.assertIn(claims[1], steps["gaps"][0])
        self.assertEqual({item["claim_id"]: item["status"] for item in ledger["claim_states"]}[claims[1]], "unresolved")
        self.assert_report_accepts(ledger)

    def test_refutation_09_does_not_confirm_is_a_gap_and_the_claim_stays_open(self):
        """Run 20261006T150309Z-fdd8d6: 08 REFUTED, 09 UNRESOLVED blocked on refuted -> unresolved."""
        refuted = []
        def refute(document):
            row = next(row for row in document["reviews"] if row["status"] == "UNRESOLVED")
            row["status"] = "REFUTED"
            refuted.append(row["claim_id"])
        self.republish("08-blue-team-refutation", refute)
        ledger, steps = self.derive()
        claim = refuted[0]
        self.assertEqual(len(steps["gaps"]), 1)
        self.assertIn("08-blue-team-refutation-refutation-unconfirmed", steps["gaps"][0])
        self.assertIn(claim, steps["gaps"][0])
        count = len(self.origin["entries"])
        chain = [(entry["decision_authority"]["job_id"], entry["from_status"], entry["status"])
                 for entry in ledger["entries"][count:] if entry["claim_id"] == claim]
        self.assertEqual(chain, [("07-red-team-adversarial", "candidate", "under_review"),
                                 ("09-independent-verification", "under_review", "unresolved")])
        self.assertEqual(claim_ledger.validate_ledger(ledger), [])
        self.assert_report_accepts(ledger)

    def test_wrong_authority_blocks_the_job_and_the_report(self):
        def impersonate(document):
            document["reviews"][0]["blue_reviewer"]["role_id"] = "red-team-adversary"
        ledger, _ = self.derive()
        self.republish("08-blue-team-refutation", impersonate)
        with self.assertRaisesRegex(Blocked, "authority"):
            self.derive()
        forged = copy.deepcopy(ledger)
        entry = forged["entries"][len(self.origin["entries"]) + 2]
        entry["decision_authority"]["job_id"] = "09-independent-verification"
        forged["head_hash"] = demo_report_fixture._rehash_entries(forged["entries"])
        forged["claim_states"] = [{"claim_id": item["claim_id"], "status": item["status"],
            "latest_event_id": [row for row in forged["entries"] if row["claim_id"] == item["claim_id"]][-1]["event_id"]}
            for item in forged["claim_states"]]
        with self.assertRaises(Blocked):
            self.assert_report_accepts(forged)

    def test_rationale_prose_is_commentary_and_a_structured_promotion_blocks(self):
        # Run 20261006T150309Z-fdd8d6: an 08 rationale "whether the buffer is fixed-size" blocked the
        # final ledger as an "is fixed" promotion. State comes from the status enum (ADR-0036).
        baseline, _ = self.derive()

        def prose(document):
            for row in document["reviews"]:
                row["refutation_rationale"] = ("Whether the buffer is fixed-size was not checked; upstream says "
                                               "the overflow is fixed and the module is compliant.")
        self.republish("08-blue-team-refutation", prose)
        ledger, steps = self.derive()
        self.assertEqual([entry["status"] for entry in ledger["entries"]],
                         [entry["status"] for entry in baseline["entries"]])
        self.assertEqual(steps["gaps"], [])

        def promote(document):
            document["reviews"][0]["remediation_status"] = "fixed"
        self.republish("08-blue-team-refutation", promote)
        with self.assertRaises(Blocked):
            self.derive()
        with self.assertRaisesRegex(Blocked, "prohibited promoted claim"):
            claim_ledger._reject_promotions({"reviews": [{"remediation_status": "fixed"}]})

    def test_actor_is_the_pool_request_and_that_link_is_rederived_not_trusted(self):
        """Run 20261004T054551Z-357581: real 07/08/09 actors name the reviewer-pool request, not the
        stage attempt. The link is re-derived from the stage's hashed inputs/lineage and its pool."""
        ledger, _ = self.derive()
        red = [entry for entry in ledger["entries"] if entry["status"] == "under_review"][0]
        actor = read_json(self.jobs / "07-red-team-adversarial" / "attempts" / "red-1" /
                          "red-team-adversarial.json")["hypotheses"][0]["reviewer"]
        self.assertNotEqual(actor["attempt_id"], "red-1")
        self.assertEqual(actor["artifact_path"], f"requests/{actor['attempt_id']}.json")
        self.assertEqual(red["decision_authority"]["attempt_id"], "red-1")
        # A well-formed reviewer identity that is not the pool instance which decided the claim.
        stranger = demo_report_fixture.reviewer_actor(RUN_ID, "08-blue-team-refutation",
            actor["source_generation"], actor["component_generation"], label="other")
        self.republish("08-blue-team-refutation",
                       lambda document: document["reviews"][0].update(blue_reviewer=stranger))
        with self.assertRaisesRegex(Blocked, "pool reviewer"):
            self.derive()

    def test_tampered_pool_request_or_missing_pool_lineage_blocks(self):
        pool = self.jobs / "deterministic-pool-merge" / "09-independent-verification"
        attempt = pool / "attempts" / read_json(pool / "accepted.json")["attempt_id"]
        request = next(attempt.glob("pools/*/requests/*.json"))
        value = read_json(request); value["job_id"] = "08-blue-team-refutation"
        atomic_json(request, value)
        with self.assertRaisesRegex(Blocked, "reviewer pool is not accepted"):
            self.derive()
        # Re-accept the tampered pool and re-bind 09 to it: the request's own identity still fails.
        accept(pool, attempt.name)
        pointer = read_json(pool / "accepted.json"); pointer["job"] = "deterministic-pool-merge"
        atomic_json(pool / "accepted.json", pointer)
        stage = self.jobs / "09-independent-verification" / "attempts" / "verify-1"
        inputs = read_json(stage / "inputs.json")
        inputs["pool_binding"]["accepted_pointer_sha256"] = "sha256:" + file_hash(pool / "accepted.json")
        atomic_json(stage / "inputs.json", inputs)
        atomic_json(stage / "lineage.json", demo_report_fixture.stage_lineage(inputs))
        envelope = read_json(stage / "result.json"); envelope["input_fingerprint"] = "sha256:" + digest(inputs)
        atomic_json(stage / "result.json", envelope)
        self.republish("09-independent-verification", lambda document: None)
        with self.assertRaisesRegex(Blocked, "not a request of the accepted reviewer pool"):
            self.derive()
        (self.jobs / "08-blue-team-refutation" / "attempts" / "blue-1" / "inputs.json").unlink()
        self.republish("08-blue-team-refutation", lambda document: None)
        with self.assertRaisesRegex(Blocked, "decision artifact is missing"):
            self.derive()

    def test_stage_that_reviewed_another_head_or_no_decisions_blocks(self):
        self.republish("07-red-team-adversarial", lambda document: document.update(ledger_head_sha256="sha256:" + "0" * 64))
        with self.assertRaisesRegex(Blocked, "another ledger head"):
            self.derive()
        with self.assertRaisesRegex(Blocked, "no lifecycle decision chain"):
            report._lifecycle_origin(self.origin)

    def test_worker_publishes_receipts_reuses_on_resume_and_report_loads_it(self):
        def data_path(run_id, *parts):
            return Path(self.temp.name, "data", *parts)
        with mock.patch.object(final, "data_path", data_path):
            pointer = final.run(RUN_ID, "dagster-1")
            self.assertEqual(pointer["status"], "OK")
            again = final.run(RUN_ID, "dagster-2")
            self.assertEqual(again["attempt_id"], pointer["attempt_id"])
            final.validate(RUN_ID)
        loaded = report.load_accepted(self.jobs / final.JOB / "accepted.json", run_id=RUN_ID, name="ledger")
        self.assertEqual(loaded["reference"]["job_id"], final.JOB)
        self.assert_report_accepts(loaded["documents"][final.LEDGER])
        attempt = self.jobs / final.JOB / "attempts" / pointer["attempt_id"]
        self.assertEqual(read_json(attempt / "status.json")["decisions"], 5)

    def test_structural_citation_enters_the_final_ledger_and_a_tampered_record_blocks(self):
        """ADR-0035: a 09 VERIFIED row resting on a tev: record re-run-verified before it is appended."""
        verifier = demo_report_fixture.reviewer_actor(RUN_ID, "09-independent-verification", "", "")["attempt_id"]
        citation, path = tool_evidence_fixture.record(self.jobs.parent, "09-independent-verification", verifier)
        def cite(document):
            row = next(row for row in document["verifications"] if row["status"] == "VERIFIED")
            row["verification_citations"] = [citation]
            for item in row["proof_obligations"]:
                item["citations"] = [citation]
        self.republish("09-independent-verification", cite)
        ledger, _ = self.derive()
        verified = [entry for entry in ledger["entries"] if entry["status"] == "verified"]
        self.assertEqual([item["citation_id"] for item in verified[0]["citations"]][-1:], [citation["citation_id"]])
        self.assert_report_accepts(ledger)
        record = read_json(path); record["answer"]["rows"] = []
        atomic_json(path, record)
        with self.assertRaisesRegex(Blocked, "invalid tool evidence"):
            self.derive()


if __name__ == "__main__":
    unittest.main()
