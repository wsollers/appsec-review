import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import claim_lifecycle_core as claims
from execution_state import Blocked, read_json
import remediation_proposal as worker
from schema_validate import validate_document

FIXTURES = ROOT / "tests/fixtures/claim-lifecycle"
RUN_ID = "remediation-run"
SOURCE = "sha256:" + "2" * 64


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def binding(job, artifact):
    return {"job_id": job, "attempt_id": job + "-1",
            "pointer_sha256": "sha256:" + "1" * 64, "artifact_path": artifact,
            "artifact_sha256": "sha256:" + "3" * 64}


def verification():
    red = claims.red_team(fixture("claim-ledger.json"),
        binding("claim-ledger-routing", "claim-decision-ledger.json"), fixture("red-decisions.json"))
    blue = claims.blue_team(red, binding("07-red-team-adversarial", "red-team-adversarial.json"),
                            fixture("blue-decisions.json"))
    return claims.verify(blue, binding("08-blue-team-refutation", "blue-team-refutation.json"),
                         fixture("verification-decisions.json"))


def inputs():
    environment = {"job_id": "02-native-build", "attempt_id": "native-1",
        "accepted_pointer_sha256": "sha256:" + "4" * 64,
        "envelope_sha256": "sha256:" + "5" * 64,
        "artifact_path": "jobs/02-native-build/attempts/native-1/native-build.json",
        "artifact_sha256": "sha256:" + "6" * 64, "source_revision": "abc123",
        "source_generation": SOURCE,
        "units": [{"unit_id": "hello", "image_id": "image_build_123456789abc",
            "image_digest": "sha256:" + "7" * 64,
            "compile_database_sha256": "sha256:" + "8" * 64,
            "binary_sha256": ["sha256:" + "9" * 64]}]}
    environment["environment_sha256"] = worker._sha(environment)
    return {"run_id": RUN_ID, "verification": verification(),
        "verification_binding": binding("09-independent-verification", "independent-verification.json"),
        "environment": environment, "verification_source_generation": SOURCE,
        "build_pointer_status": "OK", "code": worker._code_hashes()}


class RemediationProposalTests(unittest.TestCase):
    def test_only_verified_claims_receive_evidence_bounded_unapplied_proposals(self):
        value = worker.build_result(inputs(), "proposal-1")
        self.assertEqual(validate_document(value, "remediation-proposal.schema.json"), [])
        self.assertEqual(value["status"], "OK_WITH_GAPS")
        self.assertEqual(len(value["proposals"]), 1)
        proposal = value["proposals"][0]
        self.assertEqual(proposal["claim_id"], "claim-aaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertFalse(proposal["target_modified"])
        self.assertEqual(proposal["patch_status"], "NOT_GENERATED")
        self.assertEqual(proposal["retest"]["status"], "NOT_RUN")
        self.assertEqual(proposal["retest"]["environment_sha256"],
                         value["environment"]["environment_sha256"])
        self.assertEqual({item["citation_id"] for item in proposal["evidence"]},
                         {"citation-a", "citation-c"})

    def test_no_verified_claims_publish_an_explicit_non_applicable_no_op(self):
        value = inputs()
        for record in value["verification"]["verifications"]:
            record["status"] = "UNRESOLVED"
        result = worker.build_result(value, "proposal-na")
        self.assertEqual(result["status"], "SKIPPED_NA")
        self.assertEqual(result["proposals"], [])
        self.assertEqual(result["no_op"], {"applicable": True,
            "reason": "no-independently-verified-claims"})
        self.assertEqual(validate_document(result, "remediation-proposal.schema.json"), [])

    def test_run_publishes_and_reuses_a_current_common_envelope(self):
        value = inputs()
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / worker.JOB
            with mock.patch.object(worker, "root", return_value=base), \
                    mock.patch.object(worker, "current_inputs", return_value=value):
                first = worker.run(RUN_ID, "dagster-1")
                second = worker.run(RUN_ID, "dagster-2")
                self.assertEqual(first["attempt_id"], second["attempt_id"])
                attempt = base / "attempts" / first["attempt_id"]
                envelope = read_json(attempt / "result.json")
                self.assertEqual(envelope["execution_status"], "OK_WITH_GAPS")
                self.assertEqual(envelope["output_contract"], worker.CONTRACT)
                self.assertEqual(set(path.name for path in attempt.iterdir()), {
                    "inputs.json", worker.RESULT, worker.SUMMARY, "permission.json",
                    "lineage.json", "status.json", "result.json"})
                (attempt / worker.RESULT).write_text("{}", encoding="utf-8")
                with self.assertRaises(Blocked):
                    worker.run(RUN_ID, "dagster-3")

    def test_run_accepts_no_verified_claims_as_an_explicit_no_op(self):
        value = inputs()
        for record in value["verification"]["verifications"]:
            record["status"] = "UNRESOLVED"
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / worker.JOB
            with mock.patch.object(worker, "root", return_value=base), \
                    mock.patch.object(worker, "current_inputs", return_value=value):
                pointer = worker.run(RUN_ID, "dagster-na")
                attempt = base / "attempts" / pointer["attempt_id"]
                self.assertEqual(pointer["status"], "OK")
                self.assertEqual(read_json(attempt / worker.RESULT)["status"], "SKIPPED_NA")
                self.assertTrue(read_json(attempt / "status.json")["no_op"])

    def test_registry_declares_the_real_worker_and_closed_contract(self):
        template = read_json(ROOT / "registry/job-templates/11-remediation-proposal.json")
        contract = read_json(ROOT / "registry/output-contracts/11-remediation-proposal.json")
        self.assertTrue(template["implemented"])
        self.assertEqual(template["execution"]["worker"], "remediation_proposal.py")
        self.assertEqual(template["composition"]["output_contract_id"], worker.CONTRACT)
        self.assertEqual(contract["result_schema"], {"artifact": worker.RESULT,
            "schema_file": "remediation-proposal.schema.json"})
        self.assertEqual(validate_document(template, "job-template.schema.json"), [])
        self.assertEqual(validate_document(contract, "output-contract.schema.json"), [])


if __name__ == "__main__":
    unittest.main()
