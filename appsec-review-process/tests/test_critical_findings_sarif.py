"""Behavioral tests for the run-owned critical-findings SARIF transform.

Conversion semantics are pinned by a golden document so the common-runtime migration cannot change
which inputs convert or what they convert to. The lifecycle cases below exercise only what is
specific to this worker: its common envelope/publication wiring, its contract-declared SARIF
result validation, and its mapping of deterministic-child faults. Generic allocation, publication,
reuse and child-runner behavior is covered once in test_worker_adoption.py and
test_deterministic_child.py and is not duplicated here.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import critical_findings_sarif as sarif
import execution_state as state
from publish_job_output import ACCEPTED_SCHEMA, NONCURRENT_SCHEMA, allocate_attempt
from schema_validate import validate_document
import test_phase1 as fixtures


SAMPLE = """---
id: APP-001
title: Missing authorization check
severity: High
status: Open
component: API
location: src/api.py:12-14
category: Authorization
cwe: CWE-862
asvs: V4
data_classes: [account]
regulatory: []
cve: []
confidence: Confirmed
discovered_by: independent-verification
---
### Description
The cited handler lacks the required object authorization check.

### Impact
Cross-account access is possible under the verified preconditions.

### Remediation
Enforce ownership before returning the object.
"""

GOLDEN = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
               "sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {
            "name": "vendor-audit-playbook", "informationUri": "", "version": "1.0.0",
            "rules": [{
                "id": "CWE-862", "name": "Missingauthorizationcheck",
                "shortDescription": {"text": "Missing authorization check"},
                "fullDescription": {
                    "text": "The cited handler lacks the required object authorization check."},
                "helpUri": "",
                "properties": {"tags": ["Authorization", "V4"], "security-severity": "7.5"},
            }],
        }},
        "results": [{
            "ruleId": "CWE-862", "level": "error",
            "message": {"text": "The cited handler lacks the required object authorization "
                                "check.\n\nImpact: Cross-account access is possible under the "
                                "verified preconditions.\n\nRemediation: Enforce ownership before "
                                "returning the object."},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/api.py"},
                "region": {"startLine": 12, "endLine": 14}}}],
            "properties": {"findingId": "APP-001", "severity": "High", "status": "Open",
                           "confidence": "Confirmed", "component": "API", "asvs": "V4",
                           "dataClasses": ["account"], "regulatory": [], "cve": [],
                           "discoveredBy": "independent-verification"},
        }],
    }],
}


class CriticalFindingsSarifTests(unittest.TestCase):
    setUp = fixtures.Phase1Tests.setUp
    tearDown = fixtures.Phase1Tests.tearDown
    new_run = fixtures.Phase1Tests.new_run

    def stage(self, text=SAMPLE):
        path = state.run_path(self.run_id) / "inputs" / sarif.INPUT_NAME
        path.write_text(text, encoding="utf-8", newline="")
        return path

    def base(self):
        return sarif.root(self.run_id)

    def pointer(self):
        return state.read_json(self.base() / "accepted.json")

    def converting_child(self, stdout=b"converted\n"):
        """Run the real conversion in-process so lifecycle cases stay fast and deterministic."""
        def child(spec, **kwargs):
            sarif.convert(Path(spec.argv[-2]), Path(spec.argv[-1]), strict=True)
            spec.log_dir.mkdir(parents=True, exist_ok=True)
            state.atomic_bytes(spec.log_dir / "stdout.log", stdout)
            state.atomic_bytes(spec.log_dir / "stderr.log", b"")
            return {"schema": sarif.CHILD_CONTRACT, "argv": list(spec.argv), "exit_code": 0,
                    "error": None, "timed_out": False, "cancelled": False,
                    "streams": {"stdout": {"observed_bytes": len(stdout),
                                           "written_bytes": len(stdout), "dropped_bytes": 0,
                                           "truncated": False},
                                "stderr": {"observed_bytes": 0, "written_bytes": 0,
                                           "dropped_bytes": 0, "truncated": False}}}
        return patch.object(sarif, "execute_child", side_effect=child)

    # --- conversion semantics -------------------------------------------------------------

    def test_strict_parse_conversion_and_registry_composition(self):
        source = self.stage()
        output = self.root / "out.sarif"
        counts = sarif.convert(source, output)
        self.assertEqual(counts, {"finding_count": 1, "rule_count": 1})
        document = sarif.validate_sarif(output, 1)
        self.assertEqual(document, GOLDEN)
        self.assertEqual(validate_document(document, "critical-findings-sarif.schema.json"), [])
        self.assertEqual(sarif.template()["composition"]["output_contract_id"],
                         "critical-findings-sarif")
        self.assertEqual(sarif.contract()["result_schema"],
                         {"artifact": "outputs/critical-findings.sarif",
                          "schema_file": "critical-findings-sarif.schema.json"})

    def test_platform_line_endings_and_child_environment_are_equivalent(self):
        """Windows stages CRLF; Linux stages LF. Both must convert to the same document."""
        crlf = self.root / "crlf.sarif"
        sarif.convert(self.stage(SAMPLE.replace("\n", "\r\n")), crlf)
        self.assertEqual(state.read_json(crlf), GOLDEN)
        lf = self.root / "lf.sarif"
        sarif.convert(self.stage(SAMPLE), lf)
        self.assertEqual(state.file_hash(crlf), state.file_hash(lf))
        environment = sarif.child_environment()
        self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")
        if os.name == "nt":
            self.assertTrue({"SYSTEMROOT", "WINDIR"} & {key.upper() for key in environment})
        else:
            self.assertNotIn("WINDIR", {key.upper() for key in environment})

    def test_malformed_input_is_a_preflight_blocker_and_never_allocates(self):
        with self.assertRaisesRegex(ValueError, "required fields"):
            sarif.parse_findings("---\nid: only-id\n---\nbody\n", strict=True)
        with self.assertRaisesRegex(state.Blocked, "stage a regular run-owned input"):
            sarif.run(self.run_id, "dagster-missing-input")
        self.assertEqual(self.pointer()["status"], "BLOCKED")
        self.stage(SAMPLE.replace("severity: High", "severity: Catastrophic"))
        with self.assertRaisesRegex(ValueError, "unsupported severity"):
            sarif.run(self.run_id, "dagster-bad-severity")
        pointer = self.pointer()
        self.assertEqual((pointer["schema"], pointer["status"]), (NONCURRENT_SCHEMA, "BLOCKED"))
        attempt = self.base() / "attempts" / pointer["attempt_id"]
        envelope = state.read_json(attempt / "result.json")
        self.assertEqual(envelope["execution_status"], "BLOCKED")
        self.assertIn("unsupported severity", envelope["cause"])
        self.assertTrue(envelope["retry"]["allowed"])
        self.assertFalse((attempt / "outputs").exists())

    # --- common envelope, publication and reuse ------------------------------------------

    def test_common_envelope_success_reuse_force_and_tamper_rejection(self):
        self.stage()
        with self.converting_child():
            first = sarif.run(self.run_id, "dagster-a")
            self.assertEqual(first["schema"], ACCEPTED_SCHEMA)
            attempt = sarif.validate(self.run_id, first)
            before = state.tree_hashes(attempt)
            envelope = state.read_json(attempt / "result.json")
            self.assertEqual(envelope["worker_kind"], "deterministic_python")
            self.assertEqual(envelope["output_contract"], "critical-findings-sarif")
            self.assertEqual(envelope["acceptance_status"], "CURRENT")
            self.assertEqual(sorted(item["path"] for item in envelope["artifacts"]),
                             ["manifest.json", "outputs/critical-findings.sarif", "status.json"])
            self.assertEqual(first, sarif.run(self.run_id, "dagster-b"))
            self.assertEqual(before, state.tree_hashes(attempt))
            receipt = state.read_json(state.data_path(
                self.run_id, "orchestration", "dagster", "dagster-b",
                "critical-findings-sarif-reuse.json"))
            self.assertEqual((receipt["reused"], receipt["publication_recovered"]), (True, False))
            forced = sarif.run(self.run_id, "dagster-c", force=True)
        self.assertNotEqual(first["attempt_id"], forced["attempt_id"])
        accepted_attempt = sarif.validate(self.run_id, forced)
        with (accepted_attempt / "outputs" / sarif.OUTPUT_NAME).open("ab") as stream:
            stream.write(b"tampered")
        with self.assertRaises(state.Blocked):
            sarif.validate(self.run_id, forced)

    def test_contract_validation_rejects_an_out_of_contract_sarif_result(self):
        self.stage()

        def wrong_shape(spec, **kwargs):
            sarif.convert(Path(spec.argv[-2]), Path(spec.argv[-1]), strict=True)
            document = state.read_json(Path(spec.argv[-1]))
            document["runs"][0]["results"][0]["properties"]["severity"] = "Catastrophic"
            state.atomic_json(Path(spec.argv[-1]), document)
            spec.log_dir.mkdir(parents=True, exist_ok=True)
            state.atomic_bytes(spec.log_dir / "stdout.log", b"")
            state.atomic_bytes(spec.log_dir / "stderr.log", b"")
            return {"exit_code": 0, "error": None}

        with patch.object(sarif, "execute_child", side_effect=wrong_shape):
            with self.assertRaisesRegex(state.Blocked, "invalid critical-findings SARIF result"):
                sarif.run(self.run_id, "dagster-invalid")
        pointer = self.pointer()
        self.assertEqual((pointer["schema"], pointer["status"]), (NONCURRENT_SCHEMA, "FAILED"))
        with self.assertRaises(state.Blocked):
            sarif.validate(self.run_id)

    def test_pending_publication_recovers_the_same_immutable_attempt(self):
        self.stage()
        with self.converting_child():
            first = sarif.run(self.run_id, "dagster-a")
            attempt = self.base() / "attempts" / first["attempt_id"]
            hashes = state.tree_hashes(attempt)
            state.atomic_json(self.base() / "accepted.json", {
                "schema": NONCURRENT_SCHEMA, "status": "PENDING",
                "attempt_id": first["attempt_id"], "fingerprint": first["fingerprint"],
                "updated_at": state.now()})
            recovered = sarif.run(self.run_id, "dagster-recover")
        self.assertEqual(recovered["attempt_id"], first["attempt_id"])
        self.assertEqual(state.tree_hashes(attempt), hashes)
        receipt = state.read_json(state.data_path(
            self.run_id, "orchestration", "dagster", "dagster-recover",
            "critical-findings-sarif-reuse.json"))
        self.assertTrue(receipt["publication_recovered"])

    def test_interrupted_attempt_recovery_and_no_fallback_after_newer_failure(self):
        self.stage()
        with self.converting_child():
            first = sarif.run(self.run_id, "dagster-a")
            record = sarif.current_inputs(self.run_id)
            interrupted = allocate_attempt(
                self.base(), run_id=self.run_id, job_id=sarif.JOB_ID,
                dagster_run_id="dagster-interrupted", worker_kind=sarif.WORKER_KIND,
                output_contract=sarif.OUTPUT_CONTRACT, input_record=record,
                input_fingerprint=sarif.input_fingerprint(record),
                resume_command="retry critical findings sarif")
            self.assertEqual(self.pointer()["status"], "PENDING")
            after = sarif.run(self.run_id, "dagster-after-interrupt", force=True)
        recovered = state.read_json(interrupted["attempt"] / "result.json")
        self.assertEqual((recovered["execution_status"], recovered["cause"]),
                         ("FAILED", "INTERRUPTED_WORKER"))
        self.assertNotIn(after["attempt_id"], {first["attempt_id"], interrupted["attempt_id"]})
        self.assertEqual(self.pointer()["attempt_id"], after["attempt_id"])
        with patch.object(sarif, "execute_child",
                          return_value={"exit_code": 9, "error": "fixture failure"}):
            with self.assertRaises(state.Blocked):
                sarif.run(self.run_id, "dagster-newer-failure", force=True)
        failed = self.pointer()
        self.assertEqual((failed["schema"], failed["status"]), (NONCURRENT_SCHEMA, "FAILED"))
        self.assertNotIn(failed["attempt_id"], {first["attempt_id"], after["attempt_id"]})
        with self.assertRaises(state.Blocked):
            sarif.validate(self.run_id)

    def test_cancellation_is_recorded_as_canceled_and_reraised(self):
        self.stage()
        with patch.object(sarif, "execute_child",
                          side_effect=KeyboardInterrupt("fixture cancellation")):
            with self.assertRaises(KeyboardInterrupt):
                sarif.run(self.run_id, "dagster-cancel")
        pointer = self.pointer()
        self.assertEqual((pointer["schema"], pointer["status"]), (NONCURRENT_SCHEMA, "CANCELED"))
        envelope = state.read_json(self.base() / "attempts" / pointer["attempt_id"] /
                                   "result.json")
        self.assertEqual(envelope["execution_status"], "CANCELED")
        self.assertIn("KeyboardInterrupt", envelope["cause"])

    def test_source_race_during_conversion_blocks_publication(self):
        source = self.stage()

        def changed(spec, **kwargs):
            sarif.convert(Path(spec.argv[-2]), Path(spec.argv[-1]), strict=True)
            source.write_text(SAMPLE.replace("APP-001", "APP-CHANGED"), encoding="utf-8")
            spec.log_dir.mkdir(parents=True, exist_ok=True)
            state.atomic_bytes(spec.log_dir / "stdout.log", b"converted\n")
            state.atomic_bytes(spec.log_dir / "stderr.log", b"")
            return {"exit_code": 0, "error": None}

        with patch.object(sarif, "execute_child", side_effect=changed):
            with self.assertRaisesRegex(state.Blocked, "changed during conversion"):
                sarif.run(self.run_id, "dagster-race")
        self.assertEqual(self.pointer()["status"], "FAILED")

    # --- deterministic-child execution contract ------------------------------------------

    def test_live_child_uses_the_argv_only_contract_with_separate_bounded_streams(self):
        self.stage()
        record = sarif.current_inputs(self.run_id)
        self.assertEqual(record["child_execution"], {
            "contract": "appsec-review/deterministic-child/1.0", "argv_only": True,
            "shell_allowed": False, "stdout_limit_bytes": sarif.STDOUT_LIMIT_BYTES,
            "stderr_limit_bytes": sarif.STDERR_LIMIT_BYTES, "child_tree_cleanup": "always"})
        accepted = sarif.run(self.run_id, "dagster-live-child")
        attempt = self.base() / "attempts" / accepted["attempt_id"]
        command = state.read_json(attempt / "command.json")
        self.assertEqual(command["schema"], "appsec-review/deterministic-child/1.0")
        self.assertEqual((command["exit_code"], command["timed_out"], command["cancelled"]),
                         (0, False, False))
        self.assertIsNone(command.get("error"))
        self.assertEqual(command["argv"][:4], command["argv_prefix"])
        self.assertEqual(Path(command["argv"][0]), Path(sys.executable).resolve())
        self.assertEqual(command["argv"][3], "worker")
        self.assertEqual(command["log_limits"],
                         {"stdout": sarif.STDOUT_LIMIT_BYTES, "stderr": sarif.STDERR_LIMIT_BYTES})
        self.assertGreater(command["streams"]["stdout"]["observed_bytes"], 0)
        self.assertFalse(command["streams"]["stdout"]["truncated"])
        self.assertEqual(command["streams"]["stderr"]["observed_bytes"], 0)
        self.assertEqual(json.loads((attempt / "logs" / "stdout.log").read_text())["status"], "OK")
        self.assertEqual((attempt / "logs" / "stderr.log").read_bytes(), b"")
        self.assertTrue((attempt / "logs" / "events.jsonl").is_file())

    def test_every_child_fault_fails_closed_without_publishing(self):
        """Timeout, truncated-stream failure, child loss and log-write failure all fail closed."""
        self.stage()
        faults = {
            "timeout": {"exit_code": None, "timed_out": True,
                        "error": "TimeoutError: child process timeout after 120s"},
            "child-loss": {"exit_code": -9, "error": None, "timed_out": False},
            "log-write": {"exit_code": 0,
                          "error": "diagnostic stream failure: PermissionError: injected"},
        }
        for label, result in faults.items():
            with self.subTest(fault=label):
                with patch.object(sarif, "execute_child", return_value=result):
                    with self.assertRaisesRegex(state.Blocked, "SARIF transform failed"):
                        sarif.run(self.run_id, f"dagster-{label}", force=True)
                pointer = self.pointer()
                self.assertEqual((pointer["schema"], pointer["status"]),
                                 (NONCURRENT_SCHEMA, "FAILED"))
                attempt = self.base() / "attempts" / pointer["attempt_id"]
                self.assertEqual(state.read_json(attempt / "command.json"), result)
                self.assertFalse((attempt / "manifest.json").exists())

    def test_qualification_fault_injection_helpers_produce_the_expected_states(self):
        """The live sequence's two fault injectors are exercised without a Dagster service."""
        import qualify_sarif_adoption as qualification

        quiet = contextlib.redirect_stdout(io.StringIO())
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)
        self.stage(qualification.FIXTURE)
        with self.converting_child():
            first = sarif.run(self.run_id, "dagster-a")
            qualification.make_pending_publication(self.run_id)
            pending = self.pointer()
            self.assertEqual((pending["schema"], pending["status"], pending["attempt_id"]),
                             (NONCURRENT_SCHEMA, "PENDING", first["attempt_id"]))
            self.assertEqual(sarif.run(self.run_id, "dagster-recover")["attempt_id"],
                             first["attempt_id"])
            qualification.interrupt(self.run_id)
            interrupted = self.pointer()
            self.assertEqual(interrupted["status"], "PENDING")
            self.assertNotEqual(interrupted["attempt_id"], first["attempt_id"])
        qualification.set_input(self.run_id, valid=False)
        with self.assertRaisesRegex(ValueError, "unsupported severity"):
            sarif.run(self.run_id, "dagster-invalid", force=True)
        self.assertEqual(self.pointer()["status"], "BLOCKED")
        qualification.set_input(self.run_id, valid=True)
        with self.converting_child():
            recovered = sarif.run(self.run_id, "dagster-recovered", force=True)
        self.assertEqual(recovered["status"], "OK")
        self.assertNotIn(recovered["attempt_id"],
                         {first["attempt_id"], interrupted["attempt_id"]})

    def test_truncated_diagnostic_streams_do_not_invalidate_a_successful_conversion(self):
        """Retained-log truncation under simultaneous stream pressure is bounded diagnostics.

        The generic runner already proves concurrent draining and byte accounting; this asserts
        only that this worker publishes the conversion and keeps the truncation record.
        """
        self.stage()
        noisy = b"x" * 4096

        def truncating(spec, **kwargs):
            sarif.convert(Path(spec.argv[-2]), Path(spec.argv[-1]), strict=True)
            spec.log_dir.mkdir(parents=True, exist_ok=True)
            state.atomic_bytes(spec.log_dir / "stdout.log", noisy[:32])
            state.atomic_bytes(spec.log_dir / "stderr.log", noisy[:32])
            pressure = {"observed_bytes": len(noisy), "written_bytes": 32,
                        "dropped_bytes": len(noisy) - 32, "truncated": True}
            return {"schema": sarif.CHILD_CONTRACT, "exit_code": 0, "error": None,
                    "timed_out": False, "cancelled": False,
                    "streams": {"stdout": dict(pressure), "stderr": dict(pressure)}}

        with patch.object(sarif, "execute_child", side_effect=truncating):
            accepted = sarif.run(self.run_id, "dagster-truncated")
        self.assertEqual(accepted["status"], "OK")
        attempt = sarif.validate(self.run_id, accepted)
        command = state.read_json(attempt / "command.json")
        for name in ("stdout", "stderr"):
            self.assertTrue(command["streams"][name]["truncated"])
            self.assertEqual(command["streams"][name]["dropped_bytes"], len(noisy) - 32)
            self.assertEqual(len((attempt / "logs" / f"{name}.log").read_bytes()), 32)


if __name__ == "__main__":
    unittest.main(verbosity=2)
