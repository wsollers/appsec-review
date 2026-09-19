"""Behavioral tests for the run-owned critical-findings SARIF transform."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import critical_findings_sarif as sarif
import execution_state as state
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


class CriticalFindingsSarifTests(unittest.TestCase):
    setUp = fixtures.Phase1Tests.setUp
    tearDown = fixtures.Phase1Tests.tearDown
    new_run = fixtures.Phase1Tests.new_run

    def stage(self, text=SAMPLE):
        path = state.run_path(self.run_id) / "inputs" / sarif.INPUT_NAME
        path.write_text(text, encoding="utf-8")
        return path

    def test_strict_parse_conversion_and_registry_composition(self):
        source = self.stage()
        output = self.root / "out.sarif"
        counts = sarif.convert(source, output)
        self.assertEqual(counts, {"finding_count": 1, "rule_count": 1})
        document = sarif.validate_sarif(output, 1)
        result = document["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "CWE-862")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"],
                         {"startLine": 12, "endLine": 14})
        self.assertEqual(sarif.template()["composition"]["output_contract_id"],
                         "critical-findings-sarif")

    def test_immutable_attempt_reuse_force_and_tamper_rejection(self):
        self.stage()
        first = sarif.run(self.run_id, "dagster-a")
        attempt = sarif.validate(self.run_id, first)
        before = state.tree_hashes(attempt)
        self.assertEqual(first, sarif.run(self.run_id, "dagster-b"))
        self.assertEqual(before, state.tree_hashes(attempt))
        forced = sarif.run(self.run_id, "dagster-c", force=True)
        self.assertNotEqual(first["attempt_id"], forced["attempt_id"])
        accepted_attempt = sarif.validate(self.run_id, forced)
        with (accepted_attempt / "outputs" / "critical-findings.sarif").open("ab") as stream:
            stream.write(b"tampered")
        with self.assertRaises(state.Blocked):
            sarif.validate(self.run_id, forced)

    def test_malformed_input_and_failed_newer_attempt_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "required fields"):
            sarif.parse_findings("---\nid: only-id\n---\nbody\n", strict=True)
        self.stage()
        good = sarif.run(self.run_id, "dagster-a")
        self.assertEqual(good["status"], "OK")
        with patch.object(sarif, "execute", return_value={"exit_code": 9, "error": "fixture failure"}):
            with self.assertRaises(state.Blocked):
                sarif.run(self.run_id, "dagster-b", force=True)
        self.assertEqual(state.read_json(sarif.root(self.run_id) / "accepted.json")["status"], "FAILED")
        with self.assertRaises(state.Blocked):
            sarif.validate(self.run_id)

    def test_input_change_during_work_blocks_publication(self):
        source = self.stage()

        def changed(argv, cwd, logs, timeout, **kwargs):
            output = Path(argv[-1])
            sarif.convert(Path(argv[-2]), output)
            source.write_text(SAMPLE.replace("APP-001", "APP-CHANGED"), encoding="utf-8")
            state.atomic_bytes(logs / "stdout.log", b"converted\n")
            state.atomic_bytes(logs / "stderr.log", b"")
            return {"exit_code": 0, "error": None}

        with patch.object(sarif, "execute", side_effect=changed):
            with self.assertRaisesRegex(state.Blocked, "changed during conversion"):
                sarif.run(self.run_id, "dagster-race")


if __name__ == "__main__":
    unittest.main()
