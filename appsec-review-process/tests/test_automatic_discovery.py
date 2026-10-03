"""Focused lifecycle tests for zero-config common-envelope D01-D04 discovery."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import automatic_discovery as worker  # noqa: E402
import discovery_gate as discovery  # noqa: E402
import execution_state as state  # noqa: E402
import publish_job_output  # noqa: E402


class AutomaticDiscoveryLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.owner = Path(self.temporary.name).resolve()
        self.old_runs = state.RUNS
        state.RUNS = self.owner / "runs"
        self.run_id = "automatic-discovery-fixture"
        self.job = discovery.CONSUMER_JOB
        self.base = discovery.root(self.run_id, self.job)
        self.base.mkdir(parents=True)
        self.record = {"job": self.job, "mode": "automatic", "target_root": str(self.owner),
            "source_snapshot_sha256": "sha256:" + "b" * 64, "source_revision": "r",
            "upstream": {"job": discovery.ADOPTED_JOB, "attempt_id": "partition-attempt",
                         "repository-partition-map.json": "c" * 64},
            "code": {"discovery_gate.py": "d" * 64}, "run_id": self.run_id}
        self.value = {"schema": "appsec-review/project-discovery/1.0", "target": "target",
            "source_revision": "r", "projects": [], "safe_command_plan": [],
            "coverage_gaps": ["no independently buildable project in routed scope"]}
        self.facts = {"dispatch_mode": "automatic", "persona_job_id": "d02-devproject",
            "persona_attempt_id": "p" * 32, "persona_result_sha256": "e" * 64,
            "model": {"provider": "anthropic", "family": "family", "model_id": "id", "snapshot": "id"},
            "budget": "probe", "persona_id": "developer-engineer", "role_id": "project-discovery-analyst",
            "domain_id": "repo-project-discovery", "tooling_profile_id": "static-repo-project-inspector",
            "artifacts_read": ["configure.ac", "repository-partition-map.json"]}

    def tearDown(self):
        state.RUNS = self.old_runs
        self.temporary.cleanup()

    def patches(self, dispatch):
        return (patch.object(worker, "current_inputs", return_value=dict(self.record)),
                patch.object(discovery, "_dispatch_project_persona", dispatch),
                patch.object(discovery, "_require_upstream_inputs"),
                patch.object(publish_job_output, "validate_job_output", return_value=[]))

    def run_worker(self, dispatch, dagster="dagster-a", force=False):
        contexts = self.patches(dispatch)
        with contexts[0], contexts[1], contexts[2], contexts[3]:
            result = worker.run(self.run_id, dagster, self.job, force)
            attempt = worker.validate(self.run_id, self.job)
        return result, attempt

    def test_common_envelope_publishes_named_artifacts_permission_and_lineage(self):
        result, attempt = self.run_worker(
            lambda run_id, base, record: (dict(self.value), "# Discovery\n", dict(self.facts)))
        self.assertEqual(result["schema"], publish_job_output.ACCEPTED_SCHEMA)
        self.assertEqual(result["status"], "OK_WITH_GAPS")
        self.assertTrue((attempt / "project-inventory.json").is_file())
        self.assertFalse((attempt / "output.json").exists())
        permission = state.read_json(attempt / "permission.json")
        lineage = state.read_json(attempt / "lineage.json")
        self.assertEqual(permission["source_snapshot_sha256"], self.record["source_snapshot_sha256"])
        self.assertEqual(permission["permissions"], ["read-source", "read-run-data", "write-run-data"])
        self.assertIsNone(lineage["build_lineage_sha256"])
        envelope = state.read_json(attempt / "result.json")
        self.assertEqual({item["path"] for item in envelope["artifacts"]},
                         {"project-inventory.json", "project-discovery-summary.md", "status.json",
                          "permission.json", "lineage.json"})

    def test_absence_and_notes_are_reported_but_only_gaps_set_the_status(self):
        """P30/P34: verified absence and by-design notes stay visible and do not make OK_WITH_GAPS."""
        note = {"statement": "No CI/CD workflow is declared.",
                "basis": {"search_scope": [".github/workflows/*"], "inventory_count": 0, "evidence_citations": []}}
        value = {**self.value, "coverage_gaps": [], "absence_observations": [note],
                 "informational_notes": [dict(note, statement="vendor/x is built by its parent project")]}
        result, attempt = self.run_worker(lambda run_id, base, record: (dict(value), "# D\n", dict(self.facts)))
        self.assertEqual(result["status"], "OK")
        envelope = state.read_json(attempt / "result.json")
        self.assertEqual(envelope["gaps"], [])
        self.assertIn("1 absence observations and 1 informational notes", envelope["summary"])
        status = state.read_json(attempt / "status.json")
        self.assertEqual((status["absence_observations"], status["informational_notes"]), (1, 1))
        self.assertEqual(state.read_json(attempt / "project-inventory.json")["absence_observations"], [note])

    def test_same_inputs_reuse_and_changed_upstream_dispatches_again(self):
        calls = []
        def dispatch(run_id, base, record):
            calls.append(record["upstream"])
            return dict(self.value), "# Discovery\n", dict(self.facts)
        first, _ = self.run_worker(dispatch)
        second, _ = self.run_worker(dispatch, dagster="dagster-b")
        self.assertEqual(first["attempt_id"], second["attempt_id"])
        self.assertEqual(len(calls), 1)
        self.record["upstream"] = {**self.record["upstream"],
                                   "repository-partition-map.json": "f" * 64}
        third, _ = self.run_worker(dispatch, dagster="dagster-c")
        self.assertNotEqual(third["attempt_id"], first["attempt_id"])
        self.assertEqual(len(calls), 2)

    def test_model_or_invoker_unavailable_is_retained_as_actionable_blocked(self):
        with patch.object(worker, "current_inputs", side_effect=RuntimeError("configured invoker unavailable")):
            with self.assertRaisesRegex(RuntimeError, "configured invoker unavailable"):
                worker.run(self.run_id, "dagster-a", self.job)
        pointer = state.read_json(self.base / "accepted.json")
        self.assertEqual(pointer["schema"], publish_job_output.NONCURRENT_SCHEMA)
        self.assertEqual(pointer["status"], "BLOCKED")
        attempt = self.base / "attempts" / pointer["attempt_id"]
        envelope = state.read_json(attempt / pointer["envelope_path"])
        self.assertIn("configured invoker unavailable", envelope["cause"])
        self.assertIn("configured model/invoker", envelope["summary"])

    def test_d01_uses_existing_qualified_automatic_common_path(self):
        sentinel = {"status": "OK", "job": discovery.ADOPTED_JOB}
        with patch.object(discovery, "_run_partition_automatic", return_value=sentinel) as delegated:
            self.assertEqual(worker.run(self.run_id, "dagster-a", discovery.ADOPTED_JOB), sentinel)
        delegated.assert_called_once_with(self.run_id, "dagster-a", False)

    def test_one_zero_config_api_publishes_devops_and_sre_contract_artifacts(self):
        topology = {"schema": "appsec-review/operations-topology/1.0", "target": "target",
            "source_revision": "r", "services": [], "operational_notes": [],
            "coverage_gaps": ["no service or deployment unit is declared"]}
        cases = ((discovery.DEVOPS_JOB, self.value, "project-inventory.json"),
                 (discovery.SRE_JOB, topology, "service-inventory.json"))
        for job, value, artifact in cases:
            with self.subTest(job=job):
                discovery.root(self.run_id, job).mkdir(parents=True, exist_ok=True)
                record = {**self.record, "job": job}
                with patch.object(worker, "current_inputs", return_value=record), \
                     patch.object(discovery, "_dispatch_project_persona",
                                  return_value=(dict(value), "# Summary\n", dict(self.facts))), \
                     patch.object(discovery, "_require_upstream_inputs"), \
                     patch.object(publish_job_output, "validate_job_output", return_value=[]):
                    pointer = worker.run(self.run_id, "dagster-" + job, job)
                    attempt = worker.validate(self.run_id, job)
                self.assertEqual(pointer["schema"], publish_job_output.ACCEPTED_SCHEMA)
                self.assertTrue((attempt / artifact).is_file())
                self.assertTrue((attempt / "permission.json").is_file())
                self.assertTrue((attempt / "lineage.json").is_file())

    def test_common_upstream_prefers_contract_artifact_but_legacy_remains_readable(self):
        with tempfile.TemporaryDirectory() as folder:
            attempt = Path(folder)
            (attempt / "project-inventory.json").write_text("{}\n", encoding="utf-8")
            self.assertEqual(discovery._upstream_payload_filename(self.job, attempt),
                             "project-inventory.json")
            (attempt / "project-inventory.json").unlink()
            self.assertEqual(discovery._upstream_payload_filename(self.job, attempt), "output.json")


if __name__ == "__main__":
    unittest.main()
