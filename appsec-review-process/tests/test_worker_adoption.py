"""Focused tests for registry handoffs and the two Batch 2 worker adoptions."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import create_job_handoff as handoffs
import discovery_gate
import execution_state as state
from publish_job_output import (ACCEPTED_SCHEMA, NONCURRENT_SCHEMA, admit_reusable,
                                allocate_attempt, coordinate_worker_lifecycle,
                                mark_attempt_started, persist_terminal_current, publish_validated,
                                record_noncurrent, record_terminal_current,
                                record_terminal_noncurrent)
from schema_validate import validate_document
from worker_result import artifact_records, terminal_envelope


def partition_result(content_hash):
    citation = {"source_type": "source_file", "path": "src/main.py", "line_range": None,
                "tool_name": None, "tool_rule_id": None, "content_hash": content_hash,
                "note": "fixture"}
    return {
        "schema": "appsec-review/repository-partition-map/0.1",
        "target": "fixture", "source_revision": "a" * 40,
        "partitions": [{
            "partition_id": "server", "name": "Server", "kinds": ["server"],
            "include_paths": ["src/**"], "exclude_paths": [],
            "primary_persona_id": "developer-engineer", "supporting_persona_ids": [],
            "routing_rationale": "Application source", "confidence": "high",
            "evidence_citations": [citation], "relationships": [], "overlap_notes": [],
            "disposition": "review", "disposition_reason": "in scope",
            "rescope_trigger": "new project root",
        }],
        "coverage": {"inventory_scope": ["**/*"], "unassigned_paths": [],
                     "uninspected_scope": [], "budget_limitations": [],
                     "category_checks": [{"category": "server", "result": "found",
                                          "search_scope": ["src/**"],
                                          "evidence_citations": [citation]}]},
    }


class AdoptionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.owner = Path(self.temporary.name)
        self.old_runs = state.RUNS
        state.RUNS = self.owner / "runs"
        self.run_id = "batch2-fixture"
        run = state.RUNS / self.run_id
        (run / "inputs").mkdir(parents=True)
        self.target = self.owner / "target"
        (self.target / "src").mkdir(parents=True)
        (self.target / "src/main.py").write_text("print('fixture')\n", encoding="utf-8")
        self.source_hash = state.file_hash(self.target / "src/main.py")
        state.atomic_json(run / "inputs/artifact-manifest.json", {
            "schema": "fixture", "target": {"repo_path": str(self.target)}})

    def tearDown(self):
        state.RUNS = self.old_runs
        self.temporary.cleanup()

    def test_resolved_handoff_hashes_every_registry_record_and_bounded_input(self):
        path, value = handoffs.create_handoff(
            self.run_id, "02-repository-partition-discovery",
            ["inputs/artifact-manifest.json"], scope_id="fixture")
        self.assertTrue(path.is_file())
        self.assertEqual(set(value["composition"]), set(handoffs.KINDS))
        self.assertTrue(value["identity"]["composition_sha256"].startswith("sha256:"))
        self.assertEqual(value["claim_class"]["claim_class_id"], "supplied_partition_map")
        self.assertEqual(value["identity"]["claim_class_sha256"],
                         value["claim_class"]["sha256"])
        self.assertEqual(value["prompt"]["path"],
                         "appsec-review-process/02-evidence-pregather/repository-partition-discovery.md")
        self.assertEqual(value["inputs"][0]["sha256"],
                         state.file_hash(state.RUNS / self.run_id / "inputs/artifact-manifest.json"))
        second, repeated = handoffs.create_handoff(
            self.run_id, "02-repository-partition-discovery",
            ["inputs/artifact-manifest.json"], scope_id="fixture")
        self.assertEqual(path, second)
        self.assertEqual(value, repeated)
        for invalid in ("../escape.json", "C:/escape.json", "outside/file.json"):
            with self.subTest(path=invalid), self.assertRaises(ValueError):
                handoffs.build_handoff(self.run_id, "02-repository-partition-discovery", [invalid])
        with self.assertRaises(ValueError):
            handoffs.build_handoff(self.run_id, "not-a-job", [])

    def test_project_discovery_has_dedicated_result_schema(self):
        value = {"schema": "appsec-review/project-discovery/1.0", "target": "fixture",
                 "source_revision": "a" * 40, "projects": [], "safe_command_plan": [],
                 "coverage_gaps": ["no project manifests"]}
        self.assertEqual(validate_document(value, "project-discovery.schema.json"), [])
        value["safe_command_plan"] = [{"project_id": "x", "purpose": "build",
                                       "argv": [], "authorization": "read-only",
                                       "side_effects": [], "evidence_citations": []}]
        self.assertTrue(validate_document(value, "project-discovery.schema.json"))

    def test_partition_common_envelope_reuse_and_invalid_newer_attempt_no_fallback(self):
        supplied = discovery_gate.supplied_path(self.run_id, discovery_gate.ADOPTED_JOB)
        state.atomic_json(supplied, partition_result(self.source_hash))
        first = discovery_gate.run(self.run_id, "dagster-a", discovery_gate.ADOPTED_JOB)
        self.assertEqual(first["schema"], ACCEPTED_SCHEMA)
        self.assertEqual(first, discovery_gate.run(
            self.run_id, "dagster-b", discovery_gate.ADOPTED_JOB))
        attempt = discovery_gate.validate(self.run_id, discovery_gate.ADOPTED_JOB, first)
        envelope = state.read_json(attempt / "result.json")
        self.assertEqual(envelope["worker_kind"], "supplied_human_decision")
        self.assertEqual(envelope["acceptance_status"], "CURRENT")
        invalid = partition_result(self.source_hash)
        invalid["partitions"][0]["include_paths"] = ["../escape"]
        state.atomic_json(supplied, invalid)
        with self.assertRaises(state.Blocked):
            discovery_gate.run(self.run_id, "dagster-c", discovery_gate.ADOPTED_JOB)
        failed = state.read_json(discovery_gate.root(self.run_id, discovery_gate.ADOPTED_JOB) /
                                 "accepted.json")
        self.assertEqual(failed["schema"], NONCURRENT_SCHEMA)
        self.assertEqual(failed["status"], "FAILED")
        self.assertNotEqual(failed["attempt_id"], first["attempt_id"])

    def test_partition_cancellation_is_noncurrent(self):
        supplied = discovery_gate.supplied_path(self.run_id, discovery_gate.ADOPTED_JOB)
        state.atomic_json(supplied, partition_result(self.source_hash))
        with patch.object(discovery_gate.SuppliedHumanDecisionAdapter, "execute",
                          side_effect=KeyboardInterrupt("fixture cancellation")):
            with self.assertRaises(KeyboardInterrupt):
                discovery_gate.run(self.run_id, "dagster-cancel", discovery_gate.ADOPTED_JOB)
        pointer = state.read_json(discovery_gate.root(self.run_id, discovery_gate.ADOPTED_JOB) /
                                  "accepted.json")
        self.assertEqual(pointer["status"], "CANCELED")
        self.assertEqual(pointer["schema"], NONCURRENT_SCHEMA)

    def test_partition_cross_record_ids_fail_closed(self):
        supplied = discovery_gate.supplied_path(self.run_id, discovery_gate.ADOPTED_JOB)
        invalid = partition_result(self.source_hash)
        invalid["partitions"][0]["relationships"] = [{
            "target_partition_id": "missing-partition", "kind": "calls", "basis": "declared",
            "evidence_citations": [invalid["partitions"][0]["evidence_citations"][0]],
        }]
        state.atomic_json(supplied, invalid)
        with self.assertRaisesRegex(state.Blocked, "worker result validation failed"):
            discovery_gate.run(self.run_id, "dagster-invalid-ids", discovery_gate.ADOPTED_JOB)
        pointer = state.read_json(discovery_gate.root(self.run_id, discovery_gate.ADOPTED_JOB) /
                                  "accepted.json")
        self.assertEqual(pointer["status"], "FAILED")


class PublicationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.owner = Path(self.temporary.name)
        self.base = self.owner / "job"
        self.attempt = self.base / "attempts/attempt-1"
        self.attempt.mkdir(parents=True)
        state.atomic_json(self.attempt / "output.json", {"ok": True})
        state.atomic_json(self.attempt / "status.json", {"status": "OK"})
        self.registry = self.owner / "registry/output-contracts"
        self.registry.mkdir(parents=True)
        state.atomic_json(self.registry / "fixture-contract.json", {
            "schema": "appsec-review/output-contract/0.1", "contract_id": "fixture-contract",
            "display_name": "Fixture", "required_files": ["output.json", "status.json"],
            "required_status_fields": ["status"], "validation_rules": ["fixture"]})
        self.graph = self.owner / "job-graph.json"
        state.atomic_json(self.graph, {"jobs": {
            "producer": {"dependencies": []},
            "consumer": {"dependencies": [{"job": "producer", "kind": "required",
                                              "contract": "fixture-contract",
                                              "allowed_skip_reasons": []}]}}})
        self.fingerprint = "sha256:" + "a" * 64
        self.envelope = terminal_envelope(
            run_id="run-1", job_id="producer", attempt_id="attempt-1",
            worker_kind="deterministic_python", execution_status="OK",
            acceptance_status="CURRENT", input_fingerprint=self.fingerprint,
            output_contract="fixture-contract", started_at="start", finished_at="finish",
            summary="fixture", artifacts=artifact_records(
                self.attempt, ["output.json", "status.json"]))
        state.atomic_json(self.attempt / "result.json", self.envelope)
        mark_attempt_started(self.base, "attempt-1")

    def tearDown(self):
        self.temporary.cleanup()

    def publish(self, fingerprint=None):
        return publish_validated(
            self.base, self.attempt, self.attempt / "result.json",
            fingerprint or self.fingerprint, expected_run_id="run-1",
            expected_job_id="producer", consumer_job_id="consumer",
            registry_root=self.registry.parent, graph_path=self.graph)

    def allocate(self, attempt_id_factory=None):
        return allocate_attempt(
            self.base, run_id="run-1", job_id="producer", dagster_run_id="dagster-new",
            worker_kind="deterministic_python", output_contract="fixture-contract",
            input_record={"fixture": True}, input_fingerprint=self.fingerprint,
            resume_command="retry fixture", attempt_id_factory=attempt_id_factory)

    def terminal_kwargs(self, allocation):
        return {
            "run_id": "run-1", "job_id": "producer", "dagster_run_id": "dagster-new",
            "worker_kind": "deterministic_python", "output_contract": "fixture-contract",
            "input_fingerprint": self.fingerprint, "started_at": allocation["started_at"],
            "execution_status": "OK", "summary": "fixture complete",
            "status_record": state.read_json(allocation["attempt"] / "status.json"),
            "artifact_paths": ["output.json", "status.json"],
        }

    def admit(self):
        return admit_reusable(
            self.base, self.fingerprint, expected_run_id="run-1",
            expected_job_id="producer", consumer_job_id="consumer",
            registry_root=self.registry.parent, graph_path=self.graph)

    def coordinate(self, derive, execute, **kwargs):
        return coordinate_worker_lifecycle(
            self.base, run_id="run-1", job_id="producer",
            dagster_run_id="dagster-lifecycle", worker_kind="deterministic_python",
            output_contract="fixture-contract", resume_command="retry fixture",
            derive_inputs=derive, fingerprint_inputs=lambda _record: self.fingerprint,
            execute_attempt=execute,
            preflight_failure_inputs=lambda exc: {"preflight": type(exc).__name__},
            force=True, attempt_id_factory=lambda: "attempt-2", **kwargs)

    def test_lifecycle_preflight_blocker_is_recorded_and_original_exception_escapes(self):
        def blocked():
            raise state.Blocked("fixture preflight")

        with self.assertRaisesRegex(state.Blocked, "fixture preflight"):
            self.coordinate(blocked, lambda *_args: {})
        pointer = state.read_json(self.base / "accepted.json")
        envelope = state.read_json(self.base / "attempts/attempt-2/result.json")
        self.assertEqual((pointer["status"], envelope["execution_status"]),
                         ("BLOCKED", "BLOCKED"))

    def test_lifecycle_work_failure_and_cancellation_map_without_double_terminal_write(self):
        def failed(_allocation, _record, _fingerprint):
            raise ValueError("fixture work failure")

        with self.assertRaisesRegex(ValueError, "fixture work failure"):
            self.coordinate(lambda: {"fixture": True}, failed)
        pointer = state.read_json(self.base / "accepted.json")
        self.assertEqual(pointer["status"], "FAILED")
        self.assertFalse((self.base / "attempts/attempt-2/failure-result.json").exists())

        self.base = self.owner / "cancel-job"
        with self.assertRaises(KeyboardInterrupt):
            self.coordinate(
                lambda: {"fixture": True},
                lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt("fixture cancel")))
        pointer = state.read_json(self.base / "accepted.json")
        self.assertEqual(pointer["status"], "CANCELED")

    def test_lifecycle_does_not_write_second_terminal_after_worker_records_one(self):
        def terminal_then_raise(allocation, _record, fingerprint):
            record_terminal_noncurrent(
                self.base, allocation["attempt"], run_id="run-1", job_id="producer",
                dagster_run_id="dagster-lifecycle", worker_kind="deterministic_python",
                output_contract="fixture-contract", input_fingerprint=fingerprint,
                started_at=allocation["started_at"], execution_status="FAILED",
                cause="worker-owned terminal", summary="worker failed",
                resume_command="retry fixture")
            raise RuntimeError("after terminal")

        with self.assertRaisesRegex(RuntimeError, "after terminal"):
            self.coordinate(lambda: {"fixture": True}, terminal_then_raise)
        attempt = self.base / "attempts/attempt-2"
        self.assertTrue((attempt / "result.json").is_file())
        self.assertFalse((attempt / "failure-result.json").exists())
        self.assertEqual(state.read_json(self.base / "accepted.json")["status"], "FAILED")

    def test_lifecycle_lock_contention_allocates_nothing(self):
        called = []
        with state.Lock(self.base / "job.lock"):
            with self.assertRaisesRegex(state.Blocked, "active lock"):
                self.coordinate(lambda: called.append(True) or {}, lambda *_args: {})
        self.assertEqual(called, [])
        self.assertEqual(sorted(path.name for path in (self.base / "attempts").iterdir()),
                         ["attempt-1"])

    def test_validation_is_read_only_and_corrupt_or_stale_result_cannot_publish(self):
        bad = deepcopy(self.envelope)
        bad["artifacts"][0]["sha256"] = "0" * 64
        state.atomic_json(self.attempt / "result.json", bad)
        with self.assertRaises(state.Blocked):
            self.publish()
        self.assertEqual(state.read_json(self.base / "accepted.json")["status"], "PENDING")
        state.atomic_json(self.attempt / "result.json", self.envelope)
        with self.assertRaises(state.Blocked):
            self.publish("sha256:" + "b" * 64)
        self.assertEqual(state.read_json(self.base / "accepted.json")["status"], "PENDING")

    def test_newer_failure_replaces_success_and_old_attempt_is_not_fallback(self):
        accepted = self.publish()
        self.assertEqual(accepted["schema"], ACCEPTED_SCHEMA)
        second = self.base / "attempts/attempt-2"
        second.mkdir()
        mark_attempt_started(self.base, "attempt-2")
        failed = terminal_envelope(
            run_id="run-1", job_id="producer", attempt_id="attempt-2",
            worker_kind="deterministic_python", execution_status="FAILED",
            acceptance_status="NOT_ACCEPTED", input_fingerprint=self.fingerprint,
            output_contract="fixture-contract", started_at="start", finished_at="finish",
            summary="failed", artifacts=[], cause="fixture failure")
        state.atomic_json(second / "result.json", failed)
        pointer = record_noncurrent(self.base, second / "result.json", failed)
        self.assertEqual(pointer["status"], "FAILED")
        self.assertNotEqual(pointer["attempt_id"], accepted["attempt_id"])
        with self.assertRaises(state.Blocked):
            publish_validated(
                self.base, self.attempt, self.attempt / "result.json", self.fingerprint,
                expected_run_id="run-1", expected_job_id="producer",
                consumer_job_id="consumer", registry_root=self.registry.parent,
                graph_path=self.graph)

    def test_central_allocation_retries_collision_and_moves_both_pointers(self):
        candidates = iter(["attempt-1", "attempt-2"])
        allocation = self.allocate(lambda: next(candidates))
        self.assertEqual(allocation["attempt_id"], "attempt-2")
        self.assertEqual(state.read_json(self.base / "latest.json")["attempt_id"], "attempt-2")
        pending = state.read_json(self.base / "accepted.json")
        self.assertEqual((pending["schema"], pending["status"], pending["attempt_id"]),
                         (NONCURRENT_SCHEMA, "PENDING", "attempt-2"))
        self.assertEqual(state.read_json(allocation["attempt"] / "inputs.json"),
                         {"fixture": True})
        self.assertEqual(state.read_json(allocation["attempt"] / "status.json")["status"],
                         "RUNNING")

    def test_next_allocation_recovers_interrupted_attempt_before_replacement(self):
        first = self.allocate(lambda: "attempt-2")
        second = self.allocate(lambda: "attempt-3")
        recovered = second["recovered"]
        self.assertEqual(recovered["status"], "FAILED")
        self.assertEqual(recovered["attempt_id"], first["attempt_id"])
        envelope = state.read_json(first["attempt"] / "result.json")
        self.assertEqual(envelope["execution_status"], "FAILED")
        self.assertEqual(envelope["cause"], "INTERRUPTED_WORKER")
        self.assertEqual(state.read_json(first["attempt"] / "status.json")["status"], "FAILED")
        self.assertEqual(state.read_json(self.base / "accepted.json")["status"], "PENDING")
        self.assertEqual(state.read_json(self.base / "latest.json")["attempt_id"],
                         second["attempt_id"])

    def test_terminal_noncurrent_is_durable_and_requires_newest_attempt(self):
        allocation = self.allocate(lambda: "attempt-2")
        pointer = record_terminal_noncurrent(
            self.base, allocation["attempt"], run_id="run-1", job_id="producer",
            dagster_run_id="dagster-new", worker_kind="deterministic_python",
            output_contract="fixture-contract", input_fingerprint=self.fingerprint,
            started_at=allocation["started_at"], execution_status="BLOCKED",
            cause="fixture prerequisite missing", summary="fixture blocked",
            resume_command="retry fixture")
        envelope_path = allocation["attempt"] / pointer["envelope_path"]
        self.assertEqual(pointer["envelope_sha256"], state.file_hash(envelope_path))
        self.assertEqual(state.read_json(envelope_path)["execution_status"], "BLOCKED")
        newer = self.allocate(lambda: "attempt-3")
        with self.assertRaisesRegex(state.Blocked, "not the newest"):
            record_terminal_noncurrent(
                self.base, allocation["attempt"], run_id="run-1", job_id="producer",
                dagster_run_id="dagster-old", worker_kind="deterministic_python",
                output_contract="fixture-contract", input_fingerprint=self.fingerprint,
                started_at=allocation["started_at"], execution_status="FAILED",
                cause="late failure", summary="late", resume_command="retry fixture")
        self.assertEqual(state.read_json(self.base / "latest.json")["attempt_id"],
                         newer["attempt_id"])

    def test_success_terminal_is_centralized_and_immutably_reusable(self):
        allocation = self.allocate(lambda: "attempt-2")
        state.atomic_json(allocation["attempt"] / "output.json", {"ok": "new"})
        pointer = record_terminal_current(
            self.base, allocation["attempt"], **self.terminal_kwargs(allocation),
            consumer_job_id="consumer", registry_root=self.registry.parent,
            graph_path=self.graph)
        admitted = self.admit()
        self.assertEqual(admitted["pointer"], pointer)
        self.assertFalse(admitted["recovered_publication"])
        self.assertEqual(state.read_json(allocation["attempt"] / "status.json")["status"],
                         "OK")

    def test_post_envelope_interruption_recovers_publication_without_new_attempt(self):
        allocation = self.allocate(lambda: "attempt-2")
        state.atomic_json(allocation["attempt"] / "output.json", {"ok": "recover"})
        persist_terminal_current(
            self.base, allocation["attempt"], **self.terminal_kwargs(allocation))
        self.assertEqual(state.read_json(self.base / "accepted.json")["status"], "PENDING")
        admitted = self.admit()
        self.assertTrue(admitted["recovered_publication"])
        self.assertEqual(admitted["pointer"]["attempt_id"], allocation["attempt_id"])
        self.assertEqual(state.read_json(self.base / "latest.json")["attempt_id"],
                         allocation["attempt_id"])

    def test_pending_recovery_runs_worker_postcheck_before_publication(self):
        allocation = self.allocate(lambda: "attempt-2")
        state.atomic_json(allocation["attempt"] / "output.json", {"ok": "recover"})
        persist_terminal_current(
            self.base, allocation["attempt"], **self.terminal_kwargs(allocation))

        def reject(_attempt, _envelope):
            raise state.Blocked("worker postcheck rejected candidate")

        with self.assertRaisesRegex(state.Blocked, "postcheck rejected"):
            admit_reusable(
                self.base, self.fingerprint, expected_run_id="run-1",
                expected_job_id="producer", consumer_job_id="consumer",
                registry_root=self.registry.parent, graph_path=self.graph,
                post_validate=reject)
        self.assertEqual(state.read_json(self.base / "accepted.json")["status"], "PENDING")

    def test_reuse_rejects_corrupt_pointer_and_stale_newest_identity(self):
        pointer = self.publish()
        corrupt = dict(pointer)
        corrupt["envelope_sha256"] = "0" * 64
        state.atomic_json(self.base / "accepted.json", corrupt)
        with self.assertRaisesRegex(state.Blocked, "envelope changed"):
            self.admit()
        state.atomic_json(self.base / "accepted.json", pointer)
        state.atomic_json(self.base / "latest.json", {"attempt_id": "attempt-2"})
        with self.assertRaisesRegex(state.Blocked, "not the newest"):
            self.admit()

    def test_success_validator_rejection_leaves_pending_and_durable_candidate(self):
        allocation = self.allocate(lambda: "attempt-2")
        state.atomic_json(allocation["attempt"] / "output.json", {"ok": "rejected"})
        with patch("publish_job_output.validate_job_output", return_value=["fixture rejected"]):
            with self.assertRaisesRegex(state.Blocked, "fixture rejected"):
                record_terminal_current(
                    self.base, allocation["attempt"], **self.terminal_kwargs(allocation),
                    consumer_job_id="consumer", registry_root=self.registry.parent,
                    graph_path=self.graph)
        self.assertTrue((allocation["attempt"] / "result.json").is_file())
        self.assertEqual(state.read_json(self.base / "accepted.json")["status"], "PENDING")


if __name__ == "__main__":
    unittest.main(verbosity=2)
