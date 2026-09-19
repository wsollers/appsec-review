"""Focused cross-platform tests for the common worker-result validation boundary."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from execution_state import file_hash
from validate_job_output import validate_job_output
from worker_adapters import (
    DeterministicPythonAdapter,
    SuppliedHumanDecisionAdapter,
    UnsupportedWorkerAdapter,
    WorkerRequest,
)
from worker_result import validate_immutable_reuse, validate_transition, validate_worker_result


class WorkerResultRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.attempt = self.base / "attempt-1"
        (self.attempt / "outputs").mkdir(parents=True)
        (self.attempt / "outputs/result.json").write_text('{"ok":true}\n', encoding="utf-8")
        (self.attempt / "status.json").write_text('{"status":"OK"}\n', encoding="utf-8")
        self.registry = self.base / "registry"
        (self.registry / "output-contracts").mkdir(parents=True)
        contract = {
            "schema": "appsec-review/output-contract/0.1",
            "contract_id": "fixture-contract",
            "display_name": "Fixture",
            "required_files": ["outputs/result.json", "status.json"],
            "required_status_fields": ["status"],
            "validation_rules": ["fixture"],
        }
        (self.registry / "output-contracts/fixture-contract.json").write_text(
            json.dumps(contract), encoding="utf-8")
        self.graph = self.base / "job-graph.json"
        self.graph.write_text(json.dumps({"jobs": {
            "producer-job": {"contract": "fixture-contract", "dependencies": []},
            "consumer-job": {"contract": "consumer-contract", "dependencies": [{
                "job": "producer-job", "kind": "optional", "contract": "fixture-contract",
                "allowed_skip_reasons": ["not-requested"]}]},
        }}), encoding="utf-8")
        self.fingerprint = "sha256:" + "a" * 64
        self.envelope = {
            "schema": "appsec-review/worker-result-envelope/1.0",
            "run_id": "run-1", "job_id": "producer-job", "attempt_id": "attempt-1",
            "worker_kind": "deterministic_python", "execution_status": "OK",
            "acceptance_status": "CURRENT", "input_fingerprint": self.fingerprint,
            "output_contract": "fixture-contract", "started_at": "2026-09-19T10:00:00Z",
            "finished_at": "2026-09-19T10:01:00Z", "summary": "complete",
            "artifacts": self.artifacts(), "gaps": [], "skip_reason": None, "cause": None,
            "retry": {"allowed": False, "resume_command": None},
            "superseded_by_attempt_id": None,
        }

    def tearDown(self):
        self.temporary.cleanup()

    def artifacts(self):
        return [{"path": name, "sha256": file_hash(self.attempt / name),
                 "media_type": "application/json"}
                for name in ("outputs/result.json", "status.json")]

    def errors(self, envelope=None, **kwargs):
        return validate_job_output(
            self.attempt, envelope or self.envelope, self.fingerprint,
            expected_run_id="run-1", expected_job_id="producer-job",
            registry_root=self.registry, graph_path=self.graph, **kwargs)

    def test_valid_current_result(self):
        self.assertEqual(self.errors(), [])

    def test_every_execution_terminal_has_explicit_semantics(self):
        cases = {
            "OK": ("CURRENT", [], None, None),
            "OK_WITH_GAPS": ("CURRENT", ["bounded gap"], None, None),
            "SKIPPED": ("CURRENT", [], "not-requested", None),
            "BLOCKED": ("NOT_ACCEPTED", [], None, "missing input"),
            "FAILED": ("NOT_ACCEPTED", [], None, "worker error"),
            "CANCELED": ("NOT_ACCEPTED", [], None, "operator canceled"),
            "UNRESOLVED": ("NOT_ACCEPTED", ["question remains"], None, "bounded work exhausted"),
        }
        for status, (acceptance, gaps, skip, cause) in cases.items():
            with self.subTest(status=status):
                envelope = deepcopy(self.envelope)
                envelope.update(execution_status=status, acceptance_status=acceptance,
                                gaps=gaps, skip_reason=skip, cause=cause)
                (self.attempt / "status.json").write_text(
                    json.dumps({"status": status}), encoding="utf-8")
                envelope["artifacts"] = self.artifacts()
                kwargs = {"consumer_job_id": "consumer-job"} if status == "SKIPPED" else {}
                self.assertEqual(self.errors(envelope, **kwargs), [])

    def test_failure_like_status_requires_cause(self):
        envelope = deepcopy(self.envelope)
        envelope.update(execution_status="FAILED", acceptance_status="NOT_ACCEPTED")
        self.assertIn("requires an explicit cause", "\n".join(self.errors(envelope)))

    def test_skip_requires_exact_consumer_edge_authorization(self):
        envelope = deepcopy(self.envelope)
        envelope.update(execution_status="SKIPPED", skip_reason="not-applicable-non-native")
        self.assertIn("not authorized", "\n".join(self.errors(envelope, consumer_job_id="consumer-job")))
        envelope["skip_reason"] = "not-requested"
        self.assertIn("requires a named consumer", "\n".join(self.errors(envelope)))

    def test_corrupted_artifact_hash_fails(self):
        envelope = deepcopy(self.envelope)
        envelope["artifacts"][0]["sha256"] = "0" * 64
        self.assertIn("artifact hash mismatch", "\n".join(self.errors(envelope)))

    def test_artifact_traversal_and_absolute_paths_fail(self):
        for bad in ("../escape.json", "C:/escape.json", "/escape.json", "outputs\\result.json"):
            with self.subTest(path=bad):
                envelope = deepcopy(self.envelope)
                envelope["artifacts"][0]["path"] = bad
                self.assertIn("artifact path", "\n".join(self.errors(envelope)))

    def test_missing_required_file_manifest_entry_fails(self):
        envelope = deepcopy(self.envelope)
        envelope["artifacts"].pop()
        self.assertIn("required output is absent", "\n".join(self.errors(envelope)))

    def test_missing_artifact_file_fails(self):
        (self.attempt / "status.json").unlink()
        self.assertIn("artifact is missing", "\n".join(self.errors()))

    def test_stale_input_fingerprint_fails(self):
        errors = validate_job_output(
            self.attempt, self.envelope, "sha256:" + "b" * 64,
            expected_run_id="run-1", expected_job_id="producer-job",
            registry_root=self.registry, graph_path=self.graph)
        self.assertIn("stale input fingerprint", "\n".join(errors))

    def test_supersession_is_acceptance_only_and_names_replacement(self):
        envelope = deepcopy(self.envelope)
        envelope.update(acceptance_status="SUPERSEDED", superseded_by_attempt_id="attempt-2")
        self.assertEqual(validate_worker_result(envelope), [])
        envelope["superseded_by_attempt_id"] = "attempt-1"
        self.assertIn("cannot supersede itself", "\n".join(validate_worker_result(envelope)))

    def test_run_and_job_identity_must_match_owner(self):
        errors = validate_job_output(
            self.attempt, self.envelope, self.fingerprint,
            expected_run_id="other-run", expected_job_id="other-job",
            registry_root=self.registry, graph_path=self.graph)
        joined = "\n".join(errors)
        self.assertIn("run_id does not match", joined)
        self.assertIn("job_id does not match", joined)

    def test_state_transition_rules(self):
        self.assertEqual(validate_transition("RUNNING", "OK"), [])
        self.assertIn("illegal execution transition", "\n".join(validate_transition("OK", "RUNNING")))
        self.assertEqual(validate_transition("CURRENT", "SUPERSEDED", "acceptance"), [])
        self.assertIn("illegal acceptance transition",
                      "\n".join(validate_transition("SUPERSEDED", "CURRENT", "acceptance")))

    def test_immutable_reuse_requires_exact_envelope(self):
        self.assertEqual(validate_immutable_reuse(self.envelope, deepcopy(self.envelope)), [])
        mutated = deepcopy(self.envelope)
        mutated["summary"] = "rewritten"
        self.assertIn("mutates the immutable", "\n".join(validate_immutable_reuse(self.envelope, mutated)))
        self.assertEqual(self.errors(accepted_envelope=deepcopy(self.envelope), reuse=True), [])

    def test_republish_requires_explicit_reuse_mode(self):
        self.assertIn("cannot be republished", "\n".join(
            self.errors(accepted_envelope=deepcopy(self.envelope))))

    def test_adapter_protocol_executes_only_bounded_kinds(self):
        request = WorkerRequest("run-1", "producer-job", "attempt-1", self.attempt, {"x": 1})
        deterministic = DeterministicPythonAdapter(lambda value: {"job": value.job_id})
        self.assertEqual(deterministic.execute(request), {"job": "producer-job"})
        supplied = self.attempt / "supplied/result.json"
        supplied.parent.mkdir()
        supplied.write_text('{"decision":"approved"}', encoding="utf-8")
        self.assertEqual(SuppliedHumanDecisionAdapter().execute(request)["decision"], "approved")
        for kind in ("pinned_container", "persona", "pool_coordinator", "join_controller"):
            with self.subTest(kind=kind), self.assertRaises(NotImplementedError):
                UnsupportedWorkerAdapter(kind).execute(request)

    def test_supplied_adapter_rejects_unsafe_paths(self):
        for path in ("../result.json", "C:/result.json", "supplied\\result.json"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                SuppliedHumanDecisionAdapter(path)


class ContractSpecificValidatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.run = self.base / "run-1"
        self.target = self.base / "target"
        self.target.mkdir()
        (self.target / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
        (self.run / "inputs").mkdir(parents=True)
        (self.run / "inputs/artifact-manifest.json").write_text(json.dumps({
            "target": {"repo_path": str(self.target)}}), encoding="utf-8")
        self.attempt = self.run / "data/jobs/producer/whole/attempts/attempt-1"
        self.attempt.mkdir(parents=True)
        self.registry = self.base / "registry"
        (self.registry / "output-contracts").mkdir(parents=True)
        self.contract = {
            "schema": "appsec-review/output-contract/0.1",
            "contract_id": "project-discovery", "display_name": "Project discovery",
            "required_files": ["project-inventory.json", "status.json"],
            "required_status_fields": ["status", "attempt_id"],
            "result_schema": {"artifact": "project-inventory.json",
                              "schema_file": "project-discovery.schema.json"},
            "claim_class": {
                "claim_class_id": "supplied_project_discovery",
                "allowed_assertions": ["declared-project-structure",
                                       "statically-inferred-build-plan", "coverage-gap"],
                "forbidden_promotions": ["finding", "severity", "runtime-state"],
            },
            "validation_rules": ["fixture"],
        }
        self._write_contract()
        self.graph = self.base / "job-graph.json"
        self.graph.write_text(json.dumps({"jobs": {"producer": {"dependencies": []}}}),
                              encoding="utf-8")
        self.fingerprint = "sha256:" + "a" * 64
        self.payload = {
            "schema": "appsec-review/project-discovery/1.0", "target": "fixture",
            "source_revision": "a" * 40,
            "projects": [{"project_id": "app", "root": ".", "languages": ["Python"],
                          "manifests": ["pyproject.toml"], "lockfiles": [],
                          "candidate_buildenv_images": [], "commands": ["python -m build"],
                          "evidence_citations": [self.citation()], "confidence": "high"}],
            "safe_command_plan": [{"project_id": "app", "purpose": "inspect",
                                    "argv": ["python", "-m", "build"],
                                    "authorization": "read-only", "side_effects": [],
                                    "evidence_citations": [self.citation()]}],
            "coverage_gaps": ["Not a verified finding; no observed runtime state was inspected."],
        }
        self.write_attempt()

    def tearDown(self):
        self.temporary.cleanup()

    def citation(self):
        return {"source_type": "source_file", "path": "pyproject.toml", "line_range": None,
                "tool_name": None, "tool_rule_id": None,
                "content_hash": file_hash(self.target / "pyproject.toml"), "note": "fixture"}

    def _write_contract(self):
        (self.registry / "output-contracts/project-discovery.json").write_text(
            json.dumps(self.contract), encoding="utf-8")

    def write_attempt(self):
        (self.attempt / "project-inventory.json").write_text(
            json.dumps(self.payload), encoding="utf-8")
        (self.attempt / "status.json").write_text(
            json.dumps({"status": "OK", "attempt_id": "attempt-1"}), encoding="utf-8")

    def errors(self):
        artifacts = [{"path": name, "sha256": file_hash(self.attempt / name),
                      "media_type": "application/json"}
                     for name in self.contract["required_files"]]
        envelope = {
            "schema": "appsec-review/worker-result-envelope/1.0", "run_id": "run-1",
            "job_id": "producer", "attempt_id": "attempt-1",
            "worker_kind": "supplied_human_decision", "execution_status": "OK",
            "acceptance_status": "CURRENT", "input_fingerprint": self.fingerprint,
            "output_contract": "project-discovery", "started_at": "start", "finished_at": "finish",
            "summary": "fixture", "artifacts": artifacts, "gaps": [], "skip_reason": None,
            "cause": None, "retry": {"allowed": False, "resume_command": None},
            "superseded_by_attempt_id": None,
        }
        return validate_job_output(
            self.attempt, envelope, self.fingerprint, expected_run_id="run-1",
            expected_job_id="producer", registry_root=self.registry, graph_path=self.graph)

    def test_schema_citations_paths_and_cross_record_ids_pass(self):
        self.assertEqual(self.errors(), [])

    def test_stale_citation_and_cross_record_id_fail(self):
        self.payload["projects"][0]["evidence_citations"][0]["content_hash"] = "0" * 64
        self.payload["safe_command_plan"][0]["project_id"] = "missing"
        self.write_attempt()
        joined = "\n".join(self.errors())
        self.assertIn("cited repository file is stale", joined)
        self.assertIn("does not resolve to a project", joined)

    def test_repository_traversal_fails(self):
        self.payload["projects"][0]["root"] = "../escape"
        self.write_attempt()
        self.assertIn("without traversal", "\n".join(self.errors()))

    def test_secret_leak_fixtures_fail_without_mutation(self):
        for leaked in ("Bearer abcdefghijklmnopqrstuvwxyz123456",
                       "-----BEGIN PRIVATE KEY-----"):
            with self.subTest(leaked=leaked.split()[0]):
                self.payload["safe_command_plan"][0]["argv"] = [leaked]
                self.write_attempt()
                before = (self.attempt / "project-inventory.json").read_bytes()
                self.assertIn("forbidden in a published result", "\n".join(self.errors()))
                self.assertEqual((self.attempt / "project-inventory.json").read_bytes(), before)

    def test_only_declared_result_artifact_is_schema_validated(self):
        self.contract["required_files"].append("auxiliary.json")
        self._write_contract()
        (self.attempt / "auxiliary.json").write_text("not-json", encoding="utf-8")
        self.assertEqual(self.errors(), [])

    def test_required_status_field_and_value_are_enforced(self):
        (self.attempt / "status.json").write_text(json.dumps({"status": "FAILED"}), encoding="utf-8")
        joined = "\n".join(self.errors())
        self.assertIn("missing required field: attempt_id", joined)
        self.assertIn("does not match the worker envelope", joined)

    def test_cross_contract_claim_class_identity_fails(self):
        self.contract["claim_class"]["claim_class_id"] = "supply_chain_posture_evidence"
        self._write_contract()
        self.assertIn("claim-class identity does not match", "\n".join(self.errors()))

    def test_finding_severity_and_runtime_promotions_fail_without_mutation(self):
        self.payload["findings"] = [{"severity": "high"}]
        self.payload["coverage_gaps"] = ["live scan found a verified finding; severity: high"]
        self.write_attempt()
        before = (self.attempt / "project-inventory.json").read_bytes()
        joined = "\n".join(self.errors())
        self.assertIn("finding promotion is forbidden", joined)
        self.assertIn("severity promotion is forbidden", joined)
        self.assertIn("runtime-state promotion is forbidden", joined)
        self.assertEqual((self.attempt / "project-inventory.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
