"""Focused mutation tests for the machine-readable design-parity inventory."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))

from validate_design_parity import (
    render_mermaid,
    render_readiness,
    render_report,
    resolve_repo_path,
    validate_manifest,
    validate_worker_result,
)


class DesignParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((ROOT / "design-parity-manifest.json").read_text(encoding="utf-8"))

    def mutated(self):
        return deepcopy(self.manifest)

    def errors(self, manifest, repo=REPO):
        return "\n".join(validate_manifest(manifest, repo=repo)["errors"])

    def record(self, manifest, job_id):
        return next(record for record in manifest["jobs"] if record["id"] == job_id)

    def copy_repo(self, destination):
        repo = Path(destination)
        shutil.copytree(ROOT, repo / "appsec-review-process", ignore=shutil.ignore_patterns("runs", "__pycache__"))
        shutil.copytree(resolve_repo_path("orchestrator/dagster"), repo / "orchestrator/dagster")
        shutil.copytree(resolve_repo_path("schemas"), repo / "schemas")
        (repo / "docs").mkdir()
        outputs = {"full-review-workflow.mmd": render_mermaid(self.manifest),
                   "design-parity-readiness.md": render_readiness(self.manifest)}
        for name, content in outputs.items():
            source = REPO / "docs" / name
            if source.is_file():
                shutil.copy2(source, repo / "docs" / name)
            else:
                (repo / "docs" / name).write_text(content, encoding="utf-8")
        return repo

    def test_current_honest_baseline(self):
        result = validate_manifest(self.manifest)
        self.assertEqual(result["status"], "PASS", result["errors"])
        self.assertEqual(result["job_count"], 51)
        self.assertEqual(result["capability_count"], 15)
        self.assertIn("resource_pools: no dedicated Dagster resource pools are configured", result["gaps"])

    def test_missing_and_extra_graph_nodes(self):
        missing = self.mutated()
        missing["jobs"].pop()
        self.assertIn("manifest missing graph jobs", self.errors(missing))
        extra = self.mutated()
        clone = deepcopy(extra["jobs"][0])
        clone["id"] = clone["graph"]["node"] = "99-not-in-graph"
        extra["jobs"].append(clone)
        self.assertIn("manifest has jobs absent from graph", self.errors(extra))

    def test_duplicate_ids(self):
        manifest = self.mutated()
        manifest["jobs"].append(deepcopy(manifest["jobs"][0]))
        self.assertIn("duplicate job id", self.errors(manifest))

    def test_broken_registry_composition_reference(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            shutil.copytree(ROOT, repo / "appsec-review-process", ignore=shutil.ignore_patterns("runs", "__pycache__"))
            shutil.copytree(resolve_repo_path("orchestrator/dagster"), repo / "orchestrator/dagster")
            template = repo / "appsec-review-process/registry/job-templates/00-intake.json"
            value = json.loads(template.read_text(encoding="utf-8"))
            value["composition"]["persona_id"] = "missing-persona"
            template.write_text(json.dumps(value), encoding="utf-8")
            self.assertIn("broken registry composition", self.errors(self.mutated(), repo))

    def test_missing_worker_validator_contract_and_schema(self):
        fields = [
            ("execution", "worker", "appsec-review-process/missing.py:run", "missing worker entrypoint"),
            ("execution", "validator", "appsec-review-process/missing.py:validate", "missing validator entrypoint"),
            ("output", "contract_file", "missing-contract.json", "missing declared contract_file"),
            ("output", "schema_file", "missing-schema.json", "missing declared schema_file"),
        ]
        for section, field, value, expected in fields:
            with self.subTest(field=field):
                manifest = self.mutated()
                self.record(manifest, "00-intake")[section][field] = value
                self.assertIn(expected, self.errors(manifest))

    def test_registry_result_schema_identity_mismatch(self):
        manifest = self.mutated()
        self.record(manifest, "02-ossf-scorecard")["output"]["schema_file"] = None
        self.assertIn("registry result-schema identity mismatch", self.errors(manifest))

    def test_registry_claim_class_identity_mismatch(self):
        manifest = self.mutated()
        self.record(manifest, "02-ossf-scorecard")["output"]["claim_class"] = "verified_finding"
        self.assertIn("registry claim-class identity mismatch", self.errors(manifest))

    def test_false_implemented_and_qualified_claim(self):
        manifest = self.mutated()
        record = self.record(manifest, "02-devops-project-discovery")
        record["readiness"] = "implemented_and_qualified"
        self.assertIn("false implemented_and_qualified claim", self.errors(manifest))

    def test_standalone_only_conflicts_with_lifecycle_wiring(self):
        manifest = self.mutated()
        self.record(manifest, "02-build-configure")["readiness"] = "standalone_only"
        self.assertIn("standalone_only conflicts", self.errors(manifest))

    def test_supplied_gate_cannot_be_called_automatic_dispatch(self):
        manifest = self.mutated()
        record = self.record(manifest, "02-repository-partition-discovery")
        record["execution"]["mode"] = "persona"
        self.assertIn("supplied-artifact readiness requires", self.errors(manifest))

    def test_blocked_op_cannot_be_called_implemented(self):
        manifest = self.mutated()
        self.record(manifest, "02-devops-project-discovery")["readiness"] = "implemented_not_qualified"
        self.assertIn("blocked_op cannot be classified", self.errors(manifest))

    def test_launcher_and_sensor_mismatch(self):
        launcher = self.mutated()
        launcher["dagster_inventory"]["launcher_jobs"].pop()
        self.assertIn("launcher job mismatch", self.errors(launcher))
        sensor = self.mutated()
        sensor["dagster_inventory"]["failure_sensor_jobs"].pop()
        self.assertIn("failure_sensor_jobs mismatch", self.errors(sensor))

    def test_unassigned_pool_is_an_explicit_gap_not_an_invented_default(self):
        result = validate_manifest(self.manifest)
        self.assertEqual(result["status"], "PASS")
        self.assertIn("02-evidence-index: resource pool unassigned", result["gaps"])

    def test_qualification_reference_mutation(self):
        manifest = self.mutated()
        self.record(manifest, "00-intake")["qualification"]["references"][0] = "missing-qualification.json"
        self.assertIn("missing qualification reference", self.errors(manifest))

    def test_deterministic_report_output(self):
        result = validate_manifest(self.manifest)
        first = render_report(self.manifest, result)
        second = render_report(deepcopy(self.manifest), validate_manifest(deepcopy(self.manifest)))
        self.assertEqual(first, second)
        self.assertIn("Lifecycle jobs: **51**", first)

    def test_common_worker_result_envelope_semantics(self):
        base = {
            "schema": "appsec-review/worker-result-envelope/1.0",
            "run_id": "run-1", "job_id": "02-source-sast", "attempt_id": "attempt-1",
            "worker_kind": "pinned_container", "execution_status": "OK",
            "acceptance_status": "CURRENT", "input_fingerprint": "sha256:" + "a" * 64,
            "output_contract": "source-sast", "started_at": "2026-09-19T10:00:00Z",
            "finished_at": "2026-09-19T10:01:00Z", "summary": "completed",
            "artifacts": [], "gaps": [], "skip_reason": None, "cause": None,
            "retry": {"allowed": False, "resume_command": None},
            "superseded_by_attempt_id": None,
        }
        self.assertEqual(validate_worker_result(base), [])
        skipped = deepcopy(base)
        skipped["execution_status"] = "SKIPPED"
        self.assertIn("SKIPPED requires", "\n".join(validate_worker_result(skipped)))
        unresolved = deepcopy(base)
        unresolved["execution_status"] = "UNRESOLVED"
        unresolved["acceptance_status"] = "NOT_ACCEPTED"
        self.assertIn("requires at least one explicit gap", "\n".join(validate_worker_result(unresolved)))
        superseded = deepcopy(base)
        superseded["acceptance_status"] = "SUPERSEDED"
        self.assertIn("requires the replacement attempt", "\n".join(validate_worker_result(superseded)))

    def test_terminal_transition_contract_mutations(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.copy_repo(temporary)
            path = repo / "appsec-review-process/worker-result-contract.json"
            contract = json.loads(path.read_text(encoding="utf-8"))
            contract["execution_states"]["transitions"]["OK"] = ["RUNNING"]
            path.write_text(json.dumps(contract), encoding="utf-8")
            self.assertIn("terminal state OK has outgoing transitions", self.errors(self.mutated(), repo))

    def test_graph_cycle_and_unreachable_mutations(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.copy_repo(temporary)
            path = repo / "appsec-review-process/job-graph.json"
            graph = json.loads(path.read_text(encoding="utf-8"))
            graph["jobs"]["00-intake"]["dependencies"] = [{
                "job": "10-synthesis-report", "kind": "required",
                "contract": "10-synthesis-report", "allowed_skip_reasons": []}]
            path.write_text(json.dumps(graph), encoding="utf-8")
            errors = self.errors(self.mutated(), repo)
            self.assertIn("graph root has dependencies", errors)
            self.assertIn("graph dependency cycle", errors)
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.copy_repo(temporary)
            path = repo / "appsec-review-process/job-graph.json"
            graph = json.loads(path.read_text(encoding="utf-8"))
            graph["jobs"]["02-operations-doc-ingest"]["dependencies"] = []
            path.write_text(json.dumps(graph), encoding="utf-8")
            self.assertIn("graph nodes unreachable", self.errors(self.mutated(), repo))

    def test_graph_dependency_semantics_mutations(self):
        mutations = [
            ("kind", "unknown", "invalid dependency kind"),
            ("contract", "wrong-contract", "dependency contract mismatch"),
            ("allowed_skip_reasons", ["invented-skip"], "unknown skip reasons"),
        ]
        for field, value, expected in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                repo = self.copy_repo(temporary)
                path = repo / "appsec-review-process/job-graph.json"
                graph = json.loads(path.read_text(encoding="utf-8"))
                dependency = graph["jobs"]["10-synthesis-report"]["dependencies"][-1]
                dependency[field] = value
                path.write_text(json.dumps(graph), encoding="utf-8")
                self.assertIn(expected, self.errors(self.mutated(), repo))

    def test_graph_namespace_collision(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.copy_repo(temporary)
            path = repo / "appsec-review-process/job-graph.json"
            graph = json.loads(path.read_text(encoding="utf-8"))
            graph["jobs"]["02-ossf-scorecard"]["namespace"] = "00-intake"
            path.write_text(json.dumps(graph), encoding="utf-8")
            self.assertIn("graph namespace collision", self.errors(self.mutated(), repo))

    def test_optional_dependency_requires_skip_reason(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.copy_repo(temporary)
            path = repo / "appsec-review-process/job-graph.json"
            graph = json.loads(path.read_text(encoding="utf-8"))
            dependency = graph["jobs"]["10-synthesis-report"]["dependencies"][-2]
            dependency["kind"] = "optional"
            dependency["allowed_skip_reasons"] = []
            path.write_text(json.dumps(graph), encoding="utf-8")
            self.assertIn("optional dependency", self.errors(self.mutated(), repo))

    def test_generated_views_are_deterministic_and_current(self):
        mermaid = render_mermaid(self.manifest)
        readiness = render_readiness(self.manifest)
        self.assertEqual(mermaid, render_mermaid(deepcopy(self.manifest)))
        self.assertEqual(readiness, render_readiness(deepcopy(self.manifest)))
        if (REPO / "appsec-review-process").is_dir():
            self.assertEqual((REPO / "docs/full-review-workflow.mmd").read_text(encoding="utf-8"), mermaid)
            self.assertEqual((REPO / "docs/design-parity-readiness.md").read_text(encoding="utf-8"), readiness)

    def test_stale_generated_view_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.copy_repo(temporary)
            path = repo / "docs/full-review-workflow.mmd"
            path.write_text(path.read_text(encoding="utf-8") + "%% stale\n", encoding="utf-8")
            self.assertIn("stale generated lifecycle_mermaid", self.errors(self.mutated(), repo))


if __name__ == "__main__":
    unittest.main(verbosity=2)
