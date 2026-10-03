from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import automatic_evidence_inputs
import bounded_analysis_workers as bounded
import build_index
import bounded_transform_orchestration as orchestration
import execution_state
from execution_state import Blocked, atomic_json, file_hash, tree_hashes
import full_review_input_assembly as assembly
from publish_job_output import ACCEPTED_SCHEMA
from validate_job_output import NO_ORCHESTRATION_FACTS, validate_job_output
from worker_result import artifact_records, terminal_envelope
import intake


STAMP = "2026-09-27T12:00:00Z"
# The accepted-intake source projection lineage; the fixture projection is the staged in-run target.
PROJECTION_BINDING = {key: "fixture-" + key for key in automatic_evidence_inputs.SOURCE_BINDING_KEYS}


class FullReviewInputAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.runs = Path(self.temp.name) / "runs"
        self.run = self.runs / "review-1"
        self.target = self.run / "inputs" / "target"
        self.target.mkdir(parents=True)
        (self.target / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        self.manifest = self.run / "inputs" / "artifact-manifest.json"
        atomic_json(self.manifest, {"target": {"repo_path": str(self.target)}})
        self.generation = "sha256:" + file_hash(self.manifest)
        self.source = self._accepted_fuzz("data/upstream/fuzz", self.generation)
        projection = patch.object(automatic_evidence_inputs, "source_projection", side_effect=lambda _run_id: (
            self.target, dict(PROJECTION_BINDING), assembly._source_files(self.target)))
        projection.start()
        self.addCleanup(projection.stop)

    def tearDown(self):
        self.temp.cleanup()

    def _accepted_fuzz(self, relative: str, generation: str) -> Path:
        base = self.run / relative
        upstream = {"job_id": "fixture", "attempt_id": "fixture-1", "artifact_path": "fixture.json",
                    "artifact_sha256": "sha256:" + "1" * 64,
                    "accepted_pointer_sha256": "sha256:" + "2" * 64}
        result = bounded.fuzz_triage(run_id="review-1", attempt_id="source-1",
            source_generation=generation, bindings=[upstream], targets=[{
                "target_id": "target-1", "component_id": "component-1", "entrypoint": "LLVMFuzzerTestOneInput",
                "input_model": "bytes", "buildable": True, "deterministic": True, "isolation": "process",
                "blockers": [], "citation_ids": ["cite-1"]}])
        envelope = bounded.publish_attempt(base, result, started_at=STAMP, finished_at=STAMP)
        atomic_json(base / "latest.json", {"attempt_id": "source-1", "updated_at": STAMP})
        atomic_json(base / "accepted.json", {"schema": ACCEPTED_SCHEMA, "status": "OK_WITH_GAPS",
            "run_id": "review-1", "job": "13-fuzz-target-triage", "attempt_id": "source-1",
            "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
            "envelope_sha256": file_hash(base / "attempts/source-1/result.json"),
            "hashes": tree_hashes(base / "attempts/source-1"), "accepted_at": STAMP})
        return base / "accepted.json"

    def _accepted_component(self) -> Path:
        base = self.run / "data/jobs/01-component-characterization"
        attempt = base / "attempts/component-1"
        attempt.mkdir(parents=True)
        value = json.loads((ROOT / "tests/fixtures/component-characterization/hello-autotools.json").read_text())
        value["functional_components"][0]["representative_locations"] = ["main.c"]
        value["source_snapshot_sha256"] = "sha256:" + intake.source_identity(self.target)["fingerprint"]
        atomic_json(attempt / "component-purpose-map.json", value)
        atomic_json(attempt / "component-purpose-map.md", {"fixture": True})
        atomic_json(attempt / "status.json", {"process": "01-component-characterization", "status": "OK"})
        envelope = terminal_envelope(run_id="review-1", job_id="01-component-characterization",
            attempt_id="component-1", worker_kind="deterministic_python", execution_status="OK",
            acceptance_status="CURRENT", input_fingerprint="sha256:" + "a" * 64,
            output_contract="component-map", started_at=STAMP, finished_at=STAMP,
            summary="fixture component map", artifacts=artifact_records(attempt,
                ["component-purpose-map.json", "component-purpose-map.md", "status.json"]))
        atomic_json(attempt / "result.json", envelope)
        atomic_json(base / "latest.json", {"attempt_id": "component-1", "updated_at": STAMP})
        atomic_json(base / "accepted.json", {"schema": ACCEPTED_SCHEMA, "status": "OK",
            "run_id": "review-1", "job": "01-component-characterization", "attempt_id": "component-1",
            "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
            "envelope_sha256": file_hash(attempt / "result.json"), "hashes": tree_hashes(attempt),
            "accepted_at": STAMP})
        return base / "accepted.json"

    def _accepted_build_index(self) -> Path:
        """A real build index of the staged target; dependency request 1.1 binds it for the SBOM."""
        base = self.run / "data/jobs/02-build-index"
        if (base / "accepted.json").is_file():
            return base / "accepted.json"
        attempt = base / "attempts/index-1"
        attempt.mkdir(parents=True)
        source = intake.source_identity(str(self.target))
        records = {"source_revision": source["revision"], "source_fingerprint": source["fingerprint"],
                   "scope": {"excluded_paths": []}}
        partitions = {"schema": "appsec-review/repository-partition-map/0.1", "target": "fixture",
                      "source_revision": source["revision"], "partitions": [], "coverage": {}}
        inputs = [{"job": "00-intake", "artifact": "intake.json", "attempt_id": "0" * 32, "sha256": "a" * 64},
                  {"job": "02-repository-partition-discovery", "artifact": "repository-partition-map.json",
                   "attempt_id": "1" * 32, "sha256": "b" * 64}]
        atomic_json(attempt / "build-index.json",
                    build_index.build_index(self.target, source, records, partitions, inputs))
        envelope = terminal_envelope(run_id="review-1", job_id="02-build-index", attempt_id="index-1",
            worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
            input_fingerprint="sha256:" + "b" * 64, output_contract="build-index", started_at=STAMP,
            finished_at=STAMP, summary="fixture build index",
            artifacts=artifact_records(attempt, ["build-index.json"]))
        atomic_json(attempt / "result.json", envelope)
        atomic_json(base / "latest.json", {"attempt_id": "index-1", "updated_at": STAMP})
        atomic_json(base / "accepted.json", {"schema": ACCEPTED_SCHEMA, "status": "OK",
            "run_id": "review-1", "job": "02-build-index", "attempt_id": "index-1",
            "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
            "envelope_sha256": file_hash(attempt / "result.json"), "hashes": tree_hashes(attempt),
            "accepted_at": STAMP})
        return base / "accepted.json"

    def _plan(self, *, sources=None) -> Path:
        self._accepted_build_index()
        sources = sources or [{"alias": "fuzz-source", "pointer_path": "data/upstream/fuzz/accepted.json",
            "job_id": "13-fuzz-target-triage", "contract": "fuzz-target-triage",
            "artifact": "fuzz-target-triage.json", "artifact_schema": "fuzz-target-triage.schema.json",
            "generation_pointer": "/source_generation"},
            {**assembly.BUILD_INDEX_SOURCE, "pointer_path": "data/jobs/02-build-index/accepted.json"}]
        value = {"schema": assembly.PLAN_SCHEMA, "run_id": "review-1",
            "source_generation": self.generation, "generated_at": STAMP, "accepted_sources": sources,
            "launches": [
                {"adapter": "bounded", "job_id": "13-fuzz-target-triage", "upstream": ["fuzz-source"],
                 "payload": {"targets": [{"target_id": "target-2", "component_id": "component-1",
                    "entrypoint": "parse_packet", "input_model": "bytes", "buildable": True,
                    "deterministic": True, "isolation": "process", "blockers": [],
                    "citation_ids": [{"$accepted": "fuzz-source", "pointer": "/targets/0/citation_ids/0"}]}]}},
                {"adapter": "vendor", "job_id": "02-secrets-inventory",
                 "source_root": {"$run_path": "inputs/target", "kind": "directory"}},
                {"adapter": "dependency", "job_id": "02-sbom-inventory",
                 "payload": {"source_files": {"$source_files": "inputs/target"},
                             "build_index": {"$binding": "build-index"}},
                 "tool": {"target_path": {"$run_path": "inputs/target", "kind": "directory"}}}
            ]}
        plan = self.run / "inputs" / "full-review-plan.json"
        atomic_json(plan, value)
        return plan

    def _assemble(self, plan: Path | None = None):
        output = self.run / "data/jobs/02-full-review-input-assembly"
        result = assembly.assemble(plan or self._plan(), self.run.absolute(), output,
            attempt_id="assembly-1", started_at=STAMP, finished_at=STAMP)
        return output, result

    def test_accepted_assembly_emits_all_three_existing_request_dialects(self):
        output, result = self._assemble()
        self.assertEqual([row["adapter"] for row in result["requests"]],
                         ["dependency", "vendor", "bounded"])
        attempt = output / "attempts/assembly-1"
        bounded_request = json.loads((attempt / "requests/13-fuzz-target-triage.json").read_text())
        vendor_request = json.loads((attempt / "requests/02-secrets-inventory.json").read_text())
        dependency_request = json.loads((attempt / "requests/02-sbom-inventory.json").read_text())
        self.assertEqual(bounded_request["schema"], orchestration.REQUEST_SCHEMA)
        self.assertEqual(bounded_request["payload"]["targets"][0]["citation_ids"], ["cite-1"])
        self.assertEqual(vendor_request["source_root"], str(self.target.absolute()))
        self.assertEqual(dependency_request["payload"]["source_files"],
                         {"main.c": "sha256:" + file_hash(self.target / "main.c")})
        pointer = json.loads((output / "accepted.json").read_text())
        self.assertEqual(pointer["schema"], ACCEPTED_SCHEMA)
        self.assertEqual(pointer["hashes"], tree_hashes(attempt))
        envelope = json.loads((attempt / "result.json").read_text())
        self.assertEqual(validate_job_output(attempt, envelope, pointer["fingerprint"],
            expected_run_id="review-1", expected_job_id=assembly.JOB,
            orchestration=NO_ORCHESTRATION_FACTS), [])

    def test_assembled_bounded_request_executes_through_public_adapter(self):
        output, _ = self._assemble()
        request = output / "attempts/assembly-1/requests/13-fuzz-target-triage.json"
        target_root = self.run / "data/jobs/13-fuzz-target-triage"
        with patch.object(execution_state, "RUNS", self.runs), \
             patch.object(orchestration, "run_path", execution_state.run_path), \
             patch.object(orchestration, "data_path", execution_state.data_path):
            envelope = orchestration.execute(job_id="13-fuzz-target-triage", run_id="review-1",
                input_path=str(request), output_root=str(target_root), attempt_id="downstream-1")
        self.assertEqual(envelope["acceptance_status"], "CURRENT")
        result = json.loads((target_root / "attempts/downstream-1/fuzz-target-triage.json").read_text())
        self.assertEqual(result["upstream"][0]["attempt_id"], "source-1")
        self.assertEqual(result["targets"][0]["target_id"], "target-2")

    def test_component_map_derives_exact_first_wave_and_explicit_na_rows(self):
        pointer = self._accepted_component()
        self._accepted_build_index()
        plan_path = self.run / "inputs/derived-full-review-plan.json"
        plan = assembly.derive_plan(pointer, self.run.absolute(), plan_path,
            run_id="review-1", generated_at=STAMP)
        self.assertEqual([row["job_id"] for row in plan["launches"]],
            ["02-sbom-inventory", "02-secrets-inventory", "05-native-memory"])
        self.assertIn("02-binary-hardening", {row["job_id"] for row in plan["skipped"]})
        output, result = self._assemble(plan_path)
        self.assertEqual([row["job_id"] for row in result["requests"]],
            ["02-sbom-inventory", "02-secrets-inventory", "05-native-memory"])
        sbom = json.loads((output / "attempts/assembly-1/requests/02-sbom-inventory.json").read_text())
        self.assertEqual(sbom["payload"]["build_index"]["attempt_id"], "index-1")
        native = json.loads((output / "attempts/assembly-1/requests/05-native-memory.json").read_text())
        self.assertEqual(native["payload"]["units"][0]["path"], "main.c")
        self.assertEqual(native["payload"]["units"][0]["citations"][0]["observed_fact"],
                         "Writes the fixture greeting and exits.")

    def test_sbom_without_accepted_build_index_is_an_explicit_skip(self):
        plan = assembly.derive_plan(self._accepted_component(), self.run.absolute(),
            self.run / "inputs/derived-full-review-plan.json", run_id="review-1", generated_at=STAMP)
        self.assertNotIn("02-sbom-inventory", [row["job_id"] for row in plan["launches"]])
        skipped = {row["job_id"]: row["reason"] for row in plan["skipped"]}
        self.assertIn("02-build-index", skipped["02-sbom-inventory"])

    def test_dockerfile_and_workflows_are_iac_inputs(self):
        for path in ("Dockerfile", "docker/api.Dockerfile", "Containerfile", "Dockerfile.dev",
                     ".github/workflows/ci.yml", "infra/main.tf", "deploy/app.yaml"):
            self.assertTrue(assembly._iac_input(path), path)
        for path in ("main.c", "config.yaml", "docs/workflows/ci.yml"):
            self.assertFalse(assembly._iac_input(path), path)

    def test_derived_requests_dispatch_and_collect_exact_results(self):
        pointer = self._accepted_component()
        self._accepted_build_index()
        plan = self.run / "inputs/derived-full-review-plan.json"
        assembly.derive_plan(pointer, self.run.absolute(), plan, run_id="review-1", generated_at=STAMP)
        output, _ = self._assemble(plan)
        observed = []

        def qualified_executor(adapter, job_id, request_path, run_root, attempt_id, dagster_run_id):
            request = json.loads(request_path.read_text())
            observed.append((adapter, job_id, request["source_generation"], attempt_id, dagster_run_id))
            if adapter == "bounded":
                return assembly._dispatch_one(adapter, job_id, request_path, run_root,
                                              attempt_id, dagster_run_id)
            return {"status": "CURRENT", "job_id": job_id,
                    "request_sha256": "sha256:" + file_hash(request_path)}

        with patch.object(execution_state, "RUNS", self.runs), \
             patch.object(orchestration, "run_path", execution_state.run_path), \
             patch.object(orchestration, "data_path", execution_state.data_path):
            dispatched = assembly.dispatch(output, self.run.absolute(),
                self.run / "data/jobs/02-full-review-input-dispatch", attempt_id="dispatch-1",
                dagster_run_id="dagster-1", started_at=STAMP, finished_at=STAMP,
                executor=qualified_executor)
        self.assertEqual([row[1] for row in observed],
            ["02-sbom-inventory", "02-secrets-inventory", "05-native-memory"])
        self.assertEqual(len(dispatched["results"]), 3)
        self.assertTrue(all(row["status"] == "CURRENT" for row in dispatched["results"]))
        self.assertEqual(len(list((self.run / "data/jobs/05-native-memory/attempts").glob("full-dispatch-1-*"))), 1)
        dispatch_root = self.run / "data/jobs/02-full-review-input-dispatch"
        pointer_value = json.loads((dispatch_root / "accepted.json").read_text())
        self.assertEqual(pointer_value["hashes"], tree_hashes(dispatch_root / "attempts/dispatch-1"))

    def test_stale_plan_and_mixed_accepted_generation_fail_closed(self):
        plan = self._plan()
        value = json.loads(plan.read_text())
        value["source_generation"] = "sha256:" + "0" * 64
        atomic_json(plan, value)
        with self.assertRaisesRegex(Blocked, "plan source generation is stale"):
            self._assemble(plan)

        plan = self._plan()
        other = self._accepted_fuzz("data/upstream/other", "sha256:" + "9" * 64)
        value = json.loads(plan.read_text())
        value["accepted_sources"].append({"alias": "other", "pointer_path": str(other.relative_to(self.run)),
            "job_id": "13-fuzz-target-triage", "contract": "fuzz-target-triage",
            "artifact": "fuzz-target-triage.json", "artifact_schema": "fuzz-target-triage.schema.json",
            "generation_pointer": "/source_generation"})
        atomic_json(plan, value)
        with self.assertRaisesRegex(Blocked, "stale or mixed generation"):
            self._assemble(plan)

    def test_traversal_and_unknown_resolver_fail_closed(self):
        plan = self._plan()
        value = json.loads(plan.read_text())
        value["accepted_sources"][0]["pointer_path"] = "../outside/accepted.json"
        atomic_json(plan, value)
        with self.assertRaisesRegex(Blocked, "normalized relative path"):
            self._assemble(plan)
        plan = self._plan()
        value = json.loads(plan.read_text())
        value["launches"][0]["payload"]["targets"][0]["citation_ids"] = [{"$unknown": "x"}]
        atomic_json(plan, value)
        with self.assertRaisesRegex(Blocked, "resolver expression is not closed"):
            self._assemble(plan)


if __name__ == "__main__":
    unittest.main()
