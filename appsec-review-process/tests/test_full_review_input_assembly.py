from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import bounded_analysis_workers as bounded
import bounded_transform_orchestration as orchestration
import execution_state
from execution_state import Blocked, atomic_json, file_hash, tree_hashes
import full_review_input_assembly as assembly
from publish_job_output import ACCEPTED_SCHEMA
from validate_job_output import NO_ORCHESTRATION_FACTS, validate_job_output


STAMP = "2026-09-27T12:00:00Z"


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

    def _plan(self, *, sources=None) -> Path:
        sources = sources or [{"alias": "fuzz-source", "pointer_path": "data/upstream/fuzz/accepted.json",
            "job_id": "13-fuzz-target-triage", "contract": "fuzz-target-triage",
            "artifact": "fuzz-target-triage.json", "artifact_schema": "fuzz-target-triage.schema.json",
            "generation_pointer": "/source_generation"}]
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
                 "payload": {"source_files": {"$source_files": "inputs/target"}},
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
