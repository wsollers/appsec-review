"""Shared lifecycle integration for the independently qualified bounded transforms."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import bounded_transform_orchestration as adapter
import execution_state
from execution_state import Blocked, file_hash


class BoundedTransformOrchestrationTests(unittest.TestCase):
    def make_run(self, folder: str):
        runs = Path(folder) / "runs"
        owner = runs / "run-1"
        (owner / "inputs").mkdir(parents=True)
        (owner / "data" / "requests").mkdir(parents=True)
        manifest = owner / "inputs" / "artifact-manifest.json"
        manifest.write_text('{"source":"fixture"}\n', encoding="utf-8")
        return runs, owner, "sha256:" + file_hash(manifest)

    def test_explicit_run_owned_request_calls_only_facade_seams(self):
        with tempfile.TemporaryDirectory() as folder:
            runs, owner, generation = self.make_run(folder)
            pointer = owner / "data" / "upstream" / "accepted.json"
            pointer.parent.mkdir()
            pointer.write_text("{}\n", encoding="utf-8")
            request = owner / "data" / "requests" / "native.json"
            request.write_text(json.dumps({
                "schema": adapter.REQUEST_SCHEMA, "run_id": "run-1", "job_id": "05-native-memory",
                "source_generation": generation,
                "upstream": [{"pointer_path": str(pointer), "job_id": "02-native-sast",
                              "contract": "native-sast", "artifact": "native-sast.json",
                              "schema": "native-sast.schema.json"}],
                "payload": {"units": []},
            }), encoding="utf-8")
            calls = []

            def load(path, **kwargs):
                calls.append(("load", path, kwargs))
                return {}, {"job_id": kwargs["job_id"], "attempt_id": "up-1",
                            "artifact_path": kwargs["artifact"], "artifact_sha256": "sha256:" + "a" * 64,
                            "accepted_pointer_sha256": "sha256:" + "b" * 64}

            def analyze(**kwargs):
                calls.append(("analyze", kwargs))
                return {"job_id": "05-native-memory", "attempt_id": kwargs["attempt_id"]}

            def publish(root, result, **kwargs):
                calls.append(("publish", root, result, kwargs))
                return {"attempt_id": result["attempt_id"], "job_id": result["job_id"]}

            facade = SimpleNamespace(load_upstream=load, analyze=analyze, publish_attempt=publish)
            with patch.object(execution_state, "RUNS", runs), \
                 patch.object(adapter, "run_path", execution_state.run_path), \
                 patch.object(adapter, "data_path", execution_state.data_path), \
                 patch.dict(adapter.FACADES, {"05-native-memory": (facade, "analyze", "units")}):
                result = adapter.execute(job_id="05-native-memory", run_id="run-1",
                    input_path=str(request), output_root=str(owner / "data/jobs/05-native-memory"),
                    attempt_id="attempt-1")
            self.assertEqual(result["attempt_id"], "attempt-1")
            self.assertEqual([row[0] for row in calls], ["load", "analyze", "publish"])
            self.assertEqual(calls[1][1]["source_generation"], generation)
            self.assertEqual(calls[2][1], owner / "data/jobs/05-native-memory")

    def test_missing_or_cross_run_inputs_fail_closed_before_facade(self):
        with tempfile.TemporaryDirectory() as folder:
            runs, owner, generation = self.make_run(folder)
            request = owner / "data" / "requests" / "native.json"
            base = {"schema": adapter.REQUEST_SCHEMA, "run_id": "run-1", "job_id": "05-native-memory",
                    "source_generation": generation, "upstream": [], "payload": {"units": []}}
            request.write_text(json.dumps(base), encoding="utf-8")
            with patch.object(execution_state, "RUNS", runs), \
                 patch.object(adapter, "run_path", execution_state.run_path), \
                 patch.object(adapter, "data_path", execution_state.data_path):
                with self.assertRaisesRegex(Blocked, "at least one accepted upstream"):
                    adapter.execute(job_id="05-native-memory", run_id="run-1", input_path=str(request),
                        output_root=str(owner / "data/jobs/05-native-memory"), attempt_id="attempt-1")
                with self.assertRaisesRegex(Blocked, "input path is not run-owned"):
                    adapter.execute(job_id="05-native-memory", run_id="run-1",
                        input_path=str(Path(folder) / "outside.json"),
                        output_root=str(owner / "data/jobs/05-native-memory"), attempt_id="attempt-1")


if __name__ == "__main__":
    unittest.main()
