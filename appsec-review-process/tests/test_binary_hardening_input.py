from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

PROCESS = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(PROCESS))

import binary_hardening_input as subject
import execution_state
from execution_state import Blocked


class BinaryHardeningInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get("APPSEC_RUNS_ROOT")
        execution_state.RUNS = Path(self.temp.name) / "runs"
        self.run_id = "binary-route"
        self.run = execution_state.run_path(self.run_id)
        (self.run / "inputs").mkdir(parents=True)
        (self.run / "inputs/artifact-manifest.json").write_text(
            json.dumps({"target": {"repo_path": "/not-used"}}), encoding="utf-8")
        self.native_root = execution_state.data_path(self.run_id, "jobs", "02-native-build")
        self.attempt = self.native_root / "attempts/native-1"
        self.binary = self.attempt / "outputs/unit-a/binaries/bin/hello"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"\x7fELF" + b"fixture" * 8)
        sha = "sha256:" + hashlib.sha256(self.binary.read_bytes()).hexdigest()
        result = {"schema": "appsec-review/native-build/1", "run_id": self.run_id,
            "source_revision": "abc", "upstream": {}, "status": "OK", "coverage_gaps": [],
            "units": [{"unit_id": "unit-a", "status": "OK", "image_id": "image_build_123456789abc",
                "image_digest": "sha256:" + "1" * 64, "commands": [{}, {}],
                "compile_database": {"path": "x", "sha256": "sha256:" + "2" * 64, "entries": 1},
                "binaries": [{"source_path": "bin/hello", "artifact_path": "outputs/unit-a/binaries/bin/hello",
                    "sha256": sha, "size_bytes": self.binary.stat().st_size}]}]}
        (self.attempt / "native-build.json").write_text(json.dumps(result), encoding="utf-8")
        (self.attempt / "result.json").write_text(json.dumps({"status": "CURRENT"}), encoding="utf-8")
        self.native_root.mkdir(parents=True, exist_ok=True)
        (self.native_root / "accepted.json").write_text(json.dumps({"attempt_id": "native-1"}), encoding="utf-8")
        self.validate = mock.patch.object(subject.native_build, "validate", return_value=self.attempt)
        self.root = mock.patch.object(subject.native_build, "root", return_value=self.native_root)
        self.validate.start(); self.root.start()

    def tearDown(self):
        self.validate.stop(); self.root.stop()
        if self.previous is None:
            os.environ.pop("APPSEC_RUNS_ROOT", None)
        else:
            os.environ["APPSEC_RUNS_ROOT"] = self.previous
        self.temp.cleanup()

    def test_stages_only_declared_accepted_binaries_and_reuses_identically(self):
        (self.attempt / "tool.log").write_text("not an input", encoding="utf-8")
        root = subject.stage(self.run_id)
        self.assertEqual((root / "unit-a/bin/hello").read_bytes(), self.binary.read_bytes())
        self.assertFalse((root / "tool.log").exists())
        self.assertEqual(subject.stage(self.run_id), root)
        manifest = subject.validate(self.run_id, root)
        self.assertEqual(manifest["native_build"]["attempt_id"], "native-1")

    def test_tampered_staged_or_native_binary_fails_closed(self):
        root = subject.stage(self.run_id)
        (root / "unit-a/bin/hello").write_bytes(b"changed")
        with self.assertRaisesRegex(Blocked, "staged binary changed"):
            subject.validate(self.run_id, root)
        (root / "unit-a/bin/hello").write_bytes(self.binary.read_bytes())
        self.binary.write_bytes(b"\x7fELFchanged")
        with self.assertRaisesRegex(Blocked, "accepted native binary changed"):
            subject.validate(self.run_id, root)

    def test_request_points_at_the_projected_native_binaries(self):
        path = subject.stage_request(self.run_id, "dagster-1")
        request = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(request["job_id"], "02-binary-hardening")
        self.assertEqual(Path(request["source_root"]),
                         execution_state.data_path(self.run_id, "jobs", "02-binary-hardening",
                                                   "inputs", "native-1", "binaries"))


if __name__ == "__main__":
    unittest.main()
