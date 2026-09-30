"""Brief N / ADR-0014 item 6: per (unit, tool group) memo for 02-native-sast.

End to end through native_sast.run with scripted B13 trials: a hit re-verifies the owner trial,
publishes a byte-identical copy of its raw analyzer outputs and validates; tampering is a miss.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_execution as ce  # noqa: E402
import container_execution_support as support  # noqa: E402
import execution_state as state  # noqa: E402
import native_sast as worker  # noqa: E402
from test_container_execution import ScriptedDocker  # noqa: E402
from test_native_sast import FIXTURE, accepted_native_build  # noqa: E402

RUN = "run-e03"


class NativeSastMemoTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.native_base, _attempt, self.target, self.fingerprint = accepted_native_build(self.root / "native")
        defaults = {**ce.host_defaults()}
        defaults["docker_executable"] = defaults["docker_executable"] or Path(sys.executable).resolve()
        if not ce._USER_RE.match(defaults["container_user"]):
            defaults["container_user"] = "10001:10001"
        real_registry = ce.load_image_registry
        audit_native = {**support.fixture_record(), "image_id": worker.IMAGE_ID}

        def registry(directory):
            return {**real_registry(directory), worker.IMAGE_ID: audit_native}
        self.containers = 0
        scripted = ScriptedDocker()
        original = scripted.child

        def child(spec, **kwargs):
            self.containers += 1
            result = original(spec, **kwargs)
            trial = Path(spec.owner_root)
            if trial.name == "clang-cppcheck":
                out = trial / "scratch/native-sast"; out.mkdir(parents=True, exist_ok=True)
                for name in ("findings-clang-tidy.json", "native-sast-manifest.json", "cppcheck.xml"):
                    shutil.copyfile(FIXTURE / name, out / name)
                (out / "clang-tidy.log").write_text("raw diagnostic\n")
            else:
                out = trial / "scratch/csa"; out.mkdir(parents=True, exist_ok=True)
                for name in ("findings-csa.json", "csa-summary.json"):
                    shutil.copyfile(FIXTURE / name, out / name)
            return result
        scripted.child = child
        docker, execute = scripted.patches()
        for patch in (mock.patch.object(state, "RUNS", self.root / "runs"),
                      mock.patch.dict(os.environ, {"APPSEC_CACHE_ROOT": str(self.root / "cache"),
                                                   "APPSEC_RUN_MODE": "dev"}),
                      mock.patch.object(ce, "host_defaults", return_value=defaults),
                      mock.patch.object(ce, "load_image_registry", side_effect=registry),
                      docker, execute):
            patch.start(); self.addCleanup(patch.stop)
        state.run_path(RUN).mkdir(parents=True)

    def run_job(self, dagster, force=False):
        return worker.run(RUN, dagster, native_build_root=self.native_base,
                          native_build_fingerprint=self.fingerprint, force=force)

    def attempt(self, pointer):
        return worker.root(RUN) / "attempts" / pointer["attempt_id"]

    def test_unchanged_unit_groups_are_reused_copied_and_validated(self):
        first = self.run_job("d1")
        self.assertEqual((first["status"], self.containers), ("OK_WITH_GAPS", 2))
        second = self.run_job("d2", force=True)
        self.assertEqual(self.containers, 2, "memo hits must not start containers")
        attempt = self.attempt(second)
        receipts = state.read_json(attempt / worker.RECEIPTS)
        self.assertEqual({r["owner_attempt_id"] for r in receipts}, {first["attempt_id"]})
        for receipt in receipts:
            self.assertEqual(worker._scratch_hashes(attempt / receipt["trial_path"]),
                             worker._scratch_hashes(self.attempt(first) / receipt["trial_path"]))
        old = state.read_json(self.attempt(first) / worker.RESULT)
        new = state.read_json(attempt / worker.RESULT)
        self.assertEqual(old["units"], new["units"])
        self.assertEqual(worker.validate(RUN, native_build_root=self.native_base,
                                         native_build_fingerprint=self.fingerprint), attempt)

    def test_tampered_owner_trial_runs_fresh(self):
        first = self.run_job("d1")
        [receipt, _] = state.read_json(self.attempt(first) / worker.RECEIPTS)
        (self.attempt(first) / receipt["trial_path"] / "logs/container/stdout.log").write_bytes(b"x\n")
        self.run_job("d2", force=True)
        self.assertEqual(self.containers, 3)   # the tampered group reran, the other was reused

    def test_tampered_owner_raw_output_runs_fresh(self):
        first = self.run_job("d1")
        [receipt, _] = state.read_json(self.attempt(first) / worker.RECEIPTS)
        (self.attempt(first) / receipt["trial_path"] / "scratch/native-sast/clang-tidy.log").write_text("forged\n")
        self.run_job("d2", force=True)
        self.assertEqual(self.containers, 3)

    def test_edited_copy_fails_validation(self):
        self.run_job("d1")
        second = self.run_job("d2", force=True)
        attempt = self.attempt(second)
        [receipt, _] = state.read_json(attempt / worker.RECEIPTS)
        (attempt / receipt["trial_path"] / "scratch/native-sast/clang-tidy.log").write_text("forged\n")
        with self.assertRaises(state.Blocked):
            worker._validate_attempt(RUN, attempt, state.read_json(attempt / "inputs.json"))

    def test_prod_default_runs_every_group(self):
        with mock.patch.dict(os.environ, {"APPSEC_RUN_MODE": "prod"}):
            self.run_job("d1")
            self.run_job("d2", force=True)
        self.assertEqual(self.containers, 4)


if __name__ == "__main__":
    unittest.main()
