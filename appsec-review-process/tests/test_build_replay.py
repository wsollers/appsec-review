"""Focused happy-path tests for stages 14 and 15."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import build_replay as worker  # noqa: E402
import execution_state as state  # noqa: E402
import permission_capabilities as permissions  # noqa: E402


class BuildReplayTests(unittest.TestCase):
    LOCK = {
        "unit_id": "dir:.",
        "image": {"image_id": "image_build_123456789abc", "digest": "sha256:" + "b" * 64,
                  "digest_kind": "image-id"},
        "configure": [{"phase": "configure", "argv": ["autoreconf", "-fi"], "cwd": "."},
                      {"phase": "configure", "argv": ["./configure"], "cwd": "."}],
        "build": [{"phase": "build", "argv": ["make"], "cwd": "."}],
        "compile_database": {"method": "bear", "entries": 1,
                             "compiler_allowlist": ["/opt/llvm/bin/clang"]},
    }

    def test_specs_are_two_distinct_jobs_and_profiles(self):
        self.assertEqual(set(worker.SPECS), {"02-build-configure", "02-native-build"})
        self.assertEqual(worker.spec("02-build-configure")["phases"], ("configure",))
        self.assertEqual(worker.spec("02-native-build")["phases"], ("configure", "build"))
        self.assertNotEqual(worker.spec("02-build-configure")["profile"],
                            worker.spec("02-native-build")["profile"])

    def test_requests_are_offline_read_only_and_replay_only_selected_phases(self):
        record = {"image_id": "image_build_123456789abc", "digest": "sha256:" + "b" * 64}
        permission = {"requirement": {}, "grants": [], "decision": {}}
        inputs = {"target_path": "/target", "source_snapshot_sha256": "sha256:" + "a" * 64,
                  "control": {"value": {"timeout_seconds": 60}}}
        with mock.patch.object(worker, "_permission", return_value=permission):
            configure = worker._request("run", "02-build-configure", "attempt", record, self.LOCK, inputs)
            native = worker._request("run", "02-native-build", "attempt", record, self.LOCK, inputs)
        for request in (configure, native):
            self.assertEqual(request["network"], {"mode": "none", "destinations": []})
            self.assertEqual(request["target_mounts"], [{"host_path": "/target", "container_path": "/workspace"}])
            self.assertEqual(request["scratch_path"], "scratch")
            self.assertNotIn("\n", request["argv"][2])
        self.assertEqual([x["argv"] for x in json.loads(configure["argv"][3])["commands"]],
                         [["autoreconf", "-fi"], ["./configure"]])
        self.assertEqual([x["argv"] for x in json.loads(native["argv"][3])["commands"]],
                         [["autoreconf", "-fi"], ["./configure"], ["make"]])

    def test_exact_job_bound_grant_is_required(self):
        source = "sha256:" + "a" * 64
        job = "02-build-configure"
        requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": job,
                       "capabilities": [worker._cap(job)]}
        grant = {"schema": "appsec-review/permission-grant/1.0", "grant_id": "g", "effect": "ALLOW",
                 "authority": {"name": "Owner", "role": "engagement-owner"},
                 # Relative to now: a fixed window expired on 2026-09-28 and the test began failing.
                 "issued_at": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "binding": {"run_id": "run", "source_snapshot_sha256": source, "job_id": job},
                 "justification": "happy path", "capabilities": requirement["capabilities"]}
        control = {"requirements": {job: requirement}, "grants": [grant]}
        self.assertEqual(worker._permission(control, job, "run", source)["decision"]["decision"], "GRANTED")
        widened = json.loads(json.dumps(control))
        widened["grants"][0]["binding"]["job_id"] = "02-native-build"
        with self.assertRaises(permissions.PermissionDenied):
            worker._permission(widened, job, "run", source)

    def test_compile_database_is_nonempty_fixed_clang_and_scratch_local(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "compile_commands.json")
            allowed = ["/opt/llvm/bin/clang"]
            state.atomic_json(path, [{"file": "/scratch/src/a.c", "directory": "/scratch/src",
                                      "arguments": [allowed[0], "-c", "a.c"]}])
            self.assertEqual(len(worker._compile_db(path, allowed)), 1)
            for bad in ([], [{"file": "/scratch/src/a.c", "arguments": ["gcc", "-c", "a.c"]}],
                        [{"file": "/host/a.c", "arguments": [allowed[0], "-c", "a.c"]}]):
                state.atomic_json(path, bad)
                with self.assertRaises(RuntimeError): worker._compile_db(path, allowed)

    def test_control_lives_outside_accepted_inputs(self):
        path = worker.control_path("run-1")
        self.assertEqual(path.relative_to(state.run_path("run-1")).as_posix(),
                         "data/controls/build-replay.json")

    def test_current_inputs_resolves_and_binds_the_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            control = root / "build-replay.json"
            control.write_text("{}", encoding="utf-8")
            target = root / "target"
            target.mkdir()
            with mock.patch.object(worker, "control_path", return_value=control), \
                 mock.patch.object(worker, "read_json", return_value={}), \
                 mock.patch.object(worker, "validate_document", return_value=[]), \
                 mock.patch.object(worker, "_source_snapshot", return_value="sha256:" + "a" * 64), \
                 mock.patch.object(worker, "_target", return_value=target) as resolve, \
                 mock.patch.object(worker, "_permission", return_value={"decision": {}}), \
                 mock.patch.object(worker, "_upstream", return_value=(root, {"locks": [], "source_revision": "rev"}, {})), \
                 mock.patch.object(worker, "source_tree_sha256", return_value="sha256:" + "b" * 64), \
                 mock.patch.object(worker.pc, "input_fingerprint_component", return_value="sha256:" + "c" * 64), \
                 mock.patch.object(worker.ce, "boundary_sha256", return_value="sha256:" + "d" * 64), \
                 mock.patch.object(worker, "_code_hashes", return_value={}):
                result = worker.current_inputs("run", "02-build-configure")
            resolve.assert_called_once_with("run")
            self.assertEqual(result["target_path"], str(target))

    def test_source_tree_sha256_binds_bytes_and_symlink_targets_but_not_git(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)
            (target / "src").mkdir()
            source = target / "src" / "main.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            try:
                (target / "main-link.c").symlink_to("src/main.c")
            except OSError as exc:
                self.skipTest(f"symlinks unavailable on this host: {exc}")
            (target / ".git").mkdir()
            (target / ".git" / "index").write_bytes(b"first")
            initial = worker.source_tree_sha256(target)
            (target / ".git" / "index").write_bytes(b"second")
            self.assertEqual(worker.source_tree_sha256(target), initial)
            source.write_text("int main(void) { return 1; }\n", encoding="utf-8")
            self.assertNotEqual(worker.source_tree_sha256(target), initial)
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (target / "main-link.c").unlink()
            (target / "main-link.c").symlink_to("src/other.c")
            self.assertNotEqual(worker.source_tree_sha256(target), initial)


if __name__ == "__main__":
    unittest.main()
