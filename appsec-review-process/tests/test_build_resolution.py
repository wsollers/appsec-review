"""Focused stage-13 tests: closed rendering, grants, B13 request and clang-only judgment."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import build_resolution as worker  # noqa: E402
import container_execution as ce  # noqa: E402
import execution_state as state  # noqa: E402


class BuildResolutionTests(unittest.TestCase):
    PLAN = {
        "unit_id": "dir:.", "root": ".", "class": "compiled-native",
        "image": {"base": "audit-buildenv-cpp", "apt_packages": [
            {"name": "libtool"}, {"name": "autoconf"}, {"name": "autoconf"}]},
        "commands": [{"phase": "configure", "argv": ["autoreconf", "-fi"], "cwd": "."},
                     {"phase": "configure", "argv": ["./configure"], "cwd": "."},
                     {"phase": "build", "argv": ["make"], "cwd": "."}],
        "compile_database": {"method": "bear"},
    }

    def test_renderer_is_deterministic_one_mirror_and_never_copies_target(self):
        base = {"digest": "sha256:" + "a" * 64, "reference": "sha256:" + "a" * 64,
                "build_reference": "audit-buildenv-cpp:local",
                "record_sha256": "sha256:" + "b" * 64}
        first = worker._render(self.PLAN, base["build_reference"], worker.APT_MIRROR)
        second = worker._render(self.PLAN, base["build_reference"], worker.APT_MIRROR)
        self.assertEqual(first, second)
        self.assertEqual(first.count("archive.ubuntu.com"), 1)
        self.assertNotIn("security.ubuntu.com", first)
        self.assertNotIn("COPY", first)
        self.assertIn("autoconf libtool", first)
        image_id, fingerprint = worker._spec(self.PLAN, base, worker.APT_MIRROR)
        self.assertRegex(image_id, r"^image_build_[0-9a-f]{12}$")
        self.assertRegex(fingerprint, r"^sha256:[0-9a-f]{64}$")

    def test_request_is_offline_read_only_target_and_exact_grants(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder, "target"); target.mkdir()
            control = {"mode": "success", "build_command_timeout_seconds": 60,
                       "permission": {"requirement": {}, "grants": []}}
            inputs = {"control": {"value": control}, "target_path": str(target),
                      "source_snapshot_sha256": "sha256:" + "a" * 64}
            permission = {"requirement": {"x": 1}, "grants": [{"x": 2}], "decision": {"x": 3}}
            record = {"image_id": "image_build_123456789abc", "digest": "sha256:" + "b" * 64}
            with mock.patch.object(worker, "_permission", return_value=permission):
                request = worker._request("run", "attempt", Path(folder), record, self.PLAN, inputs)
        self.assertEqual(request["network"], {"mode": "none", "destinations": []})
        self.assertEqual(request["target_mounts"], [{"host_path": str(target), "container_path": "/workspace"}])
        self.assertEqual(request["scratch_path"], "scratch")
        self.assertEqual(request["permission"], permission)
        self.assertEqual(request["argv"][:2], ["/usr/bin/python3", "-c"])
        self.assertNotIn("\n", request["argv"][2])
        cfg = json.loads(request["argv"][3])
        self.assertEqual([c["argv"] for c in cfg["commands"]],
                         [["autoreconf", "-fi"], ["./configure"], ["make"]])

    def test_permission_model_accepts_only_exact_apt_and_target_execution_grants(self):
        source = "sha256:" + "a" * 64
        requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": worker.JOB,
                       "capabilities": [worker._cap("package-restore", origin="staged-run-config"),
                                        worker._cap("target-execution", origin="staged-run-config")]}
        grant = {"schema": "appsec-review/permission-grant/1.0", "grant_id": "g", "effect": "ALLOW",
                 "authority": {"name": "Owner", "role": "engagement-owner"},
                 "issued_at": "2026-09-26T00:00:00Z", "expires_at": "2026-09-28T00:00:00Z",
                 "binding": {"run_id": "run", "source_snapshot_sha256": source, "job_id": worker.JOB},
                 "justification": "Stage 13", "capabilities": requirement["capabilities"]}
        control = {"permission": {"requirement": requirement, "grants": [grant]}}
        decision = worker._permission(control, "run", source, "2026-09-27T00:00:00Z")
        self.assertEqual(decision["decision"]["decision"], "GRANTED")
        widened = json.loads(json.dumps(control))
        widened["permission"]["requirement"]["capabilities"].append(
            worker._cap("target-execution", origin="staged-run-config", target_path="src"))
        widened["permission"]["grants"][0]["capabilities"] = widened["permission"]["requirement"]["capabilities"]
        with self.assertRaises(state.Blocked):
            worker._permission(widened, "run", source, "2026-09-27T00:00:00Z")

    def test_compile_database_requires_nonempty_fixed_clang_and_trial_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "compile_commands.json")
            allowed = ["/opt/llvm/bin/clang", "/opt/llvm/bin/clang++"]
            state.atomic_json(path, [{"directory": "/scratch/src", "file": "/scratch/src/a.cpp",
                                      "arguments": ["/opt/llvm/bin/clang++", "-c", "a.cpp"]}])
            self.assertEqual(len(worker._compile_db(path, allowed)), 1)
            for value in ([], [{"directory": "/scratch/src", "file": "/scratch/src/a.cpp",
                                "arguments": ["g++", "-c", "a.cpp"]}],
                          [{"directory": "/scratch/src", "file": "/host/a.cpp",
                            "arguments": ["/opt/llvm/bin/clang++", "-c", "a.cpp"]}]):
                state.atomic_json(path, value)
                with self.subTest(value=value), self.assertRaises(RuntimeError):
                    worker._compile_db(path, allowed)

    def test_host_local_registry_accepts_only_closed_image_build_namespace(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            good = {"schema": "appsec-review/container-image/1.0",
                    "image_id": "image_build_123456789abc",
                    "repository": "appsec-build/image-build-123456789abc",
                    "digest": "sha256:" + "a" * 64, "digest_kind": "image-id",
                    "dockerfile_sha256": "sha256:" + "b" * 64,
                    "build_fingerprint_sha256": "sha256:" + "c" * 64,
                    "build_attempt_id": "001", "purpose": "test", "provenance": "test"}
            state.atomic_json(directory / "image_build_123456789abc.json", good)
            self.assertIn(good["image_id"], ce.load_image_registry(directory))
            changed = dict(good, digest="sha256:" + "d" * 64)
            state.atomic_json(directory / "image_build_123456789abc.json", changed)
            self.assertEqual(ce.load_image_registry(directory)[good["image_id"]]["digest"], changed["digest"])

    def test_catalog_reuse_rejects_fingerprint_or_image_drift(self):
        with tempfile.TemporaryDirectory() as folder:
            old = worker.catalog_root
            worker.catalog_root = lambda: Path(folder)
            try:
                image_id = "image_build_123456789abc"
                catalog_path, container_path = worker._catalog(image_id)
                state.atomic_json(catalog_path, {"spec_fingerprint_sha256": "sha256:" + "a" * 64})
                state.atomic_json(container_path, {"digest": "sha256:" + "b" * 64})
                control = {"build_image_reuse": "auto"}
                with self.assertRaises(state.Blocked):
                    worker._build_image(Path(folder, "attempt"), image_id,
                        "sha256:" + "c" * 64, "FROM x\n", control, False)
                with mock.patch.object(worker, "_inspect", return_value=None), self.assertRaises(state.Blocked):
                    worker._build_image(Path(folder, "attempt"), image_id,
                        "sha256:" + "a" * 64, "FROM x\n", control, False)
            finally:
                worker.catalog_root = old

    def test_control_is_outside_accepted_intake_inputs(self):
        path = worker.control_path("run-1")
        self.assertEqual(path.relative_to(state.run_path("run-1")).as_posix(),
                         "data/controls/build-resolution.json")


if __name__ == "__main__":
    unittest.main()
