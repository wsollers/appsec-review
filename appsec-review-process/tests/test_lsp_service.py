"""lsp_service: one start under concurrent first queries, stale-lock recovery, readiness gaps, one retry then
gap, recorded replay, idle/teardown release and the B13 container argv. Fakes only: no Docker."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

PROCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROCESS))

import container_execution as ce  # noqa: E402
import lsp_service  # noqa: E402
from tests import lsp_fakes as fakes  # noqa: E402

QUERY = {"method": "definition", "path": "main.py", "line": 6, "character": 4}


def dead_pid() -> int:
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    return child.pid


class Base(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = fakes.write_project(Path(temp.name).resolve() / "checkout")
        self.base = Path(temp.name).resolve() / "lsp"
        self.launcher = fakes.FakeLauncher()
        self.spawn = fakes.ThreadSpawner(self.launcher)
        self.addCleanup(self.spawn.shutdown)
        self.server = fakes.python_spec(self.root)

    def broker(self, **kwargs) -> lsp_service.Broker:
        kwargs.setdefault("launcher", self.launcher)
        kwargs.setdefault("spawn", self.spawn)
        kwargs.setdefault("config", {"start_seconds": 20.0, "idle_seconds": 60.0, "request_seconds": 5.0})
        return lsp_service.Broker("run-1", self.base, [self.server], **kwargs)


class StartOnce(Base):
    def test_concurrent_first_queries_start_exactly_one_container(self):
        self.launcher.delay = 0.3   # every caller arrives while the first start is in flight
        results, barrier = [], threading.Barrier(8)

        def ask(line):
            barrier.wait()
            results.append(self.broker().query("python", "default", {**QUERY, "line": line}))
        threads = [threading.Thread(target=ask, args=(1 + index % 4,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        self.assertEqual(self.launcher.starts, 1)
        self.assertEqual(len(results), 8)
        self.assertTrue(all(row["status"] == "OK" for row in results), results)
        owner = json.loads((self.base / "locks" / "python-default.lock" / "owner.json").read_text())
        self.assertEqual((owner["state"], owner["pid"]), ("ready", os.getpid()))
        self.assertTrue(owner["container_id"].startswith("appsec-"))
        self.assertIn("started_at", owner)
        # identical queries converge on one recording (first writer wins)
        keys = {row["recording"] for row in results}
        self.assertEqual(len(keys), 4)

    def test_stale_lock_with_a_dead_owner_is_recovered_with_a_record(self):
        lock = self.base / "locks" / "python-default.lock"
        lock.mkdir(parents=True)
        (lock / "owner.json").write_text(json.dumps({
            "pid": dead_pid(), "state": "ready", "container_id": "appsec-gone", "port": 1, "token": "x",
            "identity_sha256": self.server["identity_sha256"]}))
        answer = self.broker().query("python", "default", QUERY)
        self.assertEqual(answer["status"], "OK", answer)
        self.assertEqual(self.launcher.starts, 1)
        self.assertIn("appsec-gone", self.launcher.stopped)
        records = list((self.base / "recoveries").glob("*.json"))
        self.assertEqual(len(records), 1)
        record = json.loads(records[0].read_text())
        self.assertIn("is gone", record["reason"])
        self.assertEqual(record["previous_owner"]["container_id"], "appsec-gone")

    def test_live_owner_whose_container_vanished_is_recovered(self):
        lock = self.base / "locks" / "python-default.lock"
        lock.mkdir(parents=True)
        (lock / "owner.json").write_text(json.dumps({
            "pid": os.getpid(), "host": None, "state": "ready", "container_id": "appsec-vanished", "port": 9,
            "token": "x", "identity_sha256": self.server["identity_sha256"]}))
        answer = self.broker().query("python", "default", QUERY)
        self.assertEqual(answer["status"], "OK", answer)
        self.assertEqual(self.launcher.starts, 1)
        reason = json.loads(next((self.base / "recoveries").glob("*.json")).read_text())["reason"]
        self.assertIn("appsec-vanished is gone", reason)


class Failures(Base):
    def test_start_failure_is_retried_once_then_a_gap(self):
        self.launcher.fail = 5
        broker = self.broker()
        first = broker.query("python", "default", QUERY)
        self.assertEqual(first["status"], "GAP")
        self.assertEqual(first["gaps"][0]["kind"], "lsp-server-failed")
        self.assertEqual(self.launcher.starts, 2)
        second = broker.query("python", "default", {**QUERY, "line": 2})
        self.assertEqual(second["gaps"][0]["kind"], "lsp-server-failed")
        self.assertEqual(self.launcher.starts, 2)   # no retry storm
        failure = json.loads((self.base / "failures" / "python-default.json").read_text())
        self.assertEqual(failure["attempts"], 2)
        self.assertFalse((self.base / "locks" / "python-default.lock").exists())

    def test_not_ready_without_compile_commands_is_a_gap(self):
        plan = [{"server_key": "cpp", "server": "clangd", "readiness": "compile_commands", "build_inputs": []},
                {"server_key": "go", "server": "gopls", "readiness": "markers", "build_inputs": []},
                {"server_key": "python", "server": "pylsp", "readiness": "none", "build_inputs": []}]
        ready, gaps = lsp_service.readiness(plan, target=self.root, native_units=None)
        self.assertEqual([(row["server_key"], row["variant"]) for row in ready], [("python", "default")])
        details = {gap["server_key"]: gap["detail"] for gap in gaps}
        self.assertEqual(details["cpp"], "lsp-not-ready: no compile_commands")
        self.assertTrue(details["go"].startswith("lsp-not-ready: no go.mod"))
        answer = self.broker().query("cpp", "locked-x", QUERY)
        self.assertEqual(answer["gaps"][0]["kind"], "lsp-not-ready")
        self.assertEqual(self.launcher.starts, 0)

    def test_compile_commands_variants_and_markers_make_servers_ready(self):
        (self.root / "go.mod").write_text("module x\n")
        units = [{"unit_id": "dir:.", "adapted": [{"file": "/workspace/a.c"}],
                  "build_variant": {"variant_id": "locked-1"}, "compile_database": {"adapted_sha256": "sha256:" + "c" * 64}}]
        plan = [{"server_key": "cpp", "server": "clangd", "readiness": "compile_commands", "build_inputs": []},
                {"server_key": "go", "server": "gopls", "readiness": "markers", "build_inputs": ["go.mod"]}]
        ready, gaps = lsp_service.readiness(plan, target=self.root, native_units=units)
        self.assertEqual(gaps, [])
        self.assertEqual([(row["server_key"], row["variant"], row["build_input"]["kind"]) for row in ready],
                         [("cpp", "locked-1", "compile_commands"), ("go", "default", "build_file")])


class Replay(Base):
    def test_recorded_replay_is_identical_and_needs_no_server(self):
        live = self.broker().query("python", "default", QUERY)
        self.assertFalse(live["replayed"])
        replay = lsp_service.Broker("run-1", self.base, [self.server], replay_only=True).query("python", "default", QUERY)
        self.assertTrue(replay["replayed"])
        strip = lambda row: {k: v for k, v in row.items() if k != "replayed"}   # noqa: E731
        self.assertEqual(strip(replay), strip(live))
        again = self.broker().query("python", "default", QUERY)
        self.assertEqual(strip(again), strip(live))
        self.assertEqual(self.launcher.starts, 1)
        record = json.loads(lsp_service.Recordings(self.base).path(live["recording"]).read_text())
        self.assertTrue(lsp_service.sealed(record))
        for key in ("method", "params", "response", "server", "image", "build_variant", "recorded_at",
                    "source_snapshot_sha256", "build_input_sha256"):
            self.assertIn(key, record)
        self.assertEqual(record["server"]["version"], "1.2")
        self.assertEqual(record["image"]["digest"], fakes.IMAGE["digest"])

    def test_other_inputs_do_not_replay_and_tampering_is_a_gap(self):
        live = self.broker().query("python", "default", QUERY)
        other = fakes.python_spec(self.root)
        other["identity"] = {**other["identity"], "source_snapshot_sha256": "sha256:" + "d" * 64}
        other["identity_sha256"] = lsp_service._sha(other["identity"])
        missing = lsp_service.Broker("run-1", self.base, [other], replay_only=True).query("python", "default", QUERY)
        self.assertEqual(missing["gaps"][0]["kind"], "lsp-not-recorded")
        path = lsp_service.Recordings(self.base).path(live["recording"])
        record = json.loads(path.read_text())
        record["response"]["results"] = []
        path.write_text(json.dumps(record))
        tampered = lsp_service.Broker("run-1", self.base, [self.server], replay_only=True).query("python", "default", QUERY)
        self.assertEqual(tampered["gaps"][0]["kind"], "lsp-recording-invalid")


class Lifecycle(Base):
    def test_idle_timeout_stops_the_container_and_releases_the_lock(self):
        broker = self.broker(config={"start_seconds": 20.0, "idle_seconds": 0.3, "request_seconds": 5.0})
        self.assertEqual(broker.query("python", "default", QUERY)["status"], "OK")
        lock = self.base / "locks" / "python-default.lock"
        deadline = time.monotonic() + 10
        while lock.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(lock.exists())
        self.assertEqual(len(self.launcher.stopped), 1)
        released = list((self.base / "locks" / "released").glob("python-default.lock.idle.*"))
        self.assertEqual(len(released), 1)
        self.assertEqual(json.loads((released[0] / "owner.json").read_text())["state"], "stopped")

    def test_teardown_at_run_end(self):
        self.assertEqual(self.broker().query("python", "default", QUERY)["status"], "OK")
        rows = lsp_service.teardown(self.base, launcher=self.launcher)
        self.assertEqual(rows, [{"lock": "python-default.lock", "forced": False}])
        self.assertEqual(len(self.launcher.stopped), 1)


class ContainerArgv(unittest.TestCase):
    def launcher(self, image_id: str) -> lsp_service.ContainerLauncher:
        launcher = lsp_service.ContainerLauncher.__new__(lsp_service.ContainerLauncher)
        launcher.ce, launcher.run_id, launcher.base = ce, "run-1", Path("/tmp")
        launcher.runtime = ce.ContainerRuntime(
            docker_executable=Path("/usr/bin/docker"), docker_host=None, images_dir=ce.IMAGES_DIR, host_flavor="posix",
            container_user="1000:1000", source_snapshot_sha256=fakes.SNAPSHOT, registry_ceiling=[],
            clock=lambda: "2026-10-04T00:00:00Z", cancel=threading.Event())
        self.registry = {image_id: {"digest": fakes.IMAGE["digest"], "digest_kind": "image-id"}}
        return launcher

    def test_network_none_read_only_source_and_one_scratch_mount(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            server = fakes.python_spec(root, "cpp", "locked-1",
                                       {"kind": "compile_commands", "unit_id": "dir:.", "sha256": "sha256:" + "c" * 64})
            launcher = self.launcher("audit-buildenv-cpp")
            name = ce.container_name("run-1", "02-lsp-xref", "cpp-locked-1")
            with mock.patch.object(ce, "load_image_registry", return_value=self.registry):
                argv = launcher.argv(server, name, root / "scratch",
                                     [(str(root), "/workspace"), (str(root / "db"), lsp_service.COMPILE_DB_MOUNT)])
        argv = list(argv)
        self.assertEqual(argv[1:3], ["run", "--interactive"])
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertIn("--read-only", argv)
        self.assertIn("--cap-drop", argv)
        mounts = [argv[i + 1] for i, word in enumerate(argv) if word == "--mount"]
        self.assertIn(f"type=bind,source={root},target=/workspace,readonly", mounts)
        self.assertIn(f"type=bind,source={root / 'db'},target={lsp_service.COMPILE_DB_MOUNT},readonly", mounts)
        self.assertEqual([m for m in mounts if not m.endswith(",readonly")],
                         [f"type=bind,source={root / 'scratch'},target=/scratch"])
        self.assertIn("--compile-commands-dir=" + lsp_service.COMPILE_DB_MOUNT, argv)
        self.assertIn("--background-index=false", argv)
        self.assertFalse(any(word.startswith("--query-driver") for word in argv))

    def test_presets_never_run_project_code_or_fetch(self):
        go = lsp_service.SERVER_PLAN["go"]["argv"]
        self.assertIn("GOFLAGS=-mod=readonly", go)
        self.assertIn("GOPROXY=off", go)
        rust = lsp_service.SERVER_PLAN["rust"]["initialization_options"]
        self.assertEqual((rust["cargo"]["buildScripts"]["enable"], rust["procMacro"]["enable"], rust["checkOnSave"]),
                         (False, False, False))
        java = lsp_service.SERVER_PLAN["java"]["initialization_options"]["settings"]["java"]
        self.assertEqual((java["import"]["maven"]["enabled"], java["import"]["gradle"]["enabled"]), (False, False))
        self.assertIn("jdtls-build-import-disabled", lsp_service.SERVER_PLAN["java"]["limit"])
        self.assertNotIn("csharp", lsp_service.SERVER_PLAN)
        self.assertIn("c_sharp", lsp_service.WITHHELD)


if __name__ == "__main__":
    unittest.main()
