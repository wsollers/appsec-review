"""Pinned-container argv adapter (B13): live boundary tests against a real docker daemon.

The daemon is probed once. These tests skip ONLY when no daemon answers (for example inside the
code-server, which deliberately has no docker socket); they import cleanly everywhere. The fixture
image is the registry record ``fixture-harmless`` and is only ever named by digest. If the digest
is not present locally the class pulls it *by digest* once; the adapter itself never pulls.

Every test ends by proving that no container carrying the adapter label is left behind.
"""
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_execution as ce  # noqa: E402
import container_execution_support as support  # noqa: E402
from worker_adapters import PinnedContainerAdapter, WorkerRequest  # noqa: E402
from worker_result import validate_worker_result  # noqa: E402

LABEL = "appsec-review.adapter=" + ce.ADAPTER_ID


def docker_command(*arguments: str, timeout: int = 120) -> subprocess.CompletedProcess:
    executable = ce.host_defaults()["docker_executable"]
    return subprocess.run([str(executable), *arguments], stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=timeout, check=False,
                          env=ce.docker_client_environment(os.environ, None))


def probe_daemon() -> str | None:
    if ce.host_defaults()["docker_executable"] is None:
        return "no docker executable on PATH"
    try:
        if docker_command("version", "--format", "{{.Server.Version}}", timeout=30).returncode != 0:
            return "no docker daemon is reachable"
    except (OSError, subprocess.SubprocessError):
        return "no docker daemon is reachable"
    return None


DAEMON_ABSENT = probe_daemon()


def labelled_containers() -> list[str]:
    done = docker_command("ps", "--all", "--quiet", "--filter", "label=" + LABEL)
    return done.stdout.decode("utf-8").split()


@unittest.skipIf(DAEMON_ABSENT, DAEMON_ABSENT or "")
class LiveBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reference = ce.image_reference(support.fixture_record())
        if docker_command("image", "inspect", reference).returncode != 0:
            pulled = docker_command("pull", reference, timeout=600)       # by digest, never by tag
            if pulled.returncode != 0:
                raise RuntimeError("the digest-pinned fixture image is absent and could not be pulled by digest")
        if labelled_containers():
            raise RuntimeError("containers from an earlier adapter run exist; refusing to hide them")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.attempt = self.root / "attempt"
        self.attempt.mkdir()
        self.target = self.root / "target"
        self.target.mkdir()
        (self.target / "source.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
        self.name = ce.container_name(**support.IDS)

    def tearDown(self):
        left = labelled_containers()
        self.temporary.cleanup()
        self.assertEqual(left, [], "a container was left behind")

    def run_argv(self, argv, runtime=None, **over):
        request = support.request(self.target, argv, **over)
        result = support.run(runtime or support.runtime(), self.attempt, request)
        self.assertEqual(support.verify(self.attempt, request), [])
        self.assertEqual(docker_command("ps", "--all", "--quiet", "--filter", f"name=^/{self.name}$").stdout, b"")
        return request, result

    def log(self, name: str) -> str:
        return (self.attempt / "logs" / "container" / f"{name}.log").read_text(encoding="utf-8")

    # -- the harmless fixture inside the boundary

    def test_echo_runs_exactly_the_argv_array(self):
        _, result = self.run_argv(["/bin/echo", "hello world", "$HOME", ";", "--privileged", "`id`"])
        self.assertEqual((result["execution_status"], result["cause"], result["exit_code"]), ("OK", None, 0))
        self.assertEqual(self.log("stdout"), "hello world $HOME ; --privileged `id`\n")

    def test_scratch_is_the_only_writable_location(self):
        _, result = self.run_argv(["/bin/touch", "/scratch/made-by-container"])
        self.assertEqual(result["execution_status"], "OK")
        made = self.attempt / "scratch" / "made-by-container"
        self.assertTrue(made.is_file())
        if hasattr(os, "getuid"):
            self.assertEqual(made.stat().st_uid, os.getuid())
        before = sorted(p.name for p in self.target.iterdir())
        for index, path in enumerate(("/workspace/written", "/etc/written", "/written", "/usr/written")):
            attempt = self.root / f"attempt-ro-{index}"
            attempt.mkdir()
            request = support.request(self.target, ["/bin/touch", path])
            result = support.run(support.runtime(), attempt, request)
            with self.subTest(path=path):
                self.assertEqual((result["execution_status"], result["cause"]), ("FAILED", "CONTAINER_EXIT_NONZERO"))
                self.assertNotEqual(result["exit_code"], 0)
        self.assertEqual(sorted(p.name for p in self.target.iterdir()), before)

    def test_target_is_readable_and_mounted_read_only(self):
        _, result = self.run_argv(["/bin/cat", "/workspace/source.c"])
        self.assertEqual(result["execution_status"], "OK")
        self.assertIn("int main", self.log("stdout"))

    def test_network_is_absent(self):
        _, result = self.run_argv(["/bin/cat", "/proc/net/dev"])
        interfaces = [line.split(":")[0].strip() for line in self.log("stdout").splitlines()[2:]]
        self.assertEqual(interfaces, ["lo"])
        attempt = self.root / "attempt-wget"
        attempt.mkdir()
        request = support.request(self.target, ["/usr/bin/wget", "-T", "3", "-q", "-O", "/scratch/page",
                                                "http://1.1.1.1/"])
        result = support.run(support.runtime(), attempt, request)
        self.assertEqual((result["execution_status"], result["cause"]), ("FAILED", "CONTAINER_EXIT_NONZERO"))
        self.assertFalse((attempt / "scratch" / "page").exists() and (attempt / "scratch" / "page").stat().st_size)

    def test_process_is_unprivileged_without_capabilities_or_new_privileges(self):
        _, result = self.run_argv(["/bin/cat", "/proc/self/status"])
        status = dict(line.split(":\t", 1) for line in self.log("stdout").splitlines() if ":\t" in line)
        for capability_set in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            self.assertEqual(int(status[capability_set], 16), 0, capability_set)
        self.assertEqual(status["NoNewPrivs"].strip(), "1")
        self.assertNotEqual(status["Uid"].split()[0], "0")
        self.assertEqual(status["Uid"].split()[0], support.runtime().container_user.split(":")[0])

    def test_tmp_is_writable_but_not_executable(self):
        # busybox is a multiplexer, not a listed shell: the shell guard is a lint, the container is
        # the boundary. It is used here only to chain "copy, then try to execute".
        _, result = self.run_argv(["/bin/busybox", "sh", "-c", "cp /bin/busybox /tmp/copy && /tmp/copy true"])
        self.assertEqual(result["cause"], "CONTAINER_EXIT_NONZERO")
        self.assertIn("Permission denied", self.log("stderr"))

    def test_host_environment_does_not_pass_through(self):
        name, value = "B13_HOST_ONLY_VARIABLE", "b13-" + "host-value"
        with mock.patch.dict(os.environ, {name: value, "DOCKER_CONTEXT": "default"}):
            self.run_argv(["/usr/bin/env"], environment=[{"name": "TZ", "value": "UTC"}])
        lines = set(self.log("stdout").splitlines())
        self.assertIn("HOME=/tmp", lines)
        self.assertIn("TZ=UTC", lines)
        self.assertNotIn(value, self.log("stdout"))
        self.assertEqual({line.split("=")[0] for line in lines} - {"HOME", "TZ", "PATH", "HOSTNAME", "PWD", "SHLVL"},
                         set())

    def test_retained_output_is_bounded_and_the_run_still_succeeds(self):
        _, result = self.run_argv(["/usr/bin/seq", "1", "200000"], limits=support.limits(stdout_limit_bytes=1024))
        stdout = result["streams"]["stdout"]
        self.assertEqual((result["execution_status"], stdout["written_bytes"], stdout["truncated"]), ("OK", 1024, True))
        self.assertGreater(stdout["observed_bytes"], 1_000_000)
        self.assertEqual((self.attempt / "logs" / "container" / "stdout.log").stat().st_size, 1024)

    # -- distinct terminal diagnostics, container always removed

    def test_timeout_removes_the_container(self):
        started = time.monotonic()
        _, result = self.run_argv(["/bin/sleep", "120"], limits=support.limits(timeout_seconds=2))
        self.assertEqual((result["execution_status"], result["cause"], result["exit_code"]), ("FAILED", "TIMEOUT", None))
        self.assertLess(time.monotonic() - started, 60)

    def test_cancellation_removes_the_container(self):
        cancel = threading.Event()
        timer = threading.Timer(1.5, cancel.set)
        timer.start()
        try:
            _, result = self.run_argv(["/bin/sleep", "120"], runtime=support.runtime(cancel=cancel))
        finally:
            timer.cancel()
        self.assertEqual((result["execution_status"], result["cause"]), ("CANCELED", "CANCELED"))

    def lose(self, *verb: str):
        def act():
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                running = docker_command("ps", "--quiet", "--filter", f"name=^/{self.name}$").stdout.strip()
                if running:
                    docker_command(*verb, self.name)
                    return
                time.sleep(0.1)
        thread = threading.Thread(target=act, daemon=True)
        thread.start()
        try:
            return self.run_argv(["/bin/sleep", "120"])[1]
        finally:
            thread.join(timeout=60)

    def test_a_container_killed_from_outside_is_worker_loss(self):
        result = self.lose("kill")
        self.assertEqual((result["execution_status"], result["cause"]), ("FAILED", "WORKER_LOST"))

    def test_a_container_removed_from_outside_is_worker_loss(self):
        result = self.lose("rm", "--force")
        self.assertEqual((result["execution_status"], result["cause"]), ("FAILED", "WORKER_LOST"))

    def test_log_write_failure_is_failed_and_removes_the_container(self):
        with mock.patch.object(ce.deterministic_child, "_write_log_chunk", side_effect=OSError("disk full")):
            _, result = self.run_argv(["/usr/bin/yes", "diagnostic"])
        self.assertEqual((result["execution_status"], result["cause"]), ("FAILED", "LOG_WRITE_FAILED"))

    def test_memory_limit_is_enforced(self):
        _, result = self.run_argv(["/usr/bin/tail", "/dev/zero"],
                                  limits=support.limits(memory_bytes=32 * 1024 * 1024, timeout_seconds=60))
        self.assertEqual((result["execution_status"], result["cause"]), ("FAILED", "OOM_KILLED"))

    def test_a_missing_executable_is_a_start_failure(self):
        _, result = self.run_argv(["/no/such/executable"])
        self.assertEqual((result["execution_status"], result["cause"]), ("FAILED", "CONTAINER_START_FAILED"))

    def test_keyboard_interrupt_is_recorded_removed_and_reraised(self):
        real = ce.deterministic_child.execute_child

        def interrupted(spec, *, cancel=None, observer=None):
            stop = threading.Event()
            threading.Timer(1.5, stop.set).start()
            real(spec, cancel=stop)
            raise KeyboardInterrupt
        request = support.request(self.target, ["/bin/sleep", "120"])
        with mock.patch.object(ce.deterministic_child, "execute_child", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                support.run(support.runtime(), self.attempt, request)
        self.assertEqual(support.verify(self.attempt, request), [])
        result = ce.load_verified_result(self.attempt, **support.IDS, request=request, images_dir=ce.IMAGES_DIR, **support.host_facts())
        self.assertEqual(result["cause"], "CANCELED")

    # -- blocked before any container

    def test_an_unprovisioned_digest_is_blocked_and_never_pulled(self):
        images = self.root / "images"
        images.mkdir()
        absent = "sha256:" + "0123456789abcdef" * 4
        (images / "fixture-harmless.json").write_text(json.dumps(
            {**support.fixture_record(), "digest": absent}), encoding="utf-8")
        request = support.request(self.target, ["/bin/true"], image={"image_id": "fixture-harmless", "digest": absent})
        result = support.run(support.runtime(images_dir=images), self.attempt, request)
        self.assertEqual((result["execution_status"], result["cause"]), ("BLOCKED", "IMAGE_NOT_PROVISIONED"))
        self.assertEqual(support.verify(self.attempt, request, images_dir=images), [])
        self.assertFalse((self.attempt / "scratch").exists())

    def test_an_unreachable_daemon_is_blocked(self):
        runtime = support.runtime(docker_host="unix://" + str(self.root / "no-daemon.sock"))
        request = support.request(self.target, ["/bin/true"])
        result = support.run(runtime, self.attempt, request)
        self.assertEqual((result["execution_status"], result["cause"]), ("BLOCKED", "DOCKER_UNAVAILABLE"))
        self.assertEqual(support.verify(self.attempt, request), [])

    # -- adapter protocol, on-disk verifier and envelope against a real attempt

    def test_adapter_protocol_envelope_and_file_tamper_invariant(self):
        request = support.request(self.target, ["/bin/cp", "/workspace/source.c", "/scratch/report.txt"])
        adapter = PinnedContainerAdapter(support.runtime())
        result = adapter.execute(WorkerRequest(support.RUN, support.JOB, support.ATTEMPT, self.attempt,
                                               {"container_request": request}))
        self.assertEqual(result["execution_status"], "OK")
        envelope = ce.to_worker_envelope(
            self.attempt, **support.IDS, request=request, images_dir=ce.IMAGES_DIR, **support.host_facts(),
            input_fingerprint=ce.fingerprint_material(request, support.fixture_record())["sha256"],
            output_contract="fixture-contract", output_paths=["scratch/report.txt"], resume_command=None)
        self.assertEqual(validate_worker_result(envelope), [])
        self.assertEqual((envelope["worker_kind"], envelope["execution_status"]), ("pinned_container", "OK"))
        log_dir = self.attempt / "logs" / "container"
        for path in sorted(log_dir.iterdir()):
            original = path.read_bytes()
            with self.subTest(tampered=path.name):
                path.write_bytes(original + b"\n")
                self.assertTrue(support.verify(self.attempt, request))
                path.write_bytes(original)
        self.assertEqual(support.verify(self.attempt, request), [])
        command = json.loads((log_dir / "command.json").read_text(encoding="utf-8"))
        self.assertEqual(command["argv"][1:4], ["run", "--name", self.name])
        self.assertIn("@sha256:", " ".join(command["argv"]))
        self.assertNotRegex(" ".join(command["argv"]), r"alpine:[a-z0-9]")


if __name__ == "__main__":
    unittest.main()
