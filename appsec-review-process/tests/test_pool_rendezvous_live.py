"""Wait-all rendezvous (C02): live cases against a real docker daemon, through the real B13 adapter.

The daemon is probed once (B13's probe). These tests skip ONLY when no daemon answers (for example
inside the code-server, which deliberately has no docker socket); they import cleanly everywhere.
Every test ends by proving that no container carrying the adapter label is left behind.
"""
from __future__ import annotations

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
import pool_rendezvous as pr  # noqa: E402
import pool_rendezvous_support as support  # noqa: E402
from pool_rendezvous_support import HANG_SECONDS  # noqa: E402
import pool_specification as ps  # noqa: E402
import test_container_execution_live as b13_live  # noqa: E402

DAEMON_ABSENT = b13_live.DAEMON_ABSENT


@unittest.skipIf(DAEMON_ABSENT, DAEMON_ABSENT or "")
class LiveRendezvousTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        b13_live.LiveBoundaryTests.setUpClass.__func__(cls)      # fixture image by digest; no leftovers to hide

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.ws = support.RendezvousWorkspace(Path(self.temporary.name).resolve())

    def tearDown(self):
        support.join_pool_threads()
        left = b13_live.labelled_containers()
        self.temporary.cleanup()
        self.assertEqual(left, [], "a container was left behind")

    def pool(self, *tool_argvs, personas: int = 1, **over):
        groups = []
        for index, argv in enumerate(tool_argvs):
            group = self.ws.tool_group(f"tool-{index}", 1)
            group["tool_request"]["argv"] = list(argv)
            groups.append(group)
        if personas:
            groups.append(self.ws.persona_group("reviewers", personas))
        spec = self.ws.spec(groups, **over)
        return spec, self.ws.expand(spec)

    def test_a_mixed_live_pool_keeps_every_outcome_and_verifies_from_disk(self):
        spec, plan = self.pool(["/bin/echo", "hello"], ["/bin/false"], ["/bin/touch", "/scratch/made"], personas=2)
        manifest = self.ws.run(spec, plan)
        self.assertEqual(support.states(manifest), [pr.SUCCEEDED, pr.SUCCEEDED, pr.SUCCEEDED, pr.FAILED, pr.SUCCEEDED])
        self.assertEqual(manifest["instances"][3]["adapter_cause"], "CONTAINER_EXIT_NONZERO")
        self.assertEqual([record["container_removed"] for record in manifest["instances"][2:]], [True] * 3)
        self.assertEqual(manifest["outcome"], pr.DEGRADED)
        self.assertTrue((self.ws.instance_root(plan, 4) / "scratch" / "made").is_file())
        self.assertEqual(self.ws.verify(spec, plan), [])
        log = self.ws.instance_root(plan, 2) / "logs" / "container" / "stdout.log"
        log.write_bytes(b"goodbye\n")
        self.assertIn("instances[2]", self.ws.verify(spec, plan)[0])

    def test_a_pool_cancel_stops_a_running_container_and_the_next_one_is_never_launched(self):
        spec, plan = self.pool(["/bin/sleep", "120"], ["/bin/echo", "never"], personas=0)
        started = threading.Event()
        real = ce.deterministic_child.execute_child

        def child(child_spec, *, cancel=None, observer=None):
            started.set()
            return real(child_spec, cancel=cancel, observer=observer)
        box: dict = {}
        with mock.patch.object(ce.deterministic_child, "execute_child", side_effect=child):
            thread = threading.Thread(target=lambda: box.update(manifest=self.ws.run(spec, plan, persona_runtime=None)))
            thread.start()
            self.assertTrue(started.wait(HANG_SECONDS))
            self.ws.cancel.set()
            thread.join(HANG_SECONDS * 3)
        self.assertFalse(thread.is_alive())
        manifest = box["manifest"]
        self.assertEqual(support.states(manifest), [pr.CANCELED, pr.NOT_LAUNCHED_CANCELED])
        self.assertEqual((manifest["instances"][0]["container_removed"], manifest["outcome"]), (True, pr.POOL_CANCELED))
        self.assertEqual(self.ws.verify(spec, plan), [])

    def test_a_container_still_running_when_the_wait_ends_is_stopped_removed_and_not_adopted(self):
        spec, plan = self.pool(["/bin/sleep", "120"], personas=1)
        manifest = self.ws.run(spec, plan, wait_limit_seconds=3, drain_seconds=120)
        self.assertEqual(support.states(manifest), [pr.SUCCEEDED, pr.RENDEZVOUS_TIMED_OUT])
        late = manifest["instances"][1]
        self.assertEqual((late["worker_stopped"], late["result_file"]), (True, None))
        self.assertTrue(self.ws.result_path(plan, 1).is_file(), "B13 recorded its cancel; it is simply not adopted")
        self.assertEqual(self.ws.verify(spec, plan), [])

    def test_a_restart_removes_the_container_a_killed_coordinator_left_running(self):
        spec, plan = self.pool(["/bin/sleep", "120"], ["/bin/echo", "after"], personas=0)
        name = support.container_name(plan, 0)
        process = subprocess.Popen(support.coordinator_command(self.ws, spec, support.ids(plan)[0]),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        guard = threading.Timer(HANG_SECONDS, process.kill)
        guard.start()
        try:
            line = process.stdout.readline()
            deadline = time.monotonic() + HANG_SECONDS         # the daemon, not this process, starts the container
            while time.monotonic() < deadline and not b13_live.docker_command(
                    "ps", "--quiet", "--filter", f"name=^/{name}$").stdout.strip():
                time.sleep(0.2)
            process.kill()
            _, stderr = process.communicate(timeout=HANG_SECONDS)
        finally:
            guard.cancel()
        self.assertEqual(line.strip(), b"BLOCKED", stderr.decode("utf-8", "replace")[-2000:])
        self.assertTrue(b13_live.docker_command("ps", "--quiet", "--filter", f"name=^/{name}$").stdout.strip(),
                        "the killed coordinator's container should still be running")

        manifest = self.ws.run(spec, plan, persona_runtime=None)
        self.assertEqual(support.states(manifest), [pr.CRASHED, pr.SUCCEEDED])
        self.assertEqual(b13_live.docker_command("ps", "--all", "--quiet", "--filter", f"name=^/{name}$").stdout, b"")
        self.assertEqual(self.ws.verify(spec, plan), [])
        self.assertEqual(ps.verify_expansion(self.ws.root(plan), **self.ws.arguments(spec)), [])


if __name__ == "__main__":
    unittest.main()
