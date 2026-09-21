"""Wait-all rendezvous (C02): live cases against a real docker daemon, through the real B13 adapter.

The daemon is probed once (B13's probe). These tests skip ONLY when no daemon answers (for example
inside the code-server, which deliberately has no docker socket); they import cleanly everywhere.

Hermetic on a shared host (review of PR #35, F3): every pool of a test carries a pool id made at run
time, so its instance ids -- and with them B13's derived container names -- belong to this test
alone, and a test ends by proving that none of ITS OWN containers is left. What any other session
runs under the adapter label can neither fail nor block a test here; the one host-wide look at the
label is advisory and only prints.
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
import uuid

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
        reference = ce.image_reference(b13_live.support.fixture_record())
        if b13_live.docker_command("image", "inspect", reference).returncode != 0:
            pulled = b13_live.docker_command("pull", reference, timeout=600)       # by digest, never by tag
            if pulled.returncode != 0:
                raise RuntimeError("the digest-pinned fixture image is absent and could not be pulled by digest")

    @classmethod
    def tearDownClass(cls):
        # Advisory only: the label is host-wide, so these may be another session's. Never a failure.
        others = b13_live.labelled_containers()
        if others:
            print(f"note: {len(others)} container(s) with the adapter label exist on this host; none is "
                  "one of this module's (each test proved that for its own names)", file=sys.stderr)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.ws = support.RendezvousWorkspace(Path(self.temporary.name).resolve())
        self.plans: list = []

    def own_containers(self) -> list:
        """Exactly the container names B13 derives for this test's pinned-container instances."""
        return [ce.container_name(**instance.ids) for plan in self.plans for instance in plan.instances
                if instance.worker_kind == ps.PINNED_CONTAINER]

    def left_behind(self) -> list:
        return [name for name in self.own_containers() if b13_live.docker_command(
            "ps", "--all", "--quiet", "--filter", f"name=^/{name}$").stdout.strip()]

    def tearDown(self):
        support.join_pool_threads()
        left = self.left_behind()
        for name in left:                # never leave one of ours behind, even when the test failed
            b13_live.docker_command("rm", "--force", "--volumes", name)
        self.temporary.cleanup()
        self.assertEqual(left, [], "one of this test's own containers was left behind")

    def pool(self, *tool_argvs, personas: int = 1, **over):
        groups = []
        for index, argv in enumerate(tool_argvs):
            group = self.ws.tool_group(f"tool-{index}", 1)
            group["tool_request"]["argv"] = list(argv)
            groups.append(group)
        if personas:
            groups.append(self.ws.persona_group("reviewers", personas))
        # a pool id nobody else has: the specification hash, every instance id and every derived
        # container name are this test's own, whatever else runs on the host
        spec = self.ws.spec(groups, **{"pool_id": "live-" + uuid.uuid4().hex[:24], **over})
        plan = self.ws.expand(spec)
        self.plans.append(plan)
        return spec, plan

    def test_the_leftover_check_sees_only_this_test_s_own_containers(self):
        """F3's regression, without needing a second session: a labelled container that is NOT one of
        this test's (the reviewer's run 4 had another reviewer's) cannot fail this test's teardown,
        while one of its own names would."""
        spec, plan = self.pool(["/bin/echo", "hello"], personas=0)
        _, other_plan = self.pool(["/bin/echo", "hello"], personas=0)
        self.plans.remove(other_plan)                # "another session": same adapter, same label, not ours
        foreign = ce.container_name(**other_plan.instances[0].ids)
        self.assertNotIn(foreign, self.own_containers())
        self.assertEqual(len(set(self.own_containers())), 1)
        reference = ce.image_reference(b13_live.support.fixture_record())
        created = b13_live.docker_command("create", "--pull", "never", "--name", foreign, "--label",
                                          b13_live.LABEL, reference, "/bin/true")
        self.assertEqual(created.returncode, 0, created.stderr.decode("utf-8", "replace")[-500:])
        try:
            self.assertIn(created.stdout.decode("utf-8").strip()[:12], b13_live.labelled_containers())
            self.assertEqual(self.ws.run(spec, plan)["outcome"], pr.COMPLETE)
            self.assertEqual(self.left_behind(), [], "another session's container was counted as ours")
            self.plans.append(other_plan)            # ... and had it been ours, it WOULD have been seen
            self.assertEqual(self.left_behind(), [foreign])
            self.plans.remove(other_plan)
        finally:
            b13_live.docker_command("rm", "--force", "--volumes", foreign)

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
            thread = threading.Thread(target=lambda: box.update(manifest=self.ws.run(spec, plan)))
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

        manifest = self.ws.run(spec, plan)
        self.assertEqual(support.states(manifest), [pr.CRASHED, pr.SUCCEEDED])
        self.assertEqual(b13_live.docker_command("ps", "--all", "--quiet", "--filter", f"name=^/{name}$").stdout, b"")
        self.assertEqual(self.ws.verify(spec, plan), [])
        self.assertEqual(ps.verify_expansion(self.ws.root(plan), **self.ws.arguments(spec)), [])


if __name__ == "__main__":
    unittest.main()
