"""Brief N / ADR-0014 item 6: per-operation memo in the B13 IR toolchain (hit, miss, tamper, prod)."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_execution as ce  # noqa: E402
import container_execution_support as support  # noqa: E402
import execution_state as state  # noqa: E402
import ir_b13_toolchain as irt  # noqa: E402
import item_memo  # noqa: E402
from test_container_execution import ScriptedDocker  # noqa: E402

RUN = "run-ir-memo"
JOB = "02-ir-link"
TOOLCHAIN = "sha256:" + "a" * 64


class IrMemoTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        defaults = {**ce.host_defaults()}
        defaults["docker_executable"] = defaults["docker_executable"] or Path(sys.executable).resolve()
        if not ce._USER_RE.match(defaults["container_user"]):
            defaults["container_user"] = "10001:10001"
        self.defaults = defaults
        for patch in (mock.patch.object(state, "RUNS", self.root / "runs"),
                      mock.patch.dict(os.environ, {"APPSEC_CACHE_ROOT": str(self.root / "cache"),
                                                   "APPSEC_RUN_MODE": "dev"}),
                      mock.patch.object(ce, "host_defaults", return_value=defaults),
                      mock.patch.object(irt, "_runtime", side_effect=lambda source: self.runtime()),
                      mock.patch.object(irt, "_image", return_value=(
                          support.FIXTURE_IMAGE_ID, support.fixture_record()["digest"], TOOLCHAIN, {}))):
            patch.start(); self.addCleanup(patch.stop)
        self.capture = state.data_path(RUN, "jobs", "02-ir-capture", "attempts", "cap-1")
        (self.capture / "modules").mkdir(parents=True)
        (self.capture / "modules" / "a.bc").write_bytes(b"BC\xc0\xde module a")
        self.inputs = {"run_id": RUN, "source_snapshot_sha256": "sha256:" + "d" * 64,
                       "source_tree_sha256": "sha256:" + "e" * 64}
        self.containers = 0

    def runtime(self):
        return ce.ContainerRuntime(docker_executable=self.defaults["docker_executable"], docker_host=None,
            images_dir=ce.IMAGES_DIR, host_flavor=self.defaults["host_flavor"],
            container_user=self.defaults["container_user"], source_snapshot_sha256=self.inputs["source_snapshot_sha256"],
            registry_ceiling=[], clock=lambda: support.NOW, cancel=threading.Event())

    def toolchain(self, name):
        attempt = state.data_path(RUN, "jobs", JOB, "attempts", name)
        attempt.mkdir(parents=True)
        toolchain = object.__new__(irt.B13IrToolchain)
        toolchain.job, toolchain.inputs, toolchain.attempt, toolchain.run_id = JOB, self.inputs, attempt, RUN
        toolchain.images = None
        toolchain.image_id, toolchain.image_digest = support.FIXTURE_IMAGE_ID, support.fixture_record()["digest"]
        toolchain.toolchain_sha256, toolchain.image_record = TOOLCHAIN, {}
        toolchain.runtime, toolchain.receipts, toolchain.target = self.runtime(), [], None
        toolchain.memo = item_memo.Memo("ir:" + JOB)
        return toolchain

    def link(self, name, exit_code=0):
        toolchain = self.toolchain(name)
        scripted = ScriptedDocker(client_exit=exit_code)
        original = scripted.child

        def child(spec, **kwargs):
            self.containers += 1
            result = original(spec, **kwargs)
            scratch = Path(spec.owner_root) / "scratch"; scratch.mkdir(exist_ok=True)
            (scratch / "linked.bc").write_bytes(b"BC\xc0\xde linked")
            return result
        scripted.child = child
        first, second = scripted.patches()
        with first, second:
            code, raw = toolchain._run("link", ["/opt/llvm/bin/llvm-link", "/inputs/capture/modules/a.bc",
                                                "-o", "/scratch/linked.bc"],
                                       [{"host_path": str(self.capture), "container_path": "/inputs/capture"}],
                                       "linked.bc")
        toolchain.publish_receipts()
        return toolchain, code, raw

    def test_unchanged_operation_reuses_the_owner_trial_and_validates(self):
        first, code, _raw = self.link("att-1")
        self.assertEqual((code, self.containers), (0, 1))
        second, code, raw = self.link("att-2")
        self.assertEqual((code, self.containers), (0, 1), "a memo hit must not start a container")
        [receipt] = second.receipts
        self.assertEqual(receipt["owner_attempt_id"], "att-1")
        self.assertEqual(raw.read_bytes(), b"BC\xc0\xde linked")
        self.assertTrue(str(raw).startswith(str(first.attempt)))
        irt.validate_receipts(JOB, self.inputs, second.attempt)   # re-verified in the owner attempt

    def test_tampered_owner_trial_runs_fresh(self):
        first, _code, _raw = self.link("att-1")
        (first.attempt / first.receipts[0]["trial_path"] / "logs/container/stdout.log").write_bytes(b"x\n")
        second, _code, _raw = self.link("att-2")
        self.assertEqual(self.containers, 2)
        self.assertNotIn("owner_attempt_id", second.receipts[0])

    def test_tampered_owner_output_runs_fresh(self):
        first, _code, raw = self.link("att-1")
        raw.write_bytes(b"BC\xc0\xde forged")
        self.link("att-2")
        self.assertEqual(self.containers, 2)

    def test_changed_input_module_is_a_miss(self):
        self.link("att-1")
        (self.capture / "modules" / "a.bc").write_bytes(b"BC\xc0\xde module a changed")
        self.link("att-2")
        self.assertEqual(self.containers, 2)

    def test_failed_operation_is_not_memoised(self):
        _toolchain, code, _raw = self.link("att-1", exit_code=1)
        self.assertEqual(code, 1)
        self.link("att-2")
        self.assertEqual(self.containers, 2)

    def test_prod_default_runs_every_operation(self):
        with mock.patch.dict(os.environ, {"APPSEC_RUN_MODE": "prod"}):
            self.link("att-1")
            self.link("att-2")
        self.assertEqual(self.containers, 2)

    def test_forged_owner_receipt_is_rejected(self):
        self.link("att-1")
        second, _code, _raw = self.link("att-2")
        document = state.read_json(second.attempt / irt.RECEIPT)
        document["operations"][0]["owner_attempt_id"] = "att-2"      # itself
        state.atomic_json(second.attempt / irt.RECEIPT, document)
        with self.assertRaises(state.Blocked):
            irt.validate_receipts(JOB, self.inputs, second.attempt)
        document["operations"][0]["owner_attempt_id"] = "missing"
        state.atomic_json(second.attempt / irt.RECEIPT, document)
        with self.assertRaises(state.Blocked):
            irt.validate_receipts(JOB, self.inputs, second.attempt)


if __name__ == "__main__":
    unittest.main()
