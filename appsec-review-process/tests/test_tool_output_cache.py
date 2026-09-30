"""Tool-output cache (brief N): hit, miss, invalidate, tampered and timeout cases."""
from __future__ import annotations

import json
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

import container_execution as ce
import container_execution_support as support
import dependency_b13_adapters as adapters
import dependency_workers as workers
import execution_state
import tool_output_cache as toc
import tunables
from test_container_execution import ScriptedDocker

RUN = "run-dependency"
TIMEOUT = {"client_exit": -9, "metadata": {"timed_out": True, "error": "TimeoutError: bounded"}}


class ToolOutputCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.runs = self.root / "runs"
        self.target = self.root / "target"; self.target.mkdir(); (self.target / "package.json").write_text("{}\n")
        self.images = self.root / "images"; self.images.mkdir()
        base = support.fixture_record()
        for spec in adapters.SPECS.values():
            record = {**base, "image_id": spec["image"], "repository": "docker.io/library/" + spec["image"]}
            (self.images / (spec["image"] + ".json")).write_text(json.dumps(record))
        self.source = "sha256:" + "a" * 64
        self.setting = "dev"
        patches = [mock.patch.object(execution_state, "RUNS", self.runs),
                   mock.patch.dict(os.environ, {"APPSEC_CACHE_ROOT": str(self.root / "cache"),
                                                "APPSEC_RUN_MODE": "dev"}),
                   mock.patch.object(tunables, "shared", side_effect=self.shared)]
        for patch in patches:
            patch.start(); self.addCleanup(patch.stop)

    def tearDown(self):
        self.temporary.cleanup()

    def shared(self, name):
        if name == "tool_output_cache":
            return self.setting
        if name == "tool_output_cache_max_entries":
            return 4096
        return tunables._shared()[name]["value"]

    def runtime(self):
        defaults = ce.host_defaults()
        return ce.ContainerRuntime(docker_executable=defaults["docker_executable"] or Path(sys.executable).resolve(),
            docker_host=None, images_dir=self.images, host_flavor=defaults["host_flavor"],
            container_user=defaults["container_user"] if ce._USER_RE.match(defaults["container_user"]) else "10001:10001",
            source_snapshot_sha256=self.source, registry_ceiling=[], clock=lambda: support.NOW,
            cancel=threading.Event())

    def attempt_root(self, kind, name, owned=True):
        base = (execution_state.data_path(RUN, "jobs", adapters.SPECS[kind]["job"], "orchestration-attempts")
                if owned else self.root / "elsewhere")
        path = base / name / "b13" / kind
        path.mkdir(parents=True)
        return path

    def execute(self, kind, scripted, output, name, owned=True):
        attempt = self.attempt_root(kind, name, owned)
        original_child = scripted.child
        def child(spec, **kwargs):
            result = original_child(spec, **kwargs)
            scratch = Path(spec.owner_root) / "scratch"
            scratch.mkdir(exist_ok=True)
            (scratch / adapters.SPECS[kind]["output"]).write_bytes(output)
            return result
        scripted.child = child
        first, second = scripted.patches()
        with first, second:
            result = adapters.execute(kind, run_id=RUN, adapter_attempt_id=name + "-" + kind,
                source_snapshot_sha256=self.source, attempt_root=attempt,
                supplied_runtime=self.runtime(), target=self.target)
        return result, attempt

    def entries(self):
        return toc.store().entries()

    def events(self):
        path = toc.store().directory / "events.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []

    def assert_worker_accepts(self, kind, result):
        request = {"run_id": RUN, "source_snapshot_sha256": self.source, "b13_attempt": result["b13_attempt"]}
        _document, receipt, output = workers._tool(request, adapters.SPECS[kind]["job"], kind)
        self.assertEqual(str(output), result["tool_output"])
        return receipt

    # --- hit / miss ---------------------------------------------------------------------------

    def test_second_attempt_reuses_the_reverified_attempt_with_provenance(self):
        first_docker = ScriptedDocker()
        first, first_root = self.execute("syft", first_docker, b'{"components": []}\n', "a1")
        self.assertTrue(first_docker.child_specs)
        self.assertNotIn("reused_from", first)
        self.assertEqual(len(self.entries()), 1)
        second_docker = ScriptedDocker()
        with mock.patch.object(ce, "load_verified_result", wraps=ce.load_verified_result) as verify:
            second, second_root = self.execute("syft", second_docker, b"never written\n", "a2")
        self.assertEqual(second_docker.child_specs, [], "a hit must not start a container")
        self.assertTrue(verify.called, "a hit must re-verify the cached B13 attempt")
        self.assertEqual(second["b13_attempt"], first["b13_attempt"])
        self.assertEqual(second["reused_from"]["attempt_root"], str(first_root))
        self.assertEqual(second["reused_from"]["attempt_id"], "a1-syft")
        reuse = json.loads((second_root / "tool-output-reuse.json").read_text())
        self.assertEqual((reuse["schema"], reuse["attempt_id"], reuse["outcome"]),
                         (adapters.REUSE_SCHEMA, "a2-syft", "OUTPUT"))
        receipt = self.assert_worker_accepts("syft", second)
        self.assertEqual(receipt["attempt_id"], "a1-syft")

    def test_changed_input_bytes_are_a_miss(self):
        self.execute("syft", ScriptedDocker(), b"{}\n", "a1")
        (self.target / "package.json").write_text('{"name": "changed"}\n')
        docker = ScriptedDocker()
        result, _ = self.execute("syft", docker, b"{}\n", "a2")
        self.assertTrue(docker.child_specs)
        self.assertNotIn("reused_from", result)
        self.assertEqual(len(self.entries()), 2)

    def test_target_content_never_names_its_own_key(self):
        """The key is our digest over the bytes: a file claiming a hash does not change it, and
        two trees with the same claim but different bytes get different keys."""
        claim = '{"sha256": "%s"}\n' % ("0" * 64)
        (self.target / "claimed.json").write_text(claim)
        first = toc.tree_digest(self.target)
        (self.target / "package.json").write_text('{"x": 1}\n')
        self.assertNotEqual(toc.tree_digest(self.target), first)

    def test_changed_limits_are_a_miss(self):
        self.execute("syft", ScriptedDocker(), b"{}\n", "a1")
        real = tunables.container_limits
        def limits(job, prefix="container"):
            return {**real(job, prefix), "memory_bytes": real(job, prefix)["memory_bytes"] * 2}
        docker = ScriptedDocker()
        with mock.patch.object(tunables, "container_limits", side_effect=limits):
            result, _ = self.execute("syft", docker, b"{}\n", "a2")
        self.assertTrue(docker.child_specs)
        self.assertNotIn("reused_from", result)

    # --- invalidation / tampering ------------------------------------------------------------

    def test_tampered_cached_attempt_is_invalidated_and_run_fresh(self):
        _first, first_root = self.execute("syft", ScriptedDocker(), b"{}\n", "a1")
        (first_root / "logs/container/stdout.log").write_bytes(b"tampered\n")
        docker = ScriptedDocker()
        result, _ = self.execute("syft", docker, b"{}\n", "a2")
        self.assertTrue(docker.child_specs)
        self.assertNotIn("reused_from", result)
        self.assertTrue(any(e["event"] == "invalidate" and "re-verification" in e["reason"] for e in self.events()))
        # the fresh verified attempt replaced the entry
        [(_path, entry)] = self.entries()
        self.assertEqual(entry["b13_attempt"]["request"]["attempt_id"], "a2-syft")

    def test_tampered_cached_output_is_invalidated(self):
        first, _ = self.execute("syft", ScriptedDocker(), b"{}\n", "a1")
        Path(first["tool_output"]).write_bytes(b'{"components": [{"name": "forged"}]}\n')
        docker = ScriptedDocker()
        result, _ = self.execute("syft", docker, b"{}\n", "a2")
        self.assertTrue(docker.child_specs)
        self.assertNotIn("reused_from", result)

    def test_tampered_entry_is_invalidated(self):
        self.execute("syft", ScriptedDocker(), b"{}\n", "a1")
        [(path, entry)] = self.entries()
        entry["b13_attempt"]["expected_result_sha256"] = "sha256:" + "f" * 64
        path.write_text(json.dumps(entry))
        docker = ScriptedDocker()
        result, _ = self.execute("syft", docker, b"{}\n", "a2")
        self.assertTrue(docker.child_specs)
        self.assertNotIn("reused_from", result)
        entry["material"]["mode"] = "prod"      # an entry that no longer matches its own key
        path.write_text(json.dumps(entry))
        self.assertIsNone(toc.store().get(entry["key"], {**entry["material"], "mode": "dev"}))

    def test_entry_pointing_outside_the_run_job_tree_is_rejected(self):
        self.execute("syft", ScriptedDocker(), b"{}\n", "a1")
        [(path, entry)] = self.entries()
        foreign = self.root / "foreign"; foreign.mkdir()
        entry["b13_attempt"]["attempt_root"] = str(foreign)
        path.write_text(json.dumps(entry))
        docker = ScriptedDocker()
        self.execute("syft", docker, b"{}\n", "a2")
        self.assertTrue(docker.child_specs)

    # --- what is and is not cached -----------------------------------------------------------

    def test_timeout_gap_is_cached_only_for_the_same_limits(self):
        first, _ = self.execute("scancode", ScriptedDocker(**TIMEOUT), b"", "a1")
        self.assertIn("ended TIMEOUT", first["tool_gap"])
        docker = ScriptedDocker()
        second, second_root = self.execute("scancode", docker, b"{}\n", "a2")
        self.assertEqual(docker.child_specs, [])
        self.assertEqual((second["tool_gap"], second["reused_from"]["attempt_id"]), (first["tool_gap"], "a1-scancode"))
        self.assertEqual(json.loads((second_root / "tool-output-reuse.json").read_text())["outcome"], "GAP")
        with self.assertRaises(workers.ToolGap):
            workers._tool({"run_id": RUN, "source_snapshot_sha256": self.source,
                           "b13_attempt": second["b13_attempt"]}, "02-license-scan", "scancode", allow_gap=True)
        real = tunables.container_limits
        def longer(job, prefix="container"):
            return {**real(job, prefix), "timeout_seconds": real(job, prefix)["timeout_seconds"] * 2}
        docker = ScriptedDocker()
        with mock.patch.object(tunables, "container_limits", side_effect=longer):
            third, _ = self.execute("scancode", docker, b"{}\n", "a3")
        self.assertTrue(docker.child_specs, "a longer timeout must retry the tool")
        self.assertIsNotNone(third["tool_output"])

    def test_nonzero_exit_gap_blocked_and_canceled_attempts_are_never_cached(self):
        self.execute("scancode", ScriptedDocker(client_exit=2), b"{", "a1")      # verified gap, not cached
        with self.assertRaises(adapters.AdapterBlocked):
            self.execute("syft", ScriptedDocker(**TIMEOUT), b"{}\n", "a2")       # blocked
        with self.assertRaises(adapters.AdapterBlocked):
            self.execute("syft", ScriptedDocker(client_exit=3), b"{}\n", "a3")   # blocked
        self.assertEqual(self.entries(), [])

    def test_prod_default_is_off_and_never_hits_a_dev_entry(self):
        self.execute("syft", ScriptedDocker(), b"{}\n", "a1")                    # dev entry
        with mock.patch.dict(os.environ, {"APPSEC_RUN_MODE": "prod"}):
            self.assertFalse(toc.enabled())
            self.assertEqual(tunables._shared()["tool_output_cache"]["value"], "dev")
            docker = ScriptedDocker()
            self.execute("syft", docker, b"{}\n", "p1")
            self.assertTrue(docker.child_specs)
            self.setting = "on"                                                 # controller flips prod
            docker = ScriptedDocker()
            result, _ = self.execute("syft", docker, b"{}\n", "p2")
            self.assertTrue(docker.child_specs, "a prod run never reuses a dev entry")
            self.assertNotIn("reused_from", result)
            docker = ScriptedDocker()
            result, _ = self.execute("syft", docker, b"{}\n", "p3")
            self.assertEqual(docker.child_specs, [])
            self.assertEqual(result["reused_from"]["attempt_id"], "p2-syft")

    def test_off_setting_and_unowned_attempts_bypass_the_cache(self):
        self.setting = "off"
        self.execute("syft", ScriptedDocker(), b"{}\n", "a1")
        self.assertEqual(self.entries(), [])
        self.setting = "dev"
        self.execute("syft", ScriptedDocker(), b"{}\n", "a2", owned=False)
        self.assertEqual(self.entries(), [])
        self.setting = "bogus"
        self.assertFalse(toc.enabled())

    def test_linked_input_tree_is_uncacheable_but_still_runs(self):
        (self.target / "link").symlink_to(self.target / "package.json")
        with self.assertRaises(toc.Uncacheable):
            toc.tree_digest(self.target)
        docker = ScriptedDocker()
        result, _ = self.execute("syft", docker, b"{}\n", "a1")
        self.assertTrue(docker.child_specs)
        self.assertEqual(self.entries(), [])

    def test_prune_caps_entries_oldest_first_and_drops_dead_attempts(self):
        store = toc.store()
        for n in range(5):
            material = {"n": n}
            store.put(toc.key_of(material), material, {"b13_attempt": {"attempt_root": str(self.root / f"gone{n}")}})
        self.assertEqual(store.prune(max_entries=3), 2)
        self.assertEqual(len(store.entries()), 3)
        self.assertEqual(store.prune(alive=toc.attempt_alive), 3)
        self.assertEqual(store.entries(), [])


if __name__ == "__main__":
    unittest.main()
