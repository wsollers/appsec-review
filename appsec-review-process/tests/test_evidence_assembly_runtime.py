"""Focused tests for the trusted F02 C01/C02 runtime constructor."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import evidence_assembly as assembly  # noqa: E402
import evidence_assembly_input  # noqa: E402
import evidence_assembly_runtime as runtime  # noqa: E402
from execution_state import Blocked, read_json  # noqa: E402
import persona_invocation as pi  # noqa: E402
import pool_rendezvous  # noqa: E402
from persona_invocation_support import MODEL  # noqa: E402
from test_evidence_assembly import make_rendezvous, PLAN  # noqa: E402
from test_evidence_assembly_input import make_run  # noqa: E402


class Unavailable:
    invoker_id = pi.FixtureInvoker.invoker_id

    def invoke(self, package, *, output_root, cancel):
        raise pi.InvokerUnavailable("test unavailable")


class EvidenceAssemblyRuntimeTests(unittest.TestCase):
    def prepared_run(self, folder: Path) -> Path:
        source_pool = folder / "source-pool"
        workspace, _spec, plan = make_rendezvous(source_pool)
        self.addCleanup(lambda: None)
        fixture = folder / "run-fixture"
        fixture.mkdir()
        run_root, _source = make_run(fixture, plan)
        return run_root

    def patches(self, run_root: Path):
        return (mock.patch.object(runtime, "run_path", return_value=run_root),
                mock.patch.object(runtime.mvr, "resolve_run_model_versions", return_value={}),
                mock.patch.object(runtime.mvr, "model_identity_for", return_value=MODEL))

    def test_producer_binding_completes_without_a_model_call_d31(self):
        """D-31: the default binding invoker fills every value locally; no claude dispatch happens."""
        with tempfile.TemporaryDirectory() as value:
            run_root = self.prepared_run(Path(value))
            p1, p2, p3 = self.patches(run_root)
            with p1, p2, p3, \
                    mock.patch("claude_cli_invoker.cbr.resolve_claude_binary", return_value="/usr/bin/claude"), \
                    mock.patch("claude_cli_invoker.rc._dispatch_streaming",
                               side_effect=AssertionError("no model call expected")):
                prepared = runtime.prepare(PLAN["run_id"], "dagster-binding-local",
                                           clock=lambda: "2026-09-27T00:00:02Z")
            args = prepared.assembly_arguments()
            verified = pool_rendezvous.load_verified_manifest(**args)
            self.assertEqual(verified.manifest["outcome"], pool_rendezvous.COMPLETE)
            plan = evidence_assembly_input.derive_plan(
                run_root, run_id=PLAN["run_id"], source_snapshot_sha256=prepared.source_snapshot_sha256, **args)
            self.assertEqual(len(plan["producers"]), len(evidence_assembly_input._dependencies()))

    def test_prepare_uses_exact_graph_denominator_and_returns_f02_arguments(self):
        with tempfile.TemporaryDirectory() as value:
            run_root = self.prepared_run(Path(value))
            p1, p2, p3 = self.patches(run_root)
            with p1, p2, p3:
                prepared = runtime.prepare(PLAN["run_id"], "dagster-binding",
                                           invoker=pi.FixtureInvoker(),
                                           clock=lambda: "2026-09-27T00:00:02Z")
            args = prepared.assembly_arguments()
            verified = pool_rendezvous.load_verified_manifest(**args)
            dependencies = evidence_assembly_input._dependencies()
            self.assertEqual(verified.manifest["outcome"], pool_rendezvous.COMPLETE)
            self.assertEqual([group["group_id"] for group in prepared.expected_spec["worker_groups"]],
                             sorted(edge["job"][3:][:40] for edge in dependencies))
            self.assertEqual(len(verified.instances), len(dependencies))
            for group in prepared.expected_spec["worker_groups"]:
                request = group["persona_request"]
                self.assertEqual(group["permission"]["decision"]["capabilities"], [])
                self.assertEqual({Path(item["path"]).name for item in request["readable_inputs"]},
                                 {"accepted.json", "result.json", "permission.json", "lineage.json"})
            plan = evidence_assembly_input.derive_plan(
                run_root, run_id=PLAN["run_id"],
                source_snapshot_sha256=prepared.source_snapshot_sha256, **args)
            self.assertEqual(len(plan["producers"]), len(dependencies))

    def test_unavailable_member_is_retained_and_prepare_fails_closed(self):
        with tempfile.TemporaryDirectory() as value:
            run_root = self.prepared_run(Path(value))
            p1, p2, p3 = self.patches(run_root)
            with p1, p2, p3, self.assertRaises(Blocked):
                runtime.prepare(PLAN["run_id"], "dagster-unavailable", invoker=Unavailable(),
                                clock=lambda: "2026-09-27T00:00:02Z")
            manifests = list((run_root / "data" / "jobs" / assembly.JOB / "rendezvous")
                             .glob("*/terminal-instances.json"))
            self.assertEqual(len(manifests), 1)
            terminal = read_json(manifests[0])
            self.assertNotEqual(terminal["outcome"], pool_rendezvous.COMPLETE)
            self.assertEqual(len(terminal["instances"]), len(evidence_assembly_input._dependencies()))
            self.assertTrue(all(item["state"] == pool_rendezvous.BLOCKED
                                for item in terminal["instances"]))

    def test_stale_producer_fails_before_creating_a_pool(self):
        with tempfile.TemporaryDirectory() as value:
            run_root = self.prepared_run(Path(value))
            job = evidence_assembly_input._dependencies()[0]["job"]
            accepted = run_root / "data" / "jobs" / job / "accepted.json"
            accepted.write_text("{}\n", encoding="utf-8")
            p1, p2, p3 = self.patches(run_root)
            with p1, p2, p3, self.assertRaises(Blocked):
                runtime.prepare(PLAN["run_id"], "dagster-stale", invoker=pi.FixtureInvoker())
            self.assertFalse((run_root / "data" / "jobs" / assembly.JOB / "pools").exists())


if __name__ == "__main__":
    unittest.main()
