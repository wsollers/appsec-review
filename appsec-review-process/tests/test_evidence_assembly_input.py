"""Focused tests for automatic, run-owned F02 supply construction."""
from __future__ import annotations

import copy
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import evidence_assembly as assembly  # noqa: E402
import evidence_assembly_input as constructor  # noqa: E402
from execution_state import Blocked, atomic_json, file_hash, read_json, tree_hashes  # noqa: E402
from test_evidence_assembly import make_rendezvous, make_supply, PLAN  # noqa: E402
from worker_result import artifact_records  # noqa: E402


def make_run(folder: Path, plan) -> tuple[Path, Path]:
    producer_source = folder / "producer-source"
    producer_source.mkdir()
    source = make_supply(producer_source, plan)
    run_root = folder / "run"
    jobs = run_root / "data" / "jobs"
    jobs.mkdir(parents=True)
    atomic_json(run_root / "inputs" / "artifact-manifest.json", {
        "run_id": PLAN["run_id"],
        "source_identity": {"revision": "fixture-revision",
                            "fingerprint": PLAN["source_snapshot_sha256"].removeprefix("sha256:")},
    })
    for producer in (source / "producers").iterdir():
        shutil.copytree(producer, jobs / producer.name)
    return run_root.resolve(), source


def reseal_receipt(run_root: Path, job: str, name: str, value: dict) -> None:
    producer = run_root / "data" / "jobs" / job
    pointer = read_json(producer / "accepted.json")
    attempt = producer / "attempts" / pointer["attempt_id"]
    atomic_json(attempt / name, value)
    envelope = read_json(attempt / "result.json")
    envelope["artifacts"] = artifact_records(
        attempt, [item["path"] for item in envelope["artifacts"]])
    atomic_json(attempt / "result.json", envelope)
    pointer["envelope_sha256"] = file_hash(attempt / "result.json")
    pointer["hashes"] = tree_hashes(attempt)
    atomic_json(producer / "accepted.json", pointer)


class EvidenceAssemblyInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pool_temporary = tempfile.TemporaryDirectory()
        cls.workspace, cls.spec, cls.plan = make_rendezvous(cls.pool_temporary.name)

    @classmethod
    def tearDownClass(cls):
        # Imported support owns the pool threads and joins them from its own test class; all are
        # already terminal before these tests start, so removal is safe here.
        cls.pool_temporary.cleanup()

    def pool_arguments(self):
        return {"pool_root": self.workspace.root(self.plan), "expected_spec": self.spec,
                "context": self.workspace.context(),
                "rendezvous_parent": self.workspace.rendezvous_parent}

    def test_stages_exact_graph_denominator_and_assembly_revalidates_it(self):
        with tempfile.TemporaryDirectory() as folder_value:
            folder = Path(folder_value)
            run_root, _ = make_run(folder, self.plan)
            output = run_root / "data" / "assembly-inputs" / "generation-1"
            staged = constructor.stage_supply(
                run_root, output, run_id=PLAN["run_id"],
                source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                **self.pool_arguments())
            self.assertEqual(staged, output)
            supply = read_json(staged / assembly.SUPPLY)
            dependencies = read_json(assembly.GRAPH)["jobs"][assembly.JOB]["dependencies"]
            self.assertEqual([item["job_id"] for item in supply["producers"]],
                             [edge["job"] for edge in dependencies])
            manifest, _copies = assembly.inspect_supply(
                staged, run_id=PLAN["run_id"],
                source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                **self.pool_arguments())
            self.assertEqual(manifest["assembly_status"], "COMPLETE")
            self.assertTrue(any(item["disposition"] == "authorized-skip"
                                for item in manifest["producers"]))

    def test_legacy_or_stale_producer_is_rejected_without_publishing_supply(self):
        cases = ("legacy", "stale")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder_value:
                folder = Path(folder_value)
                run_root, _ = make_run(folder, self.plan)
                producer = run_root / "data" / "jobs" / "02-source-sast"
                if case == "legacy":
                    atomic_json(producer / "accepted.json", {"status": "OK", "attempt_id": "legacy"})
                else:
                    atomic_json(producer / "latest.json", {"attempt_id": "newer-attempt"})
                output = run_root / "data" / "assembly-inputs" / case
                with self.assertRaises(Blocked):
                    constructor.stage_supply(
                        run_root, output, run_id=PLAN["run_id"],
                        source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                        **self.pool_arguments())
                self.assertFalse(output.exists())

    def test_resealed_stale_source_lineage_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder_value:
            folder = Path(folder_value)
            run_root, _ = make_run(folder, self.plan)
            job = "02-source-sast"
            producer = run_root / "data" / "jobs" / job
            pointer = read_json(producer / "accepted.json")
            attempt = producer / "attempts" / pointer["attempt_id"]
            receipt = read_json(attempt / "permission.json")
            receipt["source_snapshot_sha256"] = "sha256:" + "c" * 64
            reseal_receipt(run_root, job, "permission.json", receipt)
            with self.assertRaises(Blocked):
                constructor.derive_plan(
                    run_root, run_id=PLAN["run_id"],
                    source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                    **self.pool_arguments())

    def test_producer_specific_build_lineage_is_retained(self):
        with tempfile.TemporaryDirectory() as folder_value:
            folder = Path(folder_value)
            run_root, _ = make_run(folder, self.plan)
            job = "02-source-sast"
            changed = "sha256:" + "d" * 64
            producer = run_root / "data" / "jobs" / job
            pointer = read_json(producer / "accepted.json")
            attempt = producer / "attempts" / pointer["attempt_id"]
            receipt = read_json(attempt / "lineage.json")
            receipt["build_lineage_sha256"] = changed
            reseal_receipt(run_root, job, "lineage.json", receipt)
            plan = constructor.derive_plan(
                run_root, run_id=PLAN["run_id"],
                source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                **self.pool_arguments())
            binding = next(item for item in plan["supply"]["producers"]
                           if item["job_id"] == job)
            self.assertEqual(binding["build_lineage_sha256"], changed)

    def test_c01_specification_or_output_boundary_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder_value:
            folder = Path(folder_value)
            run_root, _ = make_run(folder, self.plan)
            spec = copy.deepcopy(self.spec)
            spec["attempt_id"] = "another-terminal-generation"
            with self.assertRaises(Blocked):
                constructor.derive_plan(
                    run_root, run_id=PLAN["run_id"],
                    source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                    pool_root=self.workspace.root(self.plan), expected_spec=spec,
                    context=self.workspace.context(),
                    rendezvous_parent=self.workspace.rendezvous_parent)
            with self.assertRaises(Blocked):
                constructor.stage_supply(
                    run_root, folder / "outside-run", run_id=PLAN["run_id"],
                    source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                    **self.pool_arguments())

    def test_manifest_bound_alias_is_retained_without_rewriting_receipts(self):
        with tempfile.TemporaryDirectory() as folder_value:
            folder = Path(folder_value)
            run_root, _ = make_run(folder, self.plan)
            alias = "sha256:" + file_hash(run_root / "inputs" / "artifact-manifest.json")
            job = "02-source-sast"
            producer = run_root / "data" / "jobs" / job
            pointer = read_json(producer / "accepted.json")
            attempt = producer / "attempts" / pointer["attempt_id"]
            permission = read_json(attempt / "permission.json")
            permission["source_snapshot_sha256"] = alias
            lineage = read_json(attempt / "lineage.json")
            lineage["source_snapshot_sha256"] = alias
            reseal_receipt(run_root, job, "permission.json", permission)
            reseal_receipt(run_root, job, "lineage.json", lineage)
            before = read_json(attempt / "lineage.json")
            output = run_root / "data" / "assembly-inputs" / "manifest-alias"
            staged = constructor.stage_supply(
                run_root, output, run_id=PLAN["run_id"],
                source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                **self.pool_arguments())
            supply = read_json(staged / assembly.SUPPLY)
            binding = next(item for item in supply["producers"] if item["job_id"] == job)
            self.assertEqual(binding["source_snapshot_sha256"], PLAN["source_snapshot_sha256"])
            self.assertEqual(binding["producer_source_snapshot_sha256"], alias)
            self.assertEqual(read_json(attempt / "lineage.json"), before)
            manifest, _copies = assembly.inspect_supply(
                staged, run_id=PLAN["run_id"],
                source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                **self.pool_arguments())
            entry = next(item for item in manifest["producers"] if item["job_id"] == job)
            self.assertEqual(entry["source_snapshot_sha256"], PLAN["source_snapshot_sha256"])
            self.assertEqual(entry["producer_source_snapshot_sha256"], alias)

    def test_stale_manifest_alias_and_alias_without_build_lineage_are_rejected(self):
        for stale, without_build in ((True, False), (False, True)):
            with self.subTest(stale=stale, without_build=without_build), \
                    tempfile.TemporaryDirectory() as folder_value:
                folder = Path(folder_value)
                run_root, _ = make_run(folder, self.plan)
                alias = ("sha256:" + "e" * 64 if stale else
                         "sha256:" + file_hash(run_root / "inputs" / "artifact-manifest.json"))
                job = "02-source-sast"
                producer = run_root / "data" / "jobs" / job
                pointer = read_json(producer / "accepted.json")
                attempt = producer / "attempts" / pointer["attempt_id"]
                permission = read_json(attempt / "permission.json")
                permission["source_snapshot_sha256"] = alias
                lineage = read_json(attempt / "lineage.json")
                lineage["source_snapshot_sha256"] = alias
                if without_build:
                    lineage["build_lineage_sha256"] = None
                reseal_receipt(run_root, job, "permission.json", permission)
                reseal_receipt(run_root, job, "lineage.json", lineage)
                with self.assertRaises(Blocked):
                    constructor.derive_plan(
                        run_root, run_id=PLAN["run_id"],
                        source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                        **self.pool_arguments())

    def test_whole_scope_root_is_accepted_and_dual_roots_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder_value:
            folder = Path(folder_value)
            run_root, _ = make_run(folder, self.plan)
            job = "02-source-sast"
            root = run_root / "data" / "jobs" / job
            whole = root / "whole"
            whole.mkdir()
            for name in ("accepted.json", "latest.json", "attempts"):
                shutil.move(str(root / name), str(whole / name))
            plan = constructor.derive_plan(
                run_root, run_id=PLAN["run_id"],
                source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                **self.pool_arguments())
            selected = next(item for item in plan["producers"] if item["job_id"] == job)
            self.assertEqual(selected["root"], whole.resolve())
            shutil.copy2(whole / "accepted.json", root / "accepted.json")
            shutil.copy2(whole / "latest.json", root / "latest.json")
            with self.assertRaises(Blocked):
                constructor.derive_plan(
                    run_root, run_id=PLAN["run_id"],
                    source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                    **self.pool_arguments())


if __name__ == "__main__":
    unittest.main()
