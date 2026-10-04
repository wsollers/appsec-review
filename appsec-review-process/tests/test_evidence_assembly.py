"""Focused nominal tests for the F02 evidence-assembly core."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import component_characterization as cc  # noqa: E402
import evidence_assembly as worker  # noqa: E402
import execution_state  # noqa: E402
from execution_state import Blocked, atomic_json, file_hash, read_json, tree_hashes  # noqa: E402
import pool_rendezvous as pr  # noqa: E402
import pool_rendezvous_support as rendezvous_support  # noqa: E402
from worker_result import artifact_records, terminal_envelope  # noqa: E402

PLAN = read_json(ROOT / "tests" / "fixtures" / "evidence-assembly" / "complete-plan.json")


def make_rendezvous(folder, attempt_id="terminal-generation-1", workspace=None):
    """One C01/C02 producer-binding generation; a second call with the same ``workspace`` is the next
    launch's generation (same pool parent and context, new instance ids)."""
    workspace = workspace or rendezvous_support.RendezvousWorkspace(Path(folder).resolve())
    dependencies = read_json(worker.GRAPH)["jobs"][worker.JOB]["dependencies"]
    groups = []
    for edge in dependencies:
        group = workspace.persona_group(edge["job"][3:][:40], 1)
        group["permission"] = rendezvous_support.c01.permission(
            job_id=worker.JOB, run_id=PLAN["run_id"])
        groups.append(group)
    spec = workspace.spec(groups, pool_id="evidence-assembly", lane="pregather",
        run_id=PLAN["run_id"], job_id=worker.JOB, attempt_id=attempt_id)
    plan = workspace.expand(spec)
    workspace.run(spec, plan, max_parallel=pr.MAX_PARALLEL)
    return workspace, spec, plan


def make_supply(folder, plan, *, omit=(), duplicate=None, source_override=None, build_override=None,
                stale=None, corrupt=None):
    supply_root = Path(folder, "supply"); supply_root.mkdir()
    graph = read_json(worker.GRAPH)
    dependencies = graph["jobs"][worker.JOB]["dependencies"]
    terminal_ids = {item.entry["group_id"]: item.instance_id for item in plan.instances}
    bindings = []
    for edge in dependencies:
        job = edge["job"]
        if job in omit:
            continue
        attempt_id = "attempt-" + hashlib.sha256(job.encode()).hexdigest()[:12]
        attempt = supply_root / "producers" / job / "attempts" / attempt_id
        permission = {"schema": worker.PERMISSION_SCHEMA, "run_id": PLAN["run_id"], "job_id": job,
            "source_snapshot_sha256": PLAN["source_snapshot_sha256"],
            "permissions": PLAN["permissions"]}
        atomic_json(attempt / "permission.json", permission)
        atomic_json(attempt / "lineage.json", {"schema": worker.LINEAGE_SCHEMA,
            "run_id": PLAN["run_id"], "job_id": job,
            "source_snapshot_sha256": PLAN["source_snapshot_sha256"],
            "build_lineage_sha256": PLAN["build_lineage_sha256"]})
        atomic_json(attempt / "evidence.json", {"producer": job, "evidence": "fixture-only"})
        status, skip_reason, gaps = "OK", None, []
        if job == PLAN["authorized_skip"]["job_id"]:
            status, skip_reason = "SKIPPED", PLAN["authorized_skip"]["reason"]
        if job == PLAN["gapped_job"]:
            status, gaps = "OK_WITH_GAPS", [PLAN["gap"]]
        artifacts = artifact_records(attempt, ["permission.json", "lineage.json", "evidence.json"])
        envelope = terminal_envelope(run_id=PLAN["run_id"], job_id=job, attempt_id=attempt_id,
            worker_kind="deterministic_python", execution_status=status, acceptance_status="CURRENT",
            input_fingerprint="sha256:" + hashlib.sha256((job + "-fingerprint").encode()).hexdigest(),
            output_contract=edge["contract"], started_at="2026-09-27T00:00:00Z",
            finished_at="2026-09-27T00:00:01Z", summary="fixture producer", artifacts=artifacts,
            gaps=gaps, skip_reason=skip_reason)
        atomic_json(attempt / "result.json", envelope)
        producer_root = supply_root / "producers" / job
        pointer = {"schema": "appsec-review/accepted-worker-result/1.0", "status": status,
            "run_id": PLAN["run_id"], "job": job, "attempt_id": attempt_id,
            "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
            "envelope_sha256": file_hash(attempt / "result.json"), "hashes": tree_hashes(attempt),
            "accepted_at": "2026-09-27T00:00:02Z"}
        if status == "SKIPPED":
            pointer["reason"] = skip_reason
        atomic_json(producer_root / "accepted.json", pointer)
        atomic_json(producer_root / "latest.json", {"attempt_id": "stale-attempt" if stale == job else attempt_id})
        binding_source = source_override if source_override and source_override[0] == job else None
        binding_build = build_override if build_override and build_override[0] == job else None
        bindings.append({"job_id": job,
            "source_snapshot_sha256": binding_source[1] if binding_source else PLAN["source_snapshot_sha256"],
            "producer_source_snapshot_sha256": PLAN["source_snapshot_sha256"],
            "build_lineage_sha256": binding_build[1] if binding_build else PLAN["build_lineage_sha256"],
            "permissions": PLAN["permissions"],
            "terminal_instance_ids": [terminal_ids[job[3:][:40]]]})
    if duplicate:
        bindings.append(copy.deepcopy(next(item for item in bindings if item["job_id"] == duplicate)))
    supply = {"schema": worker.SUPPLY_SCHEMA, "run_id": PLAN["run_id"],
              "source_snapshot_sha256": PLAN["source_snapshot_sha256"], "producers": bindings}
    atomic_json(supply_root / worker.SUPPLY, supply)
    if corrupt:
        path = supply_root / "producers" / corrupt / "attempts"
        attempt = next(path.iterdir())
        (attempt / "evidence.json").write_text('{"changed":true}\n')
    return supply_root


def reseal_producer(supply_root, job):
    producer = Path(supply_root, "producers", job)
    pointer = read_json(producer / "accepted.json")
    attempt = producer / "attempts" / pointer["attempt_id"]
    pointer["envelope_sha256"] = file_hash(attempt / "result.json")
    pointer["hashes"] = tree_hashes(attempt)
    atomic_json(producer / "accepted.json", pointer)


class EvidenceAssemblyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pool_temporary = tempfile.TemporaryDirectory()
        cls.workspace, cls.spec, cls.plan = make_rendezvous(cls.pool_temporary.name)

    @classmethod
    def tearDownClass(cls):
        rendezvous_support.join_pool_threads()
        cls.pool_temporary.cleanup()

    def pool_arguments(self):
        return {"pool_root": self.workspace.root(self.plan), "expected_spec": self.spec,
                "context": self.workspace.context(),
                "rendezvous_parent": self.workspace.rendezvous_parent}

    def inspect(self, supply):
        return worker.inspect_supply(supply, run_id=PLAN["run_id"],
            source_snapshot_sha256=PLAN["source_snapshot_sha256"], **self.pool_arguments())

    def test_complete_manifest_is_deterministic_hash_bound_and_preserves_citation_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder, self.plan)
            first, copies = self.inspect(supply)
            second, _ = self.inspect(supply)
            self.assertEqual(first, second)
            self.assertEqual(first["assembly_status"], "COMPLETE")
            self.assertEqual(first["manifest_sha256"], worker.manifest_sha256(first))
            dependencies = read_json(worker.GRAPH)["jobs"][worker.JOB]["dependencies"]
            self.assertEqual(len(first["producers"]), len(dependencies))
            self.assertEqual(len(copies), 1 + sum(len(item["artifacts"])
                                                  for item in first["producers"]))
            artifact = first["producers"][0]["artifacts"][0]
            self.assertEqual(set(artifact), {"producer_job_id", "producer_attempt_id", "producer_path",
                                              "path", "sha256", "media_type"})
            skipped = next(item for item in first["producers"] if item["disposition"] == "authorized-skip")
            self.assertEqual(skipped["skip_reason"], PLAN["authorized_skip"]["reason"])
            self.assertTrue(any(gap["kind"] == "producer-gap" for gap in first["coverage_gaps"]))

    def test_missing_producer_is_explicit_but_incomplete_and_cannot_publish(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder, self.plan, omit={"02-source-sast"})
            manifest, _ = self.inspect(supply)
            missing = next(item for item in manifest["producers"] if item["job_id"] == "02-source-sast")
            self.assertEqual(missing["disposition"], "missing")
            self.assertEqual(manifest["assembly_status"], "INCOMPLETE")
            job_root = Path(folder, "job")
            with mock.patch.object(worker, "root", return_value=job_root):
                with self.assertRaises(Blocked):
                    worker.run(PLAN["run_id"], "dagster-fixture", supply_root=supply,
                               source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                               **self.pool_arguments())
            pointer = read_json(job_root / "accepted.json")
            self.assertEqual(pointer["status"], "BLOCKED")
            self.assertFalse(any(job_root.glob("attempts/*/intel-manifest.json")))

    def test_complete_generation_publishes_common_envelope_and_copied_artifacts(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder, self.plan)
            job_root = Path(folder, "job")
            with mock.patch.object(worker, "root", return_value=job_root):
                pointer = worker.run(PLAN["run_id"], "dagster-fixture", supply_root=supply,
                    source_snapshot_sha256=PLAN["source_snapshot_sha256"], **self.pool_arguments())
            self.assertEqual(pointer["status"], "OK_WITH_GAPS")
            attempt = job_root / "attempts" / pointer["attempt_id"]
            manifest = read_json(attempt / worker.RESULT)
            self.assertEqual(manifest["assembly_status"], "COMPLETE")
            self.assertEqual(pointer["hashes"], tree_hashes(attempt))
            for producer in manifest["producers"]:
                for artifact in producer["artifacts"]:
                    self.assertEqual("sha256:" + file_hash(attempt / artifact["path"]), artifact["sha256"])

    def test_corrupt_artifact_and_stale_pointer_fail_closed(self):
        for variant in ("corrupt", "stale"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as folder:
                kwargs = {variant: "02-source-sast"}
                supply = make_supply(folder, self.plan, **kwargs)
                with self.assertRaises(Blocked):
                    self.inspect(supply)

    def test_mixed_source_generation_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(
                folder, self.plan,
                source_override=("02-source-sast", "sha256:" + "c" * 64))
            with self.assertRaises(Blocked):
                self.inspect(supply)

    def test_producer_specific_build_lineage_is_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            changed = "sha256:" + "d" * 64
            supply = make_supply(
                folder, self.plan, build_override=("02-source-sast", changed))
            producer_root = supply / "producers" / "02-source-sast"
            pointer = read_json(producer_root / "accepted.json")
            lineage_path = producer_root / "attempts" / pointer["attempt_id"] / "lineage.json"
            lineage = read_json(lineage_path)
            lineage["build_lineage_sha256"] = changed
            atomic_json(lineage_path, lineage)
            attempt = lineage_path.parent
            envelope = read_json(attempt / "result.json")
            envelope["artifacts"] = artifact_records(
                attempt, [item["path"] for item in envelope["artifacts"]])
            atomic_json(attempt / "result.json", envelope)
            reseal_producer(supply, "02-source-sast")
            manifest, _copies = self.inspect(supply)
            producer = next(item for item in manifest["producers"]
                            if item["job_id"] == "02-source-sast")
            self.assertEqual(producer["build_lineage_sha256"], changed)

    def test_duplicate_producer_binding_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder, self.plan, duplicate="02-source-sast")
            with self.assertRaises(Blocked):
                self.inspect(supply)

    def test_unauthorized_skip_and_permission_mismatch_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder, self.plan)
            job = PLAN["authorized_skip"]["job_id"]
            producer = supply / "producers" / job
            pointer = read_json(producer / "accepted.json")
            envelope_path = producer / "attempts" / pointer["attempt_id"] / "result.json"
            envelope = read_json(envelope_path); envelope["skip_reason"] = "not-requested"
            atomic_json(envelope_path, envelope); reseal_producer(supply, job)
            with self.assertRaises(Blocked):
                self.inspect(supply)
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder, self.plan)
            config = read_json(supply / worker.SUPPLY)
            config["producers"][0]["permissions"] = ["network"]
            atomic_json(supply / worker.SUPPLY, config)
            with self.assertRaises(Blocked):
                self.inspect(supply)

    def test_resealed_terminal_request_adapter_and_result_hash_forgery_is_rederived_and_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace, spec, plan = make_rendezvous(Path(folder, "pool"))
            supply = make_supply(folder, plan)
            path = workspace.manifest_path(plan)
            terminal = read_json(path)
            terminal["instances"][0]["request_sha256"] = "sha256:" + "0" * 64
            terminal["instances"][0]["adapter_result_sha256"] = "sha256:" + "1" * 64
            terminal["instances"][0]["result_file"]["sha256"] = "sha256:" + "2" * 64
            terminal["manifest_sha256"] = pr.manifest_sha256(terminal)
            path.unlink(); path.write_bytes(pr.canonical_bytes(terminal))
            with self.assertRaises(Blocked):
                worker.inspect_supply(supply, run_id=PLAN["run_id"],
                    source_snapshot_sha256=PLAN["source_snapshot_sha256"],
                    pool_root=workspace.root(plan), expected_spec=spec, context=workspace.context(),
                    rendezvous_parent=workspace.rendezvous_parent)

    def test_unclaimed_or_wrongly_claimed_terminal_instance_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = make_supply(folder, self.plan)
            config = read_json(supply / worker.SUPPLY)
            config["producers"][0]["terminal_instance_ids"] = [config["producers"][1]["terminal_instance_ids"][0]]
            atomic_json(supply / worker.SUPPLY, config)
            with self.assertRaises(Blocked):
                self.inspect(supply)

    def test_wrong_or_open_accepted_pointer_shape_is_rejected_even_when_resealed(self):
        for edit in (lambda pointer: pointer.update(schema="forged/schema"),
                     lambda pointer: pointer.update(extra="resealed-but-not-common"),
                     lambda pointer: pointer.update(envelope_path="other.json")):
            with self.subTest(edit=edit), tempfile.TemporaryDirectory() as folder:
                supply = make_supply(folder, self.plan)
                producer = supply / "producers" / "02-source-sast"
                pointer = read_json(producer / "accepted.json")
                edit(pointer)
                atomic_json(producer / "accepted.json", pointer)
                with self.assertRaises(Blocked):
                    self.inspect(supply)

    def test_graph_accepts_implemented_barrier_and_rejects_blocked_or_unimplemented(self):
        graph = read_json(worker.GRAPH)
        self.assertTrue(graph["jobs"][worker.JOB]["implemented"])
        dependencies, _sha = worker._graph()
        self.assertTrue(dependencies)
        for mutation in (lambda node: node.update(implemented=False),
                         lambda node: node.pop("join_policy")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as folder:
                candidate = copy.deepcopy(graph)
                mutation(candidate["jobs"][worker.JOB])
                path = Path(folder, "job-graph.json")
                atomic_json(path, candidate)
                with mock.patch.object(worker, "GRAPH", path), self.assertRaises(Blocked):
                    worker._graph()


def change_producer(supply_root, job):
    """Republish one producer's evidence with different bytes (envelope and pointer resealed)."""
    producer = Path(supply_root, "producers", job)
    attempt = producer / "attempts" / read_json(producer / "accepted.json")["attempt_id"]
    atomic_json(attempt / "evidence.json", {"producer": job, "evidence": "changed"})
    envelope = read_json(attempt / "result.json")
    envelope["artifacts"] = artifact_records(attempt, [item["path"] for item in envelope["artifacts"]])
    atomic_json(attempt / "result.json", envelope)
    reseal_producer(supply_root, job)


class ResumeReuseTests(unittest.TestCase):
    """Run 20261004T054551Z-357581: a resumed full_review re-ran 02-evidence-assembly and therefore
    01/03 and every model stage, because the fingerprint and the manifest bound the per-launch
    producer-binding pool (new instance ids every launch) instead of what the producers published."""

    @classmethod
    def setUpClass(cls):
        cls.pool_temporary = tempfile.TemporaryDirectory()
        cls.workspace, cls.spec1, cls.plan1 = make_rendezvous(cls.pool_temporary.name, "generation-launch-1")
        _workspace, cls.spec2, cls.plan2 = make_rendezvous(None, "generation-launch-2", cls.workspace)

    @classmethod
    def tearDownClass(cls):
        rendezvous_support.join_pool_threads()
        cls.pool_temporary.cleanup()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        runs = mock.patch.object(execution_state, "RUNS", self.folder / "runs")
        runs.start(); self.addCleanup(runs.stop)

    def supply(self, name, plan):
        folder = self.folder / name
        folder.mkdir()
        return make_supply(folder, plan)

    def arguments(self, spec, plan, supply):
        return {"supply_root": supply, "source_snapshot_sha256": PLAN["source_snapshot_sha256"],
                "pool_root": self.workspace.root(plan), "expected_spec": spec,
                "context": self.workspace.context(), "rendezvous_parent": self.workspace.rendezvous_parent}

    def launch(self, dagster_run_id, spec, plan, supply):
        pointer = worker.run(PLAN["run_id"], dagster_run_id, **self.arguments(spec, plan, supply))
        # What 01-component-characterization binds from the accepted assembly.
        _attempt, evidence = cc._accepted_evidence(PLAN["run_id"], PLAN["source_snapshot_sha256"])
        return pointer, evidence

    def record(self, spec, plan, supply):
        arguments = self.arguments(spec, plan, supply)
        return worker.current_inputs(PLAN["run_id"], arguments.pop("supply_root"),
                                     arguments.pop("source_snapshot_sha256"), **arguments)

    def test_unchanged_producers_reuse_the_assembly_and_the_01_input_record_across_launches(self):
        self.assertNotEqual({item.instance_id for item in self.plan1.instances},
                            {item.instance_id for item in self.plan2.instances})
        supply1, supply2 = self.supply("supply-1", self.plan1), self.supply("supply-2", self.plan2)
        first_record = self.record(self.spec1, self.plan1, supply1)
        second_record = self.record(self.spec2, self.plan2, supply2)
        self.assertNotEqual(first_record["terminal_manifest_sha256"], second_record["terminal_manifest_sha256"])
        self.assertEqual(worker.fingerprint(first_record), worker.fingerprint(second_record))

        first, first_evidence = self.launch("dagster-launch-1", self.spec1, self.plan1, supply1)
        second, second_evidence = self.launch("dagster-launch-2", self.spec2, self.plan2, supply2)
        self.assertEqual(second, first)                       # REUSE: same attempt, fingerprint, pointer
        self.assertEqual(second_evidence, first_evidence)     # 01 binds an identical record
        attempts = worker.root(PLAN["run_id"]) / "attempts"
        self.assertEqual([path.name for path in attempts.iterdir()], [first["attempt_id"]])

        attempt = attempts / first["attempt_id"]
        manifest = read_json(attempt / worker.RESULT)
        self.assertEqual(manifest["schema"], worker.SCHEMA)
        self.assertNotIn("terminal_instances", manifest)
        self.assertFalse(any("terminal_instance_ids" in item for item in manifest["producers"]))
        # The retained audit record names the generation that produced the attempt and re-verifies.
        binding = read_json(attempt / worker.BINDING)
        self.assertEqual(binding["manifest_sha256"], manifest["manifest_sha256"])
        claimed = {iid for item in binding["producers"] for iid in item["terminal_instance_ids"]}
        self.assertEqual(claimed, {item.instance_id for item in self.plan1.instances})
        self.assertEqual(worker.validate(PLAN["run_id"], **self.arguments(self.spec2, self.plan2, supply2)),
                         attempt)

    def test_retained_terminal_binding_is_verified_against_its_pool(self):
        supply1, supply2 = self.supply("supply-1", self.plan1), self.supply("supply-2", self.plan2)
        first, _ = self.launch("dagster-launch-1", self.spec1, self.plan1, supply1)
        attempt = worker.root(PLAN["run_id"]) / "attempts" / first["attempt_id"]
        binding = read_json(attempt / worker.BINDING)
        binding["producers"][0]["terminal_instance_ids"] = ["0" * 32]
        atomic_json(attempt / worker.BINDING, binding)
        # Reseal the envelope and the pointer so only the re-derivation from the pool can object.
        envelope = read_json(attempt / "result.json")
        envelope["artifacts"] = artifact_records(attempt, [item["path"] for item in envelope["artifacts"]])
        atomic_json(attempt / "result.json", envelope)
        base = worker.root(PLAN["run_id"])
        pointer = read_json(base / "accepted.json")
        pointer.update(envelope_sha256=file_hash(attempt / "result.json"), hashes=tree_hashes(attempt))
        atomic_json(base / "accepted.json", pointer)
        with self.assertRaisesRegex(Blocked, "does not re-verify against its pool"):
            worker.validate(PLAN["run_id"], **self.arguments(self.spec2, self.plan2, supply2))

    def test_changed_producer_content_makes_a_new_assembly_and_propagates_to_01(self):
        supply1, supply2 = self.supply("supply-1", self.plan1), self.supply("supply-2", self.plan2)
        change_producer(supply2, "02-source-sast")
        first, first_evidence = self.launch("dagster-launch-1", self.spec1, self.plan1, supply1)
        second, second_evidence = self.launch("dagster-launch-2", self.spec2, self.plan2, supply2)
        self.assertNotEqual(second["attempt_id"], first["attempt_id"])
        self.assertNotEqual(second["fingerprint"], first["fingerprint"])
        self.assertNotEqual(second_evidence["manifest_self_sha256"], first_evidence["manifest_self_sha256"])
        self.assertNotEqual(second_evidence["generation_sha256"], first_evidence["generation_sha256"])
        self.assertNotEqual(second_evidence["attempt_id"], first_evidence["attempt_id"])


if __name__ == "__main__":
    unittest.main()
