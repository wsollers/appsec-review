import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import persona_tool_pool_lifecycle as lifecycle
import control_lane_orchestration
from execution_state import Blocked, atomic_json, read_json

RUN_ID = "graph-pool-run"
SOURCE = "sha256:" + "2" * 64
MODEL = {"provider": "anthropic", "family": "claude-sonnet-5",
         "model_id": "claude-sonnet-5-20260927", "snapshot": "claude-sonnet-5-20260927"}


def intake(empty=False):
    paths = [] if empty else ["configure.ac", "src/main.cpp", "src/runner.cpp"]
    return {"schema": "appsec-review/intake/1", "source_fingerprint": "2" * 64,
        "source_revision": "abc123", "business_goal": "Review hello-autotools",
        "platforms": ["Linux"], "budget": "standard", "execution_environment": {},
        "permissions": [], "scope": {"include": ["**"], "exclude": [], "excluded_paths": [],
            "unavailable": [], "all_paths": paths, "primary_selection_excludes_other_scope": False},
        "families": {"native": paths[1:] if paths else []}, "manifests": ["configure.ac"] if paths else [],
        "native": {"applicable": bool(paths)}, "selected_jobs": [], "ready_to_collect": True,
        "pregather_complete": False, "findings": [],
        "limitations": ["Intake is static and records no completed security verification."]}


def build_inputs(base: Path, *, empty=False):
    value = intake(empty)
    accepted = base / "intake-attempt"
    (accepted / "outputs").mkdir(parents=True)
    atomic_json(accepted / "outputs" / "intake.json", value)
    binding = {"job_id": "00-intake", "attempt_id": "intake-1",
        "pointer_path": str(base / "accepted.json"), "pointer_sha256": "sha256:" + "1" * 64,
        "artifact_path": "outputs/intake.json",
        "artifact_sha256": "sha256:" + lifecycle.file_hash(accepted / "outputs" / "intake.json"),
        "source_snapshot_sha256": "sha256:" + value["source_fingerprint"]}
    with mock.patch.object(lifecycle, "_load_intake",
            return_value=(value, binding, accepted, SOURCE, "2026-09-27T12:00:00Z")), \
            mock.patch.object(lifecycle.model_versions, "model_identity_for", return_value=MODEL):
        return lifecycle._current_inputs(RUN_ID)


def merged(inputs, *, producers=2):
    expected = lifecycle._expected_candidates(
        inputs["intake"], inputs["intake_binding"]["artifact_sha256"])
    candidates = []
    for raw in expected:
        row = {**raw, "worker_ids": [f"worker-{i}" for i in range(producers)],
               "producer_ids": [f"producer-{i}" for i in range(producers)]}
        row["semantic_sha256"] = lifecycle._sha({key: row[key] for key in
            ("subject_id", "assertion", "claim_class")})
        candidates.append(row)
    value = {"schema": "appsec-review/deterministic-pool-merge/1.0", "run_id": RUN_ID,
        "expected_worker_ids": ["worker-0", "worker-1"] if expected else [],
        "observed_worker_ids": ["worker-0", "worker-1"] if expected else [],
        "missing_worker_ids": [], "candidates": candidates, "conflicts": []}
    value["merge_sha256"] = lifecycle._sha(value)
    return value


class GraphPoolLifecycleTests(unittest.TestCase):
    def test_intake_control_generation_uses_staged_run_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            run = Path(folder)
            base = run / "data" / "jobs" / "00-intake" / "whole"
            attempt = base / "attempts" / "intake-1"
            (attempt / "outputs").mkdir(parents=True)
            atomic_json(attempt / "outputs" / "intake.json", intake())
            atomic_json(base / "accepted.json", {"retained": True})
            atomic_json(run / "inputs" / "artifact-manifest.json", {"run_id": RUN_ID})
            pointer = {"status":"OK", "run_id":RUN_ID, "attempt_id":"intake-1",
                       "published_at":"2026-09-27T12:00:00.123456+00:00"}
            with mock.patch.object(lifecycle.phase1, "accepted", return_value=pointer), \
                 mock.patch.object(lifecycle, "data_path",
                     side_effect=lambda _run,*parts:run.joinpath("data", *parts)), \
                 mock.patch.object(lifecycle, "run_path", return_value=run):
                _value, _binding, _attempt, generation, accepted_at = lifecycle._load_intake(RUN_ID)
            self.assertEqual(generation, "sha256:" + lifecycle.file_hash(
                run / "inputs" / "artifact-manifest.json"))
            self.assertEqual(accepted_at, "2026-09-27T12:00:00Z")

    def test_permission_timestamp_rejects_naive_time(self):
        with self.assertRaisesRegex(Blocked, "has no timezone"):
            lifecycle._permission_timestamp("2026-09-27T12:00:00")

    def test_c01_plan_has_two_distinct_persona_producers(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            inputs = build_inputs(base)
            attempt = base / "dispatch-attempt"
            attempt.mkdir()
            context, _rendezvous = lifecycle._materialize_context(inputs, attempt)
            plan = lifecycle.pool_specification.plan_expansion(inputs["spec"], context=context)
            self.assertEqual(len(plan.instances), 2)
            self.assertEqual(len({item.instance_id for item in plan.instances}), 2)
            personas = {item.request.request["persona"]["persona_id"] for item in plan.instances}
            self.assertEqual(personas, {"claim-reviewer", "reverse-engineer"})

    def _patch_runtime(self, base: Path, inputs: dict, merge: dict, *, outcome="COMPLETE"):
        box = {}

        def launch(spec, *, context, runtime):
            plan = lifecycle.pool_specification.expand_pool(spec, context=context)
            rendezvous_root = lifecycle.pool_rendezvous.rendezvous_root(plan, runtime.rendezvous_parent)
            rendezvous_root.mkdir(parents=True)
            atomic_json(rendezvous_root / lifecycle.pool_rendezvous.MANIFEST_FILE,
                        {"retained": "fixture", "outcome": outcome})
            box["verified"] = SimpleNamespace(manifest={"manifest_sha256": "sha256:" + "7" * 64,
                "outcome": outcome}, instances=[object(), object()] if outcome != "EMPTY" else [])
            return lifecycle.pool_launcher.LaunchedPool(pool_root=plan.pool_root(context),
                pool_directory=plan.pool_directory, expansion_sha256=plan.manifest["expansion_sha256"],
                terminal_manifest_sha256="sha256:" + "7" * 64, outcome=outcome,
                instance_count=len(box["verified"].instances))

        def load(*_args, **_kwargs):
            return box["verified"]

        return (mock.patch.object(lifecycle, "root", return_value=base),
                mock.patch.object(lifecycle, "_current_inputs", return_value=inputs),
                mock.patch.object(lifecycle.pool_launcher, "launch", side_effect=launch),
                mock.patch.object(lifecycle.pool_rendezvous, "load_verified_manifest", side_effect=load),
                mock.patch.object(lifecycle.deterministic_pool_merge,
                                  "merge_verified_manifest", return_value=merge))

    def test_success_reuse_and_external_control_request(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder).resolve()
            inputs = build_inputs(workspace)
            base = workspace / "dispatch"
            patches = self._patch_runtime(base, inputs, merged(inputs))
            with patches[0], patches[1], patches[2] as launch, patches[3], patches[4]:
                first = lifecycle.run(RUN_ID, "dagster-1")
                second = lifecycle.run(RUN_ID, "dagster-2")
            self.assertEqual(first["attempt_id"], second["attempt_id"])
            self.assertEqual(launch.call_count, 1)
            request = read_json(base / lifecycle.VIEW_REQUEST)
            context = read_json(base / lifecycle.VIEW_CONTEXT)
            self.assertEqual(set(request), {"schema", "run_id", "job_id", "source_generation",
                                            "generated_at", "payload"})
            self.assertEqual(request["job_id"], "deterministic-pool-merge")
            self.assertEqual(request["payload"]["context"], lifecycle._control_context(context))
            self.assertTrue(Path(request["payload"]["spec_path"]).is_file())
            rebuilt = control_lane_orchestration._pool_context(
                request["payload"]["context"], workspace, SOURCE)
            self.assertEqual(rebuilt.pool_parent, Path(context["pool_parent"]))

    def test_single_producer_candidate_fails_and_tombstones_external_view(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder).resolve()
            inputs = build_inputs(workspace)
            base = workspace / "dispatch"
            patches = self._patch_runtime(base, inputs, merged(inputs, producers=1))
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                with self.assertRaises(Blocked):
                    lifecycle.run(RUN_ID, "dagster-failed")
            self.assertEqual(read_json(base / "accepted.json")["status"], "FAILED")
            self.assertEqual(read_json(base / lifecycle.VIEW_REQUEST)["status"], "NONCURRENT")

    def test_empty_scope_retains_zero_instance_skip_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder).resolve()
            inputs = build_inputs(workspace, empty=True)
            base = workspace / "dispatch"
            patches = self._patch_runtime(base, inputs, merged(inputs), outcome="EMPTY")
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                pointer = lifecycle.run(RUN_ID, "dagster-empty")
            self.assertEqual(pointer["status"], "OK_WITH_GAPS")
            attempt = base / "attempts" / pointer["attempt_id"]
            self.assertEqual(read_json(attempt / "applicability.json")["decision"], "SKIPPED_NA")
            self.assertEqual(read_json(attempt / lifecycle.RESULT)["instance_count"], 0)

    def test_canonical_candidate_is_target_derived_and_requires_two_producers(self):
        value = intake()
        evidence = "sha256:" + "a" * 64
        candidates = lifecycle._expected_candidates(value, evidence)
        assertion = json.loads(candidates[0]["assertion"])
        self.assertEqual(assertion["scope_paths"], ["src/main.cpp", "src/runner.cpp"])
        self.assertNotIn("browser", candidates[0]["assertion"].lower())


class DeterministicInvokerTests(unittest.TestCase):
    """D4: the intake cell writes the canonical candidates itself; no model is called."""

    def package(self, data: bytes):
        sha = "sha256:" + lifecycle.persona_invocation._bytes_sha(data).split(":", 1)[-1]
        first = SimpleNamespace(root=lifecycle.ROOT_ID, path="outputs/intake.json", data=data, sha256=sha)
        contract = json.loads((ROOT / "pipeline/output-contracts/claim-review-pool-candidates.json").read_text())
        request = {"invoker_id": lifecycle.INVOKER_ID, "model": MODEL,
                   "persona": {"persona_id": "claim-reviewer", "persona_sha256": "sha256:" + "3" * 64}}
        return SimpleNamespace(inputs=(first,), composition={"output_contract": contract}, request=request,
                               request_sha256="sha256:" + "4" * 64, allowed_claim_classes=("candidate_only",),
                               prompt=b"pinned prompt, never sent")

    def test_writes_the_canonical_candidates_without_a_model(self):
        data = json.dumps(intake()).encode("utf-8")
        package = self.package(data)
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(lifecycle.cli, "ClaudeCliInvoker", side_effect=AssertionError("model called")):
            out = Path(folder)
            lifecycle.GraphReviewInvoker().invoke(package, output_root=out, cancel=SimpleNamespace(is_set=lambda: False))
            written = read_json(out / "candidates.json")
            manifest = read_json(out / lifecycle.persona_invocation.MANIFEST_FILE)
        self.assertEqual(written["candidates"], lifecycle._expected_candidates(intake(), package.inputs[0].sha256))
        self.assertEqual((manifest["invoker_id"], manifest["usage"]["input_units"], manifest["usage"]["output_units"]),
                         (lifecycle.INVOKER_ID, 0, 0))
        self.assertEqual([claim["claim_id"] for claim in manifest["claims"]], ["review_accepted_scope"])
        self.assertTrue(any("No model was called" in line for line in manifest["limitations"]))
        # persona_invocation re-derives input_bytes as prompt + inputs and refuses any other count.
        self.assertEqual(manifest["usage"]["input_bytes"], len(package.prompt) + len(data))
        self.assertEqual(lifecycle.persona_invocation.validate_document(
            manifest, lifecycle.persona_invocation.OUTPUT_SCHEMA), [])

    def test_the_real_pool_publishes_two_identical_candidates(self):
        # No launch, rendezvous or merge patch: the pool and persona_invocation's output checks run for real.
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder).resolve()
            inputs = build_inputs(workspace)
            base = workspace / "dispatch"
            with mock.patch.object(lifecycle, "root", return_value=base), \
                    mock.patch.object(lifecycle, "_current_inputs", return_value=inputs):
                pointer = lifecycle.run(RUN_ID, "dagster-real")
            self.assertEqual(pointer["status"], "OK")
            written = sorted(base.glob("attempts/*/pool-context/pools/*/instances/*/outputs/persona/candidates.json"))
            self.assertEqual(len(written), 2)
            self.assertEqual(read_json(written[0]), read_json(written[1]))

    def test_the_pool_requests_name_the_deterministic_invoker(self):
        with tempfile.TemporaryDirectory() as folder:
            inputs = build_inputs(Path(folder).resolve())
        invokers = {group["persona_request"]["invoker_id"] for group in inputs["spec"]["worker_groups"]}
        self.assertEqual(invokers, {lifecycle.INVOKER_ID})


if __name__ == "__main__":
    unittest.main()
