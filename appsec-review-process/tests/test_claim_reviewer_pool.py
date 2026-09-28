import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import claim_lifecycle_core as core
import claim_reviewer_pool as reviewer_pool
import claim_review_lifecycle as lifecycle
from execution_state import Blocked, read_json
from schema_validate import validate_document

FIXTURES = ROOT / "tests/fixtures/claim-lifecycle"
RUN_ID = "claim-run"
SOURCE = "sha256:" + "2" * 64


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def binding(job="claim-ledger-routing", artifact="claim-decision-ledger.json"):
    return {"job_id": job, "attempt_id": job + "-1",
            "pointer_sha256": "sha256:" + "1" * 64,
            "artifact_path": artifact, "artifact_sha256": "sha256:" + "3" * 64}


def merge(stage="07-red-team-adversarial", decisions=None):
    decisions = copy.deepcopy(decisions if decisions is not None else fixture("red-decisions.json")["decisions"])
    candidates = []
    for index, decision in enumerate(decisions):
        candidate = {"candidate_id": f"decision-{decision['claim_id']}",
            "subject_id": decision["claim_id"],
            "assertion": json.dumps(decision, sort_keys=True, separators=(",", ":")),
            "evidence_sha256": "sha256:" + "4" * 64,
            "claim_class": lifecycle.POOL_CLASSES[stage],
            "worker_ids": ["reviewer-1"], "producer_ids": ["claim-reviewer"]}
        candidate["semantic_sha256"] = lifecycle._sha({key: candidate[key] for key in
            ("subject_id", "assertion", "claim_class")})
        candidates.append(candidate)
    value = {"schema": "appsec-review/deterministic-pool-merge/1.0", "run_id": RUN_ID,
        "expected_worker_ids": ["reviewer-1"], "observed_worker_ids": ["reviewer-1"],
        "missing_worker_ids": [], "candidates": candidates, "conflicts": []}
    value["merge_sha256"] = lifecycle._sha(value)
    return value


def prepared(stage="07-red-team-adversarial", *, empty=False):
    upstream = fixture("claim-ledger.json")
    if empty:
        upstream = {"schema": "appsec-review/claim-ledger-input/0.1", "run_id": RUN_ID,
            "ledger_head_id": "empty", "ledger_head_sha256": "sha256:" + "d" * 64,
            "candidates": []}
    return {"run_id": RUN_ID, "stage": stage, "source_generation": SOURCE,
        "upstream": upstream, "upstream_binding": binding(),
        "upstream_attempt": "unused", "upstream_artifact": "claim-decision-ledger.json",
        "accepted_at": "2026-09-27T12:00:00Z",
        "spec": {"schema": "test-spec", "stage": stage, "empty": empty},
        "applicability": "SKIPPED_NA_NO_CANDIDATES" if empty else "APPLICABLE",
        "code": reviewer_pool._code_hashes()}


class ClaimReviewerPoolTests(unittest.TestCase):
    def test_prepare_derives_population_and_spec_only_from_accepted_upstream(self):
        upstream = fixture("claim-ledger.json")
        request = {name: {} for name in reviewer_pool.pool_specification.PERSONA_TEMPLATE_FIELDS}
        permission = {"permission": "fixture"}
        with mock.patch.object(reviewer_pool.lifecycle, "_load_upstream",
                return_value=(upstream, binding(), SOURCE)), \
                mock.patch.object(reviewer_pool, "_upstream_location",
                return_value=(Path("C:/accepted/attempt"), "claim-decision-ledger.json")), \
                mock.patch.object(reviewer_pool, "read_json",
                return_value={"accepted_at": "2026-09-27T12:00:00.123456+00:00"}), \
                mock.patch.object(reviewer_pool, "_request_template",
                return_value=(request, permission)):
            value = reviewer_pool.prepare(RUN_ID, "dagster", "07-red-team-adversarial")
        self.assertEqual(value["upstream"], upstream)
        self.assertEqual(value["spec"]["worker_groups"][0]["count"], 1)
        self.assertEqual(value["spec"]["worker_groups"][0]["persona_request"], request)
        self.assertNotIn("decisions", value)

    def test_real_prepared_spec_passes_c01_planning(self):
        upstream = fixture("claim-ledger.json")
        model = {"provider": "anthropic", "family": "claude-sonnet-5",
                 "model_id": "claude-sonnet-5-20260927", "snapshot": "claude-sonnet-5-20260927"}
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            accepted = base / "accepted-attempt"
            accepted.mkdir()
            artifact = accepted / "claim-decision-ledger.json"
            artifact.write_text(json.dumps(upstream), encoding="utf-8")
            with mock.patch.object(reviewer_pool.lifecycle, "_load_upstream",
                    return_value=(upstream, binding(), SOURCE)), \
                    mock.patch.object(reviewer_pool, "_upstream_location",
                    return_value=(accepted, artifact.name)), \
                    mock.patch.object(reviewer_pool, "read_json",
                    return_value={"accepted_at": "2026-09-27T12:00:00.123456+00:00"}), \
                    mock.patch.object(reviewer_pool.model_versions, "model_identity_for",
                    return_value=model):
                value = reviewer_pool.prepare(RUN_ID, "dagster", "07-red-team-adversarial")
            pool_parent = base / "pools"
            pool_parent.mkdir()
            menu = value["evidence_menu"]
            menu_root = reviewer_pool.evidence_menu.write(base / "evidence-menu", menu)
            roots = {reviewer_pool.ROOT_ID: accepted,
                     **reviewer_pool.evidence_menu.readable_roots(RUN_ID, menu, menu_root)}
            context = reviewer_pool.pool_specification.PoolContext(pool_parent=pool_parent,
                registry_dir=reviewer_pool.persona_invocation.REGISTRY_DIR,
                prompt_root=ROOT, readable_roots=roots,
                allowed_models=(model,), invoker_id="claude-cli",
                images_dir=reviewer_pool.container_execution.IMAGES_DIR,
                host_flavor="windows" if sys.platform == "win32" else "posix",
                docker_host=None, docker_executable=None, container_user=None, mount_roots={},
                source_snapshot_sha256=SOURCE, registry_ceiling=None)
            plan = reviewer_pool.pool_specification.plan_expansion(value["spec"], context=context)
            self.assertEqual(len(plan.instances), 1)
            readable = plan.instances[0].request.request["readable_inputs"]
            self.assertEqual(readable[0]["path"], artifact.name)
            self.assertEqual((readable[1]["root"], readable[1]["path"]),
                             (reviewer_pool.evidence_menu.MENU_ROOT_ID, reviewer_pool.evidence_menu.MENU_FILE))

    def test_prepared_spec_pins_supporting_evidence_the_persona_may_read(self):
        from tests.test_supporting_evidence_menu import publish
        import execution_state
        upstream = fixture("claim-ledger.json")
        model = {"provider": "anthropic", "family": "claude-sonnet-5",
                 "model_id": "claude-sonnet-5-20260927", "snapshot": "claude-sonnet-5-20260927"}
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            publish(base / RUN_ID / "data" / "jobs", "02-ir-facts",
                    {"ir-facts.json": b'{"facts": [], "debug_locations": []}'}, run=RUN_ID)
            accepted = base / "accepted-attempt"
            accepted.mkdir()
            artifact = accepted / "claim-decision-ledger.json"
            artifact.write_text(json.dumps(upstream), encoding="utf-8")
            with mock.patch.object(execution_state, "RUNS", base), \
                    mock.patch.object(reviewer_pool.lifecycle, "_load_upstream",
                    return_value=(upstream, binding(), SOURCE)), \
                    mock.patch.object(reviewer_pool, "_upstream_location",
                    return_value=(accepted, artifact.name)), \
                    mock.patch.object(reviewer_pool, "read_json",
                    return_value={"accepted_at": "2026-09-27T12:00:00.123456+00:00"}), \
                    mock.patch.object(reviewer_pool.model_versions, "model_identity_for",
                    return_value=model):
                value = reviewer_pool.prepare(RUN_ID, "dagster", "07-red-team-adversarial")
                pool_parent = base / "pools"
                pool_parent.mkdir()
                menu_root = reviewer_pool.evidence_menu.write(base / "evidence-menu", value["evidence_menu"])
                roots = {reviewer_pool.ROOT_ID: accepted,
                         **reviewer_pool.evidence_menu.readable_roots(RUN_ID, value["evidence_menu"], menu_root)}
                context = reviewer_pool.pool_specification.PoolContext(pool_parent=pool_parent,
                    registry_dir=reviewer_pool.persona_invocation.REGISTRY_DIR,
                    prompt_root=ROOT, readable_roots=roots,
                    allowed_models=(model,), invoker_id="claude-cli",
                    images_dir=reviewer_pool.container_execution.IMAGES_DIR,
                    host_flavor="windows" if sys.platform == "win32" else "posix",
                    docker_host=None, docker_executable=None, container_user=None, mount_roots={},
                    source_snapshot_sha256=SOURCE, registry_ceiling=None)
                plan = reviewer_pool.pool_specification.plan_expansion(value["spec"], context=context)
            readable = plan.instances[0].request.request["readable_inputs"]
            self.assertEqual([row["root"] for row in readable],
                             [reviewer_pool.ROOT_ID, "evidence-menu", "supporting-evidence"])
            self.assertEqual(readable[2]["path"], "02-ir-facts/attempts/a1/ir-facts.json")
            self.assertIn("supporting_evidence_menu.py", value["code"])

    def _runtime_patches(self, base, value, result):
        launched = reviewer_pool.pool_launcher.LaunchedPool(
            pool_root=base / "unused", pool_directory="pool-1",
            expansion_sha256="sha256:" + "6" * 64,
            terminal_manifest_sha256="sha256:" + "7" * 64,
            outcome="EMPTY" if value["applicability"].startswith("SKIPPED") else "COMPLETE",
            instance_count=0 if value["applicability"].startswith("SKIPPED") else 1)

        def context(_inputs, attempt):
            (attempt / "pools").mkdir()
            (attempt / "rendezvous").mkdir()
            return SimpleNamespace(pool_parent=attempt / "pools")

        return (mock.patch.object(reviewer_pool, "root", return_value=base),
                mock.patch.object(reviewer_pool, "prepare", return_value=value),
                mock.patch.object(reviewer_pool, "_context", side_effect=context),
                mock.patch.object(reviewer_pool.pool_launcher, "launch", return_value=launched),
                mock.patch.object(reviewer_pool.pool_rendezvous, "load_verified_manifest",
                                  return_value=object()),
                mock.patch.object(reviewer_pool.deterministic_pool_merge,
                                  "merge_verified_manifest", return_value=result))

    def test_success_publishes_stage_scoped_merge_and_reuses_it(self):
        value, result = prepared(), merge()
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / "deterministic-pool-merge" / "07-red-team-adversarial"
            patches = self._runtime_patches(base, value, result)
            with patches[0], patches[1], patches[2], patches[3] as launch, patches[4], patches[5]:
                first = reviewer_pool.run(RUN_ID, "dagster-1", value["stage"])
                second = reviewer_pool.run(RUN_ID, "dagster-2", value["stage"])
            self.assertEqual(first["attempt_id"], second["attempt_id"])
            self.assertEqual(launch.call_count, 1)
            attempt = base / "attempts" / first["attempt_id"]
            self.assertEqual(read_json(attempt / reviewer_pool.RESULT), result)
            self.assertEqual(read_json(attempt / "pool-receipt.json")["decision"], "APPLICABLE")

    def test_empty_population_publishes_accepted_skip_receipt(self):
        value = prepared(empty=True)
        result = merge(decisions=[])
        result["expected_worker_ids"] = []
        result["observed_worker_ids"] = []
        result["merge_sha256"] = lifecycle._sha({key: item for key, item in result.items()
                                                  if key != "merge_sha256"})
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / "merge" / value["stage"]
            patches = self._runtime_patches(base, value, result)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                pointer = reviewer_pool.run(RUN_ID, "dagster-empty", value["stage"])
            self.assertEqual(pointer["status"], "OK_WITH_GAPS")
            receipt = read_json(base / "attempts" / pointer["attempt_id"] / "pool-receipt.json")
            self.assertEqual(receipt["decision"], "SKIPPED_NA")
            self.assertEqual(receipt["instance_count"], 0)

    def test_incomplete_decision_population_fails_and_new_attempt_recovers(self):
        value = prepared()
        bad = merge(decisions=fixture("red-decisions.json")["decisions"][:1])
        good = merge()
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / "merge" / value["stage"]
            patches = self._runtime_patches(base, value, bad)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                with self.assertRaises(Blocked):
                    reviewer_pool.run(RUN_ID, "dagster-failed", value["stage"])
            failed = read_json(base / "accepted.json")
            self.assertEqual(failed["status"], "FAILED")
            patches = self._runtime_patches(base, value, good)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                recovered = reviewer_pool.run(RUN_ID, "dagster-recovered", value["stage"])
            self.assertEqual(recovered["status"], "OK")
            self.assertNotEqual(recovered["attempt_id"], failed["attempt_id"])

    def test_runtime_identity_and_registry_contracts_are_closed(self):
        package = SimpleNamespace(request={"job_id": "09-independent-verification",
            "attempt_id": "persona-attempt"}, request_sha256="sha256:" + "a" * 64,
            inputs=(SimpleNamespace(sha256="sha256:" + "b" * 64),))
        instructions = reviewer_pool._runtime_instructions(package)
        self.assertIn("independent-verifier", instructions)
        self.assertIn("never emit VERIFIED", instructions)
        # identity, hashes and the candidate wrapper are derived (claim_review_derive), not copied
        self.assertNotIn("persona-attempt", instructions)
        self.assertNotIn("sha256:" + "a" * 64, instructions)
        self.assertIn(reviewer_pool.derive.PERSONA_SCHEMA, instructions)
        for path, schema in ((ROOT / "registry/job-templates/claim-review-pool-cell.json",
                              "job-template.schema.json"),
                             (ROOT / "registry/output-contracts/claim-review-pool-candidates.json",
                              "output-contract.schema.json")):
            self.assertEqual(validate_document(json.loads(path.read_text()), schema), [])


if __name__ == "__main__":
    unittest.main()
