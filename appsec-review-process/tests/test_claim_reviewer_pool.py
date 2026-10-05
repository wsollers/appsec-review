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
import registry_paths

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
        "spec": {"schema": "test-spec", "stage": stage, "empty": empty,
                 "rendezvous_timeout_seconds": 2400},
        "shards": [],
        "applicability": "SKIPPED_NA_NO_CANDIDATES" if empty else "APPLICABLE",
        "code": reviewer_pool._code_hashes()}


class ClaimReviewerPoolTests(unittest.TestCase):
    def test_prepare_derives_population_and_spec_only_from_accepted_upstream(self):
        upstream = fixture("claim-ledger.json")
        request = {name: {} for name in reviewer_pool.pool_specification.PERSONA_TEMPLATE_FIELDS}
        request["budget"] = {"input_unit_limit": 800_000, "output_unit_limit": 200_000,
                             "timeout_seconds": 1800}
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
        # the two fixture claims are causally linked, so they form one shard and one instance
        self.assertEqual([shard["claim_ids"] for shard in value["shards"]],
                         [sorted(item["claim_id"] for item in upstream["candidates"])])
        self.assertEqual(value["spec"]["worker_groups"][0]["count"], 1)
        self.assertEqual(value["spec"]["worker_groups"][0]["group_id"], "reviewer-00")
        self.assertEqual(value["spec"]["worker_groups"][0]["persona_request"], request)
        self.assertEqual(value["spec"]["pool_budget"]["max_instances"], 1)
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
            attempt = base / "attempt"
            attempt.mkdir()
            context = reviewer_pool._context(value, attempt)
            plan = reviewer_pool.pool_specification.plan_expansion(value["spec"], context=context)
            self.assertEqual(len(plan.instances), 1)
            request = plan.instances[0].request.request
            readable = request["readable_inputs"]
            self.assertEqual(readable[0]["path"], "shard-00.json")
            self.assertEqual(request["persona"]["persona_id"], value["shards"][0]["persona_id"])
            self.assertIn(request["persona"]["persona_id"],
                          reviewer_pool._stage_personas()["07-red-team-adversarial"])
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
                attempt = base / "attempt"
                attempt.mkdir()
                context = reviewer_pool._context(value, attempt)
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

    def _sharded(self):
        """The fixture ledger without its causal link: two independent claims, two shards."""
        upstream = fixture("claim-ledger.json")
        for record in upstream["candidates"]:
            record["causal_claim_ids"] = []
        value = prepared()
        value["upstream"] = upstream
        value["shards"] = reviewer_pool.plan("07-red-team-adversarial", upstream)
        value["spec"]["worker_groups"] = [{"group_id": shard["group_id"]} for shard in value["shards"]]
        return value

    def _merge_from(self, value, shards):
        """A real deterministic merge where only the named shards' instances returned decisions."""
        from review_control_loops import deterministic_merge
        digest = reviewer_pool.pool_specification.spec_sha256(value["spec"])
        decisions = {item["claim_id"]: item for item in fixture("red-decisions.json")["decisions"]}
        expected, results = [], []
        for shard in value["shards"]:
            worker = reviewer_pool.pool_specification.instance_id(digest, shard["group_id"], 0)
            expected.append({"worker_id": worker, "producer_id": shard["persona_id"], "run_id": RUN_ID})
            if shard["group_id"] not in shards:
                results.append({"worker_id": worker, "producer_id": shard["persona_id"], "run_id": RUN_ID,
                                "status": "FAILED", "candidates": []})
                continue
            rows = [{"candidate_id": f"decision-{claim_id}", "subject_id": claim_id,
                     "assertion": json.dumps(decisions[claim_id], sort_keys=True, separators=(",", ":")),
                     "evidence_sha256": shard["sha256"], "claim_class": "candidate_only"}
                    for claim_id in shard["claim_ids"]]
            results.append({"worker_id": worker, "producer_id": shard["persona_id"], "run_id": RUN_ID,
                            "status": "OK", "candidates": rows})
        return deterministic_merge(RUN_ID, expected, results)

    def test_claims_are_sharded_across_instances_with_distinct_personas(self):
        value = self._sharded()
        self.assertEqual(len(value["shards"]), 2)
        self.assertEqual(sorted(i for shard in value["shards"] for i in shard["claim_ids"]),
                         sorted(item["claim_id"] for item in value["upstream"]["candidates"]))
        personas = [shard["persona_id"] for shard in value["shards"]]
        self.assertEqual(len(set(personas)), 2)
        self.assertEqual(reviewer_pool.plan("07-red-team-adversarial", value["upstream"]), value["shards"])
        shard = json.loads(reviewer_pool._shard_bytes("07-red-team-adversarial", value["upstream"],
                                                      value["shards"][0]["claim_ids"]))
        self.assertEqual([r["claim_id"] for r in shard["candidates"]], value["shards"][0]["claim_ids"])

    def test_sharded_spec_passes_c01_planning_one_persona_per_instance(self):
        upstream = fixture("claim-ledger.json")
        for record in upstream["candidates"]:
            record["causal_claim_ids"] = []
        model = {"provider": "anthropic", "family": "claude-sonnet-5",
                 "model_id": "claude-sonnet-5-20260927", "snapshot": "claude-sonnet-5-20260927"}
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            accepted = base / "accepted-attempt"
            accepted.mkdir()
            (accepted / "claim-decision-ledger.json").write_text(json.dumps(upstream), encoding="utf-8")
            with mock.patch.object(reviewer_pool.lifecycle, "_load_upstream",
                    return_value=(upstream, binding(), SOURCE)), \
                    mock.patch.object(reviewer_pool, "_upstream_location",
                    return_value=(accepted, "claim-decision-ledger.json")), \
                    mock.patch.object(reviewer_pool, "read_json",
                    return_value={"accepted_at": "2026-09-27T12:00:00.123456+00:00"}), \
                    mock.patch.object(reviewer_pool.model_versions, "model_identity_for",
                    return_value=model):
                value = reviewer_pool.prepare(RUN_ID, "dagster", "07-red-team-adversarial")
            attempt = base / "attempt"
            attempt.mkdir()
            plan = reviewer_pool.pool_specification.plan_expansion(
                value["spec"], context=reviewer_pool._context(value, attempt))
            self.assertEqual(len(plan.instances), 2)
            self.assertEqual(value["spec"]["pool_budget"]["max_instances"], 2)
            requests = [item.request.request for item in plan.instances]
            self.assertEqual(sorted(r["readable_inputs"][0]["path"] for r in requests),
                             ["shard-00.json", "shard-01.json"])
            self.assertEqual(len({r["persona"]["persona_id"] for r in requests}), 2)
            self.assertEqual(len({r["outer_prompt"]["sha256"] for r in requests}), 2)
            # Every 07 reviewer runs as the stage's registry role, whose ceiling is the stage class.
            self.assertEqual({r["persona"]["role_id"] for r in requests}, {"red-team-adversary"})
            self.assertEqual({tuple(r["allowed_claim_classes"]) for r in requests}, {("candidate_only",)})

    def test_sharded_merge_publishes_with_full_coverage(self):
        value = self._sharded()
        result = self._merge_from(value, {shard["group_id"] for shard in value["shards"]})
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / "merge" / value["stage"]
            patches = self._runtime_patches(base, value, result)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                pointer = reviewer_pool.run(RUN_ID, "dagster-sharded", value["stage"])
            self.assertEqual(pointer["status"], "OK")
            coverage = read_json(base / "attempts" / pointer["attempt_id"] / reviewer_pool.COVERAGE)
            self.assertEqual(coverage["unreviewed_claim_ids"], [])
            self.assertEqual([row["persona_id"] for row in coverage["shards"]],
                             [shard["persona_id"] for shard in value["shards"]])

    def test_one_failed_instance_records_its_claims_as_unreviewed_gaps(self):
        value = self._sharded()
        failed = value["shards"][1]
        result = self._merge_from(value, {value["shards"][0]["group_id"]})
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / "merge" / value["stage"]
            patches = self._runtime_patches(base, value, result)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                with self.assertRaises(Blocked) as raised:
                    reviewer_pool.run(RUN_ID, "dagster-partial", value["stage"])
            self.assertIn("1 of 2 claims unreviewed", str(raised.exception))
            self.assertIn(failed["group_id"], str(raised.exception))
            pointer = read_json(base / "accepted.json")
            self.assertEqual(pointer["status"], "FAILED")
            coverage = read_json(base / "attempts" / pointer["attempt_id"] / reviewer_pool.COVERAGE)
            self.assertEqual(coverage["unreviewed_claim_ids"], failed["claim_ids"])
            self.assertEqual([row["unreviewed_claim_ids"] for row in coverage["shards"]],
                             [[], failed["claim_ids"]])

    def test_runtime_identity_and_registry_contracts_are_closed(self):
        package = SimpleNamespace(request={"job_id": "09-independent-verification",
            "attempt_id": "persona-attempt"}, request_sha256="sha256:" + "a" * 64,
            inputs=(SimpleNamespace(sha256="sha256:" + "b" * 64),))
        instructions = reviewer_pool._runtime_instructions(package)
        self.assertIn("independent-verifier", instructions)
        self.assertIn("VERIFIED needs every obligation SATISFIED", instructions)   # ADR-0035
        self.assertIn("An incomplete answer supports only UNRESOLVED", instructions)
        # identity, hashes and the candidate wrapper are derived (claim_review_derive), not copied
        self.assertNotIn("persona-attempt", instructions)
        self.assertNotIn("sha256:" + "a" * 64, instructions)
        self.assertIn(reviewer_pool.derive.PERSONA_SCHEMA, instructions)
        for path, schema in ((registry_paths.template("claim-review-pool-cell"),
                              "job-template.schema.json"),
                             (registry_paths.contract("claim-review-pool-candidates"),
                              "output-contract.schema.json")):
            self.assertEqual(validate_document(json.loads(path.read_text()), schema), [])


if __name__ == "__main__":
    unittest.main()
