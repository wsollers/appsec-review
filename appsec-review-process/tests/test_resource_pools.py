"""Resource pools (B15): declaration invariants, derivation, outer limits, source and doc ties.

Pure tests: they need no Dagster and run on the host. The instance and contention tests are in
test_resource_pools_dagster.py and run in the code-server.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import resource_pools as rp  # noqa: E402
import validate_design_parity as parity  # noqa: E402
from schema_validate import SCHEMAS_DIR  # noqa: E402

ORCHESTRATION = Path(os.environ.get("APPSEC_ORCHESTRATOR_ROOT", ROOT.parent / "orchestrator" / "dagster"))
WORKFLOW_SOURCE = ROOT / "dagster_workflow.py"
DEFINITIONS_SOURCE = ORCHESTRATION / "definitions.py"
DAGSTER_YAML = ORCHESTRATION / "dagster.yaml"
DOC = ROOT.parent / "docs" / "resource-pools.md"
SUPPORTED_KEYWORDS = {"$schema", "$id", "title", "description", "type", "required", "properties",
                      "additionalProperties", "enum", "const", "pattern", "items", "minItems", "$ref"}
# The executor caps as they were before B15. Pools may not be an excuse to change one.
EXECUTOR_CAPS = {"engagement_workflow": "plan", "build_discovery": 3, "build_execution": 2, "evidence_index": 2,
                 "critical_findings_sarif": 1, "ossf_scorecard": 1, "repository_partition_discovery": 1,
                 "full_review": 3}


def _decorator_calls(path: Path, name: str):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(target, ast.Name) and target.id == name:
                    yield node, decorator


class Declaration(unittest.TestCase):
    def test_constants_are_consistent(self):
        self.assertEqual(rp.constant_errors(), [])

    def test_the_six_pools_and_the_unassigned_state(self):
        self.assertEqual(set(rp.POOL_IDS), {"cpu", "memory", "docker", "network", "persona_llm",
                                            "dynamic_analysis"})
        self.assertEqual(rp.UNASSIGNED, "unassigned")
        self.assertNotIn(rp.UNASSIGNED, rp.POOL_IDS)
        for pool_id in rp.POOL_IDS:
            self.assertRegex(pool_id, r"^\S+\Z")  # Dagster's own pool-name rule

    def test_no_limit_is_looser_than_what_the_outer_limits_already_permit(self):
        self.assertEqual(rp.AGGREGATE_STEP_CEILING, 6)
        for pool in rp.POOLS:
            self.assertGreaterEqual(pool.limit, 1, pool.pool_id)
            self.assertLessEqual(pool.limit, rp.EXECUTOR_STEP_CEILING, pool.pool_id)
            self.assertLess(pool.limit, rp.AGGREGATE_STEP_CEILING, pool.pool_id)
            self.assertTrue(pool.justification.strip(), pool.pool_id)
        self.assertLessEqual(rp.DEFAULT_POOL_LIMIT, min(rp.LIMITS.values()))

    def test_inconsistent_constants_are_reported_and_block_apply(self):
        broken = rp.POOLS[:-1] + (rp.Pool(rp.DYNAMIC_ANALYSIS, 7, "w", "j"),)
        with mock.patch.object(rp, "POOLS", broken):
            self.assertTrue(any("dynamic_analysis" in error for error in rp.constant_errors()))
            with self.assertRaises(rp.PoolStateError):
                rp.apply_limits(object())
        with mock.patch.dict(rp.PERSONA_BUDGET_CELLS, {"deep": 4}):
            self.assertTrue(any("budget class" in error for error in rp.constant_errors()))
        with mock.patch.object(rp, "PRECEDENCE", rp.PRECEDENCE[:-1]):
            self.assertTrue(any("precedence" in error for error in rp.constant_errors()))


class Derivation(unittest.TestCase):
    def test_worker_kinds(self):
        self.assertEqual(rp.derive_pool("pinned_container", [], memory_heavy=False), rp.DOCKER)
        self.assertEqual(rp.derive_pool("persona", [], memory_heavy=False), rp.PERSONA_LLM)
        self.assertEqual(rp.derive_pool("deterministic_python", [], memory_heavy=False), rp.CPU)
        self.assertEqual(rp.derive_pool("deterministic_python", [], memory_heavy=True), rp.MEMORY)
        self.assertEqual(rp.derive_pool("supplied_human_decision", (), memory_heavy=False), rp.CPU)

    def test_every_adapter_kind_is_covered(self):
        import worker_adapters
        kinds = {value.kind for value in vars(worker_adapters).values()
                 if isinstance(value, type) and isinstance(getattr(value, "kind", None), str)}
        self.assertEqual(kinds, set(rp.WORKER_KIND_POOLS))

    def test_follow_up_8_permission_kinds(self):
        for kind, pool in [("fixed-network-destination", rp.NETWORK), ("package-restore", rp.NETWORK),
                           ("dynamic-testing", rp.DYNAMIC_ANALYSIS), ("debugger-ptrace", rp.DYNAMIC_ANALYSIS),
                           ("target-execution", rp.DOCKER)]:
            self.assertEqual(rp.derive_pool("deterministic_python", [kind], memory_heavy=False), pool, kind)
        for kind in ("credential-use", "target-mutation"):
            self.assertEqual(rp.derive_pool("deterministic_python", [kind], memory_heavy=False), rp.CPU, kind)

    def test_every_registered_permission_kind_has_a_decision(self):
        registered = {path.stem for path in (ROOT / "registry" / "permission-capabilities").glob("*.json")}
        self.assertTrue(registered)
        self.assertEqual(registered, set(rp.PERMISSION_KIND_POOLS))

    def test_conflicts_resolve_by_the_fixed_precedence(self):
        self.assertEqual(rp.PRECEDENCE, (rp.DYNAMIC_ANALYSIS, rp.DOCKER, rp.PERSONA_LLM, rp.NETWORK,
                                         rp.MEMORY, rp.CPU))
        every = list(rp.PERMISSION_KIND_POOLS)
        for worker_kind in rp.WORKER_KIND_POOLS:
            self.assertEqual(rp.derive_pool(worker_kind, every, memory_heavy=True), rp.DYNAMIC_ANALYSIS)
        self.assertEqual(rp.derive_pool("persona", ["fixed-network-destination"], memory_heavy=False),
                         rp.PERSONA_LLM)
        self.assertEqual(rp.derive_pool("persona", ["target-execution"], memory_heavy=False), rp.DOCKER)
        self.assertEqual(rp.derive_pool("pinned_container", ["package-restore"], memory_heavy=True), rp.DOCKER)
        self.assertEqual(rp.derive_pool("deterministic_python", ["package-restore"], memory_heavy=True),
                         rp.NETWORK)
        # Order and repetition of the grants never matter.
        self.assertEqual(rp.derive_pool("deterministic_python", ["target-execution", "debugger-ptrace"],
                                        memory_heavy=False),
                         rp.derive_pool("deterministic_python", {"debugger-ptrace", "target-execution"},
                                        memory_heavy=False))

    def test_derivation_is_total_over_the_vocabulary_and_never_unassigned(self):
        for worker_kind in rp.WORKER_KIND_POOLS:
            for kind in rp.PERMISSION_KIND_POOLS:
                for heavy in (False, True):
                    self.assertIn(rp.derive_pool(worker_kind, [kind], memory_heavy=heavy), rp.POOL_IDS)

    def test_unknown_or_malformed_input_fails_closed(self):
        bad_calls = [
            lambda: rp.derive_pool("pool_coordinator", [], memory_heavy=False),
            lambda: rp.derive_pool("", [], memory_heavy=False),
            lambda: rp.derive_pool(None, [], memory_heavy=False),
            lambda: rp.derive_pool("persona", ["network"], memory_heavy=False),
            lambda: rp.derive_pool("persona", ["network:api.scorecard.dev"], memory_heavy=False),
            lambda: rp.derive_pool("persona", [None], memory_heavy=False),
            lambda: rp.derive_pool("persona", "target-execution", memory_heavy=False),
            lambda: rp.derive_pool("persona", {"target-execution": True}, memory_heavy=False),
            lambda: rp.derive_pool("persona", None, memory_heavy=False),
            lambda: rp.derive_pool("persona", [], memory_heavy=None),
            lambda: rp.derive_pool("persona", [], memory_heavy=1),
        ]
        for call in bad_calls:
            with self.assertRaises(rp.PoolAssignmentError):
                call()
        with self.assertRaises(TypeError):  # no optional safety input
            rp.derive_pool("persona", [])
        with self.assertRaises(TypeError):
            rp.derive_pool("persona")

    def test_budget_classes_fit_the_persona_pool_without_raising_it(self):
        self.assertEqual({name: rp.persona_slot_request(name) for name in ("probe", "standard", "deep")},
                         {"probe": 1, "standard": 2, "deep": 3})
        self.assertLessEqual(max(rp.PERSONA_BUDGET_CELLS.values()), rp.LIMITS[rp.PERSONA_LLM])
        for bad in ("", "DEEP", "full", None, 3):
            with self.assertRaises(rp.PoolAssignmentError):
                rp.persona_slot_request(bad)
        with mock.patch.dict(rp.LIMITS, {rp.PERSONA_LLM: 2}):
            self.assertEqual(rp.persona_slot_request("standard"), 2)
            with self.assertRaises(rp.PoolAssignmentError):
                rp.persona_slot_request("deep")

    def test_unassigned_is_a_recorded_value_with_a_closed_reason(self):
        self.assertEqual(rp.unassigned("coordination_only"),
                         {rp.TAG_POOL: "unassigned", rp.TAG_REASON: "coordination_only"})
        for bad in ("", "because", None, "cpu"):
            with self.assertRaises(rp.PoolAssignmentError):
                rp.unassigned(bad)
        with self.assertRaises(TypeError):
            rp.unassigned()


class OuterLimits(unittest.TestCase):
    """Pools only ever add constraints: every limit that existed before B15 is still there."""

    def setUp(self):
        self.yaml = DAGSTER_YAML.read_text(encoding="utf-8")

    def test_run_queue_limits_are_unchanged(self):
        self.assertEqual(re.findall(r"max_concurrent_runs:\s*(-?\d+)", self.yaml), ["2"])
        self.assertRegex(self.yaml, r"- key: engagement_run_id\n\s+value:\n\s+applyLimitPerUniqueValue: true\n"
                                    r"\s+limit: 1\n\s+- key: nvd_feed_id\n\s+limit: 1\n")
        self.assertEqual(re.findall(r"^\s+limit:\s*(\d+)", self.yaml, re.M), ["1", "1"])
        self.assertIn("class: QueuedRunCoordinator", self.yaml)
        self.assertEqual(rp.OUTER_LIMITS, {"max_concurrent_runs": 2, "per_engagement_limit": 1,
                                           "nvd_feed_limit": 1})

    def test_yaml_holds_only_the_floor_and_the_slot_release_setting(self):
        self.assertEqual(re.findall(r"^concurrency:\n  default_op_concurrency_limit: (\d+)\n", self.yaml, re.M),
                         [str(rp.DEFAULT_POOL_LIMIT)])
        self.assertEqual(re.findall(r"^  free_slots_after_run_end_seconds: (\d+)$", self.yaml, re.M),
                         [str(rp.FREE_SLOTS_AFTER_RUN_END_SECONDS)])
        # `concurrency.pools` / `concurrency.runs` would make Dagster reject the run_coordinator limits.
        self.assertNotRegex(self.yaml, r"^\s+(pools|runs):", )
        for pool_id in rp.POOL_IDS:
            self.assertNotRegex(self.yaml, rf"\b{pool_id}\b")

    def test_executor_caps_are_unchanged(self):
        import workflow
        tree = ast.parse(WORKFLOW_SOURCE.read_text(encoding="utf-8"))
        found = {}
        for node, decorator in _decorator_calls(WORKFLOW_SOURCE, "job"):
            executor = next(k.value for k in decorator.keywords if k.arg == "executor_def")
            cap = executor.args[0].values[executor.args[0].keys.index(
                next(k for k in executor.args[0].keys if k.value == "max_concurrent"))]
            found[node.name] = cap.value if isinstance(cap, ast.Constant) else "plan"
        self.assertEqual(found, EXECUTOR_CAPS)
        self.assertEqual(workflow.plan()["max_concurrent_steps"], 3)
        self.assertEqual(max([3, *[v for v in found.values() if isinstance(v, int)]]), rp.EXECUTOR_STEP_CEILING)
        self.assertIsNotNone(tree)


class SourceTies(unittest.TestCase):
    def test_every_op_names_a_pool_or_records_unassigned(self):
        seen = 0
        for path in (WORKFLOW_SOURCE, DEFINITIONS_SOURCE):
            for node, decorator in _decorator_calls(path, "op"):
                seen += 1
                keywords = {k.arg for k in decorator.keywords} if isinstance(decorator, ast.Call) else set()
                self.assertEqual(len(keywords & {"pool", "tags"}), 1, f"{path.name}:{node.name}")
        self.assertGreaterEqual(seen, 24)

    def test_no_pool_id_or_limit_is_a_local_constant(self):
        for path in (WORKFLOW_SOURCE, DEFINITIONS_SOURCE):
            for node, decorator in _decorator_calls(path, "op"):
                if not isinstance(decorator, ast.Call):
                    continue
                for keyword in decorator.keywords:
                    if keyword.arg in ("pool", "tags"):
                        literals = [item.value for item in ast.walk(keyword.value)
                                    if isinstance(item, ast.Constant) and isinstance(item.value, str)]
                        self.assertFalse(set(literals) & (set(rp.POOL_IDS) | {rp.UNASSIGNED, rp.TAG_POOL}),
                                         f"{path.name}:{node.name}")
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("set_concurrency_slots", text)
            self.assertNotIn("dagster/concurrency_key", text)

    def test_the_load_time_check_and_the_guard_sensor_are_registered(self):
        text = DEFINITIONS_SOURCE.read_text(encoding="utf-8")
        self.assertIn("resource_pools.build_guard_sensor()", text)
        self.assertRegex(text, r"(?m)^resource_pools\.require_explicit_assignments\(defs\)$")

    def test_parity_validator_accepts_the_declared_vocabulary_and_no_other(self):
        manifest = parity.read_json(parity.MANIFEST)
        values = {record["resource_pool"] for record in manifest["jobs"] + manifest["capabilities"]}
        self.assertLessEqual(values, set(rp.POOL_IDS) | {rp.UNASSIGNED})

        def pool_errors(pools):
            candidate = deepcopy(manifest)
            candidate["dagster_inventory"]["resource_pools"] = pools
            return [error for error in parity.validate_manifest(candidate)["errors"] if "pool" in error.lower()]

        self.assertEqual(pool_errors(list(rp.POOL_IDS)), [])
        for wrong in (["cpu"], list(rp.POOL_IDS) + ["gpu"], list(rp.POOL_IDS) + ["cpu"],
                      [rp.UNASSIGNED, *rp.POOL_IDS[1:]]):
            self.assertIn("manifest resource pools do not match resource_pools.POOL_IDS", pool_errors(wrong))
        candidate = deepcopy(manifest)
        candidate["dagster_inventory"]["resource_pools"] = list(rp.POOL_IDS)
        candidate["jobs"][0]["resource_pool"] = "gpu"
        self.assertTrue(any("unknown resource pool gpu" in error
                            for error in parity.validate_manifest(candidate)["errors"]))


class StateSchema(unittest.TestCase):
    def test_schema_is_closed_and_uses_only_the_supported_subset(self):
        schema = json.loads((SCHEMAS_DIR / rp.STATE_SCHEMA_FILE).read_text(encoding="utf-8"))

        def walk(node, path):
            if isinstance(node, dict) and ("type" in node or "properties" in node or "enum" in node
                                           or "const" in node or "pattern" in node):
                self.assertLessEqual(set(node), SUPPORTED_KEYWORDS, path)
                if "pattern" in node:
                    self.assertTrue(node["pattern"].startswith("^") and node["pattern"].endswith("\\Z"), path)
                if "properties" in node:
                    self.assertIs(node.get("additionalProperties"), False, path)
                    self.assertEqual(sorted(node["required"]), sorted(node["properties"]), path)
                    for key, value in node["properties"].items():
                        self.assertNotRegex(key, r"(?i)token|secret|authorization|password|credential", path)
                        walk(value, f"{path}.{key}")
                if "items" in node:
                    walk(node["items"], path + "[]")

        walk(schema, "$")
        self.assertEqual(schema["properties"]["schema"]["const"], rp.STATE_SCHEMA_ID)
        enum = schema["properties"]["pools"]["items"]["properties"]["pool_id"]["enum"]
        self.assertEqual(enum, list(rp.POOL_IDS))
        self.assertEqual(schema["properties"]["pools"]["minItems"], len(rp.POOL_IDS))
        reasons = schema["properties"]["assignments"]["properties"]["unassigned"]["items"]["properties"]["reason"]
        self.assertEqual(reasons["enum"], list(rp.UNASSIGNED_REASONS))

    def test_overlap_sweep(self):
        self.assertEqual(rp.max_overlap([]), 0)
        self.assertEqual(rp.max_overlap([(0, 1), (1, 2)]), 1)  # touching intervals do not overlap
        self.assertEqual(rp.max_overlap([(0, 2), (1, 3), (1.5, 1.6)]), 3)
        self.assertEqual(rp.max_overlap([(0, None), (5, 6)]), 2)  # an open step never releases


class Documentation(unittest.TestCase):
    def test_doc_table_is_the_declaration(self):
        text = DOC.read_text(encoding="utf-8")
        rows = re.findall(r"^\| `([a-z_]+)` \| (\d+) \| [^|]+ \| [^|]+ \|$", text, re.M)
        self.assertEqual(rows, [(pool.pool_id, str(pool.limit)) for pool in rp.POOLS])
        for pool in rp.POOLS:
            self.assertIn(pool.justification, " ".join(text.split()), pool.pool_id)
        budget = re.findall(r"^\| `(probe|standard|deep)` \| (\d+) \|", text, re.M)
        self.assertEqual(dict(budget), {name: str(cells) for name, cells in rp.PERSONA_BUDGET_CELLS.items()})
        self.assertIn(" > ".join(f"`{pool}`" for pool in rp.PRECEDENCE), text)
        for kind, pool in rp.PERMISSION_KIND_POOLS.items():
            self.assertRegex(text, rf"\| `{kind}` \| (`{pool}`|none) \|" if pool else rf"\| `{kind}` \| none \|")
        for reason in rp.UNASSIGNED_REASONS:
            self.assertIn(f"`{reason}`", text)
        self.assertIn(f"default_op_concurrency_limit: {rp.DEFAULT_POOL_LIMIT}", text)
        self.assertIn(f"free_slots_after_run_end_seconds: {rp.FREE_SLOTS_AFTER_RUN_END_SECONDS}", text)
        self.assertIn("load evidence", text.lower())


if __name__ == "__main__":
    unittest.main()
