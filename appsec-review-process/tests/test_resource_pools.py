"""Resource pools (B15): declaration invariants, derivation, outer limits, source and doc ties.

Pure tests: they need no Dagster and run on the host. The instance and contention tests are in
test_resource_pools_dagster.py and run in the code-server.
"""
from __future__ import annotations

import ast
import builtins
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import resource_pools as rp  # noqa: E402
import validate_design_parity as parity  # noqa: E402
from schema_validate import SCHEMAS_DIR, validate_document  # noqa: E402

ORCHESTRATION = Path(os.environ.get("APPSEC_ORCHESTRATOR_ROOT", ROOT.parent / "orchestrator" / "dagster"))
WORKFLOW_SOURCE = ROOT / "dagster_workflow.py"
DEFINITIONS_SOURCE = ORCHESTRATION / "definitions.py"
DAGSTER_YAML = ORCHESTRATION / "dagster.yaml"
REQUIREMENTS = ORCHESTRATION / "requirements.txt"
DOC = ROOT.parent / "docs" / "pools" / "resource-pools.md"
SUPPORTED_KEYWORDS = {"$schema", "$id", "title", "description", "type", "required", "properties",
                      "additionalProperties", "enum", "const", "pattern", "items", "minItems", "$ref"}
# The executor caps as they were before B15. Pools may not be an excuse to change one.
EXECUTOR_CAPS = {"engagement_workflow": "plan", "build_discovery": 3, "build_execution": 2, "evidence_index": 2,
                 "critical_findings_sarif": 1, "ossf_scorecard": 1, "repository_partition_discovery": 1, "dev_project_discovery": 1,
                 "full_review": 3}


def _decorator_calls(path: Path, name: str):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(target, ast.Name) and target.id == name:
                    yield node, decorator


def reseal(document):
    """What a forger with this module can do: re-derive every derived field, then re-hash."""
    document["pooled_steps_recorded"] = rp.pooled_steps_recorded(document["runs"])
    document["observed_overlap"] = rp.overlap_by_pool(document["runs"])
    document["errors"] = rp._state_errors(document)
    document["result"] = "FAIL" if document["errors"] else "PASS"
    document["state_sha256"] = rp._state_digest(document)
    return document


def state_fixture():
    """A pool-state document of the shape `build_state` writes, built without Dagster. The
    Dagster suite checks that a real `build_state` document has exactly this shape."""
    def run(number, engagement, steps):
        return {"dagster_run_id": f"{number:08d}-0000-0000-0000-000000000000", "job": "contention",
                "status": "SUCCESS", "engagement_run_id": engagement,
                "steps": [{"step_key": key, "pool_id": pool, "started": start, "ended": end}
                          for key, pool, start, end in steps]}
    return reseal({
        "schema": rp.STATE_SCHEMA_ID, "generated_at": "2026-09-21T00:00:00+00:00",
        "dagster_version": rp.DAGSTER_VERSION, "declaration_sha256": rp.declaration_digest(),
        "default_pool_limit": {"expected": rp.DEFAULT_POOL_LIMIT, "observed": rp.DEFAULT_POOL_LIMIT},
        "free_slots_after_run_end_seconds": {"expected": rp.FREE_SLOTS_AFTER_RUN_END_SECONDS,
                                             "observed": rp.FREE_SLOTS_AFTER_RUN_END_SECONDS},
        "outer_limits": {"expected": dict(rp.OUTER_LIMITS), "observed": dict(rp.OUTER_LIMITS)},
        "pools": [{"pool_id": pool.pool_id, "expected_limit": pool.limit, "observed_limit": pool.limit,
                   "from_default": False, "claimed_slots": 0, "pending_steps": 0, "state": "OK"}
                  for pool in rp.POOLS],
        "foreign_pools": [],
        "assignments": {"pooled": [{"job": "evidence_index", "op": "evidence_index_work", "pool_id": rp.MEMORY}],
                        "unassigned": [{"job": "evidence_index", "op": "reserve", "reason": "coordination_only"}],
                        "errors": []},
        "runs": [run(1, "eng-a", [("memory_0", rp.MEMORY, 10.0, 13.0), ("memory_1", rp.MEMORY, 13.5, 16.0)]),
                 run(2, None, [("cpu_0", rp.CPU, 11.0, 12.5)])]})


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


    def test_op_factories_use_only_these_module_globals(self):
        # Other suites (the vendor pre-pass graph test of PR #30) cut an op factory such as
        # `blocked_op` out of this file by AST and exec it in a hand-built namespace. A module
        # global that the factory starts to use is a NameError there, not here. This pins the exact
        # set per factory: when one changes, every such namespace has to supply the new name (see
        # docs/pools/resource-pools.md, "After PR #30 merges").
        tree = ast.parse(WORKFLOW_SOURCE.read_text(encoding="utf-8"))
        defined = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                defined.add(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                defined.update((alias.asname or alias.name).split(".")[0] for alias in node.names)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                defined.update(name.id for target in targets for name in ast.walk(target)
                               if isinstance(name, ast.Name))
        factories = {}
        for factory in tree.body:  # a top-level function that builds a decorated function
            if not isinstance(factory, ast.FunctionDef) or not any(
                    isinstance(node, ast.FunctionDef) and node is not factory and node.decorator_list
                    for node in ast.walk(factory)):
                continue
            local = set()
            for node in ast.walk(factory):
                if isinstance(node, ast.FunctionDef):
                    local.add(node.name)
                    arguments = node.args
                    local.update(arg.arg for arg in arguments.posonlyargs + arguments.args + arguments.kwonlyargs)
                    self.assertIsNone(arguments.vararg)
                    self.assertIsNone(arguments.kwarg)
                elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                    local.add(node.id)
                # Scopes this simple name analysis does not model; none is used in a factory today.
                self.assertNotIsInstance(node, (ast.Global, ast.Nonlocal, ast.Import, ast.ImportFrom, ast.Lambda,
                                                ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp))
            free = {node.id for node in ast.walk(factory)
                    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)} - local - set(dir(builtins))
            self.assertEqual(free - defined, set(), factory.name + " uses a name the module never defines")
            factories[factory.name] = free
        self.assertEqual(factories, {
            "branch_op": {"op", "MetadataValue", "workflow", "data_path", "CPU_POOL"},
            "blocked_op": {"op", "In", "Failure", "MetadataValue", "data_path", "now", "atomic_json",
                           "NOT_IMPLEMENTED"}})
        # The global is the recorded unassigned state, not a copy of its literals.
        value = [node.value for node in tree.body if isinstance(node, ast.Assign)
                 and [getattr(target, "id", None) for target in node.targets] == ["NOT_IMPLEMENTED"]]
        self.assertEqual([ast.unparse(node) for node in value],
                         ["resource_pools.unassigned('worker_not_implemented')"])

    def test_the_dagster_version_is_the_pinned_requirement(self):
        pins = re.findall(r"^dagster==(\S+)$", REQUIREMENTS.read_text(encoding="utf-8"), re.M)
        self.assertEqual(pins, [rp.DAGSTER_VERSION])


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

    def test_step_pool_and_flag_are_in_the_schema(self):
        schema = json.loads((SCHEMAS_DIR / rp.STATE_SCHEMA_FILE).read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["pooled_steps_recorded"], {"type": "boolean"})
        self.assertEqual(state_fixture()["state_sha256"], rp._state_digest(state_fixture()))
        self.assertEqual(validate_document(state_fixture(), rp.STATE_SCHEMA_FILE), [])

    def test_overlap_sweep(self):
        self.assertEqual(rp.max_overlap([]), 0)
        self.assertEqual(rp.max_overlap([(0, 1), (1, 2)]), 1)  # touching intervals do not overlap
        self.assertEqual(rp.max_overlap([(0, 2), (1, 3), (1.5, 1.6)]), 3)
        self.assertEqual(rp.max_overlap([(0, None), (5, 6)]), 2)  # an open step never releases


PLANT = "PLANTED_zz9"
# Replacement values tried for every leaf, by the type of the value that is there.
HOSTILE = {
    bool: lambda value: [not value],
    int: lambda value: [-1, value + 1, 99],
    float: lambda value: [-1.0, value + 1000.0, value + 1.5],
    type(None): lambda value: [PLANT, 1],
    str: lambda value: [item for item in (
        PLANT, "0.0.1", "sha256:" + "0" * 64, "1999-01-01T00:00:00+00:00", "FAILURE", "DRIFT", "FAIL",
        rp.CPU, rp.DOCKER, "Memory", rp.UNASSIGNED, "bootstrap_diagnostic", "9" * 8 + "-0000-0000-0000-" + "0" * 12,
        "appsec-review/resource-pool-state/1.0", "appsec-review/resource-pool-state/2.0") if item != value],
}
# Leaves a consistent reseal can change and still verify PASS, each because no byte on disk or
# constant in the module determines it. Anything else that verifies is an unbound trusted field.
FREE_LEAVES = {
    "generated_at": "a clock reading; only its shape is checked",
    "pools[].claimed_slots": "a live count; bound to 0..expected_limit, not to one value",
    "pools[].pending_steps": "a live count; bound to >= 0",
    "assignments.pooled[].job": "registered names; bound to be listed once", "assignments.pooled[].op": "same",
    "assignments.pooled[].pool_id": "any declared pool is a possible assignment",
    "assignments.unassigned[].job": "same", "assignments.unassigned[].op": "same",
    "assignments.unassigned[].reason": "any closed reason is possible",
    "runs[].dagster_run_id": "an identifier; bound to be listed once", "runs[].job": "a registered name",
    "runs[].status": "a failed or canceled run is valid evidence (failure injection)",
    "runs[].engagement_run_id": "an identifier; two runs sharing one must not overlap",
    "runs[].steps[].step_key": "an identifier; bound to be unique in its run",
    "runs[].steps[].pool_id": "another declared pool verifies only while its limit still holds",
    "runs[].steps[].started": "a clock reading; any value that keeps every limit verifies",
    "runs[].steps[].ended": "same",
}


def _leaves(node, path=()):
    if isinstance(node, dict):
        for key in node:
            yield from _leaves(node[key], path + (key,))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _leaves(item, path + (index,))
    else:
        yield path, node


def _containers(node, path=()):
    if isinstance(node, dict):
        yield path
    for key, item in (node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else ()):
        yield from _containers(item, path + (key,))


def _at(document, path):
    for key in path:
        document = document[key]
    return document


def _label(path):
    return "".join("[]" if isinstance(key, int) else "." + key for key in path).lstrip(".")


class StateVerifier(unittest.TestCase):
    """Host-runnable: `verify_state_file` needs no Dagster."""

    def setUp(self):
        location = os.environ.get("PHASE1_TEST_DATA")
        if location:
            Path(location).mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=location)
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "state.json"

    def verify(self, document=None, *, text=None):
        self.path.write_text(json.dumps(document) if text is None else text, encoding="utf-8")
        problems = rp.verify_state_file(self.path)
        self.assertNotIn(PLANT, json.dumps(problems))
        return problems

    def accepted(self, document):
        """The qualification reading of a document: verifies, PASS, and records pooled steps."""
        return self.verify(document) == [] and document["result"] == "PASS" and document["pooled_steps_recorded"]

    def test_the_fixture_verifies(self):
        self.assertTrue(self.accepted(state_fixture()))

    def test_every_leaf_edited_alone(self):
        unbound = set()
        for path, value in _leaves(state_fixture()):
            for hostile in HOSTILE[type(value)](value):
                document = state_fixture()
                _at(document, path[:-1])[path[-1]] = hostile
                self.assertTrue(self.verify(document), (path, "edited, nothing re-derived"))
                if path[0] in ("pooled_steps_recorded", "observed_overlap", "errors", "result", "state_sha256"):
                    continue  # derived fields: a reseal would overwrite the edit
                try:
                    reseal(document)
                except (TypeError, ValueError):  # a value of the wrong type: the forger can only re-hash
                    document["state_sha256"] = rp._state_digest(document)
                if self.accepted(document):
                    unbound.add(_label(path))
        self.assertEqual(unbound, set(FREE_LEAVES))

    def test_every_key_removed_and_an_extra_key_added(self):
        for path in _containers(state_fixture()):
            for key in list(_at(state_fixture(), path)):
                document = state_fixture()
                del _at(document, path)[key]
                document["state_sha256"] = rp._state_digest(document) if "state_sha256" in document else None
                self.assertEqual(len(self.verify(document)), 1, (path, key))
            document = state_fixture()
            _at(document, path)[PLANT] = PLANT
            document["state_sha256"] = rp._state_digest(document)
            self.assertRegex(self.verify(document)[0], r"^state document fails its schema \(\d+ errors\)\Z")

    def test_repeated_keys(self):
        # The reviewer's case: a FAIL document's keys first, a PASS copy of the same keys last.
        good = state_fixture()
        bad = state_fixture()
        for step in bad["runs"][0]["steps"]:
            step["started"], step["ended"] = 10.0, 20.0
        reseal(bad)
        self.assertEqual(bad["result"], "FAIL")
        text = json.dumps(good)
        text = text[:1] + '"result":"FAIL","errors":' + json.dumps(bad["errors"]) + ',"runs":' + \
            json.dumps(bad["runs"]) + "," + text[1:]
        self.assertEqual(json.loads(text), good)  # a plain loader sees only the PASS copy
        refusal = ["state document is not readable JSON with unique keys and finite numbers"]
        self.assertEqual(self.verify(text=text), refusal)
        self.assertEqual(self.verify(text=json.dumps(good)[:-1] + ',"result":"PASS"}'), refusal)
        nested = json.dumps(good).replace('"claimed_slots": 0', '"claimed_slots": 0, "claimed_slots": 0', 1)
        self.assertNotEqual(nested, json.dumps(good))
        self.assertEqual(self.verify(text=nested), refusal)

    def test_non_finite_and_negative_step_times(self):
        refusal = ["state document is not readable JSON with unique keys and finite numbers"]
        # The reviewer's case: two memory steps (limit 1) that never end, started at 1e999.
        document = state_fixture()
        for step in document["runs"][0]["steps"]:
            step["started"], step["ended"] = float("inf"), None
        document["observed_overlap"] = rp.overlap_by_pool(document["runs"])
        self.assertEqual(rp._state_errors(document), [])  # the sweep is blind to it: inf opens after it closes
        with self.assertRaises(ValueError):
            rp._state_digest(document)  # and the producer's canonical form refuses to emit Infinity
        text = json.dumps(state_fixture())
        for literal in ("1e999", "-1e999", "Infinity", "-Infinity", "NaN"):
            for field in ('"started": 10.0', '"ended": 13.0', '"claimed_slots": 0'):
                self.assertIn(field, text)
                self.assertEqual(self.verify(text=text.replace(field, field.split(":")[0] + ": " + literal, 1)),
                                 refusal, (literal, field))
        for field in ("started", "ended"):
            document = state_fixture()
            document["runs"][1]["steps"][0]["started"] = -5.0
            document["runs"][1]["steps"][0][field] = -5.0 if field == "started" else -1.0
            self.assertIn("a step time is negative", self.verify(reseal(document)))

    def test_unbound_fields_the_review_found(self):
        def edited(change):
            document = state_fixture()
            change(document)
            return reseal(document)

        def overlapping(pool_id):
            def change(document):
                for step in document["runs"][0]["steps"]:
                    step.update(started=10.0, ended=20.0, pool_id=pool_id)
            return change

        document = edited(lambda d: d.__setitem__("declaration_sha256", "sha256:" + "0" * 64))
        self.assertEqual(self.verify(document), ["declaration_sha256 is not the hash of this resource_pools.py"])
        document = edited(lambda d: d.__setitem__("dagster_version", "0.0.1"))
        self.assertEqual((document["result"], document["errors"]), ("FAIL", ["dagster version: not the pinned version"]))
        document = edited(lambda d: d["pools"][0].__setitem__("claimed_slots", 99))
        self.assertEqual(document["errors"], ["pool cpu: more slots are claimed than the declared limit"])
        self.assertTrue(self.accepted(edited(lambda d: d["pools"][0].__setitem__("claimed_slots", rp.LIMITS[rp.CPU]))))
        for field, value in (("claimed_slots", -9), ("pending_steps", -1)):
            document = edited(lambda d: d["pools"][0].__setitem__(field, value))
            self.assertEqual(self.verify(document), ["pool cpu: a slot or pending-step count is negative"])
        for pool_id in ("Memory", rp.UNASSIGNED, PLANT):
            document = edited(overlapping(pool_id))
            self.assertEqual(document["errors"], ["runs: a recorded step names an undeclared pool"])
            self.assertEqual(self.verify(document), [])  # a consistent FAIL document
            document["errors"], document["result"] = [], "PASS"
            document["state_sha256"] = rp._state_digest(document)
            self.assertEqual(self.verify(document), ["errors do not follow from the document"])
        self.assertEqual(edited(overlapping(rp.MEMORY))["errors"], ["pool memory: observed overlap exceeds the limit"])
        document = edited(lambda d: d.__setitem__("assignments", {"pooled": [], "unassigned": [], "errors": []}))
        self.assertEqual(document["errors"], ["assignments: no op was inspected"])
        for target in ("pooled", "unassigned"):
            document = edited(lambda d: d["assignments"]["unassigned"].append(
                dict(d["assignments"][target][0], reason="coordination_only", pool_id=None)))
            for item in document["assignments"]["unassigned"]:
                item.pop("pool_id", None)
            document["state_sha256"] = rp._state_digest(document)
            self.assertEqual(self.verify(document), ["assignments: a (job, op) pair is listed more than once"])
        document = edited(lambda d: d["runs"].append(dict(deepcopy(d["runs"][1]), steps=[])))
        self.assertEqual(self.verify(document), ["runs: a Dagster run id is listed more than once"])
        document = edited(lambda d: d["runs"][0]["steps"][1].__setitem__("step_key", "memory_0"))
        self.assertEqual(self.verify(document), ["runs: a step key is listed more than once in one run"])
        for foreign in (["gpu", "gpu"], ["zeta", "gpu"], [rp.CPU]):
            document = edited(lambda d: d.__setitem__("foreign_pools", foreign))
            self.assertIn("foreign pools are not a sorted list of distinct undeclared pools", self.verify(document))

    def test_no_pooled_step_is_not_qualification_evidence(self):
        for runs in ([], [dict(state_fixture()["runs"][0], steps=[])]):
            document = state_fixture()
            document["runs"] = runs
            reseal(document)
            self.assertEqual((self.verify(document), document["result"]), ([], "PASS"))
            self.assertIs(document["pooled_steps_recorded"], False)
            self.assertFalse(self.accepted(document))
            document["pooled_steps_recorded"] = True
            document["state_sha256"] = rp._state_digest(document)
            self.assertEqual(self.verify(document), ["pooled_steps_recorded does not follow from the recorded steps"])

    def test_unreadable_documents(self):
        refusal = ["state document is not readable JSON with unique keys and finite numbers"]
        self.assertEqual(self.verify(text="{"), refusal)
        self.assertEqual(self.verify(text="[" * 100000), refusal)
        self.assertEqual(rp.verify_state_file(Path(self.directory.name) / "absent.json"), refusal)
        self.path.write_bytes(b"\xff\xfe")
        self.assertEqual(rp.verify_state_file(self.path), refusal)
        self.assertEqual(self.verify(text="[]")[0][:33], "state document fails its schema (")


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
        kinds = re.findall(r"^\| `([a-z_]+)` \| `([a-z_]+)`( \(`([a-z_]+)` when `memory_heavy`\))? \|$", text, re.M)
        self.assertEqual([row[0] for row in kinds], list(rp.WORKER_KIND_POOLS))
        for kind, pool, _, heavy in kinds:
            self.assertEqual(rp.derive_pool(kind, (), memory_heavy=False), pool, kind)
            # A row that names no memory-heavy pool claims the pool is the same either way.
            self.assertEqual(rp.derive_pool(kind, (), memory_heavy=True), heavy or pool, kind)
        for reason in rp.UNASSIGNED_REASONS:
            self.assertIn(f"`{reason}`", text)
        self.assertIn(f"default_op_concurrency_limit: {rp.DEFAULT_POOL_LIMIT}", text)
        self.assertIn(f"free_slots_after_run_end_seconds: {rp.FREE_SLOTS_AFTER_RUN_END_SECONDS}", text)
        self.assertIn("load evidence", text.lower())


if __name__ == "__main__":
    unittest.main()
