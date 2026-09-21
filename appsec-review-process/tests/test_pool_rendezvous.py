"""Wait-all rendezvous and terminal-instance manifest (backlog batch C02).

Every pool is a real C01 expansion and every instance runs through the real B13/B14 adapters (B13
behind its scripted docker seam here; the live cases are in test_pool_rendezvous_live.py). No test
sleeps to synchronize: invokers signal and block on events, and every wait is bounded.
"""
from __future__ import annotations

from copy import deepcopy
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_execution as ce  # noqa: E402
import persona_invocation as pi  # noqa: E402
import persona_invocation_support as b14  # noqa: E402
import pool_rendezvous as pr  # noqa: E402
import pool_rendezvous_support as support  # noqa: E402
from pool_rendezvous_support import HANG_SECONDS, MARKER, Gated, Routed, RoutedDocker  # noqa: E402
import pool_specification as ps  # noqa: E402
import resource_pools as rp  # noqa: E402
import schema_validate  # noqa: E402
from test_container_execution import ScriptedDocker  # noqa: E402
import worker_adapters  # noqa: E402

with tempfile.TemporaryDirectory() as _probe:
    SYMLINKS = support.c01.symlinks_supported(Path(_probe))     # probed once; a POSIX host never skips

SCHEMAS = (pr.MANIFEST_SCHEMA, pr.INSTANCE_SCHEMA)
KEYWORDS = {"$schema", "$id", "title", "description", "type", "required", "properties",
            "additionalProperties", "enum", "const", "pattern", "items", "minItems", "$ref"}
ZERO_SHA = "sha256:" + "0" * 64


class Background:
    """Runs one call in a thread and hands back its value or its exception, within a bound."""

    def __init__(self, call) -> None:
        self.box: dict = {}

        def target():
            try:
                self.box["value"] = call()
            except BaseException as exc:      # noqa: BLE001 - re-raised in result()
                self.box["error"] = exc
        self.thread = threading.Thread(target=target, daemon=True, name="test-coordinator")
        self.thread.start()

    def result(self):
        self.thread.join(HANG_SECONDS)
        if self.thread.is_alive():
            raise AssertionError("the rendezvous did not end")
        if "error" in self.box:
            raise self.box["error"]
        return self.box["value"]


def iter_then(first: list, then):
    """A mock side effect: the listed values once, then whatever ``then()`` says."""
    values = list(first)

    def effect(*_args, **_kwargs):
        return values.pop(0) if values else then()
    return effect


def wait_for(event: threading.Event) -> None:
    if not event.wait(HANG_SECONDS):
        raise AssertionError("an expected event never happened")


class Case(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(support.join_pool_threads)
        self.ws = support.RendezvousWorkspace(Path(self.temporary.name).resolve())
        self.docker = RoutedDocker(ScriptedDocker)

    def scripted(self, docker=None):
        first, second = (docker or self.docker).patches()
        first.start()
        second.start()
        self.addCleanup(first.stop)
        self.addCleanup(second.stop)

    def personas(self, count: int, **over) -> tuple:
        spec = self.ws.spec([self.ws.persona_group("reviewers", count)], **over)
        return spec, self.ws.expand(spec)

    def mixed(self, personas: int = 2, tools: int = 2, **over) -> tuple:
        spec = self.ws.mixed(personas, tools, **over)
        return spec, self.ws.expand(spec)

    def raw(self, plan) -> bytes:
        return self.ws.manifest_path(plan).read_bytes()

    def assert_invariants(self, manifest, plan):
        """The instance list IS the expansion's, counts sum to the total, the outcome is the pure
        function of the states, and a result is adopted exactly for the five result states."""
        self.assertEqual([record["instance_id"] for record in manifest["instances"]], support.ids(plan))
        counts = dict(manifest["counts"])
        self.assertEqual(counts.pop("instances"), len(plan.manifest["instances"]))
        self.assertEqual(sorted(counts), sorted(pr.STATES))
        self.assertEqual(sum(counts.values()), len(plan.manifest["instances"]))
        found = support.states(manifest)
        self.assertEqual(counts, {state: found.count(state) for state in pr.STATES})
        self.assertEqual(manifest["outcome"], pr.pool_outcome(found))
        for record, entry in zip(manifest["instances"], plan.manifest["instances"]):
            for name in ("group_id", "ordinal", "worker_kind", "attempt_root", "resource_pool",
                         "request_sha256", "input_fingerprint"):
                self.assertEqual(record[name], entry[name])
            adopted = record["state"] in pr.RESULT_STATES
            self.assertEqual(record["result_file"] is not None, adopted)
            self.assertEqual(record["adapter_status"] is not None, adopted)
            self.assertEqual(record["worker_stopped"] is not None, record["state"] == pr.RENDEZVOUS_TIMED_OUT)
            self.assertIn(record["state_reason"], pr.REASONS_BY_STATE[record["state"]])

    def published(self, spec, plan):
        """The manifest on disk verifies, equals what load_verified_manifest returns, and holds; the
        verified record hands over a result exactly for the five result states."""
        self.assertEqual(self.ws.verify(spec, plan), [])
        verified = self.ws.load(spec, plan)
        loaded = verified.manifest
        self.assertEqual(pr.canonical_bytes(pr.thaw(loaded)), self.raw(plan))
        self.assert_invariants(loaded, plan)
        self.assertEqual([item.instance for item in verified.instances], list(plan.instances))
        self.assertEqual([item.record for item in verified.instances], list(loaded["instances"]))
        for item in verified.instances:
            self.assertEqual(item.result is not None, item.state in pr.RESULT_STATES)
        return loaded

    def reseal(self, plan, edit) -> None:
        """A dishonest producer: edits the manifest and correctly reseals its hash."""
        manifest = json.loads(self.raw(plan).decode("utf-8"))
        edit(manifest)
        manifest["manifest_sha256"] = pr.manifest_sha256(manifest)
        path = self.ws.manifest_path(plan)
        path.unlink()
        path.write_bytes(pr.canonical_bytes(manifest))


# ---- schemas and constants -------------------------------------------------------------------------

def _objects(node, path="$"):
    if isinstance(node, dict):
        if "properties" in node:
            yield path, node
        for key, value in node.items():
            yield from _objects(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _objects(value, f"{path}[{index}]")


def _nodes(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _nodes(value)
    elif isinstance(node, list):
        for value in node:
            yield from _nodes(value)


class SchemaTests(unittest.TestCase):
    def load(self, name):
        return json.loads((schema_validate.SCHEMAS_DIR / name).read_text(encoding="utf-8"))

    def test_schemas_use_only_the_validator_subset_and_are_closed_with_every_property_required(self):
        for name in SCHEMAS:
            schema = self.load(name)
            for node in _nodes(schema):
                if "properties" in node or "type" in node or "$ref" in node:
                    self.assertLessEqual(set(node) - {"properties"}, KEYWORDS | set(), (name, sorted(node)))
                if isinstance(node.get("pattern"), str):
                    self.assertTrue(node["pattern"].endswith("\\Z"), (name, node["pattern"]))
            for path, node in _objects(schema):
                self.assertIs(node.get("additionalProperties"), False, (name, path))
                self.assertEqual(sorted(node["required"]), sorted(node["properties"]), (name, path))

    def test_the_closed_vocabularies_are_the_module_s_and_the_adapters(self):
        instance, manifest = self.load(pr.INSTANCE_SCHEMA), self.load(pr.MANIFEST_SCHEMA)
        self.assertEqual(instance["properties"]["state"]["enum"], list(pr.STATES))
        self.assertEqual(manifest["properties"]["outcome"]["enum"], list(pr.OUTCOMES))
        self.assertEqual(sorted(manifest["properties"]["counts"]["properties"]), sorted(("instances", *pr.STATES)))
        causes = {cause for cause in (*ce.STATUS_BY_CAUSE, *pi.STATUS_BY_CAUSE)}
        self.assertEqual(set(instance["properties"]["adapter_cause"]["enum"]), causes)
        statuses = {*ce.STATUS_BY_CAUSE.values(), *pi.STATUS_BY_CAUSE.values(), None}
        self.assertEqual(set(instance["properties"]["adapter_status"]["enum"]), statuses)
        self.assertEqual(manifest["properties"]["schema"]["const"], pr.MANIFEST_ID)
        self.assertEqual(manifest["properties"]["classification"]["const"], pr.CLASSIFICATION_ID)
        self.assertEqual(manifest["properties"]["expansion"]["const"], ps.EXPANSION_ID)
        self.assertEqual(manifest["properties"]["empty_pool_reason"]["enum"], [*ps.EMPTY_POOL_REASONS, None])
        self.assertEqual(len(set(pr.STATES)), len(pr.STATES))
        self.assertEqual(len(pr.STATES), 11)
        self.assertLessEqual(set(pr.RESULT_STATES), set(pr.STATES))
        # Q4: the reason enum is the module's table, which is total over the states
        self.assertEqual(instance["properties"]["state_reason"]["enum"], list(pr.STATE_REASONS))
        self.assertEqual(instance["properties"]["state_reason"]["type"], "string", "every entry has a reason")
        self.assertEqual(sorted(pr.REASONS_BY_STATE), sorted(pr.STATES))
        self.assertEqual(sorted(pr.STATE_REASONS),
                         sorted(value for name, value in vars(pr).items() if name.startswith("REASON_")))
        self.assertEqual(sorted(pr.STATE_REASONS),
                         sorted({reason for reasons in pr.REASONS_BY_STATE.values() for reason in reasons}))
        self.assertEqual(len(pr.REASONS_BY_STATE[pr.INVALID]), 5)
        self.assertEqual(len(pr.REASONS_BY_STATE[pr.MISSING]), 3)

    def test_no_property_name_is_free_text_or_secret_looking(self):
        import evidence_redaction
        for name in SCHEMAS:
            for _, node in _objects(self.load(name)):
                for key, value in node["properties"].items():
                    self.assertIsNone(evidence_redaction._KEYWORD_RE.search(key), key)
                    if value.get("type") == "string" or value.get("type") == ["string", "null"]:
                        self.assertTrue("pattern" in value or "enum" in value, (name, key, "free text"))

    def test_the_in_process_caps_never_exceed_the_merged_limits(self):
        self.assertLessEqual(pr.MAX_PARALLEL, rp.AGGREGATE_STEP_CEILING)
        self.assertLessEqual(pr.DRAIN_BOUNDS[1], 180)
        self.assertGreater(pr.LIVENESS_BACKSTOP_SECONDS, 1, "a backstop this short would be a poll")
        source = inspect.getsource(pr)
        self.assertNotIn("time.sleep", source)
        self.assertNotIn("shell=True", source)


# ---- required arguments, the runtime and its bindings ----------------------------------------------

class ContractTests(Case):
    def test_every_safety_argument_is_required(self):
        spec, plan = self.personas(1)
        root = self.ws.root(plan)
        full = {**self.ws.arguments(spec), "runtime": self.ws.runtime()}
        for name in full:
            arguments = dict(full)
            del arguments[name]
            with self.subTest(run=name), self.assertRaises(TypeError):
                pr.run_rendezvous(root, **arguments)
        full = self.ws.reader_arguments(spec)
        self.assertEqual(sorted(full), ["context", "expected_spec", "rendezvous_parent"],
                         "the context is the single carrier: no reader takes host facts beside it")
        for call in (pr.verify_manifest, pr.load_verified_manifest):
            for name in full:
                arguments = dict(full)
                del arguments[name]
                with self.subTest(call=call.__name__, omitted=name), self.assertRaises(TypeError):
                    call(root, **arguments)
        full = {**self.ws.classifier_arguments(plan), "observation": pr.REPORTED}
        for name in full:
            arguments = dict(full)
            del arguments[name]
            with self.subTest(classify=name), self.assertRaises(TypeError):
                pr.classify_instance(plan, 0, **arguments)
        full = {**self.ws.classifier_arguments(plan), "observations": [pr.REPORTED]}
        for name in full:
            arguments = dict(full)
            del arguments[name]
            with self.subTest(derive=name), self.assertRaises(TypeError):
                pr.derive_manifest(plan, **arguments)
        for name in self.ws.runtime_fields():
            fields = self.ws.runtime_fields()
            del fields[name]
            with self.subTest(runtime_field=name), self.assertRaises(TypeError):
                pr.RendezvousRuntime(**fields)
        with self.assertRaises(TypeError):
            pr.run_rendezvous(root, **self.ws.arguments(spec), runtime=self.ws.runtime_fields())
        self.assertEqual(support.c01.tree(self.ws.rendezvous_parent), [])

    def refused(self, spec, plan, fragment, **runtime_over) -> str:
        before = support.c01.tree(self.ws.base)
        with self.assertRaises(pr.RendezvousError) as caught:
            self.ws.run(spec, plan, **runtime_over)
        self.assertIn(fragment, str(caught.exception))
        self.assertNotIn(MARKER, str(caught.exception))
        self.assertNotIn(str(self.ws.base), str(caught.exception))
        self.assertEqual(support.c01.tree(self.ws.base), before, "a refused rendezvous created or launched something")
        return str(caught.exception)

    def test_the_runtime_is_validated_before_anything_is_created(self):
        spec, plan = self.mixed(1, 1)
        hostile = {
            "max_parallel": [0, pr.MAX_PARALLEL + 1, True, 1.5, "2", None],
            "wait_limit_seconds": [0, -1, float("nan"), float("inf"), True, "1", ps.MAX_TOTAL_TIMEOUT_SECONDS + 1],
            "drain_seconds": [-1, pr.DRAIN_BOUNDS[1] + 1, 1.5, True, None],
        }
        for name, values in hostile.items():
            for value in values:
                with self.subTest(field=name, value=repr(value)):
                    self.refused(spec, plan, "runtime." + name, **{name: value})
        plain = threading.Event()       # the adapters would accept it; it cannot wake the waiter
        self.refused(spec, plan, "runtime.cancel must be a PoolCancel", cancel=plain)

    def test_the_rendezvous_parent_may_not_be_reachable_by_a_worker(self):
        spec, plan = self.personas(1)
        inside = self.ws.pool_parent / "manifests"
        inside.mkdir()
        hostile = [self.ws.pool_parent, self.ws.data, self.ws.base, Path("relative"), self.ws.base / "absent",
                   str(self.ws.rendezvous_parent), self.ws.rendezvous_parent / "." / "x" / "..",
                   self.ws.base / "targets" / ".." / "rendezvous"]
        if SYMLINKS:
            link = self.ws.base / "rendezvous-link"
            link.symlink_to(self.ws.rendezvous_parent, target_is_directory=True)
            hostile.append(link)
        for value in hostile:
            with self.subTest(parent=repr(value)[-40:]):
                self.refused(spec, plan, "rendezvous_parent", rendezvous_parent=value)
                if isinstance(value, Path):
                    errors = self.ws.verify(spec, plan, rendezvous_parent=value)
                    self.assertEqual(len(errors), 1)
                    self.assertIn("rendezvous_parent", errors[0])
        inside.rmdir()
        with self.subTest(parent="inside the pool parent"):
            os.mkdir(inside)
            try:
                self.refused(spec, plan, "lies beneath context.pool_parent", rendezvous_parent=inside)
            finally:
                inside.rmdir()

    def test_the_runtime_holds_only_launch_objects_and_the_context_builds_both_adapter_runtimes(self):
        """Q3: the context is the single carrier. No ready-made adapter runtime can be handed in, so
        nothing can run under one registry, image directory or snapshot and be verified under another."""
        launch_only = set(ps.CONTAINER_LAUNCH_ONLY_FIELDS) | set(ps.PERSONA_LAUNCH_ONLY_FIELDS)
        fields = set(self.ws.runtime_fields())
        self.assertEqual(fields, launch_only | {"rendezvous_parent", "max_parallel", "wait_limit_seconds",
                                                "drain_seconds"})
        self.assertFalse(fields & set(self.ws.context_fields()), "a host fact has a second carrier")
        for name in ("ContainerHostFacts", "host_facts_of", "_host_facts_errors", "_binding_errors"):
            self.assertFalse(hasattr(pr, name), name)
        spec, plan = self.mixed(1, 1)
        context, runtime = self.ws.context(), self.ws.runtime()
        built = pr.adapter_runtimes(plan, context, runtime)
        self.assertEqual(sorted(built), sorted(ps.WORKER_KINDS))
        for kind, arguments in ((ps.PINNED_CONTAINER, context.container_verification_arguments()),
                                (ps.PERSONA, context.persona_verification_arguments())):
            self.assertIs(built[kind].cancel, runtime.cancel)
            self.assertIs(built[kind].clock, runtime.clock)
            for name, value in arguments.items():
                self.assertEqual(getattr(built[kind], name), value, name)
        self.assertIs(built[ps.PERSONA].invoker, runtime.invoker)
        self.assertEqual(built[ps.PERSONA].stop_grace_seconds, runtime.stop_grace_seconds)

    def test_a_launch_object_the_context_or_an_adapter_refuses_launches_nothing(self):
        self.scripted()     # no real docker here: the code-server has none, and a host must not run one
        spec, plan = self.mixed(1, 1)

        class Other(pi.FixtureInvoker):
            invoker_id = "other-invoker"
        hostile = {"another invoker": {"invoker": Other()}, "no invoker": {"invoker": None},
                   "a clock that is not callable": {"clock": b14.NOW},
                   "a stop grace the adapter refuses": {"stop_grace_seconds": -1}}
        for label, over in hostile.items():
            with self.subTest(case=label):
                before = support.c01.tree(self.ws.base)
                runtime = pr.RendezvousRuntime(**{**self.ws.runtime_fields(), **over})
                with self.assertRaises(ps.PoolSpecError) as caught:
                    pr.run_rendezvous(self.ws.root(plan), **self.ws.arguments(spec), runtime=runtime)
                self.assertNotIn(MARKER, str(caught.exception))
                self.assertEqual(support.c01.tree(self.ws.base), before)
        # a context without the container facts cannot launch, classify or verify a container instance
        bare = self.ws.context(docker_executable=None, container_user=None)
        self.assertEqual(self.ws.run(spec, plan)["outcome"], pr.COMPLETE)
        errors = pr.verify_manifest(self.ws.root(plan), **self.ws.reader_arguments(spec, context=bare))
        self.assertEqual(len(errors), 1)
        with self.assertRaises(pr.RendezvousError):
            pr.classify_instance(plan, 1, pool_root=self.ws.root(plan), context=bare, observation=pr.REPORTED)

    def test_a_pool_of_one_kind_needs_only_that_kind_s_launch_objects(self):
        spec, plan = self.personas(1)
        self.assertEqual(sorted(pr.adapter_runtimes(plan, self.ws.context(), self.ws.runtime())), [ps.PERSONA])
        tools = self.ws.spec([self.ws.tool_group("scanners", 1)], attempt_id="attempt-tools")
        self.scripted()
        runtime = pr.RendezvousRuntime(**{**self.ws.runtime_fields(), "invoker": None})
        manifest = pr.run_rendezvous(self.ws.root(self.ws.expand(tools)), **self.ws.arguments(tools), runtime=runtime)
        self.assertEqual(support.states(manifest), [pr.SUCCEEDED])
        manifest = self.ws.run(spec, plan)
        self.assertEqual(support.states(manifest), [pr.SUCCEEDED])

    def test_the_expansion_is_verified_first_and_a_wrong_pool_root_launches_nothing(self):
        spec, plan = self.personas(1)
        other = deepcopy(spec)
        other["attempt_id"] = "attempt-other"
        with self.assertRaises(ps.PoolSpecError):
            pr.run_rendezvous(self.ws.root(plan), expected_spec=other, context=self.ws.context(),
                              runtime=self.ws.runtime())
        request = self.ws.root(plan) / plan.requests[0].relative_path
        request.write_bytes(request.read_bytes() + b" ")
        with self.assertRaises(ps.PoolSpecError):
            self.ws.run(spec, plan)
        self.assertEqual(support.c01.tree(self.ws.rendezvous_parent), [])
        self.assertEqual(support.c01.tree(self.ws.instance_root(plan, 0)), [])


class OutcomeFunctionTests(unittest.TestCase):
    def test_the_pool_outcome_is_a_pure_function_of_the_states(self):
        others = [state for state in pr.STATES if state != pr.SUCCEEDED]
        self.assertEqual(pr.pool_outcome([]), pr.EMPTY)
        self.assertEqual(pr.pool_outcome([pr.SUCCEEDED] * 3), pr.COMPLETE)
        for state in others:
            with self.subTest(state=state):
                canceled = state in (pr.CANCELED, pr.NOT_LAUNCHED_CANCELED)
                self.assertEqual(pr.pool_outcome([state]), pr.POOL_CANCELED if canceled else pr.POOL_FAILED)
                self.assertEqual(pr.pool_outcome([pr.SUCCEEDED, state, pr.SUCCEEDED]),
                                 pr.POOL_CANCELED if canceled else pr.DEGRADED)
                self.assertEqual(pr.pool_outcome([state, pr.SUCCEEDED]), pr.pool_outcome([pr.SUCCEEDED, state]))
                self.assertNotEqual(pr.pool_outcome([pr.SUCCEEDED, state]), pr.COMPLETE)
        with self.assertRaises(pr.RendezvousError):
            pr.pool_outcome([pr.SUCCEEDED, "OK"])

    def test_every_adapter_status_and_cause_maps_to_exactly_one_result_state(self):
        for table in (ce.STATUS_BY_CAUSE, pi.STATUS_BY_CAUSE):
            for cause, status in table.items():
                state = pr._result_state(status, cause)
                self.assertIn(state, pr.RESULT_STATES, (status, cause))
                self.assertEqual(state == pr.SUCCEEDED, status == "OK")
                self.assertEqual(state == pr.INSTANCE_TIMED_OUT, cause == "TIMEOUT")
        self.assertIsNone(pr._result_state("OK_WITH_GAPS", None))


# ---- zero, one, many, mixed --------------------------------------------------------------------------

class ZeroOneManyTests(Case):
    def test_an_empty_pool_publishes_EMPTY_with_its_reason_and_is_never_a_result_set(self):
        spec = self.ws.spec([self.ws.persona_group("reviewers", 0)], empty_pool_reason="scope_excluded")
        plan = self.ws.expand(spec)
        manifest = self.ws.run(spec, plan)
        self.assertEqual((manifest["outcome"], manifest["expansion_state"], manifest["empty_pool_reason"]),
                         (pr.EMPTY, ps.EMPTY, "scope_excluded"))
        self.assertEqual(manifest["instances"], ())
        self.assertNotEqual(manifest["outcome"], pr.COMPLETE)
        self.published(spec, plan)

    def test_a_missing_pool_root_and_an_unfinished_one_are_not_an_empty_pool(self):
        spec = self.ws.spec([self.ws.persona_group("reviewers", 0)])
        plan = ps.plan_expansion(spec, context=self.ws.context())
        with self.assertRaises(ps.PoolSpecError):
            self.ws.run(spec, plan)
        plan = self.ws.expand(spec)
        (self.ws.root(plan) / ps.EXPANSION_FILE).unlink()
        with self.assertRaises(ps.PoolSpecError):
            self.ws.run(spec, plan)
        self.assertEqual(support.c01.tree(self.ws.rendezvous_parent), [])

    def test_one_instance(self):
        spec, plan = self.personas(1)
        manifest = self.ws.run(spec, plan)
        self.assertEqual((support.states(manifest), manifest["outcome"]), ([pr.SUCCEEDED], pr.COMPLETE))
        self.published(spec, plan)

    def test_many_mixed_instances_keep_their_kind_their_order_and_their_own_result(self):
        self.scripted()
        spec, plan = self.mixed(3, 2)
        manifest = self.ws.run(spec, plan)
        self.assertEqual(manifest["outcome"], pr.COMPLETE)
        self.assertEqual([record["worker_kind"] for record in manifest["instances"]],
                         [ps.PERSONA] * 3 + [ps.PINNED_CONTAINER] * 2)
        for index, record in enumerate(manifest["instances"]):
            data = self.ws.result_path(plan, index).read_bytes()
            self.assertEqual(record["result_file"], {
                "path": self.ws.result_path(plan, index).relative_to(self.ws.root(plan)).as_posix(),
                "sha256": pr._bytes_sha(data), "bytes": len(data)})
            persona = record["worker_kind"] == ps.PERSONA
            self.assertEqual((record["invoker_stopped"], record["container_removed"]),
                             (True, None) if persona else (None, True))
        self.assertEqual(len({record["result_file"]["sha256"] for record in manifest["instances"]}), 5)
        self.published(spec, plan)
        self.assertEqual(support.pool_threads(), [])

    def test_the_manifest_has_no_timestamp_no_host_path_and_no_container_name(self):
        self.scripted()
        spec, plan = self.mixed(1, 1)
        self.ws.run(spec, plan)
        text = self.raw(plan).decode("utf-8")
        self.assertIsNone(re.search(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T", text))
        self.assertNotIn(str(self.ws.base), text)
        self.assertNotIn(self.temporary.name, text)
        self.assertIsNone(re.search(r"[a-z]+-[0-9a-f]{32}", text), "prefix-<hex> does not survive the redactor")
        self.assertNotIn(support.container_name(plan, 1), text)

    def test_the_returned_manifest_is_deeply_immutable(self):
        spec, plan = self.personas(1)
        for manifest in (self.ws.run(spec, plan), self.published(spec, plan)):
            with self.assertRaises(TypeError):
                manifest["outcome"] = pr.COMPLETE
            with self.assertRaises(TypeError):
                manifest["instances"][0]["state"] = pr.SUCCEEDED
            with self.assertRaises(TypeError):
                manifest["counts"]["succeeded"] = 9
            with self.assertRaises((TypeError, AttributeError)):
                manifest["instances"].append({})


# ---- adapter outcomes: failure, blocked, instance timeout, invalid, crash --------------------------

class AdapterOutcomeTests(Case):
    def test_failed_blocked_and_timed_out_instances_stay_visible_beside_the_successes(self):
        spec, plan = self.mixed(3, 3)
        ids = support.ids(plan)
        self.scripted(RoutedDocker(ScriptedDocker, {
            support.container_name(plan, 4): ScriptedDocker(client_exit=3),
            support.container_name(plan, 5): ScriptedDocker(client_exit=-9, metadata={
                "timed_out": True, "error": "TimeoutError: x"})}))
        invoker = Routed({ids[1]: b14.Raising(RuntimeError(MARKER)),
                          ids[2]: b14.Raising(pi.InvokerUnavailable(MARKER))})
        manifest = self.ws.run(spec, plan, invoker)
        self.assertEqual(support.states(manifest), [pr.SUCCEEDED, pr.FAILED, pr.BLOCKED, pr.SUCCEEDED, pr.FAILED,
                                                    pr.INSTANCE_TIMED_OUT])
        self.assertEqual([record["adapter_cause"] for record in manifest["instances"]],
                         [None, "INVOKER_EXCEPTION", "INVOKER_UNAVAILABLE", None, "CONTAINER_EXIT_NONZERO", "TIMEOUT"])
        self.assertEqual([record["adapter_status"] for record in manifest["instances"]],
                         ["OK", "FAILED", "BLOCKED", "OK", "FAILED", "FAILED"])
        self.assertEqual(manifest["outcome"], pr.DEGRADED)
        self.assertNotIn(MARKER, self.raw(plan).decode("utf-8"))
        self.published(spec, plan)

    def test_a_persona_that_exceeds_its_own_timeout_is_instance_timed_out_not_rendezvous_timed_out(self):
        group = self.ws.persona_group("reviewers", 1)
        group["persona_request"]["budget"]["timeout_seconds"] = 1
        spec = self.ws.spec([group])
        plan = self.ws.expand(spec)
        gate = Gated()
        manifest = self.ws.run(spec, plan, gate)
        wait_for(gate.finished)
        self.assertEqual(support.states(manifest), [pr.INSTANCE_TIMED_OUT])
        self.assertEqual((manifest["instances"][0]["adapter_cause"], manifest["instances"][0]["invoker_stopped"]),
                         ("TIMEOUT", True))
        self.assertEqual(manifest["outcome"], pr.POOL_FAILED)
        self.published(spec, plan)

    def test_a_pool_where_nothing_succeeded_is_FAILED(self):
        spec, plan = self.mixed(0, 2)
        self.scripted(RoutedDocker(ScriptedDocker, default=ScriptedDocker(version=1)))
        manifest = self.ws.run(spec, plan)
        self.assertEqual(support.states(manifest), [pr.BLOCKED, pr.BLOCKED])
        self.assertEqual(manifest["outcome"], pr.POOL_FAILED)
        self.published(spec, plan)

    def tampering_adapter(self, plan, index, edit):
        """The honest adapter, then exactly one departure on disk before the coordinator looks."""
        original = worker_adapters.PersonaInvocationAdapter.execute
        target = support.ids(plan)[index]

        def execute(adapter, request):
            value = original(adapter, request)
            if request.attempt_id == target:
                edit(self.ws.result_path(plan, index))
            return value
        patch = mock.patch.object(worker_adapters.PersonaInvocationAdapter, "execute", autospec=True,
                                  side_effect=execute)
        patch.start()
        self.addCleanup(patch.stop)

    def test_a_result_the_adapter_s_verifier_refuses_is_invalid_whatever_the_adapter_returned(self):
        spec, plan = self.personas(2)

        def edit(path):
            result = json.loads(path.read_text(encoding="utf-8"))
            result["input_bytes"] += 1
            result["result_sha256"] = pi.result_sha256(result)       # resealed, and still not what ran
            path.write_bytes(pi.canonical_bytes(result))
        self.tampering_adapter(plan, 1, edit)
        manifest = self.ws.run(spec, plan)
        self.assertEqual(support.states(manifest), [pr.SUCCEEDED, pr.INVALID])
        self.assertIsNone(manifest["instances"][1]["result_file"])
        self.assertEqual(manifest["outcome"], pr.DEGRADED)
        self.published(spec, plan)

    def test_an_attempt_whose_result_was_never_persisted_is_crashed(self):
        spec, plan = self.personas(2)
        self.tampering_adapter(plan, 0, lambda path: path.unlink())
        manifest = self.ws.run(spec, plan)
        self.assertEqual(support.states(manifest), [pr.CRASHED, pr.SUCCEEDED])
        self.published(spec, plan)

    def test_an_adapter_that_cannot_persist_its_result_raises_and_the_instance_is_crashed(self):
        spec, plan = self.personas(2)
        target = self.ws.result_path(plan, 1)
        real = pi.atomic_bytes

        def failing(path, data):
            if Path(path) == target:
                raise OSError(MARKER)
            return real(path, data)
        with mock.patch.object(pi, "atomic_bytes", side_effect=failing):
            manifest = self.ws.run(spec, plan)
        self.assertEqual(support.states(manifest), [pr.SUCCEEDED, pr.CRASHED])
        self.published(spec, plan)

    def test_a_worker_thread_that_cannot_start_or_dies_without_reporting_is_not_waited_for_forever(self):
        for label, seam in (("cannot start", mock.Mock(side_effect=RuntimeError("no thread"))),
                            ("never runs", mock.Mock(return_value=None))):
            with self.subTest(case=label):
                spec, plan = self.personas(3, attempt_id="attempt-" + label.split()[0], budget_class="probe")
                with mock.patch.object(pr, "_start_worker", seam), \
                        mock.patch.object(pr, "LIVENESS_BACKSTOP_SECONDS", 0.05):
                    manifest = self.ws.run(spec, plan)
                self.assertEqual(seam.call_count, 3, "a lost worker's slot is given to the next instance")
                self.assertEqual(support.states(manifest), [pr.MISSING] * 3)
                self.assertEqual([record["state_reason"] for record in manifest["instances"]],
                                 [pr.REASON_THREAD_NOT_STARTED] * 3)
                self.assertEqual(manifest["outcome"], pr.POOL_FAILED)
                self.published(spec, plan)

    def test_any_exception_from_an_adapter_s_verifier_is_invalid_in_the_coordinator_and_the_verifier(self):
        """The general rule behind a real regression: B13's verifier gained required arguments, the
        old call raised TypeError, and every container instance had to become `invalid` -- never a
        propagated exception, never a pass. Simulated here with a seam on each adapter's verifier."""
        self.scripted()
        errors = {"a changed signature": TypeError("load_verified_result() missing 1 required argument: " + MARKER),
                  "a refusal": ce.ContainerRequestError(MARKER), "an OS error": OSError(MARKER),
                  "a bug": ZeroDivisionError(MARKER)}
        for number, (label, error) in enumerate(errors.items()):
            for module, kind_index in ((pi, 0), (ce, 1)):
                with self.subTest(error=label, adapter=module.__name__):
                    spec, plan = self.mixed(1, 1, attempt_id=f"attempt-{number}-{kind_index}")
                    with mock.patch.object(module, "load_verified_result", side_effect=error):
                        manifest = self.ws.run(spec, plan)            # the coordinator: no exception escapes
                        expected = [pr.SUCCEEDED, pr.SUCCEEDED]
                        expected[kind_index] = pr.INVALID
                        self.assertEqual(support.states(manifest), expected)
                        self.assertEqual(manifest["instances"][kind_index]["state_reason"], pr.REASON_RESULT_REFUSED)
                        self.assertNotEqual(manifest["outcome"], pr.COMPLETE)
                        self.assertIsNone(manifest["instances"][kind_index]["result_file"])
                        self.assertNotIn(MARKER, self.raw(plan).decode("utf-8"))
                        self.assertEqual(self.ws.verify(spec, plan), [])
                    # the verifier, against an honest manifest, when ITS adapter call starts to raise
                    other, other_plan = self.mixed(1, 1, attempt_id=f"attempt-{number}-{kind_index}-honest")
                    self.assertEqual(self.ws.run(other, other_plan)["outcome"], pr.COMPLETE)
                    with mock.patch.object(module, "load_verified_result", side_effect=error):
                        found = self.ws.verify(other, other_plan)
                        self.assertEqual(len(found), 1)
                        self.assertIn(f"instances[{kind_index}]", found[0])
                        self.assertNotIn(MARKER, found[0])
                        with self.assertRaises(pr.RendezvousError) as caught:
                            self.ws.load(other, other_plan)
                        self.assertNotIn(MARKER, str(caught.exception))
                        record = pr.classify_instance(other_plan, kind_index, observation=pr.REPORTED,
                                                      **self.ws.classifier_arguments(other_plan))
                        self.assertEqual(record["state"], pr.INVALID)

    def test_a_success_whose_invoker_or_container_may_still_be_writing_is_never_adopted(self):
        """Second line of defence: B14 and B13 never record an OK with a live invoker or a container
        they could not remove. Should one ever verify, it is still not a success here."""
        self.scripted()
        spec, plan = self.mixed(1, 1)
        self.ws.run(spec, plan)
        real = pr._load_result
        for index, field in ((0, "invoker_stopped"), (1, "container_removed")):
            def doctored(instance, attempt_root, context, field=field, wanted=support.ids(plan)[index]):
                result = pr.thaw(real(instance, attempt_root, context))
                return pr.freeze({**result, field: False} if instance.instance_id == wanted else result)
            with self.subTest(field=field), mock.patch.object(pr, "_load_result", side_effect=doctored):
                record = pr.classify_instance(plan, index, **self.ws.classifier_arguments(plan),
                                              observation=pr.REPORTED)
                self.assertEqual((record["state"], record["state_reason"], record["result_file"]),
                                 (pr.INVALID, pr.REASON_WRITER_NOT_STOPPED, None))


# ---- cancel ---------------------------------------------------------------------------------------

class CancelTests(Case):
    def test_a_pool_cancel_mid_flight_cancels_the_running_and_accounts_for_every_instance(self):
        self.scripted()
        spec, plan = self.mixed(4, 1)                     # standard: two persona slots
        ids = support.ids(plan)
        gates = {ids[1]: Gated(), ids[2]: Gated()}
        invoker = Routed(gates)
        # instance 0 is honest and quick; 1 and 2 then hold both slots; 3 is never launched
        first = Gated()
        invoker.routes[ids[0]] = first
        running = Background(lambda: self.ws.run(spec, plan, invoker))
        wait_for(first.started)
        first.release.set()
        for gate in gates.values():
            wait_for(gate.started)
        self.assertFalse(self.ws.manifest_path(plan).exists())
        self.ws.cancel.set()
        manifest = running.result()
        found = support.states(manifest)
        self.assertEqual(found[0], pr.SUCCEEDED)
        self.assertEqual(found[1:4], [pr.CANCELED, pr.CANCELED, pr.NOT_LAUNCHED_CANCELED])
        self.assertIn(found[4], (pr.SUCCEEDED, pr.CANCELED, pr.NOT_LAUNCHED_CANCELED))
        self.assertEqual(manifest["outcome"], pr.POOL_CANCELED)
        self.assertEqual([manifest["instances"][i]["invoker_stopped"] for i in (1, 2)], [True, True])
        self.assertNotIn(ids[3], invoker.invoked)
        self.assertEqual(support.c01.tree(self.ws.instance_root(plan, 3)), [])
        self.published(spec, plan)
        self.assertEqual(support.pool_threads(), [])

    def test_a_pool_canceled_before_it_starts_launches_nothing_and_still_publishes(self):
        spec, plan = self.personas(3)
        self.ws.cancel.set()
        invoker = Routed()
        manifest = self.ws.run(spec, plan, invoker)
        self.assertEqual(support.states(manifest), [pr.NOT_LAUNCHED_CANCELED] * 3)
        self.assertEqual((manifest["outcome"], invoker.invoked), (pr.POOL_CANCELED, []))
        self.published(spec, plan)

    def test_an_interrupt_of_the_coordinator_is_a_cancel_and_is_re_raised_after_publication(self):
        spec, plan = self.personas(2, budget_class="probe")
        gate = Gated()
        real = threading.Condition
        raised = []

        class Interrupting(real):
            def wait(self, timeout=None):
                if not raised and gate.started.is_set() and threading.current_thread().name == "test-coordinator":
                    raised.append(True)
                    raise KeyboardInterrupt
                return super().wait(timeout)
        invoker = Routed({support.ids(plan)[0]: gate})
        with mock.patch.object(pr.threading, "Condition", Interrupting), \
                mock.patch.object(pr, "LIVENESS_BACKSTOP_SECONDS", 0.05):
            running = Background(lambda: self.ws.run(spec, plan, invoker))
            wait_for(gate.started)
            with self.assertRaises(KeyboardInterrupt):
                running.result()
        manifest = self.published(spec, plan)
        self.assertEqual(support.states(manifest), [pr.CANCELED, pr.NOT_LAUNCHED_CANCELED])

    def interrupting(self, when, times: int = 1):
        """A Condition whose ``wait`` raises KeyboardInterrupt in the coordinator thread, ``times``
        times, once ``when()`` holds: the operator's Ctrl-C."""
        real, raised = threading.Condition, []

        class Interrupting(real):
            def wait(inner, timeout=None):
                if len(raised) < times and threading.current_thread().name == "test-coordinator" and when():
                    raised.append(True)
                    raise KeyboardInterrupt
                return super().wait(timeout)
        return mock.patch.object(pr.threading, "Condition", Interrupting), raised

    def closing(self):
        """Patches TerminalLedger.close so that a test knows the wait has ended and the drain began."""
        state, real = {"closed": False}, pr.TerminalLedger.close

        def close(ledger):
            state["closed"] = True
            return real(ledger)
        return mock.patch.object(pr.TerminalLedger, "close", close), state

    def test_an_interrupt_during_the_drain_still_publishes_and_the_late_result_is_never_adopted(self):
        """Review of PR #35, F1, the reviewer's R2 case: the interrupt lands in a Condition.wait AFTER
        ledger.close(). Before the fix nothing was published, the KeyboardInterrupt escaped, and the
        next run adopted the late instance as `succeeded` / COMPLETE."""
        spec, plan = self.personas(1)
        gate = Gated(honor_cancel=False)
        closed, state = self.closing()
        condition, raised = self.interrupting(lambda: state["closed"])
        with condition, closed:
            running = Background(lambda: self.ws.run(spec, plan, gate, stop_grace_seconds=60,
                                                     wait_limit_seconds=0.5, drain_seconds=2))
            wait_for(gate.started)
            with self.assertRaises(KeyboardInterrupt):
                running.result()
        self.assertEqual(raised, [True], "the interrupt never landed in the drain")
        manifest = self.published(spec, plan)             # published BEFORE the interrupt was re-raised
        self.assertEqual(support.states(manifest), [pr.RENDEZVOUS_TIMED_OUT])
        self.assertEqual(manifest["instances"][0]["state_reason"], pr.REASON_WORKER_STILL_RUNNING)
        before = self.raw(plan)
        gate.release.set()                                # the late instance now finishes, validly
        wait_for(gate.finished)
        support.join_pool_threads()
        self.ws.cancel = pr.PoolCancel()
        invoker = Routed()
        with self.assertRaises(pr.RendezvousPublishedError):
            self.ws.run(spec, plan, invoker)              # R2: this used to publish ['succeeded'] COMPLETE
        self.assertEqual((self.raw(plan), invoker.invoked), (before, []))
        self.assertEqual(support.states(self.published(spec, plan)), [pr.RENDEZVOUS_TIMED_OUT])

    def test_a_second_interrupt_cuts_the_drain_short_and_the_manifest_is_still_published(self):
        spec, plan = self.personas(1)
        gate = Gated(honor_cancel=False)
        closed, state = self.closing()
        condition, raised = self.interrupting(lambda: state["closed"], times=2)
        with condition, closed:
            running = Background(lambda: self.ws.run(spec, plan, gate, stop_grace_seconds=60,
                                                     wait_limit_seconds=0.5, drain_seconds=pr.DRAIN_BOUNDS[1]))
            wait_for(gate.started)
            with self.assertRaises(KeyboardInterrupt):
                running.result()                          # bounded by HANG_SECONDS, far below the 180 s drain
        self.assertEqual(raised, [True, True])
        self.assertEqual(support.states(self.published(spec, plan)), [pr.RENDEZVOUS_TIMED_OUT])
        gate.release.set()
        wait_for(gate.finished)

    def test_an_interrupt_anywhere_after_the_launch_is_held_until_publication(self):
        """Derivation, validation and publication are inside the held section too, and entering
        publication again links nothing twice."""
        seams = {"derive": (pr, "derive_manifest"), "validate": (pr, "manifest_errors"),
                 "before the link": (pr.os, "link"), "after the link": (pr.os, "link"),
                 "system exit": (pr, "derive_manifest")}
        for number, (label, (owner, name)) in enumerate(seams.items()):
            with self.subTest(interrupt=label):
                spec, plan = self.personas(1, attempt_id=f"attempt-held-{number}")
                real, raised = getattr(owner, name), []

                def interrupted(*args, real=real, raised=raised, label=label, **kwargs):
                    if not raised:
                        raised.append(True)
                        if label == "after the link":
                            real(*args, **kwargs)
                        raise SystemExit(3) if label == "system exit" else KeyboardInterrupt
                    return real(*args, **kwargs)
                with mock.patch.object(owner, name, side_effect=interrupted), \
                        self.assertRaises(SystemExit if label == "system exit" else KeyboardInterrupt):
                    self.ws.run(spec, plan)
                self.assertEqual(raised, [True])
                self.assertTrue(self.ws.cancel.is_set(), "an interrupt is a pool cancel")
                self.assertEqual(support.states(self.published(spec, plan)), [pr.SUCCEEDED])
                self.assertEqual(os.listdir(pr.rendezvous_root(plan, self.ws.rendezvous_parent)), [pr.MANIFEST_FILE])
                self.ws.cancel = pr.PoolCancel()

    def test_an_interrupt_that_lands_in_a_worker_s_start_is_not_launched_and_never_timed_out(self):
        """Review of PR #35, Q4: between taking an instance off the pending list and starting its
        thread. It used to be published as `rendezvous_timed_out` with `worker_stopped: false` for a
        worker that never existed."""
        for label, start_anyway in (("before the thread starts", False), ("after the thread started", True)):
            with self.subTest(interrupt=label):
                spec, plan = self.personas(2, budget_class="probe", attempt_id="attempt-" + label.split()[0])
                raised, invoker = [], Routed()

                def start(thread, raised=raised, start_anyway=start_anyway):
                    if not raised:
                        raised.append(True)
                        if start_anyway:
                            thread.start()
                        raise KeyboardInterrupt
                    thread.start()
                with mock.patch.object(pr, "_start_worker", side_effect=start), \
                        mock.patch.object(pr, "LIVENESS_BACKSTOP_SECONDS", 0.05), \
                        self.assertRaises(KeyboardInterrupt):
                    self.ws.run(spec, plan, invoker)
                manifest = self.published(spec, plan)
                support.join_pool_threads()
                found = support.states(manifest)
                self.assertEqual(found[1], pr.NOT_LAUNCHED_CANCELED)
                if not start_anyway:
                    self.assertEqual((found[0], invoker.invoked), (pr.NOT_LAUNCHED_CANCELED, []))
                # started: it either passed the launch gate before the cancel (and then ran and was
                # canceled by its adapter) or it did not (and then launched nothing); never in between
                self.assertIn(found[0], (pr.NOT_LAUNCHED_CANCELED, pr.CANCELED, pr.SUCCEEDED))
                self.assertEqual(found[0] == pr.NOT_LAUNCHED_CANCELED, invoker.invoked == [])
                self.assertNotIn(pr.RENDEZVOUS_TIMED_OUT, found)
                self.ws.cancel = pr.PoolCancel()

    def test_an_interrupt_storm_is_given_back_instead_of_being_held_for_ever(self):
        spec, plan = self.personas(1)
        with mock.patch.object(pr, "derive_manifest", side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self.ws.run(spec, plan)
        self.assertFalse(self.ws.manifest_path(plan).exists())

    def test_a_stuck_invoker_is_recorded_as_not_stopped_and_its_later_output_is_never_adopted(self):
        spec, plan = self.personas(1)
        gate = Gated(honor_cancel=False)
        running = Background(lambda: self.ws.run(spec, plan, gate, stop_grace_seconds=0))
        wait_for(gate.started)
        self.ws.cancel.set()
        manifest = running.result()
        record = manifest["instances"][0]
        self.assertEqual((record["state"], record["adapter_cause"], record["invoker_stopped"]),
                         (pr.CANCELED, "CANCELED", False))
        before = self.raw(plan)
        gate.release.set()                                  # the invoker now writes a complete, honest output
        wait_for(gate.finished)
        self.assertTrue((self.ws.instance_root(plan, 0) / "outputs" / "persona" / pi.MANIFEST_FILE).is_file())
        self.assertEqual(self.raw(plan), before)
        loaded = self.published(spec, plan)
        self.assertEqual(loaded["instances"][0]["state"], pr.CANCELED)
        self.assertNotEqual(loaded["outcome"], pr.COMPLETE)


# ---- rendezvous timeout and late finish -------------------------------------------------------------

class Blocking(ScriptedDocker):
    """B13's scripted docker client, except that it does not come back until released. It ignores
    the cancel it is handed, which is what makes a LATE, VALID, OK result possible."""

    def __init__(self, **over):
        super().__init__(**over)
        self.started, self.release = threading.Event(), threading.Event()

    def before_child(self, cancel):
        self.started.set()
        self.release.wait(HANG_SECONDS)


class LateFinishTests(Case):
    def test_an_instance_that_finishes_after_the_wait_ended_is_recorded_as_such_and_never_adopted(self):
        spec, plan = self.mixed(1, 2)
        blocking = Blocking()
        self.scripted(RoutedDocker(ScriptedDocker, {support.container_name(plan, 1): blocking}))
        manifest = self.ws.run(spec, plan, wait_limit_seconds=0.3, drain_seconds=0)
        self.assertTrue(blocking.started.is_set())
        self.assertEqual(support.states(manifest), [pr.SUCCEEDED, pr.RENDEZVOUS_TIMED_OUT,
                                                    pr.NOT_LAUNCHED_RENDEZVOUS_TIMEOUT])
        late = manifest["instances"][1]
        self.assertEqual((late["worker_stopped"], late["result_file"], late["adapter_status"]), (False, None, None))
        self.assertEqual(manifest["outcome"], pr.DEGRADED)
        self.assertTrue(self.ws.cancel.is_set(), "the coordinator stops what it no longer waits for")
        before = self.raw(plan)
        self.published(spec, plan)

        blocking.release.set()                          # ... and now the late instance finishes, validly
        support.join_pool_threads()
        late_instance = plan.instances[1]
        self.assertEqual(ce.verify_container_result(
            late_instance.attempt_root_path(self.ws.root(plan)), **late_instance.ids,
            request=late_instance.request.request, **self.ws.context().container_verification_arguments()), [])
        self.assertEqual(json.loads(self.ws.result_path(plan, 1).read_text(encoding="utf-8"))["execution_status"], "OK")
        self.assertEqual(self.raw(plan), before, "the published manifest changed")
        loaded = self.published(spec, plan)
        self.assertEqual(support.states(loaded)[1], pr.RENDEZVOUS_TIMED_OUT)
        self.assertEqual(support.c01.tree(self.ws.instance_root(plan, 2)), [], "launched after the wait ended")
        with self.assertRaises(pr.RendezvousPublishedError):
            self.ws.run(spec, plan)
        self.assertEqual(self.raw(plan), before, "a second run adopted the late result")

    def test_a_late_terminal_report_is_refused_by_the_closed_ledger(self):
        ledger = pr.TerminalLedger(["a", "b"])
        ledger.report("a")
        self.assertEqual(ledger.close(), frozenset({"a"}))
        with self.assertRaises(pr.RendezvousError):
            ledger.report("b")
        self.assertEqual(ledger.reported, frozenset({"a"}))

    def test_a_worker_that_winds_down_within_the_drain_is_recorded_as_stopped_and_still_not_adopted(self):
        spec, plan = self.personas(2, budget_class="probe")
        gate = Gated()                                   # honours the cancel the coordinator sets
        invoker = Routed({support.ids(plan)[0]: gate})
        manifest = self.ws.run(spec, plan, invoker, wait_limit_seconds=0.3, drain_seconds=30)
        self.assertEqual(support.states(manifest), [pr.RENDEZVOUS_TIMED_OUT, pr.NOT_LAUNCHED_RENDEZVOUS_TIMEOUT])
        self.assertIs(manifest["instances"][0]["worker_stopped"], True)
        self.assertEqual(manifest["outcome"], pr.POOL_FAILED)
        self.assertEqual(support.pool_threads(), [])
        # B14 wrote a valid CANCELED result while winding down. It is on disk, and it is not adopted.
        self.assertEqual(json.loads(self.ws.result_path(plan, 0).read_text(encoding="utf-8"))["cause"], "CANCELED")
        self.assertIsNone(manifest["instances"][0]["result_file"])
        self.published(spec, plan)

    def test_the_runtime_can_only_narrow_the_specification_s_rendezvous_timeout(self):
        spec, plan = self.personas(1, rendezvous_timeout_seconds=30)
        gate = Gated()
        # 29 s into a 30 s specification timeout until the instance is really running, then 31 s
        clock = lambda: 1031.0 if gate.started.is_set() else 1029.0       # noqa: E731
        with mock.patch.object(pr.time, "monotonic", side_effect=iter_then([1000.0], clock)), \
                mock.patch.object(pr, "LIVENESS_BACKSTOP_SECONDS", 0.05):
            manifest = self.ws.run(spec, plan, gate, wait_limit_seconds=3600, drain_seconds=0)
        gate.release.set()
        self.assertEqual(support.states(manifest), [pr.RENDEZVOUS_TIMED_OUT])
        self.assertEqual(manifest["instances"][0]["state_reason"], pr.REASON_WORKER_STILL_RUNNING)


# ---- publication never occurs early -----------------------------------------------------------------

class PublicationTests(Case):
    def test_no_manifest_exists_at_any_moment_before_the_last_instance_is_terminal(self):
        spec, plan = self.personas(3, budget_class="deep")
        ids = support.ids(plan)
        root = pr.rendezvous_root(plan, self.ws.rendezvous_parent)
        seen: list = []

        class Watching(pi.FixtureInvoker):
            def invoke(inner, package, *, output_root, cancel):
                seen.append(sorted(os.listdir(root)))
                super().invoke(package, output_root=output_root, cancel=cancel)
                seen.append(sorted(os.listdir(root)))
        gate = Gated(before=lambda: seen.append(sorted(os.listdir(root))))
        done = {name: threading.Event() for name in ids}
        original = worker_adapters.PersonaInvocationAdapter.execute

        def execute(adapter, request):
            try:
                return original(adapter, request)
            finally:
                done[request.attempt_id].set()
        at_publication: list = []
        real_publish = pr._publish

        def publish(target, data):
            at_publication.append([self.ws.result_path(plan, index).is_file() for index in range(3)])
            return real_publish(target, data)
        with mock.patch.object(worker_adapters.PersonaInvocationAdapter, "execute", autospec=True,
                               side_effect=execute), mock.patch.object(pr, "_publish", side_effect=publish):
            running = Background(lambda: self.ws.run(spec, plan, Routed({ids[2]: gate}, default=Watching())))
            wait_for(gate.started)
            wait_for(done[ids[0]])
            wait_for(done[ids[1]])
            # two of three are terminal on disk, the third is running: nothing may be published
            self.assertEqual(os.listdir(root), [])
            self.assertEqual(self.ws.verify(spec, plan),
                             ["the rendezvous root does not hold exactly the terminal-instance manifest"])
            self.assertEqual(at_publication, [])
            gate.release.set()
            manifest = running.result()
        self.assertEqual(seen, [[]] * 5)
        self.assertEqual(at_publication, [[True, True, True]], "published once, after every result was on disk")
        self.assertEqual(manifest["outcome"], pr.COMPLETE)
        self.assertEqual(os.listdir(root), [pr.MANIFEST_FILE])
        self.published(spec, plan)

    def test_a_crash_between_the_last_terminal_state_and_publication_leaves_no_manifest(self):
        spec, plan = self.personas(2)
        root = pr.rendezvous_root(plan, self.ws.rendezvous_parent)
        for label, seam in (("before the link", mock.patch.object(pr.os, "link", side_effect=OSError(MARKER))),
                            ("while writing", mock.patch.object(pr.os, "fsync", side_effect=OSError(MARKER)))):
            with self.subTest(crash=label):
                with seam, self.assertRaises(OSError):
                    self.ws.run(spec, plan)
                self.assertEqual(os.listdir(root), [], "a partial manifest or a temporary file was left")
                self.assertNotEqual(self.ws.verify(spec, plan), [])
                with self.assertRaises(pr.RendezvousError):
                    self.ws.load(spec, plan)
        invoker = Routed()
        manifest = self.ws.run(spec, plan, invoker)          # the restart publishes what is on disk
        self.assertEqual((support.states(manifest), invoker.invoked), ([pr.SUCCEEDED] * 2, []))
        self.published(spec, plan)

    def test_a_manifest_that_would_not_verify_is_not_published(self):
        spec, plan = self.personas(1)
        with mock.patch.object(pr, "manifest_errors", return_value=["x"]), self.assertRaises(pr.RendezvousError):
            self.ws.run(spec, plan)
        self.assertEqual(os.listdir(pr.rendezvous_root(plan, self.ws.rendezvous_parent)), [])

    def test_publication_is_exclusive_all_or_nothing_and_never_replaces(self):
        root = self.ws.rendezvous_parent / "direct"
        root.mkdir()
        pr._publish(root, b"first")
        with self.assertRaises(pr.RendezvousPublishedError):
            pr._publish(root, b"second")
        self.assertEqual(((root / pr.MANIFEST_FILE).read_bytes(), os.listdir(root)), (b"first", [pr.MANIFEST_FILE]))
        self.assertEqual(os.stat(root / pr.MANIFEST_FILE).st_nlink, 1)


# ---- restart ---------------------------------------------------------------------------------------

class RestartTests(Case):
    def kill_coordinator_inside(self, spec, plan, index: int) -> None:
        """A real coordinator in its own process, killed (SIGKILL) while instance ``index`` runs."""
        process = subprocess.Popen(support.coordinator_command(self.ws, spec, support.ids(plan)[index]),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        guard = threading.Timer(HANG_SECONDS, process.kill)
        guard.start()
        try:
            line = process.stdout.readline()
            process.kill()
            _, stderr = process.communicate(timeout=HANG_SECONDS)
        finally:
            guard.cancel()
        self.assertEqual(line.strip(), b"BLOCKED", stderr.decode("utf-8", "replace")[-2000:])

    def test_a_second_run_adopts_the_terminal_classifies_the_half_written_and_launches_only_the_rest(self):
        spec, plan = self.personas(4)
        ids = support.ids(plan)
        self.kill_coordinator_inside(spec, plan, 2)
        self.assertFalse(self.ws.manifest_path(plan).exists())
        half = support.c01.tree(self.ws.instance_root(plan, 2))
        self.assertIn("logs/persona/request.json", half)
        self.assertNotIn("logs/persona/" + pi.RESULT_FILE, half)
        self.assertEqual(support.c01.tree(self.ws.instance_root(plan, 3)), [])
        before = {index: self.ws.result_path(plan, index).read_bytes() for index in (0, 1)}

        invoker = Routed()
        manifest = self.ws.run(spec, plan, invoker)
        self.assertEqual(support.states(manifest), [pr.SUCCEEDED, pr.SUCCEEDED, pr.CRASHED, pr.SUCCEEDED])
        self.assertEqual(invoker.invoked, [ids[3]], "a terminal or half-written instance was relaunched")
        self.assertEqual({index: self.ws.result_path(plan, index).read_bytes() for index in (0, 1)}, before)
        self.assertEqual(support.c01.tree(self.ws.instance_root(plan, 2)), half, "relaunched into a half-written root")
        self.assertEqual(manifest["outcome"], pr.DEGRADED)
        self.published(spec, plan)
        derived = pr.derive_manifest(plan, **self.ws.classifier_arguments(plan),
                                     observations=[pr.REPORTED] * 4)
        self.assertEqual(self.raw(plan), pr.canonical_bytes(derived))

    def test_a_restart_publishes_the_bytes_an_uninterrupted_run_publishes(self):
        """Same specification, same clock, two hosts' worth of directories: one coordinator died
        after two instances, the other never did. No timestamp, host path or run history is in the
        manifest, so the bytes are equal."""
        other_directory = tempfile.TemporaryDirectory()
        self.addCleanup(other_directory.cleanup)
        other = support.RendezvousWorkspace(Path(other_directory.name).resolve())
        published = []
        for ws, interrupted in ((self.ws, True), (other, False)):
            spec = ws.spec([ws.persona_group("reviewers", 4)])
            plan = ws.expand(spec)
            if interrupted:        # exactly what a coordinator does for an instance, and then it is gone
                adapter = worker_adapters.PersonaInvocationAdapter(
                    pr.adapter_runtimes(plan, ws.context(), ws.runtime())[ps.PERSONA])
                for instance in plan.instances[:2]:
                    adapter.execute(worker_adapters.WorkerRequest(
                        **instance.ids, attempt_root=instance.attempt_root_path(ws.root(plan)),
                        inputs={"persona_request": instance.request.request}))
            invoker = Routed()
            ws.run(spec, plan, invoker)
            self.assertEqual(len(invoker.invoked), 2 if interrupted else 4)
            published.append(ws.manifest_path(plan).read_bytes())
        self.assertEqual(published[0], published[1])

    def test_what_a_dead_coordinator_s_publication_left_is_cleared_or_finished_never_trusted(self):
        spec, plan = self.personas(1)
        root = pr.rendezvous_root(plan, self.ws.rendezvous_parent)
        root.mkdir()
        stale = root / ".terminal-instances.0123456789ab.tmp"
        stale.write_bytes(b'{"outcome": "COMPLETE"}')
        manifest = self.ws.run(spec, plan)
        self.assertEqual((support.states(manifest), os.listdir(root)), ([pr.SUCCEEDED], [pr.MANIFEST_FILE]))
        # killed between the link and the unlink: the manifest is complete but has two names
        os.link(self.ws.manifest_path(plan), stale)
        self.assertEqual(self.ws.verify(spec, plan),
                         ["the rendezvous root does not hold exactly the terminal-instance manifest"])
        before = self.raw(plan)
        with self.assertRaises(pr.RendezvousPublishedError):
            self.ws.run(spec, plan)
        self.assertEqual((self.raw(plan), os.listdir(root)), (before, [pr.MANIFEST_FILE]))
        self.published(spec, plan)

    def test_a_rendezvous_root_that_holds_something_foreign_is_refused(self):
        spec, plan = self.personas(1)
        root = pr.rendezvous_root(plan, self.ws.rendezvous_parent)
        root.mkdir()
        (root / "notes.json").write_bytes(b"{}")
        invoker = Routed()
        with self.assertRaises(pr.RendezvousError):
            self.ws.run(spec, plan, invoker)
        self.assertEqual((invoker.invoked, os.listdir(root)), ([], ["notes.json"]))
        if SYMLINKS:
            spec, plan = self.personas(1, attempt_id="attempt-linked")
            elsewhere = self.ws.base / "elsewhere"
            elsewhere.mkdir()
            pr.rendezvous_root(plan, self.ws.rendezvous_parent).symlink_to(elsewhere, target_is_directory=True)
            with self.assertRaises(pr.RendezvousError):
                self.ws.run(spec, plan, invoker)
            self.assertEqual((invoker.invoked, os.listdir(elsewhere)), ([], []))


# ---- duplicate terminal ----------------------------------------------------------------------------

class DuplicateTerminalTests(Case):
    def test_the_ledger_refuses_an_unknown_instance_and_a_second_report_and_keeps_the_first(self):
        ledger = pr.TerminalLedger(["a", "b"])
        ledger.report("a")
        for hostile in ("a", "c", MARKER, None):
            with self.subTest(report=hostile), self.assertRaises(pr.RendezvousError) as caught:
                ledger.report(hostile)
            self.assertNotIn(MARKER, str(caught.exception))
        self.assertEqual(ledger.reported, frozenset({"a"}))
        with self.assertRaises(pr.RendezvousError):
            pr.TerminalLedger(["a", "a"])

    def test_a_second_run_after_publication_fails_closed_and_launches_nothing(self):
        spec, plan = self.personas(2)
        self.ws.run(spec, plan)
        before, stamp = self.raw(plan), os.stat(self.ws.manifest_path(plan))
        invoker = Routed()
        with mock.patch.object(pr, "_wait", wraps=pr._wait) as waited, \
                self.assertRaises(pr.RendezvousPublishedError) as caught:
            self.ws.run(spec, plan, invoker)
        self.assertEqual(waited.call_count, 0, "refused only at the link, after waiting again")
        self.assertIn("never replaced", str(caught.exception))
        after = os.stat(self.ws.manifest_path(plan))
        self.assertEqual((self.raw(plan), invoker.invoked), (before, []))
        self.assertEqual((after.st_ino, after.st_mtime_ns), (stamp.st_ino, stamp.st_mtime_ns))

    def test_a_second_coordinator_racing_the_first_launches_nothing_and_publishes_nothing(self):
        spec, plan = self.personas(2)
        gate = Gated()
        first = Routed({support.ids(plan)[0]: gate})
        running = Background(lambda: self.ws.run(spec, plan, first))
        wait_for(gate.started)
        second = Routed()
        other = pr.PoolCancel()
        with self.assertRaises(pr.RendezvousBusyError) as caught:
            self.ws.run(spec, plan, second, cancel=other)
        self.assertNotIn(str(self.ws.base), str(caught.exception))
        self.assertEqual(second.invoked, [])
        self.assertFalse(self.ws.manifest_path(plan).exists())
        gate.release.set()
        manifest = running.result()
        self.assertEqual(manifest["outcome"], pr.COMPLETE)
        self.published(spec, plan)

    def test_two_coordinators_started_together_publish_exactly_one_manifest_and_launch_each_instance_once(self):
        spec, plan = self.personas(3)
        barrier = threading.Barrier(2)
        invokers = [Routed(), Routed()]

        def coordinator(invoker):
            cancel = pr.PoolCancel()
            barrier.wait(HANG_SECONDS)
            return self.ws.run(spec, plan, invoker, cancel=cancel)
        running = [Background(lambda invoker=invoker: coordinator(invoker)) for invoker in invokers]
        outcomes = []
        for background in running:
            try:
                outcomes.append(background.result()["outcome"])
            except (pr.RendezvousBusyError, pr.RendezvousPublishedError) as exc:
                outcomes.append(type(exc))
        self.assertEqual(outcomes.count(pr.COMPLETE), 1, outcomes)
        self.assertEqual(sorted(invokers[0].invoked + invokers[1].invoked), sorted(support.ids(plan)))
        self.published(spec, plan)

    def test_a_manifest_with_a_duplicate_unknown_reordered_or_absent_instance_is_refused(self):
        spec, plan = self.personas(3)
        self.ws.run(spec, plan)
        honest = self.raw(plan)

        def recount(manifest):
            found = [record["state"] for record in manifest["instances"]]
            manifest["counts"] = {"instances": len(found), **{state: found.count(state) for state in pr.STATES}}
        edits = {
            "duplicate": lambda m: m["instances"].append(deepcopy(m["instances"][0])),
            "duplicate in place": lambda m: m["instances"].__setitem__(1, deepcopy(m["instances"][0])),
            "unknown": lambda m: m["instances"][2].update(instance_id="0" * 32, attempt_root="instances/" + "0" * 32),
            "reordered": lambda m: m["instances"].reverse(),
            "absent": lambda m: m["instances"].pop(),
            "empty success": lambda m: (m["instances"].clear(), m.update(outcome=pr.COMPLETE)),
        }
        for label, edit in edits.items():
            with self.subTest(edit=label):
                self.reseal(plan, lambda m, edit=edit: (edit(m), recount(m)))
                errors = self.ws.verify(spec, plan)
                self.assertEqual(len(errors), 1)
                self.assertIn("each once and in order", errors[0])
                self.ws.manifest_path(plan).write_bytes(honest)
        self.assertEqual(self.ws.verify(spec, plan), [])


# ---- missing instance -------------------------------------------------------------------------------

class MissingInstanceTests(Case):
    def test_only_damage_to_one_expected_root_is_left_to_classification_and_it_is_selected_by_code(self):
        spec, plan = self.personas(2)
        arguments = self.ws.arguments(spec)
        shutil.rmtree(self.ws.instance_root(plan, 1))
        codes = [finding.code for finding in ps.check_expansion(self.ws.root(plan), **arguments).findings]
        self.assertEqual(codes, [ps.CODE_INSTANCE_ROOT_MISSING])
        self.assertEqual(pr.expansion_errors(self.ws.root(plan), **arguments), [])
        if SYMLINKS:
            self.ws.instance_root(plan, 1).symlink_to(self.ws.instance_root(plan, 0), target_is_directory=True)
            codes = [finding.code for finding in ps.check_expansion(self.ws.root(plan), **arguments).findings]
            self.assertEqual(codes, [ps.CODE_INSTANCE_ROOT_NOT_PRIVATE])
            self.assertEqual(pr.expansion_errors(self.ws.root(plan), **arguments), [])
        (self.ws.root(plan) / ps.SPEC_FILE).write_bytes(b"{}")
        self.assertEqual(len(pr.expansion_errors(self.ws.root(plan), **arguments)), 1)
        source = inspect.getsource(pr)
        self.assertNotIn("verify_expansion(", source, "findings are selected by code, from one check")
        self.assertEqual(source.count("plan_expansion("), 0, "the verifier derives the plan a second time")

    def test_a_pool_root_change_the_executor_refuses_is_refused_by_the_verifier_too(self):
        """Review of PR #35, F2 (the reviewer's R1 case first): executor and verifier apply one rule.
        Only a deleted or replaced EXPECTED root is an instance outcome."""
        def extra_root(ws, plan):
            extra = ws.root(plan) / ps.INSTANCES_DIR / ("f" * 32)
            extra.mkdir()
            (extra / "planted.txt").write_text("x", encoding="utf-8")

        def instances_not_a_directory(ws, plan):
            directory = ws.root(plan) / ps.INSTANCES_DIR
            directory.rename(ws.base / "moved-instances")
            directory.write_bytes(b"")

        def instances_is_a_link(ws, plan):
            directory = ws.root(plan) / ps.INSTANCES_DIR
            directory.rename(ws.base / "moved-instances")
            directory.symlink_to(ws.base / "moved-instances", target_is_directory=True)

        cases = [("an unexpected extra root", extra_root, ps.CODE_INSTANCE_ROOT_UNEXPECTED),
                 ("instances is a file", instances_not_a_directory, ps.CODE_INSTANCES_NOT_DIRECTORY)]
        if SYMLINKS:
            cases.append(("instances is a link", instances_is_a_link, ps.CODE_INSTANCES_NOT_DIRECTORY))
        for number, (label, damage, code) in enumerate(cases):
            with self.subTest(case=label):
                directory = tempfile.TemporaryDirectory()
                self.addCleanup(directory.cleanup)
                ws = support.RendezvousWorkspace(Path(directory.name).resolve())
                spec, plan = ws.spec([ws.persona_group("reviewers", 2)]), None
                plan = ws.expand(spec)
                ws.run(spec, plan)
                self.assertEqual(ws.verify(spec, plan), [])
                damage(ws, plan)
                codes = [finding.code for finding in ps.check_expansion(ws.root(plan), **ws.arguments(spec)).findings]
                self.assertIn(code, codes)
                errors = ws.verify(spec, plan)
                self.assertEqual(len(errors), 1)
                self.assertIn("the pool expansion does not verify", errors[0])
                with self.assertRaises(pr.RendezvousError):
                    ws.load(spec, plan)
                # ... exactly as the executor refuses the same pool root
                other = support.RendezvousWorkspace.__new__(support.RendezvousWorkspace)
                other.__dict__.update(ws.__dict__)
                other.rendezvous_parent = ws.base / "second-rendezvous"
                other.rendezvous_parent.mkdir()
                other.cancel = pr.PoolCancel()
                with self.assertRaises(ps.PoolSpecError):
                    other.run(spec, plan)

    def test_every_c01_finding_code_but_the_two_damage_codes_refuses_the_manifest(self):
        """Shared roots (``instance_roots_shared``) cannot be staged without a link, which is itself
        ``not private``; so the rule is pinned over C01's whole closed code list, through its public
        ``check_expansion``: exactly ``INSTANCE_ROOT_DAMAGE_CODES`` is tolerated."""
        spec, plan = self.personas(2)
        self.ws.run(spec, plan)
        honest = ps.check_expansion(self.ws.root(plan), **self.ws.arguments(spec))
        self.assertEqual(honest.findings, ())
        self.assertEqual(ps.INSTANCE_ROOT_DAMAGE_CODES,
                         {ps.CODE_INSTANCE_ROOT_MISSING, ps.CODE_INSTANCE_ROOT_NOT_PRIVATE})
        for code in ps.FINDING_CODES:
            finding = ps.ExpansionFinding(code, "fixed text for " + code, None)
            with self.subTest(code=code), mock.patch.object(
                    ps, "check_expansion", return_value=ps.ExpansionCheck(honest.plan, (finding,))):
                errors = self.ws.verify(spec, plan)
                if code in ps.INSTANCE_ROOT_DAMAGE_CODES:
                    self.assertEqual(errors, [])
                else:
                    self.assertEqual(errors, ["the pool expansion does not verify: fixed text for " + code])
                    with self.assertRaises(pr.RendezvousError):
                        self.ws.load(spec, plan)

    def test_an_instance_whose_root_disappears_is_missing_and_is_never_launched_into(self):
        spec, plan = self.personas(3, budget_class="probe")         # one slot: strictly one after another
        ids = support.ids(plan)

        class Deleting(pi.FixtureInvoker):
            def invoke(inner, package, *, output_root, cancel):
                shutil.rmtree(self.ws.instance_root(plan, 2))
                super().invoke(package, output_root=output_root, cancel=cancel)
        invoker = Routed({ids[0]: Deleting()})
        manifest = self.ws.run(spec, plan, invoker)
        self.assertEqual(support.states(manifest), [pr.SUCCEEDED, pr.SUCCEEDED, pr.MISSING])
        self.assertEqual(manifest["instances"][2]["state_reason"], pr.REASON_ROOT_ABSENT)
        self.assertEqual((manifest["outcome"], invoker.invoked), (pr.DEGRADED, ids[:2]))
        self.assertFalse(self.ws.instance_root(plan, 2).exists(), "the adapter was launched and rebuilt the root")
        self.published(spec, plan)

    def test_a_root_replaced_by_a_link_or_already_holding_something_is_never_launched_into(self):
        spec, plan = self.personas(3, budget_class="probe")
        ids = support.ids(plan)
        elsewhere = self.ws.base / "elsewhere"
        elsewhere.mkdir()

        class Replacing(pi.FixtureInvoker):
            def invoke(inner, package, *, output_root, cancel):
                (self.ws.instance_root(plan, 1) / "planted.json").write_bytes(b"{}")
                if SYMLINKS:
                    self.ws.instance_root(plan, 2).rmdir()
                    self.ws.instance_root(plan, 2).symlink_to(elsewhere, target_is_directory=True)
                super().invoke(package, output_root=output_root, cancel=cancel)
        invoker = Routed({ids[0]: Replacing()})
        executed = []
        original = worker_adapters.PersonaInvocationAdapter.execute

        def execute(adapter, request):
            executed.append(request.attempt_id)
            return original(adapter, request)
        with mock.patch.object(worker_adapters.PersonaInvocationAdapter, "execute", autospec=True,
                               side_effect=execute):
            manifest = self.ws.run(spec, plan, invoker)
        self.assertEqual(executed, ids[:1] if SYMLINKS else [ids[0], ids[2]], "an adapter was handed a bad root")
        self.assertEqual(support.states(manifest), [pr.SUCCEEDED, pr.CRASHED, pr.INVALID if SYMLINKS else pr.SUCCEEDED])
        self.assertEqual(invoker.invoked, ids[:1] if SYMLINKS else [ids[0], ids[2]])
        self.assertEqual(manifest["instances"][1]["state_reason"], pr.REASON_NO_RESULT_FILE)
        if SYMLINKS:
            self.assertEqual(manifest["instances"][2]["state_reason"], pr.REASON_ROOT_NOT_PRIVATE)
        self.assertEqual(os.listdir(elsewhere), [])
        self.assertEqual(support.c01.tree(self.ws.instance_root(plan, 1)), ["planted.json"])
        self.published(spec, plan)

    def test_a_worker_that_returns_success_and_leaves_nothing_on_disk_is_missing_never_a_success(self):
        spec, plan = self.personas(2)
        with mock.patch.object(worker_adapters.PersonaInvocationAdapter, "execute", autospec=True,
                               return_value={"execution_status": "OK", "cause": None}):
            manifest = self.ws.run(spec, plan)
        self.assertEqual(support.states(manifest), [pr.MISSING, pr.MISSING])
        self.assertEqual([record["state_reason"] for record in manifest["instances"]], [pr.REASON_NO_EVIDENCE] * 2)
        self.assertEqual(manifest["outcome"], pr.POOL_FAILED)
        self.published(spec, plan)

    def test_an_adopted_instance_that_disappears_after_publication_stops_the_manifest_verifying(self):
        spec, plan = self.personas(2)
        self.ws.run(spec, plan)
        shutil.rmtree(self.ws.instance_root(plan, 0))
        errors = self.ws.verify(spec, plan)
        self.assertEqual(len(errors), 1)
        self.assertIn("instances[0]", errors[0])


# ---- concurrency ------------------------------------------------------------------------------------

class Counting(pi.FixtureInvoker):
    """Honest, and meets ``parties`` other invocations at a barrier first: that many really do run
    at once, and ``peak`` is the most that ever did."""

    def __init__(self, parties: int) -> None:
        self.barrier = threading.Barrier(parties)
        self.guard, self.now, self.peak = threading.Lock(), 0, 0

    def invoke(self, package, *, output_root, cancel):
        with self.guard:
            self.now += 1
            self.peak = max(self.peak, self.now)
        try:
            self.barrier.wait(HANG_SECONDS)
            super().invoke(package, output_root=output_root, cancel=cancel)
        finally:
            with self.guard:
                self.now -= 1


class ConcurrencyTests(Case):
    def test_personas_in_flight_never_exceed_the_recorded_slot_request(self):
        for budget_class, slots in rp.PERSONA_BUDGET_CELLS.items():
            with self.subTest(budget_class=budget_class):
                spec, plan = self.personas(slots * 2, budget_class=budget_class, attempt_id="attempt-" + budget_class)
                self.assertEqual(plan.manifest["totals"]["persona_slot_request"], slots)
                invoker = Counting(slots)
                manifest = self.ws.run(spec, plan, invoker)
                self.assertEqual((manifest["outcome"], invoker.peak), (pr.COMPLETE, slots))

    def test_the_runtime_s_overall_bound_narrows_everything(self):
        spec, plan = self.personas(4, budget_class="deep")
        invoker = Counting(1)
        manifest = self.ws.run(spec, plan, invoker, max_parallel=1)
        self.assertEqual((manifest["outcome"], invoker.peak), (pr.COMPLETE, 1))

    def test_a_slot_request_can_never_raise_the_persona_pool_limit(self):
        spec, plan = self.personas(1)
        forged = pr.thaw(plan.manifest)
        forged["totals"]["persona_slot_request"] = 99
        forged["totals"]["resource_pools"] = [{"resource_pool": rp.PERSONA_LLM, "instances": 99}]
        limits = pr._limits(mock.Mock(manifest=forged), self.ws.runtime())
        self.assertEqual(limits, (pr.MAX_PARALLEL, rp.LIMITS[rp.PERSONA_LLM], {rp.PERSONA_LLM: rp.LIMITS[rp.PERSONA_LLM]}))

    def test_tool_instances_never_overlap_beyond_the_docker_pool_limit(self):
        spec, plan = self.mixed(0, 3)
        log, guard = [], threading.Lock()
        started = [threading.Event() for _ in range(3)]

        class Logging(ScriptedDocker):
            def __init__(inner, index):
                super().__init__()
                inner.index = index

            def before_child(inner, cancel):
                with guard:
                    log.append(("start", inner.index))
                started[inner.index].set()
                if inner.index < 2:                       # give a broken cap every chance to show itself
                    started[inner.index + 1].wait(0.3)

            def child(inner, spec_, *, cancel=None, observer=None):
                value = super().child(spec_, cancel=cancel, observer=observer)
                with guard:
                    log.append(("end", inner.index))
                return value
        self.assertEqual(rp.LIMITS[rp.DOCKER], 1)
        self.scripted(RoutedDocker(ScriptedDocker, {support.container_name(plan, index): Logging(index)
                                                    for index in range(3)}))
        manifest = self.ws.run(spec, plan)
        self.assertEqual(manifest["outcome"], pr.COMPLETE)
        self.assertEqual(log, [(word, index) for index in range(3) for word in ("start", "end")])

    def test_the_wait_is_event_driven_not_a_poll(self):
        spec, plan = self.personas(4, budget_class="probe")
        waits: list = []
        real = threading.Condition

        class Recording(real):
            def wait(inner, timeout=None):
                # the coordinator's own waits; not B14's or a test's events, nor Thread.start()'s untimed one
                if threading.current_thread().name == "test-coordinator" and timeout is not None:
                    waits.append(timeout)
                return super().wait(timeout)
        gate = Gated()
        # with the backstop out of reach, only a worker's own notification can move the pool on
        with mock.patch.object(pr.threading, "Condition", Recording), \
                mock.patch.object(pr, "LIVENESS_BACKSTOP_SECONDS", HANG_SECONDS * 10):
            running = Background(lambda: self.ws.run(spec, plan, Routed({support.ids(plan)[3]: gate})))
            wait_for(gate.started)
            idle = len(waits)
            self.assertFalse(gate.release.wait(0.5))          # half a second in which nothing happens
            self.assertEqual(len(waits), idle, "the waiter woke although nothing happened")
            gate.release.set()
            manifest = running.result()
        self.assertEqual(manifest["outcome"], pr.COMPLETE)
        self.assertLessEqual(len(waits), 2 * 4, "more wake-ups than worker events")
        self.assertTrue(all(0 < timeout <= HANG_SECONDS for timeout in waits), waits)      # never a spin, never past the deadline

    def test_a_cancel_wakes_the_waiter_without_waiting_for_the_backstop(self):
        cancel = pr.PoolCancel()
        woke = []
        cancel.subscribe(lambda: woke.append(cancel.is_set()))
        cancel.set()
        self.assertEqual(woke, [True])
        self.assertIsInstance(cancel, threading.Event)
        cancel.unsubscribe(woke.append)                       # unknown listener: nothing happens
        spec, plan = self.personas(1)
        gate = Gated()
        with mock.patch.object(pr, "LIVENESS_BACKSTOP_SECONDS", HANG_SECONDS * 10):
            running = Background(lambda: self.ws.run(spec, plan, gate))
            wait_for(gate.started)
            self.assertEqual(len(self.ws.cancel._listeners), 1, "the waiter is not subscribed to the cancel")
            self.ws.cancel.set()
            self.assertEqual(support.states(running.result()), [pr.CANCELED])
        self.assertEqual(self.ws.cancel._listeners, [], "the coordinator left a listener behind")


# ---- the verifier -----------------------------------------------------------------------------------

class VerifierTests(Case):
    def setUp(self):
        super().setUp()
        self.spec, self.plan = self.mixed(3, 2)
        ids = support.ids(self.plan)
        self.scripted(RoutedDocker(ScriptedDocker, {
            support.container_name(self.plan, 4): ScriptedDocker(client_exit=3, stdout=(MARKER + "\n").encode())}))
        self.ws.run(self.spec, self.plan, Routed({ids[1]: b14.Raising(RuntimeError(MARKER))}))
        self.honest = self.raw(self.plan)
        self.assertEqual(self.ws.verify(self.spec, self.plan), [])

    def restore(self):
        path = self.ws.manifest_path(self.plan)
        path.unlink()
        path.write_bytes(self.honest)

    def refuted(self, label) -> list:
        errors = self.ws.verify(self.spec, self.plan)
        self.assertNotEqual(errors, [], label)
        for error in errors:
            self.assertNotIn(MARKER, error)
            self.assertNotIn(str(self.ws.base), error)
        with self.assertRaises(pr.RendezvousError):
            self.ws.load(self.spec, self.plan)
        return errors

    def test_every_top_level_field_is_bound_even_when_the_hash_is_resealed(self):
        manifest = json.loads(self.honest.decode("utf-8"))
        hostile = {
            "schema": "appsec-review/pool-expansion/1.0", "classification": MARKER, "expansion": MARKER,
            "expansion_sha256": ZERO_SHA, "spec_sha256": ZERO_SHA, "pool_directory": "0" * 32, "pool_id": MARKER,
            "lane": MARKER, "run_id": MARKER, "job_id": MARKER, "attempt_id": MARKER, "wait_all": 1,
            "rendezvous_timeout_seconds": manifest["rendezvous_timeout_seconds"] + 1,
            "empty_pool_reason": "scope_excluded", "expansion_state": ps.EMPTY, "outcome": pr.COMPLETE,
            "counts": {**manifest["counts"], pr.SUCCEEDED: 5, pr.FAILED: 0}, "instances": [],
        }
        self.assertEqual(sorted([*hostile, "manifest_sha256"]), sorted(manifest))
        for name, value in hostile.items():
            with self.subTest(field=name):
                self.reseal(self.plan, lambda m, name=name, value=value: m.__setitem__(name, value))
                errors = self.refuted(name)
                if name == "wait_all":          # the schema subset's `const: true` admits 1; the module does not
                    self.assertEqual(errors, ["wait_all must be the JSON value true"])
                self.restore()
        path = self.ws.manifest_path(self.plan)
        manifest["manifest_sha256"] = ZERO_SHA
        path.write_bytes(pr.canonical_bytes(manifest))
        self.assertIn("manifest_sha256 does not match the manifest record", self.refuted("manifest_sha256"))

    def test_every_instance_field_is_bound_even_when_the_hash_is_resealed(self):
        manifest = json.loads(self.honest.decode("utf-8"))
        self.assertEqual(support.states(manifest), [pr.SUCCEEDED, pr.FAILED, pr.SUCCEEDED, pr.SUCCEEDED, pr.FAILED])
        other = manifest["instances"][0]
        hostile = {
            "instance_id": other["instance_id"], "group_id": MARKER, "ordinal": 7, "worker_kind": ps.PINNED_CONTAINER,
            "attempt_root": other["attempt_root"], "resource_pool": rp.CPU, "request_sha256": ZERO_SHA,
            "input_fingerprint": ZERO_SHA, "state": pr.SUCCEEDED, "state_reason": pr.REASON_RESULT_REFUSED,
            "adapter_status": "OK", "adapter_cause": None,
            "result_file": other["result_file"], "invoker_stopped": False, "container_removed": True,
            "worker_stopped": True,
        }
        self.assertEqual(sorted(hostile), sorted(manifest["instances"][1]))
        for name, value in hostile.items():
            with self.subTest(field=name):
                self.reseal(self.plan, lambda m, name=name, value=value: m["instances"][1].__setitem__(name, value))
                self.refuted(name)
                self.restore()
        for part, value in (("path", other["result_file"]["path"]), ("sha256", ZERO_SHA), ("bytes", 1)):
            with self.subTest(result_file=part):
                self.reseal(self.plan, lambda m, part=part, value=value:
                            m["instances"][1]["result_file"].__setitem__(part, value))
                self.refuted(part)
                self.restore()

    def test_a_failure_cannot_be_upgraded_and_no_result_can_be_borrowed(self):
        def upgrade(manifest):
            failed, good = manifest["instances"][1], manifest["instances"][0]
            for name in ("state", "adapter_status", "adapter_cause", "result_file", "invoker_stopped"):
                failed[name] = deepcopy(good[name])
            found = [record["state"] for record in manifest["instances"]]
            manifest["counts"] = {"instances": 5, **{state: found.count(state) for state in pr.STATES}}
            manifest["outcome"] = pr.pool_outcome(found)
        self.reseal(self.plan, upgrade)
        self.assertIn("instances[1]", self.refuted("upgrade")[0])

    def test_a_dishonest_producer_who_edits_one_adapter_result_and_reseals_every_hash_is_refused(self):
        path = self.ws.result_path(self.plan, 1)
        result = json.loads(path.read_text(encoding="utf-8"))
        result.update(execution_status="OK", cause=None, outcome="returned")
        result["result_sha256"] = pi.result_sha256(result)
        data = pi.canonical_bytes(result)
        path.write_bytes(data)

        def edit(manifest):
            record = manifest["instances"][1]
            record.update(state=pr.SUCCEEDED, adapter_status="OK", adapter_cause=None, invoker_stopped=True,
                          result_file={"path": record["attempt_root"] + "/logs/persona/" + pi.RESULT_FILE,
                                       "sha256": pr._bytes_sha(data), "bytes": len(data)})
            found = [item["state"] for item in manifest["instances"]]
            manifest["counts"] = {"instances": 5, **{state: found.count(state) for state in pr.STATES}}
            manifest["outcome"] = pr.pool_outcome(found)
        self.reseal(self.plan, edit)
        self.assertIn("instances[1]", self.refuted("resealed result")[0])

    def test_every_file_of_every_adopted_attempt_is_read_not_just_hashed(self):
        for index in range(5):
            root = self.ws.instance_root(self.plan, index)
            files = [path for path in sorted(root.rglob("*")) if path.is_file()]
            self.assertGreaterEqual(len(files), 3)
            for path in files:
                with self.subTest(instance=index, file=path.relative_to(root).as_posix()):
                    honest = path.read_bytes()
                    path.write_bytes(honest + b" ")
                    self.assertIn(f"instances[{index}]", self.refuted(path.name)[0])
                    path.write_bytes(honest)
        self.assertEqual(self.ws.verify(self.spec, self.plan), [])

    def test_the_manifest_file_itself_is_read_strictly(self):
        path = self.ws.manifest_path(self.plan)
        text = self.honest.decode("utf-8")
        cases = {
            "repeated key": text.replace('"outcome":', '"outcome":"COMPLETE","outcome":', 1).encode("utf-8"),
            "not canonical": json.dumps(json.loads(text)).encode("utf-8"),
            "not json": b"{",
            "not an object": b"[]",
            "not utf-8": b"\xff\xfe",
            "oversized": self.honest + b" " * ps.MAX_DOCUMENT_BYTES,
        }
        for label, data in cases.items():
            with self.subTest(case=label):
                self.assertNotEqual(data, self.honest)
                path.write_bytes(data)
                self.refuted(label)
                self.restore()
        self.assertIn("exactly one reading", (path.write_bytes(cases["repeated key"]), self.refuted("key"))[1][0])
        self.restore()
        (path.parent / "extra.json").write_bytes(b"{}")
        self.assertIn("does not hold exactly", self.refuted("extra file")[0])
        (path.parent / "extra.json").unlink()
        os.link(path, self.ws.base / "second-name.json")
        self.assertIn("hard-linked", self.refuted("hard link")[0])
        (self.ws.base / "second-name.json").unlink()
        if SYMLINKS:
            moved = self.ws.base / "moved.json"
            os.replace(path, moved)
            path.symlink_to(moved)
            self.assertIn("linked", self.refuted("linked manifest")[0])
            path.unlink()
            os.replace(moved, path)
            root = path.parent
            os.replace(root, self.ws.base / "moved-root")
            root.symlink_to(self.ws.base / "moved-root", target_is_directory=True)
            self.assertIn("is a link", self.refuted("linked root")[0])
            root.unlink()
            os.replace(self.ws.base / "moved-root", root)
        self.assertEqual(self.ws.verify(self.spec, self.plan), [])

    def test_the_wrong_party_and_the_wrong_pool_are_refused(self):
        other = deepcopy(self.spec)
        other["attempt_id"] = "attempt-other"
        errors = pr.verify_manifest(self.ws.root(self.plan), **self.ws.reader_arguments(other))
        self.assertEqual(len(errors), 1)
        self.assertIn("the pool expansion does not verify", errors[0])
        other_plan = self.ws.expand(other)                   # a real sibling pool that never had a rendezvous
        self.assertIn("no manifest was published", self.ws.verify(other, other_plan)[0])
        sibling = pr.rendezvous_root(other_plan, self.ws.rendezvous_parent)
        shutil.copytree(self.ws.manifest_path(self.plan).parent, sibling)
        self.assertNotEqual(self.ws.verify(other, other_plan), [], "another pool's manifest was accepted")
        elsewhere = self.ws.base / "other-rendezvous"
        elsewhere.mkdir()
        self.assertIn("no manifest was published", self.ws.verify(self.spec, self.plan, rendezvous_parent=elsewhere)[0])
        request = self.ws.root(self.plan) / self.plan.requests[0].relative_path
        request.write_bytes(request.read_bytes() + b" ")
        self.assertIn("the pool expansion does not verify", self.refuted("edited request")[0])

    def test_an_observation_only_state_cannot_be_claimed_against_the_disk(self):
        """never-launched needs an empty root; nothing adopts a result without the adapter's verifier."""
        for state in (pr.NOT_LAUNCHED_CANCELED, pr.NOT_LAUNCHED_RENDEZVOUS_TIMEOUT, pr.MISSING, pr.CRASHED,
                      pr.FAILED, pr.BLOCKED, pr.CANCELED, pr.INSTANCE_TIMED_OUT):
            with self.subTest(state=state):
                def edit(manifest, state=state):
                    manifest["instances"][0].update(state=state, adapter_status=None, adapter_cause=None,
                                                    result_file=None, invoker_stopped=None)
                    found = [item["state"] for item in manifest["instances"]]
                    manifest["counts"] = {"instances": 5, **{name: found.count(name) for name in pr.STATES}}
                    manifest["outcome"] = pr.pool_outcome(found)
                self.reseal(self.plan, edit)
                self.assertIn("instances[0]", self.refuted(state)[0])
                self.restore()

    def test_what_a_manifest_can_say_about_a_verified_success_is_that_success_or_nothing_adopted(self):
        """The verifier proves agreement with the disk, not which observation the coordinator made
        (nothing is signed). So the claims it accepts for an instance are exactly what the rule
        derives for SOME observation: for a verified OK attempt that is the success itself or a
        state that adopts no result. Never another result, and never a success without one."""
        arguments = self.ws.classifier_arguments(self.plan)
        for index, honest in ((0, pr.SUCCEEDED), (1, pr.FAILED)):
            claims = [pr.classify_instance(self.plan, index, **arguments, observation=observation)
                      for observation in pr.OBSERVATIONS]
            self.assertEqual({record["state"] for record in claims}, {honest, pr.RENDEZVOUS_TIMED_OUT, pr.INVALID})
            for record in claims:
                if record["state"] != honest:
                    self.assertEqual([record[name] for name in ("adapter_status", "adapter_cause", "result_file",
                                                                "invoker_stopped", "container_removed")], [None] * 5)

    def test_the_container_facts_are_the_context_s_and_are_the_ones_the_launch_used(self):
        """B13's verifier builds the one docker argv a run can have from the docker executable and the
        container user. They are the CONTEXT's (C01), never a default and never read from the attempt."""
        hostile = {
            "another docker executable": {"docker_executable": Path("/usr/local/bin/other-docker")},
            "another container user": {"container_user": "4242:4242"},
        }
        for label, over in hostile.items():
            with self.subTest(facts=label):
                errors = self.ws.verify(self.spec, self.plan, context=self.ws.context(**over))
                self.assertEqual(len(errors), 2, "exactly the two pinned-container instances stop verifying")
                self.assertTrue(all("instances[3]" in e or "instances[4]" in e for e in errors), errors)
                with self.assertRaises(pr.RendezvousError):
                    self.ws.load(self.spec, self.plan, context=self.ws.context(**over))

    def test_a_pool_without_containers_needs_no_container_facts(self):
        spec, plan = self.personas(1, attempt_id="attempt-personas-only")
        self.ws.run(spec, plan)
        bare = self.ws.context(docker_executable=None, container_user=None, mount_roots={})
        self.assertEqual(self.ws.verify(spec, plan, context=bare), [])

    def test_one_wait_cannot_have_ended_both_ways(self):
        spec, plan = self.personas(2, attempt_id="attempt-both")
        self.ws.cancel.set()
        self.ws.run(spec, plan)

        def edit(manifest):
            manifest["instances"][1].update(state=pr.NOT_LAUNCHED_RENDEZVOUS_TIMEOUT,
                                            state_reason=pr.REASON_WAIT_ENDED_BEFORE_LAUNCH)
            manifest["counts"].update({pr.NOT_LAUNCHED_CANCELED: 1, pr.NOT_LAUNCHED_RENDEZVOUS_TIMEOUT: 1})
        self.reseal(plan, edit)
        errors = self.ws.verify(spec, plan)
        self.assertEqual(len(errors), 1)
        self.assertIn("both by cancel and by timeout", errors[0])

    def test_the_reason_is_total_closed_and_re_derived_or_bounded_by_the_verifier(self):
        """Q4. Every (disk fact, observation) pair derives a state and one of THAT state's reasons;
        a resealed reason is refused when the disk decides it, and bounded to the closed set of the
        same state when only the coordinator saw it."""
        instance = self.plan.instances[0]
        verified = pr._disk_facts(instance, self.ws.root(self.plan), self.ws.context())
        self.assertEqual(verified[0], pr._VERIFIED)
        seen = set()
        for kind in (pr._ROOT_ABSENT, pr._ROOT_NOT_PRIVATE, pr._NO_EVIDENCE, pr._NO_RESULT, pr._RESULT_REFUSED,
                     pr._VERIFIED):
            for observation in pr.OBSERVATIONS:
                record = pr._entry(instance, verified if kind == pr._VERIFIED else (kind, None), observation)
                self.assertIn(record["state_reason"], pr.REASONS_BY_STATE[record["state"]])
                seen.add((record["state"], record["state_reason"]))
        unreachable_here = {(pr.INVALID, pr.REASON_WRITER_NOT_STOPPED), (pr.INVALID, pr.REASON_STATUS_UNKNOWN)}
        unreachable_here |= {(state, pr.REASON_VERIFIED_RESULT) for state in pr.RESULT_STATES if state != pr.SUCCEEDED}
        everything = {(state, reason) for state, reasons in pr.REASONS_BY_STATE.items() for reason in reasons}
        self.assertEqual(seen, everything - unreachable_here)
        # the disk decides: instances[1] FAILED with a verified result; no other reason verifies
        for reason in pr.STATE_REASONS:
            if reason == pr.REASON_VERIFIED_RESULT:
                continue
            with self.subTest(resealed_reason=reason):
                self.reseal(self.plan, lambda m, reason=reason: m["instances"][1].__setitem__("state_reason", reason))
                self.refuted("instances[1]")
                self.restore()

    def test_a_reason_only_the_coordinator_saw_is_bounded_to_its_state_s_closed_set(self):
        spec, plan = self.personas(1, attempt_id="attempt-bounded")
        with mock.patch.object(worker_adapters.PersonaInvocationAdapter, "execute", autospec=True, return_value={}):
            manifest = self.ws.run(spec, plan)
        self.assertEqual((manifest["instances"][0]["state"], manifest["instances"][0]["state_reason"]),
                         (pr.MISSING, pr.REASON_NO_EVIDENCE))
        honest = self.raw(plan)
        for reason, accepted in ((pr.REASON_THREAD_NOT_STARTED, True), (pr.REASON_ROOT_ABSENT, False),
                                 (pr.REASON_RESULT_REFUSED, False)):
            with self.subTest(reason=reason):
                self.reseal(plan, lambda m, reason=reason: m["instances"][0].__setitem__("state_reason", reason))
                self.assertEqual(self.ws.verify(spec, plan) == [], accepted)
                self.ws.manifest_path(plan).unlink()
                self.ws.manifest_path(plan).write_bytes(honest)

    def test_the_first_ten_lines_of_c03_against_the_reader(self):
        """Review of PR #35, F4. A consumer gets the verified adapter results with the manifest: it
        calls no adapter verifier, re-supplies no host fact beside the context, and can read a pool
        with a `missing` instance, which `ps.load_verified_expansion` refuses."""
        spec, plan = self.personas(3, budget_class="probe", attempt_id="attempt-c03")
        ids = support.ids(plan)

        class Deleting(pi.FixtureInvoker):
            def invoke(inner, package, *, output_root, cancel):
                shutil.rmtree(self.ws.instance_root(plan, 2))
                super().invoke(package, output_root=output_root, cancel=cancel)
        self.ws.run(spec, plan, Routed({ids[0]: Deleting()}))
        pool_root, context, parent = self.ws.root(plan), self.ws.context(), self.ws.rendezvous_parent
        with self.assertRaises(ps.PoolSpecError):                  # the trap the doc now names
            ps.load_verified_expansion(pool_root, expected_spec=spec, context=context)

        # ---- C03's first ten lines (docs/rendezvous/pool-rendezvous.md, "Reading a rendezvous") ----
        verified = pr.load_verified_manifest(pool_root, expected_spec=spec, context=context,
                                             rendezvous_parent=parent)
        if verified.outcome not in (pr.COMPLETE, pr.DEGRADED):
            raise AssertionError("nothing to merge")
        candidates = []
        for item in verified.in_state(pr.SUCCEEDED):
            attempt_root = item.instance.attempt_root_path(pool_root)
            for output in item.result["outputs"]:
                candidates.append((item.instance.instance_id, item.result["persona_id"], item.result["model"],
                                   attempt_root / item.result["output_root"] / output["path"], output["sha256"]))
        absent = [(item.instance.instance_id, item.record["state_reason"]) for item in verified.in_state(pr.MISSING)]
        # ---- end ----

        self.assertEqual(sorted({candidate[0] for candidate in candidates}), sorted(ids[:2]))
        self.assertTrue(candidates)
        for _, _, _, path, sha in candidates:
            self.assertEqual(pr._bytes_sha(path.read_bytes()), sha)
        self.assertEqual(absent, [(ids[2], pr.REASON_ROOT_ABSENT)])
        self.assertEqual(verified.plan.spec_sha256, plan.spec_sha256)
        with self.assertRaises(pr.RendezvousError):
            verified.in_state("done")

    def test_what_the_reader_returns_cannot_be_changed(self):
        verified = self.ws.load(self.spec, self.plan)
        self.assertEqual([item.result is not None for item in verified.instances], [True] * 5)
        for item, record in zip(verified.instances, verified.manifest["instances"]):
            data = (pi.canonical_bytes if item.instance.worker_kind == ps.PERSONA
                    else ce.canonical_request_bytes)(pr.thaw(item.result))
            self.assertEqual(record["result_file"]["sha256"], pr._bytes_sha(data), "the result the record pins")
            self.assertEqual(data, self.ws.result_path(self.plan, item.instance.index).read_bytes())
        from dataclasses import FrozenInstanceError
        with self.assertRaises(FrozenInstanceError):
            verified.manifest = {}
        with self.assertRaises(FrozenInstanceError):
            verified.instances[0].result = None
        for mutate in (lambda: verified.manifest.__setitem__("outcome", pr.COMPLETE),
                       lambda: verified.manifest["instances"][0].__setitem__("state", pr.SUCCEEDED),
                       lambda: verified.instances[1].result.__setitem__("execution_status", "OK"),
                       lambda: verified.instances[1].record.__setitem__("state", pr.SUCCEEDED),
                       lambda: verified.instances[0].result["outputs"].append({})):
            with self.assertRaises((TypeError, AttributeError)):
                mutate()
        self.assertIsInstance(verified.instances, tuple)

    def test_classification_refuses_an_unknown_observation_and_a_short_observation_list(self):
        arguments = self.ws.classifier_arguments(self.plan)
        with self.assertRaises(pr.RendezvousError):
            pr.classify_instance(self.plan, 0, **arguments, observation="succeeded")
        with self.assertRaises(pr.RendezvousError):
            pr.derive_manifest(self.plan, **arguments, observations=[pr.REPORTED] * 4)
        for observation in pr.OBSERVATIONS:
            record = pr.classify_instance(self.plan, 0, **arguments, observation=observation)
            self.assertEqual(schema_validate.validate_document(record, pr.INSTANCE_SCHEMA), [])
            self.assertEqual(record["state"] == pr.SUCCEEDED, observation == pr.REPORTED)


if __name__ == "__main__":
    unittest.main()
