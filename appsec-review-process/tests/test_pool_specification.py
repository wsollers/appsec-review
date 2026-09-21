"""Pool specification and deterministic instance expansion (backlog batch C01)."""
from __future__ import annotations

from copy import deepcopy
import inspect
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_execution as ce  # noqa: E402
import container_execution_support as b13  # noqa: E402
import permission_capabilities as pc  # noqa: E402
import persona_invocation as pi  # noqa: E402
import persona_invocation_support as b14  # noqa: E402
import pool_specification as ps  # noqa: E402
import pool_specification_support as support  # noqa: E402
from pool_specification_support import MARKER, NETWORK  # noqa: E402
import resource_pools as rp  # noqa: E402
import schema_validate  # noqa: E402

with tempfile.TemporaryDirectory() as _probe:
    SYMLINKS = support.symlinks_supported(Path(_probe))     # probed once; a POSIX host never skips

SCHEMAS = (ps.SPEC_SCHEMA, ps.GROUP_SCHEMA, ps.EXPANSION_SCHEMA, ps.INSTANCE_SCHEMA)
KEYWORDS = {"$schema", "$id", "title", "description", "type", "required", "properties",
            "additionalProperties", "enum", "const", "pattern", "items", "minItems", "$ref"}


class Case(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.ws = support.PoolWorkspace(Path(self.temporary.name).resolve())

    def refused(self, spec, fragment: str, **context_over) -> str:
        """The specification is refused with this rule, and nothing at all is created."""
        before = support.tree(self.ws.base)
        with self.assertRaises(ps.PoolSpecError) as caught:
            ps.expand_pool(spec, context=self.ws.context(**context_over))
        message = str(caught.exception)
        self.assertIn(fragment, message)
        self.assertNotIn(MARKER, message)
        self.assertEqual(support.tree(self.ws.base), before, "a refused specification created something")
        return message

    def expand(self, spec, **context_over) -> ps.ExpansionPlan:
        return ps.expand_pool(spec, context=self.ws.context(**context_over))

    def verify(self, plan, spec, **context_over) -> list:
        return ps.verify_expansion(self.ws.root(plan), expected_spec=spec, context=self.ws.context(**context_over))


# ---- schemas ---------------------------------------------------------------------------------------

def _objects(node, path="$"):
    if isinstance(node, dict):
        if "properties" in node:
            yield path, node
        for key, value in node.items():
            yield from _objects(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _objects(value, f"{path}[{index}]")


class SchemaTests(unittest.TestCase):
    def load(self, name):
        return json.loads((schema_validate.SCHEMAS_DIR / name).read_text(encoding="utf-8"))

    def test_every_object_is_closed_every_property_required_and_only_the_subset_is_used(self):
        for name in SCHEMAS:
            schema = self.load(name)
            for path, node in _objects(schema):
                with self.subTest(schema=name, at=path):
                    self.assertIs(node.get("additionalProperties"), False)
                    self.assertEqual(sorted(node["required"]), sorted(node["properties"]))

            def walk(node, inside_properties=False):
                if isinstance(node, dict):
                    if not inside_properties:
                        self.assertLessEqual(set(node), KEYWORDS, name)
                        if "pattern" in node:
                            self.assertTrue(node["pattern"].startswith("^") and node["pattern"].endswith("\\Z"), name)
                    for key, value in node.items():
                        walk(value, key == "properties" and not inside_properties)
                elif isinstance(node, list):
                    for value in node:
                        walk(value)
            walk(schema)

    def test_each_template_property_is_the_adapters_own_schema_for_it(self):
        group = self.load(ps.GROUP_SCHEMA)["properties"]
        for template, fields, adapter in (("persona_request", ps.PERSONA_TEMPLATE_FIELDS, pi.REQUEST_SCHEMA),
                                          ("tool_request", ps.TOOL_TEMPLATE_FIELDS, ce.REQUEST_SCHEMA)):
            theirs = self.load(adapter)
            mine = group[template]
            self.assertEqual(tuple(mine["properties"]), fields)
            for field in fields:
                self.assertEqual(mine["properties"][field], theirs["properties"][field], field)
            assigned = set(theirs["properties"]) - set(fields)
            self.assertEqual(assigned - {"permission"}, {
                "schema", "run_id", "job_id", "attempt_id", "log_path",
                *(("output_root", "permission_fingerprint_sha256") if template == "persona_request"
                  else ("scratch_path",))})
            self.assertEqual(group["permission"], theirs["properties"]["permission"])

    def test_closed_vocabularies_are_the_modules_own(self):
        spec, expansion = self.load(ps.SPEC_SCHEMA), self.load(ps.EXPANSION_SCHEMA)
        group, instance = self.load(ps.GROUP_SCHEMA), self.load(ps.INSTANCE_SCHEMA)
        self.assertEqual(tuple(spec["properties"]["budget_class"]["enum"]), ps.BUDGET_CLASSES)
        self.assertEqual(set(ps.BUDGET_CLASSES), set(rp.PERSONA_BUDGET_CELLS))
        for schema in (spec, expansion):
            self.assertEqual(schema["properties"]["empty_pool_reason"]["enum"], [*ps.EMPTY_POOL_REASONS, None])
            self.assertEqual(schema["properties"]["wait_all"], {"const": True})
        for schema in (group, instance):
            self.assertEqual(tuple(schema["properties"]["worker_kind"]["enum"]), ps.WORKER_KINDS)
        self.assertEqual(set(ps.WORKER_KINDS), {pi.WORKER_KIND, ce.WORKER_KIND})
        self.assertLessEqual(set(ps.WORKER_KINDS), set(rp.WORKER_KIND_POOLS))
        self.assertEqual(spec["properties"]["schema"]["const"], ps.SPEC_ID)
        self.assertEqual(expansion["properties"]["schema"]["const"], ps.EXPANSION_ID)
        self.assertEqual(expansion["properties"]["id_derivation"]["const"], ps.ID_DERIVATION_ID)
        self.assertEqual(sorted(instance["properties"]["request_schema"]["enum"]),
                         sorted((pi.REQUEST_ID, ce.REQUEST_ID)))
        closed_words = set()              # the schemas hold a pool-id shape, never a pool id

        def words(node):
            if isinstance(node, dict):
                closed_words.update(value for value in node.get("enum", []) if isinstance(value, str))
                if isinstance(node.get("const"), str):
                    closed_words.add(node["const"])
                for value in node.values():
                    words(value)
            elif isinstance(node, list):
                for value in node:
                    words(value)
        words([spec, expansion, group, instance])
        self.assertFalse(closed_words & {*rp.POOL_IDS, rp.UNASSIGNED})

    def test_no_property_this_module_adds_has_a_secret_looking_name(self):
        import evidence_redaction
        adapters = set()
        for name in (pi.REQUEST_SCHEMA, ce.REQUEST_SCHEMA):
            adapters |= {key for _, node in _objects(self.load(name)) for key in node["properties"]}
        for name in SCHEMAS:
            for _, node in _objects(self.load(name)):
                for key in set(node["properties"]) - adapters:
                    self.assertIsNone(evidence_redaction._KEYWORD_RE.search(key), key)


# ---- counts: zero, one, many, invalid --------------------------------------------------------------

class CountTests(Case):
    def test_zero_instances_is_a_recorded_state_with_a_reason_not_an_error_and_not_a_success(self):
        for label, groups in (("no groups", []),
                              ("groups of zero", [self.ws.persona_group(count=0), self.ws.tool_group(count=0)])):
            with self.subTest(case=label):
                spec = self.ws.spec(groups, empty_pool_reason="upstream_produced_no_work")
                plan = self.expand(spec)
                manifest = plan.manifest
                self.assertEqual((manifest["state"], manifest["empty_pool_reason"]),
                                 (ps.EMPTY, "upstream_produced_no_work"))
                self.assertEqual((manifest["instances"], plan.requests), ((), ()))
                self.assertEqual(manifest["totals"]["instances"], 0)
                self.assertEqual([(g["worker_kind"], g["count"], g["instance_ids"]) for g in manifest["groups"]],
                                 [(g["worker_kind"], 0, ()) for g in spec["worker_groups"]])
                self.assertEqual(support.tree(self.ws.root(plan)),
                                 [ps.EXPANSION_FILE, ps.INSTANCES_DIR, ps.REQUESTS_DIR, ps.SPEC_FILE])
                self.assertEqual(self.verify(plan, spec), [])
                self.assertNotIn("OK", json.dumps(ps.thaw(manifest)))

    def test_an_empty_pool_must_say_why_and_a_populated_pool_must_not(self):
        self.refused(self.ws.spec([], empty_pool_reason=None), "empty_pool_reason is required exactly when")
        self.refused(self.ws.spec([self.ws.persona_group()], empty_pool_reason="scope_excluded"),
                     "empty_pool_reason is required exactly when")
        self.refused(self.ws.spec([], empty_pool_reason="because " + MARKER), "fails its closed schema")

    def test_one_and_many(self):
        one = self.expand(self.ws.spec([self.ws.persona_group(count=1)]))
        self.assertEqual((one.manifest["state"], len(one.manifest["instances"])), (ps.POPULATED, 1))
        groups = [self.ws.persona_group("reviewers", ps.MAX_GROUP_COUNT), self.ws.tool_group("scanners", ps.MAX_GROUP_COUNT)]
        spec = self.ws.spec(groups, attempt_id="attempt-many",
                            pool_budget={"max_instances": ps.MAX_INSTANCES, "max_persona_input_units": 10 ** 6,
                                         "max_persona_output_units": 10 ** 6, "max_total_timeout_seconds": 86_400})
        many = self.expand(spec)
        self.assertEqual(len(many.manifest["instances"]), ps.MAX_INSTANCES)
        self.assertEqual(self.verify(many, spec), [])

    def test_invalid_counts_are_rejected_by_position(self):
        for label, count in (("negative", -1), ("bool", True), ("float", 1.0), ("fraction", 1.5),
                             ("string", "2"), ("marker string", MARKER), ("null", None),
                             ("over the group bound", ps.MAX_GROUP_COUNT + 1), ("list", [1])):
            with self.subTest(case=label):
                group = self.ws.persona_group()
                group["count"] = count
                self.refused(self.ws.spec([group], empty_pool_reason=None),
                             f"worker_groups[0].count must be an integer within 0..{ps.MAX_GROUP_COUNT}")

    def test_the_hard_upper_bound_and_the_declared_bound(self):
        groups = [self.ws.persona_group(f"g{index}", ps.MAX_GROUP_COUNT) for index in range(3)]
        self.refused(self.ws.spec(groups), f"more than {ps.MAX_INSTANCES} instances")
        spec = self.ws.mixed(3, 2)
        spec["pool_budget"]["max_instances"] = 4
        self.refused(spec, "more instances than pool_budget.max_instances")
        spec["pool_budget"]["max_instances"] = ps.MAX_INSTANCES + 1
        self.refused(spec, f"pool_budget.max_instances must be an integer within 0..{ps.MAX_INSTANCES}")
        self.refused(self.ws.spec([self.ws.persona_group(f"g{index:02d}", 0) for index in range(ps.MAX_GROUPS + 1)]),
                     f"more than {ps.MAX_GROUPS} worker groups")

    def test_wait_all_is_required_and_may_only_be_true(self):
        for label, value in (("false", False), ("the number one", 1), ("one point zero", 1.0),
                             ("a string", "true"), ("null", None)):
            with self.subTest(case=label):
                self.refused(self.ws.mixed(wait_all=value), "wait_all must be the JSON value true")
        spec = self.ws.mixed()
        del spec["wait_all"]
        self.refused(spec, "wait_all must be the JSON value true")

    def test_groups_have_one_spelling_and_one_template(self):
        spec = self.ws.mixed()
        spec["worker_groups"].reverse()
        self.refused(spec, "worker_groups must be sorted by group_id")
        twice = self.ws.spec([self.ws.persona_group("same"), self.ws.persona_group("same")])
        self.refused(twice, "a group_id may appear once")
        both = self.ws.mixed()
        both["worker_groups"][0]["tool_request"] = deepcopy(both["worker_groups"][1]["tool_request"])
        self.refused(both, "exactly the request template of its worker kind")
        swapped = self.ws.mixed()
        swapped["worker_groups"][0]["worker_kind"] = ps.PINNED_CONTAINER
        self.refused(swapped, "exactly the request template of its worker kind")
        unknown = self.ws.mixed()
        unknown["worker_groups"][0]["worker_kind"] = "tool"          # design-v3 5.5's word; not a merged kind
        self.refused(unknown, "fails its closed schema")


# ---- deterministic identity --------------------------------------------------------------------------

def _shuffled(node, rng):
    if isinstance(node, dict):
        keys = list(node)
        rng.shuffle(keys)
        return {key: _shuffled(node[key], rng) for key in keys}
    if isinstance(node, list):
        return [_shuffled(item, rng) for item in node]
    return node


_CHILD = """
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[2])
import pool_specification as ps, pool_specification_support as support
ws = support.PoolWorkspace(Path(sys.argv[3]).resolve())
spec = ws.spec([ws.persona_group("reviewers", 3), ws.persona_group("skeptics", 2)])
plan = ps.expand_pool(spec, context=ws.context())
print(ps._bytes_sha(plan.manifest_bytes), ps._bytes_sha((ws.root(plan) / ps.EXPANSION_FILE).read_bytes()))
"""


class DeterminismTests(Case):
    def test_one_specification_derives_one_byte_sequence(self):
        spec = self.ws.mixed()
        context = self.ws.context()
        first = ps.plan_expansion(spec, context=context)
        rng = random.Random(7)
        for _ in range(5):
            again = ps.plan_expansion(_shuffled(spec, rng), context=context)
            self.assertEqual(again.manifest_bytes, first.manifest_bytes)
            self.assertEqual([item.data for item in again.requests], [item.data for item in first.requests])
        written = self.expand(spec)
        self.assertEqual((self.ws.root(written) / ps.EXPANSION_FILE).read_bytes(), first.manifest_bytes)

    def test_the_manifest_does_not_depend_on_where_the_pool_parent_is(self):
        spec = self.ws.mixed()
        elsewhere = self.ws.base / "elsewhere" / "deeper"
        elsewhere.mkdir(parents=True)
        here, there = self.expand(spec), self.expand(spec, pool_parent=elsewhere)
        self.assertEqual(here.manifest_bytes, there.manifest_bytes)
        self.assertNotIn(str(self.ws.base), json.dumps(ps.thaw(here.manifest)))
        self.assertEqual(support.tree(self.ws.root(here)), support.tree(elsewhere / there.pool_directory))

    def test_another_process_with_another_hash_seed_derives_the_same_bytes(self):
        digests = set()
        for seed in ("1", "4242"):
            with tempfile.TemporaryDirectory() as folder:
                done = subprocess.run(
                    [sys.executable, "-B", "-c", _CHILD, str(ROOT), str(Path(__file__).resolve().parent), folder],
                    env={**os.environ, "PYTHONHASHSEED": seed}, capture_output=True, text=True, check=False)
                self.assertEqual(done.returncode, 0, done.stderr[-2000:])
                planned, on_disk = done.stdout.split()
                self.assertEqual(planned, on_disk)
                digests.add(planned)
        self.assertEqual(len(digests), 1)

    def test_an_instance_id_is_a_pure_function_of_specification_group_and_ordinal(self):
        spec = self.ws.mixed()
        plan = ps.plan_expansion(spec, context=self.ws.context())
        for entry in plan.manifest["instances"]:
            self.assertEqual(entry["instance_id"],
                             ps.instance_id(ps.spec_sha256(spec), entry["group_id"], entry["ordinal"]))
            self.assertEqual(entry["instance_id"], pc.digest(
                [ps.ID_DERIVATION_ID, "sha256:" + pc.digest(spec), entry["group_id"], entry["ordinal"]])[:32])
            self.assertEqual(entry["attempt_id"], entry["instance_id"])
        self.assertEqual(plan.pool_directory, ps.pool_directory(ps.spec_sha256(spec)))
        self.assertEqual([(e["group_id"], e["ordinal"]) for e in plan.manifest["instances"]],
                         [("reviewers", 0), ("reviewers", 1), ("reviewers", 2), ("scanners", 0), ("scanners", 1)])

    def test_a_different_specification_derives_different_ids_everywhere(self):
        base = self.ws.mixed()
        seen = {entry["instance_id"] for entry in ps.plan_expansion(base, context=self.ws.context()).manifest["instances"]}
        edits = {
            "run": lambda s: s.update(worker_groups=self._rebound(s, run_id="run-other"), run_id="run-other"),
            "attempt": lambda s: s.update(attempt_id="attempt-retry"),
            "pool id": lambda s: s.update(pool_id="other-pool"),
            "lane": lambda s: s.update(lane="08-blue-team-refutation"),
            "budget class": lambda s: s.update(budget_class="deep"),
            "rendezvous": lambda s: s.update(rendezvous_timeout_seconds=3_601),
            "a count": lambda s: s["worker_groups"][0].update(count=4),
            "a group id": lambda s: s["worker_groups"][1].update(group_id="scanners-b"),
            "a budget": lambda s: s["worker_groups"][0]["persona_request"]["budget"].update(timeout_seconds=31),
            "an argv": lambda s: s["worker_groups"][1]["tool_request"]["argv"].append("again"),
        }
        for label, edit in edits.items():
            with self.subTest(edit=label):
                spec = deepcopy(base)
                edit(spec)
                plan = ps.plan_expansion(spec, context=self.ws.context())
                ids = {entry["instance_id"] for entry in plan.manifest["instances"]}
                self.assertFalse(ids & seen, "two different specifications share an instance id")
                seen |= ids

    def _rebound(self, spec, *, run_id):
        groups = deepcopy(spec["worker_groups"])
        for group in groups:
            group["permission"] = support.permission(run_id=run_id)
        return groups

    def test_duplicate_personas_are_distinct_instances_with_distinct_roots(self):
        spec = self.ws.spec([self.ws.persona_group("reviewers", 4)])
        plan = self.expand(spec)
        entries = plan.manifest["instances"]
        self.assertEqual(len({e["instance_id"] for e in entries}), 4)
        self.assertEqual(len({e["attempt_root"] for e in entries}), 4)
        self.assertEqual(len({e["input_fingerprint"] for e in entries}), 4)
        self.assertEqual(len({e["request_sha256"] for e in entries}), 4)
        personas = {item.request["persona"]["persona_id"] for item in plan.requests}
        self.assertEqual(len(personas), 1, "the duplicates are the same persona")
        self.assertEqual(len({os.stat(self.ws.instance_root(plan, i)).st_ino for i in range(4)}), 4)


# ---- collisions ------------------------------------------------------------------------------------

class CollisionTests(Case):
    def test_no_two_instances_of_a_mixed_many_pool_share_anything(self):
        spec = self.ws.mixed(9, 8)
        plan = self.expand(spec)
        entries = plan.manifest["instances"]
        roots = [self.ws.instance_root(plan, index) for index in range(len(entries))]
        for label, values in (
                ("id", [e["instance_id"].lower() for e in entries]),
                ("attempt root", [str(path).lower() for path in roots]),
                ("root identity", [(os.stat(p, follow_symlinks=False).st_dev,
                                    os.stat(p, follow_symlinks=False).st_ino) for p in roots]),
                ("container name", [ce.container_name(e["run_id"], e["job_id"], e["attempt_id"]) for e in entries]),
                ("request file", [e["request_file"]["path"].lower() for e in entries]),
                ("writable path", [str(root / path).lower() for root, e in zip(roots, entries)
                                   for path in e["writable_paths"]])):
            self.assertEqual(len(values), len(set(values)), label)
        for entry, item in zip(entries, plan.requests):
            request = ps.thaw(item.request)
            declared = ([request["scratch_path"], request["log_path"]] if entry["worker_kind"] == ps.PINNED_CONTAINER
                        else [request["output_root"], request["log_path"]])
            self.assertEqual(sorted(declared), list(entry["writable_paths"]))
            self.assertNotIn("container_name", entry, "`appsec-<hex>` would not survive the V06 redactor")
        self.assertEqual([str(p) for p in roots if p.is_symlink() or not p.is_dir() or any(p.iterdir())], [])

    def test_a_forced_id_collision_fails_closed_and_creates_nothing(self):
        spec = self.ws.mixed(9, 8)       # 17 instances cannot fit 16 one-digit ids
        with mock.patch.object(ps, "ID_HEX_CHARS", 1):
            message = self.refused(spec, "two instances derive one instance id: the expansion fails closed")
        self.assertIsNone(re.search(r"[0-9a-f]{8}", message), "a message quoted an id")
        self.assertEqual(self.verify(self.expand(spec), spec), [])       # the seam leaves no residue

    def test_each_collision_rule_is_checked_on_its_own(self):
        plan = ps.plan_expansion(self.ws.mixed(2, 2), context=self.ws.context())
        honest = ps.thaw(plan.manifest["instances"])
        ps._collision_errors(deepcopy(honest))
        for label, edit in (
                ("instance id", lambda e: e[1].update(instance_id=e[0]["instance_id"].upper())),
                ("attempt root", lambda e: e[1].update(attempt_root=e[0]["attempt_root"].upper())),
                ("request file", lambda e: e[1]["request_file"].update(path=e[0]["request_file"]["path"])),
                ("container name", lambda e: e[3].update(attempt_id=e[2]["attempt_id"])),
                ("writable path", lambda e: e[1].update(attempt_root=e[0]["attempt_root"],
                                                         instance_id="other"))):
            with self.subTest(rule=label):
                entries = deepcopy(honest)
                edit(entries)
                with self.assertRaises(ps.PoolSpecError) as caught:
                    ps._collision_errors(entries)
                if label != "writable path":
                    self.assertIn(f"two instances derive one {label}", str(caught.exception))

    def test_a_pool_root_is_created_once(self):
        spec = self.ws.mixed()
        plan = self.expand(spec)
        before = {path: path.stat().st_mtime_ns for path in self.ws.root(plan).rglob("*")}
        with self.assertRaises(ps.PoolSpecError) as caught:
            self.expand(spec)
        self.assertIn("the pool root already exists", str(caught.exception))
        self.assertEqual({path: path.stat().st_mtime_ns for path in self.ws.root(plan).rglob("*")}, before)
        retry = deepcopy(spec)
        retry["attempt_id"] = "attempt-retry"
        self.assertNotEqual(self.expand(retry).pool_directory, plan.pool_directory)

    def test_a_squatted_pool_root_is_refused_even_when_it_is_a_dangling_link(self):
        spec = self.ws.mixed()
        plan = ps.plan_expansion(spec, context=self.ws.context())
        if SYMLINKS:
            self.ws.root(plan).symlink_to(self.ws.base / "nowhere")
        else:
            self.ws.root(plan).write_bytes(b"")
        with self.assertRaises(ps.PoolSpecError):
            self.expand(spec)
        self.assertFalse((self.ws.base / "nowhere").exists())


# ---- mixed kinds, pools, permissions and budgets ---------------------------------------------------

class MixedKindTests(Case):
    def test_kinds_are_retained_and_each_request_is_its_adapters(self):
        spec = self.ws.mixed(2, 2)
        plan = self.expand(spec)
        manifest = plan.manifest
        self.assertEqual([g["worker_kind"] for g in manifest["groups"]], [ps.PERSONA, ps.PINNED_CONTAINER])
        self.assertEqual((manifest["totals"]["persona_instances"], manifest["totals"]["pinned_container_instances"]),
                         (2, 2))
        for entry, item in zip(manifest["instances"], plan.requests):
            request = ps.thaw(item.request)
            ids = {name: entry[name] for name in ("run_id", "job_id", "attempt_id")}
            on_disk = (self.ws.root(plan) / entry["request_file"]["path"]).read_bytes()
            self.assertEqual(on_disk, item.data)
            self.assertEqual(json.loads(on_disk), request)
            self.assertEqual((entry["request_file"]["sha256"], entry["request_file"]["bytes"]),
                             (ps._bytes_sha(on_disk), len(on_disk)))
            if entry["worker_kind"] == ps.PERSONA:
                self.assertEqual((entry["request_schema"], request["schema"]), (pi.REQUEST_ID, pi.REQUEST_ID))
                self.assertEqual(pi.request_errors(request, **ids), [])
                self.assertEqual(entry["request_sha256"], pi.request_sha256(request))
                self.assertTrue(ce.request_errors(request, **ids))
            else:
                self.assertEqual((entry["request_schema"], request["schema"]), (ce.REQUEST_ID, ce.REQUEST_ID))
                self.assertEqual(ce.request_errors(request, **ids), [])
                self.assertEqual(entry["request_sha256"], ce.request_sha256(request))
                self.assertTrue(pi.request_errors(request, **ids))

    def test_the_fingerprint_folds_in_the_adapters_own_material(self):
        spec = self.ws.mixed(1, 1)
        plan = ps.plan_expansion(spec, context=self.ws.context())
        context = self.ws.context()
        for entry, item in zip(plan.manifest["instances"], plan.requests):
            request = ps.thaw(item.request)
            ids = {name: entry[name] for name in ("run_id", "job_id", "attempt_id")}
            if entry["worker_kind"] == ps.PERSONA:
                resolved = pi.resolve_request(
                    request, **ids, attempt_root=context.pool_parent, registry_dir=context.registry_dir,
                    prompt_root=context.prompt_root, readable_roots=context.readable_roots,
                    allowed_models=context.allowed_models)
                material = pi.fingerprint_material(resolved)
            else:
                material = ce.fingerprint_material(request, b13.fixture_record())
            self.assertEqual(entry["adapter_fingerprint_sha256"], material["sha256"])
            self.assertEqual(entry["permission_fingerprint_sha256"],
                             pc.input_fingerprint_component(request["permission"]["decision"]))
            self.assertEqual(entry["input_fingerprint"], ps._sha({
                "schema": ps.FINGERPRINT_ID, "spec_sha256": plan.spec_sha256, "instance_id": entry["instance_id"],
                "group_id": entry["group_id"], "ordinal": entry["ordinal"], "worker_kind": entry["worker_kind"],
                "resource_pool": entry["resource_pool"], "adapter_fingerprint": material}))

    def test_a_changed_input_changes_the_fingerprint_and_nothing_else_about_identity(self):
        spec = self.ws.spec([self.ws.persona_group()])
        before = ps.plan_expansion(spec, context=self.ws.context()).manifest["instances"][0]
        (self.ws.data / "evidence" / "notes.md").write_bytes(b"changed evidence\n")
        self.refused(spec, "bytes on disk do not have the pinned size and sha256")
        repinned = self.ws.spec([self.ws.persona_group()])
        after = ps.plan_expansion(repinned, context=self.ws.context()).manifest["instances"][0]
        self.assertNotEqual(before["input_fingerprint"], after["input_fingerprint"])
        self.assertNotEqual(before["adapter_fingerprint_sha256"], after["adapter_fingerprint_sha256"])

    def test_every_resource_pool_is_derived_never_stated(self):
        policy = {"allowed_pools": list(sorted(rp.POOL_IDS))}
        groups = [self.ws.persona_group("a-plain"), self.ws.persona_group("b-networked", capabilities=NETWORK),
                  self.ws.persona_group("c-heavy", memory_heavy=True), self.ws.tool_group("d-plain"),
                  self.ws.tool_group("e-networked", capabilities=NETWORK),
                  self.ws.tool_group("f-dynamic", capabilities=[("dynamic-testing", {"technique": "fuzzing",
                                                                                     "target_path": "."})])]
        spec = self.ws.spec(groups, resource_pool_policy=policy)
        try:
            plan = ps.plan_expansion(spec, context=self.ws.context())
        except ps.PoolSpecError as exc:      # the dynamic-testing parameters are B11's vocabulary
            self.fail(str(exc))
        derived = {}
        for entry, item in zip(plan.manifest["instances"], plan.requests):
            capabilities = item.request["permission"]["decision"]["capabilities"]
            kinds = sorted({capability["kind"] for capability in capabilities})
            self.assertEqual(list(entry["granted_permission_kinds"]), kinds)
            self.assertEqual(entry["resource_pool"],
                             rp.derive_pool(entry["worker_kind"], kinds, memory_heavy=entry["memory_heavy"]))
            self.assertEqual(entry["persona_slot_request"],
                             rp.persona_slot_request(spec["budget_class"]) if entry["worker_kind"] == ps.PERSONA else None)
            derived[entry["group_id"]] = entry["resource_pool"]
        self.assertEqual(derived, {"a-plain": rp.PERSONA_LLM, "b-networked": rp.PERSONA_LLM,
                                   "c-heavy": rp.PERSONA_LLM, "d-plain": rp.DOCKER, "e-networked": rp.DOCKER,
                                   "f-dynamic": rp.DYNAMIC_ANALYSIS})
        self.assertEqual({row["resource_pool"]: row["instances"] for row in plan.manifest["totals"]["resource_pools"]},
                         {rp.PERSONA_LLM: 3, rp.DOCKER: 2, rp.DYNAMIC_ANALYSIS: 1})

    def test_the_policy_bounds_the_derived_pool_and_cannot_name_an_unknown_one(self):
        dynamic = self.ws.tool_group(capabilities=[("dynamic-testing", {"technique": "fuzzing", "target_path": "."})])
        self.refused(self.ws.spec([dynamic]), "derives a resource pool outside resource_pool_policy.allowed_pools")
        only_docker = {"allowed_pools": [rp.DOCKER]}
        self.refused(self.ws.mixed(resource_pool_policy=only_docker), "outside resource_pool_policy.allowed_pools")
        for label, pools in (("unknown", ["gpu"]), ("the unassigned state", [rp.UNASSIGNED]),
                             ("unsorted", [rp.PERSONA_LLM, rp.DOCKER]), ("repeated", [rp.DOCKER, rp.DOCKER])):
            with self.subTest(case=label):
                self.refused(self.ws.mixed(resource_pool_policy={"allowed_pools": pools}),
                             "allowed_pools must be sorted, unique resource_pools pool ids")
        with mock.patch.object(rp, "derive_pool", side_effect=rp.PoolAssignmentError(MARKER)):
            self.refused(self.ws.mixed(), "no resource pool can be derived")

    def test_the_budget_class_sets_the_persona_slot_request(self):
        for budget_class, cells in rp.PERSONA_BUDGET_CELLS.items():
            plan = ps.plan_expansion(self.ws.mixed(budget_class=budget_class), context=self.ws.context())
            self.assertEqual(plan.manifest["totals"]["persona_slot_request"], cells)
            self.assertEqual(cells, rp.persona_slot_request(budget_class))
        self.refused(self.ws.mixed(budget_class="unlimited"), "fails its closed schema")

    def test_pool_totals_are_recorded_and_bounded(self):
        spec = self.ws.mixed(3, 2)
        totals = ps.plan_expansion(spec, context=self.ws.context()).manifest["totals"]
        persona = spec["worker_groups"][0]["persona_request"]["budget"]
        tool = spec["worker_groups"][1]["tool_request"]["limits"]
        self.assertEqual(totals["persona_input_units"], 3 * persona["input_unit_limit"])
        self.assertEqual(totals["persona_output_units"], 3 * persona["output_unit_limit"])
        self.assertEqual(totals["timeout_seconds_sum"], 3 * persona["timeout_seconds"] + 2 * tool["timeout_seconds"])
        self.assertEqual(totals["timeout_seconds_max"], max(persona["timeout_seconds"], tool["timeout_seconds"]))
        for name, total in (("max_persona_input_units", "persona_input_units"),
                            ("max_persona_output_units", "persona_output_units"),
                            ("max_total_timeout_seconds", "timeout_seconds_sum")):
            with self.subTest(bound=name):
                exact, under = deepcopy(spec), deepcopy(spec)
                exact["pool_budget"][name] = totals[total]
                ps.plan_expansion(exact, context=self.ws.context())
                under["pool_budget"][name] = totals[total] - 1
                self.refused(under, f"the instances' {total} exceed pool_budget.{name}")
                over = deepcopy(spec)
                over["pool_budget"][name] = ps.POOL_BUDGET_BOUNDS[name][1] + 1
                self.refused(over, f"pool_budget.{name} must be an integer within")
        short = deepcopy(spec)
        short["rendezvous_timeout_seconds"] = totals["timeout_seconds_max"] - 1
        self.refused(short, "rendezvous_timeout_seconds is shorter than one instance's own timeout")
        for value in (0, ps.MAX_TOTAL_TIMEOUT_SECONDS + 1):
            self.refused(self.ws.mixed(rendezvous_timeout_seconds=value), "rendezvous_timeout_seconds must be")

    def test_an_instance_budget_the_adapter_refuses_is_refused_here(self):
        spec = self.ws.mixed()
        spec["worker_groups"][0]["persona_request"]["budget"]["input_unit_limit"] = pi.BUDGET_BOUNDS["input_unit_limit"][1] + 1
        self.refused(spec, "unbounded context: budget.input_unit_limit")
        spec = self.ws.mixed()
        spec["worker_groups"][1]["tool_request"]["limits"]["timeout_seconds"] = 0
        self.refused(spec, "limits.timeout_seconds must be an integer within")


class PermissionTests(Case):
    def test_every_instance_carries_the_block_bound_to_its_own_run_and_job(self):
        plan = ps.plan_expansion(self.ws.mixed(2, 2), context=self.ws.context())
        for item in plan.requests:
            permission = ps.thaw(item.request["permission"])
            self.assertEqual((permission["decision"]["run_id"], permission["decision"]["job_id"]),
                             (item.request["run_id"], item.request["job_id"]))
            self.assertEqual(permission["requirement"]["job_id"], item.request["job_id"])
            granted = pc.require_granted(permission["decision"], requirement=permission["requirement"],
                                         grants=permission["grants"],
                                         context=b14.context(job_id=support.JOB, run_id=support.RUN))
            self.assertEqual(granted, permission["decision"]["capabilities"])

    def test_a_consistent_block_for_another_job_or_run_is_refused(self):
        for label, block, fragment in (
                ("another job", support.permission(job_id="job-other"), "declared for a different job"),
                ("another run", support.permission(run_id="run-other"), "bound to a different run or job")):
            for index in (0, 1):
                with self.subTest(case=label, group=index):
                    spec = self.ws.mixed()
                    spec["worker_groups"][index]["permission"] = block
                    self.refused(spec, fragment)

    def test_a_block_for_another_source_snapshot_is_refused(self):
        self.refused(self.ws.mixed(), "is not the decision its requirement and grants derive",
                     source_snapshot_sha256="sha256:" + "b" * 64)

    def test_the_specification_cannot_grant_what_the_decision_does_not(self):
        """Edits ONLY the decision's capability set, then reseals every hash a producer controls."""
        spec = self.ws.mixed()
        granted = support.permission(NETWORK)["decision"]
        decision = spec["worker_groups"][1]["permission"]["decision"]
        decision["capabilities"] = deepcopy(granted["capabilities"])
        decision["fingerprint_material"] = pc.fingerprint_material(decision["decision"], decision["capabilities"])
        decision["grants_applied"], decision["valid_until"] = granted["grants_applied"], granted["valid_until"]
        decision["decision_sha256"] = pc.decision_sha256(decision)
        self.assertEqual(pc.validate_decision(decision), [])
        self.refused(spec, "is not the decision its requirement and grants derive")

    def test_a_network_destination_outside_the_granted_set_is_refused(self):
        wanted = {"mode": "granted-fixed-destinations",
                  "destinations": [{"scheme": "https", "host": "api.example.org", "port": 443}]}
        self.refused(self.ws.spec([self.ws.tool_group(network=wanted)]),
                     "a network destination is not in the capability set its decision grants")
        other = deepcopy(wanted)
        other["destinations"][0]["host"] = "evil.example.org"
        self.refused(self.ws.spec([self.ws.tool_group(capabilities=NETWORK, network=other)]),
                     "a network destination is not in the capability set its decision grants")
        ps.plan_expansion(self.ws.spec([self.ws.tool_group(capabilities=NETWORK, network=wanted)]),
                          context=self.ws.context())

    def test_a_denied_decision_is_not_expandable(self):
        group = self.ws.tool_group()
        requirement = support.permission(NETWORK)["requirement"]
        denied = pc.evaluate(requirement, [], b14.context(job_id=support.JOB, run_id=support.RUN))
        self.assertEqual(denied["decision"], pc.DENIED)
        group["permission"] = {"requirement": requirement, "grants": [], "decision": denied}
        self.refused(self.ws.spec([group]), "is not GRANTED")

    def test_a_corrupt_decision_and_a_registry_ceiling_are_refused_with_fixed_text(self):
        spec = self.ws.mixed()
        spec["worker_groups"][0]["permission"]["decision"]["evaluated_at"] = "2026-13-45T99:99:99Z"
        self.refused(spec, "is not a self-consistent permission decision")
        self.refused(self.ws.spec([self.ws.tool_group(capabilities=NETWORK)]),
                     "is not the decision its requirement and grants derive", registry_ceiling=[])


# ---- scope -----------------------------------------------------------------------------------------

class PersonaScopeTests(Case):
    def scoped(self, entry: dict) -> dict:
        group = self.ws.persona_group()
        group["persona_request"]["readable_inputs"][1] = entry
        return self.ws.spec([group])

    def pin(self, path: Path, relative: str, root: str = "run-data") -> dict:
        return {"root": root, **b14.file_pin(path, relative), "role": "evidence", "producer_request_sha256": None}

    def test_absolute_dotted_and_aliased_inputs_are_refused(self):
        source = self.ws.data / "evidence" / "notes.md"
        for label, relative in (("absolute", str(source)), ("parent", "evidence/../evidence/notes.md"),
                                ("dot", "./evidence/notes.md"), ("empty segment", "evidence//notes.md"),
                                ("trailing dot", "evidence/notes.md.")):
            with self.subTest(case=label):
                self.refused(self.scoped(self.pin(source, relative)), "refuses this request")
        self.refused(self.scoped(self.pin(source, "evidence\\notes.md")), "fails its closed schema")

    def test_an_input_outside_the_declared_roots_is_refused(self):
        outside = self.ws.base / "outside.json"
        outside.write_bytes(b"{}")
        self.refused(self.scoped(self.pin(outside, "outside.json", root="elsewhere")),
                     "root is not a declared readable root")
        self.refused(self.scoped(self.pin(outside, "outside.json")), "does not exist")

    def test_linked_inputs_are_refused(self):
        if not SYMLINKS:
            self.skipTest("this host cannot create symbolic links")
        source = self.ws.data / "evidence" / "notes.md"
        (self.ws.data / "evidence" / "alias.md").symlink_to(source)
        (self.ws.data / "linked").symlink_to(self.ws.data / "evidence")
        self.refused(self.scoped(self.pin(source, "evidence/alias.md")), "refuses this request")
        self.refused(self.scoped(self.pin(source, "linked/notes.md")), "leaves its root or crosses a link")
        os.link(source, self.ws.data / "evidence" / "hard.md")
        self.refused(self.scoped(self.pin(source, "evidence/hard.md")), "hard-linked file")

    def test_nothing_beneath_the_pool_parent_is_readable(self):
        """The pool parent is inside the readable root, so only the rule keeps these out."""
        first_spec = self.ws.mixed(attempt_id="attempt-first")
        first = self.expand(first_spec)
        sibling = self.ws.instance_root(first, 0)
        (sibling / "outputs").mkdir()
        (sibling / "outputs" / "secret-notes.json").write_bytes(b'{"a": 1}')
        stray = self.ws.pool_parent / "stray.json"
        stray.write_bytes(b"{}")
        relative = lambda path: path.relative_to(self.ws.data).as_posix()      # noqa: E731
        for label, path in (("a sibling pool's instance output", sibling / "outputs" / "secret-notes.json"),
                            ("a sibling pool's expansion manifest", self.ws.root(first) / ps.EXPANSION_FILE),
                            ("a sibling pool's specification", self.ws.root(first) / ps.SPEC_FILE),
                            ("another instance's request file",
                             self.ws.root(first) / first.manifest["instances"][1]["request_file"]["path"]),
                            ("a file in the pool parent itself", stray)):
            with self.subTest(case=label):
                self.refused(self.scoped(self.pin(path, relative(path))),
                             "is inside the attempt; an attempt never reads itself")
        self.assertEqual(ps.plan_expansion(self.scoped(self.pin(self.ws.data / "evidence" / "notes.md",
                                                                "evidence/notes.md")),
                                           context=self.ws.context()).manifest["state"], ps.POPULATED)

    def test_a_prompt_beneath_the_pool_parent_is_refused(self):
        prompt = self.ws.pool_parent / "prompt.md"
        prompt.write_bytes(b"# prompt\n")
        group = self.ws.persona_group()
        group["persona_request"]["outer_prompt"] = b14.file_pin(prompt, "prompt.md")
        self.refused(self.ws.spec([group]), "is inside the attempt", prompt_root=self.ws.pool_parent)

    def test_the_wrong_invoker_and_the_wrong_model_are_refused(self):
        self.refused(self.ws.mixed(), "invoker_id is not the invoker this context will launch", invoker_id="other-invoker")
        self.refused(self.ws.mixed(), "invoker_id is not the invoker this context will launch", invoker_id=None)
        self.refused(self.ws.mixed(), "model is not on the runtime's model allow-list", allowed_models=(b14.OTHER_MODEL,))
        ps.plan_expansion(self.ws.spec([self.ws.tool_group()]), context=self.ws.context(invoker_id=None))


class ToolScopeTests(Case):
    def mounted(self, host_path: str) -> dict:
        group = self.ws.tool_group()
        group["tool_request"]["target_mounts"][0]["host_path"] = host_path
        return self.ws.spec([group])

    def test_relative_dotted_and_missing_mounts_are_refused(self):
        for label, path in (("relative", "targets/repo"), ("parent", str(self.ws.targets / "x" / ".." / "repo")),
                            ("dot", str(self.ws.targets) + "/./repo"), ("trailing slash", str(self.ws.target) + "/"),
                            ("missing", str(self.ws.targets / "absent")), ("marker", "/" + MARKER),
                            ("a file", str(self.ws.target / "main.c"))):
            with self.subTest(case=label):
                self.refused(self.mounted(path), "refuses this scope")

    def test_linked_mounts_are_refused(self):
        if not SYMLINKS:
            self.skipTest("this host cannot create symbolic links")
        (self.ws.targets / "alias").symlink_to(self.ws.target)
        self.refused(self.mounted(str(self.ws.targets / "alias")), "refuses this scope")
        (self.ws.base / "via").symlink_to(self.ws.targets)
        self.refused(self.mounted(str(self.ws.base / "via" / "repo")), "refuses this scope")

    def test_a_mount_outside_every_declared_mount_root_is_refused(self):
        outside = self.ws.base / "undeclared"
        outside.mkdir()
        self.refused(self.mounted(str(outside)), "target_mounts[0] is outside every declared mount root")
        self.refused(self.mounted(str(self.ws.target)), "outside every declared mount root", mount_roots=())
        ps.plan_expansion(self.mounted(str(self.ws.target)), context=self.ws.context(mount_roots=(self.ws.target,)))

    def test_nothing_that_is_contains_or_lies_beneath_the_pool_parent_is_mountable(self):
        first = self.expand(self.ws.mixed(attempt_id="attempt-first"))
        sibling = self.ws.instance_root(first, 3)
        (sibling / "scratch").mkdir()
        everything = (self.ws.base,)          # even when every directory is a declared mount root
        for label, path in (("the pool parent", self.ws.pool_parent), ("an ancestor of it", self.ws.data),
                            ("a sibling pool root", self.ws.root(first)),
                            ("a sibling pool's instances directory", self.ws.root(first) / ps.INSTANCES_DIR),
                            ("a sibling pool's requests directory", self.ws.root(first) / ps.REQUESTS_DIR),
                            ("another instance's root", sibling), ("another instance's scratch", sibling / "scratch")):
            with self.subTest(case=label):
                self.refused(self.mounted(str(path)), "applied at the pool parent, refuses this scope",
                             mount_roots=everything)

    def test_the_adapters_other_refusals_reach_the_specification(self):
        shell = self.ws.tool_group()
        shell["tool_request"]["argv"] = ["/bin/sh", "-c", "echo " + MARKER]
        self.refused(self.ws.spec([shell]), "argv[0] is a shell executable")
        image = self.ws.tool_group()
        image["tool_request"]["image"]["digest"] = "sha256:" + "0" * 64
        self.refused(self.ws.spec([image]), "image.digest is not the digest registered")
        empty = self.ws.base / "no-images"
        empty.mkdir()
        self.refused(self.ws.spec([self.ws.tool_group()]), "not a valid container image registry", images_dir=empty)


# ---- cross-instance path access, with the adapters' own rules against real directories -------------

class CrossInstanceAccessTests(Case):
    def setUp(self):
        super().setUp()
        self.spec = self.ws.mixed(3, 3)
        self.plan = self.expand(self.spec)
        self.context = self.ws.context()
        self.entries = self.plan.manifest["instances"]
        self.roots = [self.ws.instance_root(self.plan, index) for index in range(len(self.entries))]

    def ids(self, index):
        return {name: self.entries[index][name] for name in ("run_id", "job_id", "attempt_id")}

    def resolve(self, request, index, attempt_root):
        return pi.resolve_request(request, **self.ids(index), attempt_root=attempt_root,
                                  registry_dir=self.context.registry_dir, prompt_root=self.context.prompt_root,
                                  readable_roots=self.context.readable_roots,
                                  allowed_models=self.context.allowed_models)

    def mounts(self, request, attempt_root):
        return ce.request_mount_sources(request, attempt_root=attempt_root, host_flavor=self.context.host_flavor,
                                        docker_host=self.context.docker_host)

    def test_for_every_pair_neither_request_can_reach_the_others_root(self):
        pairs = 0
        for a, item in enumerate(self.plan.requests):
            request = ps.thaw(item.request)
            for b, other in enumerate(self.roots):
                if a == b:
                    continue
                pairs += 1
                victim = other / "private"
                victim.mkdir(exist_ok=True)
                (victim / "note.json").write_bytes(b'{"private": true}')
                if item.worker_kind == ps.PERSONA:
                    self.resolve(request, a, other)                  # the honest request reaches nothing of B's
                    self.resolve(request, a, self.roots[a])          # and resolves in its own root
                    forged = deepcopy(request)
                    path = victim / "note.json"
                    forged["readable_inputs"][1] = {
                        "root": "run-data", **b14.file_pin(path, path.relative_to(self.ws.data).as_posix()),
                        "role": "evidence", "producer_request_sha256": None}
                    for boundary in (other, self.ws.root(self.plan), self.context.pool_parent):
                        with self.assertRaises(pi.PersonaRequestError) as caught:
                            self.resolve(forged, a, boundary)
                        self.assertIn("is inside the attempt", str(caught.exception))
                else:
                    self.mounts(request, other)
                    self.mounts(request, self.roots[a])
                    for target in (other, victim):
                        forged = deepcopy(request)
                        forged["target_mounts"][0]["host_path"] = str(target)
                        for boundary in (other, self.ws.root(self.plan), self.context.pool_parent):
                            with self.assertRaises(ce.ContainerRequestError):
                                self.mounts(forged, boundary)
        self.assertEqual(pairs, 30)

    def test_writable_paths_stay_inside_the_instances_own_root(self):
        from execution_state import beneath
        for index, (entry, root) in enumerate(zip(self.entries, self.roots)):
            for path in entry["writable_paths"]:
                inside = beneath(root, root.joinpath(*path.split("/")))
                for other_index, other in enumerate(self.roots):
                    if other_index != index:
                        with self.assertRaises(ValueError):
                            beneath(other, inside)
                self.assertFalse(os.path.lexists(inside), "the adapter, not the expander, creates it")

    def test_the_expanded_requests_run_in_their_own_roots_and_verify(self):
        """Producible state: the real B14 adapter (fixture invoker) and the real B13 adapter
        (scripted docker) accept the expanded requests as they are, each in its private root."""
        import test_container_execution as b13_tests
        for index, item in enumerate(self.plan.requests):
            request, root = ps.thaw(item.request), self.roots[index]
            if item.worker_kind == ps.PERSONA:
                runtime = self.ws.persona.runtime(readable_roots=dict(self.context.readable_roots))
                result = pi.run_invocation(runtime, **self.ids(index), attempt_root=root, request=request)
                self.assertEqual((result["execution_status"], result["cause"]), ("OK", None))
                fields = self.ws.persona.runtime_fields(readable_roots=dict(self.context.readable_roots))
                self.assertEqual(pi.verify_invocation_result(
                    root, **self.ids(index), request=request,
                    **{name: fields[name] for name in ("registry_dir", "prompt_root", "readable_roots",
                                                       "allowed_models", "source_snapshot_sha256",
                                                       "registry_ceiling")}), [])
                self.assertEqual((root / "logs" / "persona" / pi.REQUEST_FILE).read_bytes(), item.data)
            else:
                first, second = b13_tests.ScriptedDocker().patches()
                with first, second:
                    result = ce.run_container(b13.runtime(), **self.ids(index), attempt_root=root, request=request)
                self.assertEqual((result["execution_status"], result["container_name"]),
                                 ("OK", ce.container_name(**self.ids(index))))
                self.assertEqual(ce.verify_container_result(
                    root, **self.ids(index), request=request, images_dir=ce.IMAGES_DIR, **b13.host_facts()), [])
                self.assertEqual((root / "logs" / "container" / ce.REQUEST_FILE).read_bytes(), item.data)
            self.assertEqual(sorted(p.name for p in root.iterdir()),
                             sorted({path.split("/")[0] for path in self.entries[index]["writable_paths"]}))
        # Launching fills the private roots; the expansion itself still verifies, byte for byte.
        self.assertEqual(self.verify(self.plan, self.spec), [])

    def test_a_request_is_refused_by_the_adapter_in_any_other_instances_identity(self):
        for a, item in enumerate(self.plan.requests):
            b = (a + 1) % len(self.roots)
            if self.plan.requests[b].worker_kind != item.worker_kind:
                continue
            errors = (pi if item.worker_kind == ps.PERSONA else ce).request_errors(ps.thaw(item.request), **self.ids(b))
            self.assertIn("request.attempt_id is not the attempt_id of the worker request it arrived in", errors)


# ---- the verifier ----------------------------------------------------------------------------------

def _mutations(value):
    """One replacement per JSON type, each different from the value."""
    if isinstance(value, bool):
        return [not value, MARKER]
    if isinstance(value, int):
        return [value + 1, MARKER]
    if isinstance(value, str):
        return [value + "x", MARKER, None] if value else [MARKER]
    if value is None:
        return [MARKER, "no_applicable_work"]
    if isinstance(value, list):
        return [value + [deepcopy(value[0])] if value else [MARKER], value[:-1] if value else [1], MARKER]
    return [MARKER, {}]


class VerifierTests(Case):
    def setUp(self):
        super().setUp()
        self.spec = self.ws.mixed(2, 2)
        self.plan = self.expand(self.spec)
        self.root = self.ws.root(self.plan)

    def errors(self, **over) -> list:
        arguments = {"expected_spec": self.spec, "context": self.ws.context()}
        arguments.update(over)
        errors = ps.verify_expansion(self.root, **arguments)
        self.assertNotIn(MARKER, json.dumps(errors))
        return errors

    def reseal(self, manifest: dict) -> None:
        manifest["expansion_sha256"] = ps.expansion_sha256(manifest)
        (self.root / ps.EXPANSION_FILE).write_bytes(ps.canonical_bytes(manifest))

    def test_the_honest_expansion_verifies_and_loads_immutably(self):
        self.assertEqual(self.errors(), [])
        loaded = ps.load_verified_expansion(self.root, expected_spec=self.spec, context=self.ws.context())
        self.assertEqual(loaded.manifest_bytes, (self.root / ps.EXPANSION_FILE).read_bytes())
        self.assertEqual(loaded, self.plan)

    def test_every_top_level_position_of_the_manifest_is_bound_even_when_resealed(self):
        honest = json.loads((self.root / ps.EXPANSION_FILE).read_text(encoding="utf-8"))
        self.assertEqual(sorted(honest), sorted(json.loads(
            (schema_validate.SCHEMAS_DIR / ps.EXPANSION_SCHEMA).read_text(encoding="utf-8"))["required"]))
        for name in sorted(honest):
            for position, replacement in enumerate(_mutations(honest[name])):
                with self.subTest(field=name, mutation=position):
                    edited = deepcopy(honest)
                    edited[name] = replacement
                    if name != "expansion_sha256":
                        self.reseal(edited)
                    else:
                        (self.root / ps.EXPANSION_FILE).write_bytes(ps.canonical_bytes(edited))
                    self.assertTrue(self.errors(), "an edited, resealed manifest verified")
        (self.root / ps.EXPANSION_FILE).write_bytes(self.plan.manifest_bytes)
        self.assertEqual(self.errors(), [])

    def test_every_position_of_every_instance_record_is_bound_even_when_resealed(self):
        honest = json.loads((self.root / ps.EXPANSION_FILE).read_text(encoding="utf-8"))
        for index in (0, 3):
            for name in sorted(honest["instances"][index]):
                with self.subTest(instance=index, field=name):
                    edited = deepcopy(honest)
                    edited["instances"][index][name] = _mutations(edited["instances"][index][name])[0]
                    self.reseal(edited)
                    errors = self.errors()
                    self.assertTrue(errors, "an edited, resealed instance record verified")
                    if not ps.validate_document(edited, ps.EXPANSION_SCHEMA):
                        self.assertIn("expansion.json field instances is not what the expected specification "
                                      "derives", errors)
        dropped = deepcopy(honest)
        del dropped["instances"][1]
        dropped["groups"][0]["instance_ids"].pop()
        dropped["totals"]["instances"] -= 1
        self.reseal(dropped)
        self.assertTrue(self.errors(), "a manifest that forgot an expected instance verified")

    def test_a_dishonest_producer_who_edits_one_request_and_reseals_every_hash_is_refused(self):
        manifest = json.loads((self.root / ps.EXPANSION_FILE).read_text(encoding="utf-8"))
        entry = manifest["instances"][2]
        path = self.root / entry["request_file"]["path"]
        request = json.loads(path.read_text(encoding="utf-8"))
        request["argv"] = ["/bin/cat", "/workspace/main.c"]
        data = ce.canonical_request_bytes(request)
        path.write_bytes(data)
        entry["request_file"].update(sha256=ps._bytes_sha(data), bytes=len(data))
        entry["request_sha256"] = ce.request_sha256(request)
        self.reseal(manifest)
        self.assertEqual(ce.request_errors(request, **{n: entry[n] for n in ("run_id", "job_id", "attempt_id")}), [])
        errors = self.errors()
        self.assertIn("the request file of instances[2] is not the request the expected specification derives", errors)
        self.assertIn("expansion.json field instances is not what the expected specification derives", errors)

    def test_a_request_file_edited_without_touching_the_manifest_is_refused(self):
        """The manifest still hashes the honest bytes: only READING the file notices."""
        for index, entry in enumerate(self.plan.manifest["instances"]):
            path = self.root / entry["request_file"]["path"]
            honest = path.read_bytes()
            for label, data in (("edited", honest.replace(b'"run_id"', b'"run_id" ')), ("emptied", b""),
                                ("marker", MARKER.encode())):
                with self.subTest(instance=index, case=label):
                    path.write_bytes(data)
                    self.assertEqual(self.errors(), [f"the request file of instances[{index}] is not the request "
                                                     "the expected specification derives"])
            path.write_bytes(honest)

    def test_the_specification_copy_is_read_and_bound(self):
        path = self.root / ps.SPEC_FILE
        edited = deepcopy(self.spec)
        edited["rendezvous_timeout_seconds"] += 1
        manifest = json.loads((self.root / ps.EXPANSION_FILE).read_text(encoding="utf-8"))
        data = ps.canonical_bytes(edited)
        path.write_bytes(data)
        manifest["specification_file"].update(sha256=ps._bytes_sha(data), bytes=len(data))
        manifest["spec_sha256"] = ps.spec_sha256(edited)
        self.reseal(manifest)
        errors = self.errors()
        self.assertIn("specification.json is not the canonical bytes of the expected specification", errors)
        self.assertIn("expansion.json field spec_sha256 is not what the expected specification derives", errors)

    def test_the_wrong_party_the_other_specification_does_not_verify_this_pool(self):
        other = deepcopy(self.spec)
        other["attempt_id"] = "attempt-other"
        self.assertEqual(self.errors(expected_spec=other),
                         ["pool_root is not the pool directory the expected specification derives beneath "
                          "context.pool_parent"])
        elsewhere = self.ws.base / "elsewhere"
        elsewhere.mkdir()
        self.assertEqual(self.errors(context=self.ws.context(pool_parent=elsewhere)),
                         ["pool_root is not the pool directory the expected specification derives beneath "
                          "context.pool_parent"])
        for spelling in (str(self.root), self.root.parent / "x" / ".." / self.root.name, self.root / "instances" / ".."):
            self.assertEqual(ps.verify_expansion(spelling, expected_spec=self.spec, context=self.ws.context()),
                             ["pool_root is not the pool directory the expected specification derives beneath "
                              "context.pool_parent"])

    def test_a_specification_the_expander_would_refuse_cannot_verify(self):
        """One shared rule: the verifier does not accept what the expander refuses."""
        (self.ws.data / "evidence" / "notes.md").write_bytes(b"evidence changed after expansion\n")
        errors = self.errors()
        self.assertEqual(len(errors), 1)
        self.assertIn("the expected specification is not expandable", errors[0])
        with self.assertRaises(ps.PoolSpecError):
            ps.plan_expansion(self.spec, context=self.ws.context())
        with self.assertRaises(ps.PoolSpecError):
            ps.load_verified_expansion(self.root, expected_spec=self.spec, context=self.ws.context())

    def test_the_expander_and_the_verifier_share_one_rule(self):
        source = inspect.getsource(ps)
        self.assertEqual(source.count("plan_expansion(spec, context=context)"), 1)
        self.assertEqual(source.count("plan_expansion(expected_spec, context=context)"), 2)
        with mock.patch.object(ps, "plan_expansion", side_effect=ps.PoolSpecError("refused")) as rule:
            with self.assertRaises(ps.PoolSpecError):
                ps.expand_pool(self.spec, context=self.ws.context())
            self.assertTrue(ps.verify_expansion(self.root, expected_spec=self.spec, context=self.ws.context()))
            self.assertEqual(rule.call_count, 2)

    def test_missing_extra_and_misplaced_entries(self):
        cases = {
            "an extra file in the pool root": lambda root, first: (root / "notes.txt").write_bytes(b"x"),
            "a leftover temporary file": lambda root, first: (root / ".abc.tmp").write_bytes(b"x"),
            "no manifest": lambda root, first: (root / ps.EXPANSION_FILE).unlink(),
            "no specification": lambda root, first: (root / ps.SPEC_FILE).unlink(),
            "a missing request": lambda root, first: (root / first["request_file"]["path"]).unlink(),
            "an extra request": lambda root, first: (root / ps.REQUESTS_DIR / (MARKER + ".json")).write_bytes(b"{}"),
            "a missing instance root": lambda root, first: (root / first["attempt_root"]).rmdir(),
            "an extra instance root": lambda root, first: (root / ps.INSTANCES_DIR / MARKER).mkdir(),
            "an instance root that is a file": lambda root, first: ((root / first["attempt_root"]).rmdir(),
                                                                    (root / first["attempt_root"]).write_bytes(b"")),
            "a request that is a directory": lambda root, first: ((root / first["request_file"]["path"]).unlink(),
                                                                  (root / first["request_file"]["path"]).mkdir()),
        }
        for label, damage in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as folder:
                ws = support.PoolWorkspace(Path(folder).resolve())
                spec = ws.mixed(2, 2)
                plan = ps.expand_pool(spec, context=ws.context())
                self.assertEqual(ps.verify_expansion(ws.root(plan), expected_spec=spec, context=ws.context()), [])
                damage(ws.root(plan), plan.manifest["instances"][0])
                errors = ps.verify_expansion(ws.root(plan), expected_spec=spec, context=ws.context())
                self.assertTrue(errors)
                self.assertNotIn(MARKER, json.dumps(errors))

    def test_links_are_refused_everywhere(self):
        if not SYMLINKS:
            self.skipTest("this host cannot create symbolic links")
        entries = self.plan.manifest["instances"]
        first, second = self.root / entries[0]["attempt_root"], self.root / entries[1]["attempt_root"]
        first.rmdir()
        first.symlink_to(second, target_is_directory=True)
        self.assertEqual(self.errors(), ["an instance root is a link, is not a directory, or two roots are one directory"])
        first.unlink()
        first.mkdir()
        self.assertEqual(self.errors(), [])
        request = self.root / entries[0]["request_file"]["path"]
        copy = self.ws.base / "request-copy.json"
        copy.write_bytes(request.read_bytes())
        request.unlink()
        request.symlink_to(copy)
        self.assertEqual(self.errors(), ["the request file of instances[0] is not the request the expected "
                                         "specification derives"])
        request.unlink()
        os.link(copy, request)
        self.assertEqual(self.errors(), ["the request file of instances[0] is not the request the expected "
                                         "specification derives"])
        request.unlink()
        request.write_bytes(copy.read_bytes())
        self.assertEqual(self.errors(), [])
        manifest = self.root / ps.EXPANSION_FILE
        moved = self.ws.base / "expansion-copy.json"
        moved.write_bytes(manifest.read_bytes())
        manifest.unlink()
        manifest.symlink_to(moved)
        self.assertEqual(self.errors(), ["expansion.json is missing, linked, hard-linked, oversized or unreadable"])

    def test_a_linked_pool_root_is_refused(self):
        if not SYMLINKS:
            self.skipTest("this host cannot create symbolic links")
        real = self.ws.base / "real-pool"
        self.root.rename(real)
        self.root.symlink_to(real, target_is_directory=True)
        self.assertEqual(self.errors(), ["the pool root is missing, is a link or is not a directory"])

    def test_malformed_manifest_bytes(self):
        honest = json.loads(self.plan.manifest_bytes)
        twice = self.plan.manifest_bytes.replace(
            b'{\n', b'{\n  "state": "' + MARKER.encode() + b'",\n', 1)
        self.assertEqual(json.loads(twice), honest, "the parser keeps the last reading")
        for label, data, fragment in (
                ("a repeated key", twice, "exactly one reading"),
                ("not JSON", b"\xff\xfe" + MARKER.encode(), "exactly one reading"),
                ("an array", b"[]", "exactly one reading"),
                ("NaN", b'{"schema": NaN}', "exactly one reading"),
                ("outside the schema", ps.canonical_bytes({**honest, MARKER: 1}), "fails its closed schema"),
                ("not canonical", json.dumps(honest).encode("utf-8"), "not in the canonical byte form"),
                ("oversized", b" " * (ps.MAX_DOCUMENT_BYTES + 1), "oversized")):
            with self.subTest(case=label):
                (self.root / ps.EXPANSION_FILE).write_bytes(data)
                errors = self.errors()
                self.assertEqual(len(errors), 1)
                self.assertIn(fragment, errors[0])

    def test_no_safety_input_is_optional(self):
        for function in (ps.plan_expansion, ps.expand_pool, ps.verify_expansion, ps.load_verified_expansion,
                         ps.instance_id, ps.pool_directory, ps.validate_context, ps.parse_document):
            for name, parameter in inspect.signature(function).parameters.items():
                self.assertIs(parameter.default, inspect.Parameter.empty, f"{function.__name__}({name})")
        for name in ("expected_spec", "context"):
            arguments = {"expected_spec": self.spec, "context": self.ws.context()}
            del arguments[name]
            with self.subTest(omitted=name), self.assertRaises(TypeError):
                ps.verify_expansion(self.root, **arguments)
        with self.assertRaises(TypeError):
            ps.verify_expansion(expected_spec=self.spec, context=self.ws.context())
        with self.assertRaises(TypeError):
            ps.expand_pool(self.spec)
        with self.assertRaises(TypeError):
            ps.plan_expansion(self.spec, context=self.ws.context_fields())
        for name in self.ws.context_fields():
            fields = self.ws.context_fields()
            del fields[name]
            with self.subTest(context_field=name), self.assertRaises(TypeError):
                ps.PoolContext(**fields)

    def test_the_context_is_validated(self):
        link = self.ws.base / "parent-link"
        if SYMLINKS:
            link.symlink_to(self.ws.pool_parent, target_is_directory=True)
        hostile = {
            "pool_parent": [Path("relative"), self.ws.base / "absent", str(self.ws.pool_parent),
                            self.ws.pool_parent / "." / "x" / "..", *([link] if SYMLINKS else [])],
            "registry_dir": [str(pi.REGISTRY_DIR)], "prompt_root": [None], "images_dir": [str(ce.IMAGES_DIR)],
            "readable_roots": [[], {"run-data": str(self.ws.data)}], "allowed_models": [[b14.MODEL]],
            "invoker_id": ["Not An Id", 7], "host_flavor": ["plan9"], "docker_host": [7],
            "mount_roots": [[self.ws.targets], (self.ws.base / "absent",), (str(self.ws.targets),)],
            "source_snapshot_sha256": ["sha256:short", None], "registry_ceiling": ["none", ()],
        }
        self.assertEqual(sorted(hostile), sorted(self.ws.context_fields()))
        for name, values in hostile.items():
            for value in values:
                with self.subTest(field=name, value=repr(value)[:40]), self.assertRaises(ps.PoolSpecError) as caught:
                    ps.plan_expansion(self.spec, context=self.ws.context(**{name: value}))
                self.assertIn(f"context.{name}", str(caught.exception))


class HostileTextTests(Case):
    def test_no_specification_value_reaches_a_message(self):
        """Every string position of a valid specification, one at a time, becomes the marker."""
        spec = self.ws.mixed(1, 1)
        positions = []

        def collect(node, path):
            if isinstance(node, dict):
                for key, value in node.items():
                    collect(value, path + [key])
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    collect(value, path + [index])
            elif isinstance(node, str):
                positions.append(path)
        collect(spec, [])
        self.assertGreater(len(positions), 60)
        accepted = 0
        for path in positions:
            edited = deepcopy(spec)
            node = edited
            for step in path[:-1]:
                node = node[step]
            node[path[-1]] = MARKER + " " + MARKER.upper()
            try:
                ps.plan_expansion(edited, context=self.ws.context())
                accepted += 1
            except ps.PoolSpecError as exc:
                self.assertNotIn(MARKER, str(exc).lower(), path)
        self.assertLessEqual(accepted, 3, "free text a specification may carry: grant authority and justification")

    def test_the_returned_records_are_deeply_immutable(self):
        spec = self.ws.mixed(1, 1)
        plan = self.expand(spec)
        with self.assertRaises(TypeError):
            plan.manifest["state"] = ps.EMPTY
        with self.assertRaises(TypeError):
            plan.manifest["instances"][0]["resource_pool"] = rp.CPU
        with self.assertRaises((TypeError, AttributeError)):
            plan.manifest["instances"].append({})
        with self.assertRaises(TypeError):
            plan.requests[1].request["argv"] = ()
        with self.assertRaises(TypeError):
            plan.requests[0].request["permission"]["decision"]["decision"] = pc.DENIED
        with self.assertRaises(TypeError):
            plan.specification["worker_groups"][0]["count"] = 9
        with self.assertRaises(AttributeError):
            plan.manifest_bytes = b""
        spec["worker_groups"][0]["count"] = 9           # the caller's copy is not the plan's
        self.assertEqual(plan.specification["worker_groups"][0]["count"], 1)

    def test_parse_document_rejects_a_repeated_key_at_any_depth(self):
        honest = ps.canonical_bytes(self.ws.mixed(1, 1))
        self.assertEqual(ps.parse_document(honest), self.ws.mixed(1, 1))
        nested = honest.replace(b'"max_instances":', b'"max_instances": 1,\n    "max_instances":', 1)
        self.assertNotEqual(nested, honest)
        for data in (nested, b"[1]", b'"text"', b"{", "text", b'{"a": Infinity}', b" " * (ps.MAX_DOCUMENT_BYTES + 1)):
            with self.assertRaises(ps.PoolSpecError) as caught:
                ps.parse_document(data)
            self.assertNotIn("max_instances", str(caught.exception))


class DocumentationTests(unittest.TestCase):
    DOC = ROOT.parent / "docs" / "pool-specification.md"

    def test_the_document_states_the_modules_constants(self):
        text = self.DOC.read_text(encoding="utf-8")
        for value in (ps.SPEC_ID, ps.EXPANSION_ID, ps.ID_DERIVATION_ID, ps.FINGERPRINT_ID, ps.SPEC_FILE,
                      ps.EXPANSION_FILE, *SCHEMAS, *ps.EMPTY_POOL_REASONS, *ps.WORKER_KINDS,
                      ps.TOOL_SCRATCH_PATH, ps.TOOL_LOG_PATH, ps.PERSONA_OUTPUT_ROOT, ps.PERSONA_LOG_PATH,
                      f"`MAX_INSTANCES` | {ps.MAX_INSTANCES}", f"`MAX_GROUPS` | {ps.MAX_GROUPS}",
                      f"`MAX_GROUP_COUNT` | {ps.MAX_GROUP_COUNT}",
                      f"`MAX_TOTAL_TIMEOUT_SECONDS` | {ps.MAX_TOTAL_TIMEOUT_SECONDS}",
                      "plan_expansion", "expand_pool", "verify_expansion", "load_verified_expansion",
                      "parse_document"):
            self.assertIn(value, text)
        readme = (schema_validate.SCHEMAS_DIR / "README.md").read_text(encoding="utf-8")
        for name in SCHEMAS:
            self.assertIn(name, readme)


if __name__ == "__main__":
    unittest.main()
