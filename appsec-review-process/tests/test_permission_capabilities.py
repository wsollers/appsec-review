"""Golden, mutation, fingerprint and redaction tests for the permission-capability model (B11).

One focused negative test per acceptance word: unknown, widened, target-controlled, missing,
stale, conflicting. Every one of them asserts the decision is DENIED with an empty capability set,
i.e. the job fails before work. Nothing here touches a worker, the launcher, the graph or a run.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import permission_capabilities as pc  # noqa: E402
from schema_validate import SchemaStore, validate_document  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "permission-capabilities"
ALL_SCHEMAS = [
    "permission-capability.schema.json",
    "permission-capability-parameters.schema.json",
    "permission-capability-entry.schema.json",
    "permission-requirement.schema.json",
    "permission-grant.schema.json",
    "permission-decision.schema.json",
    "permission-decision-ui.schema.json",
]
REQUIRED_KINDS = {
    "target-execution", "fixed-network-destination", "dynamic-testing", "debugger-ptrace",
    "credential-use", "package-restore", "target-mutation",
}
# Assembled at runtime so no secret-shaped literal is tracked in this repository.
SECRETS = {
    "github-token": "ghp_" + "a1B2" * 9,
    "aws-access-key": "AKIA" + "ABCDEFGHIJKLMNOP",
    "api-key": "sk-" + "Zx9" * 8,
    "bearer-token": "Bearer " + "abcDEF123456" * 2,
    "private-key": "-----BEGIN " + "PRIVATE KEY-----",
    "basic-auth-url": "https://deploy:" + "hunter2" + "@registry.example.com/",
    "high-entropy-token": "Q7x" + "m2Lp9Zr4Tn8Vb6Yc1Wd5Kf3Hj0Gs7Aa",
}
MARKER = "Tr0ub4dor&3 marker-value"  # not secret-shaped: proves free text is never echoed at all


def load(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def walk_schema(node, path="$"):
    if isinstance(node, dict):
        if node.get("type") == "object" and "properties" in node:
            yield path, node
        for key, value in node.items():
            yield from walk_schema(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk_schema(value, f"{path}[{index}]")


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = SchemaStore()
        cls.definitions = pc.load_definitions(store=cls.store)

    def setUp(self):
        self.requirement = load("requirement.golden.json")
        self.grants = load("grants.golden.json")
        self.context = load("context.golden.json")

    def evaluate(self, requirement=None, grants=None, context=None):
        return pc.evaluate(self.requirement if requirement is None else requirement,
                           self.grants if grants is None else grants,
                           context or self.context, self.definitions, self.store)

    def codes(self, decision):
        return {reason["code"] for reason in decision["reasons"]}

    def assertDenied(self, decision, *codes):
        self.assertEqual(decision["decision"], pc.DENIED, decision["reasons"])
        self.assertEqual(decision["capabilities"], [], "a denied decision must expose no capability")
        self.assertEqual(decision["grants_applied"], [])
        self.assertEqual(validate_document(decision, pc.DECISION_SCHEMA, self.store), [])
        self.assertEqual(pc.validate_decision(decision, self.store), [])
        for code in codes:
            self.assertIn(code, self.codes(decision))
        with self.assertRaises(pc.PermissionDenied):
            pc.input_fingerprint_component(decision)
        with self.assertRaises(pc.PermissionDenied):
            pc.require_granted(decision, run_id=self.context["run_id"], job_id=self.context["job_id"],
                               source_snapshot_sha256=self.context["source_snapshot_sha256"],
                               now=self.context["now"])

    def network_only(self):
        """Smallest scenario: one fixed network destination and one job-bound grant for it."""
        requirement = deepcopy(self.requirement)
        requirement["capabilities"] = requirement["capabilities"][:1]
        grant = deepcopy(self.grants[0])
        grant["capabilities"] = grant["capabilities"][:1]
        grant["binding"]["job_id"] = self.context["job_id"]
        return requirement, [grant]


class SchemaHygieneTests(Base):
    def test_every_schema_is_closed_and_fully_required(self):
        for name in ALL_SCHEMAS:
            schema = self.store.load(name)
            self.assertEqual(schema.get("$id"), name)
            nodes = list(walk_schema(schema))
            self.assertTrue(nodes)
            for path, node in nodes:
                self.assertIs(node.get("additionalProperties"), False, f"{name} {path} is not closed")
                self.assertEqual(set(node.get("required", [])), set(node["properties"]),
                                 f"{name} {path}: every declared property must be required")

    def test_schemas_use_only_the_supported_validator_subset(self):
        supported = {"$schema", "$id", "title", "description", "type", "required", "properties",
                     "additionalProperties", "enum", "const", "pattern", "items", "minItems", "$ref"}

        def keywords(node, inside_properties=False):
            if isinstance(node, dict):
                for key, value in node.items():
                    if not inside_properties:
                        yield key
                    yield from keywords(value, key == "properties" and not inside_properties)
            elif isinstance(node, list):
                for value in node:
                    yield from keywords(value)
        for name in ALL_SCHEMAS:
            self.assertLessEqual(set(keywords(self.store.load(name))), supported, name)

    def test_no_schema_offers_a_home_for_a_credential_value(self):
        for name in ALL_SCHEMAS:
            for path, node in walk_schema(self.store.load(name)):
                for prop in node["properties"]:
                    self.assertIsNone(pc.SECRET_FIELD_RE.search(prop), f"{name} {path}.{prop}")
                    self.assertNotIn(prop, {"value", "credential", "env", "environment", "headers"})

    def test_registry_covers_every_required_kind_with_default_deny(self):
        self.assertEqual({kind for kind, _ in self.definitions}, REQUIRED_KINDS)
        for record in self.definitions.values():
            self.assertEqual(record["default_decision"], "DENY")
            self.assertNotIn("registry", record["allowed_grant_origins"])
        enum = self.store.load("permission-capability.schema.json")["properties"]["kind"]["enum"]
        self.assertEqual(set(enum), REQUIRED_KINDS)

    def test_module_constants_match_schema_enums(self):
        params = self.store.load("permission-capability-parameters.schema.json")["properties"]
        self.assertEqual(tuple(params), pc.PARAMETER_NAMES)
        reasons = self.store.load(pc.DECISION_SCHEMA)["properties"]["reasons"]["items"]["properties"]["code"]["enum"]
        declared = {getattr(pc, name) for name in dir(pc) if name.isupper() and getattr(pc, name) == name}
        self.assertEqual(set(reasons), declared - {pc.GRANTED, pc.DENIED})
        origins = self.store.load(pc.ENTRY_SCHEMA)["properties"]["origin"]["enum"]
        self.assertLessEqual(set(pc.TARGET_CONTROLLED_ORIGINS), set(origins))

    def test_broken_registry_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(pc.PermissionModelError):
                pc.load_definitions(Path(tmp), self.store)
            record = deepcopy(self.definitions[("credential-use", "1.0")])
            record["default_decision"] = "ALLOW"
            (Path(tmp) / "credential-use.json").write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaises(pc.PermissionModelError):
                pc.load_definitions(Path(tmp), self.store)
            record["default_decision"] = "DENY"
            (Path(tmp) / "credential-use.json").unlink()
            (Path(tmp) / "renamed.json").write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaises(pc.PermissionModelError):
                pc.load_definitions(Path(tmp), self.store)


class GoldenTests(Base):
    def test_golden_inputs_validate(self):
        self.assertEqual(validate_document(self.requirement, pc.REQUIREMENT_SCHEMA, self.store), [])
        for grant in self.grants:
            self.assertEqual(validate_document(grant, pc.GRANT_SCHEMA, self.store), [])

    def test_golden_is_granted_with_the_exact_set(self):
        decision = self.evaluate()
        self.assertEqual(decision["decision"], pc.GRANTED, decision["reasons"])
        self.assertEqual(decision["reasons"], [])
        self.assertEqual(validate_document(decision, pc.DECISION_SCHEMA, self.store), [])
        self.assertEqual(pc.validate_decision(decision, self.store), [])
        self.assertEqual({c["kind"] for c in decision["capabilities"]}, REQUIRED_KINDS)
        expected = sorted(json.dumps(c["parameters"], sort_keys=True) for c in self.requirement["capabilities"])
        self.assertEqual(sorted(json.dumps(c["parameters"], sort_keys=True) for c in decision["capabilities"]),
                         expected)
        self.assertEqual([g["grant_id"] for g in decision["grants_applied"]],
                         ["grant-dynamic", "grant-network-restore"])
        self.assertEqual(decision["valid_until"], "2026-09-26T00:00:00Z")
        caps = pc.require_granted(decision, run_id=self.context["run_id"], job_id=self.context["job_id"],
                                  source_snapshot_sha256=self.context["source_snapshot_sha256"],
                                  now=self.context["now"])
        self.assertEqual(caps, decision["capabilities"])

    def test_default_deny_with_no_grants(self):
        decision = self.evaluate(grants=[])
        self.assertDenied(decision, pc.MISSING_GRANT)
        self.assertEqual(len(decision["reasons"]), len(self.requirement["capabilities"]))

    def test_a_job_requiring_nothing_is_granted_the_empty_set(self):
        requirement = {**self.requirement, "capabilities": []}
        decision = self.evaluate(requirement, [g for g in self.grants if g["binding"]["job_id"] is None])
        self.assertEqual(decision["decision"], pc.GRANTED)
        self.assertEqual(decision["capabilities"], [])
        self.assertEqual(decision["grants_applied"], [])

    def test_evaluate_is_pure(self):
        before = json.dumps([self.requirement, self.grants, self.context], sort_keys=True)
        first, second = self.evaluate(), self.evaluate()
        self.assertEqual(first, second)
        self.assertEqual(json.dumps([self.requirement, self.grants, self.context], sort_keys=True), before)

    def test_malformed_trusted_context_raises_without_echo(self):
        for key, value in (("now", "yesterday"), ("run_id", "../x"), ("source_snapshot_sha256", "abc")):
            with self.assertRaises(pc.PermissionModelError) as caught:
                self.evaluate(context={**self.context, key: value})
            self.assertNotIn(value, str(caught.exception))
        with self.assertRaises(pc.PermissionModelError):
            self.evaluate(context={k: v for k, v in self.context.items() if k != "now"})

    def test_requirement_for_another_job_is_rejected(self):
        self.assertDenied(self.evaluate({**self.requirement, "job_id": "02-ossf-scorecard"}), pc.CONTEXT_MISMATCH)

    def test_require_granted_rechecks_binding_and_expiry(self):
        decision = self.evaluate()
        args = dict(run_id=self.context["run_id"], job_id=self.context["job_id"],
                    source_snapshot_sha256=self.context["source_snapshot_sha256"], now=self.context["now"])
        for change in ({"run_id": "other-run"}, {"job_id": "other-job"},
                       {"source_snapshot_sha256": "sha256:" + "0" * 64}, {"now": "2026-09-26T00:00:00Z"}):
            with self.assertRaises(pc.PermissionDenied):
                pc.require_granted(decision, **{**args, **change})
        tampered = deepcopy(decision)
        tampered["capabilities"][0]["parameters"]["port"] = 8443
        with self.assertRaises(pc.PermissionDenied):
            pc.require_granted(tampered, **args)


class AcceptanceWordTests(Base):
    def test_unknown_capability_kind_or_version_fails_before_work(self):
        for field, value in (("kind", "raw-socket"), ("version", "9.9")):
            requirement = deepcopy(self.requirement)
            requirement["capabilities"][0][field] = value
            self.assertDenied(self.evaluate(requirement), pc.UNKNOWN_CAPABILITY)
            grants = deepcopy(self.grants)
            grants[0]["capabilities"][0][field] = value
            decision = self.evaluate(grants=grants)
            self.assertDenied(decision, pc.UNKNOWN_CAPABILITY, pc.MISSING_GRANT)
            self.assertNotIn(value, json.dumps(decision))

    def test_widened_grant_fails_before_work(self):
        cases = {
            "wildcard host": ("host", "*.scorecard.dev"),
            "bare wildcard": ("host", "*"),
            "cidr": ("host", "10.0.0.0/8"),
            "any port": ("port", 0),
            "null port": ("port", None),
            "port range": ("port", "443-8443"),
            "port list": ("port", [443, 8443]),
        }
        for label, (name, value) in cases.items():
            with self.subTest(label):
                requirement, grants = self.network_only()
                grants[0]["capabilities"][0]["parameters"][name] = value
                self.assertDenied(self.evaluate(requirement, grants), pc.WIDENED_GRANT)
        with self.subTest("extra port beyond the requirement"):
            requirement, grants = self.network_only()
            extra = deepcopy(grants[0]["capabilities"][0])
            extra["parameters"]["port"] = 8443
            grants[0]["capabilities"].append(extra)
            self.assertDenied(self.evaluate(requirement, grants), pc.WIDENED_GRANT)
        with self.subTest("broader path"):
            grants = deepcopy(self.grants)
            for entry in grants[1]["capabilities"]:
                if entry["kind"] == "target-mutation":
                    entry["parameters"]["target_path"] = "packages"
            self.assertDenied(self.evaluate(grants=grants), pc.WIDENED_GRANT)
        with self.subTest("whole-tree path from a run-wide grant"):
            grants = deepcopy(self.grants)
            for grant in grants:
                grant["binding"]["job_id"] = None
                for entry in grant["capabilities"]:
                    if entry["kind"] == "target-execution":
                        entry["parameters"]["target_path"] = "."
            self.assertDenied(self.evaluate(grants=grants), pc.WIDENED_GRANT)

    def test_widened_requirement_fails_before_work(self):
        for label, kind, name, value in (
                ("wildcard host", "fixed-network-destination", "host", "*.npmjs.org"),
                ("path escape", "target-mutation", "target_path", "packages/../.."),
                ("absolute path", "target-mutation", "target_path", "/etc"),
                ("windows path", "target-mutation", "target_path", "C:\\Windows"),
                ("unbounded technique", "dynamic-testing", "technique", None)):
            with self.subTest(label):
                requirement = deepcopy(self.requirement)
                for entry in requirement["capabilities"]:
                    if entry["kind"] == kind:
                        entry["parameters"][name] = value
                self.assertDenied(self.evaluate(requirement), pc.WIDENED_REQUIREMENT)
        with self.subTest("requirement exceeds the registry ceiling"):
            ceiling = deepcopy(self.requirement["capabilities"][:3])
            decision = self.evaluate(context={**self.context, "registry_ceiling": ceiling})
            self.assertDenied(decision, pc.WIDENED_REQUIREMENT)
            full = deepcopy(self.requirement["capabilities"])
            self.assertEqual(self.evaluate(context={**self.context, "registry_ceiling": full})["decision"],
                             pc.GRANTED)
        with self.subTest("ceiling itself must come from the registry"):
            ceiling = deepcopy(self.requirement["capabilities"])
            ceiling[0]["origin"] = "staged-run-config"
            self.assertDenied(self.evaluate(context={**self.context, "registry_ceiling": ceiling}),
                              pc.TARGET_CONTROLLED)

    def test_target_controlled_values_fail_before_work(self):
        for origin in pc.TARGET_CONTROLLED_ORIGINS:
            with self.subTest(f"grant:{origin}"):
                grants = deepcopy(self.grants)
                grants[0]["capabilities"][0]["origin"] = origin
                self.assertDenied(self.evaluate(grants=grants), pc.TARGET_CONTROLLED)
            with self.subTest(f"requirement:{origin}"):
                requirement = deepcopy(self.requirement)
                requirement["capabilities"][0]["origin"] = origin
                self.assertDenied(self.evaluate(requirement), pc.TARGET_CONTROLLED)
        with self.subTest("the registry cannot grant"):
            grants = deepcopy(self.grants)
            grants[0]["capabilities"][0]["origin"] = "registry"
            self.assertDenied(self.evaluate(grants=grants), pc.TARGET_CONTROLLED)
        with self.subTest("missing origin is not trusted"):
            requirement = deepcopy(self.requirement)
            del requirement["capabilities"][0]["origin"]
            self.assertDenied(self.evaluate(requirement), pc.TARGET_CONTROLLED)

    def test_missing_grant_fails_before_work(self):
        grants = deepcopy(self.grants)
        removed = grants[1]["capabilities"].pop()
        decision = self.evaluate(grants=grants)
        self.assertDenied(decision, pc.MISSING_GRANT)
        self.assertEqual(self.codes(decision), {pc.MISSING_GRANT})
        self.assertEqual([r["capability_key"].split("@")[0] for r in decision["reasons"]], [removed["kind"]])
        with self.subTest("a near-miss grant is not a grant"):
            requirement, grants = self.network_only()
            grants[0]["binding"]["job_id"] = None
            grants[0]["capabilities"][0]["parameters"]["host"] = "api.securityscorecards.dev"
            self.assertEqual(self.codes(self.evaluate(requirement, grants)), {pc.MISSING_GRANT})
        with self.subTest("a grant for another job is not a grant"):
            requirement, grants = self.network_only()
            grants[0]["binding"]["job_id"] = "02-ossf-scorecard"
            self.assertEqual(self.codes(self.evaluate(requirement, grants)), {pc.MISSING_GRANT})

    def test_stale_grant_fails_before_work(self):
        cases = {
            "expired": lambda g: g.update(expires_at="2026-09-20T12:00:00Z"),
            "not yet valid": lambda g: g.update(issued_at="2026-09-21T00:00:00Z"),
            "different run": lambda g: g["binding"].update(run_id="20260101T000000Z-older1"),
            "different snapshot": lambda g: g["binding"].update(source_snapshot_sha256="sha256:" + "cd" * 32),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                grants = deepcopy(self.grants)
                mutate(grants[1])
                decision = self.evaluate(grants=grants)
                self.assertDenied(decision, pc.STALE_GRANT)
                self.assertEqual(self.codes(decision), {pc.STALE_GRANT})
        with self.subTest("a current grant beside a stale one still grants"):
            stale = deepcopy(self.grants[1])
            stale.update(grant_id="grant-dynamic-old", issued_at="2026-09-01T00:00:00Z",
                         expires_at="2026-09-02T00:00:00Z")
            decision = self.evaluate(grants=self.grants + [stale])
            self.assertEqual(decision["decision"], pc.GRANTED)
            self.assertNotIn("grant-dynamic-old", [g["grant_id"] for g in decision["grants_applied"]])
        with self.subTest("expiry before issue is invalid, not current"):
            grants = deepcopy(self.grants)
            grants[1].update(issued_at="2026-09-20T00:00:00Z", expires_at="2026-09-19T00:00:00Z")
            self.assertDenied(self.evaluate(grants=grants), pc.INVALID_RECORD)

    def test_conflicting_grants_fail_before_work_and_deny_wins(self):
        deny = deepcopy(self.grants[0])
        deny.update(grant_id="deny-credential", effect="DENY")
        deny["capabilities"] = [c for c in deny["capabilities"] if c["kind"] == "credential-use"]
        decision = self.evaluate(grants=self.grants + [deny])
        self.assertDenied(decision, pc.CONFLICTING_GRANTS, pc.EXPLICIT_DENY)
        denied = [r for r in decision["reasons"] if r["code"] == pc.EXPLICIT_DENY]
        self.assertEqual([r["grant_id"] for r in denied], ["deny-credential"])
        self.assertTrue(all(r["capability_key"].startswith("credential-use@") for r in decision["reasons"]))
        self.assertEqual(self.evaluate(grants=[deny] + self.grants), decision)
        with self.subTest("kind-wide deny"):
            for name in pc.PARAMETER_NAMES:
                deny["capabilities"][0]["parameters"][name] = None
            self.assertDenied(self.evaluate(grants=self.grants + [deny]), pc.CONFLICTING_GRANTS, pc.EXPLICIT_DENY)
        with self.subTest("deny without any allow is an explicit deny, not a conflict"):
            only = [g for g in self.grants + [deny] if g["grant_id"] != "grant-network-restore"]
            codes = self.codes(self.evaluate(grants=only))
            self.assertIn(pc.EXPLICIT_DENY, codes)
            self.assertNotIn(pc.CONFLICTING_GRANTS, codes)
        with self.subTest("one grant_id, two different contents"):
            twin = deepcopy(self.grants[1])
            twin["justification"] = "A different approval text."
            self.assertDenied(self.evaluate(grants=self.grants + [twin]), pc.CONFLICTING_GRANTS)
        with self.subTest("an expired deny no longer applies"):
            deny.update(issued_at="2026-09-01T00:00:00Z", expires_at="2026-09-02T00:00:00Z")
            self.assertEqual(self.evaluate(grants=self.grants + [deny])["decision"], pc.GRANTED)

    def test_structurally_invalid_records_fail_before_work(self):
        for label, mutate in (
                ("extra property", lambda r, g: g[0].update(note="x")),
                ("missing authority", lambda r, g: g[0].pop("authority")),
                ("anonymous authority", lambda r, g: g[0]["authority"].update(name="")),
                ("parameter of another kind", lambda r, g: r["capabilities"][0]["parameters"].update(ecosystem="npm")),
                ("out-of-range port", lambda r, g: r["capabilities"][0]["parameters"].update(port=70000)),
                ("address literal host", lambda r, g: r["capabilities"][0]["parameters"].update(host="10.0.0.1")),
                ("single-label host", lambda r, g: r["capabilities"][0]["parameters"].update(host="localhost")),
                ("uppercase host", lambda r, g: r["capabilities"][0]["parameters"].update(host="API.Scorecard.dev")),
                ("duplicate requirement", lambda r, g: r["capabilities"].append(deepcopy(r["capabilities"][0]))),
                ("newline smuggling", lambda r, g: g[0].update(justification="ok\nok"))):
            with self.subTest(label):
                requirement, grants = deepcopy(self.requirement), deepcopy(self.grants)
                mutate(requirement, grants)
                self.assertDenied(self.evaluate(requirement, grants), pc.INVALID_RECORD)
        self.assertDenied(self.evaluate(grants={"not": "a list"}), pc.INVALID_RECORD)
        self.assertDenied(self.evaluate(requirement=["not", "an", "object"]), pc.INVALID_RECORD)


class FingerprintTests(Base):
    def fingerprint(self, requirement=None, grants=None):
        decision = self.evaluate(requirement, grants)
        self.assertEqual(decision["decision"], pc.GRANTED, decision["reasons"])
        return pc.input_fingerprint_component(decision)

    def test_digest_matches_the_shared_runtime_digest(self):
        import execution_state
        for value in ({"b": [1, 2], "a": None}, [], "x", self.requirement):
            self.assertEqual(pc.digest(value), execution_state.digest(value))

    def test_fingerprint_is_deterministic_and_self_describing(self):
        decision = self.evaluate()
        material = decision["fingerprint_material"]
        self.assertEqual(material["sha256"], self.fingerprint())
        body = {k: material[k] for k in ("schema", "decision", "capabilities")}
        self.assertEqual(material["sha256"], "sha256:" + pc.digest(body))
        self.assertEqual(material["capabilities"], decision["capabilities"])
        self.assertRegex(material["sha256"], r"^sha256:[0-9a-f]{64}$")

    def test_grant_and_requirement_order_do_not_matter(self):
        baseline = self.evaluate()
        rng = random.Random(11)
        for _ in range(10):
            requirement, grants = deepcopy(self.requirement), deepcopy(self.grants)
            rng.shuffle(requirement["capabilities"])
            rng.shuffle(grants)
            for grant in grants:
                rng.shuffle(grant["capabilities"])
            decision = self.evaluate(requirement, grants)
            self.assertEqual(decision["fingerprint_material"], baseline["fingerprint_material"])
            self.assertEqual(decision["capabilities"], baseline["capabilities"])
            self.assertEqual(decision["grants_applied"], baseline["grants_applied"])
        self.assertEqual(self.evaluate(grants=list(reversed(self.grants))), baseline)
        self.assertEqual(self.evaluate(grants=self.grants + deepcopy(self.grants)), baseline)

    def test_denied_reasons_do_not_depend_on_grant_order(self):
        grants = deepcopy(self.grants)
        grants[0]["capabilities"][0]["origin"] = "target-repository"
        grants[1]["expires_at"] = "2026-09-20T00:00:00Z"
        self.assertEqual(self.evaluate(grants=grants), self.evaluate(grants=list(reversed(grants))))

    def test_any_change_in_the_exact_set_changes_the_fingerprint(self):
        baseline = self.fingerprint()
        seen = {baseline}
        for kind, name, value in (("fixed-network-destination", "port", 8443),
                                  ("fixed-network-destination", "host", "api.securityscorecards.dev"),
                                  ("fixed-network-destination", "scheme", "http"),
                                  ("credential-use", "credential_ref", "cred:npm-other"),
                                  ("credential-use", "credential_scope", "read-only-api"),
                                  ("target-mutation", "target_path", "packages"),
                                  ("dynamic-testing", "technique", "fuzzing"),
                                  ("debugger-ptrace", "attach_mode", "debugger-child"),
                                  ("package-restore", "ecosystem", "pypi")):
            requirement, grants = deepcopy(self.requirement), deepcopy(self.grants)
            for entry in requirement["capabilities"] + [c for g in grants for c in g["capabilities"]]:
                if entry["kind"] == kind:
                    entry["parameters"][name] = value
            fingerprint = self.fingerprint(requirement, grants)
            self.assertNotIn(fingerprint, seen, f"{kind}.{name}")
            seen.add(fingerprint)
        with self.subTest("removing a capability"):
            requirement, grants = deepcopy(self.requirement), deepcopy(self.grants)
            requirement["capabilities"].pop()
            grants[1]["capabilities"].pop()
            self.assertNotIn(self.fingerprint(requirement, grants), seen)
        with self.subTest("a changed capability definition"):
            definitions = deepcopy(self.definitions)
            definitions[("target-mutation", "1.0")]["boundary_notes"].append("Revised boundary.")
            changed = pc.evaluate(self.requirement, self.grants, self.context, definitions, self.store)
            self.assertNotIn(changed["fingerprint_material"]["sha256"], seen)

    def test_reissued_identical_grant_does_not_change_the_fingerprint(self):
        grants = deepcopy(self.grants)
        grants[1].update(grant_id="grant-dynamic-reissued", expires_at="2026-09-30T00:00:00Z")
        self.assertEqual(self.fingerprint(grants=grants), self.fingerprint())

    def test_widened_grant_never_yields_the_granted_fingerprint(self):
        granted = self.evaluate()["fingerprint_material"]["sha256"]
        requirement, grants = self.network_only()
        narrow = self.evaluate(requirement, grants)["fingerprint_material"]["sha256"]
        extra = deepcopy(grants[0]["capabilities"][0])
        extra["parameters"]["port"] = 8443
        grants[0]["capabilities"].append(extra)
        widened = self.evaluate(requirement, grants)
        self.assertDenied(widened, pc.WIDENED_GRANT)
        self.assertNotIn(widened["fingerprint_material"]["sha256"], {granted, narrow})


class RedactionTests(Base):
    def outputs(self, decision):
        return json.dumps(decision, sort_keys=True) + json.dumps(pc.ui_safe_projection(decision), sort_keys=True)

    def placements(self, value):
        """Every place an operator mistake or a hostile staged file could put a credential value."""
        def in_requirement(mutate):
            requirement = deepcopy(self.requirement)
            mutate(requirement)
            return requirement, deepcopy(self.grants)

        def in_grant(mutate):
            grants = deepcopy(self.grants)
            mutate(grants[0])
            return deepcopy(self.requirement), grants
        cred = lambda record: next(c for c in record["capabilities"] if c["kind"] == "credential-use")  # noqa: E731
        return {
            "grant credential_ref": in_grant(lambda g: cred(g)["parameters"].update(credential_ref=value)),
            "requirement credential_ref": in_requirement(lambda r: cred(r)["parameters"].update(credential_ref=value)),
            "grant extra credential_value": in_grant(lambda g: cred(g)["parameters"].update(credential_value=value)),
            "grant extra password": in_grant(lambda g: g.update(password=value)),
            "grant justification": in_grant(lambda g: g.update(justification="use " + value)),
            "grant authority name": in_grant(lambda g: g["authority"].update(name=value)),
            "grant id": in_grant(lambda g: g.update(grant_id=value)),
            "grant host": in_grant(lambda g: g["capabilities"][0]["parameters"].update(host=value)),
            "requirement kind": in_requirement(lambda r: r["capabilities"][0].update(kind=value)),
            "requirement property name": in_requirement(lambda r: r.update({value: "x"})),
            "requirement command profile": in_requirement(
                lambda r: r["capabilities"][3]["parameters"].update(command_profile_id=value)),
        }

    def test_secret_shaped_values_anywhere_are_rejected_and_never_echoed(self):
        for label, secret in SECRETS.items():
            for place, (requirement, grants) in self.placements(secret).items():
                with self.subTest(f"{label} in {place}"):
                    decision = self.evaluate(requirement, grants)
                    self.assertDenied(decision, pc.SECRET_MATERIAL)
                    self.assertEqual(self.codes(decision), {pc.SECRET_MATERIAL})
                    self.assertIsNone(decision["inputs"]["requirement_sha256"])
                    self.assertIsNone(decision["inputs"]["grants_sha256"])
                    rendered = self.outputs(decision)
                    self.assertNotIn(secret, rendered)
                    self.assertNotIn(secret[-12:], rendered)

    def test_unrecognizable_free_text_is_never_echoed(self):
        for place, (requirement, grants) in self.placements(MARKER).items():
            with self.subTest(place):
                rendered = self.outputs(self.evaluate(requirement, grants))
                self.assertNotIn(MARKER, rendered)
                self.assertNotIn("Tr0ub4dor", rendered)

    def test_credential_value_in_the_reference_field_is_named(self):
        requirement, grants = self.placements("hunter2")["grant credential_ref"]
        decision = self.evaluate(requirement, grants)
        self.assertDenied(decision, pc.SECRET_MATERIAL)
        self.assertIn("credential-value-in-reference-field", json.dumps(decision))
        self.assertNotIn("hunter2", self.outputs(decision))

    def test_granted_records_carry_a_reference_id_and_the_ui_projection_not_even_that(self):
        decision = self.evaluate()
        tracked = json.dumps(decision)
        self.assertIn("cred:npm-readonly", tracked)
        for text in ("Pat Example", "engagement-owner", "Approved dynamic test window"):
            self.assertNotIn(text, tracked)
        projection = pc.ui_safe_projection(decision)
        self.assertEqual(validate_document(projection, pc.DECISION_UI_SCHEMA, self.store), [])
        rendered = json.dumps(projection)
        for text in ("cred:", "npm-readonly", "Pat Example", "detail", "justification"):
            self.assertNotIn(text, rendered)
        self.assertEqual(projection["fingerprint_sha256"], decision["fingerprint_material"]["sha256"])
        self.assertEqual(len(projection["capabilities"]), len(decision["capabilities"]))

    def test_denied_ui_projection_is_schema_valid_and_names_codes_only(self):
        grants = deepcopy(self.grants)
        grants[1]["expires_at"] = "2026-09-20T00:00:00Z"
        projection = pc.ui_safe_projection(self.evaluate(grants=grants))
        self.assertEqual(validate_document(projection, pc.DECISION_UI_SCHEMA, self.store), [])
        self.assertEqual({r["code"] for r in projection["reasons"]}, {pc.STALE_GRANT})
        self.assertTrue(all(set(r) == {"code", "capability_kind", "grant_id"} for r in projection["reasons"]))

    def test_output_guards_refuse_tampered_records(self):
        decision = self.evaluate()
        tampered = deepcopy(decision)
        tampered["reasons"] = []
        tampered["grants_applied"][0]["grant_id"] = SECRETS["high-entropy-token"]
        with self.assertRaises(pc.PermissionModelError) as caught:
            pc.ui_safe_projection(tampered)
        self.assertNotIn(SECRETS["high-entropy-token"], str(caught.exception))
        with self.assertRaises(pc.PermissionModelError) as caught:
            pc.assert_no_secret_material({"authority": {"name": SECRETS["github-token"]}})
        self.assertNotIn(SECRETS["github-token"], str(caught.exception))

    def test_tracked_registry_and_fixtures_hold_no_secret_material(self):
        paths = sorted(pc.DEFINITIONS_DIR.glob("*.json")) + sorted(FIXTURES.rglob("*.json"))
        self.assertGreaterEqual(len(paths), 10)
        for path in paths:
            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(pc.secret_findings(record), [], path.name)


if __name__ == "__main__":
    unittest.main()
