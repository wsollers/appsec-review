"""Pool specification (C01) against other slices: the V06 redactor, a T06 OWASP validator handoff,
a B13 container result and a B14 persona result offered where a specification, a manifest or a
request file is expected; and a T06 handoff carried as a pool's readable input."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_execution as ce  # noqa: E402
import container_execution_support as b13  # noqa: E402
import evidence_redaction  # noqa: E402
import persona_invocation as pi  # noqa: E402
import persona_invocation_support as b14  # noqa: E402
import pool_specification as ps  # noqa: E402
import pool_specification_support as support  # noqa: E402
from pool_specification_support import MARKER, NETWORK  # noqa: E402


class Case(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.ws = support.PoolWorkspace(Path(self.temporary.name).resolve())


class RedactionSurvivalTests(Case):
    """The redactor replaces the VALUE under any secret-looking key and any secret-shaped string.
    A pool root that changed when published would stop verifying."""

    def test_every_published_document_survives_the_redactor_unchanged(self):
        for label, capabilities in (("empty grant set", None), ("granted network capability", NETWORK)):
            with self.subTest(case=label):
                spec = self.ws.spec([self.ws.persona_group("reviewers", 2, capabilities=capabilities),
                                     self.ws.tool_group("scanners", 2, capabilities=capabilities)],
                                    attempt_id="attempt-" + label.split()[0])
                plan = ps.expand_pool(spec, context=self.ws.context())
                published = self.ws.base / ("published-" + label.split()[0])
                receipt = evidence_redaction.redact_tree(self.ws.root(plan), published, on_unhandled="refuse",
                                                         limits=evidence_redaction.DEFAULT_LIMITS)
                expected = sorted([ps.EXPANSION_FILE, ps.SPEC_FILE, *(item.relative_path for item in plan.requests)])
                self.assertEqual([(r["path"], r["disposition"]) for r in receipt["files"]],
                                 [(name, "unchanged") for name in expected])
                for name in expected:
                    self.assertEqual((published / name).read_bytes(), (self.ws.root(plan) / name).read_bytes())

    def test_no_property_name_in_the_manifest_is_secret_looking(self):
        plan = ps.plan_expansion(self.ws.mixed(), context=self.ws.context())
        names: set = set()

        def collect(node):
            if isinstance(node, dict):
                names.update(node)
                for value in node.values():
                    collect(value)
            elif isinstance(node, list):
                for value in node:
                    collect(value)
        collect(ps.thaw(plan.manifest))
        spec = ps.thaw(plan.specification)
        for group in spec["worker_groups"]:          # B11 / B13 / B14 vocabulary is theirs
            group["permission"] = group["persona_request"] = group["tool_request"] = None
        collect(spec)
        for name in sorted(names):
            self.assertIsNone(evidence_redaction._KEYWORD_RE.search(name), name)


class ForeignDocumentTests(Case):
    """Documents of other slices are canonical, self-hashed JSON too. None of them is a pool
    specification, an expansion manifest or a request of the other kind."""

    def setUp(self):
        super().setUp()
        import test_container_execution as b13_tests
        import test_owasp_validator_handoff as t06
        import owasp_validator_handoff
        fixture = t06.OwaspValidatorHandoffTests("setUp")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        _, request_path, *_ = fixture.publish_upstream(count=1)
        built = owasp_validator_handoff.build(fixture.run_id, request_path)
        attempt = fixture.data / "jobs" / owasp_validator_handoff.JOB_ID / "whole" / "attempts" / built["attempt_id"]
        handoff_set = json.loads((attempt / "outputs" / "owasp-validator-handoff-set.json").read_text(encoding="utf-8"))
        self.owasp_data = fixture.data
        self.handoff_path = attempt / handoff_set["handoffs"][0]["path"]
        self.handoff = json.loads(self.handoff_path.read_text(encoding="utf-8"))

        container_attempt = self.ws.base / "container-attempt"
        container_attempt.mkdir()
        first, second = b13_tests.ScriptedDocker(stdout=(MARKER + "\n").encode()).patches()
        with first, second:
            container = b13.run(b13.runtime(), container_attempt, b13.request(self.ws.target, ["/bin/echo", "x"]))
        persona = b14.Workspace(self.ws.base / "b14")
        self.foreign = {
            "a T06 validator handoff": self.handoff,
            "a B13 container result": ce.thaw(container),
            "a B14 persona result": pi.thaw(persona.run(persona.request())),
            "a B13 request": b13.request(self.ws.target, ["/bin/echo", "x"]),
            "a B14 request": persona.request(),
        }

    def test_a_foreign_document_is_not_a_specification(self):
        for label, document in self.foreign.items():
            with self.subTest(document=label):
                document = {**document, "wait_all": True}        # even when it borrows the one required word
                before = support.tree(self.ws.pool_parent)
                with self.assertRaises(ps.PoolSpecError) as caught:
                    ps.expand_pool(document, context=self.ws.context())
                self.assertIn("fails its closed schema", str(caught.exception))
                self.assertNotIn(MARKER, str(caught.exception))
                for value in (document.get("handoff_id"), document.get("result_sha256")):
                    if value:
                        self.assertNotIn(value, str(caught.exception))
                self.assertEqual(support.tree(self.ws.pool_parent), before)
                self.assertEqual(ps.spec_errors({k: v for k, v in document.items() if k != "wait_all"})[0][:8],
                                 "wait_all")

    def test_a_foreign_document_is_not_a_manifest_a_specification_copy_or_a_request(self):
        spec = self.ws.mixed(1, 1)
        plan = ps.expand_pool(spec, context=self.ws.context())
        root = self.ws.root(plan)
        targets = [ps.EXPANSION_FILE, ps.SPEC_FILE, *(item.relative_path for item in plan.requests)]
        for label, document in self.foreign.items():
            for name in targets:
                with self.subTest(document=label, file=name):
                    honest = (root / name).read_bytes()
                    (root / name).write_bytes(ps.canonical_bytes(document))
                    errors = ps.verify_expansion(root, expected_spec=spec, context=self.ws.context())
                    self.assertEqual(len(errors), 1)
                    self.assertNotIn(MARKER, errors[0])
                    (root / name).write_bytes(honest)
        self.assertEqual(ps.verify_expansion(root, expected_spec=spec, context=self.ws.context()), [])

    def test_a_request_of_the_other_kind_cannot_stand_in_for_a_template(self):
        spec = self.ws.mixed(1, 1)
        spec["worker_groups"][0]["persona_request"] = spec["worker_groups"][1]["tool_request"]
        with self.assertRaises(ps.PoolSpecError) as caught:
            ps.plan_expansion(spec, context=self.ws.context())
        self.assertIn("fails its closed schema", str(caught.exception))

    def test_a_handoff_travels_as_a_readable_input_and_widens_nothing(self):
        """What T10 will do: the handoff is exact bytes with role ``handoff``. Its own tool
        contract, budget and prohibited claims are not read by the expander."""
        relative = self.handoff_path.relative_to(self.owasp_data).as_posix()
        entry = {"root": "owasp-run-data", **b14.file_pin(self.handoff_path, relative), "role": "handoff",
                 "producer_request_sha256": None}
        group = self.ws.persona_group("validators", 2)
        plain = ps.plan_expansion(self.ws.spec([group]), context=self.ws.context())
        group["persona_request"]["readable_inputs"][0] = entry
        spec = self.ws.spec([group])
        roots = {"run-data": self.ws.data, "owasp-run-data": self.owasp_data}
        plan = ps.expand_pool(spec, context=self.ws.context(readable_roots=roots))
        self.assertEqual(ps.verify_expansion(self.ws.root(plan), expected_spec=spec,
                                             context=self.ws.context(readable_roots=roots)), [])
        self.assertTrue(self.handoff["tool_contract"]["allowed_tools"])
        for item, entry_record in zip(plan.requests, plan.manifest["instances"]):
            self.assertEqual(item.request["tools"], ())
            self.assertEqual(item.request["budget"], plain.requests[0].request["budget"])
            self.assertEqual(item.request["readable_inputs"][0]["role"], "handoff")
            self.assertNotIn(self.handoff["handoff_id"], json.dumps(ps.thaw(plan.manifest)))
            self.assertEqual(entry_record["resource_pool"], plain.manifest["instances"][0]["resource_pool"])
        self.assertNotEqual(plan.manifest["instances"][0]["input_fingerprint"],
                            plain.manifest["instances"][0]["input_fingerprint"])
        with self.assertRaises(ps.PoolSpecError):          # the undeclared root is not readable
            ps.plan_expansion(spec, context=self.ws.context())

    def test_a_published_copy_of_a_pool_root_does_not_verify_as_the_pool(self):
        spec = self.ws.mixed(1, 1)
        plan = ps.expand_pool(spec, context=self.ws.context())
        copy = self.ws.base / "copy" / plan.pool_directory
        shutil.copytree(self.ws.root(plan), copy)
        self.assertEqual(ps.verify_expansion(copy, expected_spec=spec, context=self.ws.context()),
                         ["pool_root is not the pool directory the expected specification derives beneath "
                          "context.pool_parent"])
        self.assertEqual(ps.verify_expansion(copy, expected_spec=spec,
                                             context=self.ws.context(pool_parent=copy.parent)), [])


if __name__ == "__main__":
    unittest.main()
