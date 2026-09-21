"""Wait-all rendezvous (C02) against other slices: the V06 redactor over a published manifest with
every kind of state in it, and documents of other slices (a C01 expansion, a B13 result, a B14
result, a T06 OWASP validator handoff) offered where a terminal-instance manifest is expected."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_execution as ce  # noqa: E402
import evidence_redaction  # noqa: E402
import persona_invocation as pi  # noqa: E402
import persona_invocation_support as b14  # noqa: E402
import pool_rendezvous as pr  # noqa: E402
import pool_rendezvous_support as support  # noqa: E402
from pool_rendezvous_support import MARKER, Routed, RoutedDocker  # noqa: E402
import pool_specification as ps  # noqa: E402
from test_container_execution import ScriptedDocker  # noqa: E402


class Case(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(support.join_pool_threads)
        self.ws = support.RendezvousWorkspace(Path(self.temporary.name).resolve())

    def varied(self):
        """One mixed pool with failed, blocked, canceled and succeeded instances of both kinds."""
        spec = self.ws.mixed(4, 2)
        plan = self.ws.expand(spec)
        ids = support.ids(plan)
        gate = support.Gated()
        invoker = Routed({ids[0]: b14.Raising(RuntimeError(MARKER)),
                          ids[1]: b14.Raising(pi.InvokerUnavailable(MARKER)), ids[2]: gate})

        class Canceling(ScriptedDocker):           # the second tool instance is what cancels the pool
            def before_child(inner, cancel):
                self.ws.cancel.set()
        docker = RoutedDocker(ScriptedDocker, {
            support.container_name(plan, 4): ScriptedDocker(stdout=(MARKER + "\n").encode()),
            support.container_name(plan, 5): Canceling(client_exit=-9, metadata={
                "cancelled": True, "error": "InterruptedError: x"})})
        first, second = docker.patches()
        with first, second:
            manifest = self.ws.run(spec, plan, invoker, max_parallel=2)
        return spec, plan, manifest


class RedactionSurvivalTests(Case):
    def test_a_published_manifest_with_every_kind_of_state_survives_the_redactor_unchanged(self):
        spec, plan, manifest = self.varied()
        found = set(support.states(manifest))
        self.assertLessEqual({pr.FAILED, pr.BLOCKED, pr.SUCCEEDED, pr.CANCELED}, found)
        self.assertEqual(manifest["outcome"], pr.POOL_CANCELED)
        source = pr.rendezvous_root(plan, self.ws.rendezvous_parent)
        published = self.ws.base / "published"
        receipt = evidence_redaction.redact_tree(source, published, on_unhandled="refuse",
                                                 limits=evidence_redaction.DEFAULT_LIMITS)
        self.assertEqual([(record["path"], record["disposition"]) for record in receipt["files"]],
                         [(pr.MANIFEST_FILE, "unchanged")])
        self.assertEqual((published / pr.MANIFEST_FILE).read_bytes(), self.ws.manifest_path(plan).read_bytes())
        self.assertEqual(self.ws.verify(spec, plan), [])
        # the rendezvous root is itself a publishable path: bare hex, like the pool root
        self.assertRegex(source.name, r"\A[0-9a-f]{32}\Z")

    def test_an_empty_pool_s_manifest_survives_too(self):
        spec = self.ws.spec([self.ws.persona_group("reviewers", 0)])
        plan = self.ws.expand(spec)
        self.ws.run(spec, plan)
        receipt = evidence_redaction.redact_tree(pr.rendezvous_root(plan, self.ws.rendezvous_parent),
                                                 self.ws.base / "published", on_unhandled="refuse",
                                                 limits=evidence_redaction.DEFAULT_LIMITS)
        self.assertEqual([record["disposition"] for record in receipt["files"]], ["unchanged"])

    def test_no_property_name_in_a_manifest_is_secret_looking(self):
        _, _, manifest = self.varied()
        names: set = set()

        def collect(node):
            if isinstance(node, dict):
                names.update(node)
                for value in node.values():
                    collect(value)
            elif isinstance(node, list):
                for value in node:
                    collect(value)
        collect(pr.thaw(manifest))
        self.assertGreater(len(names), 30)
        for name in sorted(names):
            self.assertIsNone(evidence_redaction._KEYWORD_RE.search(name), name)


class ForeignDocumentTests(Case):
    """Other slices publish canonical, self-hashed JSON as well. None of it is a manifest."""

    def test_a_document_of_another_slice_is_not_a_terminal_instance_manifest(self):
        import owasp_validator_handoff
        import test_owasp_validator_handoff as t06
        fixture = t06.OwaspValidatorHandoffTests("setUp")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        _, request_path, *_ = fixture.publish_upstream(count=1)
        built = owasp_validator_handoff.build(fixture.run_id, request_path)
        attempt = fixture.data / "jobs" / owasp_validator_handoff.JOB_ID / "whole" / "attempts" / built["attempt_id"]
        handoff_set = json.loads((attempt / "outputs" / "owasp-validator-handoff-set.json").read_text(encoding="utf-8"))
        handoff = json.loads((attempt / handoff_set["handoffs"][0]["path"]).read_text(encoding="utf-8"))

        spec = self.ws.mixed(1, 1)
        plan = self.ws.expand(spec)
        first, second = RoutedDocker(ScriptedDocker).patches()
        with first, second:
            self.ws.run(spec, plan)
        honest = self.ws.manifest_path(plan).read_bytes()
        foreign = {
            "the C01 expansion": ps.thaw(plan.manifest),
            "the C01 specification": spec,
            "a B14 persona result": json.loads(self.ws.result_path(plan, 0).read_text(encoding="utf-8")),
            "a B13 container result": json.loads(self.ws.result_path(plan, 1).read_text(encoding="utf-8")),
            "a B14 request": pi.thaw(plan.requests[0].request),
            "a T06 validator handoff": handoff,
        }
        path = self.ws.manifest_path(plan)
        for label, document in foreign.items():
            for borrowed in ({}, {"schema": pr.MANIFEST_ID, "outcome": pr.COMPLETE, "wait_all": True}):
                with self.subTest(document=label, borrowed=sorted(borrowed)):
                    path.unlink()
                    path.write_bytes(pr.canonical_bytes({**document, **borrowed}))
                    errors = self.ws.verify(spec, plan)
                    self.assertEqual(len(errors), 1)
                    self.assertIn("fails its closed schema", errors[0])
                    self.assertNotIn(MARKER, errors[0])
                    for value in (document.get("handoff_id"), document.get("result_sha256")):
                        if value:
                            self.assertNotIn(value, errors[0])
                    with self.assertRaises(pr.RendezvousError):
                        self.ws.load(spec, plan)
        path.unlink()
        path.write_bytes(honest)
        self.assertEqual(self.ws.verify(spec, plan), [])

    def test_a_manifest_is_not_an_expansion_a_specification_or_an_adapter_result(self):
        spec = self.ws.mixed(1, 1)
        plan = self.ws.expand(spec)
        first, second = RoutedDocker(ScriptedDocker).patches()
        with first, second:
            manifest = pr.thaw(self.ws.run(spec, plan))
        with self.assertRaises(ps.PoolSpecError):
            ps.plan_expansion({**manifest, "wait_all": True}, context=self.ws.context())
        expansion = self.ws.root(plan) / ps.EXPANSION_FILE
        expansion.write_bytes(pr.canonical_bytes(manifest))
        self.assertEqual(len(ps.verify_expansion(self.ws.root(plan), **self.ws.arguments(spec))), 1)
        expansion.write_bytes(plan.manifest_bytes)
        for index in (0, 1):                  # ... nor can it stand in for the result it points at
            self.ws.result_path(plan, index).write_bytes(pr.canonical_bytes(manifest))
        errors = self.ws.verify(spec, plan)
        self.assertEqual(len(errors), 2)
        records = [pr.classify_instance(plan, index, **self.ws.classifier_arguments(plan),
                                        observation=pr.REPORTED) for index in (0, 1)]
        self.assertEqual([record["state"] for record in records], [pr.INVALID, pr.INVALID])
        self.assertEqual(ce.RESULT_FILE, "container-result.json")


if __name__ == "__main__":
    unittest.main()
