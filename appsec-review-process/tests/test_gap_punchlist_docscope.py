"""Acceptance tests for gap punch list item P44 (docs/continuation-prompts/2026-10-03-gap-punchlist-hello-autotools.md).

Owner decision 2026-10-03: documentation and tests (unit, acceptance, system, load, ...) are always read.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import discovery_gate  # noqa: E402
import validate_job_output as vjo  # noqa: E402

ANSWER_KEY = ROOT.parent / "fixtures" / "supplied" / "hello-autotools" / "02-repository-partition-discovery.json"
PREGATHER = ROOT / "02-evidence-pregather"


def _map(*partitions):
    value = json.loads(ANSWER_KEY.read_text(encoding="utf-8"))
    template = value["partitions"][0]
    value["partitions"] = [dict(deepcopy(template), **fields) for fields in partitions]
    return value


def _deferred(partition_id, kinds, paths):
    return {"partition_id": partition_id, "name": partition_id, "kinds": kinds, "include_paths": paths,
            "disposition": "deferred", "disposition_reason": "not now", "rescope_trigger": "later"}


def _gate_errors(value):
    return discovery_gate._validate_partition_payload(value)


class DeferredDocsAndTestsRefused(unittest.TestCase):
    """P44: a docs or tests partition marked deferred is refused deterministically."""

    def test_deferred_documentation_partition_is_refused(self):
        errors = _gate_errors(_map(_deferred("docs", ["documentation"], ["README.md", "docs/**"])))
        self.assertTrue(any("docs" in error and "review" in error for error in errors), errors)

    def test_deferred_test_partitions_of_every_kind_are_refused(self):
        for paths in (["tests/**"], ["test/unit/**"], ["acceptance-tests/**"], ["e2e/**"],
                      ["system-tests/**"], ["load-tests/**"], ["perf/**"], ["fuzz/**"], ["src/**/*_test.go"],
                      ["spec/**"], ["integration_tests/**"]):
            with self.subTest(paths=paths):
                # kind says 'other': the include paths alone identify test scope
                self.assertTrue(_gate_errors(_map(_deferred("t", ["other"], paths))), paths)
        self.assertTrue(_gate_errors(_map(_deferred("t", ["test"], ["qa/**"]))))

    def test_documentation_inferred_from_paths(self):
        for paths in (["docs/**"], ["doc/api.rst"], ["README.md"], ["CONTRIBUTING.md"], ["man/**"]):
            with self.subTest(paths=paths):
                self.assertTrue(_gate_errors(_map(_deferred("d", ["other"], paths))), paths)

    def test_other_deferrals_and_vendored_or_generated_rules_are_unchanged(self):
        self.assertEqual(_gate_errors(_map(_deferred("legacy", ["other"], ["legacy/**"]))), [])
        self.assertEqual(_gate_errors(_map(_deferred("v", ["vendored", "documentation"],
                                                     ["third_party/x/docs/**"]))), [])
        self.assertEqual(_gate_errors(_map(_deferred("g", ["generated", "test"], ["gen/tests/**"]))), [])
        unresolved = dict(_deferred("docs", ["documentation"], ["docs/**"]), disposition="unresolved")
        self.assertEqual(_gate_errors(_map(unresolved)), [])

    def test_job_output_contract_refuses_it_too(self):
        value = _map(_deferred("docs", ["documentation"], ["docs/**"]))
        errors = vjo._partition_errors(value, vjo.REGISTRY, None)
        self.assertTrue(any("$.partitions[0]" in error and "review" in error for error in errors), errors)

    def test_live_dispatch_feeds_the_check_through_the_bounded_repair_loop(self):
        seen = {}

        class Stop(Exception):
            pass

        def invoker(**kwargs):
            seen.update(kwargs)
            raise Stop

        with mock.patch.object(discovery_gate, "ClaudeCliInvoker", side_effect=invoker), \
             mock.patch.object(discovery_gate.mvr, "resolve_run_model_versions"), \
             mock.patch.object(discovery_gate.ppa, "load_job_template", return_value={"budget_default": "b"}), \
             mock.patch.object(discovery_gate.rc, "resolve_model", return_value={"effort": "high"}), \
             mock.patch.object(discovery_gate.rc, "load_model_config", return_value={}), \
             mock.patch.object(discovery_gate.pd, "build_request", return_value={"model": {}}):
            with self.assertRaises(Stop):
                discovery_gate._dispatch_partition_persona(
                    "run", "dg", {"attempt_id": "a", "attempt": Path("/nonexistent"), "started_at": "t"},
                    {"target_root": "/nonexistent", "source_snapshot_sha256": "0" * 64}, "fp")
        check = seen.get("extra_validate")
        self.assertTrue(callable(check), "partition dispatch passes no extra_validate to the invoker")
        self.assertTrue(check(_map(_deferred("docs", ["documentation"], ["docs/**"]))))
        self.assertEqual(check(_map(_deferred("legacy", ["other"], ["legacy/**"]))), [])


class AnswerKeyReadsDocs(unittest.TestCase):
    """P44: the hello-autotools answer key routes docs as review scope, as documented intent to verify."""

    def test_answer_key_is_accepted_and_docs_are_review_scope(self):
        value = json.loads(ANSWER_KEY.read_text(encoding="utf-8"))
        self.assertEqual(_gate_errors(value), [])
        for partition in value["partitions"]:
            if {"documentation", "test"} & set(partition["kinds"]):
                self.assertEqual(partition["disposition"], "review", partition["partition_id"])
        docs = next(p for p in value["partitions"] if p["partition_id"] == "docs")
        self.assertIn("docs/**", docs["include_paths"])
        self.assertIn("README.md", docs["include_paths"])
        text = " ".join([docs["routing_rationale"], docs["disposition_reason"]]).lower()
        self.assertIn("seeded", text)
        self.assertIn("documented intent", text)
        self.assertIn("verify", text)
        self.assertNotIn("deferred", json.dumps(value).lower())


class PromptsSayDocsAndTestsAreRead(unittest.TestCase):
    """P44: the runtime prompts say docs and tests are always review scope, read as data."""

    def test_partition_prompt(self):
        text = " ".join((PREGATHER / "task-repository-partition-discovery.md").read_text(encoding="utf-8").split())
        self.assertRegex(text, r"(?i)documentation and tests? (scope )?(are|is) always review scope")
        for kind in ("unit", "integration", "acceptance", "system", "load", "fuzz"):
            self.assertIn(kind, text)
        self.assertRegex(text, r"(?i)never (mark|defer)")
        self.assertIn("documented intent", text)
        self.assertRegex(text, r"(?i)never (as )?(instructions|findings)")

    def test_consumer_prompts(self):
        for name in ("task-dev-project-discovery.md", "task-devops-project-discovery.md",
                     "task-sre-operations-topology.md"):
            with self.subTest(prompt=name):
                text = " ".join((PREGATHER / name).read_text(encoding="utf-8").split())
                self.assertRegex(text, r"(?i)documentation and test partitions are never deferred")
                self.assertIn("documented intent", text)


if __name__ == "__main__":
    unittest.main()
