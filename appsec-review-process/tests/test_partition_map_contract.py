"""02-repository-partition-discovery after alignment-plan R02.

The closed sets the task states are schema-structural (one check per category, not-found needs a
search scope, deferred needs a reason and trigger, path syntax); the publication checks run inside
the repair loop (``discovery_gate.partition_in_loop_errors``); an uninspected category with no
resolvable citation gets no claim instead of a borrowed one; the task prompt's example is the supplied
fixture.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import claude_cli_invoker as cci
import discovery_gate
import persona_dispatch as pd
from schema_validate import validate_document

SCHEMA = "repository-partition-map.schema.json"
FIXTURE = ROOT.parent / "fixtures/supplied/hello-autotools/02-repository-partition-discovery.json"
CATEGORIES = ("client", "server", "api", "shared-library", "iac", "cicd", "build-release",
              "deployment", "operations", "test", "generated", "vendored", "documentation")


def citation(path: str) -> dict:
    return {"source_type": "source_file", "path": path, "line_range": None, "tool_name": None,
            "tool_rule_id": None, "content_hash": None, "note": "n"}


def small_map() -> dict:
    return {
        "schema": "appsec-review/repository-partition-map/0.1", "target": "fixture", "source_revision": "unknown",
        "partitions": [
            {"partition_id": "server", "name": "Server", "kinds": ["server"], "include_paths": ["src/**"],
             "exclude_paths": [], "primary_persona_id": "developer-engineer", "supporting_persona_ids": [],
             "routing_rationale": "Application source.", "confidence": "high",
             "evidence_citations": [citation("src/main.py")],
             "relationships": [{"target_partition_id": "ci", "kind": "builds", "basis": "inferred",
                                "evidence_citations": [citation(".github/workflows/ci.yml")]}],
             "overlap_notes": [], "disposition": "review", "disposition_reason": "", "rescope_trigger": ""},
            {"partition_id": "ci", "name": "CI", "kinds": ["cicd"], "include_paths": [".github/**"],
             "exclude_paths": [], "primary_persona_id": "devops-engineer", "supporting_persona_ids": [],
             "routing_rationale": "Workflow definitions.", "confidence": "high",
             "evidence_citations": [citation(".github/workflows/ci.yml")], "relationships": [],
             "overlap_notes": [], "disposition": "review", "disposition_reason": "", "rescope_trigger": ""}],
        "coverage": {"inventory_scope": ["**"], "unassigned_paths": [], "uninspected_scope": [],
                     "budget_limitations": [],
                     "category_checks": [{"category": c, "result": "found" if c in ("server", "cicd") else "not-found",
                                          "search_scope": ["**"], "evidence_citations": []} for c in CATEGORIES]},
    }


class SchemaClosedSetTests(unittest.TestCase):
    def test_the_supplied_fixture_and_the_small_map_are_valid(self):
        self.assertEqual(validate_document(json.loads(FIXTURE.read_text(encoding="utf-8")), SCHEMA), [])
        self.assertEqual(validate_document(small_map(), SCHEMA), [])

    def test_every_category_needs_exactly_one_check(self):
        value = small_map()
        value["coverage"]["category_checks"] = [c for c in value["coverage"]["category_checks"]
                                                if c["category"] != "operations"]
        self.assertTrue(validate_document(value, SCHEMA))
        value = small_map()
        value["coverage"]["category_checks"][0]["category"] = "native-code"   # a free category is gone
        self.assertTrue(validate_document(value, SCHEMA))

    def test_not_found_needs_a_search_scope_and_deferred_needs_reason_and_trigger(self):
        value = small_map()
        value["coverage"]["category_checks"][-1]["search_scope"] = []
        self.assertTrue(any("search_scope" in e for e in validate_document(value, SCHEMA)))
        value = small_map()
        value["partitions"][1]["disposition"] = "deferred"
        errors = validate_document(value, SCHEMA)
        self.assertTrue(any("disposition_reason" in e for e in errors) and any("rescope_trigger" in e for e in errors))

    def test_path_fields_reject_dot_traversal_absolute_and_prose(self):
        for bad in (".", "./src", "../x", "/etc", "src/", "a//b"):
            value = small_map()
            value["coverage"]["inventory_scope"] = [bad]
            with self.subTest(path=bad):
                self.assertTrue(validate_document(value, SCHEMA))


class InLoopTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.target = Path(self.temporary.name)
        (self.target / "src").mkdir()
        (self.target / ".github/workflows").mkdir(parents=True)
        (self.target / "src/main.py").write_text("print('x')\n", encoding="utf-8")
        (self.target / ".github/workflows/ci.yml").write_text("on: push\n", encoding="utf-8")
        self.by_path = {p: "sha256:" + hashlib.sha256((self.target / p).read_bytes()).hexdigest()
                        for p in ("src/main.py", ".github/workflows/ci.yml")}

    def tearDown(self):
        self.temporary.cleanup()

    def errors(self, value: dict) -> list[str]:
        return discovery_gate.partition_in_loop_errors(value, source_revision="a" * 40, by_path=self.by_path,
                                                       target_root=self.target)

    def test_a_valid_answer_passes_after_backfill(self):
        value = small_map()
        self.assertEqual(self.errors(value), [])
        self.assertIsNone(value["partitions"][0]["evidence_citations"][0]["content_hash"])   # copy only

    def test_publication_errors_come_back_to_the_model(self):
        value = small_map()
        value["partitions"][0]["relationships"][0]["target_partition_id"] = "no-such-partition"
        self.assertTrue(any("target ID does not resolve" in e for e in self.errors(value)))
        value = small_map()
        value["partitions"][1]["evidence_citations"] = [citation("missing.yml")]
        self.assertTrue(any(e.startswith("$.partitions[1].evidence_citations[0]") for e in self.errors(value)))
        value = small_map()
        value["partitions"][0]["supporting_persona_ids"] = ["developer-engineer"]
        self.assertTrue(any("must be unique" in e for e in self.errors(value)))


class ClaimBuilderTests(unittest.TestCase):
    def test_an_uninspected_category_without_a_resolvable_citation_gets_no_borrowed_claim(self):
        value = small_map()
        value["coverage"]["category_checks"][0] = {"category": "client", "result": "uninspected",
                                                  "search_scope": [], "evidence_citations": []}
        inputs = (SimpleNamespace(root=pd.DEFAULT_READABLE_ROOT, path="src/main.py", data=b"x", sha256="a" * 64),
                  SimpleNamespace(root=pd.DEFAULT_READABLE_ROOT, path=".github/workflows/ci.yml", data=b"x",
                                  sha256="b" * 64))
        claims = cci._claims_from_partition_map(value, inputs, ("repository_partition_map", "evidence_gap"),
                                                "repository-partition-map.json")
        self.assertEqual([c["claim_class"] for c in claims], ["repository_partition_map"] * 2)

    def test_an_uninspected_category_with_a_resolvable_citation_is_claimed(self):
        value = small_map()
        value["coverage"]["category_checks"][0] = {"category": "client", "result": "uninspected",
                                                  "search_scope": [], "evidence_citations": [citation("src/main.py")]}
        inputs = (SimpleNamespace(root=pd.DEFAULT_READABLE_ROOT, path="src/main.py", data=b"x", sha256="a" * 64),
                  SimpleNamespace(root=pd.DEFAULT_READABLE_ROOT, path=".github/workflows/ci.yml", data=b"x",
                                  sha256="b" * 64))
        claims = cci._claims_from_partition_map(value, inputs, ("repository_partition_map", "evidence_gap"),
                                                "repository-partition-map.json")
        gap = [c for c in claims if c["claim_class"] == "evidence_gap"]
        self.assertEqual([c["citations"][0]["path"] for c in gap], ["src/main.py"])


class TaskPromptTests(unittest.TestCase):
    def test_the_example_is_the_supplied_fixture_with_null_hashes(self):
        text = (ROOT / "02-evidence-pregather/task-repository-partition-discovery.md").read_text(encoding="utf-8")
        example = json.loads(text.split("## Example", 1)[1].split("```json\n", 1)[1].split("\n```", 1)[0])
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

        def null_hashes(node):
            if isinstance(node, dict):
                if "source_type" in node:
                    node["content_hash"] = None
                for value in node.values():
                    null_hashes(value)
            elif isinstance(node, list):
                for value in node:
                    null_hashes(value)
        null_hashes(fixture)
        self.assertEqual(example, fixture)


if __name__ == "__main__":
    unittest.main()
