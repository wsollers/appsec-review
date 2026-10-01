"""02-dev-project-discovery and 02-devops-project-discovery after alignment-plan R03.

The task rules that used to be prose only are checked by ``discovery_gate.project_rule_errors``, both
at acceptance (``_require_upstream_inputs``) and in the repair loop (``project_in_loop_errors``, the
automatic dispatch's ``extra_validate``); the task prompts' examples are the supplied fixtures.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import discovery_gate as dg

FIXTURES = ROOT.parent / "fixtures/supplied/hello-autotools"
PARTITIONS = json.loads((FIXTURES / "02-repository-partition-discovery.json").read_text(encoding="utf-8"))
DEV = json.loads((FIXTURES / "02-dev-project-discovery.json").read_text(encoding="utf-8"))
DEVOPS = json.loads((FIXTURES / "02-devops-project-discovery.json").read_text(encoding="utf-8"))


def citation(path):
    return {"source_type": "source_file", "path": path, "line_range": None, "tool_name": None,
            "tool_rule_id": None, "content_hash": None, "note": "n"}


class DevRuleTests(unittest.TestCase):
    def errors(self, value):
        return dg.project_rule_errors(dg.CONSUMER_JOB, value, PARTITIONS, None)

    def test_the_supplied_fixture_passes(self):
        self.assertEqual(self.errors(DEV), [])

    def test_catalog_images_plan_entries_restores_and_deferred_partitions(self):
        value = deepcopy(DEV)
        value["projects"][0]["candidate_buildenv_images"] = ["gcc:latest"]
        self.assertTrue(any("not images in the Build Environment Catalog" in e for e in self.errors(value)))
        value = deepcopy(DEV)
        value["projects"][0]["candidate_buildenv_images"] = []
        self.assertTrue(any("no catalog image" in e for e in self.errors(value)))
        value = deepcopy(DEV)
        value["safe_command_plan"] = []
        self.assertTrue(any("no safe_command_plan entry" in e for e in self.errors(value)))
        value = deepcopy(DEV)
        value["safe_command_plan"][0] = {**value["safe_command_plan"][0], "argv": ["npm", "ci"],
                                         "authorization": "script-execution-required"}
        self.assertTrue(any("must be network-required" in e for e in self.errors(value)))
        value = deepcopy(DEV)
        value["coverage_gaps"] = [gap for gap in value["coverage_gaps"] if "'docs'" not in gap]
        self.assertTrue(any("partition 'docs' is deferred" in e for e in self.errors(value)))


class DevopsRuleTests(unittest.TestCase):
    def errors(self, value, source_root=None):
        return dg.project_rule_errors(dg.DEVOPS_JOB, value, PARTITIONS, source_root)

    def test_the_supplied_fixture_passes(self):
        self.assertEqual(self.errors(DEVOPS), [])

    def test_run_deploy_push_native_build_and_docker_socket_are_refused(self):
        for argv in (["docker", "run", "img"], ["docker", "compose", "up"], ["/usr/bin/docker", "push", "x"],
                     ["kubectl", "apply", "-f", "k.yaml"], ["make"], ["./configure"], ["npm", "run", "build"],
                     ["docker", "build", "-v", "/var/run/docker.sock:/var/run/docker.sock", "."]):
            value = deepcopy(DEVOPS)
            value["safe_command_plan"][0] = {**value["safe_command_plan"][0], "argv": argv}
            with self.subTest(argv=argv):
                self.assertTrue(self.errors(value))

    def test_a_declared_image_must_appear_in_a_cited_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "Dockerfile").write_text("FROM debian:bookworm-slim\n", encoding="utf-8")
            value = {"projects": [{"project_id": "container-image", "candidate_buildenv_images": ["debian:bookworm-slim"],
                                   "evidence_citations": [citation("Dockerfile")]}],
                     "safe_command_plan": [], "coverage_gaps": []}
            self.assertEqual(self.errors(value, root), [])
            value["projects"][0]["candidate_buildenv_images"] = ["alpine:3.20"]
            self.assertTrue(any("does not appear in any file" in e for e in self.errors(value, root)))


class InLoopTests(unittest.TestCase):
    def test_the_in_loop_check_applies_overwrites_then_the_acceptance_checks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "Dockerfile").write_text("FROM debian:bookworm-slim\n", encoding="utf-8")
            by_path = {"Dockerfile": "sha256:" + hashlib.sha256((root / "Dockerfile").read_bytes()).hexdigest()}
            value = {"schema": "appsec-review/project-discovery/1.0", "target": "model guess", "source_revision": "?",
                     "projects": [{"project_id": "container-image", "root": ".", "languages": ["dockerfile"],
                                   "manifests": ["Dockerfile"], "lockfiles": [],
                                   "candidate_buildenv_images": ["debian:bookworm-slim"],
                                   "commands": ["docker build ."], "evidence_citations": [citation("Dockerfile")],
                                   "confidence": "high"}],
                     "safe_command_plan": [{"project_id": "container-image", "purpose": "build", "argv": ["docker", "build", "."],
                                            "authorization": "network-required", "side_effects": ["pulls the base image"],
                                            "evidence_citations": [citation("Dockerfile")]}],
                     "coverage_gaps": ["Partition 'docs' is deferred."]}
            check = lambda v: dg.project_in_loop_errors(dg.DEVOPS_JOB, v, source_revision="a" * 40, target="hello",
                                                        by_path=by_path, target_root=root, partition_map=PARTITIONS)
            self.assertEqual(check(value), [])
            self.assertIsNone(value["projects"][0]["evidence_citations"][0]["content_hash"])   # copy only
            value["safe_command_plan"][0]["argv"] = ["docker", "run", "hello"]
            self.assertTrue(any("is not planned here" in e for e in check(value)))


class TaskPromptTests(unittest.TestCase):
    def test_the_examples_are_the_supplied_fixtures_with_null_hashes(self):
        for task, fixture in (("task-dev-project-discovery.md", DEV), ("task-devops-project-discovery.md", DEVOPS)):
            text = (ROOT / "02-evidence-pregather" / task).read_text(encoding="utf-8")
            example = json.loads(text.split("## Example", 1)[1].split("```json\n", 1)[1].split("\n```", 1)[0])
            expected = json.loads(json.dumps(fixture).replace('"content_hash": "', '"content_hash": "X'))
            def null(node):
                if isinstance(node, dict):
                    if "source_type" in node:
                        node["content_hash"] = None
                    for value in node.values():
                        null(value)
                elif isinstance(node, list):
                    for value in node:
                        null(value)
            null(expected)
            with self.subTest(task=task):
                self.assertEqual(example, expected)


if __name__ == "__main__":
    unittest.main()
