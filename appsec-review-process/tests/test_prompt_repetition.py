"""One home per requirement (plan P9): no clause restated in three or more rendered sections.

Advisory until a template is migrated: ``MIGRATED`` (empty until the first work-queue item lands) is
held to zero repeated clusters; every other dispatched template only has to render through the check.
``python3 -B appsec-review-process/prompt_lint.py report`` prints the current clusters.
"""
from __future__ import annotations

import sys
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import prompt_lint
from schema_validate import SchemaStore

MIGRATED: frozenset[str] = frozenset({"01-component-characterization",   # R01
                                     "02-repository-partition-discovery",   # R02
                                     "02-dev-project-discovery", "02-devops-project-discovery",   # R03
                                     "02-sre-operations-topology",   # R04
                                     "02-build-classify"})   # R05


class RepetitionTests(unittest.TestCase):
    def test_migrated_templates_state_each_requirement_once(self):
        store = SchemaStore()
        for template_id in sorted(MIGRATED):
            with self.subTest(template=template_id):
                clusters = prompt_lint.repetition(template_id, store=store)
                self.assertEqual([cluster["clauses"][0][1] for cluster in clusters], [])

    def test_the_check_runs_on_every_dispatched_template(self):
        store = SchemaStore()
        for template_id in sorted(prompt_lint.DISPATCHED):
            with self.subTest(template=template_id):
                self.assertIsInstance(prompt_lint.repetition(template_id, store=store), list)

    def test_a_restated_rule_is_found_and_a_single_statement_is_not(self):
        rule = "Never infer a team owner from a directory name without evidence that names the owner."
        sections = [("role", f'```json\n{{"must_not": ["{rule}"]}}\n```'),
                    ("domain", f'```json\n{{"common_failure_modes": ["{rule}"]}}\n```'),
                    ("task", "Do not infer a team owner from a directory name without evidence naming the owner."),
                    ("output_contract", '```json\n{"validation_rules": ["every citation resolves"]}\n```')]
        with mock.patch.object(prompt_lint, "_sections", return_value=sections):
            clusters = prompt_lint.repetition("01-component-characterization")
        self.assertEqual([cluster["sections"] for cluster in clusters], [["domain", "role", "task"]])


if __name__ == "__main__":
    unittest.main()
