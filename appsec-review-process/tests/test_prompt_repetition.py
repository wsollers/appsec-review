"""One home per requirement (plan P9): no clause restated in three or more rendered sections.

Advisory until a template is migrated: ``MIGRATED`` (empty until the first work-queue item lands) is
held to zero repeated clusters; every other dispatched template only has to render through the check.
``python3 -B appsec-review-process/prompt_lint.py report`` prints the current clusters.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import prompt_lint
from schema_validate import SchemaStore

MIGRATED: frozenset[str] = frozenset()


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

    def test_a_restated_rule_is_found(self):
        # 01's role, task and output contract each restate the no-findings boundary (audit, 01 row).
        clusters = prompt_lint.repetition("01-component-characterization")
        self.assertTrue(any({"role", "task", "output_contract"} <= set(cluster["sections"]) for cluster in clusters))


if __name__ == "__main__":
    unittest.main()
