"""Dispatched task prompts follow the plan's fixed shape (plan section 1.1, P1-P3, P6).

``## Goal``, ``## Inputs``, ``## Output``, ``## Procedure``, ``## Rules``, ``## Example``,
``## Before you finish``, in that order, and the example validates against the schema the model is
shown. ``PENDING`` lists templates not migrated yet; it only shrinks. A pending template that already
passes fails here too, so it is taken off the list in the same change that migrates it.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import prompt_lint
from schema_validate import SchemaStore

# docs/prompt-persona-role-alignment-plan-2026-10-01.md, section 5 work queue.
PENDING: frozenset[str] = frozenset()   # empty since R18 (the intake cells no longer call a model)


class TaskPromptStructureTests(unittest.TestCase):
    def test_pending_only_names_dispatched_templates(self):
        self.assertLessEqual(PENDING, set(prompt_lint.DISPATCHED))

    def test_migrated_task_prompts_have_the_fixed_shape_and_a_valid_example(self):
        store = SchemaStore()
        for template_id in sorted(set(prompt_lint.DISPATCHED) - PENDING):
            with self.subTest(template=template_id):
                self.assertEqual(prompt_lint.structure_errors(template_id, store), [])

    def test_a_pending_template_that_already_passes_must_leave_the_list(self):
        store = SchemaStore()
        for template_id in sorted(PENDING):
            with self.subTest(template=template_id):
                self.assertNotEqual(prompt_lint.structure_errors(template_id, store), [],
                                    "migrated: remove it from PENDING")


class StructureCheckTests(unittest.TestCase):
    """The checker itself, on a synthetic prompt (no registry file is changed)."""

    def check(self, text: str) -> list[str]:
        from unittest import mock
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "task.md"
            path.write_text(text, encoding="utf-8")
            with mock.patch.object(prompt_lint, "task_prompt_path", return_value=path), \
                    mock.patch.object(prompt_lint, "shown_schema", return_value="evidence-citation.schema.json"):
                return prompt_lint.structure_errors("01-component-characterization")

    def body(self, example: str) -> str:
        return "\n\n".join(f"## {heading}\nx" if heading != "Example" else f"## Example\n```json\n{example}\n```"
                           for heading in prompt_lint.REQUIRED_HEADINGS)

    def test_a_missing_heading_is_reported(self):
        self.assertIn("missing heading '## Goal'", self.check(self.body("{}").replace("## Goal\n", "")))

    def test_an_invalid_example_is_reported(self):
        self.assertTrue(any("does not validate" in error for error in self.check(self.body('{"bogus": 1}'))))

    def test_headings_out_of_order_are_reported(self):
        text = self.body("{}").replace("## Goal", "## Tmp").replace("## Inputs", "## Goal").replace("## Tmp", "## Inputs")
        self.assertTrue(any("out of order" in error for error in self.check(text)))


if __name__ == "__main__":
    unittest.main()
