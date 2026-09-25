"""Task prompt naming convention (2026-09-25).

A job template's ``task_prompt`` is ``appsec-review-process/<process>/task-<name>.md``, where
``<process>`` is the template's own ``process`` folder and ``<name>`` is its ``job_template_id``
without the leading ``NN-`` process number (``02-devops-project-discovery`` ->
``02-evidence-pregather/task-devops-project-discovery.md``). The ``task-`` prefix keeps a job's task
prompt apart from the lane's own ``prompt.md``/``config.md``/``subprompts.md`` in the same folder.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "registry" / "job-templates"


def expected_task_prompt(template: dict) -> str:
    name = re.sub(r"^[0-9]+-", "", template["job_template_id"])
    return f"appsec-review-process/{template['process']}/task-{name}.md"


class TaskPromptNamingTests(unittest.TestCase):
    def test_every_task_prompt_follows_the_convention_and_exists(self):
        checked = 0
        for path in sorted(TEMPLATES.glob("*.json")):
            template = json.loads(path.read_text(encoding="utf-8"))
            if "task_prompt" not in template:
                continue
            checked += 1
            with self.subTest(template=path.name):
                self.assertEqual(template["task_prompt"], expected_task_prompt(template))
                self.assertTrue((ROOT.parent / template["task_prompt"]).is_file(),
                                template["task_prompt"] + " does not exist")
        self.assertGreater(checked, 0, "no job template declares a task_prompt")

    def test_no_orphan_task_prompts(self):
        declared = set()
        for path in TEMPLATES.glob("*.json"):
            template = json.loads(path.read_text(encoding="utf-8"))
            if "task_prompt" in template:
                declared.add(template["task_prompt"])
        # Only the numbered process folders hold job task prompts (templates/task-handoff.md is not one).
        for prompt in sorted(ROOT.glob("[0-9][0-9]-*/task-*.md")):
            with self.subTest(prompt=prompt.name):
                self.assertIn(prompt.relative_to(ROOT.parent).as_posix(), declared,
                              "task prompt is not referenced by any job template")


if __name__ == "__main__":
    unittest.main()
