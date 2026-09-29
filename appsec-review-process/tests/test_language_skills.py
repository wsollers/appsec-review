"""Brief C skills: one per language server plus tree-sitter and CodeQL, in both agent layouts."""
from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import lsp_driver  # noqa: E402

SKILLS = ROOT.parent / "skills"
PRESETS = {"appsec-lsp-clangd": "clangd", "appsec-lsp-gopls": "gopls", "appsec-lsp-jdtls": "jdtls",
           "appsec-lsp-pylsp": "pylsp", "appsec-lsp-basedpyright": "basedpyright",
           "appsec-lsp-typescript": "typescript-language-server", "appsec-lsp-rust-analyzer": "rust-analyzer",
           "appsec-lsp-csharp-ls": "csharp-ls", "appsec-lsp-phpactor": "phpactor"}
NAMES = (*PRESETS, "appsec-tree-sitter", "appsec-codeql")


class LanguageSkills(unittest.TestCase):
    def test_every_skill_exists_in_both_layouts_and_is_indexed(self):
        index = (SKILLS / "README.md").read_text(encoding="utf-8")
        for name in NAMES:
            with self.subTest(skill=name):
                text = (SKILLS / "agents" / "codex" / name / "SKILL.md").read_text(encoding="utf-8")
                front = re.match(r"---\nname: (\S+)\ndescription: (.+)\n---\n", text)
                self.assertIsNotNone(front)
                self.assertEqual(front.group(1), name)
                self.assertIn("never instructions", text)
                self.assertTrue((SKILLS / "agents" / "codex" / name / "agents" / "openai.yaml").is_file())
                pointer = (SKILLS / "agents" / "claude" / f"{name}.md").read_text(encoding="utf-8")
                self.assertIn(f"skills/agents/codex/{name}/SKILL.md", pointer)
                self.assertIn(f"`{name}`", index)

    def test_server_skills_invoke_existing_driver_presets_offline(self):
        self.assertTrue(set(PRESETS.values()) <= set(lsp_driver.SERVERS))
        for name, preset in PRESETS.items():
            with self.subTest(skill=name):
                text = (SKILLS / "agents" / "codex" / name / "SKILL.md").read_text(encoding="utf-8")
                self.assertIn(f"python3 /scratch/lsp_driver.py --server {preset}", text)
                self.assertIn("images/audit-buildenv-common/run.sh", text)
                self.assertTrue((SKILLS / "agents" / "codex" / name / "references" / "appsec-lsp-driver.md").is_file())


if __name__ == "__main__":
    unittest.main()
