"""Every file a dispatched prompt is assembled from is in its worker's code fingerprint (plan P10).

``persona_prompt_assembly.prompt_source_paths`` names the files; ``prompt_lint.DISPATCHED`` names the
fingerprint that must cover them. An edit to an unfingerprinted prompt file would not force a rerun,
so an accepted attempt would silently keep the old prompt's answer.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import registry_paths

import persona_prompt_assembly as ppa
import prompt_lint
from schema_validate import SchemaStore


def renderable() -> set[str]:
    store, names = SchemaStore(), set()
    for path in sorted(registry_paths.JOB_TEMPLATES_DIR.glob("*.json")):
        template_id = json.loads(path.read_text(encoding="utf-8"))["job_template_id"]
        try:
            ppa.assemble_prompt_text(template_id, store)
        except ppa.PromptAssemblyError:
            continue
        names.add(template_id)
    return names


def variants(template_id: str) -> list[tuple[str | None, str | None]]:
    template = prompt_lint.load_template(template_id)
    personas = set(template.get("persona_variants") or [])
    for pool in (template.get("stage_personas") or {}).values():
        personas |= set(pool)
    roles = set(template.get("role_variants") or []) | set((template.get("stage_roles") or {}).values())
    return [(None, None)] + [(persona, None) for persona in sorted(personas)] + [(None, role) for role in sorted(roles)]


class DispatchMapTests(unittest.TestCase):
    def test_every_renderable_template_is_classified_exactly_once(self):
        dispatched, idle = set(prompt_lint.DISPATCHED), set(prompt_lint.NOT_DISPATCHED)
        self.assertFalse(dispatched & idle)
        self.assertEqual(renderable(), dispatched | idle)


class SourcePathTests(unittest.TestCase):
    def test_source_paths_cover_every_file_the_assembler_reads(self):
        store = SchemaStore()
        original = ppa._read_utf8
        for template_id in sorted(prompt_lint.DISPATCHED):
            declared = set(ppa.prompt_source_paths(template_id))
            for persona_id, role_id in variants(template_id):
                read: list[Path] = []

                def recording(path, root, label):
                    read.append(Path(path))
                    return original(path, root, label)
                with self.subTest(template=template_id, persona=persona_id, role=role_id), \
                        mock.patch.object(ppa, "_read_utf8", recording):
                    ppa.assemble_prompt_text(template_id, store, persona_id=persona_id, role_id=role_id)
                    relative = {path.resolve().relative_to(ppa.ROOT.resolve()).as_posix() for path in read}
                    self.assertIn("pipeline/prompt-fragments/governing-rules.md", relative)   # reads were seen
                    self.assertLessEqual(relative, declared)


class FingerprintTests(unittest.TestCase):
    def test_every_dispatched_prompt_file_is_fingerprinted(self):
        for template_id in sorted(prompt_lint.DISPATCHED):
            with self.subTest(template=template_id):
                missing = set(ppa.prompt_source_paths(template_id)) - set(prompt_lint.fingerprint(template_id))
                self.assertEqual(missing, set(), f"{prompt_lint.DISPATCHED[template_id][1]} does not fingerprint")


if __name__ == "__main__":
    unittest.main()
