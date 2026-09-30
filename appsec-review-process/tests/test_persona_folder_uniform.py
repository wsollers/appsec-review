"""One folder for personas and roles, structurally identical (brief J).

Every persona is ``personas/personas/<id>/{persona.json, prompt.md}`` and every role is
``personas/roles/<id>/{role.json, prompt.md}``: the same files, the same keys in the same order,
schema-valid, and nothing else in the tree. Job templates may only name records that exist.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import registry_paths

import catalog_personas
import persona_registry
from schema_validate import SchemaStore, validate_document

FOLDERS = persona_registry.FOLDER_ROOT
PROVENANCE_KEYS = ["generated_by", "source", "reviewed", "note"]


def records(directory: str) -> list[tuple[Path, dict]]:
    file_name = persona_registry.KINDS[directory][0]
    return [(folder, json.loads((folder / file_name).read_text(encoding="utf-8")))
            for folder in sorted((FOLDERS / directory).iterdir())]


def templates() -> list[dict]:
    return [json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(registry_paths.JOB_TEMPLATES_DIR.glob("*.json"))]


class FolderLayoutTests(unittest.TestCase):
    def test_the_tree_holds_the_two_schemas_and_the_two_record_folders_only(self):
        self.assertEqual(sorted(path.name for path in FOLDERS.iterdir()),
                         ["persona.schema.json", "personas", "role.schema.json", "roles"])
        for directory in persona_registry.KINDS:
            self.assertFalse((registry_paths.REGISTRY / directory).exists(), f"registry/{directory} is back")

    def test_every_folder_holds_exactly_its_record_and_prompt(self):
        for directory, (file_name, _, _) in persona_registry.KINDS.items():
            folders = sorted((FOLDERS / directory).iterdir())
            self.assertTrue(folders, directory)
            for folder in folders:
                with self.subTest(folder=f"{directory}/{folder.name}"):
                    self.assertTrue(folder.is_dir(), "orphan file beside the record folders")
                    self.assertEqual(sorted(path.name for path in folder.iterdir()),
                                     sorted([file_name, persona_registry.PROMPT_FILE]))
                    self.assertTrue(all(path.is_file() for path in folder.iterdir()))


class RecordShapeTests(unittest.TestCase):
    def test_every_record_has_the_schema_key_set_in_the_schema_order_and_is_valid(self):
        store = SchemaStore()
        for directory, (_, schema_name, _) in persona_registry.KINDS.items():
            schema = json.loads((FOLDERS / schema_name).read_text(encoding="utf-8"))
            order = list(schema["properties"])
            self.assertEqual(schema["required"], order, schema_name)
            self.assertIs(schema["additionalProperties"], False, schema_name)
            for folder, record in records(directory):
                with self.subTest(record=f"{directory}/{folder.name}"):
                    self.assertEqual(list(record), order)
                    self.assertEqual(validate_document(record, schema_name, store), [])

    def test_ids_match_their_folder_and_are_unique(self):
        for directory, (_, _, field) in persona_registry.KINDS.items():
            ids = [record[field] for _, record in records(directory)]
            self.assertEqual(ids, [folder.name for folder, _ in records(directory)], directory)
            self.assertEqual(len(ids), len(set(ids)), directory)

    def test_provenance_is_explicitly_empty_or_the_full_generator_block(self):
        for folder, record in records("personas"):
            with self.subTest(persona=folder.name):
                provenance = record["provenance"]
                self.assertIn(list(provenance), ([], PROVENANCE_KEYS))
                if provenance:
                    self.assertEqual(provenance["generated_by"], catalog_personas.GENERATOR)

    def test_prompt_md_is_the_prompt_section_the_assembler_renders(self):
        for directory in persona_registry.KINDS:
            for folder, _ in records(directory):
                with self.subTest(record=f"{directory}/{folder.name}"):
                    self.assertEqual((folder / persona_registry.PROMPT_FILE).read_text(encoding="utf-8"),
                                     catalog_personas.prompt_text(folder, directory))

    def test_loading_leaves_out_only_empty_optional_fields(self):
        for directory, (_, _, field) in persona_registry.KINDS.items():
            for folder, record in records(directory):
                value = persona_registry.loaded(directory, record)
                dropped = set(record) - set(value)
                self.assertLessEqual(dropped, set(persona_registry.ELIDED_WHEN_EMPTY[directory]), folder.name)
                self.assertTrue(all(record[key] in ([], {}) for key in dropped), folder.name)
                self.assertEqual(value[field], folder.name)


class ReferenceTests(unittest.TestCase):
    """Personas carry no role reference; roles and personas are bound together by job templates,
    so every id a template names (composition, variants, stage pools) must be a folder."""

    def test_every_persona_and_role_a_job_template_names_exists(self):
        personas = set(persona_registry.record_ids(registry_paths.REGISTRY, "personas"))
        roles = set(persona_registry.record_ids(registry_paths.REGISTRY, "roles"))
        for template in templates():
            with self.subTest(template=template["job_template_id"]):
                named_personas = {template["composition"]["persona_id"], *(template.get("persona_variants") or [])}
                for pool in (template.get("stage_personas") or {}).values():
                    named_personas |= set(pool)
                named_roles = {template["composition"]["role_id"], *(template.get("role_variants") or []),
                               *(template.get("stage_roles") or {}).values()}
                self.assertLessEqual(named_personas, personas)
                self.assertLessEqual(named_roles, roles)


if __name__ == "__main__":
    unittest.main()
