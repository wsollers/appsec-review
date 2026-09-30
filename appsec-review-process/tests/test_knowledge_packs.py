"""Knowledge packs (ADR-0034, W1 and W4): the registry kind, the persona key, the job template's
``knowledge_packs`` map, the prompt section, input identity and ``knowledge_packs.py check``.

Every pack here is a test fixture written into a temporary copy of the registry; no real pack is read.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import attack_reference  # noqa: E402
import catalog_personas  # noqa: E402
import knowledge_packs  # noqa: E402
import persona_invocation as pi  # noqa: E402
import persona_prompt_assembly as ppa  # noqa: E402
import persona_registry  # noqa: E402
import registry_paths  # noqa: E402
import tunables  # noqa: E402
from persona_invocation_support import composition_block, copy_registry  # noqa: E402
from schema_validate import SCHEMAS_DIR, SchemaStore, validate_document  # noqa: E402

PACK = "fixture-injection"
ATTACKER = "malicious-tenant"                      # 07 stage persona (attacker), not in the template map
DEFENDER = "defensive-skeptic"                     # 08 stage persona (defender)
TEMPLATE = "claim-review-pool-cell"
# The W3 assignments, now in claim-review-pool-cell.json's knowledge_packs map (ADR-0034 addendum 1).
TEMPLATE_MAP = {"cloud-initial-access-operator": ["cloud-exposure"],
                "opportunistic-public-web-attacker": ["injection"], "api-contract-abuser": ["injection"],
                "supply-chain-attacker": ["supply-chain"], "insider-developer": ["supply-chain"]}


def fixture_pack(pack_id: str = PACK, **changes) -> dict:
    value = {
        "schema": "appsec-review/knowledge-pack/0.1",
        "pack_id": pack_id,
        "display_name": "Fixture injection",
        "summary": "Untrusted input reaches an interpreter without neutralisation.",
        "applies_to": ["http-api"],
        "looks_for": ["string-built SQL", "shell commands built from request fields"],
        "preconditions": ["attacker controls a request field"],
        "proof_obligations": ["cite the source-to-sink path with file and line"],
        "false_positive_traps": ["parameterised query that only looks concatenated"],
        "refs": {"attack_tactics": ["initial-access"], "attack_techniques": ["T1190"],
                 "capec": ["CAPEC-66"], "cwe": ["CWE-89"]},
        "must_not": [],
    }
    value.update(changes)
    return value


class Registry:
    """A temporary registry copy (pipeline/ plus the personas/ folder beside it)."""

    def __init__(self, base: Path) -> None:
        self.dir = copy_registry(base / registry_paths.DIRNAME)
        (self.dir / registry_paths.KNOWLEDGE_PACKS).mkdir(exist_ok=True)

    def write_pack(self, record: dict, name: str | None = None) -> Path:
        path = self.dir / registry_paths.KNOWLEDGE_PACKS / f"{name or record['pack_id']}.json"
        path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        return path

    def persona_path(self, persona_id: str) -> Path:
        return persona_registry.record_path(self.dir, "personas", persona_id)[1]

    def template_path(self, template_id: str = TEMPLATE) -> Path:
        return registry_paths.template(template_id, self.dir)

    def set_template_map(self, mapping, template_id: str = TEMPLATE) -> None:
        """Replace the template's ``knowledge_packs`` map (None removes the key)."""
        path = self.template_path(template_id)
        template = json.loads(path.read_text(encoding="utf-8"))
        if mapping is None:
            template.pop("knowledge_packs", None)
        else:
            template["knowledge_packs"] = mapping
        path.write_text(json.dumps(template, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def set_packs(self, persona_id: str, packs: list[str]) -> None:
        path = self.persona_path(persona_id)
        record = json.loads(path.read_text(encoding="utf-8"))
        record["knowledge_packs"] = packs
        path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.registry = Registry(Path(self._tmp.name))
        self.registry.write_pack(fixture_pack())
        self.registry.set_packs(ATTACKER, [PACK])

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def check(self, **kwargs) -> list[str]:
        kwargs.setdefault("reference", None)
        kwargs.setdefault("cwe", None)
        return knowledge_packs.check(self.registry.dir, **kwargs)[0]


class SchemaTests(unittest.TestCase):
    def test_pack_schema_lists_every_key_required_in_adr_order(self):
        schema = json.loads((SCHEMAS_DIR / "knowledge-pack.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(list(schema["properties"]), list(knowledge_packs.KEY_ORDER))
        self.assertEqual(schema["required"], list(knowledge_packs.KEY_ORDER))
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(list(schema["properties"]["refs"]["properties"]), list(knowledge_packs.REF_KEYS))
        self.assertEqual(schema["properties"]["schema"]["const"], knowledge_packs.SCHEMA_ID)
        for key, cap in knowledge_packs.CAPS.items():
            self.assertEqual(schema["properties"][key]["maxItems"], cap, key)
        for key in knowledge_packs.REF_KEYS:
            self.assertEqual(schema["properties"]["refs"]["properties"][key]["maxItems"], knowledge_packs.REF_CAP)
        self.assertEqual(validate_document(fixture_pack(), "knowledge-pack.schema.json", SchemaStore()), [])

    def test_persona_schema_has_knowledge_packs_right_before_provenance(self):
        schema = json.loads((persona_registry.FOLDER_ROOT / "persona.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(list(schema["properties"])[-2:], ["knowledge_packs", "provenance"])

    def test_the_cap_is_a_tunable_not_a_schema_limit(self):
        """ADR-0034 addendum 2: no hard-coded maxItems on persona packs in either schema."""
        self.assertEqual(tunables.shared("knowledge_packs_per_persona_max"), 2)
        self.assertEqual(persona_registry.packs_per_persona_max(), 2)
        persona = json.loads((persona_registry.FOLDER_ROOT / "persona.schema.json").read_text(encoding="utf-8"))
        self.assertNotIn("maxItems", persona["properties"]["knowledge_packs"])
        template = json.loads((SCHEMAS_DIR / "job-template.schema.json").read_text(encoding="utf-8"))
        value = template["properties"]["knowledge_packs"]
        self.assertNotIn("maxItems", value["additionalProperties"])
        self.assertNotIn("knowledge_packs", template["required"])
        store = SchemaStore()
        base = json.loads(registry_paths.template(TEMPLATE).read_text(encoding="utf-8"))
        self.assertEqual(validate_document(base, "job-template.schema.json", store), [])
        self.assertTrue(validate_document({**base, "knowledge_packs": ["injection"]}, "job-template.schema.json", store))
        self.assertTrue(validate_document({**base, "knowledge_packs": {ATTACKER: "injection"}},
                                          "job-template.schema.json", store))

    def test_real_template_carries_the_w3_assignments_and_the_defaults_are_empty(self):
        template = json.loads(registry_paths.template(TEMPLATE).read_text(encoding="utf-8"))
        self.assertEqual(template["knowledge_packs"], TEMPLATE_MAP)
        self.assertEqual(list(template)[list(template).index("stage_personas") + 1], "knowledge_packs")
        for persona_id, packs in TEMPLATE_MAP.items():
            self.assertEqual(persona_registry.persona_pack_ids(registry_paths.REGISTRY, persona_id), [], persona_id)
            self.assertEqual(persona_registry.resolve_pack_ids(template, persona_id), packs, persona_id)
        self.assertEqual(persona_registry.resolve_pack_ids(template, ATTACKER), [])

    def test_registry_paths_and_every_real_persona_carry_the_key(self):
        self.assertEqual(registry_paths.KNOWLEDGE_PACKS_DIR, registry_paths.REGISTRY / "knowledge-packs")
        self.assertTrue(registry_paths.KNOWLEDGE_PACKS_DIR.is_dir())
        for persona_id in persona_registry.record_ids(registry_paths.REGISTRY, "personas"):
            record = json.loads(persona_registry.record_path(registry_paths.REGISTRY, "personas", persona_id)[1]
                                .read_text(encoding="utf-8"))
            self.assertIsInstance(record["knowledge_packs"], list, persona_id)

    def test_catalog_label_becomes_the_field(self):
        text = ("## Core Attacker And Abuse Personas\n\n### fixture-attacker\n\nFinds things.\n\n"
                "Knowledge packs:\n\n- `fixture-injection`\n\nInputs:\n\n- code\n")
        record = catalog_personas.record("fixture-attacker", catalog_personas.parse(text)["fixture-attacker"])
        self.assertEqual(record["knowledge_packs"], [PACK])
        self.assertEqual(list(record)[-2:], ["knowledge_packs", "provenance"])
        self.assertNotIn("knowledge_packs", record["assumptions"])


class CheckTests(Base):
    def test_the_real_registry_passes_without_a_snapshot_and_says_format_only(self):
        errors, notes = knowledge_packs.check(registry_paths.REGISTRY, reference=None, cwe=None)
        self.assertEqual(errors, [])
        self.assertTrue(any("format-checked only" in note for note in notes))

    def test_default_resolution_never_fails_for_a_missing_snapshot(self):
        with mock.patch.object(attack_reference, "load", return_value=(None, {"code": attack_reference.GAP_MISSING})):
            errors, notes = knowledge_packs.check(self.registry.dir)
        self.assertEqual(errors, [])
        self.assertIn(attack_reference.GAP_MISSING, " ".join(notes))

    def test_a_valid_fixture_pack_and_persona_pass(self):
        self.assertEqual(self.check(), [])

    def test_bad_id_formats_and_unknown_tactic_fail(self):
        refs = {"attack_tactics": ["not-a-tactic"], "attack_techniques": ["T12"],
                "capec": ["CAPEC-0"], "cwe": ["cwe-89"]}
        self.registry.write_pack(fixture_pack(refs=refs))
        errors = "\n".join(self.check())
        for text in ("attack_tactics 'not-a-tactic'", "attack_techniques 'T12'", "capec 'CAPEC-0'", "cwe 'cwe-89'"):
            self.assertIn(text, errors)

    def test_file_name_must_match_pack_id(self):
        self.registry.write_pack(fixture_pack("other-name"), name="misnamed")
        self.assertIn("knowledge-packs/misnamed.json: pack_id does not match the file name", self.check())

    def test_caps_are_enforced(self):
        self.registry.write_pack(fixture_pack(looks_for=[f"item {n}" for n in range(13)]))
        self.assertIn("knowledge-packs/fixture-injection.json: looks_for has more than 12 entries", self.check())
        refs = dict(fixture_pack()["refs"], attack_techniques=[f"T{1000 + n}" for n in range(16)])
        self.registry.write_pack(fixture_pack(refs=refs))
        self.assertIn("knowledge-packs/fixture-injection.json: refs.attack_techniques has more than 15 ids",
                      self.check())

    def test_the_cap_comes_from_the_tunable(self):
        self.registry.write_pack(fixture_pack("fixture-b"))
        self.registry.set_packs(ATTACKER, [PACK, "fixture-b"])
        self.assertEqual(self.check(), [])
        with mock.patch.object(tunables, "shared", side_effect=lambda name: {"knowledge_packs_per_persona_max": 1}[name]):
            self.assertIn(f"personas/{ATTACKER}: lists more than 1 knowledge packs", self.check())
        self.assertIn(f"personas/{ATTACKER}: lists more than 1 knowledge packs", self.check(cap=1))

    def test_persona_may_list_at_most_two_existing_packs(self):
        for name in ("fixture-b", "fixture-c"):
            self.registry.write_pack(fixture_pack(name))
        self.registry.set_packs(ATTACKER, [PACK, "fixture-b", "fixture-c"])
        self.assertIn(f"personas/{ATTACKER}: lists more than 2 knowledge packs", self.check())
        self.registry.set_packs(ATTACKER, ["no-such-pack"])
        self.assertIn(f"personas/{ATTACKER}: knowledge pack 'no-such-pack' does not exist", self.check())

    def test_only_attacker_and_domain_specialist_personas_may_list_packs(self):
        self.registry.set_packs(DEFENDER, [PACK])
        errors = self.check()
        self.assertTrue(any(error.startswith(f"personas/{DEFENDER}: only attacker and domain-specialist")
                            for error in errors), errors)

    def test_a_resolved_snapshot_must_know_every_id(self):
        class Reference:
            identity = {"snapshot_id": "fixture-snapshot"}
            tactics = {"TA0001": {"shortname": "initial-access"}}

            def validate_technique(self, value):
                return attack_reference.UNKNOWN_ID

            def validate_capec(self, value):
                return attack_reference.DEPRECATED

        class Cwe:
            used = "fixture-snapshot"

            def validate(self, value):
                raise ValueError("unknown")

        errors, notes = knowledge_packs.check(self.registry.dir, reference=Reference(), cwe=Cwe())
        self.assertIn("knowledge-packs/fixture-injection.json: refs.attack_techniques T1190 is UNKNOWN_ID "
                      "in the MITRE snapshot", errors)
        self.assertIn("knowledge-packs/fixture-injection.json: refs.capec CAPEC-66 is DEPRECATED in the MITRE snapshot",
                      errors)
        self.assertTrue(any("refs.cwe CWE-89" in error for error in errors))
        self.assertFalse(any("format-checked only" in note for note in notes))


class TemplateCheckTests(Base):
    """``knowledge_packs.py check`` validates every job template's map with the persona-default rules."""

    WHERE = f"job-templates/{TEMPLATE}.json: knowledge_packs"

    def test_the_real_template_map_and_a_valid_fixture_map_pass(self):
        self.assertEqual(self.check(), [])
        self.registry.set_template_map({ATTACKER: [PACK], DEFENDER: []})
        self.assertEqual(self.check(), [])

    def test_unknown_persona_and_persona_outside_the_template_fail(self):
        self.registry.set_template_map({"no-such-persona": [PACK]})
        errors = self.check()
        self.assertIn(f"{self.WHERE}['no-such-persona']: persona does not exist", errors)
        self.registry.set_template_map({"general-red-team-hunter": [PACK]})
        errors = self.check()
        self.assertTrue(any(e.startswith(f"{self.WHERE}['general-red-team-hunter']: persona is not one the template runs as")
                            for e in errors), errors)

    def test_unknown_pack_fails(self):
        self.registry.set_template_map({ATTACKER: ["no-such-pack"]})
        self.assertIn(f"{self.WHERE}['{ATTACKER}']: knowledge pack 'no-such-pack' does not exist", self.check())

    def test_category_rule_applies_to_the_map(self):
        self.registry.set_template_map({DEFENDER: [PACK]})
        errors = self.check()
        self.assertTrue(any(e.startswith(f"{self.WHERE}['{DEFENDER}']: only attacker and domain-specialist")
                            for e in errors), errors)

    def test_cap_applies_to_the_map_from_the_tunable(self):
        for name in ("fixture-b", "fixture-c"):
            self.registry.write_pack(fixture_pack(name))
        self.registry.set_template_map({ATTACKER: [PACK, "fixture-b", "fixture-c"]})
        self.assertIn(f"{self.WHERE}['{ATTACKER}']: lists more than 2 knowledge packs", self.check())
        self.registry.set_template_map({ATTACKER: [PACK, "fixture-b"]})
        self.assertEqual(self.check(), [])
        self.assertIn(f"{self.WHERE}['{ATTACKER}']: lists more than 1 knowledge packs", self.check(cap=1))

    def test_a_map_that_is_not_a_map_fails(self):
        self.registry.set_template_map([PACK])
        self.assertIn(f"{self.WHERE} is not a map of persona id to pack ids", self.check())


class ResolutionTests(Base):
    """One rule (``persona_registry.resolve_pack_ids``): named in the map -> exactly those packs."""

    def setUp(self) -> None:
        super().setUp()
        self.registry.write_pack(fixture_pack("fixture-b"))

    def template(self) -> dict:
        return json.loads(self.registry.template_path().read_text(encoding="utf-8"))

    def test_override_wins_over_the_persona_default(self):
        self.registry.set_template_map({ATTACKER: ["fixture-b"]})
        self.assertEqual(persona_registry.resolve_pack_ids(self.template(), ATTACKER, self.registry.dir), ["fixture-b"])

    def test_empty_list_removes_the_default(self):
        self.registry.set_template_map({ATTACKER: []})
        self.assertEqual(persona_registry.resolve_pack_ids(self.template(), ATTACKER, self.registry.dir), [])

    def test_a_persona_not_named_falls_back_to_its_default(self):
        self.registry.set_template_map({DEFENDER: []})
        self.assertEqual(persona_registry.resolve_pack_ids(self.template(), ATTACKER, self.registry.dir), [PACK])
        self.registry.set_template_map(None)
        self.assertEqual(persona_registry.resolve_pack_ids(self.template(), ATTACKER, self.registry.dir), [PACK])
        self.assertEqual(persona_registry.resolve_pack_ids(None, ATTACKER, self.registry.dir), [PACK])

    def test_a_malformed_map_is_refused(self):
        with self.assertRaises(ValueError):
            persona_registry.resolve_pack_ids({"knowledge_packs": {ATTACKER: "fixture-b"}}, ATTACKER, self.registry.dir)
        with self.assertRaises(ValueError):
            persona_registry.resolve_pack_ids({"knowledge_packs": [ATTACKER]}, ATTACKER, self.registry.dir)


class PromptTests(Base):
    def setUp(self) -> None:
        super().setUp()
        patcher = mock.patch.object(ppa, "REGISTRY_DIR", self.registry.dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_packs_render_right_after_the_persona_section_with_the_framing_statement(self):
        text, _ = ppa.assemble_prompt_text(TEMPLATE, persona_id=ATTACKER)
        persona = text.index(f"## Persona ({ATTACKER})")
        packs = text.index("## Knowledge Packs\n\n" + ppa.KNOWLEDGE_PACK_FRAMING + "\n")
        pack = text.index(f"## Knowledge Pack ({PACK})\n\n```json\n"
                          + json.dumps(fixture_pack(), indent=2, sort_keys=True) + "\n```\n")
        role = text.index("## Role (")
        self.assertLess(persona, packs)
        self.assertLess(packs, pack)
        self.assertLess(pack, role)
        self.assertIn("never evidence", ppa.KNOWLEDGE_PACK_FRAMING)
        self.assertIn("coverage gap", ppa.KNOWLEDGE_PACK_FRAMING)
        self.assertIn('never as "no issues found"', ppa.KNOWLEDGE_PACK_FRAMING)

    def test_a_persona_without_packs_renders_exactly_as_before(self):
        text, _ = ppa.assemble_prompt_text(TEMPLATE, persona_id=DEFENDER)
        self.assertNotIn("Knowledge Pack", text)
        folder = self.registry.persona_path(DEFENDER).parent
        record = json.loads((folder / "persona.json").read_text(encoding="utf-8"))
        self.assertNotIn("knowledge_packs", persona_registry.loaded("personas", record))
        self.assertEqual(ppa.render_persona_prompt(DEFENDER, record, self.registry.dir),
                         (folder / "prompt.md").read_text(encoding="utf-8"))

    def test_folder_prompt_md_carries_the_section(self):
        folder = self.registry.persona_path(ATTACKER).parent
        rendered = catalog_personas.prompt_text(folder, "personas")
        self.assertIn(f"## Knowledge Pack ({PACK})", rendered)
        self.assertIn(rendered, ppa.assemble_prompt_text(TEMPLATE, persona_id=ATTACKER)[0])

    def test_render_is_a_pure_function_of_the_registry(self):
        first = ppa.assemble_prompt_text(TEMPLATE, persona_id=ATTACKER)[0]
        self.assertEqual(first, ppa.assemble_prompt_text(TEMPLATE, persona_id=ATTACKER)[0])
        self.registry.write_pack(fixture_pack(summary="A different focus."))
        self.assertNotEqual(first, ppa.assemble_prompt_text(TEMPLATE, persona_id=ATTACKER)[0])

    def test_template_override_renders_instead_of_the_default(self):
        self.registry.write_pack(fixture_pack("fixture-b"))
        self.registry.set_template_map({ATTACKER: ["fixture-b"]})
        text = ppa.assemble_prompt_text(TEMPLATE, persona_id=ATTACKER)[0]
        self.assertIn("## Knowledge Pack (fixture-b)", text)
        self.assertNotIn(f"## Knowledge Pack ({PACK})", text)
        # prompt.md has no job context: it keeps the persona default
        folder = self.registry.persona_path(ATTACKER).parent
        self.assertIn(f"## Knowledge Pack ({PACK})", catalog_personas.prompt_text(folder, "personas"))

    def test_template_empty_list_removes_the_section(self):
        self.registry.set_template_map({ATTACKER: []})
        self.assertNotIn("Knowledge Pack", ppa.assemble_prompt_text(TEMPLATE, persona_id=ATTACKER)[0])

    def test_real_template_gives_the_mapped_personas_their_packs(self):
        with mock.patch.object(ppa, "REGISTRY_DIR", registry_paths.REGISTRY):
            for persona_id, packs in TEMPLATE_MAP.items():
                with self.subTest(persona=persona_id):
                    text = ppa.assemble_prompt_text(TEMPLATE, persona_id=persona_id)[0]
                    self.assertIn("## Knowledge Packs\n", text)
                    for pack_id in packs:
                        self.assertIn(f"## Knowledge Pack ({pack_id})", text)
            for persona_id in (ATTACKER, DEFENDER, "authenticated-low-priv-user"):
                with self.subTest(persona=persona_id):
                    self.assertNotIn("Knowledge Pack", ppa.assemble_prompt_text(TEMPLATE, persona_id=persona_id)[0])

    def test_prompt_cache_path_does_not_depend_on_the_map(self):
        with mock.patch.object(ppa, "PROMPT_CACHE_DIR", Path(self._tmp.name) / "prompt-cache"), \
                mock.patch.object(ppa, "PROMPT_ROOT", Path(self._tmp.name)):
            first = ppa.assemble_outer_prompt(TEMPLATE, persona_id=ATTACKER)
            self.registry.set_template_map({ATTACKER: []})
            second = ppa.assemble_outer_prompt(TEMPLATE, persona_id=ATTACKER)
        self.assertEqual(first["path"], second["path"])
        self.assertNotEqual(first["sha256"], second["sha256"])

    def test_a_missing_pack_stops_assembly(self):
        self.registry.set_packs(ATTACKER, ["no-such-pack"])
        with self.assertRaises(ppa.PromptAssemblyError):
            ppa.assemble_prompt_text(TEMPLATE, persona_id=ATTACKER)


class IdentityTests(Base):
    def _block(self, persona_id: str) -> dict:
        block = composition_block(TEMPLATE, self.registry.dir)
        path = self.registry.persona_path(persona_id)
        record = persona_registry.loaded("personas", json.loads(path.read_text(encoding="utf-8")))
        return {**block, "persona_id": persona_id, "persona_sha256": pi._sha(record)}

    def test_composition_loads_and_hashes_the_personas_packs(self):
        store = SchemaStore()
        records = pi.load_composition(self.registry.dir, self._block(ATTACKER), store)
        self.assertEqual(dict(records["knowledge_packs"]), {PACK: fixture_pack()})
        before = pi.composition_sha256(records)
        self.registry.write_pack(fixture_pack(summary="A different focus."))
        after = pi.composition_sha256(pi.load_composition(self.registry.dir, self._block(ATTACKER), store))
        self.assertNotEqual(before, after)

    def test_a_persona_without_packs_keeps_its_composition_hash(self):
        records = pi.load_composition(self.registry.dir, self._block(DEFENDER), SchemaStore())
        self.assertNotIn("knowledge_packs", records)
        legacy = pi._sha({name: pi._sha(pi.thaw(records[name])) for name, _, _, _ in pi.COMPOSITION_KINDS})
        self.assertEqual(pi.composition_sha256(records), legacy)

    def test_knowledge_pack_rels_follow_the_persona_files(self):
        paths = [f"personas/personas/{ATTACKER}/persona.json", f"personas/personas/{DEFENDER}/persona.json",
                 "claim_reviewer_pool.py"]
        self.assertEqual(persona_registry.knowledge_pack_rels(paths, self.registry.dir),
                         [f"pipeline/knowledge-packs/{PACK}.json"])

    def test_knowledge_pack_rels_use_the_packs_the_job_template_resolves(self):
        self.registry.write_pack(fixture_pack("fixture-b"))
        paths = [registry_paths.template_rel(TEMPLATE), f"personas/personas/{ATTACKER}/persona.json"]
        rel = lambda pack_id: f"pipeline/knowledge-packs/{pack_id}.json"   # noqa: E731
        self.registry.set_template_map({ATTACKER: ["fixture-b"]})
        self.assertEqual(persona_registry.knowledge_pack_rels(paths, self.registry.dir), [rel("fixture-b")])
        self.registry.set_template_map({ATTACKER: []})
        self.assertEqual(persona_registry.knowledge_pack_rels(paths, self.registry.dir), [])
        self.registry.set_template_map({DEFENDER: []})
        self.assertEqual(persona_registry.knowledge_pack_rels(paths, self.registry.dir), [rel(PACK)])
        self.registry.set_template_map(None)
        real = persona_registry.knowledge_pack_rels(
            [registry_paths.template_rel(TEMPLATE), *(f"personas/personas/{p}/persona.json" for p in TEMPLATE_MAP)])
        self.assertEqual(real, sorted({rel(p) for packs in TEMPLATE_MAP.values() for p in packs}))

    def test_composition_uses_the_template_resolved_packs(self):
        self.registry.write_pack(fixture_pack("fixture-b"))
        self.registry.set_template_map({ATTACKER: ["fixture-b"]})
        store = SchemaStore()
        records = pi.load_composition(self.registry.dir, self._block(ATTACKER), store)
        self.assertEqual(dict(records["knowledge_packs"]), {"fixture-b": fixture_pack("fixture-b")})
        overridden = pi.composition_sha256(records)
        self.registry.set_template_map({ATTACKER: []})
        records = pi.load_composition(self.registry.dir, self._block(ATTACKER), store)
        self.assertNotIn("knowledge_packs", records)
        self.assertNotEqual(pi.composition_sha256(records), overridden)

    def test_handoff_composition_hash_uses_the_template_resolved_packs(self):
        import create_job_handoff
        import execution_state
        run_id = "kp-handoff-fixture"
        with mock.patch.object(execution_state, "RUNS", Path(self._tmp.name) / "runs"):
            (execution_state.RUNS / run_id).mkdir(parents=True)
            calls = []

            def resolve(template, persona_id, registry_dir=None, persona_record=None):
                calls.append((template.get("job_template_id"), "knowledge_packs" in template, persona_id))
                return list(resolved)

            with mock.patch.object(create_job_handoff.persona_registry, "resolve_pack_ids", side_effect=resolve):
                resolved = []
                without = create_job_handoff.build_handoff(run_id, TEMPLATE, [])
                resolved = ["injection"]
                with_pack = create_job_handoff.build_handoff(run_id, TEMPLATE, [])
        self.assertEqual(calls[0], (TEMPLATE, True, "claim-reviewer"))
        self.assertNotEqual(without["identity"]["composition_sha256"], with_pack["identity"]["composition_sha256"])


class HashCoverageTests(unittest.TestCase):
    """Every job that hashes a persona.json into its code identity also hashes that persona's packs."""

    SITES = (("claim_reviewer_pool", "_code_hashes"), ("hypothesis_discovery", "_code_hashes"),
             ("attack_chain_pool", "code_hashes"), ("threat_workbench", "code_hashes"),
             ("poc_fix_pool", "code_hashes"), ("synthesis_report", "_generator_sha256"))

    def test_every_persona_hashing_job_hashes_listed_packs(self):
        import importlib
        expected = f"pipeline/knowledge-packs/{PACK}.json"
        with mock.patch.object(persona_registry, "persona_pack_ids", return_value=[PACK]):
            for module_name, function in self.SITES:
                module = importlib.import_module(module_name)
                with self.subTest(module=module_name), \
                        mock.patch.object(module, "file_hash", side_effect=lambda path: "h:" + Path(path).name):
                    if module_name == "synthesis_report":
                        with mock.patch.object(module, "_sha", side_effect=lambda value: value):
                            values = getattr(module, function)()
                    else:
                        values = getattr(module, function)()
                    self.assertIn(expected, values)

    def test_every_module_naming_a_persona_file_uses_the_helper(self):
        for path in sorted(ROOT.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            if path.name in ("persona_registry.py", "catalog_personas.py"):
                continue
            if "personas/personas/" in text:
                with self.subTest(module=path.name):
                    self.assertIn("knowledge_pack_rels", text)


if __name__ == "__main__":
    unittest.main()
