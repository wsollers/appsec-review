from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import registry_paths

import component_characterization as cc
import execution_state as state
import persona_invocation as pi
import persona_prompt_assembly as ppa
import validate_job_output as output_validator
from schema_validate import SchemaStore, validate_document
from worker_result import artifact_records, terminal_envelope


class ComponentCharacterizationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.owner = Path(self.temporary.name)
        self.target = self.owner / "hello-autotools"
        (self.target / "src").mkdir(parents=True)
        (self.target / "src/main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        (self.target / "Makefile.am").write_text("bin_PROGRAMS = hello\nhello_SOURCES = src/main.c\n", encoding="utf-8")
        (self.target / "README.md").write_text("# hello-autotools\n", encoding="utf-8")
        self.evidence = self.owner / "evidence"
        self.evidence.mkdir()
        fixture = ROOT / "tests/fixtures/component-characterization/hello-autotools.json"
        text = fixture.read_text(encoding="utf-8")
        text = text.replace("MAIN_HASH", state.file_hash(self.target / "src/main.c"))
        text = text.replace("MAKE_HASH", state.file_hash(self.target / "Makefile.am"))
        text = text.replace("README_HASH", state.file_hash(self.target / "README.md"))
        self.value = json.loads(text)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def canonical_schema_stub(value, name):
        if name == "intel-manifest.schema.json":
            return []
        return validate_document(value, name)

    def test_schema_registry_composition_and_claim_ceiling_are_closed(self):
        self.assertEqual(validate_document(self.value, "component-purpose-map.schema.json"), [])
        store = SchemaStore()
        prompt, template = ppa.assemble_prompt_text(cc.TEMPLATE, store)
        self.assertIn("This job produces evidence organization and routing only", prompt)
        records = pi.load_composition(registry_paths.REGISTRY, {
            "job_template_id": cc.TEMPLATE,
            "job_template_sha256": pi._sha(template),
            **{name + "_id": template["composition"][name + "_id"]
               for name, *_rest in pi.COMPOSITION_KINDS if name != "job_template"},
            **{name + "_sha256": pi._sha(pi._load_record(registry_paths.REGISTRY, directory, schema, field,
                template["composition"][name + "_id"], store))
               for name, directory, schema, field in pi.COMPOSITION_KINDS if name != "job_template"},
        }, store)
        ceiling = pi.claim_ceiling(records["role"], records["tooling_profile"])
        expected_ceiling = {
            "static_scope_classification", "statically_inferred_component_purpose",
            "evidence_backed_ownership", "component_relationship", "component_tag",
            "review_routing", "unknown", "coverage_gap", "rescope_trigger",
        }
        expected_contract = {
            "static-scope-classification", "statically-inferred-component-purpose",
            "evidence-backed-ownership", "component-relationship", "component-tag",
            "review-routing", "unknown", "coverage-gap", "rescope-trigger",
        }
        self.assertEqual(set(ceiling["allowed"]), expected_ceiling)
        contract = json.loads((registry_paths.contract("component-map")).read_text(
            encoding="utf-8"))
        policy = output_validator.CLAIM_CLASS_POLICIES["component-map"]
        contract_allowed = set(contract["claim_class"]["allowed_assertions"])
        self.assertEqual(contract_allowed, expected_contract)
        self.assertEqual(policy["allowed_assertions"], expected_contract)
        self.assertEqual({item.replace("_", "-") for item in ceiling["allowed"]}, contract_allowed)
        self.assertEqual(policy["claim_class_id"], contract["claim_class"]["claim_class_id"])
        self.assertTrue({"finding", "severity", "runtime_state"} <= set(ceiling["prohibited"]))

    def test_fixture_passes_deterministic_semantic_validation(self):
        self.assertEqual(cc.validate_payload(self.value, target_root=self.target,
                                             evidence_root=self.evidence), [])

    def test_expected_category_must_be_mapped_or_explicitly_absent(self):
        invalid = deepcopy(self.value)
        invalid["negative_evidence"] = [item for item in invalid["negative_evidence"]
                                         if item["category"] != "generated"]
        errors = cc.validate_payload(invalid, target_root=self.target, evidence_root=self.evidence)
        self.assertTrue(any("generated" in error for error in errors))

    def test_category_coverage_citation_must_actually_match_the_category(self):
        """Schema already guarantees all six keys are present in the classified/absent shape; this
        is the Python cross-check that a citation is real and for the right category -- not, e.g., a
        model citing a scope classified 'build-tooling' as satisfying 'first-party' (2026-10-01)."""
        wrong_scope = deepcopy(self.value)
        wrong_scope["category_coverage"]["first-party"] = {
            "status": "classified", "scope_ids": ["build-definition"]}  # build-definition is build-tooling
        errors = cc.category_coverage_errors(wrong_scope)
        self.assertTrue(any("'first-party'" in e and "'build-definition'" in e and "build-tooling" in e
                            for e in errors), errors)

        wrong_negative = deepcopy(self.value)
        wrong_negative["category_coverage"]["vendored"] = {
            "status": "absent", "negative_evidence_id": "neg-generated"}  # recorded for 'generated'
        errors = cc.category_coverage_errors(wrong_negative)
        self.assertTrue(any("'vendored'" in e and "neg-generated" in e and "generated" in e
                            for e in errors), errors)

        unresolved = deepcopy(self.value)
        unresolved["category_coverage"]["documentation"] = {
            "status": "absent", "negative_evidence_id": "neg-does-not-exist"}
        errors = cc.category_coverage_errors(unresolved)
        self.assertTrue(any("unresolved negative evidence" in e and "neg-does-not-exist" in e
                            for e in errors), errors)

        self.assertEqual(cc.category_coverage_errors(self.value), [])

    def test_candidate_security_tags_round_trips_through_full_schema_and_repair(self):
        """The published (post-repair) document must validate, not the model's draft: the model's
        placeholder cwe_name/cwe_catalog pass the loosened schema pre-repair, then Python overwrites
        both from the real catalog, and the result still validates against the full schema."""
        tagged = deepcopy(self.value)
        tagged["functional_components"][0]["candidate_security_tags"] = [{
            "cwe_id": "CWE-79", "cwe_name": "model's guess", "cwe_catalog": "model's guess",
            "rationale": "Illustrative: not evidenced by this fixture's actual source.",
            "evidence_citations": [tagged["functional_components"][0]["evidence_citations"][0]],
        }]
        self.assertEqual(cc.security_tag_errors(tagged), [])
        cc._resolve_security_tags(tagged)
        tag = tagged["functional_components"][0]["candidate_security_tags"][0]
        self.assertEqual(tag["cwe_id"], "CWE-79")
        self.assertNotIn("model's guess", (tag["cwe_name"], tag["cwe_catalog"]))
        self.assertEqual(cc.validate_payload(tagged, target_root=self.target,
                                             evidence_root=self.evidence), [])

    def test_unresolvable_cwe_id_fails_the_repair_before_publication(self):
        bad = deepcopy(self.value)
        bad["functional_components"][0]["candidate_security_tags"] = [{
            "cwe_id": "CWE-999999", "cwe_name": "x", "cwe_catalog": "x", "rationale": "x",
            "evidence_citations": [bad["functional_components"][0]["evidence_citations"][0]],
        }]
        self.assertTrue(any("CWE-999999" in e for e in cc.security_tag_errors(bad)))
        with self.assertRaises(ValueError):
            cc._resolve_security_tags(bad)

    def test_rejects_stale_citations_prohibited_conclusions_and_broken_references(self):
        stale = deepcopy(self.value)
        stale["functional_components"][0]["evidence_citations"][0]["content_hash"] = "0" * 64
        self.assertTrue(any("stale" in error for error in cc.validate_payload(
            stale, target_root=self.target, evidence_root=self.evidence)))

        conclusion = deepcopy(self.value)
        conclusion["functional_components"][0]["severity"] = "high"
        errors = cc.validate_payload(conclusion, target_root=self.target, evidence_root=self.evidence)
        self.assertTrue(errors)

        broken = deepcopy(self.value)
        broken["analysis_exclusions"][0]["rescope_trigger_id"] = "missing"
        self.assertTrue(any("does not resolve" in error for error in cc.validate_payload(
            broken, target_root=self.target, evidence_root=self.evidence)))

        missing = deepcopy(self.value)
        missing["functional_components"][0]["evidence_citations"] = []
        self.assertTrue(cc.validate_payload(missing, target_root=self.target,
                                            evidence_root=self.evidence))

    def test_conclusion_prose_is_commentary_and_structured_promotion_fails(self):
        """2026-10-01, run 20261001T064759Z-4a8586: a real response wrote '...without asserting
        exploitability or a compliance verdict' and was rejected by a phrase rule. ADR-0036: text is
        commentary; only a structured promotion field fails."""
        baseline = cc.validate_payload(self.value, target_root=self.target, evidence_root=self.evidence)
        for text in ("for routing to the secrets/crypto review lane, without asserting exploitability or a "
                     "compliance verdict.", "A confirmed vulnerability exists here; severity: critical.",
                     "The parser's buffer is fixed-size."):
            prose = deepcopy(self.value)
            prose["functional_components"][0]["observed_purpose"] = text
            self.assertEqual(cc.validate_payload(prose, target_root=self.target, evidence_root=self.evidence),
                             baseline, text)
        promoted = deepcopy(self.value)
        promoted["functional_components"][0]["severity"] = "critical"
        self.assertTrue(cc.validate_payload(promoted, target_root=self.target, evidence_root=self.evidence))
        self.assertTrue(any("prohibited conclusion field" in e for e in cc._walk_keys(promoted)))

    def test_overlapping_and_unassigned_physical_paths_fail_closed(self):
        overlapping = deepcopy(self.value)
        overlapping["code_scope_classification"][1]["path_patterns"].append("src/**")
        errors = cc.validate_payload(overlapping, target_root=self.target,
                                     evidence_root=self.evidence)
        self.assertTrue(any("overlapping" in error and "src/main.c" in error for error in errors))

        unassigned = deepcopy(self.value)
        unassigned["code_scope_classification"][2]["path_patterns"] = ["docs/**"]
        errors = cc.validate_payload(unassigned, target_root=self.target,
                                     evidence_root=self.evidence)
        self.assertTrue(any("not assigned" in error and "README.md" in error for error in errors))

    def test_component_relationship_and_tag_ids_are_deterministic(self):
        bad_component = deepcopy(self.value)
        bad_component["functional_components"][0]["component_id"] = "model-chosen-id"
        self.assertTrue(any("deterministic slug" in error for error in cc.validate_payload(
            bad_component, target_root=self.target, evidence_root=self.evidence)))

        bad_relationship = deepcopy(self.value)
        bad_relationship["component_relationships"][0]["relationship_id"] = "arbitrary"
        self.assertTrue(any("deterministic id" in error for error in cc.validate_payload(
            bad_relationship, target_root=self.target, evidence_root=self.evidence)))

        bad_tags = deepcopy(self.value)
        bad_tags["tag_cloud"] = list(reversed(bad_tags["tag_cloud"]))
        self.assertTrue(any("deterministic lexical order" in error for error in cc.validate_payload(
            bad_tags, target_root=self.target, evidence_root=self.evidence)))

    def test_provisional_intel_manifest_requires_complete_exact_hash_bound_lineage(self):
        attempt = self.owner / "assembly"
        terminal = attempt / "terminal-instances.json"
        terminal.parent.mkdir(parents=True)
        state.atomic_json(terminal, {"schema": "fixture/terminal-instances/1"})
        artifact = attempt / "assembled/evidence.json"
        artifact.parent.mkdir(parents=True)
        state.atomic_json(artifact, {"schema": "fixture/evidence/1"})
        source = self.value["source_snapshot_sha256"]
        manifest = {
            "schema": "appsec-review/intel-manifest/2.0", "run_id": "fixture-run",
            "source_snapshot_sha256": source, "assembly_status": "COMPLETE",
            "generation": {"generation_sha256": "sha256:" + "4" * 64,
                           "graph_sha256": "sha256:" + "5" * 64},
            "terminal_binding": {"path": "terminal-binding.json"},
            "producers": [{
                "job_id": "02-evidence-index", "contract": "evidence-index",
                "disposition": "accepted", "attempt_id": "evidence-1",
                "input_fingerprint": "sha256:" + "a" * 64, "execution_status": "OK",
                "accepted_pointer_sha256": "sha256:" + "8" * 64,
                "envelope_sha256": "sha256:" + "b" * 64, "source_snapshot_sha256": source,
                "build_lineage_sha256": None, "permissions": [],
                "gaps": [], "skip_reason": None,
                "artifacts": [{
                    "producer_job_id": "02-evidence-index", "producer_attempt_id": "evidence-1",
                    "producer_path": "evidence.json", "path": "assembled/evidence.json",
                    "sha256": "sha256:" + state.file_hash(artifact), "media_type": "application/json",
                }],
            }],
            "coverage_gaps": [], "manifest_sha256": "sha256:" + "0" * 64,
        }
        manifest["manifest_sha256"] = cc._manifest_self_sha256(manifest)
        binding = write_terminal_binding(attempt, manifest, terminal)
        envelope_artifacts = {"terminal-binding.json": state.file_hash(binding),
                              "terminal-instances.json": state.file_hash(terminal),
                              "assembled/evidence.json": state.file_hash(artifact)}
        with patch.object(cc, "validate_document", side_effect=self.canonical_schema_stub):
            errors, readable = cc._intel_manifest_errors(
                manifest, run_id="fixture-run", source_snapshot_sha256=source,
                attempt=attempt, envelope_artifacts=envelope_artifacts)
        self.assertEqual(errors, [])
        self.assertEqual(readable, envelope_artifacts)

        with patch.object(cc, "validate_document", side_effect=FileNotFoundError("schema absent")):
            errors, _ = cc._intel_manifest_errors(
                manifest, run_id="fixture-run", source_snapshot_sha256=source,
                attempt=attempt, envelope_artifacts=envelope_artifacts)
        self.assertTrue(any("remains blocked on F02" in error for error in errors))

        for mutate, expected in (
                (lambda value: value.__setitem__("assembly_status", "INCOMPLETE"), "not a COMPLETE"),
                (lambda value: value.__setitem__("source_snapshot_sha256", "sha256:" + "9" * 64),
                 "source snapshot"),
                (lambda value: value.__setitem__("manifest_sha256", "sha256:" + "9" * 64),
                 "self hash"),
                (lambda value: value["producers"][0]["artifacts"][0].__setitem__("sha256", "sha256:" + "9" * 64),
                 "hash-bound")):
            changed = deepcopy(manifest)
            mutate(changed)
            with patch.object(cc, "validate_document", side_effect=self.canonical_schema_stub):
                errors, _ = cc._intel_manifest_errors(
                    changed, run_id="fixture-run", source_snapshot_sha256=source,
                    attempt=attempt, envelope_artifacts=envelope_artifacts)
            self.assertTrue(any(expected in error for error in errors), errors)


def write_terminal_binding(attempt, manifest, terminal):
    """The intel-manifest/2.0 retained audit record beside a fixture manifest."""
    path = attempt / "terminal-binding.json"
    state.atomic_json(path, {
        "schema": "appsec-review/evidence-assembly-terminal-binding/1.0", "run_id": manifest["run_id"],
        "manifest_sha256": manifest["manifest_sha256"], "expected_spec_sha256": "sha256:" + "7" * 64,
        "terminal_instances": {"path": "terminal-instances.json",
            "sha256": "sha256:" + state.file_hash(terminal),
            "manifest_sha256": "sha256:" + "6" * 64, "outcome": "COMPLETE", "counts": {}},
        "producers": [{"job_id": item["job_id"], "terminal_instance_ids": ["one"]}
                      for item in manifest["producers"]]})
    return path


class ComponentCharacterizationLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.owner = Path(self.temporary.name)
        self.old_runs = state.RUNS
        state.RUNS = self.owner / "runs"
        self.run_id = "component-fixture"
        self.target = self.owner / "target"
        (self.target / "src").mkdir(parents=True)
        (self.target / "src/main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        (self.target / "Makefile.am").write_text("bin_PROGRAMS = hello\nhello_SOURCES = src/main.c\n", encoding="utf-8")
        (self.target / "README.md").write_text("# hello-autotools\n", encoding="utf-8")
        self.evidence = self.owner / "evidence"
        self.evidence.mkdir()
        fixture = ROOT / "tests/fixtures/component-characterization/hello-autotools.json"
        text = fixture.read_text(encoding="utf-8")
        text = text.replace("MAIN_HASH", state.file_hash(self.target / "src/main.c"))
        text = text.replace("MAKE_HASH", state.file_hash(self.target / "Makefile.am"))
        text = text.replace("README_HASH", state.file_hash(self.target / "README.md"))
        self.value = json.loads(text)
        self.inputs = {
            "job": cc.JOB, "run_id": self.run_id, "target_root": str(self.target),
            "target_name": "hello-autotools", "source_revision": None,
            "source_snapshot_sha256": self.value["source_snapshot_sha256"],
            "evidence_root": str(self.evidence), "evidence": {
                "job": cc.UPSTREAM_JOB, "attempt_id": "assembly-1",
                "pointer_sha256": "e" * 64, "envelope_sha256": "d" * 64,
                "manifest_sha256": "b" * 64, "manifest_self_sha256": "sha256:" + "c" * 64,
                "input_fingerprint": "sha256:" + "f" * 64,
                "generation_sha256": "sha256:" + "4" * 64,
                "graph_sha256": "sha256:" + "5" * 64,
                "terminal_manifest_sha256": "sha256:" + "6" * 64,
                "terminal_instances_path": "terminal-instances.json",
                "terminal_instances_sha256": "sha256:" + "1" * 64,
                "terminal_instances_manifest_sha256": "sha256:" + "6" * 64,
                "producers_sha256": "2" * 64,
                "artifact_set_sha256": "3" * 64, "artifacts": [],
            },
            "code": cc._code_hashes(),
        }

    def tearDown(self):
        state.RUNS = self.old_runs
        self.temporary.cleanup()

    def dispatch(self, *_args):
        return deepcopy(self.value), "# Component map\n", {
            "budget": "standard",
            "persona": {"persona_id": "developer-engineer", "role_id": "component-characterizer",
                        "domain_id": "component-characterization",
                        "tooling_profile_id": "component-evidence-router"},
            "model": {"alias": "fixture", "provider": "fixture", "version": "fixture"},
            "persona_result_sha256": "sha256:" + "b" * 64,
            "artifacts_read": ["src/main.c", "Makefile.am", "README.md"],
        }

    def test_current_inputs_exposes_only_published_assembly_artifacts(self):
        run = state.RUNS / self.run_id
        (run / "inputs").mkdir(parents=True)
        state.atomic_json(run / "inputs/artifact-manifest.json", {
            "schema": "fixture", "target": {"repo_path": str(self.target)}})
        base = run / "data/jobs" / cc.UPSTREAM_JOB
        attempt = base / "attempts/assembly-1"
        attempt.mkdir(parents=True)
        terminal = attempt / "terminal-instances.json"
        state.atomic_json(terminal, {"schema": "fixture/terminal-instances/1"})
        assembled = attempt / "assembled/evidence-index.json"
        assembled.parent.mkdir()
        state.atomic_json(assembled, {"schema": "fixture/evidence-index/1", "entries": []})
        source_snapshot = "sha256:" + cc.intake.source_identity(str(self.target))["fingerprint"]
        manifest = {
            "schema": "appsec-review/intel-manifest/2.0", "run_id": self.run_id,
            "source_snapshot_sha256": source_snapshot, "assembly_status": "COMPLETE",
            "generation": {"generation_sha256": "sha256:" + "4" * 64,
                           "graph_sha256": "sha256:" + "5" * 64},
            "terminal_binding": {"path": "terminal-binding.json"},
            "producers": [{
                "job_id": "02-evidence-index", "contract": "evidence-index",
                "disposition": "accepted", "attempt_id": "evidence-1",
                "input_fingerprint": "sha256:" + "a" * 64, "execution_status": "OK",
                "accepted_pointer_sha256": "sha256:" + "8" * 64,
                "envelope_sha256": "sha256:" + "b" * 64, "source_snapshot_sha256": source_snapshot,
                "build_lineage_sha256": None, "permissions": [],
                "gaps": [], "skip_reason": None,
                "artifacts": [{
                    "producer_job_id": "02-evidence-index", "producer_attempt_id": "evidence-1",
                    "producer_path": "evidence-index.json",
                    "path": "assembled/evidence-index.json",
                    "sha256": "sha256:" + state.file_hash(assembled), "media_type": "application/json",
                }],
            }],
            "coverage_gaps": [], "manifest_sha256": "0" * 64,
        }
        manifest["manifest_sha256"] = cc._manifest_self_sha256(manifest)
        write_terminal_binding(attempt, manifest, terminal)
        state.atomic_json(attempt / cc.UPSTREAM_MANIFEST, manifest)
        state.atomic_json(attempt / "status.json", {"status": "OK"})
        (attempt / "raw-tool-output.log").write_text("must not become a readable input\n",
                                                       encoding="utf-8")
        fingerprint = "sha256:" + "c" * 64
        envelope = terminal_envelope(
            run_id=self.run_id, job_id=cc.UPSTREAM_JOB, attempt_id="assembly-1",
            worker_kind="deterministic_python", execution_status="OK",
            acceptance_status="CURRENT", input_fingerprint=fingerprint,
            output_contract="pregather", started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z", summary="fixture",
            artifacts=artifact_records(attempt, [cc.UPSTREAM_MANIFEST, "status.json", "terminal-binding.json",
                                                  "terminal-instances.json", "assembled/evidence-index.json"]))
        state.atomic_json(attempt / "result.json", envelope)
        state.atomic_json(base / "accepted.json", {
            "schema": "appsec-review/accepted-worker-result/1.0", "status": "OK",
            "run_id": self.run_id, "job": cc.UPSTREAM_JOB, "attempt_id": "assembly-1",
            "fingerprint": fingerprint, "envelope_path": "result.json",
            "envelope_sha256": state.file_hash(attempt / "result.json"), "hashes": {},
        })
        with patch.object(cc, "validate_document",
                          side_effect=ComponentCharacterizationTests.canonical_schema_stub):
            inputs = cc.current_inputs(self.run_id)
        staged = Path(inputs["evidence_root"])
        self.assertTrue((staged / cc.UPSTREAM_MANIFEST).is_file())
        self.assertTrue((staged / "assembled/evidence-index.json").is_file())
        self.assertEqual(inputs["evidence"]["terminal_instances_sha256"], "sha256:" + state.file_hash(terminal))
        self.assertFalse((staged / "status.json").exists())
        self.assertFalse((staged / "raw-tool-output.log").exists())

    def test_canonical_schema_bytes_bind_current_inputs_and_missing_schema_blocks(self):
        schema_root = self.owner / "schemas"
        schema_root.mkdir()
        (schema_root / "component-purpose-map.schema.json").write_bytes(
            (ROOT.parent / "schemas/component-purpose-map.schema.json").read_bytes())
        for name in cc.INTEL_MANIFEST_SCHEMAS:
            (schema_root / name).write_text('{"version":1}\n', encoding="utf-8")
        evidence = deepcopy(self.inputs["evidence"])
        with patch.object(cc, "SCHEMAS", schema_root), patch.object(
                cc, "_target", return_value=(self.target, {
                    "fingerprint": self.value["source_snapshot_sha256"].removeprefix("sha256:"),
                    "revision": None})), patch.object(
                cc, "_accepted_evidence", return_value=(self.evidence, evidence)), patch.object(
                cc, "_stage_evidence", return_value=self.evidence):
            first = cc.current_inputs(self.run_id)
            (schema_root / cc.INTEL_MANIFEST_SCHEMAS[0]).write_text(
                '{"version":2}\n', encoding="utf-8")
            second = cc.current_inputs(self.run_id)
        schema_key = "schemas/" + cc.INTEL_MANIFEST_SCHEMAS[0]
        self.assertNotEqual(first["code"][schema_key], second["code"][schema_key])
        self.assertNotEqual(state.digest(first), state.digest(second))

        missing = deepcopy({
            "schema": "appsec-review/intel-manifest/2.0", "run_id": self.run_id,
            "source_snapshot_sha256": self.value["source_snapshot_sha256"],
        })
        with patch.object(cc, "validate_document", side_effect=FileNotFoundError("absent")):
            errors, _ = cc._intel_manifest_errors(
                missing, run_id=self.run_id,
                source_snapshot_sha256=self.value["source_snapshot_sha256"],
                attempt=self.evidence, envelope_artifacts={})
        self.assertEqual(errors, [
            "canonical intel-manifest schema is unavailable; F03 remains blocked on F02"])
        (schema_root / cc.INTEL_MANIFEST_SCHEMAS[0]).unlink()
        with patch.object(cc, "SCHEMAS", schema_root):
            self.assertEqual(cc._code_hashes()[schema_key], cc.ABSENT_SCHEMA_SHA256)

    def test_common_lifecycle_publishes_and_reuses_valid_map(self):
        with patch.object(cc, "current_inputs", return_value=self.inputs), patch.object(
                cc, "_dispatch_persona", side_effect=self.dispatch) as dispatched:
            first = cc.run(self.run_id, "dagster-a")
            second = cc.run(self.run_id, "dagster-b")
        self.assertEqual(first["schema"], "appsec-review/accepted-worker-result/1.0")
        self.assertEqual(first["attempt_id"], second["attempt_id"])
        self.assertEqual(dispatched.call_count, 1)
        attempt = cc.root(self.run_id) / "attempts" / first["attempt_id"]
        self.assertEqual(state.read_json(attempt / cc.RESULT), self.value)

    def test_invalid_new_attempt_blocks_older_success(self):
        with patch.object(cc, "current_inputs", return_value=self.inputs), patch.object(
                cc, "_dispatch_persona", side_effect=self.dispatch):
            accepted = cc.run(self.run_id, "dagster-a")
        invalid = deepcopy(self.value)
        invalid["functional_components"][0]["path_patterns"] = ["no-such-dir/**"]
        with patch.object(cc, "current_inputs", return_value=self.inputs), patch.object(
                cc, "_dispatch_persona", return_value=(invalid, "# invalid\n", self.dispatch()[2])):
            with self.assertRaises(ValueError):
                cc.run(self.run_id, "dagster-b", force=True)
        pointer = state.read_json(cc.root(self.run_id) / "accepted.json")
        self.assertEqual(pointer["status"], "FAILED")
        self.assertNotEqual(pointer["attempt_id"], accepted["attempt_id"])

    def test_published_map_is_bound_to_exact_manifest_lineage(self):
        with patch.object(cc, "current_inputs", return_value=self.inputs), patch.object(
                cc, "_dispatch_persona", side_effect=self.dispatch):
            accepted = cc.run(self.run_id, "dagster-a")
        attempt = cc.root(self.run_id) / "attempts" / accepted["attempt_id"]
        value = state.read_json(attempt / cc.RESULT)
        value["evidence_manifest_lineage"]["generation_sha256"] = "sha256:" + "9" * 64
        state.atomic_json(attempt / cc.RESULT, value)
        with self.assertRaisesRegex(state.Blocked, "identity"):
            cc._validate_attempt(self.run_id, attempt, self.inputs)


class PatternAnchoring(unittest.TestCase):
    def test_patterns_are_anchored_at_the_root(self):
        from component_characterization import _matches, _location_path
        self.assertTrue(_matches("LICENSE", "LICENSE"))
        self.assertFalse(_matches("vendor/cJSON-1.7.18/LICENSE", "LICENSE"))
        self.assertTrue(_matches("vendor/cJSON-1.7.18/LICENSE", "**/LICENSE"))
        self.assertTrue(_matches("src/a/b.cpp", "src/**"))
        self.assertFalse(_matches("src/a/b.cpp", "src/*"))
        self.assertTrue(_matches("docs/x.md", "docs/*.md"))
        self.assertEqual(_location_path("src/main.cpp:23-61"), "src/main.cpp")
        self.assertEqual(_location_path("src/main.cpp:7"), "src/main.cpp")


class NormalizeLanesAndReferencesTest(unittest.TestCase):
    """B4: lane vocabulary and cross-reference lineage are derived by Python."""

    def test_lane_spellings_map_to_the_closed_vocabulary_and_unknowns_are_gaps(self) -> None:
        value = {"functional_components": [{"component_id": "a", "downstream_lanes": [
                     "04-asvs-masvs", "Native Memory", "deployment_hardening", "native-memory", "made-up-lane"]}],
                 "parallel_review_groups": [{"group_id": "g", "component_ids": ["a"], "downstream_lanes": ["ASVS-MASVS"]}],
                 "classification_gaps": []}
        cc._normalize_lanes(value)
        self.assertEqual(value["functional_components"][0]["downstream_lanes"],
                         ["04-asvs-masvs", "05-native-memory", "15-deployment-hardening"])
        self.assertEqual(value["parallel_review_groups"][0]["downstream_lanes"], ["04-asvs-masvs"])
        self.assertEqual([g["subject"] for g in value["classification_gaps"]], ["functional_components:a"])
        self.assertNotIn("made-up-lane", json.dumps(value["classification_gaps"][0]["reason"]))

    def test_a_lane_list_with_no_known_lane_is_left_alone(self) -> None:
        value = {"functional_components": [{"component_id": "a", "downstream_lanes": ["nope"]}], "classification_gaps": []}
        cc._normalize_lanes(value)
        self.assertEqual(value["functional_components"][0]["downstream_lanes"], ["nope"])
        self.assertEqual(value["classification_gaps"], [])

    def test_group_membership_is_derived_from_the_component_and_missing_groups_are_created(self) -> None:
        value = {"functional_components": [
                     {"component_id": "a", "parallel_review_group": "g1", "downstream_lanes": ["04-asvs-masvs"]},
                     {"component_id": "b", "parallel_review_group": "g1", "downstream_lanes": ["05-native-memory"]},
                     {"component_id": "c", "parallel_review_group": "g2", "downstream_lanes": ["04-asvs-masvs"]}],
                 "parallel_review_groups": [{"group_id": "g1", "component_ids": ["a", "ghost"], "downstream_lanes": ["x"], "rationale": "r"}],
                 "classification_gaps": []}
        cc._normalize_references(value)
        groups = {g["group_id"]: g for g in value["parallel_review_groups"]}
        self.assertEqual(groups["g1"]["component_ids"], ["a", "b"])
        self.assertEqual(groups["g2"]["component_ids"], ["c"])
        self.assertEqual(groups["g2"]["downstream_lanes"], ["04-asvs-masvs"])
        self.assertEqual([g["subject"] for g in value["classification_gaps"]], ["parallel_review_groups:g2"])

    def test_unresolved_trigger_and_unknown_ids_are_removed_and_recorded(self) -> None:
        value = {"functional_components": [{"component_id": "a"}],
                 "code_scope_classification": [{"scope_id": "s"}],
                 "rescope_triggers": [{"trigger_id": "t", "affected_scope_ids": ["s", "zz"], "affected_component_ids": ["a", "b"]}],
                 "unknowns": [{"unknown_id": "u", "affected_component_ids": ["b"]}],
                 "classification_gaps": []}
        cc._normalize_references(value)
        self.assertEqual(value["rescope_triggers"][0]["affected_scope_ids"], ["s"])
        self.assertEqual(value["rescope_triggers"][0]["affected_component_ids"], ["a"])
        self.assertEqual(value["unknowns"][0]["affected_component_ids"], [])
        self.assertEqual(len(value["classification_gaps"]), 3)

    def test_exact_duplicates_dropped_and_unknown_ownership_never_names_a_party(self) -> None:
        component = {"component_id": "a", "ownership": {"kind": "unknown", "responsible_party": "Someone"}}
        value = {"functional_components": [component, dict(component)], "classification_gaps": []}
        cc._normalize_references(value)
        self.assertEqual(len(value["functional_components"]), 1)
        self.assertIsNone(value["functional_components"][0]["ownership"]["responsible_party"])


class UnresolvedRelationshipTest(unittest.TestCase):
    def test_edge_to_a_non_component_becomes_a_gap(self) -> None:
        value = {"functional_components": [{"component_id": "a"}, {"component_id": "b"}],
                 "component_relationships": [
                     {"relationship_id": "a-calls-b", "relationship_type": "calls", "from_component_id": "a", "to_component_id": "b"},
                     {"relationship_id": "dup", "relationship_type": "calls", "from_component_id": "a", "to_component_id": "b"},
                     {"relationship_id": "a--writes-to--tmp-log", "relationship_type": "writes-to", "from_component_id": "a", "to_component_id": "tmp-log"}],
                 "classification_gaps": []}
        cc._drop_unresolved_relationships(value)
        self.assertEqual([r["relationship_id"] for r in value["component_relationships"]], ["a--calls--b"])
        self.assertEqual([g["subject"] for g in value["classification_gaps"]],
                         ["component_relationships:a--writes-to--tmp-log"])


class RepairAgainstTargetTest(unittest.TestCase):
    def test_orders_tags_drops_foreign_locations_and_gaps_unscoped_files(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "src").mkdir(); (root / "src/a.c").write_text("x"); (root / "flake.nix").write_text("x")
            value = {"tag_cloud": [{"tag": "t", "component_ids": ["b", "a", "a"]}],
                     "functional_components": [{"component_id": "a", "representative_locations": ["src/a.c:3", "docs/index.md"]}],
                     "code_scope_classification": [{"scope_id": "s", "path_patterns": ["src/**"]}],
                     "classification_gaps": []}
            cc._repair_against_target(value, root)
        self.assertEqual(value["tag_cloud"][0]["component_ids"], ["a", "b"])
        self.assertEqual(value["functional_components"][0]["representative_locations"], ["src/a.c:3"])
        self.assertEqual([g["subject"] for g in value["classification_gaps"]], ["scope:flake.nix"])


class NormalizeTagCloudTest(unittest.TestCase):
    def test_repeated_and_unordered_tags_are_merged_and_sorted(self) -> None:
        cite = {"path": "a.c", "line_range": "1-2"}
        value = {"tag_cloud": [
            {"tag": "parser", "weight": 10, "component_ids": ["b"], "confidence": "high", "evidence_citations": [cite]},
            {"tag": "io", "weight": 5, "component_ids": ["a"], "confidence": "medium", "evidence_citations": [cite]},
            {"tag": "parser", "weight": 30, "component_ids": ["a", "b"], "confidence": "low", "evidence_citations": [cite]}]}
        cc._normalize_tag_cloud(value)
        tags = [item["tag"] for item in value["tag_cloud"]]
        self.assertEqual(tags, ["io", "parser"])
        parser = value["tag_cloud"][1]
        self.assertEqual((parser["component_ids"], parser["weight"], parser["confidence"]), (["a", "b"], 30, "low"))
        self.assertEqual(parser["evidence_citations"], [cite])


class SecurityTagResolutionTest(unittest.TestCase):
    """candidate_security_tags is optional and non-binding: the model supplies cwe_id + rationale
    + evidence; Python resolves and overwrites cwe_name/cwe_catalog from the pinned CWE catalog, the
    same discipline claim_lifecycle_core._cwe_judgment already uses for 07/09/12 (it cannot know our
    catalog's exact identity string, and guessing the canonical name invites drift)."""

    def _component(self, **tag):
        return {"component_id": "x", "candidate_security_tags": [{
            "cwe_id": "CWE-79", "cwe_name": "placeholder", "cwe_catalog": "placeholder",
            "rationale": "innerHTML assignment from an unsanitized request parameter.",
            "evidence_citations": [], **tag}]}

    def test_a_real_cwe_id_is_resolved_and_its_name_and_catalog_are_overwritten(self):
        value = {"functional_components": [self._component()]}
        self.assertEqual(cc.security_tag_errors(value), [])
        cc._resolve_security_tags(value)
        tag = value["functional_components"][0]["candidate_security_tags"][0]
        self.assertEqual(tag["cwe_id"], "CWE-79")
        self.assertIn("Cross-site Scripting", tag["cwe_name"])
        self.assertNotEqual(tag["cwe_catalog"], "placeholder")
        self.assertTrue(tag["cwe_catalog"])  # Python's value, never the model's

    def test_an_unresolvable_cwe_id_is_reported_pre_repair_and_raises_if_not_fixed(self):
        value = {"functional_components": [self._component(cwe_id="CWE-999999")]}
        errors = cc.security_tag_errors(value)
        self.assertTrue(any("CWE-999999" in e and "does not resolve" in e for e in errors), errors)
        with self.assertRaises(ValueError):
            cc._resolve_security_tags(value)

    def test_absent_field_is_not_an_error(self):
        value = {"functional_components": [{"component_id": "x"}]}
        self.assertEqual(cc.security_tag_errors(value), [])
        cc._resolve_security_tags(value)  # must not raise when the optional field is simply absent


class RetypeCitationsTest(unittest.TestCase):
    def test_wrong_source_type_is_relabelled_by_where_the_file_exists(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            target, evidence = Path(folder) / "t", Path(folder) / "e"
            (target / "src").mkdir(parents=True); (evidence / "scan").mkdir(parents=True)
            (target / "src/a.c").write_text("int a;"); (evidence / "scan/out.json").write_text("{}")
            value = {"x": {"evidence_citations": [
                {"source_type": "tool_output", "path": "scan/out.json"},
                {"source_type": "tool_output", "path": "src/a.c"},
                {"source_type": "source_file", "path": "src/a.c"},
                {"source_type": "tool_output", "path": "missing.txt"}]}}
            cc._retype_citations(value, target, evidence)
            got = value["x"]["evidence_citations"]
            expected = cc.file_hash(evidence / "scan/out.json")
        self.assertEqual([c["source_type"] for c in got], ["upstream_lane", "source_file", "source_file", "tool_output"])
        self.assertEqual(got[0]["content_hash"], expected)
        self.assertNotIn("content_hash", got[3])


if __name__ == "__main__":
    unittest.main()


class EvidencePathResolutionTests(unittest.TestCase):
    """Run 20261001T064759Z-4a8586: 30 citations named outputs/<job>/<file> for evidence/<job>/<attempt>/<file>."""

    def test_job_and_file_resolve_to_the_unique_evidence_file(self):
        import component_characterization as cc
        with tempfile.TemporaryDirectory() as folder:
            target, evidence = Path(folder) / "target", Path(folder) / "upstream"
            target.mkdir()
            real = evidence / "evidence" / "02-dev-project-discovery" / "c5d29a91da674a1c855b884a506673e1"
            real.mkdir(parents=True)
            (real / "project-discovery-summary.md").write_text("# s\n")
            value = {"components": [{"citations": [
                {"source_type": "upstream_lane", "path": "outputs/02-dev-project-discovery/project-discovery-summary.md"},
                {"source_type": "upstream_lane", "path": "outputs/02-devops-project-discovery/project-discovery-summary.md"},
            ]}]}
            with unittest.mock.patch.object(cc, "_citations", lambda v: v["components"][0]["citations"]):
                cc._resolve_evidence_paths(value, target, evidence)
            first, second = value["components"][0]["citations"]
            self.assertEqual(first["path"],
                             "evidence/02-dev-project-discovery/c5d29a91da674a1c855b884a506673e1/project-discovery-summary.md")
            self.assertTrue(first["content_hash"])
            self.assertEqual(second["path"], "outputs/02-devops-project-discovery/project-discovery-summary.md")


class OrchestratorFillTest(unittest.TestCase):
    """Run 20261006T150309Z-fdd8d6: the model refused to invent 11 of 16 lineage hashes it could not read,
    so the reply failed the schema three rounds running. Python now binds those fields before the check."""

    def test_python_owned_fields_are_set_before_validation_and_the_model_is_told_to_omit_them(self):
        evidence = {key: "1" * 64 for key in ("manifest_sha256", "envelope_sha256", "pointer_sha256",
                                              "producers_sha256", "artifact_set_sha256")}
        evidence.update(attempt_id="intel-1", manifest_self_sha256="sha256:" + "2" * 64,
                        input_fingerprint="3" * 64, generation_sha256="sha256:" + "4" * 64,
                        graph_sha256="sha256:" + "5" * 64, terminal_manifest_sha256="sha256:" + "6" * 64,
                        terminal_instances_path="pools/x/terminal-instances.json",
                        terminal_instances_sha256="sha256:" + "7" * 64,
                        terminal_instances_manifest_sha256="sha256:" + "8" * 64)
        record = {"target_name": "hello", "source_revision": "abc", "source_snapshot_sha256": "sha256:" + "9" * 64,
                  "evidence": evidence}
        envelope = {"result": {"components": [], "evidence_manifest_lineage": {"invented": True}}}
        self.assertEqual(cc._orchestrator_fill(record)(envelope, "result"), [])
        value = envelope["result"]
        self.assertEqual(value["evidence_manifest_lineage"], cc._manifest_lineage(record))
        self.assertEqual((value["target"], value["source_revision"], value["source_snapshot_sha256"]),
                         ("hello", "abc", "sha256:" + "9" * 64))
        self.assertEqual(value["components"], [])
        # a reply with no JSON object is left for the normal schema rejection
        prose = {"result": "I could not produce the map"}
        cc._orchestrator_fill(record)(prose, "result")
        self.assertEqual(prose["result"], "I could not produce the map")
        for field in cc.ORCHESTRATOR_FIELDS:
            self.assertIn(field, cc.ORCHESTRATOR_INSTRUCTIONS)
