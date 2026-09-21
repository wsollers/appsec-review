"""Persona invocation adapter (B14): request pins, hostile text, independence, outcomes, verifier."""
from __future__ import annotations

from copy import deepcopy
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import persona_invocation as pi  # noqa: E402
import persona_invocation_support as support  # noqa: E402
from persona_invocation_support import MARKER, Rewriting, relist  # noqa: E402
from schema_validate import SCHEMAS_DIR, validate_document  # noqa: E402
from worker_adapters import PersonaInvocationAdapter, UnsupportedWorkerAdapter, WorkerAdapter, WorkerRequest  # noqa: E402

SCHEMA_FILES = ("persona-invocation-request.schema.json", "persona-invoker-output.schema.json",
                "persona-invocation-record.schema.json", "persona-invocation-result.schema.json",
                "persona-model-identity.schema.json", "persona-invocation-file.schema.json")
SUPPORTED_KEYWORDS = {"$schema", "$id", "title", "description", "type", "required", "properties",
                      "additionalProperties", "enum", "const", "pattern", "items", "minItems", "$ref"}
OTHER_SHA = "sha256:" + "1" * 64

with tempfile.TemporaryDirectory() as _probe:
    SYMLINKS = support.symlinks_supported(Path(_probe))


class Case(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.ws = support.Workspace(self.base)

    def rejected(self, request, pattern: str, runtime=None, **ids) -> str:
        """Refused before any file or any invoker call, without echoing the marker."""
        invoker = support.Recording()
        runtime = runtime or self.ws.runtime(invoker=invoker)
        with self.assertRaises(pi.PersonaRequestError) as caught:
            self.ws.run(request, runtime, **ids)
        self.assertFalse(hasattr(invoker, "package"), "the invoker was called")
        self.assertEqual(list(self.ws.attempt.iterdir()), [], "a rejected request left evidence behind")
        message = str(caught.exception)
        self.assertRegex(message, pattern)
        self.assertNotIn(MARKER, message)
        return message

    def log(self, name: str) -> Path:
        return self.ws.attempt / "logs" / "persona" / name

    def read(self, name: str) -> dict:
        return json.loads(self.log(name).read_text(encoding="utf-8"))

    def write_result(self, result: dict, rehash: bool) -> None:
        if rehash:
            result["result_sha256"] = pi.result_sha256(result)
        self.log(pi.RESULT_FILE).write_bytes(pi.canonical_bytes(result))

    def reseal(self, name: str, data: bytes) -> None:
        """Replaces one log file and correctly re-hashes it in the result."""
        self.log(name).write_bytes(data)
        result = self.read(pi.RESULT_FILE)
        for entry in result["files"]:
            if entry["path"] == name:
                entry.update(sha256=pi._bytes_sha(data), bytes=len(data))
        self.write_result(result, True)

    def assert_rejected(self, request, **over) -> list[str]:
        errors = self.ws.verify(request, **over)
        self.assertTrue(errors, "a tampered attempt verified")
        self.assertNotIn(MARKER, " ".join(errors))
        with self.assertRaises(pi.PersonaRequestError) as caught:
            pi.to_worker_envelope(self.ws.attempt, **self.ws.verifier_arguments(request, **over),
                                  input_fingerprint=OTHER_SHA, resume_command=None)
        self.assertNotIn(MARKER, str(caught.exception))
        return errors


# ---- schemas ---------------------------------------------------------------------------------------

class SchemaConventionTests(unittest.TestCase):
    def walk(self, node, name, trail="$"):
        if not isinstance(node, dict):
            return
        if "properties" in node or node.get("type") == "object" or (
                isinstance(node.get("type"), list) and "object" in node["type"]):
            self.assertIs(node.get("additionalProperties"), False, f"{name} {trail} is open")
            self.assertEqual(sorted(node["required"]), sorted(node["properties"]),
                             f"{name} {trail}: every declared property must be required")
        for key, value in node.items():
            if key == "properties":
                for prop, child in value.items():
                    self.assertIsNone(self.redactor_keyword(prop), f"{name} {trail}.{prop} is a secret-ish name")
                    self.walk(child, name, f"{trail}.{prop}")
                continue
            self.assertIn(key, SUPPORTED_KEYWORDS, f"{name} {trail}: unsupported keyword {key}")
            if key == "pattern":
                self.assertTrue(value.startswith("^") and value.endswith("\\Z"), f"{name} {trail}")
            if key == "$ref":
                self.assertTrue((SCHEMAS_DIR / value).is_file(), f"{name} {trail}: $ref sibling")
            if key == "items":
                self.walk(value, name, trail + "[]")

    @staticmethod
    def redactor_keyword(name: str):
        import evidence_redaction
        return evidence_redaction._KEYWORD_RE.search(name)

    def test_schemas_are_closed_required_and_inside_the_supported_subset(self):
        for name in SCHEMA_FILES:
            raw = (SCHEMAS_DIR / name).read_bytes()
            self.assertNotIn(b"\r", raw, name)
            self.walk(json.loads(raw.decode("utf-8")), name)

    def test_request_schema_has_no_property_for_text_a_default_or_an_absolute_path(self):
        schema = json.loads((SCHEMAS_DIR / SCHEMA_FILES[0]).read_text(encoding="utf-8"))
        names = set()

        def collect(node):
            if isinstance(node, dict):
                names.update(node.get("properties", {}))
                for value in node.values():
                    collect(value)
            elif isinstance(node, list):
                for value in node:
                    collect(value)
        collect(schema)
        for forbidden in ("prompt_text", "text", "instructions", "system", "default_model", "alias",
                          "permissions", "scope", "argv", "command", "absolute_path", "writable_roots"):
            self.assertNotIn(forbidden, names)

    def test_cause_outcome_and_role_enums_are_the_module_tables(self):
        result = json.loads((SCHEMAS_DIR / SCHEMA_FILES[3]).read_text(encoding="utf-8"))["properties"]
        self.assertEqual(set(result["cause"]["enum"]), set(pi.STATUS_BY_CAUSE))
        self.assertEqual(set(result["execution_status"]["enum"]), set(pi.STATUS_BY_CAUSE.values()))
        self.assertEqual(set(result["outcome"]["enum"]), {"returned", *pi.CAUSE_BY_OUTCOME})
        self.assertEqual(set(pi.SUMMARIES), set(pi.STATUS_BY_CAUSE))
        self.assertEqual(len(set(pi.SUMMARIES.values())), len(pi.SUMMARIES))
        self.assertEqual(set(result["invocation_role"]["enum"]), {"produce", *pi.REVIEW_ROLES})
        for cause in ("TIMEOUT", "CANCELED", "INVOKER_EXCEPTION", "INVOKER_UNAVAILABLE", "PERMISSION_DENIED",
                      "MALFORMED_RESULT", "PROHIBITED_CLAIM", "OUTPUT_ESCAPE", "BUDGET_EXCEEDED",
                      "SELF_VERIFICATION"):
            self.assertIn(cause, pi.STATUS_BY_CAUSE)


# ---- registry ----------------------------------------------------------------------------------------

class RegistryTests(Case):
    def copy_registry(self) -> Path:
        return support.copy_registry(self.base / "registry")

    def edit(self, registry: Path, directory: str, name: str, change) -> None:
        path = registry / directory / (name + ".json")
        record = json.loads(path.read_text(encoding="utf-8"))
        change(record)
        path.write_text(json.dumps(record), encoding="utf-8")

    def test_tracked_registry_passes_as_is_and_the_default_denied_set_is_pinned(self):
        self.assertEqual(pi.validate_persona_registry(pi.REGISTRY_DIR), [])
        # Role `evidence-indexer` allows only evidence_index; its profile's claim_limits.allowed
        # list does not carry it, so the intersection is empty: never invocable (reported gap).
        self.assertEqual(pi.not_invocable_templates(pi.REGISTRY_DIR), ["02-evidence-index"])

    def test_ceiling_is_the_role_narrowed_by_the_profile_and_the_baseline(self):
        limits = support.ceiling()
        self.assertEqual(limits["allowed"], ("candidate_followup", "coverage_gap", "dynamic_test_request"))
        for prohibited in (*pi.BASELINE_PROHIBITED, "control_verdict", "executive_go_no_go"):
            self.assertIn(prohibited, limits["prohibited"])
        self.assertFalse(set(limits["allowed"]) & set(limits["prohibited"]))
        role = {"allowed_outputs": ["a", "b", "c", "d"], "forbidden_outputs": ["x"]}
        profile = {"claim_limits": {"a": "allowed", "b": "allowed_with_caveat", "c": "follow_up_only",
                                    "d": "forbidden", "forbidden": ["y"]}}
        derived = pi.claim_ceiling(role, profile)
        self.assertEqual(derived["allowed"], ("a", "b"))
        self.assertTrue({"c", "d", "x", "y"} <= set(derived["prohibited"]))
        profile["claim_limits"]["allowed"] = ["b"]
        self.assertEqual(pi.claim_ceiling(role, profile)["allowed"], ("b",))

    def test_tool_ids_are_derived_from_the_exact_action_text(self):
        records = pi.load_composition(pi.REGISTRY_DIR, support.composition_block(), pi.SchemaStore())
        tools = pi.tool_ids(records["tooling_profile"])
        self.assertEqual(sorted(tools.values()), sorted(records["tooling_profile"]["allowed_actions"]))
        for tool in tools:
            self.assertRegex(tool, r"^act-[0-9a-f]{24}\Z")
        changed = deepcopy(records["tooling_profile"])
        changed["allowed_actions"][0] += " and anything else"
        self.assertNotEqual(set(pi.tool_ids(changed)), set(tools))

    def test_registry_defects_the_adapter_relies_on_are_reported(self):
        cases = {
            "role allows a claim class that no persona": ("roles", "standards-control-validator",
                                                          lambda r: r["allowed_outputs"].append("remediation_status")),
            "role allows and forbids": ("roles", "standards-control-validator",
                                        lambda r: r["forbidden_outputs"].append("coverage_gap")),
            "unique claim-class ids": ("roles", "standards-control-validator",
                                       lambda r: r["allowed_outputs"].append("Any finding " + MARKER)),
            "free text, not a closed word": ("tooling-profiles", "owasp-worklist-builder",
                                             lambda r: r["claim_limits"].update(applicability="allowed if " + MARKER)),
            "unique bounded single-line actions": ("tooling-profiles", "owasp-worklist-builder",
                                                   lambda r: r["allowed_actions"].append("run\nanything")),
            "invalid or misnamed": ("personas", "owasp-validator", lambda r: r.update(persona_id="someone-else")),
        }
        for pattern, (directory, name, change) in cases.items():
            with self.subTest(pattern=pattern):
                registry = self.copy_registry()
                self.addCleanup(shutil.rmtree, registry, True)
                self.edit(registry, directory, name, change)
                errors = pi.validate_persona_registry(registry)
                shutil.rmtree(registry)
                self.assertTrue(any(pattern in error for error in errors), errors)
                self.assertNotIn(MARKER, " ".join(errors))

    def test_a_persona_record_outside_any_template_is_still_validated(self):
        registry = self.copy_registry()
        (registry / "personas" / "stray.json").write_text(json.dumps({"persona_id": "stray"}), encoding="utf-8")
        self.assertIn("personas/stray: invalid, unreadable or misnamed", pi.validate_persona_registry(registry))
        self.assertEqual(pi.validate_persona_registry(self.base / "absent"), ["persona registry is missing or empty"])


# ---- request pins: each bound, each edited alone ----------------------------------------------------

class RequestPinTests(Case):
    def test_the_golden_request_is_accepted_and_every_top_level_property_is_required(self):
        golden = self.ws.request()
        self.assertEqual(pi.request_errors(golden, **support.IDS), [])
        for name in golden:
            with self.subTest(missing=name):
                edited = deepcopy(golden)
                del edited[name]
                self.rejected(edited, "closed schema|model identity is missing|unbounded context")
        edited = deepcopy(golden)
        edited["prompt_text"] = MARKER
        self.rejected(edited, "closed schema")

    def test_outer_prompt_is_pinned_by_path_size_and_hash_of_exact_bytes(self):
        for field, value in (("sha256", OTHER_SHA), ("bytes", 5), ("path", "prompts/other.md")):
            with self.subTest(field=field):
                edited = self.ws.request()
                edited["outer_prompt"][field] = value
                self.rejected(edited, "outer_prompt: (bytes on disk|does not exist)")
        request = self.ws.request()
        prompt = self.ws.prompts / "prompts" / "outer.md"
        prompt.write_bytes(prompt.read_bytes().replace(b"Assess", b"assess"))
        self.rejected(request, "outer_prompt: bytes on disk do not have the pinned size and sha256")

    def test_outer_prompt_is_located_beneath_the_runtime_prompt_root_only(self):
        self.assertEqual(pi.PROMPT_ROOT, pi.ROOT)
        for path in ("/etc/hostname", "../process/prompts/outer.md", "prompts/./outer.md", "prompts//outer.md",
                     "./prompts/outer.md", "prompts/outer.md/", "prompts/outer.md.", "prompts\\outer.md"):
            with self.subTest(path=path):
                edited = self.ws.request()
                edited["outer_prompt"]["path"] = path
                self.rejected(edited, "outer_prompt.path is not one normalized relative path|closed schema")
        self.rejected(self.ws.request(), "outer_prompt: does not exist",
                      self.ws.runtime(invoker=support.Recording(), prompt_root=self.ws.data))
        with self.assertRaisesRegex(pi.PersonaRequestError, "prompt_root must be an absolute"):
            self.ws.run(self.ws.request(), self.ws.runtime(prompt_root=Path("relative")))

    def test_every_composition_id_and_hash_is_bound_to_the_registry_and_the_template(self):
        golden = self.ws.request()
        for name in golden["persona"]:
            with self.subTest(field=name):
                edited = deepcopy(golden)
                edited["persona"][name] = OTHER_SHA if name.endswith("_sha256") else "no-such-record"
                self.rejected(edited, "persona\\.|record named by the request")
        swaps = {"persona": "developer-engineer", "role": "evidence-indexer", "domain": "intake-state",
                 "tooling_profile": "read-only-intake", "output_contract": "intake"}
        for name, other in swaps.items():
            with self.subTest(swapped=name):
                edited = deepcopy(golden)
                directory = next(d for n, d, _, _ in pi.COMPOSITION_KINDS if n == name)
                record = json.loads((pi.REGISTRY_DIR / directory / (other + ".json")).read_text(encoding="utf-8"))
                edited["persona"][name + "_id"], edited["persona"][name + "_sha256"] = other, pi._sha(record)
                self.rejected(edited, f"persona.{name}_id is not what the named job template composes")

    def test_a_registry_record_edited_after_the_request_was_built_is_refused(self):
        registry = support.copy_registry(self.base / "registry")
        request = self.ws.request()
        path = registry / "personas" / "owasp-validator.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        record["must_not"] = []
        path.write_text(json.dumps(record), encoding="utf-8")
        self.rejected(request, "persona.persona_sha256 is not the hash of the registered record",
                      self.ws.runtime(invoker=support.Recording(), registry_dir=registry))

    def test_an_uninvocable_composition_is_refused(self):
        request = self.ws.request(persona=support.composition_block("02-evidence-index"))
        self.rejected(request, "allows no claim class")

    def test_model_identity_is_required_exact_and_allow_listed(self):
        golden = self.ws.request()
        for part in golden["model"]:
            for value in (None, "", "DROP"):
                with self.subTest(part=part, value=value):
                    edited = deepcopy(golden)
                    if value == "DROP":
                        del edited["model"][part]
                    else:
                        edited["model"][part] = value
                    self.rejected(edited, "model identity is missing")
        for field, value in (("snapshot", "latest"), ("snapshot", "stable"), ("snapshot", "v-next"),
                             ("model_id", "fixture-model-latest"), ("snapshot", "2026-09-01-preview")):
            with self.subTest(alias=value):
                edited = deepcopy(golden)
                edited["model"][field] = value
                self.rejected(edited, "moving alias|no version digits")
        edited = deepcopy(golden)
        edited["model"]["snapshot"] = "Latest " + MARKER
        self.rejected(edited, "closed schema")
        for part in golden["model"]:
            with self.subTest(not_listed=part):
                edited = deepcopy(golden)
                edited["model"][part] = "other-9"
                self.rejected(edited, "model is not on the runtime's model allow-list")
        for models in ((), [support.MODEL], ({"provider": "p"},), ({**support.MODEL, "snapshot": "latest"},)):
            with self.subTest(models=models), self.assertRaisesRegex(pi.PersonaRequestError, "allowed_models"):
                self.ws.run(golden, self.ws.runtime(allowed_models=models))

    def test_the_invoker_is_pinned(self):
        self.rejected(self.ws.request(invoker_id="another-invoker"), "not the invoker the request pins")

        class Anonymous:
            def invoke(self, package, *, output_root, cancel): ...
        for invoker in (Anonymous(), object(), None):
            with self.subTest(invoker=invoker), self.assertRaisesRegex(pi.PersonaRequestError, "runtime.invoker"):
                self.ws.run(self.ws.request(), self.ws.runtime(invoker=invoker))

    def test_tools_are_derived_ids_from_the_profile_never_free_text(self):
        records = pi.load_composition(pi.REGISTRY_DIR, support.composition_block(), pi.SchemaStore())
        tools = sorted(pi.tool_ids(records["tooling_profile"]))
        budget = {**self.ws.request()["budget"], "tool_call_limit": 5}
        invoker = support.Recording()
        result = self.ws.run(self.ws.request(tools=tools[:2], budget=budget), self.ws.runtime(invoker=invoker))
        self.assertIsNone(result["cause"])
        self.assertEqual(sorted(invoker.package.tool_actions), tools[:2])
        for bad, pattern in (([records["tooling_profile"]["allowed_actions"][0]], "closed schema"),
                             (["shell " + MARKER], "closed schema"),
                             (["act-" + "0" * 24], "tools names an id the tooling profile does not derive"),
                             (tools[:2][::-1], "sorted, unique"), ([tools[0], tools[0]], "sorted, unique")):
            with self.subTest(tools=bad):
                shutil.rmtree(self.ws.attempt)
                self.ws.attempt.mkdir()
                self.rejected(self.ws.request(tools=bad, budget=budget), pattern)
        self.rejected(self.ws.request(tools=tools[:1]), "tool_call_limit must be zero exactly when no tool")
        self.rejected(self.ws.request(budget=budget), "tool_call_limit must be zero exactly when no tool")

    def test_every_budget_limit_is_required_and_bounded(self):
        golden = self.ws.request()
        for name, (low, high) in pi.BUDGET_BOUNDS.items():
            for value in ("DROP", None, 0, -1, high + 1, True, 1.5, "10"):
                if name == "tool_call_limit" and value == 0:
                    continue
                with self.subTest(limit=name, value=value):
                    edited = deepcopy(golden)
                    if value == "DROP":
                        del edited["budget"][name]
                    else:
                        edited["budget"][name] = value
                    self.rejected(edited, "unbounded context")
        edited = deepcopy(golden)
        edited["budget"]["unlimited"] = True
        self.rejected(edited, "closed schema")

    def test_an_input_set_larger_than_the_budget_is_refused_before_invocation(self):
        golden = self.ws.request()
        total = golden["outer_prompt"]["bytes"] + sum(e["bytes"] for e in golden["readable_inputs"])
        exact = deepcopy(golden)
        exact["budget"]["input_byte_limit"] = total
        self.assertIsNone(self.ws.run(exact)["cause"])
        shutil.rmtree(self.ws.attempt)
        self.ws.attempt.mkdir()
        edited = deepcopy(golden)
        edited["budget"]["input_byte_limit"] = total - 1
        self.rejected(edited, "unbounded context: the prompt and readable inputs exceed")
        lying = deepcopy(golden)       # a smaller declared size does not get a larger file in
        lying["readable_inputs"][0]["bytes"] = 1
        self.rejected(lying, r"readable_inputs\[0\]: bytes on disk")

    def test_readable_inputs_are_pinned_to_bytes_on_disk(self):
        for field, value, pattern in (("sha256", OTHER_SHA, "bytes on disk"), ("bytes", 3, "bytes on disk"),
                                      ("path", "evidence/absent.json", "does not exist"),
                                      ("root", "other-root", "root is not a declared readable root"),
                                      ("role", "instructions", "closed schema")):
            with self.subTest(field=field):
                edited = self.ws.request()
                edited["readable_inputs"][0][field] = value
                self.rejected(edited, pattern)
        request = self.ws.request()
        (self.ws.data / "evidence" / "source.json").write_bytes(b"{}")
        self.rejected(request, r"readable_inputs\[0\]: bytes on disk")
        self.rejected(self.ws.request(readable_inputs=[]), "closed schema")

    def test_two_spellings_of_one_input_are_never_both_accepted(self):
        golden = self.ws.request()
        first = golden["readable_inputs"][0]
        for path in ("evidence/./source.json", "evidence//source.json", "./evidence/source.json",
                     "evidence/../evidence/source.json", "/evidence/source.json", "evidence/source.json/",
                     "evidence /source.json", "evidence/source.json.", "evidence\\source.json",
                     str(self.ws.data / "evidence" / "source.json")):
            with self.subTest(path=path):
                edited = deepcopy(golden)
                edited["readable_inputs"].append({**first, "path": path})
                self.rejected(edited, "not one normalized relative path|closed schema")
        edited = deepcopy(golden)
        edited["readable_inputs"].append(dict(first))
        self.rejected(edited, r"readable_inputs\[2\] repeats an earlier input")
        upper = deepcopy(golden)
        upper["readable_inputs"].append({**first, "path": "Evidence/source.json"})
        self.rejected(upper, r"readable_inputs\[2\] repeats an earlier input")
        # One directory under two root names: identity is device+inode, not the string.
        twice = deepcopy(golden)
        twice["readable_inputs"].append({**first, "root": "alias-root"})
        runtime = self.ws.runtime(invoker=support.Recording(),
                                  readable_roots={"run-data": self.ws.data, "alias-root": self.ws.data})
        self.rejected(twice, r"readable_inputs\[2\]: is the same file as the prompt or an earlier input", runtime)
        prompt_again = deepcopy(golden)
        prompt_again["readable_inputs"].append({"root": "process", "role": "reference", "producer_request_sha256": None,
                                                **golden["outer_prompt"]})
        runtime = self.ws.runtime(invoker=support.Recording(),
                                  readable_roots={"run-data": self.ws.data, "process": self.ws.prompts})
        self.rejected(prompt_again, r"readable_inputs\[2\]: is the same file as the prompt", runtime)

    def test_a_host_that_reports_another_true_spelling_is_refused(self):
        """A case-insensitive host resolves `evidence/source.json` and `Evidence/Source.json` to
        one file. The name the host reports as real must be the name the request used."""
        from unittest import mock
        real = os.path.realpath

        def reported(path, **keywords):
            return real(path, **keywords).replace("source.json", "Source.json")
        request = self.ws.request()
        with mock.patch("os.path.realpath", side_effect=reported):
            self.rejected(request, r"readable_inputs\[0\]: is not the one real spelling of the file")

    def test_links_special_files_and_directories_are_not_inputs(self):
        source = self.ws.data / "evidence" / "source.json"
        hard = self.ws.data / "evidence" / "hard.json"
        os.link(source, hard)
        edited = self.ws.request()
        edited["readable_inputs"] = [self.ws.input("evidence/hard.json")]
        self.rejected(edited, "is a link, a hard-linked file, a directory or a special file")
        hard.unlink()
        folder = self.ws.request()
        folder["readable_inputs"][0]["path"] = "evidence"
        self.rejected(folder, "is a link, a hard-linked file, a directory or a special file")
        if not SYMLINKS:
            self.skipTest("this host cannot create symbolic links")
        outside = self.base / "outside.json"
        outside.write_bytes(source.read_bytes())
        (self.ws.data / "evidence" / "soft.json").symlink_to(outside)
        (self.ws.data / "linked").symlink_to(self.ws.data / "evidence")
        for path in ("evidence/soft.json", "linked/source.json"):
            with self.subTest(path=path):
                edited = self.ws.request()
                edited["readable_inputs"][0]["path"] = path
                self.rejected(edited, "leaves its root or crosses a link")
        linked_root = self.base / "data-link"
        linked_root.symlink_to(self.ws.data)
        self.rejected(self.ws.request(), "a readable root must be an absolute, existing, non-link directory",
                      self.ws.runtime(invoker=support.Recording(), readable_roots={"run-data": linked_root}))

    def test_an_attempt_never_reads_itself(self):
        own = self.ws.attempt / "status.json"
        own.write_bytes(b"{}")
        request = self.ws.request()
        request["readable_inputs"][0] = {"root": "attempt", **support.file_pin(own, "status.json"),
                                         "role": "evidence", "producer_request_sha256": None}
        runtime = self.ws.runtime(invoker=support.Recording(),
                                  readable_roots={"run-data": self.ws.data, "attempt": self.ws.attempt})
        with self.assertRaisesRegex(pi.PersonaRequestError, "is inside the attempt"):
            self.ws.run(request, runtime)
        via_parent = self.ws.request()
        via_parent["readable_inputs"][0] = {"root": "base", **support.file_pin(own, "attempt/status.json"),
                                            "role": "evidence", "producer_request_sha256": None}
        runtime = self.ws.runtime(invoker=support.Recording(), readable_roots={"base": self.base})
        with self.assertRaisesRegex(pi.PersonaRequestError, "is inside the attempt"):
            self.ws.run(via_parent, runtime)
        self.assertFalse(hasattr(runtime.invoker, "package"))

    def test_output_root_and_log_path_are_single_new_run_owned_and_disjoint(self):
        for field in ("output_root", "log_path"):
            for path in ("../outside", "/tmp/outside", "a/../b", "a//b", "./a", "a/.", "a/b/", "a\\b", "a /b", "a./b",
                         "out/" + MARKER + "*"):
                with self.subTest(field=field, path=path):
                    self.rejected(self.ws.request(**{field: path}),
                                  f"{field} is not one normalized relative path|closed schema")
        for out, log in (("same", "same"), ("out", "out/logs"), ("logs/out", "logs"), ("Out", "out/logs")):
            with self.subTest(out=out, log=log):
                self.rejected(self.ws.request(output_root=out, log_path=log), "must not be equal or contain")
        for existing in ("outputs/persona", "logs/persona"):
            with self.subTest(existing=existing):
                target = self.ws.attempt.joinpath(*existing.split("/"))
                target.mkdir(parents=True)
                with self.assertRaisesRegex(pi.PersonaRequestError, "must not exist: the adapter creates them"):
                    self.ws.run(self.ws.request())
                shutil.rmtree(self.ws.attempt)
                self.ws.attempt.mkdir()
        if SYMLINKS:
            elsewhere = self.base / "elsewhere"
            elsewhere.mkdir()
            (self.ws.attempt / "outputs").symlink_to(elsewhere)
            with self.assertRaisesRegex(pi.PersonaRequestError, "leaves the attempt or crosses a link"):
                self.ws.run(self.ws.request())
            self.assertEqual(list(elsewhere.iterdir()), [])

    def test_claim_classes_may_narrow_but_never_widen_the_registry_ceiling(self):
        limits = support.ceiling()
        narrowed = self.ws.request(allowed_claim_classes=[limits["allowed"][0]],
                                   prohibited_claim_classes=sorted({*limits["prohibited"], limits["allowed"][1]}))
        self.assertIsNone(self.ws.run(narrowed)["cause"])
        shutil.rmtree(self.ws.attempt)
        self.ws.attempt.mkdir()
        cases = (
            ({"allowed_claim_classes": sorted({*limits["allowed"], "control_verdict"}),
              "prohibited_claim_classes": sorted(set(limits["prohibited"]) - {"control_verdict"})}, "widens"),
            ({"allowed_claim_classes": sorted({*limits["allowed"], "verified_finding"})}, "both allowed and prohibited"),
            ({"allowed_claim_classes": sorted({*limits["allowed"], "invented_class"})}, "widens"),
            ({"prohibited_claim_classes": [c for c in limits["prohibited"] if c != "final_severity"]}, "drops a class"),
            ({"prohibited_claim_classes": sorted({*limits["prohibited"], "invented_class"})}, "outside the composition"),
            ({"allowed_claim_classes": []}, "closed schema"),
            ({"allowed_claim_classes": ["Anything " + MARKER]}, "closed schema"),
            ({"allowed_claim_classes": list(limits["allowed"])[::-1]}, "sorted and unique"),
        )
        for over, pattern in cases:
            with self.subTest(pattern=pattern):
                self.rejected(self.ws.request(**over), pattern)

    def test_request_identity_is_bound_to_the_worker_request_it_arrived_in(self):
        for field in support.IDS:
            with self.subTest(field=field):
                self.rejected(self.ws.request(), f"request.{field} is not the {field}", **{field: "another"})

    def test_attempt_root_must_be_a_real_absolute_directory(self):
        for root in (Path("relative"), self.base / "absent", self.ws.data / "evidence" / "source.json"):
            with self.subTest(root=root), self.assertRaisesRegex(pi.PersonaRequestError, "attempt_root must be"):
                pi.run_invocation(self.ws.runtime(), **support.IDS, attempt_root=root, request=self.ws.request())


# ---- no optional safety inputs -------------------------------------------------------------------------

class RequiredArgumentTests(Case):
    FUNCTIONS = (pi.request_errors, pi.resolve_request, pi.run_invocation, pi.verify_invocation_result,
                 pi.load_verified_result, pi.to_worker_envelope, pi.derive_output, pi.scan_output_tree,
                 pi._read_pinned, pi._gate, pi.write_invoker_output, pi.load_composition, pi.claim_ceiling,
                 pi.validate_persona_registry)

    def test_no_safety_function_has_a_defaulted_parameter(self):
        for function in self.FUNCTIONS:
            for name, parameter in inspect.signature(function).parameters.items():
                if function is pi.request_errors and name == "store":
                    continue       # a schema cache, not a safety input
                with self.subTest(function=function.__name__, parameter=name):
                    self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_omitting_any_runtime_field_or_argument_is_a_type_error(self):
        fields = self.ws.runtime_fields()
        for name in fields:
            with self.subTest(runtime_field=name), self.assertRaises(TypeError):
                pi.PersonaRuntime(**{key: value for key, value in fields.items() if key != name})
        request = self.ws.request()
        self.ws.run(request)
        arguments = self.ws.verifier_arguments(request)
        for name in arguments:
            with self.subTest(verifier_argument=name), self.assertRaises(TypeError):
                pi.verify_invocation_result(self.ws.attempt, **{k: v for k, v in arguments.items() if k != name})
        envelope = {**arguments, "input_fingerprint": OTHER_SHA, "resume_command": None}
        for name in envelope:
            with self.subTest(envelope_argument=name), self.assertRaises(TypeError):
                pi.to_worker_envelope(self.ws.attempt, **{k: v for k, v in envelope.items() if k != name})
        with self.assertRaises(TypeError):
            pi.run_invocation({"invoker": pi.FixtureInvoker()}, **support.IDS, attempt_root=self.ws.attempt,
                              request=request)

    def test_runtime_fields_are_validated_before_anything_else(self):
        cases = {"registry_dir": "registry", "prompt_root": "prompts", "readable_roots": {},
                 "source_snapshot_sha256": "a" * 64, "registry_ceiling": "none", "clock": NOW_STRING,
                 "cancel": False, "stop_grace_seconds": 61}
        for name, value in cases.items():
            with self.subTest(field=name), self.assertRaisesRegex(pi.PersonaRequestError, f"runtime.{name}"):
                self.ws.run({"not": "a request"}, self.ws.runtime(**{name: value}))
        for value in (-1, True, 1.5):
            with self.subTest(grace=value), self.assertRaisesRegex(pi.PersonaRequestError, "stop_grace_seconds"):
                self.ws.run(self.ws.request(), self.ws.runtime(stop_grace_seconds=value))
        with self.assertRaisesRegex(pi.PersonaRequestError, "runtime.clock must return"):
            self.ws.run(self.ws.request(), self.ws.runtime(clock=lambda: "yesterday " + MARKER))
        self.assertEqual(list(self.ws.attempt.iterdir()), [])


NOW_STRING = support.NOW


# ---- independence -----------------------------------------------------------------------------------------

class IndependenceTests(Case):
    def test_an_independent_reviewer_runs_for_every_reviewing_role(self):
        for role in pi.REVIEW_ROLES:
            with self.subTest(role=role):
                request = self.ws.reviewing(role)
                result = self.ws.run(request)
                self.assertIsNone(result["cause"])
                self.assertEqual(result["independence_rule"], pi.INDEPENDENCE_ID)
                self.assertEqual(list(result["verified_invocations"]), [request["producers"][0]["request_sha256"]])
                self.assertEqual(self.ws.verify(request), [])
                shutil.rmtree(self.ws.attempt)
                self.ws.attempt.mkdir()

    def test_each_independence_condition_is_enforced_alone(self):
        cases = (
            ({"persona_id": "owasp-validator"}, r"self-verification: producers\[0\] is the same persona"),
            ({"model": {**support.OTHER_MODEL, "family": support.MODEL["family"]}},
             r"self-verification: producers\[0\] is the same model family"),
            ({"model": deepcopy(support.MODEL)}, "same model family"),
            ({"job_id": support.JOB, "attempt_id": support.ATTEMPT}, r"self-verification: producers\[0\] is this attempt"),
            ({"model": {**support.OTHER_MODEL, "snapshot": "latest"}}, r"producers\[0\].model names a moving alias"),
        )
        for over, pattern in cases:
            with self.subTest(pattern=pattern):
                self.rejected(self.ws.reviewing(**over), pattern)

    def test_a_reviewer_must_name_and_read_every_producer_and_a_producer_names_none(self):
        golden = self.ws.reviewing()
        without = deepcopy(golden)
        without["producers"] = []
        self.rejected(without, "must name 1..64 producer invocations")
        unread = deepcopy(golden)
        unread["readable_inputs"] = unread["readable_inputs"][1:]
        self.rejected(unread, "every producer must be read")
        relabelled = deepcopy(golden)
        relabelled["readable_inputs"][0].update(role="evidence", producer_request_sha256=None)
        self.rejected(relabelled, "every producer must be read")
        undeclared = deepcopy(golden)
        undeclared["readable_inputs"][0]["producer_request_sha256"] = OTHER_SHA
        self.rejected(undeclared, "every producer output must name a declared producer")
        unnamed = deepcopy(golden)
        unnamed["readable_inputs"][0]["producer_request_sha256"] = None
        self.rejected(unnamed, "required exactly for producer output")
        twice = deepcopy(golden)
        twice["producers"].append(deepcopy(twice["producers"][0]))
        self.rejected(twice, "producers repeat a request hash")
        producing = deepcopy(golden)
        producing["invocation_role"] = "produce"
        self.rejected(producing, "a producing invocation cannot name producers or read producer output")

    def test_a_result_that_claims_to_verify_itself_fails_closed(self):
        def own(manifest, root, package):
            manifest["verified_invocations"] = [package.request_sha256]
        request = self.ws.reviewing()
        result = self.ws.run(request, self.ws.runtime(invoker=Rewriting(own)))
        self.assertEqual((result["execution_status"], result["cause"]), ("FAILED", "SELF_VERIFICATION"))
        self.assertEqual(self.ws.verify(request), [])
        shutil.rmtree(self.ws.attempt)
        self.ws.attempt.mkdir()

        def claims(manifest, root, package):
            manifest["verified_invocations"] = [OTHER_SHA]
        producing = self.ws.request()
        result = self.ws.run(producing, self.ws.runtime(invoker=Rewriting(claims)))
        self.assertEqual(result["cause"], "SELF_VERIFICATION")
        shutil.rmtree(self.ws.attempt)
        self.ws.attempt.mkdir()
        result = self.ws.run(request, self.ws.runtime(invoker=Rewriting(claims)))
        self.assertEqual(result["cause"], "UNDECLARED_CITATION")


# ---- outcomes ------------------------------------------------------------------------------------------------

def hostile_invokers() -> dict[str, tuple]:
    """cause -> (invoker, note). Each departs from the honest fixture in exactly one way."""
    def manifest_edit(change):
        def edit(manifest, root, package):
            return change(manifest, root, package)
        return Rewriting(edit)

    def escape(manifest, root, package):
        (root.parent.parent / "escaped.txt").write_text(MARKER, encoding="utf-8")

    def listed_escape(manifest, root, package):
        manifest["files"].append({"path": "../escaped.json", "sha256": OTHER_SHA, "bytes": 1})

    def extra_file(manifest, root, package):
        (root / "notes" / "unlisted.md").write_text("unlisted " + MARKER, encoding="utf-8")

    def missing_file(manifest, root, package):
        (root / "notes" / "fixture-note.json").unlink()
        (root / "notes" / "other.json").write_text("{}", encoding="utf-8")

    def not_utf8(manifest, root, package):
        (root / "notes" / "fixture-note.json").write_bytes(b"\xff\xfe\x00")
        relist(manifest, root)

    # Found in verification: the parser keeps the last of two equal keys, so the claim check never
    # saw the first value; and a published path is text that the check did not read at all.
    def shadowed_key(manifest, root, package):
        (root / "notes" / "shadowed.json").write_bytes(
            b'{"note": "this issue is exploitable, critical severity", "note": "benign"}')
        relist(manifest, root)

    def nested_shadowed_key(manifest, root, package):
        (root / "notes" / "shadowed.json").write_bytes(
            b'{"outer": [{"note": "severity: high", "note": "benign"}]}')
        relist(manifest, root)

    def assertion_in_file_name(manifest, root, package):
        (root / "notes" / "critical-severity_exploitable.md").write_text("benign\n", encoding="utf-8")
        relist(manifest, root)

    def assertion_in_directory_name(manifest, root, package):
        (root / "is exploitable").mkdir()
        (root / "is exploitable" / "note.md").write_text("benign\n", encoding="utf-8")
        relist(manifest, root)

    def binary_suffix(manifest, root, package):
        (root / "notes" / "payload.bin").write_bytes(b"MZ")
        relist(manifest, root)

    def deeply_nested(manifest, root, package):
        (root / "notes" / "fixture-note.json").write_bytes(b"[" * 200000 + b"]" * 200000)
        relist(manifest, root)

    def oversized_manifest(manifest, root, package):
        manifest["limitations"] = ["x" * 1990] * 540

    def too_many(manifest, root, package):
        for index in range(12):
            (root / f"extra-{index:02d}.txt").write_text("x", encoding="utf-8")
        relist(manifest, root)

    def too_big(manifest, root, package):
        (root / "big.txt").write_text("x" * 70000, encoding="utf-8")
        relist(manifest, root)

    def way_too_big(manifest, root, package):
        (root / "huge.txt").write_bytes(b"x" * (65536 + pi.MAX_MANIFEST_BYTES + 1))

    def prohibited_text(manifest, root, package):
        manifest["claims"][0]["statement"] = "This is a critical severity issue and it is exploitable."

    def prohibited_file(manifest, root, package):
        (root / "summary.md").write_text("# Summary\n\nThe vulnerability is confirmed.\n", encoding="utf-8")
        relist(manifest, root)

    def set_at(*keys, value):
        def change(manifest, root, package):
            node = manifest
            for key in keys[:-1]:
                node = node[key]
            node[keys[-1]] = value
        return change

    def cite(**over):
        def change(manifest, root, package):
            manifest["claims"][0]["citations"][0].update(over)
        return change

    def link(manifest, root, package):
        (root / "notes" / "link.json").symlink_to(root / "notes" / "fixture-note.json")

    cases = {
        "OUTPUT_ESCAPE": [escape, listed_escape,
                          lambda m, r, p: (r / "empty").mkdir(),
                          lambda m, r, p: os.link(r / "notes" / "fixture-note.json", r / "notes" / "twin.json"),
                          lambda m, r, p: (r / "notes" / "bad name*.json").write_text("{}", encoding="utf-8")],
        "MALFORMED_RESULT": [extra_file, missing_file, not_utf8, binary_suffix, oversized_manifest, deeply_nested,
                             shadowed_key, nested_shadowed_key,
                             lambda m, r, p: b"[" * 200000 + b"]" * 200000,
                             lambda m, r, p: b"{not json " + MARKER.encode(),
                             lambda m, r, p: b"\xff\xfe",
                             lambda m, r, p: {**m, "note": MARKER},
                             lambda m, r, p: {k: v for k, v in m.items() if k != "usage"},
                             set_at("files", 0, "sha256", value=OTHER_SHA),
                             set_at("files", 0, "bytes", value=1),
                             set_at("usage", "input_bytes", value=1),
                             set_at("usage", "output_bytes", value=1),
                             set_at("usage", "output_units", value=-1),
                             set_at("claims", 0, "file", value="notes/absent.json"),
                             set_at("claims", 0, "statement", value="line one\nline two"),
                             lambda m, r, p: m["claims"].append(deepcopy(m["claims"][0]))],
        "IDENTITY_MISMATCH": [set_at("request_sha256", value=OTHER_SHA), set_at("invoker_id", value="other-invoker"),
                              set_at("persona_id", value="developer-engineer"),
                              set_at("persona_sha256", value=OTHER_SHA),
                              set_at("model", value=deepcopy(support.OTHER_MODEL)),
                              set_at("model", "snapshot", value="2026-09-02")],
        "BUDGET_EXCEEDED": [too_many, too_big, way_too_big, set_at("usage", "input_units", value=20001),
                            set_at("usage", "output_units", value=20001)],
        "UNDECLARED_TOOL": [lambda m, r, p: m["tool_calls"].append({"tool_id": "act-" + "0" * 24, "calls": 1})],
        "PROHIBITED_CLAIM": [set_at("claims", 0, "claim_class", value="verified_finding"),
                             set_at("claims", 0, "claim_class", value="control_verdict"),
                             set_at("claims", 0, "claim_class", value="invented_class"),
                             prohibited_text, prohibited_file, assertion_in_file_name,
                             assertion_in_directory_name,
                             set_at("limitations", value=["The system is fully compliant."])],
        "UNDECLARED_CITATION": [cite(path="evidence/unlisted.json"), cite(sha256=OTHER_SHA), cite(root="other-root"),
                                lambda m, r, p: m["injection_suspected"].append(
                                    {"root": "run-data", "path": "secrets/env", "sha256": OTHER_SHA, "locator": "x"})],
    }
    if SYMLINKS:
        cases["OUTPUT_ESCAPE"].append(link)
    return {cause: [manifest_edit(change) for change in changes] for cause, changes in cases.items()}


class OutcomeTests(Case):
    def fresh(self):
        shutil.rmtree(self.ws.attempt)
        self.ws.attempt.mkdir()
        outside = self.base / "attempt-escape"
        if outside.exists():
            outside.unlink()

    def check(self, request, result, cause, status):
        self.assertEqual((result["execution_status"], result["cause"]), (status, cause))
        if cause is not None:
            self.assertEqual((list(result["outputs"]), result["usage"], result["output_manifest_sha256"]),
                             ([], None, None), "a failed invocation exposed output")
        self.assertEqual(self.ws.verify(request), [], "an honest adapter record must verify from disk")
        envelope = pi.to_worker_envelope(self.ws.attempt, **self.ws.verifier_arguments(request),
                                         input_fingerprint=OTHER_SHA, resume_command="resume " + support.JOB)
        self.assertEqual((envelope["worker_kind"], envelope["acceptance_status"], envelope["execution_status"],
                          envelope["cause"], envelope["summary"]),
                         ("persona", "NOT_ACCEPTED", status, cause, pi.SUMMARIES[cause]))
        self.assertEqual(envelope["retry"]["allowed"], cause is not None)
        self.assertNotIn(MARKER, json.dumps(pi.thaw(result)) + json.dumps(envelope))
        return envelope

    def test_success_lists_every_output_and_maps_to_a_not_accepted_persona_envelope(self):
        request = self.ws.request()
        result = self.ws.run(request)
        envelope = self.check(request, result, None, "OK")
        self.assertEqual([entry["path"] for entry in result["outputs"]],
                         [pi.MANIFEST_FILE, "notes/fixture-note.json"])
        self.assertEqual(sorted(a["path"] for a in envelope["artifacts"]),
                         ["logs/persona/invocation-result.json", "logs/persona/invocation.json",
                          "logs/persona/request.json", "outputs/persona/invoker-output.json",
                          "outputs/persona/notes/fixture-note.json"])
        self.assertEqual(envelope["output_contract"], request["persona"]["output_contract_id"])
        self.assertEqual(result["input_bytes"], result["usage"]["input_bytes"])
        self.assertEqual(sorted(p.name for p in self.ws.attempt.iterdir()), ["logs", "outputs"])

    def test_every_hostile_invoker_has_its_distinct_failed_cause_and_never_a_success(self):
        for cause, invokers in hostile_invokers().items():
            for index, invoker in enumerate(invokers):
                with self.subTest(cause=cause, variant=index):
                    self.fresh()
                    request = self.ws.request()
                    result = self.ws.run(request, self.ws.runtime(invoker=invoker))
                    envelope = self.check(request, result, cause, "FAILED")
                    self.assertFalse(any(a["path"].startswith("outputs/") for a in envelope["artifacts"]))

    def test_an_invoker_that_edits_the_adapters_own_log_fails_and_the_attempt_never_verifies(self):
        def edit_request_copy(manifest, root, package):
            path = root.parent.parent / "logs" / "persona" / pi.REQUEST_FILE
            path.write_bytes(path.read_bytes() + b" ")
        request = self.ws.request()
        result = self.ws.run(request, self.ws.runtime(invoker=Rewriting(edit_request_copy)))
        self.assertEqual((result["execution_status"], result["cause"]), ("FAILED", "OUTPUT_ESCAPE"))
        self.assertIn("request.json is not the expected request", self.ws.verify(request))

    def test_an_invoker_that_edits_a_readable_input_fails_closed(self):
        def edit_evidence(manifest, root, package):
            (self.ws.data / "evidence" / "notes.md").write_bytes(b"rewritten by the invoker " + MARKER.encode())
        request = self.ws.request()
        result = self.ws.run(request, self.ws.runtime(invoker=Rewriting(edit_evidence)))
        self.assertEqual((result["execution_status"], result["cause"]), ("FAILED", "OUTPUT_ESCAPE"))
        self.assertEqual(list(result["outputs"]), [])
        self.assertTrue(self.read(pi.RECORD_FILE)["inputs_changed"])
        self.assertNotIn(MARKER, " ".join(self.ws.verify(request)))

    def test_an_invoker_that_echoes_injected_text_cannot_put_it_in_an_adapter_record(self):
        def echo(manifest, root, package):
            text = package.inputs[1].data.decode("utf-8").replace("\n", " ").strip()
            manifest["claims"][0]["statement"] = text[:1500]
            manifest["limitations"] = [package.prompt.decode("utf-8").splitlines()[-1][:1500]]
        request = self.ws.request()
        result = self.ws.run(request, self.ws.runtime(invoker=Rewriting(echo)))
        manifest = (self.ws.attempt / "outputs" / "persona" / pi.MANIFEST_FILE).read_bytes()
        self.assertIn(MARKER.encode(), manifest, "the hostile fixture did not echo")
        self.check(request, result, None, "OK")
        for name in (pi.REQUEST_FILE, pi.RECORD_FILE, pi.RESULT_FILE):
            self.assertNotIn(MARKER.encode(), self.log(name).read_bytes())
        for field in ("model", "output_root", "log_path", "permission_fingerprint_sha256"):
            self.assertEqual(pi.thaw(result[field]), request[field])
        self.assertEqual(list(result["claim_classes"]), request["allowed_claim_classes"][:1])

    def test_a_non_canonical_manifest_is_malformed(self):
        request = self.ws.request()
        result = self.ws.run(request, self.ws.runtime(invoker=Rewriting(lambda m, r, p: None, canonical=False)))
        self.check(request, result, "MALFORMED_RESULT", "FAILED")

    def test_an_invoker_that_writes_nothing_is_malformed_not_empty_success(self):
        class Silent:
            invoker_id = pi.FixtureInvoker.invoker_id

            def invoke(self, package, *, output_root, cancel):
                return {"execution_status": "OK", "note": MARKER}
        request = self.ws.request()
        self.check(request, self.ws.run(request, self.ws.runtime(invoker=Silent())), "MALFORMED_RESULT", "FAILED")

    def test_exception_unavailable_timeout_and_cancellation_are_distinct(self):
        request = self.ws.request()
        result = self.ws.run(request, self.ws.runtime(invoker=support.Raising(RuntimeError("boom " + MARKER))))
        self.check(request, result, "INVOKER_EXCEPTION", "FAILED")
        self.fresh()
        result = self.ws.run(request, self.ws.runtime(invoker=support.Raising(pi.InvokerUnavailable(MARKER))))
        self.check(request, result, "INVOKER_UNAVAILABLE", "BLOCKED")
        self.fresh()
        quick = self.ws.request()
        quick["budget"]["timeout_seconds"] = 1
        result = self.ws.run(quick, self.ws.runtime(invoker=support.Sleeping()))
        self.check(quick, result, "TIMEOUT", "FAILED")
        self.assertTrue(result["invoker_stopped"])
        self.fresh()
        stubborn = support.Sleeping(honor_cancel=False)
        result = self.ws.run(quick, self.ws.runtime(invoker=stubborn, stop_grace_seconds=0))
        stubborn.release.set()
        self.check(quick, result, "TIMEOUT", "FAILED")
        self.assertFalse(result["invoker_stopped"])
        self.fresh()
        cancel, started = threading.Event(), threading.Event()
        timer = threading.Thread(target=lambda: (started.wait(10), cancel.set()))
        timer.start()
        result = self.ws.run(request, self.ws.runtime(invoker=support.Sleeping(started), cancel=cancel))
        timer.join()
        self.check(request, result, "CANCELED", "CANCELED")
        self.fresh()
        recording = support.Recording()
        result = self.ws.run(request, self.ws.runtime(invoker=recording, cancel=cancel))
        self.check(request, result, "CANCELED", "CANCELED")
        self.assertFalse(hasattr(recording, "package"), "an already-canceled invocation still called the invoker")

    def test_returned_result_is_deeply_immutable(self):
        result = self.ws.run(self.ws.request())
        with self.assertRaises(TypeError):
            result["cause"] = "edited"
        with self.assertRaises(TypeError):
            result["model"]["snapshot"] = "edited"
        with self.assertRaises(TypeError):
            result["outputs"][0]["sha256"] = OTHER_SHA
        self.assertIsInstance(result["outputs"], tuple)

    def test_a_result_that_cannot_be_persisted_is_an_error_never_a_success(self):
        from unittest import mock
        original = pi.atomic_bytes

        def failing(path, data):
            if Path(path).name == pi.RESULT_FILE:
                raise OSError("disk full")
            original(path, data)
        with mock.patch.object(pi, "atomic_bytes", side_effect=failing), self.assertRaises(pi.PersonaExecutionError):
            self.ws.run(self.ws.request())
        self.assertTrue(self.ws.verify(self.ws.request()))


# ---- untrusted text is data ------------------------------------------------------------------------------------

class UntrustedTextTests(Case):
    def test_hostile_prompt_and_evidence_change_nothing_and_are_never_echoed(self):
        request = self.ws.request()
        self.assertIn(MARKER.encode(), (self.ws.prompts / "prompts" / "outer.md").read_bytes())
        invoker = support.Recording()
        result = self.ws.run(request, self.ws.runtime(invoker=invoker))
        self.assertIsNone(result["cause"])
        package = invoker.package
        self.assertEqual(pi.thaw(package.request), request)
        self.assertEqual(package.granted_capabilities, ())
        self.assertEqual(package.allowed_claim_classes, tuple(request["allowed_claim_classes"]))
        self.assertEqual(package.prohibited_claim_classes, tuple(request["prohibited_claim_classes"]))
        self.assertEqual(invoker.output_root, self.ws.attempt / "outputs" / "persona")
        self.assertEqual(dict(package.tool_actions), {})
        for name in (pi.REQUEST_FILE, pi.RECORD_FILE, pi.RESULT_FILE):
            self.assertNotIn(MARKER.encode(), self.log(name).read_bytes(), name)
        for path in (self.ws.attempt / "outputs").rglob("*"):
            if path.is_file():
                self.assertNotIn(MARKER.encode(), path.read_bytes(), path.name)
        for field in ("model", "output_root", "log_path", "invocation_role", "permission_fingerprint_sha256"):
            self.assertEqual(pi.thaw(result[field]), request[field])

    def test_the_package_is_frozen_verified_bytes_not_paths(self):
        invoker = support.Recording()
        request = self.ws.request()
        self.ws.run(request, self.ws.runtime(invoker=invoker))
        package = invoker.package
        self.assertEqual(package.prompt, (self.ws.prompts / "prompts" / "outer.md").read_bytes())
        self.assertEqual([(i.path, pi._bytes_sha(i.data)) for i in package.inputs],
                         [(e["path"], e["sha256"]) for e in request["readable_inputs"]])
        with self.assertRaises(Exception):
            package.prompt = b"edited"
        with self.assertRaises(TypeError):
            package.request["budget"]["timeout_seconds"] = 86400
        with self.assertRaises(TypeError):
            package.composition["role"]["allowed_outputs"] += ("verified_finding",)
        with self.assertRaises(TypeError):
            package.tool_actions["act-" + "0" * 24] = "anything"
        self.assertFalse(any(isinstance(value, (Path, str)) and str(self.base) in str(value)
                             for value in (package.prompt, *[i.path for i in package.inputs])))

    def test_hostile_values_in_a_request_never_reach_a_message(self):
        hostile = MARKER + " '; rm -rf / #"
        edits = [("run_id", hostile), ("invoker_id", hostile), ("output_root", hostile), ("log_path", hostile),
                 ("invocation_role", hostile), ("tools", [hostile]), ("allowed_claim_classes", [hostile]),
                 ("permission_fingerprint_sha256", hostile), (hostile, hostile)]
        for field, value in edits:
            with self.subTest(field=field if field != hostile else "extra property"):
                self.rejected(self.ws.request(**{field: value}), "closed schema")
        nested = self.ws.request()
        nested["readable_inputs"][0]["path"] = hostile
        nested["persona"]["persona_id"] = hostile
        nested["outer_prompt"]["path"] = hostile
        message = self.rejected(nested, "closed schema")
        self.assertIn("$.readable_inputs[0].path", message)
        for value in (None, [], "request " + MARKER, 7):
            with self.subTest(value=value):
                self.rejected(value, "request is not an object")


# ---- permission gate --------------------------------------------------------------------------------------------

class PermissionTests(Case):
    NETWORK = [("fixed-network-destination", {"scheme": "https", "host": "api.example.org", "port": 443})]

    def test_the_fingerprint_pin_is_bound_to_the_decision(self):
        self.rejected(self.ws.request(permission_fingerprint_sha256=OTHER_SHA), "permission_fingerprint_sha256 is not")
        forged = self.ws.request()
        forged["permission"]["decision"]["fingerprint_material"]["sha256"] = OTHER_SHA
        forged["permission_fingerprint_sha256"] = OTHER_SHA
        self.rejected(forged, "permission_fingerprint_sha256 is not")
        granted = self.ws.request(permission=support.permission(self.NETWORK))
        self.assertNotEqual(granted["permission_fingerprint_sha256"], self.ws.request()["permission_fingerprint_sha256"])
        swapped = deepcopy(granted)
        swapped["permission_fingerprint_sha256"] = self.ws.request()["permission_fingerprint_sha256"]
        self.rejected(swapped, "permission_fingerprint_sha256 is not")

    def test_wrong_party_and_wrong_state_decisions_block_before_the_invoker(self):
        cases = {
            "another job": support.permission(job_id="another-job"),
            "another run": support.permission(run_id="another-run"),
            "expired at the runtime clock": None,
            "denied": None,
        }
        for label in cases:
            with self.subTest(case=label):
                shutil.rmtree(self.ws.attempt)
                self.ws.attempt.mkdir()
                invoker = support.Recording()
                runtime = self.ws.runtime(invoker=invoker)
                if label == "expired at the runtime clock":
                    request = self.ws.request(permission=support.permission(self.NETWORK))
                    runtime = self.ws.runtime(invoker=invoker, clock=lambda: "2026-09-22T00:00:00Z")
                elif label == "denied":
                    block = support.permission(self.NETWORK)
                    block["grants"] = []
                    block["decision"] = support.pc.evaluate(block["requirement"], [], support.context())
                    request = self.ws.request(permission=block)
                else:
                    request = self.ws.request(permission=cases[label])
                result = self.ws.run(request, runtime)
                self.assertEqual((result["execution_status"], result["cause"], result["outcome"]),
                                 ("BLOCKED", "PERMISSION_DENIED", "not_invoked"))
                self.assertFalse(hasattr(invoker, "package"))
                self.assertFalse((self.ws.attempt / "outputs").exists())
                over = {"source_snapshot_sha256": support.SNAPSHOT}
                self.assertEqual(self.ws.verify(request, **over), [])

    def test_granted_capabilities_come_only_from_the_gate_and_arrive_frozen(self):
        invoker = support.Recording()
        request = self.ws.request(permission=support.permission(self.NETWORK))
        self.assertIsNone(self.ws.run(request, self.ws.runtime(invoker=invoker))["cause"])
        granted = invoker.package.granted_capabilities
        self.assertEqual([c["kind"] for c in granted], ["fixed-network-destination"])
        self.assertEqual(granted[0]["parameters"]["host"], "api.example.org")
        with self.assertRaises(TypeError):
            granted[0]["parameters"]["host"] = "evil.example"
        self.assertEqual(self.ws.verify(request), [])
        self.assertTrue(self.ws.verify(request, source_snapshot_sha256="sha256:" + "f" * 64))

    def test_a_denied_run_resealed_as_ok_and_an_ok_run_resealed_as_denied_are_rejected(self):
        request = self.ws.request(permission=support.permission(job_id="another-job"))
        self.ws.run(request)
        result = self.read(pi.RESULT_FILE)
        result.update(execution_status="OK", cause=None)
        self.write_result(result, True)
        self.assert_rejected(request)
        shutil.rmtree(self.ws.attempt)
        self.ws.attempt.mkdir()
        request = self.ws.request()
        self.ws.run(request)
        result = self.read(pi.RESULT_FILE)
        result.update(execution_status="BLOCKED", cause="PERMISSION_DENIED", **pi.no_facts())
        self.write_result(result, True)
        self.assert_rejected(request)


# ---- verifier -----------------------------------------------------------------------------------------------------

class VerifierTests(Case):
    def produce(self, request=None, **runtime):
        request = request or self.ws.request()
        result = self.ws.run(request, self.ws.runtime(**runtime))
        self.assertEqual(self.ws.verify(request), [])
        return request, result

    def manifest_path(self) -> Path:
        return self.ws.attempt / "outputs" / "persona" / pi.MANIFEST_FILE

    def test_editing_only_one_result_field_is_rejected_with_and_without_a_rehash(self):
        request, _ = self.produce()
        golden = self.read(pi.RESULT_FILE)
        edits = {
            "schema": "appsec-review/persona-invocation-result/2.0", "adapter": pi.ADAPTER_ID + "x",
            "independence_rule": pi.INDEPENDENCE_ID + "x", "run_id": "other-run", "job_id": "other-job",
            "attempt_id": "other-attempt", "request_sha256": OTHER_SHA, "package_sha256": OTHER_SHA,
            "invocation_role": "verify", "invoker_id": "other-invoker", "prompt_sha256": OTHER_SHA,
            "composition_sha256": OTHER_SHA, "model": deepcopy(support.OTHER_MODEL),
            "permission_fingerprint_sha256": OTHER_SHA, "readable_inputs_sha256": OTHER_SHA, "input_bytes": 1,
            "execution_status": "FAILED", "cause": "TIMEOUT", "outcome": "timed_out", "invoker_stopped": False,
            "started_at": "2026-09-19T00:00:00Z", "finished_at": "2026-09-25T00:00:00Z",
            "output_root": "elsewhere", "log_path": "logs/other", "output_manifest_sha256": OTHER_SHA,
            "outputs": golden["outputs"][:1],
            "usage": {**golden["usage"], "output_units": golden["usage"]["output_units"] + 1},
            "claim_classes": [], "claim_count": 9, "verified_invocations": [OTHER_SHA],
            "files": golden["files"][:1], "result_sha256": OTHER_SHA,
        }
        self.assertEqual(set(edits), set(golden), "every top-level result field must have an edit")
        for field, value in edits.items():
            for rehash in (False, True):
                with self.subTest(field=field, rehash=rehash):
                    edited = deepcopy(golden)
                    edited[field] = value
                    self.write_result(edited, rehash and field != "result_sha256")
                    self.assert_rejected(request)
        nested = [
            lambda r: r["outputs"][1].__setitem__("sha256", OTHER_SHA),
            lambda r: r["outputs"][1].__setitem__("bytes", 1),
            lambda r: r["outputs"][1].__setitem__("path", "notes/other.json"),
            lambda r: r["outputs"].reverse(),
            lambda r: r["files"][0].__setitem__("sha256", OTHER_SHA),
            lambda r: r["files"].reverse(),
            lambda r: r["usage"].__setitem__("input_bytes", 1),
            lambda r: r["model"].__setitem__("snapshot", "2026-09-02"),
            lambda r: r.__setitem__("claim_classes", ["verified_finding"]),
            lambda r: r.__setitem__("note", MARKER),
            lambda r: r.__setitem__("cause", MARKER),
        ]
        for index, edit in enumerate(nested):
            with self.subTest(nested=index):
                edited = deepcopy(golden)
                edit(edited)
                self.write_result(edited, True)
                self.assert_rejected(request)
        self.write_result(deepcopy(golden), False)
        self.assertEqual(self.ws.verify(request), [])

    def test_every_invocation_record_field_is_cross_checked_even_when_correctly_resealed(self):
        request, _ = self.produce()
        golden = self.read(pi.RECORD_FILE)
        edits = {
            "schema": "appsec-review/persona-invocation-record/2.0", "adapter": pi.ADAPTER_ID + "x",
            "request_sha256": OTHER_SHA, "package_sha256": OTHER_SHA, "invoker_id": "other-invoker",
            "outcome": "raised", "invoker_stopped": False, "timeout_seconds": 86400,
            "started_at": "2026-09-19T00:00:00Z", "finished_at": "2026-09-25T00:00:00Z",
            "output_tree_state": "irregular", "output_tree": golden["output_tree"][:1],
            "attempt_changed_outside_output_root": True, "inputs_changed": True,
        }
        self.assertEqual(set(edits), set(golden), "every top-level record field must have an edit")
        original = self.log(pi.RECORD_FILE).read_bytes()
        for field, value in edits.items():
            with self.subTest(field=field):
                self.reseal(pi.RECORD_FILE, pi.canonical_bytes({**golden, field: value}))
                self.assert_rejected(request)
        with self.subTest(extra=True):
            self.reseal(pi.RECORD_FILE, pi.canonical_bytes({**golden, "note": MARKER}))
            self.assert_rejected(request)
        self.reseal(pi.RECORD_FILE, original)
        self.assertEqual(self.ws.verify(request), [])

    def test_every_manifest_field_edit_is_rejected_even_when_the_result_is_correctly_resealed(self):
        """A dishonest producer edits the invoker manifest and reseals every hash the result
        carries. The adapter's own scan in invocation.json is the second projection."""
        request, _ = self.produce()
        golden = json.loads(self.manifest_path().read_text(encoding="utf-8"))
        original = self.manifest_path().read_bytes()
        edits = {
            "schema": "appsec-review/persona-invoker-output/2.0", "request_sha256": OTHER_SHA,
            "invoker_id": "other-invoker", "persona_id": "developer-engineer", "persona_sha256": OTHER_SHA,
            "model": deepcopy(support.OTHER_MODEL),
            "usage": {**golden["usage"], "output_units": golden["usage"]["output_units"] + 1},
            "tool_calls": [{"tool_id": "act-" + "0" * 24, "calls": 1}], "files": [],
            "claims": [], "verified_invocations": [OTHER_SHA],
            "injection_suspected": deepcopy(golden["claims"][0]["citations"]),
            "limitations": ["edited " + MARKER],
        }
        self.assertEqual(set(edits), set(golden), "every top-level manifest field must have an edit")
        for field, value in edits.items():
            with self.subTest(field=field):
                data = pi.canonical_bytes({**golden, field: value})
                self.manifest_path().write_bytes(data)
                result = self.read(pi.RESULT_FILE)
                result["output_manifest_sha256"] = pi._bytes_sha(data)
                result["outputs"][0].update(sha256=pi._bytes_sha(data), bytes=len(data))
                if field == "usage":
                    result["usage"] = value
                if field == "claims":
                    result.update(claim_classes=[], claim_count=0)
                self.write_result(result, True)
                self.assert_rejected(request)
        self.manifest_path().write_bytes(original)

    def test_a_failed_run_resealed_as_ok_and_forged_output_are_rejected(self):
        def prohibited(manifest, root, package):
            manifest["claims"][0]["claim_class"] = "verified_finding"
        request, result = self.produce(invoker=Rewriting(prohibited))
        self.assertEqual(result["cause"], "PROHIBITED_CLAIM")
        state, tree, contents = pi.scan_output_tree(self.ws.attempt / "outputs" / "persona", request["budget"])
        forged = self.read(pi.RESULT_FILE)
        forged.update(execution_status="OK", cause=None, outputs=tree,
                      output_manifest_sha256=pi._bytes_sha(contents[pi.MANIFEST_FILE]),
                      usage=json.loads(contents[pi.MANIFEST_FILE])["usage"],
                      claim_classes=["verified_finding"], claim_count=1)
        self.write_result(forged, True)
        self.assert_rejected(request)
        shutil.rmtree(self.ws.attempt)
        self.ws.attempt.mkdir()
        request, result = self.produce(invoker=support.Raising(RuntimeError("x")))
        honest = support.Workspace(self.base / "second")
        honest.run(honest.request())
        shutil.copytree(honest.attempt / "outputs" / "persona", self.ws.attempt / "outputs" / "persona",
                        dirs_exist_ok=True)
        forged = self.read(pi.RESULT_FILE)
        forged.update(execution_status="OK", cause=None, outcome="returned")
        self.write_result(forged, True)
        self.assert_rejected(request)

    def test_every_file_of_the_attempt_tampered_one_at_a_time_is_rejected_and_nothing_is_echoed(self):
        request, _ = self.produce()
        files = sorted(path for path in self.ws.attempt.rglob("*") if path.is_file())
        self.assertEqual([path.relative_to(self.ws.attempt).as_posix() for path in files],
                         ["logs/persona/invocation-result.json", "logs/persona/invocation.json",
                          "logs/persona/request.json", "outputs/persona/invoker-output.json",
                          "outputs/persona/notes/fixture-note.json"])
        for path in files:
            original = path.read_bytes()
            mutations = {"appended": original + MARKER.encode(), "prefixed": MARKER.encode() + original,
                         "emptied": b"", "one byte": bytes([original[0] ^ 1]) + original[1:],
                         "not utf-8": b"\xff" + original}
            for label, data in mutations.items():
                with self.subTest(file=path.name, mutation=label):
                    path.write_bytes(data)
                    self.assert_rejected(request)
            with self.subTest(file=path.name, mutation="deleted"):
                path.unlink()
                self.assert_rejected(request)
            if SYMLINKS:
                with self.subTest(file=path.name, mutation="replaced by a link to identical bytes"):
                    twin = self.base / ("twin-" + path.name)
                    twin.write_bytes(original)
                    path.symlink_to(twin)
                    self.assert_rejected(request)
                    path.unlink()
            with self.subTest(file=path.name, mutation="hard link to identical bytes"):
                twin = self.base / ("hard-" + path.name)
                twin.write_bytes(original)
                os.link(twin, path)
                self.assert_rejected(request)
                path.unlink()
                twin.unlink()
            path.write_bytes(original)
            self.assertEqual(self.ws.verify(request), [])
        for folder in (self.ws.attempt / "logs" / "persona", self.ws.attempt / "outputs" / "persona"):
            with self.subTest(folder=folder.name, mutation="extra file"):
                (folder / "extra.json").write_text(json.dumps({"note": MARKER}), encoding="utf-8")
                self.assert_rejected(request)
                (folder / "extra.json").unlink()
            with self.subTest(folder=folder.name, mutation="extra directory"):
                (folder / "sub").mkdir()
                self.assert_rejected(request)
                (folder / "sub").rmdir()
        with self.subTest(mutation="non-canonical but equal JSON"):
            self.log(pi.RESULT_FILE).write_text(json.dumps(self.read(pi.RESULT_FILE)), encoding="utf-8")
            self.assert_rejected(request)

    def test_one_failed_cause_relabelled_as_another_is_rejected_when_resealed(self):
        def prohibited(manifest, root, package):
            manifest["claims"][0]["claim_class"] = "verified_finding"
        request, result = self.produce(invoker=Rewriting(prohibited))
        self.assertEqual(result["cause"], "PROHIBITED_CLAIM")
        golden = self.read(pi.RESULT_FILE)
        for cause in pi.OUTPUT_CAUSES:
            if cause == "PROHIBITED_CLAIM":
                continue
            with self.subTest(relabelled=cause):
                self.write_result({**deepcopy(golden), "cause": cause}, True)
                self.assertIn("the cause is not what the output root, the manifest and the request derive",
                              self.assert_rejected(request))
        self.write_result(golden, True)
        self.assertEqual(self.ws.verify(request), [])

    def test_a_resealed_output_file_cannot_contradict_the_adapters_scan(self):
        request, _ = self.produce()
        note = self.ws.attempt / "outputs" / "persona" / "notes" / "fixture-note.json"
        note.write_bytes(pi.canonical_bytes({"forged": True}))
        manifest = json.loads(self.manifest_path().read_text(encoding="utf-8"))
        relist(manifest, self.manifest_path().parent)
        self.manifest_path().write_bytes(pi.canonical_bytes(manifest))
        state, tree, contents = pi.scan_output_tree(self.manifest_path().parent, request["budget"])
        result = self.read(pi.RESULT_FILE)
        result.update(outputs=tree, usage=manifest["usage"],
                      output_manifest_sha256=pi._bytes_sha(contents[pi.MANIFEST_FILE]))
        self.write_result(result, True)
        errors = self.assert_rejected(request)
        self.assertIn("the output root on disk is not the tree invocation.json recorded", errors)

    def test_the_wrong_party_the_wrong_expected_request_and_changed_inputs_are_rejected(self):
        request, _ = self.produce()
        for field in support.IDS:
            with self.subTest(wrong=field):
                self.assert_rejected(request, **{field: "another"})
        other = deepcopy(request)
        other["budget"]["timeout_seconds"] += 1
        self.assert_rejected(other)
        narrowed = deepcopy(request)
        narrowed["allowed_claim_classes"] = narrowed["allowed_claim_classes"][:1]
        narrowed["prohibited_claim_classes"] = sorted({*narrowed["prohibited_claim_classes"],
                                                       *request["allowed_claim_classes"][1:]})
        self.assert_rejected(narrowed)
        self.assert_rejected(request, allowed_models=(support.OTHER_MODEL,))
        self.assert_rejected(request, prompt_root=self.ws.data)
        self.assert_rejected(request, readable_roots={"run-data": self.ws.prompts})
        evidence = self.ws.data / "evidence" / "notes.md"
        original = evidence.read_bytes()
        evidence.write_bytes(original + b"later edit")
        errors = self.assert_rejected(request)
        self.assertRegex(errors[0], r"the expected request does not resolve: readable_inputs\[1\]")
        evidence.write_bytes(original)
        self.assertEqual(self.ws.verify(request), [])

    def test_impossible_outcome_shapes_are_rejected_even_when_resealed(self):
        request, _ = self.produce(invoker=support.Raising(RuntimeError("x")))
        golden_result, golden_record = self.read(pi.RESULT_FILE), self.read(pi.RECORD_FILE)
        for outcome, cause, status in (("timed_out", "TIMEOUT", "FAILED"), ("canceled", "CANCELED", "CANCELED"),
                                       ("unavailable", "INVOKER_UNAVAILABLE", "BLOCKED")):
            with self.subTest(consistent_relabel=outcome):
                # Relabelled in the result only; invocation.json still says what happened.
                self.reseal(pi.RECORD_FILE, pi.canonical_bytes(golden_record))
                result = deepcopy(golden_result)
                result.update(outcome=outcome, cause=cause, execution_status=status)
                result["files"] = self.read(pi.RESULT_FILE)["files"]
                self.write_result(result, True)
                self.assert_rejected(request)
        shapes = [
            dict(cause="TIMEOUT"), dict(execution_status="BLOCKED"), dict(outcome="not_invoked"),
            dict(cause="PERMISSION_DENIED", execution_status="BLOCKED", outcome="not_invoked"),
            dict(cause=None, execution_status="OK"),
        ]
        for shape in shapes:
            with self.subTest(shape=shape):
                self.reseal(pi.RECORD_FILE, pi.canonical_bytes(golden_record))
                result = deepcopy(golden_result)
                result.update(shape)
                result["files"] = self.read(pi.RESULT_FILE)["files"]
                self.write_result(result, True)
                self.assert_rejected(request)


# ---- adapter protocol -------------------------------------------------------------------------------------------

class AdapterTests(Case):
    def test_persona_adapter_runs_the_request_in_worker_inputs(self):
        adapter = PersonaInvocationAdapter(self.ws.runtime())
        self.assertIsInstance(adapter, WorkerAdapter)
        self.assertEqual(adapter.kind, "persona")
        request = self.ws.request()
        result = adapter.execute(WorkerRequest(support.RUN, support.JOB, support.ATTEMPT, self.ws.attempt,
                                               {"persona_request": request}))
        self.assertIsNone(result["cause"])
        self.assertEqual(self.ws.verify(request), [])

    def test_adapter_requires_a_runtime_a_persona_request_and_the_right_party(self):
        with self.assertRaises(TypeError):
            PersonaInvocationAdapter()
        with self.assertRaises(TypeError):
            PersonaInvocationAdapter({"invoker": pi.FixtureInvoker()})
        adapter = PersonaInvocationAdapter(self.ws.runtime())
        for inputs in ({}, {"container_request": {}}, None):
            with self.subTest(inputs=inputs), self.assertRaises(pi.PersonaRequestError):
                adapter.execute(WorkerRequest(support.RUN, support.JOB, support.ATTEMPT, self.ws.attempt, inputs))
        with self.assertRaisesRegex(pi.PersonaRequestError, "run_id is not the run_id"):
            adapter.execute(WorkerRequest("another-run", support.JOB, support.ATTEMPT, self.ws.attempt,
                                          {"persona_request": self.ws.request()}))

    def test_still_unimplemented_kinds_raise_before_work(self):
        worker_request = WorkerRequest(support.RUN, support.JOB, support.ATTEMPT, self.ws.attempt, {})
        for kind in ("pool_coordinator", "join_controller"):
            with self.subTest(kind=kind), self.assertRaises(NotImplementedError):
                UnsupportedWorkerAdapter(kind).execute(worker_request)

    def test_fingerprint_follows_the_request_and_the_capability_set_not_grant_timestamps(self):
        def material(request):
            resolved = pi.resolve_request(
                request, **support.IDS, attempt_root=self.ws.attempt,
                **{k: v for k, v in self.ws.verifier_arguments(request).items()
                   if k in ("registry_dir", "prompt_root", "readable_roots", "allowed_models")})
            return pi.fingerprint_material(resolved)["sha256"]
        base = material(self.ws.request())
        self.assertEqual(base, material(self.ws.request()))
        changed = self.ws.request()
        changed["budget"]["timeout_seconds"] += 1
        self.assertNotEqual(base, material(changed))
        network = PermissionTests.NETWORK
        first = material(self.ws.request(permission=support.permission(network)))
        reissued = support.permission(network)
        reissued["grants"][0].update(grant_id="grant-reissued", issued_at="2026-09-20T01:00:00Z")
        reissued["decision"] = support.pc.evaluate(reissued["requirement"], reissued["grants"], support.context())
        self.assertEqual(first, material(self.ws.request(permission=reissued)))
        self.assertNotEqual(first, base)


# ---- documentation ------------------------------------------------------------------------------------------------

class DocumentationTests(unittest.TestCase):
    DOC = ROOT.parent / "docs" / "persona-invocation-adapter.md"
    SECTIONS = ["Status", "Protocol", "Request pins", "Registry composition, tool ids and claim ceiling",
                "Untrusted text", "Independence and self-verification", "Invoker contract",
                "Outcomes", "Result and verification", "Worker-result envelope", "Limitations",
                "Integration follow-ups"]

    def test_document_sections_are_an_allow_list(self):
        text = self.DOC.read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"^## (.+)$", text, flags=re.M), self.SECTIONS)
        self.assertEqual(re.findall(r"^# (.+)$", text, flags=re.M), ["Persona invocation adapter"])

    def test_document_names_every_cause_limit_identity_and_baseline_class(self):
        text = self.DOC.read_text(encoding="utf-8")
        for needle in (*[c for c in pi.STATUS_BY_CAUSE if c], *pi.BUDGET_BOUNDS, *pi.BASELINE_PROHIBITED,
                       pi.ADAPTER_ID, pi.REQUEST_ID, pi.OUTPUT_ID, pi.RECORD_ID, pi.RESULT_ID,
                       pi.INDEPENDENCE_ID, pi.FINGERPRINT_ID, pi.MANIFEST_FILE, pi.RECORD_FILE, pi.RESULT_FILE,
                       "02-evidence-index", "PersonaInvoker"):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)
        for line in text.splitlines():
            self.assertLessEqual(len(line), 240, "free-text line is unbounded")
            self.assertNotRegex(line, r"[\x00-\x08\x0b-\x1f]")
        self.assertFalse(pi._asserts_prohibited([text], set(pi.BASELINE_PROHIBITED)),
                         "the document itself asserts a prohibited claim")


if __name__ == "__main__":
    unittest.main()
