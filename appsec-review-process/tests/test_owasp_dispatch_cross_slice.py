"""T10 across slices: the V06 redactor, the schema subset, the process layout, and a coordinator
that really dies (SIGKILL) and is resumed through C02's restart semantics."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from owasp_dispatch_support import (  # noqa: E402
    DispatchCase, Gated, HANG_SECONDS, MARKER, NoCandidate, Routed, ValidatorInvoker, od, refresh,
)
import evidence_redaction  # noqa: E402
import execution_state  # noqa: E402
import persona_invocation_support as b14  # noqa: E402
import pool_rendezvous as pr  # noqa: E402
import schema_validate  # noqa: E402

SCHEMAS = sorted(schema_validate.SCHEMAS_DIR.glob("owasp-dispatch-*.schema.json"))
SUBSET = {"$schema", "$id", "title", "description", "type", "required", "properties", "additionalProperties",
          "enum", "const", "pattern", "items", "minItems", "$ref"}


def names(node, found: set) -> set:
    if isinstance(node, dict):
        found.update(node)
        for value in node.values():
            names(value, found)
    elif isinstance(node, list):
        for value in node:
            names(value, found)
    return found


class Varied(DispatchCase):
    """One accepted attempt with every kind of cell: valid, failed, refused by T07, without a
    candidate, canceled, never launched and request-only; plus a BLOCKED attempt before it."""
    chapters = ("V1", "V2", "V3", "V5", "V6", "V7")
    dynamic_chapters = ("V4",)

    def varied(self) -> dict:
        def unsupported(candidate, package):
            candidate["fragment_results"][0]["proof_obligation_results"][0]["evidence_citations"] = []
            refresh(candidate)
        ordinals = [entry["ordinal"] for entry in self.handoff_set["handoffs"] if entry["handoff_mode"] == od.STATIC_MODE]
        invoker = Routed({ordinals[1]: b14.Raising(RuntimeError(MARKER)), ordinals[2]: ValidatorInvoker(unsupported),
                          ordinals[3]: NoCandidate(), ordinals[4]: Gated(on_start=self.cancel.set)})
        return self.dispatch(invoker, max_parallel=1)


class RedactionSurvivalTests(Varied):
    def publish(self, files: dict, name: str) -> None:
        source, published = self.base / (name + "-source"), self.base / (name + "-published")
        for relative, data in files.items():
            path = source.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        receipt = evidence_redaction.redact_tree(source, published, on_unhandled="refuse",
                                                 limits=evidence_redaction.DEFAULT_LIMITS)
        self.assertEqual(sorted((record["path"], record["disposition"]) for record in receipt["files"]),
                         sorted((relative, "unchanged") for relative in files))
        for relative, data in files.items():
            self.assertEqual(published.joinpath(*relative.split("/")).read_bytes(), data)

    def test_every_published_t10_document_survives_the_redactor_unchanged(self):
        pointer = self.varied()
        accounting = self.accounting(pointer)
        self.assertLessEqual({"valid_result", "failed", "invalid", "canceled", "skipped", "request_only"},
                             {cell["terminal_class"] for cell in accounting["cells"]})
        self.assertLessEqual({"validation_refused", "candidate_missing", "cell_state"},
                             {cell["not_assessed_reason"] for cell in accounting["cells"]})
        self.assertEqual(accounting["dispatch_outcome"], pr.POOL_CANCELED)
        self.publish(self.published_files(pointer), "accepted")
        self.assertEqual(self.verify(pointer), [])

    def test_a_blocked_attempt_s_documents_survive_too(self):
        self.request_path = self.write_request(handoffs={**self.request["handoffs"], "handoff_set_sha256": "0" * 64})
        with self.assertRaises(od.DispatchBlocked):
            self.dispatch()
        latest = json.loads((self.job_root / "latest.json").read_text("utf-8"))["attempt_id"]
        attempt = self.job_root / "attempts" / latest
        self.publish({path.relative_to(self.job_root).as_posix(): path.read_bytes() for path in (
            attempt / od.ATTEMPT_FILE, attempt / od.INPUTS_FILE, attempt / od.STATUS_FILE,
            self.job_root / "latest.json")}, "blocked")

    def test_no_t05_t06_t07_identifier_and_no_prefixed_hex_shape_is_published(self):
        pointer = self.varied()
        text = b"\n".join(self.published_files(pointer).values()).decode("utf-8")
        self.assertIsNone(re.search(r"[A-Za-z]-[0-9a-f]{16,}", text))
        upstream = set()
        for ordinal, entry in enumerate(self.handoff_set["handoffs"], 1):
            upstream |= {entry["handoff_id"], entry["batch_id"]}
            for fragment in self.handoff(ordinal)["assigned_fragments"]:
                upstream |= {fragment["fragment_id"], fragment["assignment_id"], fragment["target_id"]}
        upstream.add(self.result_pointer(1)["result_id"])
        self.assertGreater(len(upstream), 20)
        for value in sorted(upstream):
            self.assertNotIn(value, text)
        for path in self.published_files(pointer):
            self.assertIsNone(re.search(r"[A-Za-z]-[0-9a-f]{16,}", path))
        self.assertNotIn(MARKER, text)

    def test_no_property_name_is_secret_looking(self):
        pointer = self.varied()
        found: set = set()
        for data in self.published_files(pointer).values():
            names(json.loads(data), found)
        for path in SCHEMAS:
            schema = json.loads(path.read_text(encoding="utf-8"))
            names(schema, found)
        found |= set(names(json.loads((od.CONFIG_ROOT / "default-v1.json").read_text(encoding="utf-8")), set()))
        self.assertGreater(len(found), 80)
        for name in sorted(found):
            self.assertIsNone(evidence_redaction._KEYWORD_RE.search(name), name)
            self.assertNotIn("max_tokens", name)


class SchemaSubsetTests(unittest.TestCase):
    def walk(self, node, where: str):
        self.assertLessEqual(set(node), SUBSET, where)
        if "pattern" in node:
            self.assertTrue(node["pattern"].startswith("^") and node["pattern"].endswith("\\Z"), where)
        types = node.get("type")
        if types == "object" or (isinstance(types, list) and "object" in types):
            self.assertIs(node.get("additionalProperties"), False, where)
            self.assertEqual(sorted(node["required"]), sorted(node["properties"]), where)
        for name, child in node.get("properties", {}).items():
            self.walk(child, f"{where}.{name}")
        if "items" in node:
            self.walk(node["items"], where + "[]")
        if "$ref" in node:
            self.assertTrue((schema_validate.SCHEMAS_DIR / node["$ref"]).is_file(), where)

    def test_every_t10_schema_is_closed_fully_required_and_inside_the_validator_subset(self):
        self.assertEqual(len(SCHEMAS), 8)
        for path in SCHEMAS:
            self.walk(json.loads(path.read_text(encoding="utf-8")), path.name)

    def test_the_tracked_configuration_is_valid_and_disables_everything_as_json_false(self):
        config = json.loads((od.CONFIG_ROOT / "default-v1.json").read_text(encoding="utf-8"))
        self.assertEqual(schema_validate.validate_document(config, od.CONFIG_SCHEMA), [])
        for name in ("dynamic_execution", "manual_observation", "network_access"):
            self.assertIs(config[name], False)
        loaded, _ = od._load_config({"path": "appsec-review-process/config/owasp-dispatch/default-v1.json",
                                     "config_digest": execution_state.digest(config)})
        self.assertEqual(loaded, config)
        self.assertEqual(sorted(entry["handoff_class"] for entry in config["prohibited_claim_map"]),
                         sorted(__import__("owasp_validator_handoff").REQUIRED_PROHIBITED_CLAIMS))


class LayoutTests(unittest.TestCase):
    def test_files_are_located_through_the_module_root_never_through_a_repository_path(self):
        source = Path(od.__file__).read_text(encoding="utf-8")
        self.assertNotIn('"appsec-review-process"', source)
        self.assertNotIn("'appsec-review-process'", source)
        self.assertEqual(od.CONFIG_ROOT, od.ROOT / "config" / "owasp-dispatch")
        self.assertEqual(od.ROOT, Path(od.__file__).resolve().parent)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)

    def test_the_tracked_tree_is_never_written(self):
        source = Path(od.__file__).read_text(encoding="utf-8")
        for line in source.splitlines():
            if "atomic_bytes(" in line and "import" not in line:
                self.assertRegex(line, r"atomic_bytes\((base|attempt|path)\b", line)


@unittest.skipUnless(os.name == "posix", "SIGKILL")
class CoordinatorLossTests(DispatchCase):
    def start(self, block_at: int) -> subprocess.Popen:
        process = subprocess.Popen(self.coordinator_command(block_at), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.stderr.close)
        self.addCleanup(lambda: (process.poll() is None and process.kill(), process.wait(HANG_SECONDS)))
        line = process.stdout.readline()
        self.assertEqual(line.strip(), b"BLOCKED", process.stderr.read() if process.poll() is not None else b"")
        return process

    def test_a_killed_coordinator_is_resumed_in_its_own_attempt_and_the_lost_cell_is_not_assessed(self):
        process = self.start(2)
        with self.assertRaises(execution_state.Blocked):          # the first coordinator is alive: nothing runs twice
            self.dispatch()
        killed = json.loads((self.job_root / "latest.json").read_text("utf-8"))["attempt_id"]
        os.kill(process.pid, signal.SIGKILL)
        process.wait(HANG_SECONDS)
        self.assertFalse((self.job_root / "accepted.json").exists())
        invoker = Routed()
        pointer = self.dispatch(invoker, max_parallel=1)
        self.assertEqual(pointer["attempt_id"], killed)           # resumed, not re-dispatched
        self.assertEqual(sorted(path.name for path in (self.job_root / "attempts").iterdir()), [killed])
        self.assertEqual(invoker.invoked, [3])                    # only the cell nobody had started
        accounting = self.accounting(pointer)
        self.assertEqual([cell["state"] for cell in accounting["cells"]], [pr.SUCCEEDED, pr.CRASHED, pr.SUCCEEDED])
        self.assertEqual([cell["terminal_class"] for cell in accounting["cells"]],
                         ["valid_result", "failed", "valid_result"])
        self.assertEqual(accounting["dispatch_outcome"], pr.DEGRADED)
        self.assertEqual(self.verify(pointer), [])
        self.assertIs(self.dispatch(Routed())["reused"], False)   # a lost cell is retried, never reused

    def test_a_resume_under_other_inputs_is_a_new_attempt(self):
        process = self.start(1)
        killed = json.loads((self.job_root / "latest.json").read_text("utf-8"))["attempt_id"]
        os.kill(process.pid, signal.SIGKILL)
        process.wait(HANG_SECONDS)
        self.request_path = self.write_request(model=dict(b14.OTHER_MODEL))
        pointer = self.dispatch()
        self.assertNotEqual(pointer["attempt_id"], killed)
        status = json.loads((self.job_root / "attempts" / killed / od.STATUS_FILE).read_text("utf-8"))
        self.assertEqual(status["status"], "RUNNING")             # left as it died; never made to look current
        self.assertEqual(od.thaw(self.load(allowed_models=(b14.MODEL, b14.OTHER_MODEL)))["attempt_id"],
                         pointer["attempt_id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
