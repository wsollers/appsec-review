"""Focused happy-path tests for the isolated D09 source-SAST worker slice."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import source_sast as worker  # noqa: E402
from schema_validate import validate_document  # noqa: E402


class SourceSastTests(unittest.TestCase):
    IMAGE = {"image_id": "tool-semgrep", "digest": "sha256:" + "a" * 64}

    def test_request_is_offline_read_only_and_uses_hash_bound_rules_mount(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder, "target"); target.mkdir()
            inputs = {"target_path": str(target), "source_snapshot_sha256": "sha256:" + "b" * 64,
                      "image": self.IMAGE}
            with mock.patch.object(worker, "_permission", return_value={"requirement": {}, "grants": [], "decision": {}}):
                request = worker._request("run", "adapter", inputs)
        self.assertEqual(request["network"], {"mode": "none", "destinations": []})
        self.assertEqual(request["target_mounts"][0], {"host_path": str(target), "container_path": "/workspace"})
        self.assertEqual(request["target_mounts"][1]["container_path"], "/inputs/source-sast-rules")
        self.assertEqual(request["scratch_path"], "scratch")
        self.assertIn("/inputs/source-sast-rules/rules-v1.yml", request["argv"])
        self.assertNotIn("--config=auto", request["argv"])

    def test_language_requests_are_fixed_offline_and_schema_valid(self):
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder,"target"); target.mkdir()
            inputs={"target_path":str(target),"source_snapshot_sha256":"sha256:"+"b"*64}
            for tool in ("gosec","spotbugs","phpstan","psalm","phpcs"):
                spec=worker.language_adapters.TOOLS[tool]
                plan={"tool_id":tool,"status":"READY","executed":False,"image_id":"fixture-harmless",
                      "image_digest":"sha256:"+"a"*64,"argv":spec["argv"]}
                request=worker._language_request("run","attempt",inputs,plan)
                self.assertEqual(request["network"],{"mode":"none","destinations":[]})
                self.assertEqual(request["target_mounts"],[{"host_path":str(target),"container_path":"/workspace"}])
                self.assertEqual(request["argv"],spec["argv"])
                self.assertEqual(validate_document(request,"pinned-container-request.schema.json"),[])

    def test_normalization_discards_message_snippet_and_severity(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder).resolve()
            source = target / "src" / "greet.cpp"; source.parent.mkdir(); source.write_text("strcpy(a,b);\n")
            raw = {"results": [{"check_id": "inputs.source-sast-rules.appsec.c.strcpy", "path": "/workspace/src/greet.cpp",
                                "start": {"line": 1}, "end": {"line": 1},
                                "extra": {"message": "secret raw message", "lines": "strcpy(a,b)", "severity": "ERROR"}}]}
            result = worker.normalize_semgrep(raw, target=target, run_id="run", attempt_id="attempt",
                source_snapshot_sha256="sha256:" + "b" * 64, image=self.IMAGE)
        self.assertEqual(result["leads"][0]["category"], "unsafe-copy")
        encoded = json.dumps(result)
        self.assertNotIn("secret raw message", encoded)
        self.assertNotIn("strcpy(a,b)", encoded)
        self.assertNotIn("severity", encoded.lower())
        self.assertEqual(validate_document(result, "source-sast.schema.json"), [])

    def test_normalization_is_deterministic_and_sorted(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder).resolve()
            for name in ("a.cpp", "b.cpp"):
                (target / name).write_text("x\n")
            raw = {"results": [
                {"check_id": "appsec.c.memcpy", "path": "/workspace/b.cpp", "start": {"line": 1}, "end": {"line": 1}},
                {"check_id": "appsec.c.system", "path": "/workspace/a.cpp", "start": {"line": 1}, "end": {"line": 1}},
            ]}
            args = dict(target=target, run_id="run", attempt_id="attempt",
                        source_snapshot_sha256="sha256:" + "b" * 64, image=self.IMAGE)
            first = worker.normalize_semgrep(raw, **args)
            second = worker.normalize_semgrep(raw, **args)
        self.assertEqual(first, second)
        self.assertEqual([lead["path"] for lead in first["leads"]], ["a.cpp", "b.cpp"])

    def test_unknown_rule_and_path_escape_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder).resolve(); (target / "a.cpp").write_text("x\n")
            base = {"path": "/workspace/a.cpp", "start": {"line": 1}, "end": {"line": 1}}
            args = dict(target=target, run_id="run", attempt_id="attempt",
                        source_snapshot_sha256="sha256:" + "b" * 64, image=self.IMAGE)
            with self.assertRaises(RuntimeError):
                worker.normalize_semgrep({"results": [{**base, "check_id": "unknown"}]}, **args)
            with self.assertRaises(RuntimeError):
                worker.normalize_semgrep({"results": [{**base, "check_id": "appsec.c.memcpy", "path": "../a.cpp"}]}, **args)

    def test_contract_registry_records_are_explicitly_not_fully_qualified(self):
        template = json.loads((ROOT / "registry/job-templates/02-source-sast.json").read_text())
        contract = json.loads((ROOT / "registry/output-contracts/source-sast.json").read_text())
        self.assertTrue(template["implemented"])
        self.assertEqual(template["composition"]["output_contract_id"], contract["contract_id"])
        self.assertIn("qualification", contract["required_status_fields"])
        self.assertIn("implemented_not_qualified", (ROOT / "source_sast.py").read_text())


if __name__ == "__main__":
    unittest.main()
