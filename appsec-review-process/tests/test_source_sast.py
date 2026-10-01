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
import registry_paths

import source_sast as worker  # noqa: E402
import container_execution as ce  # noqa: E402
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
            registry={image_id:{"image_id":image_id,"digest":"sha256:"+"a"*64}
                      for image_id in worker.language_adapters.TOOL_IMAGES.values()}
            for plan in worker.language_adapters.build_plan(["go","java","php"],registry):
                tool=plan["tool_id"]
                request=worker._language_request("run","attempt",inputs,plan)
                self.assertEqual(request["network"],{"mode":"none","destinations":[]})
                expected=[{"host_path":str(target),"container_path":"/workspace"}]
                if tool=="psalm": expected.append({"host_path":str(worker.PSALM_CONFIG.parent),"container_path":"/inputs/source-sast-php"})
                self.assertEqual(request["target_mounts"],expected)
                self.assertEqual(request["argv"],plan["argv"])
                self.assertEqual(validate_document(request,"pinned-container-request.schema.json"),[])

    def test_live_language_tool_path_smoke_when_images_and_docker_exist(self):
        registry=ce.load_image_registry(ce.IMAGES_DIR)
        ready=worker.language_adapters.build_plan(["go","java","php"],registry)
        ready=[item for item in ready if item["status"]=="READY"]
        if not ready: self.skipTest("no pinned Go/Java/PHP B16 images are provisioned")
        if ce.host_defaults()["docker_executable"] is None: self.skipTest("Docker is unavailable")
        version_flags={"gosec":["-version"],"spotbugs":["-version"],"phpstan":["--version"],"psalm":["--version"],"phpcs":["--version"]}
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder,"target"); target.mkdir(); runtime=worker._runtime("sha256:"+"b"*64)
            for plan in ready:
                smoke={**plan,"argv":[plan["argv"][0],*version_flags[plan["tool_id"]]]}
                attempt=Path(folder,plan["tool_id"]); attempt.mkdir()
                request=worker._language_request("run",plan["tool_id"],{"target_path":str(target),"source_snapshot_sha256":"sha256:"+"b"*64},smoke)
                terminal=ce.run_container(runtime,run_id="run",job_id=worker.JOB,attempt_id=plan["tool_id"],attempt_root=attempt,request=request)
                self.assertEqual(terminal["execution_status"],"OK",plan["tool_id"])
                self.assertEqual(ce.verify_container_result(attempt,run_id="run",job_id=worker.JOB,attempt_id=plan["tool_id"],
                  request=request,images_dir=runtime.images_dir,expected_result_sha256=terminal["result_sha256"],**worker._host(runtime)),[])

    FIXTURE = ROOT / "tests" / "fixtures" / "source-sast-c"
    RECORDED = ROOT / "tests" / "fixtures" / "source-sast-c-semgrep.json"

    def test_request_runs_the_vendored_opengrep_rules_as_a_second_config(self):
        with tempfile.TemporaryDirectory() as folder:
            inputs = {"target_path": folder, "source_snapshot_sha256": "sha256:" + "b" * 64, "image": self.IMAGE}
            with mock.patch.object(worker, "_permission", return_value={"requirement": {}, "grants": [], "decision": {}}):
                argv = worker._request("run", "adapter", inputs)["argv"]
        configs = [argv[index + 1] for index, item in enumerate(argv) if item == "--config"]
        self.assertEqual(configs, ["/inputs/source-sast-rules/rules-v1.yml", "/inputs/source-sast-rules/opengrep-rules"])

    def test_vendored_rules_are_the_16_locked_c_rules_with_license_and_notice(self):
        lock = worker._vendored_lock()
        self.assertEqual(lock["commit"], "f1d2b562b414783763fd02a6ed2736eaed622efa")
        rules = worker.vendored_rules()
        self.assertEqual(len(rules), 16)
        self.assertTrue(all(rule_id.startswith("c.lang.") for rule_id in rules))
        self.assertTrue((worker.VENDORED_RULES_DIR / "LICENSE").is_file())
        self.assertIn(lock["commit"], (worker.VENDORED_RULES_DIR / "NOTICE").read_text())
        enum = json.loads((ROOT.parent / "schemas" / "source-sast.schema.json").read_text())[
            "properties"]["leads"]["items"]["properties"]["category"]["enum"]
        self.assertLessEqual({row["category"] for row in rules.values()} | set(worker.RULE_CATEGORIES.values()), set(enum))
        self.assertEqual(rules["c.lang.security.insecure-use-printf-fn"], {"category": "format-string", "cwe": ["CWE-134"]})

    def test_vendored_rule_drift_blocks(self):
        with tempfile.TemporaryDirectory() as folder:
            copy = Path(folder, "opengrep-rules")
            import shutil
            shutil.copytree(worker.VENDORED_RULES_DIR, copy)
            with mock.patch.object(worker, "VENDORED_RULES_DIR", copy):
                worker._vendored_lock()
                rule = copy / "c/lang/security/insecure-use-gets-fn.yaml"
                rule.write_text(rule.read_text() + "# edited\n")
                with self.assertRaisesRegex(worker.Blocked, "differs from its locked hash"):
                    worker._vendored_lock()
                rule.unlink()
                with self.assertRaisesRegex(worker.Blocked, "differ from the lock"):
                    worker._vendored_lock()
                (copy / "c/lang/security/insecure-use-gets-fn.yaml").write_text("rules: []\n")
                (copy / "c/lang/security/extra.yaml").write_text("rules: []\n")
                with self.assertRaisesRegex(worker.Blocked, "differ from the lock"):
                    worker._vendored_lock()

    def test_recorded_semgrep_output_normalizes_both_rulesets(self):
        """Replay of a live tool-semgrep 1.178.0 run on tests/fixtures/source-sast-c (both configs)."""
        raw = json.loads(self.RECORDED.read_text())
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder).resolve()
            (target / "vuln.c").write_bytes((self.FIXTURE / "vuln.c").read_bytes())
            result = worker.normalize_semgrep(raw, target=target, run_id="run", attempt_id="attempt",
                source_snapshot_sha256="sha256:" + "b" * 64, image=self.IMAGE)
        self.assertEqual(validate_document(result, "source-sast.schema.json"), [])
        by_rule = {}
        for lead in result["leads"]:
            by_rule.setdefault(lead["rule_id"], []).append(lead)
        # repository rules: strcpy, memcpy, system, non-literal printf
        self.assertEqual({(row["rule_id"], row["start_line"]) for row in result["leads"] if row["tool_id"] == worker.TOOL_ID},
                         {("appsec.c.strcpy", 11), ("appsec.c.memcpy", 17), ("appsec.c.printf-nonliteral", 22),
                          ("appsec.c.printf-nonliteral", 26), ("appsec.c.system", 30)})
        expected_vendored = {
            "c.lang.security.insecure-use-string-copy-fn": ("unsafe-copy", [11]),
            "c.lang.security.insecure-use-strcat-fn": ("unsafe-copy", [12]),
            "c.lang.security.insecure-use-printf-fn": ("format-string", [21, 22]),  # sprintf/printf(argv[1])
            "c.lang.security.info-leak-on-non-formated-string": ("format-string", [22]),
            "c.lang.security.insecure-use-gets-fn": ("unsafe-input", [34]),
            "c.lang.security.insecure-use-scanf-fn": ("unsafe-input", [35]),
            "c.lang.security.insecure-use-strtok-fn": ("unsafe-api", [39]),
            "c.lang.correctness.incorrect-use-ato-fn": ("unchecked-conversion", [40]),
            "c.lang.security.use-after-free": ("memory-lifetime", [46]),
            "c.lang.security.double-free": ("memory-lifetime", [47]),
            "c.lang.security.insecure-use-memset": ("sensitive-memory-clear", [51]),
            "c.lang.security.random-fd-exhaustion": ("resource-exhaustion", [55]),
        }
        for rule_id, (category, lines) in expected_vendored.items():
            rows = by_rule[rule_id]
            self.assertEqual(([row["category"] for row in rows][0], [row["start_line"] for row in rows]), (category, lines))
            self.assertEqual({row["tool_id"] for row in rows}, {worker.VENDORED_TOOL_ID})
        self.assertEqual(by_rule["c.lang.security.insecure-use-gets-fn"][0]["cwe"], ["CWE-676"])
        self.assertNotIn("cwe", by_rule["c.lang.correctness.incorrect-use-ato-fn"][0])
        tools = {row["tool_id"]: row["records"] for row in result["tools"]}
        self.assertEqual(tools, {worker.TOOL_ID: 5, worker.VENDORED_TOOL_ID: 13})
        self.assertTrue(all(row["source_sha256"] == "sha256:" + worker.file_hash(self.FIXTURE / "vuln.c")
                            for row in result["leads"]))
        self.assertEqual(result["coverage_gaps"], [worker.RULES_GAP])

    def test_undeclared_vendored_rule_id_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder).resolve(); (target / "a.c").write_text("x\n")
            raw = {"results": [{"check_id": worker.VENDORED_RULE_PREFIX + "c.lang.security.not-vendored",
                                "path": "/workspace/a.c", "start": {"line": 1}, "end": {"line": 1}}]}
            with self.assertRaisesRegex(RuntimeError, "undeclared vendored rule id"):
                worker.normalize_semgrep(raw, target=target, run_id="run", attempt_id="attempt",
                    source_snapshot_sha256="sha256:" + "b" * 64, image=self.IMAGE)

    def test_live_semgrep_matches_the_recorded_fixture_when_image_and_docker_exist(self):
        registry = ce.load_image_registry(ce.IMAGES_DIR)
        if "tool-semgrep" not in registry: self.skipTest("tool-semgrep has no B16 record here")
        if ce.host_defaults()["docker_executable"] is None: self.skipTest("Docker is unavailable")
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder, "target"); target.mkdir()
            (target / "vuln.c").write_bytes((self.FIXTURE / "vuln.c").read_bytes())
            inputs = {"target_path": str(target), "source_snapshot_sha256": "sha256:" + "b" * 64,
                      "image": registry["tool-semgrep"]}
            runtime = worker._runtime(inputs["source_snapshot_sha256"])
            request = worker._request("run", "semgrep-live", inputs)
            attempt = Path(folder, "attempt"); attempt.mkdir()
            terminal = ce.run_container(runtime, run_id="run", job_id=worker.JOB, attempt_id="semgrep-live",
                                        attempt_root=attempt, request=request)
            self.assertEqual(terminal["execution_status"], "OK")
            raw = json.loads((attempt / "scratch" / "semgrep.json").read_text())
        recorded = json.loads(self.RECORDED.read_text())
        key = lambda rows: sorted((row["check_id"], row["start"]["line"], row["end"]["line"]) for row in rows)
        self.assertEqual(key(raw["results"]), key(recorded["results"]))

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
            for start,end in ((2,2),(1,2)):
                with self.assertRaises(RuntimeError):
                    worker.normalize_semgrep({"results":[{"check_id":"appsec.c.memcpy","path":"/workspace/a.cpp",
                        "start":{"line":start},"end":{"line":end}}]},**args)

    def test_language_versions_and_paths_come_from_authenticated_tool_metadata(self):
        registry={}
        for tool,image_id in worker.language_adapters.TOOL_IMAGES.items():
            registry[image_id]={"image_id":image_id,"digest":"sha256:"+"a"*64}
        plan=worker.language_adapters.build_plan(["go","java","php"],registry)
        values={item["tool_id"]:item for item in plan}
        self.assertEqual(values["gosec"]["version"],"2.29.0")
        self.assertEqual(values["spotbugs"]["version"],"4.10.4")
        self.assertEqual(values["phpstan"]["version"],"2.2.16")
        self.assertEqual(values["psalm"]["version"],"6.18.1")
        self.assertEqual(values["phpcs"]["version"],"4.0.4")
        self.assertEqual(values["spotbugs"]["argv"][0],"/opt/spotbugs/bin/spotbugs")
        self.assertIn("--config=/inputs/source-sast-php/psalm.xml",values["psalm"]["argv"])
        self.assertTrue(all(item["tool_metadata_sha256"].startswith("sha256:") for item in plan))

    def test_psalm_prefers_canonical_file_path_over_display_path(self):
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder).resolve(); source=target/"index.php"; source.write_text("<?php\nreturn 1;\n")
            raw=[{"type":"InvalidReturnType","file_name":"../../workspace/index.php",
                  "file_path":"/workspace/index.php","line_from":2}]
            leads=worker.language_adapters.normalize("psalm",json.dumps(raw).encode(),target)
        self.assertEqual(leads[0]["path"],"index.php")

    def test_contract_registry_records_are_explicitly_not_fully_qualified(self):
        template = json.loads((registry_paths.template("02-source-sast")).read_text())
        contract = json.loads((registry_paths.contract("source-sast")).read_text())
        self.assertTrue(template["implemented"])
        self.assertEqual(template["composition"]["output_contract_id"], contract["contract_id"])
        self.assertIn("qualification", contract["required_status_fields"])
        self.assertIn("implemented_not_qualified", (ROOT / "source_sast.py").read_text())

    def test_producer_receipts_use_canonical_permissions_and_bind_inputs(self):
        inputs = {"run_id": "run-1", "source_snapshot_sha256": "sha256:" + "b" * 64,
                  "accepted": {"attempt": "one"}}
        permission, lineage = worker._producer_receipts(inputs)
        template = json.loads((registry_paths.template("02-source-sast")).read_text())
        self.assertEqual(permission["permissions"], template["permissions"])
        self.assertEqual(permission["source_snapshot_sha256"], inputs["source_snapshot_sha256"])
        self.assertEqual(lineage["build_lineage_sha256"], "sha256:" + worker.digest(inputs))


if __name__ == "__main__":
    unittest.main()


class UncoveredLanguageGapTests(unittest.TestCase):
    """Run 20261001T032047Z-fd64eb: Python, JS, TS, C#, Rust, Bash and PowerShell had no source SAST tool
    and no gap said so."""

    def test_each_uncovered_language_is_a_named_gap(self):
        import source_sast_language_adapters as adapters
        gaps = adapters.uncovered_language_gaps([
            "projects/python/case-073/app.py", "projects/typescript/case-012/index.ts",
            "projects/bash/case-019/run.sh", "projects/powershell/case-020/run.ps1",
            "projects/rust/case-004/src/main.rs", "node_modules/x/index.js", "projects/go/case-007/main.go"])
        self.assertEqual([g.split(" ")[0] for g in gaps], ["powershell", "python", "rust", "shell", "typescript"])
        self.assertIn("02-codeql-python is its only static analysis", gaps[1])
        self.assertIn("no static analyzer runs on it", gaps[2])

    def test_spotbugs_gap_names_its_cause(self):
        import source_sast_language_adapters as adapters
        gaps = adapters.execution_gaps([{"status": "READY", "tool_id": "spotbugs", "language": "java"}], set())
        self.assertIn("compiled classes", gaps[0])
