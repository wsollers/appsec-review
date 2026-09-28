"""02-codeql-sast: plan, request, SARIF normalization, gaps, and a scripted end-to-end publish."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import codeql_sast as worker  # noqa: E402
import container_execution as ce  # noqa: E402
import execution_state  # noqa: E402
from schema_validate import validate_document  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures"
SARIF = FIXTURE / "codeql-cpp-source-sast-c.sarif"   # live audit-codeql 2.27.0 cpp run on source-sast-c/
DIGEST = "sha256:" + "a" * 64


def _plan(languages=("cpp",), registry=None):
    metadata, sha = worker.tool_metadata()
    registry = {worker.IMAGE_ID: {"image_id": worker.IMAGE_ID, "digest": DIGEST}} if registry is None else registry
    return worker.build_plan(list(languages), registry, metadata, sha, {"threads": 2, "ram_mb": 2048})


class CodeqlSastUnitTests(unittest.TestCase):
    def test_tool_metadata_is_bound_to_the_pinned_bundle_and_lane_script(self):
        metadata, _ = worker.tool_metadata()
        self.assertEqual((metadata["tool"], metadata["version"]), ("codeql", "2.27.0"))
        self.assertEqual(metadata["lane_script"]["path"], "/opt/scripts/codeql-sast-lane.sh")
        with tempfile.TemporaryDirectory() as folder:
            copy = Path(folder, "audit-codeql"); shutil.copytree(worker.IMAGE_ROOT, copy)
            tool = json.loads((copy / "tool.json").read_text()); tool["bundle"]["sha256"] = "0" * 64
            (copy / "tool.json").write_text(json.dumps(tool))
            with mock.patch.object(worker, "IMAGE_ROOT", copy), mock.patch.object(worker, "TOOL_METADATA", copy / "tool.json"):
                with self.assertRaisesRegex(worker.Blocked, "differs from the pinned image build"):
                    worker.tool_metadata()

    def test_language_detection_and_plan(self):
        paths = ["src/a.c", "include/a.hpp", "web/app.ts", "tool.py", "svc/main.go", "lib/x.rb", "A.java", "B.cs",
                 ".git/hooks/pre-commit.py", "README.md"]
        self.assertEqual(worker.detected_languages(paths),
                         ["cpp", "csharp", "go", "java", "javascript", "python", "ruby"])
        plan = {row["language"]: row for row in _plan(worker.detected_languages(paths))}
        self.assertEqual(plan["go"]["status"], "UNSUPPORTED_OFFLINE")
        self.assertEqual(plan["cpp"]["argv"], ["/opt/scripts/codeql-sast-lane.sh", "cpp", "none",
            "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls", "2", "2048"])
        self.assertTrue(all(row["build_mode"] == "none" for row in plan.values() if row["status"] == "READY"))
        missing = _plan(["cpp"], registry={})
        self.assertEqual(missing[0]["status"], "UNAVAILABLE")
        self.assertIn("no current B16 record", missing[0]["gap"])

    def test_request_is_offline_read_only_and_valid(self):
        with tempfile.TemporaryDirectory() as folder:
            inputs = {"target_path": folder, "source_snapshot_sha256": "sha256:" + "b" * 64,
                      "limits": {"timeout_seconds": 60, "memory_bytes": 4 << 30, "cpu_millis": 2000, "pids": 256,
                                 "tmpfs_bytes": 1 << 28, "stdout_limit_bytes": 1 << 20, "stderr_limit_bytes": 1 << 20}}
            request = worker._request("run", "codeql-cpp-a", inputs, _plan()[0])
        self.assertEqual(request["network"], {"mode": "none", "destinations": []})
        self.assertEqual(request["target_mounts"], [{"host_path": folder, "container_path": "/workspace"}])
        self.assertEqual(validate_document(request, "pinned-container-request.schema.json"), [])
        self.assertEqual(ce.request_errors(request, run_id="run", job_id=worker.JOB, attempt_id="codeql-cpp-a"), [])

    def test_tunables_bound_ram_below_the_container_memory(self):
        analysis = worker._analysis_tunables()
        self.assertLess(analysis["ram_mb"] * 1024 * 1024, worker._limits()["memory_bytes"])
        with mock.patch.object(worker.tunables, "value", side_effect=lambda job, name: 64 << 30 if name == "codeql_ram_bytes" else 4):
            with self.assertRaisesRegex(worker.Blocked, "below container_memory_bytes"):
                worker._analysis_tunables()

    def test_recorded_sarif_normalizes_to_cwe_tagged_leads_without_messages(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder).resolve()
            shutil.copy(FIXTURE / "source-sast-c" / "vuln.c", target / "vuln.c")
            leads, dropped = worker.normalize_sarif("cpp", SARIF.read_bytes(), target)
        self.assertEqual(dropped, 0)
        got = {(row["rule_id"], row["start_line"]) for row in leads}
        self.assertEqual(got, {("cpp/unsafe-strcat", 12), ("cpp/non-constant-format", 21), ("cpp/non-constant-format", 22),
                               ("cpp/non-constant-format", 26), ("cpp/unbounded-write", 35), ("cpp/use-after-free", 46),
                               ("cpp/double-free", 47)})
        by_rule = {row["rule_id"]: row for row in leads}
        self.assertEqual(by_rule["cpp/double-free"]["cwe"], ["CWE-415"])
        self.assertEqual(by_rule["cpp/unsafe-strcat"]["cwe"], ["CWE-120", "CWE-251", "CWE-676"])
        self.assertEqual(by_rule["cpp/double-free"]["rule_name"], "Potential double free")
        self.assertTrue(all(row["path"] == "vuln.c" and row["category"] == "codeql-security-query" for row in leads))
        self.assertNotIn("may already have been freed", json.dumps(leads))
        inputs = {"source_snapshot_sha256": "sha256:" + "b" * 64, "plan": _plan()}
        result = worker.assemble(run_id="run", attempt_id="attempt", inputs=inputs,
                                 outcomes={"cpp": {"gap": None, "leads": leads, "dropped": 0}})
        self.assertEqual(validate_document(result, "codeql-sast.schema.json"), [])
        self.assertEqual(result["status"], "OK_WITH_GAPS")
        self.assertEqual(result["coverage_gaps"], [worker.FIDELITY_GAPS["cpp"]])
        self.assertEqual(result["tools"][0]["records"], 7)

    def test_results_outside_the_checkout_are_dropped_and_counted(self):
        document = json.loads(SARIF.read_text())
        results = document["runs"][0]["results"]
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "../etc/passwd"
        results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "file:///usr/include/stdio.h"
        results[2]["locations"][0]["physicalLocation"]["region"]["startLine"] = 999
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder).resolve()
            shutil.copy(FIXTURE / "source-sast-c" / "vuln.c", target / "vuln.c")
            leads, dropped = worker.normalize_sarif("cpp", json.dumps(document).encode(), target)
            self.assertEqual((len(leads), dropped), (4, 3))
            with self.assertRaises(RuntimeError):
                worker.normalize_sarif("cpp", b"{not json", target)
            with self.assertRaises(RuntimeError):
                worker.normalize_sarif("cpp", b'{"version": "2.1.0"}', target)
        inputs = {"source_snapshot_sha256": "sha256:" + "b" * 64, "plan": _plan()}
        result = worker.assemble(run_id="run", attempt_id="attempt", inputs=inputs,
                                 outcomes={"cpp": {"gap": None, "leads": leads, "dropped": dropped}})
        self.assertIn("codeql-results-outside-checkout:cpp:3", result["coverage_gaps"])

    def test_tool_failures_are_gaps_and_cancellation_blocks(self):
        self.assertIsNone(worker.terminal_gap("cpp", {"execution_status": "OK", "exit_code": 0}))
        self.assertIn("ended TIMEOUT", worker.terminal_gap("cpp", {"execution_status": "FAILED", "cause": "TIMEOUT"}))
        self.assertIn("ended OOM_KILLED", worker.terminal_gap("java", {"execution_status": "FAILED", "cause": "OOM_KILLED"}))
        self.assertIn("CONTAINER_EXIT_NONZERO exit 2", worker.terminal_gap(
            "csharp", {"execution_status": "FAILED", "cause": "CONTAINER_EXIT_NONZERO", "exit_code": 2}))
        for terminal in ({"execution_status": "CANCELED", "cause": "CANCELED"},
                         {"execution_status": "BLOCKED", "cause": "IMAGE_NOT_PROVISIONED"},
                         {"execution_status": "FAILED", "cause": "CLEANUP_FAILED"}):
            with self.assertRaises(worker.Blocked):
                worker.terminal_gap("cpp", terminal)

    def test_empty_plan_and_all_gaps_still_publish(self):
        inputs = {"source_snapshot_sha256": "sha256:" + "b" * 64, "plan": []}
        result = worker.assemble(run_id="run", attempt_id="attempt", inputs=inputs, outcomes={})
        self.assertEqual((result["status"], result["tools"], result["leads"]), ("OK_WITH_GAPS", [], []))
        self.assertEqual(validate_document(result, "codeql-sast.schema.json"), [])
        inputs["plan"] = _plan(["go", "cpp"])
        with self.assertRaisesRegex(worker.Blocked, "has no receipt"):
            worker.assemble(run_id="run", attempt_id="attempt", inputs=inputs, outcomes={})


class CodeqlSastScriptedPublishTests(unittest.TestCase):
    """run() end to end with scripted docker: cpp returns the recorded SARIF, python times out."""

    def setUp(self):
        from test_container_execution import ScriptedDocker
        import container_execution_support as support
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name).resolve()
        self.runs, self.images, target = base / "runs", base / "images", base / "target"
        self.images.mkdir(); target.mkdir()
        shutil.copy(FIXTURE / "source-sast-c" / "vuln.c", target / "vuln.c")
        (target / "tool.py").write_text("print('x')\n")
        record = {**support.fixture_record(), "image_id": worker.IMAGE_ID, "repository": "docker.io/library/audit-codeql"}
        (self.images / "audit-codeql.json").write_text(json.dumps(record))
        inputs = self.runs / "run-codeql" / "inputs"; inputs.mkdir(parents=True)
        (inputs / "artifact-manifest.json").write_text(json.dumps({"target": {"repo_path": str(target)}}))
        scripted = ScriptedDocker()
        original = scripted.child

        def child(spec, **kwargs):
            language = list(spec.argv)[-5]
            if language == "python":
                scripted.client_exit, scripted.metadata = -9, {"timed_out": True, "error": "TimeoutError: bounded"}
                scripted.state = {"Status": "exited", "ExitCode": -9, "OOMKilled": False}
                (Path(spec.owner_root) / "scratch" / "db").mkdir(parents=True, exist_ok=True)  # left by a killed run
                (Path(spec.owner_root) / "scratch" / "db" / "trap").write_text("x")
            else:
                scripted.client_exit, scripted.metadata = 0, {}
                scripted.state = {"Status": "exited", "ExitCode": 0, "OOMKilled": False}
                scratch = Path(spec.owner_root) / "scratch"; scratch.mkdir(exist_ok=True)
                (scratch / "codeql.sarif").write_bytes(SARIF.read_bytes())
            return original(spec, **kwargs)

        scripted.child = child
        defaults = ce.host_defaults()
        self.runtime = lambda source: ce.ContainerRuntime(
            docker_executable=defaults["docker_executable"] or Path(sys.executable).resolve(), docker_host=None,
            images_dir=self.images, host_flavor=defaults["host_flavor"],
            container_user=defaults["container_user"] if ce._USER_RE.match(defaults["container_user"]) else "10001:10001",
            source_snapshot_sha256=source, registry_ceiling=[], clock=lambda: support.NOW, cancel=threading.Event())
        self.patches = [*scripted.patches(), mock.patch.object(execution_state, "RUNS", self.runs),
                        mock.patch.object(ce, "IMAGES_DIR", self.images),
                        mock.patch.object(worker, "_runtime", side_effect=self.runtime)]
        for patch in self.patches: patch.start()

    def tearDown(self):
        for patch in reversed(self.patches): patch.stop()
        self.temporary.cleanup()

    def test_publishes_ok_with_gaps_and_revalidates(self):
        envelope = worker.run("run-codeql", "dagster-1")
        self.assertEqual(envelope["status"], "OK_WITH_GAPS")
        attempt = worker.root("run-codeql") / "attempts" / envelope["attempt_id"]
        result = json.loads((attempt / worker.RESULT).read_text())
        self.assertEqual([row["tool_id"] for row in result["tools"]], ["codeql-cpp"])
        self.assertEqual(len(result["leads"]), 7)
        self.assertIn("CodeQL python ended TIMEOUT; no CodeQL leads for python.", result["coverage_gaps"])
        self.assertIn(worker.FIDELITY_GAPS["cpp"], result["coverage_gaps"])
        receipts = json.loads((attempt / worker.RECEIPTS).read_text())["tools"]
        self.assertEqual({row["language"]: row["raw_result_sha256"] is None for row in receipts},
                         {"cpp": False, "python": True})
        self.assertFalse((attempt / "tools" / "codeql-python" / "scratch" / "db").exists())
        self.assertEqual(worker.validate("run-codeql"), attempt)
        # Tampering with the retained SARIF is caught on re-validation.
        sarif = attempt / "tools" / "codeql-cpp" / "scratch" / "codeql.sarif"
        sarif.write_bytes(sarif.read_bytes().replace(b"cpp/double-free", b"cpp/double-freX"))
        with self.assertRaises(worker.Blocked):
            worker.validate("run-codeql")


if __name__ == "__main__":
    unittest.main()
