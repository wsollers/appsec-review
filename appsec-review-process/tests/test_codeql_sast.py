"""02-codeql-<lang> nodes (ADR-0023): plan, gating, request, SARIF normalization, gaps, retained databases,
and scripted end-to-end publishes."""
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


def _inputs(plan, language="cpp", present=True, **extra):
    return {"job": worker.JOBS[language], "language": language, "present": present,
            "source_snapshot_sha256": "sha256:" + "b" * 64, "plan": plan, **extra}


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
        self.assertEqual(worker.detected_languages(["src/lib.rs"]), ["rust"])
        self.assertEqual(sorted(worker.JOBS.values()), sorted(f"02-codeql-{l}" for l in worker.LANGUAGES))
        rust = _plan(["rust"])[0]
        self.assertEqual((rust["status"], rust["argv"]), ("UNSUPPORTED_OFFLINE", []))
        self.assertIn("language not supported", rust["gap"])
        plan = {row["language"]: row for row in _plan(worker.detected_languages(paths))}
        self.assertEqual(plan["cpp"]["argv"], ["/opt/scripts/codeql-sast-lane.sh", "cpp", "none",
            "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls", "2", "2048", "keep-db"])
        # Go runs with autobuild on the image's offline Go toolchain (2026-10-01; was UNSUPPORTED_OFFLINE).
        self.assertEqual((plan["go"]["status"], plan["go"]["build_mode"]), ("READY", "autobuild"))
        self.assertEqual(plan["go"]["argv"], ["/opt/scripts/codeql-sast-lane.sh", "go", "autobuild",
            "codeql/go-queries:codeql-suites/go-security-extended.qls", "2", "2048", "keep-db"])
        self.assertIn("go", worker.FIDELITY_GAPS)
        self.assertTrue(all(row["build_mode"] == "none" for row in plan.values()
                            if row["status"] == "READY" and row["language"] != "go"))
        missing = _plan(["cpp"], registry={})
        self.assertEqual(missing[0]["status"], "UNAVAILABLE")
        self.assertIn("no current B16 record", missing[0]["gap"])

    def test_request_is_offline_read_only_and_valid(self):
        with tempfile.TemporaryDirectory() as folder:
            inputs = {"job": worker.JOBS["cpp"], "target_path": folder, "source_snapshot_sha256": "sha256:" + "b" * 64,
                      "limits": {"timeout_seconds": 60, "memory_bytes": 4 << 30, "cpu_millis": 2000, "pids": 256,
                                 "tmpfs_bytes": 1 << 28, "stdout_limit_bytes": 1 << 20, "stderr_limit_bytes": 1 << 20}}
            request = worker._request("run", "codeql-cpp-a", inputs, _plan()[0])
        self.assertEqual(request["network"], {"mode": "none", "destinations": []})
        self.assertEqual(request["target_mounts"], [{"host_path": folder, "container_path": "/workspace"}])
        self.assertEqual(validate_document(request, "pinned-container-request.schema.json"), [])
        self.assertEqual(ce.request_errors(request, run_id="run", job_id=worker.JOBS["cpp"], attempt_id="codeql-cpp-a"), [])

    def test_tunables_bound_ram_below_the_container_memory(self):
        for language in worker.LANGUAGES:
            analysis = worker._analysis_tunables(language)
            self.assertLess(analysis["ram_mb"] * 1024 * 1024, worker._limits(language)["memory_bytes"])
        with mock.patch.object(worker.tunables, "value", side_effect=lambda job, name: 64 << 30 if name == "codeql_ram_bytes" else 4):
            with self.assertRaisesRegex(worker.Blocked, "below container_memory_bytes"):
                worker._analysis_tunables("python")

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
        inputs = _inputs(_plan())
        result = worker.assemble(run_id="run", attempt_id="attempt", inputs=inputs,
                                 outcomes={"cpp": {"gap": None, "leads": leads, "dropped": 0}})
        self.assertEqual(validate_document(result, "codeql-language.schema.json"), [])
        self.assertEqual((result["job_id"], result["language"], result["databases"]), ("02-codeql-cpp", "cpp", []))
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
        inputs = _inputs(_plan())
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

    def test_absent_language_skips_and_unbuildable_languages_are_gaps(self):
        result = worker.assemble(run_id="run", attempt_id="attempt", inputs=_inputs([], "java", present=False),
                                 outcomes={})
        self.assertEqual((result["status"], result["skip_reason"], result["tools"]),
                         ("SKIPPED", "not-applicable-language-absent", []))
        self.assertEqual(validate_document(result, "codeql-language.schema.json"), [])
        # Rust is still not run (no pinned suite): a gap, never a failure. (Go was the example until it
        # gained autobuild on 2026-10-01.)
        go = worker.assemble(run_id="run", attempt_id="attempt", inputs=_inputs(_plan(["rust"]), "rust"), outcomes={})
        self.assertEqual((go["status"], go["databases"]), ("OK_WITH_GAPS", []))
        self.assertIn("language not supported", go["coverage_gaps"][0])
        not_built = worker.assemble(run_id="run", attempt_id="attempt", outcomes={
            "cpp": {"gap": None, "leads": [], "dropped": 0}},
            inputs=_inputs(_plan(), not_built="language not built: no accepted 02-native-build publication; "
                                              "ran --build-mode none only"))
        self.assertTrue(not_built["coverage_gaps"][0].startswith("language not built: no accepted 02-native-build"))
        self.assertEqual(validate_document(go, "codeql-language.schema.json"), [])
        with self.assertRaisesRegex(worker.Blocked, "has no receipt"):
            worker.assemble(run_id="run", attempt_id="attempt", inputs=_inputs(_plan()), outcomes={})

    def test_database_tree_and_pointer(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder, "db")
            self.assertIsNone(worker.database_tree(db))
            (db / "db-cpp").mkdir(parents=True)
            self.assertIsNone(worker.database_tree(db))            # empty
            (db / "codeql-database.yml").write_text("sourceLocationPrefix: /workspace\n")
            (db / "db-cpp" / "a.trap").write_bytes(b"x" * 10)
            tree = worker.database_tree(db)
            self.assertEqual((tree["files"], tree["bytes"]), (2, 10 + len("sourceLocationPrefix: /workspace\n")))
            (db / "link").symlink_to(db / "codeql-database.yml")
            self.assertIsNone(worker.database_tree(db))            # links are never kept
        row = _plan()[0]
        record = {"store_path": "codeql-databases/02-codeql-cpp/attempt/cpp", **tree}
        published = worker.pointer(_inputs([row]), "attempt", row, record)
        self.assertEqual(validate_document(published, "codeql-database-pointer.schema.json"), [])
        self.assertEqual((published["build_mode"], published["bundle_version"]), ("none", "2.27.0"))
        result = worker.assemble(run_id="run", attempt_id="attempt", inputs=_inputs([row]),
                                 outcomes={"cpp": {"gap": None, "leads": [], "dropped": 0, "database": record}})
        self.assertEqual(result["databases"], [published])
        self.assertEqual(result["tools"][0]["database_id"], published["database_id"])
        absent = worker.assemble(run_id="run", attempt_id="attempt", inputs=_inputs([row]), outcomes={
            "cpp": {"gap": None, "leads": [], "dropped": 0, "database": None, "database_gap": "codeql-database-absent:cpp"}})
        self.assertIn("codeql-database-absent:cpp", absent["coverage_gaps"])


UNITS = [{"unit_id": "unit-a", "key": "0123456789abcdef", "adapted_sha256": "sha256:" + "c" * 64,
          "adapted": [{"file": "/workspace/vuln.c", "directory": "/workspace",
                       "arguments": ["/opt/llvm/bin/clang", "-c", "/workspace/vuln.c"]}]}]
NATIVE = {worker.TRACED_IMAGE_ID: {"image_id": worker.TRACED_IMAGE_ID, "digest": "sha256:" + "d" * 64}}


def _traced(units=UNITS, registry=NATIVE):
    metadata, sha = worker.tool_metadata()
    return worker.traced_plan(units, registry, metadata, sha, {"threads": 2, "ram_mb": 2048},
                              worker.graph_pack_sha256())


class CodeqlTracedUnitTests(unittest.TestCase):
    def test_metadata_binds_the_native_image_replay_script_and_graph_pack(self):
        metadata, _ = worker.tool_metadata()
        self.assertEqual(metadata["traced"]["image_id"], "audit-codeql-native")
        self.assertRegex(metadata["replay_script_sha256"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(worker.graph_pack_sha256(), r"^sha256:[0-9a-f]{64}$")
        with tempfile.TemporaryDirectory() as folder:
            copy = Path(folder, "audit-codeql"); shutil.copytree(worker.IMAGE_ROOT, copy)
            native = copy / "Dockerfile.native"
            native.write_text(native.read_text().replace("5e0f04bc", "00000000"))
            with mock.patch.object(worker, "IMAGE_ROOT", copy), mock.patch.object(worker, "TOOL_METADATA", copy / "tool.json"):
                with self.assertRaisesRegex(worker.Blocked, "pinned native image build"):
                    worker.tool_metadata()

    def test_traced_plan_rows(self):
        row = _traced()[0]
        self.assertEqual((row["status"], row["build_mode"], row["plan_key"]),
                         ("READY", "traced", "codeql-cpp-traced:0123456789abcdef"))
        self.assertEqual(row["argv"], ["/opt/scripts/codeql-sast-lane.sh", "cpp", "traced",
            "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls", "2", "2048", "keep-db",
            "/inputs/codeql-db/0123456789abcdef/compile_commands.json", "/inputs/codeql-queries"])
        self.assertEqual(row["compile_database_entries"], 1)
        self.assertEqual(_traced(units=[])[0]["status"], "NO_UNITS")
        self.assertEqual(_traced(units=[])[0]["gap"], worker.TRACED_NO_UNITS)
        missing = _traced(registry={})[0]
        self.assertEqual(missing["status"], "UNAVAILABLE")
        self.assertIn("audit-codeql-native has no current B16 record", missing["gap"])

    def test_traced_request_mounts_the_databases_and_the_query_pack_read_only(self):
        with tempfile.TemporaryDirectory() as folder:
            inputs = {"job": worker.JOBS["cpp"], "target_path": folder, "source_snapshot_sha256": "sha256:" + "b" * 64,
                      "limits": {"timeout_seconds": 60, "memory_bytes": 4 << 30, "cpu_millis": 2000, "pids": 256,
                                 "tmpfs_bytes": 1 << 28, "stdout_limit_bytes": 1 << 20, "stderr_limit_bytes": 1 << 20}}
            with self.assertRaisesRegex(worker.Blocked, "adapted compile databases"):
                worker._request("run", "codeql-cpp-traced-a", inputs, _traced()[0])
            request = worker._request("run", "codeql-cpp-traced-a", inputs, _traced()[0], Path(folder) / "db")
        self.assertEqual([m["container_path"] for m in request["target_mounts"]],
                         ["/workspace", "/inputs/codeql-db", "/inputs/codeql-queries"])
        self.assertEqual(request["target_mounts"][2]["host_path"], str(worker.GRAPH_PACK))
        self.assertEqual(request["image"]["image_id"], "audit-codeql-native")
        self.assertEqual(validate_document(request, "pinned-container-request.schema.json"), [])
        self.assertEqual(ce.request_errors(request, run_id="run", job_id=worker.JOBS["cpp"], attempt_id="codeql-cpp-traced-a"), [])

    def test_replay_stats_are_validated(self):
        with tempfile.TemporaryDirectory() as folder:
            trial = Path(folder); (trial / "scratch").mkdir()
            self.assertIsNone(worker.read_replay(trial))
            for value, expected in (({"total": 3, "ok": 2, "failed": 1, "refused": 0}, True),
                                    ({"total": 3, "ok": 2, "failed": 0, "refused": 0}, False),
                                    ({"total": 1, "ok": True, "failed": 0, "refused": 0}, False),
                                    ({"total": 1, "ok": 1, "failed": 0, "refused": 0, "x": 1}, False)):
                (trial / "scratch" / "replay.json").write_text(json.dumps(value))
                self.assertEqual(worker.read_replay(trial) is not None, expected, value)

    def test_assemble_reports_traced_tools_and_replay_gaps(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder).resolve()
            shutil.copy(FIXTURE / "source-sast-c" / "vuln.c", target / "vuln.c")
            leads, dropped = worker.normalize_sarif("cpp", SARIF.read_bytes(), target, tool_id="codeql-cpp-traced")
        self.assertTrue(all(row["tool_id"] == "codeql-cpp-traced" for row in leads))
        plan = _plan() + _traced()
        inputs = _inputs(plan)
        replay = {"total": 4, "ok": 3, "failed": 1, "refused": 0}
        outcomes = {"cpp": {"gap": None, "leads": [], "dropped": 0},
                    "codeql-cpp-traced:0123456789abcdef": {"gap": None, "leads": leads, "dropped": dropped,
                                                           "replay": replay}}
        result = worker.assemble(run_id="run", attempt_id="attempt", inputs=inputs, outcomes=outcomes)
        self.assertEqual(validate_document(result, "codeql-language.schema.json"), [])
        traced = [row for row in result["tools"] if row["build_mode"] == "traced"][0]
        self.assertEqual((traced["unit_id"], traced["replay"], traced["image_id"]),
                         ("unit-a", replay, "audit-codeql-native"))
        self.assertIn("codeql-traced-replay-incomplete:codeql-cpp-traced:0123456789abcdef:ok=3:failed=1:refused=0:total=4",
                      result["coverage_gaps"])
        self.assertEqual(result["coverage_gaps"].count(worker.FIDELITY_GAPS["cpp"]), 1)
        with self.assertRaisesRegex(worker.Blocked, "codeql-cpp-traced:0123456789abcdef has no receipt"):
            worker.assemble(run_id="run", attempt_id="attempt", inputs=inputs, outcomes={"cpp": outcomes["cpp"]})


class CodeqlSastScriptedPublishTests(unittest.TestCase):
    """run() end to end with scripted docker: cpp returns the recorded SARIF and keeps its database,
    python times out, java is absent (SKIPPED)."""

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
            argv = list(spec.argv)
            entry = next(i for i, item in enumerate(argv) if item.startswith("--entrypoint="))
            language = argv[entry + 2]    # --entrypoint=<lane> <image> LANGUAGE MODE ...
            scratch = Path(spec.owner_root) / "scratch"
            if language == "python":
                scripted.client_exit, scripted.metadata = -9, {"timed_out": True, "error": "TimeoutError: bounded"}
                scripted.state = {"Status": "exited", "ExitCode": -9, "OOMKilled": False}
                (scratch / "db").mkdir(parents=True, exist_ok=True)  # left by a killed run
                (scratch / "db" / "trap").write_text("x")
            else:
                scripted.client_exit, scripted.metadata = 0, {}
                scripted.state = {"Status": "exited", "ExitCode": 0, "OOMKilled": False}
                scratch.mkdir(exist_ok=True)
                (scratch / "codeql.sarif").write_bytes(SARIF.read_bytes())
                (scratch / "db" / "db-cpp").mkdir(parents=True, exist_ok=True)   # keep-db
                (scratch / "db" / "codeql-database.yml").write_text("primaryLanguage: cpp\n")
                (scratch / "db" / "db-cpp" / "default.trap").write_text(argv[-1] + "\n")
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
        envelope = worker.run("run-codeql", "dagster-1", "cpp")
        self.assertEqual(envelope["status"], "OK_WITH_GAPS")
        attempt = worker.root("run-codeql", "cpp") / "attempts" / envelope["attempt_id"]
        result = json.loads((attempt / worker.RESULT).read_text())
        self.assertEqual([row["tool_id"] for row in result["tools"]], ["codeql-cpp"])
        self.assertEqual(len(result["leads"]), 7)
        self.assertIn(worker.FIDELITY_GAPS["cpp"], result["coverage_gaps"])
        self.assertEqual(result["coverage_gaps"][0],
                         "language not built: no accepted 02-native-build publication; ran --build-mode none only")
        [database] = result["databases"]
        self.assertEqual(result["tools"][0]["database_id"], database["database_id"])
        self.assertEqual(database["store_path"], f"codeql-databases/02-codeql-cpp/{envelope['attempt_id']}/cpp")
        store = worker.verify_database("run-codeql", database)
        self.assertEqual(store, worker.database_store("run-codeql") / "02-codeql-cpp" / envelope["attempt_id"] / "cpp")
        self.assertFalse((attempt / "tools" / "codeql-cpp" / "scratch" / "db").exists())
        self.assertEqual(worker.validate("run-codeql", "cpp"), attempt)
        document, binding, gap = worker.load_accepted("run-codeql", "cpp")
        self.assertEqual((document, binding["attempt_id"], gap), (result, envelope["attempt_id"], None))
        # A changed database is a consumer-side gap, never a silent reuse.
        (store / "db-cpp" / "default.trap").write_text("changed\n")
        self.assertIsNone(worker.verify_database("run-codeql", database))
        # Tampering with the retained SARIF is caught on re-validation.
        sarif = attempt / "tools" / "codeql-cpp" / "scratch" / "codeql.sarif"
        sarif.write_bytes(sarif.read_bytes().replace(b"cpp/double-free", b"cpp/double-freX"))
        with self.assertRaises(worker.Blocked):
            worker.validate("run-codeql", "cpp")

    def test_timeout_is_a_gap_and_the_killed_database_is_dropped(self):
        envelope = worker.run("run-codeql", "dagster-1", "python")
        self.assertEqual(envelope["status"], "OK_WITH_GAPS")
        attempt = worker.root("run-codeql", "python") / "attempts" / envelope["attempt_id"]
        result = json.loads((attempt / worker.RESULT).read_text())
        self.assertEqual((result["tools"], result["databases"]), ([], []))
        self.assertIn("CodeQL python ended TIMEOUT; no CodeQL leads for python.", result["coverage_gaps"])
        receipts = json.loads((attempt / worker.RECEIPTS).read_text())["tools"]
        self.assertIsNone(receipts[0]["raw_result_sha256"])
        self.assertFalse((attempt / "tools" / "codeql-python" / "scratch" / "db").exists())
        self.assertEqual(worker.validate("run-codeql", "python"), attempt)

    def test_absent_language_publishes_skipped(self):
        envelope = worker.run("run-codeql", "dagster-1", "java")
        self.assertEqual((envelope["status"], envelope["reason"]), ("SKIPPED", "not-applicable-language-absent"))
        attempt = worker.root("run-codeql", "java") / "attempts" / envelope["attempt_id"]
        self.assertEqual(json.loads((attempt / worker.RESULT).read_text())["status"], "SKIPPED")
        self.assertEqual(worker.validate("run-codeql", "java"), attempt)
        document, binding, gap = worker.load_accepted("run-codeql", "java")
        self.assertEqual((document["status"], binding["status"], gap), ("SKIPPED", "SKIPPED", None))
        self.assertEqual(worker.load_accepted("run-codeql", "ruby")[2], "engine-input-absent:02-codeql-ruby")


class CodeqlTracedScriptedPublishTests(CodeqlSastScriptedPublishTests):
    """run() with an accepted native build wired in: build-mode none cpp plus one traced unit."""

    def setUp(self):
        super().setUp()
        record = {**json.loads((self.images / "audit-codeql.json").read_text()), "image_id": worker.TRACED_IMAGE_ID,
                  "repository": "docker.io/library/audit-codeql-native"}
        (self.images / "audit-codeql-native.json").write_text(json.dumps(record))
        self.native_root = Path(self.temporary.name).resolve() / "native-build"
        self.native_root.mkdir()
        binding = {"job_id": "02-native-build", "attempt_id": "a1", "fingerprint": "sha256:" + "e" * 64}
        self.loader = mock.patch.object(worker, "load_native_units", return_value=(binding, UNITS))
        self.loader.start()
        (Path(self.temporary.name).resolve() / "target" / "tool.py").unlink()

    def tearDown(self):
        self.loader.stop()
        super().tearDown()

    def wired(self):
        return {"native_build_root": self.native_root, "native_build_fingerprint": "sha256:" + "e" * 64}

    def test_timeout_is_a_gap_and_the_killed_database_is_dropped(self):
        self.skipTest("python is absent from the traced fixture")

    def test_native_build_state_reads_the_accepted_pointer(self):
        self.assertEqual(worker.native_build_state("run-codeql")[2], "no accepted 02-native-build publication")
        base = execution_state.data_path("run-codeql", "jobs", "02-native-build"); base.mkdir(parents=True)
        (base / "accepted.json").write_text(json.dumps({"status": "SKIPPED", "reason": "not-applicable-non-native"}))
        self.assertEqual(worker.native_build_state("run-codeql"),
                         (None, None, "02-native-build SKIPPED (not-applicable-non-native)"))
        (base / "accepted.json").write_text(json.dumps({"status": "OK", "fingerprint": "sha256:" + "e" * 64}))
        self.assertEqual(worker.native_build_state("run-codeql"), (base, "sha256:" + "e" * 64, None))

    def test_publishes_ok_with_gaps_and_revalidates(self):
        original_outcome = worker._outcome

        def outcome(row, trial, terminal, target, job="02-codeql"):
            # Stand in for the traced lane's replay counts and one decoded graph table.
            if row.get("build_mode") == "traced":
                scratch = trial / "scratch"
                scratch.mkdir(exist_ok=True)
                if not (scratch / "replay.json").exists():
                    (scratch / "replay.json").write_text(json.dumps({"total": 1, "ok": 1, "failed": 0, "refused": 0}))
                    (scratch / "graph").mkdir(exist_ok=True)
                    (scratch / "graph" / "CallEdges.csv").write_text('"caller_name"\n"main"\n')
            return original_outcome(row, trial, terminal, target, job)

        with mock.patch.object(worker, "_outcome", side_effect=outcome):
            envelope = worker.run("run-codeql", "dagster-1", "cpp", **self.wired())
        self.assertEqual(envelope["status"], "OK_WITH_GAPS")
        attempt = worker.root("run-codeql", "cpp") / "attempts" / envelope["attempt_id"]
        result = json.loads((attempt / worker.RESULT).read_text())
        self.assertEqual([row["tool_id"] for row in result["tools"]], ["codeql-cpp", "codeql-cpp-traced"])
        self.assertEqual(result["build_modes"], ["none", "traced"])
        self.assertFalse(any(gap.startswith("language not built") for gap in result["coverage_gaps"]))
        traced = result["tools"][1]
        self.assertEqual((traced["unit_id"], traced["replay"]), ("unit-a", {"total": 1, "ok": 1, "failed": 0, "refused": 0}))
        self.assertEqual({row["tool_id"] for row in result["leads"]}, {"codeql-cpp", "codeql-cpp-traced"})
        self.assertEqual([(row["build_mode"], row["unit_id"]) for row in result["databases"]],
                         [("none", None), ("traced", "unit-a")])
        self.assertTrue(result["databases"][1]["store_path"].endswith("/codeql-cpp-traced-0123456789abcdef"))
        adapted = attempt / "adapted-inputs" / "0123456789abcdef" / "compile_commands.json"
        self.assertEqual(json.loads(adapted.read_text()), UNITS[0]["adapted"])
        receipts = {row.get("plan_key", row["language"]): row for row in
                    json.loads((attempt / worker.RECEIPTS).read_text())["tools"]}
        graph = receipts["codeql-cpp-traced:0123456789abcdef"]["graph_outputs"]
        self.assertIsNotNone(graph["CallEdges.ql"])
        self.assertIsNone(graph["EntryPoints.ql"])
        request = json.loads((attempt / "tools" / "codeql-cpp-traced-0123456789abcdef" / "logs" / "container" /
                              ce.REQUEST_FILE).read_text())
        self.assertEqual(request["image"]["image_id"], "audit-codeql-native")
        self.assertEqual(worker.validate("run-codeql", "cpp", **self.wired()), attempt)
        csv = attempt / "tools" / "codeql-cpp-traced-0123456789abcdef" / "scratch" / "graph" / "CallEdges.csv"
        csv.write_text('"caller_name"\n"other"\n')
        with self.assertRaises(worker.Blocked):
            worker.validate("run-codeql", "cpp", **self.wired())
        with self.assertRaisesRegex(worker.Blocked, "graph tables differ"):
            worker._validate_attempt("run-codeql", attempt,
                                     worker.current_inputs("run-codeql", "cpp", **self.wired()))


if __name__ == "__main__":
    unittest.main()
