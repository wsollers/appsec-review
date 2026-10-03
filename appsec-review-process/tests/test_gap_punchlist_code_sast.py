"""Acceptance tests for gap punch list P07-P15 (hello-autotools, 2026-10-03): code index, CPG,
CodeQL, native SAST, source SAST and tree-sitter coverage gaps that should not be reported as gaps.

Each test encodes the behaviour after the fix and is an expected failure until it lands.
See docs/TODO/gap-punchlist-hello-autotools-2026-10-03.md.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import registry_paths  # noqa: E402,F401

import code_graph_evidence as cpg  # noqa: E402
import code_query_fixture as fx  # noqa: E402
import codeql_sast  # noqa: E402
import native_sast  # noqa: E402
import native_sast_adapters  # noqa: E402
import source_sast  # noqa: E402
import source_sast_language_adapters as language_adapters  # noqa: E402
import treesitter_ast  # noqa: E402
from execution_state import atomic_json, file_hash  # noqa: E402
from test_codeql_sast import FIXTURE as CODEQL_FIXTURE, SARIF, _inputs, _plan, _traced  # noqa: E402
import test_native_sast as native_tests  # noqa: E402
from test_native_sast import FIXTURE as NATIVE_FIXTURE, VARIANT, trial_tree  # noqa: E402

SHA = "sha256:" + "1" * 64


class CodeGraphEvidenceGaps(unittest.TestCase):
    """P07, P08: 02-code-property-graph normalisation."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        (self.target / "src").mkdir(parents=True)
        (self.target / "src/main.c").write_text(
            "int copy(char *d, char *s) { strcpy(d, s); return 0; }\nint main(void) { return copy(0, 0); }\n",
            encoding="utf-8")
        self.raw = self.root / "records.jsonl"

    def tearDown(self):
        self.temp.cleanup()

    def row(self, **changes):
        value = {"kind": "call", "label": "CALL", "name": "strcpy", "full_name": "strcpy",
                 "caller": "copy:int(char*,char*)", "type_name": "ANY", "file": "/workspace/src/main.c",
                 "line": 1, "column": 30, "code": "strcpy(d, s)"}
        value.update(changes)
        return value

    def normalize(self, *rows):
        self.raw.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        return cpg.normalize_jsonl(self.raw, target=self.target, run_id="run-1",
            source_snapshot_sha256=SHA, source_revision="abc123", image_id="audit-native",
            image_digest=SHA, exporter_sha256=SHA, build_identity_sha256=SHA)

    def test_p07_external_method_stub_is_not_a_location_gap(self):
        """P07: a location-less METHOD stub (<operator>.*) is not a no-source-location gap; a location-less CALL is."""
        stub = self.row(kind="symbol", label="METHOD", name="<operator>.assignment",
                        full_name="<operator>.assignment", caller="", type_name="", file="<empty>",
                        line=None, column=None, code="<empty>")
        document = self.normalize(self.row(), stub)
        reasons = [gap["reason"] for gap in document["coverage_gaps"]]
        self.assertNotIn("no-source-location", reasons,
                         "external METHOD stub without a location is counted as a no-source-location gap")
        self.assertEqual(document["status"], "OK")
        document = self.normalize(self.row(), self.row(file="<empty>", line=None, column=None))
        self.assertIn({"reason": "no-source-location", "count": 1}, document["coverage_gaps"])

    def test_p08_duplicate_rows_are_info_not_a_gap(self):
        """P08: identical exporter rows are deduplicated without setting OK_WITH_GAPS or a duplicate gap."""
        document = self.normalize(self.row(), self.row())
        self.assertEqual(document["record_count"], 1)
        self.assertNotEqual(document["status"], "OK_WITH_GAPS",
                            "deduplicated macro-expansion rows set OK_WITH_GAPS")
        self.assertNotIn("duplicate", [gap["reason"] for gap in document["coverage_gaps"]])


class CodeIndexGaps(unittest.TestCase):
    """P09, P10: 02-code-index hard-coded gaps."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_p09_unbound_ir_and_debug_sources_are_not_reported_as_not_indexed(self):
        """P09: with no accepted 02-ir-facts / 02-debug-symbol-index source, no source-not-indexed gap is emitted."""
        _, result = fx.build(self.folder)
        self.assertNotIn("source-not-indexed:02-ir-facts", result["gaps"],
                         "source-not-indexed:02-ir-facts is hard-coded although no IR source was bound")
        self.assertNotIn("source-not-indexed:02-debug-symbol-index", result["gaps"])

    def test_p09_code_index_has_optional_edges_to_ir_and_debug_jobs(self):
        """P09: job-graph gives 02-code-index (optional) dependencies on 02-ir-facts and 02-debug-symbol-index."""
        graph = json.loads((ROOT / "pipeline" / "job-graph.json").read_text(encoding="utf-8"))
        dependencies = {row["job"] for row in graph["jobs"]["02-code-index"]["dependencies"]}
        self.assertIn("02-ir-facts", dependencies, "02-code-index has no edge to 02-ir-facts")
        self.assertIn("02-debug-symbol-index", dependencies)

    def test_p10_inheritance_records_clear_the_no_inheritance_gap(self):
        """P10: an INHERITS type record fills type_edges and the no-inheritance-edges gap is not emitted."""
        inherits = {**fx.type_decl("Button", "ui.Button", "src/widget.cpp", 12),
                    "label": "INHERITS", "type_name": "ui.Widget", "code": "class Button : public Widget"}
        records, summary = fx.write_cpg(self.folder, records=fx.RECORDS + [inherits])
        import code_index
        result = code_index.build(self.folder / code_index.SQLITE, records=records, cpg_summary=summary,
                                  sources={"cpg": {"job": "02-code-property-graph", "attempt_id": "cpg1",
                                                   "records_sha256": summary["records_file"]["sha256"]}},
                                  treesitter=fx.TREESITTER, export_tables=fx.EXPORTS)
        self.assertNotIn("cpg-exporter:no-inheritance-edges", result["gaps"],
                         "no-inheritance-edges is hard-coded although an INHERITS record was exported")
        self.assertTrue(result["capabilities"]["type_edges"])

    def test_p10_exporter_walks_inheritance_and_method_refs(self):
        """P10: the Joern exporter walks inheritsFromTypeFullName and cpg.methodRef."""
        exporter = (REPO / "pipeline" / "joern_export_records.sc").read_text(encoding="utf-8")
        self.assertTrue("inheritsFromTypeFullName" in exporter,
                        "joern_export_records.sc does not walk inheritsFromTypeFullName")
        self.assertTrue("methodRef" in exporter, "joern_export_records.sc does not walk cpg.methodRef")


class CodeqlFidelityGap(unittest.TestCase):
    @unittest.expectedFailure
    def test_p11_traced_success_replaces_build_mode_none_fidelity_gap(self):
        """P11: when a traced cpp row succeeded, the build-mode-none fidelity gap is not in coverage_gaps."""
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder).resolve()
            shutil.copy(CODEQL_FIXTURE / "source-sast-c" / "vuln.c", target / "vuln.c")
            leads, dropped = codeql_sast.normalize_sarif("cpp", SARIF.read_bytes(), target,
                                                         tool_id="codeql-cpp-traced")
        replay = {"total": 4, "ok": 4, "failed": 0, "refused": 0}
        outcomes = {"cpp": {"gap": None, "leads": [], "dropped": 0},
                    "codeql-cpp-traced:0123456789abcdef": {"gap": None, "leads": leads, "dropped": dropped,
                                                           "replay": replay}}
        result = codeql_sast.assemble(run_id="run", attempt_id="attempt", inputs=_inputs(_plan() + _traced()),
                                      outcomes=outcomes)
        self.assertNotIn(codeql_sast.FIDELITY_GAPS["cpp"], result["coverage_gaps"],
                         "build-mode-none fidelity gap reported although traced units ran")


class NativeSastCompileErrors(unittest.TestCase):
    IMAGE = native_tests.NativeSastTests.IMAGE

    @unittest.expectedFailure
    def test_p12_compile_errors_are_not_tool_errors(self):
        """P12: clang-tidy files_compile_error yields clang-tidy-compile-error:<n>, not clang-tidy-tool-error."""
        with tempfile.TemporaryDirectory() as folder:
            attempt = Path(folder, "attempt"); attempt.mkdir()
            target = Path(folder, "target"); shutil.copytree(NATIVE_FIXTURE / "target", target)
            clang, csa = trial_tree(attempt)
            manifest_path = clang / "scratch/native-sast/native-sast-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["clang_tidy"]["files_nonzero_exit"] = 1
            manifest["clang_tidy"]["files_compile_error"] = 1
            atomic_json(manifest_path, manifest)
            adapted, unsupported = native_sast_adapters.adapt_compile_database(
                json.loads((NATIVE_FIXTURE / "compile_commands.json").read_text()))
            unit = {"unit_id": "dir:.", "build_variant": VARIANT,
                    "compile_database": {"path": "db", "sha256": "sha256:" + "1" * 64, "entries": 2,
                                         "adapted_path": "adapted-inputs/0123456789abcdef/compile_commands.json",
                                         "adapted_sha256": native_sast_adapters.canonical_sha(adapted)},
                    "adapted": adapted, "unsupported": unsupported}
            inputs = {"image": self.IMAGE, "config": json.loads(native_sast.CONFIG.read_text()),
                      "config_sha256": "sha256:" + file_hash(native_sast.CONFIG)}
            result = native_sast.normalize_unit(unit, target=target, attempt=attempt,
                                                clang_trial=clang, csa_trial=csa, inputs=inputs)
        gaps = result["coverage_gaps"]
        self.assertFalse([gap for gap in gaps if gap.startswith("clang-tidy-tool-error")],
                         f"compile errors reported as clang-tidy tool errors: {gaps}")
        self.assertTrue(any(gap.startswith("clang-tidy-compile-error:1") for gap in gaps))

    @unittest.expectedFailure
    def test_p12_runner_classifies_clang_diagnostic_error_exit_as_compile_error(self):
        """P12: run_native_sast.py counts rc=1 with clang-diagnostic-error as files_compile_error, not a tool error."""
        path = REPO / "images/audit-native/scripts/run_native_sast.py"
        spec = importlib.util.spec_from_file_location("run_native_sast_p12", path)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        stderr = ("/workspace/src/hello.c:1:10: error: 'config.h' file not found [clang-diagnostic-error]\n"
                  "#include \"config.h\"\n")

        def fake_run(cmd, **kwargs):
            if cmd[0] == "clang-tidy":
                return types.SimpleNamespace(returncode=1, stdout="", stderr=stderr)
            return types.SimpleNamespace(returncode=0, stdout="", stderr="<results/>")

        with tempfile.TemporaryDirectory() as folder:
            compdb = Path(folder, "compile_commands.json")
            compdb.write_text(json.dumps([{"directory": folder, "file": "src/hello.c",
                                           "command": "cc -c src/hello.c"}]), encoding="utf-8")
            out = Path(folder, "out")
            argv = ["run_native_sast.py", "--compile-commands", str(compdb), "--out", str(out), "--jobs", "1"]
            with mock.patch.object(runner.subprocess, "run", side_effect=fake_run), \
                    mock.patch.object(sys, "argv", argv), mock.patch("builtins.print"):
                runner.main()
            manifest = json.loads((out / "native-sast-manifest.json").read_text())
        self.assertEqual(manifest["clang_tidy"].get("files_compile_error"), 1,
                         "clang-diagnostic-error exit is not counted as a compile error")
        self.assertEqual(manifest["clang_tidy"]["files_nonzero_exit"]
                         - manifest["clang_tidy"]["files_compile_error"], 0)


class SourceSastCoverage(unittest.TestCase):
    @unittest.expectedFailure
    def test_p13_repository_rules_include_a_taint_rule(self):
        """P13: rules-v1.yml has a mode: taint rule with a known category, and RULES_GAP no longer denies taint."""
        import yaml
        rules = yaml.safe_load(source_sast.RULES.read_text(encoding="utf-8"))["rules"]
        taint = [rule["id"] for rule in rules if rule.get("mode") == "taint"]
        self.assertTrue(taint, "no repository-owned Semgrep rule uses mode: taint")
        self.assertTrue(set(taint) <= set(source_sast.RULE_CATEGORIES))
        self.assertNotIn("do not cover taint", source_sast.RULES_GAP)

    @unittest.expectedFailure
    def test_p14_shell_has_a_shellcheck_plan_row_and_no_uncovered_gap(self):
        """P14: a target with tests/run.sh gets a shellcheck plan row and no 'no static analyzer' shell gap."""
        paths = ["tests/run.sh", "src/hello.c"]
        gaps = language_adapters.uncovered_language_gaps(paths)
        self.assertFalse([gap for gap in gaps if gap.startswith("shell ")],
                         f"shell source is still an uncovered language gap: {gaps}")
        self.assertIn("shell", language_adapters.detected_languages(paths))
        registry = {"tool-shellcheck": {"image_id": "tool-shellcheck", "digest": "sha256:" + "a" * 64}}
        plan = language_adapters.build_plan(["shell"], registry)
        self.assertEqual([row["tool_id"] for row in plan], ["shellcheck"])
        self.assertEqual(plan[0]["hit_exit_codes"], [1])


class TreesitterNonSource(unittest.TestCase):
    @unittest.expectedFailure
    def test_p15_build_and_doc_files_are_not_no_grammar_gaps(self):
        """P15: Makefile.am, configure.ac, README.md and friends are non-source info, not no-grammar gaps."""
        fake = types.SimpleNamespace(Language=lambda value: value, Parser=lambda language: None)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ("Makefile.am", "configure.ac", "README.md", "Makefile", "configure", "m4/ax.m4",
                         "config.h.in"):
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text("x\n", encoding="utf-8")
            scan = treesitter_ast.Scan(root, tree_sitter=fake, label="fixture")
            list(scan.records())
        no_grammar = [gap for gap in scan.gaps if gap["kind"] == "no-grammar"]
        self.assertEqual(no_grammar, [], "autotools/doc files are reported as no-grammar gaps")


if __name__ == "__main__":
    unittest.main()
