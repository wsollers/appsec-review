"""Exported-symbol and CodeQL entry points for reachability (brief Q): unique joins only, escapes, gaps."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import dep_reachability_engines as engines
import entry_exports as ex
import finding_enrichment as enrichment
import reachability as r
import synthesis_report_presentation as presentation
from test_reachability import call, graph, method
import test_report_finding_enrichment as fe

LIB = "lib/api.c"


def library(extra=()):
    """``api_parse`` (exported) -> ``decode`` -> strcpy; ``internal`` (static, never exported) -> memcpy."""
    return r.CallGraph.from_records([
        method("api_parse:int(char*)", "api_parse", LIB, 1, 10),
        method("decode:void(char*)", "decode", LIB, 12, 20),
        method("internal:void()", "internal", LIB, 22, 30),
        call("api_parse:int(char*)", "decode:void(char*)", "decode", LIB, 5),
        call("decode:void(char*)", "<unresolvedNamespace>.strcpy:<unresolvedSignature>(2)", "strcpy", LIB, 15),
        call("internal:void()", "<unresolvedNamespace>.memcpy:<unresolvedSignature>(3)", "memcpy", LIB, 25),
        *extra])


def row(symbol, demangled=None, binding="GLOBAL", visibility="DEFAULT", hidden=False):
    return {"symbol": symbol, "demangled": symbol if demangled is None else demangled, "binding": binding,
            "visibility": visibility, "version_hidden": hidden}


def block(*rows, kind="shared-library", complete=True, gaps=()):
    return {"schema": ex.EXPORTS_SCHEMA, "format": "elf", "artifact_kind": kind, "table": ".dynsym",
            "complete": complete, "gaps": list(gaps), "functions": list(rows)}


def table(*rows, **kw):
    return ex.export_table(block(*rows, **kw), artifact="libapi.so", binary_sha256="sha256:" + "b" * 64)


class ExportJoinTests(unittest.TestCase):
    def test_unique_join_is_an_exported_symbol_root_with_witness_label(self):
        g = library()
        extra = ex.join_exports(g, [table(row("api_parse"))])
        self.assertEqual(list(extra.roots), ["api_parse:int(char*)"])
        result = r.assess_location(g, LIB, 15, extra=extra)
        self.assertEqual(result["state"], r.REACHABLE)
        self.assertEqual([step["function"] for step in result["witness"]], ["api_parse", "decode", "(finding location)"])
        self.assertEqual(result["entry_point"]["label"], "exported-symbol")
        self.assertEqual((result["entry_point"]["artifact"], result["entry_point"]["symbol"]), ("libapi.so", "api_parse"))
        self.assertEqual(result["witness"][0]["entry"]["label"], "exported-symbol")
        self.assertIn("exported-symbol: api_parse in libapi.so", result["reason"])
        # Nothing else changed: the static function is still proven UNREACHABLE.
        self.assertEqual(r.assess_location(g, LIB, 25, extra=extra)["state"], r.UNREACHABLE)
        # Without the export the library is rootless: UNKNOWN, never a guessed path.
        self.assertEqual(r.assess_location(g, LIB, 15)["state"], r.UNKNOWN)

    def test_an_export_that_is_a_program_entry_keeps_its_plain_witness(self):
        g = graph()
        extra = ex.join_exports(g, [table(row("main"))])
        result = r.assess_location(g, "app/parse.c", 25, extra=extra)
        self.assertEqual(result["witness"][0]["function"], "main")
        self.assertNotIn("label", result["entry_point"])
        self.assertEqual(result["extra_entries"], {"roots": 1, "escapes": 0, "gaps": []})

    def test_ambiguous_join_is_an_escape_and_never_an_entry(self):
        overload = method("fx.overload:int(char*)", "overload", LIB, 40, 42)
        other = method("fx.overload:int(int)", "overload", LIB, 44, 46)
        sink = call("fx.overload:int(char*)", "<unresolvedNamespace>.memcpy:<unresolvedSignature>(3)", "memcpy", LIB, 41)
        g = library([overload, other, sink])
        extra = ex.join_exports(g, [table(row("api_parse"), row("_ZN2fx8overloadEPKc", "fx::overload(char const*)"),
                                          row("_ZN2fx8overloadEi", "fx::overload(int)"))])
        self.assertEqual(list(extra.roots), ["api_parse:int(char*)"])
        self.assertEqual([item["reason"] for item in extra.escapes], ["ambiguous-export", "ambiguous-export"])
        result = r.assess_location(g, LIB, 41, extra=extra)
        self.assertEqual(result["state"], r.UNKNOWN)
        self.assertEqual(result["escapes"][0]["reason"], "ambiguous-export")
        self.assertIn("no entry was assumed", result["reason"])

    def test_missing_symbol_is_a_coverage_gap_not_a_root(self):
        g = library()
        extra = ex.join_exports(g, [table(row("api_parse"), row("not_in_cpg"))])
        self.assertEqual(list(extra.roots), ["api_parse:int(char*)"])
        self.assertIn("export-symbol-not-in-cpg:libapi.so:1", extra.gaps)
        result = r.assess_location(g, LIB, 25, extra=extra)
        self.assertEqual(result["state"], r.UNKNOWN)
        self.assertIn("export-symbol-not-in-cpg", result["reason"])

    def test_hidden_local_and_static_functions_are_never_roots(self):
        g = library([method("dir/lib/api.c:helper:void()", "helper", LIB, 50, 52)])
        extra = ex.join_exports(g, [table(row("internal", visibility="HIDDEN"), row("decode", binding="LOCAL"),
                                          row("api_parse", visibility="INTERNAL"), row("helper"))])
        self.assertEqual(extra.roots, {})
        # A file-scoped CPG method (internal linkage) cannot be what a library exports: a gap, not a root.
        self.assertIn("export-symbol-not-in-cpg:libapi.so:1", extra.gaps)
        self.assertEqual(table(row("internal", visibility="HIDDEN"))["exports"], [])

    def test_unjoinable_names_are_gaps(self):
        names = [row("_ZN1CclEv", "C::operator()()"), row("_Z3maxIiET_S0_S0_", "int max<int>(int, int)"),
                 row("_ZThn8_N1B1fEv", "non-virtual thunk to B::f()"), row("?f@@YAHXZ", None),
                 row("_ZN1C1fEv", None)]
        self.assertEqual([ex.export_qualified(item) for item in names], [None] * 5)
        self.assertEqual(ex.export_qualified(row("_ZN2ns1C1mEi", "ns::C::m(int) const")), "ns.C.m")
        extra = ex.join_exports(library(), [table(*names)])
        self.assertEqual(extra.gaps, ("export-symbol-unjoinable:libapi.so:5",))

    def test_shipped_library_without_a_complete_export_table_is_unknown_never_unreachable(self):
        g = library([method("main:int(int,char**)", "main", "app/main.c", 1, 5),
                     call("main:int(int,char**)", "api_parse:int(char*)", "api_parse", "app/main.c", 3)])
        self.assertEqual(r.assess_location(g, LIB, 25)["state"], r.UNREACHABLE)          # tunable off
        complete = ex.join_exports(g, [table(row("api_parse"))])
        self.assertEqual(r.assess_location(g, LIB, 25, extra=complete)["state"], r.UNREACHABLE)
        for tables, gaps in (([table(row("api_parse"), complete=False, gaps=["export-table-truncated"])], ()),
                             ([table(row("api_parse"), complete=False)], ()),
                             ([table(row("api_parse", hidden=True))], ()),
                             ([ex.export_table(None, artifact="libapi.so", binary_sha256=None)], ()),
                             ([ex.export_table({"schema": ex.EXPORTS_SCHEMA}, artifact="x", binary_sha256=None)], ()),
                             ([], ["export-facts-missing:02-binary-triage"])):
            extra = ex.join_exports(g, tables, gaps)
            result = r.assess_location(g, LIB, 25, extra=extra)
            self.assertEqual(result["state"], r.UNKNOWN, tables)
            self.assertIn("entry facts are incomplete", result["reason"])
            # a proven path stays proven
            self.assertEqual(r.assess_location(g, LIB, 15, extra=extra)["state"], r.REACHABLE)
        # An executable's exports are not a library interface: no roots, no gap.
        exe = ex.join_exports(g, [table(row("api_parse"), kind="executable")])
        self.assertEqual((exe.roots, exe.gaps), ({}, ()))
        self.assertEqual(r.assess_location(g, LIB, 25, extra=exe)["state"], r.UNREACHABLE)

    def test_malformed_rows_give_an_incomplete_table(self):
        bad = dict(row("api_parse"), extra="x")
        self.assertEqual(ex.export_table(block(bad), artifact="a", binary_sha256=None)["gaps"], ["export-row-invalid"])
        self.assertFalse(ex.export_table(block(bad), artifact="a", binary_sha256=None)["complete"])


class TriageEvidenceTests(unittest.TestCase):
    def write_attempt(self, attempt: Path, summary: dict, tamper: bool = False) -> None:
        trial = attempt / "tools/0001/scratch/evidence"; trial.mkdir(parents=True)
        data = json.dumps(summary).encode()
        (trial / "summary.json").write_bytes(data)
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        (attempt / ex.RECEIPT_FILE).write_text(json.dumps({"operations": [
            {"binary_id": "bin-1", "binary_sha256": "sha256:" + "c" * 64, "trial_path": "tools/0001",
             "output_files": [{"path": ex.SUMMARY_OUTPUT, "sha256": digest}]}]}))
        if tamper:
            (trial / "summary.json").write_bytes(data + b" ")

    def test_tables_are_read_from_hash_bound_summaries(self):
        with tempfile.TemporaryDirectory() as directory:
            attempt = Path(directory)
            self.write_attempt(attempt, {"path": "/inputs/build/libapi.so", "dynamic_exports": block(row("api_parse"))})
            tables, gaps = ex.tables_from_triage(attempt)
            self.assertEqual(gaps, [])
            self.assertEqual((tables[0]["artifact"], tables[0]["complete"]), ("libapi.so", True))
            self.assertEqual(tables[0]["exports"], [{"symbol": "api_parse", "demangled": "api_parse"}])

    def test_tampered_or_old_summaries_are_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            attempt = Path(directory) / "a"
            self.write_attempt(attempt, {"path": "/x/libapi.so", "dynamic_exports": block(row("api_parse"))}, tamper=True)
            tables, gaps = ex.tables_from_triage(attempt)
            self.assertEqual(gaps, ["export-evidence-unverified:bin-1"])
            self.assertFalse(tables[0]["complete"])
            old = Path(directory) / "b"
            self.write_attempt(old, {"path": "/x/libapi.so", "format": "elf"})   # image before brief Q
            tables, _ = ex.tables_from_triage(old)
            self.assertEqual(tables[0]["gaps"], ["export-table-missing"])
            self.assertEqual(ex.tables_from_triage(Path(directory) / "none"),
                             ([], ["export-facts-missing:02-binary-triage:receipt"]))


class CodeqlEntryTests(unittest.TestCase):
    ROWS = [{"name": "handle", "file": "app/parse.c", "line": "1", "reason": "route-handler"},
            {"name": "copy", "file": "app/parse.c", "line": "22", "reason": "remote-flow-source"},
            {"name": "dead", "file": "app/dead.c", "line": "1", "reason": "no-internal-caller"}]

    def test_rows_join_by_definition_on_the_same_snapshot(self):
        g = graph()
        extra = ex.join_codeql_entries(g, self.ROWS, graph_snapshot="sha256:s", rows_snapshot="sha256:s")
        self.assertEqual(list(extra.roots), ["parse:void(char*)"])
        self.assertEqual(extra.roots["parse:void(char*)"]["reason"], "route-handler")
        # remote-flow-source and no-internal-caller are not entries: dead stays UNREACHABLE.
        self.assertEqual(r.assess_location(g, "app/dead.c", 3, extra=extra)["state"], r.UNREACHABLE)

    def test_snapshot_mismatch_ambiguity_and_absence_never_root(self):
        g = graph([method("parse2:void()", "parse2", "app/parse.c", 1, 3)])
        self.assertEqual(ex.join_codeql_entries(g, self.ROWS, graph_snapshot="a", rows_snapshot="b").gaps,
                         ("codeql-entry-snapshot-mismatch:1",))
        ambiguous = ex.join_codeql_entries(g, self.ROWS, graph_snapshot="a", rows_snapshot="a")
        self.assertEqual((ambiguous.roots, ambiguous.escapes[0]["reason"]), ({}, "ambiguous-codeql-entry"))
        absent = ex.join_codeql_entries(graph(), [dict(self.ROWS[0], line="7")], graph_snapshot="a", rows_snapshot="a")
        self.assertEqual((absent.roots, absent.gaps), ({}, ("codeql-entry-not-in-cpg:1",)))

    def test_cpg_engine_takes_extra_roots(self):
        g = library()
        query = engines.Query("m1", "cpp", "pkg", [{"symbol": "strcpy"}])
        self.assertEqual(engines.CpgEngine(g).assess(query)["state"], engines.UNKNOWN)
        extra = ex.join_exports(g, [table(row("api_parse"))])
        self.assertEqual(engines.CpgEngine(g, extra).assess(query)["state"], engines.REACHABLE)


class DefaultOffTests(unittest.TestCase):
    # sha256 of the golden scenarios below computed with reachability.py before brief Q.
    GOLDEN = "sha256:4c9a4ebbc8d9d9854efdcdd8fe6892188565a451236fa587af1a02f41a9421eb"

    def scenarios(self):
        out, g = {}, graph()
        for line in (25, 3, 12, 99):
            out[f"parse:{line}"] = r.assess_location(g, "app/parse.c", line)
        out["dead"] = r.assess_location(g, "app/dead.c", 3)
        pointer = call("parse:void(char*)", "<operator>.pointerCall", "<operator>.pointerCall", "app/parse.c", 13)
        out["escape"] = r.assess_location(graph([pointer]), "app/dead.c", 3)
        out["gap"] = r.assess_location(graph(gaps=[{"reason": "no-source-location", "count": 3}]), "app/dead.c", 3)
        out["extra-name"] = r.assess_location(g, "app/dead.c", 3, ["dead"])
        out["symbols"] = r.assess_symbols(g, [{"symbol": "strcpy"}, {"symbol": "memcpy"}], g.entry_points())
        return out

    def test_results_are_byte_identical_without_extra_entries(self):
        text = json.dumps(self.scenarios(), sort_keys=True).encode()
        self.assertEqual("sha256:" + hashlib.sha256(text).hexdigest(), self.GOLDEN)

    def test_tunables_default_off_and_bindings_unchanged(self):
        self.assertFalse(ex.enabled("reachability_export_entries"))
        self.assertFalse(ex.enabled("reachability_codeql_entries"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fe.write_run(root)
            self.assertNotIn("export_entries", enrichment.input_bindings(root))
            report = fe.report_with([fe.finding("claim-orphan", 13, "CRITICAL")])
            off = enrichment.build(report, root, snapshot_dir=root / "none")
            self.assertEqual(off["findings"][0]["reachability"]["state"], r.UNREACHABLE)
            self.assertNotIn("extra_entries", off["findings"][0]["reachability"])

    def test_fuzz_harness_entry_is_absent_from_the_shared_table(self):
        self.assertIs(engines.ENTRY_POINT_SOURCES["cpp"]["names"], r.PROGRAM_ENTRY_NAMES)
        for names in (r.PROGRAM_ENTRY_NAMES, *(row["names"] for row in engines.ENTRY_POINT_SOURCES.values())):
            self.assertNotIn("LLVMFuzzerTestOneInput", names)


class EnrichmentWiringTests(unittest.TestCase):
    def run_with(self, root: Path, summary: dict | None) -> dict:
        if summary is not None:
            attempt = root / "data/jobs/02-binary-triage/attempts/t-1"
            TriageEvidenceTests().write_attempt(attempt, summary)
            (root / "data/jobs/02-binary-triage/accepted.json").write_text(
                json.dumps({"attempt_id": "t-1", "status": "OK_WITH_GAPS"}))
        report = fe.report_with([fe.finding("claim-orphan", 13, "CRITICAL")])
        with mock.patch.object(ex, "enabled", lambda name: name == "reachability_export_entries"):
            self.assertIn("export_entries", enrichment.input_bindings(root))
            return enrichment.build(report, root, snapshot_dir=root / "none")["findings"][0]

    def test_on_export_roots_the_library_function(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fe.write_run(root)
            row = self.run_with(root, {"path": "/b/libapp.so", "dynamic_exports": block(row_("orphan"))})
            self.assertEqual(row["reachability"]["state"], r.REACHABLE)
            self.assertEqual(row["reachability"]["entry_point"]["label"], "exported-symbol")
            self.assertEqual(row["severity"]["final"], "CRITICAL")
            text = presentation._reachability_text(row["reachability"], None)
            self.assertTrue(text.endswith("[entry: exported-symbol orphan in libapp.so]"), text)

    def test_on_without_triage_evidence_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fe.write_run(root)
            row = self.run_with(root, None)
            self.assertEqual((row["reachability"]["state"], row["severity"]["final"]), (r.UNKNOWN, "HIGH"))
            self.assertIn("export-facts-missing", row["reachability"]["reason"])


row_ = row


if __name__ == "__main__":
    unittest.main()


def _producer():
    """images/audit-binary-analysis/scripts/binary-summary.py with its image-only imports stubbed."""
    import importlib.util, types
    for name in ("lief", "pefile"):
        sys.modules.setdefault(name, types.ModuleType(name))
    spec = importlib.util.spec_from_file_location(
        "binary_summary", ROOT.parent / "images/audit-binary-analysis/scripts/binary-summary.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def _have(*tools):
    import shutil
    try:
        import elftools  # noqa: F401
    except ImportError:
        return False
    return all(shutil.which(tool) for tool in tools)


@unittest.skipUnless(_have("g++", "c++filt"), "needs g++, c++filt and pyelftools (the smoke test runs it in the image)")
class ProducerTests(unittest.TestCase):
    def test_dynsym_exports_exclude_static_and_hidden(self):
        import subprocess
        producer = _producer()
        from elftools.elf.elffile import ELFFile
        with tempfile.TemporaryDirectory() as directory:
            library = Path(directory) / "libentry.so"
            subprocess.run(["g++", "-shared", "-fPIC", "-O0", "-fvisibility=hidden", "-o", str(library),
                            str(ROOT.parent / "images/test/entry-exports/libentry.cpp")], check=True)
            with library.open("rb") as handle:
                exports = producer.elf_exports(ELFFile(handle))
        self.assertEqual((exports["artifact_kind"], exports["complete"]), ("shared-library", True))
        names = sorted(row["demangled"] for row in exports["functions"])
        self.assertEqual(names, ["entry_parse", "fx::overload(char const*)", "fx::overload(int)"])
        table = ex.export_table(exports, artifact="libentry.so", binary_sha256=None)
        self.assertEqual(len(table["exports"]), 3)
