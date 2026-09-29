"""Dependency reachability core (ADR-0022): symbols, engine choice, lattice, hash-bound witness."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dep_reachability as d
import dep_reachability_engines as e
import reachability as r
from schema_validate import validate_document

SHA = "sha256:" + "a" * 64
FILES = {"app/main.c": "sha256:" + "1" * 64, "app/parse.c": "sha256:" + "2" * 64,
         "vendor/zlib/inflate.c": "sha256:" + "3" * 64, "app/dead.c": "sha256:" + "4" * 64}


def method(full, name, path, start, end):
    return {"kind": "symbol", "label": "METHOD", "full_name": full, "name": name, "source_path": path,
            "start_line": start, "end_line": end, "source_sha256": SHA}


def call(caller, callee, name, path, line, code=""):
    return {"kind": "call", "label": "CALL", "caller": caller, "full_name": callee, "name": name,
            "source_path": path, "start_line": line, "code": code}


def cpg(extra=()):
    return r.CallGraph.from_records([
        method("main:int()", "main", "app/main.c", 1, 10),
        method("parse:void()", "parse", "app/parse.c", 1, 20),
        method("inflate:int()", "inflate", "vendor/zlib/inflate.c", 100, 400),
        method("dead:void()", "dead", "app/dead.c", 1, 9),
        method("gz_unused:void()", "gz_unused", "vendor/zlib/inflate.c", 500, 520),
        call("main:int()", "parse:void()", "parse", "app/main.c", 5),
        call("parse:void()", "inflate:int()", "inflate", "app/parse.c", 12, "inflate(&s)"),
        call("parse:void()", "<unresolvedNamespace>.png_read_row:<unresolvedSignature>(2)", "png_read_row",
             "app/parse.c", 14, "png_read_row(p, r)"),
        call("dead:void()", "<unresolvedNamespace>.xmlParseFile:<unresolvedSignature>(1)", "xmlParseFile",
             "app/dead.c", 3), *extra])


def sbom(*components):
    return {"components": [{"component_id": cid, "name": name, "ecosystem": eco} for cid, name, eco in components]}


def sca(*matches):
    return {"matches": [{"match_id": mid, "component_ref": cref, "advisory_id": adv, "aliases": [adv]}
                        for mid, cref, adv in matches]}


class FakeOsv:
    identity = {"snapshot_id": "osv-test", "data_timestamp": "2026-09-28T00:00:00Z", "gaps": []}

    def __init__(self, advisories):
        self.rows = advisories

    def advisories(self, ids):
        return [row for row in self.rows if row["id"] in set(ids)]


def run(matches, components, engine_set, *, reviewed=None, osv=None, osv_gap="osv-not-configured"):
    return d.analyse(sca=sca(*matches), sbom=sbom(*components), files=FILES, engine_set=engine_set,
                     osv=osv, osv_gap=osv_gap, reviewed=reviewed)


class CoreTests(unittest.TestCase):
    def test_vendored_c_function_reachable_with_hash_bound_witness(self):
        out = run([("VM-000001", "SC-000001", "CVE-2022-37434")], [("SC-000001", "zlib", "conan")],
                  e.EngineSet(cpg=cpg()), reviewed={"CVE-2022-37434": ["inflate"]})
        record = out["document"]["matches"][0]
        self.assertEqual(record["verdict"], "reachable")
        self.assertEqual([hop["function"] for hop in record["witness"]], ["main", "parse", "inflate"])
        self.assertEqual(record["witness"][0]["sha256"], FILES["app/main.c"])
        self.assertEqual(record["symbols"], [{"package": None, "symbol": "inflate", "source": "reviewed-map"}])
        row = out["assessments"][0]
        self.assertEqual((row["match_ref"], row["classification"]), ("VM-000001", "reachable"))
        self.assertTrue(all(item["kind"] == "call" and item["sha256"].startswith("sha256:") for item in row["evidence"]))

    def test_external_library_call_is_reachable_and_ends_at_the_call_site(self):
        out = run([("VM-000002", "SC-000002", "CVE-2019-7317")], [("SC-000002", "libpng16", "deb")],
                  e.EngineSet(cpg=cpg()), reviewed={"CVE-2019-7317": ["png_read_row"]})
        witness = out["document"]["matches"][0]["witness"]
        self.assertEqual(witness[-1]["note"], "call into the vulnerable dependency function")
        self.assertEqual((witness[-1]["file"], witness[-1]["line"]), ("app/parse.c", 14))

    def test_cpg_unreachable_is_bound_to_the_target(self):
        out = run([("VM-000003", "SC-000003", "CVE-2016-1000")], [("SC-000003", "libxml2", "deb")],
                  e.EngineSet(cpg=cpg()), reviewed={"CVE-2016-1000": ["xmlParseFile"]})
        record = out["document"]["matches"][0]
        self.assertEqual(record["verdict"], "unreachable")
        self.assertEqual(out["assessments"][0]["evidence"][0]["locator"], "no-path-to:dead@1")
        self.assertEqual(out["assessments"][0]["evidence"][0]["sha256"], FILES["app/dead.c"])

    def test_no_symbols_is_unknown_package_presence_only(self):
        out = run([("VM-000004", "SC-000004", "CVE-2024-0001")], [("SC-000004", "zlib", "conan")],
                  e.EngineSet(cpg=cpg()), osv=FakeOsv([]))
        record = out["document"]["matches"][0]
        self.assertEqual(record["verdict"], "unknown")
        self.assertIn("REACHABILITY_UNKNOWN:VM-000004:no-advisory-symbols", record["gaps"])
        self.assertEqual(out["assessments"], [])

    def test_unusable_osv_is_named_in_the_gap(self):
        out = run([("VM-000005", "SC-000005", "GO-2024-0001")], [("SC-000005", "golang.org/x/net", "golang")],
                  e.EngineSet(), osv_gap="osv-unusable:TOO_OLD")
        self.assertIn("REACHABILITY_UNKNOWN:VM-000005:osv-unusable:TOO_OLD", out["document"]["coverage_gaps"])

    def test_osv_symbols_filtered_by_ecosystem_and_package(self):
        advisory = {"id": "GO-2024-0001", "affected": [
            {"ecosystem": "Go", "name": "golang.org/x/net", "symbols": [
                {"path": "golang.org/x/net/html", "symbol": "Parse"}, {"path": "golang.org/x/net/html", "symbol": "bad name!"}]},
            {"ecosystem": "Go", "name": "golang.org/x/text", "symbols": [{"path": "golang.org/x/text", "symbol": "Other"}]},
            {"ecosystem": "npm", "name": "golang.org/x/net", "symbols": [{"path": None, "symbol": "Npm"}]}]}
        out = run([("VM-000006", "SC-000006", "GO-2024-0001")], [("SC-000006", "golang.org/x/net", "golang")],
                  e.EngineSet(), osv=FakeOsv([advisory]))
        record = out["document"]["matches"][0]
        self.assertEqual(record["symbols"], [{"package": "golang.org/x/net/html", "symbol": "Parse", "source": "osv"}])
        self.assertIn("REACHABILITY_UNKNOWN:VM-000006:advisory-symbols-rejected:1", record["gaps"])
        self.assertIn("REACHABILITY_UNKNOWN:VM-000006:engine-input-absent:codeql:go", record["gaps"])
        self.assertEqual(record["verdict"], "unknown")

    def test_witness_outside_projection_falls_to_unknown(self):
        extra = [method("helper:void()", "helper", "gen/helper.c", 1, 5),
                 call("main:int()", "helper:void()", "helper", "app/main.c", 6),
                 call("helper:void()", "<unresolvedNamespace>.sqlite3_exec:<x>(1)", "sqlite3_exec", "gen/helper.c", 3)]
        out = run([("VM-000007", "SC-000007", "CVE-2020-0001")], [("SC-000007", "sqlite3", "deb")],
                  e.EngineSet(cpg=cpg(extra)), reviewed={"CVE-2020-0001": ["sqlite3_exec"]})
        record = out["document"]["matches"][0]
        self.assertEqual(record["verdict"], "unknown")
        self.assertIn("REACHABILITY_UNKNOWN:VM-000007:witness-not-hash-bound", record["gaps"])

    def test_component_missing_and_unsupported_ecosystem_are_gaps(self):
        out = run([("VM-000008", "SC-000099", "CVE-2020-0002"), ("VM-000009", "SC-000009", "CVE-2020-0003")],
                  [("SC-000009", "thing", "spm")], e.EngineSet())
        gaps = out["document"]["coverage_gaps"]
        self.assertIn("REACHABILITY_UNKNOWN:VM-000008:component-not-in-sbom", gaps)
        self.assertIn("REACHABILITY_UNKNOWN:VM-000009:ecosystem-unsupported:spm", gaps)

    def test_document_validates_and_is_deterministic(self):
        args = ([("VM-000001", "SC-000001", "CVE-2022-37434"), ("VM-000003", "SC-000003", "CVE-2016-1000")],
                [("SC-000001", "zlib", "conan"), ("SC-000003", "libxml2", "deb")])
        reviewed = {"CVE-2022-37434": ["inflate"], "CVE-2016-1000": ["xmlParseFile"]}
        first = run(*args, e.EngineSet(cpg=cpg()), reviewed=reviewed)
        second = run(*args, e.EngineSet(cpg=cpg()), reviewed=reviewed)
        self.assertEqual(first, second)
        document = {**first["document"], "run_id": "run-1", "job_id": "06-cve-reachability", "attempt_id": "a-1",
                    "source_snapshot_sha256": SHA, "sca_binding": {}}
        self.assertEqual(validate_document(document, "dependency-reachability.schema.json"), [])
        self.assertEqual(document["counts"], {"reachable": 1, "unreachable": 1, "unknown": 0})


class LatticeTests(unittest.TestCase):
    def row(self, engine, state, ran=True, hint=False, witness=()):
        return e.result(engine, ran=ran, state=state, reason=f"{engine} said {state}", witness=list(witness),
                        **({"witness_hint": [{"file": "a"}]} if hint else {}))

    def test_any_proof_wins_and_hints_never_prove(self):
        verdict, best, _ = d.join("go", [self.row("codeql", "unknown"), self.row("lsp", "reachable", witness=[{}]),
                                          self.row("treesitter", "unknown", hint=True)])
        self.assertEqual((verdict, best["engine"]), ("reachable", "lsp"))
        self.assertEqual(d.join("go", [self.row("treesitter", "reachable")])[0], "unknown")

    def test_unreachable_needs_the_strongest_graph_engine_and_quiet_others(self):
        self.assertEqual(d.join("cpp", [self.row("cpg", "unreachable"), self.row("codeql", "unknown")])[0], "unreachable")
        self.assertEqual(d.join("cpp", [self.row("cpg", "unreachable"), self.row("codeql", "unknown", hint=True)])[0],
                         "unknown")
        self.assertEqual(d.join("go", [self.row("lsp", "unreachable")])[0], "unknown")
        self.assertEqual(d.join("cpp", [self.row("cpg", "unknown", ran=False), self.row("codeql", "unreachable")])[0],
                         "unknown")


class SymbolMatchTests(unittest.TestCase):
    def test_package_and_qualifier_narrow_name_matches(self):
        self.assertTrue(r.symbol_matches("golang.org/x/net/html.Tokenizer.Next", "Tokenizer.Next", "golang.org/x/net/html"))
        self.assertFalse(r.symbol_matches("golang.org/x/net/html.Parser.Next", "Tokenizer.Next", "golang.org/x/net/html"))
        self.assertFalse(r.symbol_matches("example.com/other.Parse", "Parse", "golang.org/x/net/html"))
        self.assertTrue(r.symbol_matches("<unresolvedNamespace>.strcpy:<sig>(2)", "strcpy"))

    def test_symbol_text_is_validated(self):
        kept, rejected = d.clean_symbols([{"symbol": "ok_name"}, {"symbol": "rm -rf /"}, {"symbol": 3},
                                          {"symbol": "X", "package": "../../etc"}], "osv")
        self.assertEqual([row["symbol"] for row in kept], ["ok_name"])
        self.assertEqual(rejected, 3)


class HostileTextTests(unittest.TestCase):
    def test_names_from_target_code_are_control_stripped(self):
        witness, _ = d.bind_witness([{"function": "evil\x1b[31m\nname", "file": "app/main.c", "line": 1,
                                      "note": "a\x00b"}], FILES)
        self.assertEqual(witness[0]["function"], "evil [31m name")
        self.assertEqual(witness[0]["note"], "a b")


if __name__ == "__main__":
    unittest.main()
