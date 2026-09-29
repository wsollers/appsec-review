"""Engine adapters for dependency reachability (ADR-0022): codeql tables, lsp hierarchy, tree-sitter hints."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dep_reachability as d
import dep_reachability_codeql as q
import dep_reachability_engines as e

HTML = {"package": "golang.org/x/net/html", "symbol": "Parse", "source": "osv"}
HEADER = ",".join(e.CALL_EDGE_COLUMNS)


def query(symbols=(HTML,), language="go", entries=()):
    return e.Query(match_id="VM-000001", language=language, package="golang.org/x/net", symbols=list(symbols),
                   entry_points=list(entries))


def csv_bytes(columns, rows):
    return ("\n".join([",".join(columns)] + [",".join(f'"{v}"' for v in row) for row in rows]) + "\n").encode()


EDGES = [
    ("example.com/app.main", "cmd/main.go", 5, "cmd/main.go", 7, "example.com/app/web.Serve", "web/serve.go", 3, "yes"),
    ("example.com/app/web.Serve", "web/serve.go", 3, "web/serve.go", 9, "golang.org/x/net/html.Parse", "", 0, "no"),
    ("example.com/app/tool.Dead", "tool/dead.go", 1, "tool/dead.go", 4, "golang.org/x/net/html.Tokenize", "", 0, "no"),
]
ENTRIES = [("example.com/app.main", "cmd/main.go", 5, "main")]


def tables(edges=EDGES, entries=ENTRIES, **extra):
    decoded = {"CallEdges": e.read_table(csv_bytes(e.CALL_EDGE_COLUMNS, edges), "CallEdges"),
               "EntryPoints": e.read_table(csv_bytes(e.ENTRY_COLUMNS, entries), "EntryPoints")}
    for name, rows in extra.items():
        decoded[name] = e.read_table(csv_bytes(e.TABLES[name], rows), name)
    return {"go": decoded}


class CodeqlEngineTests(unittest.TestCase):
    def test_call_edges_give_a_witness_ending_at_the_dependency_call(self):
        found = e.CodeqlEngine(tables()).assess(query())
        self.assertEqual(found["state"], "reachable")
        self.assertEqual([step["function"] for step in found["witness"]],
                         ["main", "Serve", "Parse"])
        self.assertEqual((found["witness"][-1]["file"], found["witness"][-1]["line"]), ("web/serve.go", 9))
        self.assertEqual(found["witness"][0]["calls_next_at"], "cmd/main.go:7")

    def test_no_path_is_unknown_never_unreachable(self):
        tokenize = {"package": "golang.org/x/net/html", "symbol": "Tokenize", "source": "osv"}
        found = e.CodeqlEngine(tables()).assess(query([tokenize]))
        self.assertEqual(found["state"], "unknown")
        self.assertIn("not proof", found["reason"])

    def test_other_package_with_the_same_name_does_not_match(self):
        other = {"package": "example.com/other", "symbol": "Parse", "source": "osv"}
        self.assertEqual(e.CodeqlEngine(tables()).assess(query([other]))["state"], "unknown")

    def test_reachability_row_is_a_direct_witness_and_taint_is_recorded(self):
        reach = [("example.com/app.main", "cmd/main.go", 5, "example.com/app/web.Serve", "web/serve.go", 9,
                  "golang.org/x/net/html", "Parse")]
        taint = [("web/serve.go", 4, "web/serve.go", 9, "golang.org/x/net/html", "Parse")]
        found = e.CodeqlEngine(tables(edges=[], entries=[], Reachability=reach, TaintReach=taint)).assess(query())
        self.assertEqual(found["state"], "reachable")
        self.assertEqual(found["witness"][0]["resolution"], "codeql-calls*")
        self.assertEqual(found["taint_paths"], [{"source": "web/serve.go:4", "sink": "web/serve.go:9"}])

    def test_absent_and_invalid_tables_are_gaps(self):
        self.assertEqual(e.CodeqlEngine({}).assess(query())["gaps"], ["engine-input-absent:codeql:go"])
        with self.assertRaises(ValueError):
            e.read_table(b"a,b\n1,2\n", "CallEdges")
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "CallEdges.csv").write_bytes(b"wrong,header\n")
            (Path(folder) / "EntryPoints.csv").write_bytes(csv_bytes(e.ENTRY_COLUMNS, ENTRIES))
            decoded, gaps = e.load_codeql_dirs({"go": Path(folder)})
        self.assertIn("codeql-table-invalid:go:CallEdges", gaps["go"])
        self.assertNotIn("codeql-table-absent:go:Reachability", gaps["go"])  # optional table
        self.assertEqual(set(decoded["go"]), {"EntryPoints"})

    def test_joined_through_the_core_with_hash_binding(self):
        files = {"cmd/main.go": "sha256:" + "1" * 64, "web/serve.go": "sha256:" + "2" * 64}
        out = d.analyse(sca={"matches": [{"match_id": "VM-000001", "component_ref": "SC-000001",
                                          "advisory_id": "GO-2022-0001", "aliases": []}]},
                        sbom={"components": [{"component_id": "SC-000001", "name": "golang.org/x/net", "ecosystem": "golang"}]},
                        files=files, engine_set=e.EngineSet(codeql=tables()), osv=None, osv_gap=None,
                        reviewed={"GO-2022-0001": [{"package": "golang.org/x/net/html", "symbol": "Parse"}]})
        record = out["document"]["matches"][0]
        self.assertEqual(record["verdict"], "reachable")
        self.assertEqual([hop["sha256"] for hop in record["witness"]], [files["cmd/main.go"], files["web/serve.go"],
                                                                        files["web/serve.go"]])
        self.assertEqual([row["engine"] for row in record["engines"]], ["codeql", "lsp", "treesitter"])


def lsp_row(path, line, callers, sink=None, status="OK"):
    asked = {"method": "incomingCalls", "path": path, "line": line, "character": 5}
    if sink:
        asked["sink_symbol"] = sink
    return {"query_index": 0, "query": asked, "status": status, "results": callers}


def caller(name, path, line, call_line):
    return {"name": name, "kind": 12, "path": path, "start_line": line, "start_character": 5,
            "end_line": line, "end_character": 9, "call_lines": [call_line]}


class LspEngineTests(unittest.TestCase):
    def document(self):
        return {"results": [
            lsp_row("vendor/golang.org/x/net/html/parse.go", 2300, [caller("Serve", "web/serve.go", 3, 9)],
                    sink={"package": "golang.org/x/net/html", "symbol": "Parse"}),
            lsp_row("web/serve.go", 3, [caller("main", "cmd/main.go", 5, 7)])], "gaps": []}

    def test_incoming_calls_chain_to_main(self):
        found = e.LspEngine({"go": self.document()}).assess(query())
        self.assertEqual(found["state"], "reachable")
        self.assertEqual([(s["function"], s["file"], s["line"]) for s in found["witness"]],
                         [("main", "cmd/main.go", 5), ("Serve", "web/serve.go", 3), ("Parse", "web/serve.go", 9)])
        self.assertEqual(found["witness"][0]["calls_next_at"], "cmd/main.go:7")

    def test_no_entry_point_is_unknown_and_untagged_answers_are_not_sinks(self):
        document = self.document()
        document["results"] = document["results"][:1]
        self.assertEqual(e.LspEngine({"go": document}).assess(query())["state"], "unknown")
        untagged = {"results": [lsp_row("web/serve.go", 3, [caller("main", "cmd/main.go", 5, 7)])], "gaps": []}
        found = e.LspEngine({"go": untagged}).assess(query())
        self.assertIn("lsp-no-sink-query:go", found["gaps"])
        self.assertFalse(e.LspEngine({}).assess(query())["ran"])


class TreesitterEngineTests(unittest.TestCase):
    def test_name_matches_are_hints_never_proof(self):
        ast = {"files": [{"path": "web/serve.go", "language": "go", "functions": [
            {"name": "Serve", "kind": "function_declaration", "start_line": 3, "end_line": 12}],
            "calls": [{"callee": "html.Parse", "line": 9}, {"callee": "fmt.Println", "line": 10}]},
            {"path": "x.py", "language": "python", "functions": [], "calls": [{"callee": "Parse", "line": 1}]}]}
        found = e.TreesitterEngine(ast).assess(query())
        self.assertEqual(found["state"], "unknown")
        self.assertEqual(found["witness_hint"], [{"file": "web/serve.go", "line": 9, "callee": "html.Parse",
                                                  "symbol": "Parse", "function": "Serve"}])
        verdict, _, _ = d.join("go", [e.CodeqlEngine({}).assess(query()), e.LspEngine({}).assess(query()), found])
        self.assertEqual(verdict, "unknown")


class CodeqlPackTests(unittest.TestCase):
    def test_pins_and_files(self):
        self.assertEqual(q.check_pins(), [])

    def test_symbols_are_rows_of_a_generated_model_pack(self):
        files = q.data_extension("go", [{"package": "golang.org/x/net/html", "symbol": "Parse"},
                                        {"package": "golang.org/x/net/html", "symbol": "Tokenizer.Next"}])
        model = json.loads(files["symbols.model.yml"])
        self.assertEqual(model["extensions"][0]["addsTo"], {"pack": "appsec/go-reachability", "extensible": "vulnerableSymbol"})
        self.assertEqual(model["extensions"][0]["data"], [["golang.org/x/net/html", "Parse"],
                                                          ["golang.org/x/net/html", "Tokenizer.Next"]])
        self.assertIn(b"appsec/go-reachability: \"*\"", files["qlpack.yml"])
        for bad in ({"package": "x", "symbol": "a\") or any("}, {"package": None, "symbol": "Parse"},
                    {"package": "x\nextensions", "symbol": "P"}):
            with self.assertRaises(ValueError):
                q.data_extension("go", [bad])
        with self.assertRaises(ValueError):
            q.data_extension("php", [])

    def test_plan_is_argv_only_and_offline(self):
        steps = q.plan("java")
        self.assertIn("--build-mode=none", steps[0])
        self.assertTrue(all(step[0] == q.CODEQL for step in steps))
        self.assertEqual(len(steps), 1 + 2 * len(q.QUERIES))
        self.assertTrue(q.pack_sha256("go").startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
