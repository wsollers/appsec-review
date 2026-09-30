"""treesitter_ast.py: deterministic, hash-bound AST summary over bundled fixture sources.

Parsing tests need py-tree-sitter and the pinned grammars (every compiler image has them at
/opt/treesitter/bin/python; on a host: pip install -r images/audit-lsp-vendor/requirements-treesitter.txt).
Without them those tests skip; the file walker, hashing and schema checks still run.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import treesitter_ast as ast  # noqa: E402
from schema_validate import validate_document  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "treesitter-ast"
try:
    import tree_sitter  # noqa: F401
    HAVE_TREE_SITTER = True
except ImportError:
    HAVE_TREE_SITTER = False


class ContainerRequest(unittest.TestCase):
    """The job's real B13 request must pass the boundary schema (2026-09-30: an environment name outside the
    allowlist rejected every run before Docker started)."""

    def test_request_passes_the_pinned_container_request_schema(self):
        import container_execution as ce
        import treesitter_ast_job as job
        import tunables
        inputs = {"image": {"digest": "sha256:" + "a" * 64}, "limits": job._limits(), "target_path": "/tmp/target",
                  "source_snapshot_sha256": "sha256:" + "b" * 64, "container_limits": tunables.container_limits(job.JOB)}
        request = job._request("20260930T214459Z-ce7e7f", "ts-0123456789ab", inputs, Path("/tmp/staged"))
        self.assertEqual(validate_document(request, ce.REQUEST_SCHEMA), [])
        self.assertEqual(request["argv"][:2], ["/opt/treesitter/bin/python", "-B"])


class Walker(unittest.TestCase):
    def test_walk_is_sorted_skips_vcs_and_never_follows_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".git").mkdir()
            (root / ".git" / "config.py").write_text("x = 1\n")
            (root / "b").mkdir()
            (root / "b" / "z.py").write_text("x = 1\n")
            (root / "a.py").write_text("x = 1\n")
            (root / "link.py").symlink_to(root / "a.py")
            (root / "dirlink").symlink_to(root / "b")
            rows = list(ast.iter_files(root))
        self.assertEqual([(name, problem) for name, _path, problem in rows],
                         [("a.py", None), ("b/z.py", None), ("dirlink", "symlink-skipped"),
                          ("link.py", "symlink-skipped")])

    def test_file_list_rejects_escapes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.py").write_text("x = 1\n")
            rows = list(ast.iter_files(root, ["a.py", "../etc/passwd", "/etc/passwd", "missing.py", "a.py"]))
        self.assertEqual([(name, problem) for name, _path, problem in rows],
                         [("../etc/passwd", "path-outside-root"), ("/etc/passwd", "path-outside-root"),
                          ("a.py", None), ("missing.py", "not-a-file")])

    def test_clean_strips_controls_collapses_space_and_truncates(self):
        self.assertEqual(ast.clean(b"a\x1b[2J\n\n  b\x00c"), "a [2J b c")
        self.assertEqual(ast.clean("x" * 500), "x" * ast.TEXT_LIMIT)
        self.assertIsNone(ast.clean(b"\x00\x01"))

    def test_verify_detects_any_change_to_the_body(self):
        body = {"schema": ast.SCHEMA, "files": [], "gaps": []}
        document = dict(body, content_sha256="sha256:" + hashlib.sha256(ast.canonical(body)).hexdigest())
        self.assertTrue(ast.verify(document))
        document["files"] = [{"path": "x"}]
        self.assertFalse(ast.verify(document))

    def test_schema_file_is_registered_and_closed(self):
        schema = json.loads((ROOT.parent / "schemas" / "treesitter-ast.schema.json").read_text())
        self.assertEqual(schema["properties"]["schema"]["const"], ast.SCHEMA)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["properties"]["files"]["items"]["properties"]["language"]["enum"]),
                         set(ast.GRAMMARS))
        self.assertTrue(set(ast.SUFFIXES.values()) <= set(ast.GRAMMARS))


@unittest.skipUnless(HAVE_TREE_SITTER, "py-tree-sitter and the pinned grammars are not installed")
class Parse(unittest.TestCase):
    def build(self, root=FIXTURE, **kwargs):
        return ast.build(root, label="fixture", **kwargs)

    def test_fixture_summary_is_exact(self):
        document, stats = self.build()
        self.assertEqual(validate_document(document, "treesitter-ast.schema.json"), [])
        self.assertTrue(ast.verify(document))
        self.assertEqual(stats["files"], 5)
        files = {row["path"]: row for row in document["files"]}
        self.assertEqual(list(files), ["native/main.c", "src/app.py", "src/broken.py", "src/pkg/util.py", "web/main.ts"])
        self.assertEqual(files["native/main.c"]["functions"],
                         [{"name": "copy", "kind": "function_definition", "start_line": 4, "end_line": 6},
                          {"name": "main", "kind": "function_definition", "start_line": 8, "end_line": 12}])
        self.assertEqual(files["native/main.c"]["calls"], [{"callee": "strcpy", "line": 5}, {"callee": "copy", "line": 10}])
        self.assertEqual([row["text"] for row in files["native/main.c"]["imports"]],
                         ["#include <string.h>", '#include "local.h"'])
        self.assertEqual(files["src/app.py"]["calls"], [{"callee": "os.path.join", "line": 6},
                                                        {"callee": "util.read", "line": 6},
                                                        {"callee": "load", "line": 11}])
        self.assertEqual([(row["name"], row["kind"]) for row in files["web/main.ts"]["functions"]],
                         [("run", "arrow_function"), ("main", "function_declaration")])
        self.assertEqual(files["src/broken.py"]["error_nodes"], 1)
        self.assertEqual(files["src/app.py"]["sha256"],
                         "sha256:" + hashlib.sha256((FIXTURE / "src/app.py").read_bytes()).hexdigest())
        kinds = {row["kind"]: row["count"] for row in files["src/app.py"]["node_kinds"]}
        self.assertEqual(kinds["function_definition"], 2)
        self.assertEqual(document["gaps"], [{"kind": "no-grammar", "path": None,
                                             "detail": "1 file(s) with suffix .txt"}])
        self.assertEqual(document["totals"], {"files": 5, "bytes": sum(row["bytes"] for row in files.values()),
                                              "functions": 8, "calls": 10, "imports": 5, "error_nodes": 1,
                                              "gaps": 1})
        self.assertEqual({row["language"] for row in document["generator"]["grammars"]}, set(ast.GRAMMARS))

    def test_same_bytes_same_document_and_one_byte_changes_it(self):
        first, _ = self.build()
        second, _ = self.build()
        self.assertEqual(ast.canonical(first), ast.canonical(second))
        with tempfile.TemporaryDirectory() as temp:
            copy = Path(temp) / "fixture"
            shutil.copytree(FIXTURE, copy)
            (copy / "src" / "pkg" / "util.py").write_text("def read(path):\n    return path\n")
            changed, _ = ast.build(copy, label="fixture")
        self.assertNotEqual(changed["content_sha256"], first["content_sha256"])
        self.assertNotEqual(changed["source_manifest_sha256"], first["source_manifest_sha256"])

    def test_limits_become_gaps(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "fixture"
            shutil.copytree(FIXTURE, root)
            (root / "big.py").write_text("x = 1\n" * 100)
            (root / "calls.py").write_text("".join(f"f{i}()\n" for i in range(12)))
            os.symlink(root / "src" / "app.py", root / "alias.py")
            document, _ = ast.build(root, label="fixture", limits={"max_file_bytes": 400, "max_rows_per_file": 10})
        kinds = [(gap["kind"], gap["path"]) for gap in document["gaps"]]
        self.assertIn(("file-too-large", "big.py"), kinds)
        self.assertIn(("rows-truncated", "calls.py"), kinds)
        self.assertIn(("symlink-skipped", "alias.py"), kinds)
        calls = next(row for row in document["files"] if row["path"] == "calls.py")["calls"]
        self.assertEqual(len(calls), 10)
        self.assertEqual(validate_document(document, "treesitter-ast.schema.json"), [])

    def test_max_files_stops_parsing_and_records_the_rest(self):
        document, _ = self.build(limits={"max_files": 2})
        self.assertEqual(document["totals"]["files"], 2)
        self.assertEqual([gap["path"] for gap in document["gaps"] if gap["kind"] == "max-files"],
                         ["src/broken.py", "src/pkg/util.py", "web/main.ts"])

    def test_streamed_file_equals_the_in_memory_document(self):
        document, _ = self.build()
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "ast.json"
            totals, _ = ast.write(FIXTURE, out, label="fixture")
            streamed = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(streamed, document)
        self.assertEqual(totals["content_sha256"], document["content_sha256"])
        self.assertTrue(ast.verify(streamed))

    def test_cli_writes_document_and_stats(self):
        with tempfile.TemporaryDirectory() as temp:
            out, stats = Path(temp) / "ast.json", Path(temp) / "stats.json"
            self.assertEqual(ast.main(["--root", str(FIXTURE), "--label", "fixture", "--out", str(out),
                                       "--stats", str(stats)]), 0)
            document = json.loads(out.read_text())
            self.assertTrue(ast.verify(document))
            self.assertIn("wall_seconds", json.loads(stats.read_text()))
            self.assertNotIn("wall_seconds", document)


if __name__ == "__main__":
    unittest.main()
