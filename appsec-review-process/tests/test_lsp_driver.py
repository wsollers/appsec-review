"""lsp_driver.py against a scripted JSON-RPC server: answers, limits and gap records."""
from __future__ import annotations

import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import lsp_driver  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "lsp"
FAKE = FIXTURE / "fake_lsp_server.py"
LIMITS = {"total_seconds": 20.0, "request_seconds": 5.0}


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve() / "project"
        shutil.copytree(FIXTURE / "project", self.root)

    def tearDown(self):
        self.temp.cleanup()

    def drive(self, mode, queries, **limits):
        return lsp_driver.drive([sys.executable, str(FAKE), mode, str(self.root)], self.root, queries,
                                limits={**LIMITS, **limits}, server_name="fake")


class Answers(Base):
    def test_every_method_returns_rooted_sorted_locations(self):
        queries = [
            {"method": "definition", "path": "main.py", "line": 5, "character": 4},
            {"method": "references", "path": "main.py", "line": 1, "character": 4},
            {"method": "documentSymbol", "path": "main.py"},
            {"method": "workspaceSymbol", "query": "helper"},
            {"method": "incomingCalls", "path": "main.py", "line": 1, "character": 4},
            {"method": "outgoingCalls", "path": "main.py", "line": 1, "character": 4},
        ]
        document = self.drive("ok", queries)
        self.assertEqual(document["status"], "OK", document["gaps"])
        self.assertEqual(document["schema"], "appsec-review/lsp-query-result/1")
        self.assertEqual(document["server"]["info"], {"name": "fake [31mserver", "version": "1.0"})
        self.assertEqual(document["server"]["exit_code"], 0)
        definition, references, symbols, workspace, incoming, outgoing = document["results"]
        self.assertEqual(definition["results"], [{"path": "main.py", "start_line": 1, "start_character": 4,
                                                  "end_line": 1, "end_character": 4}])
        # duplicates collapse, order is deterministic, the out-of-root location is counted not kept
        self.assertEqual([row["start_line"] for row in references["results"]], [1, 5])
        self.assertEqual(references["dropped_outside_root"], 1)
        self.assertEqual([(row["name"], row.get("container")) for row in symbols["results"]],
                         [("helper", None), ("inner name", "helper"), ("main", None)])
        self.assertEqual(symbols["results"][0]["end_line"], 2)
        self.assertEqual(workspace["results"][0]["container"], "main")
        self.assertEqual(incoming["results"], [{"name": "main", "kind": 12, "path": "main.py", "start_line": 4,
                                                "start_character": 4, "end_line": 4, "end_character": 4,
                                                "call_lines": [5]}])
        self.assertEqual((outgoing["results"], outgoing["dropped_outside_root"]), ([], 1))

    def test_locations_outside_the_root_are_dropped_and_counted(self):
        document = self.drive("outside", [{"method": "definition", "path": "main.py", "line": 1}])
        row = document["results"][0]
        self.assertEqual((row["status"], row["results"], row["dropped_outside_root"]), ("OK", [], 2))

    def test_result_cap_truncates_and_records_a_gap(self):
        document = self.drive("ok", [{"method": "references", "path": "main.py", "line": 1}], max_results=1)
        self.assertEqual(document["status"], "OK_WITH_GAPS")
        self.assertTrue(document["results"][0]["truncated"])
        self.assertEqual(document["gaps"][0]["kind"], "truncated")

    def test_output_is_deterministic(self):
        queries = [{"method": "documentSymbol", "path": "main.py"},
                   {"method": "references", "path": "main.py", "line": 1}]
        first, second = self.drive("ok", queries), self.drive("ok", queries)
        for document in (first, second):
            document["server"].pop("notifications")
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))


class Gaps(Base):
    def kinds(self, document):
        return [gap["kind"] for gap in document["gaps"]]

    def test_missing_server_is_a_gap_not_a_crash(self):
        document = lsp_driver.drive(["definitely-not-a-language-server"], self.root, [], limits=LIMITS)
        self.assertEqual((document["status"], self.kinds(document)), ("FAILED", ["server-missing"]))

    def test_unsupported_capability(self):
        document = self.drive("nocaps", [{"method": "definition", "path": "main.py", "line": 1}])
        self.assertEqual(self.kinds(document), ["unsupported"])
        self.assertEqual(document["results"][0]["status"], "GAP")
        self.assertEqual(document["status"], "FAILED")

    def test_crash_after_initialize(self):
        document = self.drive("crash", [{"method": "documentSymbol", "path": "main.py"}])
        self.assertIn("protocol", self.kinds(document))
        self.assertEqual(document["server"]["exit_code"], 3)
        self.assertEqual(document["status"], "FAILED")

    def test_hang_hits_the_request_timeout(self):
        document = self.drive("hang", [{"method": "documentSymbol", "path": "main.py"}], request_seconds=0.5)
        self.assertEqual(self.kinds(document)[0], "timeout")
        self.assertEqual(document["status"], "FAILED")

    def test_total_deadline_skips_remaining_queries(self):
        queries = [{"method": "documentSymbol", "path": "main.py"}] * 3
        document = self.drive("hang", queries, request_seconds=0.4, total_seconds=1.0)
        self.assertEqual(len(document["results"]), 3)
        self.assertTrue(all(row["status"] == "GAP" for row in document["results"]))
        self.assertTrue(all(kind == "timeout" for kind in self.kinds(document)))

    def test_oversized_message_is_refused(self):
        document = self.drive("oversize", [{"method": "documentSymbol", "path": "main.py"}], max_message_bytes=1024)
        self.assertEqual(self.kinds(document), ["protocol"])
        self.assertIn("max_message_bytes", document["gaps"][0]["detail"])

    def test_malformed_header_is_refused(self):
        document = self.drive("garbage", [])
        self.assertEqual(self.kinds(document), ["protocol"])
        self.assertEqual(document["status"], "FAILED")

    def test_paths_outside_root_and_bad_queries_are_gaps(self):
        (self.root.parent / "secret.py").write_text("x = 1\n")
        (self.root / "link.py").symlink_to(self.root.parent / "secret.py")
        queries = [{"method": "documentSymbol", "path": "../secret.py"},
                   {"method": "documentSymbol", "path": "/etc/passwd"},
                   {"method": "documentSymbol", "path": "link.py"},
                   {"method": "definition", "path": "main.py"},
                   {"method": "hover", "path": "main.py"},
                   {"method": "documentSymbol", "path": "main.py"}]
        document = self.drive("ok", queries)
        self.assertEqual(self.kinds(document), ["path-outside-root"] * 3 + ["invalid-query"] * 2)
        self.assertEqual(document["status"], "OK_WITH_GAPS")
        self.assertEqual(document["results"][-1]["status"], "OK")

    def test_server_error_keeps_only_the_numeric_code(self):
        document = self.drive("error", [{"method": "documentSymbol", "path": "main.py"},
                                        {"method": "incomingCalls", "path": "main.py", "line": 1}])
        self.assertEqual([gap["detail"] for gap in document["gaps"]],
                         ["query 0: documentSymbol returned error code -32803",
                          "query 1: prepareCallHierarchy returned error code -32803"])
        self.assertNotIn("IGNORE", json.dumps(document))

    def test_file_size_cap(self):
        document = self.drive("ok", [{"method": "documentSymbol", "path": "main.py"}], max_file_bytes=10)
        self.assertIn("file-too-large", self.kinds(document))
        self.assertEqual(document["results"][0]["status"], "GAP")

    def test_query_count_cap(self):
        document = self.drive("ok", [{"method": "documentSymbol", "path": "main.py"}] * 3, max_queries=2)
        self.assertEqual(len(document["results"]), 2)
        self.assertEqual(self.kinds(document), ["invalid-query"])


class Framing(unittest.TestCase):
    def test_read_frame_limits(self):
        frame = lsp_driver.encode({"jsonrpc": "2.0", "id": 1, "result": None})
        self.assertEqual(lsp_driver.read_frame(io.BytesIO(frame), 1024)["id"], 1)
        self.assertIsNone(lsp_driver.read_frame(io.BytesIO(b""), 1024))
        for raw, message in ((frame, "exceeds"), (b"X: 1\r\n\r\n", "no Content-Length"),
                             (b"Content-Length: 10\r\n\r\n{}", "inside a message body"),
                             (b"Content-Length: 2\r\n\r\n[]", "not a JSON object"),
                             (b"A" * 9000, "header exceeds")):
            with self.subTest(message=message):
                with self.assertRaisesRegex(lsp_driver.ProtocolError, message):
                    lsp_driver.read_frame(io.BytesIO(raw), 16 if message == "exceeds" else 1024)

    def test_cli_writes_a_document_and_rejects_bad_usage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve() / "project"
            shutil.copytree(FIXTURE / "project", root)
            out = Path(temp) / "out" / "result.json"
            code = lsp_driver.main(["--command", json.dumps([sys.executable, str(FAKE), "ok", str(root)]),
                                    "--root", str(root), "--state-dir", str(Path(temp) / "state"),
                                    "--query", json.dumps({"method": "documentSymbol", "path": "main.py"}),
                                    "--request-seconds", "5", "--out", str(out)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.read_text())["status"], "OK")
            with self.assertRaises(SystemExit) as raised:
                lsp_driver.main(["--command", "[]", "--root", str(root)])
            self.assertEqual(raised.exception.code, 2)

    def test_presets_cover_every_compiler_image_server(self):
        self.assertEqual(set(lsp_driver.SERVERS), {
            "clangd", "gopls", "jdtls", "pylsp", "basedpyright", "typescript-language-server",
            "vscode-json-language-server", "rust-analyzer", "csharp-ls", "phpactor"})
        for name, preset in lsp_driver.SERVERS.items():
            self.assertTrue(preset["argv"] and all(isinstance(word, str) for word in preset["argv"]), name)


if __name__ == "__main__":
    unittest.main()
