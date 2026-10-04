import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import input_mcp  # noqa: E402


class _Inputs:
    entries = [{"ref": "t:a.c"}]
    by_ref = {"t:a.c": {"sha256": "sha256:" + "0" * 64}}

    def text(self, ref):
        return "one\ntwo\nthree\n"


class InputReadDedup(unittest.TestCase):
    def setUp(self):
        input_mcp._RETURNED.clear()

    def test_same_range_twice_returns_a_pointer_then_again_returns_text(self):
        first = input_mcp.call("run", _Inputs(), "input_read", {"ref": "t:a.c"})
        self.assertIn("2: two", first["text"])
        second = input_mcp.call("run", _Inputs(), "input_read", {"ref": "t:a.c"})
        self.assertEqual(second["text"], "")
        self.assertIn("returned earlier", second["already_returned"])
        third = input_mcp.call("run", _Inputs(), "input_read", {"ref": "t:a.c", "again": True})
        self.assertIn("2: two", third["text"])

    def test_a_different_range_is_not_deduplicated(self):
        input_mcp.call("run", _Inputs(), "input_read", {"ref": "t:a.c"})
        other = input_mcp.call("run", _Inputs(), "input_read", {"ref": "t:a.c", "start": 2})
        self.assertIn("2: two", other["text"])


class ArgumentTypes(unittest.TestCase):
    """The server validates arguments against each tool's inputSchema before calling it."""
    schema = next(t["inputSchema"] for t in input_mcp.TOOLS if t["name"] == "input_read")

    def test_boolean_again_is_accepted(self):
        input_mcp._check(self.schema, {"ref": "t:a.c", "again": True})

    def test_wrong_types_are_refused(self):
        for args in ({"ref": "t:a.c", "again": 1}, {"ref": "t:a.c", "start": True}, {"ref": 3}):
            with self.assertRaises(ValueError):
                input_mcp._check(self.schema, args)


class ToolCallCap(unittest.TestCase):
    """max_tool_calls_per_cell: past the cap every call gets a fixed budget_exhausted error, is not run,
    and is counted under _budget_exhausted for the invoker's receipt gap; the count spans repair rounds."""

    def setUp(self):
        import json
        import tempfile
        from unittest import mock
        self.json = json
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.usage = Path(folder.name) / "tool-usage.json"
        for patch in (mock.patch.object(input_mcp, "data_path", side_effect=lambda *p: Path(folder.name).joinpath(*p)),
                      mock.patch.dict(input_mcp.USAGE, {"path": str(self.usage)}, clear=True),
                      mock.patch.dict(input_mcp.BUDGET, {"max": 2})):
            patch.start()
            self.addCleanup(patch.stop)
        input_mcp._RETURNED.clear()

    def ask(self):
        self.start = getattr(self, "start", 0) + 1
        return input_mcp.handle("run", _Inputs(), {"method": "tools/call", "params": {
            "name": "input_read", "arguments": {"ref": "t:a.c", "start": self.start}}})

    def test_calls_past_the_cap_are_refused_with_a_bounded_error_and_counted(self):
        self.assertFalse(self.ask()["isError"])
        self.assertFalse(self.ask()["isError"])
        refused = self.ask()
        self.assertTrue(refused["isError"])
        self.assertTrue(refused["content"][0]["text"].startswith("budget_exhausted:"))
        self.assertLess(len(refused["content"][0]["text"]), 400)
        counts = self.json.loads(self.usage.read_text())
        self.assertEqual(counts, {"input_read": 2, input_mcp.BUDGET_EXHAUSTED: 1})

    def test_a_restarted_server_keeps_counting_against_the_same_cap(self):
        self.usage.write_text(self.json.dumps({"input_read": 2}))
        input_mcp.USAGE.pop("counts", None)
        input_mcp._load_usage()
        self.assertTrue(self.ask()["isError"])


class EvidenceReadPaths(unittest.TestCase):
    """evidence_read failed on 93 of 503 calls (hello-autotools 20261004T054551Z-357581). The real
    evidence_store.query over a fixture index, one test per cause: the forms the model holds for a file
    (input ref, citation path, cite with a line), upstream refs, the line window, the end of the file,
    excluded and non-text files, and a parallel cell holding the index lock."""

    def setUp(self):
        import hashlib
        import json
        import sqlite3
        import tempfile
        from unittest import mock
        import evidence_store
        self.store = evidence_store
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        base = Path(folder.name) / "whole"
        attempt = base / "attempts" / "a1"
        (attempt / "objects").mkdir(parents=True)
        db = sqlite3.connect(attempt / "index.sqlite")
        db.execute("CREATE TABLE files(path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL, "
                   "ssdeep TEXT NOT NULL, text_status TEXT NOT NULL)")
        for path, text, status in (("source/src/hello.c", "".join(f"line {n}\n" for n in range(1, 121)), "indexed"),
                                   ("source/lib/hello.c", "other\n", "indexed"),
                                   ("source/doc/logo.png", "\x00png", "binary")):
            data = text.encode()
            sha = hashlib.sha256(data).hexdigest()
            (attempt / "objects" / sha).write_bytes(data)
            db.execute("INSERT INTO files VALUES (?,?,?,?,?)", (path, sha, len(data), "3:x:y", status))
        db.commit(); db.close()
        (attempt / "manifest.json").write_text(json.dumps({"excluded": [
            {"path": "source/build/config.h", "reason": "excluded by accepted intake scope"}]}))
        self.pointer = {"status": "OK", "attempt_id": "a1"}
        (base / "accepted.json").write_text(json.dumps(self.pointer))
        for patch in (mock.patch.object(evidence_store, "root", return_value=base),
                      mock.patch.object(evidence_store, "validate", return_value=(self.pointer, attempt))):
            patch.start()
            self.addCleanup(patch.stop)
        input_mcp.SNAPSHOT.clear()

    def read(self, **args):
        return input_mcp.call("run", None, "evidence_read", args)

    def test_the_documented_index_path_reads_unchanged(self):
        result = self.read(path="source/src/hello.c", start=2, limit=2)
        self.assertEqual(result["results"][0]["excerpt"], "line 2\nline 3")
        self.assertNotIn("notes", result)

    def test_citation_path_and_input_ref_forms_resolve_to_the_indexed_path(self):
        with self.assertRaisesRegex(ValueError, "not in the accepted index"):   # the failure before the fix
            self.store.query("run", "read", path="src/hello.c", fresh=False)
        for path in ("src/hello.c", "target-repository:src/hello.c", "./src/hello.c", "/workspace/src/hello.c"):
            result = self.read(path=path, limit=1)
            self.assertEqual(result["results"][0]["path"], "source/src/hello.c", path)
            self.assertIn("resolved to the indexed path 'source/src/hello.c'", result["notes"][0])

    def test_a_cite_with_a_line_range_reads_that_range(self):
        for path in ("src/hello.c:7-9", "source/src/hello.c#L7-L9"):
            row = self.read(path=path)["results"][0]
            self.assertEqual((row["start_line"], row["end_line"]), (7, 9), path)
        self.assertEqual(self.read(path="src/hello.c:7", limit=1)["results"][0]["excerpt"], "line 7")

    def test_an_upstream_ref_is_refused_with_the_tool_that_reads_it(self):
        with self.assertRaisesRegex(ValueError, "pinned input ref \\(root 'upstream-artifacts'\\).*input_read"):
            self.read(path="upstream-artifacts:outputs/component-map.json")

    def test_a_limit_over_the_window_is_clamped_not_refused(self):
        result = self.read(path="source/src/hello.c", limit=200)
        self.assertEqual(result["results"][0]["end_line"], 50)
        self.assertIn("over the 50-line window", result["notes"][0])

    def test_a_start_past_the_end_names_the_file_length(self):
        with self.assertRaisesRegex(ValueError, "start line 500 is beyond the end of source/src/hello.c \\(120 lines\\)"):
            self.read(path="source/src/hello.c", start=500)

    def test_an_unknown_path_says_what_was_tried_and_offers_same_named_files(self):
        with self.assertRaisesRegex(ValueError, "tried source/hello.c.*exactly as evidence_search.*"
                                               "source/lib/hello.c, source/src/hello.c"):
            self.read(path="hello.c")

    def test_excluded_and_non_text_files_are_named_as_such(self):
        with self.assertRaisesRegex(ValueError, "excluded from the evidence index \\(excluded by accepted intake scope\\)"):
            self.read(path="build/config.h")
        with self.assertRaisesRegex(ValueError, "text is not indexed \\(binary\\)"):
            self.read(path="doc/logo.png")

    def test_a_parallel_cell_holding_the_index_lock_is_waited_for(self):
        from unittest import mock
        real, calls = self.store.query, []

        def busy(*args, **kwargs):
            calls.append(1)
            if len(calls) < 3:
                raise self.store.Blocked("active lock: job.lock; retry after owner exits; never delete lock files")
            return real(*args, **kwargs)
        with mock.patch.object(self.store, "query", side_effect=busy), mock.patch.object(input_mcp.time, "sleep"):
            self.assertEqual(self.read(path="source/src/hello.c", limit=1)["results"][0]["excerpt"], "line 1")
        self.assertEqual(len(calls), 3)

    def test_the_audit_records_the_resolution_note(self):
        summary = input_mcp._summary("evidence_read", self.read(path="src/hello.c", limit=1))
        self.assertEqual(summary["refs"], ["source/src/hello.c"])
        self.assertIn("resolved", summary["notes"][0])


if __name__ == "__main__":
    unittest.main()
