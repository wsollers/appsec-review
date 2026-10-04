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


if __name__ == "__main__":
    unittest.main()
