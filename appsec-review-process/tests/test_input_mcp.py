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


if __name__ == "__main__":
    unittest.main()
