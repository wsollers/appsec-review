"""model_version_registry: which aliases a run probes."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import model_version_registry as mvr  # noqa: E402


class ConfiguredAliasesTests(unittest.TestCase):
    def test_deterministic_python_is_not_probed_as_a_model(self):
        """Run 20261001T032047Z-fd64eb: every run made one failing `claude --model deterministic-python` call."""
        aliases = mvr.configured_aliases()
        self.assertNotIn("deterministic-python", aliases)
        self.assertIn("haiku", aliases)
        self.assertIn("claude-sonnet-5", aliases)


if __name__ == "__main__":
    unittest.main()
