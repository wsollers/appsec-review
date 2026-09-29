from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import schema_format_lint as lint  # noqa: E402
from schema_validate import SCHEMAS_DIR  # noqa: E402


class FormatLint(unittest.TestCase):
    def test_repository_is_at_its_baseline(self):
        self.assertEqual(lint.problems(), [])
        committed = (SCHEMAS_DIR / lint.BASELINE).read_text(encoding="utf-8")
        self.assertEqual(committed, lint.render_baseline(lint.inline_copies()))

    def _tree(self, tmp: str, schema: dict, baseline: dict | None = None) -> Path:
        base = Path(tmp)
        (base / "common").mkdir()
        shutil.copy(SCHEMAS_DIR / "common" / "formats.schema.json", base / "common")
        (base / "x.schema.json").write_text(json.dumps(schema))
        if baseline is not None:
            (base / lint.BASELINE).write_text(lint.render_baseline(baseline))
        return base

    def test_new_inline_copy_fails_and_ref_passes(self):
        inline = {"type": "object", "properties": {
            "a": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "b": {"type": "string", "pattern": "^[0-9a-f]{64}\\Z"},
            "c": {"enum": ["low", "medium", "high"]},
            "d": {"type": "string", "pattern": "^other\\Z"}}}
        with tempfile.TemporaryDirectory() as tmp:
            base = self._tree(tmp, inline)
            self.assertEqual(lint.inline_copies(base),
                             {"x.schema.json": {"confidence": 1, "sha256_hex": 1, "sha256_ref": 1}})
            found = lint.problems(base)
            self.assertEqual(len(found), 3)
            self.assertIn("common/formats.schema.json#/$defs/sha256_ref", "\n".join(found))
        referenced = {"type": "object", "properties": {
            "a": {"$ref": "common/formats.schema.json#/$defs/sha256_ref"}}}
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(lint.problems(self._tree(tmp, referenced)), [])

    def test_baseline_ratchets_both_ways(self):
        schema = {"properties": {"a": {"pattern": "^[0-9a-f]{40}$"}}}
        with tempfile.TemporaryDirectory() as tmp:
            base = self._tree(tmp, schema, {"x.schema.json": {"git_sha1": 1}})
            self.assertEqual(lint.problems(base), [])
        with tempfile.TemporaryDirectory() as tmp:
            base = self._tree(tmp, schema, {"x.schema.json": {"git_sha1": 2}})
            self.assertIn("--write-baseline", lint.problems(base)[0])

    def test_escaped_dollar_is_not_an_anchor(self):
        self.assertEqual(lint._anchor("^a\\$"), "^a\\$")
        self.assertEqual(lint._anchor("^a$"), "^a")
        self.assertEqual(lint._anchor("^a\\Z"), "^a")


if __name__ == "__main__":
    unittest.main()
