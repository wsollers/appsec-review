from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import execution_state as state  # noqa: E402
import formats  # noqa: E402

HEX = "ab" * 32


class Formats(unittest.TestCase):
    def test_every_kind_resolves_and_rejects_a_trailing_newline(self):
        samples = {"sha256_ref": "sha256:" + HEX, "sha256_hex": HEX, "sha256_ref_or_hex": HEX,
                   "git_sha1": "a" * 40, "hex128_id": "b" * 32, "utc_timestamp": "2026-09-29T01:02:03Z",
                   "utc_date": "2026-09-29", "identifier": "run-1", "run_id": "r_1", "job_id": "02-x",
                   "attempt_id": "a1", "slug": "red-team", "dotted_id": "Lib.x_1",
                   "lower_dotted_id": "lib.x", "semver": "1.2.3", "nonneg_int": 0,
                   "confidence": "high", "confidence_or_unknown": "unknown", "ok_status": "OK",
                   "publishable_status": "SKIPPED", "evidence_strength": "WEAK_INFERENCE",
                   "budget_tier": "deep"}
        self.assertEqual(sorted(samples), formats.kinds())
        for kind, value in samples.items():
            self.assertEqual(formats.check(kind, value), value, kind)
            if isinstance(value, str) and kind not in ("confidence", "confidence_or_unknown",
                                                       "ok_status", "publishable_status",
                                                       "evidence_strength", "budget_tier"):
                self.assertFalse(formats.is_valid(kind, value + "\n"), kind)

    def test_rejections(self):
        for kind, value in (("sha256_ref", HEX), ("sha256_hex", HEX.upper()), ("git_sha1", "a" * 39),
                            ("utc_timestamp", "2026-09-29T01:02:03+00:00"),
                            ("utc_timestamp", "2026-13-29T01:02:03Z"), ("identifier", "-x"),
                            ("identifier", "x" * 121), ("slug", "Red"), ("nonneg_int", -1),
                            ("nonneg_int", True), ("confidence", "unknown")):
            with self.assertRaises(formats.FormatError, msg=(kind, value)):
                formats.check(kind, value)
        with self.assertRaises(KeyError):
            formats.ref("nope")

    def test_identifier_matches_execution_state(self):
        pattern = formats._STORE.load(formats.FORMATS_SCHEMA)["$defs"]["identifier"]["pattern"]
        source = Path(state.__file__).read_text(encoding="utf-8")
        self.assertIn(pattern[1:-2], source)
        for value in ("a", "A-b_c", "x" * 120):
            self.assertTrue(formats.is_valid("identifier", value))
            state.identifier(value)

    def test_timestamps(self):
        self.assertTrue(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", formats.utc_now()))
        self.assertEqual(formats.utc_second("2026-09-29T01:02:03.999999+00:00"), "2026-09-29T01:02:03Z")
        self.assertEqual(formats.utc_second("2026-09-29T03:02:03+02:00"), "2026-09-29T01:02:03Z")
        aware = datetime(2026, 9, 29, 1, 2, 3, tzinfo=timezone(timedelta(hours=-1)))
        self.assertEqual(formats.utc_second(aware), "2026-09-29T02:02:03Z")
        self.assertEqual(formats.utc_second(state.now())[:4], str(datetime.now(timezone.utc).year))
        for bad in ("2026-09-29T01:02:03", " 2026-09-29T01:02:03Z", "", "x", 5):
            with self.assertRaises(formats.FormatError, msg=bad):
                formats.utc_second(bad)

    def test_digests(self):
        self.assertEqual(formats.sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(formats.sha256_ref(HEX.upper()), "sha256:" + HEX)
        self.assertEqual(formats.sha256_hex("sha256:" + HEX), HEX)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f"
            path.write_bytes(b"abc")
            self.assertEqual(formats.sha256_ref(path), formats.sha256_ref(b"abc"))
        with self.assertRaises(formats.FormatError):
            formats.sha256_hex("abc")
        value = {"b": [1, "é"], "a": None}
        self.assertEqual(formats.digest(value), state.digest(value))
        self.assertEqual(formats.canonical_json(value), b'{"a":null,"b":[1,"\\u00e9"]}')


if __name__ == "__main__":
    unittest.main()
