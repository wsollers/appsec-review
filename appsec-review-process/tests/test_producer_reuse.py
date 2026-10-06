"""producer_reuse: content keys that survive no-op changes and move on real ones."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import container_execution as ce  # noqa: E402
import producer_reuse  # noqa: E402


class ImageIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.images = Path(temporary.name)
        self.record = dict(next(iter(ce.load_image_registry(ce.IMAGES_DIR).values())))

    def key(self, record):
        (self.images / (record["image_id"] + ".json")).write_text(json.dumps(record))
        return producer_reuse.key(producer_reuse.images([record["image_id"]], self.images))

    def test_a_rekeyed_or_cache_rebuilt_record_with_the_same_digest_keeps_the_key(self):
        first = self.key(self.record)
        rekeyed = {**self.record, "purpose": self.record["purpose"] + " (rebuilt from cache)",
                   "provenance": "rekeyed"}
        self.assertNotEqual(ce._sha(rekeyed), ce._sha(self.record))   # the old whole-record key moved
        self.assertEqual(self.key(rekeyed), first)

    def test_a_new_image_digest_changes_the_key(self):
        first = self.key(self.record)
        digest = self.record["digest"]
        changed = {**self.record, "digest": digest[:-1] + ("0" if digest[-1] != "0" else "1")}
        self.assertNotEqual(self.key(changed), first)


if __name__ == "__main__":
    unittest.main()
