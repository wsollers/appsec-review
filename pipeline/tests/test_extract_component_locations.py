"""Focused tests for the deterministic CycloneDX location transform."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import extract_component_locations as locations


FIXTURE = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {"name": "alpha", "group": "org.example", "version": "1.2.3", "purl": "pkg:maven/org.example/alpha@1.2.3",
         "properties": [
             {"name": "syft:package:foundBy", "value": "java-pom-cataloger"},
             {"name": "syft:package:type", "value": "java-archive"},
             {"name": "syft:package:language", "value": "java"},
             {"name": "syft:location:0:path", "value": "/src/server/pom.xml"},
             {"name": "syft:location:1:path", "value": "samples\\demo\\pom.xml"},
         ]},
        {"name": "beta", "version": "4", "properties": [
            {"name": "syft:package:foundBy", "value": "binary-classifier-cataloger"}
        ]},
    ],
}


class ComponentLocationTests(unittest.TestCase):
    def test_extracts_each_location_and_preserves_no_location(self):
        rows = locations.extract_rows(FIXTURE)
        self.assertEqual(len(rows), 3)
        self.assertEqual([row["Location"] for row in rows],
                         ["/src/server/pom.xml", "samples\\demo\\pom.xml", ""])
        self.assertEqual(rows[2]["Package"], "beta")
        self.assertEqual(rows[2]["FoundBy"], "binary-classifier-cataloger")

        prefixes, missing, samples = locations.summaries(rows, 2)
        self.assertEqual(prefixes["/src/server"], 1)
        self.assertEqual(prefixes["/samples/demo"], 1)
        self.assertEqual(prefixes["(no location data)"], 1)
        key = "binary-classifier-cataloger | (none) | (none)"
        self.assertEqual(missing[key], 1)
        self.assertEqual(samples[key], ["beta@4"])

    def test_csv_shape_and_atomic_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "component-locations.csv"
            rows = locations.extract_rows(FIXTURE)
            locations.write_csv(output, rows)
            with output.open(encoding="utf-8", newline="") as stream:
                parsed = list(csv.DictReader(stream))
            self.assertEqual(tuple(parsed[0]), locations.CSV_FIELDS)
            self.assertEqual(parsed, rows)
            locations.write_csv(output, rows[:1])
            with output.open(encoding="utf-8", newline="") as stream:
                self.assertEqual(len(list(csv.DictReader(stream))), 1)

    def test_rejects_malformed_or_unbounded_shapes(self):
        for document in ({}, {"components": []}, {"components": ["bad"]},
                         {"components": [{"name": "x", "properties": {}}]}):
            with self.subTest(document=document), self.assertRaises(ValueError):
                locations.extract_rows(document)
        with self.assertRaises(ValueError):
            locations.summaries([], 0)

    def test_cli_writes_csv_and_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "sbom.json"
            output = root / "locations.csv"
            source.write_text(json.dumps(FIXTURE), encoding="utf-8")
            captured = io.StringIO()
            previous = sys.stdout
            try:
                sys.stdout = captured
                self.assertEqual(locations.main(["--sbom", str(source), "--out", str(output),
                                                 "--summary-top-levels", "2"]), 0)
            finally:
                sys.stdout = previous
            self.assertTrue(output.is_file())
            self.assertIn("Total components in SBOM: 2", captured.getvalue())
            self.assertIn("Total (package, version, location) rows: 3", captured.getvalue())
            self.assertIn("binary-classifier-cataloger | (none) | (none)", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
