"""Pinned CVSS v4.0 calculator (ADR-0020).

Expected scores are FIRST CVSS v4.0 calculator results for widely published vectors (the
specification's examples and common NVD CNA vectors); the full macrovector table is pinned by hash.
"""
from __future__ import annotations

import itertools
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import cvss4
import cvss4_reference_check

FIRST_SAMPLE = ROOT / "tests" / "fixtures" / "cvss4-first-reference-sample.json"
PROVENANCE = ROOT.parent / "data" / "reference" / "cvss" / "cvss4-lookup-provenance.json"

VECTORS = {
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 9.3,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H": 10.0,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 8.7,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 8.6,
    "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 9.2,
    "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 8.5,
    "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 7.0,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N": 8.7,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N": 8.7,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N": 7.1,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N": 6.9,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N": 6.9,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N": 5.3,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N": 5.3,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N": 5.1,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N": 0.0,
}


class CVSS4Tests(unittest.TestCase):
    def test_published_calculator_vectors(self):
        for vector, expected in VECTORS.items():
            self.assertEqual(cvss4.score(vector), expected, vector)

    def test_table_is_complete_and_pinned(self):
        expected = {f"{a}{b}{c}{d}{e}{f}" for a, b, (c, f), d, e in itertools.product(
            range(3), range(2), [(0, 0), (0, 1), (1, 0), (1, 1), (2, 1)], range(3), range(3))}
        self.assertEqual(set(cvss4.LOOKUP), expected)
        self.assertEqual(cvss4.lookup_sha256(), cvss4.LOOKUP_SHA256)

    def test_threat_metric_lowers_score_and_severity_bands(self):
        base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        self.assertLess(cvss4.score(base + "/E:U"), cvss4.score(base))
        self.assertEqual([cvss4.severity(v) for v in (9.0, 7.0, 4.0, 0.1, 0.0)],
                         ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"])

    def test_invalid_vectors_and_proposals_name_the_metric(self):
        for bad in ("CVSS:3.1/AV:N", "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N"):
            with self.assertRaises(cvss4.CVSSError):
                cvss4.score(bad)
        metrics = dict(AV="L", AC="L", AT="N", PR="N", UI="N", VC="H", VI="H", VA="H", SC="N", SI="N", SA="N")
        rationale = {key: "because" for key in metrics}
        record = cvss4.assess(metrics, rationale)
        self.assertEqual(record["vector"], "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        self.assertEqual((record["score"], record["severity"]), (8.6, "HIGH"))
        with self.assertRaisesRegex(cvss4.CVSSError, "justification"):
            cvss4.assess(metrics, {**rationale, "AV": " "})
        with self.assertRaisesRegex(cvss4.CVSSError, "VC"):
            cvss4.assess({**metrics, "VC": "X"}, rationale)

    def test_matches_first_reference_calculator_sample(self):
        # Results of FIRST cvss-v4-calculator (pinned commit in data/reference/cvss) for 1,500
        # vectors, including threat, environmental and supplemental metrics.
        sample = json.loads(FIRST_SAMPLE.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(sample["vectors"]), 1000)
        self.assertTrue(any("/E:" in v or "/MAV:" in v for v in sample["vectors"]))
        for vector, (macrovector, expected) in sample["vectors"].items():
            self.assertEqual(cvss4.macrovector(cvss4.parse(vector)), macrovector, vector)
            self.assertEqual(cvss4.score(vector), expected, vector)

    def test_provenance_pins_the_verified_table(self):
        provenance = json.loads(PROVENANCE.read_text(encoding="utf-8"))
        self.assertEqual(provenance["lookup_sha256"], cvss4.LOOKUP_SHA256)
        self.assertEqual(len(provenance["reference"]["resolved_commit"]), 40)
        result = provenance["result"]
        self.assertEqual((result["lookup_mismatches"], result["score_mismatches"]), (0, 0))
        sample = json.loads(FIRST_SAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(sample["reference_files"], provenance["reference"]["files"])

    def test_reference_check_reports_every_mismatch(self):
        vectors = cvss4_reference_check.candidate_vectors(0, 1)[:3]
        reference = {
            "lookup": {**cvss4.LOOKUP, "000000": 9.9},
            "maxComposed": cvss4.MAX_COMPOSED, "maxSeverity": {**cvss4.MAX_SEVERITY, "eq1": {}},
            "scores": [[cvss4.macrovector(cvss4.parse(cvss4_reference_check.vector_string(v))),
                        cvss4.score(cvss4_reference_check.vector_string(v))] for v in vectors],
        }
        reference["scores"][1][1] += 0.1
        result = cvss4_reference_check.compare(reference, vectors)
        self.assertEqual([m["macrovector"] for m in result["lookup_mismatches"]], ["000000"])
        self.assertEqual(len(result["score_mismatches"]), 1)
        self.assertTrue(result["max_composed_equal"])
        self.assertFalse(result["max_severity_equal"])


if __name__ == "__main__":
    unittest.main()
