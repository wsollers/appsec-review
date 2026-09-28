"""Pinned CVSS v4.0 calculator (ADR-0020).

Expected scores are FIRST CVSS v4.0 calculator results for widely published vectors (the
specification's examples and common NVD CNA vectors); the full macrovector table is pinned by hash.
"""
from __future__ import annotations

import itertools
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import cvss4

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


if __name__ == "__main__":
    unittest.main()
