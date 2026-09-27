from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from execution_state import Blocked
import synthesis_sarif


class SynthesisSarifTests(unittest.TestCase):
    def values(self):
        citation = {"artifact_path": "src/main.c", "locator_json": "12-14", "citation_id": "citation-1"}
        report = {"status": "DRAFT_EVIDENCE_BACKED", "claim_limits": {"final": False},
            "verified_findings": [{"claim_id": "claim-1", "title": "Bounded write", "severity": "CRITICAL",
                "priority": "P0", "score": 16, "confidence": "high", "component_ids": ["parser"],
                "verification_citations": [citation]}]}
        trace = {"citations": [{"claim_id": "claim-1", "citation_id": "citation-1"}]}
        return report, trace

    def test_only_traced_verified_findings_project_with_hash_binding(self):
        report, trace = self.values()
        value = synthesis_sarif.build(report, trace, report_sha256="sha256:" + "a" * 64,
                                      trace_sha256="sha256:" + "b" * 64)
        result = value["runs"][0]["results"][0]
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"],
                         {"startLine": 12, "endLine": 14})
        self.assertEqual(result["properties"]["reportSha256"], "sha256:" + "a" * 64)

    def test_untraced_duplicate_and_non_draft_findings_reject(self):
        report, trace = self.values(); trace["citations"] = []
        with self.assertRaises(Blocked): synthesis_sarif.build(report, trace, report_sha256="x", trace_sha256="y")
        report, trace = self.values(); report["verified_findings"].append(deepcopy(report["verified_findings"][0]))
        with self.assertRaises(Blocked): synthesis_sarif.build(report, trace, report_sha256="x", trace_sha256="y")
        report, trace = self.values(); report["status"] = "FINAL_APPROVED"
        with self.assertRaises(Blocked): synthesis_sarif.build(report, trace, report_sha256="x", trace_sha256="y")


if __name__ == "__main__": unittest.main()
