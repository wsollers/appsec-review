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
        citation = {"citation_id":"citation-1","producer_job_id":"native-sast","producer_attempt_id":"a1",
            "artifact_path": "src/main.c", "artifact_sha256":"sha256:"+"c"*64,
            "locator_json": "12-14", "observed_fact":"A bounded write was independently verified."}
        report = {"schema":"appsec-review/synthesis-report/1.0","status": "DRAFT_EVIDENCE_BACKED",
            "run_id":"run-1","source_generation":"g1","component_generation":"g1",
            "ledger_head_id":"l1","ledger_head_sha256":"sha256:"+"d"*64,
            "input_manifest_sha256":"sha256:"+"e"*64,"generator_sha256":"sha256:"+"f"*64,
            "scope":{"target":"fixture","components":[{"component_id":"parser","name":"Parser","purpose":"Parse"}]},
            "owasp_coverage":{"denominators":{"selected":0,"applicable":0,"assessed":0,"satisfied":0},
                "applicability_counts":{"applicable":0,"conditional":0,"not_applicable":0,"cannot_determine":0,"out_of_scope":0},
                "assessment_counts":{"satisfied":0,"partially_satisfied":0,"not_satisfied":0,"cannot_verify":0,
                    "dynamic_test_required":0,"human_decision_required":0,"not_assessed":0,"not_applicable":0,
                    "cannot_determine":0,"out_of_scope":0}},
            "verified_findings": [{"claim_id": "claim-1", "title": "Bounded write", "severity": "CRITICAL",
                "priority": "P0", "score": 16, "confidence": "high", "component_ids": ["parser"],
                "dissent_ids":[],"citations":[citation],"verification_citations": [citation]}],
            "unresolved_candidates":[],"dissent_ids":[],"limitations":[],
            "decision":{"recommendation":"HUMAN_DECISION_REQUIRED","basis":"Human approval required."},
            "claim_limits":{"final":False,"human_signoff":False,"scoring_derived":False,"runtime_claimed":False,
                "compliance_claimed":False,"remediation_claimed":False}}
        trace = {"schema":"appsec-review/evidence-trace-index/1.0","run_id":"run-1",
            "ledger_head_sha256":"sha256:"+"d"*64,"upstream":[],
            "citations": [{"claim_id": "claim-1", **citation}]}
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

    def test_trace_mismatch_and_unsafe_uri_reject(self):
        report, trace = self.values(); trace["citations"][0]["artifact_sha256"]="sha256:"+"0"*64
        with self.assertRaisesRegex(Blocked,"exactly match"):
            synthesis_sarif.build(report,trace,report_sha256="x",trace_sha256="y")
        report, trace = self.values()
        report["verified_findings"][0]["citations"][0]["artifact_path"]="../escape.c"
        report["verified_findings"][0]["verification_citations"][0]["artifact_path"]="../escape.c"
        trace["citations"][0]["artifact_path"]="../escape.c"
        with self.assertRaisesRegex(Blocked,"unsafe"):
            synthesis_sarif.build(report,trace,report_sha256="x",trace_sha256="y")


if __name__ == "__main__": unittest.main()
