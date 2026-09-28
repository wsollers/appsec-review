"""Replay on the retained be3585 (appsec-multi-vuln) run: real leads, real CPG, canned reviewer decisions.

Read-only: the run directory is only read.  Skipped when the run is not on this host.  The finding is
the strcpy at projects/cpp/case-001/main.cpp:7, flagged by Semgrep and the Clang Static Analyzer.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import claim_ledger
import claim_lifecycle_core as core
import finding_enrichment as enrichment
import synthesis_report_presentation as presentation

RUN = Path(os.environ.get("APPSEC_REPLAY_RUN", "/mnt/projects-drive/projects/appsec-review/appsec-review-process/"
                          "runs/20260928T034921Z-be3585"))
TARGET = ("projects/cpp/case-001/main.cpp", 7)
METRICS = dict(AV="L", AC="L", AT="N", PR="N", UI="N", VC="H", VI="H", VA="H", SC="N", SI="N", SA="N")
RATIONALE = {"AV": "Input is argv[1] of a local command-line program.", "AC": "No race or layout condition.",
             "AT": "No deployment precondition.", "PR": "Any local user can run the program.",
             "UI": "No other user interaction.", "VC": "Stack overwrite can expose process memory.",
             "VI": "Return address / locals can be overwritten.", "VA": "The process crashes on overflow.",
             "SC": "No downstream system.", "SI": "No downstream system.", "SA": "No downstream system."}


def accepted(job: str) -> tuple[Path, str]:
    attempt_id = json.loads((RUN / "data/jobs" / job / "accepted.json").read_text())["attempt_id"]
    return RUN / "data/jobs" / job / "attempts" / attempt_id, attempt_id


def lead_citations() -> list[dict]:
    citations = []
    for job, artifact in (("02-source-sast", "source-sast.json"), ("02-native-sast", "native-sast.json")):
        attempt, attempt_id = accepted(job)
        document = json.loads((attempt / artifact).read_text())
        source = {"producer_job_id": job, "producer_attempt_id": attempt_id, "lead_artifact": artifact,
                  "artifact_path": artifact, "artifact_sha256": "sha256:" + "0" * 64}
        for lead in claim_ledger.normalize_leads(job, document):
            if (lead.get("path"), lead.get("start_line")) == TARGET:
                citations.append(claim_ledger._lead_citation(source, lead))
    return citations


@unittest.skipUnless((RUN / "data/jobs/02-code-property-graph/accepted.json").is_file(), "be3585 run not on this host")
class Be3585ReplayTests(unittest.TestCase):
    def test_case_001_strcpy_gets_cwe_cvss_witness_and_snippet(self):
        citations = lead_citations()
        self.assertEqual({json.loads(c["locator_json"])["tool_id"] for c in citations},
                         {"semgrep-repository-rules-v1", "clang-static-analyzer"})
        # Canned reviewer decisions: 09 names the weakness, 12 proposes CVSS base metrics.
        judgment = core._cwe_judgment("09-independent-verification", {"cwe": {
            "cwe_id": "CWE-121", "rationale": "strcpy of argv[1] into char buffer[16] on the stack"}})
        cvss = core._cvss_assessment({"cvss_v4": {"metrics": METRICS, "rationale": RATIONALE}})
        proposal = core._remediation_proposal({"remediation": {
            "objective": "Reject or truncate inputs longer than 15 bytes before copying into buffer.",
            "patch_proposal": "Replace std::strcpy(buffer, value) with a bounded copy (snprintf(buffer, sizeof buffer, \"%s\", value))."}})
        finding = {"claim_id": "claim-case001-strcpy", "title": "Stack buffer overflow: strcpy of argv[1]",
                   "component_ids": ["cpp-sample-cases"], "confidence": "high", "severity": cvss["severity"],
                   "priority": "P1", "score": 12, "dissent_ids": [], "citations": citations,
                   "verification_citations": citations[:1], "cwe_judgments": [judgment], "cvss_v4": cvss,
                   "remediation_proposal": proposal}
        report = {"run_id": RUN.name, "ledger_head_sha256": "sha256:" + "0" * 64, "verified_findings": [finding]}
        result = enrichment.build(report, RUN, snapshot_dir=Path(tempfile.gettempdir()) / "no-epss-kev-snapshot")
        row = result["findings"][0]
        self.assertEqual(row["cwe"]["primary"], "CWE-121")
        self.assertEqual([item["cwe_id"] for item in row["cwe"]["ids"]], ["CWE-121", "CWE-120", "CWE-676"])
        self.assertEqual(row["cvss_v4"]["vector"], "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        self.assertEqual(row["cvss_v4"]["score"], 8.6)
        reach = row["reachability"]
        self.assertEqual(reach["state"], "REACHABLE")
        self.assertEqual((reach["witness"][0]["function"], reach["witness"][0]["file"], reach["witness"][0]["line"]),
                         ("main", "projects/cpp/case-001/main.cpp", 4))
        self.assertEqual((reach["witness"][-1]["file"], reach["witness"][-1]["line"]), TARGET)
        self.assertEqual(row["severity"]["final"], "HIGH")
        snippet = row["snippets"][0]
        self.assertEqual(snippet["status"], "VERIFIED")
        self.assertIn("std::strcpy(buffer, value);", snippet["source"][TARGET[1] - snippet["start"]])
        self.assertEqual(row["remediation"]["items"][0]["status"], "PATCH_PROPOSED_UNVALIDATED")
        self.assertTrue(any("EPSS/KEV not assessed" in gap for gap in result["gaps"]))
        evidence_ids = {c["citation_id"]: f"E-{n:03d}" for n, c in enumerate(citations, 1)}
        rendered = presentation._findings(report, evidence_ids, result)[0]
        self.assertEqual(rendered["cwe"], "CWE-121, CWE-120, CWE-676")
        self.assertTrue(rendered["reachability"].startswith(
            "REACHABLE via main() projects/cpp/case-001/main.cpp:4 -> projects/cpp/case-001/main.cpp:7"))
        if os.environ.get("APPSEC_REPLAY_PRINT"):
            print(json.dumps({"enrichment": row, "presentation": rendered}, indent=1))


if __name__ == "__main__":
    unittest.main()
