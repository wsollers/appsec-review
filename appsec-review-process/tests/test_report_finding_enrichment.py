"""Reviewer judgment through 07/09/12 and deterministic finding enrichment for the report (ADR-0020)."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import claim_lifecycle_core as core
from execution_state import Blocked
import finding_enrichment as enrichment
from schema_validate import validate_document
import synthesis_report_presentation as presentation

FIXTURES = ROOT / "tests/fixtures/claim-lifecycle"
A = "claim-aaaaaaaaaaaaaaaaaaaaaaaa"
METRICS = dict(AV="N", AC="L", AT="N", PR="N", UI="N", VC="H", VI="H", VA="H", SC="N", SI="N", SA="N")


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def binding(job, artifact):
    return {"job_id": job, "attempt_id": job + "-1", "pointer_sha256": "sha256:" + "1" * 64,
            "artifact_path": artifact, "artifact_sha256": "sha256:" + "2" * 64}


def chain(red_cwe=None, verify_cwe=None, score_extra=None):
    red_decisions, verify_decisions, score_decisions = (fixture("red-decisions.json"),
        fixture("verification-decisions.json"), fixture("scoring-decisions.json"))
    for rows, value in ((red_decisions, red_cwe), (verify_decisions, verify_cwe)):
        if value is not None:
            next(row for row in rows["decisions"] if row["claim_id"] == A)["cwe"] = value
    if score_extra:
        next(row for row in score_decisions["decisions"] if row["claim_id"] == A).update(score_extra)
    red = core.red_team(fixture("claim-ledger.json"), binding("claim-ledger-routing", "claim-decision-ledger.json"),
                        red_decisions)
    blue = core.blue_team(red, binding("07-red-team-adversarial", "red-team-adversarial.json"),
                          fixture("blue-decisions.json"))
    verification = core.verify(blue, binding("08-blue-team-refutation", "blue-team-refutation.json"), verify_decisions)
    return core.score(verification, binding("09-independent-verification", "independent-verification.json"),
                      score_decisions)


class LifecycleJudgmentTests(unittest.TestCase):
    def test_cwe_judgments_carry_forward_and_cvss_sets_severity(self):
        cvss = {"metrics": dict(METRICS, AV="L"), "rationale": {key: "why " + key for key in METRICS}}
        scoring = chain({"cwe_id": "CWE-120", "rationale": "unbounded strcpy"},
                        {"cwe_id": "121", "rationale": "destination is a stack array"},
                        {"cvss_v4": cvss, "remediation": {"objective": "Bound the copy to sizeof(buffer)"}})
        self.assertEqual(validate_document(scoring, "scoring-prioritization.schema.json"), [])
        row = next(item for item in scoring["priorities"] if item["claim_id"] == A)
        self.assertEqual([(j["stage"], j["cwe_id"]) for j in row["cwe_judgments"]],
                         [("07-red-team-adversarial", "CWE-120"), ("09-independent-verification", "CWE-121")])
        self.assertEqual(row["cwe_judgments"][1]["cwe_name"], "Stack-based Buffer Overflow")
        self.assertEqual(row["cvss_v4"]["vector"], "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        self.assertEqual((row["cvss_v4"]["score"], row["severity"], row["priority"]), (8.6, "HIGH", "P1"))
        self.assertEqual(row["remediation_proposal"]["status"], "PATCH_PROPOSED_UNVALIDATED")
        plain = next(item for item in chain()["priorities"] if item["claim_id"] == A)
        self.assertNotIn("cwe_judgments", plain)
        self.assertEqual(plain["severity"], "CRITICAL")

    def test_invalid_judgments_fail_closed(self):
        with self.assertRaisesRegex(Blocked, "pinned CWE catalog"):
            chain(verify_cwe={"cwe_id": "CWE-99999", "rationale": "x"})
        with self.assertRaisesRegex(Blocked, "cwe judgment"):
            chain(red_cwe={"cwe_id": "CWE-120"})
        with self.assertRaisesRegex(Blocked, "cvss_v4"):
            chain(score_extra={"cvss_v4": {"metrics": dict(METRICS, AV="Z"), "rationale": {k: "x" for k in METRICS}}})
        decisions = fixture("scoring-decisions.json")
        unresolved = next(row for row in decisions["decisions"] if row["claim_id"] != A)
        unresolved["cvss_v4"] = {"metrics": METRICS, "rationale": {k: "x" for k in METRICS}}
        with self.assertRaisesRegex(Blocked, "cannot receive score factors"):
            core.score(core.verify(core.blue_team(core.red_team(fixture("claim-ledger.json"),
                binding("claim-ledger-routing", "l.json"), fixture("red-decisions.json")),
                binding("07-red-team-adversarial", "r.json"), fixture("blue-decisions.json")),
                binding("08-blue-team-refutation", "b.json"), fixture("verification-decisions.json")),
                binding("09-independent-verification", "v.json"), decisions)


SOURCE = b"#include <cstring>\nint main(int argc, char** argv) {\n    char b[16];\n    helper(argv[1]);\n    return 0;\n}\nvoid helper(const char* s) {\n    char buffer[16];\n    std::strcpy(buffer, s);\n}\nvoid orphan(const char* s) {\n    char c[4];\n    std::strcpy(c, s);\n}\n"
SHA = "sha256:" + hashlib.sha256(SOURCE).hexdigest()


def write_run(root: Path) -> None:
    tree = root / "data/automatic-inputs/source/source-1/tree/app"; tree.mkdir(parents=True)
    (tree / "main.cpp").write_bytes(SOURCE)
    attempt = root / "data/jobs/02-code-property-graph/attempts/cpg-1"; attempt.mkdir(parents=True)
    def method(full, name, start, end):
        return {"kind": "symbol", "label": "METHOD", "full_name": full, "name": name, "source_path": "app/main.cpp",
                "start_line": start, "end_line": end, "source_sha256": SHA}
    def call(caller, callee, name, line):
        return {"kind": "call", "label": "CALL", "caller": caller, "full_name": callee, "name": name,
                "source_path": "app/main.cpp", "start_line": line, "code": name}
    records = [method("main:int(int,char**)", "main", 2, 6), method("helper:void(char*)", "helper", 7, 10),
               method("orphan:void(char*)", "orphan", 11, 14),
               call("main:int(int,char**)", "helper:void(char*)", "helper", 4),
               call("helper:void(char*)", "<unresolvedNamespace>.strcpy:<unresolvedSignature>(2)", "strcpy", 9),
               call("orphan:void(char*)", "<unresolvedNamespace>.strcpy:<unresolvedSignature>(2)", "strcpy", 13)]
    data = "".join(json.dumps(item) + "\n" for item in records).encode()
    (attempt / "code-property-graph.records.jsonl").write_bytes(data)
    (attempt / "code-property-graph.json").write_text(json.dumps({"coverage_gaps": [{"reason": "duplicate", "count": 1}],
        "source_snapshot_sha256": "sha256:" + "3" * 64, "records_file": {"path": "code-property-graph.records.jsonl",
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(), "count": len(records)}}))
    (root / "data/jobs/02-code-property-graph/accepted.json").write_text(
        json.dumps({"attempt_id": "cpg-1", "status": "OK_WITH_GAPS"}))
    remediation = root / "data/jobs/11-remediation-proposal/attempts/rem-1"; remediation.mkdir(parents=True)
    (remediation / "remediation-proposal.json").write_text(json.dumps({"proposals": [
        {"claim_id": "claim-reach", "status": "PROPOSED_REVIEW_REQUIRED", "remediation_objective": "Bound the copy.",
         "patch_status": "NOT_GENERATED", "retest": {"status": "NOT_RUN"}}]}))
    (root / "data/jobs/11-remediation-proposal/accepted.json").write_text(
        json.dumps({"attempt_id": "rem-1", "status": "OK_WITH_GAPS"}))


def citation(line, tool="clang-static-analyzer", rule="security.insecureAPI.strcpy"):
    locator = {"lead_ref": f"lead_{line}", "tool_id": tool, "rule_id": rule, "category": "buffer-safety",
               "path": "app/main.cpp", "start_line": line, "source_sha256": SHA}
    return {"citation_id": f"citation-{line}-{tool}", "producer_job_id": "02-native-sast", "producer_attempt_id": "n-1",
            "artifact_path": "native-sast.json", "artifact_sha256": "sha256:" + "4" * 64,
            "locator_json": json.dumps(locator, sort_keys=True), "observed_fact": f"{tool} flagged app/main.cpp:{line}"}


def report_with(findings):
    return {"schema": "appsec-review/synthesis-report/1.0", "status": "DRAFT_EVIDENCE_BACKED", "run_id": "run-1",
            "ledger_head_sha256": "sha256:" + "5" * 64, "verified_findings": findings}


def finding(claim_id, line, severity, **extra):
    return {"claim_id": claim_id, "title": "strcpy overflow", "component_ids": ["app"], "confidence": "high",
            "severity": severity, "priority": "P0", "score": 16, "dissent_ids": [],
            "citations": [citation(line), citation(line, "semgrep-repository-rules-v1", "appsec.c.strcpy")],
            "verification_citations": [citation(line)], **extra}


class EnrichmentTests(unittest.TestCase):
    def test_reachability_arbitrates_severity_and_fields_are_collected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); write_run(root)
            judgment = {"stage": "09-independent-verification", "cwe_id": "CWE-121",
                        "cwe_name": "Stack-based Buffer Overflow", "rationale": "stack array"}
            cvss = {"version": "4.0", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    "score": 9.3, "severity": "CRITICAL"}
            report = report_with([finding("claim-reach", 9, "CRITICAL", cwe_judgments=[judgment], cvss_v4=cvss),
                                  finding("claim-orphan", 13, "CRITICAL")])
            result = enrichment.build(report, root, snapshot_dir=root / "no-snapshot")
            reach, orphan = result["findings"]
            self.assertEqual(reach["reachability"]["state"], "REACHABLE")
            self.assertEqual([step["function"] for step in reach["reachability"]["witness"]],
                             ["main", "helper", "(finding location)"])
            self.assertEqual(reach["severity"], {"lifecycle": "CRITICAL", "basis": "CVSS v4.0", "final": "CRITICAL",
                                                 "reachability_cap": None})
            self.assertEqual(reach["cwe"]["primary"], "CWE-121")
            self.assertEqual(reach["cwe"]["display"], "CWE-121, CWE-120, CWE-676")
            self.assertEqual(orphan["reachability"]["state"], "UNREACHABLE")
            self.assertEqual(orphan["severity"]["final"], "HIGH")
            self.assertIn("UNREACHABLE", orphan["severity"]["reachability_cap"])
            self.assertEqual(orphan["cwe"]["basis"], "tool rule metadata")
            self.assertEqual(reach["snippets"][0]["status"], "VERIFIED")
            self.assertEqual(reach["remediation"]["items"][0]["source"], "11-remediation-proposal")
            self.assertIsNone(reach["epss_kev"])
            self.assertTrue(any("EPSS/KEV not assessed" in gap for gap in result["gaps"]))
            self.assertEqual(result, enrichment.build(copy.deepcopy(report), root, snapshot_dir=root / "no-snapshot"))
            rows = presentation._findings(report, {c["citation_id"]: "E-001" for f in report["verified_findings"]
                                                   for c in f["citations"] + f["verification_citations"]}, result)
            self.assertEqual(rows[0]["severity_override"], "Critical")
            self.assertEqual(rows[0]["cvss"], cvss["vector"])
            self.assertEqual(rows[0]["cvss_score"], 9.3)
            self.assertTrue(rows[0]["reachability"].startswith("REACHABLE via main() app/main.cpp:2"))
            self.assertEqual(rows[0]["snippets"][0]["flaw"], [9])
            self.assertEqual(rows[1]["severity_override"], "High")
            self.assertIn("UNREACHABLE", rows[1]["reachability"])

    def test_missing_cpg_is_unknown_and_caps_critical(self):
        with tempfile.TemporaryDirectory() as directory:
            result = enrichment.build(report_with([finding("claim-x", 9, "CRITICAL")]), Path(directory),
                                      snapshot_dir=Path(directory) / "none")
            row = result["findings"][0]
            self.assertEqual((row["reachability"]["state"], row["severity"]["final"]), ("UNKNOWN", "HIGH"))
            self.assertEqual(row["snippets"][0]["status"], "WITHHELD")
            self.assertTrue(any("REACHABILITY_UNKNOWN" in gap for gap in result["gaps"]))

    def test_dependency_findings_use_06_and_epss_kev_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            attempt = root / "data/jobs/06-cve-reachability/attempts/r-1/outputs"; attempt.mkdir(parents=True)
            (attempt / "cve-reachability.json").write_text(json.dumps({"assessments": [
                {"assessment_id": "RA-000001", "match_ref": "VM-000001", "classification": "reachable",
                 "evidence": [{"kind": "call", "path": "app/main.cpp", "sha256": SHA, "locator": "main@2"}]}]}))
            (root / "data/jobs/06-cve-reachability/accepted.json").write_text(
                json.dumps({"attempt_id": "r-1", "status": "OK"}))
            locator = {"lead_ref": "VM-000001", "tool_id": "osv-scanner", "rule_id": "GHSA-x", "category": "dependency",
                       "component_ref": "SC-000001", "aliases": ["CVE-2025-0001", "GHSA-aaaa-bbbb-cccc"]}
            dep = {"citation_id": "c-dep", "producer_job_id": "02-sca-vulnerability-match", "producer_attempt_id": "s",
                   "artifact_path": "sca.json", "artifact_sha256": "sha256:" + "6" * 64,
                   "locator_json": json.dumps(locator), "observed_fact": "match"}
            report = report_with([{**finding("claim-dep", 1, "CRITICAL"), "citations": [dep],
                                   "verification_citations": [dep]}])
            from tests import test_report_reference_data as reference
            epss, kev = reference.EPSSKEVSnapshotTests().write_sources(root)
            import epss_kev_snapshot
            epss_kev_snapshot.intake(epss, kev, root / "snap")
            row = enrichment.build(report, root, snapshot_dir=root / "snap")["findings"][0]
            self.assertEqual((row["reachability"]["state"], row["severity"]["final"]), ("REACHABLE", "CRITICAL"))
            self.assertEqual((row["epss_kev"]["epss"], row["epss_kev"]["kev"], row["epss_kev"]["as_of"]),
                             (0.91234, True, "2026-09-26"))


if __name__ == "__main__":
    unittest.main()
