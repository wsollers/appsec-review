"""Report section for the correlated dependency reachability (ADR-0023): published, absent, conflict shown
honestly, and the HTML/TeX templates render it."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dependency_reachability_report as section  # noqa: E402
import synthesis_report_presentation as presentation  # noqa: E402

REPORT = {"run_id": "run-1"}
SHA = "sha256:" + "4" * 64
SUMMARY = {"schema": "appsec-review/dependency-reachability-summary/1", "run_id": "run-1", "job_id": "06-cve-reachability",
           "attempt_id": "a1", "source_snapshot_sha256": SHA,
           "counts": {"reachable": 1, "unreachable": 0, "conflict": 1, "unknown": 1},
           "engines": [{"job_id": "06-reachability-codeql", "engine": "codeql", "attempt_id": "c1", "result_sha256": SHA,
                        "status": "OK"},
                       {"job_id": "06-reachability-ir", "engine": "ir", "attempt_id": None, "result_sha256": None,
                        "status": "ABSENT"}],
           "matches": [
               {"match_id": "VM-000003", "component_ref": "SC-000003", "advisory_id": "GHSA-aaaa-bbbb-cccc",
                "component": "left-pad 1.0.0", "ecosystem": "npm", "language": "javascript", "verdict": "unknown",
                "tier": None, "deciding_engines": [], "engines": [{"engine": "codeql", "verdict": "unknown"}],
                "witness_length": 0, "entry": None, "call_site": None, "reason": "no advisory symbols", "gaps": 2},
               {"match_id": "VM-000002", "component_ref": "SC-000002", "advisory_id": "CVE-2022-37434",
                "component": "zlib 1.2.11", "ecosystem": "conan", "language": "cpp", "verdict": "conflict",
                "tier": None, "deciding_engines": ["codeql", "ir"],
                "engines": [{"engine": "codeql", "verdict": "reachable"}, {"engine": "ir", "verdict": "unreachable"}],
                "witness_length": 0, "entry": None, "call_site": None, "reason": "engines disagree", "gaps": 2},
               {"match_id": "VM-000001", "component_ref": "SC-000001", "advisory_id": "GHSA-8q59-q68h-6hv4",
                "component": "PyYAML 5.3.1", "ecosystem": "pypi", "language": "python", "verdict": "reachable",
                "tier": "through-dependency", "deciding_engines": ["codeql"],
                "engines": [{"engine": "codeql", "verdict": "reachable"}, {"engine": "ir", "verdict": "absent"}],
                "witness_length": 3, "entry": {"function": "main", "file": "app/main.py", "line": 1},
                "call_site": {"file": "site-packages/yaml/constructor.py", "line": 9}, "reason": "codeql: path",
                "gaps": 0}],
           "review": {"p1_match_ids": ["VM-000001"], "conflict_match_ids": ["VM-000002"]},
           "coverage_gaps": [], "claim_ceiling": "EVIDENCE_LEADS_ONLY"}


class SectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def publish(self, status="OK"):
        base = self.root / "data" / "jobs" / "06-cve-reachability"
        base.mkdir(parents=True)
        (base / "accepted.json").write_text(json.dumps({"status": status, "attempt_id": "a1"}))

    def test_absent_06_is_a_limitation(self):
        value = section.build(REPORT, self.root)
        self.assertEqual((value["status"], value["rows"]), ("ABSENT", []))
        self.assertIn("every dependency match is unknown", value["gaps"][0])

    def test_published_rows_order_and_conflict_gap(self):
        self.publish()
        with mock.patch.object(section.bounded_analysis_workers, "load_accepted",
                               return_value=(SUMMARY, {"artifact_sha256": SHA})) as loader:
            value = section.build(REPORT, self.root)
        self.assertEqual(loader.call_args.kwargs["artifact"], "outputs/dependency-reachability-summary.json")
        self.assertEqual([row["verdict"] for row in value["rows"]], ["reachable", "conflict", "unknown"])
        first = value["rows"][0]
        self.assertEqual((first["tier"], first["entry"], first["call_site"]),
                         ("through-dependency", "main (app/main.py:1)", "site-packages/yaml/constructor.py:9"))
        self.assertEqual(value["counts"], {"reachable": 1, "conflict": 1, "unknown": 1, "unreachable": 0})
        self.assertEqual(value["gaps"], ["dependency-reachability: VM-000002 CVE-2022-37434 engines disagree "
                                         "(conflict); left for review"])
        self.assertIn("unknown is a coverage gap", value["note"])

    @unittest.skipUnless(importlib.util.find_spec("cvss") and importlib.util.find_spec("jinja2"),
                         "the report renderer needs cvss and jinja2 (images/audit-report)")
    def test_templates_render_the_section(self):
        self.publish()
        with mock.patch.object(section.bounded_analysis_workers, "load_accepted",
                               return_value=(SUMMARY, {"artifact_sha256": SHA})):
            value = section.build(REPORT, self.root)
        projected = presentation._dependency_reachability(value)
        self.assertEqual(set(projected), {"status", "reason", "counts", "rows", "note"})
        path = ROOT.parent / "pipeline" / "report" / "render.py"
        spec = importlib.util.spec_from_file_location("appsec_review_report_renderer_test", path)
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        data = json.loads((ROOT.parent / "pipeline" / "report" / "examples" / "hello-autotools.review.json").read_text())
        for variant in (projected, None):
            with self.subTest(section=variant is not None), tempfile.TemporaryDirectory() as out:
                document = copy.deepcopy(data)
                document.pop("dependency_reachability", None)   # the sample carries its own 3B section
                if variant is not None:
                    document["dependency_reachability"] = variant
                source = Path(out) / "review.json"
                source.write_text(json.dumps(document))
                renderer.render(source, Path(out) / "presentation")
                html = (Path(out) / "presentation" / "report.html").read_text()
                tex = (Path(out) / "presentation" / "report.tex").read_text()
                self.assertIn("Dependency reachability", html)
                self.assertIn("\\section{Dependency reachability}", tex)
                if variant is not None:
                    self.assertIn("GHSA-8q59-q68h-6hv4", html)
                    self.assertIn("conflict", html)
                    self.assertIn("through-dependency", tex)
                else:
                    self.assertIn("No dependency reachability.", html)


if __name__ == "__main__":
    unittest.main()
