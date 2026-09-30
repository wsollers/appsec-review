"""The SAMPLE report data (brief P): derived blocks come from the real code paths and cannot drift."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "pipeline" / "report"))

import sample_data  # noqa: E402
from cwe_catalog import Catalog  # noqa: E402
from schema_validate import validate_document  # noqa: E402

DATA = json.loads(sample_data.EXAMPLE.read_text(encoding="utf-8"))
GRAPH = json.loads(sample_data.GRAPH.read_text(encoding="utf-8"))["jobs"]


class SampleReportDataTests(unittest.TestCase):
    def test_sample_is_labelled_and_current(self):
        self.assertTrue(DATA["report"]["sample"])
        self.assertTrue(DATA["_comment"].startswith("SAMPLE DATA."))
        self.assertEqual(sample_data.render_text(sample_data.build(DATA)),
                         sample_data.EXAMPLE.read_text(encoding="utf-8"),
                         "stale: run python3 pipeline/report/sample_data.py")

    def test_every_graph_job_is_one_process_grouped_by_its_lane(self):
        ids = [row["id"] for row in DATA["processes"]]
        self.assertEqual(sorted(ids), sorted(GRAPH))
        self.assertEqual(len(ids), len(set(ids)))
        for row in DATA["processes"]:
            self.assertEqual(row["family"], GRAPH[row["id"]]["lane"])
        self.assertEqual([item["id"] for item in DATA["families"]], sorted({job["lane"] for job in GRAPH.values()}))
        self.assertEqual(set(DATA["scoring"]["family_weight"]), {item["id"] for item in DATA["families"]})

    def test_statuses_follow_the_documented_rule_with_real_reason_codes(self):
        for row in DATA["processes"]:
            if row["id"] in sample_data.SKIPPED:
                self.assertEqual((row["status"], row["receipt"]), ("SKIPPED_NA", sample_data.SKIPPED[row["id"]]))
                self.assertTrue(row["receipt"].startswith("not-applicable-"))
            elif row["id"] in sample_data.GAPS:
                self.assertEqual(row["status"], "OK_WITH_GAPS")
            else:
                self.assertEqual(row["status"], "OK")
        source = (ROOT / "finding_enrichment.py").read_text(encoding="utf-8")
        self.assertIn(sample_data.EPSS_KEV_GAP, source)

    def test_threat_workbench_is_the_real_join_projection_with_every_table(self):
        model, record = sample_data.workbench_model()
        self.assertEqual({row["workcell_id"] for row in record["cells"]},
                         {"pii-user-data-mapper", "deployment-topology-mapper", "abuse-scenario-analyst",
                          "attack-tree-builder", "supply-chain-specialist"})
        report = sample_data.synthesis_threat_model(model)
        self.assertEqual(validate_document(report, "synthesis-report.schema.json"), [])
        section = sample_data.threat_workbench(model)
        self.assertEqual(DATA["threat_workbench"], section)
        self.assertEqual(section["status"], "PUBLISHED")
        self.assertTrue(all(section["counts"].values()), section["counts"])
        self.assertEqual({row["exposure"] for row in section["deployment_zones"]}, {"DECLARED_EXPOSURE"})

    def test_chain_and_dependency_sections_come_from_their_builders(self):
        self.assertEqual(DATA["attack_chains"]["status"], "PUBLISHED")
        self.assertEqual(DATA["attack_chains"]["chains"][0]["state"], "supported")
        self.assertEqual(DATA["dependency_reachability"], sample_data.dependency_reachability())
        self.assertEqual(DATA["dependency_reachability"]["reason"], "06-cve-reachability had no SCA match to decide")

    def test_findings_use_the_pinned_cwe_catalog_cvss_and_exploit_signal(self):
        import cvss4
        catalog = Catalog()
        for finding in DATA["findings"]:
            for cwe_id in finding["cwe"].split(", "):
                self.assertEqual(catalog.validate(cwe_id), cwe_id)
            rows = [text for stage, text in finding["trail"] if stage == "12"]
            if finding.get("cvss"):
                self.assertEqual(rows, [f"CVSS {cvss4.score(finding['cvss'])} "
                                        f"{cvss4.severity(cvss4.score(finding['cvss']))} (pinned cvss4.py)"])
            self.assertIn("EPSS/KEV not", finding["exploit_signal"])
        self.assertIn("not assessed", next(f for f in DATA["findings"] if f["id"] == "AR-005")["exploit_signal"])
        producers = {item["producer"] for item in DATA["evidence"]}
        self.assertLessEqual(producers, set(GRAPH))

    @unittest.skipUnless(importlib.util.find_spec("cvss") and importlib.util.find_spec("jinja2"),
                         "the report renderer needs cvss and jinja2 (images/audit-report)")
    def test_renders_and_no_finding_is_critical_so_12b_skips(self):
        spec = importlib.util.spec_from_file_location("appsec_review_sample_renderer",
                                                      ROOT.parent / "pipeline" / "report" / "render.py")
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        with tempfile.TemporaryDirectory() as out:
            data = renderer.render(sample_data.EXAMPLE, Path(out))
            html = (Path(out) / "report.html").read_text(encoding="utf-8")
        self.assertNotIn("Critical", {finding["severity"] for finding in data["findings"]})
        self.assertEqual(data["model"]["n_processes"], len(GRAPH))
        for text in ("Threat model workbench", "privacy-dd-", "zone-local-host", "chain-"):
            self.assertIn(text, html)


if __name__ == "__main__":
    unittest.main()
