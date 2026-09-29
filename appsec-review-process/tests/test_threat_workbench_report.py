"""Workbench records in the synthesis report (brief M2, ADR-0019 open decision 4).

03's data classes, LINDDUN privacy threats, deployment zones and attack trees travel through the
closed ``synthesis-report`` schema into ``report.md``/appendix and the rendered report section 3C.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import synthesis_report as synthesis  # noqa: E402
import synthesis_report_presentation as presentation  # noqa: E402
from schema_validate import validate_document  # noqa: E402
import test_synthesis_report as base  # noqa: E402  (module import: its tests are not re-collected here)

GOLDEN = ROOT / "tests" / "fixtures" / "threat-workbench" / "schema" / "integrated-threat-model.golden.json"
PRIVACY = {"privacy_threat_id": "pt-profile-linking", "linddun_category": "linking",
           "statement": "Profile records can be linked across tenants through the shared user id.",
           "target_element_ids": ["el-user-db"], "target_flow_ids": ["flow-login"],
           "data_class_ids": ["dc-pii-profile"], "proof_obligations": ["Show the join key is tenant scoped."],
           "regulatory_candidate_notes": ["GDPR Art. 5(1)(c) data minimisation (candidate)"],
           "evidence_class": "WEAK_INFERENCE", "confidence": "medium", "citations": [],
           "originating_workcell_id": "pii-user-data-mapper"}


def workbench_threat_model() -> dict:
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    return {key: golden[key] for key in ("data_classes", "deployment_zones", "attack_trees")} | \
        {"privacy_threats": [PRIVACY]}


class ThreatWorkbenchReportTests(unittest.TestCase):
    def build(self, extra: dict | None = None):
        inputs = base.SynthesisReportTests().inputs()
        inputs["documents"]["threat"].update(extra or {})
        return synthesis.build_report(inputs)[0]

    def test_report_carries_workbench_families_in_the_closed_schema(self):
        records = workbench_threat_model()
        report = self.build(records)
        self.assertEqual(validate_document(report, "synthesis-report.schema.json"), [])
        for key, rows in records.items():
            self.assertEqual([json.loads(item) for item in report["threat_model"][key]], rows, key)
        # A pre-workbench threat model still yields the (empty) families.
        self.assertEqual(self.build()["threat_model"]["privacy_threats"], [])

    def test_schema_still_accepts_a_pre_workbench_report(self):
        report = self.build()
        for key in ("data_classes", "privacy_threats", "deployment_zones"):
            del report["threat_model"][key]
        self.assertEqual(validate_document(report, "synthesis-report.schema.json"), [])
        report["threat_model"]["unknown_family"] = []
        self.assertNotEqual(validate_document(report, "synthesis-report.schema.json"), [])

    def test_markdown_lists_counts_and_ids_only(self):
        report_md, appendix = synthesis.render_markdown(self.build(workbench_threat_model()))
        self.assertIn("## Threat model workbench", report_md)
        self.assertIn("2 data classes, 1 privacy threats, 2 deployment zones, 1 attack trees", report_md)
        self.assertIn("LINDDUN categories raised: linking.", report_md)
        self.assertNotIn(PRIVACY["statement"], report_md + appendix)   # model text stays out of report.md
        self.assertIn("| privacy threat | `pt-profile-linking` | linking |", appendix)
        self.assertIn("| attack tree | `tree-account-takeover` | 3 nodes |", appendix)

    def test_presentation_section_projects_and_summarises(self):
        report = self.build(workbench_threat_model())
        section = presentation._threat_workbench(report["threat_model"])
        self.assertEqual(section["status"], "PUBLISHED")
        self.assertEqual(section["counts"], {"data_classes": 2, "privacy_threats": 1,
                                             "deployment_zones": 2, "attack_trees": 1})
        credential = section["data_classes"][0]
        self.assertEqual((credential["id"], credential["stores"], credential["flows"]),
                         ("dc-credential", "el-user-db", "flow-login"))
        self.assertIn("retention: documented", section["data_classes"][1]["handling"])
        self.assertEqual(section["privacy_threats"][0]["targets"], "el-user-db, flow-login")
        self.assertEqual({row["exposure"] for row in section["deployment_zones"]}, {"DECLARED_EXPOSURE"})
        tree = section["attack_trees"][0]
        self.assertEqual((tree["nodes"], tree["gates"], tree["leaves"]), (3, 1, 2))
        self.assertEqual(tree["leaf_support"], {"evidence": 0, "assumption": 1, "unresolved": 1})
        self.assertEqual(tree["verification_items"], ["thr-login-spoofing"])

    def test_absent_and_empty_sections_are_stated(self):
        self.assertEqual(presentation._threat_workbench(None)["status"], "ABSENT")
        self.assertEqual(presentation._threat_workbench({"elements": []})["status"], "ABSENT")
        empty = presentation._threat_workbench(self.build()["threat_model"])
        self.assertEqual(empty["status"], "PUBLISHED")
        self.assertIn("published no data class", empty["reason"])

    @unittest.skipUnless(importlib.util.find_spec("cvss") and importlib.util.find_spec("jinja2"),
                         "the report renderer needs cvss and jinja2 (images/audit-report)")
    def test_templates_render_the_section(self):
        path = ROOT.parent / "pipeline" / "report" / "render.py"
        spec = importlib.util.spec_from_file_location("appsec_review_report_renderer_tw", path)
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        example = json.loads((ROOT.parent / "pipeline" / "report" / "examples" /
                              "hello-autotools.review.json").read_text(encoding="utf-8"))
        self.assertEqual(example["threat_workbench"]["status"], "PUBLISHED")   # fixture output shows 3C
        section = presentation._threat_workbench(self.build(workbench_threat_model())["threat_model"])
        for variant in (section, None):
            with self.subTest(section=variant is not None), tempfile.TemporaryDirectory() as out:
                document = copy.deepcopy(example)
                document.pop("threat_workbench")
                if variant is not None:
                    document["threat_workbench"] = variant
                source = Path(out) / "review.json"
                source.write_text(json.dumps(document), encoding="utf-8")
                renderer.render(source, Path(out) / "presentation")
                html = (Path(out) / "presentation" / "report.html").read_text(encoding="utf-8")
                tex = (Path(out) / "presentation" / "report.tex").read_text(encoding="utf-8")
                self.assertIn("Threat model workbench", html)
                self.assertIn("\\section{Threat model workbench}", tex)
                if variant is not None:
                    self.assertIn("pt-profile-linking", html)
                    self.assertIn("Privacy threats (LINDDUN)", tex)
                    self.assertIn("tree-account-takeover", html)
                    self.assertIn("DECLARED\\_EXPOSURE", tex)
                else:
                    self.assertIn("No threat workbench records.", html)


if __name__ == "__main__":
    unittest.main()
