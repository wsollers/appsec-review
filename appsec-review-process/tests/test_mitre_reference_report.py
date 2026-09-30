"""Report section for the MITRE tables the run's model jobs used (ADR-0034 addendum item 3): distinct
entries, gap lines, "not used", hash checks against the accepted pointer, and the templates render it."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from execution_state import Blocked, file_hash  # noqa: E402
import mitre_query_mcp as mq  # noqa: E402
import mitre_reference_report as section  # noqa: E402
from schema_validate import validate_document  # noqa: E402

REPORT = {"run_id": "run-1"}
OK_BOUND = {"mitre_reference": {"status": "OK", "reference_sha256": "a" * 64,
                                "attack_versions": {"enterprise-attack": "19.2"}, "capec_version": "3.9"},
            "cwe_catalog": {"catalog_source": "mitre-feed", "catalog_version": "4.17",
                            "catalog_sha256": "sha256:" + "b" * 64}}
GAP_BOUND = {"mitre_reference": {"status": "MITRE_REFERENCE_STALE"},
             "cwe_catalog": {"catalog_source": "committed-curated", "catalog_version": "CWE List 4.14 (curated subset)",
                             "catalog_sha256": "sha256:" + "c" * 64, "reference_gap": "CWE_REFERENCE_STALE"}}
OK_ENTRY = mq.record(OK_BOUND, snapshot_id="sha256-0123456789abcdef")
GAP_ENTRY = mq.record(GAP_BOUND)


def manifest(entry=None):
    value = {"schema": "appsec-review/persona-invoker-output/1.0", "request_sha256": "sha256:" + "1" * 64,
             "invoker_id": "claude-cli", "persona_id": "claim-reviewer", "persona_sha256": "sha256:" + "2" * 64,
             "model": {"provider": "anthropic", "family": "claude-sonnet-5", "model_id": "claude-sonnet-5",
                       "snapshot": "claude-sonnet-5"},
             "usage": {"input_bytes": 1, "input_units": 1, "output_bytes": 0, "output_units": 0, "tool_calls": 0},
             "tool_calls": [], "files": [{"path": "result.json", "sha256": "sha256:" + "3" * 64, "bytes": 2}],
             "claims": [], "verified_invocations": [], "injection_suspected": [],
             "limitations": ["claude-cli dispatch"]}
    return {**value, "mitre_reference": entry} if entry is not None else value


class SectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def publish(self, job, entries, status="OK", attempt="a1"):
        """An accepted attempt of ``job`` (``job`` or ``job/partition``) holding one invoker output per entry."""
        base = self.root / "data" / "jobs" / job
        tree = base / "attempts" / attempt
        for index, entry in enumerate(entries):
            path = tree / "pools" / f"cell-{index}" / "outputs" / "persona" / section.MANIFEST
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest(entry)))
        (tree / "result.json").parent.mkdir(parents=True, exist_ok=True)
        (tree / "result.json").write_text("{}")
        hashes = {path.relative_to(tree).as_posix(): file_hash(path) for path in sorted(tree.rglob("*")) if path.is_file()}
        (base / "accepted.json").write_text(json.dumps({"status": status, "attempt_id": attempt, "hashes": hashes}))
        return tree

    def test_manifest_with_entry_is_schema_valid_and_a_bad_entry_is_not(self):
        self.assertEqual(validate_document(manifest(OK_ENTRY), section.MANIFEST_SCHEMA), [])
        self.assertEqual(validate_document(manifest(GAP_ENTRY), section.MANIFEST_SCHEMA), [])
        self.assertEqual(validate_document(manifest(), section.MANIFEST_SCHEMA), [])
        self.assertTrue(validate_document(manifest({**OK_ENTRY, "extra": 1}), section.MANIFEST_SCHEMA))
        self.assertTrue(validate_document(manifest({**OK_ENTRY, "gap": "SOMETHING"}), section.MANIFEST_SCHEMA))

    def test_no_granted_job_is_not_used_not_a_gap(self):
        self.publish("02-repository-partition-discovery", [None])
        value = section.build(REPORT, self.root)
        self.assertEqual((value["status"], value["entries"], value["gaps"]), ("NOT_USED", [], []))
        self.assertEqual(section.provenance_rows(value), [["MITRE reference", section.NOT_USED]])
        self.assertEqual(section.provenance_rows(None), [])

    def test_distinct_entries_are_aggregated_across_jobs_with_a_gap_line(self):
        self.publish("claim-review-pool-cell", [OK_ENTRY, OK_ENTRY, None])
        self.publish("hypothesis-hunt/whole", [OK_ENTRY, GAP_ENTRY])
        self.publish("ignored-job", [GAP_ENTRY], status="FAILED")
        value = section.build(REPORT, self.root)
        self.assertEqual(value["status"], "USED")
        self.assertEqual(len(value["entries"]), 2)
        ok = next(item for item in value["entries"] if item["gap"] is None)
        gap = next(item for item in value["entries"] if item["gap"])
        self.assertEqual((ok["jobs"], ok["invocations"]), (["claim-review-pool-cell", "hypothesis-hunt"], 3))
        self.assertEqual((gap["jobs"], gap["invocations"]), (["hypothesis-hunt"], 1))
        self.assertEqual(len(value["gaps"]), 1)
        self.assertIn("MITRE_REFERENCE_STALE and CWE_REFERENCE_STALE", value["gaps"][0])
        rows = section.provenance_rows(value)
        texts = {text for _label, text in rows}
        self.assertIn("ATT&CK enterprise-attack 19.2; CAPEC 3.9; CWE 4.17 (mitre-feed); snapshot "
                      "sha256-0123456789abcdef; table aaaaaaaaaaaaaaaa; 3 invocation(s) in 2 job(s): "
                      "claim-review-pool-cell, hypothesis-hunt", texts)
        self.assertIn("ATT&CK/CAPEC gap MITRE_REFERENCE_STALE; CWE CWE List 4.14 (curated subset) "
                      "(committed-curated, gap CWE_REFERENCE_STALE); 1 invocation(s) in 1 job(s): hypothesis-hunt", texts)
        self.assertEqual([label for label, _text in rows].count("MITRE reference gap"), 1)
        self.assertEqual(section.build(REPORT, self.root), value)   # deterministic

    def test_changed_manifest_after_acceptance_fails_closed(self):
        tree = self.publish("claim-review-pool-cell", [OK_ENTRY])
        path = next(tree.rglob(section.MANIFEST))
        path.write_text(json.dumps(manifest(GAP_ENTRY)))
        with self.assertRaisesRegex(Blocked, "changed after acceptance"):
            section.build(REPORT, self.root)

    def test_binding_names_each_manifest_by_its_accepted_hash(self):
        self.publish("claim-review-pool-cell", [OK_ENTRY])
        binding = section.input_binding(self.root)
        self.assertEqual([row["job"] for row in binding], ["claim-review-pool-cell"])
        self.assertEqual(binding[0]["manifests"][0]["path"], "pools/cell-0/outputs/persona/invoker-output.json")

    @unittest.skipUnless(importlib.util.find_spec("cvss") and importlib.util.find_spec("jinja2"),
                         "the report renderer needs cvss and jinja2 (images/audit-report)")
    def test_templates_render_the_rows(self):
        self.publish("claim-review-pool-cell", [OK_ENTRY, GAP_ENTRY])
        rows = section.provenance_rows(section.build(REPORT, self.root))
        path = ROOT.parent / "pipeline" / "report" / "render.py"
        spec = importlib.util.spec_from_file_location("appsec_review_report_renderer_mitre_test", path)
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        data = json.loads((ROOT.parent / "pipeline" / "report" / "examples" / "hello-autotools.review.json").read_text())
        for variant in (rows, None):
            with self.subTest(rows=variant is not None), tempfile.TemporaryDirectory() as out:
                document = copy.deepcopy(data)
                if variant is not None:
                    document["provenance"]["references"] = variant
                source = Path(out) / "review.json"
                source.write_text(json.dumps(document))
                renderer.render(source, Path(out) / "presentation")
                html = (Path(out) / "presentation" / "report.html").read_text()
                tex = (Path(out) / "presentation" / "report.tex").read_text()
                if variant is not None:
                    self.assertIn("ATT&amp;CK enterprise-attack 19.2", html)
                    self.assertIn("MITRE reference gap", html)
                    self.assertIn(r"ATT\&CK enterprise-attack 19.2", tex)
                else:
                    self.assertNotIn("MITRE reference", html)


if __name__ == "__main__":
    unittest.main()
