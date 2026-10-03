"""Acceptance tests for gap punch list P16-P21 (docs/TODO/gap-punchlist-hello-autotools-2026-10-03.md).

Each test encodes the desired behaviour after the fix and is an expected failure until then.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_plan as bp  # noqa: E402
import static_intelligence_core as core  # noqa: E402
import reachability_engine_jobs as jobs  # noqa: E402
import standards_source_ingest as standards_worker  # noqa: E402
from execution_state import file_hash, read_json  # noqa: E402
from schema_validate import validate_document  # noqa: E402
from worker_result import artifact_records, terminal_envelope  # noqa: E402
# Modules, not TestCase classes, so the loader does not re-run their tests here.
import test_dependency_workers as tdw  # noqa: E402
import test_standards_source_ingest as tssi  # noqa: E402
from test_reachability_engine_jobs import upstream  # noqa: E402

API_JOB = "02-api-collection-intelligence-ingest"
OPS_JOB = "02-operations-doc-ingest"
TEST_JOB = "02-test-intelligence-ingest"
UNSELECTED = ["disa_gpos_srg", "owasp_api_security_top_10", "owasp_llm_top_10", "owasp_mastg", "owasp_masvs"]
CJSON_HEADER = (
    "#ifndef cJSON__h\n#define cJSON__h\n"
    "/* project version */\n"
    "#define CJSON_VERSION_MAJOR 1\n#define CJSON_VERSION_MINOR 7\n#define CJSON_VERSION_PATCH 18\n"
    "#endif\n")


def source_files(target: Path) -> dict:
    return {p.relative_to(target).as_posix(): {"kind": "file", "sha256": file_hash(p), "bytes": p.stat().st_size}
            for p in target.rglob("*") if p.is_file()}


def extract(job: str, target: Path) -> dict:
    return core.extract(job, run_id="r", attempt_id="a", target=target,
                        source={"job_id": "00-intake", "attempt_id": "i", "fingerprint": "f",
                                "source_fingerprint": "a" * 64, "source_revision": "r",
                                "pointer_sha256": "sha256:" + "b" * 64},
                        source_files=source_files(target))


class StaticIntelligenceGapTests(unittest.TestCase):
    def test_p16_readme_only_api_and_ops_jobs_are_skipped_not_gaps(self):
        """P16: README-only target -> api-collection and operations-doc ingest are SKIPPED with no coverage gap."""
        with tempfile.TemporaryDirectory() as d:
            target = Path(d); (target / "README.md").write_text("# hello\n")
            for job in (API_JOB, OPS_JOB):
                with self.subTest(job=job):
                    out = extract(job, target)
                    self.assertEqual(out["status"], "SKIPPED")
                    self.assertEqual(out.get("applicability"), "SKIPPED_NA_NO_APPLICABLE_INPUTS")
                    self.assertEqual(out["coverage_gaps"], [])
                    self.assertEqual(validate_document(out, core.SPECS[job][2]), [])

    def test_p16_building_md_is_ingested_as_operations_doc(self):
        """P16: docs/BUILDING.md with build/install instructions is ingested by 02-operations-doc-ingest."""
        with tempfile.TemporaryDirectory() as d:
            target = Path(d); (target / "docs").mkdir()
            (target / "README.md").write_text("# hello\n")
            (target / "docs/BUILDING.md").write_text(
                "# Building hello\n\n## Build\n\nRun ./configure && make.\n\n## Install\n\nRun make install.\n")
            out = extract(OPS_JOB, target)
            self.assertGreater(len(out["records"]), 0, out["coverage_gaps"])
            self.assertIn("docs/BUILDING.md", {record["path"] for record in out["records"]})

    def test_p17_shell_and_c_test_functions_are_indexed(self):
        """P17: shell test_x() and C test_x( functions under tests/ become test-intelligence records."""
        with tempfile.TemporaryDirectory() as d:
            target = Path(d); (target / "tests").mkdir()
            (target / "tests/run.sh").write_text(
                "#!/bin/sh\nset -e\ntest_parse() {\n  ./hello --parse x\n}\ntest_parse\n")
            (target / "tests/t.c").write_text(
                "#include <assert.h>\nstatic void test_x(void) { assert(1); }\n"
                "int main(void) { test_x(); return 0; }\n")
            out = extract(TEST_JOB, target)
            summaries = " ".join(record["summary"] for record in out["records"])
            self.assertNotIn("zero-indexable-records", out["coverage_gaps"])
            self.assertIn("test_parse", summaries)
            self.assertIn("test_x", summaries)


class StandardsGapTests(unittest.TestCase):
    def test_p18_unselected_families_are_not_applicable_not_gaps(self):
        """P18: unselected standards families are published as not_applicable_families, not coverage gaps."""
        helper = tssi.StandardsSourceIngestTests()
        helper.setUp()
        try:
            result, _artifacts = standards_worker.materialize(
                run_id=helper.fixture["run_id"], attempt_id="attempt-1",
                attempt=helper.owner / "attempt", inputs=helper.inputs())
        finally:
            helper.tearDown()
        self.assertEqual([gap for gap in result["coverage_gaps"] if gap.startswith("unselected-family:")], [])
        self.assertEqual(result["status"], "OK")
        self.assertEqual(sorted(item["family"] if isinstance(item, dict) else item
                                for item in result.get("not_applicable_families", [])), UNSELECTED)


class SbomCjsonGapTests(unittest.TestCase):
    """Drives build_sbom through test_dependency_workers.DependencyWorkersTest's fixture harness."""

    def setUp(self):
        self.h = tdw.DependencyWorkersTest()
        self.h.setUp()

    def tearDown(self):
        self.h.tearDown()

    def with_member(self, member: str) -> dict:
        h = self.h
        (h.target / member).mkdir(parents=True)
        (h.target / member / "cJSON.h").write_text(CJSON_HEADER)
        (h.target / member / "cJSON.c").write_text('#include "cJSON.h"\n')
        files = {"package-lock.json": "sha256:" + "2" * 64}
        for name in ("cJSON.c", "cJSON.h"):
            files[f"{member}/{name}"] = "sha256:" + file_hash(h.target / member / name)
        h.build_index_path.write_bytes(tdw.payload({"schema": "appsec-review/build-index/1", "units": [{
            "unit_id": "dir:.", "members": [{"path": member, "reason": "referenced-by-parent-build",
                                             "signal_ids": ["s0005"], "manifests": []}]}]}))
        attempt = h.build_index_path.parent
        envelope = terminal_envelope(run_id=h.run_id, job_id="02-build-index", attempt_id="build-one",
            worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
            input_fingerprint="sha256:" + "8" * 64, output_contract="build-index",
            started_at=h.when, finished_at=h.when, summary="hello build index",
            artifacts=artifact_records(attempt, ["build-index.json"]))
        (attempt / "result.json").write_bytes(tdw.payload(envelope))
        h.build_pointer.write_bytes(tdw.payload({"schema": "appsec-review/accepted-worker-result/1.0",
            "run_id": h.run_id, "job": "02-build-index", "attempt_id": "build-one", "status": "OK",
            "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
            "envelope_sha256": tdw.workers._hash_file(attempt / "result.json").split(":", 1)[1]}))
        h.build_index["sha256"] = tdw.workers._hash_file(h.build_index_path)
        output, receipt, expected = h.tool("02-sbom-inventory", "syft", {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": []})
        envelope = h.run_request("sbom", "punchlist-cjson", h.request(
            tool_output=str(output), tool_receipt=str(receipt), expected_tool=expected, source_files=files))
        result = json.loads(h.result_path(envelope, "outputs/sbom-manifest.json").read_text())
        return {"envelope": envelope, "result": result}

    def test_p19_unversioned_vendor_cjson_gets_version_purl_and_cpe_from_header(self):
        """P19: vendor/cJSON with CJSON_VERSION_* 1.7.18 in cJSON.h -> cJSON 1.7.18 with purl and CPE."""
        out = self.with_member("vendor/cJSON")
        self.assertNotIn("no-dependency-components-detected", out["envelope"]["gaps"])
        rows = [(row["name"], row["version"], row["purl"], row["cpe"]) for row in out["result"]["components"]]
        self.assertEqual(rows, [("cJSON", "1.7.18", "pkg:github/davegamble/cjson@v1.7.18",
                                 "cpe:2.3:a:cjson_project:cjson:1.7.18:*:*:*:*:*:*:*")])

    def test_p19_versioned_vendor_cjson_carries_purl_and_cpe(self):
        """P19: vendor/cJSON-1.7.18 member yields a component with non-null purl and CPE."""
        out = self.with_member("vendor/cJSON-1.7.18")
        self.assertEqual(len(out["result"]["components"]), 1, out["envelope"]["gaps"])
        component = out["result"]["components"][0]
        self.assertIsNotNone(component["purl"], "cJSON component has no purl")
        self.assertIsNotNone(component["cpe"], "cJSON component has no CPE")


class ReachabilityOsvGapTests(unittest.TestCase):
    def test_p20_osv_gap_not_emitted_without_rows(self):
        """P20: with zero reachability rows the job-level ENGINE_INPUT:osv-* gap is not emitted."""
        inputs = {**upstream(), "osv_gap": "osv-unusable:DATA_ROOT_MISSING"}
        result = jobs.assemble(run_id="run", attempt_id="a1", engine="codeql", inputs=inputs, rows=[], languages=[])
        self.assertEqual([gap for gap in result["coverage_gaps"] if gap.startswith("ENGINE_INPUT:osv-")], [])
        self.assertEqual(result["status"], "OK")


class BuildenvCatalogGapTests(unittest.TestCase):
    def test_p21_cpp_buildenv_catalog_declares_autotools(self):
        """P21: cpp buildenv catalog entries list autotools markers and the autoconf/automake/libtool tools."""
        catalog = read_json(bp.CATALOG_PATH)
        entries = [entry for entry in catalog["images"] if entry.get("language") == "cpp"]
        self.assertTrue(entries)
        for entry in entries:
            with self.subTest(image=entry.get("image")):
                self.assertLessEqual({"configure.ac", "Makefile.am"}, set(entry.get("project_markers", [])))
                self.assertLessEqual({"autoconf", "automake", "libtool"}, set(entry.get("tools", [])))


if __name__ == "__main__":
    unittest.main()
