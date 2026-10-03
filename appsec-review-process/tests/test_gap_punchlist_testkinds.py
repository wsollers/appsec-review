"""Acceptance tests for gap punch list item P45 (docs/continuation-prompts/2026-10-03-gap-punchlist-hello-autotools.md)."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from execution_state import file_hash  # noqa: E402
from schema_validate import validate_document  # noqa: E402
import static_intelligence_core as core  # noqa: E402
import supporting_evidence_menu as menu  # noqa: E402

JOB = "02-test-intelligence-ingest"
BINDING = {"job_id": "00-intake", "attempt_id": "i", "fingerprint": "f", "source_fingerprint": "a" * 64,
           "source_revision": "r", "pointer_sha256": "sha256:" + "b" * 64}
FIXTURE = ROOT / "tests/fixtures/gap-punchlist/testkinds"
EXPECTED = {
    "tests/test_calc.py": ("unit", "pytest"), "tests/test_legacy.py": ("unit", "unittest"),
    "tests/integration/test_db.py": ("integration", "pytest"),
    "docs/examples/test_example.py": ("unit", "pytest"),
    "src/test/java/CalcTest.java": ("unit", "junit"), "src/test/java/CalcNgTest.java": ("unit", "testng"),
    "tests/NunitCalcTests.cs": ("unit", "nunit"), "tests/XunitCalcTests.cs": ("unit", "xunit"),
    "tests/MsCalcTests.cs": ("unit", "mstest"), "calc/calc_test.go": ("unit", "go-test"),
    "tests/calc.rs": ("unit", "cargo-test"), "tests/calc_gtest.cc": ("unit", "googletest"),
    "tests/calc_catch.cpp": ("unit", "catch2"), "tests/calc_doctest.cpp": ("unit", "doctest"),
    "tests/CMakeLists.txt": ("unit", "ctest"), "tests/calc.test.js": ("unit", "vitest"),
    "tests/calc.spec.js": ("unit", "jest"), "tests/mocha_calc.js": ("unit", "mocha"),
    "tests/CalcTest.php": ("unit", "phpunit"), "tests/calc.bats": ("unit", "bats"),
    "tests/Calc.Tests.ps1": ("unit", "pester"), "tests/run.sh": ("unit", "shell"),
    "tests/unity_calc.c": ("unit", "unity"), "tests/cunit_calc.c": ("unit", "cunit"),
    "tests/plain.c": ("unit", "c-harness"), "tests/testsuite.at": ("unit", "autotest"),
    "features/login.feature": ("acceptance", "gherkin"), "acceptance/login.robot": ("acceptance", "robot-framework"),
    "features/steps/login_steps.py": ("acceptance", "behave"),
    "features/step_definitions/login.steps.js": ("acceptance", "cucumber"),
    "e2e/login.spec.ts": ("system", "playwright"), "cypress/e2e/login.cy.js": ("system", "cypress"),
    "tests/ui/test_login_selenium.py": ("system", "selenium"),
    "load/script.js": ("load", "k6"), "locustfile.py": ("load", "locust"), "perf/plan.jmx": ("load", "jmeter"),
    "perf/BasicSimulation.scala": ("load", "gatling"), "perf/artillery.yml": ("load", "artillery"),
    "perf/post.lua": ("load", "wrk"), "perf/vegeta-targets.txt": ("load", "vegeta"),
    "fuzz/parse_fuzzer.cc": ("fuzz", "libfuzzer"), "calc/parse_fuzz_test.go": ("fuzz", "go-fuzz"),
    "fuzz/fuzz_parse.py": ("fuzz", "atheris"), "fuzz/fuzz_targets/parse.rs": ("fuzz", "cargo-fuzz"),
    "tests/test_props.py": ("property", "hypothesis"), "tests/Props.hs": ("property", "quickcheck"),
    "tests/props.rs": ("property", "proptest"), "scripts/smoke-test.sh": ("smoke", "shell"),
    "tests/helpers.py": ("unknown", "unknown"),
}


class TestKindClassificationTests(unittest.TestCase):
    """P45: every test record carries a closed test_kind and framework from static signals."""

    def _extract(self, target: Path) -> dict:
        files = {p.relative_to(target).as_posix(): {"kind": "file", "sha256": file_hash(p), "bytes": p.stat().st_size}
                 for p in target.rglob("*") if p.is_file()}
        return core.extract(JOB, run_id="r", attempt_id="a", target=target, source=BINDING,
                            source_files=files)

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(); self.addCleanup(self.folder.cleanup)
        self.target = Path(self.folder.name) / "target"; shutil.copytree(FIXTURE, self.target)
        self.out = self._extract(self.target)

    def test_each_fixture_is_classified_by_kind_and_framework(self):
        got: dict[str, set] = {}
        for record in self.out["records"]:
            got.setdefault(record["path"], set()).add((record.get("test_kind"), record.get("framework")))
        self.assertEqual({path: {value} for path, value in EXPECTED.items()}, got)

    def test_unrecognised_test_file_stays_an_unknown_entrypoint(self):
        helper = [r for r in self.out["records"] if r["path"] == "tests/helpers.py"]
        self.assertEqual([(r["kind"], r["test_kind"], r["framework"]) for r in helper],
                         [("test-entrypoint", "unknown", "unknown")])

    def test_non_test_sources_are_not_records(self):
        paths = {r["path"] for r in self.out["records"]}
        self.assertNotIn("src/main.c", paths); self.assertNotIn("CMakeLists.txt", paths)

    def test_citations_resolve_to_a_line_of_the_cited_file(self):
        for record in self.out["records"]:
            match = re.fullmatch(r"(.+):(\d+)", record.get("citation", ""))
            self.assertIsNotNone(match, record)
            self.assertEqual(match.group(1), record["path"])
            lines = (self.target / record["path"]).read_text().splitlines()
            self.assertTrue(1 <= int(match.group(2)) <= len(lines), record)

    def test_totals_per_kind_match_the_records_and_cover_every_kind(self):
        self.assertIn("test_kind_totals", set(self.out)); totals = self.out["test_kind_totals"]
        self.assertEqual(set(totals), set(getattr(core, "TEST_KINDS", ())))
        files = Counter(kind for kind, _fw in EXPECTED.values())
        self.assertEqual({k: v for k, v in totals.items() if v}, dict(files))

    def test_schema_validates_and_closes_the_enums(self):
        self.assertEqual(validate_document(self.out, "test-intelligence.schema.json"), [])
        schema = json.loads((ROOT.parent / "schemas/test-intelligence.schema.json").read_text())
        self.assertEqual(set(schema.get("$defs", {}).get("test_kind", {}).get("enum", [])), set(getattr(core, "TEST_KINDS", ())))
        self.assertEqual(set(schema.get("$defs", {}).get("framework", {}).get("enum", [])), set(getattr(core, "FRAMEWORKS", ())))
        for field in ("test_kind", "framework"):
            bad = json.loads(json.dumps(self.out)); bad["records"][0][field] = "bogus"
            self.assertTrue(validate_document(bad, "test-intelligence.schema.json"), field)
            del bad["records"][0][field]
            self.assertTrue(validate_document(bad, "test-intelligence.schema.json"), field)

    def test_extraction_is_deterministic_and_ok(self):
        self.assertEqual(self.out, self._extract(self.target))
        self.assertEqual((self.out["status"], self.out["coverage_gaps"]), ("OK", []))

    def test_menu_summary_carries_the_kind_totals(self):
        self.assertIn("test_kind_totals", set(self.out))
        path = self.target / "test-intelligence.json"; raw = json.dumps(self.out).encode()
        summary = menu._records(path, raw)
        for kind, count in self.out["test_kind_totals"].items():
            self.assertEqual(summary[f"test_kind_totals.{kind}"], count)


if __name__ == "__main__":
    unittest.main()
