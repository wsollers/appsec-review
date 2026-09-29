"""06 correlator lattice (ADR-0023 decision 8): reachable, unreachable, conflict, unknown; hints never prove."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock  # noqa: F401  (unittest.mock.patch.dict below)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dep_reachability_correlator as c  # noqa: E402
import dep_reachability_engines as e  # noqa: E402
from schema_validate import validate_document  # noqa: E402

SHA = "sha256:" + "1" * 64
HOPS = [{"function": "main", "file": "src/main.c", "line": 3, "sha256": SHA},
        {"function": "inflateGetHeader", "file": "src/main.c", "line": 7, "sha256": SHA,
         "note": "call into the vulnerable dependency function"}]
TARGET = {"function": "inflateGetHeader", "file": "vendor/zlib/inflate.c", "line": 40, "sha256": SHA}
SCA = {"matches": [{"match_id": "VM-000001", "component_ref": "SC-000001", "advisory_id": "CVE-2022-37434"}]}
SBOM = {"components": [{"component_id": "SC-000001", "name": "zlib", "version": "1.2.11", "ecosystem": "conan"}]}


def row(engine, verdict, **extra):
    base = {"match_id": "VM-000001", "component_ref": "SC-000001", "advisory_id": "CVE-2022-37434",
            "ecosystem": "conan", "language": "cpp", "verdict": verdict, "tier": "direct" if verdict == "reachable" else None,
            "symbols": [{"package": None, "symbol": "inflateGetHeader", "source": "reviewed-map"}],
            "resolved": [{"package": "zlib", "symbol": "inflateGetHeader", "via": "native"}], "resolution": [],
            "witness": HOPS if verdict == "reachable" else [], "taint_paths": [],
            "target": TARGET if verdict == "unreachable" else None, "database_ids": [],
            "reason": f"{engine} {verdict}", "gaps": []}
    base.update(extra)
    return base


def correlate(codeql=None, ir=None, engine_set=None):
    tables = {"codeql": {"rows": [codeql]} if codeql else None, "ir": {"rows": [ir]} if ir else None}
    return c.correlate(sca=SCA, sbom=SBOM, tables=tables, engine_set=engine_set or e.EngineSet(),
                       entry_points=[], osv=None, identity={}, input_gaps=[])


class LatticeTests(unittest.TestCase):
    def test_reachable_needs_a_proof_capable_witness(self):
        result = correlate(codeql=row("codeql", "reachable"), ir=row("ir", "unknown"))
        record = result["document"]["matches"][0]
        self.assertEqual((record["verdict"], record["deciding_engines"], record["tier"]), ("reachable", ["codeql"], "direct"))
        self.assertEqual(result["assessments"][0]["classification"], "reachable")
        self.assertEqual(len(result["assessments"][0]["evidence"]), 2)
        # For native code the complete CPG wins over CodeQL when both prove it.
        both = correlate(codeql=row("codeql", "reachable"), ir=row("ir", "reachable", witness=HOPS[1:] + HOPS[1:] + HOPS))
        self.assertEqual(both["document"]["matches"][0]["deciding_engines"], ["ir"])

    def test_unreachable_only_from_ir_and_without_hints(self):
        result = correlate(codeql=row("codeql", "unknown"), ir=row("ir", "unreachable"))
        self.assertEqual(result["document"]["matches"][0]["verdict"], "unreachable")
        self.assertEqual(result["assessments"][0]["evidence"][0]["locator"], "no-path-to:inflateGetHeader@40")
        hinted = e.EngineSet(treesitter={"files": [{"path": "src/main.c", "language": "c", "functions": [],
                                                    "calls": [{"callee": "inflateGetHeader", "line": 7}]}]})
        cautious = correlate(codeql=row("codeql", "unknown"), ir=row("ir", "unreachable"), engine_set=hinted)
        self.assertEqual(cautious["document"]["matches"][0]["verdict"], "unknown")
        self.assertEqual(cautious["assessments"], [])
        self.assertEqual(correlate(codeql=row("codeql", "unreachable", target=TARGET))["document"]["matches"][0]["verdict"],
                         "unknown")

    def test_disagreement_is_conflict_and_never_resolved(self):
        result = correlate(codeql=row("codeql", "reachable"), ir=row("ir", "unreachable"))
        record = result["document"]["matches"][0]
        self.assertEqual((record["verdict"], record["deciding_engines"], record["witness"]), ("conflict", ["codeql", "ir"], []))
        self.assertIn("REACHABILITY_CONFLICT:VM-000001", record["gaps"])
        self.assertIn("engines disagree", record["reason"])
        self.assertEqual(result["assessments"], [])        # cve-reachability.json says unknown: Critical stays capped
        self.assertEqual(validate_document(record, "dependency-reachability-match.schema.json"), [])
        summary = c.summary(result["document"], SBOM, {"codeql": None, "ir": None})
        self.assertEqual(summary["review"], {"p1_match_ids": [], "conflict_match_ids": ["VM-000001"]})
        self.assertEqual(summary["counts"]["conflict"], 1)

    def test_language_server_hints_never_make_reachable(self):
        lsp = {"cpp": {"results": [
            {"status": "OK", "query": {"method": "incomingCalls", "path": "vendor/zlib/inflate.c", "line": 40,
                                       "sink_symbol": {"package": "zlib", "symbol": "inflateGetHeader"}},
             "results": [{"name": "main", "path": "src/main.c", "start_line": 3, "call_lines": [7]}]}], "gaps": []}}
        engine_set = e.EngineSet(lsp=lsp)
        with unittest.mock.patch.dict(c.dep_reachability.ENGINES_BY_LANGUAGE, {"cpp": ("cpg", "codeql", "lsp")}):
            result = correlate(codeql=row("codeql", "unknown"), ir=row("ir", "unknown"), engine_set=engine_set)
        record = result["document"]["matches"][0]
        self.assertEqual(record["verdict"], "unknown")
        lsp_entry = next(item for item in record["engines"] if item["engine"] == "lsp")
        self.assertEqual(lsp_entry["state"], "unknown")
        self.assertTrue(lsp_entry["reason"].startswith("hint only"))
        self.assertEqual(record["witness_hints"][0]["file"], "src/main.c")

    def test_absent_and_not_applicable_engines(self):
        result = correlate(codeql=row("codeql", "unknown", gaps=["engine-not-applicable:codeql:cpp"]))
        record = result["document"]["matches"][0]
        self.assertEqual(record["verdict"], "unknown")
        self.assertIn("REACHABILITY_UNKNOWN:VM-000001:engine-input-absent:06-reachability-ir", record["gaps"])
        self.assertFalse(any("engine-not-applicable" in gap for gap in record["gaps"]))
        summary = c.summary(result["document"], SBOM, {"codeql": {"attempt_id": "a", "result_sha256": SHA, "status": "OK"},
                                                       "ir": None})
        self.assertEqual([row["verdict"] for row in summary["matches"][0]["engines"]], ["absent", "absent"])
        self.assertIn("**unknown**", c.render_markdown(summary))


if __name__ == "__main__":
    import unittest.mock  # noqa: F401
    unittest.main()
