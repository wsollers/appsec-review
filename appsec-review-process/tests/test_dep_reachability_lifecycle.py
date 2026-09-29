"""06 correlator bindings (ADR-0023 decision 8): engine tables hash-bound, re-derivable, gaps not blocks."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dep_reachability_lifecycle as lc
from execution_state import file_hash, tree_hashes
from schema_validate import validate_document

SOURCE = "sha256:" + "5" * 64
GENERATED = "2026-09-28T12:00:00Z"
FILES = {"cmd/main.go": "sha256:" + "1" * 64, "web/serve.go": "sha256:" + "2" * 64}
SCA = {"matches": [{"match_id": "VM-000001", "component_ref": "SC-000001", "advisory_id": "GO-2022-0001", "aliases": []}]}
SBOM = {"components": [{"component_id": "SC-000001", "name": "golang.org/x/net", "version": "v0.1.0",
                        "ecosystem": "golang"}]}


def table(engine, verdict="reachable", sca_attempt="sca-1", source=SOURCE, **row):
    witness = [{"function": "main", "file": "cmd/main.go", "line": 5, "sha256": FILES["cmd/main.go"]},
               {"function": "Serve", "file": "web/serve.go", "line": 9, "sha256": FILES["web/serve.go"],
                "note": "call into the vulnerable dependency function"}] if verdict == "reachable" else []
    base = {"match_id": "VM-000001", "component_ref": "SC-000001", "advisory_id": "GO-2022-0001",
            "ecosystem": "golang", "language": "go", "verdict": verdict,
            "tier": "direct" if verdict == "reachable" else None,
            "symbols": [{"package": "golang.org/x/net/html", "symbol": "Parse", "source": "reviewed-map"}],
            "resolved": [{"package": "golang.org/x/net/html", "symbol": "Parse", "via": "import path"}],
            "resolution": ["go golang.org/x/net: not vendored; call sites only"], "witness": witness,
            "taint_paths": [], "target": None, "database_ids": [], "reason": f"{engine} said {verdict}",
            "gaps": [] if engine == "codeql" else ["engine-not-applicable:ir:go"], **row}
    return {"schema": "appsec-review/engine-reachability/1", "run_id": "run",
            "job_id": {"codeql": "06-reachability-codeql", "ir": "06-reachability-ir"}[engine], "attempt_id": "a1",
            "engine": engine, "source_snapshot_sha256": source,
            "sca_binding": {"job_id": "02-sca-vulnerability-match", "attempt_id": sca_attempt, "sha256": SOURCE},
            "status": "OK", "languages": [], "rows": [base],
            "counts": {"reachable": int(verdict == "reachable"), "unreachable": int(verdict == "unreachable"),
                       "unknown": int(verdict == "unknown")}, "coverage_gaps": [], "claim_ceiling": "EVIDENCE_LEADS_ONLY"}


class LifecycleBindingTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.run = Path(self.folder.name) / "run"
        (self.run / "inputs").mkdir(parents=True)
        patches = [mock.patch.object(lc, "run_path", lambda _run: self.run),
                   mock.patch.object(lc, "data_path", lambda _run, *parts: self.run.joinpath("data", *parts)),
                   mock.patch("osv_lookup.default_root", lambda: Path(self.folder.name) / "no-osv")]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(self.folder.cleanup)

    def publish(self, job, result, document):
        base = self.run / "data" / "jobs" / job
        attempt = base / "attempts" / "a1"
        attempt.mkdir(parents=True)
        (attempt / result).write_text(json.dumps(document))
        (attempt / "result.json").write_text("{}")
        (base / "accepted.json").write_text(json.dumps({
            "run_id": "run", "job": job, "attempt_id": "a1", "status": "OK", "hashes": tree_hashes(attempt),
            "envelope_path": "result.json", "envelope_sha256": file_hash(attempt / "result.json")}))
        return attempt

    def test_absent_engine_tables_are_gaps_and_the_result_is_honest_unknown(self):
        bound = lc.bindings("run", SOURCE, GENERATED, "sca-1")
        self.assertEqual(bound["tables"], {"codeql": None, "ir": None})
        self.assertEqual(bound["gaps"], ["engine-input-absent:06-reachability-codeql",
                                         "engine-input-absent:06-reachability-ir"])
        self.assertTrue(bound["osv_gap"].startswith("osv-"))
        derived = lc.derive("run", bound, sca=SCA, sbom=SBOM, files=FILES, generated_at=GENERATED)
        self.assertEqual(derived["assessments"], [])
        self.assertIn("ENGINE_INPUT:engine-input-absent:06-reachability-codeql", derived["document"]["coverage_gaps"])
        self.assertEqual(derived["document"]["matches"][0]["verdict"], "unknown")
        self.assertEqual(derived["summary"]["engines"][0]["status"], "ABSENT")

    def test_engine_tables_prove_reachable_and_rederive_identically(self):
        self.publish("06-reachability-codeql", lc.ENGINE_RESULT, table("codeql"))
        self.publish("06-reachability-ir", lc.ENGINE_RESULT, table("ir", "unknown"))
        bound = lc.bindings("run", SOURCE, GENERATED, "sca-1")
        self.assertEqual(bound["gaps"], [])
        first = lc.derive("run", bound, sca=SCA, sbom=SBOM, files=FILES, generated_at=GENERATED)
        second = lc.derive("run", lc.bindings("run", SOURCE, GENERATED, "sca-1"), sca=SCA, sbom=SBOM, files=FILES,
                           generated_at=GENERATED)
        self.assertEqual(first, second)
        self.assertEqual(first["assessments"][0]["classification"], "reachable")
        record = first["document"]["matches"][0]
        self.assertEqual((record["verdict"], record["tier"], record["deciding_engines"]), ("reachable", "direct", ["codeql"]))
        self.assertEqual(record["symbols"][0]["source"], "reviewed-map")
        self.assertEqual(validate_document(record, "dependency-reachability-match.schema.json"), [])
        self.assertEqual(first["summary"]["review"]["p1_match_ids"], ["VM-000001"])

    def test_stale_or_mixed_tables_are_not_used(self):
        attempt = self.publish("06-reachability-codeql", lc.ENGINE_RESULT, table("codeql", sca_attempt="sca-0"))
        self.assertIn("engine-input-stale:06-reachability-codeql", lc.bindings("run", SOURCE, GENERATED, "sca-1")["gaps"])
        self.assertIn("engine-input-mixed-lineage:06-reachability-codeql",
                      lc.bindings("run", "sha256:" + "6" * 64, GENERATED, "sca-0")["gaps"])
        (attempt / "extra.txt").write_text("tamper")
        self.assertIn("engine-input-not-current:06-reachability-codeql",
                      lc.bindings("run", SOURCE, GENERATED, "sca-0")["gaps"])

    def test_a_bound_table_changed_before_derivation_is_stale(self):
        attempt = self.publish("06-reachability-codeql", lc.ENGINE_RESULT, table("codeql"))
        bound = lc.bindings("run", SOURCE, GENERATED, "sca-1")
        (attempt / lc.ENGINE_RESULT).write_text(json.dumps(table("codeql", "unknown")))
        with self.assertRaises(lc.Stale):
            lc.derive("run", bound, sca=SCA, sbom=SBOM, files=FILES, generated_at=GENERATED)

    def test_accepted_publications_are_verified_and_lineage_checked(self):
        attempt = self.publish(lc.CPG_JOB, lc.CPG_RESULT, {"source_snapshot_sha256": SOURCE, "status": "OK",
                                                           "records_file": {"path": "r.jsonl", "sha256": "sha256:" + "0" * 64}})
        cpg, gaps = lc._cpg("run", SOURCE)
        self.assertEqual((cpg["attempt_id"], gaps), ("a1", []))
        self.assertEqual(lc._cpg("run", "sha256:" + "6" * 64)[1], ["engine-input-mixed-lineage:02-code-property-graph"])
        (attempt / "extra.txt").write_text("tamper")
        self.assertEqual(lc._cpg("run", SOURCE)[1], ["engine-input-not-current:02-code-property-graph"])


if __name__ == "__main__":
    unittest.main()
