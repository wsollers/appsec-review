"""06 lifecycle bindings for dependency reachability (ADR-0022 decision 9): hash-bound, re-derivable, gaps not blocks."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dep_reachability_engines as e
import dep_reachability_lifecycle as lc
from execution_state import file_hash, tree_hashes

SOURCE = "sha256:" + "5" * 64
GENERATED = "2026-09-28T12:00:00Z"
FILES = {"cmd/main.go": "sha256:" + "1" * 64, "web/serve.go": "sha256:" + "2" * 64}
SCA = {"matches": [{"match_id": "VM-000001", "component_ref": "SC-000001", "advisory_id": "GO-2022-0001", "aliases": []}]}
SBOM = {"components": [{"component_id": "SC-000001", "name": "golang.org/x/net", "ecosystem": "golang"}]}


def csv_text(columns, rows):
    return "\n".join([",".join(columns)] + [",".join(str(v) for v in row) for row in rows]) + "\n"


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

    def supply_go(self):
        folder = self.run / "inputs" / lc.SUPPLIED / "codeql" / "go"
        folder.mkdir(parents=True)
        (folder / "CallEdges.csv").write_text(csv_text(e.CALL_EDGE_COLUMNS, [
            ("example.com/app.main", "cmd/main.go", 5, "cmd/main.go", 7, "example.com/app/web.Serve", "web/serve.go", 3, "yes"),
            ("example.com/app/web.Serve", "web/serve.go", 3, "web/serve.go", 9, "golang.org/x/net/html.Parse", "", 0, "no")]))
        (folder / "EntryPoints.csv").write_text(csv_text(e.ENTRY_COLUMNS, [("example.com/app.main", "cmd/main.go", 5, "main")]))
        (self.run / "inputs" / lc.REVIEWED_MAP).write_text(json.dumps(
            {"GO-2022-0001": [{"package": "golang.org/x/net/html", "symbol": "Parse"}]}))

    def test_absent_sources_are_gaps_and_the_result_is_honest_unknown(self):
        bound = lc.bindings("run", SOURCE, GENERATED)
        self.assertIsNone(bound["cpg"]); self.assertIsNone(bound["codeql"])
        self.assertIn("engine-input-absent:02-code-property-graph", bound["gaps"])
        self.assertTrue(bound["osv_gap"].startswith("osv-"))
        derived = lc.derive("run", bound, sca=SCA, sbom=SBOM, files=FILES, generated_at=GENERATED)
        self.assertEqual(derived["assessments"], [])
        self.assertIn("ENGINE_INPUT:engine-input-absent:02-codeql-sast", derived["document"]["coverage_gaps"])
        self.assertEqual(derived["document"]["matches"][0]["verdict"], "unknown")

    def test_supplied_codeql_tables_and_reviewed_map_prove_reachable_and_rederive_identically(self):
        self.supply_go()
        bound = lc.bindings("run", SOURCE, GENERATED)
        self.assertEqual(set(bound["supplied"]["codeql"]["go"]), {"CallEdges", "EntryPoints"})
        first = lc.derive("run", bound, sca=SCA, sbom=SBOM, files=FILES, generated_at=GENERATED)
        second = lc.derive("run", lc.bindings("run", SOURCE, GENERATED), sca=SCA, sbom=SBOM, files=FILES,
                           generated_at=GENERATED)
        self.assertEqual(first, second)
        self.assertEqual(first["assessments"][0]["classification"], "reachable")
        self.assertEqual(first["document"]["matches"][0]["symbols"][0]["source"], "reviewed-map")

    def test_a_bound_file_changed_before_derivation_is_stale(self):
        self.supply_go()
        bound = lc.bindings("run", SOURCE, GENERATED)
        (self.run / "inputs" / lc.SUPPLIED / "codeql" / "go" / "CallEdges.csv").write_text(
            csv_text(e.CALL_EDGE_COLUMNS, []))
        with self.assertRaises(lc.Stale):
            lc.derive("run", bound, sca=SCA, sbom=SBOM, files=FILES, generated_at=GENERATED)

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

    def test_accepted_publications_are_verified_and_lineage_checked(self):
        attempt = self.publish(lc.CPG_JOB, lc.CPG_RESULT, {"source_snapshot_sha256": SOURCE, "status": "OK",
                                                           "records_file": {"path": "r.jsonl", "sha256": "sha256:" + "0" * 64}})
        cpg, gaps = lc._cpg("run", SOURCE)
        self.assertEqual((cpg["attempt_id"], gaps), ("a1", []))
        self.assertEqual(lc._cpg("run", "sha256:" + "6" * 64)[1], ["engine-input-mixed-lineage:02-code-property-graph"])
        (attempt / "extra.txt").write_text("tamper")
        self.assertEqual(lc._cpg("run", SOURCE)[1], ["engine-input-not-current:02-code-property-graph"])

    def test_codeql_traced_tables_come_from_receipts(self):
        attempt = self.publish(lc.CODEQL_JOB, lc.CODEQL_RESULT, {"source_snapshot_sha256": SOURCE})
        graph = attempt / "tools" / "codeql-cpp-traced-u1" / "scratch" / "graph"
        graph.mkdir(parents=True)
        (graph / "CallEdges.csv").write_text(csv_text(e.CALL_EDGE_COLUMNS, []))
        (attempt / lc.CODEQL_RECEIPTS).write_text(json.dumps({"tools": [{
            "trial_path": "tools/codeql-cpp-traced-u1", "unit_id": "u1",
            "graph_outputs": {"CallEdges.ql": "sha256:" + file_hash(graph / "CallEdges.csv"), "EntryPoints.ql": None,
                              "FlowSources.ql": None}}]}))
        pointer = json.loads((attempt.parents[1] / "accepted.json").read_text())
        pointer["hashes"] = tree_hashes(attempt)
        (attempt.parents[1] / "accepted.json").write_text(json.dumps(pointer))
        codeql, gaps = lc._codeql("run", SOURCE)
        self.assertEqual([row["table"] for row in codeql["cpp_tables"]], ["CallEdges"])
        self.assertEqual(gaps, ["codeql-table-absent:cpp:EntryPoints:u1"])


if __name__ == "__main__":
    unittest.main()
