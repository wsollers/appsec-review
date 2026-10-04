"""02-code-index without its native producers: the CPG and tree-sitter are source-only, so a native build
that did not publish costs the export tables (a gap naming the producer and its state), not the index."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import code_index
import code_index_job as job
import code_query_fixture as fx
import code_query_mcp as query
import dep_reachability_lifecycle as bindings
import entry_exports
from execution_state import file_hash, tree_hashes
from publish_job_output import NONCURRENT_SCHEMA

RUN = "review-1"
SOURCE = "sha256:" + "3" * 64
# fx.build(exports=True) on the code before this change: the triage path must keep its rows byte for byte.
WITH_EXPORTS_SHA = "sha256:5d343b51b0f295781005272b903cfcaecbfebed42708698735a94528984d1905"


def _json(path: Path, value) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return path


class GraphEdge(unittest.TestCase):
    def test_binary_triage_is_an_optional_edge_and_the_source_edges_stay_required(self):
        graph = json.loads((ROOT / "pipeline" / "job-graph.json").read_text(encoding="utf-8"))["jobs"]
        edges = {dep["job"]: dep for dep in graph["02-code-index"]["dependencies"]}
        self.assertEqual(edges["02-binary-triage"]["kind"], "optional")
        self.assertEqual(edges["02-binary-triage"]["allowed_skip_reasons"],
                         ["not-applicable-non-native", "not-applicable-no-native-binaries"])
        self.assertEqual({name: edges[name]["kind"] for name in edges},
                         {"02-code-property-graph": "required", "02-treesitter-ast": "required",
                          "02-binary-triage": "optional", "02-ir-facts": "optional",
                          "02-debug-symbol-index": "optional"})
        for source in ("02-code-property-graph", "02-treesitter-ast"):   # source-only: no native-build edge
            self.assertEqual([dep["job"] for dep in graph[source]["dependencies"]], ["00-intake"])


class RunCase(unittest.TestCase):
    """A run tree under a temporary jobs root: an accepted CPG, no tree-sitter, and triage as each test lays it."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.data = Path(tmp.name)
        path = lambda _run, *parts: self.data.joinpath(*parts)
        for target in (mock.patch.object(job, "data_path", path), mock.patch.object(bindings, "data_path", path),
                       mock.patch.object(job, "_source", lambda _run: SOURCE),
                       mock.patch.object(entry_exports, "tables_from_triage", lambda _attempt: (fx.EXPORTS, []))):
            target.start(); self.addCleanup(target.stop)
        cpg = self.jobs(bindings.CPG_JOB) / "attempts" / "c1"
        _records, summary = fx.write_cpg(cpg)
        result = _json(cpg / bindings.CPG_RESULT, {**summary, "status": "OK"})
        self.cpg = {"attempt_id": "c1", "accepted_pointer_sha256": "sha256:" + "4" * 64,
                    "result_sha256": "sha256:" + file_hash(result), "records_sha256": summary["records_file"]["sha256"]}
        patch = mock.patch.object(bindings, "_cpg", lambda _run, _source: (dict(self.cpg), []))
        patch.start(); self.addCleanup(patch.stop)
        self.native = _json(self.jobs(job.NATIVE_JOB) / "accepted.json", {"status": "OK", "attempt_id": "n1"})

    def jobs(self, name: str) -> Path:
        return self.data / "jobs" / name

    def triage(self, status: str = "OK", native_pointer: str | None = None) -> None:
        base = self.jobs(job.TRIAGE_JOB); attempt = base / "attempts" / "t1"
        bound = native_pointer or "sha256:" + file_hash(self.native)
        _json(attempt / job.TRIAGE_RESULT, {"status": status, "native_build": {"pointer_sha256": bound}})
        (attempt / entry_exports.RECEIPT_FILE).write_text("{}", encoding="utf-8")
        envelope = _json(attempt / "result.json", {"execution_status": status})
        _json(base / "accepted.json", {"run_id": RUN, "job": job.TRIAGE_JOB, "attempt_id": "t1", "status": status,
                                       "hashes": tree_hashes(attempt), "envelope_path": "result.json",
                                       "envelope_sha256": file_hash(envelope)})

    def noncurrent(self, name: str, status: str) -> None:
        _json(self.jobs(name) / "accepted.json", {"schema": NONCURRENT_SCHEMA, "status": status, "run_id": RUN,
                                                  "job": name, "attempt_id": "x1"})

    def build(self) -> tuple[dict, dict]:
        inputs = job.current_inputs(RUN)
        summary = job._derive(RUN, inputs, self.data / code_index.SQLITE)
        return inputs, summary


class WithoutBinaryTriage(RunCase):
    def assert_gap(self, gap: str) -> dict:
        inputs, summary = self.build()
        self.assertIsNone(inputs["binary_triage"])
        self.assertIn(gap, inputs["input_gaps"])
        self.assertIn(gap, summary["gaps"])
        self.assertIn("source-absent:02-binary-triage export tables (code_exports unavailable)", summary["gaps"])
        self.assertFalse(summary["capabilities"]["exports"], "absent exports are unknown, never 'no exports'")
        self.assertTrue(summary["capabilities"]["cpg"])
        self.assertGreater(summary["counts"]["methods"], 0, "the source-only index is still built")
        self.assertEqual((summary["counts"]["exports"], summary["counts"]["export_tables"]), (0, 0))
        self.assertIsNone(summary["sources"]["binary_triage"])
        self.assertEqual(summary["status"], "OK_WITH_GAPS")
        return summary

    def test_never_run_triage_builds_the_index_with_an_absent_gap(self):
        self.assert_gap("source-absent:02-binary-triage")

    def test_failed_triage_names_its_state(self):
        self.noncurrent(job.TRIAGE_JOB, "FAILED")
        self.assert_gap("source-not-published:02-binary-triage:FAILED")

    def test_skipped_triage_names_its_state(self):
        self.triage("SKIPPED")
        self.assert_gap("source-skipped:02-binary-triage")

    def test_an_older_triage_is_not_bound_after_the_native_build_did_not_publish(self):
        self.triage()
        self.noncurrent(job.NATIVE_JOB, "BLOCKED")
        self.assert_gap("source-not-current:02-binary-triage:02-native-build-BLOCKED")

    def test_a_triage_of_a_replaced_native_build_is_not_bound(self):
        self.triage(native_pointer="sha256:" + "9" * 64)
        self.assert_gap("source-not-current:02-binary-triage:02-native-build-replaced")


class WithBinaryTriage(RunCase):
    def test_current_triage_is_bound_and_the_rows_are_unchanged(self):
        self.triage()
        inputs, summary = self.build()
        self.assertEqual(inputs["binary_triage"]["attempt_id"], "t1")
        self.assertFalse([gap for gap in inputs["input_gaps"] if "binary-triage" in gap])
        self.assertTrue(summary["capabilities"]["exports"])
        self.assertEqual(summary["counts"]["export_rows"], 2)
        # Same inputs straight into code_index.build: the job path adds nothing to the rows.
        records = self.jobs(bindings.CPG_JOB) / "attempts" / "c1" / "code-property-graph.records.jsonl"
        direct = code_index.build(self.data / "direct.sqlite", records=records,
                                  cpg_summary=json.loads((records.parent / bindings.CPG_RESULT).read_text()),
                                  sources=summary["sources"], export_tables=fx.EXPORTS,
                                  source_gaps=inputs["input_gaps"])
        self.assertEqual(direct["content_sha256"], summary["content_sha256"])

    def test_fixture_content_sha256_is_pinned(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        _database, result = fx.build(Path(tmp.name), exports=True)
        self.assertEqual(result["content_sha256"], WITH_EXPORTS_SHA)


class ExportQueries(unittest.TestCase):
    def test_code_exports_without_triage_is_a_gap_naming_the_producer_state(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        attempt = Path(tmp.name) / "02-code-index" / "attempts" / "a1"
        records, summary = fx.write_cpg(attempt)
        result = code_index.build(attempt / code_index.SQLITE, records=records, cpg_summary=summary,
                                  sources={"cpg": {"job": "02-code-property-graph"}, "treesitter": None,
                                           "binary_triage": None},
                                  source_gaps=["source-not-published:02-binary-triage:FAILED"])
        database = attempt / code_index.SQLITE
        result["sqlite"] = {"path": code_index.SQLITE, "sha256": query._sha(database)}
        index = query.CodeIndex(Path(tmp.name), "02-code-index/attempts/a1/code-index.json", result)
        answer = query.call(index, "code_exports", {"symbol": "parse_request"})
        self.assertFalse(answer["complete"])
        self.assertEqual(answer["rows"], [])
        self.assertIn("exports-unavailable", answer["reasons"])
        self.assertIn("source-not-published:02-binary-triage:FAILED", answer["gaps"])
        self.assertNotIn("code_exports", query.grantable({"allowed_actions": ["query tool: code_exports"]},
                                                         result["capabilities"]))


@unittest.skipUnless(importlib.util.find_spec("dagster"), "dagster is not installed")
class DagsterWiring(unittest.TestCase):
    @unittest.expectedFailure
    def test_a_raising_native_build_still_runs_the_code_index(self):
        """OPEN (dagster_workflow.wire_lifecycle, wiring owner): Dagster holds every op downstream of a failed
        op, fan-in or not, so an optional edge only tolerates a TOLERANT_OPS producer. 02-binary-triage and
        02-debug-symbol-index take the native-build gate, are held, and hold the code index with them."""
        from dagster import In, job as dagster_job, op
        from execution_state import Blocked
        import dagster_workflow as dw
        ran = []

        @op
        def stub_config():
            return {"engagement_run_id": RUN, "force": False}

        @op(ins={"configured": In(dict)})
        def seed(configured):
            return {"status": "OK"}

        def stub(name):
            @op(name="stub_" + name.replace("-", "_"), ins={"configured": In(dict), "upstream": In(list)})
            def work(configured, upstream):
                ran.append(name)
                return {"job_id": name, "status": "OK"}
            return work

        ops = {"02-native-build": dw.LIFECYCLE_OPS["02-native-build"],
               **{name: stub(name) for name in ("02-binary-triage", "02-debug-symbol-index", "02-code-index")}}

        @dagster_job
        def probe():
            configured = stub_config()
            outputs = {name: seed.alias("seed_" + name.replace("-", "_"))(configured)
                       for name in ("00-intake", "02-build-configure", "02-code-property-graph",
                                    "02-treesitter-ast", "02-ir-facts")}
            dw.wire_lifecycle(configured, outputs, ops)

        with mock.patch.object(dw.native_build_worker, "run", side_effect=Blocked("stub native build crashed")):
            probe.execute_in_process(raise_on_error=False)
        self.assertEqual(ran, ["02-code-index"])


if __name__ == "__main__":
    unittest.main()
