"""06-reachability-codeql / 06-reachability-ir (ADR-0023): rows, tiers, plan, scripted publishes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import codeql_sast  # noqa: E402
import container_execution as ce  # noqa: E402
import dep_reachability_engines as e  # noqa: E402
import execution_state  # noqa: E402
import reachability  # noqa: E402
import reachability_engine_jobs as jobs  # noqa: E402
from schema_validate import validate_document  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "dep-symbol-resolver" / "python"
SOURCE = "sha256:" + "5" * 64


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


FILES = {"app/main.py": sha("main"), "site-packages/yaml/constructor.py": sha("constructor"),
         "src/zmain.c": sha("zmain"), "vendor/zlib/inflate.c": sha("inflate")}
SCA = {"source_snapshot_sha256": SOURCE, "matches": [
    {"match_id": "VM-000001", "component_ref": "SC-000001", "advisory_id": "GHSA-8q59-q68h-6hv4", "aliases": []},
    {"match_id": "VM-000002", "component_ref": "SC-000002", "advisory_id": "CVE-2022-37434", "aliases": []},
    {"match_id": "VM-000003", "component_ref": "SC-000003", "advisory_id": "GHSA-aaaa-bbbb-cccc", "aliases": []}]}
SBOM = {"components": [
    {"component_id": "SC-000001", "name": "PyYAML", "version": "5.3.1", "ecosystem": "pypi"},
    {"component_id": "SC-000002", "name": "zlib", "version": "1.2.11", "ecosystem": "conan"},
    {"component_id": "SC-000003", "name": "left-pad", "version": "1.0.0", "ecosystem": "npm"}]}
REVIEWED = {"GHSA-8q59-q68h-6hv4": ["load"], "CVE-2022-37434": ["inflateGetHeader"]}


def csv_text(columns, rows):
    return "\n".join([",".join(columns)] + [",".join(str(v) for v in row) for row in rows]) + "\n"


def prepared():
    return jobs.prepare(sca=SCA, sbom=SBOM, reviewed=REVIEWED, osv=None, osv_gap="osv-not-configured", tree=FIXTURES)


def upstream():
    return {"source_generation": SOURCE, "generated_at": "2026-09-29T00:00:00Z",
            "sca": {"job_id": "02-sca-vulnerability-match", "attempt_id": "sca-1", "sha256": SOURCE},
            "sca_matches_sha256": SOURCE, "sbom": {"attempt_id": "sbom-1", "sha256": SOURCE},
            "source_binding": {"projection": "p1"}, "osv": None, "osv_gap": "osv-not-configured",
            "supplied": {"reviewed_map": None, "entry_points": None}, "entry_points": [], "prepared": prepared(),
            "_files": FILES, "_tree": str(FIXTURES)}


class RowTests(unittest.TestCase):
    def test_prepare_resolves_through_the_manifest_and_records_gaps(self):
        rows = {row["match_id"]: row for row in prepared()}
        self.assertEqual(rows["VM-000001"]["language"], "python")
        self.assertIn({"package": "yaml", "symbol": "load", "via": "load as a member of import yaml"},
                      rows["VM-000001"]["resolution"]["names"])
        self.assertEqual(rows["VM-000002"]["resolution"]["names"][0]["symbol"], "inflateGetHeader")
        self.assertEqual(rows["VM-000003"]["symbols"], [])
        self.assertIn("osv-not-configured", rows["VM-000003"]["gaps"])

    def test_finish_row_binds_witnesses_tiers_and_refuses_unproven_absence(self):
        item = prepared()[0]
        found = e.result("codeql", ran=True, state="reachable", reason="Reachability.ql", witness=[
            {"function": "main", "file": "app/main.py", "line": 1, "calls_next_at": "app/main.py:6"},
            {"function": "handler", "file": "app/main.py", "line": 6, "note": "call into the vulnerable dependency function"}])
        row = jobs.finish_row(item, found, FILES, engine="codeql", database_ids=["codeqldb_0123456789abcdef"],
                              unreachable_allowed=False)
        self.assertEqual((row["verdict"], row["tier"], len(row["witness"])), ("reachable", "direct", 2))
        self.assertEqual(validate_document(row, "engine-reachability-row.schema.json"), [])
        through = jobs.finish_row(item, {**found, "witness": [*found["witness"][:1], {
            "function": "construct", "file": "site-packages/yaml/constructor.py", "line": 9}]}, FILES,
            engine="codeql", database_ids=[], unreachable_allowed=False)
        self.assertEqual(through["tier"], "through-dependency")
        unbound = jobs.finish_row(item, {**found, "witness": [{"function": "x", "file": "gone.py", "line": 1}]}, FILES,
                                  engine="codeql", database_ids=[], unreachable_allowed=False)
        self.assertEqual((unbound["verdict"], unbound["tier"]), ("unknown", None))
        self.assertIn("witness-not-hash-bound", unbound["gaps"])
        absent = e.result("cpg", ran=True, state="unreachable", reason="no path",
                          target={"function": "inflateGetHeader", "file": "vendor/zlib/inflate.c", "line": 4})
        self.assertEqual(jobs.finish_row(item, absent, FILES, engine="codeql", database_ids=[],
                                         unreachable_allowed=False)["verdict"], "unknown")
        self.assertEqual(jobs.finish_row(item, absent, FILES, engine="ir", database_ids=[], unreachable_allowed=True,
                                         source_present=False)["verdict"], "unknown")
        proved = jobs.finish_row(item, absent, FILES, engine="ir", database_ids=[], unreachable_allowed=True)
        self.assertEqual((proved["verdict"], proved["target"]["sha256"]), ("unreachable", FILES["vendor/zlib/inflate.c"]))

    def test_codeql_rows_from_decoded_tables(self):
        inputs = {**upstream(), "plan": [
            {"language": "python", "state": "ran", "matches": ["VM-000001"], "node": None,
             "database": {"database_id": "codeqldb_0123456789abcdef"}, "tables": [], "argv": [], "image_digest": None,
             "symbols": [], "gaps": []},
            {"language": "cpp", "state": "no-database", "matches": ["VM-000002"], "node": None, "database": None,
             "tables": [], "argv": [], "image_digest": None, "symbols": [], "gaps": ["engine-input-absent:02-codeql-cpp"]}]}
        tables = {"CallEdges": [], "EntryPoints": [],
                  "Reachability": e.read_table(csv_text(e.REACH_COLUMNS, [
                      ("main", "app/main.py", 1, "handler", "app/main.py", 6, "yaml", "load")]).encode(), "Reachability")}
        rows, languages = jobs.codeql_rows("run", inputs, {"python": {"tables": tables, "gaps": []}}, FILES)
        by = {row["match_id"]: row for row in rows}
        self.assertEqual((by["VM-000001"]["verdict"], by["VM-000001"]["tier"]), ("reachable", "direct"))
        self.assertEqual(by["VM-000001"]["database_ids"], ["codeqldb_0123456789abcdef"])
        self.assertEqual(by["VM-000002"]["verdict"], "unknown")
        self.assertIn("engine-input-absent:02-codeql-cpp", by["VM-000002"]["gaps"])
        self.assertEqual(by["VM-000003"]["verdict"], "unknown")      # npm, no symbols
        result = jobs.assemble(run_id="run", attempt_id="a1", engine="codeql", inputs=inputs, rows=rows,
                               languages=languages)
        self.assertEqual(validate_document(result, "engine-reachability.schema.json"), [])
        self.assertEqual(result["counts"], {"reachable": 1, "unreachable": 0, "unknown": 2})
        self.assertIn("ENGINE_INPUT:engine-input-absent:02-codeql-cpp", result["coverage_gaps"])

    def test_ir_rows_prove_unreachable_only_with_the_source_present(self):
        graph = reachability.CallGraph.from_tables(
            [{"full_name": "main", "name": "main", "path": "src/zmain.c", "start_line": 1, "end_line": 9},
             {"full_name": "inflateGetHeader", "name": "inflateGetHeader", "path": "vendor/zlib/inflate.c",
              "start_line": 4, "end_line": 8}], [], (), {})
        inputs = {**upstream(), "cpg": {"attempt_id": "cpg-1", "result_sha256": SOURCE}, "cpg_gaps": [], "ir": None}
        with mock.patch.object(jobs.bindings, "_check"), mock.patch.object(jobs.reachability, "load_cpg", return_value=graph):
            rows, languages = jobs.ir_rows("run", inputs, FILES)
        by = {row["match_id"]: row for row in rows}
        self.assertEqual(by["VM-000002"]["verdict"], "unreachable")
        self.assertEqual(by["VM-000002"]["target"]["file"], "vendor/zlib/inflate.c")
        self.assertIn("engine-not-applicable:ir:python", by["VM-000001"]["gaps"])
        self.assertEqual(languages[0]["state"], "ran")
        rows, languages = jobs.ir_rows("run", {**inputs, "cpg": None, "cpg_gaps": ["engine-input-absent:02-code-property-graph"]}, FILES)
        self.assertEqual({row["match_id"]: row["verdict"] for row in rows}["VM-000002"], "unknown")
        self.assertEqual(languages[0]["state"], "no-engine")


class ScriptedEngineTests(unittest.TestCase):
    """run()/validate() for both engines with scripted docker and a fake retained database."""

    def setUp(self):
        from test_container_execution import ScriptedDocker
        import container_execution_support as support
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name).resolve()
        self.runs, self.images = base / "runs", base / "images"
        self.images.mkdir()
        (self.runs / "run-reach" / "inputs").mkdir(parents=True)
        record = {**support.fixture_record(), "image_id": codeql_sast.IMAGE_ID,
                  "repository": "docker.io/library/audit-codeql"}
        (self.images / "audit-codeql.json").write_text(json.dumps(record))
        self.database = base / "db"
        (self.database / "db-python").mkdir(parents=True)
        (self.database / "codeql-database.yml").write_text("primaryLanguage: python\n")
        (self.database / "db-python" / "x.trap").write_text("trap\n")
        tree = codeql_sast.database_tree(self.database)
        self.pointer = {"database_id": "codeqldb_0123456789abcdef", "build_mode": "none", "store_path": "x", **tree}
        scripted = ScriptedDocker()
        original = scripted.child

        def child(spec, **kwargs):
            scripted.client_exit, scripted.metadata = 0, {}
            scripted.state = {"Status": "exited", "ExitCode": 0, "OOMKilled": False}
            graph = Path(spec.owner_root) / "scratch" / "graph"
            graph.mkdir(parents=True, exist_ok=True)
            (graph / "CallEdges.csv").write_text(csv_text(e.CALL_EDGE_COLUMNS, []))
            (graph / "EntryPoints.csv").write_text(csv_text(e.ENTRY_COLUMNS, [("main", "app/main.py", 1, "module-body")]))
            (graph / "Reachability.csv").write_text(csv_text(e.REACH_COLUMNS, [
                ("main", "app/main.py", 1, "handler", "app/main.py", 6, "yaml", "load")]))
            return original(spec, **kwargs)

        scripted.child = child
        defaults = ce.host_defaults()
        self.runtime = lambda source: ce.ContainerRuntime(
            docker_executable=defaults["docker_executable"] or Path(sys.executable).resolve(), docker_host=None,
            images_dir=self.images, host_flavor=defaults["host_flavor"],
            container_user=defaults["container_user"] if ce._USER_RE.match(defaults["container_user"]) else "10001:10001",
            source_snapshot_sha256=source, registry_ceiling=[], clock=lambda: support.NOW, cancel=threading.Event())
        accepted = {"databases": [self.pointer]}
        binding = {"job_id": "02-codeql-python", "attempt_id": "cq-1", "status": "OK"}

        def load_accepted(run_id, language):
            if language == "python":
                return accepted, binding, None
            return None, None, f"engine-input-absent:{codeql_sast.JOBS[language]}"

        def verify(run_id, record):
            return self.database if codeql_sast.database_tree(self.database) == {
                k: record[k] for k in ("tree_sha256", "files", "bytes")} else None

        self.patches = [*scripted.patches(), mock.patch.object(execution_state, "RUNS", self.runs),
                        mock.patch.object(ce, "IMAGES_DIR", self.images),
                        mock.patch.object(jobs, "_runtime", side_effect=self.runtime),
                        mock.patch.object(jobs, "_upstream", side_effect=lambda run_id, job: upstream()),
                        mock.patch.object(jobs, "_files", side_effect=lambda run_id, inputs: FILES),
                        mock.patch.object(jobs.codeql_sast, "load_accepted", side_effect=load_accepted),
                        mock.patch.object(jobs.codeql_sast, "verify_database", side_effect=verify)]
        for patch in self.patches: patch.start()

    def tearDown(self):
        for patch in reversed(self.patches): patch.stop()
        self.temporary.cleanup()

    def test_codeql_engine_publishes_and_revalidates(self):
        envelope = jobs.run("run-reach", "dagster-1", "codeql")
        self.assertEqual(envelope["status"], "OK_WITH_GAPS")
        attempt = jobs.root("run-reach", "codeql") / "attempts" / envelope["attempt_id"]
        result = json.loads((attempt / jobs.RESULT).read_text())
        by = {row["match_id"]: row for row in result["rows"]}
        self.assertEqual((by["VM-000001"]["verdict"], by["VM-000001"]["tier"]), ("reachable", "direct"))
        states = {row["language"]: row["state"] for row in result["languages"]}
        self.assertEqual((states["python"], states["cpp"], states["java"]), ("ran", "no-database", "no-matches"))
        symbols = attempt / "languages" / "python" / "symbols" / "symbols.model.yml"
        self.assertIn('"yaml"', symbols.read_text())
        request = json.loads((attempt / "languages" / "python" / "run" / "logs" / "container" /
                              ce.REQUEST_FILE).read_text())
        self.assertEqual([m["container_path"] for m in request["target_mounts"]],
                         ["/inputs/codeql-db", "/inputs/pack", "/inputs/symbols"])
        self.assertEqual(request["network"], {"mode": "none", "destinations": []})
        self.assertEqual(request["argv"][:2], ["/opt/scripts/codeql-reachability-lane.sh", "python"])
        self.assertEqual(jobs.validate("run-reach", "codeql"), attempt)
        table = attempt / "languages" / "python" / "run" / "scratch" / "graph" / "Reachability.csv"
        table.write_text(csv_text(e.REACH_COLUMNS, []))
        with self.assertRaises(execution_state.Blocked):
            jobs.validate("run-reach", "codeql")

    def test_changed_database_is_a_gap_not_a_rebuild(self):
        (self.database / "db-python" / "x.trap").write_text("changed\n")
        envelope = jobs.run("run-reach", "dagster-1", "codeql")
        attempt = jobs.root("run-reach", "codeql") / "attempts" / envelope["attempt_id"]
        result = json.loads((attempt / jobs.RESULT).read_text())
        self.assertIn("ENGINE_INPUT:codeql-db-changed:python", result["coverage_gaps"])
        self.assertEqual({row["match_id"]: row["verdict"] for row in result["rows"]}["VM-000001"], "unknown")
        self.assertFalse((attempt / "languages" / "python" / "run").exists())

    def test_ir_engine_publishes_and_revalidates(self):
        graph = reachability.CallGraph.from_tables(
            [{"full_name": "main", "name": "main", "path": "src/zmain.c", "start_line": 1, "end_line": 9},
             {"full_name": "inflateGetHeader", "name": "inflateGetHeader", "path": "vendor/zlib/inflate.c",
              "start_line": 4, "end_line": 8}], [], (), {})
        with mock.patch.object(jobs.bindings, "_cpg", return_value=({"attempt_id": "cpg-1", "result_sha256": SOURCE}, [])), \
                mock.patch.object(jobs, "_ir_facts", return_value=None), mock.patch.object(jobs.bindings, "_check"), \
                mock.patch.object(jobs.reachability, "load_cpg", return_value=graph):
            envelope = jobs.run("run-reach", "dagster-1", "ir")
            attempt = jobs.root("run-reach", "ir") / "attempts" / envelope["attempt_id"]
            result = json.loads((attempt / jobs.RESULT).read_text())
            self.assertEqual({row["match_id"]: row["verdict"] for row in result["rows"]}["VM-000002"], "unreachable")
            self.assertEqual(result["engine"], "ir")
            self.assertEqual(jobs.validate("run-reach", "ir"), attempt)
            document, binding, gap = jobs.load_table("run-reach", "ir", SOURCE)
        self.assertEqual((document["engine"], binding["attempt_id"], gap), ("ir", envelope["attempt_id"], None))
        self.assertEqual(jobs.load_table("run-reach", "ir", "sha256:" + "6" * 64)[2],
                         "engine-input-mixed-lineage:06-reachability-ir")


if __name__ == "__main__":
    unittest.main()
