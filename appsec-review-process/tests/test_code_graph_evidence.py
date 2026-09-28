from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

PROCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROCESS))

import code_graph_evidence as cpg
from execution_state import Blocked, file_hash
import joern_cpg
import evidence_index_enrichment as enrichment
from schema_validate import validate_document

SHA = "sha256:" + "1" * 64


class CodeGraphEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / "target"; (self.target / "src").mkdir(parents=True)
        self.source = self.target / "src/main.c"
        self.source.write_text("typedef int count_t;\nint copy(char *d, char *s) { strcpy(d, s); return 0; }\nint main(void) { return copy(0, 0); }\n", encoding="utf-8")
        self.raw = self.root / "records.jsonl"

    def tearDown(self): self.temp.cleanup()

    def row(self, **changes):
        value = {"kind":"call","label":"CALL","name":"strcpy","full_name":"strcpy",
                 "caller":"copy:int(char*,char*)","type_name":"ANY","file":"/workspace/src/main.c",
                 "line":2,"column":35,"code":"strcpy(d, s)"}
        value.update(changes); return value

    def write(self, *rows):
        self.raw.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def normalize(self):
        return cpg.normalize_jsonl(self.raw, target=self.target, run_id="run-1",
            source_snapshot_sha256=SHA, source_revision="abc123", image_id="audit-native",
            image_digest=SHA, exporter_sha256=SHA, build_identity_sha256=SHA)

    def test_normalize_query_and_dereference(self):
        self.write(self.row(), self.row(kind="symbol",label="METHOD",name="copy",full_name="copy:int(char*,char*)",caller="",line=2,column=1,code="copy"),
                   self.row(kind="type",label="TYPE_DECL",name="count_t",full_name="count_t",caller="",type_name="count_t",line=1,column=1,code="count_t"),
                   self.row(kind="memory-operation",name="strcpy",full_name="strcpy",line=2,column=35))
        document = self.normalize()
        self.assertEqual(validate_document(document, "code-property-graph.schema.json"), [])
        self.assertEqual(document["record_count"], 4)
        flow = cpg.structural_query(document, operation="flows", caller="copy", callee="strcpy")
        self.assertTrue(flow); self.assertEqual(flow[0]["authority"], "candidate_locator_requires_dereference")
        memory = cpg.structural_query(document, operation="memory-operations", text="strcpy")
        citation = cpg.dereference(self.target, memory[0]["locator"])
        self.assertEqual(citation["authority"], "dereferenced_source_evidence")
        self.assertIn("strcpy", citation["excerpt"])
        self.assertTrue(cpg.structural_query(document, operation="symbols", text="copy"))
        self.assertTrue(cpg.structural_query(document, operation="types", text="count_t"))

    def test_redaction_and_empty_locations_are_explicit(self):
        self.write(self.row(code="password=supersecretvalue"), self.row(file="<empty>", line=None, column=None))
        document = self.normalize()
        self.assertEqual(document["record_count"], 1)
        self.assertNotIn("supersecretvalue", document["records"][0]["search_text"])
        self.assertEqual(document["coverage_gaps"], [{"reason":"no-source-location","count":1}])

    def test_malformed_and_traversal_fail_closed(self):
        self.raw.write_text("{bad\n", encoding="utf-8")
        with self.assertRaisesRegex(Blocked, "malformed"): self.normalize()
        # A path outside the checkout is never read: the record is skipped and counted as a gap.
        self.write(self.row(file="../outside.c"))
        document = self.normalize()
        self.assertEqual(document["records"], [])
        self.assertIn({"reason": "source-unavailable", "count": 1}, document["coverage_gaps"])

    def test_record_count_is_logged_not_blocked(self):
        seen = []
        original = cpg.size_log.observe
        cpg.size_log.observe = lambda *a, **k: seen.append(a)
        try:
            self.write(self.row(), self.row(name="memcpy", code="memcpy(d,s,1)"))
            self.assertEqual(len(self.normalize()["records"]), 2)
        finally: cpg.size_log.observe = original
        self.assertIn("joern_records", [item[2] for item in seen])

    def test_stale_source_locator_rejected(self):
        self.write(self.row()); document = self.normalize(); locator = document["records"][0]["locator"]
        self.source.write_text(self.source.read_text(encoding="utf-8") + "// changed\n", encoding="utf-8")
        with self.assertRaisesRegex(Blocked, "stale source"): cpg.dereference(self.target, locator)

    def test_ir_projection_retains_locator_not_authority(self):
        facts = {"debug_locations":[{"debug_location_id":"7","source_line":2,"source_column":4}],
                 "facts":[{"fact_id":"f1","kind":"memory-write","function":"copy","source_path":"src/main.c","source_sha256":SHA,"debug_location_id":"7"},
                            {"fact_id":"f2","kind":"memory-read","function":None,"source_path":None,"source_sha256":None,"debug_location_id":None}]}
        rows = list(cpg.project_ir_facts(facts))
        self.assertEqual(len(rows), 1); self.assertEqual(rows[0]["authority"], "candidate_locator_requires_dereference")
        self.assertEqual(rows[0]["locator"]["line"], 2)

    def test_query_bounds(self):
        self.write(self.row()); document = self.normalize()
        with self.assertRaises(ValueError): cpg.structural_query(document, operation="sql")
        with self.assertRaises(ValueError): cpg.structural_query(document, operation="calls", limit=101)

    def test_unavailable_pinned_image_blocks_preflight(self):
        manifest = self.root / "artifact-manifest.json"
        manifest.write_text(json.dumps({"target":{"repo_path":str(self.target)}}), encoding="utf-8")
        with mock.patch.object(joern_cpg, "_target", return_value=(self.target, SHA, "abc123")), \
             mock.patch.object(joern_cpg.ce, "load_image_registry", return_value={}):
            with self.assertRaisesRegex(Blocked, "no current B16 record"):
                joern_cpg.current_inputs("run-1")

    def test_lancedb_contract_cannot_be_confused_with_fts_authority(self):
        contract = json.loads((PROCESS / "registry/output-contracts/semantic-recall-index.json").read_text())
        template = json.loads((PROCESS / "registry/job-templates/02-semantic-recall-index.json").read_text())
        rules = " ".join(contract["validation_rules"])
        self.assertIn("Vector distance", rules)
        self.assertIn("SQLite FTS5 remains", rules)
        self.assertFalse(template["implemented"])
        self.assertNotIn("02-semantic-recall-index", enrichment.PROFILES)
        manifest = {"schema":"appsec-review/semantic-recall-index/1.0","run_id":"run",
            "status":"OK","authority":"SEMANTIC_RECALL_ONLY_LOCATORS_REQUIRE_DEREFERENCE",
            "source_snapshot_sha256":SHA,"source_tree_sha256":SHA,
            "generation_bindings":{"symbol_index_sha256":SHA,"cpg_sha256":SHA,"ir_facts_sha256":SHA},
            "embedding_model":{"model_id":"pinned-model","artifact_sha256":SHA,"preseeded":True,"network":"none"},
            "index":{"engine":"lancedb-vector","table":"chunks","tree_sha256":SHA,"rows":1},
            "redaction":"required-before-embedding","limits":{"max_rows":200000,"max_chunk_chars":4000,"max_results":100},
            "coverage_gaps":[]}
        self.assertEqual(validate_document(manifest, "semantic-recall-index.schema.json"), [])


if __name__ == "__main__": unittest.main()
