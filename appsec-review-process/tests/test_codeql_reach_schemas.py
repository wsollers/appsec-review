"""Brief G schemas: codeql-language result + database pointer, engine table, correlated summary."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from schema_validate import validate_document  # noqa: E402

SHA = "sha256:" + "a" * 64
POINTER = {"database_id": "codeqldb_0123456789abcdef", "job_id": "02-codeql-python", "attempt_id": "attempt-1",
           "plan_key": "python", "language": "python", "build_mode": "none", "unit_id": None,
           "bundle_version": "2.27.0", "tool_metadata_sha256": SHA, "image_digest": SHA,
           "source_snapshot_sha256": SHA, "store_path": "codeql-databases/02-codeql-python/attempt-1/python",
           "tree_sha256": SHA, "files": 3, "bytes": 42}
LANGUAGE = {"schema": "appsec-review/codeql-language/1", "run_id": "run", "job_id": "02-codeql-python",
            "attempt_id": "attempt-1", "language": "python", "source_snapshot_sha256": SHA, "status": "OK",
            "skip_reason": None, "build_modes": ["none"], "tools": [], "leads": [], "databases": [POINTER],
            "coverage_gaps": []}
HOP = {"function": "main", "file": "app.py", "line": 3, "sha256": SHA}
ROW = {"match_id": "VM-000001", "component_ref": "SC-000001", "advisory_id": "GHSA-aaaa-bbbb-cccc",
       "ecosystem": "pypi", "language": "python", "verdict": "reachable", "tier": "direct",
       "symbols": [{"package": "PyYAML", "symbol": "load", "source": "reviewed-map"}],
       "resolved": [{"package": "yaml", "symbol": "load", "via": "top_level.txt"}],
       "resolution": ["pypi PyYAML -> import yaml (top_level.txt)"], "witness": [HOP], "taint_paths": [],
       "target": None, "database_ids": ["codeqldb_0123456789abcdef"], "reason": "CodeQL Reachability.ql", "gaps": []}
TABLE = {"schema": "appsec-review/engine-reachability/1", "run_id": "run", "job_id": "06-reachability-codeql",
         "attempt_id": "attempt-2", "engine": "codeql", "source_snapshot_sha256": SHA,
         "sca_binding": {"job_id": "02-sca-vulnerability-match", "attempt_id": "sca-1", "sha256": SHA},
         "status": "OK", "languages": [{"language": "python", "state": "ran",
                                        "database_ids": ["codeqldb_0123456789abcdef"], "gaps": []}],
         "rows": [ROW], "counts": {"reachable": 1, "unreachable": 0, "unknown": 0}, "coverage_gaps": [],
         "claim_ceiling": "EVIDENCE_LEADS_ONLY"}
SUMMARY = {"schema": "appsec-review/dependency-reachability-summary/1", "run_id": "run",
           "job_id": "06-cve-reachability", "attempt_id": "attempt-3", "source_snapshot_sha256": SHA,
           "counts": {"reachable": 0, "unreachable": 0, "conflict": 1, "unknown": 0},
           "engines": [{"job_id": "06-reachability-codeql", "engine": "codeql", "attempt_id": "attempt-2",
                        "result_sha256": SHA, "status": "OK"}],
           "matches": [{"match_id": "VM-000001", "component_ref": "SC-000001", "advisory_id": "GHSA-aaaa-bbbb-cccc",
                        "component": "PyYAML 5.3", "ecosystem": "pypi", "language": "python", "verdict": "conflict",
                        "tier": None, "deciding_engines": ["codeql", "ir"],
                        "engines": [{"engine": "codeql", "verdict": "reachable"}, {"engine": "ir", "verdict": "unreachable"}],
                        "witness_length": 0, "entry": None, "call_site": None, "reason": "engines disagree", "gaps": 1}],
           "review": {"p1_match_ids": [], "conflict_match_ids": ["VM-000001"]}, "coverage_gaps": [],
           "claim_ceiling": "EVIDENCE_LEADS_ONLY"}


class SchemaTests(unittest.TestCase):
    def test_valid_examples(self):
        self.assertEqual(validate_document(POINTER, "codeql-database-pointer.schema.json"), [])
        self.assertEqual(validate_document(LANGUAGE, "codeql-language.schema.json"), [])
        self.assertEqual(validate_document(ROW, "engine-reachability-row.schema.json"), [])
        self.assertEqual(validate_document(TABLE, "engine-reachability.schema.json"), [])
        self.assertEqual(validate_document(SUMMARY, "dependency-reachability-summary.schema.json"), [])

    def test_skipped_language_and_traced_pointer(self):
        skipped = {**LANGUAGE, "status": "SKIPPED", "skip_reason": "not-applicable-language-absent", "databases": []}
        self.assertEqual(validate_document(skipped, "codeql-language.schema.json"), [])
        traced = {**POINTER, "job_id": "02-codeql-cpp", "language": "cpp", "build_mode": "traced",
                  "plan_key": "codeql-cpp-traced:0123456789abcdef", "unit_id": "unit-a",
                  "store_path": "codeql-databases/02-codeql-cpp/attempt-1/codeql-cpp-traced-0123456789abcdef"}
        self.assertEqual(validate_document(traced, "codeql-database-pointer.schema.json"), [])

    def test_invalid_examples_are_refused(self):
        cases = [
            ({**LANGUAGE, "job_id": "02-codeql-sast"}, "codeql-language.schema.json"),
            ({**LANGUAGE, "language": "php"}, "codeql-language.schema.json"),
            ({**LANGUAGE, "skip_reason": "because"}, "codeql-language.schema.json"),
            ({**POINTER, "store_path": "/abs/path"}, "codeql-database-pointer.schema.json"),
            ({**POINTER, "store_path": "codeql-databases/02-codeql-python/../x/y"}, "codeql-database-pointer.schema.json"),
            ({**ROW, "verdict": "conflict"}, "engine-reachability-row.schema.json"),
            ({**ROW, "tier": "transitive"}, "engine-reachability-row.schema.json"),
            ({**ROW, "reason": "line\nbreak"}, "engine-reachability-row.schema.json"),
            ({**TABLE, "engine": "lsp"}, "engine-reachability.schema.json"),
            ({**SUMMARY, "counts": {"reachable": 0, "unreachable": 0, "unknown": 0}},
             "dependency-reachability-summary.schema.json"),
        ]
        for document, schema in cases:
            with self.subTest(schema=schema, document=json.dumps(document)[:80]):
                self.assertNotEqual(validate_document(document, schema), [])
        bad_pointer = copy.deepcopy(LANGUAGE)
        bad_pointer["databases"][0]["tree_sha256"] = "sha256:short"
        self.assertNotEqual(validate_document(bad_pointer, "codeql-language.schema.json"), [])


if __name__ == "__main__":
    unittest.main()
