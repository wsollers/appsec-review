"""02-semantic-recall-index: chunk plan from accepted function spans, pinned model, LanceDB build and
bounded locator queries. A tiny deterministic embedder and an in-memory store stand in for fastembed
and LanceDB; no model is downloaded and no container runs."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

PROCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROCESS))

import code_index
from execution_state import Blocked, atomic_json, digest, file_hash
import registry_paths
from schema_validate import validate_document
import semantic_index_build as sib
import semantic_recall_index as sri

SHA = "sha256:" + "1" * 64
DIM = 512

SOURCE = {
    "src/auth.c": "int check_password(const char *given, const char *stored) {\n"
                  "    return strcmp(given, stored) == 0;\n}\n\n"
                  "void log_line(const char *text) {\n    puts(text);\n}\n",
    "src/net.py": "def open_socket(host, port):\n    s = socket.socket()\n    s.connect((host, port))\n    return s\n",
}
# (file, start, end, full_name) methods; (file, start, end, name) tree-sitter functions
METHODS = [("src/auth.c", 1, 3, "check_password"), ("src/auth.c", 5, 7, "log_line")]
TS_FUNCTIONS = [("src/auth.c", 1, 3, "check_password"), ("src/net.py", 1, 4, "open_socket")]


def embed(texts):
    """Deterministic bag-of-words embedder: each lower-case token adds to one of DIM buckets."""
    out = []
    for text in texts:
        vector = [0.0] * DIM
        for token in re.findall(r"[a-z]+", text.lower()):
            vector[hashlib.sha256(token.encode()).digest()[0] % DIM] += 1.0
        norm = math.sqrt(sum(x * x for x in vector)) or 1.0
        out.append([x / norm for x in vector])
    return out


class MemoryStore:
    """LanceStore's interface over a list (cosine distance)."""

    def __init__(self):
        self.rows = []

    def write(self, batches):
        for rows in batches:
            self.rows.extend(rows)
        return len(self.rows)

    def search(self, vector, limit):
        def distance(row):
            dot = sum(a * b for a, b in zip(vector, row["vector"]))
            norm = math.sqrt(sum(a * a for a in vector)) * math.sqrt(sum(b * b for b in row["vector"])) or 1.0
            return 1.0 - dot / norm
        ranked = sorted(self.rows, key=lambda row: (distance(row), row["row_id"]))
        return [{"row_id": row["row_id"], "distance": distance(row)} for row in ranked[:limit]]


def code_index_db(path: Path, target: Path, *, sha_override: dict[str, str] | None = None) -> Path:
    connection = sqlite3.connect(str(path))
    connection.executescript(code_index.DDL)
    for name in SOURCE:
        sha = (sha_override or {}).get(name) or "sha256:" + file_hash(target / name)
        connection.execute("INSERT INTO files VALUES(?,?,?,?)", (name, sha, code_index.language_of(name), "cpg"))
    for index, (file, start, end, name) in enumerate(METHODS, 1):
        connection.execute("INSERT INTO methods VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                           (index, name, name, name, None, file, start, end, "treesitter", 0, "c", None))
    connection.execute("INSERT INTO methods VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (99, "strcmp", "strcmp", "strcmp", None, None, None, None, "cpg-first-line", 1, None, None))
    for file, start, end, name in TS_FUNCTIONS:
        connection.execute("INSERT INTO ts_functions VALUES(?,?,?,?,?,?)", (file, name, "function", start, end, "x"))
    connection.commit(); connection.close()
    return path


def inputs_for(model_sha: str = SHA) -> dict:
    return {"source_snapshot_sha256": SHA, "source_tree_sha256": SHA,
            "generation_bindings": {"symbol_index_sha256": SHA, "cpg_sha256": SHA, "ir_facts_sha256": None},
            "model": {"model_id": "jinaai/jina-embeddings-v2-base-code", "artifact_sha256": model_sha},
            "code_index": {"gaps": []}}


class SemanticRecallIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        for name, text in SOURCE.items():
            (self.target / name).parent.mkdir(parents=True, exist_ok=True)
            (self.target / name).write_text(text, encoding="utf-8")
        self.db = code_index_db(self.root / "code-index.sqlite", self.target)

    def tearDown(self):
        self.temp.cleanup()

    def plan(self, **kwargs):
        plan_path, sidecar = self.root / "plan.jsonl", self.root / "attempt" / sri.SIDECAR
        sidecar.parent.mkdir(exist_ok=True)
        summary = sri.write_plan(self.target, self.db, max_file_bytes=1 << 20, plan_path=plan_path,
                                 sidecar_path=sidecar, **kwargs)
        return summary, list(sib.read_plan(plan_path)), list(sib.read_plan(sidecar))

    def publish(self):
        """An attempt as the worker leaves it, with the in-memory store standing in for LanceDB."""
        summary, plan, _ = self.plan()
        store = MemoryStore()
        stats = sib.build(iter(plan), embed, store, batch_size=2)
        attempt = self.root / "attempt"
        (attempt / sri.INDEX_DIR).mkdir(parents=True)
        (attempt / sri.INDEX_DIR / "chunks.lance").write_text("stand-in", encoding="utf-8")
        document = sri.manifest("run-1", inputs_for(), stats["rows"], sib.tree_sha256(attempt / sri.INDEX_DIR),
                                summary["gaps"])
        atomic_json(attempt / sri.RESULT, document)
        atomic_json(attempt / sri.RECEIPT, {"sidecar_sha256": summary["sidecar_sha256"], "plan_sha256": summary["plan_sha256"]})
        return attempt, store, summary, stats

    def test_chunk_bounds_equal_function_spans(self):
        summary, plan, sidecar = self.plan()
        spans = sorted({(f, s, e) for f, s, e, _ in METHODS + TS_FUNCTIONS})
        self.assertEqual([(row["file"], row["start_line"], row["end_line"]) for row in sidecar], spans)
        self.assertEqual(summary["rows"], 3)          # the method/tree-sitter duplicate is one chunk
        self.assertEqual([row["row_id"] for row in plan], [0, 1, 2])
        self.assertNotIn("strcmp", [row["symbol"] for row in plan])     # external methods have no span
        for row in plan:
            lines = SOURCE[row["file"]].splitlines()[row["start_line"] - 1:row["end_line"]]
            self.assertEqual(row["text"], "\n".join(lines).strip())
        self.assertNotIn("text", sidecar[0])          # the published sidecar carries locators, no source
        self.assertEqual(summary["sidecar_sha256"], "sha256:" + file_hash(self.root / "attempt" / sri.SIDECAR))
        self.assertEqual(summary["plan_sha256"], "sha256:" + file_hash(self.root / "plan.jsonl"))
        self.assertEqual(summary["gaps"], [])
        # Validation re-derives the same hashes without writing anything.
        again = sri.write_plan(self.target, self.db, max_file_bytes=1 << 20)
        self.assertEqual(again, summary)

    def test_unembedded_material_is_a_gap_not_silence(self):
        (self.target / "src/net.py").write_text(SOURCE["src/net.py"] + "# changed\n", encoding="utf-8")
        long_body = "int big(void) {\n" + "    x = x + 1;\n" * 400 + "}\n"
        (self.target / "src/auth.c").write_text(SOURCE["src/auth.c"] + long_body, encoding="utf-8")
        self.db.unlink()
        self.db = code_index_db(self.root / "code-index.sqlite", self.target,
                                sha_override={"src/net.py": "sha256:" + hashlib.sha256(SOURCE["src/net.py"].encode()).hexdigest()})
        connection = sqlite3.connect(str(self.db))
        connection.execute("INSERT INTO ts_functions VALUES(?,?,?,?,?,?)", ("src/auth.c", "big", "function", 8, 409, "c"))
        connection.execute("INSERT INTO ts_functions VALUES(?,?,?,?,?,?)", ("src/auth.c", "nolen", "function", 8, None, "c"))
        connection.commit(); connection.close()
        summary, plan, sidecar = self.plan(max_rows=10)
        self.assertIn("source-changed:src/net.py", summary["gaps"])
        self.assertTrue(any(gap.startswith("truncated:1 ") for gap in summary["gaps"]))
        self.assertTrue(any(gap.startswith("span-unknown:1 ") for gap in summary["gaps"]))
        big = next(row for row in sidecar if row["symbol"] == "big")
        self.assertEqual((big["start_line"], big["end_line"]), (8, 409))      # the locator keeps the full span
        self.assertTrue(big["truncated"])
        self.assertLessEqual(max(len(row["text"]) for row in plan), sri.MAX_CHUNK_CHARS)
        capped, _, _ = self.plan(max_rows=1)
        self.assertEqual(capped["rows"], 1)
        self.assertTrue(any(gap.startswith("max-rows:") for gap in capped["gaps"]))

    def test_manifest_validates_against_the_registered_contract(self):
        attempt, _store, summary, stats = self.publish()
        document = json.loads((attempt / sri.RESULT).read_text())
        self.assertEqual(validate_document(document, sri.SCHEMA_FILE), [])
        self.assertEqual(document["authority"], "SEMANTIC_RECALL_ONLY_LOCATORS_REQUIRE_DEREFERENCE")
        self.assertEqual(document["index"]["rows"], 3)
        self.assertEqual(stats["plan_sha256"], summary["plan_sha256"])     # what the container echoes back
        self.assertEqual(stats["vector_dim"], DIM)
        contract = json.loads(registry_paths.contract(sri.CONTRACT).read_text())
        self.assertEqual(contract["result_schema"], {"artifact": sri.RESULT, "schema_file": sri.SCHEMA_FILE})
        template = json.loads(registry_paths.template(sri.JOB).read_text())
        self.assertTrue(template["implemented"])
        self.assertEqual(template["execution"], {"worker": "semantic_recall_index.py", "arguments": ["{run_id}"]})
        gapped = sri.manifest("run-1", {**inputs_for(), "code_index": {"gaps": ["x"]}}, 3, SHA, ["code-index:x"])
        self.assertEqual(gapped["status"], "OK_WITH_GAPS")
        self.assertEqual(validate_document(gapped, sri.SCHEMA_FILE), [])

    def test_container_stats_must_match_plan_and_pinned_model(self):
        summary, plan, _ = self.plan()
        stats = sib.build(iter(plan), embed, MemoryStore(), batch_size=1)
        inputs = inputs_for()
        sri._check_stats({**stats, "model_sha256": SHA}, summary, inputs)
        with self.assertRaisesRegex(Blocked, "model other than the pinned one"):
            sri._check_stats({**stats, "model_sha256": "sha256:" + "2" * 64}, summary, inputs)
        with self.assertRaisesRegex(Blocked, "do not match the staged plan"):
            sri._check_stats({**stats, "rows": 2, "model_sha256": SHA}, summary, inputs)

    def model(self, *, pinned=True):
        base = self.root / "models"
        directory = base / "jinaai--jina-embeddings-v2-base-code" / ("a" * 40)
        for name in sib.MODEL_FILES:
            (directory / name).parent.mkdir(parents=True, exist_ok=True)
            (directory / name).write_bytes(name.encode() * 3)
        files = sib.model_files(directory)
        pin = {"model_id": "jinaai/jina-embeddings-v2-base-code", "source": "https://example.invalid/x",
               "revision": "a" * 40 if pinned else None, "files": files if pinned else {},
               "artifact_sha256": "sha256:" + digest(files) if pinned else None}
        atomic_json(self.root / "pin.json", pin)
        return base, directory

    def test_model_hash_mismatch_or_absence_blocks(self):
        base, directory = self.model()
        binding = sri.model_binding(self.root / "pin.json", base)
        self.assertEqual(binding["artifact_sha256"], sib.model_sha256(directory))   # container computes the same
        (directory / "onnx/model.onnx").write_bytes(b"tampered")
        with self.assertRaisesRegex(Blocked, "does not match its pin"):
            sri.model_binding(self.root / "pin.json", base)
        (directory / "tokenizer.json").unlink()
        with self.assertRaisesRegex(Blocked, "incomplete"):
            sri.model_binding(self.root / "pin.json", base)
        with self.assertRaisesRegex(Blocked, "not preseeded"):
            sri.model_binding(self.root / "pin.json", self.root / "elsewhere")
        self.model(pinned=False)
        with self.assertRaisesRegex(Blocked, "no recorded pin"):
            sri.model_binding(self.root / "pin.json", base)

    def test_fetch_model_records_then_enforces_the_pin(self):
        revision = "b" * 40
        upstream = self.root / "hub" / "resolve" / revision
        for name in sib.MODEL_FILES:
            (upstream / name).parent.mkdir(parents=True, exist_ok=True)
            (upstream / name).write_bytes(b"weights:" + name.encode())
        pin_path, base = self.root / "pin.json", self.root / "models"
        atomic_json(pin_path, {"model_id": "org/model", "source": (self.root / "hub").as_uri(), "revision": None,
                               "files": {}, "artifact_sha256": None})
        with self.assertRaisesRegex(SystemExit, "--revision"):
            sri.fetch_model(None, pin_path=pin_path, base=base)
        with self.assertRaisesRegex(SystemExit, "no pin recorded yet"):
            sri.fetch_model(revision, pin_path=pin_path, base=base)
        binding = sri.fetch_model(revision, write_pin=True, pin_path=pin_path, base=base)
        self.assertEqual(json.loads(pin_path.read_text())["artifact_sha256"], binding["artifact_sha256"])
        self.assertEqual(sri.fetch_model(None, pin_path=pin_path, base=base), binding)   # second host: verified
        (upstream / "tokenizer.json").write_bytes(b"swapped upstream")
        shutil.rmtree(base)
        with self.assertRaisesRegex(SystemExit, "pin says"):
            sri.fetch_model(None, pin_path=pin_path, base=base)
        self.assertFalse((base / "org--model" / revision).exists())
        with self.assertRaisesRegex(SystemExit, "re-pinning"):
            sri.fetch_model("c" * 40, pin_path=pin_path, base=base)

    def test_job_preflight_blocks_before_any_container_without_the_pinned_model(self):
        # The tracked pin is empty until a host records it: the job is BLOCKED with the preseed command.
        with mock.patch.object(sri, "_target", return_value=(self.target, SHA, "abc")), \
             mock.patch.object(sri, "_code_index", return_value=({"gaps": []}, {})), \
             mock.patch.dict(sri.os.environ, {"APPSEC_EMBEDDING_MODEL_ROOT": str(self.root / "none")}), \
             mock.patch.object(sri.ce, "run_container") as container:
            if json.loads(sri.MODEL_PIN.read_text())["artifact_sha256"] is None:
                with self.assertRaisesRegex(Blocked, "no recorded pin.*fetch-model"):
                    sri.current_inputs("run-1")
            else:
                with self.assertRaisesRegex(Blocked, "not preseeded"):
                    sri.current_inputs("run-1")
            container.assert_not_called()

    def test_query_returns_locators_that_dereference_to_snapshot_bytes(self):
        attempt, store, _summary, _stats = self.publish()
        hits = sri.query(attempt, "password strcmp compare", limit=3, embedder=embed, store=store)
        self.assertEqual(len(hits), 3)
        self.assertEqual(set(hits[0]), {"file", "start_line", "end_line", "symbol", "score"})
        self.assertEqual((hits[0]["file"], hits[0]["symbol"]), ("src/auth.c", "check_password"))
        self.assertGreaterEqual(hits[0]["score"], hits[1]["score"])
        lines = sri.dereference(attempt, self.target, hits[0])
        expected = (self.target / "src/auth.c").read_bytes().decode().splitlines()[0:3]
        self.assertEqual(lines, expected)
        self.assertIn("strcmp(given, stored)", "\n".join(lines))
        (self.target / "src/auth.c").write_text(SOURCE["src/auth.c"] + "// edit\n", encoding="utf-8")
        with self.assertRaisesRegex(Blocked, "stale source"):
            sri.dereference(attempt, self.target, hits[0])
        with self.assertRaisesRegex(Blocked, "not in this index"):
            sri.dereference(attempt, self.target, {**hits[0], "end_line": 99})

    def test_query_is_bounded_and_refuses_a_tampered_index(self):
        attempt, store, _summary, _stats = self.publish()
        for bad in (0, 101, True, "5", None):
            with self.assertRaises(ValueError):
                sri.query(attempt, "socket", limit=bad, embedder=embed, store=store)
        for bad in ("", "   ", "x" * (sri.MAX_QUERY_CHARS + 1)):
            with self.assertRaises(ValueError):
                sri.query(attempt, bad, limit=1, embedder=embed, store=store)
        self.assertEqual(len(sri.query(attempt, "socket", limit=1, embedder=embed, store=store)), 1)
        greedy = mock.Mock(search=lambda vector, limit: [{"row_id": i % 3, "distance": 0.1} for i in range(50)])
        self.assertEqual(len(sri.query(attempt, "socket", limit=2, embedder=embed, store=greedy)), 2)
        (attempt / sri.INDEX_DIR / "chunks.lance").write_text("swapped", encoding="utf-8")
        with self.assertRaisesRegex(Blocked, "LanceDB tree differs"):
            sri.query(attempt, "socket", limit=1, embedder=embed)
        with (attempt / sri.SIDECAR).open("a", encoding="utf-8") as handle:
            handle.write("{}\n")
        with self.assertRaisesRegex(Blocked, "sidecar does not match"):
            sri.query(attempt, "socket", limit=1, embedder=embed, store=store)

    def test_query_refuses_an_index_built_with_another_model(self):
        attempt, store, _summary, _stats = self.publish()
        with mock.patch.object(sri, "model_binding", return_value={"artifact_sha256": "sha256:" + "9" * 64}):
            with self.assertRaisesRegex(Blocked, "another embedding model"):
                sri.query(attempt, "socket", limit=1, store=store)

    def test_builder_rejects_oversized_rows_and_bad_batches(self):
        with self.assertRaises(ValueError):
            sib.build(iter([{"row_id": 0, "file": "a", "start_line": 1, "end_line": 1, "symbol": "", "language": None,
                             "text": "x" * (sib.MAX_CHUNK_CHARS + 1)}]), embed, MemoryStore(), batch_size=1)
        with self.assertRaises(ValueError):
            sib.build(iter([]), embed, MemoryStore(), batch_size=0)

    def test_request_mounts_plan_and_model_read_only_with_network_none(self):
        inputs = {**inputs_for(), "batch_size": 8, "image": {"digest": SHA}, "container_limits": {},
                  "model": {"model_id": "m/x", "artifact_sha256": SHA, "path": "/models/m"}}
        with mock.patch.object(sri, "_permission", return_value={}):
            request = sri._request("run-1", "semrec-1", inputs, Path("/staged"))
        self.assertEqual(request["network"], {"mode": "none", "destinations": []})
        self.assertEqual(request["target_mounts"], [{"host_path": "/staged", "container_path": "/inputs/semantic"},
                                                    {"host_path": "/models/m", "container_path": "/model"}])
        self.assertEqual(request["argv"][:3], ["/usr/bin/python3", "-B", "/inputs/semantic/semantic_index_build.py"])

    def test_oversized_diagnostic_reads_the_published_sidecar(self):
        import semantic_index_oversized as oversized
        self.plan()
        rows = oversized.rows(self.root / "attempt")
        self.assertEqual(len(rows), 3)
        self.assertEqual(oversized.flagged(rows, 1, 10 ** 9), rows)

    @unittest.skipUnless(importlib.util.find_spec("lancedb"), "lancedb is not installed on this host")
    def test_lance_store_round_trip(self):
        summary, plan, _ = self.plan()
        attempt = self.root / "attempt"
        stats = sib.build(iter(plan), embed, sib.LanceStore(attempt / sri.INDEX_DIR), batch_size=2)
        self.assertEqual(stats["rows"], 3)
        atomic_json(attempt / sri.RESULT, sri.manifest("run-1", inputs_for(), 3, sib.tree_sha256(attempt / sri.INDEX_DIR), []))
        atomic_json(attempt / sri.RECEIPT, {"sidecar_sha256": summary["sidecar_sha256"]})
        hits = sri.query(attempt, "open socket connect host port", limit=2, embedder=embed)   # the real table
        self.assertEqual(len(hits), 2)
        self.assertEqual((hits[0]["file"], hits[0]["symbol"]), ("src/net.py", "open_socket"))
        self.assertEqual(sri.dereference(attempt, self.target, hits[0]), SOURCE["src/net.py"].splitlines())


if __name__ == "__main__":
    unittest.main()
