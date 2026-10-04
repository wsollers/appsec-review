"""04-owasp-participation (ADR-0034): Python plans, budgets and validates; a fake invoker classifies.

No model and no Docker: ``invoke`` is a fake. Covers budget refusal before any call, citation
resolution (out of range, path escape, symlinks), missing/extra/duplicate records, one symbol in two
chapters, model-found functions, determinism and schema validity of every reply and the result.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import random
import sqlite3
import sys
import tempfile
import unittest

PROCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROCESS))

import code_index  # noqa: E402
import owasp_participation as op  # noqa: E402
from execution_state import Blocked, digest  # noqa: E402
from schema_validate import validate_document  # noqa: E402

CONFIG = json.loads((PROCESS / "config" / "owasp-universe" / "default-v1.json").read_text(encoding="utf-8"))
HEX = "0" * 64
SOURCE = {
    "src/io.c": "\n".join(["#include <stdio.h>", "", "FILE *open_input(const char *path)", "{",
                           "  FILE *f = fopen(path, \"r\");", "  return f;", "}", "",
                           "void log_event(const char *text)", "{", "  fprintf(stderr, \"%s\\n\", text);", "}", ""]),
    "src/util.c": "\n".join(["#include <stdlib.h>", "", "int jitter(void)", "{", "  return rand() % 3;", "}", "",
                             "int check_len(int n)", "{", "  return n < 64;", "}", ""]),
}
SPANS = {("src/io.c", "open_input"): (3, 7), ("src/io.c", "log_event"): (9, 12),
         ("src/util.c", "jitter"): (3, 6), ("src/util.c", "check_len"): (8, 11)}


def candidate(chapter: str, file: str, symbol: str) -> dict:
    start, end = SPANS[(file, symbol)]
    sha = hashlib.sha256(SOURCE[file].encode("utf-8")).hexdigest()
    return {"candidate_id": f"cand-{chapter}-" + digest([chapter, file, symbol])[:16], "chapter_id": chapter,
            "symbol": symbol, "file": file, "file_sha256": sha, "language": "c", "start_line": start, "end_line": end,
            "span_source": "treesitter",
            "matches": [{"rule_id": f"{chapter}-fixture", "kind": "calls_to", "file": file, "line": start + 1, "detail": symbol}]}


def classify(role: str = "implements"):
    def reply(cell: dict) -> dict:
        return {"records": [{"candidate_id": row["candidate_id"], "symbol": row["symbol"], "file": row["file"],
                             "start_line": row["start_line"], "end_line": row["end_line"], "role": role,
                             "citations": [{"file": row["file"], "line": row["start_line"] + 1}],
                             "rationale": "fixture classification"} for row in cell["candidates"]]}
    return reply


class Fake:
    """A participation ``invoke`` that records every cell and answers from ``reply``."""

    def __init__(self, reply=None) -> None:
        self.cells, self.reply = [], reply or classify()

    def __call__(self, cell: dict) -> dict:
        self.cells.append(deepcopy(cell))
        return self.reply(cell)


class ParticipationCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "src-root"
        for path, text in SOURCE.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        self.search = {"candidates": [candidate("V5", "src/io.c", "open_input"), candidate("V16", "src/io.c", "log_event"),
                                      candidate("V11", "src/util.c", "jitter"), candidate("V2", "src/util.c", "check_len")]}

    def run_fake(self, reply=None, *, search=None, config=None, index=None):
        fake = Fake(reply)
        result = op.participate(search or self.search, config or CONFIG, invoke=fake, source_root=self.root, index=index)
        return fake, result

    def assert_valid(self, members: dict) -> None:
        document = op.document(members, run_id="participation-fixture", source_snapshot_sha256="sha256:" + HEX,
            candidate_search={"job_id": op.SEARCH_JOB, "attempt_id": "a1", "accepted_pointer_sha256": HEX,
                              "artifact_path": "jobs/04-owasp-candidate-search/attempts/a1/owasp-candidate-search.json",
                              "artifact_sha256": HEX},
            code_index={"job_id": op.INDEX_JOB, "attempt_id": "a1", "accepted_pointer_sha256": HEX,
                        "artifact_path": "jobs/02-code-index/attempts/a1/code-index.json", "artifact_sha256": HEX},
            config={"path": op.CONFIG_PATH, "config_id": CONFIG["config_id"], "version": CONFIG["version"],
                    "config_digest": digest(CONFIG)})
        self.assertEqual(validate_document(document, op.RESULT_SCHEMA), [])

    def by_reason(self, rows: list, key: str = "reason") -> dict:
        found: dict = {}
        for row in rows:
            found.setdefault(row[key], []).append(row)
        return found


class BudgetTests(ParticipationCase):
    def test_over_budget_is_blocked_before_any_call(self):
        config = deepcopy(CONFIG)
        config["participation"]["max_participation_calls"] = 3
        fake = Fake()
        with self.assertRaisesRegex(Blocked, "4 planned participation calls exceed max_participation_calls 3"):
            op.participate(self.search, config, invoke=fake, source_root=self.root)
        self.assertEqual(fake.cells, [])

    def test_cells_split_by_max_candidates_per_cell_and_planned_calls_are_counted(self):
        config = deepcopy(CONFIG)
        config["participation"].update(max_candidates_per_cell=1, max_participation_calls=5)
        search = {"candidates": self.search["candidates"] + [candidate("V5", "src/io.c", "log_event")]}
        fake, result = self.run_fake(search=search, config=config)
        self.assertEqual(result["budget"], {"max_candidates_per_cell": 1, "max_participation_calls": 5,
                                            "planned_calls": 5, "within_budget": True})
        self.assertEqual([cell["cell_id"] for cell in fake.cells],
                         ["asvs-V2-01", "asvs-V5-01", "asvs-V5-02", "asvs-V11-01", "asvs-V16-01"])
        self.assertEqual(len(fake.cells), result["budget"]["planned_calls"])
        self.assertTrue(all(set(cell) == {"cell_id", "chapter_id", "candidates"} for cell in fake.cells))
        self.assert_valid(result)

    def test_invalid_config_and_changed_snapshot_block_before_any_call(self):
        config = deepcopy(CONFIG)
        config["participation"]["max_candidates_per_cell"] = 0
        fake = Fake()
        with self.assertRaises(Blocked):
            op.participate(self.search, config, invoke=fake, source_root=self.root)
        (self.root / "src" / "io.c").write_text(SOURCE["src/io.c"] + "// changed\n", encoding="utf-8")
        with self.assertRaisesRegex(Blocked, "snapshot"):
            op.participate(self.search, CONFIG, invoke=fake, source_root=self.root)
        self.assertEqual(fake.cells, [])

    def test_no_candidates_plans_no_call(self):
        fake, result = self.run_fake(search={"candidates": []})
        self.assertEqual((fake.cells, result["budget"]["planned_calls"], result["records"], result["gaps"]), ([], 0, [], []))
        self.assert_valid(result)


class ValidationTests(ParticipationCase):
    def test_every_candidate_gets_exactly_one_validated_record(self):
        fake, result = self.run_fake()
        self.assertEqual({row["candidate_id"] for row in result["records"]},
                         {row["candidate_id"] for row in self.search["candidates"]})
        self.assertEqual((result["unclassified"], result["rejected_records"], result["gaps"]), ([], [], []))
        record = next(row for row in result["records"] if row["symbol"] == "open_input")
        self.assertEqual((record["cell_id"], record["chapter_id"], record["start_line"], record["end_line"]), ("asvs-V5-01", "V5", 3, 7))
        self.assertEqual(record["citations"], [{"file": "src/io.c", "line": 4,
                                                "file_sha256": hashlib.sha256(SOURCE["src/io.c"].encode()).hexdigest()}])
        for cell in fake.cells:
            self.assertEqual(validate_document(classify()(cell), op.CELL_SCHEMA), [])
        self.assertTrue(all(cell["outcome"] == "accepted" for cell in result["cells"]))
        self.assert_valid(result)

    def test_citations_must_resolve_inside_the_source_root(self):
        outside = self.base / "outside.c"
        outside.write_text("int secret;\n" * 50, encoding="utf-8")
        os.symlink(outside, self.root / "src" / "escape.c")
        os.symlink(self.root / "src" / "io.c", self.root / "src" / "alias.c")
        bad = {"V5": {"file": "src/io.c", "line": 99}, "V16": {"file": "../outside.c", "line": 1},
               "V11": {"file": "src/escape.c", "line": 1}, "V2": {"file": "src/alias.c", "line": 1}}

        def reply(cell):
            value = classify()(cell)
            value["records"][0]["citations"].append(bad[cell["chapter_id"]])
            return value

        _, result = self.run_fake(reply)
        self.assertEqual(result["records"], [])
        self.assertEqual([row["reason"] for row in result["rejected_records"]], ["citation_unresolved"] * 4)
        self.assertEqual({row["reason"] for row in result["unclassified"]}, {"citation_unresolved"})
        self.assertEqual(len(result["unclassified"]), 4)
        self.assertEqual(sorted(gap["chapter_ids"][0] for gap in result["gaps"]), ["V11", "V16", "V2", "V5"])
        self.assertEqual({gap["kind"] for gap in result["gaps"]}, {"unclassified_candidates"})
        self.assert_valid(result)

    def test_an_absolute_or_backslash_path_makes_the_reply_invalid(self):
        def reply(cell):
            value = classify()(cell)
            if cell["chapter_id"] == "V5":
                value["records"][0]["citations"] = [{"file": "/etc/passwd", "line": 1}]
            return value

        _, result = self.run_fake(reply)
        v5 = next(cell for cell in result["cells"] if cell["chapter_id"] == "V5")
        self.assertEqual(v5["outcome"], "invalid_reply")
        self.assertIn({"candidate_id": self.search["candidates"][0]["candidate_id"], "chapter_id": "V5",
                       "cell_id": "asvs-V5-01", "reason": "invalid_reply"}, result["unclassified"])
        self.assertIn("invalid_reply", {gap["kind"] for gap in result["gaps"]})
        self.assert_valid(result)

    def test_missing_extra_unknown_and_duplicate_records(self):
        other = self.search["candidates"][1]["candidate_id"]   # a V16 candidate, not listed in the V5 cell

        def reply(cell):
            value = classify()(cell)
            chapter = cell["chapter_id"]
            if chapter == "V5":
                extra = dict(value["records"][0], candidate_id=other)
                value["records"].append(extra)
                value["records"].append(dict(value["records"][0], candidate_id="cand-V5-" + "f" * 16))
            elif chapter == "V16":
                value["records"] = []
            elif chapter == "V11":
                value["records"].append(deepcopy(value["records"][0]))    # identical duplicate: one kept
            elif chapter == "V2":
                value["records"].append(dict(value["records"][0], role="not_participating"))   # conflicting
            return value

        _, result = self.run_fake(reply)
        rejected = self.by_reason(result["rejected_records"])
        self.assertEqual([(row["cell_id"], row["record_index"]) for row in rejected["unknown_candidate"]],
                         [("asvs-V5-01", 1), ("asvs-V5-01", 2)])
        self.assertEqual([(row["cell_id"], row["record_index"]) for row in rejected["duplicate_record"]],
                         [("asvs-V2-01", 0), ("asvs-V2-01", 1), ("asvs-V11-01", 1)])
        unclassified = {(row["chapter_id"], row["reason"]) for row in result["unclassified"]}
        self.assertEqual(unclassified, {("V16", "missing_record"), ("V2", "duplicate_record")})
        self.assertEqual(sorted(row["chapter_id"] for row in result["records"]), ["V11", "V5"])
        self.assertEqual({(gap["kind"], gap["chapter_ids"][0]) for gap in result["gaps"]},
                         {("unclassified_candidates", "V16"), ("unclassified_candidates", "V2")})
        self.assert_valid(result)

    def test_span_outside_the_candidate_function_is_rejected(self):
        def reply(cell):
            value = classify()(cell)
            if cell["chapter_id"] == "V5":
                value["records"][0].update(start_line=9, end_line=12)
            if cell["chapter_id"] == "V16":
                value["records"][0]["file"] = "src/util.c"
            return value

        _, result = self.run_fake(reply)
        self.assertEqual([row["reason"] for row in result["rejected_records"]], ["span_mismatch", "span_mismatch"])
        self.assertEqual({row["reason"] for row in result["unclassified"]}, {"span_mismatch"})

    def test_failed_cell_is_a_gap_never_not_participating(self):
        def reply(cell):
            if cell["chapter_id"] == "V11":
                raise op.CellFailed("dispatch failed")
            return classify()(cell)

        fake, result = self.run_fake(reply)
        self.assertEqual(len(fake.cells), 4)   # the other cells still ran
        v11 = next(cell for cell in result["cells"] if cell["chapter_id"] == "V11")
        self.assertEqual((v11["outcome"], v11["reply_sha256"]), ("failed", None))
        self.assertEqual([(row["chapter_id"], row["reason"]) for row in result["unclassified"]], [("V11", "cell_failed")])
        self.assertEqual([(gap["kind"], gap["chapter_ids"]) for gap in result["gaps"]], [("cell_failed", ["V11"])])
        self.assertNotIn("V11", {row["chapter_id"] for row in result["records"]})
        self.assert_valid(result)

    def test_not_participating_is_recorded_not_routed(self):
        _, result = self.run_fake(classify("not_participating"))
        self.assertEqual({row["role"] for row in result["records"]}, {"not_participating"})
        self.assertEqual(len(result["records"]), 4)
        self.assertNotIn("decision", json.dumps(result))
        self.assert_valid(result)


class ChapterAndDiscoveryTests(ParticipationCase):
    def test_one_symbol_in_two_chapters_is_classified_in_each_cell(self):
        search = {"candidates": [candidate("V5", "src/io.c", "open_input"), candidate("V12", "src/io.c", "open_input")]}
        fake, result = self.run_fake(search=search)
        self.assertEqual([(cell["chapter_id"], [row["symbol"] for row in cell["candidates"]]) for cell in fake.cells],
                         [("V5", ["open_input"]), ("V12", ["open_input"])])
        self.assertEqual([(row["chapter_id"], row["symbol"], row["file"]) for row in result["records"]],
                         [("V5", "open_input", "src/io.c"), ("V12", "open_input", "src/io.c")])
        self.assert_valid(result)

    def test_widening_candidates_from_unparsed_languages_are_cells_like_any_other(self):
        """P1 widening hits: match kinds fts/semantic/tag_cloud, rule_id null, a free language (kotlin)."""
        text = "package app\n\nfun store(prefs: Prefs) {\n  prefs.putString(\"token\", token)\n}\n"
        (self.root / "app").mkdir()
        (self.root / "app" / "Store.kt").write_text(text, encoding="utf-8")
        row = {"candidate_id": "cand-V14-" + "a" * 16, "chapter_id": "V14", "symbol": "<module>", "file": "app/Store.kt",
               "file_sha256": "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(), "language": "kotlin",
               "start_line": 4, "end_line": 4, "span_source": "module-scope",
               "matches": [{"rule_id": None, "kind": "semantic", "file": "app/Store.kt", "line": 4, "detail": "token storage"},
                           {"rule_id": None, "kind": "tag_cloud", "file": "app/Store.kt", "line": 4, "detail": ""},
                           {"rule_id": "V14-fixture", "kind": "fts", "file": "app/Store.kt", "line": 4, "detail": "putString"}]}

        def reply(cell):
            return {"records": [{"candidate_id": row["candidate_id"], "symbol": "store", "file": "app/Store.kt",
                                 "start_line": 3, "end_line": 5, "role": "implements",
                                 "citations": [{"file": "app/Store.kt", "line": 4}], "rationale": "stores a token"}]}

        fake, result = self.run_fake(reply, search={"candidates": [row]})
        self.assertEqual(fake.cells[0]["candidates"][0]["language"], "kotlin")
        self.assertEqual([m["kind"] for m in fake.cells[0]["candidates"][0]["matches"]], ["semantic", "tag_cloud", "fts"])
        self.assertEqual([(r["candidate_id"], r["symbol"], r["start_line"], r["end_line"]) for r in result["records"]],
                         [(row["candidate_id"], "<module>", 4, 4)])
        self.assert_valid(result)

    def index(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        connection.executescript(code_index.DDL)
        for (path, name), (start, end) in sorted(SPANS.items()):
            connection.execute("INSERT INTO ts_functions VALUES(?,?,?,?,?,?)", (path, name, "function_definition", start, end, "c"))
        return connection

    def test_model_found_function_needs_the_code_index(self):
        def reply(cell):
            value = classify()(cell)
            if cell["chapter_id"] == "V16":
                value["records"].append({"candidate_id": None, "symbol": "open_input", "file": "src/io.c", "start_line": 5,
                                         "end_line": 5, "role": "consumes", "citations": [{"file": "src/io.c", "line": 5}],
                                         "rationale": "opens the input it later logs about"})
                value["records"].append({"candidate_id": None, "symbol": "nowhere", "file": "src/io.c", "start_line": 1,
                                         "end_line": 1, "role": "consumes", "citations": [{"file": "src/io.c", "line": 1}],
                                         "rationale": "not a function"})
            return value

        _, without = self.run_fake(reply)
        self.assertEqual([row["reason"] for row in without["rejected_records"]], ["symbol_not_indexed", "symbol_not_indexed"])
        _, found = self.run_fake(reply, index=self.index())
        added = [row for row in found["records"] if row["candidate_id"] is None]
        self.assertEqual([(row["chapter_id"], row["symbol"], row["start_line"], row["end_line"], row["role"]) for row in added],
                         [("V16", "open_input", 3, 7, "consumes")])
        self.assertEqual([(row["record_index"], row["reason"]) for row in found["rejected_records"]], [(2, "symbol_not_indexed")])
        self.assertEqual(found["unclassified"], [])
        self.assert_valid(found)

    def test_result_is_deterministic_and_independent_of_input_order(self):
        _, first = self.run_fake()
        shuffled = deepcopy(self.search)
        random.Random(7).shuffle(shuffled["candidates"])
        _, second = self.run_fake(search=shuffled)
        self.assertEqual(first, second)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(self.run_fake()[1], sort_keys=True))
        self.assertEqual([cell["cell_id"] for cell in first["cells"]], ["asvs-V2-01", "asvs-V5-01", "asvs-V11-01", "asvs-V16-01"])


class RegistryAndInvokerTests(unittest.TestCase):
    def test_cell_composition_grants_read_only_code_query_tools(self):
        import code_query_mcp
        import persona_dispatch
        import persona_invocation
        import persona_prompt_assembly
        from schema_validate import SchemaStore
        store = SchemaStore()
        template = persona_prompt_assembly.load_job_template(op.CELL_TEMPLATE, store)
        self.assertEqual(template["composition"]["persona_id"], "owasp-validator")
        self.assertEqual(template["composition"]["role_id"], "asvs-participation-classifier")
        composition = persona_dispatch._composition_block(op.CELL_TEMPLATE, template, store)
        records = persona_invocation.load_composition(persona_invocation.REGISTRY_DIR, composition, store)
        self.assertEqual(persona_invocation.claim_ceiling(records["role"], records["tooling_profile"])["allowed"], ("candidate_only",))
        profile = records["tooling_profile"]
        hunt = json.loads((PROCESS / "pipeline" / "tooling-profiles" / "hypothesis-hunt-static.json").read_text(encoding="utf-8"))
        self.assertEqual(code_query_mcp.profile_tools(profile), code_query_mcp.profile_tools(hunt))
        self.assertTrue(all("mutate" not in action and "execute" not in action for action in profile["allowed_actions"]))
        contract = records["output_contract"]
        self.assertEqual(contract["result_schema"], {"artifact": op.CELL_FILE, "schema_file": op.CELL_SCHEMA})
        text, _ = persona_prompt_assembly.assemble_prompt_text(op.CELL_TEMPLATE, store)
        self.assertIn("ASVS Participation Classifier Cell", text)

    def test_coverage_errors_feed_the_repair_loop(self):
        value = {"records": [{"candidate_id": "a"}, {"candidate_id": "a"}, {"candidate_id": "z"}, {"candidate_id": None}]}
        self.assertEqual(op.coverage_errors(value, ["a", "b"]),
                         ["candidate b has no record", "candidate a has 2 records; write exactly one",
                          "candidate_id z is not listed in this cell"])

    def test_replay_turns_retained_replies_into_invoke(self):
        invoke = op.replay({"asvs-V5-01": b'{"records": []}', "asvs-V2-01": b"not json"})
        self.assertEqual(invoke({"cell_id": "asvs-V5-01"}), {"records": []})
        self.assertIsNone(invoke({"cell_id": "asvs-V2-01"}))
        with self.assertRaises(op.CellFailed):
            invoke({"cell_id": "asvs-V9-01"})

    def test_parallelism_is_bounded_by_the_persona_pool(self):
        import tunables
        slots = tunables.shared("pool_persona_llm_slots")
        self.assertEqual(op.max_parallel(1), 1)
        self.assertEqual(op.max_parallel(1000), slots)


if __name__ == "__main__":
    unittest.main()
