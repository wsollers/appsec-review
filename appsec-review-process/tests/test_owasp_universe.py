"""04-owasp-universe (ADR-0034): per-chapter decisions, bundles, the validator budget and the chain it feeds.

``UniverseRun`` is the shared fixture of the OWASP chain tests: a C source tree, its accepted
candidate search and participation (synthetic, schema-valid publications), the published universe
and, on request, T03 admission.
"""
from __future__ import annotations

from collections import Counter
import contextlib
from copy import deepcopy
import hashlib
import io
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest

PROCESS = Path(__file__).resolve().parents[1]
ROOT = PROCESS.parent
sys.path.insert(0, str(PROCESS))

import execution_state  # noqa: E402
from execution_state import Blocked, digest  # noqa: E402
import owasp_universe as universe_mod  # noqa: E402
from schema_validate import validate_document  # noqa: E402

CHAPTERS = [f"V{n}" for n in range(1, 18)]
PER_CHAPTER = {"V1": 27, "V2": 11, "V3": 19, "V4": 10, "V5": 9, "V6": 35, "V7": 18, "V8": 7, "V9": 7,
               "V10": 29, "V11": 14, "V12": 9, "V13": 13, "V14": 9, "V15": 13, "V16": 16, "V17": 7}
SNAPSHOT = "sha256:" + "1" * 64
HEX = "0" * 64
CONFIG = json.loads((PROCESS / "config/owasp-universe/default-v1.json").read_text())
BATCH = json.loads((PROCESS / "config/owasp-batching/default-v2.json").read_text())
BATCH_PATH = "appsec-review-process/config/owasp-batching/default-v2.json"
CONFIG_PATH = "appsec-review-process/config/owasp-universe/default-v1.json"

HELLO = {
    "src/hello.c": "\n".join([
        "#include <stdio.h>",                                  # 1
        "#include <string.h>",                                 # 2
        "",                                                    # 3
        "static void log_message(const char *text)",           # 4
        "{",                                                   # 5
        "  fprintf(stderr, \"hello: %s\\n\", text);",          # 6
        "}",                                                   # 7
        "",                                                    # 8
        "static FILE *open_input(const char *path)",           # 9
        "{",                                                   # 10
        "  FILE *stream = fopen(path, \"r\");",                # 11
        "  if (!stream)",                                      # 12
        "    log_message(\"cannot open input\");",             # 13
        "  return stream;",                                    # 14
        "}",                                                   # 15
        "",                                                    # 16
        "int main(int argc, char **argv)",                     # 17
        "{",                                                   # 18
        "  char name[64];",                                    # 19
        "  FILE *input = open_input(argv[1]);",                # 20
        "  strncpy(name, argv[argc - 1], sizeof name - 1);",   # 21
        "  printf(\"Hello, %s\\n\", name);",                   # 22
        "  return input ? 0 : 1;",                             # 23
        "}",                                                   # 24
        ""]),
    "src/util.c": "\n".join([
        "#include <stdlib.h>",                                 # 1
        "",                                                    # 2
        "int util_jitter(void)",                               # 3
        "{",                                                   # 4
        "  return rand() % 3;",                                # 5
        "}",                                                   # 6
        ""]),
}
# (chapter, symbol, file, start, end): what a hello-world-like candidate search finds
HELLO_CANDIDATES = [
    ("V1", "main", "src/hello.c", 17, 24),
    ("V2", "main", "src/hello.c", 17, 24),
    ("V5", "open_input", "src/hello.c", 9, 15),
    ("V16", "log_message", "src/hello.c", 4, 7),
    ("V16", "open_input", "src/hello.c", 9, 15),
]


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_tree(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def candidate_id(chapter: str, file: str, symbol: str) -> str:
    return f"cand-{chapter}-" + digest([chapter, file, symbol])[:16]


def search_members(files: dict[str, str], candidates, *, incomplete=()) -> dict:
    """Schema-valid candidate-search members for ``candidates`` [(chapter, symbol, file, start, end)]."""
    hashes = {path: hashlib.sha256(text.encode("utf-8")).hexdigest() for path, text in files.items()}
    rows = [{"candidate_id": candidate_id(chapter, file, symbol), "chapter_id": chapter, "symbol": symbol,
             "file": file, "file_sha256": hashes[file], "language": "c", "start_line": start, "end_line": end,
             "span_source": "treesitter",
             "matches": [{"rule_id": f"{chapter}-fixture", "kind": "calls_to", "file": file, "line": start + 1,
                          "detail": "fixture"}]}
            for chapter, symbol, file, start, end in candidates]
    rows.sort(key=lambda row: (CHAPTERS.index(row["chapter_id"]), row["file"], row["start_line"], row["symbol"]))
    counts = Counter(row["chapter_id"] for row in rows)
    complete = not incomplete
    return {
        "coverage": {"complete": complete, "searched_languages": ["c"],
                     "unsearched_languages": [] if complete else [{"language": "kotlin", "file_count": 3, "reason": "no_grammar"}],
                     "sast_available": True},
        "chapters": [{"chapter_id": chapter, "candidate_count": counts[chapter], "excluded_count": 0,
                      "coverage_complete": chapter not in incomplete,
                      "search_basis": [{"rule_id": f"{chapter}-fixture", "kind": "calls_to", "hits": counts[chapter]}]}
                     for chapter in CHAPTERS],
        "candidates": rows, "excluded": [],
        "gaps": [] if complete else [{"gap_id": "gap-" + "a" * 20, "kind": "language_not_searched",
                                      "chapter_ids": sorted(incomplete, key=CHAPTERS.index),
                                      "statement": "Kotlin sources are not searched."}],
    }


def participation_members(search: dict, roles=None, *, unclassified=(), missing=()) -> dict:
    """Validated participation: every candidate gets ``roles.get(id, 'implements')`` unless listed otherwise."""
    roles = roles or {}
    records, rows, cells = [], [], {}
    for row in search["candidates"]:
        cell_id = f"asvs-{row['chapter_id']}-01"
        cells.setdefault(cell_id, {"cell_id": cell_id, "chapter_id": row["chapter_id"], "candidate_ids": [],
                                   "outcome": "accepted", "reply_sha256": HEX})["candidate_ids"].append(row["candidate_id"])
        if row["candidate_id"] in unclassified:
            rows.append({"candidate_id": row["candidate_id"], "chapter_id": row["chapter_id"], "cell_id": cell_id,
                         "reason": "missing_record"})
            continue
        if row["candidate_id"] in missing:
            continue
        records.append({"cell_id": cell_id, "chapter_id": row["chapter_id"], "candidate_id": row["candidate_id"],
                        "symbol": row["symbol"], "file": row["file"], "file_sha256": row["file_sha256"],
                        "start_line": row["start_line"], "end_line": row["end_line"],
                        "role": roles.get(row["candidate_id"], "implements"),
                        "citations": [{"file": row["file"], "line": row["start_line"] + 1,
                                       "file_sha256": row["file_sha256"]}],
                        "rationale": "fixture classification"})
    planned = sum(math.ceil(len(cell["candidate_ids"]) / 40) for cell in cells.values())
    gaps = []
    if rows:
        gaps.append({"gap_id": "gap-" + "b" * 20, "kind": "unclassified_candidates",
                     "chapter_ids": sorted({row["chapter_id"] for row in rows}, key=CHAPTERS.index),
                     "statement": "fixture unclassified"})
    return {"budget": {"max_candidates_per_cell": 40, "max_participation_calls": 34, "planned_calls": planned,
                       "within_budget": True},
            "cells": list(cells.values()), "records": records, "unclassified": rows, "rejected_records": [],
            "gaps": gaps}


def build(root: Path, files, candidates, *, roles=None, config=None, participation=True, incomplete=(),
          unclassified=(), missing=(), mobile=False):
    search = search_members(files, candidates, incomplete=incomplete)
    part = participation_members(search, roles, unclassified=unclassified, missing=missing) if participation else None
    universe, bundles = universe_mod.build(
        search, part, control_rows=universe_mod.chapter_control_rows(), config=config or CONFIG,
        batch_config=BATCH, batch_config_path=BATCH_PATH, source_root=root, mobile_platform=mobile)
    return search, part, universe, bundles


def universe_document(universe: dict) -> dict:
    binding = {"job_id": "04-owasp-candidate-search", "attempt_id": "a1", "accepted_pointer_sha256": HEX,
               "artifact_path": "jobs/x/attempts/a1/out.json", "artifact_sha256": HEX}
    return {"schema": "appsec-review/owasp-universe/1.0", "run_id": "fixture", "job_id": "04-owasp-universe",
            "source_snapshot_sha256": SNAPSHOT,
            "inputs": {"candidate_search": binding, "participation": dict(binding, job_id="04-owasp-participation"),
                       "asvs_reference": universe_mod.asvs_reference()},
            "config": {"path": CONFIG_PATH, "config_id": CONFIG["config_id"], "version": CONFIG["version"],
                       "config_digest": digest(CONFIG)}, **universe}


class UniverseRun:
    """Publish the ADR-0034 inputs of a run (under the caller's ``execution_state.RUNS``) and its universe."""

    def __init__(self, case: unittest.TestCase, run_id: str, files=None, candidates=None, *, roles=None,
                 incomplete=()) -> None:
        self.case, self.run_id = case, run_id
        temporary = tempfile.TemporaryDirectory()
        case.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.run = execution_state.RUNS / run_id
        self.data = self.run / "data"
        if not (self.run / "run-status.json").is_file():
            write_json(self.run / "run-status.json", {"run_id": run_id, "status": "READY"})
        self.files = dict(HELLO if files is None else files)
        self.source = self.base / "source"
        write_tree(self.source, self.files)
        write_json(self.run / "inputs" / "artifact-manifest.json", {"target": {"repo_path": str(self.source)}})
        self.search = {"schema": "appsec-review/owasp-candidate-search/1.0", "run_id": run_id,
                       "job_id": "04-owasp-candidate-search", "source_snapshot_sha256": SNAPSHOT,
                       "status": "OK", "rule_table": {"path": "data/owasp-asvs/category-rules-v1.json",
                                                      "rules_id": "owasp-asvs-category-rules", "version": "1.0.0",
                                                      "sha256": HEX},
                       "inputs": [{"job_id": job, "required": True, "accepted": True, "attempt_id": "a1",
                                   "artifact_path": f"jobs/{job}/attempts/a1/out.json", "artifact_sha256": HEX}
                                  for job in ("02-code-index", "02-code-property-graph", "02-treesitter-ast")],
                       **search_members(self.files, HELLO_CANDIDATES if candidates is None else candidates,
                                        incomplete=incomplete)}
        self.search["status"] = "OK_WITH_GAPS" if self.search["gaps"] else "OK"
        self.search_binding = self._publish(universe_mod.CANDIDATE_JOB, universe_mod.CANDIDATE_ARTIFACT, self.search,
                                            "owasp-candidate-search.schema.json")
        members = participation_members(self.search, roles)
        self.participation = {"schema": "appsec-review/owasp-participation/1.0", "run_id": run_id,
                              "job_id": "04-owasp-participation", "source_snapshot_sha256": SNAPSHOT,
                              "status": "OK_WITH_GAPS" if members["gaps"] else "OK",
                              "candidate_search": self.search_binding,
                              "code_index": dict(self.search_binding, job_id="02-code-index"),
                              "config": {"path": CONFIG_PATH, "config_id": CONFIG["config_id"],
                                         "version": CONFIG["version"], "config_digest": digest(CONFIG)},
                              **members}
        self._publish(universe_mod.PARTICIPATION_JOB, universe_mod.PARTICIPATION_ARTIFACT, self.participation,
                      "owasp-participation.schema.json")

    def _publish(self, job: str, name: str, value: dict, schema: str) -> dict:
        self.case.assertEqual(validate_document(value, schema), [])
        base = self.data / "jobs" / job / "whole"
        path = base / "attempts" / "a1" / "outputs" / name
        write_json(path, value)
        write_json(base / "accepted.json", {"status": value["status"], "run_id": self.run_id, "job_id": job,
                                            "attempt_id": "a1", "artifacts": {f"outputs/{name}": sha(path)}})
        write_json(base / "latest.json", {"attempt_id": "a1"})
        return {"job_id": job, "attempt_id": "a1", "accepted_pointer_sha256": sha(base / "accepted.json"),
                "artifact_path": path.relative_to(self.data).as_posix(), "artifact_sha256": sha(path)}

    def publish(self, **options) -> dict:
        return universe_mod.run(self.run_id, "fixture", **options)

    def universe(self) -> dict:
        return universe_mod.accepted(self.run_id)[0]


class ChapterControlRowsTests(unittest.TestCase):
    def test_pinned_snapshot_gives_the_per_chapter_l1_l2_counts(self):
        rows = universe_mod.chapter_control_rows()
        self.assertEqual(rows, PER_CHAPTER)
        self.assertEqual(sum(rows.values()), 253)
        self.assertEqual(max(rows.values()), 35)


class UniverseBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        write_tree(self.root, HELLO)

    @staticmethod
    def target(universe: dict, chapter: str) -> dict:
        return next(row for row in universe["targets"] if row["chapter_id"] == chapter)

    def test_hello_world_like_target_plans_a_small_bounded_number_of_calls(self):
        _search, _part, universe, bundles = build(self.root, HELLO, HELLO_CANDIDATES)
        participating = [row["chapter_id"] for row in universe["targets"] if row["decision"] == "participating"]
        self.assertEqual(participating, ["V1", "V2", "V5", "V16"])
        self.assertEqual(sorted(bundles, key=CHAPTERS.index), participating)
        self.assertEqual(universe["budget"]["planned_validator_calls"], 4)
        self.assertEqual([(row["chapter_id"], row["planned_calls"]) for row in universe["budget"]["per_chapter"]],
                         [("V1", 1), ("V2", 1), ("V5", 1), ("V16", 1)])
        self.assertEqual(sum(row["planned_validator_calls"] for row in universe["targets"]), 4)
        self.assertTrue(universe["budget"]["within_budget"])
        self.assertEqual(universe["status"], "OK")
        self.assertEqual([row["target_id"] for row in universe["targets"]], [f"asvs-{c}" for c in CHAPTERS])
        self.assertEqual((self.target(universe, "V3")["decision"], self.target(universe, "V3")["reason_code"]),
                         ("not_applicable", "no_candidates_complete_coverage"))
        masvs = next(row for row in universe["families"] if row["family"] == "owasp_masvs")
        self.assertEqual((masvs["decision"], masvs["reason_code"]), ("not_applicable", "no_mobile_platform"))
        self.assertEqual(validate_document(universe_document(universe), "owasp-universe.schema.json"), [])

    def test_all_chapters_participating_stays_within_the_twenty_call_budget(self):
        candidates = [(chapter, "main", "src/hello.c", 17, 24) for chapter in CHAPTERS]
        _search, _part, universe, bundles = build(self.root, HELLO, candidates)
        rows = BATCH["limits"]["max_control_target_rows"]
        expected = sum(math.ceil(PER_CHAPTER[chapter] / rows) for chapter in CHAPTERS)
        self.assertEqual(expected, 17)
        self.assertEqual(universe["budget"]["planned_validator_calls"], expected)
        self.assertLessEqual(expected, CONFIG["validation"]["max_validator_calls"])
        self.assertEqual(universe["status"], "OK")
        self.assertEqual(len(bundles), 17)

    def test_over_budget_is_blocked_with_the_plan_recorded(self):
        config = deepcopy(CONFIG)
        config["validation"]["max_validator_calls"] = 3
        _search, _part, universe, _bundles = build(self.root, HELLO, HELLO_CANDIDATES, config=config)
        self.assertEqual(universe["status"], "BLOCKED")
        self.assertFalse(universe["budget"]["within_budget"])
        self.assertEqual(universe["budget"]["planned_validator_calls"], 4)
        gap = next(row for row in universe["gaps"] if row["kind"] == "budget_exceeded")
        self.assertEqual(gap["chapter_ids"], ["V1", "V2", "V5", "V16"])
        self.assertEqual(validate_document(universe_document(universe), "owasp-universe.schema.json"), [])

    def test_not_applicable_only_for_zero_candidates_under_complete_coverage_or_all_not_participating(self):
        jitter = candidate_id("V11", "src/util.c", "util_jitter")
        candidates = [*HELLO_CANDIDATES, ("V11", "util_jitter", "src/util.c", 3, 6)]
        _s, _p, universe, bundles = build(self.root, HELLO, candidates, roles={jitter: "not_participating"})
        v11 = self.target(universe, "V11")
        self.assertEqual((v11["decision"], v11["reason_code"], v11["planned_validator_calls"]),
                         ("not_applicable", "all_candidates_not_participating", 0))
        self.assertEqual([(row["chapter_id"], row["candidate_id"]) for row in universe["excluded"]], [("V11", jitter)])
        self.assertNotIn("V11", bundles)

        # incomplete coverage: zero candidates is a gap, never N/A
        _s, _p, universe, _b = build(self.root, HELLO, HELLO_CANDIDATES, incomplete=("V3",))
        self.assertEqual((self.target(universe, "V3")["decision"], self.target(universe, "V3")["reason_code"]),
                         ("gap", "coverage_incomplete"))
        self.assertEqual(self.target(universe, "V4")["decision"], "not_applicable")
        self.assertIn("coverage_incomplete", {row["kind"] for row in universe["gaps"]})
        self.assertEqual(universe["status"], "OK_WITH_GAPS")

        # candidates without an accepted participation classification
        _s, _p, universe, bundles = build(self.root, HELLO, HELLO_CANDIDATES, participation=False)
        self.assertEqual({row["reason_code"] for row in universe["targets"] if row["candidate_count"]},
                         {"participation_unavailable"})
        self.assertEqual((bundles, universe["budget"]["planned_validator_calls"]), ({}, 0))

        # an unclassified candidate, or one silently missing its record, is a gap
        open_v5 = candidate_id("V5", "src/hello.c", "open_input")
        _s, _p, universe, _b = build(self.root, HELLO, HELLO_CANDIDATES, unclassified=(open_v5,))
        self.assertEqual(self.target(universe, "V5")["reason_code"], "unclassified_candidates")
        _s, _p, universe, _b = build(self.root, HELLO, candidates, roles={jitter: "not_participating"},
                                     missing=(jitter,))
        self.assertEqual((self.target(universe, "V11")["decision"], self.target(universe, "V11")["reason_code"]),
                         ("gap", "unclassified_candidates"))
        for value in (universe,):
            self.assertEqual(validate_document(universe_document(value), "owasp-universe.schema.json"), [])

    def test_mobile_platform_makes_masvs_a_gap_not_not_applicable(self):
        _s, _p, universe, _b = build(self.root, HELLO, HELLO_CANDIDATES, mobile=True)
        masvs = next(row for row in universe["families"] if row["family"] == "owasp_masvs")
        self.assertEqual((masvs["decision"], masvs["reason_code"]), ("gap", "mobile_platform_present"))
        (self.root / "app" / "src" / "main").mkdir(parents=True)
        self.assertFalse(universe_mod.mobile_platform(self.root))
        (self.root / "app" / "src" / "main" / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
        self.assertTrue(universe_mod.mobile_platform(self.root))

    def test_a_symbol_in_several_chapters_is_in_each_bundle_and_rolled_up_to_files(self):
        _s, _p, universe, bundles = build(self.root, HELLO, HELLO_CANDIDATES)
        lines = HELLO["src/hello.c"].splitlines()
        for chapter in ("V5", "V16"):
            target = self.target(universe, chapter)
            self.assertIn("open_input", {row["symbol"] for row in target["participants"]})
            excerpt = next(row for row in bundles[chapter]["excerpts"] if row["symbol"] == "open_input")
            self.assertEqual(excerpt["text"], "\n".join(lines[8:15]))
        v16 = self.target(universe, "V16")
        self.assertEqual(v16["files"], [{"path": "src/hello.c", "sha256": sha(self.root / "src/hello.c"),
                                         "participant_count": 2}])
        self.assertEqual(v16["evidence_bundle"]["excerpt_count"], 2)
        # one symbol found by two candidates of a chapter (or model-found) merges into one participant
        search = search_members(HELLO, HELLO_CANDIDATES)
        part = participation_members(search)
        extra = deepcopy(next(row for row in part["records"] if row["chapter_id"] == "V16" and row["symbol"] == "log_message"))
        extra.update(candidate_id=None, role="enforces")
        part["records"].append(extra)
        universe, _bundles = universe_mod.build(
            search, part, control_rows=universe_mod.chapter_control_rows(), config=CONFIG, batch_config=BATCH,
            batch_config_path=BATCH_PATH, source_root=self.root)
        merged = next(row for row in self.target(universe, "V16")["participants"] if row["symbol"] == "log_message")
        self.assertEqual((merged["roles"], len(merged["candidate_ids"])), (["implements", "enforces"], 1))

    def test_bundles_are_hash_bound_to_the_snapshot(self):
        _s, _p, universe, bundles = build(self.root, HELLO, HELLO_CANDIDATES)
        for chapter, bundle in bundles.items():
            self.assertEqual(self.target(universe, chapter)["evidence_bundle"]["sha256"], digest(bundle))
            for row in bundle["excerpts"]:
                self.assertEqual(row["text_sha256"], hashlib.sha256(row["text"].encode("utf-8")).hexdigest())
                self.assertEqual(row["file_sha256"], sha(self.root / row["file"]))
            document = {"schema": "appsec-review/owasp-participants-bundle/1.0", "run_id": "fixture",
                        "input_id": f"asvs-participants-{chapter}", "chapter_id": chapter,
                        "source_snapshot_sha256": SNAPSHOT, **bundle}
            self.assertEqual(validate_document(document, "owasp-participants-bundle.schema.json"), [])
            universe_mod.verify_bundle(document, self.root)
        forged = deepcopy(bundles["V5"])
        forged["excerpts"][0]["text"] += "\n  system(path);"
        with self.assertRaisesRegex(Blocked, "does not match the source snapshot"):
            universe_mod.verify_bundle(forged, self.root)
        (self.root / "src/hello.c").write_text(HELLO["src/hello.c"] + "\n/* edited */\n", encoding="utf-8")
        with self.assertRaisesRegex(Blocked, "changed since candidate search"):
            universe_mod.verify_bundle(bundles["V5"], self.root)
        with self.assertRaisesRegex(Blocked, "changed since candidate search"):
            build(self.root, HELLO, HELLO_CANDIDATES)

    def test_long_participants_are_cut_and_recorded_as_a_gap(self):
        config = deepcopy(CONFIG)
        config["evidence_bundle"]["max_excerpt_lines"] = 3
        _s, _p, universe, bundles = build(self.root, HELLO, HELLO_CANDIDATES, config=config)
        self.assertTrue(all(row["end_line"] - row["start_line"] < 3 for b in bundles.values() for row in b["excerpts"]))
        self.assertIn({"symbol": "main", "file": "src/hello.c", "reason": "max_excerpt_lines"}, bundles["V1"]["truncated"])
        self.assertIn("bundle_truncated", {row["kind"] for row in universe["gaps"]})


def isolated_runs(case: unittest.TestCase) -> Path:
    temporary = tempfile.TemporaryDirectory()
    case.addCleanup(temporary.cleanup)
    case.addCleanup(setattr, execution_state, "RUNS", execution_state.RUNS)
    execution_state.RUNS = Path(temporary.name) / "runs"
    return execution_state.RUNS


class UniversePublicationTests(unittest.TestCase):
    def setUp(self):
        isolated_runs(self)

    def test_run_publishes_an_accepted_universe_and_its_bundles(self):
        fixture = UniverseRun(self, "universe-publication")
        pointer = fixture.publish()
        self.assertEqual((pointer["status"], pointer["planned_validator_calls"]), ("OK", 4))
        universe, binding = universe_mod.accepted(fixture.run_id)
        self.assertEqual(binding["planned_validator_calls"], 4)
        attempt = fixture.data / "jobs" / universe_mod.JOB / "whole" / "attempts" / pointer["attempt_id"]
        for target in universe["targets"]:
            if target["evidence_bundle"]:
                self.assertEqual(sha(attempt / target["evidence_bundle"]["path"]), target["evidence_bundle"]["sha256"])
        self.assertTrue(fixture.publish()["reused"])

    def test_over_budget_universe_is_written_blocked_and_never_accepted(self):
        fixture = UniverseRun(self, "universe-blocked")
        config = deepcopy(CONFIG)
        config["validation"]["max_validator_calls"] = 2
        original = universe_mod._config

        def tight():
            _config, batch, reference = original()
            return config, batch, dict(reference, config_digest=digest(config))
        universe_mod._config = tight
        self.addCleanup(setattr, universe_mod, "_config", original)
        with self.assertRaisesRegex(Blocked, "exceed max_validator_calls 2"):
            fixture.publish()
        pointer = json.loads((fixture.data / "jobs" / universe_mod.JOB / "whole" / "accepted.json").read_text())
        self.assertEqual(pointer["status"], "BLOCKED")
        written = json.loads((fixture.data / "jobs" / universe_mod.JOB / "whole" / "attempts" / pointer["attempt_id"] /
                              universe_mod.UNIVERSE).read_text())
        self.assertEqual(validate_document(written, "owasp-universe.schema.json"), [])
        with self.assertRaisesRegex(Blocked, "universe"):
            universe_mod.accepted(fixture.run_id)

    def test_cli_reports_blocked_without_accepted_inputs(self):
        fixture = UniverseRun(self, "universe-cli")
        (fixture.data / "jobs" / universe_mod.CANDIDATE_JOB / "whole" / "accepted.json").unlink()
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(universe_mod.main(["--run-id", fixture.run_id]), 2)
        self.assertIn("OWASP_UNIVERSE_BLOCKED", stderr.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
