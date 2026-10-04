"""ADR-0034 guard tests: inference classifies, Python routes the OWASP universe.

Frozen wave-0 contracts (schemas/owasp-*.schema.json, data/owasp-asvs/category-rules-v1.json,
config/owasp-universe/default-v1.json, config/owasp-batching/default-v2.json) and the module APIs
wave 1 implements:

* ``owasp_candidate_search.search(index, rules, *, sast_hits, treesitter_gaps) -> dict`` with the
  candidate-search members ``coverage, chapters, candidates, excluded, gaps``. ``index`` is an open
  code-index SQLite connection; ``sast_hits`` the accepted 02-source-sast hits
  (``rule_id, path, start_line``) or None when SAST was not accepted; ``treesitter_gaps`` the
  accepted 02-treesitter-ast ``gaps``.
* ``owasp_participation.participate(candidate_search, config, *, invoke, source_root) -> dict`` with
  ``budget, cells, records, unclassified, rejected_records, gaps``. ``invoke(cell)`` gets
  ``{cell_id, chapter_id, candidates}`` and returns an owasp-participation-cell reply; an exceeded
  participation budget raises ``Blocked`` before the first call.
* ``owasp_universe.chapter_control_rows(reference_root=None) -> {chapter_id: l1_l2_rows}`` and
  ``owasp_universe.build(candidate_search, participation, *, control_rows, config, batch_config,
  batch_config_path, source_root, mobile_platform=False) -> (universe, bundles)`` with the universe
  members ``status, families, targets, excluded, budget, gaps`` and ``bundles`` =
  ``{chapter_id: {"excerpts": [...], "truncated": [...]}}`` for participating chapters only.
* ``owasp_workbench_lifecycle.run_dispatch`` refuses (``Blocked``) without an accepted, within-budget
  04-owasp-universe, before any validator call.

Each wave-1/2 test starts by asserting its module exists, so it fails on an AssertionError until the
module lands; remove its ``expectedFailure`` then.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import unittest

PROCESS = Path(__file__).resolve().parents[1]
ROOT = PROCESS.parent
sys.path.insert(0, str(PROCESS))

import code_index  # noqa: E402
import execution_state  # noqa: E402
from execution_state import Blocked, digest  # noqa: E402
from schema_validate import validate_document  # noqa: E402

RULES_PATH = ROOT / "data" / "owasp-asvs" / "category-rules-v1.json"
UNIVERSE_CONFIG = PROCESS / "config" / "owasp-universe" / "default-v1.json"
BATCH_V1 = PROCESS / "config" / "owasp-batching" / "default-v1.json"
BATCH_V2 = PROCESS / "config" / "owasp-batching" / "default-v2.json"
BATCH_V2_PATH = "appsec-review-process/config/owasp-batching/default-v2.json"
CHAPTERS = [f"V{n}" for n in range(1, 18)]
NEW_SCHEMAS = ("owasp-category-rules.schema.json", "owasp-candidate-search.schema.json",
               "owasp-participation-cell.schema.json", "owasp-participation.schema.json",
               "owasp-universe.schema.json", "owasp-participants-bundle.schema.json",
               "owasp-universe-config.schema.json")
SNAPSHOT = "sha256:" + "0" * 64
HEX = "0" * 64
KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "defined"}
FUNCTION = re.compile(r"^[A-Za-z_][\w \t\*]*?\b([A-Za-z_]\w*)\s*\([^;]*\)\s*$")
CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---- a deterministic C fixture tree and its code index ------------------------------------------

class Tree:
    """Writes C sources and indexes them into code_index's own DDL: every function definition
    (``name(...)`` line, body to the next column-0 ``}``) is a method with a tree-sitter span, every
    ``name(`` inside a body a call (exact when the tree defines it, else external), every
    ``#include`` an import. Rows are what a real 02-code-index would hold for the same text."""

    def __init__(self, root: Path, files: dict[str, str]) -> None:
        self.root, self.files = root, files
        for path, text in files.items():
            target = root.joinpath(*path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")

    def line(self, path: str, needle: str) -> int:
        for number, text in enumerate(self.files[path].splitlines(), 1):
            if needle in text:
                return number
        raise AssertionError(f"{needle!r} not in {path}")

    def index(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        connection.executescript(code_index.DDL)
        functions = []
        for path, text in sorted(self.files.items()):
            lines = text.splitlines()
            sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
            connection.execute("INSERT INTO files VALUES(?,?,?,?)", (path, sha, "c", "cpg+treesitter"))
            for number, row in enumerate(lines, 1):
                if row.startswith("#include"):
                    connection.execute("INSERT INTO imports VALUES(?,?,?,?)", (path, number, row, "treesitter"))
                match = FUNCTION.match(row)
                if match and number < len(lines) and lines[number].strip() == "{":
                    end = next(i for i in range(number + 1, len(lines) + 1) if lines[i - 1] == "}")
                    functions.append((path, match.group(1), number, end, sha))
        method_ids = {}
        for ordinal, (path, name, start, end, sha) in enumerate(functions, 1):
            full = f"{path}:{name}"
            method_ids.setdefault(name, (ordinal, full))
            connection.execute("INSERT INTO methods VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                               (ordinal, full, name, name, None, path, start, end, "treesitter", 0, "c", sha))
            connection.execute("INSERT INTO ts_functions VALUES(?,?,?,?,?,?)", (path, name, "function_definition", start, end, "c"))
        call_id = 0
        for ordinal, (path, name, start, end, _) in enumerate(functions, 1):
            for number in range(start + 1, end + 1):
                text = self.files[path].splitlines()[number - 1]
                for callee in CALL.findall(text):
                    if callee in KEYWORDS:
                        continue
                    call_id += 1
                    target = method_ids.get(callee)
                    connection.execute(
                        "INSERT INTO calls VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (call_id, ordinal, f"{path}:{name}", target[1] if target else callee, callee,
                         target[0] if target else None, path, number, "exact" if target else "external",
                         None, None, None, None, text.strip(), code_index._family(callee)))
                    connection.execute("INSERT INTO ts_calls VALUES(?,?,?)", (path, number, callee))
        connection.commit()
        return connection


HELLO = {
    "src/hello.c": "\n".join([
        "#include <stdio.h>",
        "#include <string.h>",
        "#include <getopt.h>",
        "#include \"cJSON.h\"",
        "",
        "static void log_message(const char *text)",
        "{",
        "  fprintf(stderr, \"hello: %s\\n\", text);",
        "}",
        "",
        "static FILE *open_input(const char *path)",
        "{",
        "  FILE *stream = fopen(path, \"r\");",
        "  if (!stream)",
        "    log_message(\"cannot open input\");",
        "  return stream;",
        "}",
        "",
        "static void copy_name(char *dest, const char *name)",
        "{",
        "  strcpy(dest, name);",
        "}",
        "",
        "int main(int argc, char **argv)",
        "{",
        "  char name[64];",
        "  int option = getopt_long(argc, argv, \"g:\", NULL, NULL);",
        "  FILE *input = open_input(argv[1]);",
        "  copy_name(name, argv[argc - 1]);",
        "  printf(\"Hello, %s\\n\", name);",
        "  return input && option ? 0 : 1;",
        "}",
        ""]),
    "vendor/cjson/cJSON.c": "\n".join([
        "#include <string.h>",
        "#include <stdlib.h>",
        "",
        "char *cJSON_strdup(const char *text)",
        "{",
        "  char *copy = malloc(strlen(text) + 1);",
        "  strcpy(copy, text);",
        "  return copy;",
        "}",
        ""]),
    "tests/test-hello.c": "\n".join([
        "#include <stdio.h>",
        "",
        "int main(int argc, char **argv)",
        "{",
        "  FILE *golden = fopen(\"tests/golden.txt\", \"r\");",
        "  return golden ? 0 : argc;",
        "}",
        ""]),
}


def implements_everything(cell: dict) -> dict:
    """A fake classifier: every listed candidate implements the chapter, cited at its first line."""
    return {"records": [{"candidate_id": row["candidate_id"], "symbol": row["symbol"], "file": row["file"],
                         "start_line": row["start_line"], "end_line": row["end_line"], "role": "implements",
                         "citations": [{"file": row["file"], "line": row["start_line"]}],
                         "rationale": "fixture classification"} for row in cell["candidates"]]}


class Spy:
    """A dispatch invoker and a participation ``invoke`` that only count calls."""

    def __init__(self, reply=None) -> None:
        self.calls, self.reply = [], reply

    def invoke(self, package, *, output_root=None, cancel=None):
        self.calls.append(package)
        raise AssertionError("no validator call may happen")

    def __call__(self, cell):
        self.calls.append(cell)
        return self.reply(cell) if self.reply else {"records": []}


class Adr34Case(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.rules = load(RULES_PATH)
        self.config = load(UNIVERSE_CONFIG)
        self.batch = load(BATCH_V2)

    def require(self, *modules: str) -> list:
        for name in modules:
            self.assertTrue(importlib.util.find_spec(name), f"{name} is not implemented yet (ADR-0034 wave 1)")
        return [importlib.import_module(name) for name in modules]

    def chain(self, files: dict[str, str], *, reply=implements_everything, config=None, treesitter_gaps=()):
        search_mod, participation_mod, universe_mod = self.require(
            "owasp_candidate_search", "owasp_participation", "owasp_universe")
        root = self.base / f"src-{len(list(self.base.iterdir()))}"
        tree = Tree(root, files)
        config = config or self.config
        search = search_mod.search(tree.index(), self.rules, sast_hits=[], treesitter_gaps=list(treesitter_gaps))
        participation = participation_mod.participate(search, config, invoke=Spy(reply), source_root=root)
        universe, bundles = universe_mod.build(
            search, participation, control_rows=universe_mod.chapter_control_rows(), config=config,
            batch_config=self.batch, batch_config_path=BATCH_V2_PATH, source_root=root)
        return tree, search, participation, universe, bundles

    def target(self, universe: dict, chapter: str) -> dict:
        return next(row for row in universe["targets"] if row["chapter_id"] == chapter)

    # documents as the three jobs publish them, for schema validation
    def binding(self, job: str) -> dict:
        return {"job_id": job, "attempt_id": "a1", "accepted_pointer_sha256": HEX,
                "artifact_path": f"jobs/{job}/attempts/a1/out.json", "artifact_sha256": HEX}

    def config_ref(self, path: str, value: dict) -> dict:
        return {"path": path, "config_id": value["config_id"], "version": value["version"], "config_digest": digest(value)}

    def assert_documents_valid(self, search: dict, participation: dict, universe: dict, bundles: dict) -> None:
        base = {"run_id": "adr34-fixture", "source_snapshot_sha256": SNAPSHOT}
        search_doc = {"schema": "appsec-review/owasp-candidate-search/1.0", **base, "job_id": "04-owasp-candidate-search",
                      "status": "OK_WITH_GAPS" if search["gaps"] else "OK",
                      "rule_table": {"path": "data/owasp-asvs/category-rules-v1.json", "rules_id": self.rules["rules_id"],
                                     "version": self.rules["version"], "sha256": HEX},
                      "inputs": [{"job_id": job, "required": job != "02-source-sast", "accepted": True, "attempt_id": "a1",
                                  "artifact_path": f"jobs/{job}/attempts/a1/out.json", "artifact_sha256": HEX}
                                 for job in ("02-code-index", "02-code-property-graph", "02-treesitter-ast", "02-source-sast")],
                      **search}
        self.assertEqual(validate_document(search_doc, "owasp-candidate-search.schema.json"), [])
        universe_path = "appsec-review-process/config/owasp-universe/default-v1.json"
        participation_doc = {"schema": "appsec-review/owasp-participation/1.0", **base, "job_id": "04-owasp-participation",
                             "status": "OK_WITH_GAPS" if participation["gaps"] else "OK",
                             "candidate_search": self.binding("04-owasp-candidate-search"),
                             "code_index": self.binding("02-code-index"),
                             "config": self.config_ref(universe_path, self.config), **participation}
        self.assertEqual(validate_document(participation_doc, "owasp-participation.schema.json"), [])
        universe_doc = {"schema": "appsec-review/owasp-universe/1.0", **base, "job_id": "04-owasp-universe",
                        "inputs": {"candidate_search": self.binding("04-owasp-candidate-search"),
                                   "participation": self.binding("04-owasp-participation"),
                                   "asvs_reference": {"family": "owasp_asvs", "edition": "5.0.0",
                                                      "snapshot_id": "sha256-e48ca4caa6619973", "manifest_sha256": HEX}},
                        "config": self.config_ref(universe_path, self.config), **universe}
        self.assertEqual(validate_document(universe_doc, "owasp-universe.schema.json"), [])
        for chapter, bundle in bundles.items():
            document = {"schema": "appsec-review/owasp-participants-bundle/1.0", **base,
                        "input_id": f"asvs-participants-{chapter}", "chapter_id": chapter, **bundle}
            self.assertEqual(validate_document(document, "owasp-participants-bundle.schema.json"), [])


class Adr34OwaspParticipationTests(Adr34Case):
    @unittest.expectedFailure
    def test_hello_autotools_like_target_plans_at_most_twelve_validator_calls(self):
        """(1) A small C CLI: candidates -> fake participation -> universe -> batch plan <= 12 calls."""
        tree, search, participation, universe, bundles = self.chain(HELLO)
        self.assertEqual([row["chapter_id"] for row in search["chapters"]], CHAPTERS)
        files = {row["file"] for row in search["candidates"]}
        self.assertEqual(files, {"src/hello.c"})
        excluded = {(row["file"], row["reason"]) for row in search["excluded"]}
        self.assertIn(("vendor/cjson/cJSON.c", "vendored_third_party"), excluded)
        self.assertIn(("tests/test-hello.c", "test_code"), excluded)
        self.assertTrue(search["coverage"]["complete"])
        self.assertEqual({row["candidate_id"] for row in search["candidates"]},
                         {row["candidate_id"] for row in participation["records"]})
        self.assertEqual(participation["unclassified"], [])

        self.assertIn(universe["status"], {"OK", "OK_WITH_GAPS"})
        self.assertEqual([row["target_id"] for row in universe["targets"]], [f"asvs-{c}" for c in CHAPTERS])
        participating = [row["chapter_id"] for row in universe["targets"] if row["decision"] == "participating"]
        self.assertTrue({"V1", "V2", "V5", "V16"} <= set(participating), participating)
        self.assertEqual(sorted(bundles, key=CHAPTERS.index), participating)
        self.assertEqual(self.target(universe, "V3")["decision"], "not_applicable")
        self.assertEqual(self.target(universe, "V3")["reason_code"], "no_candidates_complete_coverage")
        masvs = next(row for row in universe["families"] if row["family"] == "owasp_masvs")
        self.assertEqual((masvs["decision"], masvs["reason_code"]), ("not_applicable", "no_mobile_platform"))

        budget = universe["budget"]
        rows = load(BATCH_V2)["limits"]["max_control_target_rows"]
        self.assertEqual(budget["max_control_target_rows"], rows)
        self.assertEqual(budget["max_validator_calls"], self.config["validation"]["max_validator_calls"])
        expected = sum(math.ceil(self.target(universe, c)["control_rows"] / rows) for c in participating)
        self.assertEqual(budget["planned_validator_calls"], expected)
        self.assertEqual(sum(row["planned_validator_calls"] for row in universe["targets"]), expected)
        self.assertLessEqual(expected, 12)
        self.assertTrue(budget["within_budget"])
        self.assert_documents_valid(search, participation, universe, bundles)

        # an unparsed language present in the snapshot: zero candidates is a gap, never N/A
        _, gapped, _, universe, _ = self.chain(HELLO, treesitter_gaps=[
            {"kind": "no-grammar", "path": None, "detail": "3 file(s) with suffix .kt"}])
        self.assertFalse(gapped["coverage"]["complete"])
        self.assertEqual((self.target(universe, "V3")["decision"], self.target(universe, "V3")["reason_code"]),
                         ("gap", "coverage_incomplete"))

    @unittest.expectedFailure
    def test_budget_exceeded_blocks_before_any_model_call(self):
        """(2) Over budget: the universe is BLOCKED and no validator (or participation) call happens."""
        config = deepcopy(self.config)
        config["validation"]["max_validator_calls"] = 2
        _, _, _, universe, _ = self.chain(HELLO, config=config)
        self.assertEqual(universe["status"], "BLOCKED")
        self.assertFalse(universe["budget"]["within_budget"])
        self.assertGreater(universe["budget"]["planned_validator_calls"], 2)
        self.assertIn("budget_exceeded", {gap["kind"] for gap in universe["gaps"]})

        lifecycle = importlib.import_module("owasp_workbench_lifecycle")
        runs = execution_state.RUNS
        execution_state.RUNS = self.base / "runs"
        self.addCleanup(setattr, execution_state, "RUNS", runs)
        run_id = "adr34-blocked"
        (execution_state.RUNS / run_id / "data").mkdir(parents=True)
        spy = Spy()
        with self.assertRaisesRegex(Blocked, "universe"):
            lifecycle.run_dispatch(run_id, "adr34-test", invoker=spy)
        self.assertEqual(spy.calls, [])

        participation_mod = importlib.import_module("owasp_participation")
        search_mod = importlib.import_module("owasp_candidate_search")
        root = self.base / "participation-budget"
        search = search_mod.search(Tree(root, HELLO).index(), self.rules, sast_hits=[], treesitter_gaps=[])
        config["participation"]["max_participation_calls"] = 1
        spy = Spy(implements_everything)
        with self.assertRaises(Blocked):
            participation_mod.participate(search, config, invoke=spy, source_root=root)
        self.assertEqual(spy.calls, [])

    @unittest.expectedFailure
    def test_file_in_two_chapters_is_in_both_bundles(self):
        """(3) src/hello.c opens a file (V5) and logs (V16): it is in both chapter bundles."""
        tree, _, _, universe, bundles = self.chain(HELLO)
        for chapter, symbol in (("V5", "open_input"), ("V16", "log_message")):
            target = self.target(universe, chapter)
            self.assertEqual(target["decision"], "participating")
            self.assertEqual(target["evidence_bundle"]["input_id"], f"asvs-participants-{chapter}")
            self.assertIn("src/hello.c", {row["path"] for row in target["files"]})
            excerpts = {(row["file"], row["symbol"]): row for row in bundles[chapter]["excerpts"]}
            excerpt = excerpts[("src/hello.c", symbol)]
            lines = tree.files["src/hello.c"].splitlines()[excerpt["start_line"] - 1:excerpt["end_line"]]
            self.assertEqual(excerpt["text"], "\n".join(lines))
            self.assertEqual(excerpt["text_sha256"], hashlib.sha256(excerpt["text"].encode("utf-8")).hexdigest())

    @unittest.expectedFailure
    def test_component_without_participating_code_yields_no_validator_rows(self):
        """(4) Only not_participating code in src/util: it reaches no target, bundle or validator row."""
        files = {
            "src/app/app.c": "\n".join(["#include <stdio.h>", "", "int main(int argc, char **argv)", "{",
                                        "  FILE *f = fopen(argv[1], \"r\");", "  fprintf(stderr, \"open\\n\");",
                                        "  return f ? 0 : argc;", "}", ""]),
            "src/util/util.c": "\n".join(["#include <stdlib.h>", "", "int util_jitter(void)", "{",
                                          "  return rand() % 3;", "}", ""]),
        }

        def reply(cell):
            records = implements_everything(cell)["records"]
            for record in records:
                if record["file"].startswith("src/util/"):
                    record["role"] = "not_participating"
                    record["rationale"] = "UI jitter, not a security random value"
            return {"records": records}

        _, search, _, universe, bundles = self.chain(files, reply=reply)
        self.assertIn("src/util/util.c", {row["file"] for row in search["candidates"]})
        for target in universe["targets"]:
            self.assertNotIn("src/util/util.c", {row["path"] for row in target["files"]})
            self.assertNotIn("src/util/util.c", {row["file"] for row in target["participants"]})
        for bundle in bundles.values():
            self.assertNotIn("src/util/util.c", {row["file"] for row in bundle["excerpts"]})
        v11 = self.target(universe, "V11")
        self.assertEqual((v11["decision"], v11["reason_code"], v11["planned_validator_calls"]),
                         ("not_applicable", "all_candidates_not_participating", 0))
        self.assertEqual({row["file"] for row in universe["excluded"]}, {"src/util/util.c"})

    @unittest.expectedFailure
    def test_validator_calls_scale_with_chapters_not_components(self):
        """(5) 40 components with code in three chapters plan sum(ceil(L1+L2 rows / 40)) calls; 4 components plan the same."""
        def target(count: int) -> dict[str, str]:
            calls = ("fopen(path, \"r\")", "syslog(LOG_ERR, \"%s\", path)", "RAND_bytes(buffer, 16)")
            files = {}
            for index in range(count):
                call = calls[index * 3 // count]
                files[f"components/c{index:02d}/unit.c"] = "\n".join([
                    "#include <stdio.h>", "", f"int unit_{index:02d}(const char *path, unsigned char *buffer)", "{",
                    f"  return {call} != 0;", "}", ""])
            return files

        _, _, _, large, _ = self.chain(target(40))
        _, _, _, small, _ = self.chain(target(4))
        participating = [row["chapter_id"] for row in large["targets"] if row["decision"] == "participating"]
        self.assertEqual(participating, ["V5", "V11", "V16"])
        rows = load(BATCH_V2)["limits"]["max_control_target_rows"]
        ceiling = sum(math.ceil(self.target(large, chapter)["control_rows"] / rows) for chapter in participating)
        self.assertLessEqual(large["budget"]["planned_validator_calls"], ceiling)
        self.assertEqual(large["budget"]["planned_validator_calls"], small["budget"]["planned_validator_calls"])
        self.assertEqual(ceiling, 3)

    def test_rule_table_configs_and_schemas_are_frozen_and_valid(self):
        """(6) Wave-0 contracts: every new schema resolves, the rule table and configs validate."""
        import schema_keyword_lint
        problems = [line for line in schema_keyword_lint.survey()["problems"] if line.split(":")[0].split("#")[0] in NEW_SCHEMAS]
        self.assertEqual(problems, [])
        self.assertEqual(validate_document(self.rules, "owasp-category-rules.schema.json"), [])
        self.assertEqual(validate_document(self.config, "owasp-universe-config.schema.json"), [])
        self.assertEqual(self.config["batch_config_path"], BATCH_V2_PATH)
        self.assertEqual(self.config["validation"]["max_validator_calls"], 20)

        catalog_path = next((ROOT / "data/reference/owasp/owasp_asvs/5.0.0").glob("*/normalized/catalog.json"))
        controls = [row for row in load(catalog_path)["records"] if row.get("record_type") == "control"]
        names = {row["group"]["chapter_id"]: row["group"]["chapter_name"] for row in controls}
        sections = {row["group"]["section_id"] for row in controls}
        self.assertEqual([row["chapter_id"] for row in self.rules["chapters"]], CHAPTERS)
        rule_ids = set()
        for chapter in self.rules["chapters"]:
            self.assertEqual(chapter["chapter_name"], names[chapter["chapter_id"]])
            ids = {rule["rule_id"] for rule in chapter["rules"]}
            self.assertTrue(any({"c", "cpp"} & set(rule["languages"]) for rule in chapter["rules"]), chapter["chapter_id"])
            for rule in chapter["rules"]:
                self.assertTrue(rule["rule_id"].startswith(chapter["chapter_id"] + "-"), rule["rule_id"])
                self.assertNotIn(rule["rule_id"], rule_ids)
                rule_ids.add(rule["rule_id"])
                for section in rule["sections"]:
                    self.assertIn(section, sections, rule["rule_id"])
                    self.assertEqual(section.split(".")[0], chapter["chapter_id"], rule["rule_id"])
                if "pattern" in rule:
                    re.compile(rule["pattern"])
            if chapter["propagation"]:
                self.assertTrue(set(chapter["propagation"]["seed_rule_ids"]) <= ids)
        # every rule kind is answered by a table the code index really has
        tables = set(re.findall(r"CREATE (?:VIRTUAL )?TABLE (\w+)", code_index.DDL))
        self.assertTrue({"calls", "ts_calls", "methods", "ts_functions", "identifiers", "literals", "imports", "exports"} <= tables)
        self.assertEqual(sum(1 for row in controls if {"L1", "L2"} & set(row["profiles"])), 253)

        import owasp_batching
        self.assertEqual(digest(load(BATCH_V1)), "4d57bbb01cace19594884c774b41e146149be88ec33560bef613f15191fe3b12")
        config, _ = owasp_batching._load_batch_config({"path": BATCH_V2_PATH, "config_digest": digest(self.batch)})
        self.assertEqual((config["limits"]["max_control_target_rows"], config["limits"]["max_components"]), (40, 1))

        # closed contracts reject what the plan forbids
        record = {"candidate_id": None, "symbol": "f", "file": "a.c", "start_line": 1, "end_line": 2,
                  "role": "not_participating", "citations": [{"file": "a.c", "line": 1}], "rationale": "x"}
        self.assertNotEqual(validate_document({"records": [record]}, "owasp-participation-cell.schema.json"), [])
        record["role"] = "implements"
        self.assertEqual(validate_document({"records": [record]}, "owasp-participation-cell.schema.json"), [])
        self.assertNotEqual(validate_document({"records": [dict(record, downstream_lanes=["x"])]},
                                              "owasp-participation-cell.schema.json"), [])

    @unittest.expectedFailure
    def test_keyword_routing_is_deleted(self):
        """(7) P3: the component-keyword routing and the inline worklist routing are gone."""
        routing = importlib.import_module("owasp_component_routing")
        for name in ("_family_match", "_local_only", "_tokens", "NON_WEB_NA_DOMAINS", "LOCAL_KINDS", "NETWORK_TRAITS"):
            self.assertFalse(hasattr(routing, name), f"owasp_component_routing.{name} still exists")
        self.assertNotIn('"all_controls": True', Path(routing.__file__).read_text(encoding="utf-8"))
        lifecycle = importlib.import_module("standards_lifecycle")
        self.assertFalse(hasattr(lifecycle, "_route_owasp"), "standards_lifecycle._route_owasp still exists")


if __name__ == "__main__":
    unittest.main()
