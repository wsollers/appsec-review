"""04-owasp-candidate-search (ADR-0034): deterministic per-chapter candidates, exclusions, gaps and
the widening facilities (evidence-index FTS, semantic recall, component tag cloud)."""
from __future__ import annotations

from contextlib import redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

PROCESS = Path(__file__).resolve().parents[1]
ROOT = PROCESS.parent
sys.path.insert(0, str(PROCESS))

import owasp_candidate_search as search_mod  # noqa: E402
from schema_validate import validate_document  # noqa: E402
import tests.test_adr34_owasp_participation as guard  # noqa: E402  (module import: its cases are not re-collected)

RULES = json.loads((ROOT / "data" / "owasp-asvs" / "category-rules-v1.json").read_text(encoding="utf-8"))
HEX = "0" * 64
CHAPTERS = [f"V{n}" for n in range(1, 18)]


def document(result: dict) -> dict:
    inputs = [{"job_id": job, "required": job != "02-source-sast", "accepted": True, "attempt_id": "a1",
               "artifact_path": f"jobs/{job}/attempts/a1/out.json", "artifact_sha256": HEX}
              for job in ("02-code-index", "02-code-property-graph", "02-treesitter-ast", "02-source-sast")]
    return search_mod.document(result, run_id="adr34-fixture", source_snapshot_sha256="sha256:" + HEX, rules=RULES,
                               rules_sha256=HEX, inputs=inputs)


class FakeEvidence:
    """02-evidence-index's chunks table and its bounded search/read semantics (evidence_store._query)."""

    def __init__(self, files: dict[str, str], *, chunk_lines: int = 60, manifest: dict | None = None) -> None:
        self.files = {"source/" + path: text for path, text in files.items()}
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE VIRTUAL TABLE chunks USING fts5(path UNINDEXED, sha256 UNINDEXED, start_line UNINDEXED, "
                        "end_line UNINDEXED, content, tokenize='unicode61')")
        for path, text in sorted(self.files.items()):
            lines, sha = text.splitlines(), hashlib.sha256(text.encode("utf-8")).hexdigest()
            for start in range(0, len(lines), chunk_lines):
                end = min(len(lines), start + chunk_lines)
                self.db.execute("INSERT INTO chunks VALUES (?,?,?,?,?)", (path, sha, start + 1, end, "\n".join(lines[start:end])))
        self.manifest = manifest if manifest is not None else {"text_status_counts": {"indexed": len(files)}, "excluded": []}
        self.calls: list[tuple] = []

    def query(self, action, text="", path="", limit=10, start=1):
        self.calls.append((action, text, path, limit, start))
        if not 1 <= limit <= 50:
            raise ValueError("query bounds")
        if action == "search":
            match = " AND ".join('"' + word.replace('"', '""') + '"' for word in text.split())
            rows = [{"path": p, "sha256": s, "start_line": a, "end_line": b} for p, s, a, b in self.db.execute(
                "SELECT path, sha256, start_line, end_line FROM chunks WHERE chunks MATCH ? "
                "ORDER BY bm25(chunks), path, start_line LIMIT ?", (match, limit))]
        elif action == "read":
            if path not in self.files:
                raise ValueError("path is not in the accepted index")
            lines = self.files[path].splitlines()
            if start > len(lines):
                raise ValueError("start line is beyond the file")
            rows = [{"path": path, "sha256": hashlib.sha256(self.files[path].encode("utf-8")).hexdigest(), "start_line": start,
                     "end_line": min(len(lines), start + limit - 1), "excerpt": "\n".join(lines[start - 1:start - 1 + limit])}]
        else:
            raise ValueError("unknown query action")
        return {"run_id": "fixture", "attempt_id": "a1", "untrusted_content": True, "results": rows}

    def handle(self) -> dict:
        return {"query": self.query, "manifest": self.manifest}


class CandidateSearchCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def tree(self, files: dict[str, str]) -> guard.Tree:
        return guard.Tree(self.base / f"src-{len(list(self.base.iterdir()))}", files)

    def run_search(self, connection, *, sast_hits=(), treesitter_gaps=(), **kwargs) -> dict:
        result = search_mod.search(connection, RULES, sast_hits=None if sast_hits is None else list(sast_hits),
                                   treesitter_gaps=list(treesitter_gaps), **kwargs)
        self.assertEqual(validate_document(document(result), "owasp-candidate-search.schema.json"), [])
        return result

    @staticmethod
    def chapter(result: dict, chapter_id: str) -> dict:
        return next(row for row in result["chapters"] if row["chapter_id"] == chapter_id)

    @staticmethod
    def found(result: dict, chapter_id: str) -> dict[tuple[str, str], dict]:
        return {(row["file"], row["symbol"]): row for row in result["candidates"] if row["chapter_id"] == chapter_id}

    @staticmethod
    def kinds(result: dict) -> set[str]:
        return {gap["kind"] for gap in result["gaps"]}


class SearchTests(CandidateSearchCase):
    def test_hello_candidates_exclusions_and_multi_chapter_membership(self):
        result = self.run_search(self.tree(guard.HELLO).index())
        self.assertEqual([row["chapter_id"] for row in result["chapters"]], CHAPTERS)
        self.assertTrue(result["coverage"]["complete"])
        self.assertEqual(result["coverage"]["searched_languages"], ["c"])
        self.assertEqual({row["file"] for row in result["candidates"]}, {"src/hello.c"})
        v1, v2, v5, v16 = (self.found(result, chapter) for chapter in ("V1", "V2", "V5", "V16"))
        self.assertEqual(set(v1), {("src/hello.c", "copy_name")})
        self.assertEqual(set(v5), {("src/hello.c", "open_input")})
        self.assertEqual(set(v16), {("src/hello.c", "log_message")})
        self.assertEqual({row["kind"] for row in v16[("src/hello.c", "log_message")]["matches"]}, {"symbol_regex", "calls_to"})
        # V2: main by entry point and input source; its resolved callees by propagation
        self.assertEqual(set(v2), {("src/hello.c", "main"), ("src/hello.c", "open_input"), ("src/hello.c", "copy_name")})
        self.assertEqual({row["kind"] for row in v2[("src/hello.c", "main")]["matches"]}, {"entry_point", "calls_to"})
        self.assertEqual({row["kind"] for row in v2[("src/hello.c", "open_input")]["matches"]}, {"propagation"})
        # one function, several chapters
        chapters_of = {}
        for row in result["candidates"]:
            chapters_of.setdefault(row["symbol"], set()).add(row["chapter_id"])
        self.assertEqual(chapters_of["open_input"], {"V2", "V5"})
        self.assertEqual(chapters_of["copy_name"], {"V1", "V2"})
        # function spans, not files
        open_input = v5[("src/hello.c", "open_input")]
        self.assertEqual((open_input["start_line"], open_input["end_line"], open_input["span_source"]), (11, 17, "treesitter"))
        self.assertRegex(open_input["candidate_id"], r"^cand-V5-[0-9a-f]{16}\Z")
        # exclusions carry reasons and count in the chapter
        excluded = {(row["chapter_id"], row["file"], row["reason"]) for row in result["excluded"]}
        self.assertIn(("V1", "vendor/cjson/cJSON.c", "vendored_third_party"), excluded)
        self.assertIn(("V5", "tests/test-hello.c", "test_code"), excluded)
        self.assertIn(("V2", "tests/test-hello.c", "test_code"), excluded)
        self.assertEqual(self.chapter(result, "V1")["excluded_count"], 1)
        # every rule is in the basis with its raw count, zero included
        v3 = self.chapter(result, "V3")
        self.assertEqual((v3["candidate_count"], v3["coverage_complete"]), (0, True))
        self.assertEqual([row["rule_id"] for row in v3["search_basis"] if row["kind"] != "semantic"],
                         [rule["rule_id"] for rule in RULES["chapters"][2]["rules"]])
        self.assertEqual(sum(row["hits"] for row in v3["search_basis"]), 0)
        basis = {row["rule_id"]: row["hits"] for row in self.chapter(result, "V1")["search_basis"] if row["rule_id"]}
        self.assertEqual(basis["V1-native-unsafe-string"], 2)   # raw: src + vendor, before exclusions

    def test_rule_kinds_read_their_own_index_facet(self):
        files = {"src/net.c": "\n".join([
            "#include <openssl/evp.h>", "", "static const char *api_key;", "",
            "int send_headers(int fd)", "{", "  int api_key = 0;", "  add_header(fd, \"X-Frame-Options\");",
            "  return api_key;", "}", ""])}
        tree = self.tree(files)
        connection = tree.index()
        connection.execute("INSERT INTO identifiers VALUES('api_key','src/net.c',7,'int')")
        connection.execute("INSERT INTO literals VALUES('X-Frame-Options','src/net.c',8,'src/net.c:send_headers',"
                           "'call-argument-text')")
        connection.execute("INSERT INTO names(name, kind, ref, file, line) VALUES('verify_password_hash','ir-function',"
                           "'verify_password_hash','src/net.c',8)")
        sast = [{"rule_id": "semgrep.rules.appsec.c.strcpy", "path": "src/net.c", "start_line": 8},
                {"rule_id": "unrelated.rule", "path": "src/net.c", "start_line": 9}]
        result = self.run_search(connection, sast_hits=sast)
        def kinds(chapter, symbol):
            return {(row["rule_id"], row["kind"]) for row in self.found(result, chapter)[("src/net.c", symbol)]["matches"]}
        self.assertIn(("V13-secret-identifiers", "identifier_regex"), kinds("V13", "send_headers"))
        self.assertIn(("V3-security-headers", "literal_regex"), kinds("V3", "send_headers"))
        self.assertIn(("V1-native-sast-memory", "sast_rule_ids"), kinds("V1", "send_headers"))
        self.assertIn(("V6-auth-symbols", "symbol_regex"), kinds("V6", "send_headers"))   # names FTS row, enclosed
        module = self.found(result, "V11")[("src/net.c", "<module>")]
        self.assertEqual((module["span_source"], module["start_line"], module["end_line"]), ("module-scope", 1, 1))
        self.assertEqual({row["kind"] for row in module["matches"]}, {"import_regex"})
        self.assertEqual(self.chapter(result, "V1")["candidate_count"], 1)
        names = next(row for row in result["coverage"]["facilities"] if row["facility"] == "code_index_names")
        self.assertIn("1 IR-function", names["detail"])

    def test_treesitter_only_language_calls_and_unsupported_identifier_rules(self):
        connection = self.tree({"src/app.c": "int main(void)\n{\n  return 0;\n}\n"}).index()
        connection.execute("INSERT INTO files VALUES('tool/run.py',?,'python','treesitter')", (HEX,))
        connection.execute("INSERT INTO ts_functions VALUES('tool/run.py','handle','function_definition',3,9,'python')")
        connection.execute("INSERT INTO ts_calls VALUES('tool/run.py',5,'subprocess.check_output')")
        connection.execute("INSERT INTO imports VALUES('tool/run.py',1,'import hashlib','treesitter')")
        result = self.run_search(connection)
        v1 = self.found(result, "V1")[("tool/run.py", "handle")]
        self.assertEqual(v1["language"], "python")
        self.assertEqual({row["detail"] for row in v1["matches"]}, {"call subprocess.check_output"})
        self.assertIn(("tool/run.py", "<module>"), self.found(result, "V11"))
        # identifiers come from the CPG only: unknown for python here, never zero
        unsupported = [gap for gap in result["gaps"] if gap["kind"] == "rule_without_index_support"]
        self.assertTrue(any("V13-secret-identifiers" in gap["statement"] and "python" in gap["statement"] for gap in unsupported))
        self.assertFalse(self.chapter(result, "V13")["coverage_complete"])
        self.assertTrue(result["coverage"]["complete"])

    def test_gaps_for_missing_grammars_truncation_and_sast(self):
        connection = self.tree(guard.HELLO).index()
        ts_gaps = [{"kind": "no-grammar", "path": None, "detail": "3 file(s) with suffix .kt"},
                   {"kind": "no-grammar", "path": None, "detail": "1 file(s) with suffix .swift"},
                   {"kind": "file-too-large", "path": "src/big.c", "detail": "too big"},
                   {"kind": "file-too-large", "path": "vendor/huge.c", "detail": "too big"},
                   {"kind": "rows-truncated", "path": "src/hello.c", "detail": "calls capped at max_rows_per_file"},
                   {"kind": "grammar-unavailable", "path": None, "detail": "ruby: ImportError"}]
        result = self.run_search(connection, sast_hits=None, treesitter_gaps=ts_gaps)
        self.assertFalse(result["coverage"]["complete"])
        self.assertEqual(result["coverage"]["unsearched_languages"], [
            {"language": "c", "file_count": 1, "reason": "index_truncated"},
            {"language": "kotlin", "file_count": 3, "reason": "no_grammar"},
            {"language": "swift", "file_count": 1, "reason": "no_grammar"}])
        self.assertTrue(all(not row["coverage_complete"] for row in result["chapters"]))
        self.assertFalse(result["coverage"]["sast_available"])
        kinds = self.kinds(result)
        self.assertTrue({"language_not_searched", "rows_truncated", "sast_unavailable"} <= kinds)
        sast = next(gap for gap in result["gaps"] if gap["kind"] == "sast_unavailable")
        self.assertEqual(sast["chapter_ids"], ["V1"])
        # the candidates found are still published
        self.assertIn(("src/hello.c", "open_input"), self.found(result, "V5"))

    def test_unruled_language_is_unsearched_and_rust_unsafe_is_a_gap(self):
        connection = self.tree({"src/a.c": "int main(void)\n{\n  return 0;\n}\n"}).index()
        connection.execute("INSERT INTO files VALUES('lib/x.rb',?,'ruby','treesitter')", (HEX,))
        connection.execute("INSERT INTO files VALUES('core/src/lib.rs',?,'rust','cpg+treesitter')", (HEX,))
        connection.execute("INSERT INTO files VALUES('data/x.json',?,'json','treesitter')", (HEX,))
        result = self.run_search(connection)
        self.assertEqual(result["coverage"]["unsearched_languages"],
                         [{"language": "ruby", "file_count": 1, "reason": "no_rules_for_language"}])
        self.assertTrue(any(gap["kind"] == "index_incomplete" and "Rust unsafe" in gap["statement"] for gap in result["gaps"]))

    def test_empty_index_is_a_gap_in_every_chapter(self):
        connection = sqlite3.connect(":memory:")
        connection.executescript(guard.code_index.DDL)
        result = self.run_search(connection)
        self.assertEqual(result["candidates"], [])
        self.assertFalse(result["coverage"]["complete"])
        self.assertEqual([row["coverage_complete"] for row in result["chapters"]], [False] * 17)
        empty = [gap for gap in result["gaps"] if gap["kind"] == "index_incomplete" and "no files" in gap["statement"]]
        self.assertEqual(empty[0]["chapter_ids"], CHAPTERS)

    def test_output_is_deterministic_and_sorted(self):
        first = self.run_search(self.tree(guard.HELLO).index())
        reversed_files = dict(reversed(list(guard.HELLO.items())))
        second = self.run_search(self.tree(reversed_files).index())
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        keys = [(CHAPTERS.index(row["chapter_id"]), row["file"], row["start_line"], row["symbol"]) for row in first["candidates"]]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual([gap["kind"] for gap in first["gaps"]], sorted(gap["kind"] for gap in first["gaps"]))

    def test_cli_writes_the_search_result(self):
        tree = self.tree(guard.HELLO)
        database = self.base / "code-index.sqlite"
        target = sqlite3.connect(database)
        tree.index().backup(target)
        target.close()
        sast = self.base / "source-sast.json"
        sast.write_text(json.dumps({"leads": []}), encoding="utf-8")
        output = self.base / "out" / "candidate-search.json"
        self.assertEqual(search_mod.main(["--index", str(database), "--source-sast", str(sast), "--output", str(output)]), 0)
        expected = self.run_search(tree.index())
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), json.loads(json.dumps(expected)))
        with redirect_stderr(io.StringIO()) as error:
            self.assertEqual(search_mod.main(["--index", str(self.base / "missing.sqlite")]), 2)
        self.assertIn("OWASP_CANDIDATE_SEARCH_BLOCKED", error.getvalue())


class EvidenceIndexTests(CandidateSearchCase):
    CONFIG = "\n".join([
        "static const char *HEADERS[] = {",
        "  \"Content-Security-Policy\",",
        "  \"X-Content-Type-Options\",",
        "};",
        "",
        "int install(int fd)",
        "{",
        "  const char *policy = \"Strict-Transport-Security\";",
        "  return fd + (policy != 0);",
        "}",
        ""])

    def test_fts_hit_outside_call_arguments_becomes_a_candidate(self):
        files = {"src/config.c": self.CONFIG}
        evidence = FakeEvidence(files)
        result = self.run_search(self.tree(files).index(), evidence_index=evidence.handle())
        v3 = self.found(result, "V3")
        # a hit outside any function is a <module> candidate spanning the hit line (one per line)
        modules = [row for row in result["candidates"] if row["chapter_id"] == "V3" and row["symbol"] == "<module>"]
        self.assertEqual([(row["start_line"], row["end_line"], row["span_source"]) for row in modules],
                         [(2, 2, "module-scope"), (3, 3, "module-scope")])
        self.assertEqual({(match["rule_id"], match["kind"]) for row in modules for match in row["matches"]},
                         {("V3-security-headers", "fts")})
        install = v3[("src/config.c", "install")]
        self.assertEqual([(row["kind"], row["line"], row["detail"]) for row in install["matches"]],
                         [("fts", 8, "fts literal Strict-Transport-Security")])
        basis = [row for row in self.chapter(result, "V3")["search_basis"] if row["kind"] == "fts"]
        self.assertEqual({row["rule_id"]: row["hits"] for row in basis}["V3-security-headers"], 3)
        # bounded paths only, each call within the cap
        self.assertTrue(all(call[0] in ("search", "read") and call[3] <= 50 for call in evidence.calls))
        self.assertNotIn("evidence_index_unavailable", self.kinds(result))

    def test_kotlin_file_without_grammar_is_found_through_fts(self):
        index_files = {"src/app.c": "int main(void)\n{\n  return 0;\n}\n"}
        kotlin = "package app\n\nclass Net {\n  val url = \"http://api.example.com/v1\"\n}\n"
        evidence = FakeEvidence({**index_files, "android/app/src/main/Net.kt": kotlin})
        result = self.run_search(self.tree(index_files).index(), evidence_index=evidence.handle(),
                                 treesitter_gaps=[{"kind": "no-grammar", "path": None, "detail": "1 file(s) with suffix .kt"}])
        row = self.found(result, "V12")[("android/app/src/main/Net.kt", "<module>")]
        self.assertEqual((row["language"], row["start_line"]), ("kotlin", 4))
        self.assertEqual(row["file_sha256"], hashlib.sha256(kotlin.encode("utf-8")).hexdigest())
        self.assertEqual({(match["rule_id"], match["kind"]) for match in row["matches"]}, {("V12-cleartext-urls", "fts")})
        # the FTS widens; the language is still unsearched by the code index
        self.assertFalse(result["coverage"]["complete"])
        self.assertEqual(result["coverage"]["unsearched_languages"][0]["language"], "kotlin")

    def test_fts_limits_are_gaps(self):
        files = {f"src/h{index:02d}.c": "int x = 0; /* see \"Content-Security-Policy\" */\n" for index in range(3)}
        evidence = FakeEvidence(files, manifest={"text_status_counts": {"indexed": 3, "binary": 2}, "excluded": [{"path": "a"}]})
        handle = {**evidence.handle(), "limit": 2}
        result = self.run_search(self.tree({"src/a.c": "int main(void)\n{\n  return 0;\n}\n"}).index(), evidence_index=handle)
        statements = [gap["statement"] for gap in result["gaps"]]
        self.assertTrue(any(gap["kind"] == "rows_truncated" and "bounded maximum of 2" in gap["statement"] for gap in result["gaps"]))
        self.assertTrue(any("2 binary" in text and "1 excluded" in text for text in statements))
        self.assertTrue(any("whole tokens" in text for text in statements))

    def test_missing_evidence_index_is_a_gap(self):
        result = self.run_search(self.tree(guard.HELLO).index())
        gap = next(gap for gap in result["gaps"] if gap["kind"] == "evidence_index_unavailable")
        self.assertEqual(gap["chapter_ids"], CHAPTERS)
        facility = next(row for row in result["coverage"]["facilities"] if row["facility"] == "evidence_index_fts")
        self.assertEqual(facility["status"], "unavailable")
        self.assertTrue(result["coverage"]["complete"])   # a widening facility never completes or breaks coverage

    def test_fts_terms_cover_every_literal_alternative(self):
        terms, whole = search_mod.fts_terms(r"(?i)^(?:content-security-policy|x-frame-options)$")
        self.assertEqual((terms, whole), (["content-security-policy", "x-frame-options"], True))
        terms, _ = search_mod.fts_terms(r"(?i)(?:api_?key|secret)")
        self.assertEqual(terms, ["api_key", "apikey", "secret"])
        for chapter in RULES["chapters"]:
            for rule in chapter["rules"]:
                if rule["kind"] in search_mod.FTS_KINDS:
                    self.assertTrue(search_mod.fts_terms(rule["pattern"])[0], rule["rule_id"])


class TagCloudTests(CandidateSearchCase):
    FILES = {
        "src/app/app.c": "#include <stdio.h>\n\nint main(int argc, char **argv)\n{\n  FILE *f = fopen(argv[1], \"r\");\n"
                         "  return f ? 0 : argc;\n}\n",
        "src/util/keys.c": "int derive(int seed)\n{\n  return seed * 31;\n}\n",
        "vendor/lib/k.c": "int k(void)\n{\n  return 1;\n}\n"}

    def component_map(self) -> dict:
        return {"functional_components": [
                    {"component_id": "util", "path_patterns": ["src/util/**"]},
                    {"component_id": "app", "path_patterns": ["src/app/**", "vendor/lib/**"]}],
                "tag_cloud": [{"tag": "crypto", "component_ids": ["util", "app"]},
                              {"tag": "file-io", "component_ids": ["app"]},
                              {"tag": "widgets", "component_ids": ["util"]}]}

    def test_tag_cloud_widens_scope_but_never_excludes(self):
        tree = self.tree(self.FILES)
        plain = self.run_search(tree.index())
        widened = self.run_search(tree.index(), tag_cloud=self.component_map())
        plain_ids = {row["candidate_id"] for row in plain["candidates"]}
        widened_ids = {row["candidate_id"] for row in widened["candidates"]}
        self.assertTrue(plain_ids < widened_ids)
        self.assertEqual(plain["excluded"], widened["excluded"])
        v11 = self.found(widened, "V11")
        for path in ("src/util/keys.c", "src/app/app.c"):
            row = v11[(path, "<module>")]
            self.assertEqual([(match["kind"], match["rule_id"]) for match in row["matches"]], [("tag_cloud", None)])
        # a file already a candidate in the chapter gets no extra file-level row; vendored stays out
        self.assertNotIn(("src/app/app.c", "<module>"), self.found(widened, "V5"))
        self.assertNotIn("vendor/lib/k.c", {row["file"] for row in widened["candidates"]})
        facility = next(row for row in widened["coverage"]["facilities"] if row["facility"] == "tag_cloud")
        self.assertIn("widgets", facility["detail"])
        self.assertNotIn("tag_cloud_unavailable", self.kinds(widened))

    def test_missing_tag_cloud_is_a_gap(self):
        result = self.run_search(self.tree(self.FILES).index())
        self.assertIn("tag_cloud_unavailable", self.kinds(result))


class SemanticIndexTests(CandidateSearchCase):
    def test_semantic_hits_are_dereferenced_and_only_widen(self):
        tree = self.tree(guard.HELLO)
        asked = []

        def semantic(text, *, limit):
            asked.append((text, limit))
            if text == "password verification and credential storage":
                return [{"file": "src/hello.c", "start_line": 13, "end_line": 15, "symbol": "open_input", "score": 0.71},
                        {"file": "src/gone.c", "start_line": 3, "end_line": 4, "symbol": "x", "score": 0.5},
                        {"file": "../etc/passwd", "start_line": 1, "end_line": 1, "symbol": "x", "score": 0.4},
                        {"file": "vendor/cjson/cJSON.c", "start_line": 6, "end_line": 6, "symbol": "cJSON_strdup", "score": 0.3}]
            return []

        plain = self.run_search(tree.index())
        result = self.run_search(tree.index(), semantic_index=semantic, source_root=tree.root)
        self.assertIn(("password verification and credential storage", search_mod.SEMANTIC_LIMIT), asked)
        self.assertIn(("session token creation and invalidation", search_mod.SEMANTIC_LIMIT), asked)
        row = self.found(result, "V6")[("src/hello.c", "open_input")]
        self.assertEqual([(match["kind"], match["rule_id"], match["line"]) for match in row["matches"]], [("semantic", None, 13)])
        self.assertEqual(row["file_sha256"], hashlib.sha256(guard.HELLO["src/hello.c"].encode("utf-8")).hexdigest())
        self.assertTrue({c["candidate_id"] for c in plain["candidates"]} < {c["candidate_id"] for c in result["candidates"]})
        self.assertIn(("V6", "vendor/cjson/cJSON.c", None), {(r["chapter_id"], r["file"], r["rule_id"]) for r in result["excluded"]})
        unresolved = [gap for gap in result["gaps"] if "did not dereference" in gap["statement"]]
        self.assertIn("src/gone.c:3", unresolved[0]["statement"])
        self.assertNotIn("semantic_index_absent", self.kinds(result))

    def test_semantic_hits_dereference_through_the_evidence_index(self):
        tree = self.tree(guard.HELLO)
        evidence = FakeEvidence(guard.HELLO)
        result = self.run_search(tree.index(), evidence_index=evidence.handle(), semantic_index=lambda text, *, limit: [
            {"file": "src/hello.c", "start_line": 21, "end_line": 21, "symbol": "copy_name", "score": 0.9}])
        self.assertIn(("src/hello.c", "copy_name"), self.found(result, "V7"))

    def test_absent_semantic_index_is_a_gap(self):
        result = self.run_search(self.tree(guard.HELLO).index())
        gap = next(gap for gap in result["gaps"] if gap["kind"] == "semantic_index_absent")
        self.assertTrue(gap["statement"].startswith("semantic-index-absent"))
        self.assertEqual(gap["chapter_ids"], CHAPTERS)


if __name__ == "__main__":
    unittest.main()
