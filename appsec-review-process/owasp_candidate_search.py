#!/usr/bin/env python3
"""Deterministic ``04-owasp-candidate-search`` (ADR-0034): per-ASVS-chapter candidate functions.

Python decides the search universe; it never decides applicability. For each ASVS 5.0.0 chapter
V1..V17 every rule of ``data/owasp-asvs/category-rules-v1.json`` is evaluated over the accepted
code index, each from the one source the rule-table schema names (``calls_to``: ``calls.callee_name``
and ``ts_calls.callee`` last segment; ``symbol_regex``: ``methods.name/qualified``, ``ts_functions.name``
and the index's ``names`` FTS rows for IR functions and debug symbols; ``identifier_regex``:
``identifiers``; ``literal_regex``: ``literals``; ``import_regex``: ``imports``; ``sast_rule_ids``: the
accepted ``02-source-sast`` leads; ``entry_point``: ``methods``/``ts_functions`` named in
``dep_reachability_engines.ENTRY_POINT_SOURCES``, or joined by ``exports.method_id``). A hit counts only
in a file whose language the rule lists. It becomes a candidate at its enclosing function (the
``methods`` row, its caller id for calls, else the innermost ``ts_functions`` span, else a ``<module>``
candidate at the hit line); a function may be a candidate in several chapters. V2 widens from its seed
rules along resolved calls (``propagation``). Hits under the table's exclusion globs are published in
``excluded`` with their reason, never dropped. The search over-collects; 04-owasp-participation
classifies.

Three optional facilities only widen the candidate set; each missing one is a gap, never a failure:

* ``evidence_index`` (``02-evidence-index`` FTS5, through the bounded ``evidence_store.query`` paths):
  every ``literal_regex``/``identifier_regex``/``import_regex`` pattern is expanded to its literal
  alternatives and run as literal FTS terms over the full source text. Rows are locators: each is
  dereferenced (``read``) to the snapshot line, the rule's regex re-applied to that line's string
  literals / identifier tokens / text, and the line attached to its enclosing function (kind ``fts``).
  It reaches strings outside call arguments, config tables and files without a grammar (Kotlin, Swift,
  Objective-C, Scala). A term that returns the result cap, files the FTS did not index (binary, over a
  limit, excluded) and whole-token matching are gaps.
* ``semantic_index`` (``02-semantic-recall-index``; ``query(text, *, limit)`` -> ``[{file, start_line,
  end_line, symbol, score}]``): each chapter's ``semantic_queries`` are run with a fixed limit; hits are
  dereferenced to snapshot bytes (``source_root``, else the evidence index) and attached to their
  enclosing function (kind ``semantic``). Absent: a ``semantic_index_absent`` gap.
* ``tag_cloud`` (the ``01-component-characterization`` component map: model metadata): a tag in
  ``TAG_CHAPTERS`` adds a file-level ``<module>`` candidate (kind ``tag_cloud``) for each file of a
  tagged component that has no candidate in that chapter yet. It never removes or excludes anything;
  a tagged file under an exclusion glob stays excluded (counted in ``coverage.facilities``).

What the index cannot answer is a gap, never zero hits (AGENTS.md rule 2):

* a language present in the snapshot that the table has no rules for, that tree-sitter has no grammar
  for (``no-grammar``) or did not parse and the CPG did not index (``grammar-unavailable``,
  ``max-files``, ``file-too-large``, ``unreadable``) is an ``unsearched_languages`` row; coverage is
  then incomplete for every chapter (FTS hits there widen, they do not complete the search);
* a rule whose facet the index lacks for a present language (``identifiers``/``literals`` and call
  propagation come from the CPG only, ``imports`` from tree-sitter only, ``exported_symbol`` from the
  binary export tables only, entry names ``ENTRY_POINT_SOURCES`` does not list) is
  ``rule_without_index_support`` and makes that chapter's coverage incomplete;
* a searched language no rule of a chapter covers makes that chapter incomplete
  (``language_not_searched``) unless the chapter's ``languages_not_applicable`` gives a reason (a CLI
  or library may be not applicable to some chapters: shell has no browser, session or OAuth surface);
  such a language stays visible as a ``not_applicable_language`` search-basis row with its reason and
  file count. A language without rules is unsearched unless every chapter exempts it;
* limits that leave the search a lower bound are published as gaps without changing coverage:
  literals are call-argument strings only, exports are binary export tables only, Rust ``unsafe``
  blocks are not selected by any rule, shell rows are command and function names only (no
  arguments or assignments), JSON data files no chapter rule searches, tree-sitter rows truncated,
  CPG coverage gaps the index recorded, an empty ``names`` table (no IR-function or debug-symbol
  rows), source SAST not accepted (``sast_hits`` None), and every unavailable widening facility.

An empty index makes every chapter a gap, never "no candidates". ``coverage.complete`` is the
language-level answer; each chapter's ``coverage_complete`` is that AND its own rule support, and is
what a zero-candidate chapter must be read against. ``coverage.facilities`` lists every facility.

Output is sorted and stable: chapters V1..V17 with their search basis in rule-table order (then
``fts``, ``semantic``, ``tag_cloud``, ``not_applicable_language`` by language), candidates by (chapter, file, start_line, symbol), excluded by
(chapter, file, line, rule, symbol), gaps by (kind, gap_id); ids are content hashes.

CLI (the job wrapper binds accepted inputs and calls ``search``; this entry runs it on plain files)::

    python3 owasp_candidate_search.py --index code-index.sqlite [--rules category-rules-v1.json]
        [--source-sast source-sast.json] [--treesitter-ast treesitter-ast.json]
        [--evidence-run-id RUN_ID] [--component-map component-map.json]
        [--semantic-index INDEX_ROOT] [--source-root SNAPSHOT] [--output out.json]

``--source-sast`` is the accepted ``02-source-sast`` result (its ``leads``) or a JSON list of
``{rule_id, path, start_line}``; omitted means SAST was not accepted (a gap). ``--treesitter-ast``
is the accepted ``02-treesitter-ast`` document (its ``gaps``) or a JSON list of gaps; omitted means
none. ``--evidence-run-id`` binds the run's accepted ``02-evidence-index`` (``evidence_index_for``).
``--component-map`` is the accepted component purpose map. ``--semantic-index`` is the accepted
``02-semantic-recall-index`` root queried through ``semantic_recall_index.query``. The ``search``
members (``coverage, chapters, candidates, excluded, gaps``) are written as JSON (stdout without
``--output``); ``document`` wraps them into the published ``owasp-candidate-search.schema.json`` shape.
Exit 2 with ``OWASP_CANDIDATE_SEARCH_BLOCKED`` on bad input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import re._parser as _sre
import sqlite3
import sys
from typing import Any, Callable, Iterable

import code_index
from component_characterization import _glob_regex
import dep_reachability_engines

SCHEMA = "appsec-review/owasp-candidate-search/1.0"
JOB = "04-owasp-candidate-search"
RULES_PATH = "data/owasp-asvs/category-rules-v1.json"
CHAPTERS = tuple(f"V{n}" for n in range(1, 18))
MODULE = "<module>"
DETAIL_LIMIT = 500
FTS_LIMIT = 50          # evidence_query_results_max: the bounded query() cap per term
READ_WINDOW = 50        # lines per bounded query("read")
SEMANTIC_LIMIT = 10     # hits per semantic query
EXPANSION_CAP = 256     # literal alternatives per regex before it counts as unexpandable
# Index languages that are data, not program source: present but nothing to search.
NON_PROGRAM_LANGUAGES = frozenset({"json"})
# Program languages without a tree-sitter grammar here, named for coverage rows and FTS hits.
SUFFIX_LANGUAGES = {".kt": "kotlin", ".kts": "kotlin", ".swift": "swift", ".m": "objective-c",
                    ".mm": "objective-cpp", ".scala": "scala", ".sc": "scala", ".dart": "dart", ".lua": "lua",
                    ".pl": "perl", ".pm": "perl", ".r": "r", ".groovy": "groovy", ".gradle": "groovy"}
# Index language -> dep_reachability_engines.ENTRY_POINT_SOURCES key.
ENGINE = {"c": "cpp", "cpp": "cpp", "c_sharp": "csharp", "go": "go", "java": "java", "javascript": "javascript",
          "typescript": "javascript", "tsx": "javascript", "python": "python", "rust": "rust", "php": "php",
          "ruby": "ruby"}
FRAMEWORK_HANDLERS = frozenset({"ServeHTTP", "doGet", "doPost", "doPut", "doDelete", "service"})
# Index facet each rule kind reads (per language): cpg = the CPG rows, treesitter = the AST rows.
FACETS = {"calls_to": ("cpg", "treesitter"), "symbol_regex": ("cpg", "treesitter"), "identifier_regex": ("cpg",),
          "literal_regex": ("cpg",), "import_regex": ("treesitter",), "entry_point": ("cpg", "treesitter"),
          "propagation": ("cpg",)}
FTS_KINDS = {"literal_regex": "literal", "identifier_regex": "identifier", "import_regex": "import"}
TREESITTER_TRUNCATED = {"max-files", "file-too-large"}
TREESITTER_UNPARSED = {"grammar-unavailable", "unreadable"}
NAME_KINDS = ("ir-function", "debug-symbol")
# Component tag-cloud tags (01-component-characterization, model metadata) -> chapters they widen.
# Exact tags only; a tag widens, it never narrows or excludes.
TAG_CHAPTERS: dict[str, tuple[str, ...]] = {
    "encoding": ("V1",), "sanitization": ("V1",), "injection": ("V1",), "xml": ("V1",), "serialization": ("V1",),
    "deserialization": ("V1",), "templating": ("V1",), "sql": ("V1",), "database": ("V1",), "shell": ("V1",),
    "parsing": ("V1", "V2"), "parser": ("V1", "V2"), "input-validation": ("V2",), "validation": ("V2",),
    "cli": ("V2",), "command-line": ("V2",), "argument-parsing": ("V2",),
    "web": ("V3", "V4"), "frontend": ("V3",), "html": ("V3",), "browser": ("V3",), "cookie": ("V3", "V7"),
    "http": ("V4", "V12"), "api": ("V4",), "rest": ("V4",), "graphql": ("V4",), "server": ("V4",),
    "websocket": ("V4", "V17"), "file-io": ("V5",), "filesystem": ("V5",), "files": ("V5",), "upload": ("V5",),
    "archive": ("V5",), "compression": ("V5",), "authentication": ("V6",), "auth": ("V6", "V8"), "login": ("V6",),
    "password": ("V6",), "credentials": ("V6", "V13"), "session": ("V7",), "authorization": ("V8",),
    "access-control": ("V8",), "permissions": ("V8",), "privilege": ("V8",), "jwt": ("V9",), "token": ("V9",),
    "tokens": ("V9",), "oauth": ("V10",), "oidc": ("V10",), "sso": ("V10",), "crypto": ("V11",),
    "cryptography": ("V11",), "encryption": ("V11",), "random": ("V11",), "hashing": ("V11",), "tls": ("V12",),
    "ssl": ("V12",), "network": ("V12",), "networking": ("V12",), "socket": ("V12",), "sockets": ("V12",),
    "configuration": ("V13",), "config": ("V13",), "secrets": ("V13", "V14"), "environment": ("V13",),
    "privacy": ("V14",), "pii": ("V14",), "data-protection": ("V14",), "concurrency": ("V15",),
    "threading": ("V15",), "memory": ("V15",), "plugin": ("V15",), "ffi": ("V15",), "logging": ("V16",),
    "audit": ("V16",), "error-handling": ("V16",), "errors": ("V16",), "webrtc": ("V17",), "media": ("V17",)}
_SUFFIX_COUNT = re.compile(r"(\d+) file\(s\) with suffix (\S+)")
_STRING = re.compile(r'"((?:[^"\\\n]|\\.){0,400})"|\'((?:[^\'\\\n]|\\.){0,400})\'')
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")
# A source line that is an import as the tree-sitter import rows record it (FTS import_regex re-check).
_IMPORT_LINE = re.compile(r"^\s*(?:#\s*(?:include|import)\b|@?import\b|from\s+\S+\s+import\b|use\s|using\s|require(?:_once)?\b"
                          r"|include(?:_once)?\b|extern\s+crate\b)|\brequire\s*\(|\bimport\s*\("
                          r"|^\s*(?:[\w.]+\s+)?\"[^\"]+\"\s*$")   # the last: a Go import-block entry
_BREAK = "\0"


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _clip(text: Any) -> str:
    return str(text or "")[:DETAIL_LIMIT]


def _last(name: str | None) -> str:
    return re.split(r"\.|::|->|:|#", name or "")[-1]


def _suffix_language(suffix: str) -> str:
    return SUFFIX_LANGUAGES.get(suffix.lower(), f"unknown{suffix.lower()}" if suffix else "unknown")


def _language(path: str, files: dict[str, tuple]) -> str | None:
    row = files.get(path)
    return ((row[1] if row and row[1] else None) or code_index.language_of(path)
            or SUFFIX_LANGUAGES.get(PurePosixPath(path).suffix.lower()))


def _relative(path: Any) -> str | None:
    """A snapshot-relative POSIX path, or None for anything absolute, empty or escaping."""
    if not isinstance(path, str) or not path or path.startswith(("/", "\\")) or "\\" in path:
        return None
    parts = path.split("/")
    return None if any(part in ("", ".", "..") for part in parts) else path


class _Index:
    """The accepted code index as read-only lookups: files, function units, distinct column values."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.db = connection
        self.files = {path: (sha, language, source or "") for path, sha, language, source in
                      connection.execute("SELECT path, sha256, language, source FROM files ORDER BY path")}
        try:
            self.meta = {key: json.loads(value) for key, value in connection.execute("SELECT key, value FROM meta")}
        except (sqlite3.Error, ValueError):
            self.meta = {}
        self.methods: dict[int, tuple] = {}
        self.by_full: dict[str, int] = {}
        self.units: dict[str, list[tuple]] = {}
        for mid, full, name, qualified, path, start, end, span, sha in connection.execute(
                "SELECT id, full_name, name, qualified, file, start_line, end_line, span_source, file_sha256 "
                "FROM methods WHERE is_external = 0 ORDER BY id"):
            if not path or not start or not name or name.startswith(("<", ":")):
                continue
            unit = (path, qualified or name, int(start), int(max(end or start, start)),
                    "treesitter" if span == "treesitter" else "cpg-first-line", sha, mid, name)
            self.methods[mid] = unit
            self.by_full[full] = mid
            self.units.setdefault(path, []).append(unit)
        self.ts: dict[str, list[tuple]] = {}
        for path, name, start, end in connection.execute(
                "SELECT file, name, start_line, end_line FROM ts_functions ORDER BY file, start_line, end_line, name"):
            if path and name and start:
                self.ts.setdefault(path, []).append((path, name, int(start), int(max(end or start, start)),
                                                     "treesitter", None, None, _last(name)))
        self._distinct: dict[tuple[str, str], list[str]] = {}
        self.names_used = 0

    def facet(self, language: str, facet: str) -> bool:
        if facet == "treesitter" and (self.meta.get("capabilities") or {}).get("treesitter") is False:
            return False
        return any(language == lang and facet in source for _, lang, source in self.files.values())

    def distinct(self, table: str, column: str, where: str = "") -> list[str]:
        key = (table, column + where)
        if key not in self._distinct:
            self._distinct[key] = [value for (value,) in self.db.execute(
                f"SELECT DISTINCT {column} FROM {table} WHERE {column} IS NOT NULL {where} ORDER BY {column}")]
        return self._distinct[key]

    def rows(self, table: str, column: str, values: Iterable[str], select: str, where: str = "") -> list[tuple]:
        values, out = sorted(set(values)), []
        for start in range(0, len(values), 500):
            chunk = values[start:start + 500]
            out += self.db.execute(f"SELECT {select} FROM {table} WHERE {column} IN ({','.join('?' * len(chunk))}) "
                                   f"{where}", chunk).fetchall()
        return out

    def sha(self, path: str, unit_sha: str | None) -> str | None:
        return unit_sha or (self.files.get(path) or (None,))[0]

    def enclose(self, path: str, line: int, method_id: int | None = None) -> tuple:
        """The function unit a hit at ``path:line`` belongs to (caller id first, innermost span next)."""
        if method_id in self.methods:
            return self.methods[method_id]
        for pool in (self.units.get(path, ()), self.ts.get(path, ())):
            inside = [unit for unit in pool if unit[2] <= line <= unit[3]]
            if inside:
                return max(inside, key=lambda unit: (unit[2], -unit[3], unit[1]))
        return (path, MODULE, line, line, "module-scope", None, None, MODULE)


class _Evidence:
    """The accepted 02-evidence-index through its bounded ``query`` paths only (search, read)."""

    def __init__(self, handle: dict[str, Any]) -> None:
        self.query: Callable[..., dict[str, Any]] = handle["query"]
        self.manifest = handle.get("manifest")
        self.limit = max(1, min(int(handle.get("limit") or FTS_LIMIT), FTS_LIMIT))
        self.windows: dict[tuple[str, int], tuple[str | None, list[str]] | None] = {}
        self.failures: list[str] = []
        self.queries = 0

    def search(self, text: str) -> list[dict[str, Any]]:
        self.queries += 1
        try:
            return list(self.query("search", text=text, limit=self.limit)["results"])
        except Exception as exc:  # noqa: BLE001 - a failed bounded query is a recorded gap
            self.failures.append(_clip(f"search {text!r}: {type(exc).__name__}: {exc}"))
            return []

    def lines(self, path: str, start: int, end: int) -> tuple[str | None, dict[int, str]]:
        """``(file sha256, {line: text})`` for ``start..end`` of an indexed text file."""
        sha, out = None, {}
        first = ((max(start, 1) - 1) // READ_WINDOW) * READ_WINDOW + 1
        for window in range(first, max(end, start) + 1, READ_WINDOW):
            if (path, window) not in self.windows:
                try:
                    row = self.query("read", path=path, start=window, limit=READ_WINDOW)["results"][0]
                    self.windows[(path, window)] = (row.get("sha256"), row["excerpt"].split("\n"))
                except Exception as exc:  # noqa: BLE001
                    self.failures.append(_clip(f"read {path}:{window}: {type(exc).__name__}: {exc}"))
                    self.windows[(path, window)] = None
            cached = self.windows[(path, window)]
            if cached is None:
                continue
            sha = sha or cached[0]
            for offset, text in enumerate(cached[1]):
                if start <= window + offset <= end:
                    out[window + offset] = text
        return sha, out


def evidence_index_for(run_id: str) -> dict[str, Any]:
    """The run's accepted 02-evidence-index as a ``search`` ``evidence_index`` handle (validated once)."""
    import evidence_store
    from execution_state import read_json
    pointer, attempt = evidence_store.validate(run_id, fresh=True)

    def query(action: str, text: str = "", path: str = "", limit: int = 10, start: int = 1) -> dict[str, Any]:
        return evidence_store.query(run_id, action, text, path, limit, start, fresh=False)
    return {"query": query, "manifest": read_json(attempt / "manifest.json"), "attempt_id": pointer["attempt_id"]}


def _expand(items: Iterable, cap: int = EXPANSION_CAP) -> list[str]:
    """Literal alternatives of a parsed regex; ``_BREAK`` marks a non-literal stretch."""
    out = [""]
    for op, av in items:
        if op is _sre.LITERAL:
            alternatives = [chr(av)]
        elif op in (_sre.AT, _sre.ASSERT, _sre.ASSERT_NOT):
            continue
        elif op is _sre.IN and len(av) == 1 and av[0][0] is _sre.LITERAL:
            alternatives = [chr(av[0][1])]
        elif op is _sre.SUBPATTERN:
            alternatives = _expand(av[-1], cap)
        elif op is _sre.BRANCH:
            alternatives = [text for branch in av[1] for text in _expand(branch, cap)]
        elif op in (_sre.MAX_REPEAT, _sre.MIN_REPEAT) and (av[0], av[1]) in ((0, 1), (1, 1)):
            alternatives = ([""] if av[0] == 0 else []) + _expand(av[2], cap)
        else:
            alternatives = [_BREAK]
        out = [left + right for left in out for right in alternatives]
        if len(out) > cap:
            return [_BREAK]
    return out


def fts_terms(pattern: str) -> tuple[list[str], bool]:
    """Literal FTS texts that every match of ``pattern`` contains (one per alternative, fragments
    AND-ed), and whether every alternative yielded a searchable term."""
    texts, whole = set(), True
    for alternative in _expand(list(_sre.parse(pattern))):
        fragments = [part.strip() for part in alternative.split(_BREAK)]
        fragments = [part for part in fragments if len(re.findall(r"[A-Za-z0-9]", part)) >= 2]
        if not any(len(re.findall(r"[A-Za-z0-9]", part)) >= 3 for part in fragments):
            whole = False
            continue
        texts.add(" ".join(fragments))
    return sorted(texts), whole


def _line_values(kind: str, text: str) -> list[str]:
    if kind == "literal_regex":
        return [first or second for first, second in _STRING.findall(text) if first or second]
    if kind == "identifier_regex":
        return sorted(set(_IDENTIFIER.findall(text)))
    return [text.strip()] if _IMPORT_LINE.search(text) else []


def _exclusion(rules: dict[str, Any]):
    table = [(row["reason"], row["exclusion_id"], glob, _glob_regex(glob)) for row in rules.get("exclusions", [])
             for glob in row["path_globs"]]
    cache: dict[str, tuple[str, str] | None] = {}

    def excluded(path: str) -> tuple[str, str] | None:
        if path not in cache:
            cache[path] = next(((reason, f"path matches {glob} (exclusion {ident})")
                                for reason, ident, glob, pattern in table if pattern.match(path)), None)
        return cache[path]
    return excluded


def _entry_names(language: str, entry: str) -> frozenset[str]:
    names = set(dep_reachability_engines.ENTRY_POINT_SOURCES.get(ENGINE.get(language, ""), {}).get("names", ()))
    return frozenset(names & FRAMEWORK_HANDLERS if entry == "framework_handler" else names - FRAMEWORK_HANDLERS)


def _sast_match(lead_rule: str, wanted: set[str]) -> str | None:
    for rule in sorted(wanted):
        if lead_rule == rule or lead_rule.endswith("." + rule):
            return rule
    return None


def _hits(index: _Index, rule: dict[str, Any], sast_hits: list[dict[str, Any]] | None) -> list[tuple]:
    """Raw hits of one rule: (file, line, detail, unit). Language filtering is the caller's."""
    kind, out = rule["kind"], []
    if kind == "calls_to":
        names, seen = set(rule["names"]), set()
        for path, line, name, caller in sorted(index.rows("calls", "callee_name", names, "file, line, callee_name, caller_id"),
                                               key=lambda row: (row[0] or "", row[1] or 0, row[2], row[3] or 0)):
            if path and line and (path, line, name) not in seen:
                seen.add((path, line, name))
                out.append((path, line, f"call {name}", index.enclose(path, line, caller)))
        callees = [value for value in index.distinct("ts_calls", "callee") if _last(value) in names]
        for path, line, callee in sorted(index.rows("ts_calls", "callee", callees, "file, line, callee")):
            if path and line and (path, line, _last(callee)) not in seen:
                seen.add((path, line, _last(callee)))
                out.append((path, line, f"call {_clip(callee)}", index.enclose(path, line)))
    elif kind == "symbol_regex":
        pattern, units = re.compile(rule["pattern"]), set()
        for unit in sorted(index.methods.values(), key=lambda u: (u[0], u[2], u[1])):
            if pattern.search(unit[7]) or pattern.search(unit[1]):
                units.add((unit[0], unit[2]))
                out.append((unit[0], unit[2], f"symbol {_clip(unit[1])}", unit))
        named = {(unit[0], unit[7]) for unit in index.methods.values()}
        for path in sorted(index.ts):
            for unit in index.ts[path]:
                if pattern.search(unit[1]) and (path, unit[2]) not in units and not any(
                        method[2] <= unit[2] <= method[3] and method[7] == unit[7] for method in index.units.get(path, ())):
                    named.add((path, unit[7]))
                    out.append((path, unit[2], f"symbol {_clip(unit[1])}", unit))
        # Wider than the method tables: IR functions and debug symbols from the index's names FTS rows.
        where = f"AND kind IN ({','.join(repr(kind) for kind in NAME_KINDS)})"
        try:
            values = [value for value in index.distinct("names", "name", where) if pattern.search(value)]
            rows = index.rows("names", "name", values, "name, file, line, kind", where)
        except sqlite3.Error:
            rows = []
        for name, path, line, label in sorted(rows, key=lambda row: (row[1] or "", int(row[2] or 0), row[0], row[3])):
            if path and line and (path, _last(name)) not in named:
                named.add((path, _last(name)))
                index.names_used += 1
                out.append((path, int(line), f"{label} {_clip(name)}", index.enclose(path, int(line))))
    elif kind in ("identifier_regex", "literal_regex", "import_regex"):
        table, column, select, label = {
            "identifier_regex": ("identifiers", "name", "name, file, line, NULL", "identifier"),
            "literal_regex": ("literals", "value", "value, file, line, caller_full_name", "literal"),
            "import_regex": ("imports", "text", "text, file, line, NULL", "import")}[kind]
        pattern = re.compile(rule["pattern"])
        values = [value for value in index.distinct(table, column) if pattern.search(value)]
        seen = set()
        for value, path, line, caller in sorted(index.rows(table, column, values, select),
                                                key=lambda row: (row[1] or "", row[2] or 0, row[0], row[3] or "")):
            if path and line and (path, line, value) not in seen:
                seen.add((path, line, value))
                out.append((path, line, f"{label} {_clip(value)}", index.enclose(path, line, index.by_full.get(caller or ""))))
    elif kind == "sast_rule_ids":
        wanted, seen = set(rule["sast_rule_ids"]), set()
        for lead in sorted(sast_hits or [], key=lambda row: (row.get("path") or "", row.get("start_line") or 0,
                                                             row.get("rule_id") or "")):
            matched = _sast_match(str(lead.get("rule_id") or ""), wanted)
            path, line = _relative(lead.get("path")), lead.get("start_line")
            if matched and path and isinstance(line, int) and line >= 1 and (path, line, matched) not in seen:
                seen.add((path, line, matched))
                out.append((path, line, f"sast {_clip(lead['rule_id'])}", index.enclose(path, line)))
    elif kind == "entry_point" and rule["entry"] == "exported_symbol":
        for (mid,) in index.db.execute("SELECT DISTINCT method_id FROM exports WHERE method_id IS NOT NULL ORDER BY method_id"):
            unit = index.methods.get(mid)
            if unit:
                out.append((unit[0], unit[2], f"entry exported_symbol {_clip(unit[1])}", unit))
    elif kind == "entry_point":
        seen = set()
        for pool in (sorted(index.methods.values(), key=lambda u: (u[0], u[2], u[1])),
                     [unit for path in sorted(index.ts) for unit in index.ts[path]]):
            for unit in pool:
                language = _language(unit[0], index.files)
                if language and unit[7] in _entry_names(language, rule["entry"]) and (unit[0], unit[7]) not in seen:
                    seen.add((unit[0], unit[7]))
                    out.append((unit[0], unit[2], f"entry {rule['entry']} {_clip(unit[1])}", unit))
    return out


def _fts_hits(index: _Index, evidence: _Evidence, rule: dict[str, Any], truncated: list[str],
              unsearchable: list[str]) -> list[tuple]:
    """FTS hits of a literal/identifier/import rule, each dereferenced and re-checked on its line:
    (file, line, detail, unit, file sha256)."""
    kind, pattern = rule["kind"], re.compile(rule["pattern"])
    texts, whole = fts_terms(rule["pattern"])
    if not whole:
        unsearchable.append(rule["rule_id"])
    rows: dict[tuple[str, int, int], str | None] = {}
    for text in texts:
        results = evidence.search(text)
        if len(results) >= evidence.limit:
            truncated.append(f"{rule['rule_id']}: {text!r}")
        for row in results:
            path = row.get("path") or ""
            if path.startswith("source/") and isinstance(row.get("start_line"), int):
                rows[(path, row["start_line"], int(row.get("end_line") or row["start_line"]))] = row.get("sha256")
    out, seen = [], set()
    for (path, start, end), row_sha in sorted(rows.items()):
        relative = _relative(path[len("source/"):])
        if relative is None:
            continue
        sha, lines = evidence.lines(path, start, end)
        for number in sorted(lines):
            for value in _line_values(kind, lines[number]):
                if pattern.search(value) and (relative, number, value) not in seen:
                    seen.add((relative, number, value))
                    out.append((relative, number, f"fts {FTS_KINDS[kind]} {_clip(value)}", index.enclose(relative, number),
                                sha or row_sha))
    return out


def _propagate(index: _Index, seeds: list[tuple], propagation: dict[str, Any]) -> list[tuple]:
    """(seed rule id, call file, call line, detail, unit) along resolved calls, up to max_depth hops."""
    callees = propagation["direction"] == "callees"
    seen = {unit[6] for _, unit in seeds if unit[6] is not None}
    frontier = sorted({(unit[6], rule_id, unit[1]) for rule_id, unit in seeds if unit[6] is not None})
    out = []
    for depth in range(1, propagation["max_depth"] + 1):
        following = set()
        for mid, rule_id, origin in frontier:
            query = ("SELECT callee_id, file, line FROM calls WHERE caller_id = ? AND callee_id IS NOT NULL "
                     "AND resolution NOT IN ('escape', 'external') ORDER BY file, line, callee_id") if callees else (
                     "SELECT caller_id, file, line FROM calls WHERE callee_id = ? AND caller_id IS NOT NULL "
                     "AND resolution NOT IN ('escape', 'external') ORDER BY file, line, caller_id")
            for other, path, line in index.db.execute(query, (mid,)):
                unit = index.methods.get(other)
                if unit is None or other in seen or not path or not line:
                    continue
                seen.add(other)
                following.add((other, rule_id, origin))
                relation = "callee" if callees else "caller"
                out.append((rule_id, path, line, _clip(f"{relation} of {origin} (depth {depth})"), unit))
        frontier = sorted(following)
    return out


def _snapshot_line(path: str, line: int, source_root: Path | None, evidence: _Evidence | None) -> str | None:
    """The sha256 of the snapshot file holding ``path:line`` (dereferenced), or None."""
    if source_root is not None:
        root = Path(source_root).resolve()
        target = (root / path).resolve()
        if root not in target.parents or not target.is_file():
            return None
        data = target.read_bytes()
        if line > len(data.splitlines()):
            return None
        return hashlib.sha256(data).hexdigest()
    if evidence is not None:
        sha, lines = evidence.lines("source/" + path, line, line)
        return sha if line in lines else None
    return None


def _gap(kind: str, chapters: Iterable[str], statement: str) -> dict[str, Any]:
    chapter_ids = [chapter for chapter in CHAPTERS if chapter in set(chapters)]
    return {"gap_id": "gap-" + _sha([kind, chapter_ids, statement])[:20], "kind": kind, "chapter_ids": chapter_ids,
            "statement": statement[:1000]}


def _not_applicable(rules: dict[str, Any]) -> dict[str, dict[str, str]]:
    """{chapter: {language: reason}} from the table's per-chapter ``languages_not_applicable``."""
    return {chapter["chapter_id"]: dict(chapter.get("languages_not_applicable") or {}) for chapter in rules["chapters"]}


def _unsearched(index: _Index, rules: dict[str, Any], treesitter_gaps: Iterable[dict[str, Any]], excluded,
                gaps: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]], dict[str, int]]:
    table_languages = set(rules["languages"])
    exempt = _not_applicable(rules)
    counts: dict[str, int] = {}
    for path, (_, language, _) in index.files.items():
        if path.startswith("<") or excluded(path):
            continue
        name = language or _suffix_language(PurePosixPath(path).suffix)
        counts[name] = counts.get(name, 0) + 1
    present = {name: count for name, count in counts.items() if name not in NON_PROGRAM_LANGUAGES}
    rows: dict[tuple[str, str], int] = {}
    for name, count in present.items():
        # Without rules a language is unsearched unless every chapter exempts it with a reason.
        if name not in table_languages and not all(name in exempt.get(chapter, {}) for chapter in CHAPTERS):
            rows[(name, "no_rules_for_language")] = count
    cpg_only, truncated = 0, []
    for gap in treesitter_gaps or ():
        kind, path, detail = gap.get("kind"), gap.get("path"), str(gap.get("detail") or "")
        if kind == "no-grammar":
            match = _SUFFIX_COUNT.search(detail)
            if match:
                key = (_suffix_language(match.group(2)), "no_grammar")
                rows[key] = rows.get(key, 0) + int(match.group(1))
        elif kind == "rows-truncated":
            truncated.append(f"{path}: {detail}")
        elif (kind in TREESITTER_TRUNCATED or kind in TREESITTER_UNPARSED) and path:
            if excluded(path):
                continue
            if "cpg" in (index.files.get(path) or (None, None, ""))[2]:
                cpg_only += 1
                continue
            language = code_index.language_of(path) or _suffix_language(PurePosixPath(path).suffix)
            if language in NON_PROGRAM_LANGUAGES:
                continue
            key = (language, "index_truncated" if kind in TREESITTER_TRUNCATED else "not_indexed")
            rows[key] = rows.get(key, 0) + 1
        elif kind not in ("grammar-unavailable", "no-grammar") and kind:
            gaps.append(_gap("index_incomplete", CHAPTERS, _clip(f"tree-sitter gap {kind}: {path or ''} {detail}")))
    if truncated:
        gaps.append(_gap("rows_truncated", CHAPTERS, f"tree-sitter capped rows in {len(truncated)} file(s); functions, calls "
                         f"or imports past the cap are not indexed: " + "; ".join(sorted(truncated)[:10])))
    if cpg_only:
        gaps.append(_gap("index_incomplete", CHAPTERS, f"{cpg_only} file(s) were not parsed by tree-sitter and are "
                         "searched through the CPG only (no imports, first-line spans)"))
    unsearched = [{"language": language, "file_count": count, "reason": reason}
                  for (language, reason), count in sorted(rows.items())]
    for row in unsearched:
        missing = (f"; rule table {rules.get('rules_id')} {rules.get('version')} has no {row['language']} rule and no "
                   f"languages_not_applicable reason for it in any chapter, so its {row['language']} rules for "
                   f"V1..V17 are missing" if row["reason"] == "no_rules_for_language" else "")
        gaps.append(_gap("language_not_searched", CHAPTERS, f"{row['file_count']} {row['language']} file(s) not "
                         f"searched by the code index ({row['reason']}){missing}: any chapter may have code there"))
    searched = sorted(name for name in present if name in table_languages)
    return searched, unsearched, counts


def _tagged_files(index: _Index, tag_cloud: dict[str, Any]) -> tuple[dict[str, list[tuple[str, str, str]]], list[str]]:
    """{chapter: [(file, component id, tag)]} from the component map's tag cloud, and unmapped tags."""
    patterns = {row.get("component_id"): [_glob_regex(glob) for glob in row.get("path_patterns") or []
                                          if isinstance(glob, str) and glob]
                for row in tag_cloud.get("functional_components") or [] if isinstance(row, dict)}
    out: dict[str, set[tuple[str, str, str]]] = {}
    unmapped = []
    for item in tag_cloud.get("tag_cloud") or []:
        tag = item.get("tag") if isinstance(item, dict) else None
        if not isinstance(tag, str):
            continue
        chapters = TAG_CHAPTERS.get(tag)
        if not chapters:
            unmapped.append(tag)
            continue
        for component in sorted(set(item.get("component_ids") or [])):
            files = [path for path in index.files if any(regex.match(path) for regex in patterns.get(component, []))]
            for chapter in chapters:
                out.setdefault(chapter, set()).update((path, component, tag) for path in files)
    return {chapter: sorted(rows) for chapter, rows in out.items()}, sorted(set(unmapped))


def search(index: sqlite3.Connection, rules: dict[str, Any], *, sast_hits: list[dict[str, Any]] | None,
           treesitter_gaps: Iterable[dict[str, Any]], evidence_index: dict[str, Any] | None = None,
           tag_cloud: dict[str, Any] | None = None, semantic_index: Callable[..., list[dict[str, Any]]] | None = None,
           source_root: Path | None = None) -> dict[str, Any]:
    """Evaluate every chapter's rules over the open code index and widen with the optional facilities.

    ``evidence_index`` is ``{"query": evidence_store.query-shaped callable (action, text=, path=, limit=,
    start=), "manifest": the accepted manifest}`` (``evidence_index_for``); ``tag_cloud`` the accepted
    component map; ``semantic_index`` a ``query(text, *, limit)`` callable; ``source_root`` the snapshot
    semantic hits are dereferenced against (else the evidence index). See the module docstring."""
    view, excluded_path = _Index(index), _exclusion(rules)
    evidence = _Evidence(evidence_index) if evidence_index else None
    gaps: list[dict[str, Any]] = []
    searched, unsearched, file_counts = _unsearched(view, rules, treesitter_gaps, excluded_path, gaps)
    exempt = _not_applicable(rules)
    empty = not view.files
    if empty:
        gaps.append(_gap("index_incomplete", CHAPTERS, "the code index lists no files: nothing was searched, so no "
                         "chapter can be reported as having no candidates"))
    if view.files and not any(view.facet(language, "treesitter") for language in searched):
        gaps.append(_gap("treesitter_unavailable", CHAPTERS, "no indexed file has tree-sitter rows: import rules cannot "
                         "run and spans are CPG first lines"))
    for item in (view.meta.get("gaps") or []):
        if isinstance(item, str) and item.startswith("cpg-coverage-gap:"):
            gaps.append(_gap("index_incomplete", CHAPTERS, _clip(f"code index recorded {item}")))
    complete = not empty and not unsearched
    present = set(searched)
    table_languages = set(rules["languages"])
    widening_languages = set(SUFFIX_LANGUAGES.values())
    candidates: dict[tuple, dict[str, Any]] = {}
    excluded: dict[tuple, dict[str, Any]] = {}
    incomplete: set[str] = set()
    chapters, literal_chapters, sast_chapters, export_chapters = [], set(), set(), set()
    fts_truncated, fts_unsearchable, fts_chapters = [], [], set()
    semantic_unresolved, semantic_failures, semantic_hits, tag_hits = [], [], 0, 0
    tag_skipped: set[str] = set()
    data_chapters: dict[str, set[str]] = {}

    def place(chapter: str, rule_id: str | None, kind: str, path: str, line: int, detail: str, unit: tuple,
              sha: str | None = None) -> bool:
        reason = excluded_path(unit[0]) or excluded_path(path)
        if reason:
            key = (chapter, path, line, rule_id or "", unit[1])
            excluded.setdefault(key, {"chapter_id": chapter, "rule_id": rule_id, "symbol": unit[1], "file": path,
                                      "line": line, "reason": reason[0], "detail": _clip(f"{detail}; {reason[1]}")})
            return False
        sha = view.sha(unit[0], unit[5]) or sha
        if not sha:
            gaps.append(_gap("index_incomplete", [chapter], _clip(f"{unit[0]} has no recorded sha256; hit "
                                                                  f"{rule_id or kind} at line {line} cannot be bound")))
            incomplete.add(chapter)
            return False
        key = (chapter, unit[0], unit[2], unit[1])
        row = candidates.setdefault(key, {
            "candidate_id": f"cand-{chapter}-" + _sha([chapter, unit[0], unit[2], unit[1]])[:16], "chapter_id": chapter,
            "symbol": unit[1], "file": unit[0], "file_sha256": sha, "language": _language(unit[0], view.files),
            "start_line": unit[2], "end_line": unit[3], "span_source": unit[4], "matches": []})
        match = {"rule_id": rule_id, "kind": kind, "file": path, "line": line, "detail": _clip(detail)}
        if match not in row["matches"]:
            row["matches"].append(match)
        return True

    def widening(language: str | None, languages: set[str]) -> bool:
        return language in languages or (language not in table_languages and language in widening_languages)

    tagged, unmapped = _tagged_files(view, tag_cloud) if isinstance(tag_cloud, dict) else ({}, [])
    for chapter in rules["chapters"]:
        chapter_id, basis, seeds = chapter["chapter_id"], [], []
        if not chapter["rules"]:
            incomplete.add(chapter_id)
            gaps.append(_gap("rule_without_index_support", [chapter_id], _clip(f"{chapter_id} has no search rules: "
                             f"{chapter['scope_note']}")))
        covered = {language for rule in chapter["rules"] for language in rule["languages"]}
        for language in sorted(present - covered - set(exempt[chapter_id])):
            incomplete.add(chapter_id)
            gaps.append(_gap("language_not_searched", [chapter_id], f"no {chapter_id} rule covers {language} and the "
                             "rule table gives no languages_not_applicable reason for it"))
        for language in sorted(set(file_counts) - covered - set(exempt[chapter_id])):
            if language in NON_PROGRAM_LANGUAGES:
                data_chapters.setdefault(language, set()).add(chapter_id)
        propagation = chapter.get("propagation")
        seed_ids = set(propagation["seed_rule_ids"]) if propagation else set()
        fts_basis = []
        for rule in chapter["rules"]:
            kind, languages = rule["kind"], set(rule["languages"])
            relevant = sorted(languages & present)
            unsupported = []
            if kind == "sast_rule_ids":
                if sast_hits is None and relevant:
                    sast_chapters.add(chapter_id)
            elif kind == "entry_point" and rule["entry"] == "exported_symbol":
                if relevant:
                    export_chapters.add(chapter_id)
                    if not view.db.execute("SELECT 1 FROM export_tables WHERE artifact != '(gaps)' LIMIT 1").fetchone():
                        unsupported = relevant
            else:
                unsupported = [language for language in relevant
                               if not any(view.facet(language, facet) for facet in FACETS[kind])]
                if kind == "entry_point":
                    unsupported = sorted(set(unsupported) | {language for language in relevant
                                                             if not _entry_names(language, rule["entry"])})
                if kind == "literal_regex" and relevant:
                    literal_chapters.add(chapter_id)
            if unsupported:
                incomplete.add(chapter_id)
                gaps.append(_gap("rule_without_index_support", [chapter_id], _clip(
                    f"rule {rule['rule_id']} ({kind}) cannot be answered by the index for {', '.join(unsupported)}; "
                    "its hits there are unknown, not zero")))
            hits = [hit for hit in _hits(view, rule, sast_hits) if _language(hit[3][0], view.files) in languages
                    and _language(hit[0], view.files) in languages]
            basis.append({"rule_id": rule["rule_id"], "kind": kind, "hits": len(hits)})
            for path, line, detail, unit in hits:
                kept = place(chapter_id, rule["rule_id"], kind, path, line, detail, unit)
                if kept and rule["rule_id"] in seed_ids:
                    seeds.append((rule["rule_id"], unit))
            if evidence is not None and kind in FTS_KINDS:
                fts_chapters.add(chapter_id)
                found = [hit for hit in _fts_hits(view, evidence, rule, fts_truncated, fts_unsearchable)
                         if widening(_language(hit[0], view.files), languages)]
                fts_basis.append({"rule_id": rule["rule_id"], "kind": "fts", "hits": len(found)})
                for path, line, detail, unit, sha in found:
                    place(chapter_id, rule["rule_id"], "fts", path, line, detail, unit, sha)
        if propagation:
            seed_languages = {language for rule in chapter["rules"] if rule["rule_id"] in seed_ids
                              for language in rule["languages"]} & present
            lacking = sorted(language for language in seed_languages if not view.facet(language, "cpg"))
            if lacking:
                incomplete.add(chapter_id)
                gaps.append(_gap("rule_without_index_support", [chapter_id], f"{chapter_id} propagation needs resolved "
                                 f"CPG calls, absent for {', '.join(lacking)}"))
            spread = _propagate(view, seeds, propagation)
            for seed_id in sorted(seed_ids, key=[rule["rule_id"] for rule in chapter["rules"]].index):
                rows = [row for row in spread if row[0] == seed_id]
                basis.append({"rule_id": seed_id, "kind": "propagation", "hits": len(rows)})
                for _, path, line, detail, unit in rows:
                    place(chapter_id, seed_id, "propagation", path, line, detail, unit)
        basis += fts_basis
        if semantic_index is not None and chapter.get("semantic_queries"):
            count = 0
            for text in chapter["semantic_queries"]:
                try:
                    results = list(semantic_index(text, limit=SEMANTIC_LIMIT))[:SEMANTIC_LIMIT]
                except Exception as exc:  # noqa: BLE001 - a failed semantic query is a recorded gap
                    semantic_failures.append(_clip(f"{chapter_id} {text!r}: {type(exc).__name__}: {exc}"))
                    continue
                for hit in sorted(results, key=lambda row: (str(row.get("file")), row.get("start_line") or 0)):
                    path, line = _relative(hit.get("file")), hit.get("start_line")
                    if path is None or not isinstance(line, int) or line < 1:
                        semantic_unresolved.append(f"{hit.get('file')}:{line}")
                        continue
                    sha = _snapshot_line(path, line, source_root, evidence)
                    if sha is None:
                        semantic_unresolved.append(f"{path}:{line}")
                        continue
                    score = hit.get("score")
                    detail = f"semantic {text!r} symbol {_clip(hit.get('symbol'))[:200]}" + (
                        f" score {score:.3f}" if isinstance(score, (int, float)) else "")
                    count += 1
                    place(chapter_id, None, "semantic", path, line, detail, view.enclose(path, line), sha)
            semantic_hits += count
            basis.append({"rule_id": None, "kind": "semantic", "hits": count})
        if tag_cloud is not None:
            have = {row["file"] for row in candidates.values() if row["chapter_id"] == chapter_id}
            rows = [row for row in tagged.get(chapter_id, []) if row[0] not in have]
            added = set()
            for path, component, tag in rows:
                if excluded_path(path):
                    tag_skipped.add(path)
                    continue
                detail = f"component {component} tag {tag} (model metadata; widens only)"
                if place(chapter_id, None, "tag_cloud", path, 1, detail,
                         (path, MODULE, 1, 1, "module-scope", None, None, MODULE)):
                    added.add(path)
            tag_hits += len(added)
            basis.append({"rule_id": None, "kind": "tag_cloud", "hits": len(rows)})
        basis += [{"rule_id": None, "kind": "not_applicable_language", "hits": 0, "language": language,
                   "file_count": file_counts[language], "reason": _clip(reason)}
                  for language, reason in sorted(exempt[chapter_id].items())
                  if file_counts.get(language) and language not in covered]
        chapters.append({"chapter_id": chapter_id, "search_basis": basis})
    if literal_chapters:
        gaps.append(_gap("index_incomplete", literal_chapters, "code-index literals are string literals in "
                         "call-argument text only; initializers and tables are reached only through the evidence-index "
                         "FTS" + ("" if evidence else ", which was not supplied") + ", so literal_regex hits are a lower bound"))
    if export_chapters:
        gaps.append(_gap("index_incomplete", export_chapters, "exports are the binary dynamic export tables only, "
                         "not source exports; exported_symbol covers shipped native libraries only"))
    if sast_chapters:
        gaps.append(_gap("sast_unavailable", sast_chapters, "02-source-sast was not accepted: the sast_rule_ids rules "
                         "did not run"))
    for language, chapter_ids in sorted(data_chapters.items()):
        gaps.append(_gap("index_incomplete", chapter_ids, f"{file_counts[language]} {language} data file(s) are not "
                         "program source: neither the code index nor these chapters' rules search them, so values "
                         "there (configuration, endpoints, secrets) are a lower bound here; secrets are "
                         "02-secrets-inventory's"))
    if "bash" in present:
        gaps.append(_gap("index_incomplete", [row["chapter_id"] for row in rules["chapters"]
                                              if any("bash" in rule["languages"] for rule in row["rules"])],
                         "shell is indexed by tree-sitter only: bash rules see command and function names, not command "
                         "arguments (curl -k, chmod 777) or variable assignments and declarations (PASSWORD=, export "
                         "TOKEN=); the enclosing function is the candidate, and those values are a lower bound"))
    if "rust" in present:
        gaps.append(_gap("index_incomplete", ["V1", "V15"], "Rust unsafe blocks are not indexed and no rule selects "
                         "them; unsafe code is a candidate only when another rule hits it"))
    semantic_chapters = [row["chapter_id"] for row in rules["chapters"] if row.get("semantic_queries")]
    if evidence is None:
        gaps.append(_gap("evidence_index_unavailable", CHAPTERS, "02-evidence-index full-text search was not supplied: "
                         "strings outside call arguments and files without a grammar were not searched"))
    else:
        if fts_truncated:
            gaps.append(_gap("rows_truncated", fts_chapters, _clip(f"{len(fts_truncated)} FTS term(s) returned the "
                             f"bounded maximum of {evidence.limit} rows; further hits are unknown: "
                             + "; ".join(sorted(fts_truncated)[:8]))))
        if fts_unsearchable:
            gaps.append(_gap("index_incomplete", fts_chapters, _clip("rule pattern alternatives with no literal FTS term "
                             "(not searched by FTS): " + ", ".join(sorted(set(fts_unsearchable))))))
        if evidence.failures:
            gaps.append(_gap("index_incomplete", fts_chapters, _clip(f"{len(evidence.failures)} bounded evidence query/read "
                             "call(s) failed: " + "; ".join(evidence.failures[:4]))))
        manifest = evidence.manifest if isinstance(evidence.manifest, dict) else None
        if manifest is None:
            gaps.append(_gap("index_incomplete", fts_chapters, "evidence-index manifest not supplied: files the FTS did "
                             "not index are unknown, so zero FTS hits prove nothing"))
        else:
            statuses = {key: value for key, value in sorted((manifest.get("text_status_counts") or {}).items())
                        if key != "indexed" and value}
            skipped = len(manifest.get("excluded") or [])
            if statuses or skipped:
                gaps.append(_gap("index_incomplete", fts_chapters, _clip(
                    "zero FTS hits do not cover files the evidence index holds no text for: "
                    + ", ".join(f"{count} {status}" for status, count in statuses.items())
                    + (f"{', ' if statuses else ''}{skipped} excluded" if skipped else ""))))
        gaps.append(_gap("index_incomplete", fts_chapters, "FTS matches whole tokens: a pattern fragment inside a longer "
                         "token (prefix or suffix of an identifier) is not found by full-text search"))
    if semantic_index is None:
        gaps.append(_gap("semantic_index_absent", semantic_chapters, "semantic-index-absent: 02-semantic-recall-index was "
                         "not supplied; the chapters' semantic_queries did not run"))
    else:
        if semantic_unresolved:
            gaps.append(_gap("index_incomplete", semantic_chapters, _clip(f"{len(semantic_unresolved)} semantic hit(s) did "
                             "not dereference to snapshot bytes and were not used: "
                             + ", ".join(sorted(set(semantic_unresolved))[:10]))))
        if semantic_failures:
            gaps.append(_gap("index_incomplete", semantic_chapters, _clip("semantic queries failed: "
                             + "; ".join(semantic_failures[:4]))))
    if tag_cloud is None:
        gaps.append(_gap("tag_cloud_unavailable", CHAPTERS, "no accepted component map: the component tag cloud did "
                         "not widen the search"))

    rows = sorted(candidates.values(), key=lambda row: (CHAPTERS.index(row["chapter_id"]), row["file"],
                                                        row["start_line"], row["symbol"]))
    for row in rows:
        row["matches"].sort(key=lambda match: (match["file"], match["line"], match["rule_id"] or "", match["kind"],
                                               match["detail"]))
    dropped = sorted(excluded.values(), key=lambda row: (CHAPTERS.index(row["chapter_id"]), row["file"], row["line"],
                                                         row["rule_id"] or "", row["symbol"] or ""))
    for chapter in chapters:
        chapter_id = chapter["chapter_id"]
        chapter.update({"candidate_count": sum(1 for row in rows if row["chapter_id"] == chapter_id),
                        "excluded_count": sum(1 for row in dropped if row["chapter_id"] == chapter_id),
                        "coverage_complete": complete and chapter_id not in incomplete})
    try:
        name_rows = view.db.execute("SELECT COUNT(*) FROM names WHERE kind IN "
                                    f"({','.join(repr(kind) for kind in NAME_KINDS)})").fetchone()[0]
    except sqlite3.Error:
        name_rows = 0
    if not name_rows and not empty:
        gaps.append(_gap("index_incomplete", [row["chapter_id"] for row in rules["chapters"]
                                              if any(rule["kind"] == "symbol_regex" for rule in row["rules"])],
                         "the code index holds no IR-function or debug-symbol names rows: symbol_regex rules searched "
                         "the method and tree-sitter function tables only"))
    facilities = [
        {"facility": "code_index", "status": "used" if view.files else "unavailable",
         "detail": f"{len(view.files)} indexed file(s), {len(view.methods)} method(s)"},
        {"facility": "code_index_names", "status": "used" if name_rows else "unavailable",
         "detail": f"{name_rows} IR-function/debug-symbol name row(s); {view.names_used} name hit(s) beyond the "
                   "method tables"},
        {"facility": "source_sast", "status": "unavailable" if sast_hits is None else "used",
         "detail": "02-source-sast not accepted" if sast_hits is None else f"{len(sast_hits)} lead(s)"},
        {"facility": "evidence_index_fts", "status": "unavailable" if evidence is None else "used",
         "detail": "02-evidence-index not supplied" if evidence is None else
         f"{evidence.queries} bounded search(es), {len(fts_truncated)} at the result cap"},
        {"facility": "semantic_index", "status": "unavailable" if semantic_index is None else "used",
         "detail": "semantic-index-absent" if semantic_index is None else
         f"{semantic_hits} dereferenced hit(s), {len(semantic_unresolved)} unresolved"},
        {"facility": "tag_cloud", "status": "unavailable" if tag_cloud is None else "used",
         "detail": "no accepted component map" if tag_cloud is None else _clip(
             f"{tag_hits} file-level widening candidate(s); {len(tag_skipped)} tagged file(s) under exclusion "
             f"globs left excluded; unmapped tags: {', '.join(unmapped) or 'none'}")}]
    unique = {gap["gap_id"]: gap for gap in gaps}
    return {"coverage": {"complete": complete, "searched_languages": searched, "unsearched_languages": unsearched,
                         "sast_available": sast_hits is not None, "facilities": facilities},
            "chapters": [{key: chapter[key] for key in ("chapter_id", "candidate_count", "excluded_count",
                                                         "coverage_complete", "search_basis")} for chapter in chapters],
            "candidates": rows, "excluded": dropped,
            "gaps": sorted(unique.values(), key=lambda gap: (gap["kind"], gap["gap_id"]))}


def document(result: dict[str, Any], *, run_id: str, source_snapshot_sha256: str, rules: dict[str, Any],
             rules_sha256: str, inputs: list[dict[str, Any]]) -> dict[str, Any]:
    """The published ``owasp-candidate-search.schema.json`` document around a ``search`` result."""
    return {"schema": SCHEMA, "run_id": run_id, "job_id": JOB, "source_snapshot_sha256": source_snapshot_sha256,
            "status": "OK_WITH_GAPS" if result["gaps"] else "OK",
            "rule_table": {"path": RULES_PATH, "rules_id": rules["rules_id"], "version": rules["version"],
                           "sha256": rules_sha256},
            "inputs": inputs, **result}


def _load(path: Path | None, member: str) -> list[dict[str, Any]] | None:
    if path is None:
        return None
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    value = value.get(member) if isinstance(value, dict) else value
    if not isinstance(value, list):
        raise ValueError(f"{path}: expected a list or a document with {member!r}")
    return value


def _semantic(root: Path | None) -> Callable[..., list[dict[str, Any]]] | None:
    if root is None:
        return None
    import semantic_recall_index

    def query(text: str, *, limit: int) -> list[dict[str, Any]]:
        return semantic_recall_index.query(root, text, limit=limit)
    return query


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--index", type=Path, required=True, help="code-index.sqlite of the accepted 02-code-index")
    parser.add_argument("--rules", type=Path, default=Path(__file__).resolve().parents[1] / RULES_PATH)
    parser.add_argument("--source-sast", type=Path, help="accepted 02-source-sast result or list of leads")
    parser.add_argument("--treesitter-ast", type=Path, help="accepted 02-treesitter-ast document or list of gaps")
    parser.add_argument("--evidence-run-id", help="run whose accepted 02-evidence-index is searched (FTS)")
    parser.add_argument("--component-map", type=Path, help="accepted component purpose map (tag cloud)")
    parser.add_argument("--semantic-index", type=Path, help="accepted 02-semantic-recall-index root")
    parser.add_argument("--source-root", type=Path, help="snapshot root semantic hits are dereferenced against")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if not args.index.is_file():
            raise ValueError(f"{args.index}: no code index")
        rules = json.loads(args.rules.read_text(encoding="utf-8"))
        component_map = json.loads(args.component_map.read_text(encoding="utf-8")) if args.component_map else None
        evidence = evidence_index_for(args.evidence_run_id) if args.evidence_run_id else None
        connection = code_index.open_readonly(args.index)
        try:
            result = search(connection, rules, sast_hits=_load(args.source_sast, "leads"),
                            treesitter_gaps=_load(args.treesitter_ast, "gaps") or [], evidence_index=evidence,
                            tag_cloud=component_map, semantic_index=_semantic(args.semantic_index),
                            source_root=args.source_root)
        finally:
            connection.close()
    except Exception as exc:  # noqa: BLE001 - every input failure is a blocked CLI run with its reason
        print(f"OWASP_CANDIDATE_SEARCH_BLOCKED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
