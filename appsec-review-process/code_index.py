#!/usr/bin/env python3
"""Deterministic, hash-bound structural code index (brief U0.2, ADR-0032).

One SQLite database built from ACCEPTED upstream artifacts of the run, never from a fresh tool run
and never from target text:

* the ``02-code-property-graph`` records file (hash-verified by ``reachability.load_cpg``'s rule):
  methods, call sites, types, identifiers. Call resolution is ``reachability.CallGraph``'s, not a
  second resolver: every call row carries the graph's ``resolution`` (``exact``, ``unique-name``,
  ``same-file-name``, ``nearest-directory-name``), or is an ``escape`` with the graph's reason
  (``indirect-call``, ``ambiguous-name``, ``call-through-variable``), or ``external`` (a named
  callee the analysed code does not define).
* the ``02-treesitter-ast`` document when accepted: per-file functions with real spans, call sites
  and imports (the CPG exporter records only a method's first line, so spans come from here).
* the ``02-binary-triage`` dynamic export tables when accepted (``entry_exports``, brief Q),
  joined to CPG methods exactly as the reachability export entries are.
* the ``02-ir-facts`` document when accepted: per (function, file) fact counts by kind
  (``ir_functions``), joined to a CPG method by name.
* the ``02-debug-symbol-index`` records when accepted: symbol names, kinds, addresses and DWARF
  locations per binary (``debug_symbols``), joined to a CPG method by name.

What the sources do not carry is not invented: ``type_edges`` holds only the exporter's
``INHERITS`` rows (``typeDecl.inheritsFromTypeFullName``) and every hierarchy answer says
``hierarchy_complete`` only when there are some; address-taken functions are the exporter's
``METHOD_REF`` rows, ``&name`` operator calls and identifiers that name a defined function, never a
complete set. An exporter that emitted no inheritance rows for an object-oriented language, or no
method references at all, is recorded as a gap, never as silently absent.

Rows are locators into the pinned source snapshot (``path:line`` plus the file's sha256) and are
untrusted data: every name and text is control-stripped and length-capped as ``lsp_driver.clean``
does. The database is derived, never authoritative; ``content_sha256`` hashes every table's rows in
rowid order so a rebuild from the same inputs is checked row for row.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
from typing import Any, Iterable, Iterator

import lsp_driver
import reachability

SCHEMA = "appsec-review/code-index/1"
SQLITE = "code-index.sqlite"
RESULT = "code-index.json"
NAME_LIMIT = lsp_driver.NAME_LIMIT
CODE_LIMIT = 500
ARGUMENT_LIMIT = 16
# Native memory-safety triage families (code_calls_to family=...). Names match the callee's last
# segment; argument text is what the CPG recorded for the call site.
FAMILIES: dict[str, tuple[str, ...]] = {
    "unsafe-copy": ("memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat", "wcscpy", "wcsncpy",
                    "wcscat", "stpcpy", "lstrcpy", "lstrcpyA", "lstrcpyW", "bcopy", "CopyMemory",
                    "RtlCopyMemory", "memcpy_s", "strcpy_s", "strncpy_s", "strlcpy", "strlcat"),
    "format": ("sprintf", "vsprintf", "snprintf", "vsnprintf", "swprintf", "printf", "fprintf", "vprintf",
               "vfprintf", "syslog", "wsprintfA", "wsprintfW"),
    "unbounded-read": ("gets", "scanf", "fscanf", "sscanf", "vscanf", "read", "recv", "recvfrom", "fread",
                       "fgets", "getline"),
    "alloc": ("malloc", "calloc", "realloc", "reallocarray", "alloca", "_alloca", "aligned_alloc",
              "posix_memalign", "valloc", "strdup", "strndup", "HeapAlloc", "VirtualAlloc", "operator new",
              "<operator>.new"),
    "free": ("free", "cfree", "HeapFree", "VirtualFree", "operator delete", "<operator>.delete"),
}
FAMILY_OF = {name: family for family, names in FAMILIES.items() for name in names}
_STRING = re.compile(r'"(?:[^"\\\n]|\\.){1,400}"')
_ADDRESS_OF = "<operator>.addressOf"
TABLES = ("meta", "files", "methods", "calls", "sites", "types", "type_edges", "members", "identifiers",
          "literals", "imports", "ts_functions", "ts_calls", "address_taken", "export_tables", "exports",
          "ir_functions", "debug_symbols")
# Languages with type inheritance: zero INHERITS rows there is an exporter gap; C has none to export.
INHERITANCE_LANGUAGES = frozenset(("cpp", "c_sharp", "java", "javascript", "typescript", "tsx", "python", "php",
                                   "ruby"))
DDL = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE files(path TEXT PRIMARY KEY, sha256 TEXT, language TEXT, source TEXT NOT NULL);
CREATE TABLE methods(id INTEGER PRIMARY KEY, full_name TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
  qualified TEXT NOT NULL, signature TEXT, file TEXT, start_line INTEGER, end_line INTEGER,
  span_source TEXT NOT NULL, is_external INTEGER NOT NULL, language TEXT, file_sha256 TEXT);
CREATE TABLE calls(id INTEGER PRIMARY KEY, caller_id INTEGER, caller_full_name TEXT NOT NULL,
  callee_full_name TEXT NOT NULL, callee_name TEXT NOT NULL, callee_id INTEGER, file TEXT, line INTEGER,
  resolution TEXT NOT NULL, escape_reason TEXT, candidates TEXT, argument_count INTEGER,
  argument_text TEXT, code TEXT, family TEXT);
CREATE TABLE sites(file TEXT NOT NULL, line INTEGER NOT NULL, caller_full_name TEXT NOT NULL);
CREATE TABLE types(id INTEGER PRIMARY KEY, name TEXT NOT NULL, full_name TEXT NOT NULL, kind TEXT NOT NULL,
  file TEXT, line INTEGER, code TEXT);
CREATE TABLE type_edges(derived_type TEXT NOT NULL, base_type TEXT NOT NULL, source TEXT NOT NULL);
CREATE TABLE members(type_full_name TEXT NOT NULL, member TEXT NOT NULL, method_id INTEGER, kind TEXT NOT NULL,
  how TEXT NOT NULL);
CREATE TABLE identifiers(name TEXT NOT NULL, file TEXT, line INTEGER, type_name TEXT);
CREATE TABLE literals(value TEXT NOT NULL, file TEXT, line INTEGER, caller_full_name TEXT, how TEXT NOT NULL);
CREATE TABLE imports(file TEXT NOT NULL, line INTEGER, text TEXT, source TEXT NOT NULL);
CREATE TABLE ts_functions(file TEXT NOT NULL, name TEXT, kind TEXT, start_line INTEGER, end_line INTEGER,
  language TEXT);
CREATE TABLE ts_calls(file TEXT NOT NULL, line INTEGER, callee TEXT);
CREATE TABLE address_taken(method_id INTEGER, full_name TEXT NOT NULL, file TEXT, line INTEGER, how TEXT NOT NULL,
  code TEXT);
CREATE TABLE export_tables(artifact TEXT NOT NULL, binary_sha256 TEXT, artifact_kind TEXT, complete INTEGER,
  gaps TEXT);
CREATE TABLE exports(artifact TEXT NOT NULL, symbol TEXT NOT NULL, demangled TEXT, qualified TEXT,
  join_state TEXT NOT NULL, method_id INTEGER, candidates TEXT);
CREATE TABLE ir_functions(function TEXT NOT NULL, method_id INTEGER, file TEXT, line INTEGER, facts INTEGER NOT NULL,
  kinds TEXT NOT NULL);
CREATE TABLE debug_symbols(binary_id TEXT NOT NULL, binary_sha256 TEXT, name TEXT NOT NULL, kind TEXT, address TEXT,
  size INTEGER, file TEXT, line INTEGER, method_id INTEGER);
CREATE VIRTUAL TABLE names USING fts5(name, kind UNINDEXED, ref UNINDEXED, file UNINDEXED,
  line UNINDEXED, tokenize='trigram');
CREATE INDEX methods_name ON methods(name);
CREATE INDEX methods_qualified ON methods(qualified);
CREATE INDEX methods_file ON methods(file, start_line);
CREATE INDEX calls_caller ON calls(caller_id);
CREATE INDEX calls_caller_name ON calls(caller_full_name);
CREATE INDEX calls_callee ON calls(callee_id);
CREATE INDEX calls_callee_name ON calls(callee_name);
CREATE INDEX calls_family ON calls(family);
CREATE INDEX calls_file ON calls(file, line);
CREATE INDEX calls_resolution ON calls(resolution);
CREATE INDEX sites_file ON sites(file, line);
CREATE INDEX types_name ON types(name);
CREATE INDEX types_full ON types(full_name);
CREATE INDEX type_edges_derived ON type_edges(derived_type);
CREATE INDEX type_edges_base ON type_edges(base_type);
CREATE INDEX members_type ON members(type_full_name);
CREATE INDEX identifiers_name ON identifiers(name);
CREATE INDEX identifiers_file ON identifiers(file, line);
CREATE INDEX literals_file ON literals(file, line);
CREATE INDEX imports_file ON imports(file, line);
CREATE INDEX ts_functions_file ON ts_functions(file, start_line);
CREATE INDEX ts_functions_name ON ts_functions(name);
CREATE INDEX ts_calls_file ON ts_calls(file, line);
CREATE INDEX address_taken_method ON address_taken(method_id);
CREATE INDEX exports_method ON exports(method_id);
CREATE INDEX ir_functions_name ON ir_functions(function);
CREATE INDEX debug_symbols_name ON debug_symbols(name);
CREATE INDEX debug_symbols_file ON debug_symbols(file, line);
"""


def clean(value: Any, limit: int = NAME_LIMIT) -> str | None:
    """Untrusted text as the language-server driver renders it: control-stripped, length-capped."""
    return lsp_driver.clean(value, limit)


def language_of(path: str | None) -> str | None:
    import treesitter_ast
    return treesitter_ast.SUFFIXES.get(PurePosixPath(path or "").suffix.lower()) if path else None


def split_arguments(code: str, name: str) -> tuple[int | None, list[str]]:
    """Top-level arguments of a call's source text (``memcpy(dst, src, n)`` -> 3, [dst, src, n]).

    ``None`` when the text is truncated or not a parenthesised call (macro-expanded or operator
    forms): an unknown count is never guessed as zero."""
    start = code.find("(")
    if start < 0 or not code.rstrip().endswith(")"):
        return None, []
    body, depth, current, parts, quote = code[start + 1:code.rstrip().rfind(")")], 0, [], [], None
    for index, char in enumerate(body):
        if quote:
            current.append(char)
            if char == quote and body[index - 1] != "\\":
                quote = None
            continue
        if char in "\"'":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth < 0:
                return None, []
        elif char == "," and depth == 0:
            parts.append("".join(current).strip()); current = []
            continue
        current.append(char)
    if depth != 0 or quote:
        return None, []
    tail = "".join(current).strip()
    if tail or parts:
        parts.append(tail)
    return len(parts), [clean(part, 160) or "" for part in parts[:ARGUMENT_LIMIT]]


def read_records(path: Path) -> Iterator[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def verify_records(summary: dict[str, Any], records: Path) -> str:
    """The CPG records file's recorded hash (the rule ``reachability.load_cpg`` applies)."""
    digest = "sha256:" + _file_sha(records)
    if digest != (summary.get("records_file") or {}).get("sha256"):
        raise ValueError("CPG records file does not match its recorded hash")
    return digest


def _file_sha(path: Path) -> str:
    value = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _family(name: str) -> str | None:
    return FAMILY_OF.get(name)


def _enclosing_type(full_name: str) -> str | None:
    qualified = reachability.qualified_name(full_name)
    return qualified.rsplit(".", 1)[0] if "." in qualified else None


def build(db_path: Path, *, records: Path, cpg_summary: dict[str, Any], sources: dict[str, Any],
          treesitter: dict[str, Any] | None = None, export_tables: Iterable[dict[str, Any]] | None = None,
          export_gaps: Iterable[str] = (), source_gaps: Iterable[str] = (), ir_facts: dict[str, Any] | None = None,
          debug_symbols: Iterable[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Build the database at ``db_path`` (replaced) and return its summary (without file hashes).

    ``sources`` is the hash binding of every upstream artifact (recorded verbatim); ``treesitter``
    is the accepted AST document or None; ``export_tables`` the verified export tables or None;
    ``ir_facts`` the accepted IR facts document and ``debug_symbols`` the accepted debug-symbol
    records, each None when not bound (nothing to index, not a gap of this job)."""
    db_path = Path(db_path)
    if db_path.exists():
        db_path.unlink()
    records_sha = verify_records(cpg_summary, records)
    graph = reachability.CallGraph.from_records(read_records(records), cpg_summary.get("coverage_gaps", []),
                                                {"cpg_records_sha256": records_sha})
    connection = sqlite3.connect(str(db_path))
    try:
        connection.execute("PRAGMA page_size=4096")
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA synchronous=OFF")
        connection.executescript(DDL)
        counts = _fill(connection, graph, records, treesitter, export_tables, list(export_gaps))
        counts |= _fill_native(connection, graph, ir_facts, debug_symbols)
        gaps = sorted(set(source_gaps) | {f"cpg-coverage-gap:{gap}" for gap in graph.gaps})
        if treesitter is None:
            gaps.append("source-absent:02-treesitter-ast (no outline, no function spans beyond the CPG's first line)")
        if export_tables is None:
            gaps.append("source-absent:02-binary-triage export tables (code_exports unavailable)")
        languages = {language for (language,) in connection.execute("SELECT DISTINCT language FROM files WHERE source LIKE 'cpg%'")}
        if not counts["type_edges"] and languages & INHERITANCE_LANGUAGES:
            gaps.append("cpg-exporter:no-inheritance-edges")
        if not counts["method_references"]:
            gaps.append("cpg-exporter:no-method-reference-nodes")
        capabilities = {"cpg": True, "treesitter": treesitter is not None,
                        "exports": export_tables is not None, "type_edges": counts["type_edges"] > 0,
                        "method_references": counts["method_references"] > 0,
                        "ir_facts": ir_facts is not None, "debug_symbols": debug_symbols is not None}
        meta = {"schema": SCHEMA, "sources": sources, "graph_gaps": list(graph.gaps),
                "capabilities": capabilities, "gaps": gaps}
        connection.executemany("INSERT INTO meta VALUES(?,?)",
                               sorted((key, _json(value)) for key, value in meta.items()))
        connection.commit()
        content = content_sha256(connection)
        connection.execute("VACUUM")
        connection.commit()
    finally:
        connection.close()
    return {"schema": SCHEMA, "sources": sources, "capabilities": capabilities, "counts": counts,
            "graph_gaps": list(graph.gaps), "gaps": gaps, "content_sha256": content,
            "sqlite_version": sqlite3.sqlite_version,
            "claim_boundary": "STRUCTURAL_LOCATORS_NOT_FINDINGS_REQUIRE_SOURCE_DEREFERENCE"}


def _fill(connection: sqlite3.Connection, graph: reachability.CallGraph, records: Path,
          treesitter: dict[str, Any] | None, export_tables: Iterable[dict[str, Any]] | None,
          export_gaps: list[str]) -> dict[str, int]:
    insert = connection.execute
    signatures: dict[str, str] = {}
    files: dict[str, tuple[str | None, str]] = {}
    types: list[tuple] = []
    edges: set[tuple[str, str, str]] = set()
    address: list[tuple[str, str, str, int, str, str]] = []   # (name, full name or "", file, line, how, code)
    references = 0
    defined_short = set(graph.by_short)
    identifiers = literals = 0
    names_rows: list[tuple] = []
    for record in read_records(records):
        kind, path, line = record.get("kind"), record.get("source_path"), record.get("start_line") or 0
        if path and path not in files:
            files[path] = (record.get("source_sha256"), "cpg")
        if kind == "symbol" and record.get("label") == "METHOD":
            signatures.setdefault(record.get("full_name") or "", record.get("type_name") or "")
        elif kind == "type" and record.get("label") == "INHERITS":
            derived, base = clean(record.get("full_name"), 1000), clean(record.get("type_name"), 1000)
            if derived and base:
                edges.add((derived, base, "cpg-inherits"))
        elif kind == "type":
            types.append((clean(record.get("name")) or "", clean(record.get("full_name"), 1000) or "",
                          clean(record.get("label")) or "TYPE_DECL", path, line, clean(record.get("code"), CODE_LIMIT)))
        elif kind == "identifier":
            name = clean(record.get("name"))
            if name:
                insert("INSERT INTO identifiers VALUES(?,?,?,?)", (name, path, line, clean(record.get("type_name"))))
                identifiers += 1
                if name in defined_short:
                    address.append((name, "", path, line, "identifier-names-function", clean(record.get("code"), CODE_LIMIT) or ""))
        elif kind == "method-reference":
            references += 1
            full, name, code = record.get("full_name") or "", clean(record.get("name")) or "", clean(record.get("code"), CODE_LIMIT) or ""
            if full in graph.methods:
                address.append((graph.methods[full]["name"], full, path, line, "method-reference", code))
            elif name in defined_short:
                address.append((name, "", path, line, "method-reference", code))
        elif kind in ("call", "memory-operation"):
            code = record.get("code") or ""
            if record.get("full_name") == _ADDRESS_OF or record.get("name") == _ADDRESS_OF:
                target = code.strip().lstrip("&").strip().strip("()").strip()
                target = target.rsplit("::", 1)[-1]
                if target in defined_short:
                    address.append((target, "", path, line, "address-of-operator", clean(code, CODE_LIMIT) or ""))
            for match in _STRING.findall(code):
                value = clean(match[1:-1], NAME_LIMIT)
                if value:
                    insert("INSERT INTO literals VALUES(?,?,?,?,?)",
                           (value, path, line, clean(record.get("caller"), 1000), "call-argument-text"))
                    literals += 1
    method_ids: dict[str, int] = {}
    ts_spans: dict[str, list[tuple[int, int, str | None]]] = {}
    for item in (treesitter or {}).get("files", []):
        for function in item.get("functions", []):
            ts_spans.setdefault(item["path"], []).append((function["start_line"], function["end_line"], function.get("name")))
    for index, full in enumerate(sorted(graph.methods), 1):
        method = graph.methods[full]
        path, start = method["path"], method["start_line"]
        end, span = method["end_line"], "cpg-first-line"
        short = method["name"]
        for first, last, name in sorted(ts_spans.get(path or "", [])):
            leaf = (name or "").replace("::", ".").rsplit(".", 1)[-1]
            if first <= start <= last and leaf == short:
                end, span = max(last, start), "treesitter"
                break
        method_ids[full] = index
        insert("INSERT INTO methods VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
               (index, clean(full, 1000), clean(short) or "", clean(reachability.qualified_name(full), 1000) or "",
                clean(signatures.get(full), 1000), path, start, end, span, 0, language_of(path),
                method.get("source_sha256")))
        names_rows.append((clean(short) or "", "method", str(index), path, start))
        owner = _enclosing_type(full)
        if owner:
            insert("INSERT INTO members VALUES(?,?,?,?,?)", (owner, clean(short) or "", index, "method",
                                                             "qualified-name-prefix"))
    call_id = 0
    seen_callees: set[str] = set()
    for caller in sorted(set(graph.edges) | set(graph.escapes) | set(graph.external)):
        rows = ([("edge", row) for row in graph.edges.get(caller, [])] +
                [("escape", row) for row in graph.escapes.get(caller, [])] +
                [("external", row) for row in graph.external.get(caller, [])])
        rows.sort(key=lambda item: (item[1]["path"] or "", item[1]["line"], item[1]["callee"], item[0]))
        for what, row in rows:
            call_id += 1
            code = row.get("code") or ""
            short = (reachability.short_name(row["target"]) if what == "edge" else
                     row.get("symbol") or reachability.short_name(row["callee"] or ""))
            count, arguments = (None, []) if len(code) >= 160 else split_arguments(code, short)
            resolution = row["resolution"] if what == "edge" else what
            callee_full = row["target"] if what == "edge" else row["callee"]
            insert("INSERT INTO calls VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (call_id, method_ids.get(caller), clean(caller, 1000) or "", clean(callee_full, 1000) or "",
                    clean(short) or "", method_ids.get(row["target"]) if what == "edge" else None,
                    row["path"], row["line"], resolution, row.get("reason"),
                    _json(row.get("candidates")) if row.get("candidates") else None,
                    count, _json(arguments) if count is not None else None, clean(code, CODE_LIMIT),
                    _family(short)))
            if short and short not in seen_callees:
                seen_callees.add(short)
                names_rows.append((clean(short) or "", "call-target", short, None, None))
    for (path, line), callers in sorted(graph.sites.items(), key=lambda item: (item[0][0] or "", item[0][1])):
        for caller in sorted(callers):
            insert("INSERT INTO sites VALUES(?,?,?)", (path, line, clean(caller, 1000) or ""))
    types.sort(key=lambda row: (row[3] or "", row[4], row[1]))
    for index, row in enumerate(types, 1):
        insert("INSERT INTO types VALUES(?,?,?,?,?,?,?)", (index, *row))
        names_rows.append((row[0], "type", str(index), row[3], row[4]))
    for derived, base, source in sorted(edges):
        insert("INSERT INTO type_edges VALUES(?,?,?)", (derived, base, source))
    for name, exact, path, line, how, code in sorted(set(address), key=lambda row: (row[2] or "", row[3], row[0], row[4], row[1])):
        for full in [exact] if exact else sorted(graph.by_short.get(name, [])):
            insert("INSERT INTO address_taken VALUES(?,?,?,?,?,?)", (method_ids[full], clean(full, 1000), path, line,
                                                                   how, code))
    for item in sorted((treesitter or {}).get("files", []), key=lambda row: row["path"]):
        path = item["path"]
        files[path] = (files.get(path, (item.get("sha256"), ""))[0] or item.get("sha256"),
                       "cpg+treesitter" if path in files else "treesitter")
        for function in item.get("functions", []):
            insert("INSERT INTO ts_functions VALUES(?,?,?,?,?,?)", (path, clean(function.get("name")),
                   function.get("kind"), function["start_line"], function["end_line"], item.get("language")))
            if function.get("name"):
                names_rows.append((clean(function["name"]) or "", "ts-function", path, path, function["start_line"]))
        for call in item.get("calls", []):
            insert("INSERT INTO ts_calls VALUES(?,?,?)", (path, call["line"], clean(call.get("callee"))))
        for row in item.get("imports", []):
            insert("INSERT INTO imports VALUES(?,?,?,?)", (path, row["line"], clean(row.get("text")), "treesitter"))
    for path, (sha, source) in sorted(files.items()):
        insert("INSERT INTO files VALUES(?,?,?,?)", (path, sha, language_of(path), source))
    exports = 0
    if export_tables is not None:
        import entry_exports
        tables = sorted(export_tables, key=lambda item: (item["artifact"], item["binary_sha256"] or ""))
        index_q: dict[str, list[str]] = {}
        for full in graph.methods:
            index_q.setdefault(reachability.qualified_name(full), []).append(full)
        for table in tables:
            insert("INSERT INTO export_tables VALUES(?,?,?,?,?)", (clean(table["artifact"]), table["binary_sha256"],
                   table["artifact_kind"], int(bool(table["complete"])), _json(table["gaps"])))
            for row in table["exports"]:
                qualified = entry_exports.export_qualified(row)
                candidates = sorted(index_q.get(qualified, [])) if qualified else []
                if qualified is None:
                    state = "unjoinable"
                elif len(candidates) > 1:
                    state = "ambiguous"
                elif len(candidates) == 1 and not reachability.file_scoped(candidates[0]):
                    state = "joined"
                else:
                    state = "not-in-cpg"
                insert("INSERT INTO exports VALUES(?,?,?,?,?,?,?)", (clean(table["artifact"]), clean(row["symbol"], 1000),
                       clean(row.get("demangled"), 1000), qualified, state,
                       method_ids.get(candidates[0]) if state == "joined" else None,
                       _json(candidates[:8]) if state == "ambiguous" else None))
                exports += 1
        if export_gaps:
            insert("INSERT INTO export_tables VALUES(?,?,?,?,?)", ("(gaps)", None, "unknown", 0, _json(sorted(export_gaps))))
    names_rows += [(name, "identifier", name, None, None) for (name,) in
                   connection.execute("SELECT DISTINCT name FROM identifiers ORDER BY name")]
    names_rows += [(value, "literal", value, None, None) for (value,) in
                   connection.execute("SELECT DISTINCT value FROM literals ORDER BY value")]
    connection.executemany("INSERT INTO names(name, kind, ref, file, line) VALUES(?,?,?,?,?)",
                           [row for row in names_rows if row[0]])
    return {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in TABLES if table != "meta"} | {"identifiers": identifiers, "literals": literals,
                                                       "export_rows": exports, "method_references": references}


def _fill_native(connection: sqlite3.Connection, graph: reachability.CallGraph, ir_facts: dict[str, Any] | None,
                 debug_symbols: Iterable[dict[str, Any]] | None) -> dict[str, int]:
    """IR fact functions and debug symbols, joined to a CPG method only when the name is unique (in
    the file when one is recorded); everything else keeps ``method_id`` NULL."""
    def join(name: str | None, path: str | None) -> int | None:
        candidates = graph.by_short.get(name or "", [])
        local = [full for full in candidates if path and graph.methods[full]["path"] == path]
        chosen = local if len(local) == 1 else candidates if len(candidates) == 1 else []
        return ids.get(chosen[0]) if chosen else None
    ids = {full: mid for mid, full in connection.execute("SELECT id, full_name FROM methods")}
    names_rows: list[tuple] = []
    functions: dict[tuple[str, str | None], dict[str, Any]] = {}
    lines = {item.get("debug_location_id"): item.get("source_line") for item in (ir_facts or {}).get("debug_locations", [])
             if isinstance(item, dict)}
    for fact in (ir_facts or {}).get("facts", []):
        if not fact.get("function"):
            continue
        row = functions.setdefault((fact["function"], fact.get("source_path")), {"line": None, "kinds": {}})
        line = lines.get(fact.get("debug_location_id"))
        if isinstance(line, int) and (row["line"] is None or line < row["line"]):
            row["line"] = line
        row["kinds"][fact["kind"]] = row["kinds"].get(fact["kind"], 0) + 1
    for (function, path), row in sorted(functions.items(), key=lambda item: (item[0][1] or "", item[0][0])):
        name = clean(function, 1000) or ""
        connection.execute("INSERT INTO ir_functions VALUES(?,?,?,?,?,?)", (name, join(function, path), path, row["line"],
                           sum(row["kinds"].values()), _json(row["kinds"])))
        names_rows.append((clean(function) or "", "ir-function", name, path, row["line"]))
    symbols = []
    for record in debug_symbols or []:
        for symbol in record.get("symbols", []):
            symbols.append((clean(record.get("binary_id"), 1000) or "", record.get("binary_sha256"),
                            clean(symbol.get("name"), 1000) or "", clean(symbol.get("kind")), clean(symbol.get("address")),
                            symbol.get("size"), symbol.get("source_path"), symbol.get("line")))
    for row in sorted(set(symbols), key=lambda row: (row[0], row[6] or "", row[7] or 0, row[2], row[4] or "")):
        if row[2]:
            connection.execute("INSERT INTO debug_symbols VALUES(?,?,?,?,?,?,?,?,?)", (*row, join(row[2], row[6])))
            names_rows.append((clean(row[2]) or "", "debug-symbol", row[2], row[6], row[7]))
    connection.executemany("INSERT INTO names(name, kind, ref, file, line) VALUES(?,?,?,?,?)",
                           [row for row in names_rows if row[0]])
    return {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("ir_functions", "debug_symbols")}


def content_sha256(connection: sqlite3.Connection) -> str:
    """sha256 over every table's rows in rowid order (the logical content, independent of page layout)."""
    value = hashlib.sha256()
    for table in TABLES + ("names",):
        value.update(table.encode() + b"\n")
        for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid"):
            value.update(_json(list(row)).encode("utf-8") + b"\n")
    return "sha256:" + value.hexdigest()


def open_readonly(path: Path) -> sqlite3.Connection:
    """Read-only, immutable connection: the query side can never write the published database."""
    uri = "file:" + str(Path(path).resolve()) + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True, check_same_thread=False)
    connection.execute("PRAGMA query_only=ON")
    return connection


def meta(connection: sqlite3.Connection) -> dict[str, Any]:
    return {key: json.loads(value) for key, value in connection.execute("SELECT key, value FROM meta")}


def hydrate_graph(connection: sqlite3.Connection) -> reachability.CallGraph:
    """A ``reachability.CallGraph`` restored from the index's own rows, exactly as the build resolved it.

    Nothing is re-resolved: edges, escapes, externals and call sites are the rows the graph produced
    at build time, so ``locate`` and ``analyze`` answer as over the CPG records."""
    graph = reachability.CallGraph()
    by_id: dict[int, str] = {}
    for mid, full, name, path, start, end, sha in connection.execute(
            "SELECT id, full_name, name, file, start_line, end_line, file_sha256 FROM methods ORDER BY id"):
        by_id[mid] = full
        graph.methods[full] = {"full_name": full, "name": name, "path": path, "start_line": start,
                               "end_line": start, "source_sha256": sha, "span_end": end}
        graph.by_short.setdefault(name, []).append(full)
    for (caller, callee, short, callee_id, path, line, resolution, reason, candidates, code) in connection.execute(
            "SELECT caller_full_name, callee_full_name, callee_name, callee_id, file, line, resolution, "
            "escape_reason, candidates, code FROM calls ORDER BY id"):
        site = {"path": path, "line": line, "callee": callee, "code": code or ""}
        if resolution == "escape":
            row = {**site, "reason": reason}
            if candidates:
                row["candidates"] = json.loads(candidates)
            graph.escapes.setdefault(caller, []).append(row)
        elif resolution == "external":
            graph.external.setdefault(caller, []).append({**site, "symbol": short})
        else:
            graph.edges.setdefault(caller, []).append({**site, "target": by_id.get(callee_id, callee),
                                                       "resolution": resolution})
    for path, line, caller in connection.execute("SELECT file, line, caller_full_name FROM sites ORDER BY rowid"):
        graph.sites.setdefault((path, line), []).append(caller)
    info = meta(connection)
    graph.gaps = list(info.get("graph_gaps", []))
    graph.identity = {"code_index_content": "hydrated", **(info.get("sources", {}).get("cpg") or {})}
    return graph
