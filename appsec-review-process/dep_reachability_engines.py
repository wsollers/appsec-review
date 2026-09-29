"""Reachability engine adapters for ``dep_reachability.py`` (ADR-0022 decision 3).

Every engine answers one question behind the same interface -- can an entry point of the
application reach a call of one of these dependency symbols? -- over evidence that is already on
disk and hash-bound by the caller. No engine executes anything:

* ``cpg``        Joern CPG (+ IR facts) through ``reachability.py``; may return all three states.
* ``codeql``     CodeQL table outputs (``CallEdges``/``EntryPoints``/``Reachability``/``TaintReach``
                 CSVs from the query packs in ``data/codeql-reachability/<lang>/`` or the traced
                 C/C++ graph pack). Static edges miss virtual/dynamic dispatch, so a missing path is
                 ``unknown``, never ``unreachable``.
* ``lsp``        ``lsp-query-result`` documents (``lsp_driver.py``) whose ``incomingCalls`` answers
                 chain from a tagged sink to an entry point; ``reachable`` or ``unknown`` only.
* ``treesitter`` ``treesitter-ast`` call sites matched by name: always ``unknown``, with a
                 ``witness_hint`` when a call site matches (brief E: never ``reachable`` alone).

An engine whose input is absent does not run and says so as a gap (``engine-input-absent``).
"""
from __future__ import annotations

from collections import deque
import csv
from dataclasses import dataclass, field
import hashlib
import io
import json
from pathlib import Path
import re
from typing import Any, Iterable

import reachability

REACHABLE, UNREACHABLE, UNKNOWN = "reachable", "unreachable", "unknown"
STATE = {reachability.REACHABLE: REACHABLE, reachability.UNREACHABLE: UNREACHABLE, reachability.UNKNOWN: UNKNOWN}
# What an engine's answer can prove (dep_reachability.join): "complete" may prove reachable and
# unreachable; "graph" and "hierarchy" may prove reachable only; "hint" proves nothing.
STRENGTH = {"cpg": "complete", "codeql": "graph", "lsp": "hierarchy", "treesitter": "hint"}
MAX_HINTS = 32
MAX_LSP_NODES = 20_000

# Name-based entry points per analysis language (ADR-0022 decision 7). Framework handlers and
# routes come from the CodeQL EntryPoints queries; a run can add names through the hash-bound
# inputs/reachability-entry-points.json.
ENTRY_POINTS: dict[str, tuple[str, ...]] = {
    "cpp": ("main", "wmain", "WinMain", "wWinMain", "DllMain", "LLVMFuzzerTestOneInput"),
    "go": ("main", "init"), "java": ("main",), "csharp": ("Main",), "python": ("main", "__main__"),
    "javascript": ("main",), "rust": ("main",), "php": (), "ruby": (),
}
TREESITTER_LANGUAGES = {
    "cpp": ("c", "cpp"), "go": ("go",), "java": ("java",), "csharp": ("c_sharp",),
    "javascript": ("javascript", "typescript", "tsx"), "python": ("python",), "rust": ("rust",),
    "php": ("php",), "ruby": ("ruby",),
}
CALL_EDGE_COLUMNS = ("caller_name", "caller_file", "caller_line", "call_file", "call_line",
                     "callee_name", "callee_file", "callee_line", "callee_defined")
ENTRY_COLUMNS = ("name", "file", "line", "reason")
REACH_COLUMNS = ("entry_name", "entry_file", "entry_line", "caller_name", "call_file", "call_line",
                 "package", "symbol")
TAINT_COLUMNS = ("source_file", "source_line", "sink_file", "sink_line", "package", "symbol")
TABLES = {"CallEdges": CALL_EDGE_COLUMNS, "EntryPoints": ENTRY_COLUMNS, "Reachability": REACH_COLUMNS,
          "TaintReach": TAINT_COLUMNS}


@dataclass(frozen=True)
class Query:
    match_id: str
    language: str
    package: str
    symbols: list[dict[str, Any]]
    entry_points: list[str] = field(default_factory=list)


def result(engine: str, *, ran: bool, state: str = UNKNOWN, reason: str, witness: list[dict[str, Any]] | None = None,
           gaps: Iterable[str] = (), **extra: Any) -> dict[str, Any]:
    return {"engine": engine, "ran": ran, "state": state, "reason": reason, "witness": list(witness or []),
            "gaps": list(gaps), **extra}


def _last(symbol: str) -> str:
    return re.split(r"[.:]+", symbol)[-1]


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---- cpg ---------------------------------------------------------------------------------------

class CpgEngine:
    name = "cpg"

    def __init__(self, graph: reachability.CallGraph | None) -> None:
        self.graph = graph

    def assess(self, query: Query) -> dict[str, Any]:
        if self.graph is None:
            return result(self.name, ran=False, reason="no accepted code property graph",
                          gaps=["engine-input-absent:cpg"])
        entries = self.graph.entry_points([*ENTRY_POINTS.get(query.language, ()), *query.entry_points])
        found = reachability.assess_symbols(self.graph, query.symbols, entries)
        gaps = [] if found["state"] != reachability.UNKNOWN else ["cpg-undecided"]
        return result(self.name, ran=True, state=STATE[found["state"]], reason=found["reason"],
                      witness=found["witness"], gaps=gaps, target=found.get("target"))


# ---- codeql ------------------------------------------------------------------------------------

def read_table(data: bytes, table: str) -> list[dict[str, str]]:
    """Decode one ``codeql bqrs decode --format=csv`` table; the header must be the contract."""
    reader = csv.reader(io.StringIO(data.decode("utf-8", errors="replace")))
    rows = list(reader)
    if not rows or tuple(item.strip() for item in rows[0]) != TABLES[table]:
        raise ValueError(f"{table}: CSV header is not the contract ({', '.join(TABLES[table])})")
    width = len(TABLES[table])
    return [dict(zip(TABLES[table], row)) for row in rows[1:] if len(row) == width]


def graph_from_codeql(tables: dict[str, list[dict[str, str]]], identity: dict[str, Any] | None = None
                      ) -> tuple[reachability.CallGraph, list[str]]:
    """A ``reachability.CallGraph`` from ``CallEdges`` (+ ``EntryPoints`` names)."""
    functions: dict[str, dict[str, Any]] = {}

    def key(name: str, path: str, line: Any) -> str:
        return f"{name}|{path}|{_int(line)}"

    def define(name: str, path: str, line: Any) -> str:
        full = key(name, path, line)
        if full not in functions:
            functions[full] = {"full_name": full, "name": _last(name) or name, "path": path or None,
                               "start_line": _int(line), "end_line": _int(line)}
        return full

    calls = []
    for row in tables.get("CallEdges", []):
        if not row["caller_file"]:
            continue
        caller = define(row["caller_name"], row["caller_file"], row["caller_line"])
        if row["callee_defined"] == "yes" and row["callee_file"]:
            callee = define(row["callee_name"], row["callee_file"], row["callee_line"])
        else:
            callee = row["callee_name"]
        calls.append({"caller": caller, "callee": callee, "name": _last(row["callee_name"]),
                      "path": row["call_file"], "line": _int(row["call_line"]), "code": ""})
    entries = []
    for row in tables.get("EntryPoints", []):
        if row["file"]:
            entries.append(define(row["name"], row["file"], row["line"]))
    graph = reachability.CallGraph.from_tables(functions.values(), calls, (), identity)
    return graph, sorted(set(entries))


class CodeqlEngine:
    name = "codeql"

    def __init__(self, tables: dict[str, dict[str, list[dict[str, str]]]], gaps: dict[str, list[str]] | None = None) -> None:
        self.tables, self.table_gaps = tables, gaps or {}
        self._graphs: dict[str, tuple[reachability.CallGraph, list[str]]] = {}

    def assess(self, query: Query) -> dict[str, Any]:
        tables = self.tables.get(query.language)
        gaps = list(self.table_gaps.get(query.language, []))
        if not tables:
            return result(self.name, ran=False, reason=f"no CodeQL reachability tables for {query.language}",
                          gaps=gaps or [f"engine-input-absent:codeql:{query.language}"])
        found: dict[str, Any] | None = None
        if tables.get("CallEdges"):
            if query.language not in self._graphs:
                self._graphs[query.language] = graph_from_codeql(tables)
            graph, roots = self._graphs[query.language]
            entries = sorted(set(roots) | set(graph.entry_points([*ENTRY_POINTS.get(query.language, ()),
                                                                  *query.entry_points])))
            found = reachability.assess_symbols(graph, query.symbols, entries)
        wanted = {(item.get("package") or "", item["symbol"]) for item in query.symbols}
        direct = sorted((row for row in tables.get("Reachability", [])
                         if (row["package"], row["symbol"]) in wanted and row["entry_file"] and row["call_file"]),
                        key=lambda row: (row["entry_file"], _int(row["entry_line"]), row["call_file"], _int(row["call_line"])))
        taint = sorted({(row["source_file"], _int(row["source_line"]), row["sink_file"], _int(row["sink_line"]))
                        for row in tables.get("TaintReach", []) if (row["package"], row["symbol"]) in wanted})
        extra = {"taint_paths": [{"source": f"{a}:{b}", "sink": f"{c}:{d}"} for a, b, c, d in taint[:MAX_HINTS]]}
        if found and found["state"] == reachability.REACHABLE:
            return result(self.name, ran=True, state=REACHABLE, reason="CodeQL call edges: " + found["reason"],
                          witness=found["witness"], gaps=gaps, **extra)
        if direct:
            row = direct[0]
            witness = [{"function": row["entry_name"], "file": row["entry_file"], "line": _int(row["entry_line"]),
                        "calls_next_at": f"{row['call_file']}:{row['call_line']}", "resolution": "codeql-calls*"},
                       {"function": row["caller_name"], "file": row["call_file"], "line": _int(row["call_line"]),
                        "note": "call into the vulnerable dependency function"}]
            return result(self.name, ran=True, state=REACHABLE,
                          reason=f"CodeQL Reachability.ql: {row['entry_name']}() reaches a call of {row['symbol']}",
                          witness=witness, gaps=gaps, **extra)
        reason = ("CodeQL static call edges found no path; a missing edge is not proof "
                  "(virtual or dynamic dispatch)") if found and found["state"] == reachability.UNREACHABLE else (
                  found["reason"] if found else "no Reachability.ql row for the advisory symbols")
        return result(self.name, ran=True, state=UNKNOWN, reason=reason, gaps=gaps, **extra)


# ---- lsp ---------------------------------------------------------------------------------------

class LspEngine:
    """Backward search over ``incomingCalls`` answers from queries tagged ``sink_symbol``."""
    name = "lsp"

    def __init__(self, documents: dict[str, dict[str, Any]]) -> None:
        self.documents = documents

    def assess(self, query: Query) -> dict[str, Any]:
        document = self.documents.get(query.language)
        if document is None:
            return result(self.name, ran=False, reason=f"no language-server call-hierarchy document for {query.language}",
                          gaps=[f"engine-input-absent:lsp:{query.language}"])
        callers: dict[tuple[str, int], list[dict[str, Any]]] = {}
        sinks: list[tuple[tuple[str, int], str]] = []
        wanted = {(item.get("package") or "", item["symbol"]) for item in query.symbols}
        for row in document.get("results", []):
            asked = row.get("query") or {}
            if row.get("status") != "OK" or asked.get("method") != "incomingCalls":
                continue
            node = (str(asked.get("path")), _int(asked.get("line")))
            callers.setdefault(node, []).extend(item for item in row.get("results", []) if isinstance(item, dict))
            sink = asked.get("sink_symbol")
            if isinstance(sink, dict) and (sink.get("package") or "", sink.get("symbol")) in wanted:
                sinks.append((node, str(sink.get("symbol"))))
        gaps = [f"lsp-server-gap:{gap.get('kind', 'unknown')}" for gap in document.get("gaps", [])
                if isinstance(gap, dict)][:8]
        if not sinks:
            return result(self.name, ran=True, reason="no incomingCalls answer for the advisory symbols",
                          gaps=gaps + [f"lsp-no-sink-query:{query.language}"])
        roots = set(ENTRY_POINTS.get(query.language, ())) | set(query.entry_points)
        for sink, symbol in sorted(sinks):
            parent: dict[tuple[str, int], tuple[tuple[str, int] | None, dict[str, Any] | None]] = {sink: (None, None)}
            queue: deque[tuple[str, int]] = deque([sink])
            while queue and len(parent) < MAX_LSP_NODES:
                node = queue.popleft()
                for caller in sorted(callers.get(node, []), key=lambda c: (c.get("path", ""), _int(c.get("start_line")))):
                    key = (str(caller.get("path")), _int(caller.get("start_line")))
                    if key in parent:
                        continue
                    parent[key] = (node, caller)
                    if caller.get("name") in roots:
                        return result(self.name, ran=True, state=REACHABLE, gaps=gaps,
                                      reason=f"language-server call hierarchy: {caller['name']}() reaches {symbol}",
                                      witness=self._witness(parent, key, symbol))
                    queue.append(key)
        return result(self.name, ran=True, reason="call hierarchy reached no entry point (not proof of absence)",
                      gaps=gaps)

    @staticmethod
    def _witness(parent: dict, start: tuple[str, int], symbol: str) -> list[dict[str, Any]]:
        steps, node = [], start
        while node is not None:
            previous, caller = parent[node]
            if caller is None:
                break
            lines = caller.get("call_lines") or [caller.get("start_line")]
            steps.append({"function": caller.get("name"), "file": caller.get("path"), "line": _int(caller.get("start_line")),
                          "calls_next_at": f"{caller.get('path')}:{_int(lines[0])}", "resolution": "lsp-call-hierarchy",
                          "_call_line": _int(lines[0])})
            node = previous
        last = steps[-1]
        steps.append({"function": symbol, "file": last["file"], "line": last.pop("_call_line"),
                      "note": "call into the vulnerable dependency function"})
        for step in steps:
            step.pop("_call_line", None)
        return steps


# ---- tree-sitter -------------------------------------------------------------------------------

class TreesitterEngine:
    name = "treesitter"

    def __init__(self, document: dict[str, Any] | None) -> None:
        self.document = document

    def assess(self, query: Query) -> dict[str, Any]:
        if self.document is None:
            return result(self.name, ran=False, reason="no tree-sitter AST summary",
                          gaps=[f"engine-input-absent:treesitter:{query.language}"])
        languages = TREESITTER_LANGUAGES.get(query.language, ())
        names = {_last(item["symbol"]): item["symbol"] for item in query.symbols}
        hints = []
        for entry in self.document.get("files", []):
            if entry.get("language") not in languages:
                continue
            for call in entry.get("calls", []):
                callee = call.get("callee") or ""
                last = _last(callee) if callee else ""
                if last in names:
                    function = next((f.get("name") for f in entry.get("functions", [])
                                     if _int(f.get("start_line")) <= _int(call.get("line")) <= _int(f.get("end_line"))), None)
                    hints.append({"file": entry["path"], "line": _int(call.get("line")), "callee": callee[:200],
                                  "symbol": names[last], "function": function})
        hints.sort(key=lambda row: (row["file"], row["line"], row["callee"]))
        if not hints:
            return result(self.name, ran=True, reason="no name-matched call site of the advisory symbols")
        return result(self.name, ran=True, witness_hint=hints[:MAX_HINTS],
                      reason=f"{len(hints)} name-matched call site(s) (tree-sitter; a name match is never proof)")


# ---- the set used by one 06 attempt ------------------------------------------------------------

class EngineSet:
    def __init__(self, *, cpg: reachability.CallGraph | None = None,
                 codeql: dict[str, dict[str, list[dict[str, str]]]] | None = None,
                 codeql_gaps: dict[str, list[str]] | None = None,
                 lsp: dict[str, dict[str, Any]] | None = None, treesitter: dict[str, Any] | None = None,
                 identity: dict[str, Any] | None = None) -> None:
        self.engines = {"cpg": CpgEngine(cpg), "codeql": CodeqlEngine(codeql or {}, codeql_gaps),
                        "lsp": LspEngine(lsp or {}), "treesitter": TreesitterEngine(treesitter)}
        self._identity = identity or {}

    def assess(self, name: str, query: Query) -> dict[str, Any]:
        return self.engines[name].assess(query)

    def identity(self) -> dict[str, Any]:
        return self._identity

    @classmethod
    def from_paths(cls, *, cpg_attempt: Path | None = None, codeql: dict[str, Path] | None = None,
                   lsp: dict[str, Path] | None = None, treesitter: Path | None = None) -> "EngineSet":
        """Offline/CLI construction from files on disk (the 06 lifecycle binds its own inputs)."""
        identity: dict[str, Any] = {}
        graph = reachability.load_cpg(cpg_attempt) if cpg_attempt else None
        if graph is not None:
            identity["cpg"] = graph.identity
        tables, table_gaps = load_codeql_dirs(codeql or {})
        identity["codeql"] = {lang: {name: sha256_bytes((directory / f"{name}.csv").read_bytes())
                                     for name in TABLES if (directory / f"{name}.csv").is_file()}
                              for lang, directory in sorted((codeql or {}).items())}
        documents = {lang: json.loads(path.read_text()) for lang, path in (lsp or {}).items()}
        identity["lsp"] = {lang: sha256_bytes(path.read_bytes()) for lang, path in sorted((lsp or {}).items())}
        ast = json.loads(treesitter.read_text()) if treesitter else None
        identity["treesitter"] = sha256_bytes(treesitter.read_bytes()) if treesitter else None
        return cls(cpg=graph, codeql=tables, codeql_gaps=table_gaps, lsp=documents, treesitter=ast, identity=identity)


def load_codeql_dirs(directories: dict[str, Path]) -> tuple[dict[str, dict[str, list[dict[str, str]]]], dict[str, list[str]]]:
    """``{lang: dir}`` -> decoded tables and per-language gaps (a bad or absent table is a gap)."""
    tables: dict[str, dict[str, list[dict[str, str]]]] = {}
    gaps: dict[str, list[str]] = {}
    for language, directory in sorted(directories.items()):
        decoded = {}
        for name in TABLES:
            path = Path(directory) / f"{name}.csv"
            if not path.is_file() or path.is_symlink():
                gaps.setdefault(language, []).append(f"codeql-table-absent:{language}:{name}")
                continue
            try:
                decoded[name] = read_table(path.read_bytes(), name)
            except ValueError:
                gaps.setdefault(language, []).append(f"codeql-table-invalid:{language}:{name}")
        if decoded:
            tables[language] = decoded
    return tables, gaps
