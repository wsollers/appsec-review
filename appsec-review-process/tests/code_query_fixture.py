"""Small C/C++ fixture for the code index and the code_* query tools (brief U).

A CPG records file shaped like ``code_graph_evidence.normalize_jsonl`` output (method records carry
only their first line, as Joern's exporter does), a tree-sitter AST document with real spans, and
one export table. Designed cases: a unique symbol (``parse_request``), an overloaded one
(``log_msg`` in app/ and lib/), a callback whose only callers are indirect (``on_message``: address
taken at app/parse.c:15, an indirect call in main), an ambiguous call (tools/cli.c -> log_msg), the
unsafe-copy family with argument text, a string literal, and two C++ types with a same-named method.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

SHA = {path: "sha256:" + hashlib.sha256(path.encode()).hexdigest() for path in (
    "app/main.c", "app/parse.c", "app/net.c", "app/log.c", "lib/log.c", "tools/cli.c", "src/widget.cpp")}


def method(full, name, path, line, signature=""):
    return {"kind": "symbol", "label": "METHOD", "name": name, "full_name": full, "caller": "",
            "type_name": signature, "code": name, "source_path": path, "source_sha256": SHA[path],
            "start_line": line, "end_line": line}


def call(caller, callee, name, path, line, code="", kind="call"):
    return {"kind": kind, "label": "CALL", "name": name, "full_name": callee, "caller": caller, "type_name": "",
            "code": code, "source_path": path, "source_sha256": SHA[path], "start_line": line, "end_line": line}


def type_decl(name, full, path, line):
    return {"kind": "type", "label": "TYPE_DECL", "name": name, "full_name": full, "caller": "", "type_name": full,
            "code": "class " + name, "source_path": path, "source_sha256": SHA[path], "start_line": line,
            "end_line": line}


def ident(name, path, line):
    return {"kind": "identifier", "label": "IDENTIFIER", "name": name, "full_name": "", "caller": "",
            "type_name": "int", "code": name, "source_path": path, "source_sha256": SHA[path], "start_line": line,
            "end_line": line}


U = "<unresolvedNamespace>.{0}:<unresolvedSignature>({1})"
RECORDS = [
    method("main", "main", "app/main.c", 3, "int(int,char**)"),
    call("main", "parse_request", "parse_request", "app/main.c", 6, "parse_request(argv[1], 64)"),
    call("main", "<operator>.pointerCall", "<operator>.pointerCall", "app/main.c", 8, "handler(msg)"),
    method("parse_request", "parse_request", "app/parse.c", 2, "int(char*,int)"),
    call("parse_request", "copy_field", "copy_field", "app/parse.c", 8, "copy_field(dst, src)"),
    call("parse_request", U.format("memcpy", 3), "memcpy", "app/parse.c", 10, "memcpy(dst, src, len)", "memory-operation"),
    call("parse_request", U.format("sprintf", 3), "sprintf", "app/parse.c", 12, 'sprintf(buf, "%s:%d", host)'),
    call("parse_request", U.format("log_msg", 1), "log_msg", "app/parse.c", 13, "log_msg(buf)"),
    call("parse_request", U.format("register_cb", 1), "register_cb", "app/parse.c", 15, "register_cb(&on_message)"),
    call("parse_request", "<operator>.addressOf", "<operator>.addressOf", "app/parse.c", 15, "&on_message"),
    method("copy_field", "copy_field", "app/parse.c", 20, "void(char*,char*)"),
    call("copy_field", U.format("strcpy", 2), "strcpy", "app/parse.c", 22, "strcpy(dst, src)", "memory-operation"),
    method("on_message", "on_message", "app/net.c", 1, "void(char*)"),
    call("on_message", "copy_field", "copy_field", "app/net.c", 4, "copy_field(out, msg)"),
    method("app/log.c:log_msg", "log_msg", "app/log.c", 1, "void(char*)"),
    method("lib/log.c:log_msg", "log_msg", "lib/log.c", 1, "void(char*)"),
    method("cli_main", "cli_main", "tools/cli.c", 1, "int()"),
    call("cli_main", U.format("log_msg", 1), "log_msg", "tools/cli.c", 3, "log_msg(\"hello\")"),
    type_decl("Widget", "ui.Widget", "src/widget.cpp", 3),
    type_decl("Button", "ui.Button", "src/widget.cpp", 12),
    method("ui.Widget.draw:void()", "draw", "src/widget.cpp", 5, "void()"),
    method("ui.Button.draw:void()", "draw", "src/widget.cpp", 14, "void()"),
    ident("len", "app/parse.c", 10),
]
TREESITTER = {"schema": "appsec-review/treesitter-ast/1", "files": [
    {"path": "app/main.c", "language": "c", "sha256": SHA["app/main.c"], "functions": [
        {"name": "main", "kind": "function_definition", "start_line": 3, "end_line": 11}],
     "calls": [{"callee": "parse_request", "line": 6}, {"callee": "handler", "line": 8}],
     "imports": [{"text": "#include \"parse.h\"", "line": 1}]},
    {"path": "app/parse.c", "language": "c", "sha256": SHA["app/parse.c"], "functions": [
        {"name": "parse_request", "kind": "function_definition", "start_line": 2, "end_line": 17},
        {"name": "copy_field", "kind": "function_definition", "start_line": 19, "end_line": 23}],
     "calls": [{"callee": "memcpy", "line": 10}, {"callee": "strcpy", "line": 22}],
     "imports": [{"text": "#include <string.h>", "line": 1}]},
    {"path": "app/net.c", "language": "c", "sha256": SHA["app/net.c"], "functions": [
        {"name": "on_message", "kind": "function_definition", "start_line": 1, "end_line": 6}],
     "calls": [{"callee": "copy_field", "line": 4}], "imports": []},
    {"path": "scripts/tool.py", "language": "python", "sha256": "sha256:" + "1" * 64, "functions": [
        {"name": "run", "kind": "function_definition", "start_line": 1, "end_line": 4}],
     "calls": [], "imports": [{"text": "import os", "line": 1}]},
], "gaps": []}
EXPORTS = [{"artifact": "libapp.so", "binary_sha256": "sha256:" + "2" * 64, "artifact_kind": "shared-library",
            "complete": True, "gaps": [], "exports": [{"symbol": "parse_request", "demangled": None},
                                                       {"symbol": "log_msg", "demangled": None}]}]


def write_cpg(folder: Path, records=RECORDS, gaps=()) -> tuple[Path, dict]:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "code-property-graph.records.jsonl"
    data = b"".join(json.dumps(record, sort_keys=True).encode() + b"\n" for record in records)
    path.write_bytes(data)
    summary = {"records_file": {"path": path.name, "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                                "count": len(records)}, "coverage_gaps": list(gaps),
               "source_snapshot_sha256": "sha256:" + "3" * 64}
    return path, summary


def build(folder: Path, *, treesitter=True, exports=True, gaps=()) -> tuple[Path, dict]:
    import code_index
    records, summary = write_cpg(folder, gaps=gaps)
    database = folder / code_index.SQLITE
    sources = {"cpg": {"job": "02-code-property-graph", "attempt_id": "cpg1",
                       "records_sha256": summary["records_file"]["sha256"]}}
    result = code_index.build(database, records=records, cpg_summary=summary, sources=sources,
                              treesitter=TREESITTER if treesitter else None,
                              export_tables=EXPORTS if exports else None)
    return database, result


def publish(jobs: Path, **kwargs) -> tuple[str, dict]:
    """A code index laid out as an accepted 02-code-index attempt; returns (ref path, summary)."""
    attempt = jobs / "02-code-index" / "attempts" / "a1"
    database, result = build(attempt, **kwargs)
    summary = {**result, "sqlite": {"path": database.name,
                                    "sha256": "sha256:" + hashlib.sha256(database.read_bytes()).hexdigest(),
                                    "bytes": database.stat().st_size}}
    (attempt / "code-index.json").write_text(json.dumps(summary, sort_keys=True))
    return "02-code-index/attempts/a1/code-index.json", summary
