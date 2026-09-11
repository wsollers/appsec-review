#!/usr/bin/env python3
"""
build_symbol_index.py — tree-sitter based, best-effort symbol/definition and
call-site index across the polyglot vendor codebase (C#, C++, Python, Go,
PHP, plus a lightweight HCL/Terraform block extractor).

This is Phase 0A of the Vendor Code Audit Playbook, deliberately upstream of
every LLM prompt: it turns "grep around and hope" into a structured JSON
index that the Discovery (Phase 1) and CVE-reachability (Phase 5) prompts
can be handed directly instead of asking a model to search a codebase from
memory.

WHAT THIS IS NOT: a substitute for CodeQL, joern, or a real language-server
(Roslyn/gopls/pyright) call graph. Tree-sitter gives you syntax, not full
semantic resolution — overloads, dynamic dispatch, and cross-file symbol
binding are not resolved here. Treat the output as "candidate call edges by
name" for triage, and reach for CodeQL/joern/language-server tooling (see
the playbook's Phase 5 notes) when you need a semantically exact call graph,
e.g. to confirm a CVE-reachability finding before it ships in a report.

Usage:
    pip install tree-sitter tree-sitter-language-pack --break-system-packages
    python3 build_symbol_index.py /path/to/repo -o /evidence/symbol-index

Output: one JSON file per source file under the output directory, mirroring
the input relative path (e.g. gameserver/net/listener.cpp.json), plus a
combined index.json with every definition and call site flattened for easy
grepping/loading, and a summary.json with per-language file/def/call counts.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    import tree_sitter
    import tree_sitter_language_pack as tlp
except ImportError:
    sys.exit(
        "This script requires tree-sitter + tree-sitter-language-pack:\n"
        "  pip install tree-sitter tree-sitter-language-pack --break-system-packages"
    )

# ---------------------------------------------------------------------------
# Extension -> tree-sitter grammar name, and the definition/call queries.
# Queries deliberately favor recall over precision — false positives in a
# "candidate call sites" index are cheap to discard; false negatives hide a
# reachable path.
# ---------------------------------------------------------------------------

LANGUAGES: dict[str, dict[str, Any]] = {
    "python": {
        "extensions": {".py"},
        "query": """
            (function_definition name: (identifier) @func.name)
            (class_definition name: (identifier) @class.name)
            (call function: (identifier) @call.name)
            (call function: (attribute attribute: (identifier) @call.name))
            (import_statement) @import.stmt
            (import_from_statement) @import.stmt
        """,
    },
    "cpp": {
        "extensions": {".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"},
        "query": """
            (function_definition declarator: (function_declarator declarator: (identifier) @func.name))
            (function_definition declarator: (function_declarator declarator: (field_identifier) @func.name))
            (class_specifier name: (type_identifier) @class.name)
            (struct_specifier name: (type_identifier) @class.name)
            (call_expression function: (identifier) @call.name)
            (call_expression function: (qualified_identifier name: (identifier) @call.name))
            (call_expression function: (field_expression field: (field_identifier) @call.name))
            (preproc_include) @import.stmt
        """,
    },
    "go": {
        "extensions": {".go"},
        "query": """
            (function_declaration name: (identifier) @func.name)
            (method_declaration name: (field_identifier) @func.name)
            (call_expression function: (identifier) @call.name)
            (call_expression function: (selector_expression field: (field_identifier) @call.name))
            (import_spec) @import.stmt
        """,
    },
    "php": {
        "extensions": {".php"},
        "query": """
            (function_definition name: (name) @func.name)
            (method_declaration name: (name) @func.name)
            (class_declaration name: (name) @class.name)
            (function_call_expression function: (name) @call.name)
            (member_call_expression name: (name) @call.name)
            (scoped_call_expression name: (name) @call.name)
        """,
    },
    "csharp": {
        "extensions": {".cs"},
        "query": """
            (method_declaration name: (identifier) @func.name)
            (class_declaration name: (identifier) @class.name)
            (invocation_expression function: (identifier) @call.name)
            (invocation_expression function: (member_access_expression name: (identifier) @call.name))
            (using_directive) @import.stmt
        """,
    },
}

# HCL gets a lighter, structural (not call-graph) pass: resource/module/data
# blocks and their labels. Terraform's own `terraform graph` command is the
# authoritative dependency graph for actual resource references — this is
# just enough to inventory *what's declared* per file for Phase 1 discovery.
HCL_QUERY = """
(block (identifier) @block.type (string_lit (template_literal) @block.label))
"""

EXT_TO_LANG = {ext: name for name, cfg in LANGUAGES.items() for ext in cfg["extensions"]}
EXT_TO_LANG.update({".tf": "hcl", ".tf.json": "hcl"})

_parser_cache: dict[str, tree_sitter.Parser] = {}
_query_cache: dict[str, tree_sitter.Query] = {}


def get_parser(lang_name: str) -> tree_sitter.Parser:
    if lang_name not in _parser_cache:
        _parser_cache[lang_name] = tlp.get_parser(lang_name)
    return _parser_cache[lang_name]


def get_query(lang_name: str, query_src: str) -> tree_sitter.Query:
    if lang_name not in _query_cache:
        lang = tlp.get_language(lang_name)
        _query_cache[lang_name] = tree_sitter.Query(lang, query_src)
    return _query_cache[lang_name]


def index_file(path: Path, lang_name: str) -> dict[str, Any]:
    src_bytes = path.read_bytes()
    parser = get_parser(lang_name)
    tree = parser.parse(src_bytes)

    if lang_name == "hcl":
        query_src = HCL_QUERY
    else:
        query_src = LANGUAGES[lang_name]["query"]

    query = get_query(lang_name, query_src)
    cursor = tree_sitter.QueryCursor(query)
    captures = cursor.captures(tree.root_node)

    def node_text(n) -> str:
        return src_bytes[n.start_byte:n.end_byte].decode("utf-8", errors="replace")

    defs, classes, calls, imports, blocks = [], [], [], [], []
    for cap_name, nodes in captures.items():
        for n in nodes:
            line = n.start_point[0] + 1
            if cap_name == "func.name":
                defs.append({"name": node_text(n), "line": line})
            elif cap_name == "class.name":
                classes.append({"name": node_text(n), "line": line})
            elif cap_name == "call.name":
                calls.append({"name": node_text(n), "line": line})
            elif cap_name == "import.stmt":
                imports.append({"text": node_text(n).strip().splitlines()[0][:200], "line": line})
            elif cap_name in ("block.type",):
                blocks.append({"type": node_text(n), "line": line})

    return {
        "path": None,  # filled in by caller
        "language": lang_name,
        "definitions": sorted(defs, key=lambda d: d["line"]),
        "classes": sorted(classes, key=lambda d: d["line"]),
        "calls": sorted(calls, key=lambda d: d["line"]),
        "imports": sorted(imports, key=lambda d: d["line"]),
        "hcl_blocks": sorted(blocks, key=lambda d: d["line"]) if lang_name == "hcl" else [],
        "parse_had_error": tree.root_node.has_error,
    }


def iter_source_files(root: Path):
    skip_dirs = {".git", "node_modules", "vendor", "bin", "obj", ".terraform", "dist", "build", "Library", "Temp"}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        suffix = p.suffix.lower()
        if suffix in EXT_TO_LANG:
            yield p


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", type=Path, help="Repository root to index")
    ap.add_argument("-o", "--output", type=Path, required=True, help="Output directory for the index")
    ap.add_argument("--max-file-bytes", type=int, default=3_000_000,
                     help="Skip files larger than this (default 3MB) — huge generated files rarely need indexing")
    args = ap.parse_args()

    repo = args.repo.resolve()
    out_dir = args.output
    out_dir.mkdir(parents=True, exist_ok=True)

    combined: list[dict[str, Any]] = []
    per_lang_counts: dict[str, dict[str, int]] = {}
    errors: list[str] = []

    files = list(iter_source_files(repo))
    print(f"Found {len(files)} candidate source file(s) under {repo}", file=sys.stderr)

    for i, path in enumerate(files, 1):
        rel = path.relative_to(repo)
        lang_name = EXT_TO_LANG.get(path.suffix.lower())
        if lang_name is None:
            continue
        try:
            if path.stat().st_size > args.max_file_bytes:
                errors.append(f"SKIPPED (too large): {rel}")
                continue
            result = index_file(path, lang_name)
        except Exception as e:  # keep going — one bad file shouldn't kill the run
            errors.append(f"FAILED: {rel} — {e}")
            continue

        result["path"] = str(rel).replace("\\", "/")
        combined.append(result)

        counts = per_lang_counts.setdefault(lang_name, {"files": 0, "definitions": 0, "calls": 0, "parse_errors": 0})
        counts["files"] += 1
        counts["definitions"] += len(result["definitions"]) + len(result["classes"])
        counts["calls"] += len(result["calls"])
        if result["parse_had_error"]:
            counts["parse_errors"] += 1

        out_path = out_dir / (str(rel).replace("\\", "/") + ".json")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

        if i % 200 == 0:
            print(f"  indexed {i}/{len(files)}...", file=sys.stderr)

    (out_dir / "index.json").write_text(json.dumps(combined, indent=2), encoding="utf-8")
    (out_dir / "summary.json").write_text(
        json.dumps({"per_language": per_lang_counts, "errors": errors, "total_files": len(combined)}, indent=2),
        encoding="utf-8",
    )
    if errors:
        (out_dir / "errors.log").write_text("\n".join(errors), encoding="utf-8")

    print(f"Indexed {len(combined)} file(s). Summary: {json.dumps(per_lang_counts)}", file=sys.stderr)
    if errors:
        print(f"{len(errors)} file(s) skipped/failed — see {out_dir / 'errors.log'}", file=sys.stderr)


if __name__ == "__main__":
    main()
