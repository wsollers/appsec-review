#!/usr/bin/env python3
"""Generate a retrieval plan for the LLM from evidence indexes and findings.

The plan is a navigation aid, not proof. It tells the LLM where to look next:
risky files, repeated symbols, candidate callers/callees, and semantic queries.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SECURITY_QUERIES = [
    "authentication and authorization checks",
    "request parsing and deserialization of untrusted input",
    "file upload import export path traversal",
    "buffer copy length calculation memory allocation bounds",
    "cryptographic key generation encryption signing verification",
    "SQL query construction database command execution",
    "process execution shell command construction",
    "network listener socket RPC IPC message handler",
    "secret token credential storage logging",
    "update download plugin extension loading trust boundary",
]


def load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def norm(path: str) -> str:
    return path.replace("\\", "/").lstrip("/")


def load_symbol_index(path: Path) -> list[dict]:
    data = load_json(path)
    return data if isinstance(data, list) else []


def symbol_maps(index: list[dict]) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    defs: dict[str, list[dict]] = defaultdict(list)
    calls: dict[str, list[dict]] = defaultdict(list)
    for rec in index:
        path = norm(rec.get("path", ""))
        for d in rec.get("definitions", []) or []:
            defs[d.get("name", "")].append({"path": path, "line": d.get("line", 0), "language": rec.get("language", "")})
        for c in rec.get("calls", []) or []:
            calls[c.get("name", "")].append({"path": path, "line": c.get("line", 0), "language": rec.get("language", "")})
    return defs, calls


def interesting_symbol(name: str) -> bool:
    return bool(re.search(r"(auth|login|token|session|parse|decode|deserialize|encrypt|decrypt|sign|verify|exec|shell|query|sql|copy|alloc|read|write|socket|listen|upload|download|import|export)", name, re.I))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--static-evidence", required=True)
    ap.add_argument("--correlated-findings", required=True)
    ap.add_argument("--native-scratch", default="")
    ap.add_argument("--out", required=True)
    ap.add_argument("--top", type=int, default=30)
    args = ap.parse_args()

    static = Path(args.static_evidence)
    native = Path(args.native_scratch) if args.native_scratch else None
    corr = load_json(Path(args.correlated_findings)) or {}
    clusters = corr.get("clusters", []) if isinstance(corr, dict) else []
    sym_index = load_symbol_index(static / "symbol-index" / "index.json")
    sym_summary = load_json(static / "symbol-index" / "summary.json") or {}
    defs, calls = symbol_maps(sym_index)

    file_score = Counter()
    symbol_score = Counter()
    for c in clusters:
        file = c.get("file") or ""
        if file:
            file_score[file] += max(1, len(c.get("tools", []))) * max(1, c.get("finding_count", 1))
        for f in c.get("findings", []) or []:
            msg = f.get("message", "")
            for name in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b", msg):
                if interesting_symbol(name):
                    symbol_score[name] += 1

    # Pull in risky-looking symbols from the index itself, weighted by references.
    for name, locs in defs.items():
        if interesting_symbol(name):
            symbol_score[name] += len(calls.get(name, [])) + len(locs)

    risky_files = [{"file": f, "score": n} for f, n in file_score.most_common(args.top)]
    symbols = []
    for name, score in symbol_score.most_common(args.top):
        symbols.append({
            "symbol": name,
            "score": score,
            "definitions": defs.get(name, [])[:8],
            "candidate_callers": calls.get(name, [])[:20],
            "candidate_call_count": len(calls.get(name, [])),
            "note": "candidate call graph from tree-sitter names; confirm with source/CodeQL/Joern before treating as reachability proof",
        })

    semantic_index_dir = static / "semantic-index"
    semantic_available = semantic_index_dir.exists()
    semantic_queries = []
    for q in SECURITY_QUERIES:
        semantic_queries.append({
            "query": q,
            "command": f"python3 scripts/query_semantic_index.py {semantic_index_dir} {json.dumps(q)} --limit 10 --json",
            "available": semantic_available,
        })

    source_searches = []
    for pat in [
        r"memcpy|memmove|strcpy|strncpy|sprintf|snprintf",
        r"TODO|FIXME|HACK|XXX|SECURITY|unsafe",
        r"password|secret|token|apikey|api_key|credential",
        r"system\(|popen\(|CreateProcess|ShellExecute|exec\(",
        r"deserialize|unserialize|pickle|yaml\.load|JsonConvert",
        r"SELECT .*\\+|INSERT .*\\+|UPDATE .*\\+|SqlCommand",
    ]:
        source_searches.append({"pattern": pat, "command": f"rg -n --glob '!node_modules' --glob '!vendor' {json.dumps(pat)} <target>"})

    codeql_db = native / "codeql" / "db-cpp" if native else None
    codeql_regular = native / "codeql" / "cpp.sarif" if native else None
    codeql_mythos = native / "codeql" / "mythos.sarif" if native else None
    codeql_guidance = {
        "available": bool(codeql_db and codeql_db.exists()),
        "database": str(codeql_db) if codeql_db else "",
        "regular_security_extended_sarif": str(codeql_regular) if codeql_regular else "",
        "custom_memory_queries_sarif": str(codeql_mythos) if codeql_mythos else "",
        "custom_query_pack": "queries/mythos-cpp",
        "trust": "Use CodeQL findings as SAST evidence. Use custom query results as memory-safety candidates; confirm high-impact claims with IR facts, source, or reviewer analysis.",
        "follow_up_commands": [
            "codeql database analyze <native-scratch>/codeql/db-cpp codeql/cpp-queries:codeql-suites/cpp-security-extended.qls --format=sarif-latest --output=<out>/cpp-rerun.sarif --rerun",
            "codeql database analyze <native-scratch>/codeql/db-cpp queries/mythos-cpp --additional-packs=/opt/codeql/qlpacks --format=sarif-latest --output=<out>/mythos-rerun.sarif --rerun",
        ],
    }

    plan = {
        "schema": "appsec-review/retrieval-plan/0.1",
        "purpose": "Navigation plan for LLM/human review. Retrieval hints are not findings unless corroborated by evidence.",
        "symbol_index": {
            "available": bool(sym_index),
            "summary": sym_summary,
            "path": str(static / "symbol-index" / "index.json"),
            "trust": "candidate definitions/call sites by syntax/name; not semantic reachability proof",
        },
        "semantic_index": {
            "available": semantic_available,
            "path": str(semantic_index_dir),
            "trust": "recall/retrieval aid only; cite source lines and tool evidence for claims",
        },
        "codeql": codeql_guidance,
        "risky_files": risky_files,
        "symbols_to_inspect": symbols,
        "semantic_queries": semantic_queries,
        "source_searches": source_searches,
        "next_review_tasks": [
            "Start with clusters corroborated by multiple tools or native verification statuses.",
            "For each unresolved native finding, retrieve callers and adjacent validation logic before judging.",
            "For each secret/SCA/BinSkim hit, confirm applicability and reachability before reporting.",
            "Use semantic search to find equivalent code paths not covered by the first finding cluster.",
            "Record missing evidence requests explicitly instead of inferring clean status.",
        ],
    }

    out = Path(args.out)
    out.write_text(json.dumps(plan, indent=1), encoding="utf-8")
    md = out.with_suffix(".md")
    lines = [
        "# Retrieval Plan",
        "",
        "This plan is a navigation aid, not proof. Use it to decide what source and evidence to retrieve next.",
        "",
        "## Indexes",
        f"- Symbol index: `{plan['symbol_index']['path']}` available={plan['symbol_index']['available']}",
        f"- Semantic index: `{plan['semantic_index']['path']}` available={plan['semantic_index']['available']}",
        f"- CodeQL database: `{plan['codeql']['database']}` available={plan['codeql']['available']}",
        "",
        "## CodeQL",
        f"- Regular C/C++ security suite SARIF: `{plan['codeql']['regular_security_extended_sarif']}`",
        f"- Custom memory query SARIF: `{plan['codeql']['custom_memory_queries_sarif']}`",
        f"- Custom query pack: `{plan['codeql']['custom_query_pack']}`",
        f"- Trust note: {plan['codeql']['trust']}",
        "- Follow-up commands:",
    ]
    for cmd in codeql_guidance["follow_up_commands"]:
        lines.append(f"  - `{cmd}`")
    lines += [
        "",
        "## Risky Files",
    ]
    for item in risky_files[:20]:
        lines.append(f"- `{item['file']}` score={item['score']}")
    lines += ["", "## Symbols / Candidate Callers"]
    for s in symbols[:20]:
        locs = ", ".join(f"{d['path']}:{d['line']}" for d in s["definitions"][:3]) or "no definition indexed"
        lines.append(f"- `{s['symbol']}` score={s['score']} definitions={locs} candidate_callers={s['candidate_call_count']}")
    lines += ["", "## Semantic Queries"]
    for q in semantic_queries:
        lines.append(f"- {q['query']}: `{q['command']}`")
    lines += ["", "## Source Searches"]
    for q in source_searches:
        lines.append(f"- `{q['command']}`")
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out} and {md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
