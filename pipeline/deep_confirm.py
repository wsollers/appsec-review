#!/usr/bin/env python3
"""Add call-graph, IR, and cross-tool confirmation context to correlated findings.

This is a deterministic triage layer. It does not prove semantic reachability.
It turns each correlated cluster into a compact confirmation record:

* which substrates saw it: source SAST, native CSA/IR bundle, CodeQL
* whether IR facts exist near the source line
* the likely enclosing symbol, nearby callees, and candidate callers from the
  tree-sitter symbol index
* a conservative confirmation level for the LLM/human to use as routing
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


IR_KINDS = ("field_geps", "geps", "size_calls", "allocas", "ctor_stores")
SOURCE_TOOLS = {"semgrep", "cppcheck-static", "binskim", "mobsfscan-android", "mobsfscan-ios"}
NATIVE_TOOLS = {"clang-tidy", "cppcheck-native", "native-bundle", "native-informational"}
CODEQL_TOOLS = {"codeql-cpp-security-extended", "codeql-mythos"}
LEVEL_PRIORITY = {
    "mechanism-confirmed": 0,
    "codeql-ir-corroborated": 1,
    "cross-tool-corroborated": 2,
    "codeql-only": 3,
    "source-only": 4,
    "unclassified": 5,
}


def load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def norm_path(path: str | None) -> str:
    if not path:
        return ""
    p = str(path).replace("\\", "/")
    if "/workspace/" in p:
        return p.split("/workspace/", 1)[1].lstrip("/")
    return p.lstrip("/")


def basename(path: str | None) -> str:
    return norm_path(path).split("/")[-1]


def line_in_range(line: int, start: int, end: int, default_window: int = 12) -> bool:
    if line <= 0:
        return False
    if end <= 0:
        return abs(line - start) <= default_window
    return start <= line <= end


def load_symbol_records(path: Path) -> list[dict]:
    data = load_json(path)
    return data if isinstance(data, list) else []


def build_symbol_context(records: list[dict]) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    by_file: dict[str, list[dict]] = defaultdict(list)
    callers_by_name: dict[str, list[dict]] = defaultdict(list)

    for rec in records:
        file = norm_path(rec.get("path", ""))
        symbols = []
        for d in rec.get("definitions", []) or []:
            if d.get("name"):
                symbols.append({"name": d.get("name"), "line": int(d.get("line") or 0), "kind": "function"})
        for c in rec.get("classes", []) or []:
            if c.get("name"):
                symbols.append({"name": c.get("name"), "line": int(c.get("line") or 0), "kind": "class"})
        symbols.sort(key=lambda s: s["line"])
        for i, sym in enumerate(symbols):
            next_line = symbols[i + 1]["line"] if i + 1 < len(symbols) else 0
            sym["end_line"] = max(0, next_line - 1) if next_line else 0
            sym["path"] = file
            by_file[file].append(sym)

        for call in rec.get("calls", []) or []:
            name = call.get("name")
            if not name:
                continue
            callers_by_name[name].append({
                "path": file,
                "line": int(call.get("line") or 0),
                "language": rec.get("language", ""),
            })

    return by_file, callers_by_name


def enclosing_symbol(file: str, line: int, by_file: dict[str, list[dict]]) -> dict | None:
    symbols = by_file.get(file, [])
    if not symbols:
        return None
    containing = [s for s in symbols if line_in_range(line, s.get("line", 0), s.get("end_line", 0))]
    if containing:
        return max(containing, key=lambda s: s.get("line", 0))
    before = [s for s in symbols if s.get("line", 0) <= line]
    return max(before, key=lambda s: s.get("line", 0)) if before else symbols[0]


def nearby_callees(file: str, line_min: int, line_max: int, records: list[dict], window: int) -> list[dict]:
    lo = max(1, line_min - window) if line_min else 0
    hi = line_max + window if line_max else 0
    out = []
    for rec in records:
        if norm_path(rec.get("path", "")) != file:
            continue
        for call in rec.get("calls", []) or []:
            line = int(call.get("line") or 0)
            if (lo and hi and lo <= line <= hi) or (not lo and line):
                out.append({"name": call.get("name", ""), "line": line})
    return sorted(out, key=lambda c: (c["line"], c["name"]))[:24]


def load_ir_facts(paths: list[Path]) -> dict[str, dict[int, list[dict]]]:
    facts: dict[str, dict[int, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for path in paths:
        data = load_json(path)
        if not isinstance(data, dict):
            continue
        module = data.get("module") or path.stem.removeprefix("ir-facts-")
        for kind in IR_KINDS:
            for item in data.get(kind, []) or []:
                loc = item.get("loc") if isinstance(item, dict) else None
                if not isinstance(loc, dict) or "file" not in loc or "line" not in loc:
                    continue
                fact = {
                    "kind": kind,
                    "module": module,
                    "file": norm_path(loc.get("file", "")),
                    "line": int(loc.get("line") or 0),
                    "function": item.get("demangled") or item.get("function") or "",
                }
                for key in ("struct", "ptr_field", "bounded_by_fields", "index_depends_on_arg", "callee"):
                    if key in item:
                        fact[key] = item[key]
                facts[basename(fact["file"])][fact["line"]].append(fact)
    return facts


def facts_near(facts: dict[str, dict[int, list[dict]]], file: str, line_min: int, line_max: int, tol: int) -> list[dict]:
    if line_min <= 0 and line_max <= 0:
        return []
    lo = max(1, (line_min or line_max) - tol)
    hi = (line_max or line_min) + tol
    out = []
    by_line = facts.get(basename(file), {})
    for line in range(lo, hi + 1):
        out.extend(by_line.get(line, []))
    return out[:40]


def classify_cluster(cluster: dict, ir_near: list[dict]) -> tuple[str, list[str]]:
    tools = set(cluster.get("tools", []) or [])
    statuses = cluster.get("verification_statuses", {}) or {}
    reasons = []
    substrates = 0
    if tools & SOURCE_TOOLS:
        substrates += 1
        reasons.append("source-level SAST evidence")
    if tools & (NATIVE_TOOLS | CODEQL_TOOLS):
        substrates += 1
        reasons.append("native/CodeQL tool evidence")
    if ir_near:
        substrates += 1
        reasons.append("IR facts near source location")
    if statuses.get("VERIFIED_PRIMITIVE"):
        return "mechanism-confirmed", reasons + ["native verifier reported VERIFIED_PRIMITIVE"]
    if tools & CODEQL_TOOLS and ir_near:
        return "codeql-ir-corroborated", reasons
    if substrates >= 2:
        return "cross-tool-corroborated", reasons
    if tools & CODEQL_TOOLS:
        return "codeql-only", reasons
    if tools & SOURCE_TOOLS:
        return "source-only", reasons
    return "unclassified", reasons


def confirmation_sort_key(item: dict) -> tuple:
    tools = set(item.get("tools", []) or [])
    has_native = bool(tools & (NATIVE_TOOLS | CODEQL_TOOLS))
    return (
        LEVEL_PRIORITY.get(item.get("confirmation_level", "unclassified"), 9),
        -int(bool(item.get("ir_facts_nearby"))),
        -int(has_native),
        item.get("file", ""),
        int(item.get("line_min") or 0),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--correlated-findings", required=True)
    ap.add_argument("--static-evidence", required=True)
    ap.add_argument("--native-scratch", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--line-window", type=int, default=20)
    ap.add_argument("--top", type=int, default=120)
    args = ap.parse_args()

    corr_path = Path(args.correlated_findings)
    static = Path(args.static_evidence)
    native = Path(args.native_scratch)
    out = Path(args.out)

    corr = load_json(corr_path) or {}
    clusters = corr.get("clusters", []) if isinstance(corr, dict) else []
    symbol_index_path = static / "symbol-index" / "index.json"
    symbol_records = load_symbol_records(symbol_index_path)
    symbols_by_file, callers_by_name = build_symbol_context(symbol_records)
    ir_paths = sorted(native.glob("ir-facts-*.json"))
    ir_index = load_ir_facts(ir_paths)

    confirmations = []
    for cluster in clusters:
        file = norm_path(cluster.get("file", ""))
        line_min = int(cluster.get("line_min") or 0)
        line_max = int(cluster.get("line_max") or line_min or 0)
        ir_near = facts_near(ir_index, file, line_min, line_max, args.line_window)
        level, reasons = classify_cluster(cluster, ir_near)
        symbol = enclosing_symbol(file, line_min or line_max, symbols_by_file)
        candidate_callers = []
        if symbol and symbol.get("name"):
            candidate_callers = callers_by_name.get(symbol["name"], [])[:30]
        confirmations.append({
            "cluster_id": cluster.get("id", ""),
            "confirmation_level": level,
            "reasons": reasons,
            "file": file,
            "line_min": line_min,
            "line_max": line_max,
            "tools": cluster.get("tools", []),
            "verification_statuses": cluster.get("verification_statuses", {}),
            "enclosing_symbol": symbol,
            "candidate_callers": candidate_callers,
            "nearby_callees": nearby_callees(file, line_min, line_max, symbol_records, args.line_window),
            "ir_facts_nearby": ir_near,
            "findings": cluster.get("findings", [])[:12],
            "trust": "candidate callers/callees are syntax/name based; use CodeQL/Joern/source review for semantic reachability proof",
        })

    confirmations.sort(key=confirmation_sort_key)
    level_counts = Counter(c["confirmation_level"] for c in confirmations)
    tool_counts = Counter(t for c in confirmations for t in c.get("tools", []))
    report = {
        "schema": "appsec-review/deep-confirmation/0.1",
        "purpose": "Cross-tool and call-graph confirmation context for LLM/human triage; not a final vulnerability verdict.",
        "inputs": {
            "correlated_findings": str(corr_path),
            "symbol_index": str(symbol_index_path),
            "ir_facts": [str(p) for p in ir_paths],
        },
        "counts": {
            "clusters": len(clusters),
            "confirmed": len(confirmations),
            "by_confirmation_level": dict(level_counts.most_common()),
            "by_tool": dict(tool_counts.most_common()),
        },
        "confirmations": confirmations[: args.top],
    }
    out.write_text(json.dumps(report, indent=1), encoding="utf-8")

    md = out.with_suffix(".md")
    lines = [
        "# Deep Confirmation",
        "",
        "This is a deterministic routing artifact, not a final vulnerability verdict.",
        "",
        f"- clusters analyzed: {len(clusters)}",
        f"- symbol index: `{symbol_index_path}` available={bool(symbol_records)}",
        f"- IR fact files: {len(ir_paths)}",
        f"- confirmation levels: {dict(level_counts.most_common())}",
        "",
    ]
    for item in confirmations[:80]:
        sym = item.get("enclosing_symbol") or {}
        sym_text = f"{sym.get('name')} @ {sym.get('path')}:{sym.get('line')}" if sym else "not indexed"
        lines += [
            f"## {item['cluster_id']} `{item['file']}:{item['line_min']}-{item['line_max']}`",
            f"- level: **{item['confirmation_level']}**",
            f"- tools: {', '.join(item.get('tools') or [])}",
            f"- reasons: {'; '.join(item.get('reasons') or ['none'])}",
            f"- enclosing symbol: `{sym_text}`",
            f"- candidate callers: {len(item.get('candidate_callers') or [])}",
            f"- nearby callees: {', '.join(sorted({c['name'] for c in item.get('nearby_callees') or [] if c.get('name')})[:12]) or 'none indexed'}",
            f"- IR facts nearby: {len(item.get('ir_facts_nearby') or [])}",
            "",
        ]
    md.write_text("\n".join(lines), encoding="utf-8")
    print(f"deep-confirmed {len(confirmations)} clusters -> {out} / {md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
