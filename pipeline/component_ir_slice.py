#!/usr/bin/env python3
"""Extract component-scoped evidence from LLVM IR.

The deterministic native pipeline already emits linked bitcode. This utility consumes
LLVM textual IR (`.ll`) and a component-purpose map, then writes a compact JSON/MD
slice for one component. It is intentionally conservative: direct call edges and
debug locations are retrieval/compiled-evidence hints, not proof of semantic
reachability.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import shutil
from collections import Counter
from pathlib import Path
from typing import Any


DEFINE_RE = re.compile(r"^define\b.*?@(?P<name>[^\s(]+)\(")
CALL_RE = re.compile(r"\b(?:call|invoke)\b[^@]*@(?P<callee>[A-Za-z_.$][A-Za-z0-9_.$-]*)(?=\()")
DBG_REF_RE = re.compile(r"!dbg !(?P<dbg>\d+)")
META_RE = re.compile(r"!(?P<id>\d+) = (?P<body>.+)$")
QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
FIELD_ID_RE = re.compile(r"\b(?P<field>\w+): !(?P<id>\d+)")
FIELD_INT_RE = re.compile(r"\b(?P<field>\w+): (?P<value>\d+)")
FIELD_STR_RE = re.compile(r'\b(?P<field>\w+): "(?P<value>(?:[^"\\]|\\.)*)"')
ALLOC_CALLEE_RE = re.compile(
    r"(?:^|::|@|_)(malloc|calloc|realloc|free|new|delete|EASTLAlloc|EASTLFree|"
    r"EASTLAllocAligned|allocate|deallocate|allocate_memory|memcpy|memmove|memset|"
    r"Znw|Znam|Zdl|Zda)(?:$|::|[.$_A-Z])",
    re.IGNORECASE,
)


def metadata_id(body: str, field: str) -> str:
    for match in FIELD_ID_RE.finditer(body):
        if match.group("field") == field:
            return match.group("id")
    return ""


def metadata_int(body: str, field: str) -> int:
    for match in FIELD_INT_RE.finditer(body):
        if match.group("field") == field:
            return int(match.group("value"))
    return 0


def metadata_str(body: str, field: str) -> str:
    for match in FIELD_STR_RE.finditer(body):
        if match.group("field") == field:
            return match.group("value")
    return ""


def parse_metadata(text: str) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    raw: dict[str, str] = {}
    for line in text.splitlines():
        m = META_RE.match(line)
        if m:
            raw[m.group("id")] = m.group("body")

    files: dict[str, dict[str, str]] = {}
    subprograms: dict[str, dict[str, Any]] = {}
    locations: dict[str, dict[str, Any]] = {}

    for mid, body in raw.items():
        if body.startswith("!DIFile("):
            q = QUOTED_RE.findall(body)
            files[mid] = {
                "filename": q[0] if len(q) > 0 else "",
                "directory": q[1] if len(q) > 1 else "",
            }

    for mid, body in raw.items():
        if body.startswith("distinct !DISubprogram(") or body.startswith("!DISubprogram("):
            file_id = metadata_id(body, "file")
            subprograms[mid] = {
                "name": metadata_str(body, "name"),
                "linkageName": metadata_str(body, "linkageName"),
                "file_id": file_id,
                "file": files.get(file_id, {}),
                "line": metadata_int(body, "line"),
            }
        elif body.startswith("!DILocation("):
            scope = metadata_id(body, "scope")
            locations[mid] = {
                "line": metadata_int(body, "line"),
                "column": metadata_int(body, "column"),
                "scope": scope,
            }

    return files, subprograms, locations


def demangle_many(names: list[str]) -> dict[str, str]:
    cxxfilt = shutil.which("c++filt")
    if not cxxfilt or not names:
        return {}
    try:
        proc = subprocess.run(
            [cxxfilt],
            input="\n".join(names) + "\n",
            text=True,
            capture_output=True,
            check=False,
        )
    except Exception:
        return {}
    if proc.returncode != 0:
        return {}
    outs = proc.stdout.splitlines()
    return {n: outs[i] for i, n in enumerate(names) if i < len(outs)}


def normalize_file(file_info: dict[str, str]) -> str:
    filename = (file_info or {}).get("filename") or ""
    directory = (file_info or {}).get("directory") or ""
    if directory and directory not in (".", "/workspace"):
        return f"{directory.rstrip('/')}/{filename}".replace("\\", "/")
    return filename.replace("\\", "/")


def load_component_catalog(component_map: Path) -> list[dict[str, Any]]:
    data = json.loads(component_map.read_text(encoding="utf-8", errors="replace"))
    components = data.get("component_cloud") or data.get("functional_components") or []
    return [item for item in components if isinstance(item, dict) and item.get("component_id")]


def component_patterns(selected: dict[str, Any]) -> dict[str, Any]:
    reps = selected.get("representative_locations") or selected.get("representative_paths") or []
    patterns = [str(p).replace("\\", "/").lstrip("./") for p in reps]
    basenames = {Path(p).name for p in patterns}
    return {"component": selected, "patterns": patterns, "basenames": sorted(basenames)}


def load_component_patterns(component_map: Path, component_id: str) -> dict[str, Any]:
    components = load_component_catalog(component_map)
    selected: dict[str, Any] | None = None
    for item in components:
        if item.get("component_id") == component_id:
            selected = item
            break
    if not selected:
        raise SystemExit(f"component_id {component_id!r} not found in {component_map}")
    return component_patterns(selected)


def path_matches(path: str, patterns: list[str], basenames: list[str]) -> bool:
    p = path.replace("\\", "/").lstrip("./")
    return any(p.endswith(pattern) for pattern in patterns) or Path(p).name in set(basenames)


def split_functions(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    out: list[dict[str, Any]] = []
    i = 0
    while i < len(lines):
        m = DEFINE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        start = i + 1
        body = [lines[i]]
        brace = lines[i].count("{") - lines[i].count("}")
        i += 1
        while i < len(lines) and brace > 0:
            body.append(lines[i])
            brace += lines[i].count("{") - lines[i].count("}")
            i += 1
        dbg_match = DBG_REF_RE.search(lines[start - 1])
        out.append({
            "raw_name": m.group("name"),
            "dbg": dbg_match.group("dbg") if dbg_match else "",
            "start_ir_line": start,
            "body": body,
        })
    return out


def loc_from_dbg(dbg_id: str, locations: dict[str, dict[str, Any]]) -> dict[str, int]:
    loc = locations.get(dbg_id or "", {})
    return {"line": int(loc.get("line") or 0), "column": int(loc.get("column") or 0)}


def analyze(ir_text: str, component_map: Path, component_id: str) -> dict[str, Any]:
    _, subprograms, locations = parse_metadata(ir_text)
    comp = load_component_patterns(component_map, component_id)
    funcs = split_functions(ir_text)
    raw_names = [f["raw_name"] for f in funcs]
    raw_names += [sp.get("linkageName", "") for sp in subprograms.values() if sp.get("linkageName")]
    demangled = demangle_many(sorted(set(n for n in raw_names if n)))
    linkage_to_sp = {sp.get("linkageName"): sp for sp in subprograms.values() if sp.get("linkageName")}

    selected: list[dict[str, Any]] = []
    call_edges: list[dict[str, Any]] = []
    alloc_related_calls: list[dict[str, Any]] = []
    pointer_arithmetic: list[dict[str, Any]] = []
    memory_intrinsics: list[dict[str, Any]] = []

    for fn in funcs:
        sp = subprograms.get(fn["dbg"], {})
        file_path = normalize_file(sp.get("file", {}))
        if not path_matches(file_path, comp["patterns"], comp["basenames"]):
            continue

        raw = fn["raw_name"]
        name = sp.get("name") or demangled.get(raw) or raw
        if raw in demangled and demangled[raw] != raw:
            display = demangled[raw]
        elif sp.get("linkageName") in demangled:
            display = demangled[sp["linkageName"]]
        else:
            display = name

        calls: list[dict[str, Any]] = []
        geps: list[dict[str, Any]] = []
        mems: list[dict[str, Any]] = []
        for line_no, line in enumerate(fn["body"], start=fn["start_ir_line"]):
            dbg_match = DBG_REF_RE.search(line)
            loc = loc_from_dbg(dbg_match.group("dbg"), locations) if dbg_match else {"line": 0, "column": 0}
            for cm in CALL_RE.finditer(line):
                callee_raw = cm.group("callee")
                callee_sp = linkage_to_sp.get(callee_raw, {})
                callee_name = demangled.get(callee_raw) or callee_sp.get("name") or callee_raw
                edge = {
                    "caller": display,
                    "callee": callee_name,
                    "callee_raw": callee_raw,
                    "source_line": loc["line"],
                    "source_column": loc["column"],
                    "ir_line": line_no,
                }
                calls.append(edge)
                call_edges.append(edge)
                if ALLOC_CALLEE_RE.search(callee_name) or ALLOC_CALLEE_RE.search(callee_raw):
                    alloc_related_calls.append(edge)
                if callee_raw.startswith("llvm.mem"):
                    mems.append(edge)
                    memory_intrinsics.append(edge)
            if "getelementptr" in line:
                entry = {
                    "function": display,
                    "source_line": loc["line"],
                    "source_column": loc["column"],
                    "ir_line": line_no,
                    "instruction": line.strip()[:220],
                }
                geps.append(entry)
                pointer_arithmetic.append(entry)

        selected.append({
            "name": display,
            "raw_name": raw,
            "source_file": file_path,
            "source_line": int(sp.get("line") or 0),
            "ir_line": fn["start_ir_line"],
            "calls": calls,
            "pointer_arithmetic": geps,
            "memory_intrinsics": mems,
        })

    return {
        "schema": "appsec-review-process/component-ir-slice/0.1",
        "component_id": component_id,
        "component": comp["component"],
        "source_patterns": comp["patterns"],
        "counts": {
            "functions": len(selected),
            "call_edges": len(call_edges),
            "allocation_related_calls": len(alloc_related_calls),
            "pointer_arithmetic": len(pointer_arithmetic),
            "memory_intrinsics": len(memory_intrinsics),
        },
        "functions": selected,
        "call_edges": call_edges,
        "allocation_related_calls": alloc_related_calls,
        "pointer_arithmetic": pointer_arithmetic,
        "memory_intrinsics": memory_intrinsics,
        "top_callees": Counter(edge["callee"] for edge in call_edges).most_common(30),
    }


def write_markdown(data: dict[str, Any], out_json: Path) -> None:
    out_md = out_json.with_suffix(".md")
    c = data["counts"]
    lines = [
        f"# Component IR Slice - {data['component_id']}",
        "",
        "Compiled-evidence slice from LLVM IR. Direct call edges and debug locations are retrieval aids, not full semantic reachability proof.",
        "",
        "## Summary",
        "",
        f"- functions: {c['functions']}",
        f"- call edges: {c['call_edges']}",
        f"- allocation-related calls: {c['allocation_related_calls']}",
        f"- pointer arithmetic / GEP instructions: {c['pointer_arithmetic']}",
        f"- memory intrinsics: {c['memory_intrinsics']}",
        "",
        "## Component",
        "",
        f"- name: `{data['component'].get('name', data['component_id'])}`",
        f"- parallel review group: `{data['component'].get('parallel_review_group', '')}`",
        "",
        "## Functions",
        "",
    ]
    for fn in data["functions"]:
        lines.append(f"### `{fn['name']}`")
        lines.append("")
        lines.append(f"- source: `{fn['source_file']}:{fn['source_line']}`")
        lines.append(f"- calls: {len(fn['calls'])}")
        lines.append(f"- GEPs: {len(fn['pointer_arithmetic'])}")
        if fn["calls"][:10]:
            lines.append("- callees: " + ", ".join(f"`{e['callee']}`" for e in fn["calls"][:10]))
        if fn["pointer_arithmetic"][:8]:
            lines.append("- GEP locations: " + ", ".join(
                f"source line {e['source_line'] or '?'} / IR {e['ir_line']}"
                for e in fn["pointer_arithmetic"][:8]
            ))
        lines.append("")
    lines += ["## Allocation-Related Calls", ""]
    for edge in data["allocation_related_calls"][:80]:
        lines.append(f"- `{edge['caller']}` -> `{edge['callee']}` at source line {edge['source_line'] or '?'}")
    if not data["allocation_related_calls"]:
        lines.append("- none observed in this component slice")
    lines += ["", "## Top Callees", ""]
    for name, count in data["top_callees"]:
        lines.append(f"- `{name}`: {count}")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ir", required=True, help="LLVM textual IR (.ll)")
    ap.add_argument("--component-map", required=True)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--component-id")
    group.add_argument("--all-components", action="store_true")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    ir_path = Path(args.ir)
    out = Path(args.out)
    ir_text = ir_path.read_text(encoding="utf-8", errors="replace")
    component_map = Path(args.component_map)

    if args.all_components:
        out.mkdir(parents=True, exist_ok=True)
        summary = []
        for component in load_component_catalog(component_map):
            component_id = component["component_id"]
            dest = out / f"{component_id}.json"
            data = analyze(ir_text, component_map, component_id)
            dest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            write_markdown(data, dest)
            summary.append({"component_id": component_id, "out": str(dest), "counts": data["counts"]})
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"out_dir": str(out), "components": len(summary), "summary": str(out / "summary.json")}, indent=2))
        return 0

    out.parent.mkdir(parents=True, exist_ok=True)
    data = analyze(ir_text, component_map, args.component_id)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    write_markdown(data, out)
    print(json.dumps({"out": str(out), "md": str(out.with_suffix(".md")), "counts": data["counts"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
