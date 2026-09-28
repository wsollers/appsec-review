#!/usr/bin/env python3
"""Deterministic call-graph reachability over the accepted CPG (and IR facts), ADR-0020.

Reachability is the final severity arbiter.  Three states, no others:

* ``REACHABLE``   -- a proven call path from an entry point to the function that contains the
  finding location, over *resolved* CPG call edges.  The witness (ordered functions with
  ``file:line`` call sites) is recorded in the finding.
* ``UNREACHABLE`` -- the target function is in the analysed graph, the bounded search from every
  entry point completed, no reached function makes an indirect / dynamically dispatched /
  ambiguous call, and the CPG reports no coverage gap that could hide an edge.
* ``UNKNOWN``     -- anything else (no entry point, target not located, bound hit, dynamic-dispatch
  escape, graph coverage gap).  The reason is recorded.

Entry points are ``main`` functions plus exported symbols / network handlers named in a
hash-bound entry-point list when a run supplies one.  The same analyser writes the
``06-cve-reachability`` evidence file (vulnerable dependency function -> call path from application
code) from a reviewer-supplied advisory -> vulnerable-function map; there is no network lookup.
"""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable

REACHABLE, UNREACHABLE, UNKNOWN = "REACHABLE", "UNREACHABLE", "UNKNOWN"
STATES = (REACHABLE, UNREACHABLE, UNKNOWN)
MAX_DEPTH = 64
MAX_NODES = 200_000
BENIGN_GAPS = {"duplicate"}  # CPG coverage-gap reasons that cannot hide a call edge
_DUPLICATE = re.compile(r"<duplicate>\d+")
_OPERATOR = ("<operator>", "<operators>")
# Callees that cannot be named statically (function pointers, "ANY" receivers, lambdas).
_INDIRECT = ("<operator>.pointerCall", "<operator>.indirectCall", "ANY.ANY", "<lambda>")


def short_name(full_name: str) -> str:
    """``ns.Class.method:sig`` / ``<unresolvedNamespace>.strcpy:<...>`` -> ``method`` / ``strcpy``."""
    parts = full_name.split(":")
    head = parts[1] if "/" in parts[0] and len(parts) > 1 else parts[0]
    return _DUPLICATE.sub("", head).rsplit(".", 1)[-1]


class CallGraph:
    """Resolved call graph from CPG records; unresolvable calls are kept as escapes."""

    def __init__(self) -> None:
        self.methods: dict[str, dict[str, Any]] = {}
        self.by_short: dict[str, list[str]] = {}
        self.edges: dict[str, list[dict[str, Any]]] = {}
        self.escapes: dict[str, list[dict[str, Any]]] = {}
        self.external: dict[str, list[dict[str, Any]]] = {}
        self.sites: dict[tuple[str, int], list[str]] = {}
        self.gaps: list[str] = []
        self.identity: dict[str, Any] = {}
        self.ir_functions: dict[tuple[str, str], int] = {}

    @classmethod
    def from_records(cls, records: Iterable[dict[str, Any]], coverage_gaps: Iterable[Any] = (),
                     identity: dict[str, Any] | None = None) -> "CallGraph":
        graph = cls()
        calls, identifiers = [], {}
        for record in records:
            kind, label = record.get("kind"), record.get("label")
            if kind == "symbol" and label == "METHOD":
                full = record["full_name"]
                if record.get("name") == "<global>" or full.endswith(":<global>"):
                    continue
                graph.methods[full] = {"full_name": full,
                    "name": _DUPLICATE.sub("", record.get("name") or short_name(full)),
                    "path": record.get("source_path"), "start_line": record.get("start_line") or 0,
                    "end_line": record.get("end_line") or record.get("start_line") or 0,
                    "source_sha256": record.get("source_sha256")}
            elif kind in ("call", "memory-operation") and label == "CALL":
                calls.append(record)
            elif kind == "identifier":
                identifiers.setdefault(record.get("source_path"), set()).add(
                    (record.get("name"), record.get("start_line") or 0))
        for full, method in graph.methods.items():
            graph.by_short.setdefault(method["name"], []).append(full)
        for record in calls:
            graph._add_call(record, identifiers)
        for table in (graph.edges, graph.escapes, graph.external):
            for rows in table.values():
                rows.sort(key=lambda row: (row["path"] or "", row["line"], row["callee"]))
        for gap in coverage_gaps:
            reason = gap.get("reason") if isinstance(gap, dict) else str(gap)
            count = gap.get("count") if isinstance(gap, dict) else None
            if reason not in BENIGN_GAPS:
                graph.gaps.append(f"{reason}:{count}" if count is not None else str(reason))
        graph.identity = dict(identity or {})
        return graph

    def _add_call(self, record: dict[str, Any], identifiers: dict[str, set]) -> None:
        caller = record.get("caller") or ""
        path, line = record.get("source_path"), record.get("start_line") or 0
        callee = record.get("full_name") or ""
        if not caller:
            return
        if path:
            callers = self.sites.setdefault((path, line), [])
            if caller not in callers:
                callers.append(caller)
        indirect = any(marker in callee for marker in _INDIRECT)
        if callee.startswith(_OPERATOR) and not indirect:
            return
        site = {"path": path, "line": line, "callee": callee, "code": (record.get("code") or "")[:160]}
        if callee in self.methods:
            self.edges.setdefault(caller, []).append({**site, "target": callee, "resolution": "exact"})
            return
        if indirect:
            self.escapes.setdefault(caller, []).append({**site, "reason": "indirect-call"})
            return
        name = _DUPLICATE.sub("", (record.get("name") or short_name(callee))).rsplit(".", 1)[-1]
        candidates = self.by_short.get(name, [])
        if len(candidates) == 1:
            self.edges.setdefault(caller, []).append({**site, "target": candidates[0],
                                                      "resolution": "unique-name"})
            return
        # Narrow an overloaded short name by locality: same file, then the nearest shared directory.
        parts = (path or "").split("/")
        for depth in range(len(parts), 0, -1):
            prefix = "/".join(parts[:depth])
            near = [item for item in candidates if (self.methods[item]["path"] or "") == prefix or
                    (self.methods[item]["path"] or "").startswith(prefix + "/")]
            if len(near) == 1:
                self.edges.setdefault(caller, []).append({**site, "target": near[0],
                    "resolution": "same-file-name" if depth == len(parts) else "nearest-directory-name"})
                return
            if len(near) > 1:
                break
        if candidates:
            self.escapes.setdefault(caller, []).append({**site, "reason": "ambiguous-name",
                                                        "candidates": sorted(candidates)[:8]})
            return
        method = self.methods.get(caller)
        if method and path and any(ident == name and method["start_line"] <= at <= method["end_line"]
                                   for ident, at in identifiers.get(path, ())):
            self.escapes.setdefault(caller, []).append({**site, "reason": "call-through-variable"})
            return
        self.external.setdefault(caller, []).append({**site, "symbol": name})

    def add_ir_facts(self, facts: dict[str, Any]) -> None:
        """Index IR functions by (source path, function) to confirm a location's function."""
        for fact in facts.get("facts", []):
            if fact.get("source_path") and fact.get("function"):
                key = (fact["source_path"], fact["function"])
                self.ir_functions[key] = self.ir_functions.get(key, 0) + 1

    def locate(self, path: str, line: int) -> tuple[str | None, str]:
        """The function containing ``path:line`` and how it was located."""
        callers = self.sites.get((path, line)) or []
        if len(callers) == 1 and callers[0] in self.methods:
            return callers[0], "cpg-call-site"
        spans = sorted((method["end_line"] - method["start_line"], full) for full, method in self.methods.items()
                       if method["path"] == path and method["start_line"] <= line <= method["end_line"])
        if spans:
            return spans[0][1], "cpg-method-span"
        return None, "not-located"

    def entry_points(self, extra: Iterable[str] = ()) -> list[str]:
        wanted = set(extra or ())
        return [full for full, method in sorted(self.methods.items())
                if method["name"] == "main" or full in wanted or method["name"] in wanted]

    def describe(self, full: str) -> dict[str, Any]:
        method = self.methods[full]
        return {"function": method["name"], "full_name": full, "file": method["path"],
                "line": method["start_line"]}


def analyze(graph: CallGraph, target: str | None, entries: list[str], *, sink: dict[str, Any] | None = None,
            max_depth: int = MAX_DEPTH, max_nodes: int = MAX_NODES) -> dict[str, Any]:
    """Bounded multi-source BFS from the entry points to ``target``; returns a reachability record."""
    base: dict[str, Any] = {"analyser": "reachability.py bounded BFS over resolved CPG call edges",
        "entry_point_count": len(entries), "max_depth": max_depth,
        "graph": {"methods": len(graph.methods), "edges": sum(len(v) for v in graph.edges.values()),
                  **graph.identity}}
    if sink:
        base["sink"] = sink
    if target is None:
        return {**base, "state": UNKNOWN, "witness": [],
                "reason": "finding location is not inside a function of the analysed graph"}
    base["target"] = graph.describe(target)
    if not entries:
        return {**base, "state": UNKNOWN, "witness": [],
                "reason": "no entry point (main / exported symbol / handler) in the analysed graph"}
    parent: dict[str, tuple[str | None, dict[str, Any] | None]] = {}
    depth: dict[str, int] = {}
    queue: deque[str] = deque()
    for entry in entries:
        parent[entry] = (None, None); depth[entry] = 0; queue.append(entry)
    truncated, escapes = False, []
    while queue:
        current = queue.popleft()
        if current == target:
            break
        for item in graph.escapes.get(current, []):
            escapes.append({"from": graph.methods[current]["name"], "site": f"{item['path']}:{item['line']}",
                            "reason": item["reason"]})
        if depth[current] >= max_depth:
            truncated = True
            continue
        for edge in graph.edges.get(current, []):
            following = edge["target"]
            if following in parent:
                continue
            if len(parent) >= max_nodes:
                truncated = True
                break
            parent[following] = (current, edge); depth[following] = depth[current] + 1
            queue.append(following)
    if target in parent:
        chain, node = [], target
        while node is not None:
            previous, edge = parent[node]
            chain.append((node, edge)); node = previous
        chain.reverse()
        witness = []
        for index, (node, _edge) in enumerate(chain):
            step = graph.describe(node)
            if index + 1 < len(chain):
                call = chain[index + 1][1]
                step["calls_next_at"] = f"{call['path']}:{call['line']}"
                step["resolution"] = call["resolution"]
            witness.append(step)
        if sink:
            witness.append({"function": "(finding location)", "file": sink.get("file"),
                            "line": sink.get("line"), "code": sink.get("code")})
        return {**base, "state": REACHABLE, "witness": witness,
                "entry_point": graph.describe(chain[0][0]),
                "reason": f"call path of {len(chain) - 1} edge(s) from entry point {graph.methods[chain[0][0]]['name']}()"}
    if truncated:
        return {**base, "state": UNKNOWN, "witness": [],
                "reason": "search bound reached before the graph was exhausted"}
    if escapes:
        return {**base, "state": UNKNOWN, "witness": [], "escapes": escapes[:10],
                "reason": f"{len(escapes)} indirect or ambiguous call(s) reachable from the entry points "
                          "(dynamic-dispatch escape)"}
    if graph.gaps:
        return {**base, "state": UNKNOWN, "witness": [],
                "reason": "CPG coverage gaps could hide call edges: " + ", ".join(graph.gaps[:5])}
    return {**base, "state": UNREACHABLE, "witness": [],
            "reason": f"no path from {len(entries)} entry point(s) over {len(parent)} reached function(s); "
                      "no dynamic-dispatch escape"}


def load_cpg(attempt: Path, ir_facts: Path | None = None) -> CallGraph:
    """Load an accepted ``02-code-property-graph`` attempt (records file hash-verified)."""
    attempt = Path(attempt)
    summary = json.loads((attempt / "code-property-graph.json").read_text())
    records_file = attempt / summary["records_file"]["path"]
    digest = "sha256:" + hashlib.sha256(records_file.read_bytes()).hexdigest()
    if digest != summary["records_file"]["sha256"]:
        raise ValueError("CPG records file does not match its recorded hash")
    with records_file.open() as handle:
        graph = CallGraph.from_records((json.loads(line) for line in handle if line.strip()),
            summary.get("coverage_gaps", []),
            {"cpg_records_sha256": digest, "source_snapshot_sha256": summary.get("source_snapshot_sha256")})
    if ir_facts is not None and Path(ir_facts).is_file():
        graph.add_ir_facts(json.loads(Path(ir_facts).read_text()))
    return graph


def assess_location(graph: CallGraph, path: str, line: int, entries_extra: Iterable[str] = (),
                    code: str | None = None) -> dict[str, Any]:
    target, how = graph.locate(path, line)
    result = analyze(graph, target, graph.entry_points(entries_extra),
                     sink={"file": path, "line": line, "code": code})
    result["located_by"] = how
    if target is None:
        ir = sorted({function for (source, function) in graph.ir_functions if source == path})
        if ir:
            result["reason"] += f"; IR facts name {len(ir)} function(s) in this file"
    return result


# ---- 06-cve-reachability evidence --------------------------------------------------------------

def _file_sha(graph: CallGraph, path: str | None) -> str | None:
    for method in graph.methods.values():
        if method["path"] == path and method.get("source_sha256"):
            return method["source_sha256"]
    return None


def cve_evidence(sca: dict[str, Any], vulnerable: dict[str, list[str]], graph: CallGraph,
                 entries_extra: Iterable[str] = ()) -> dict[str, Any]:
    """Evidence file for ``06-cve-reachability`` plus per-match witnesses.

    ``vulnerable`` maps an advisory id or alias to vulnerable function names (reviewer-supplied from
    the advisory / OSV ``affected[].ecosystem_specific``).  A match with no listed function stays
    ``unknown`` (no assessment row, so 06 records ``REACHABILITY_UNKNOWN``).
    """
    entries = graph.entry_points(entries_extra)
    assessments, witnesses = [], {}
    for match in sorted(sca.get("matches", []), key=lambda row: row["match_id"]):
        names = sorted({name for advisory in [match["advisory_id"], *match.get("aliases", [])]
                        for name in vulnerable.get(advisory, [])})
        if not names:
            witnesses[match["match_id"]] = {"state": UNKNOWN, "witness": [],
                                             "reason": "no vulnerable function is known for this advisory"}
            continue
        best = None
        for name in names:
            defined = list(graph.by_short.get(name, []))
            callers = sorted(caller for caller, rows in graph.external.items()
                             if any(row["symbol"] == name for row in rows) and caller in graph.methods)
            for target in sorted(set(defined + callers)):
                result = analyze(graph, target, entries)
                if target not in defined and result["state"] == REACHABLE:
                    call = next(row for row in graph.external[target] if row["symbol"] == name)
                    result["witness"].append({"function": name, "file": call["path"], "line": call["line"],
                        "code": call["code"], "note": "call into the vulnerable dependency function"})
                if best is None or STATES.index(result["state"]) < STATES.index(best["state"]):
                    best = {**result, "vulnerable_function": name}
        if best is None:
            best = {"state": UNKNOWN, "witness": [], "vulnerable_function": names[0],
                    "reason": "no listed vulnerable function appears in the analysed graph"}
        witnesses[match["match_id"]] = best
        if best["state"] == REACHABLE:
            evidence = [{"kind": "call", "path": step["file"], "sha256": _file_sha(graph, step["file"]),
                         "locator": f"{step['function']}@{step['line']}"[:256]}
                        for step in best["witness"] if step.get("file") and _file_sha(graph, step["file"])]
            if evidence:
                assessments.append({"match_ref": match["match_id"], "classification": "reachable",
                                    "evidence": evidence[:32]})
        elif best["state"] == UNREACHABLE and best.get("target"):
            target = best["target"]
            sha = _file_sha(graph, target["file"])
            if sha:
                assessments.append({"match_ref": match["match_id"], "classification": "unreachable",
                    "evidence": [{"kind": "call", "path": target["file"], "sha256": sha,
                                  "locator": f"no-path-to:{target['function']}@{target['line']}"[:256]}]})
    return {"assessments": assessments, "witnesses": witnesses}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("location", help="reachability of one file:line")
    one.add_argument("--cpg-attempt", type=Path, required=True)
    one.add_argument("--path", required=True)
    one.add_argument("--line", type=int, required=True)
    cve = sub.add_parser("cve-evidence", help="write inputs/cve-reachability-evidence.json (offline)")
    cve.add_argument("--cpg-attempt", type=Path, required=True)
    cve.add_argument("--sca", type=Path, required=True)
    cve.add_argument("--vulnerable-functions", type=Path, required=True,
                     help="JSON {advisory_or_alias: [function, ...]} supplied by the reviewer")
    cve.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    graph = load_cpg(args.cpg_attempt)
    if args.command == "location":
        print(json.dumps(assess_location(graph, args.path, args.line), indent=1))
        return 0
    result = cve_evidence(json.loads(args.sca.read_text()), json.loads(args.vulnerable_functions.read_text()), graph)
    args.output.write_text(json.dumps({"assessments": result["assessments"]}, indent=1, sort_keys=True) + "\n")
    args.output.with_name(args.output.stem + ".witnesses.json").write_text(
        json.dumps(result["witnesses"], indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
