#!/usr/bin/env python3
"""Verified entry points outside the CPG for ``reachability.py`` (brief Q, docs/reachability-entry-points.md).

A real entry can only turn UNREACHABLE into REACHABLE or UNKNOWN; a wrong one can manufacture a
REACHABLE witness and allow Critical.  So every root here comes from a deterministic, verified
source, a join that is not unique is an escape (never an entry), and linkage is never inferred from
source text.  Both sources sit behind a shared tunable that is off by default; with it off nothing
in this module runs and every reachability result is unchanged.

* ``reachability_export_entries`` (source 2): the dynamic export table of each shipped binary, as
  the pinned ``binary-summary`` tool records it (``dynamic_exports``: ELF ``.dynsym``, PE export
  directory) in the per-binary ``summary.json`` of the accepted ``02-binary-triage`` attempt,
  re-hashed against that attempt's B13 receipt.  A defined function export with GLOBAL / WEAK /
  UNIQUE binding and DEFAULT / PROTECTED visibility that is not version-hidden is joined by its
  demangled qualified name to ``METHOD.full_name`` (qualified part).  One candidate: an
  ``exported-symbol`` root.  Several: an ``ambiguous-export`` escape.  None, a file-scoped (internal
  linkage) candidate, or a name the join cannot express (operators, templates, thunks, MSVC names):
  a coverage gap.  Only shared libraries contribute roots; a binary whose table is missing, partial
  or of unknown kind is a gap, so an unreached function stays UNKNOWN (the shipped-library rule).
* ``reachability_codeql_entries`` (source 3): CodeQL ``EntryPoints`` rows (``name, file, line,
  reason``) whose reason is a framework registration (``CODEQL_ENTRY_REASONS``), joined by the
  handler definition's ``(path, start_line)`` only when the CPG and the CodeQL database saw the same
  source snapshot.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Iterable

import reachability

EXPORTS_SCHEMA = "appsec-review/dynamic-exports/1"
TRIAGE_JOB = "02-binary-triage"
RECEIPT_FILE = "binary-b13-receipts.json"      # binary_evidence_adapter.RECEIPT_FILE
SUMMARY_OUTPUT = "scratch/evidence/summary.json"
MAX_SUMMARY_BYTES = 256 * 1024 * 1024
MAX_EXPORTS = 100_000
KINDS = {"shared-library", "executable", "unknown"}
ROW_KEYS = {"symbol", "demangled", "binding", "visibility", "version_hidden"}
ENTRY_BINDINGS = frozenset({"GLOBAL", "WEAK", "GNU_UNIQUE", "UNIQUE"})
ENTRY_VISIBILITY = frozenset({"DEFAULT", "PROTECTED"})
# Framework registrations only.  "remote-flow-source" (a function that reads remote input) is not an
# entry: rooting at it makes dead input-reading code reachable (design note, source 4).  "main" is
# already a program entry; "no-internal-caller" / "address-taken" are guesses, not registrations.
CODEQL_ENTRY_REASONS = ("servlet", "request-mapping", "controller-action", "route-handler")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


def enabled(name: str) -> bool:
    """A source's tunable (``reachability_export_entries`` / ``reachability_codeql_entries``)."""
    import tunables
    return tunables.shared(name) is True


def _clean(value: Any, limit: int = 512) -> str:
    return _CONTROL.sub(" ", str(value))[:limit]


# ---- source 2: dynamic export tables ------------------------------------------------------------

def export_table(block: Any, *, artifact: str, binary_sha256: str | None) -> dict[str, Any]:
    """Normalise one ``dynamic_exports`` block; anything malformed is an incomplete table, never entries."""
    table: dict[str, Any] = {"artifact": _clean(artifact), "binary_sha256": binary_sha256,
                             "artifact_kind": "unknown", "complete": False, "gaps": [], "exports": []}
    if not isinstance(block, dict) or block.get("schema") != EXPORTS_SCHEMA:
        table["gaps"] = ["export-table-missing"]
        return table
    functions, gaps = block.get("functions"), block.get("gaps")
    if (block.get("artifact_kind") not in KINDS or not isinstance(block.get("complete"), bool) or
            not isinstance(functions, list) or not isinstance(gaps, list) or len(functions) > MAX_EXPORTS):
        table["gaps"] = ["export-table-invalid"]
        return table
    table["artifact_kind"] = block["artifact_kind"]
    own = sorted({_clean(item, 80) for item in gaps})
    hidden = 0
    for row in functions:
        if (not isinstance(row, dict) or set(row) != ROW_KEYS or not isinstance(row["symbol"], str) or
                not row["symbol"] or not isinstance(row["version_hidden"], bool) or
                not (row["demangled"] is None or isinstance(row["demangled"], str))):
            table["gaps"] = ["export-row-invalid"]
            table["exports"] = []
            return table
        if row["binding"] not in ENTRY_BINDINGS or row["visibility"] not in ENTRY_VISIBILITY:
            continue  # not exported to other modules: never an entry
        if row["version_hidden"]:
            hidden += 1  # still bindable by explicitly versioned references: real, but not rooted
            continue
        table["exports"].append({"symbol": row["symbol"][:4096],
                                 "demangled": row["demangled"][:4096] if row["demangled"] is not None else None})
    if hidden:
        own.append(f"export-version-hidden:{hidden}")
    table["complete"] = block["complete"] and not own
    table["gaps"] = own if own or block["complete"] else ["export-table-partial"]
    return table


def export_qualified(row: dict[str, Any]) -> str | None:
    """Demangled export -> CPG qualified name (``fx::overload(int)`` -> ``fx.overload``); None if not expressible."""
    symbol, demangled = row["symbol"], row.get("demangled")
    if symbol.startswith("?"):
        return None                       # MSVC decoration: no demangler in the pinned tool
    text = demangled if demangled is not None else symbol
    if symbol.startswith("_Z") and (demangled is None or demangled == symbol):
        return None                       # mangled but not demangled
    if any(mark in text for mark in ("operator", "<", "{", "[", "(anonymous", " for ", " to ")):
        return None                       # operators, templates, lambdas, thunks, guard variables
    head = text.split("(", 1)[0].strip()
    parts = head.split("::")
    if not parts or not all(_IDENT.fullmatch(part) for part in parts):
        return None
    return ".".join(parts)


def join_exports(graph: reachability.CallGraph, tables: Iterable[dict[str, Any]],
                 gaps: Iterable[str] = ()) -> reachability.ExtraEntries:
    """Exported-symbol roots for ``graph``: unique joins only; everything else an escape or a gap."""
    index: dict[str, list[str]] = {}
    for full in graph.methods:
        index.setdefault(reachability.qualified_name(full), []).append(full)
    roots: dict[str, dict[str, Any]] = {}
    escapes: list[dict[str, Any]] = []
    missing = [str(gap) for gap in gaps]
    for table in sorted(tables, key=lambda item: (item["artifact"], item["binary_sha256"] or "")):
        artifact, kind = table["artifact"], table["artifact_kind"]
        if kind == "executable":
            continue  # an executable's exports are not a library interface
        if kind != "shared-library" or not table["complete"]:
            # A shipped library (or a binary we cannot classify) whose exports are not fully known:
            # an unreached function could be reachable from one of them, so it stays UNKNOWN.
            missing.append(f"export-table-incomplete:{artifact}:{','.join(table['gaps']) or kind}")
        if kind != "shared-library":
            continue
        absent = unjoinable = 0
        for row in table["exports"]:
            name = export_qualified(row)
            if name is None:
                unjoinable += 1
                continue
            candidates = sorted(index.get(name, []))
            label = {"label": "exported-symbol", "artifact": artifact, "binary_sha256": table["binary_sha256"],
                     "symbol": row["symbol"], "demangled": row["demangled"]}
            if len(candidates) > 1:
                escapes.append({"reason": "ambiguous-export", "from": artifact, "site": row["symbol"],
                                "symbol": row["symbol"], "candidates": candidates[:8]})
            elif len(candidates) == 1 and not reachability.file_scoped(candidates[0]):
                roots.setdefault(candidates[0], label)
            else:
                absent += 1
        if absent:
            missing.append(f"export-symbol-not-in-cpg:{artifact}:{absent}")
        if unjoinable:
            missing.append(f"export-symbol-unjoinable:{artifact}:{unjoinable}")
    escapes.sort(key=lambda item: (item["from"], item["symbol"]))
    return reachability.ExtraEntries(roots, tuple(escapes), tuple(sorted(set(missing))))


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def tables_from_triage(attempt: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Export tables of every binary in an accepted ``02-binary-triage`` attempt, hash-checked."""
    attempt = Path(attempt)
    receipt_path = attempt / RECEIPT_FILE
    if not receipt_path.is_file() or receipt_path.is_symlink():
        return [], [f"export-facts-missing:{TRIAGE_JOB}:receipt"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    tables, gaps = [], []
    for operation in sorted(receipt.get("operations", []), key=lambda row: str(row.get("trial_path"))):
        binary_sha = operation.get("binary_sha256")
        artifact = str(operation.get("binary_id") or binary_sha)
        output = next((row for row in operation.get("output_files", []) if row.get("path") == SUMMARY_OUTPUT), None)
        trial = PurePosixPath(str(operation.get("trial_path", "")))
        if output is None or trial.is_absolute() or any(part in ("", ".", "..") for part in trial.parts):
            tables.append(export_table(None, artifact=artifact, binary_sha256=binary_sha))
            continue
        path = attempt.joinpath(*trial.parts, *PurePosixPath(SUMMARY_OUTPUT).parts)
        if (not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_SUMMARY_BYTES or
                _sha(path) != output.get("sha256")):
            gaps.append(f"export-evidence-unverified:{artifact}")
            tables.append(export_table(None, artifact=artifact, binary_sha256=binary_sha))
            continue
        try:
            summary = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            summary = {}
        if isinstance(summary, dict) and isinstance(summary.get("path"), str):
            artifact = PurePosixPath(summary["path"]).name or artifact
        block = summary.get("dynamic_exports") if isinstance(summary, dict) else None
        tables.append(export_table(block, artifact=artifact, binary_sha256=binary_sha))
    return tables, gaps


def triage_binding(attempt: Path) -> dict[str, Any]:
    """What finding enrichment binds when the tunable is on: the receipt that names every summary hash."""
    receipt = Path(attempt) / RECEIPT_FILE
    return {"receipt_sha256": _sha(receipt) if receipt.is_file() and not receipt.is_symlink() else None}


# ---- source 3: CodeQL EntryPoints rows ----------------------------------------------------------

def join_codeql_entries(graph: reachability.CallGraph, rows: Iterable[dict[str, str]], *,
                        graph_snapshot: str | None, rows_snapshot: str | None,
                        tool: str = "codeql") -> reachability.ExtraEntries:
    """``EntryPoints`` rows -> roots by the handler definition's ``(path, start_line)``.

    Exact only when both tools saw the same source snapshot; otherwise no row becomes an entry and
    the mismatch is a gap.  Rows with a reason outside ``CODEQL_ENTRY_REASONS`` are not entries.
    """
    wanted = [row for row in rows if row.get("reason") in CODEQL_ENTRY_REASONS and row.get("file")]
    if not wanted:
        return reachability.ExtraEntries()
    if not graph_snapshot or graph_snapshot != rows_snapshot:
        return reachability.ExtraEntries(gaps=(f"{tool}-entry-snapshot-mismatch:{len(wanted)}",))
    starts: dict[tuple[str, int], list[str]] = {}
    for full, method in graph.methods.items():
        starts.setdefault((method["path"], method["start_line"]), []).append(full)
    roots: dict[str, dict[str, Any]] = {}
    escapes: list[dict[str, Any]] = []
    absent = 0
    for row in sorted(wanted, key=lambda item: (item["file"], str(item.get("line")), item["reason"], item.get("name", ""))):
        try:
            line = int(row.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        candidates = sorted(starts.get((row["file"], line), []))
        label = {"label": f"{tool}-entry", "reason": row["reason"], "entry_file": row["file"], "entry_line": line,
                 "entry_name": _clean(row.get("name", ""), 200)}
        if len(candidates) == 1:
            roots.setdefault(candidates[0], label)
        elif candidates:
            escapes.append({"reason": f"ambiguous-{tool}-entry", "from": row["file"], "site": f"{row['file']}:{line}",
                            "symbol": label["entry_name"], "candidates": candidates[:8]})
        else:
            absent += 1
    gaps = (f"{tool}-entry-not-in-cpg:{absent}",) if absent else ()
    return reachability.ExtraEntries(roots, tuple(escapes), gaps)


# ---- CLI (smoke) --------------------------------------------------------------------------------

def smoke(summary_path: Path, records_path: Path, targets: list[tuple[str, int]]) -> dict[str, Any]:
    """Join one ``binary-summary`` output to a CPG records file and assess each ``path:line``."""
    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    table = export_table(summary.get("dynamic_exports"), artifact=PurePosixPath(summary.get("path", "")).name,
                         binary_sha256="sha256:" + summary.get("sha256", ""))
    with Path(records_path).open(encoding="utf-8") as handle:
        graph = reachability.CallGraph.from_records(json.loads(line) for line in handle if line.strip())
    extra = join_exports(graph, [table])
    return {"table": table, "roots": {full: label for full, label in sorted(extra.roots.items())},
            "escapes": list(extra.escapes), "gaps": list(extra.gaps),
            "assessments": {f"{path}:{line}": reachability.assess_location(graph, path, line, extra=extra)
                            for path, line in targets}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("smoke", help="join a binary-summary export table to CPG records (smoke test)")
    one.add_argument("--summary", type=Path, required=True)
    one.add_argument("--records", type=Path, required=True)
    one.add_argument("--target", action="append", default=[], help="path:line to assess (repeatable)")
    args = parser.parse_args(argv)
    targets = [(item.rsplit(":", 1)[0], int(item.rsplit(":", 1)[1])) for item in args.target]
    print(json.dumps(smoke(args.summary, args.records, targets), indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
