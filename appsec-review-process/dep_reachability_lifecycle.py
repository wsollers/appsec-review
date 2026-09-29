"""Hash-bound engine inputs and derivation for the ``06-cve-reachability`` lifecycle (ADR-0022 decision 9).

``bindings`` names every optional evidence source 06 reads, by hash: the accepted CPG and CodeQL
publications (verified against their accepted pointer and attempt tree hashes, same source
generation as the SCA match), the OSV snapshot judged at the SCA completion time, and the
run-supplied files under ``<run>/inputs/``. ``derive`` rebuilds the engine set from exactly those
bindings (re-verifying each hash) and runs ``dep_reachability.analyse``. Both are deterministic,
so ``validate`` re-derives byte-for-byte. A source that is absent, stale or fails verification is
not used and is named in ``gaps``; it never blocks the job (ADR-0013: run to report).
"""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path, PurePosixPath
from typing import Any

import dep_reachability
import dep_reachability_engines as engines
from execution_state import data_path, file_hash, read_json, run_path, tree_hashes
import reachability

RESULT = "outputs/dependency-reachability.json"
CPG_JOB, CPG_RESULT = "02-code-property-graph", "code-property-graph.json"
CODEQL_JOB, CODEQL_RESULT, CODEQL_RECEIPTS = "02-codeql-sast", "codeql-sast.json", "b13-receipts.json"
REVIEWED_MAP = "cve-reachability-functions.json"
ENTRY_POINTS = "reachability-entry-points.json"
SUPPLIED = "dependency-reachability"          # <run>/inputs/dependency-reachability/{codeql,lsp,treesitter-ast.json}
CODE = ("dep_reachability.py", "dep_reachability_engines.py", "dep_reachability_codeql.py",
        "dep_reachability_lifecycle.py", "reachability.py")
SCHEMAS = ("dependency-reachability.schema.json", "dependency-reachability-match.schema.json")


def _sha(path: Path) -> str:
    return "sha256:" + file_hash(path)


def _regular(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _accepted(run_id: str, job: str, result: str, source: str) -> tuple[dict[str, Any] | None, str | None]:
    """An accepted publication verified by pointer, envelope and attempt tree hashes, or a gap."""
    base = data_path(run_id, "jobs", job)
    pointer_path = base / "accepted.json"
    if not _regular(pointer_path):
        return None, f"engine-input-absent:{job}"
    try:
        pointer = read_json(pointer_path)
        attempt = base / "attempts" / str(pointer.get("attempt_id"))
        if (pointer.get("run_id") != run_id or pointer.get("job") != job or
                pointer.get("status") not in ("OK", "OK_WITH_GAPS") or attempt.is_symlink() or
                not attempt.is_dir() or tree_hashes(attempt) != pointer.get("hashes") or
                file_hash(attempt / pointer.get("envelope_path", "result.json")) != pointer.get("envelope_sha256")):
            return None, f"engine-input-not-current:{job}"
        document = read_json(attempt / result)
    except (OSError, ValueError, TypeError):
        return None, f"engine-input-not-current:{job}"
    if document.get("source_snapshot_sha256") != source:
        return None, f"engine-input-mixed-lineage:{job}"
    return {"attempt_id": pointer["attempt_id"], "accepted_pointer_sha256": _sha(pointer_path),
            "result_sha256": _sha(attempt / result)}, None


def _cpg(run_id: str, source: str) -> tuple[dict[str, Any] | None, list[str]]:
    binding, gap = _accepted(run_id, CPG_JOB, CPG_RESULT, source)
    if binding is None:
        return None, [gap]
    attempt = data_path(run_id, "jobs", CPG_JOB, "attempts", binding["attempt_id"])
    summary = read_json(attempt / CPG_RESULT)
    if summary.get("status") == "SKIPPED" or not isinstance(summary.get("records_file"), dict):
        return None, ["engine-input-absent:cpg-skipped"]
    return {**binding, "records_sha256": summary["records_file"].get("sha256")}, []


def _codeql(run_id: str, source: str) -> tuple[dict[str, Any] | None, list[str]]:
    """Traced C/C++ graph tables recorded in the accepted 02-codeql-sast receipts."""
    binding, gap = _accepted(run_id, CODEQL_JOB, CODEQL_RESULT, source)
    if binding is None:
        return None, [gap]
    attempt = data_path(run_id, "jobs", CODEQL_JOB, "attempts", binding["attempt_id"])
    receipts = read_json(attempt / CODEQL_RECEIPTS) if _regular(attempt / CODEQL_RECEIPTS) else {"tools": []}
    tables, gaps = [], []
    for tool in sorted(receipts.get("tools", []), key=lambda row: str(row.get("trial_path"))):
        outputs = tool.get("graph_outputs")
        if not isinstance(outputs, dict):
            continue
        for query in ("CallEdges.ql", "EntryPoints.ql"):
            if outputs.get(query) is None:
                gaps.append(f"codeql-table-absent:cpp:{query[:-3]}:{tool.get('unit_id')}")
                continue
            tables.append({"table": query[:-3], "path": f"{tool['trial_path']}/scratch/graph/{query[:-3]}.csv",
                           "sha256": outputs[query]})
    if not tables:
        gaps.append("engine-input-absent:codeql:cpp")
    return {**binding, "cpp_tables": tables}, gaps


def _supplied(run_id: str) -> dict[str, Any]:
    """Run-supplied files: reviewed map, entry points, CodeQL CSVs per language, LSP docs, tree-sitter AST."""
    inputs = run_path(run_id) / "inputs"
    found: dict[str, Any] = {}
    for key, name in (("reviewed_map", REVIEWED_MAP), ("entry_points", ENTRY_POINTS)):
        path = inputs / name
        found[key] = {"path": f"inputs/{name}", "sha256": _sha(path)} if _regular(path) else None
    root = inputs / SUPPLIED
    codeql: dict[str, dict[str, str]] = {}
    for folder in sorted((root / "codeql").iterdir()) if (root / "codeql").is_dir() else []:
        if folder.is_dir() and not folder.is_symlink() and folder.name in engines.ENTRY_POINTS:
            codeql[folder.name] = {name: _sha(folder / f"{name}.csv") for name in engines.TABLES
                                   if _regular(folder / f"{name}.csv")}
    lsp = {}
    for path in sorted((root / "lsp").glob("*.json")) if (root / "lsp").is_dir() else []:
        if _regular(path) and path.stem in engines.ENTRY_POINTS:
            lsp[path.stem] = _sha(path)
    ast = root / "treesitter-ast.json"
    found.update(codeql=codeql, lsp=lsp, treesitter=_sha(ast) if _regular(ast) else None)
    return found


def _osv(generated_at: str) -> tuple[Any, dict[str, Any] | None, str | None]:
    """The OSV snapshot judged at the SCA completion time (deterministic across validate)."""
    import osv_lookup
    now = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    source, gap = dep_reachability.open_osv(osv_lookup.default_root(), now=now)
    return source, (source.identity if source else None), gap


def bindings(run_id: str, source: str, generated_at: str) -> dict[str, Any]:
    cpg, cpg_gaps = _cpg(run_id, source)
    codeql, codeql_gaps = _codeql(run_id, source)
    osv, osv_identity, osv_gap = _osv(generated_at)
    if osv is not None:
        osv.connection.close()
    return {"cpg": cpg, "codeql": codeql, "osv": osv_identity, "osv_gap": osv_gap, "supplied": _supplied(run_id),
            "gaps": sorted(cpg_gaps + codeql_gaps),
            "code": {name: file_hash(Path(__file__).resolve().parent / name) for name in CODE}}


class Stale(RuntimeError):
    """A bound input changed between binding and derivation."""


def _check(path: Path, expected: str) -> bytes:
    data = path.read_bytes() if _regular(path) else b""
    if engines.sha256_bytes(data) != expected:
        raise Stale(f"{path.name} changed after it was bound")
    return data


def derive(run_id: str, bound: dict[str, Any], *, sca: dict[str, Any], sbom: dict[str, Any],
           files: dict[str, str], generated_at: str) -> dict[str, Any]:
    """The ``06`` evidence rows and dependency-reachability document from exactly ``bound``."""
    graph = None
    if bound["cpg"]:
        attempt = data_path(run_id, "jobs", CPG_JOB, "attempts", bound["cpg"]["attempt_id"])
        _check(attempt / CPG_RESULT, bound["cpg"]["result_sha256"])
        graph = reachability.load_cpg(attempt)
    tables: dict[str, dict[str, list[dict[str, str]]]] = {}
    table_gaps: dict[str, list[str]] = {}
    if bound["codeql"]:
        attempt = data_path(run_id, "jobs", CODEQL_JOB, "attempts", bound["codeql"]["attempt_id"])
        for row in bound["codeql"]["cpp_tables"]:
            data = _check(attempt.joinpath(*PurePosixPath(row["path"]).parts), row["sha256"])
            try:
                tables.setdefault("cpp", {}).setdefault(row["table"], []).extend(engines.read_table(data, row["table"]))
            except ValueError:
                table_gaps.setdefault("cpp", []).append(f"codeql-table-invalid:cpp:{row['table']}")
    supplied = bound["supplied"]
    root = run_path(run_id) / "inputs" / SUPPLIED
    for language, hashes in sorted(supplied["codeql"].items()):
        for name in engines.TABLES:
            if name not in hashes:
                if name in engines.REQUIRED_TABLES:
                    table_gaps.setdefault(language, []).append(f"codeql-table-absent:{language}:{name}")
                continue
            data = _check(root / "codeql" / language / f"{name}.csv", hashes[name])
            try:
                tables.setdefault(language, {})[name] = engines.read_table(data, name)
            except ValueError:
                table_gaps.setdefault(language, []).append(f"codeql-table-invalid:{language}:{name}")
    lsp = {language: json.loads(_check(root / "lsp" / f"{language}.json", sha))
           for language, sha in sorted(supplied["lsp"].items())}
    ast = json.loads(_check(root / "treesitter-ast.json", supplied["treesitter"])) if supplied["treesitter"] else None
    inputs = run_path(run_id) / "inputs"
    reviewed = (json.loads(_check(inputs / REVIEWED_MAP, supplied["reviewed_map"]["sha256"]))
                if supplied["reviewed_map"] else None)
    entries = (json.loads(_check(inputs / ENTRY_POINTS, supplied["entry_points"]["sha256"])).get("entry_points", [])
               if supplied["entry_points"] else [])
    identity = {"cpg": bound["cpg"], "codeql": bound["codeql"], "supplied": supplied}
    engine_set = engines.EngineSet(cpg=graph, codeql=tables, codeql_gaps=table_gaps, lsp=lsp, treesitter=ast,
                                   identity=identity)
    osv, osv_gap = None, bound["osv_gap"]
    if bound["osv"] is not None:
        osv, identity_now, osv_gap = _osv(generated_at)
        if identity_now != bound["osv"]:
            if osv is not None:
                osv.connection.close()
            raise Stale("OSV snapshot changed after it was bound")
    try:
        result = dep_reachability.analyse(sca=sca, sbom=sbom, files=files, engine_set=engine_set, osv=osv,
                                          osv_gap=osv_gap, reviewed=reviewed, entry_points=entries)
    finally:
        if osv is not None:
            osv.connection.close()
    document = result["document"]
    document["coverage_gaps"] = sorted(set(document["coverage_gaps"]) | {"ENGINE_INPUT:" + gap for gap in bound["gaps"]})
    return result
