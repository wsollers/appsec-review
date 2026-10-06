#!/usr/bin/env python3
"""Language-aware dependency reachability for ``06-cve-reachability`` (ADR-0022).

Per SCA match: resolve the advisory's vulnerable symbols (reviewed map, then the OSV index), pick
the engines for the dependency's ecosystem, run each over accepted hash-bound evidence, and join
their states through a fixed lattice into ``reachable | unreachable | unknown`` with a witness
path (``file:line`` hops, each bound to the sha256 of its file in the run's source projection).

Model text never decides reachability. Advisory text (symbol names) is data: it is validated
against a closed pattern and only ever compared with graph names or written as data rows. The
output is (a) ``assessments`` in the shape ``dependency_workers.build_reachability`` validates
(the ``06`` evidence file) and (b) the full per-match document
``appsec-review/dependency-reachability/1.0``. Everything is deterministic: same inputs, same bytes.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dep_reachability_engines as engines

SCHEMA = "appsec-review/dependency-reachability/1.0"
REACHABLE, UNREACHABLE, UNKNOWN = "reachable", "unreachable", "unknown"
VERDICTS = (REACHABLE, UNREACHABLE, UNKNOWN)
MAX_WITNESS = 32
MAX_SYMBOLS = 64
SYMBOL = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.:<>~-]{0,199}\Z")
PACKAGE = re.compile(r"^[A-Za-z0-9@_][A-Za-z0-9@._+~/:-]{0,199}\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


def clean_text(value: Any, limit: int = 200) -> str:
    """Names from target code (CodeQL/LSP/tree-sitter) are data: control characters stripped, truncated."""
    return _CONTROL.sub(" ", str(value if value is not None else ""))[:limit]

# SBOM ecosystem -> (analysis language, OSV ecosystem name or None).
ECOSYSTEMS: dict[str, tuple[str, str | None]] = {
    "golang": ("go", "Go"), "maven": ("java", "Maven"), "nuget": ("csharp", "NuGet"),
    "npm": ("javascript", "npm"), "pypi": ("python", "PyPI"), "cargo": ("rust", "crates.io"),
    "composer": ("php", "Packagist"), "gem": ("ruby", "RubyGems"),
    # Native: vendored sources are built and analysed with the application (CPG/IR, traced CodeQL);
    # distro packages are linked libraries whose functions appear as external calls.
    "conan": ("cpp", None), "generic": ("cpp", None), "deb": ("cpp", "Debian"),
    "rpm": ("cpp", None), "apk": ("cpp", "Alpine"),
}
# Engines per analysis language, strongest first (ADR-0022 decision 3).
ENGINES_BY_LANGUAGE: dict[str, tuple[str, ...]] = {
    "cpp": ("cpg", "codeql"),
    "go": ("codeql", "lsp", "treesitter"), "java": ("codeql", "lsp", "treesitter"),
    "csharp": ("codeql", "lsp", "treesitter"), "javascript": ("codeql", "lsp", "treesitter"),
    "python": ("codeql", "lsp", "treesitter"), "ruby": ("codeql", "treesitter"),
    "rust": ("lsp", "treesitter"), "php": ("lsp", "treesitter"),
}


def _gap(match_id: str, reason: str) -> str:
    return f"REACHABILITY_UNKNOWN:{match_id}:{reason}"[:512]


# ---- advisory symbols --------------------------------------------------------------------------

def clean_symbols(rows: Iterable[dict[str, Any]], source: str) -> tuple[list[dict[str, Any]], int]:
    """Keep well-formed ``{package, symbol}`` rows; count (never echo) the rejected ones."""
    kept, rejected = {}, 0
    for row in rows:
        symbol = row.get("symbol") if isinstance(row, dict) else None
        package = row.get("package") if isinstance(row, dict) else None
        if not isinstance(symbol, str) or not SYMBOL.fullmatch(symbol) or (
                package is not None and (not isinstance(package, str) or not PACKAGE.fullmatch(package))):
            rejected += 1
            continue
        kept[(package or "", symbol)] = {"package": package or None, "symbol": symbol, "source": source}
    return [kept[key] for key in sorted(kept)][:MAX_SYMBOLS], rejected


def reviewed_symbols(reviewed: dict[str, Any], match: dict[str, Any]) -> list[dict[str, Any]]:
    """Rows of the reviewed advisory -> function map for this match (``{id: [name | {package, symbol}]}``)."""
    rows = []
    for advisory in [match["advisory_id"], *match.get("aliases", [])]:
        for item in reviewed.get(advisory, []) or []:
            rows.append(item if isinstance(item, dict) else {"symbol": item})
    return rows


def osv_symbols(advisories: list[dict[str, Any]], osv_ecosystem: str | None, component: dict[str, Any]) -> list[dict[str, Any]]:
    """Affected symbols of the entries whose ecosystem and package name match the SBOM component."""
    import osv_index
    rows = []
    for advisory in advisories:
        for affected in advisory.get("affected", []):
            if osv_ecosystem is None or str(affected.get("ecosystem", "")).split(":", 1)[0] != osv_ecosystem:
                continue
            name = affected.get("name") or ""
            if osv_index.normalise_name(osv_ecosystem, name) != osv_index.normalise_name(osv_ecosystem, component["name"]):
                continue
            for symbol in affected.get("symbols", []):
                rows.append({"package": symbol.get("path") or name, "symbol": symbol.get("symbol")})
    return rows


class OsvSource:
    """Read-only OSV index lookups for a set of advisory ids / aliases (``osv_index`` queries)."""

    def __init__(self, connection: Any, identity: dict[str, Any]) -> None:
        self.connection, self.identity = connection, identity

    def advisories(self, ids: Iterable[str]) -> list[dict[str, Any]]:
        import osv_index
        found: dict[str, dict[str, Any]] = {}
        for value in sorted(set(ids)):
            for advisory in osv_index.by_id(self.connection, value) + osv_index.by_alias(self.connection, value):
                found[advisory["id"]] = advisory
        return [found[key] for key in sorted(found)]


# ---- verdict lattice ---------------------------------------------------------------------------

def join(language: str, results: list[dict[str, Any]]) -> tuple[str, dict[str, Any] | None, str]:
    """ADR-0022 decision 4: (verdict, deciding engine result, reason)."""
    ran = [row for row in results if row["ran"]]
    proofs = [row for row in ran if row["state"] == REACHABLE and engines.STRENGTH[row["engine"]] != "hint"]
    if proofs:
        order = ENGINES_BY_LANGUAGE[language]
        best = min(proofs, key=lambda row: (order.index(row["engine"]), len(row["witness"])))
        return REACHABLE, best, f"{best['engine']}: {best['reason']}"
    if ran:
        strongest = ran[0]
        others_quiet = all(row["state"] == UNREACHABLE or (row["state"] == UNKNOWN and not row.get("witness_hint"))
                           for row in ran[1:])
        if strongest["state"] == UNREACHABLE and engines.STRENGTH[strongest["engine"]] == "complete" and others_quiet:
            return UNREACHABLE, strongest, f"{strongest['engine']}: {strongest['reason']}"
        if strongest["state"] == UNREACHABLE and not others_quiet:
            return UNKNOWN, None, (f"{strongest['engine']} found no path but a weaker engine found "
                                   "name-matched call sites")
    reasons = "; ".join(f"{row['engine']}: {row['reason']}" for row in results) or "no engine for this language"
    return UNKNOWN, None, reasons


def bind_witness(witness: list[dict[str, Any]], files: dict[str, str]) -> tuple[list[dict[str, Any]], bool]:
    """Attach each hop's source sha256; False when any hop's file is not in the projection."""
    bound, complete = [], True
    for step in witness[:MAX_WITNESS]:
        path = step.get("file")
        sha = files.get(path) if isinstance(path, str) else None
        if sha is None:
            complete = False
        hop = {"function": clean_text(step.get("function")), "file": path, "line": int(step.get("line") or 0),
               "sha256": sha}
        for key in ("calls_next_at", "resolution", "note"):
            if step.get(key):
                hop[key] = clean_text(step[key])
        bound.append(hop)
    return bound, complete and len(witness) <= MAX_WITNESS


def _assessment(match: dict[str, Any], verdict: str, witness: list[dict[str, Any]],
                deciding: dict[str, Any] | None) -> dict[str, Any] | None:
    """The ``06`` evidence row (``dependency_workers.build_reachability`` input) or None for unknown."""
    if verdict == REACHABLE:
        evidence = [{"kind": "call", "path": hop["file"], "sha256": hop["sha256"],
                     "locator": f"{hop['function']}@{hop['line']}"[:256]} for hop in witness]
        return {"match_ref": match["match_id"], "classification": REACHABLE, "evidence": evidence}
    if verdict == UNREACHABLE and deciding and deciding.get("target"):
        target = deciding["target"]
        return {"match_ref": match["match_id"], "classification": UNREACHABLE,
                "evidence": [{"kind": "call", "path": target["file"], "sha256": target["sha256"],
                              "locator": f"no-path-to:{target['function']}@{target['line']}"[:256]}]}
    return None


# ---- per-match analysis ------------------------------------------------------------------------

def analyse(*, sca: dict[str, Any], sbom: dict[str, Any], files: dict[str, str], engine_set: engines.EngineSet,
            osv: OsvSource | None, osv_gap: str | None, reviewed: dict[str, Any] | None,
            entry_points: Iterable[str] = ()) -> dict[str, Any]:
    """The ``06`` evidence rows and the full dependency-reachability document (without run fields)."""
    components = {row["component_id"]: row for row in sbom.get("components", [])}
    entries = sorted({str(item) for item in entry_points})
    records, assessments, gaps = [], [], []
    for match in sorted(sca.get("matches", []), key=lambda row: row["match_id"]):
        match_id = match["match_id"]
        component = components.get(match["component_ref"])
        record: dict[str, Any] = {"match_id": match_id, "component_ref": match["component_ref"],
                                  "advisory_id": match["advisory_id"], "ecosystem": None, "language": None,
                                  "symbols": [], "engines": [], "verdict": UNKNOWN, "reason": "",
                                  "witness": [], "witness_hints": [], "gaps": []}
        if component is None:
            record.update(reason="SCA match cites a component absent from the accepted SBOM",
                          gaps=[_gap(match_id, "component-not-in-sbom")])
            records.append(record); gaps += record["gaps"]; continue
        language, osv_ecosystem = ECOSYSTEMS.get(component["ecosystem"], (None, None))
        record.update(ecosystem=component["ecosystem"], language=language)
        if language is None:
            record.update(reason=f"no reachability engine for ecosystem {component['ecosystem']}",
                          gaps=[_gap(match_id, "ecosystem-unsupported:" + component["ecosystem"])])
            records.append(record); gaps += record["gaps"]; continue
        symbols, rejected = clean_symbols(reviewed_symbols(reviewed or {}, match), "reviewed-map")
        if not symbols and osv is not None:
            symbols, rejected_osv = clean_symbols(osv_symbols(
                osv.advisories([match["advisory_id"], *match.get("aliases", [])]), osv_ecosystem, component), "osv")
            rejected += rejected_osv
        record["symbols"] = symbols
        if rejected:
            record["gaps"].append(_gap(match_id, f"advisory-symbols-rejected:{rejected}"))
        if not symbols:
            reason = osv_gap if osv is None and osv_gap else "no-advisory-symbols"
            record.update(reason="package-level presence only: " + (
                "the OSV index is unavailable (" + osv_gap + ")" if osv is None and osv_gap else
                "the advisory lists no vulnerable symbol and no reviewed map entry exists"))
            record["gaps"].append(_gap(match_id, reason))
            records.append(record); gaps += record["gaps"]; continue
        query = engines.Query(match_id=match_id, language=language, package=component["name"],
                              symbols=symbols, entry_points=entries)
        results = [engine_set.assess(name, query) for name in ENGINES_BY_LANGUAGE[language]]
        verdict, deciding, reason = join(language, results)
        witness, bound = bind_witness(deciding["witness"], files) if deciding else ([], True)
        if deciding and not bound:
            verdict, reason = UNKNOWN, reason + "; witness not hash-bound to the source projection"
            record["gaps"].append(_gap(match_id, "witness-not-hash-bound"))
        if verdict == UNREACHABLE and deciding:
            target = deciding.get("target") or {}
            sha = files.get(target.get("file")) if isinstance(target.get("file"), str) else None
            if sha is None:
                verdict, reason = UNKNOWN, reason + "; unreachable target not hash-bound"
                record["gaps"].append(_gap(match_id, "witness-not-hash-bound"))
            else:
                deciding = {**deciding, "target": {**target, "sha256": sha}}
        record["engines"] = [{"engine": row["engine"], "ran": row["ran"], "state": row["state"],
                              "reason": clean_text(row["reason"], 512), "witness_length": len(row["witness"])}
                             for row in results]
        for row in results:
            record["gaps"] += [_gap(match_id, item) for item in row["gaps"]]
            record["witness_hints"] += row.get("witness_hint", [])
        record["witness_hints"] = [{**hint, "callee": clean_text(hint["callee"]),
                                    "function": clean_text(hint["function"]) if hint["function"] is not None else None}
                                   for hint in record["witness_hints"][:MAX_WITNESS]]
        record.update(verdict=verdict, reason=clean_text(reason, 1024), witness=witness if verdict == REACHABLE else [])
        if verdict == UNKNOWN:
            record["gaps"].append(_gap(match_id, "undecided"))
        row = _assessment(match, verdict, witness, deciding)
        if row:
            assessments.append(row)
        record["gaps"] = sorted(set(record["gaps"]))
        records.append(record); gaps += record["gaps"]
    counts = {verdict: sum(1 for row in records if row["verdict"] == verdict) for verdict in VERDICTS}
    return {"assessments": assessments,
            "document": {"schema": SCHEMA, "engines": engine_set.identity(), "osv": osv.identity if osv else None,
                         "entry_points": entries, "counts": counts, "matches": records,
                         "coverage_gaps": sorted(set(gaps)), "claim_ceiling": "EVIDENCE_LEADS_ONLY"}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sca", type=Path, required=True, help="outputs/sca-vulnerability-match.json")
    parser.add_argument("--sbom", type=Path, required=True, help="outputs/sbom-manifest.json")
    parser.add_argument("--source-root", type=Path, required=True, help="checkout the evidence paths are relative to")
    parser.add_argument("--cpg-attempt", type=Path)
    parser.add_argument("--codeql-tables", type=Path, action="append", default=[],
                        help="LANG=DIR with CallEdges.csv / EntryPoints.csv / Reachability.csv")
    parser.add_argument("--lsp", type=Path, action="append", default=[], help="LANG=lsp-query-result.json")
    parser.add_argument("--treesitter", type=Path, help="treesitter-ast.json")
    parser.add_argument("--osv-root", type=Path, help="OSV publication root (default: no OSV lookup)")
    parser.add_argument("--reviewed-map", type=Path)
    parser.add_argument("--entry-points", type=Path, help='{"entry_points": [...]}')
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    import hashlib
    files = {path.relative_to(args.source_root).as_posix():
             "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
             for path in sorted(args.source_root.rglob("*")) if path.is_file() and not path.is_symlink()}
    engine_set = engines.EngineSet.from_paths(cpg_attempt=args.cpg_attempt,
        codeql={k: Path(v) for k, v in (str(item).split("=", 1) for item in args.codeql_tables)},
        lsp={k: Path(v) for k, v in (str(item).split("=", 1) for item in args.lsp)}, treesitter=args.treesitter)
    osv, osv_gap = None, "osv-not-configured"
    if args.osv_root:
        osv, osv_gap = open_osv(args.osv_root)
    entries = json.loads(args.entry_points.read_text()).get("entry_points", []) if args.entry_points else []
    result = analyse(sca=json.loads(args.sca.read_text()), sbom=json.loads(args.sbom.read_text()), files=files,
                     engine_set=engine_set, osv=osv, osv_gap=osv_gap,
                     reviewed=json.loads(args.reviewed_map.read_text()) if args.reviewed_map else None,
                     entry_points=entries)
    args.output.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    return 0


def open_osv(root: Path, now: Any = None, *, resolution: Any = None) -> tuple[OsvSource | None, str | None]:
    """The published OSV snapshot's index, or (None, gap reason). Never raises for an unusable feed.
    ``resolution`` is an already verified ``osv_snapshot`` Resolution (a run-bound snapshot); without
    it the current snapshot is resolved at ``now`` (default: the wall clock)."""
    from datetime import datetime, timezone
    import osv_index
    import osv_snapshot
    if resolution is None:
        try:
            resolution = osv_snapshot.resolve_snapshot(root, max_age=osv_snapshot.DEFAULT_MAX_AGE,
                                                       now=now or datetime.now(timezone.utc))
        except Exception as exc:  # noqa: BLE001 - an unreadable feed is a gap, never a crash
            return None, f"osv-unavailable:{type(exc).__name__}"
    if not resolution.usable:
        return None, f"osv-unusable:{resolution.reason}"
    if resolution.index_path is None:
        return None, "osv-no-index"
    identity = resolution.identity
    return OsvSource(osv_index.connect(resolution.index_path),
                     {"snapshot_id": identity["snapshot_id"], "data_timestamp": identity["data_timestamp"],
                      "gaps": identity.get("gaps", [])}), None


if __name__ == "__main__":
    sys.exit(main())
