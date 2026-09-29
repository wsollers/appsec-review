"""Reachability engine jobs ``06-reachability-codeql`` and ``06-reachability-ir`` (ADR-0023 decision 5).

Both fan in over the accepted SCA matches and SBOM, resolve each match's advisory symbols (the
reviewed map, then the OSV index judged at the SCA completion time) through the dependency's own
manifest (``dep_symbol_resolver``), and publish the same table ``engine-reachability.json``: one
row per match with ``verdict`` (``reachable | unreachable | unknown``), ``tier``
(``direct | through-dependency``), the advisory symbols, the resolved language-level names, the
resolution steps, a hash-bound witness and the gaps. The Python correlator (``06-cve-reachability``)
joins the tables; no engine decides the final verdict and no model is involved.

* ``codeql``: per language, the pinned pack ``data/codeql-reachability/<lang>/`` runs against the
  database the ``02-codeql-<lang>`` node retained (re-hashed before use, never rebuilt), one B13
  container per language in the pinned ``audit-codeql`` image (network none, database / pack /
  generated symbols pack mounted read-only; the lane copies the database into its scratch).
  Languages run in parallel inside the job, bounded by ``reachability_parallel_languages``.
  C/C++ has no pack: its rows come from the traced ``CallEdges``/``EntryPoints`` tables the
  ``02-codeql-cpp`` receipts hash. Static edges miss dynamic dispatch, so this engine never
  reports ``unreachable``.
* ``ir``: the CPG arbiter (``reachability.py`` through ``dep_reachability_engines.CpgEngine``, with
  the accepted IR facts when present) for native ecosystems. It is the only engine that may report
  ``unreachable``, and only when the vulnerable function is defined in the analysed graph (the
  dependency source is present) and the witness target is hash-bound. Java bytecode and .NET IL
  engines plug in behind the same ``Engine`` interface later (TODO section G).

A source that is absent, stale or fails verification is a gap, never a block (ADR-0013); an
integrity failure of this job's own evidence blocks.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import threading
from typing import Any

import automatic_evidence_inputs as automatic
import codeql_sast
import container_execution as ce
import dep_reachability
import dep_reachability_codeql
import dep_reachability_engines as engines
import dep_reachability_lifecycle as bindings
import dep_symbol_resolver as resolver
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json
import permission_capabilities as pc
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
import reachability
from schema_validate import validate_document
import tunables

JOBS = {"codeql": "06-reachability-codeql", "ir": "06-reachability-ir"}
DAGSTER_JOBS = {"codeql": "reachability_codeql", "ir": "reachability_ir"}
CONTRACT = "engine-reachability"
RESULT = "engine-reachability.json"
RECEIPTS = "b13-receipts.json"
SUMMARY = "engine-reachability-summary.md"
SCHEMA = "appsec-review/engine-reachability/1"
SCHEMA_FILE = "engine-reachability.schema.json"
PERMISSION, LINEAGE = "permission.json", "lineage.json"
CONSUMER = "06-cve-reachability"
SCRIPT_KEY = "reachability_script"
DB_MOUNT, PACK_MOUNT, SYMBOLS_MOUNT = "/inputs/codeql-db", "/inputs/pack", "/inputs/symbols"
NATIVE = ("cpp",)
MAX_ROWS_REASON = 1024
CODE_FILES = ("reachability_engine_jobs.py", "dep_reachability.py", "dep_reachability_engines.py",
              "dep_reachability_codeql.py", "dep_reachability_lifecycle.py", "dep_symbol_resolver.py",
              "reachability.py", "codeql_sast.py", "container_execution.py", "publish_job_output.py",
              f"registry/output-contracts/{CONTRACT}.json")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


def job_id(engine: str) -> str:
    if engine not in JOBS:
        raise Blocked(f"06-reachability: unknown engine {engine!r}")
    return JOBS[engine]


def root(run_id: str, engine: str) -> Path:
    return data_path(run_id, "jobs", job_id(engine))


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean(value: Any, limit: int) -> str:
    return _CONTROL.sub(" ", str(value if value is not None else ""))[:limit]


def _code(engine: str) -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    template = f"registry/job-templates/{job_id(engine)}.json"
    values[template] = file_hash(ROOT / template)
    for name in (SCHEMA_FILE, "engine-reachability-row.schema.json"):
        values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    if engine == "codeql":
        for language in sorted(dep_reachability_codeql.PACK_PINS):
            values[f"data/codeql-reachability/{language}"] = dep_reachability_codeql.pack_sha256(language)
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(values)


# ---- shared upstream: SCA, SBOM, source projection, OSV, reviewed map, entry points ---------------

def _sca(run_id: str, job: str) -> tuple[dict[str, Any], dict[str, str], str]:
    binding, _ = automatic._accepted_binding(run_id, "02-sca-vulnerability-match")
    base = Path(binding["accepted_path"]).parent
    latest = base / "latest.json"
    if latest.is_file() and read_json(latest).get("attempt_id") != binding["attempt_id"]:
        raise Blocked(f"{job}: newest SCA attempt is not the accepted success")
    result = read_json(Path(binding["path"]))
    if validate_document(result, "sca-vulnerability-match.schema.json"):
        raise Blocked(f"{job}: accepted SCA result is invalid")
    envelope = read_json(base / "attempts" / binding["attempt_id"] / "result.json")
    return result, binding, envelope["finished_at"]


def _supplied(run_id: str) -> dict[str, Any]:
    found = bindings._supplied(run_id)
    return {"reviewed_map": found["reviewed_map"], "entry_points": found["entry_points"]}


def _read_supplied(run_id: str, supplied: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    from execution_state import run_path
    inputs = run_path(run_id) / "inputs"
    reviewed = (json.loads(bindings._check(inputs / bindings.REVIEWED_MAP, supplied["reviewed_map"]["sha256"]))
                if supplied["reviewed_map"] else None)
    entries = (json.loads(bindings._check(inputs / bindings.ENTRY_POINTS, supplied["entry_points"]["sha256"]))
               .get("entry_points", []) if supplied["entry_points"] else [])
    return reviewed, sorted({str(item) for item in entries})


def prepare(*, sca: dict[str, Any], sbom: dict[str, Any], reviewed: dict[str, Any] | None,
            osv: dep_reachability.OsvSource | None, osv_gap: str | None, tree: Path) -> list[dict[str, Any]]:
    """Per SCA match: component, language, validated advisory symbols and their resolution."""
    components = {row["component_id"]: row for row in sbom.get("components", [])}
    checkout = resolver.Checkout(tree)
    prepared = []
    for match in sorted(sca.get("matches", []), key=lambda row: row["match_id"]):
        component = components.get(match["component_ref"])
        row: dict[str, Any] = {"match_id": match["match_id"], "component_ref": match["component_ref"],
                               "advisory_id": match["advisory_id"], "ecosystem": None, "language": None,
                               "package": None, "version": None, "symbols": [],
                               "resolution": None, "gaps": []}
        if component is None:
            row["gaps"].append("component-not-in-sbom")
            prepared.append(row)
            continue
        language, osv_ecosystem = dep_reachability.ECOSYSTEMS.get(component["ecosystem"], (None, None))
        row.update(ecosystem=component["ecosystem"], language=language, package=component["name"],
                   version=component.get("version"))
        if language is None:
            row["gaps"].append("ecosystem-unsupported:" + component["ecosystem"])
            prepared.append(row)
            continue
        symbols, rejected = dep_reachability.clean_symbols(dep_reachability.reviewed_symbols(reviewed or {}, match),
                                                           "reviewed-map")
        if not symbols and osv is not None:
            symbols, more = dep_reachability.clean_symbols(dep_reachability.osv_symbols(
                osv.advisories([match["advisory_id"], *match.get("aliases", [])]), osv_ecosystem, component), "osv")
            rejected += more
        if rejected:
            row["gaps"].append(f"advisory-symbols-rejected:{rejected}")
        if not symbols:
            row["gaps"].append(osv_gap if osv is None and osv_gap else "no-advisory-symbols")
        row["symbols"] = symbols
        row["resolution"] = resolver.resolve(component["ecosystem"], component["name"], component.get("version"),
                                             symbols, checkout) if symbols else None
        prepared.append(row)
    return prepared


def _upstream(run_id: str, job: str) -> dict[str, Any]:
    sca, sca_binding, generated = _sca(run_id, job)
    tree, source_binding, files = automatic.source_projection(run_id)
    from execution_state import run_path
    manifest = run_path(run_id) / "inputs" / "artifact-manifest.json"
    source = sca["source_snapshot_sha256"]
    if source != "sha256:" + file_hash(manifest):
        raise Blocked(f"{job}: accepted SCA source generation is stale")
    sbom_binding, _ = automatic._accepted_binding(run_id, "02-sbom-inventory")
    sbom = read_json(Path(sbom_binding["path"]))
    supplied = _supplied(run_id)
    reviewed, entries = _read_supplied(run_id, supplied)
    osv, osv_identity, osv_gap = bindings._osv(generated)
    try:
        prepared = prepare(sca=sca, sbom=sbom, reviewed=reviewed, osv=osv, osv_gap=osv_gap, tree=tree)
    finally:
        if osv is not None:
            osv.connection.close()
    return {"source_generation": source, "generated_at": generated,
            "sca": {"job_id": "02-sca-vulnerability-match", "attempt_id": sca_binding["attempt_id"],
                    "sha256": sca_binding["sha256"]},
            "sca_matches_sha256": "sha256:" + digest(sca["matches"]),
            "sbom": {"attempt_id": sbom_binding["attempt_id"], "sha256": sbom_binding["sha256"]},
            "source_binding": source_binding, "osv": osv_identity, "osv_gap": osv_gap, "supplied": supplied,
            "entry_points": entries, "prepared": prepared,
            "_files": files, "_tree": str(tree)}


# ---- rows ----------------------------------------------------------------------------------------

def _names(prepared: dict[str, Any]) -> list[dict[str, Any]]:
    resolution = prepared.get("resolution") or {}
    return [{"package": row["package"], "symbol": row["symbol"]} for row in resolution.get("names", [])]


def base_row(prepared: dict[str, Any]) -> dict[str, Any]:
    resolution = prepared.get("resolution") or {}
    return {"match_id": prepared["match_id"], "component_ref": prepared["component_ref"],
            "advisory_id": prepared["advisory_id"], "ecosystem": prepared["ecosystem"],
            "language": prepared["language"], "verdict": "unknown", "tier": None,
            "symbols": prepared["symbols"], "resolved": resolution.get("names", []),
            "resolution": [_clean(step, 300) for step in resolution.get("steps", [])],
            "witness": [], "taint_paths": [], "target": None, "database_ids": [], "reason": "",
            "gaps": sorted(set(prepared["gaps"]) | set(resolution.get("gaps", [])))}


def not_applicable(prepared: dict[str, Any], engine: str) -> dict[str, Any]:
    row = base_row(prepared)
    row.update(reason=f"{engine}: not applicable to {prepared['language'] or 'this component'}",
               gaps=sorted(set(row["gaps"]) | {f"engine-not-applicable:{engine}:{prepared['language']}"}))
    return row


def finish_row(prepared: dict[str, Any], found: dict[str, Any], files: dict[str, str], *, engine: str,
               database_ids: list[str], unreachable_allowed: bool, source_present: bool = True) -> dict[str, Any]:
    """An engine result -> a table row; binds the witness (or target) to the source projection."""
    row = base_row(prepared)
    gaps = set(row["gaps"]) | set(found.get("gaps", []))
    state = found["state"] if found["ran"] else "unknown"
    reason = f"{engine}: {found['reason']}"
    witness: list[dict[str, Any]] = []
    target = None
    if state == "reachable":
        witness, bound = dep_reachability.bind_witness(found["witness"], files)
        if not bound or not witness:
            state, witness = "unknown", []
            reason += "; witness not hash-bound to the source projection"
            gaps.add("witness-not-hash-bound")
    elif state == "unreachable":
        candidate = found.get("target") or {}
        sha = files.get(candidate.get("file")) if isinstance(candidate.get("file"), str) else None
        if not unreachable_allowed:
            state, reason = "unknown", reason + "; this engine cannot prove absence"
        elif not source_present:
            state, reason = "unknown", reason + "; the vulnerable function's source is not in the analysed graph"
            gaps.add("dependency-source-absent")
        elif sha is None:
            state, reason = "unknown", reason + "; unreachable target not hash-bound"
            gaps.add("witness-not-hash-bound")
        else:
            target = {"function": _clean(candidate.get("function"), 200), "file": candidate["file"],
                      "line": int(candidate.get("line") or 0), "sha256": sha}
    if state == "unknown":
        gaps.add(f"{engine}-undecided")
    tier = None
    if state == "reachable":
        roots = (prepared.get("resolution") or {}).get("vendored_roots", [])
        tier = resolver.tier(witness[-1]["file"], roots)
    row.update(verdict=state, tier=tier, witness=witness, target=target, database_ids=sorted(set(database_ids)),
               reason=_clean(reason, MAX_ROWS_REASON),
               taint_paths=[{"source": _clean(item["source"], 1100), "sink": _clean(item["sink"], 1100)}
                            for item in found.get("taint_paths", [])][:32],
               gaps=sorted(_clean(gap, 512) for gap in gaps))
    return row


def assemble(*, run_id: str, attempt_id: str, engine: str, inputs: dict[str, Any], rows: list[dict[str, Any]],
             languages: list[dict[str, Any]]) -> dict[str, Any]:
    rows = sorted(rows, key=lambda row: row["match_id"])
    gaps = sorted({f"REACHABILITY_UNKNOWN:{row['match_id']}:{gap}"[:512] for row in rows for gap in row["gaps"]
                   if not gap.startswith("engine-not-applicable:")} |
                  {f"ENGINE_INPUT:{gap}"[:512] for language in languages for gap in language["gaps"]} |
                  ({f"ENGINE_INPUT:{inputs['osv_gap']}"[:512]} if inputs.get("osv_gap") else set()))
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in ("reachable", "unreachable", "unknown")}
    return {"schema": SCHEMA, "run_id": run_id, "job_id": job_id(engine), "attempt_id": attempt_id, "engine": engine,
            "source_snapshot_sha256": inputs["source_generation"], "sca_binding": inputs["sca"],
            "status": "OK_WITH_GAPS" if gaps else "OK", "languages": languages, "rows": rows, "counts": counts,
            "coverage_gaps": gaps, "claim_ceiling": "EVIDENCE_LEADS_ONLY"}


# ---- codeql engine ---------------------------------------------------------------------------------

def reachability_script() -> tuple[dict[str, str], str]:
    """The pinned reachability lane script (tool.json ``reachability_script``, COPYed into the image)."""
    metadata, metadata_sha = codeql_sast.tool_metadata()
    entry = metadata.get(SCRIPT_KEY)
    script = codeql_sast.IMAGE_ROOT / str(entry.get("source", "")) if isinstance(entry, dict) else None
    if (script is None or set(entry) != {"path", "source"} or not str(entry["source"]).startswith("scripts/") or
            entry["path"] != "/opt/scripts/" + PurePosixPath(entry["source"]).name or
            not script.is_file() or script.is_symlink()):
        raise Blocked(f"{JOBS['codeql']}: CodeQL reachability script metadata is invalid")
    return {**entry, "sha256": "sha256:" + file_hash(script)}, metadata_sha


def _cpp_tables(run_id: str, document: dict[str, Any], binding: dict[str, Any]
                ) -> tuple[list[dict[str, str]], list[str]]:
    """Traced graph tables named by the accepted 02-codeql-cpp receipts (hash-bound, not decoded here)."""
    attempt = codeql_sast.root(run_id, "cpp") / "attempts" / binding["attempt_id"]
    receipts = read_json(attempt / codeql_sast.RECEIPTS) if (attempt / codeql_sast.RECEIPTS).is_file() else {"tools": []}
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
    return tables, gaps


def codeql_plan(run_id: str, prepared: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per CodeQL language: what runs (container / traced tables) or why not."""
    registry = ce.load_image_registry(ce.IMAGES_DIR)
    image = registry.get(codeql_sast.IMAGE_ID)
    digest_value = image.get("digest") if isinstance(image, dict) else None
    ready = isinstance(digest_value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest_value) is not None
    script, _ = reachability_script()
    threads = tunables.value(JOBS["codeql"], "codeql_threads")
    ram_mb = tunables.value(JOBS["codeql"], "codeql_ram_bytes") // (1024 * 1024)
    plan = []
    for language in codeql_sast.LANGUAGES:
        wanted = [row for row in prepared if row["language"] == language and _names(row)]
        entry: dict[str, Any] = {"language": language, "state": "no-matches", "matches": [r["match_id"] for r in wanted],
                                 "node": None, "database": None, "tables": [], "argv": [], "image_digest": None,
                                 "symbols": [], "gaps": []}
        if not wanted:
            plan.append(entry); continue
        document, binding, gap = codeql_sast.load_accepted(run_id, language)
        if document is None or binding["status"] == "SKIPPED":
            entry.update(state="no-database", gaps=[gap or f"engine-input-absent:{codeql_sast.JOBS[language]}:skipped"])
            plan.append(entry); continue
        entry["node"] = binding
        if language == "cpp":
            tables, gaps = _cpp_tables(run_id, document, binding)
            entry.update(state="ran" if tables else "no-database", tables=tables,
                         gaps=gaps + ([] if tables else ["engine-input-absent:codeql:cpp-traced-tables"]))
            plan.append(entry); continue
        if language not in dep_reachability_codeql.PACK_PINS:
            entry.update(state="no-pack", gaps=[f"codeql-no-reachability-pack:{language}"])
            plan.append(entry); continue
        databases = [row for row in document["databases"] if row["build_mode"] == "none"]
        if not databases:
            entry.update(state="no-database", gaps=[f"engine-input-absent:codeql-database:{language}"])
            plan.append(entry); continue
        if not ready:
            entry.update(state="gap", database=databases[0], gaps=[f"codeql-image-unavailable:{codeql_sast.IMAGE_ID}"])
            plan.append(entry); continue
        rows = sorted({(name["package"], name["symbol"]) for row in wanted for name in _names(row)})
        entry.update(state="ran", database=databases[0], image_digest=digest_value,
                     symbols=[{"package": p, "symbol": s} for p, s in rows],
                     argv=[script["path"], language, str(threads), str(ram_mb)])
        plan.append(entry)
    return plan


def _codeql_request(run_id: str, adapter_id: str, inputs: dict[str, Any], entry: dict[str, Any],
                    database: Path, symbols: Path) -> dict[str, Any]:
    job = JOBS["codeql"]
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": job, "capabilities": []}
    context = {"run_id": run_id, "job_id": job, "source_snapshot_sha256": inputs["source_generation"],
               "now": _utc_now(), "registry_ceiling": []}
    decision = pc.evaluate(requirement, [], context)
    pc.require_granted(decision, requirement=requirement, grants=[], context=context)
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": job, "attempt_id": adapter_id,
            "image": {"image_id": codeql_sast.IMAGE_ID, "digest": entry["image_digest"]},
            "argv": list(entry["argv"]),
            "environment": [{"name": "LANG", "value": "C.UTF-8"}, {"name": "LC_ALL", "value": "C.UTF-8"},
                            {"name": "NO_COLOR", "value": "1"}, {"name": "XDG_CACHE_HOME", "value": "/tmp/cache"}],
            "target_mounts": [{"host_path": str(database), "container_path": DB_MOUNT},
                              {"host_path": str(dep_reachability_codeql.PACK_ROOT / entry["language"]),
                               "container_path": PACK_MOUNT},
                              {"host_path": str(symbols), "container_path": SYMBOLS_MOUNT}],
            "scratch_path": "scratch", "log_path": "logs/container",
            "network": {"mode": "none", "destinations": []},
            "permission": {"requirement": requirement, "grants": [], "decision": decision},
            "limits": dict(inputs["limits"])}


def _table_hashes(trial: Path) -> dict[str, str | None]:
    found = {}
    for name in engines.TABLES:
        path = trial / "scratch" / "graph" / f"{name}.csv"
        found[name] = "sha256:" + file_hash(path) if path.is_file() and not path.is_symlink() else None
    return found


def _decode(trial: Path, hashes: dict[str, str | None], language: str) -> tuple[dict[str, list[dict[str, str]]], list[str]]:
    tables, gaps = {}, []
    for name, sha in hashes.items():
        if sha is None:
            if name in engines.REQUIRED_TABLES:
                gaps.append(f"codeql-table-absent:{language}:{name}")
            continue
        path = trial / "scratch" / "graph" / f"{name}.csv"
        data = path.read_bytes() if path.is_file() and not path.is_symlink() else b""
        if engines.sha256_bytes(data) != sha:
            raise Blocked(f"{JOBS['codeql']}: {language} {name}.csv differs from its receipt")
        try:
            tables[name] = engines.read_table(data, name)
        except ValueError:
            gaps.append(f"codeql-table-invalid:{language}:{name}")
    return tables, gaps


def symbols_pack(entry: dict[str, Any]) -> dict[str, bytes]:
    return dep_reachability_codeql.data_extension(entry["language"], entry["symbols"])


def codeql_rows(run_id: str, inputs: dict[str, Any], outcomes: dict[str, dict[str, Any]],
                files: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Rows and language states from the per-language outcomes (``tables``/``gaps``/``terminal_gap``)."""
    prepared = {row["match_id"]: row for row in inputs["prepared"]}
    rows: dict[str, dict[str, Any]] = {}
    languages = []
    for entry in inputs["plan"]:
        language = entry["language"]
        outcome = outcomes.get(language, {})
        gaps = list(entry["gaps"]) + list(outcome.get("gaps", []))
        state = entry["state"]
        tables = outcome.get("tables") or {}
        if state == "ran" and not tables:
            state = "gap"
        database_ids = [entry["database"]["database_id"]] if entry.get("database") else []
        languages.append({"language": language, "state": state, "database_ids": database_ids,
                          "gaps": sorted(set(gaps))})
        if not entry["matches"]:
            continue
        engine = engines.CodeqlEngine({language: tables} if tables else {}, {language: gaps})
        for match_id in entry["matches"]:
            item = prepared[match_id]
            query = engines.Query(match_id=match_id, language=language, package=item["package"],
                                  symbols=_names(item), entry_points=inputs["entry_points"])
            found = engine.assess(query)
            rows[match_id] = finish_row(item, found, files, engine="codeql", database_ids=database_ids,
                                        unreachable_allowed=False)
    for item in inputs["prepared"]:
        if item["match_id"] in rows:
            continue
        if item["language"] in codeql_sast.LANGUAGES and not _names(item):
            row = base_row(item)
            row.update(reason="codeql: no resolved advisory symbol (package-level presence only)",
                       gaps=sorted(set(row["gaps"]) | {"codeql-undecided"}))
            rows[item["match_id"]] = row
        else:
            rows[item["match_id"]] = not_applicable(item, "codeql")
    return list(rows.values()), languages


# ---- ir engine -------------------------------------------------------------------------------------

def _ir_facts(run_id: str, source: str) -> dict[str, Any] | None:
    base = data_path(run_id, "jobs", "02-ir-facts")
    binding, gap = bindings._accepted(run_id, "02-ir-facts", "ir-facts.json", source)
    if binding is None:
        return None
    document = read_json(base / "attempts" / binding["attempt_id"] / "ir-facts.json")
    return None if document.get("status") == "SKIPPED" else binding


def _defined(graph: reachability.CallGraph, symbols: list[dict[str, Any]]) -> bool:
    for item in symbols:
        name = re.split(r"[.:]+", item["symbol"])[-1]
        for full in graph.by_short.get(name, []):
            if reachability.symbol_matches(full, item["symbol"], item.get("package"),
                                           graph.methods[full]["path"] or "", graph.methods[full]["name"]):
                return True
    return False


def ir_rows(run_id: str, inputs: dict[str, Any], files: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    graph = None
    gaps = list(inputs["cpg_gaps"])
    if inputs["cpg"]:
        attempt = data_path(run_id, "jobs", bindings.CPG_JOB, "attempts", inputs["cpg"]["attempt_id"])
        bindings._check(attempt / bindings.CPG_RESULT, inputs["cpg"]["result_sha256"])
        facts = None
        if inputs["ir"]:
            facts = data_path(run_id, "jobs", "02-ir-facts", "attempts", inputs["ir"]["attempt_id"], "ir-facts.json")
            bindings._check(facts, inputs["ir"]["result_sha256"])
        try:
            graph = reachability.load_cpg(attempt, facts)
        except (ValueError, OSError, KeyError):
            gaps.append("engine-input-invalid:02-code-property-graph")
    engine = engines.CpgEngine(graph)
    rows = []
    wanted = [row for row in inputs["prepared"] if row["language"] in NATIVE]
    for item in inputs["prepared"]:
        if item["language"] not in NATIVE:
            rows.append(not_applicable(item, "ir"))
            continue
        if not _names(item):
            row = base_row(item)
            row.update(reason="ir: no advisory symbol (package-level presence only)",
                       gaps=sorted(set(row["gaps"]) | {"ir-undecided"}))
            rows.append(row)
            continue
        query = engines.Query(match_id=item["match_id"], language="cpp", package=item["package"],
                              symbols=_names(item), entry_points=inputs["entry_points"])
        found = engine.assess(query)
        found = {**found, "gaps": list(found["gaps"]) + gaps}
        rows.append(finish_row(item, found, files, engine="ir", database_ids=[], unreachable_allowed=True,
                               source_present=graph is not None and _defined(graph, _names(item))))
    state = ("no-matches" if not wanted else "ran" if graph is not None else "no-engine")
    return rows, [{"language": "cpp", "state": state, "database_ids": [], "gaps": sorted(set(gaps))}]


# ---- lifecycle -------------------------------------------------------------------------------------

def current_inputs(run_id: str, engine: str) -> dict[str, Any]:
    job = job_id(engine)
    upstream = _upstream(run_id, job)
    upstream.pop("_files"); upstream.pop("_tree")
    inputs = {"job": job, "engine": engine, "run_id": run_id, **upstream, "code": _code(engine)}
    if engine == "codeql":
        inputs.update(limits=tunables.container_limits(job),
                      parallel=tunables.value(job, "reachability_parallel_languages"),
                      boundary_sha256=ce.boundary_sha256(), script=reachability_script()[0],
                      plan=codeql_plan(run_id, upstream["prepared"]))
    else:
        cpg, cpg_gaps = bindings._cpg(run_id, upstream["source_generation"])
        inputs.update(cpg=cpg, cpg_gaps=cpg_gaps,
                      ir=_ir_facts(run_id, upstream["source_generation"]) if cpg else None)
    return inputs


def _files(run_id: str, inputs: dict[str, Any]) -> dict[str, str]:
    _tree, binding, files = automatic.source_projection(run_id)
    if binding != inputs["source_binding"]:
        raise Blocked(f"{inputs['job']}: source projection changed after binding")
    return files


def _runtime(source: str) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise Blocked(f"{JOBS['codeql']}: Docker is unavailable")
    return ce.ContainerRuntime(
        docker_executable=defaults["docker_executable"], docker_host=None, images_dir=ce.IMAGES_DIR,
        host_flavor=defaults["host_flavor"], container_user=defaults["container_user"],
        source_snapshot_sha256=source, registry_ceiling=[], clock=_utc_now, cancel=threading.Event())


def _host(runtime: ce.ContainerRuntime) -> dict[str, Any]:
    return {"host_flavor": runtime.host_flavor, "docker_host": runtime.docker_host,
            "docker_executable": runtime.docker_executable, "container_user": runtime.container_user}


def _cpp_outcome(run_id: str, entry: dict[str, Any]) -> dict[str, Any]:
    attempt = codeql_sast.root(run_id, "cpp") / "attempts" / entry["node"]["attempt_id"]
    tables: dict[str, list[dict[str, str]]] = {}
    gaps: list[str] = []
    for row in entry["tables"]:
        path = attempt.joinpath(*PurePosixPath(row["path"]).parts)
        try:
            data = bindings._check(path, row["sha256"])
        except bindings.Stale:
            gaps.append(f"codeql-table-changed:cpp:{row['table']}")
            continue
        try:
            tables.setdefault(row["table"], []).extend(engines.read_table(data, row["table"]))
        except ValueError:
            gaps.append(f"codeql-table-invalid:cpp:{row['table']}")
    return {"tables": tables, "gaps": gaps}


def _language_outcome(run_id: str, inputs: dict[str, Any], entry: dict[str, Any], trial: Path,
                      runtime: ce.ContainerRuntime, adapter_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run one language's queries in its container; (outcome, receipt)."""
    language = entry["language"]
    database = codeql_sast.verify_database(run_id, entry["database"])
    receipt: dict[str, Any] = {"language": language, "database_id": entry["database"]["database_id"]}
    if database is None:
        return {"tables": {}, "gaps": [f"codeql-db-changed:{language}"]}, {**receipt, "database_verified": False}
    symbols = trial / "symbols"
    symbols.mkdir(parents=True)
    for name, data in symbols_pack(entry).items():
        (symbols / name).write_bytes(data)
    request = _codeql_request(run_id, adapter_id, inputs, entry, database, symbols)
    (trial / "run").mkdir()
    terminal = ce.run_container(runtime, run_id=run_id, job_id=JOBS["codeql"], attempt_id=adapter_id,
                                attempt_root=trial / "run", request=request)
    verified = ce.load_verified_result(trial / "run", run_id=run_id, job_id=JOBS["codeql"], attempt_id=adapter_id,
        request=request, images_dir=runtime.images_dir, expected_result_sha256=terminal["result_sha256"],
        **_host(runtime))
    receipt.update(database_verified=True, adapter_attempt_id=adapter_id, expected_result_sha256=terminal["result_sha256"])
    return _verified_outcome(language, verified, trial), {**receipt, "tables": _table_hashes(trial / "run")}


def _verified_outcome(language: str, terminal: dict[str, Any], trial: Path) -> dict[str, Any]:
    gap = codeql_sast.terminal_gap(f"reachability {language}", terminal, JOBS["codeql"])
    if gap is not None:
        return {"tables": {}, "gaps": [gap]}
    tables, gaps = _decode(trial / "run", _table_hashes(trial / "run"), language)
    return {"tables": tables, "gaps": gaps}


def _write(attempt: Path, result: dict[str, Any], run_id: str, dagster_id: str, allocation: dict[str, Any],
           inputs: dict[str, Any]) -> dict[str, Any]:
    engine = inputs["engine"]
    atomic_json(attempt / RESULT, result)
    counts = result["counts"]
    (attempt / SUMMARY).write_text(
        f"# Reachability engine: {engine}\n\n"
        f"- Matches: {len(result['rows'])}; reachable {counts['reachable']}, unreachable {counts['unreachable']}, "
        f"unknown {counts['unknown']}.\n"
        + "".join(f"- {row['language']}: {row['state']}\n" for row in result["languages"])
        + f"- Explicit coverage gaps: {len(result['coverage_gaps'])}.\n", encoding="utf-8")
    status = {"process": inputs["job"], "status": result["status"], "run_id": run_id, "dagster_run_id": dagster_id,
              "attempt_id": allocation["attempt_id"], "rows": len(result["rows"]),
              "reachable": counts["reachable"], "network": "none",
              "qualification": "implemented_not_qualified", "ended_at": now()}
    atomic_json(attempt / "status.json", status)
    permission, lineage = _receipts(inputs)
    atomic_json(attempt / PERMISSION, permission)
    atomic_json(attempt / LINEAGE, lineage)
    return status


def _receipts(inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    template = read_json(ROOT / "registry" / "job-templates" / f"{inputs['job']}.json")
    common = {"run_id": inputs["run_id"], "job_id": inputs["job"], "source_snapshot_sha256": inputs["source_generation"]}
    return ({"schema": "appsec-review/producer-permission-receipt/1.0", **common,
             "permissions": template["permissions"]},
            {"schema": "appsec-review/producer-lineage-receipt/1.0", **common,
             "build_lineage_sha256": "sha256:" + digest(inputs)})


def _derive(run_id: str, attempt: Path, inputs: dict[str, Any], outcomes: dict[str, Any] | None = None) -> dict[str, Any]:
    files = _files(run_id, inputs)
    if inputs["engine"] == "codeql":
        rows, languages = codeql_rows(run_id, inputs, outcomes or {}, files)
    else:
        rows, languages = ir_rows(run_id, inputs, files)
    return assemble(run_id=run_id, attempt_id=attempt.name, engine=inputs["engine"], inputs=inputs, rows=rows,
                    languages=languages)


def _replay_outcomes(run_id: str, attempt: Path, inputs: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Re-verify every container receipt and re-decode its tables (validate path)."""
    receipts = {row["language"]: row for row in read_json(attempt / RECEIPTS).get("languages", [])}
    ran = [entry for entry in inputs["plan"] if entry["state"] == "ran" and entry["language"] != "cpp"]
    if sorted(receipts) != sorted(entry["language"] for entry in ran):
        raise Blocked(f"{inputs['job']}: B13 receipt set does not match the plan")
    outcomes: dict[str, dict[str, Any]] = {}
    runtime = _runtime(inputs["source_generation"]) if any(r.get("database_verified") for r in receipts.values()) else None
    for entry in inputs["plan"]:
        language = entry["language"]
        if entry["state"] != "ran":
            continue
        if language == "cpp":
            outcomes[language] = _cpp_outcome(run_id, entry)
            continue
        receipt = receipts[language]
        trial = attempt / "languages" / language
        if not receipt.get("database_verified"):
            outcomes[language] = {"tables": {}, "gaps": [f"codeql-db-changed:{language}"]}
            continue
        for name, data in symbols_pack(entry).items():
            if (trial / "symbols" / name).read_bytes() != data:
                raise Blocked(f"{inputs['job']}: {language} symbols pack differs from the plan")
        request = read_json(trial / "run" / "logs/container" / ce.REQUEST_FILE)
        if request.get("argv") != entry["argv"] or request.get("limits") != inputs["limits"]:
            raise Blocked(f"{inputs['job']}: {language} request differs from the plan")
        try:
            terminal = ce.load_verified_result(trial / "run", run_id=run_id, job_id=inputs["job"],
                attempt_id=receipt["adapter_attempt_id"], request=request, images_dir=runtime.images_dir,
                expected_result_sha256=receipt["expected_result_sha256"], **_host(runtime))
        except ce.ContainerRequestError as exc:
            raise Blocked(f"{inputs['job']}: B13 evidence failed re-verification for {language}") from exc
        if receipt.get("tables") != _table_hashes(trial / "run"):
            raise Blocked(f"{inputs['job']}: {language} tables differ from their receipt")
        outcomes[language] = _verified_outcome(language, terminal, trial)
    return outcomes


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    job = inputs["job"]
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{job}: immutable attempt inputs changed")
    result = read_json(attempt / RESULT)
    if validate_document(result, SCHEMA_FILE):
        raise Blocked(f"{job}: result schema validation failed")
    outcomes = _replay_outcomes(run_id, attempt, inputs) if inputs["engine"] == "codeql" else None
    if result != _derive(run_id, attempt, inputs, outcomes):
        raise Blocked(f"{job}: engine table no longer matches its hash-bound inputs")
    permission, lineage = _receipts(inputs)
    if read_json(attempt / PERMISSION) != permission or read_json(attempt / LINEAGE) != lineage:
        raise Blocked(f"{job}: canonical producer receipts changed")


def run(run_id: str, dagster_id: str, engine: str, force: bool = False) -> dict[str, Any]:
    job = job_id(engine)
    base = root(run_id, engine)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        if inputs["code"] != _code(engine):
            raise Blocked(f"{job}: implementation changed before execution")
        outcomes: dict[str, dict[str, Any]] = {}
        artifacts = [RESULT, SUMMARY, "status.json", PERMISSION, LINEAGE]
        if engine == "codeql":
            receipts = []
            containers = [entry for entry in inputs["plan"] if entry["state"] == "ran" and entry["language"] != "cpp"]
            runtime = _runtime(inputs["source_generation"]) if containers else None

            def one(entry: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]]:
                trial = attempt / "languages" / entry["language"]
                trial.mkdir(parents=True)
                adapter_id = f"reach-{entry['language']}-{allocation['attempt_id'][:12]}"
                outcome, receipt = _language_outcome(run_id, inputs, entry, trial, runtime, adapter_id)
                return entry["language"], outcome, receipt

            with ThreadPoolExecutor(max_workers=max(1, int(inputs["parallel"]))) as pool:
                for language, outcome, receipt in pool.map(one, containers):
                    outcomes[language] = outcome
                    receipts.append(receipt)
            for entry in inputs["plan"]:
                if entry["state"] == "ran" and entry["language"] == "cpp":
                    outcomes["cpp"] = _cpp_outcome(run_id, entry)
            atomic_json(attempt / RECEIPTS, {"languages": sorted(receipts, key=lambda row: row["language"])})
            artifacts.append(RECEIPTS)
        result = _derive(run_id, attempt, inputs, outcomes)
        status = _write(attempt, result, run_id, dagster_id, allocation, inputs)
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=job, dagster_run_id=dagster_id,
            worker_kind="pinned_container" if engine == "codeql" else "deterministic_python",
            output_contract=CONTRACT, input_fingerprint=fingerprint, started_at=allocation["started_at"],
            execution_status=result["status"],
            summary=f"{engine} reachability: {result['counts']['reachable']} reachable of {len(result['rows'])} match(es).",
            status_record=status, artifact_paths=artifacts, gaps=result["coverage_gaps"],
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=job, dagster_run_id=dagster_id,
        worker_kind="pinned_container" if engine == "codeql" else "deterministic_python",
        output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/launch_job.py --run-id {run_id} --job full_review --wait",
        derive_inputs=lambda: current_inputs(run_id, engine),
        fingerprint_inputs=lambda value: "sha256:" + digest(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": job,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code(engine)},
        force=force, post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        consumer_job_id=CONSUMER,
        blocked_summary=f"{job} preflight did not complete.",
        failed_summary=f"{job} did not publish; no older success may be used.")


def validate(run_id: str, engine: str) -> Path:
    base = root(run_id, engine)
    inputs = current_inputs(run_id, engine)
    attempt, _ = validate_published(base, read_json(base / "accepted.json"), "sha256:" + digest(inputs),
                                    expected_run_id=run_id, expected_job_id=job_id(engine), consumer_job_id=CONSUMER)
    _validate_attempt(run_id, attempt, inputs)
    return attempt


def run_codeql(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    return run(run_id, dagster_id, "codeql", force)


def run_ir(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    return run(run_id, dagster_id, "ir", force)


def validate_codeql(run_id: str) -> Path:
    return validate(run_id, "codeql")


def validate_ir(run_id: str) -> Path:
    return validate(run_id, "ir")


def load_table(run_id: str, engine: str, source: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    """An engine's accepted table verified by pointer, envelope and attempt tree hashes (correlator)."""
    binding, gap = bindings._accepted(run_id, job_id(engine), RESULT, source)
    if binding is None:
        return None, None, gap
    document = read_json(root(run_id, engine) / "attempts" / binding["attempt_id"] / RESULT)
    if validate_document(document, SCHEMA_FILE) or document.get("engine") != engine:
        return None, None, f"engine-input-invalid:{job_id(engine)}"
    return document, binding, None
