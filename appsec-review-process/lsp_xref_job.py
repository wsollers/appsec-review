#!/usr/bin/env python3
"""``02-lsp-xref``: language-server cross-references for every function of the accepted code index.

Inputs (bound by accepted pointer and hash): ``02-code-index`` (required; the functions: ``methods`` outside
externals, plus ``ts_functions`` the CPG lacks, and its ``files`` languages), ``02-native-build`` (optional; each
accepted unit's adapted ``compile_commands.json`` is one clangd build variant) and ``02-language-census``
(optional, read when accepted: its ``languages_needing_server`` decide which servers are needed; without it the
code index's languages do). ``lsp_service.readiness`` decides which servers are ready; the rest are gaps.

For each function whose server is ready the job asks ``definition``, ``references`` and the incoming and
outgoing call hierarchy at the function name's position (the name located on its line in the snapshot),
through ``lsp_service.Broker``: every answer is recorded under ``data/lsp/`` and hash-bound, so a retry or
the validator replays the same answers without a live server. The planned queries are counted first;
functions beyond ``max_queries`` are not asked and are an ``lsp-budget-exceeded`` gap, never silently cut.

Output: ``lsp-xref.sqlite`` beside the code index (tables ``lsp_functions``, ``lsp_definitions``,
``lsp_references``, ``lsp_calls``, ``lsp_servers``, ``lsp_files``, ``meta``; every row tagged with server,
version and build variant through ``lsp_servers``) and ``lsp-xref.json`` naming its sha256, its logical
``content_sha256``, the bindings, the server specs (so ``code_*`` tools can reach the live broker) and the
gaps: server not ready / failed / absent, unresolved includes (clangd ``pp_file_not_found``), names not
located, budget exceeded. Rows are locators and untrusted data, never findings.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import tempfile
import time
from typing import Any

import code_index
import lsp_service

JOB = "02-lsp-xref"
CONTRACT = "lsp-xref"
RESULT = "lsp-xref.json"
SQLITE = "lsp-xref.sqlite"
SUMMARY = "lsp-xref-summary.md"
SCHEMA = "appsec-review/lsp-xref/1"
SCHEMA_FILE = "lsp-xref.schema.json"
INDEX_JOB, INDEX_RESULT = "02-code-index", "code-index.json"
CENSUS_JOB, CENSUS_RESULT = "02-language-census", "language-census.json"
NON_PROGRAM = frozenset({"json"})
NATIVE_JOB = "02-native-build"
CONSUMER = "07-hypothesis-discovery"
METHODS = ("definition", "references", "incomingCalls", "outgoingCalls")
TABLES = ("meta", "lsp_servers", "lsp_files", "lsp_functions", "lsp_definitions", "lsp_references", "lsp_calls")
DDL = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE lsp_servers(server_key TEXT NOT NULL, variant TEXT NOT NULL, server TEXT NOT NULL, server_version TEXT,
  image_id TEXT NOT NULL, image_digest TEXT, build_input_sha256 TEXT, identity_sha256 TEXT NOT NULL,
  PRIMARY KEY(server_key, variant));
CREATE TABLE lsp_files(path TEXT PRIMARY KEY, language TEXT NOT NULL, server_key TEXT NOT NULL, variant TEXT NOT NULL);
CREATE TABLE lsp_functions(id INTEGER PRIMARY KEY, file TEXT NOT NULL, start_line INTEGER NOT NULL, name TEXT NOT NULL,
  language TEXT, server_key TEXT, variant TEXT, character INTEGER, status TEXT NOT NULL);
CREATE TABLE lsp_definitions(function_id INTEGER NOT NULL, path TEXT NOT NULL, start_line INTEGER NOT NULL,
  start_character INTEGER, end_line INTEGER, end_character INTEGER, server_key TEXT NOT NULL, variant TEXT NOT NULL,
  recording TEXT);
CREATE TABLE lsp_references(function_id INTEGER NOT NULL, path TEXT NOT NULL, start_line INTEGER NOT NULL,
  start_character INTEGER, server_key TEXT NOT NULL, variant TEXT NOT NULL, recording TEXT);
CREATE TABLE lsp_calls(function_id INTEGER NOT NULL, direction TEXT NOT NULL, peer_name TEXT NOT NULL,
  peer_path TEXT NOT NULL, peer_line INTEGER NOT NULL, call_lines TEXT NOT NULL, server_key TEXT NOT NULL,
  variant TEXT NOT NULL, recording TEXT);
CREATE INDEX lsp_functions_at ON lsp_functions(file, start_line);
CREATE INDEX lsp_functions_name ON lsp_functions(name);
CREATE INDEX lsp_references_fn ON lsp_references(function_id);
CREATE INDEX lsp_definitions_fn ON lsp_definitions(function_id);
CREATE INDEX lsp_calls_fn ON lsp_calls(function_id, direction);
"""


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_sha256(connection: sqlite3.Connection) -> str:
    value = hashlib.sha256()
    for table in TABLES:
        value.update(table.encode() + b"\n")
        for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid"):
            value.update(_json(list(row)).encode("utf-8") + b"\n")
    return "sha256:" + value.hexdigest()


def functions(index: sqlite3.Connection) -> list[tuple[str, int, str]]:
    """(file, start_line, short name) of every indexed function, CPG first, tree-sitter where the CPG has none."""
    found: dict[tuple[str, int], str] = {}
    for path, line, name in index.execute(
            "SELECT file, start_line, name FROM methods WHERE is_external = 0 AND file IS NOT NULL AND start_line > 0 "
            "ORDER BY file, start_line, name"):
        if name and not name.startswith(("<", ":")):
            found.setdefault((path, int(line)), name)
    for path, line, name in index.execute("SELECT file, start_line, name FROM ts_functions WHERE start_line > 0 "
                                          "ORDER BY file, start_line, name"):
        short = (name or "").replace("::", ".").split(".")[-1]
        if short:
            found.setdefault((path, int(line)), short)
    return sorted((path, line, name) for (path, line), name in found.items())


def _column(target: Path, path: str, line: int, name: str) -> int | None:
    """UTF-16 column of ``name`` on ``path:line`` in the snapshot (LSP positions), or None."""
    file = target.joinpath(*PurePosixPath(path).parts)
    try:
        if file.is_symlink() or not file.resolve().is_relative_to(target.resolve()):
            return None
        with file.open("rb") as handle:
            for number, raw in enumerate(handle, 1):
                if number == line:
                    text = raw.decode("utf-8", "replace")
                    at = text.find(name)
                    return None if at < 0 else len(text[:at].encode("utf-16-le")) // 2
    except OSError:
        return None
    return None


def index_files(index: sqlite3.Connection) -> dict[str, str]:
    """{path: language} of the code index's files (its language column, else the tree-sitter suffix map)."""
    return {path: language or code_index.language_of(path) for path, language in
            index.execute("SELECT path, language FROM files ORDER BY path")
            if path and not path.startswith("<") and (language or code_index.language_of(path))}


def census_languages(document: Any) -> dict[str, int] | None:
    """{language: files} the census says need a server, or None when it names none in a form read here."""
    if not isinstance(document, dict):
        return None
    wanted = document.get("languages_needing_server")
    if not isinstance(wanted, list):
        return None
    counts: dict[str, int] = {}
    per_language = document.get("languages")
    if isinstance(per_language, dict):
        counts = {k: v.get("files", 0) if isinstance(v, dict) else int(v or 0) for k, v in per_language.items()}
    elif isinstance(per_language, list):
        counts = {row.get("language"): int(row.get("files") or row.get("file_count") or 0)
                  for row in per_language if isinstance(row, dict)}
    names = [row if isinstance(row, str) else row.get("language") for row in wanted
             if isinstance(row, str) or isinstance(row, dict)]
    return {name: counts.get(name, 0) for name in names if isinstance(name, str)}


def file_servers(files: dict[str, str], servers: list[dict[str, Any]],
                 native_units: list[dict[str, Any]] | None) -> dict[str, tuple[str, str, str]]:
    """{path: (language, server_key, variant)} for each indexed file whose server is ready.

    C/C++: the variant whose compile database compiles the file, else (headers) the first variant."""
    variants: dict[str, list[str]] = {}
    for server in servers:
        variants.setdefault(server["identity"]["server_key"], []).append(server["identity"]["variant"])
    compiled: dict[str, str] = {}
    for unit in sorted(native_units or [], key=lambda u: u["build_variant"]["variant_id"]):
        for entry in unit.get("adapted") or []:
            relative = str(entry.get("file", ""))[len("/workspace/"):]
            compiled.setdefault(relative, unit["build_variant"]["variant_id"])
    out = {}
    for path, language in sorted(files.items()):
        key = lsp_service.LANGUAGE_SERVER.get(language)
        if key not in variants:
            continue
        variant = compiled.get(path) if key == "cpp" else None
        out[path] = (language, key, variant if variant in variants[key] else sorted(variants[key])[0])
    return out


def build(database: Path, *, index: sqlite3.Connection, target: Path,
          servers: list[dict[str, Any]], native_units: list[dict[str, Any]] | None, broker: Any,
          max_queries: int, input_gaps: list[dict[str, Any]]) -> dict[str, Any]:
    """Ask, record and tabulate; returns {counts, servers, gaps, capabilities, content_sha256}."""
    gaps = [dict(gap) for gap in input_gaps]
    files = index_files(index)
    mapping = file_servers(files, servers, native_units)
    rows = functions(index)
    eligible = [row for row in rows if row[0] in mapping]
    budget_functions = max(0, max_queries // len(METHODS))
    connection = sqlite3.connect(database)
    connection.executescript(DDL)
    versions: dict[tuple[str, str], str | None] = {}
    counts = {"functions": len(rows), "eligible": len(eligible), "asked": 0, "queries": 0, "definitions": 0,
              "references": 0, "calls": 0, "not_located": 0, "query_gaps": 0}
    unresolved: dict[str, int] = {}
    query_gap_kinds: dict[str, int] = {}
    failed: dict[str, str] = {}
    asked = 0
    for ident, (path, line, name) in enumerate(rows, 1):
        language = files.get(path) or code_index.language_of(path)
        if path not in mapping:
            connection.execute("INSERT INTO lsp_functions VALUES (?,?,?,?,?,?,?,?,?)",
                               (ident, path, line, name, language, None, None, None, "not_ready"))
            continue
        language, key, variant = mapping[path]
        if asked >= budget_functions:
            connection.execute("INSERT INTO lsp_functions VALUES (?,?,?,?,?,?,?,?,?)",
                               (ident, path, line, name, language, key, variant, None, "budget"))
            continue
        character = _column(target, path, line, name)
        if character is None:
            counts["not_located"] += 1
            connection.execute("INSERT INTO lsp_functions VALUES (?,?,?,?,?,?,?,?,?)",
                               (ident, path, line, name, language, key, variant, None, "not_located"))
            continue
        asked += 1
        status = "ok"
        for method in METHODS:
            query = {"method": method, "path": path, "line": line, "character": character}
            if method == "references":
                query["include_declaration"] = False
            answer = broker.query(key, variant, query)
            counts["queries"] += 1
            if answer.get("server") and isinstance(answer["server"], dict):
                versions.setdefault((key, variant), answer["server"].get("version"))
            if answer.get("unresolved_includes"):
                unresolved[path] = max(unresolved.get(path, 0), int(answer["unresolved_includes"]))
            for gap in answer.get("gaps") or []:
                query_gap_kinds[gap["kind"]] = query_gap_kinds.get(gap["kind"], 0) + 1
                if gap["kind"] in ("lsp-server-failed", "lsp-not-ready", "lsp-recording-invalid", "lsp-not-recorded"):
                    failed.setdefault(f"{key}/{variant}", f"{gap['kind']}: {gap['detail']}")
            if answer.get("status") != "OK":
                status = "partial"
                counts["query_gaps"] += 1
                continue
            recording = answer.get("recording")
            for item in answer.get("results") or []:
                if method == "definition":
                    counts["definitions"] += 1
                    connection.execute("INSERT INTO lsp_definitions VALUES (?,?,?,?,?,?,?,?,?)",
                                       (ident, item["path"], item["start_line"], item.get("start_character"),
                                        item.get("end_line"), item.get("end_character"), key, variant, recording))
                elif method == "references":
                    counts["references"] += 1
                    connection.execute("INSERT INTO lsp_references VALUES (?,?,?,?,?,?,?)",
                                       (ident, item["path"], item["start_line"], item.get("start_character"), key,
                                        variant, recording))
                else:
                    counts["calls"] += 1
                    connection.execute("INSERT INTO lsp_calls VALUES (?,?,?,?,?,?,?,?,?)",
                                       (ident, "incoming" if method == "incomingCalls" else "outgoing", item["name"],
                                        item["path"], item["start_line"], _json(item.get("call_lines") or []), key,
                                        variant, recording))
        connection.execute("INSERT INTO lsp_functions VALUES (?,?,?,?,?,?,?,?,?)",
                           (ident, path, line, name, language, key, variant, character, status))
    counts["asked"] = asked
    for path, (language, key, variant) in sorted(mapping.items()):
        connection.execute("INSERT INTO lsp_files VALUES (?,?,?,?)", (path, language, key, variant))
    for server in sorted(servers, key=lambda s: (s["identity"]["server_key"], s["identity"]["variant"])):
        identity = server["identity"]
        connection.execute("INSERT INTO lsp_servers VALUES (?,?,?,?,?,?,?,?)",
                           (identity["server_key"], identity["variant"], identity["server"],
                            versions.get((identity["server_key"], identity["variant"])), identity["image_id"],
                            identity["image_digest"], identity["build_input_sha256"], server["identity_sha256"]))
        if server.get("limit"):
            gaps.append({"kind": "lsp-limit", "detail": server["limit"]})
    skipped = len(eligible) - budget_functions
    if skipped > 0:
        gaps.append({"kind": "lsp-budget-exceeded", "detail":
                     f"lsp-budget-exceeded: {len(eligible)} function(s) need {len(eligible) * len(METHODS)} queries; "
                     f"max_queries {max_queries} covers {budget_functions}; {skipped} function(s) not precomputed "
                     "(the live code_* tools may still answer them)"})
    if counts["not_located"]:
        gaps.append({"kind": "lsp-name-not-located", "detail": f"{counts['not_located']} function name(s) not found on "
                     "their indexed line; not asked"})
    if unresolved:
        gaps.append({"kind": "lsp-unresolved-includes", "detail": f"clangd reported missing includes in {len(unresolved)} "
                     f"file(s) ({sum(unresolved.values())} diagnostic(s)); cross-references there are incomplete: "
                     + ", ".join(sorted(unresolved)[:10])})
    for where, detail in sorted(failed.items()):
        gaps.append({"kind": "lsp-server-failed", "detail": f"{where}: {detail}"[:1000]})
    for kind, count in sorted(query_gap_kinds.items()):
        if kind not in ("lsp-server-failed", "lsp-not-ready"):
            gaps.append({"kind": "lsp-query-gap", "detail": f"{count} query answer(s) with {kind}"})
    unique = {_json(gap): gap for gap in gaps}
    gaps = sorted(unique.values(), key=lambda gap: (gap["kind"], gap["detail"]))
    capabilities = {"lsp": bool(servers), "definition": bool(servers), "references": bool(servers),
                    "calls": bool(servers), "hover": bool(servers)}
    connection.execute("INSERT INTO meta VALUES (?,?)", ("capabilities", _json(capabilities)))
    connection.execute("INSERT INTO meta VALUES (?,?)", ("gaps", _json(gaps)))
    connection.commit()
    content = content_sha256(connection)
    connection.close()
    return {"counts": counts, "gaps": gaps, "capabilities": capabilities, "content_sha256": content,
            "budget": {"max_queries": max_queries, "planned_queries": len(eligible) * len(METHODS),
                       "functions_covered": min(len(eligible), budget_functions)}}


# ---- the graph job ----------------------------------------------------------------------------------------

def root(run_id: str) -> Path:
    from execution_state import data_path
    return data_path(run_id, "jobs", JOB)


def native_units(run_id: str) -> tuple[list[dict[str, Any]] | None, dict[str, Any] | None, str | None]:
    """(units, binding, gap) of the accepted 02-native-build (``native_sast.load_native_build``)."""
    from execution_state import Blocked, data_path, read_json
    import native_sast
    base = data_path(run_id, "jobs", NATIVE_JOB)
    pointer = base / "accepted.json"
    if not pointer.is_file() or pointer.is_symlink():
        return None, None, "native-build-absent"
    try:
        value = read_json(pointer)
        if value.get("status") == "SKIPPED":
            return None, None, "native-build-skipped"
        loaded = native_sast.load_native_build(base, run_id=run_id, expected_fingerprint=value.get("fingerprint"))
    except (Blocked, OSError, ValueError, KeyError) as exc:
        return None, None, f"native-build-not-current: {str(exc)[:200]}"
    return loaded["units"], loaded["binding"], None


def _code() -> dict[str, str]:
    from execution_state import ROOT, file_hash
    import registry_paths
    values = {name: file_hash(ROOT / name) for name in
              ("lsp_xref_job.py", "lsp_service.py", "lsp_driver.py", "code_index.py",
               registry_paths.template_rel(JOB), registry_paths.contract_rel(CONTRACT))}
    values["schemas/" + SCHEMA_FILE] = file_hash(ROOT.parent / "schemas" / SCHEMA_FILE)
    return values


def _config() -> dict[str, Any]:
    import tunables
    return {name: tunables.value(JOB, name) for name in
            ("max_queries", "request_seconds", "start_seconds", "idle_seconds")}


def current_inputs(run_id: str) -> dict[str, Any]:
    from execution_state import Blocked, ROOT, data_path, read_json
    import container_execution as ce
    import dep_reachability_lifecycle as bindings
    import treesitter_ast_job
    import tunables
    from component_characterization import _glob_regex
    target, source, _revision = treesitter_ast_job._target(run_id)
    index, index_gap = bindings._accepted(run_id, INDEX_JOB, INDEX_RESULT, source)
    if index is None:
        raise Blocked(f"{JOB}: no accepted code index for this source generation ({index_gap})")
    attempt = data_path(run_id, "jobs", INDEX_JOB, "attempts", index["attempt_id"])
    summary = read_json(attempt / INDEX_RESULT)
    index = {"job": INDEX_JOB, **index, "sqlite_sha256": (summary.get("sqlite") or {}).get("sha256")}
    if lsp_service._file_sha(attempt / code_index.SQLITE) != index["sqlite_sha256"]:
        raise Blocked(f"{JOB}: accepted code-index database does not match its summary")
    connection = code_index.open_readonly(attempt / code_index.SQLITE)
    try:
        files = index_files(connection)
    finally:
        connection.close()
    present: dict[str, int] = {}
    for language in files.values():
        present[language] = present.get(language, 0) + 1
    census, census_gap = bindings._accepted(run_id, CENSUS_JOB, CENSUS_RESULT, source)
    wanted = census_languages(read_json(data_path(run_id, "jobs", CENSUS_JOB, "attempts", census["attempt_id"],
                                                  CENSUS_RESULT))) if census else None
    if census and wanted is None:
        census_gap, census = f"census-unreadable:{CENSUS_JOB} has no languages_needing_server list", None
    languages = {name: max(count, present.get(name, 0)) for name, count in wanted.items()} if wanted is not None \
        else {name: count for name, count in present.items() if name not in NON_PROGRAM}
    rules = read_json(ROOT.parent / "data" / "owasp-asvs" / "category-rules-v1.json")
    patterns = [_glob_regex(glob) for row in rules.get("exclusions", []) if row.get("reason") != "build_system"
                for glob in row["path_globs"]]   # vendored, test, example trees hold no project build input
    plan = lsp_service.server_plan(languages, lsp_service.build_inputs(
        target, lambda path: any(pattern.match(path) for pattern in patterns)))
    units, native, native_gap = native_units(run_id)
    ready, gaps = lsp_service.readiness(plan, target=target, native_units=units, native_gap=native_gap)
    registry = ce.load_image_registry(ce.IMAGES_DIR)
    config = _config()
    limits = {"request_seconds": config["request_seconds"], "total_seconds": config["request_seconds"] * 10}
    servers = []
    for entry in ready:
        image_id = lsp_service.SERVER_PLAN[entry["server_key"]]["image_id"]
        image = registry.get(image_id)
        if image is None:
            gaps.append({"kind": "lsp-server-failed", "server_key": entry["server_key"],
                         "detail": f"{image_id} has no current B16 record: the server cannot start"})
            continue
        servers.append(lsp_service.spec(entry, image=image, source_snapshot_sha256=source, target=target,
                                        limits=limits, container_limits=tunables.container_limits(JOB)))
    for language, count in sorted(languages.items()):
        if language not in lsp_service.LANGUAGE_SERVER:
            reason = lsp_service.WITHHELD.get(language, "no pinned language server")
            gaps.append({"kind": "lsp-no-server", "detail": f"{count} {language} file(s): {reason}"})
    return {"run_id": run_id, "job": JOB, "source_snapshot_sha256": source, "target_path": str(target),
            "census": {"job": CENSUS_JOB, **census} if census else {"job": CENSUS_JOB, "absent": census_gap,
                                                                     "languages_from": INDEX_JOB},
            "code_index": index, "languages": languages,
            "native_build": native, "native_units": [{"unit_id": u["unit_id"], "variant_id": u["build_variant"]["variant_id"],
                                                      "adapted_sha256": u["compile_database"]["adapted_sha256"]}
                                                     for u in units or []],
            "servers": servers, "readiness_gaps": [{"kind": gap["kind"], "detail": gap["detail"]} for gap in gaps],
            "config": config, "code": _code()}


def _derive(run_id: str, inputs: dict[str, Any], database: Path, *, replay_only: bool,
            broker: Any = None) -> dict[str, Any]:
    from execution_state import Blocked, data_path, read_json
    index_attempt = data_path(run_id, "jobs", INDEX_JOB, "attempts", inputs["code_index"]["attempt_id"])
    sqlite_path = index_attempt / code_index.SQLITE
    if lsp_service._file_sha(sqlite_path) != inputs["code_index"]["sqlite_sha256"]:
        raise Blocked(f"{JOB}: accepted code-index database changed after binding")
    units = None
    if inputs["native_units"]:
        units, _, gap = native_units(run_id)
        if units is None or [{"unit_id": u["unit_id"], "variant_id": u["build_variant"]["variant_id"],
                              "adapted_sha256": u["compile_database"]["adapted_sha256"]} for u in units] != inputs["native_units"]:
            raise Blocked(f"{JOB}: accepted native-build units changed after binding ({gap})")
    broker = broker or lsp_service.Broker(run_id, data_path(run_id, "lsp"), inputs["servers"], replay_only=replay_only,
                                          config={key: inputs["config"][key] for key in
                                                  ("request_seconds", "start_seconds", "idle_seconds")})
    connection = code_index.open_readonly(sqlite_path)
    try:
        summary = build(database, index=connection, target=Path(inputs["target_path"]),
                        servers=inputs["servers"], native_units=units, broker=broker,
                        max_queries=inputs["config"]["max_queries"], input_gaps=inputs["readiness_gaps"])
    finally:
        connection.close()
    return {"schema": SCHEMA, "run_id": run_id, "job_id": JOB, "source_snapshot_sha256": inputs["source_snapshot_sha256"],
            "status": "OK_WITH_GAPS" if summary["gaps"] else "OK",
            "inputs": {"census": inputs["census"], "code_index": inputs["code_index"],
                       "native_build": inputs["native_build"]},
            "servers": [{**server["identity"], "identity_sha256": server["identity_sha256"],
                         "build_input": server["build_input"], "spec": server} for server in inputs["servers"]],
            **summary, "claim_boundary": "STRUCTURAL_RETRIEVAL_NOT_FINDING_OR_RUNTIME_PROOF"}


def _receipts(run_id: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    from execution_state import digest, read_json
    import registry_paths
    template = read_json(registry_paths.template(JOB))
    common = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": inputs["source_snapshot_sha256"]}
    return ({"schema": "appsec-review/producer-permission-receipt/1.0", **common, "permissions": template["permissions"]},
            {"schema": "appsec-review/producer-lineage-receipt/1.0", **common,
             "build_lineage_sha256": "sha256:" + digest(inputs)})


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    """Rebuild from the recordings only (no live server) and compare every row."""
    from execution_state import Blocked, read_json
    from schema_validate import validate_document
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{JOB}: immutable attempt inputs changed")
    result = read_json(attempt / RESULT)
    if validate_document(result, SCHEMA_FILE):
        raise Blocked(f"{JOB}: result fails schema validation")
    database = attempt / SQLITE
    if database.is_symlink() or not database.is_file() or lsp_service._file_sha(database) != result["sqlite"]["sha256"]:
        raise Blocked(f"{JOB}: published database does not match its recorded sha256")
    scratch = Path(tempfile.mkdtemp(prefix="lsp-xref-validate-"))
    try:
        rebuilt = _derive(run_id, inputs, scratch / SQLITE, replay_only=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    if {key: value for key, value in result.items() if key != "sqlite"} != rebuilt:
        raise Blocked(f"{JOB}: cross-references no longer replay from their recordings")
    permission, lineage = _receipts(run_id, inputs)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: canonical producer receipts changed")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    from execution_state import Blocked, atomic_json, digest, now
    from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        if inputs["code"] != _code():
            raise Blocked(f"{JOB}: implementation changed before execution")
        started = time.monotonic()
        result = _derive(run_id, inputs, attempt / SQLITE, replay_only=False)
        database = attempt / SQLITE
        result = {**result, "sqlite": {"path": SQLITE, "sha256": lsp_service._file_sha(database),
                                       "bytes": database.stat().st_size}}
        atomic_json(attempt / RESULT, result)
        seconds = round(time.monotonic() - started, 3)
        counts = result["counts"]
        (attempt / SUMMARY).write_text(
            "# Language-server cross-references\n\n"
            f"- Servers: {', '.join(s['server'] + '/' + s['variant'] for s in result['servers']) or 'none ready'}.\n"
            f"- Functions {counts['functions']}, asked {counts['asked']}; definitions {counts['definitions']}, "
            f"references {counts['references']}, call edges {counts['calls']}.\n"
            f"- Gaps: {len(result['gaps'])}. Built in {seconds}s; every answer is recorded under data/lsp/.\n"
            "- Rows are locators; read the source before citing.\n", encoding="utf-8")
        status = {"process": JOB, "status": result["status"], "run_id": run_id, "dagster_run_id": dagster_id,
                  "attempt_id": allocation["attempt_id"], "functions": counts["functions"], "queries": counts["queries"],
                  "build_seconds": seconds, "network": "none", "qualification": "implemented_not_qualified",
                  "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        permission, lineage = _receipts(run_id, inputs)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="deterministic_python", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=result["status"],
            summary=f"LSP xref: {counts['asked']} of {counts['functions']} function(s) asked.", status_record=status,
            artifact_paths=[RESULT, SQLITE, SUMMARY, "status.json", "permission.json", "lineage.json"],
            gaps=sorted({gap["kind"] for gap in result["gaps"]}), consumer_job_id=CONSUMER,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="deterministic_python", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/lsp_xref_job.py {run_id}",
        derive_inputs=lambda: current_inputs(run_id), fingerprint_inputs=lambda value: "sha256:" + digest(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code()}, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        consumer_job_id=CONSUMER, blocked_summary="LSP xref preflight did not complete.",
        failed_summary="LSP xref did not publish; no older success may be used.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    from execution_state import digest, read_json
    from publish_job_output import validate_published
    base = root(run_id); inputs = current_inputs(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs), expected_run_id=run_id,
                                    expected_job_id=JOB, consumer_job_id=CONSUMER)
    _validate_attempt(run_id, attempt, inputs)
    return attempt


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument("run_id"); parser.add_argument("--dagster-id", default="manual")
    parser.add_argument("--force", action="store_true"); args = parser.parse_args()
    print(run(args.run_id, args.dagster_id, args.force))
