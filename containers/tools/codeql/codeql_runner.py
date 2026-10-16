#!/usr/bin/env python3
"""Run the pinned CodeQL CLI without exposing accepted build argv to Docker metadata."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import time


CODEQL = "/opt/codeql/codeql"
MANUAL_LANGUAGES = {"cpp", "go", "java", "csharp"}
NONE_LANGUAGES = {"javascript", "python", "ruby", "rust", "actions"}


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _safe_relative(value: str) -> Path:
    logical = PurePosixPath(value)
    if not logical.parts or logical.is_absolute() or ".." in logical.parts:
        raise ValueError("CodeQL path is invalid")
    return Path(*logical.parts)


def _working_directory(workspace: Path, value: str) -> Path:
    """Resolve a replay working directory, including the workspace root marker."""
    working = workspace if value == "." else (workspace / _safe_relative(value)).resolve(strict=True)
    if workspace != working and workspace not in working.parents:
        raise ValueError("CodeQL replay command escaped workspace")
    return working


def _run(argv: list[str], *, cwd: Path, environment: dict[str, str]) -> None:
    completed = subprocess.run(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                               check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"CodeQL child process exited {completed.returncode}")


_COMPILED = re.compile(r"^Done \[\d+/\d+ comp (?:(\d+)m)?([\d.]+)s\] (\S+?)\.?$")


def _run_compile(argv: list[str], *, cwd: Path, environment: dict[str, str]) -> dict[str, float]:
    """Run ``query compile`` echoing its progress; return per-query compile seconds it reported."""
    process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, text=True, errors="replace")
    seconds: dict[str, float] = {}
    for line in process.stderr:
        sys.stderr.write(line)
        matched = _COMPILED.match(line.strip())
        if matched:
            seconds[Path(matched.group(3)).name] = int(matched.group(1) or 0) * 60 + float(matched.group(2))
    if process.wait() != 0:
        raise RuntimeError(f"CodeQL child process exited {process.returncode}")
    return seconds


def _environment() -> dict[str, str]:
    value = dict(os.environ)
    value.update({"HOME": "/tmp/codeql-home", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"})
    Path(value["HOME"]).mkdir(parents=True, exist_ok=True)
    cache = Path("/codeql-cache")
    if cache.is_dir():
        # Persistent, content-addressed compilation cache mounted by the executor.
        link = Path(value["HOME"]) / ".codeql" / "compile-cache"
        link.parent.mkdir(parents=True, exist_ok=True)
        if not link.exists() and not link.is_symlink():
            link.symlink_to(cache)
    if value.get("ANDROID_SDK_ROOT") or value.get("ANDROID_HOME"):
        # Android's Gradle plugin needs mutable dependency and preference homes during the
        # traced replay. Keep both under the run-owned scratch mount; the derived CodeQL image
        # and its Android SDK remain immutable.
        value["GRADLE_USER_HOME"] = "/scratch/.codeql-cache/gradle"
        value["ANDROID_USER_HOME"] = "/scratch/.codeql-cache/android"
        Path(value["GRADLE_USER_HOME"]).mkdir(parents=True, exist_ok=True)
        Path(value["ANDROID_USER_HOME"]).mkdir(parents=True, exist_ok=True)
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree(root: Path) -> tuple[str, int]:
    rows = []
    files = (item for item in root.rglob("*") if item.is_file() and not item.is_symlink())
    for path in sorted(files, key=lambda item: item.as_posix()):
        # Match the reviewed lock's `find ... | sort | sha256sum` identity without trusting mtimes.
        rows.append(f"{_sha256(path)}  {path.as_posix()}\n".encode())
    return hashlib.sha256(b"".join(rows)).hexdigest(), len(rows)


def _copy_database_tree(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_dir():
        raise ValueError("CodeQL database source is invalid")
    destination.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError("CodeQL database contains an unsupported symlink")
        target = destination / path.relative_to(source)
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        else:
            raise ValueError("CodeQL database contains an unsupported entry")


def inventory(args: argparse.Namespace) -> None:
    scratch = Path("/scratch").resolve(strict=True)
    output = (scratch / _safe_relative(args.output)).resolve()
    lock_path = (scratch / _safe_relative(args.asset_lock)).resolve(strict=True)
    if scratch not in output.parents or scratch not in lock_path.parents:
        raise ValueError("CodeQL inventory output escaped scratch")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("schema") != "appsec-review/codeql-assets-lock/2":
        raise ValueError("CodeQL asset lock schema is unsupported")
    completed = subprocess.run([CODEQL, "resolve", "languages", "--format=json"],
                               env=_environment(), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode != 0:
        raise RuntimeError("CodeQL extractor inventory failed")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError("CodeQL extractor inventory is invalid")
    expected = set(lock.get("extractors", {}))
    if set(value) != expected:
        raise ValueError("CodeQL extractor inventory differs from the reviewed asset lock")
    if (_sha256(Path(CODEQL)) != lock["codeql"]["cli_sha256"] or
            _sha256(Path("/opt/codeql/LICENSE.md")) != lock["codeql"]["license_sha256"]):
        raise ValueError("CodeQL CLI or license identity differs from the reviewed asset lock")
    verified_extractors = {}
    for language, expected_identity in sorted(lock["extractors"].items()):
        digest, count = _tree(Path("/opt/codeql") / language)
        if digest != expected_identity.get("tree_sha256") or count != expected_identity.get("file_count"):
            raise ValueError(f"CodeQL {language} extractor identity differs from the reviewed asset lock")
        verified_extractors[language] = {"tree_sha256": digest, "file_count": count}
    verified_packs = {}
    for language, pack in sorted(lock.get("query_packs", {}).items()):
        root = Path("/opt/codeql/qlpacks") / Path(*PurePosixPath(pack["name"]).parts) / pack["version"]
        qlpack, pack_lock = root / "qlpack.yml", root / "codeql-pack.lock.yml"
        suite_path = root / Path(*PurePosixPath(pack["suite"]).parts)
        if (_sha256(qlpack) != pack["qlpack_sha256"] or _sha256(pack_lock) != pack["lock_sha256"] or
                _sha256(suite_path) != pack["suite_sha256"]):
            raise ValueError(f"CodeQL {language} query pack identity differs from the reviewed asset lock")
        for additional in pack.get("additional_suites", []):
            additional_path = root / Path(*PurePosixPath(additional["query_suite"]).parts)
            if (additional_path.is_symlink() or
                    _sha256(additional_path) != additional["query_suite_sha256"]):
                raise ValueError(f"CodeQL {language} additional suite differs from the reviewed asset lock")
        verified_packs[language] = {"name": pack["name"], "version": pack["version"],
                                    "suite": pack["suite"], "suite_sha256": pack["suite_sha256"],
                                    "qlpack_sha256": pack["qlpack_sha256"],
                                    "lock_sha256": pack["lock_sha256"],
                                    "additional_suites": pack.get("additional_suites", [])}
    verified_custom_packs = {}
    for language, packs in sorted(lock.get("custom_query_packs", {}).items()):
        if not isinstance(packs, list):
            raise ValueError(f"CodeQL {language} custom query lock is invalid")
        verified_custom_packs[language] = []
        for pack in packs:
            root = Path(str(pack["root"]))
            suite_path = root / Path(*PurePosixPath(pack["query_suite"]).parts)
            if (root.parent != Path("/opt/codeql/custom-queries") or not root.is_dir() or
                    root.is_symlink() or suite_path.is_symlink()):
                raise ValueError(f"CodeQL {language} custom query root is invalid")
            digest, count = _tree(root)
            if (digest != pack["tree_sha256"] or count != pack["file_count"] or
                    _sha256(root / "qlpack.yml") != pack["query_pack_sha256"] or
                    _sha256(root / "codeql-pack.lock.yml") != pack["query_lock_sha256"] or
                    _sha256(suite_path) != pack["query_suite_sha256"]):
                raise ValueError(f"CodeQL {language} custom query identity differs from the reviewed asset lock")
            verified_custom_packs[language].append(dict(pack))
    prerequisite_paths = {
        "typescript_package_sha256": Path("/opt/codeql/javascript/tools/typescript-parser-wrapper/node_modules/typescript/package.json"),
        "typescript_license_sha256": Path("/opt/codeql/javascript/tools/typescript-parser-wrapper/node_modules/typescript/LICENSE.txt"),
        "rust_indexer_sha256": Path("/opt/codeql/rust/tools/index-files.sh"),
        "rust_extractor_sha256": Path("/opt/codeql/rust/tools/linux64/extractor"),
    }
    for name, path in prerequisite_paths.items():
        if _sha256(path) != lock.get("prerequisites", {}).get(name):
            raise ValueError(f"CodeQL prerequisite identity differs from the reviewed asset lock: {name}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"schema": "appsec-review/codeql-extractor-inventory/1",
                                  "languages": sorted(value), "roots": value,
                                  "extractors": verified_extractors, "query_packs": verified_packs,
                                  "custom_query_packs": verified_custom_packs,
                                  "prerequisites": lock["prerequisites"]},
                                 sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def database(args: argparse.Namespace) -> None:
    scratch = Path("/scratch").resolve(strict=True)
    workspace = (scratch / _safe_relative(args.workspace)).resolve(strict=True)
    source_root = workspace if args.source_subroot == "." else (
        workspace / _safe_relative(args.source_subroot)).resolve(strict=True)
    database_path = (scratch / _safe_relative(args.database)).resolve()
    if (scratch not in workspace.parents or scratch not in database_path.parents or
            source_root != workspace and workspace not in source_root.parents or not source_root.is_dir()):
        raise ValueError("CodeQL database path escaped scratch")
    environment = _environment()
    summaries: list[dict[str, object]] = []
    if args.mode == "none":
        if args.language not in NONE_LANGUAGES or args.replay is not None:
            raise ValueError("CodeQL source/no-build invocation is invalid")
        _run([CODEQL, "database", "create", str(database_path), "--source-root", str(source_root),
              "--language", args.language, "--build-mode", "none", "--threads", str(args.threads),
              "--ram", str(args.ram), "--overwrite"], cwd=workspace, environment=environment)
    else:
        if args.language not in MANUAL_LANGUAGES or args.replay is None:
            raise ValueError("CodeQL manual invocation is invalid")
        replay_path = (scratch / _safe_relative(args.replay)).resolve(strict=True)
        if scratch not in replay_path.parents:
            raise ValueError("CodeQL replay path escaped scratch")
        document = json.loads(replay_path.read_text(encoding="utf-8"))
        commands = document.get("commands")
        if document.get("schema") != "appsec-review/codeql-build-replay/1" or not isinstance(commands, list) or not commands:
            raise ValueError("CodeQL replay requires accepted build commands")
        _run([CODEQL, "database", "init", "--source-root", str(source_root), "--language", args.language,
              "--build-mode", "manual", str(database_path)], cwd=workspace, environment=environment)
        for ordinal, command in enumerate(commands, 1):
            if not isinstance(command, dict) or command.get("ordinal") != ordinal:
                raise ValueError("CodeQL replay command order is invalid")
            argv, command_environment = command.get("argv"), command.get("environment")
            if (not isinstance(argv, list) or not argv or len(argv) > 2048 or
                    any(not isinstance(value, str) or "\0" in value for value in argv) or
                    not isinstance(command_environment, dict) or
                    any(not isinstance(key, str) or not isinstance(value, str)
                        for key, value in command_environment.items())):
                raise ValueError("CodeQL replay command is invalid")
            digest = hashlib.sha256(_canonical(argv)).hexdigest()
            if digest != command.get("argv_sha256"):
                raise ValueError("CodeQL replay command identity changed")
            working = _working_directory(workspace, str(command.get("working_directory", "")))
            child_environment = dict(environment)
            child_environment.update(command_environment)
            _run([CODEQL, "database", "trace-command", "--threads", str(args.threads),
                  "--ram", str(args.ram), str(database_path), "--", *argv],
                 cwd=working, environment=child_environment)
            summaries.append({"ordinal": ordinal, "argv_sha256": digest,
                              "working_directory": command["working_directory"]})
        _run([CODEQL, "database", "finalize", "--threads", str(args.threads), "--ram", str(args.ram),
              str(database_path)], cwd=workspace, environment=environment)
    if args.staged_database:
        export = scratch / "database-export"
        if export.exists() or export.is_symlink():
            raise ValueError("CodeQL database export already exists")
        _copy_database_tree(database_path, export)
    (scratch / "database-summary.json").write_text(json.dumps({
        "schema": "appsec-review/codeql-database-summary/2", "language": args.language,
        "mode": args.mode, "command_count": len(summaries), "commands": summaries,
        "database": args.database, "workspace": args.workspace, "source_root": args.source_subroot,
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def query(args: argparse.Namespace) -> None:
    scratch = Path("/scratch").resolve(strict=True)
    database_path = (scratch / _safe_relative(args.database)).resolve(strict=True)
    output_path = (scratch / _safe_relative(args.output)).resolve()
    if scratch not in database_path.parents or scratch not in output_path.parents:
        raise ValueError("CodeQL query path escaped scratch")
    if args.staged_database:
        source_root = Path("/source").resolve(strict=True)
        source = (source_root / _safe_relative(args.database)).resolve(strict=True)
        if source_root not in source.parents or not source.is_dir() or source.is_symlink() or any(
                path.is_symlink() for path in source.rglob("*")):
            raise ValueError("CodeQL staged query database is invalid")
        _copy_database_tree(source, database_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if args.suite_path is not None:
        custom_root = Path("/opt/codeql/custom-queries").resolve(strict=True)
        suite_path = Path(args.suite_path).resolve(strict=True)
        if (custom_root not in suite_path.parents or suite_path.is_symlink() or
                not suite_path.is_file() or suite_path.suffix != ".qls" or
                any(value is not None for value in (args.pack, args.pack_version, args.suite))):
            raise ValueError("CodeQL custom query suite path is invalid")
        suite = str(suite_path)
    else:
        if not all((args.pack, args.pack_version, args.suite)):
            raise ValueError("CodeQL default query pack selection is incomplete")
        suite = f"{args.pack}@{args.pack_version}:{args.suite}"
    _run([CODEQL, "database", "analyze", str(database_path), suite,
          "--format", "sarifv2.1.0", "--output", str(output_path), "--no-download",
          "--threads", str(args.threads), "--ram", str(args.ram), "--max-paths", str(args.max_paths),
          "--sarif-include-query-help", "never", "--no-sarif-add-file-contents",
          "--no-sarif-add-snippets"], cwd=scratch, environment=_environment())


EXPORT_SCHEMA = "appsec-review/codeql-graph-export/1"
EXPORT_MANIFEST_SCHEMA = "appsec-review/codeql-graph-export-manifest/1"
EXPORT_COLUMNS_SCHEMA = "appsec-review/codeql-graph-export-columns/1"
_COLUMN_TYPES = {"string": str, "int": int}


def _capture(argv: list[str], *, cwd: Path, environment: dict[str, str]) -> bytes:
    completed = subprocess.run(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"CodeQL child process exited {completed.returncode}")
    return completed.stdout


def _relative_tree(root: Path) -> tuple[str, int]:
    """Location-independent tree identity of a repository-owned pack staged into scratch."""
    rows = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValueError("CodeQL export pack contains a symlink")
        if path.is_file():
            rows.append(f"{_sha256(path)}  {path.relative_to(root).as_posix()}\n".encode())
    return hashlib.sha256(b"".join(rows)).hexdigest(), len(rows)


def _scratch_path(scratch: Path, value: str, *, strict: bool) -> Path:
    path = (scratch / _safe_relative(value)).resolve(strict=strict)
    if scratch not in path.parents:
        raise ValueError("CodeQL export path escaped scratch")
    return path


def export_queries(columns: dict, language: str) -> list[dict]:
    """The ordered export queries of ``language`` from the C1 columns contract."""
    if columns.get("schema") != EXPORT_COLUMNS_SCHEMA or columns.get("export_schema") != EXPORT_SCHEMA:
        raise ValueError("CodeQL export columns contract is unsupported")
    queries = columns["languages"][language]["queries"]
    if not isinstance(queries, list) or not queries:
        raise ValueError("CodeQL export columns contract has no queries")
    seen = set()
    for item in queries:
        names = [column["name"] for column in item["columns"]]
        if (item["query_id"] in seen or item["result_set"] != item["query_id"] or not names or
                len(set(names)) != len(names) or
                any(column["type"] not in _COLUMN_TYPES for column in item["columns"])):
            raise ValueError("CodeQL export columns contract is invalid")
        seen.add(item["query_id"])
    return queries


def decoded_tuples(decoded: dict, result_set: str) -> list:
    """Rows of one result set from ``codeql bqrs decode --format=json`` output."""
    value = decoded.get(result_set, decoded)
    tuples = value.get("tuples") if isinstance(value, dict) else None
    if not isinstance(tuples, list):
        raise ValueError(f"CodeQL decoded result set {result_set} is invalid")
    return tuples


def export_document(query: dict, tuples: list, *, total_rows: int, row_limit: int,
                    bqrs_sha256: str) -> dict:
    """Build one appsec-review/codeql-graph-export/1 object from decoded BQRS tuples.

    Every cell must be a primitive of its declared column type: an entity cell (a JSON object
    carrying a CodeQL element id) or a list is rejected, so no internal id leaves the database.
    Rows are sorted by their string tuple; ``truncated`` is set when CodeQL reported more rows
    than the bound allowed to be decoded.
    """
    columns = query["columns"]
    if len(tuples) > row_limit or total_rows < len(tuples):
        raise ValueError(f"CodeQL export {query['query_id']} decoded more rows than its bound")
    rows = []
    for row in tuples:
        if not isinstance(row, list) or len(row) != len(columns):
            raise ValueError(f"CodeQL export {query['query_id']} row does not match its columns")
        for cell, column in zip(row, columns):
            expected = _COLUMN_TYPES[column["type"]]
            if isinstance(cell, bool) or not isinstance(cell, expected):
                raise ValueError(f"CodeQL export {query['query_id']} column {column['name']} is not "
                                 f"a primitive {column['type']}")
        rows.append(list(row))
    rows.sort(key=lambda row: tuple(str(value) for value in row))
    return {"schema": EXPORT_SCHEMA, "query_id": query["query_id"],
            "columns": [column["name"] for column in columns], "rows": rows,
            "row_count": total_rows, "truncated": total_rows > len(rows),
            "bqrs_sha256": bqrs_sha256}


EXPORT_SCOPE_MODES = ("whole_program", "seeded")


def _read_export_scope(scope_path: Path, seeds_path: Path) -> dict:
    """Validate the two CSV inputs bound to the pack's external predicates; return the scope record.

    ``scope.csv`` is one row ``<mode>,<depth>`` and ``seeds.csv`` has header-less rows
    ``<path>,<start_line>,<end_line>`` (empty in ``whole_program`` mode).
    """
    with scope_path.open(newline="", encoding="utf-8") as stream:
        scope_rows = [row for row in csv.reader(stream) if row]
    if len(scope_rows) != 1 or len(scope_rows[0]) != 2:
        raise ValueError("CodeQL export scope file must hold exactly one <mode>,<depth> row")
    mode, depth_text = scope_rows[0]
    if mode not in EXPORT_SCOPE_MODES or not depth_text.isascii() or not depth_text.isdigit():
        raise ValueError("CodeQL export scope file has an unsupported mode or depth")
    with seeds_path.open(newline="", encoding="utf-8") as stream:
        seed_rows = [row for row in csv.reader(stream) if row]
    seeds = set()
    for row in seed_rows:
        if (len(row) != 3 or not row[0] or any(not value.isascii() or not value.isdigit() for value in row[1:])
                or not 1 <= int(row[1]) <= int(row[2])):
            raise ValueError("CodeQL export seeds file rows must be <path>,<start_line>,<end_line>")
        seeds.add((row[0], int(row[1]), int(row[2])))
    if mode == "whole_program" and seeds:
        raise ValueError("CodeQL export seeds file must be empty in whole_program mode")
    return {"mode": mode, "depth": int(depth_text), "seed_count": len(seeds)}


def _verify_export_pack(entry: dict, pack: Path, columns_path: Path) -> None:
    digest, count = _relative_tree(pack)
    suite = pack / _safe_relative(entry["query_suite"])
    if (digest != entry["tree_sha256"] or count != entry["file_count"] or
            _sha256(pack / "qlpack.yml") != entry["query_pack_sha256"] or
            suite.is_symlink() or _sha256(suite) != entry["query_suite_sha256"] or
            _sha256(columns_path) != entry["columns_sha256"]):
        raise ValueError("CodeQL export pack identity differs from the reviewed asset lock")


def _compile_pack(pack: Path, query_files: list[str], *, threads: int, ram: int, scratch: Path,
                  environment: dict[str, str]) -> tuple[dict[str, float], int]:
    """Compile every export query in one invocation; return per-query seconds and elapsed ms.

    CodeQL's compilation cache is content addressed under HOME, so a persistent cache mount turns a
    repeat into a hit. One invocation lets CodeQL compile independent queries in parallel with
    ``--threads``; the scope and the seeds are bound at evaluation time, so the compiled queries
    (and the cache) are identical for every scope.
    """
    started = time.monotonic()
    seconds = _run_compile(
        [CODEQL, "query", "compile", "--threads", str(threads), "--ram", str(ram), "--",
         *(str(pack / _safe_relative(file)) for file in query_files)],
        cwd=scratch, environment=environment)
    return seconds, int((time.monotonic() - started) * 1000)


def compile_export(args: argparse.Namespace, scratch: Path | None = None) -> None:
    """Warm the compilation cache for the hash-pinned export pack without touching a database."""
    scratch = (scratch or Path("/scratch")).resolve(strict=True)
    pack = _scratch_path(scratch, args.pack, strict=True)
    columns_path = _scratch_path(scratch, args.columns, strict=True)
    lock_path = _scratch_path(scratch, args.asset_lock, strict=True)
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("schema") != "appsec-review/codeql-assets-lock/2":
        raise ValueError("CodeQL asset lock schema is unsupported")
    entry = lock.get("export_query_packs", {}).get(args.language)
    if not isinstance(entry, dict):
        raise ValueError(f"CodeQL asset lock has no {args.language} export pack")
    _verify_export_pack(entry, pack, columns_path)
    queries = export_queries(json.loads(columns_path.read_text(encoding="utf-8")), args.language)
    query_files = list(dict.fromkeys(query["query_file"] for query in queries))
    seconds, elapsed = _compile_pack(pack, query_files, threads=args.threads, ram=args.ram,
                                     scratch=scratch, environment=_environment())
    sys.stdout.write(json.dumps({"schema": "appsec-review/codeql-compile/1", "language": args.language,
                                 "query_count": len(query_files), "compile_ms": elapsed,
                                 "compile_s": seconds}, sort_keys=True) + "\n")


def export(args: argparse.Namespace, scratch: Path | None = None) -> None:
    """Run the hash-pinned graph export pack and decode each result set with a row bound.

    The pack and its columns contract are staged into scratch by the job and verified here
    against the asset lock. ``run-queries`` writes BQRS into the (disposable) database copy;
    each export is ``bqrs info`` for the true row count, then ``bqrs decode --rows <bound>``.
    """
    scratch = (scratch or Path("/scratch")).resolve(strict=True)
    database_path = _scratch_path(scratch, args.database, strict=True)
    pack = _scratch_path(scratch, args.pack, strict=True)
    columns_path = _scratch_path(scratch, args.columns, strict=True)
    lock_path = _scratch_path(scratch, args.asset_lock, strict=True)
    output = _scratch_path(scratch, args.output_dir, strict=False)
    scope_path = _scratch_path(scratch, args.scope_file, strict=True)
    seeds_path = _scratch_path(scratch, args.seeds_file, strict=True)
    if args.row_limit < 1 or args.max_bytes < 1:
        raise ValueError("CodeQL export bounds must be positive")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("schema") != "appsec-review/codeql-assets-lock/2":
        raise ValueError("CodeQL asset lock schema is unsupported")
    entry = lock.get("export_query_packs", {}).get(args.language)
    if not isinstance(entry, dict):
        raise ValueError(f"CodeQL asset lock has no {args.language} export pack")
    _verify_export_pack(entry, pack, columns_path)
    scope = _read_export_scope(scope_path, seeds_path)
    queries = export_queries(json.loads(columns_path.read_text(encoding="utf-8")), args.language)
    if output.exists() and any(output.iterdir()):
        raise ValueError("CodeQL export output directory is not empty")
    output.mkdir(parents=True, exist_ok=True)
    environment = _environment()
    # Compile every export query in one invocation first (CodeQL's compilation cache is content
    # addressed under HOME, so a persistent cache mount makes this a no-op on later runs), then
    # evaluate them serially so each query's evaluation time is attributable and bounded alone.
    query_files = list(dict.fromkeys(query["query_file"] for query in queries))
    compile_seconds, compile_ms = _compile_pack(pack, query_files, threads=args.threads, ram=args.ram,
                                                 scratch=scratch, environment=environment)
    evaluate_ms: dict[str, int] = {}
    # The scope and the seeds are bound to the pack's external predicates at evaluation time, so
    # the compiled queries (and the compile cache) are identical for every scope.
    external = [f"--external=exportScope={scope_path}", f"--external=exportSeed={seeds_path}"]
    for file in query_files:
        started = time.monotonic()
        _run([CODEQL, "database", "run-queries", "--threads", str(args.threads), "--ram", str(args.ram),
              *external, "--", str(database_path), str(pack / _safe_relative(file))],
             cwd=scratch, environment=environment)
        evaluate_ms[file] = int((time.monotonic() - started) * 1000)
    results = database_path / "results" / Path(*PurePosixPath(entry["query_pack"]).parts)
    written, rows_manifest = 0, []
    for query in queries:
        bqrs = results / _safe_relative(query["query_file"]).with_suffix(".bqrs")
        if not bqrs.is_file() or bqrs.is_symlink():
            raise ValueError(f"CodeQL export result for {query['query_file']} is missing")
        info = json.loads(_capture([CODEQL, "bqrs", "info", "--format=json", "--", str(bqrs)],
                                   cwd=scratch, environment=environment))
        sets = [item for item in info.get("result-sets", ()) if item.get("name") == query["result_set"]]
        if len(sets) != 1 or len(sets[0].get("columns", ())) != len(query["columns"]):
            raise ValueError(f"CodeQL export result set {query['result_set']} differs from its contract")
        total = sets[0].get("rows")
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise ValueError(f"CodeQL export result set {query['result_set']} row count is invalid")
        decoded_path = output / f".{query['query_id']}.decoded.json"
        started = time.monotonic()
        _run([CODEQL, "bqrs", "decode", "--format=json", "--result-set", query["result_set"],
              "--rows", str(args.row_limit), "--output", str(decoded_path), "--", str(bqrs)],
             cwd=scratch, environment=environment)
        if decoded_path.stat().st_size > args.max_bytes - written:
            raise ValueError("CodeQL export exceeded its configured byte bound")
        decoded = json.loads(decoded_path.read_text(encoding="utf-8"))
        decoded_path.unlink()
        document = export_document(query, decoded_tuples(decoded, query["result_set"]),
                                   total_rows=total, row_limit=args.row_limit,
                                   bqrs_sha256=_sha256(bqrs))
        decode_ms = max(0, int((time.monotonic() - started) * 1000))
        data = _canonical(document)
        written += len(data)
        if written > args.max_bytes:
            raise ValueError("CodeQL export exceeded its configured byte bound")
        target = output / f"{query['query_id']}.json"
        target.write_bytes(data)
        rows_manifest.append({"query_id": query["query_id"], "query_file": query["query_file"],
                              "path": target.name, "sha256": hashlib.sha256(data).hexdigest(),
                              "bytes": len(data), "row_count": total,
                              "exported_rows": len(document["rows"]),
                              "truncated": document["truncated"],
                              "bqrs_sha256": document["bqrs_sha256"], "decode_ms": decode_ms,
                              "evaluate_ms": evaluate_ms[query["query_file"]],
                              "compile_s": compile_seconds.get(Path(query["query_file"]).name)})
    (output / "export-manifest.json").write_bytes(_canonical({
        "schema": EXPORT_MANIFEST_SCHEMA, "export_schema": EXPORT_SCHEMA, "language": args.language,
        "pack": {key: entry[key] for key in ("query_id", "query_pack", "query_pack_version",
                                              "tree_sha256", "file_count", "columns_sha256")},
        "row_limit": args.row_limit, "max_bytes": args.max_bytes, "compile_ms": compile_ms,
        "scope": scope,
        "exports": sorted(rows_manifest, key=lambda item: item["query_id"]),
    }))


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    sub = value.add_subparsers(dest="action", required=True)
    inventory_parser = sub.add_parser("inventory")
    inventory_parser.add_argument("--output", required=True)
    inventory_parser.add_argument("--asset-lock", required=True)
    database_parser = sub.add_parser("database")
    database_parser.add_argument("--staged-database", action="store_true")
    database_parser.add_argument("--mode", choices=("manual", "none"), required=True)
    database_parser.add_argument("--language", required=True)
    database_parser.add_argument("--replay")
    database_parser.add_argument("--workspace", required=True)
    database_parser.add_argument("--source-subroot", required=True)
    database_parser.add_argument("--database", required=True)
    database_parser.add_argument("--threads", type=int, required=True)
    database_parser.add_argument("--ram", type=int, required=True)
    query_parser = sub.add_parser("query")
    query_parser.add_argument("--staged-database", action="store_true")
    query_parser.add_argument("--database", required=True)
    query_parser.add_argument("--output", required=True)
    query_parser.add_argument("--pack")
    query_parser.add_argument("--pack-version")
    query_parser.add_argument("--suite")
    query_parser.add_argument("--suite-path")
    query_parser.add_argument("--threads", type=int, required=True)
    query_parser.add_argument("--ram", type=int, required=True)
    query_parser.add_argument("--max-paths", type=int, required=True)
    compile_parser = sub.add_parser("compile")
    compile_parser.add_argument("--pack", required=True)
    compile_parser.add_argument("--columns", required=True)
    compile_parser.add_argument("--asset-lock", required=True)
    compile_parser.add_argument("--language", choices=("cpp",), required=True)
    compile_parser.add_argument("--threads", type=int, required=True)
    compile_parser.add_argument("--ram", type=int, required=True)
    export_parser = sub.add_parser("export")
    export_parser.add_argument("--database", required=True)
    export_parser.add_argument("--pack", required=True)
    export_parser.add_argument("--columns", required=True)
    export_parser.add_argument("--asset-lock", required=True)
    export_parser.add_argument("--language", choices=("cpp",), required=True)
    export_parser.add_argument("--output-dir", required=True)
    export_parser.add_argument("--scope-file", required=True)
    export_parser.add_argument("--seeds-file", required=True)
    export_parser.add_argument("--row-limit", type=int, required=True)
    export_parser.add_argument("--max-bytes", type=int, required=True)
    export_parser.add_argument("--threads", type=int, required=True)
    export_parser.add_argument("--ram", type=int, required=True)
    return value


def _make_host_accessible() -> None:
    """Expose and make disposable non-root CodeQL outputs removable by the run owner."""
    scratch = Path("/scratch")
    for path in (scratch, *scratch.rglob("*")):
        if path.is_symlink():
            continue
        try:
            mode = path.stat().st_mode
            path.chmod(mode | (0o007 if path.is_dir() else 0o004))
        except (FileNotFoundError, PermissionError):
            # Host-owned inputs need no ownership change; concurrent tool cleanup can remove
            # transient files while the final permission pass walks the completed tree.
            continue


if __name__ == "__main__":
    exit_code = 0
    try:
        parsed = parser().parse_args()
        {"inventory": inventory, "database": database, "query": query,
         "export": export, "compile": compile_export}[parsed.action](parsed)
    except Exception as exc:
        print(f"codeql-runner: {type(exc).__name__}: {exc}", file=sys.stderr)
        exit_code = 2
    finally:
        _make_host_accessible()
    raise SystemExit(exit_code)
