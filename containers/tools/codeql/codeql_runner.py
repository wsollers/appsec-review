#!/usr/bin/env python3
"""Run the pinned CodeQL CLI without exposing accepted build argv to Docker metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys


CODEQL = "/opt/codeql/codeql"
MANUAL_LANGUAGES = {"cpp", "go", "java", "csharp"}
NONE_LANGUAGES = {"javascript", "python", "rust", "actions"}


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _safe_relative(value: str) -> Path:
    logical = PurePosixPath(value)
    if not logical.parts or logical.is_absolute() or ".." in logical.parts:
        raise ValueError("CodeQL path is invalid")
    return Path(*logical.parts)


def _run(argv: list[str], *, cwd: Path, environment: dict[str, str]) -> None:
    completed = subprocess.run(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                               check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"CodeQL child process exited {completed.returncode}")


def _environment() -> dict[str, str]:
    value = dict(os.environ)
    value.update({"HOME": "/tmp/codeql-home", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"})
    Path(value["HOME"]).mkdir(parents=True, exist_ok=True)
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
        verified_packs[language] = {"name": pack["name"], "version": pack["version"],
                                    "suite": pack["suite"], "suite_sha256": pack["suite_sha256"],
                                    "qlpack_sha256": pack["qlpack_sha256"],
                                    "lock_sha256": pack["lock_sha256"]}
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
            working = (workspace / _safe_relative(str(command.get("working_directory", "")))).resolve(strict=True)
            if workspace != working and workspace not in working.parents:
                raise ValueError("CodeQL replay command escaped workspace")
            child_environment = dict(environment)
            child_environment.update(command_environment)
            _run([CODEQL, "database", "trace-command", "--threads", str(args.threads),
                  "--ram", str(args.ram), str(database_path), "--", *argv],
                 cwd=working, environment=child_environment)
            summaries.append({"ordinal": ordinal, "argv_sha256": digest,
                              "working_directory": command["working_directory"]})
        _run([CODEQL, "database", "finalize", "--threads", str(args.threads), "--ram", str(args.ram),
              str(database_path)], cwd=workspace, environment=environment)
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


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    sub = value.add_subparsers(dest="action", required=True)
    inventory_parser = sub.add_parser("inventory")
    inventory_parser.add_argument("--output", required=True)
    inventory_parser.add_argument("--asset-lock", required=True)
    database_parser = sub.add_parser("database")
    database_parser.add_argument("--mode", choices=("manual", "none"), required=True)
    database_parser.add_argument("--language", required=True)
    database_parser.add_argument("--replay")
    database_parser.add_argument("--workspace", required=True)
    database_parser.add_argument("--source-subroot", required=True)
    database_parser.add_argument("--database", required=True)
    database_parser.add_argument("--threads", type=int, required=True)
    database_parser.add_argument("--ram", type=int, required=True)
    query_parser = sub.add_parser("query")
    query_parser.add_argument("--database", required=True)
    query_parser.add_argument("--output", required=True)
    query_parser.add_argument("--pack")
    query_parser.add_argument("--pack-version")
    query_parser.add_argument("--suite")
    query_parser.add_argument("--suite-path")
    query_parser.add_argument("--threads", type=int, required=True)
    query_parser.add_argument("--ram", type=int, required=True)
    query_parser.add_argument("--max-paths", type=int, required=True)
    return value


if __name__ == "__main__":
    try:
        parsed = parser().parse_args()
        {"inventory": inventory, "database": database, "query": query}[parsed.action](parsed)
    except Exception as exc:
        print(f"codeql-runner: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2)
