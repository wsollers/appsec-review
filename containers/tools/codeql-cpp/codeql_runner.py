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


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _safe_relative(value: str) -> Path:
    logical = PurePosixPath(value)
    if not logical.parts or logical.is_absolute() or ".." in logical.parts:
        raise ValueError("CodeQL replay working directory is invalid")
    return Path(*logical.parts)


def _run(argv: list[str], *, cwd: Path, environment: dict[str, str]) -> None:
    completed = subprocess.run(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                               check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"CodeQL child process exited {completed.returncode}")


def database(args: argparse.Namespace) -> None:
    scratch = Path("/scratch").resolve(strict=True)
    replay_path = (scratch / _safe_relative(args.replay)).resolve(strict=True)
    workspace = (scratch / _safe_relative(args.workspace)).resolve(strict=True)
    database_path = (scratch / _safe_relative(args.database)).resolve()
    if scratch not in replay_path.parents or scratch not in workspace.parents or scratch not in database_path.parents:
        raise ValueError("CodeQL path escaped scratch")
    document = json.loads(replay_path.read_text(encoding="utf-8"))
    if document.get("schema") != "appsec-review/codeql-build-replay/1":
        raise ValueError("CodeQL replay schema is unsupported")
    commands = document.get("commands")
    if not isinstance(commands, list) or not commands:
        raise ValueError("CodeQL replay requires accepted build commands")
    env = dict(os.environ)
    env.update({"HOME": "/tmp/codeql-home", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"})
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    _run([CODEQL, "database", "init", "--source-root", str(workspace), "--language", "cpp",
          "--build-mode", "manual", str(database_path)], cwd=workspace, environment=env)
    summaries = []
    for ordinal, command in enumerate(commands, 1):
        if not isinstance(command, dict) or command.get("ordinal") != ordinal:
            raise ValueError("CodeQL replay command order is invalid")
        argv = command.get("argv")
        environment = command.get("environment")
        if (not isinstance(argv, list) or not argv or len(argv) > 2048 or
                any(not isinstance(value, str) or "\0" in value for value in argv) or
                not isinstance(environment, dict) or any(not isinstance(key, str) or not isinstance(value, str)
                                                         for key, value in environment.items())):
            raise ValueError("CodeQL replay command is invalid")
        digest = hashlib.sha256(_canonical(argv)).hexdigest()
        if digest != command.get("argv_sha256"):
            raise ValueError("CodeQL replay command identity changed")
        working = (workspace / _safe_relative(str(command.get("working_directory", "")))).resolve(strict=True)
        if workspace != working and workspace not in working.parents:
            raise ValueError("CodeQL replay command escaped workspace")
        command_env = dict(env)
        command_env.update(environment)
        _run([CODEQL, "database", "trace-command", "--threads", str(args.threads),
              "--ram", str(args.ram), "--working-dir", str(working),
              str(database_path), "--", *argv],
             cwd=working, environment=command_env)
        summaries.append({"ordinal": ordinal, "argv_sha256": digest,
                          "working_directory": command["working_directory"]})
    _run([CODEQL, "database", "finalize", "--threads", str(args.threads),
          "--ram", str(args.ram), str(database_path)], cwd=workspace, environment=env)
    summary_path = scratch / "database-summary.json"
    summary_path.write_text(json.dumps({
        "schema": "appsec-review/codeql-database-summary/1",
        "command_count": len(summaries), "commands": summaries,
        "database": args.database, "source_root": args.workspace,
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def query(args: argparse.Namespace) -> None:
    scratch = Path("/scratch").resolve(strict=True)
    database_path = (scratch / _safe_relative(args.database)).resolve(strict=True)
    output_path = (scratch / _safe_relative(args.output)).resolve()
    if scratch not in database_path.parents or scratch not in output_path.parents:
        raise ValueError("CodeQL query path escaped scratch")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update({"HOME": "/tmp/codeql-home", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"})
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    suite = f"{args.pack}@{args.pack_version}:{args.suite}"
    _run([CODEQL, "database", "analyze", str(database_path), suite,
          "--format", "sarifv2.1.0", "--output", str(output_path), "--no-download",
          "--threads", str(args.threads), "--ram", str(args.ram),
          "--max-paths", str(args.max_paths), "--sarif-include-query-help", "never",
          "--no-sarif-add-file-contents", "--no-sarif-add-snippets"],
         cwd=scratch, environment=env)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    sub = value.add_subparsers(dest="action", required=True)
    database_parser = sub.add_parser("database")
    database_parser.add_argument("--replay", required=True)
    database_parser.add_argument("--workspace", required=True)
    database_parser.add_argument("--database", required=True)
    database_parser.add_argument("--threads", type=int, required=True)
    database_parser.add_argument("--ram", type=int, required=True)
    query_parser = sub.add_parser("query")
    query_parser.add_argument("--database", required=True)
    query_parser.add_argument("--output", required=True)
    query_parser.add_argument("--pack", required=True)
    query_parser.add_argument("--pack-version", required=True)
    query_parser.add_argument("--suite", required=True)
    query_parser.add_argument("--threads", type=int, required=True)
    query_parser.add_argument("--ram", type=int, required=True)
    query_parser.add_argument("--max-paths", type=int, required=True)
    return value


if __name__ == "__main__":
    try:
        parsed = parser().parse_args()
        database(parsed) if parsed.action == "database" else query(parsed)
    except Exception as exc:
        print(f"codeql-runner: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2)
