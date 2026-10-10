#!/usr/bin/env python3
"""Bounded read-only SQLite utility for controlled container execution."""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
from pathlib import Path
import sqlite3
import sys
import time
from typing import Any, Mapping, Sequence


VERSION = "1.0.0"
DEFAULT_ROOT = "/target"
MAX_ROWS = 1_000
MAX_CELL_BYTES = 65_536
MAX_SECONDS = 30.0
MAX_VM_STEPS = 5_000_000


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="sqlite-tool")
    commands = value.add_subparsers(dest="command", required=True)
    commands.add_parser("version")
    for name in ("inspect", "integrity"):
        command = commands.add_parser(name)
        command.add_argument("database")
        command.add_argument("--timeout-seconds", type=float, default=5.0)
    query = commands.add_parser("query")
    query.add_argument("database")
    query.add_argument("--sql", required=True)
    query.add_argument("--parameters", default="[]",
                       help="JSON array for positional parameters or object for named parameters")
    query.add_argument("--limit", type=int, default=100)
    query.add_argument("--max-cell-bytes", type=int, default=MAX_CELL_BYTES)
    query.add_argument("--timeout-seconds", type=float, default=5.0)
    return value


def allowed_root() -> Path:
    return Path(os.environ.get("APPSEC_SQLITE_ROOT", DEFAULT_ROOT)).resolve(strict=True)


def resolve_database(value: str, root: Path) -> Path:
    candidate = Path(value).resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"database path is outside {root}") from exc
    if not candidate.is_file():
        raise ValueError("database path is not a regular file")
    return candidate


def connect(database: Path, timeout_seconds: float) -> sqlite3.Connection:
    if not 0 < timeout_seconds <= MAX_SECONDS:
        raise ValueError(f"timeout-seconds must be greater than zero and at most {MAX_SECONDS:g}")
    uri = database.as_uri() + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True, timeout=0.1)
    connection.row_factory = sqlite3.Row
    connection.enable_load_extension(False)
    connection.execute("PRAGMA query_only=ON")
    deadline = time.monotonic() + timeout_seconds
    calls = 0

    def progress() -> int:
        nonlocal calls
        calls += 1
        return int(calls * 1_000 > MAX_VM_STEPS or time.monotonic() > deadline)

    connection.set_progress_handler(progress, 1_000)
    return connection


def readonly_authorizer() -> Any:
    allowed = {
        sqlite3.SQLITE_FUNCTION,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_RECURSIVE,
        sqlite3.SQLITE_SELECT,
    }

    def authorize(action: int, _one: str | None, _two: str | None,
                  _database: str | None, _trigger: str | None) -> int:
        # FTS5 consults this read-only pragma while constructing a virtual table.
        if action == sqlite3.SQLITE_PRAGMA and _one == "data_version":
            return sqlite3.SQLITE_OK
        # SQLite 3.40 reports ephemeral virtual-table schema construction as updates to
        # sqlite_master. query_only, immutable mode, and the denied writable_schema pragma
        # still prevent these authorizer events from becoming persistent writes.
        if action == sqlite3.SQLITE_UPDATE and _one == "sqlite_master":
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY

    return authorize


def bounded_value(value: Any, maximum: int) -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, bytes):
        clipped = value[:maximum]
        return {"base64": base64.b64encode(clipped).decode("ascii"),
                "bytes": len(value), "truncated": len(value) > maximum}
    text = str(value)
    encoded = text.encode("utf-8")
    if len(encoded) <= maximum:
        return text
    clipped = encoded[:maximum].decode("utf-8", errors="ignore")
    return {"text": clipped, "bytes": len(encoded), "truncated": True}


def inspect_database(connection: sqlite3.Connection, database: Path) -> Mapping[str, Any]:
    objects = [dict(row) for row in connection.execute(
        "SELECT type, name, tbl_name FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name LIMIT 1001"
    )]
    truncated = len(objects) > 1_000
    objects = objects[:1_000]
    options = {str(row[0]) for row in connection.execute("PRAGMA compile_options")}
    return {
        "schema": "appsec-review/sqlite-inspection/1",
        "database": database.name,
        "bytes": database.stat().st_size,
        "sqlite_version": sqlite3.sqlite_version,
        "fts5": "ENABLE_FTS5" in options,
        "application_id": connection.execute("PRAGMA application_id").fetchone()[0],
        "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
        "page_count": connection.execute("PRAGMA page_count").fetchone()[0],
        "page_size": connection.execute("PRAGMA page_size").fetchone()[0],
        "objects": objects,
        "truncated": truncated,
    }


def integrity(connection: sqlite3.Connection, database: Path) -> Mapping[str, Any]:
    rows = [str(row[0]) for row in connection.execute("PRAGMA integrity_check(100)")]
    return {
        "schema": "appsec-review/sqlite-integrity/1",
        "database": database.name,
        "ok": rows == ["ok"],
        "results": rows,
    }


def parameters(value: str) -> Sequence[Any] | Mapping[str, Any]:
    decoded = json.loads(value)
    if not isinstance(decoded, (list, dict)):
        raise ValueError("parameters must decode to a JSON array or object")
    return decoded


def query_database(connection: sqlite3.Connection, database: Path, sql: str,
                   values: Sequence[Any] | Mapping[str, Any], limit: int,
                   max_cell_bytes: int) -> Mapping[str, Any]:
    if not 1 <= limit <= MAX_ROWS:
        raise ValueError(f"limit must be between 1 and {MAX_ROWS}")
    if not 1 <= max_cell_bytes <= MAX_CELL_BYTES:
        raise ValueError(f"max-cell-bytes must be between 1 and {MAX_CELL_BYTES}")
    connection.set_authorizer(readonly_authorizer())
    cursor = connection.execute(sql, values)
    if cursor.description is None:
        raise ValueError("query must return rows")
    columns = [str(item[0]) for item in cursor.description]
    fetched = cursor.fetchmany(limit + 1)
    return {
        "schema": "appsec-review/sqlite-query/1",
        "database": database.name,
        "columns": columns,
        "rows": [[bounded_value(value, max_cell_bytes) for value in row]
                 for row in fetched[:limit]],
        "truncated": len(fetched) > limit,
    }


def run(argv: Sequence[str] | None = None) -> Mapping[str, Any] | str:
    args = parser().parse_args(argv)
    if args.command == "version":
        return f"sqlite-tool {VERSION} (SQLite {sqlite3.sqlite_version})"
    root = allowed_root()
    database = resolve_database(args.database, root)
    with connect(database, args.timeout_seconds) as connection:
        if args.command == "inspect":
            return inspect_database(connection, database)
        if args.command == "integrity":
            return integrity(connection, database)
        if args.command == "query":
            return query_database(connection, database, args.sql, parameters(args.parameters),
                                  args.limit, args.max_cell_bytes)
    raise AssertionError("unhandled command")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = run(argv)
        print(result if isinstance(result, str) else json.dumps(result, sort_keys=True,
                                                                 separators=(",", ":"),
                                                                 allow_nan=False))
        return 0
    except (ValueError, OSError, sqlite3.Error, json.JSONDecodeError) as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)[:1024]},
                         sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
