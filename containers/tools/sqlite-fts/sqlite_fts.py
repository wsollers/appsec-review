#!/usr/local/bin/python
"""Offline FTS5 builder for bounded, already-sanitized index documents."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from pathlib import PurePosixPath
import sqlite3
import sys
from urllib.parse import quote


VERSION = "1.0.0"
SCHEMA = "appsec-review/sqlite-fts-documents/1"
FIELDS = frozenset({"identity", "name", "path", "text"})


def _inside(path: Path, root: Path, *, existing: bool) -> Path:
    resolved_root = root.resolve(strict=True)
    resolved = path.resolve(strict=existing)
    if not resolved.is_relative_to(resolved_root):
        raise ValueError(f"path must stay under {root}")
    return resolved


def _probe() -> str:
    with sqlite3.connect(":memory:") as database:
        database.execute("CREATE VIRTUAL TABLE probe USING fts5(text, tokenize='unicode61')")
        database.execute("INSERT INTO probe(text) VALUES ('fts5 ready')")
        if database.execute("SELECT count(*) FROM probe WHERE probe MATCH 'ready'").fetchone()[0] != 1:
            raise RuntimeError("FTS5 probe failed")
    return sqlite3.sqlite_version


def _documents(path: Path, *, max_records: int, max_input_bytes: int, max_text_bytes: int):
    if path.stat().st_size > max_input_bytes:
        raise ValueError("input exceeds byte limit")
    seen: set[str] = set()
    with path.open("rb") as stream:
        for number, raw in enumerate(stream, start=1):
            if number > max_records:
                raise ValueError("input exceeds record limit")
            if len(raw) > max_text_bytes + 16384:
                raise ValueError(f"record {number} exceeds byte limit")
            record = json.loads(raw)
            if not isinstance(record, dict) or set(record) != FIELDS:
                raise ValueError(f"record {number} must have exactly identity/name/path/text")
            if any(not isinstance(record[key], str) for key in FIELDS):
                raise ValueError(f"record {number} fields must be strings")
            identity = record["identity"]
            if not identity or len(identity) > 4096 or identity in seen:
                raise ValueError(f"record {number} has empty, duplicate, or oversized identity")
            seen.add(identity)
            if len(record["text"].encode("utf-8")) > max_text_bytes:
                raise ValueError(f"record {number} text exceeds byte limit")
            if len(record["name"]) > 4096 or len(record["path"]) > 4096:
                raise ValueError(f"record {number} name/path exceeds limit")
            logical_path = PurePosixPath(record["path"])
            if (logical_path.is_absolute() or ".." in logical_path.parts
                    or "\\" in record["path"] or "\x00" in record["path"]):
                raise ValueError(f"record {number} path is not logical and relative")
            yield (identity, record["name"], record["path"], record["text"])


def build(args: argparse.Namespace) -> None:
    source = _inside(Path(args.input), Path(args.input_root), existing=True)
    destination = Path(args.output)
    parent = _inside(destination.parent, Path(args.output_root), existing=True)
    destination = parent / destination.name
    if destination.exists() or destination.name in {"", ".", ".."}:
        raise ValueError("output must be a new file")
    temporary = destination.with_name(destination.name + ".building")
    if temporary.exists():
        raise ValueError("temporary output already exists")
    digest = hashlib.sha256(source.read_bytes()).hexdigest() if source.stat().st_size <= args.max_input_bytes else None
    if digest is None:
        raise ValueError("input exceeds byte limit")
    database = sqlite3.connect(temporary)
    count = 0
    try:
        database.executescript("""
            PRAGMA journal_mode=DELETE;
            PRAGMA synchronous=FULL;
            PRAGMA page_size=4096;
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
            CREATE VIRTUAL TABLE search_fts USING fts5(
                identity UNINDEXED, name, path, text, tokenize='unicode61'
            );
        """)
        for row in _documents(source, max_records=args.max_records,
                              max_input_bytes=args.max_input_bytes,
                              max_text_bytes=args.max_text_bytes):
            database.execute("INSERT INTO search_fts(identity,name,path,text) VALUES (?,?,?,?)", row)
            count += 1
        database.executemany("INSERT INTO metadata(key,value) VALUES (?,?)", sorted({
            "schema": SCHEMA,
            "tool_version": VERSION,
            "sqlite_version": sqlite3.sqlite_version,
            "tokenizer": "unicode61",
            "input_sha256": digest,
            "record_count": str(count),
        }.items()))
        database.execute("INSERT INTO search_fts(search_fts) VALUES ('integrity-check')")
        database.commit()
        database.execute("VACUUM")
    except BaseException:
        database.close()
        temporary.unlink(missing_ok=True)
        raise
    database.close()
    temporary.replace(destination)
    print(json.dumps({"schema": SCHEMA, "sqlite_version": sqlite3.sqlite_version,
                      "record_count": count, "input_sha256": digest,
                      "output": str(destination)}, sort_keys=True))


def verify(args: argparse.Namespace) -> None:
    path = _inside(Path(args.index), Path(args.input_root), existing=True)
    with sqlite3.connect(f"file:{quote(str(path), safe='/')}?mode=ro&immutable=1", uri=True) as database:
        metadata = dict(database.execute("SELECT key,value FROM metadata"))
        if metadata.get("schema") != SCHEMA or metadata.get("tokenizer") != "unicode61":
            raise ValueError("index schema or tokenizer mismatch")
        if database.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("SQLite integrity check failed")
        count = database.execute("SELECT count(*) FROM search_fts").fetchone()[0]
        if count != int(metadata.get("record_count", "-1")):
            raise ValueError("record count mismatch")
    print(json.dumps({"schema": SCHEMA, "record_count": count, "input_sha256": metadata["input_sha256"]},
                     sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version")
    commands.add_parser("probe")
    builder = commands.add_parser("build")
    builder.add_argument("--input", required=True)
    builder.add_argument("--output", required=True)
    builder.add_argument("--input-root", default="/workspace")
    builder.add_argument("--output-root", default="/scratch")
    builder.add_argument("--max-records", type=int, default=100000)
    builder.add_argument("--max-input-bytes", type=int, default=16777216)
    builder.add_argument("--max-text-bytes", type=int, default=131072)
    checker = commands.add_parser("verify")
    checker.add_argument("--index", required=True)
    checker.add_argument("--input-root", default="/workspace")
    args = parser.parse_args()
    if args.command == "version":
        print(f"sqlite-fts {VERSION}; SQLite {sqlite3.sqlite_version}")
    elif args.command == "probe":
        print(f"FTS5 ready; SQLite {_probe()}")
    elif args.command == "build":
        if min(args.max_records, args.max_input_bytes, args.max_text_bytes) < 1:
            raise ValueError("all limits must be positive")
        build(args)
    else:
        verify(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, sqlite3.Error, json.JSONDecodeError) as error:
        print(f"sqlite-fts: {error}", file=sys.stderr)
        raise SystemExit(2)
