"""Bounded-memory syntax metrics: per-file shard row access and a streamed facts document.

Accepted shards are JSONL files sorted by row bytes, so one file's rows are scattered across a shard.
Holding every parsed row in memory grows with the target tree and exhausted the code-location memory
limit on large C targets.  This index scans each shard once, verifies its hash over the same bytes it
indexes, and records only the byte span of each wanted row in a scratch SQLite database.  Callers then
load one file's rows at a time, so peak memory follows the largest file rather than the whole tree.
Per-file facts are likewise streamed to disk instead of being retained until the end of the step.
"""

from __future__ import annotations

from collections.abc import Collection, Iterator, Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Any

_BATCH = 4096


def _verified_path(run_root: Path, identity: Mapping[str, Any]) -> Path:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("accepted artifact is unavailable or outside the run")
    return path


class ShardRowIndex:
    """Map wanted source paths to the byte spans of their rows across verified shards."""

    def __init__(self, run_root: Path, shards: Sequence[Mapping[str, Any]], wanted: Collection[str],
                 scratch: Path) -> None:
        self._paths: list[Path] = []
        self._stats: list[tuple[int, int]] = []
        self._database_path = scratch / "shard-rows.sqlite"
        scratch.mkdir(parents=True, exist_ok=True)
        if self._database_path.exists():
            self._database_path.unlink()
        self._database = sqlite3.connect(self._database_path)
        self._database.execute("PRAGMA journal_mode=OFF")
        self._database.execute("PRAGMA synchronous=OFF")
        self._database.execute("CREATE TABLE rows (path TEXT NOT NULL, shard INTEGER NOT NULL, "
                               "offset INTEGER NOT NULL, length INTEGER NOT NULL)")
        try:
            wanted_set = frozenset(wanted)
            for identity in shards:
                self._scan(run_root, identity, wanted_set)
            self._database.execute("CREATE INDEX rows_by_path ON rows (path, shard, offset)")
            self._database.commit()
        except BaseException:
            self.close()
            raise

    def _scan(self, run_root: Path, identity: Mapping[str, Any], wanted: frozenset[str]) -> None:
        path = _verified_path(run_root, identity)
        shard = len(self._paths)
        digest = hashlib.sha256()
        batch: list[tuple[str, int, int, int]] = []
        offset = 0
        with path.open("rb") as stream:
            stat = os.fstat(stream.fileno())
            for line in stream:
                digest.update(line)
                if line.strip():
                    row_path = json.loads(line)["path"]
                    if row_path in wanted:
                        batch.append((str(row_path), shard, offset, len(line)))
                        if len(batch) >= _BATCH:
                            self._database.executemany("INSERT INTO rows VALUES (?, ?, ?, ?)", batch)
                            batch.clear()
                offset += len(line)
        if digest.hexdigest() != identity.get("sha256"):
            raise ValueError("accepted artifact identity changed")
        if batch:
            self._database.executemany("INSERT INTO rows VALUES (?, ?, ?, ?)", batch)
        self._paths.append(path)
        self._stats.append((stat.st_size, stat.st_mtime_ns))

    def has_rows(self, path: str) -> bool:
        return self._database.execute("SELECT 1 FROM rows WHERE path = ? LIMIT 1", (path,)).fetchone() is not None

    def rows(self, path: str) -> list[Mapping[str, Any]]:
        """Return one file's rows, re-reading only that file's byte spans from the verified shards."""
        spans = self._database.execute("SELECT shard, offset, length FROM rows WHERE path = ? "
                                       "ORDER BY shard, offset", (path,)).fetchall()
        result: list[Mapping[str, Any]] = []
        stream = None
        current = -1
        try:
            for shard, offset, length in spans:
                if shard != current:
                    if stream is not None:
                        stream.close()
                    stream = self._paths[shard].open("rb")
                    stat = os.fstat(stream.fileno())
                    if (stat.st_size, stat.st_mtime_ns) != self._stats[shard]:
                        raise ValueError("accepted artifact identity changed")
                    current = shard
                stream.seek(offset)
                data = stream.read(length)
                if len(data) != length:
                    raise ValueError("accepted artifact identity changed")
                row = json.loads(data)
                if row.get("path") != path:
                    raise ValueError("accepted artifact identity changed")
                result.append(row)
        finally:
            if stream is not None:
                stream.close()
        return result

    def close(self) -> None:
        self._database.close()
        self._database_path.unlink(missing_ok=True)

    def __enter__(self) -> "ShardRowIndex":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class FilesDocumentWriter:
    """Write ``{..., "files": {path: record, ...}, ...}`` one record at a time.

    The result is byte-identical to ``canonical_json`` of the whole document, provided records are
    added in ascending path order and the other top-level keys are passed to ``finish``.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._body_path = path.parent / f".{path.name}.files"
        self._body = self._body_path.open("wb")
        self._last: str | None = None

    def add(self, key: str, record: Mapping[str, Any]) -> None:
        if self._last is not None and key <= self._last:
            raise ValueError("streamed document records must be added in ascending key order")
        if self._last is not None:
            self._body.write(b",")
        self._body.write(_canonical(key) + b":" + _canonical(record))
        self._last = key

    def finish(self, fields: Mapping[str, Any]) -> None:
        if "files" in fields:
            raise ValueError("streamed document fields must not repeat files")
        self._body.close()
        temporary = self.path.parent / f".{self.path.name}.tmp"
        try:
            with temporary.open("wb") as output, self._body_path.open("rb") as body:
                output.write(b"{")
                keys = sorted([*fields, "files"])
                for position, key in enumerate(keys):
                    if position:
                        output.write(b",")
                    output.write(_canonical(key) + b":")
                    if key == "files":
                        output.write(b"{")
                        while chunk := body.read(1024 * 1024):
                            output.write(chunk)
                        output.write(b"}")
                    else:
                        output.write(_canonical(fields[key]))
                output.write(b"}\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)
            self._body_path.unlink(missing_ok=True)

    def abort(self) -> None:
        self._body.close()
        self._body_path.unlink(missing_ok=True)
