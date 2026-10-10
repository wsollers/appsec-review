from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "containers" / "tools" / "sqlite" / "sqlite_tool.py"
SPEC = importlib.util.spec_from_file_location("sqlite_tool", TOOL_PATH)
assert SPEC and SPEC.loader
sqlite_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sqlite_tool)


def database(tmp_path: Path) -> Path:
    path = tmp_path / "index.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT)")
        connection.execute("CREATE VIRTUAL TABLE records_fts USING fts5(value)")
        connection.execute("INSERT INTO records(value) VALUES ('alpha'), ('beta')")
        connection.execute("INSERT INTO records_fts(value) VALUES ('alpha'), ('beta')")
    return path


def test_inspect_integrity_and_parameterized_fts_query(tmp_path: Path, monkeypatch) -> None:
    path = database(tmp_path)
    monkeypatch.setenv("APPSEC_SQLITE_ROOT", str(tmp_path))

    inspected = sqlite_tool.run(["inspect", str(path)])
    assert inspected["fts5"] is True
    assert {item["name"] for item in inspected["objects"]} >= {"records", "records_fts"}
    assert sqlite_tool.run(["integrity", str(path)])["ok"] is True

    result = sqlite_tool.run([
        "query", str(path), "--sql",
        "SELECT value FROM records_fts WHERE records_fts MATCH ? ORDER BY value",
        "--parameters", '["alpha"]',
    ])
    assert result["rows"] == [["alpha"]]
    assert result["truncated"] is False


def test_query_rejects_writes_pragmas_attach_and_multiple_statements(
        tmp_path: Path, monkeypatch) -> None:
    path = database(tmp_path)
    monkeypatch.setenv("APPSEC_SQLITE_ROOT", str(tmp_path))
    prohibited = (
        "DELETE FROM records",
        "PRAGMA user_version",
        "ATTACH DATABASE '/tmp/other.sqlite' AS other",
        "SELECT 1; SELECT 2",
    )
    for sql in prohibited:
        with pytest.raises(sqlite3.Error):
            sqlite_tool.run(["query", str(path), "--sql", sql])
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM records").fetchone()[0] == 2


def test_database_must_resolve_beneath_allowed_root(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "mounted"
    root.mkdir()
    outside = database(tmp_path)
    monkeypatch.setenv("APPSEC_SQLITE_ROOT", str(root))
    with pytest.raises(ValueError, match="outside"):
        sqlite_tool.run(["inspect", str(outside)])
