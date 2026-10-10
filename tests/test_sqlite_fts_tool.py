from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import subprocess
import sys


TOOL = Path(__file__).resolve().parents[1] / "containers" / "tools" / "sqlite-fts" / "sqlite_fts.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True, check=False)


def test_build_and_verify_searchable_fts5_index(tmp_path: Path) -> None:
    source = tmp_path / "documents.jsonl"
    source.write_text(
        json.dumps({"identity": "source:auth.py:check", "name": "check", "path": "src/auth.py",
                    "text": "authorization decision"}) + "\n"
        + json.dumps({"identity": "finding:123", "name": "injection", "path": "reports/findings.json",
                      "text": "SQL injection finding"}) + "\n",
        encoding="utf-8",
    )
    index = tmp_path / "search.sqlite"
    result = _run("build", "--input", str(source), "--input-root", str(tmp_path),
                  "--output", str(index), "--output-root", str(tmp_path))
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["record_count"] == 2
    verified = _run("verify", "--index", str(index), "--input-root", str(tmp_path))
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["record_count"] == 2
    with sqlite3.connect(f"file:{index}?mode=ro", uri=True) as database:
        assert database.execute(
            "SELECT identity FROM search_fts WHERE search_fts MATCH ?", ("authorization",)
        ).fetchall() == [("source:auth.py:check",)]


def test_build_rejects_duplicate_identity_and_escaped_logical_path(tmp_path: Path) -> None:
    source = tmp_path / "documents.jsonl"
    index = tmp_path / "search.sqlite"
    rows = [{"identity": "one", "name": "x", "path": "src/x.py", "text": "x"},
            {"identity": "one", "name": "y", "path": "src/y.py", "text": "y"}]
    for invalid_rows in (rows, [{**rows[0], "path": "..\\secret"}]):
        source.write_text("".join(json.dumps(row) + "\n" for row in invalid_rows), encoding="utf-8")
        result = _run("build", "--input", str(source), "--input-root", str(tmp_path),
                      "--output", str(index), "--output-root", str(tmp_path))
        assert result.returncode == 2
        assert not index.exists()
        assert not (tmp_path / "search.sqlite.building").exists()
