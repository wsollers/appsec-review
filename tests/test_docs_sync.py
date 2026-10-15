"""The docs-sync record names a real main commit the documentation was reconciled against.

Staleness is deliberately not checked: `main` moving past ``synced_commit`` is normal, and noticing
it is the job of the ``docs-sync`` development skill, not of CI.
"""
from __future__ import annotations

from datetime import date
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "docs" / "docs-sync.json"
SCHEMA = "appsec-review/docs-sync/1"


def _record() -> dict:
    return json.loads(RECORD.read_text(encoding="utf-8"))


def test_record_has_the_docs_sync_schema() -> None:
    record = _record()
    assert set(record) == {"schema", "synced_commit", "synced_at"}
    assert record["schema"] == SCHEMA
    assert re.fullmatch(r"[0-9a-f]{40}", record["synced_commit"])
    assert date.fromisoformat(record["synced_at"]).isoformat() == record["synced_at"]


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True,
                          timeout=60, check=False)


def test_synced_commit_is_in_history_when_history_is_available() -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    if _git("rev-parse", "--is-inside-work-tree").stdout.strip() != "true":
        pytest.skip("not a git checkout")
    shallow = _git("rev-parse", "--is-shallow-repository").stdout.strip() == "true"
    commit = _record()["synced_commit"]
    present = _git("cat-file", "-e", f"{commit}^{{commit}}").returncode == 0
    ancestor = present and _git("merge-base", "--is-ancestor", commit, "HEAD").returncode == 0
    if shallow and not ancestor:
        # The commit, or the path from it to HEAD, may lie beyond the fetched history.
        pytest.skip("shallow clone: the synced commit's ancestry cannot be established")
    assert present, f"synced_commit {commit} is not a commit in this repository"
    assert ancestor, f"synced_commit {commit} is not an ancestor of HEAD"
