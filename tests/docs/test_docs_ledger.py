"""The portable documentation ledger covers tracked files, not host-local walk state."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path, PurePosixPath
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
LEDGER = "docs/docs-ledger.json"
SCHEMA = "appsec-review/docs-ledger/1"
KINDS = {
    "architecture", "operations", "process", "task", "walk", "review", "schema",
    "history", "generated",
}
SUBSYSTEMS = {
    "images and deployment", "target acquisition and build", "code intelligence",
    "scanners and evidence collection", "review inference and guidance",
    "runtime interchange", "reporting and metrics", "testing and operations",
}
DISPOSITIONS = {"keep", "revise", "merge-into", "retire", "generated"}
FIELDS = {"path", "kind", "subsystem", "disposition", "reason", "decision_record"}


def _in_scope(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return (
        path in {"AGENTS.md", "scripts/README.md"}
        or path.startswith("docs/")
        or len(parts) >= 2 and parts[0] == "containers" and parts[-1] == "README.md"
    )


def _tracked_documents() -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True,
        check=True, timeout=5,
    )
    return {path for path in result.stdout.split("\0") if path and _in_scope(path)}


def _relative_file(root: Path, path: str) -> Path:
    assert isinstance(path, str) and path, "path must be a nonempty string"
    relative = PurePosixPath(path)
    assert (
        not relative.is_absolute() and ".." not in relative.parts
        and "\\" not in path and relative.as_posix() == path
    ), f"noncanonical repository-relative path: {path}"
    resolved = (root / path).resolve()
    assert resolved.is_relative_to(root.resolve()), f"path escapes checkout: {path}"
    assert resolved.is_file(), f"ledger file does not exist: {path}"
    return resolved


def _validate(document: dict, root: Path, tracked: set[str]) -> None:
    assert document["schema"] == SCHEMA, "unknown ledger schema"
    rows = document["documents"]
    assert isinstance(rows, list), "documents must be a list"
    by_path: dict[str, dict] = {}
    for row in rows:
        assert isinstance(row, dict), "document row must be an object"
        assert FIELDS <= row.keys(), f"missing ledger fields: {FIELDS - row.keys()}"
        assert row.keys() <= FIELDS | {"merge_target"}, "unknown ledger fields"
        path = row["path"]
        _relative_file(root, path)
        assert _in_scope(path), f"out-of-scope ledger path: {path}"
        assert not path.startswith("docs/walks/"), "host-local walks must not enter the portable ledger"
        assert path not in by_path, f"duplicate ledger path: {path}"
        by_path[path] = row
        assert row["kind"] in KINDS, f"unknown kind: {path}"
        assert row["subsystem"] in SUBSYSTEMS, f"unknown subsystem: {path}"
        assert row["disposition"] in DISPOSITIONS, f"unknown disposition: {path}"
        assert type(row["decision_record"]) is bool, f"decision_record must be boolean: {path}"
        assert (
            isinstance(row["reason"], str) and row["reason"].strip()
            and "\n" not in row["reason"]
        ), f"reason must be a nonempty single line: {path}"
        assert not (
            row["decision_record"] and row["disposition"] in {"retire", "merge-into"}
        ), f"decision record must be preserved: {path}"
        if row["disposition"] == "merge-into":
            assert row.get("merge_target"), f"merge-into requires a target: {path}"
        else:
            assert "merge_target" not in row, f"merge_target without merge-into: {path}"

    assert not any(path.startswith("docs/walks/") for path in tracked), (
        "host-local walks must not be tracked"
    )
    missing = sorted(tracked - by_path.keys())
    extra = sorted(by_path.keys() - tracked)
    assert not missing, f"tracked documentation missing from ledger: {missing}"
    assert not extra, f"ledger rows are not tracked documentation: {extra}"
    assert list(by_path) == sorted(by_path), "ledger paths must be sorted"
    for path, row in by_path.items():
        if row["disposition"] != "merge-into":
            continue
        target = row["merge_target"]
        assert target in by_path, f"merge target missing from ledger: {path}: {target}"
        _relative_file(root, target)
        assert target != path, f"self merge: {path}"
        assert by_path[target]["disposition"] not in {"merge-into", "retire"}, (
            f"merge target is not a retained destination: {path}: {target}"
        )


@pytest.fixture
def inventory(tmp_path: Path) -> tuple[Path, dict, set[str]]:
    paths = ["docs/architecture/source.md", "docs/operations/target.md"]
    rows = []
    for path in paths:
        file = tmp_path / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("# Fixture\n", encoding="utf-8")
        rows.append({
            "path": path, "kind": "architecture", "subsystem": "runtime interchange",
            "disposition": "keep", "reason": "Keep the fixture contract.",
            "decision_record": False,
        })
    return tmp_path, {"schema": SCHEMA, "documents": rows}, set(paths)


def test_committed_ledger_covers_tracked_documentation() -> None:
    document = json.loads((ROOT / LEDGER).read_text(encoding="utf-8"))
    # Include the new ledger itself before its first commit, without absorbing others' drafts.
    _validate(document, ROOT, _tracked_documents() | {LEDGER})


@pytest.mark.parametrize(("path", "expected"), [
    ("AGENTS.md", True),
    ("README.md", False),
    ("containers/README.md", True),
    ("containers/tools/codeql/README.md", True),
    ("containers/tools/codeql/Dockerfile", False),
    ("docs/architecture/example.md", True),
    ("docs/assets/example.png", True),
    ("docs/schemas/example.schema.json", True),
    ("docs/schemas/upstream/LICENSE", True),
    ("scripts/README.md", True),
    ("scripts/example.sh", False),
    ("tests/docs/example.md", False),
], ids=[
    "agent-rules", "root-readme-excluded", "container-index", "tool-readme",
    "dockerfile-excluded", "authored-page", "image-asset", "json-schema",
    "upstream-license", "script-index", "script-excluded", "test-doc-excluded",
])
def test_inventory_scope_includes_non_markdown_assets(path: str, expected: bool) -> None:
    assert _in_scope(path) is expected


def test_valid_keep_and_merge_rows(inventory) -> None:
    root, document, tracked = inventory
    _validate(document, root, tracked)
    document["documents"][0].update(
        disposition="merge-into", merge_target="docs/operations/target.md",
    )
    _validate(document, root, tracked)


def test_missing_tracked_document_fails(inventory) -> None:
    root, document, tracked = inventory
    document["documents"].pop()
    with pytest.raises(AssertionError, match="tracked documentation missing"):
        _validate(document, root, tracked)


def test_missing_file_fails(inventory) -> None:
    root, document, tracked = inventory
    (root / document["documents"][0]["path"]).unlink()
    with pytest.raises(AssertionError, match="ledger file does not exist"):
        _validate(document, root, tracked)


def test_merge_without_target_fails(inventory) -> None:
    root, document, tracked = inventory
    document["documents"][0]["disposition"] = "merge-into"
    with pytest.raises(AssertionError, match="merge-into requires a target"):
        _validate(document, root, tracked)


@pytest.mark.parametrize("disposition", ["merge-into", "retire"])
def test_decision_record_cannot_be_removed(inventory, disposition: str) -> None:
    root, document, tracked = inventory
    document["documents"][0].update(decision_record=True, disposition=disposition)
    with pytest.raises(AssertionError, match="decision record must be preserved"):
        _validate(document, root, tracked)


@pytest.mark.parametrize(("field", "value", "message"), [
    ("kind", "unknown", "unknown kind"),
    ("subsystem", "unknown", "unknown subsystem"),
    ("disposition", "unknown", "unknown disposition"),
    ("decision_record", "false", "decision_record must be boolean"),
    ("reason", "", "reason must be a nonempty single line"),
    ("reason", "First line.\nSecond line.", "reason must be a nonempty single line"),
], ids=["kind", "subsystem", "disposition", "decision-flag", "empty-reason", "multiline-reason"])
def test_invalid_classification_fails(inventory, field: str, value: str, message: str) -> None:
    root, document, tracked = inventory
    document["documents"][0][field] = value
    with pytest.raises(AssertionError, match=message):
        _validate(document, root, tracked)


def test_duplicate_row_fails(inventory) -> None:
    root, document, tracked = inventory
    document["documents"].append(deepcopy(document["documents"][0]))
    with pytest.raises(AssertionError, match="duplicate ledger path"):
        _validate(document, root, tracked)


@pytest.mark.parametrize("target", ["docs/missing.md", "docs/architecture/source.md"],
                         ids=["missing-target", "self-merge"])
def test_merge_requires_a_distinct_inventoried_target(inventory, target: str) -> None:
    root, document, tracked = inventory
    document["documents"][0].update(disposition="merge-into", merge_target=target)
    with pytest.raises(AssertionError, match="merge target missing|self merge"):
        _validate(document, root, tracked)


def test_merge_target_cannot_be_retired(inventory) -> None:
    root, document, tracked = inventory
    document["documents"][0].update(
        disposition="merge-into", merge_target="docs/operations/target.md",
    )
    document["documents"][1]["disposition"] = "retire"
    with pytest.raises(AssertionError, match="merge target is not a retained destination"):
        _validate(document, root, tracked)


def test_untracked_walk_state_is_not_a_portable_requirement(inventory) -> None:
    root, document, tracked = inventory
    walk = root / "docs/walks/local-state.md"
    walk.parent.mkdir()
    walk.write_text("Host-local data, not ledger input.", encoding="utf-8")
    _validate(document, root, tracked)
    walk.unlink()
    _validate(document, root, tracked)


def test_walk_rows_cannot_leak_into_the_committed_ledger(inventory) -> None:
    root, document, tracked = inventory
    walk = root / "docs/walks/local-state.md"
    walk.parent.mkdir()
    walk.write_text("Host-local data.", encoding="utf-8")
    document["documents"][0]["path"] = "docs/walks/local-state.md"
    with pytest.raises(AssertionError, match="host-local walks must not enter"):
        _validate(document, root, tracked)


@pytest.mark.parametrize("path", ["../outside.md", "/outside.md", "docs/../other.md"],
                         ids=["parent-path", "absolute-path", "parent-segment"])
def test_noncanonical_path_fails(inventory, path: str) -> None:
    root, document, tracked = inventory
    document["documents"][0]["path"] = path
    with pytest.raises(AssertionError, match="noncanonical repository-relative path"):
        _validate(document, root, tracked)


def test_untracked_draft_row_fails(inventory) -> None:
    root, document, tracked = inventory
    tracked.remove(document["documents"][0]["path"])
    with pytest.raises(AssertionError, match="ledger rows are not tracked"):
        _validate(document, root, tracked)


def test_unsorted_rows_fail(inventory) -> None:
    root, document, tracked = inventory
    document["documents"].reverse()
    with pytest.raises(AssertionError, match="ledger paths must be sorted"):
        _validate(document, root, tracked)
