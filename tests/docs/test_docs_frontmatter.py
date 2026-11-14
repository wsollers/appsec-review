from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.docs_support import frontmatter, validate_frontmatter, with_frontmatter

ROOT = Path(__file__).resolve().parents[2]
COMMIT = "a" * 40


def values() -> dict:
    return {"title": "Fixture", "kind": "architecture", "subsystem": "runtime interchange",
            "status": "current", "jobs": ["job_fixture"], "last reconciled": COMMIT}


def test_every_document_has_valid_frontmatter(doc_pages, doc_inventory) -> None:
    commit = json.loads((ROOT / "docs/docs-sync.json").read_text())["synced_commit"]
    errors = []
    for path, text in sorted(doc_pages.items()):
        try:
            metadata, _ = frontmatter(text)
            validate_frontmatter(metadata, jobs=set(doc_inventory["jobs"]), reconciled=commit)
        except ValueError as error:
            errors.append(f"{path}: {error}")
    assert not errors, "\n".join(errors)


@pytest.mark.parametrize(("field", "value"), [
    ("kind", "invalid"), ("subsystem", "invalid"), ("status", "in-progress"),
    ("jobs", ["job_unknown"]), ("last reconciled", "b" * 40),
], ids=["kind", "subsystem", "status", "job", "watermark"])
def test_invalid_metadata_fails(field, value) -> None:
    metadata = values()
    metadata[field] = value
    with pytest.raises(ValueError):
        validate_frontmatter(metadata, jobs={"job_fixture"}, reconciled=COMMIT)


@pytest.mark.parametrize("text", [
    "# Missing metadata\n", "---\ntitle: Fixture\n",
    "---\ntitle: One\ntitle: Two\n---\n", "---\nunknown: value\n---\n",
    '---\njobs: ["job_z", "job_a"]\n---\n',
], ids=["missing", "unterminated", "duplicate", "unknown-key", "unordered-jobs"])
def test_invalid_frontmatter_is_not_silently_accepted(text) -> None:
    with pytest.raises(ValueError):
        frontmatter(text)


def test_metadata_round_trip_preserves_authored_body() -> None:
    body = '# A dated record\n\nKeep `old-schema/1` and this [link](record.md).\n'
    metadata, actual = frontmatter(with_frontmatter(values(), body))
    assert metadata == values() and actual == body
