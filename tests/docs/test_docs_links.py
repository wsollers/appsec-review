from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.docs_support import anchors, frontmatter, link_errors, links, with_frontmatter

ROOT = Path(__file__).resolve().parents[2]


def document(body: str) -> str:
    return with_frontmatter({"title": "Fixture", "kind": "architecture",
                             "subsystem": "runtime interchange", "status": "current",
                             "last reconciled": "a" * 40}, body)


def archive_errors(doc_pages) -> set[str]:
    ledger = json.loads((ROOT / "docs/docs-ledger.json").read_text(encoding="utf-8"))
    result = set()
    for path, record in ledger["scope"]["archive_citations"].items():
        metadata, body = frontmatter(doc_pages[path])
        assert metadata["status"] == "historical" and record["gap"] == "T-148"
        targets = sorted(set(target for target in links(body) if target.startswith("../../old/")))
        digest = hashlib.sha256(json.dumps(targets, separators=(",", ":")).encode()).hexdigest()
        assert digest == record["targets_sha256"], "new or changed archive citations require review"
        assert len(targets) == record["count"]
        result.update(f"{path}: missing link: {target}" for target in targets)
    return result


def test_current_and_available_historical_links_resolve(doc_pages) -> None:
    errors = set(link_errors(ROOT, doc_pages))
    assert not errors - archive_errors(doc_pages), "\n".join(sorted(errors - archive_errors(doc_pages)))


def test_historical_archive_citations_have_source_coverage(doc_pages) -> None:
    missing = set(link_errors(ROOT, doc_pages)) & archive_errors(doc_pages)
    if missing:
        pytest.skip(f"T-148: {len(missing)} historical old/ citations have no local source; "
                    "the dated record is preserved, not verified")


@pytest.mark.parametrize("target", ["missing.md", "target.md#missing"], ids=["missing-file", "missing-anchor"])
def test_broken_relative_links_fail(tmp_path: Path, target: str) -> None:
    (tmp_path / "target.md").write_text("# Present\n", encoding="utf-8")
    assert link_errors(tmp_path, {"source.md": document(f"[broken]({target})")})


def test_inline_and_fenced_examples_are_not_links() -> None:
    body = "`[example](missing.md)`\n````md\n[example](missing.md)\n```\n````\n"
    assert links(body) == []
    assert links("~~~md\n[example](missing.md)\n~~~\n") == []


def test_reference_links_images_and_parentheses_resolve(tmp_path: Path) -> None:
    (tmp_path / "file_(draft).md").write_text("# A `typed` heading\n", encoding="utf-8")
    (tmp_path / "diagram.svg").write_text("<svg/>", encoding="utf-8")
    body = '[text][ref]\n\n[ref]: file_(draft).md#a-typed-heading\n![diagram](diagram.svg)\n'
    assert link_errors(tmp_path, {"source.md": document(body)}) == []
    assert links("[text](file_(draft).md#a-typed-heading)") == ["file_(draft).md#a-typed-heading"]


def test_duplicate_headings_and_explicit_aliases() -> None:
    assert anchors('# Same\n## Same\n<a id="legacy"></a>\n') == {"same", "same-1", "legacy"}


def test_unresolved_reference_and_repository_escape_fail(tmp_path: Path) -> None:
    body = "[bad][absent]\n[escape](../outside.md)"
    errors = link_errors(tmp_path, {"source.md": document(body)})
    assert any("unresolved-reference" in error for error in errors)
    assert any("escapes repository" in error for error in errors)
