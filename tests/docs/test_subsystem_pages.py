from __future__ import annotations

import re

from scripts.docs_support import frontmatter


SUBSYSTEMS = (
    "images-and-deployment",
    "target-acquisition-and-build",
    "code-intelligence",
    "scanners-and-evidence-collection",
    "review-inference-and-guidance",
    "runtime-interchange",
    "reporting-and-metrics",
    "testing-and-operations",
)
SECTIONS = ("As built today", "Decisions", "Named gaps", "Jobs and pages", "Dataflow")


def test_each_subsystem_has_one_current_source_grounded_dive(doc_pages) -> None:
    for name in SUBSYSTEMS:
        path = f"docs/architecture/{name}.md"
        assert path in doc_pages, f"subsystem page missing from the ledger: {path}"
        text = doc_pages[path]
        metadata, body = frontmatter(text)
        assert metadata["kind"] == "architecture", path
        assert metadata["status"] == "current", path
        assert tuple(re.findall(r"^## (.+)$", body, re.MULTILINE)) == SECTIONS, path
        sections = re.split(r"^## .+$", body, flags=re.MULTILINE)[1:]
        assert all(section.strip() for section in sections), path
        assert re.search(r"\d{4}-\d{2}-\d{2}", sections[1]), path
        assert re.search(r"\[[^]]+\]\([^)]*\.md(?:#[^)]*)?\)", sections[1]), path
        assert re.search(r"\bT-\d{3}\b", sections[2]), path
        assert re.search(r"\[[^]]+\]\([^)]*\.md(?:#[^)]*)?\)", sections[3]), path
        assert re.search(r"```mermaid\n(?:flowchart|graph) .+?\n.+?\n```",
                         sections[4], re.DOTALL), path
