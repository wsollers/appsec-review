from __future__ import annotations

import json
from pathlib import Path
import re
import tomllib

from scripts.docs_support import frontmatter, identifier_errors, link_errors, links


ROOT = Path(__file__).resolve().parents[2]
PAGE = "docs/architecture/testing.md"


def enforcement_rows() -> list[list[str]]:
    text = (ROOT / PAGE).read_text(encoding="utf-8")
    section = text.split("## Forward contract and enforcement\n", 1)[1].split("\n## Tiers\n", 1)[0]
    return [re.split(r"(?<!\\)\|", line)[1:-1] for line in section.splitlines()
            if line.startswith("| ") and not line.startswith(("| Contract ", "| ---"))]


def test_every_testing_rule_names_existing_enforcement_or_a_registered_gap() -> None:
    ids = set(re.findall(r"^### (T-\d{3}) ", (ROOT / "docs/TODO.md").read_text(), re.M))
    rows = enforcement_rows()
    assert rows
    for row in rows:
        assert len(row) == 3
        references = links(row[1])
        assert references, f"rule has no enforcement reference: {row[0]}"
        for reference in references:
            path = ((ROOT / PAGE).parent / reference.split("#", 1)[0]).resolve()
            assert path.is_relative_to(ROOT) and path.is_file(), reference
        if "stated, not" in row[2]:
            gaps = set(re.findall(r"T-\d{3}", row[2]))
            assert gaps and gaps <= ids, f"unregistered enforcement gap: {row[0]}"


def test_forward_contract_uses_the_configured_tier_defaults() -> None:
    options = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["pytest"]["ini_options"]
    assert {name: float(options[f"{name}_time_budget_seconds"])
            for name in ("unit", "integration", "live")} == {
                "unit": 10.0, "integration": 300.0, "live": 1800.0}
    text = (ROOT / PAGE).read_text()
    assert "under ten minutes for the whole unit suite" in text
    assert "300 s" in text and "1800 s" in text


def test_suite_ceiling_is_not_claimed_from_a_selected_ci_timeout() -> None:
    row = next(row for row in enforcement_rows() if "whole unit suite" in row[0])
    assert "stated, not enforced" in row[2].lower()
    assert "T-109" in row[2] and "not proof" in row[2]


def test_testing_contract_links_and_identifiers_resolve() -> None:
    text = (ROOT / PAGE).read_text()
    metadata, _ = frontmatter(text)
    assert metadata["status"] == "current"
    inventory = json.loads((ROOT / "docs/generated/inventory.json").read_text())
    assert identifier_errors(text, inventory) == []
    assert link_errors(ROOT, {PAGE: text}) == []
