from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def doc_inventory() -> dict:
    return json.loads((ROOT / "docs/generated/inventory.json").read_text(encoding="utf-8"))


@pytest.fixture
def doc_pages() -> dict[str, str]:
    ledger = json.loads((ROOT / "docs/docs-ledger.json").read_text(encoding="utf-8"))
    return {row["path"]: (ROOT / row["path"]).read_text(encoding="utf-8")
            for row in ledger["documents"] if row["path"].endswith(".md")}
