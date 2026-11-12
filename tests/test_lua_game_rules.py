"""Exact Lua fixture matching in the locally built, pinned scanner images.

The engines' native --test reader does not recognize Lua's -- comments. Read the
annotations here and compare the complete scan result, not just selected hits.
"""

from __future__ import annotations

from pathlib import Path
import re
import tomllib

import yaml


ROOT = Path(__file__).parents[1]
PACK = ROOT / "rules" / "lua-game-security"
PREFIX = "appsec-review.lua."
RULES = yaml.safe_load((PACK / "game-security.yml").read_text(encoding="utf-8"))["rules"]
FIXTURE = PACK / "fixtures" / "game-security.lua"


def _annotations(kind: str) -> set[tuple[str, int]]:
    return {
        (match[1], number + 1)
        for number, line in enumerate(FIXTURE.read_text(encoding="utf-8").splitlines(), 1)
        if (match := re.fullmatch(rf"\s*-- {kind}: (\S+)", line))
    }


def test_rules_have_metadata_and_positive_and_negative_fixtures() -> None:
    ids = {rule["id"] for rule in RULES}
    assert ids and len(ids) == len(RULES)
    assert {name for name, _ in _annotations("ruleid")} == ids
    assert {name for name, _ in _annotations("ok")} == ids
    assert not (_annotations("ruleid") & _annotations("ok"))
    for rule in RULES:
        assert rule["id"].startswith(PREFIX)
        assert rule["languages"] == ["lua"]
        assert rule["severity"] in {"INFO", "WARNING"}
        metadata = rule["metadata"]
        assert metadata["category"] == "security"
        assert metadata["confidence"] in {"LOW", "MEDIUM", "HIGH"}
        assert metadata["review_signal"] in {
            "audit", "dangerous-capability", "dynamic-sink", "insecure-configuration",
        }
        assert all(re.match(r"CWE-\d+: ", cwe) for cwe in metadata["cwe"])
        if metadata["review_signal"] == "audit":
            assert rule["severity"] == "INFO"


def test_lua_pack_is_registered_for_offline_validation() -> None:
    registry = tomllib.loads((ROOT / "rules" / "registry.toml").read_text(encoding="utf-8"))
    pack = next(pack for pack in registry["packs"] if pack["id"] == "lua-game-security")
    assert pack["path"] == "rules/lua-game-security"
    assert pack["engine"] == "semgrep"
    assert pack["state"] == "enabled"
    assert pack["language"] == "lua"
