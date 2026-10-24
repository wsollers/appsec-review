"""Exact Lua fixture matching in the locally built, pinned scanner images.

The engines' native --test reader does not recognize Lua's -- comments. Read the
annotations here and compare the complete scan result, not just selected hits.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import tomllib

import pytest
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
    assert len(ids) == len(RULES) == 20
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


@pytest.mark.parametrize("engine", ["semgrep", "opengrep"])
def test_pinned_engine_matches_exactly_the_annotated_lines(engine: str, tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker is unavailable; Lua engine coverage is not verified")
    tool = tomllib.loads(
        (ROOT / "containers" / "tools" / engine / "tool.toml").read_text(encoding="utf-8")
    )
    image = f"appsec-review/tool-{engine}:{tool['version']}"
    inspected = subprocess.run(
        ["docker", "image", "inspect", image], capture_output=True, timeout=30, check=False,
    )
    if inspected.returncode != 0:
        pytest.skip(f"Local image {image} unavailable; Lua engine coverage is not verified")
    command = [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--user", "10001:10001", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "256",
        "--memory", "1g", "--cpus", "2", "--tmpfs", "/tmp:rw,size=256m",
        "-e", "HOME=/tmp", "-e", "XDG_CONFIG_HOME=/tmp",
        "-e", "SEMGREP_SEND_METRICS=off", "-e", "SEMGREP_ENABLE_VERSION_CHECK=0",
        "--mount", f"type=bind,source={PACK},target=/pack,readonly",
        "--entrypoint", tool["executable"], image,
        "scan", "--disable-version-check", "--strict", "--json", "--quiet",
        "--config", "/pack/game-security.yml",
    ]
    if engine == "semgrep":
        command += ["--metrics", "off"]
    command += ["--", "/pack/fixtures/game-security.lua"]
    result = subprocess.run(command, capture_output=True, timeout=300, check=False)
    (tmp_path / f"{engine}.stdout.json").write_bytes(result.stdout)
    (tmp_path / f"{engine}.stderr.txt").write_bytes(result.stderr)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    document = json.loads(result.stdout)
    assert document["version"] == tool["version"]
    assert document["errors"] == [], document["errors"]
    assert document["paths"]["scanned"] == ["/pack/fixtures/game-security.lua"]
    assert not document["paths"].get("skipped")
    found = []
    for item in document["results"]:
        check_id = item["check_id"]
        assert PREFIX in check_id, check_id
        rule_id = PREFIX + check_id.split(PREFIX, 1)[1]
        assert item["path"] == "/pack/fixtures/game-security.lua"
        found.append((rule_id, item["start"]["line"]))
    assert len(found) == len(set(found)), "Duplicate findings"
    assert set(found) == _annotations("ruleid"), (
        f"missing={sorted(_annotations('ruleid') - set(found))}; "
        f"unexpected={sorted(set(found) - _annotations('ruleid'))}"
    )
