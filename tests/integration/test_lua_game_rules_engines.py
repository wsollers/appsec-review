"""The Lua game-security pack matches exactly its annotated fixture lines in both pinned engines.

Skips, naming the gap, when Docker or a tool image is missing. The metadata and registration
checks stay in ``tests/test_lua_game_rules.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tomllib

import pytest

from tests.test_lua_game_rules import PACK, PREFIX, ROOT, _annotations


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
