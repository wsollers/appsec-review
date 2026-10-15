"""Repository-authored Semgrep rules match what they claim and nothing broader.

Runs the real Semgrep engine when it is installed (it is pinned in the tool-semgrep image);
otherwise only the static checks run.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml


ROOT = Path(__file__).parents[1]
SECURITY = ROOT / "rules" / "semgrep" / "security.yml"
SHELL_RULE = "appsec-review.shell-unquoted-expansion"
SCRIPT = """#!/bin/bash
echo hello world
rm -rf "$dir"
rm -rf $dir
cp "$a" "${b}/x"
cp ${src} /tmp
ls -l
x=$y
echo "$@"
echo $@
grep foo $file | wc -l
printf '%s\\n' "$name"
echo "value $b here"
"""
UNQUOTED_LINES = {4, 6, 10, 11}


def _shell_rule() -> dict:
    rules = yaml.safe_load(SECURITY.read_text(encoding="utf-8"))["rules"]
    return next(rule for rule in rules if rule["id"] == SHELL_RULE)


def test_shell_rule_is_not_a_bare_two_metavariable_command() -> None:
    # `$CMD $ARG` matched every two-word command, so every script produced false findings.
    assert _shell_rule()["pattern"] == "$CMD ... ${$X} ..."


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep engine is not installed")
def test_shell_rule_matches_only_unquoted_expansions(tmp_path: Path) -> None:
    script = tmp_path / "run.sh"
    script.write_text(SCRIPT, encoding="utf-8")
    completed = subprocess.run(
        ["semgrep", "scan", "--metrics", "off", "--disable-version-check", "--json",
         "--config", str(SECURITY), str(script)],
        capture_output=True, check=False, timeout=300)
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")[-2000:]
    results = json.loads(completed.stdout)["results"]
    lines = {item["start"]["line"] for item in results if item["check_id"].endswith(SHELL_RULE)}
    assert lines == UNQUOTED_LINES
