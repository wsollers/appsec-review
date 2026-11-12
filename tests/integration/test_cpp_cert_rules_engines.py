"""The SEI CERT pack rules referenced by the C++ CERT crosswalk, run in the pinned engines.

Semgrep runs in the local tool image; OpenGrep parity runs a pinned host executable when one is
configured. Both skip, naming the gap, when their engine is missing. The offline bundle, pack and
crosswalk checks stay in ``tests/test_cpp_cert_rules.py``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from tests.test_cpp_cert_rules import (
    PACK, ROOT, SEMGREP_IMAGE, _canonical_finding_ids, _expected_positive_lines, _referenced_fixtures,
    _referenced_rule_files, _semgrep_ids,
)


def _docker_with_semgrep_image() -> bool:
    if not shutil.which("docker"):
        return False
    check = subprocess.run(
        ["docker", "image", "inspect", SEMGREP_IMAGE],
        capture_output=True,
        timeout=15,
        check=False,
    )
    return check.returncode == 0


def _referenced_findings(document: dict) -> set[tuple[str, int]]:
    return {(rule_id, finding["start"]["line"])
            for finding in document["results"]
            if (rule_id := next(iter(_canonical_finding_ids({"results": [finding]})))) in _semgrep_ids()}


def test_semgrep_rules_hit_positive_fixture_and_not_clean_fixture() -> None:
    if not _docker_with_semgrep_image():
        pytest.skip(f"pinned local image is unavailable: {SEMGREP_IMAGE}")

    mount = f"{PACK.resolve()}:/pack:ro"
    command = [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
        "-e", "SEMGREP_SEND_METRICS=off", "-e", "SEMGREP_ENABLE_VERSION_CHECK=0",
        "-v", mount, SEMGREP_IMAGE, "/opt/tool/bin/semgrep", "scan",
        "--disable-version-check", "--metrics", "off", "--json", "--quiet",
        *[argument for relative in _referenced_rule_files() for argument in ("--config", f"/pack/{relative}")],
        *[f"/pack/{relative}" for relative in _referenced_fixtures()],
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["errors"] == []
    assert _canonical_finding_ids(document) >= _semgrep_ids()
    assert _referenced_findings(document) == _expected_positive_lines()


def test_opengrep_parity_when_pinned_executable_is_available() -> None:
    executable = os.environ.get("APPSEC_REVIEW_OPENGREP") or shutil.which("opengrep")
    if executable is None or not Path(executable).is_file():
        pytest.skip("no pinned OpenGrep executable is available; parity remains a named coverage gap")
    # OpenGrep aborts at start-up when XDG_CONFIG_HOME does not exist.
    (ROOT / "test" / "tmp" / "opengrep-home" / ".config").mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            executable, "scan", "--json", "--disable-version-check",
            *[argument for relative in _referenced_rule_files() for argument in ("--config", str(PACK / relative))],
            *[str(PACK / relative) for relative in _referenced_fixtures()],
        ],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
        env={**os.environ, "HOME": str(ROOT / "test" / "tmp" / "opengrep-home"),
             "XDG_CONFIG_HOME": str(ROOT / "test" / "tmp" / "opengrep-home" / ".config")},
    )
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["errors"] == []
    assert _canonical_finding_ids(document) >= _semgrep_ids()
    assert _referenced_findings(document) == _expected_positive_lines()
