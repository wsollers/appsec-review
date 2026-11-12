"""The C++ memory-safety Semgrep rules and the widened gitleaks pattern, run in the pinned engines.

Skips, naming the gap, when Docker or a tool image is missing. The lock, registry and pattern
checks stay in ``tests/test_cpp_memory_safety_rules.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from tests.test_cpp_memory_safety_rules import (
    FIXTURES, GITLEAKS, GITLEAKS_IMAGE, NEW_RULES, OPENGREP_IMAGE, SEMGREP, SEMGREP_IMAGE,
)


def _docker_ready(*images: str) -> bool:
    if shutil.which("docker") is None:
        return False
    return all(subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0
               for image in images)


def _scan(image: str, entrypoint: str, extra: list[str], rules: Path, target: Path) -> list[tuple[str, int, str]]:
    command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "1000:1000", "--cap-drop", "ALL",
               "--tmpfs", "/tmp:rw,size=256m", "-e", "HOME=/tmp", "-v", f"{target}:/target:ro",
               "-v", f"{rules}:/rules:ro", "--entrypoint", entrypoint, image,
               "scan", "--disable-version-check", *extra, "--config", "/rules/review-signals.yml", "--json", "--quiet",
               "/target"]
    output = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False).stdout
    document = json.loads(output)
    assert not document.get("errors"), document["errors"][:2]
    return sorted((Path(item["path"]).name, item["start"]["line"], item["check_id"].rsplit(".", 1)[-1])
                  for item in document["results"] if item["check_id"].rsplit(".", 1)[-1] in NEW_RULES)


@pytest.mark.skipif(not _docker_ready(SEMGREP_IMAGE, OPENGREP_IMAGE), reason="Semgrep and Opengrep images are not built")
@pytest.mark.parametrize("image, entrypoint, extra", [
    (SEMGREP_IMAGE, "/opt/tool/bin/semgrep", ["--metrics", "off"]),
    (OPENGREP_IMAGE, "/opt/tool/opengrep/opengrep.bin", []),
])
def test_both_engines_report_the_vulnerable_fixture_and_nothing_in_the_safe_one(image, entrypoint, extra, tmp_path) -> None:
    target = tmp_path / "target"
    shutil.copytree(FIXTURES, target)  # outside tests/, which Semgrep skips by default
    found = _scan(image, entrypoint, extra, SEMGREP, target)
    vulnerable = Path(FIXTURES / "vulnerable.cpp").read_text(encoding="utf-8").splitlines()
    expected = sorted(("vulnerable.cpp", number, rule.split("EXPECT ")[1].strip())
                      for number, rule in enumerate(vulnerable, 1) if "EXPECT " in rule)
    assert found == expected
    assert not [item for item in found if item[0] == "safe.cpp"]


@pytest.mark.skipif(not _docker_ready(GITLEAKS_IMAGE), reason="gitleaks image is not built")
def test_gitleaks_with_the_bundle_finds_the_array_declared_key_that_the_defaults_miss(tmp_path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "config.cpp").write_text('namespace {\nconst char relay_api_key[] = "rk_7f3c9a1e5b2d8f40c6a9e3b1d7f5c2a8";\n}\n',
                                       encoding="utf-8")

    def findings(config: Path | None) -> list[str]:
        command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "1000:1000",
                   "--cap-drop", "ALL", "--tmpfs", "/tmp:rw,size=64m", "-e", "HOME=/tmp", "-v", f"{target}:/target:ro",
                   "-v", f"{GITLEAKS}:/rules-gitleaks:ro", "--entrypoint", "sh", GITLEAKS_IMAGE, "-c",
                   "gitleaks dir /target %s --no-banner --redact --report-format json --report-path /tmp/r.json "
                   "--exit-code 0 >/dev/null 2>&1; cat /tmp/r.json" % (f"--config {config}" if config else "")]
        output = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False).stdout
        return [item["RuleID"] for item in (json.loads(output) or [])]

    assert findings(None) == []
    assert findings(Path("/rules-gitleaks/generic-secrets.toml")) == ["generic-api-key"]


# Everything the built-in rule reports must still be reported with the widened pattern; the widening may only add.
_UPSTREAM_BATTERY = [
    'api_key = "Zk3pQ9xLm2Vb7TnR4sWd8Yh"', 'API_KEY = "Zk3pQ9xLm2Vb7TnR4sWd8Yh"', 'Token: "Zk3pQ9xLm2Vb7TnR4sWd8Yh"',
    'AUTH_SECRET = "Zk3pQ9xLm2Vb7TnR4sWd8Yh"', "x.apiKey = 'Zk3pQ9xLm2Vb7TnR4sWd8Yh'", 'password => "Zk3pQ9xLm2Vb7TnR4sWd8Yh"',
    "creds := `Zk3pQ9xLm2Vb7TnR4sWd8Yh`", 'secret_key=Zk3pQ9xLm2Vb7TnR4sWd8Yh', 'client_secret: Zk3pQ9xLm2Vb7TnR4sWd8Yh',
    'name = "hello world, plain text"', 'monkey = "abcdefghijklmnop"', 'keyboard = 1234567890123',
]


@pytest.mark.skipif(not _docker_ready(GITLEAKS_IMAGE), reason="gitleaks image is not built")
def test_the_widened_pattern_reports_everything_the_built_in_rule_reports(tmp_path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "battery.cpp").write_text("\n".join(_UPSTREAM_BATTERY) + "\n", encoding="utf-8")

    def lines(config: Path | None) -> set[int]:
        command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "1000:1000",
                   "--cap-drop", "ALL", "--tmpfs", "/tmp:rw,size=64m", "-e", "HOME=/tmp", "-v", f"{target}:/target:ro",
                   "-v", f"{GITLEAKS}:/rules-gitleaks:ro", "--entrypoint", "sh", GITLEAKS_IMAGE, "-c",
                   "gitleaks dir /target %s --no-banner --redact --report-format json --report-path /tmp/r.json "
                   "--exit-code 0 >/dev/null 2>&1; cat /tmp/r.json" % (f"--config {config}" if config else "")]
        output = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False).stdout
        return {item["StartLine"] for item in (json.loads(output) or []) if item["RuleID"] == "generic-api-key"}

    built_in = lines(None)
    assert built_in, "the battery no longer exercises the built-in rule"
    assert built_in <= lines(Path("/rules-gitleaks/generic-secrets.toml"))
