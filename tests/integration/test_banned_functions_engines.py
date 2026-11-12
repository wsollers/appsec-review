"""Both pinned engines report the banned-function rules at their tier and nothing else.

Runs the generated ``rules/semgrep/banned-functions.yml`` in the local Semgrep and OpenGrep tool
images against the fixture. Skips, naming the gap, when Docker or an image is missing; the
table, generator and lock checks stay in ``tests/test_banned_functions.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from tests.test_banned_functions import FIXTURES, OPENGREP_IMAGE, ROOT, SEMGREP_IMAGE


def _docker_ready(*images: str) -> bool:
    if shutil.which("docker") is None:
        return False
    return all(subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0
               for image in images)


def _scan(image: str, entrypoint: str, extra: list[str], target: Path) -> list[tuple[str, int, str, str]]:
    rules = ROOT / "rules" / "semgrep"
    command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "1000:1000", "--cap-drop", "ALL",
               "--tmpfs", "/tmp:rw,size=256m", "-e", "HOME=/tmp", "-v", f"{target}:/target:ro",
               "-v", f"{rules}:/rules:ro", "--entrypoint", entrypoint, image,
               "scan", "--disable-version-check", *extra, "--config", "/rules/banned-functions.yml", "--json",
               "--quiet", "/target"]
    document = json.loads(subprocess.run(command, capture_output=True, text=True, timeout=300, check=False).stdout)
    assert not document.get("errors"), document["errors"][:2]
    return sorted((Path(item["path"]).name, item["start"]["line"], item["check_id"].rsplit("-", 1)[-1],
                   item["extra"]["severity"]) for item in document["results"])


@pytest.mark.skipif(not _docker_ready(SEMGREP_IMAGE, OPENGREP_IMAGE), reason="Semgrep and Opengrep images are not built")
@pytest.mark.parametrize("image, entrypoint, extra", [
    (SEMGREP_IMAGE, "/opt/tool/bin/semgrep", ["--metrics", "off"]),
    (OPENGREP_IMAGE, "/opt/tool/opengrep/opengrep.bin", []),
])
def test_both_engines_report_banned_calls_at_their_tier_and_nothing_else(image, entrypoint, extra, tmp_path) -> None:
    target = tmp_path / "target"
    shutil.copytree(FIXTURES, target)  # outside tests/, which Semgrep skips by default
    severity = {"high": "ERROR", "warning": "WARNING", "review": "INFO"}
    expected = sorted(("vulnerable.cpp", number, text.split("EXPECT ")[1].strip(), severity[text.split("EXPECT ")[1].strip()])
                      for number, text in enumerate((FIXTURES / "vulnerable.cpp").read_text(encoding="utf-8").splitlines(), 1)
                      if "EXPECT " in text)
    assert len(expected) == 14
    assert _scan(image, entrypoint, extra, target) == expected
