from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tomllib

import pytest

from appsec_review.container_runtime.catalog import load_catalog


ROOT = Path(__file__).resolve().parents[1]
REPORT_MANIFEST = "containers/report/latex/tool.toml"


def _matches(parts: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    if not pattern:
        return not parts
    if pattern[0] == "**":
        return (_matches(parts, pattern[1:])
                or bool(parts) and _matches(parts[1:], pattern))
    return (bool(parts) and fnmatchcase(parts[0], pattern[0])
            and _matches(parts[1:], pattern[1:]))


def _included(path: str, rules: str) -> bool:
    """Model ordered Docker exclusions, including matches on parent directories."""
    parts = PurePosixPath(path).parts
    included = True
    for line in rules.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line == ".":
            continue
        negate = line.startswith("!")
        pattern = line.removeprefix("!").strip("/")
        # Keep this bounded model honest if the repository adopts more complex syntax.
        assert not any(char in pattern for char in "\\[]?"), pattern
        if any(_matches(parts[:end], tuple(pattern.split("/")))
               for end in range(1, len(parts) + 1)):
            included = negate
    return included


def _enabled_tools() -> list[dict]:
    document = tomllib.loads((ROOT / "containers/catalog.toml").read_text(encoding="utf-8"))
    return [image for image in document["images"]
            if image.get("state") == "enabled" and image.get("kind") == "tool"]


def _stage_catalog(root: Path, rules: str) -> None:
    document = tomllib.loads((ROOT / "containers/catalog.toml").read_text(encoding="utf-8"))
    paths = {"containers/catalog.toml", document["runtime_policy"],
             *(image["tool_manifest"] for image in _enabled_tools())}
    for relative in sorted(paths):
        if _included(relative, rules):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)


@pytest.mark.parametrize(("path", "rules", "included"), [
    ("containers/report/latex/tool.toml", "containers/**", False),
    ("containers/report/latex/tool.toml", "containers/**\n!containers/tools/*/tool.toml", False),
    ("containers/tools/git/nested/tool.toml", "containers/**\n!containers/tools/*/tool.toml", False),
    ("containers/report/latex/tool.toml", "containers/**\n!containers/**/tool.toml", True),
    ("containers/report/latex/tool.toml", "containers\n!containers/report/latex/tool.toml", True),
    ("containers/report/latex/tool.toml", "!containers/**/tool.toml\ncontainers/**", False),
    ("containers/tools/git/downloads/archive.tar", "containers/**\n!containers/tools/*/\n"
     "containers/tools/*/**\n!containers/tools/*/tool.toml", False),
])
def test_build_context_rule_matching(path: str, rules: str, included: bool) -> None:
    assert _included(path, rules) is included


def test_packaged_runtime_catalog_loads_every_enabled_manifest(tmp_path: Path) -> None:
    rules = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    _stage_catalog(tmp_path, rules)
    catalog = load_catalog(tmp_path)
    expected = {image["id"]: image for image in _enabled_tools()}
    assert set(catalog.tools) == set(expected)
    assert expected["tool-report-latex"]["manual"] is True
    for tool_id, image in expected.items():
        tool = catalog.tool(tool_id)
        assert tool.manifest_path == tmp_path / image["tool_manifest"]
        assert tool.expected_image_id == image.get("image_id")
        assert tool.version == image["version"]


def test_original_context_omission_reproduces_missing_report(tmp_path: Path) -> None:
    rules = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    _stage_catalog(tmp_path, rules + "\ncontainers/report/**\n")
    assert not (tmp_path / REPORT_MANIFEST).exists()
    with pytest.raises(FileNotFoundError, match="report"):
        load_catalog(tmp_path)


@pytest.mark.parametrize("manifest", [image["tool_manifest"] for image in _enabled_tools()])
def test_packaged_catalog_rejects_any_missing_enabled_manifest(tmp_path: Path, manifest: str) -> None:
    _stage_catalog(tmp_path, (ROOT / ".dockerignore").read_text(encoding="utf-8"))
    (tmp_path / manifest).unlink()
    with pytest.raises(FileNotFoundError, match="tool.toml"):
        load_catalog(tmp_path)


def test_report_build_assets_stay_out_of_runtime_context() -> None:
    rules = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    for relative in ("Dockerfile", "acquire_assets.sh", "assets.lock.json",
                     "packages.manifest", "render-pdf.sh", "template/report.tex",
                     "downloads/texlive.tar.gz"):
        assert not _included(f"containers/report/latex/{relative}", rules), relative
    assert _included(REPORT_MANIFEST, rules)


def test_shared_runtime_build_checks_packaged_catalog(tmp_path: Path) -> None:
    assert not (ROOT / "deploy/dagster/Dockerfile.dockerignore").exists()
    dockerfile = (ROOT / "deploy/dagster/Dockerfile").read_text(encoding="utf-8")
    runtime = dockerfile.split(" AS runtime-base\n", 1)[1].split("\nFROM ", 1)[0]
    assert "WORKDIR /opt/app\n" in runtime
    command, = [command for command in re.findall(r'python -c "([^"]+)"', runtime)
                if "appsec_review.container_runtime.catalog" in command]
    assert runtime.index("COPY containers ./containers") < runtime.index(command)
    for stage in ("runtime", "runtime-copilot-base", "runtime-windows-base", "test"):
        assert f"FROM runtime-base AS {stage}\n" in dockerfile
    assert "FROM runtime-copilot-base AS runtime-copilot\n" in dockerfile
    assert "FROM runtime-windows-base AS runtime-windows\n" in dockerfile
    _stage_catalog(tmp_path, (ROOT / ".dockerignore").read_text(encoding="utf-8"))
    completed = subprocess.run(
        [sys.executable, "-c", command], cwd=tmp_path, capture_output=True, text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    (tmp_path / REPORT_MANIFEST).unlink()
    failed = subprocess.run(
        [sys.executable, "-c", command], cwd=tmp_path, capture_output=True, text=True,
        timeout=30,
    )
    assert failed.returncode != 0
    assert "FileNotFoundError" in failed.stderr and "tool.toml" in failed.stderr
