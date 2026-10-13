"""Installed deployments resolve repository-owned assets from their configured root."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from appsec_review.application_paths import application_asset, application_root, verify_runtime_assets


ROOT = Path(__file__).resolve().parents[1]


def test_configured_root_wins_over_python_package_location(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "installed-app"
    asset = root / "rules" / "example.json"
    asset.parent.mkdir(parents=True)
    asset.write_text("{}", encoding="utf-8")
    config = root / "appsec-review.toml"
    config.write_text("", encoding="utf-8")
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG", str(config))

    assert application_root("rules/example.json") == root
    assert application_asset("rules/example.json") == asset


@pytest.mark.parametrize("path", ("../secret", "/absolute", "rules/../../secret"))
def test_application_assets_reject_escaping_paths(path: str) -> None:
    with pytest.raises(ValueError, match="relative and contained"):
        application_root(path)


def test_required_runtime_asset_inventory_is_complete() -> None:
    verify_runtime_assets()


def test_graph_catalog_loads_from_an_installed_layout(tmp_path: Path) -> None:
    root = tmp_path / "installed-app"
    shutil.copytree(ROOT / "rules" / "codeql-graph-export", root / "rules" / "codeql-graph-export")
    config = root / "appsec-review.toml"
    config.write_text("", encoding="utf-8")
    environment = dict(os.environ)
    environment["APPSEC_REVIEW_CONFIG"] = str(config)
    environment["PYTHONPATH"] = str(ROOT / "src")
    command = (
        "from appsec_review.graph.catalog import CATALOG_SCHEMA_PATH, load_catalog; "
        "catalog = load_catalog(); print(CATALOG_SCHEMA_PATH); print(catalog.version)"
    )

    completed = subprocess.run(
        [sys.executable, "-c", command], cwd=tmp_path, env=environment,
        check=True, capture_output=True, text=True,
    )

    lines = completed.stdout.splitlines()
    assert Path(lines[0]) == root / "rules" / "codeql-graph-export" / "catalog.schema.json"
    assert lines[1] == "appsec-review/graph-catalog/1"
