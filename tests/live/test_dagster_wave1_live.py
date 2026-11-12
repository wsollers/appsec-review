"""The real wave-1 Dagster graph runs the application graph with every cataloged tool image.

Skips, naming each missing image, on hosts that cannot run the whole catalog. The graph-shape
checks that need no engine stay in ``tests/orchestration/dagster/test_definitions.py``.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import shutil
import subprocess

import pytest

dagster = pytest.importorskip("dagster")

from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.orchestration.dagster import adapter, build_definitions

ROOT = Path(__file__).resolve().parents[2]


def _missing_catalog_images() -> list[str]:
    """Tool images the full wave-1 graph needs that this host cannot run."""
    if shutil.which("docker") is None:
        return ["docker"]
    catalog = load_catalog(ROOT)
    missing = []
    for tool_id, tool in sorted(catalog.tools.items()):
        probe = subprocess.run(("docker", "image", "inspect", tool.tag), capture_output=True, timeout=60)
        if probe.returncode != 0:
            missing.append(tool_id)
    return missing


@pytest.mark.skipif(
    Path("/.dockerenv").exists() and not Path("/var/run/docker.sock").exists(),
    reason="the deployment-test container was not given a Docker engine",
)
def test_wave1_dagster_path_runs_application_graph(tmp_path: Path, monkeypatch) -> None:
    # The real wave-1 graph runs every cataloged tool image. Skip, naming what is missing,
    # rather than fail on hosts without the images.
    missing = _missing_catalog_images()
    if missing:
        pytest.skip("live wave-1 run needs local tool images: " + ", ".join(missing))
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))
    config = ROOT / "appsec-review.toml"
    # Keep run output under the test's temporary directory, never in the repository's runs/.
    load = adapter.load_config

    def isolated(source):
        loaded = load(source)
        runs = tmp_path / "runs"
        return replace(loaded, runtime=replace(loaded.runtime, runs_dir=runs, metadata_dir=runs / "metadata"))

    monkeypatch.setattr(adapter, "load_config", isolated)
    result = build_definitions(config).get_job_def("wave1_review").execute_in_process()
    assert result.success
    assert "evidence_collection__evidence_publication__assemble_manifest" in {
        node.name for node in build_definitions(config).get_job_def("wave1_review").graph.node_defs}
