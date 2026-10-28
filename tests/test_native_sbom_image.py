from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_dependency_intelligence.integration import convert_syft, sbom_bounds
from appsec_review.observability import EventLog
from appsec_review.runtime import JobContext, UnitContext
from appsec_review.storage import atomic_json
from appsec_review.storage.shared import reference


ROOT = Path(__file__).parents[1]


def test_existing_syft_image_converts_and_enriches_spdx(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("SPDX image validation unavailable: Docker is not installed")
    probe = subprocess.run(["docker", "image", "inspect", "appsec-review/tool-syft:1.52.0"],
                           capture_output=True, timeout=30, check=False)
    if probe.returncode:
        pytest.skip("SPDX image validation unavailable: Docker daemon or pinned Syft image is missing")
    from appsec_review.jobs.job_dependency_intelligence.sbom import build_spdx, validate_spdx
    config = load_config(ROOT / "appsec-review.toml")
    root = tmp_path / "run"
    root.mkdir()
    attempt = root / "data" / "jobs" / "job_dependency_intelligence" / "attempts" / "attempt_0001"
    unit_root = attempt / "steps" / "publication" / "tasks" / "publish_sbom"
    unit_root.mkdir(parents=True)
    source = root / "syft.json"
    atomic_json(source, {
        "artifacts": [], "artifactRelationships": [], "descriptor": {"name": "syft", "version": "1.52.0"},
        "source": {"id": "test", "name": "native-spdx-smoke", "version": "", "type": "directory",
                   "metadata": {"path": "/target"}},
        "schema": {"version": "16.1.10", "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.10.json"},
    })
    events = EventLog(attempt / "events.jsonl")
    context = JobContext(
        run_id="run", attempt_id="attempt_0001", trigger="test", repository_root=ROOT,
        run_root=root, attempt_root=attempt, metadata_root=tmp_path / "metadata",
        orchestration={}, config=config.jobs["job_dependency_intelligence"], events=events,
        source_fingerprint="f" * 64,
    )
    unit = UnitContext(context, "publication.publish_sbom", "publication", "publish_sbom", unit_root, {})
    baseline = convert_syft(reference(root, source), unit=unit)
    assert baseline["document"]["spdxVersion"] == "SPDX-2.3"
    validate_spdx(baseline["document"], bounds=sbom_bounds(context.config.settings))
    result = build_spdx(
        source_fingerprint="f" * 64, created="2026-10-28T00:00:00Z", baselines=[baseline],
        discovery={"schema": "appsec-review/native-discovery/1", "candidates": [], "evidence": [],
                   "gaps": [], "coverage": {}, "metrics": {}},
        input_identities=[reference(root, source)], bounds=sbom_bounds(context.config.settings),
    )
    validate_spdx(result["document"], bounds=sbom_bounds(context.config.settings))
    assert result["document"]["spdxVersion"] == "SPDX-2.3"
    assert baseline["tool_identity"]["image_id"].startswith("sha256:")
    conversion = json.loads((unit_root / "conversion.json").read_bytes())
    receipt = json.loads((root / conversion["execution"]["path"]).read_bytes())
    assert receipt["image_id"] == baseline["tool_identity"]["image_id"]
    assert receipt["exit_code"] == 0
