"""Manual Unity capability -> build -> artifact -> telemetry acceptance.

This requires the same explicit provisioning as job_project_build/test_unity_project_builds.py.
It is not a unit test and must not be executed by a unit-only command.
"""

from __future__ import annotations

from pathlib import Path

from appsec_review.jobs.cataloging import inventory
from appsec_review.jobs.engine_discovery import discover_unity
from appsec_review.jobs.job_artifact_indexing import load_accepted_artifact_index
from appsec_review.jobs.job_dependency_intelligence.discovery import discover_native_dependencies
from appsec_review.jobs.job_dependency_intelligence.native_sbom_contracts import NativeBounds, SbomBounds
from appsec_review.jobs.job_dependency_intelligence.sbom import build_spdx, validate_spdx
from appsec_review.jobs.job_dependency_intelligence.unity import enrich_unity_spdx
from appsec_review.observability import aggregate_run_metrics
from appsec_review.storage import file_sha256
from tests.acceptance.job_project_build.test_unity_project_builds import run_provisioned_unity


def test_unity_outputs_reach_review_artifact_inventory_and_engine_metrics(tmp_path: Path) -> None:
    run_root, plan, project, language = run_provisioned_unity(tmp_path)
    receipt, = language["receipts"]
    assert receipt["engine"]["kind"] == "unity" and receipt["terminal_status"] == "SUCCEEDED"
    assert receipt["commands"] and receipt["artifacts"]
    for artifact in receipt["artifacts"]:
        assert file_sha256(run_root / artifact["path"]) == artifact["sha256"]
    indexed = load_accepted_artifact_index(run_root)
    assert indexed["source_fingerprint"] == language["source_fingerprint"]
    metrics = aggregate_run_metrics(run_root)["review"]["build_units"]
    assert metrics["discovered_by_engine"] == {"unity": 1}
    assert metrics["by_engine"]["unity"]["outcomes"] == {"SUCCEEDED": 1}
    assert plan["build_topology"]["build_actions"][0]["engine"]["declared_version"] == "2022.3.62f1"
    assert project["build_dispatches"] == []
    target = tmp_path / "target"
    snapshot = language["source_fingerprint"]
    def read_descriptor(descriptor, limit):
        with (target / descriptor["path"]).open("rb") as stream:
            return stream.read(limit + 1)

    unity = discover_unity(inventory(target)["files"], read_text=read_descriptor)
    native = discover_native_dependencies(
        source_fingerprint=snapshot, files=[], invocations=[], artifacts=[],
        read_file=lambda _record, _limit: b"",
        bounds=NativeBounds(100, 100, 100, 262144, 1048576, 100, 100, 100, 8192, 1024))
    bounds = SbomBounds(1_000_000, 10_000, 2_000_000, 8192)
    baseline = build_spdx(
        source_fingerprint=snapshot, created="2026-11-04T00:00:00Z", baselines=[],
        discovery=native, input_identities=[], bounds=bounds)
    document = enrich_unity_spdx(baseline, unity, source_fingerprint=snapshot, bounds=bounds)["document"]
    validate_spdx(document, bounds=bounds)
    builtin = next(item for item in document["packages"] if item["name"] == "com.unity.modules.physics")
    assert builtin["versionInfo"] == "1.0.0" and builtin["filesAnalyzed"] is False
    assert all("packageVerificationCode" not in item and "checksums" not in item
               for item in document["packages"])
    assert not any(item["relationshipType"] == "CONTAINS" for item in document["relationships"])
