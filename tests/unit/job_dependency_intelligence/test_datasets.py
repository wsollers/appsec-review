"""Every file dependency_intelligence publishes is claimed by one of its dataset declarations."""
from __future__ import annotations

import pytest

from appsec_review.indexing.inventory import compile_glob
from appsec_review.jobs.job_dependency_intelligence.datasets import DATASETS
from appsec_review.runtime.datasets import validate_declarations

A = "data/jobs/job_dependency_intelligence/attempts/attempt_0003"
H = "a" * 64

# Every path shape the publication audit reported as unaccounted in smoke-cpp run 2026-11-14-0001
# (dispatch 629d4db5, 137 violations), plus the files the existing declarations already claimed.
OBSERVED = [
    f"{A}/steps/inputs/tasks/load_accepted/protected-native-inputs.json",
    f"{A}/steps/inputs/tasks/load_accepted/unity-inventory.json",
    f"{A}/steps/resolution/tasks/detect_dependencies/native-discovery.json",
    f"{A}/steps/resolution/tasks/curate_components/native-discovery.json",
    f"{A}/steps/resolution/tasks/curate_components/model-artifacts.json",
    f"{A}/steps/resolution/tasks/curate_components/native-inference.json",
    f"{A}/steps/resolution/tasks/curate_components/native-inference-metrics.json",
    f"{A}/steps/resolution/tasks/investigate_components/native-discovery.json",
    f"{A}/steps/resolution/tasks/investigate_components/model-artifacts.json",
    f"{A}/steps/resolution/tasks/investigate_components/native-inference.json",
    f"data/native-inference/unit-{H}/{H}/attempt-000002/request.json",
    f"data/native-inference/unit-{H}/{H}/attempt-000002/response.json",
    f"data/native-inference/unit-{H}/{H}/attempt-000002/attempt.json",
    f"data/native-sbom/{H}/syft.json",
    f"data/native-sbom/{H}/conversion/execution.json",
    f"data/native-sbom/{H}/conversion/raw/stdout.bin",
    f"data/native-sbom/{H}/conversion/raw/stderr.bin",
    f"{A}/steps/publication/tasks/publish_sbom/conversion.json",
    f"{A}/steps/publication/tasks/publish_sbom/native-sbom-provenance.json",
    f"{A}/steps/publication/tasks/publish_sbom/native-sbom-metrics.json",
    f"{A}/steps/publication/tasks/publish_sbom/baseline.spdx.json",
    f"{A}/steps/acceptance/tasks/publish_handoff/dependency-intelligence.json",
]


def _claimants(path: str) -> list[str]:
    return [item.output_kind for item in DATASETS
            for pattern in item.artifacts if compile_glob(pattern).fullmatch(path)]


def test_declarations_are_valid() -> None:
    validate_declarations("job_dependency_intelligence", DATASETS)


@pytest.mark.parametrize("path", OBSERVED)
def test_every_published_file_is_claimed_by_exactly_one_declaration(path: str) -> None:
    assert len(_claimants(path)) == 1, (path, _claimants(path))


def test_raw_model_and_tool_streams_are_protected() -> None:
    kinds = {item.output_kind: item for item in DATASETS}
    for kind in ("native_inputs", "native_inference_io", "native_sbom_conversion"):
        assert kinds[kind].disposition == "protected", kind
