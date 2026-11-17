"""Every run-owned file job_code_graph_index writes is claimed by exactly one of its dataset declarations."""
from __future__ import annotations

import pytest

from appsec_review.indexing.inventory import compile_glob
from appsec_review.jobs.job_code_graph_index.datasets import DATASETS
from appsec_review.runtime.datasets import validate_declarations

A = "data/jobs/job_code_graph_index/attempts/attempt_0001/steps"
S = "data/code-graph/scopes/codeql-unit-5991e47ff8fd0c7b6c705817"

# Paths observed on smoke-cpp run 2026-11-14-0005 plus the scorecard the job publishes since T-5016.
OBSERVED = [
    f"{A}/load/tasks/accepted_inputs/code-graph-inputs.json",
    f"{A}/acceptance/tasks/publish_handoff/code-graph-summary.json",
    f"{A}/acceptance/tasks/publish_handoff/graph-quality-scorecard.json",
    f"{A}/acceptance/tasks/publish_handoff/graph-quality-scorecard.txt",
    f"{S}/work/normalized.json",
    f"{S}/work/crosschecked.json",
    f"{S}/checkpoint.json",
    f"{A}/acceptance/tasks/publish_handoff/alternate-cpg-summary.json",
    "data/code-graph/alternate-cpg/cpg-nodes.jsonl",
    "data/code-graph/alternate-cpg/cpg-edges.jsonl",
    "data/code-graph/alternate-cpg/cpg-paths.jsonl",
]


def _claimants(path: str) -> list[str]:
    return [item.output_kind for item in DATASETS
            for pattern in item.artifacts if compile_glob(pattern).fullmatch(path)]


def test_declarations_are_valid() -> None:
    validate_declarations("job_code_graph_index", DATASETS)


@pytest.mark.parametrize("path", OBSERVED)
def test_every_run_owned_file_is_claimed_by_exactly_one_declaration(path: str) -> None:
    assert len(_claimants(path)) == 1, (path, _claimants(path))


def test_the_scorecard_is_an_artifact_only_measurement_with_its_closed_schema() -> None:
    kinds = {item.output_kind: item for item in DATASETS}
    scorecard = kinds["code_graph_scorecard"]
    assert scorecard.disposition == "artifact_only" and scorecard.schema == "appsec-review/graph-quality-scorecard/1"
    assert scorecard.step == "acceptance" and "not evidence" in scorecard.reason
