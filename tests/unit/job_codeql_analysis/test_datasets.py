"""Every run-owned file job_codeql_analysis writes is claimed by exactly one of its dataset declarations."""
from __future__ import annotations

import pytest

from appsec_review.indexing.inventory import compile_glob
from appsec_review.jobs.job_codeql_analysis.datasets import DATASETS
from appsec_review.runtime.datasets import validate_declarations

A = "data/jobs/job_codeql_analysis/attempts/attempt_0001"
S = "data/codeql/scopes/codeql-unit-5991e47ff8fd0c7b6c705817"

# Paths observed on smoke-cpp run 2026-11-14-0005, the first run with a real C/C++ CodeQL scope; the two
# cache-initialization files were the publication audit's "unaccounted_file" violations (fault 15).
OBSERVED = [
    "data/codeql/cache-initialization/appsec-codeql-compile-68c7e693d38170f016750452.json",
    "data/codeql/cache-initialization/appsec-codeql-compile-68c7e693d38170f016750452.lock",
    f"{A}/artifacts/codeql/summary.json",
    f"{A}/artifacts/codeql/plan.json",
    f"{A}/steps/plan/tasks/inventory/inventory/extractor-inventory.json",
    f"{S}/scope.json",
    f"{S}/database/db-cpp/codeql-database.yml",
    f"{S}/workspace/src/main.cpp",
    f"{S}/executions/database/execution.json",
    f"{S}/queries/results.sarif",
    "data/codeql/predecessor-import.lock",
]


def _claimants(path: str) -> list[str]:
    return [item.output_kind for item in DATASETS
            for pattern in item.artifacts if compile_glob(pattern).fullmatch(path)]


def test_declarations_are_valid() -> None:
    validate_declarations("job_codeql_analysis", DATASETS)


@pytest.mark.parametrize("path", OBSERVED)
def test_every_run_owned_file_is_claimed_by_exactly_one_declaration(path: str) -> None:
    assert len(_claimants(path)) == 1, (path, _claimants(path))


def test_cache_initialization_is_bookkeeping_not_evidence() -> None:
    kinds = {item.output_kind: item for item in DATASETS}
    assert kinds["codeql_cache_initialization"].disposition == "artifact_only"
