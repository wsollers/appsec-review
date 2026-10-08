from __future__ import annotations

from pathlib import Path

import pytest

from tests import conftest


def test_pytest_scratch_path_accepts_designated_tree() -> None:
    conftest._require_pytest_scratch_path(
        option="--basetemp",
        value="test/tmp/focused-run",
        invocation_dir=conftest._REPOSITORY_ROOT,
    )


@pytest.mark.parametrize(
    "value",
    [".pytest-focused", "test/tmp-focused", "test/tmp/../escaped", Path("t")],
)
def test_pytest_scratch_path_rejects_repository_pollution(value: str | Path) -> None:
    with pytest.raises(pytest.UsageError, match="must stay under"):
        conftest._require_pytest_scratch_path(
            option="--basetemp",
            value=value,
            invocation_dir=conftest._REPOSITORY_ROOT,
        )
