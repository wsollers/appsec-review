"""Repository-wide pytest safety checks."""

from __future__ import annotations

from pathlib import Path

import pytest


_REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
_PYTEST_SCRATCH_ROOT = (_REPOSITORY_ROOT / "test" / "tmp").resolve()


def _resolved_from_invocation(value: str | Path, invocation_dir: Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = invocation_dir / path
    return path.resolve()


def _require_pytest_scratch_path(*, option: str, value: str | Path, invocation_dir: Path) -> None:
    resolved = _resolved_from_invocation(value, invocation_dir)
    try:
        resolved.relative_to(_PYTEST_SCRATCH_ROOT)
    except ValueError as error:
        raise pytest.UsageError(
            f"{option} must stay under {_PYTEST_SCRATCH_ROOT}; received {resolved}. "
            "Use a unique test/tmp/<session-name> descendant for an isolated run."
        ) from error


def pytest_configure(config: pytest.Config) -> None:
    """Fail before tests can populate disposable directories outside test/tmp."""

    config.addinivalue_line(
        "markers",
        "requires_target(name): needs the local checkout targets/<name>; skipped when it is absent",
    )

    invocation_dir = Path(config.invocation_params.dir)
    basetemp = config.getoption("basetemp")
    if basetemp is None:
        raise pytest.UsageError("pytest requires the configured --basetemp=test/tmp")
    _require_pytest_scratch_path(
        option="--basetemp",
        value=basetemp,
        invocation_dir=invocation_dir,
    )
    # test/tmp is ignored, so a fresh checkout or worktree does not have it, and pytest
    # creates only the final --basetemp component. Create the validated parent here.
    _resolved_from_invocation(basetemp, invocation_dir).parent.mkdir(parents=True, exist_ok=True)
    # With ``-p no:cacheprovider`` the cache plugin never registers ``cache_dir`` and
    # writes no cache, so there is no location to police.
    if config.pluginmanager.has_plugin("cacheprovider"):
        _require_pytest_scratch_path(
            option="cache_dir",
            value=config.getini("cache_dir"),
            invocation_dir=_REPOSITORY_ROOT,
        )


def pytest_ignore_collect(collection_path: Path, config: pytest.Config) -> bool | None:
    """Keep implicit discovery on the fast paths; explicit selections remain on demand."""
    if config.args_source is not pytest.Config.ArgsSource.TESTPATHS:
        return None
    try:
        relative = collection_path.relative_to(_REPOSITORY_ROOT / "tests")
    except ValueError:
        return None
    if relative.parts and relative.parts[0] in {"integration", "live"}:
        return True
    if len(relative.parts) == 1 and collection_path.match("test_live_*.py"):
        return True
    return None


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Skip, with the reason, tests whose local review target checkout is absent."""

    for marker in item.iter_markers("requires_target"):
        name = marker.args[0]
        if not (_REPOSITORY_ROOT / "targets" / name).is_dir():
            pytest.skip(f"local review target checkout is absent: targets/{name}")
