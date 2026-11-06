"""Repository-wide pytest safety checks."""

from __future__ import annotations

from pathlib import Path
import os

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


class _TestTimings:
    """Stream every test's start, finish, phase durations and outcome into SQLite as it happens.

    The database sits beside ``--basetemp`` (pytest wipes the basetemp itself), and each row is
    committed immediately, so a stalled or killed session still shows the test that never finished.
    """

    def __init__(self, path: Path) -> None:
        import sqlite3
        import time

        self._clock = time.time
        self.path = path
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS test_timings (session_started REAL, pid INTEGER, nodeid TEXT, "
            "file TEXT, started REAL, finished REAL, duration_s REAL, setup_s REAL, call_s REAL, "
            "teardown_s REAL, outcome TEXT, PRIMARY KEY (session_started, nodeid))")
        self._session = self._clock()

    def start(self, nodeid: str, file: str) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO test_timings (session_started, pid, nodeid, file, started, outcome) "
            "VALUES (?, ?, ?, ?, ?, 'running')", (self._session, os.getpid(), nodeid, file, self._clock()))

    def report(self, report: pytest.TestReport) -> None:
        column = {"setup": "setup_s", "call": "call_s", "teardown": "teardown_s"}[report.when]
        outcome = "xfailed" if hasattr(report, "wasxfail") and report.skipped else report.outcome
        if report.when != "call" and report.failed:
            outcome = "error"
        self._db.execute(
            f"UPDATE test_timings SET {column} = ?, outcome = CASE "
            "WHEN outcome IN ('failed', 'error') THEN outcome "
            "WHEN ? = 'passed' AND outcome <> 'running' THEN outcome ELSE ? END "
            "WHERE session_started = ? AND nodeid = ?",
            (report.duration, outcome, outcome, self._session, report.nodeid))

    def finish(self, nodeid: str) -> None:
        self._db.execute(
            "UPDATE test_timings SET finished = ?, duration_s = ? - started "
            "WHERE session_started = ? AND nodeid = ?",
            (self._clock(), self._clock(), self._session, nodeid))

    def close(self) -> None:
        self._db.close()


_TIMINGS: _TestTimings | None = None


def pytest_sessionstart(session: pytest.Session) -> None:
    global _TIMINGS
    config = session.config
    if getattr(config.option, "collectonly", False):
        return
    basetemp = _resolved_from_invocation(config.getoption("basetemp"), Path(config.invocation_params.dir))
    _TIMINGS = _TestTimings(basetemp.parent / f"{basetemp.name}.timings.sqlite")


def pytest_runtest_logstart(nodeid: str, location: tuple[str, int | None, str]) -> None:
    if _TIMINGS is not None:
        _TIMINGS.start(nodeid, location[0])


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if _TIMINGS is not None:
        _TIMINGS.report(report)


def pytest_runtest_logfinish(nodeid: str, location: tuple[str, int | None, str]) -> None:
    if _TIMINGS is not None:
        _TIMINGS.finish(nodeid)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    global _TIMINGS
    if _TIMINGS is not None:
        _TIMINGS.close()
        _TIMINGS = None


_FIRST_TEST_MODULE = _REPOSITORY_ROOT / "tests" / "test_000_unit_environment_guard.py"


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Run the production-sizing guard before every other collected test.

    Path order alone does not do this: tests/orchestration/ sorts before tests/test_*.py.
    """
    first = [item for item in items if Path(str(item.path)).resolve() == _FIRST_TEST_MODULE]
    if first:
        items[:] = first + [item for item in items if Path(str(item.path)).resolve() != _FIRST_TEST_MODULE]


def pytest_ignore_collect(collection_path: Path, config: pytest.Config) -> bool | None:
    """Keep implicit discovery on the fast paths; explicit selections remain on demand."""
    if config.args_source is pytest.Config.ArgsSource.ARGS:
        return None
    try:
        relative = collection_path.relative_to(_REPOSITORY_ROOT / "tests")
    except ValueError:
        return None
    if relative.parts and relative.parts[0] in {"integration", "acceptance", "live"}:
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


@pytest.fixture(autouse=True)
def _no_telemetry_report_container(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run-completion hooks in unit tests never start the LaTeX report container.

    Integration and live tests keep the real renderer; tests of the renderer call it directly.
    """
    try:
        relative = Path(str(request.node.path)).resolve().relative_to(_REPOSITORY_ROOT / "tests")
    except ValueError:
        return
    if relative.parts and relative.parts[0] in {"integration", "live"} or relative.name.startswith("test_live_"):
        return
    from appsec_review.reporting import telemetry_finalize

    monkeypatch.setattr(telemetry_finalize, "render_telemetry_report", lambda *args, **kwargs: None)


@pytest.fixture
def acceptance_workspace(tmp_path: Path):
    """Use the supervisor's immutable workspace, or an isolated workspace for focused unit tests."""
    import json
    from appsec_review.acceptance.lanes import LaneWorkspace

    selected = os.environ.get("APPSEC_ACCEPTANCE_ROOT")
    if selected:
        root = Path(selected).resolve()
        owner = json.loads((root / "owner.json").read_text(encoding="utf-8"))
        workspace = LaneWorkspace(Path(owner["repository"]), root, owner["lane"], owner["invocation_id"])
        if workspace.runs_dir != Path(os.environ["APPSEC_ACCEPTANCE_RUNS_DIR"]).resolve():
            raise pytest.UsageError("acceptance job fixture must use invocation-owned runs_dir")
        return workspace
    return LaneWorkspace.create(tmp_path, "fixture")


@pytest.fixture
def acceptance_runs_dir(acceptance_workspace) -> Path:
    """Job fixtures must bind runtime.runs_dir here, never to the checkout's production runs."""
    return acceptance_workspace.runs_dir


class AcceptingRecordingImageVerifier:
    """Unit-test-only image verifier: accepts every image and records each verification."""

    enforced = False

    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def verify(self, image_id: str, *, reference: str | None = None) -> None:
        self.calls.append((image_id, reference))


_REAL_IMAGE_POLICY_DIRECTORIES = frozenset({"live", "integration", "acceptance"})


def _uses_real_image_policy(path: Path) -> bool:
    """Live, integration, and acceptance tests launch real images under the configured policy."""
    try:
        relative = path.resolve().relative_to(_REPOSITORY_ROOT / "tests")
    except ValueError:
        return False
    return (relative.parts[0] in _REAL_IMAGE_POLICY_DIRECTORIES
            or relative.name.startswith("test_live_") or "_live" in relative.stem)


@pytest.fixture(scope="module", autouse=True)
def _unit_test_module_image_verifier(request: pytest.FixtureRequest):
    """Install an accepting process-wide image verifier for unit tests that fake ``docker inspect``.

    Module scope, so module-scoped fixtures that launch fake builds also see it. Unit tests
    fabricate image IDs that no trust anchor has signed. Tests of signature enforcement must pass
    explicit verifiers (or install their own default) rather than rely on this one. Live,
    integration, and acceptance tests are left to the configured signing policy.
    """
    from appsec_review.signing.policy import set_default_image_verifier

    if _uses_real_image_policy(Path(str(request.node.path))):
        yield None
        return
    verifier = AcceptingRecordingImageVerifier()
    set_default_image_verifier(verifier)
    try:
        yield verifier
    finally:
        set_default_image_verifier(None)


@pytest.fixture(autouse=True)
def _unit_test_accepting_image_verifier(_unit_test_module_image_verifier):
    """Reinstall the module's accepting verifier for each test, with a fresh call record.

    A test that clears or replaces the process-wide default cannot leak that into later tests.
    """
    from appsec_review.signing.policy import set_default_image_verifier

    verifier = _unit_test_module_image_verifier
    if verifier is None:
        yield None
        return
    verifier.calls.clear()
    set_default_image_verifier(verifier)
    try:
        yield verifier
    finally:
        set_default_image_verifier(verifier)
