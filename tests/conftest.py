"""Repository-wide pytest safety checks."""

from __future__ import annotations

from pathlib import Path
import os

import pytest

from tests import time_budgets


_REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
_TIER_BUDGETS = pytest.StashKey[dict]()
_PHASE_CLOCK = pytest.StashKey[time_budgets.PhaseClock]()
_PYTEST_SCRATCH_ROOT = (_REPOSITORY_ROOT / "test" / "tmp").resolve()
_HOST_PINS_PREVIOUS = pytest.StashKey[str | None]()


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
    config.addinivalue_line("markers", time_budgets.MARKER_HELP)
    config.stash[_TIER_BUDGETS] = time_budgets.tier_budgets(config.getini)

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
    if not any(_uses_real_image_policy(Path(arg.split("::", 1)[0])) for arg in config.args):
        from appsec_review.config.host_pins import HOST_PINS_ENV
        from tests.host_pins_support import fixture_preinstalled, write_host_pins
        previous = os.environ.get(HOST_PINS_ENV)
        if previous is not None and not Path(previous).resolve().is_relative_to(_PYTEST_SCRATCH_ROOT):
            raise pytest.UsageError(f"unit tests must not inherit production {HOST_PINS_ENV}")
        config.stash[_HOST_PINS_PREVIOUS] = previous
        base = _resolved_from_invocation(basetemp, invocation_dir)
        pins = write_host_pins(base.parent / f"{base.name}.host-pins.toml", runtimes=fixture_preinstalled())
        os.environ[HOST_PINS_ENV] = str(pins)


def pytest_unconfigure(config: pytest.Config) -> None:
    if _HOST_PINS_PREVIOUS in config.stash:
        from appsec_review.config.host_pins import HOST_PINS_ENV
        previous = config.stash[_HOST_PINS_PREVIOUS]
        if previous is None:
            os.environ.pop(HOST_PINS_ENV, None)
        else:
            os.environ[HOST_PINS_ENV] = previous


SLOW_TEST_SECONDS = 10.0


class _TestTimings:
    """Stream every test's start, finish, phase durations, worker and outcome into SQLite.

    The database sits beside ``--basetemp`` (pytest wipes the basetemp itself), and each row is
    committed immediately, so a stalled or killed session still shows the test that never finished.
    Only the controlling process writes: under pytest-xdist it receives every worker's events.
    ``duration_s`` is the sum of the test's own setup, call and teardown phases.
    """

    def __init__(self, path: Path) -> None:
        import sqlite3
        import time

        self._clock = time.time
        self.path = path
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS test_timings (session_started REAL, pid INTEGER, worker TEXT, "
            "nodeid TEXT, file TEXT, started REAL, finished REAL, duration_s REAL, setup_s REAL, "
            "call_s REAL, teardown_s REAL, outcome TEXT, PRIMARY KEY (session_started, nodeid))")
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
        gateway = getattr(getattr(report, "node", None), "gateway", None)
        worker = getattr(gateway, "id", None) or "main"
        self._db.execute(
            f"UPDATE test_timings SET {column} = ?, worker = ?, outcome = CASE "
            "WHEN outcome IN ('failed', 'error') THEN outcome "
            "WHEN ? = 'passed' AND outcome <> 'running' THEN outcome ELSE ? END "
            "WHERE session_started = ? AND nodeid = ?",
            (report.duration, worker, outcome, outcome, self._session, report.nodeid))

    def finish(self, nodeid: str) -> None:
        self._db.execute(
            "UPDATE test_timings SET finished = ?, "
            "duration_s = COALESCE(setup_s, 0) + COALESCE(call_s, 0) + COALESCE(teardown_s, 0) "
            "WHERE session_started = ? AND nodeid = ?",
            (self._clock(), self._session, nodeid))

    def slower_than(self, seconds: float) -> list[tuple[str, float, str]]:
        return self._db.execute(
            "SELECT nodeid, duration_s, outcome FROM test_timings WHERE session_started = ? "
            "AND duration_s > ? ORDER BY duration_s DESC", (self._session, seconds)).fetchall()

    def close(self) -> None:
        self._db.close()


_TIMINGS: _TestTimings | None = None


def _is_xdist_worker(config: pytest.Config) -> bool:
    return hasattr(config, "workerinput")


def _is_xdist_controller(config: pytest.Config) -> bool:
    return not _is_xdist_worker(config) and getattr(config.option, "dist", "no") != "no"


def _environment_guard_preflight() -> None:
    """Under pytest-xdist no single test runs first, so check the guard before any worker starts."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("_unit_environment_guard_preflight", _FIRST_TEST_MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        module.test_unit_session_does_not_inherit_production_sizing()
    except AssertionError as error:
        pytest.exit(f"unit environment guard failed before starting workers:\n{error}", returncode=1)


@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session: pytest.Session) -> None:
    global _TIMINGS
    config = session.config
    if getattr(config.option, "collectonly", False) or _is_xdist_worker(config):
        return
    if _is_xdist_controller(config) and _FIRST_TEST_MODULE.is_file():
        _environment_guard_preflight()
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


def pytest_terminal_summary(terminalreporter, exitstatus: int, config: pytest.Config) -> None:
    """Flag every test whose own setup, call and teardown took longer than SLOW_TEST_SECONDS."""
    if _TIMINGS is None:
        return
    slow = _TIMINGS.slower_than(SLOW_TEST_SECONDS)
    terminalreporter.section(f"tests slower than {SLOW_TEST_SECONDS:g}s: {len(slow)}")
    for nodeid, seconds, outcome in slow:
        terminalreporter.write_line(f"{seconds:8.2f}s {outcome:<8} {nodeid}")
    terminalreporter.write_line(f"timings: {_TIMINGS.path}")


def pytest_unconfigure(config: pytest.Config) -> None:
    # Not sessionfinish: the terminal summary that lists slow tests runs inside sessionfinish.
    global _TIMINGS
    if _TIMINGS is not None:
        _TIMINGS.close()
        _TIMINGS = None


_FIRST_TEST_MODULE = _REPOSITORY_ROOT / "tests" / "test_000_unit_environment_guard.py"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--shuffle-seed", type=int, default=None, metavar="SEED",
        help="run collected tests in an order shuffled by SEED to expose order-dependent tests; "
             "rerun with the same SEED to reproduce. Every pytest-xdist worker uses the same order.")
    for tier, name in time_budgets.TIER_INI_OPTIONS.items():
        parser.addini(name, f"per-test time budget in seconds for the {tier} tier (setup, call and teardown)",
                      default=f"{time_budgets.DEFAULT_TIER_BUDGETS[tier]:g}")


def pytest_report_header(config: pytest.Config) -> str | None:
    seed = config.getoption("shuffle_seed")
    return None if seed is None else f"test order shuffled with --shuffle-seed={seed}"


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Optionally shuffle, then run the production-sizing guard before every other collected test.

    Path order alone does not do this: tests/orchestration/ sorts before tests/test_*.py.
    """
    seed = config.getoption("shuffle_seed")
    if seed is not None:
        import random

        random.Random(seed).shuffle(items)
    first = [item for item in items if Path(str(item.path)).resolve() == _FIRST_TEST_MODULE]
    if first:
        items[:] = first + [item for item in items if Path(str(item.path)).resolve() != _FIRST_TEST_MODULE]
    budgets = config.stash[_TIER_BUDGETS]
    for item in items:
        budget = time_budgets.budget_for(
            item.nodeid, time_budgets.tier_of(Path(str(item.path)), _REPOSITORY_ROOT / "tests"),
            item.get_closest_marker(time_budgets.MARKER), budgets)
        if budget is not None:
            item.stash[_PHASE_CLOCK] = time_budgets.PhaseClock(budget)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):
    """Fail an integration or live test that overruns its declared time budget."""
    report = yield
    clock = item.stash.get(_PHASE_CLOCK, None)
    if clock is not None:
        clock.observe(report)
    return report


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
    return (bool(relative.parts) and relative.parts[0] in _REAL_IMAGE_POLICY_DIRECTORIES
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
