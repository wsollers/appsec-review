from threading import Event, Lock
from pathlib import Path
import time
import json
import pytest

from appsec_review.codeql.scheduler import ready_scopes
from appsec_review.config.assurance import ResourceBudget
from appsec_review.observability import EventLog
from appsec_review.runtime.resources import Reservation, ResourceAdmission


def test_ready_query_precedes_slowest_database_and_output_is_stable():
    queried = Event()
    def database(scope):
        if scope == "slow":
            assert queried.wait(5), "query was held behind the slow database"
        return {"scope": scope}
    def query(value, profile):
        queried.set()
        return {**value, "profile": profile}
    result = ready_scopes(
        ["slow", "fast"], concurrency=2, database=database,
        profiles=lambda value: ["default"], query=query,
        normalize=lambda value: value, export=lambda value: value,
    )
    assert [item["scope"] for item in result["normalize"]] == ["slow", "fast"]


def test_aggregate_admission_limits_mixed_thread_actions(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    admission = ResourceAdmission(tmp_path, ResourceBudget(cpu=4, memory_mb=100, staging_memory_mb=1))
    events = EventLog(tmp_path / "events.jsonl")
    lock = Lock()
    active = [0]
    peaks = []
    def action(memory):
        with admission.reserve(Reservation(2, memory), events=events, action="fixture"):
            with lock:
                active[0] += memory
                peaks.append(active[0])
            time.sleep(0.02)
            with lock:
                active[0] -= memory
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(action, [60, 60, 40]))
    assert max(peaks) <= 100
    assert active == [0]


def test_unconfirmed_container_keeps_reservation_until_explicit_reconciliation(tmp_path):
    from appsec_review.observability import PipelineLog, aggregate_run_metrics
    from appsec_review.runtime.resources import track_container
    admission = ResourceAdmission(tmp_path, ResourceBudget(cpu=4, memory_mb=100, staging_memory_mb=1))
    events = EventLog(tmp_path / "events.jsonl", PipelineLog(tmp_path), {"run_id": tmp_path.name})
    with admission.reserve(Reservation(2, 60), events=events, action="fixture") as lease:
        track_container("fixture-container")
    state = json.loads((admission.root / "leases.json").read_text())
    assert state["leases"][lease]["containers"] == ["fixture-container"]
    assert state["leases"][lease]["quarantine"] == "container_death_unconfirmed"
    with pytest.raises(TimeoutError):
        with admission.reserve(Reservation(2, 60), events=events, action="blocked", timeout_seconds=0,
                               unit_id="execution.scopes", scope_id="scope-blocked",
                               query_profile="security"):
            pytest.fail("quarantined resources must not be overcommitted")
    admitted, timeout = aggregate_run_metrics(tmp_path)["resource_admissions"]
    assert admitted["resource_lease_id"] == lease and admitted["status"] == "ADMITTED"
    assert timeout["status"] == "TIMED_OUT" and timeout["resource_lease_id"] != lease
    assert timeout["unit_id"] == "execution.scopes" and timeout["scope_id"] == "scope-blocked"
    assert timeout["query_profile"] == "security" and timeout["queue_delay_ms"] >= 0
    assert timeout["reason"] == "admission_timeout_or_unreconciled_lease"
    assert admission.reconcile(lambda name: True) == []
    assert admission.reconcile(lambda name: name == "fixture-container",
                               confirmed_cleanup=lambda entry: True) == [lease]


def test_dead_launcher_reconciliation_checks_process_start_and_container(tmp_path, monkeypatch):
    from appsec_review.runtime import resources
    admission = ResourceAdmission(tmp_path, ResourceBudget(cpu=4, memory_mb=100, staging_memory_mb=1))
    events = EventLog(tmp_path / "events.jsonl")
    with admission.reserve(Reservation(2, 60), events=events, action="fixture") as lease:
        resources.track_container("fixture-orphan")
    path = admission.root / "leases.json"
    state = json.loads(path.read_text())
    entry = state["leases"][lease]
    entry.pop("owner_finished")
    entry.pop("quarantine")
    path.write_text(json.dumps(state))
    monkeypatch.setattr(resources, "process_identity", lambda pid: "reused-pid-different-start")
    assert admission.reconcile(lambda name: False) == []
    assert admission.reconcile(lambda name: True) == [lease]


def test_confirmed_container_death_releases_lease_on_action_failure(tmp_path):
    from appsec_review.runtime.resources import track_container, container_stopped
    admission = ResourceAdmission(tmp_path, ResourceBudget(cpu=4, memory_mb=100, staging_memory_mb=1))
    events = EventLog(tmp_path / "events.jsonl")
    with pytest.raises(RuntimeError):
        with admission.reserve(Reservation(2, 60), events=events, action="fixture"):
            track_container("fixture-container")
            container_stopped("fixture-container")
            raise RuntimeError("producer failed")
    assert json.loads((admission.root / "leases.json").read_text())["leases"] == {}


def _executor(tmp_path, runner):
    from types import SimpleNamespace
    from appsec_review.codeql.runtime import CodeQLExecutor, CodeQLImage, IMAGE_SCHEMA
    image_id = "sha256:" + "a" * 64
    image = CodeQLImage(IMAGE_SCHEMA, "fixture", image_id, image_id, "build:fixture",
                        image_id, "codeql:fixture", "10001:10001", "codeql-1", "runner-1",
                        False, "manifest.json")
    settings = SimpleNamespace(inventory_timeout_seconds=30, database_timeout_seconds=30,
                               query_timeout_seconds=30, output_bytes=1024, threads=2, ram_mb=1024)
    return CodeQLExecutor(image=image, run_root=tmp_path / "run", settings=settings, runner=runner)


@pytest.mark.parametrize("action", ["database", "export"])
@pytest.mark.parametrize("confirmed_stopped", [False, True])
def test_initialization_timeout_tracks_and_bounds_helpers_without_silent_fallback(
        tmp_path, action, confirmed_stopped):
    calls = []
    def runner(argv, timeout):
        calls.append(tuple(argv))
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, ("sha256:" + "a" * 64).encode(), b"", False
        if "chown" in argv:
            return None, b"", b"fixture timeout", True
        if argv[:3] == ("docker", "rm", "--force"):
            return (0 if confirmed_stopped else 1), b"", b"removal failed", False
        if argv[:3] == ("docker", "container", "inspect"):
            return 0, b"true", b"", False
        return 0, b"generation-1", b"", False
    executor = _executor(tmp_path, runner)
    (executor.run_root / "scratch" / "export").mkdir(parents=True)
    admission = ResourceAdmission(tmp_path, ResourceBudget(cpu=2, memory_mb=4096))
    expected = "initialization failed" if confirmed_stopped else "death is unconfirmed"
    with pytest.raises(RuntimeError, match=expected):
        with admission.reserve(Reservation(2, 2560), events=EventLog(tmp_path / "events.jsonl"),
                               action=action):
            executor.execute(action, ("--database", "database"), scratch_root=executor.run_root / "scratch")
    [helper] = [call for call in calls if "chown" in call]
    name = helper[helper.index("--name") + 1]
    assert helper[helper.index("--cpus") + 1] == "1"
    assert helper[helper.index("--memory") + 1] == "128m"
    assert helper[helper.index("--pids-limit") + 1] == "64"
    assert "-R" not in helper
    assert not any("/opt/appsec/codeql_runner.py" in call for call in calls)
    leases = json.loads((admission.root / "leases.json").read_text())["leases"]
    if confirmed_stopped:
        assert leases == {}
    else:
        [lease] = leases.values()
        assert lease["containers"] == [name]
        assert lease["quarantine"] == "codeql_container_death_unconfirmed"
    assert not list(executor.run_root.glob("data/codeql/cache-initialization/*.json"))
    assert not (executor.run_root / "scratch").stat().st_mode & 0o002


def test_compile_cache_initialization_is_single_flight_and_recreated_volume_is_not_trusted(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    calls = []
    generation = ["generation-1"]
    def runner(argv, timeout):
        calls.append(tuple(argv))
        if "chown" in argv:
            time.sleep(0.02)
        return 0, generation[0].encode(), b"", False
    executor = _executor(tmp_path, runner)
    with ThreadPoolExecutor(max_workers=2) as pool:
        volumes = list(pool.map(executor._compile_cache, ["10001:10001", "10001:10001"]))
    assert volumes[0] == volumes[1]
    assert len([call for call in calls if "chown" in call]) == 1
    generation[0] = "generation-2"
    assert executor._compile_cache("10001:10001") == volumes[0]
    assert len([call for call in calls if "chown" in call]) == 2


def test_compile_cache_requires_declarations_and_is_run_private(tmp_path):
    from dataclasses import replace
    from appsec_review.codeql.runtime import compile_cache_volume
    def forbidden(argv, timeout):
        pytest.fail("missing releases must not inspect or initialize a compile cache")
    executor = _executor(tmp_path, forbidden)
    image = executor.image
    first = compile_cache_volume(image, executor.run_root)
    assert first != compile_cache_volume(image, tmp_path / "other-run")
    assert first != compile_cache_volume(replace(image, component_release_id="codeql-2"), executor.run_root)
    executor.image = replace(image, component_release_id=None)
    assert executor._compile_cache("10001:10001") is None


def test_compile_cache_creation_failure_is_not_a_silent_cold_cache_fallback(tmp_path):
    executor = _executor(tmp_path, lambda argv, timeout: (1, b"", b"volume unavailable", False))
    with pytest.raises(RuntimeError, match="could not be created"):
        executor._compile_cache("10001:10001")


@pytest.mark.parametrize("action", ["database", "query"])
@pytest.mark.parametrize("removed", [False, True])
def test_native_codeql_uses_private_bind_scratch_without_root_volume_helpers(
        tmp_path, monkeypatch, action, removed):
    from appsec_review.container_runtime.native_commands import NativeRun, parse_native_command
    from appsec_review.runtime.resources import review_resource_scope

    monkeypatch.setenv("APPSEC_NATIVE_DEPLOYMENT_ID", "fixture")
    calls, scratch_paths = [], []
    image_id = "sha256:" + "a" * 64
    executor = None

    def runner(argv, timeout):
        calls.append(tuple(argv))
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, image_id.encode(), b"", False
        if "/opt/appsec/codeql_runner.py" in argv:
            parsed = parse_native_command(argv)
            assert isinstance(parsed, NativeRun)
            database = next(mount for mount in parsed.mounts if mount.target == "/scratch/database")
            path = Path(database.source)
            scratch_paths.append(path)
            assert path.is_dir() and not path.stat().st_mode & 0o077
            assert "--staged-database" in parsed.arguments
            assert int(parsed.user.split(":")[0]) != 0
            if action == "query":
                assert any(mount.target == "/source" and mount.read_only for mount in parsed.mounts)
                assert any(mount.target == "/codeql-cache" for mount in parsed.mounts)
            else:
                exported = executor.run_root / "scratch/database-export"
                exported.mkdir()
                (exported / "contents").write_text("fixture database")
            return 0, b"fixture", b"", False
        if argv[:3] == ("docker", "rm", "--force"):
            return 0, b"", b"", False
        if argv[:3] == ("docker", "container", "inspect"):
            return ((1, b"", f"Error: No such container: {argv[3]}".encode(), False) if removed
                    else (0, b"false", b"", False))
        pytest.fail(f"unmodeled native engine operation: {argv}")

    executor = _executor(tmp_path, runner)
    scratch = executor.run_root / "scratch"
    scratch.mkdir(parents=True)
    with review_resource_scope(tmp_path / "metadata", ResourceBudget(), EventLog(tmp_path / "events.jsonl")):
        if removed:
            result = executor.execute(action, ("--database", "database"), scratch_root=scratch)
            assert result.limits["database_storage"] == "disposable-native-bind"
            if action == "query":
                assert result.limits["compile_cache"] == "run-private-native-bind"
            else:
                assert (scratch / "database/contents").read_text() == "fixture database"
        else:
            with pytest.raises(RuntimeError, match="removal is unconfirmed"):
                executor.execute(action, ("--database", "database"), scratch_root=scratch)
    assert len(scratch_paths) == 1
    assert scratch_paths[0].exists() is not removed
    assert not any(call[:2] == ("docker", "volume") or "chown" in call for call in calls)
    assert not scratch.stat().st_mode & 0o022


def test_dagster_codeql_topology_has_one_ready_coordinator():
    from pathlib import Path
    from appsec_review.orchestration.dagster import build_definitions
    graph = build_definitions(Path(__file__).parents[1] / "appsec-review.toml").get_job_def("wave1_review").graph
    nodes = {node.name for node in graph.node_defs if node.name.startswith("codeql_analysis__")}
    assert nodes == {
        "codeql_analysis__begin", "codeql_analysis__plan__inventory",
        "codeql_analysis__execution__scopes", "codeql_analysis__acceptance__publish_handoff",
        "codeql_analysis__finalize"}
    def upstream(node):
        mapping = graph.dependency_structure.input_to_upstream_outputs_for_node(node)
        return {output.node_name for outputs in mapping.values() for output in outputs}
    assert "codeql_analysis__plan__inventory" in upstream("codeql_analysis__execution__scopes")
    assert "codeql_analysis__execution__scopes" in upstream("codeql_analysis__acceptance__publish_handoff")
