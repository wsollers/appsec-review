"""Registered operator path with fake Dagster/process/kernel/engine dependencies only."""
from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from appsec_review.container_runtime import native_client
from appsec_review.container_runtime.buildkit_worker import process_token
from appsec_review.container_runtime.executor import _default_runner
from appsec_review.container_runtime.engine_broker import encoded, SCHEMA
from appsec_review.orchestration.dagster import native_operator
from appsec_review.orchestration.dagster.native import child_environment, prepare_instance
from appsec_review.orchestration.dagster.native_lifecycle import NativeSupervisor
from appsec_review.runtime import launch, resources
from tests.test_native_dagster_process import configuration, save_config
from tests.test_native_engine_broker import native, create_payload  # noqa: F401
from tests.test_bounded_image_build_service import forbid_real_execution  # noqa: F401


@pytest.mark.parametrize("failure", [None, "engine-cleanup", "database-health"])
def test_registered_operator_reaches_run_child_broker_and_owned_cleanup(native, tmp_path, monkeypatch, failure):
    import dagster

    config = configuration(tmp_path)
    config_path = save_config(tmp_path / "native.toml", config)
    prepare_instance(config_path)
    contract = replace(native.client.contract, host_cgroup=native.config.host_cgroup,
                       image_ids=native.config.native_engine.grants[0].image_ids)
    manifest = native.context.run_root / "data/configuration/manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"resolved_sha256": contract.binding["configuration_id"]}))
    monkeypatch.setattr(native_client.NativeClientContract, "load", lambda path: contract)
    monkeypatch.setattr(native_operator, "verify_application_cgroup",
                        lambda value: value == contract or pytest.fail("changed host contract"))
    monkeypatch.setattr(native_operator, "load_config", lambda path: SimpleNamespace(
        review_policy=native.context.review_policy,
        runtime=SimpleNamespace(runs_dir=native.context.run_root.parent)))
    monkeypatch.setattr(native_operator.NativeReadiness, "connected", lambda self: True)
    children, sequence = {}, []
    finished = False
    database_lost = False

    class Instance:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get_runs(self, **kwargs):
            return []

        def get_run_by_id(self, run_id):
            if finished:
                return SimpleNamespace(is_finished=True, status=dagster.DagsterRunStatus.SUCCESS)
            return None

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def execute(self, query):
            assert query == "SELECT 1"
            if database_lost:
                raise RuntimeError("database ownership lost")

        def fetchone(self):
            return (1,)

    @contextmanager
    def ownership(value):
        assert value == config
        sequence.append("database-owner")
        yield SimpleNamespace(cursor=Cursor)
        sequence.append("database-release")

    @contextmanager
    def postgres_runtime():
        sequence.append("bounded-db-runtime")
        yield

    monkeypatch.setattr(native_operator, "bounded_postgres", postgres_runtime)

    def peer_request(self, action, payload, **kwargs):
        sequence.append(action)
        data = encoded({"schema": SCHEMA, "request_id": kwargs.get("request_id") or uuid4().hex,
                        "binding": self.binding(), "action": action, "payload": payload})
        result = json.loads(native.broker.dispatch(data, native.peer))["result"]
        if result.get("quarantine") or result["state"] == "UNKNOWN":
            raise RuntimeError("fake transport observed real broker quarantine")
        return result

    monkeypatch.setattr(native_client.NativeClient, "request", peer_request)
    environment = child_environment(config_path, os.environ)

    def spawn(argv, **kwargs):
        assert kwargs["env"] == environment and kwargs["cwd"] == config.repository_root
        assert sequence.index("image.inspect") < sequence.index("database-owner")
        assert argv[0] != "docker"
        role = next(role for role, command in config.commands().items() if command == argv)
        sequence.append(role)
        pid = 20000 + len(children)
        children[pid] = f"fixture:{pid}"
        return SimpleNamespace(pid=pid, poll=lambda: None)

    def identity(pid):
        return process_token(pid) if pid == os.getpid() else children.get(pid)

    def terminate(pid, token, sig):
        assert children[pid] == token
        del children[pid]

    def supervisor(path, ready):
        return NativeSupervisor(path, ready, spawn=spawn, identity=identity,
                                terminate=terminate, ownership=ownership)

    monkeypatch.setattr(native_operator, "NativeSupervisor", supervisor)
    monkeypatch.setattr(native_operator.NativeReadiness, "shutdown_complete", lambda self: not children)
    monkeypatch.setattr(dagster.DagsterInstance, "from_config", lambda home: Instance())
    class Pool:
        def __init__(self, **kwargs):
            assert kwargs["max_workers"] == 1

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def submit(self, function, *args, **kwargs):
            result = function(*args, **kwargs)
            return SimpleNamespace(result=lambda **kw: result, done=lambda: True)

    monkeypatch.setattr(native_operator, "ThreadPoolExecutor", Pool)
    _, tool = create_payload(native)

    class Runner:
        def begin_attempt(self, job, **kwargs):
            sequence.append("common-launch")
            assert kwargs["run_id"] == contract.binding["run_id"]
            with resources.review_resource_scope(native.context.metadata_root, contract.resources,
                                                  native.context.events, require_container_removal=True), \
                    native_client.native_engine_scope(native.context), \
                    resources.reserve_execution(cpu="2", memory="4g", action="native.integration", timeout_seconds=30):
                outcome = _default_runner(tool, 30)
                assert outcome.exit_code == 0
                name = tool[tool.index("--name") + 1]
                native.engine.confirmed = failure != "engine-cleanup"
                assert _default_runner(("docker", "rm", "--force", name), 30).exit_code == 0
                assert _default_runner(("docker", "container", "inspect", name,
                                        "--format", "{{.State.Running}}"), 30).exit_code == 1
                resources.container_stopped(name)
            return {"run_id": kwargs["run_id"]}

    def cli(argv, **kwargs):
        nonlocal finished, database_lost
        assert tuple(argv[:5]) == (config.python_executable, "-m", "dagster", "job", "launch")
        assert argv[argv.index("-w") + 1] == str(Path(config.dagster_home) / "workspace.yaml")
        assert argv[argv.index("-j") + 1] == "wave1_review"
        assert kwargs["env"]["APPSEC_REVIEW_TARGET"] == contract.target_root
        assert kwargs["timeout"] == 60 and kwargs["check"]
        sequence.append("run-child")
        # Simulate Dagster's inherited child process, without launching a process or bypassing begin().
        with monkeypatch.context() as patch:
            for key, value in kwargs["env"].items():
                patch.setenv(key, value)
            inputs = launch.LaunchInputs(Path(contract.target_root), contract.binding["target_snapshot"])
            launch.begin(Runner(), SimpleNamespace(job_id="fixture"), inputs,
                         run_id=contract.binding["run_id"], trigger="manual",
                         orchestration={"system": "dagster", "run_id": run_id})
        finished = True
        database_lost = failure == "database-health"

    # main -> execute uses this injected bounded CLI dependency; everything beyond it is real app routing.
    original_execute = native_operator.execute
    monkeypatch.setattr(native_operator, "execute",
                        lambda path, run_id, **kw: original_execute(path, run_id, launch=cli, **kw))
    run_id = str(uuid4())
    if failure:
        with pytest.raises(RuntimeError):
            native_operator.main(["run", "--config", str(config_path), "--run-id", run_id])
        assert json.loads((Path(config.dagster_home) / "native-submission.json").read_bytes())["state"] == "UNKNOWN"
    else:
        assert native_operator.main(["run", "--config", str(config_path), "--run-id", run_id]) == 0
        assert not children and native.broker.interlock.owner() is None
        assert sequence.index("image.inspect") < sequence.index("code-location") < sequence.index("run-child")
        assert sequence.index("common-launch") < sequence.index("execution.create") < sequence.index("execution.remove")
        assert sequence[-1] == "database-release"


def test_native_operator_is_a_registered_package_entrypoint():
    import tomllib

    document = tomllib.loads(Path("pyproject.toml").read_text())
    assert document["project"]["scripts"]["appsec-review-native"] == (
        "appsec_review.orchestration.dagster.native_operator:main")
