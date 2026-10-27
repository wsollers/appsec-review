from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from appsec_review.orchestration.dagster import native_operator, native_lifecycle
from tests.test_native_dagster_process import configuration
from tests.test_bounded_image_build_service import forbid_real_execution  # noqa: F401


@pytest.fixture
def endpoint(monkeypatch):
    observed = SimpleNamespace(inode="42", token="generation", local="0100007F", listening=True)
    monkeypatch.setattr(native_operator, "process_token", lambda pid: observed.token)
    original_iterdir, original_open = Path.iterdir, Path.open
    original_readlink = native_operator.os.readlink

    def entries(path):
        return iter([path / "8"]) if str(path) == "/proc/1234/fd" else original_iterdir(path)

    def readlink(path):
        if str(path) == "/proc/1234/fd/8":
            return f"socket:[{observed.inode}]"
        if str(path) in {"/proc/1234/ns/net", "/proc/self/ns/net"}:
            return "net:[fixture]"
        return original_readlink(path)

    def table(path, *args, **kwargs):
        if str(path) != "/proc/1234/net/tcp":
            return original_open(path, *args, **kwargs)
        data = "header\n"
        if observed.listening:
            data += f"0: {observed.local}:36B0 00000000:0000 0A 0:0 0:0 0 1000 0 42\n"
        return BytesIO(data.encode())

    monkeypatch.setattr(Path, "iterdir", entries)
    monkeypatch.setattr(Path, "open", table)
    monkeypatch.setattr(native_operator.os, "readlink", readlink)
    return observed


@pytest.mark.parametrize("fault", [None, "foreign", "generation", "non-loopback", "not-started"])
def test_readiness_requires_owned_listener_inode_and_generation(endpoint, fault):
    if fault == "foreign":
        endpoint.inode = "99"
    elif fault == "generation":
        endpoint.token = "replacement"
    elif fault == "non-loopback":
        endpoint.local = "00000000"
    elif fault == "not-started":
        endpoint.listening = False
    owner = {"pid": 1234, "start_token": "generation"}
    if fault in {"foreign", "generation", "non-loopback"}:
        with pytest.raises(RuntimeError):
            native_operator.verify_owned_listener(owner, 14000)
    else:
        assert native_operator.verify_owned_listener(owner, 14000) is (fault is None)


def test_foreign_healthy_port_is_rejected_before_any_readiness_request(endpoint, tmp_path, monkeypatch):
    endpoint.inode = "99"
    config = configuration(tmp_path)
    home = Path(config.dagster_home)
    home.mkdir()
    owner = {"pid": 1234, "start_token": "generation"}
    (home / "native-processes.json").write_text(json.dumps({
        "processes": {"code-location": owner, "webserver": owner}}))
    ready = object.__new__(native_operator.NativeReadiness)
    ready.config = config
    ready.instance = SimpleNamespace(get_runs=lambda **kwargs: [])
    from dagster._grpc.client import DagsterGrpcClient

    monkeypatch.setattr(DagsterGrpcClient, "get_server_id",
                        lambda *a, **kw: pytest.fail("queried a foreign gRPC endpoint"))
    monkeypatch.setattr(native_operator, "urlopen",
                        lambda *a, **kw: pytest.fail("queried a foreign webserver endpoint"))
    with pytest.raises(RuntimeError, match="foreign process"):
        ready.connected()


def test_stalled_database_poll_has_a_local_deadline_and_closes_connection(monkeypatch):
    from psycopg2.extensions import POLL_READ

    closed, waits = [], []
    connection = SimpleNamespace(poll=lambda: POLL_READ, fileno=lambda: 42,
                                 close=lambda: closed.append(True))
    monkeypatch.setattr(native_lifecycle.time, "monotonic", lambda: 10)

    def wait(read, write, errors, timeout):
        waits.append((read, write, timeout))
        return [], [], []

    monkeypatch.setattr(native_lifecycle.select, "select", wait)
    with native_lifecycle.database_deadline(2), pytest.raises(TimeoutError):
        native_lifecycle._wait_for_postgres(connection)
    assert waits == [([42], [], 2)]
    assert closed == [True]


def test_expired_database_operation_does_not_start_polling(monkeypatch):
    values = iter([10, 20, 20])
    monkeypatch.setattr(native_lifecycle.time, "monotonic", lambda: next(values))
    closed = []
    connection = SimpleNamespace(close=lambda: closed.append(True),
                                 poll=lambda: pytest.fail("expired database operation polled"))
    with native_lifecycle.database_deadline(2), pytest.raises(TimeoutError):
        native_lifecycle._wait_for_postgres(connection)
    assert closed == [True]
