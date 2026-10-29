import base64
from contextlib import contextmanager
from copy import deepcopy
import json
import multiprocessing
import os
from pathlib import Path
import socket
import threading
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import pytest

from appsec_review.config.assurance import parse_review_policy
from appsec_review.container_runtime import image_builder as builders
from appsec_review.observability.events import EventLog
from appsec_review.runtime.resources import (
    Reservation, ResourceAdmission, review_resource_scope, track_image_build,
)


BASE = "sha256:" + "a" * 64
BUILT = "sha256:" + "b" * 64
ROOT = Path(__file__).parents[1]


def configuration(tmp_path, **overrides):
    values = {"endpoint": str(tmp_path / "builder.sock"), "tenant_id": "tenant-one",
              "release_id": "fixture-builder-1", **overrides}
    return parse_review_policy({"project_id": "project-one", "image_builder": values})


def context(tmp_path, *, policy=None, run="run-one"):
    root = tmp_path / "runs" / run
    root.mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    return SimpleNamespace(
        review_policy=policy or configuration(tmp_path), run_root=root,
        metadata_root=tmp_path / "runs" / "metadata", target_root=target, source_fingerprint="target-one",
        events=EventLog(root / "events.jsonl"),
    )


@contextmanager
def active(context):
    with review_resource_scope(context.metadata_root, context.review_policy.resources, context.events), \
            builders.image_builder_scope(context):
        yield


def leases(context):
    path = context.metadata_root / "resource-admission" / "leases.json"
    return json.loads(path.read_text())["leases"] if path.exists() else {}


class FakeBackend:
    def __init__(self):
        self.calls = []
        self.requests = {}
        self.images = {}
        self.failure = None

    def request(self, action, body, timeout):
        assert timeout > 0
        self.calls.append(action)
        binding = deepcopy(body["binding"])
        self.requests[action] = deepcopy(body)
        response = {"binding": binding, "worker": {"id": "worker-one", "start_token": "generation-one"},
                    "resource_budget": deepcopy(body.get("resource_budget"))}
        if action == "prepare":
            assert not list(Path(binding["context"]).iterdir())
            limits = body["limits"]
            observed = {
                "cpu_quota_us": limits["cpu"] * 100000, "cpu_period_us": 100000,
                "memory_max": limits["memory_bytes"],
                "host_cpu_quota_us": limits["host_cpu"] * 100000, "host_cpu_period_us": 100000,
                "host_memory_max": limits["host_overhead_bytes"],
            } if limits.get("resource_mode") != "concurrency_only" else {
                prefix + key: value for prefix in ("", "host_") for key, value in {
                    "resource_mode": "concurrency_only", "cpu_quota_us": None, "memory_max": None,
                    "cpu_period_us": 100000, "swap_max": 0, "inherited_limits": [],
                }.items()
            }
            response.update(state="PREPARED", private_context=True, limits=observed)
            if self.failure == "limits":
                response["limits"]["memory_max"] = (observed["memory_max"] or 1) * 2
            if self.failure == "isolation":
                response["private_context"] = False
            if self.failure == "stale_image":
                self.images[binding["output_tag"]] = BASE
        elif action == "start":
            assert (Path(binding["context"]) / "Dockerfile").is_file()
            if self.failure == "timeout":
                raise TimeoutError("fixture build timed out")
            if self.failure != "stale_image":
                self.images[binding["output_tag"]] = BUILT
            response.update(state="SUCCEEDED", exit_code=0, image_id=BUILT,
                            stdout=base64.b64encode(b"fixture built").decode(), stderr="")
            if self.failure == "missing_image":
                del response["image_id"]
            if self.failure == "wrong_image":
                response["image_id"] = "sha256:" + "c" * 64
            if self.failure == "worker":
                response["worker"]["start_token"] = "replacement"
            if self.failure == "tenant":
                response["binding"]["tenant_id"] = "other"
            if self.failure == "logs":
                response["stdout"] = "A" * (2 * builders.MAX_LOG_BYTES)
            if self.failure == "failed":
                response.update(state="FAILED", exit_code=7)
        elif action == "cancel":
            response["state"] = "CANCELLED"
        elif action == "cleanup":
            response.update(state="CLEANED", work_stopped=True, context_released=True)
            if self.failure == "cleanup":
                response["work_stopped"] = False
        else:
            raise AssertionError(action)
        return response


@pytest.fixture
def backend(monkeypatch):
    fake = FakeBackend()
    monkeypatch.setattr(builders, "UnixBuilderClient", lambda owner: fake)
    return fake


@pytest.mark.parametrize("overrides", (
    {"cpu": True}, {"memory_mb": 0}, {"max_concurrency": 0}, {"host_cpu": 20},
    {"release_id": ""}, {"endpoint": "relative"}, {"unexpected": 1},
    {"resource_mode": "unrestricted"}, {"resource_mode": "concurrency_only", "max_concurrency": 2},
))
def test_builder_configuration_rejects_invalid_or_unbudgeted_contract(tmp_path, overrides):
    with pytest.raises(ValueError):
        configuration(tmp_path, **overrides)


def test_builder_configuration_requires_operator_project_and_preserves_default_policy(tmp_path):
    with pytest.raises(ValueError, match="project binding"):
        parse_review_policy({"image_builder": configuration(tmp_path).image_builder.view()})
    assert "image_builder" not in parse_review_policy({}).view()


def test_builder_tracks_intent_before_preparation_and_confirms_cleanup(tmp_path, backend):
    owner = context(tmp_path)
    with active(owner):
        tag = f"appsec-review-codeql:{builders.builder_namespace()[:12]}fixture"
        with builders.bounded_image_preparation(identity="recipe-one", tag=tag, timeout_seconds=10) as session:
            entries = list(leases(owner).values())
            assert len(entries) == 1
            assert entries[0]["reservation"] == {"cpu": 2, "memory_mb": 5120, "io_slots": 1}
            assert entries[0]["builds"][0]["build_id"] == session.build_id
            assert entries[0]["builds"][0]["worker"] == session.worker
            (session.context / "Dockerfile").write_text("FROM fixture\n")
            assert session.build(network="none") == (0, b"fixture built", b"", False)
        builders.verify_builder_receipt(session.receipt(), identity="recipe-one", tag=tag, image_id=BUILT)
        with pytest.raises(ValueError, match="receipt"):
            builders.verify_builder_receipt(session.receipt(), identity="recipe-one", tag=tag, image_id=BASE)
    assert backend.calls == ["prepare", "start", "cancel", "cleanup"]
    assert leases(owner) == {}
    receipt = json.loads((session.root / "terminal.json").read_text())
    assert receipt["enforcement"]["private_context"]
    assert receipt["execution"]["state"] == "SUCCEEDED"
    assert receipt["cleanup"]["work_stopped"]
    events = [json.loads(line) for line in (owner.run_root / "events.jsonl").read_text().splitlines()]
    completed = [event for event in events if event.get("event") == "OPERATION_COMPLETED"]
    assert completed[-1]["work"]["builder_launches"] == 1


@pytest.mark.parametrize("failure,retained", (
    ("limits", False), ("isolation", False), ("timeout", False), ("logs", False),
    ("worker", True), ("tenant", True), ("cleanup", True),
))
@pytest.mark.parametrize("resource_mode", ("bounded", "concurrency_only"))
def test_builder_failure_requires_independent_cleanup(tmp_path, backend, failure, retained, resource_mode):
    owner = context(tmp_path, policy=configuration(tmp_path, resource_mode=resource_mode))
    backend.failure = failure
    with active(owner):
        tag = f"appsec-review-codeql:{builders.builder_namespace()[:12]}fixture"
        with pytest.raises((ValueError, RuntimeError, TimeoutError)):
            with builders.bounded_image_preparation(identity="recipe-one", tag=tag, timeout_seconds=10) as session:
                (session.context / "Dockerfile").write_text("FROM fixture\n")
                session.build(network="none")
    assert "cleanup" in backend.calls
    assert bool(leases(owner)) is retained
    admission = ResourceAdmission(owner.metadata_root, owner.review_policy.resources)
    if retained:
        entry = next(iter(leases(owner).values()))
        assert entry["owner_finished"] and entry["quarantine"] and entry["builds"]
        assert admission.reconcile(lambda name: True, confirmed_cleanup=lambda entry: True) == []
        assert len(admission.reconcile(lambda name: True, confirmed_cleanup=lambda entry: True,
                                       confirmed_build_stopped=lambda build: True)) == 1


@pytest.mark.parametrize("kind", ("project", "codeql"))
@pytest.mark.parametrize("failure", (None, "missing_image", "wrong_image", "stale_image", "failed"))
def test_resolvers_use_bounded_backend_and_reuse_its_run_bound_receipt(tmp_path, backend, kind, failure):
    from appsec_review.codeql.runtime import CodeQLImageResolver
    from appsec_review.config.assurance import ComponentReleases
    from appsec_review.container_runtime import BuildProfile, ProjectImageResolver
    owner = context(tmp_path)
    backend.failure = failure
    calls = []

    def runner(argv, timeout):
        calls.append(argv)
        assert argv[:3] == ("docker", "image", "inspect"), "bounded path mutated Docker through legacy runner"
        value = BASE if argv[3] in {"base", "source"} else backend.images.get(argv[3])
        return (0, value.encode(), b"", False) if value else (1, b"", b"missing", False)

    releases = ComponentReleases({key: "fixture-1" for key in
                                  ("platform", "build_toolchain", "codeql", "codeql_runner")})
    with active(owner):
        if kind == "project":
            (owner.target_root / "package.json").write_text('{"name":"fixture"}')
            resolver = ProjectImageResolver(metadata_root=owner.metadata_root, target_root=owner.target_root,
                                            runner=runner, releases=releases, run_root=owner.run_root)
            recipe = {"source_dir": ".", "system_packages": ["cmake"], "network_required": True,
                      "dependency_files": ["package.json"], "build_system": "node",
                      "build_commands": [["npm", "run", "build"]]}
            def resolve():
                return resolver.resolve(recipe, BuildProfile("node", "base", BASE, "10001:10001"))[0]
        else:
            resolver = CodeQLImageResolver(repository_root=ROOT, metadata_root=owner.metadata_root,
                                            settings=SimpleNamespace(source_image_tag="source", source_image_id=BASE),
                                            runner=runner, releases=releases)
            def resolve():
                return resolver.resolve(build_image_tag="base", build_image_id=BASE, runtime_user="10001:10001")[0]
        if failure is not None:
            with pytest.raises((ValueError, RuntimeError), match="image|exited"):
                resolve()
            assert leases(owner) == {}
            assert not list(owner.metadata_root.glob("*-images/**/manifest.json"))
            return
        first, second = resolve(), resolve()
        assert not first.reused and second.reused
        assert first.image_id == second.image_id == BUILT
        assert first.preparation_receipt == second.preparation_receipt
        assert backend.calls.count("start") == 1
    spec = backend.requests["start"]
    assert spec["binding"]["tenant_id"] == "tenant-one"
    assert spec["binding"]["run_id"] == owner.run_root.name
    dockerfile = (Path(spec["binding"]["context"]) / "Dockerfile").read_text()
    if kind == "project":
        assert "cmake" in dockerfile and "npm" in dockerfile
        assert (Path(spec["binding"]["context"]) / "inputs" / "0000").read_text() == '{"name":"fixture"}'
    else:
        assert spec["network"] == "none"
        assert spec["image_inputs"] and spec["build_args"]["RUNTIME_USER"] == "10001:10001"
    assert leases(owner) == {}


def test_builder_namespace_isolates_runs_and_tenants(tmp_path):
    first = context(tmp_path)
    second = context(tmp_path, run="run-two")
    third = context(tmp_path, run="run-three", policy=configuration(tmp_path, tenant_id="tenant-two"))
    names = []
    for owner in (first, second, third):
        with active(owner):
            names.append(builders.builder_namespace())
    assert len(set(names)) == 3


def test_builder_limit_rejects_second_build_before_backend_preparation(tmp_path, backend):
    owner = context(tmp_path)
    with active(owner):
        tag = f"appsec-review-codeql:{builders.builder_namespace()[:12]}fixture"
        with builders.bounded_image_preparation(identity="one", tag=tag, timeout_seconds=10):
            with pytest.raises(TimeoutError, match="concurrency admission"):
                with builders.bounded_image_preparation(identity="two", tag=tag, timeout_seconds=0.01):
                    pytest.fail("second build bypassed concurrency admission")
            assert backend.calls == ["prepare"]
    assert leases(owner) == {}


def _abandon_build(root, affinity, cgroup):
    assert sorted(os.sched_getaffinity(0)) == affinity
    assert Path("/proc/self/cgroup").read_text() == cgroup
    owner = context(Path(root))
    with ResourceAdmission(owner.metadata_root, owner.review_policy.resources).reserve(
            Reservation(2, 5120), events=owner.events, action="fixture-abandoned-build"):
        track_image_build({"build_id": "fixture-build", "worker": {"id": "fixture", "start_token": "one"}},
                          max_concurrency=1, timeout_seconds=1)
        os._exit(0)


def test_launcher_death_does_not_release_unconfirmed_builder(tmp_path):
    worker = multiprocessing.get_context("spawn").Process(
        target=_abandon_build, args=(str(tmp_path), sorted(os.sched_getaffinity(0)),
                                    Path("/proc/self/cgroup").read_text()))
    worker.start()
    try:
        worker.join(15)
        assert worker.exitcode == 0
    finally:
        if worker.is_alive():
            worker.terminate()
            worker.join(5)
    admission = ResourceAdmission(tmp_path / "runs/metadata", configuration(tmp_path).resources)
    assert admission.reconcile(lambda name: True) == []
    assert len(admission.reconcile(lambda name: True, confirmed_build_stopped=lambda build: True)) == 1


def test_builder_contract_is_frozen_in_configuration_and_claim(tmp_path, backend):
    from appsec_review.config import load_config
    from appsec_review.runtime import Job, JobRunner, Unit
    from tests.test_job_runtime import write_config
    path = write_config(tmp_path)
    with path.open("a") as stream:
        stream.write('\n[review_policy]\nproject_id="fixture"\n[review_policy.image_builder]\n'
                     f'endpoint={json.dumps(str(tmp_path / "builder.sock"))}\n'
                     'tenant_id="fixture-tenant"\nrelease_id="fixture-builder"\n')
    config = load_config(path)
    runner = JobRunner(config)
    job = Job("job_fixture", "fixture", lambda context: {}, units=(Unit("work.only", lambda unit: {}),))
    claim = runner.begin_attempt(job)
    frozen = json.loads((config.runtime.runs_dir / claim["run_id"] / "data/configuration/resolved.json").read_text())
    assert frozen["review_policy"]["image_builder"] == config.review_policy.image_builder.view()
    assert claim["review_policy"] == config.review_policy.view()
    changed = deepcopy(claim)
    changed["review_policy"]["image_builder"]["tenant_id"] = "other"
    with pytest.raises(ValueError, match="policy"):
        runner._context_from_claim(job, changed)
    assert backend.calls == []


def test_concurrency_only_policy_is_explicit_truthful_and_receipt_bound(tmp_path, backend):
    owner = context(tmp_path, policy=configuration(tmp_path, resource_mode="concurrency_only"))
    assert configuration(tmp_path).image_builder.resource_mode == "bounded"
    with active(owner):
        tag = f"derived:{builders.builder_namespace()[:12]}fixture"
        with builders.bounded_image_preparation(identity="fixture", tag=tag, timeout_seconds=10) as session:
            reservation = next(iter(leases(owner).values()))["reservation"]
            budget = owner.review_policy.resources
            assert reservation == {"cpu": budget.cpu - 1, "memory_mb": budget.memory_mb - 512, "io_slots": 1}
            (session.context / "Dockerfile").write_text("FROM fixture\n")
            session.build(network="none")
        builders.verify_builder_receipt(session.receipt(), identity="fixture", tag=tag, image_id=BUILT)
        changed = json.loads((session.root / "terminal.json").read_text())
        changed["enforcement"]["requested_limits"]["resource_mode"] = "bounded"
        changed_path = session.root / "changed.json"
        changed_path.write_text(json.dumps(changed))
        with pytest.raises(ValueError, match="resource policy"):
            builders.verify_builder_receipt(builders.reference(owner.run_root, changed_path),
                                           identity="fixture", tag=tag, image_id=BUILT)
    requested = backend.requests["prepare"]["limits"]
    assert requested["resource_mode"] == "concurrency_only"
    assert all(requested[name] is None for name in ("cpu", "host_cpu", "memory_bytes", "host_overhead_bytes"))
    assert session.enforcement["limits"]["cpu_quota_us"] is None
    assert backend.calls == ["prepare", "start", "cancel", "cleanup"]


@pytest.fixture
def socket_path():
    with TemporaryDirectory(prefix="performance-097f-sock-", dir=ROOT / "test/tmp") as directory:
        yield Path(directory) / "s"


@pytest.mark.parametrize("response_kind", ("matching", "wrong_nonce", "oversized", "deadline"))
def test_unix_protocol_checks_response_nonce_and_private_peer(tmp_path, socket_path, response_kind):
    owner = context(tmp_path, policy=configuration(tmp_path, endpoint=str(socket_path)))
    endpoint = socket_path
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(endpoint))
    endpoint.chmod(0o600)
    server.listen(1)
    server.settimeout(5)
    errors = []
    finish = threading.Event()

    def respond():
        try:
            with server.accept()[0] as client:
                client.settimeout(5)
                request = b""
                while not request.endswith(b"\n"):
                    request += client.recv(65536)
                value = json.loads(request)
                if response_kind == "deadline":
                    finish.wait(5)
                    return
                response = json.dumps({
                    "schema": builders.SCHEMA,
                    "request_id": "wrong" if response_kind == "wrong_nonce" else value["request_id"],
                    "body": {"fixture": True},
                }).encode()
                if response_kind == "oversized":
                    response = b" " * (builders.MAX_RESPONSE_BYTES + 10)
                client.sendall(response)
        except BrokenPipeError:
            if response_kind != "oversized":
                errors.append("unexpected broken pipe")
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=respond)
    worker.start()
    try:
        with builders.image_builder_scope(owner):
            client = builders.UnixBuilderClient(builders.require_builder())
            if response_kind == "matching":
                assert client.request("fixture", {}, 5) == {"fixture": True}
            elif response_kind == "deadline":
                with pytest.raises(TimeoutError):
                    client.request("fixture", {}, 0.05)
            else:
                with pytest.raises(ValueError, match="binding mismatch|protocol bound"):
                    client.request("fixture", {}, 5)
    finally:
        finish.set()
        worker.join(6)
        server.close()
        endpoint.unlink()
    assert not worker.is_alive() and not errors
