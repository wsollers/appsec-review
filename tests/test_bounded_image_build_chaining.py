"""Real resolvers/client/service/admission and OCI input staging; fake workers only."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from appsec_review.codeql.runtime import CodeQLImageResolver
from appsec_review.codeql import runtime as codeql_runtime
from appsec_review.container_runtime import BuildProfile, ProjectImageResolver
from appsec_review.container_runtime import buildkit_worker as workers
from appsec_review.container_runtime import image_builder as clients
from appsec_review.container_runtime import image_builder_service as services
from appsec_review.container_runtime import project_images
from appsec_review.config.image_builder_service import BuilderImage
from appsec_review.runtime.resources import review_resource_scope
from tests import test_bounded_image_build_service as fixtures
from tests.test_bounded_image_build_service import forbid_real_execution  # noqa: F401


SOURCE = "sha256:" + "e" * 64
OUTPUTS = ("sha256:" + "b" * 64, "sha256:" + "f" * 64, "sha256:" + "9" * 64)
MANIFEST = "sha256:" + "1" * 64


class ChainedDriver(fixtures.FakeDriver):
    def __init__(self):
        super().__init__()
        self.tags = {"base:release": fixtures.BASE, "codeql:release": SOURCE}
        self.available = {fixtures.BASE, SOURCE}
        self.starts = []
        self.transported = []
        self.missing_input = None
        self.wrong_transport = None
        self.fail_cleanup_once = False

    def inspect(self, argv, timeout):
        assert argv[:3] == ("docker", "image", "inspect")
        assert timeout > 0
        image_id = self.tags.get(argv[3], argv[3] if argv[3] in self.available else None)
        return (0, image_id.encode(), b"", False) if image_id else (1, b"", b"missing", False)

    def run(self, argv, timeout, **kwargs):
        """Fake only the Docker/skopeo subprocess boundary used by real _inputs."""
        assert timeout > 0
        if argv[0] == self.service.config.docker_binary:
            assert argv[3:5] == ["image", "inspect"]
            image_id = argv[5]
            if image_id not in self.available or image_id == self.missing_input:
                return 1, b"", b"input disappeared"
            return 0, json.dumps([{"Id": image_id, "Config": {}}]).encode(), b""
        assert argv[0] == self.service.config.skopeo_binary and argv[1] == "copy"
        assert argv[-2].startswith("docker-daemon:sha256:")
        image_id = argv[-2].removeprefix("docker-daemon:")
        self.transported.append(image_id)
        destination = Path(argv[-1][4:].rsplit(":", 1)[0])
        (destination / "blobs" / "sha256").mkdir(parents=True)
        (destination / "index.json").write_text(json.dumps({"manifests": [{"digest": MANIFEST}]}))
        (destination / "blobs" / "sha256" / MANIFEST[7:]).write_text(json.dumps({
            "config": {"digest": SOURCE if image_id == self.wrong_transport else image_id},
        }))
        return 0, b"", b""

    def start(self, record, save):
        super().start(record, save)
        stage = workers.BuildKitWorker(self.service.config, runner=self, proof=fixtures.FakeProof())
        aliases, stores = stage._inputs(record, save)
        assert all(value.startswith("oci-layout://") for value in aliases.values())
        assert "--oci-layout" in stores
        self.starts.append({
            "binding": deepcopy(record["binding"]), "inputs": deepcopy(record["start"]["image_inputs"]),
            "authorized_inputs": deepcopy(record["start"]["authorized_inputs"]), "aliases": aliases,
            "dockerfile": (Path(record["directory"]) / "context" / "Dockerfile").read_text(),
        })

    def status(self, record, save):
        self.calls.append("status")
        image_id = OUTPUTS[len(self.starts) - 1]
        self.tags[record["binding"]["output_tag"]] = image_id
        self.available.add(image_id)
        return {"state": "SUCCEEDED", "exit_code": 0, "image_id": image_id, "stdout": "", "stderr": ""}

    def cleanup(self, record, save):
        if self.fail_cleanup_once:
            self.fail_cleanup_once = False
            return False
        return super().cleanup(record, save)


@pytest.fixture
def chain(tmp_path, monkeypatch):
    original = fixtures.configuration
    def forbidden_payload_hash(*args, **kwargs):
        pytest.fail("descriptor-free image chaining must not fingerprint supplied payloads")
    monkeypatch.setattr(project_images, "file_sha256", forbidden_payload_hash)
    monkeypatch.setattr(codeql_runtime, "file_sha256", forbidden_payload_hash)

    def configuration(root):
        config, context = original(root)
        config = replace(
            config, grants=(replace(config.grants[0], allow_network=True),),
            images=(*config.images, BuilderImage(alias="codeql:release", image_id=SOURCE, release_id="codeql-v1")),
            network_id="2" * 64, proxy_container_id="3" * 64,
            proxy_image_id="sha256:" + "4" * 64, proxy_release_id="fixture-proxy",
            proxy_url="http://10.0.0.2:3128", ip_release_id="fixture-iproute2",
        )
        return config, context

    monkeypatch.setattr(fixtures, "configuration", configuration)
    driver = ChainedDriver()
    harness = fixtures.Harness(tmp_path, driver=driver, require_worker_reservation=True)

    class Transport:
        def __init__(self, owner):
            pass

        def request(self, action, body, timeout):
            assert timeout > 0
            message = {"schema": services.SCHEMA, "request_id": uuid4().hex, "action": action, "body": body}
            return json.loads(harness.service.dispatch(services.encoded(message), harness.peer))["body"]

    monkeypatch.setattr(clients, "UnixBuilderClient", Transport)
    context = harness.context
    context.target_root.mkdir()
    repository = tmp_path / "repository"
    tools = repository / "containers" / "tools" / "codeql"
    tools.mkdir(parents=True)
    source = Path(__file__).resolve().parents[1] / "containers" / "tools" / "codeql" / "Dockerfile"
    (tools / "Dockerfile").write_bytes(source.read_bytes())
    (tools / "codeql_runner.py").write_text("# Never executed by this fake build.\n")
    project = ProjectImageResolver(
        metadata_root=context.metadata_root, target_root=context.target_root,
        runner=driver.inspect, run_root=context.run_root)
    codeql = CodeQLImageResolver(
        repository_root=repository, metadata_root=context.metadata_root, runner=driver.inspect,
        settings=SimpleNamespace(source_image_tag="codeql:release", source_image_id=SOURCE))
    recipe = {
        "source_dir": ".", "build_system": "cmake", "dependency_files": [],
        "system_packages": ["make"], "network_required": False,
    }
    profile = BuildProfile("native", "base:release", fixtures.BASE, "10001:10001")
    try:
        with review_resource_scope(context.metadata_root, context.review_policy.resources, context.events), \
                clients.image_builder_scope(context):
            yield SimpleNamespace(
                harness=harness, driver=driver, project=project, codeql=codeql,
                recipe=recipe, profile=profile, transport=Transport(None))
    finally:
        harness.service.close()


def layer(chain, project):
    return chain.codeql.resolve(
        build_image_tag=project.image_tag, build_image_id=project.image_id, runtime_user="10001:10001")[0]


@pytest.mark.parametrize("repair,restart", [(False, False), (True, False), (False, True)])
def test_actual_project_client_service_codeql_chain_including_derived_base_repair(chain, repair, restart):
    config = chain.harness.config
    project, _, _ = chain.project.resolve(chain.recipe, chain.profile)
    assert project.image_id == OUTPUTS[0]
    assert project.dockerfile_sha256 is None
    assert project.image_id not in {image.image_id for image in config.images}
    if repair:
        repair_recipe = {
            **chain.recipe, "system_packages": [],
            "image_repairs": {"environment": {"CC": "clang"}, "dependency_restores": []},
        }
        project, _, _ = chain.project.resolve(
            repair_recipe, replace(chain.profile, tag=project.image_tag, image_id=project.image_id))
        assert project.image_id == OUTPUTS[1]
        repair_start = chain.driver.starts[1]
        assert set(repair_start["inputs"].values()) == {OUTPUTS[0]}
        alias = next(iter(repair_start["inputs"]))
        assert repair_start["dockerfile"].startswith(f"FROM {alias}\n")
        assert 'ENV CC="clang"' in repair_start["dockerfile"]
    if restart:
        chain.harness.service.close()
        chain.harness.service = chain.harness.open()
    codeql = layer(chain, project)
    assert codeql.build_image_id == project.image_id
    assert codeql.image_id == OUTPUTS[2 if repair else 1]
    final = chain.driver.starts[-1]
    assert set(final["inputs"].values()) == {SOURCE, project.image_id}
    assert set(final["inputs"]) <= set(final["aliases"])
    assert project.image_id in chain.driver.transported
    assert chain.harness.config == config
    for record in chain.harness.service.store.records():
        assert record["state"] == "CLEANED"
        assert record["execution"]["state"] == "SUCCEEDED"
        assert record["output_authorization"]["worker"] == record["cleanup"]["worker"]
        assert record["output_authorization"]["binding"] == record["cleanup"]["binding"]


@pytest.mark.parametrize("fault", [
    "tenant_id", "project_id", "run_id", "namespace", "target_snapshot", "release_id",
    "wrong-result-id", "wrong-worker", "wrong-result-binding", "missing-proof",
    "failed", "unclean", "cleanup-receipt", "quarantined", "service-contract",
    "directory-rebound", "context-rebound",
])
def test_chained_output_authorization_rejects_stale_cross_run_and_unconfirmed_results(chain, fault):
    project, _, _ = chain.project.resolve(chain.recipe, chain.profile)
    record = chain.harness.service.store.records()[0]
    if fault in {"tenant_id", "project_id", "run_id", "namespace", "target_snapshot", "release_id"}:
        for value in (record["binding"], record["output_authorization"]["binding"], record["cleanup"]["binding"]):
            value[fault] = "other"
        if fault != "release_id":
            record["grant"][fault] = "other"
    elif fault == "wrong-result-id":
        record["execution"]["image_id"] = SOURCE
    elif fault == "wrong-worker":
        record["worker"]["start_token"] = "0" * 32
        record["cleanup"]["worker"] = deepcopy(record["worker"])
    elif fault == "wrong-result-binding":
        record["output_authorization"]["binding"]["recipe_identity"] = "other"
    elif fault == "missing-proof":
        record.pop("output_authorization")
    elif fault == "failed":
        record["execution"].update(state="FAILED", exit_code=1)
    elif fault == "unclean":
        record["state"] = "SUCCEEDED"
    elif fault == "cleanup-receipt":
        record["cleanup"]["context_released"] = False
    elif fault == "quarantined":
        record["quarantine"] = "unresolved"
    elif fault == "service-contract":
        record["service_contract"]["release_id"] = "other"
    elif fault == "directory-rebound":
        Path(record["directory"]).mkdir(mode=0o700)
    else:
        Path(record["binding"]["context"]).mkdir(mode=0o700)
    chain.harness.service.store.save(record)
    assert project.image_id not in chain.harness.service._prior_output_ids(chain.harness.config.grants[0])
    with pytest.raises((ValueError, RuntimeError, PermissionError)):
        layer(chain, project)
    assert len(chain.driver.starts) == 1


@pytest.mark.parametrize("fault", ["arbitrary", "changed-tag", "missing-input", "wrong-oci-config"])
def test_chain_never_substitutes_a_base_or_accepts_stale_tags_and_transport(chain, fault):
    project, _, _ = chain.project.resolve(chain.recipe, chain.profile)
    if fault == "arbitrary":
        unknown = "sha256:" + "7" * 64
        chain.driver.tags[project.image_tag] = unknown
        chain.driver.available.add(unknown)
        project = replace(project, image_id=unknown)
    elif fault == "changed-tag":
        chain.driver.tags[project.image_tag] = SOURCE
    elif fault == "missing-input":
        chain.driver.missing_input = project.image_id
    else:
        chain.driver.wrong_transport = project.image_id
    with pytest.raises((ValueError, RuntimeError, PermissionError)):
        layer(chain, project)
    assert len(chain.driver.starts) == 1


def test_later_confirmed_cleanup_does_not_authorize_a_quarantined_success(chain):
    chain.driver.fail_cleanup_once = True
    with pytest.raises((ValueError, RuntimeError)):
        chain.project.resolve(chain.recipe, chain.profile)
    record = chain.harness.service.store.records()[0]
    assert record["execution"]["state"] == "SUCCEEDED" and record["output_quarantined"]
    result = chain.transport.request("cleanup", {
        "binding": record["binding"], "worker": record["worker"],
        "resource_budget": chain.harness.config.resources.view(),
    }, 60)
    assert result["state"] == "CLEANED"
    assert OUTPUTS[0] not in chain.harness.service._prior_output_ids(chain.harness.config.grants[0])
    assert len(chain.harness.lifetime.reconcile()) == 1
    with pytest.raises((ValueError, RuntimeError, PermissionError)):
        layer(chain, SimpleNamespace(image_tag=record["binding"]["output_tag"], image_id=OUTPUTS[0]))
    assert len(chain.driver.starts) == 1


def test_driver_cannot_inject_a_different_result_worker_binding(chain, monkeypatch):
    original = chain.driver.status

    def hostile(record, save):
        return {**original(record, save), "worker": {"id": "other", "start_token": "other"}}

    monkeypatch.setattr(chain.driver, "status", hostile)
    with pytest.raises((ValueError, RuntimeError)):
        chain.project.resolve(chain.recipe, chain.profile)
    assert chain.harness.service._prior_output_ids(chain.harness.config.grants[0]) == set()
