"""Explicit installed runtimes are declarations, never synthetic build/cache receipts."""
from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from appsec_review.codeql import runtime
from appsec_review.config import load_config
from appsec_review.config.assurance import ComponentReleases, ResourceBudget
from appsec_review.config.codeql import parse_codeql_settings
from appsec_review.container_runtime.identity import application_runtime_user
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_codeql_analysis import job as codeql
from appsec_review.jobs.job_codeql_analysis.datasets import DATASETS
from appsec_review.jobs.job_codeql_analysis.planning import CodeQLScope, SCOPE_SCHEMA
from appsec_review.observability import PipelineLog
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime import resources
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from tests.capture_fakes import build_capture_toml
from tests.test_codeql_analysis import _settings_value
from tests.test_codeql_predecessor import _table


SOURCE = "sha256:" + "1" * 64
BASE = "sha256:" + "2" * 64
INSTALLED_SOURCE = "sha256:" + "3" * 64
INSTALLED_BUILD = "sha256:" + "4" * 64
OTHER = "sha256:" + "6" * 64
USER = application_runtime_user("10001:10001")
NOMINAL_USER = "10001:10001"
RELEASES = {"codeql": "codeql-fixture-1", "codeql_runner": "runner-fixture-1"}


@pytest.fixture(autouse=True)
def no_real_processes(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("preinstalled-runtime fixture attempted an external process")
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def declaration(build=SOURCE, installed=INSTALLED_SOURCE, **changes):
    return {"source_image_id": SOURCE, "build_image_id": build,
            "runtime_image_id": installed, "runtime_user": USER,
            "codeql_release_id": RELEASES["codeql"], "runner_release_id": RELEASES["codeql_runner"],
            **changes}


def settings_value():
    value = _settings_value()
    value.update(source_image_tag="source:fixture", source_image_id=SOURCE, runtime_user=USER,
                 threads=1, ram_mb=2048, concurrency=1,
                 preinstalled_runtimes=[declaration(), declaration(BASE, INSTALLED_BUILD)])
    for language in value["languages"].values():
        language.update(additional_queries=[], custom_queries=[])
    return value


class FakeDocker:
    def __init__(self, wrapper_path=None):
        self.calls = []
        self.images = {"source:fixture": SOURCE, "build:fixture": BASE,
                       INSTALLED_SOURCE: INSTALLED_SOURCE, INSTALLED_BUILD: INSTALLED_BUILD,
                       SOURCE: SOURCE, BASE: BASE}
        self.actions = []
        self.wrapper_path = wrapper_path

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        assert timeout > 0
        if argv[:3] == ("docker", "image", "inspect"):
            image = self.images.get(argv[3])
            return (0, (image + "\n").encode(), b"", False) if image else (1, b"", b"missing", False)
        if argv[:3] in {("docker", "volume", "create"), ("docker", "volume", "rm")}:
            return 0, b"", b"", False
        if argv[:3] == ("docker", "volume", "inspect"):
            return 0, b"fixture-generation", b"", False
        if argv[:3] == ("docker", "rm", "--force"):
            return 0, b"", b"", False
        if argv[:2] == ("docker", "run"):
            assert argv[argv.index("--entrypoint") + 1] in {"chown", "python3"}
            if argv[argv.index("--entrypoint") + 1] == "chown":
                return 0, b"", b"", False
            assert argv[argv.index("--user") + 1] == USER
            assert argv[argv.index("--cpus") + 1] == "1"
            assert argv[argv.index("--memory") + 1] == "3072m"
            assert argv[argv.index("--entrypoint") + 2] in {INSTALLED_SOURCE, INSTALLED_BUILD}
            wrapper_mounts = [value for value in argv if "dst=/opt/appsec/codeql_runner.py" in value]
            if self.wrapper_path is None:
                assert not wrapper_mounts
            else:
                assert wrapper_mounts == [
                    f"type=bind,src={self.wrapper_path},dst=/opt/appsec/codeql_runner.py,readonly"]
                assert self.wrapper_path.read_text() == "fixture application runner\n"
            lease = resources._ACTIVE.get()
            assert lease is not None and not lease.closed
            assert lease.request.cpu == 1 and lease.request.memory_mb == 3584
            mount = next(value for value in argv if value.startswith("type=bind,src=")
                         and value.endswith(",dst=/scratch"))
            scratch = Path(mount.removeprefix("type=bind,src=").removesuffix(",dst=/scratch"))
            action = argv[argv.index("/opt/appsec/codeql_runner.py") + 1]
            self.actions.append(action)
            if action == "inventory":
                atomic_json(scratch / "extractor-inventory.json",
                            {"schema": "appsec-review/codeql-extractor-inventory/1",
                             "languages": ["cpp", "python"]})
            elif action == "database":
                if argv[argv.index("--mode") + 1] == "manual":
                    replay = json.loads((scratch / "protected-replay.json").read_text())
                    assert replay["build_image_id"] == BASE
                    assert replay["commands"][0]["argv"] == ["cc", "-c", "main.c", "-o", "main.o"]
                    assert replay["dependency_hashes"] == {"target-dependency": "a" * 64}
                    assert argv[argv.index("--entrypoint") + 2] == INSTALLED_BUILD
                database = scratch / "database-export"
                database.mkdir()
                (database / "codeql-database.yml").write_text("fixture: true\n")
                (database / "data.bin").write_bytes(b"new database")
            elif action == "query":
                assert (scratch / "query-database/data.bin").read_bytes() == b"new database"
                atomic_json(scratch / "sarif/results.sarif", {"version": "2.1.0", "runs": []})
            else:
                pytest.fail(f"unexpected action {action}")
            return 0, b"fixture", b"", False
        pytest.fail(f"unexpected Docker operation: {argv}")


def resolver(tmp_path, *, value=None, docker=None, releases=None):
    return runtime.CodeQLImageResolver(
        repository_root=tmp_path, metadata_root=tmp_path / "metadata",
        settings=parse_codeql_settings(value or settings_value()), runner=docker or FakeDocker(),
        releases=ComponentReleases(RELEASES if releases is None else releases))


@pytest.mark.parametrize("build,installed", [(SOURCE, INSTALLED_SOURCE), (BASE, INSTALLED_BUILD)])
def test_explicit_runtime_is_inspected_each_time_without_build_or_cache_reuse(tmp_path, build, installed):
    docker = FakeDocker()
    selected = resolver(tmp_path, docker=docker)
    for _ in range(2):
        image, stdout, stderr = selected.resolve(
            build_image_tag="source:fixture" if build == SOURCE else "build:fixture",
            build_image_id=build, runtime_user=USER)
        assert image.schema == runtime.PREINSTALLED_IMAGE_SCHEMA
        assert image.preinstalled and image.image_build_performed is False and not image.reused
        assert image.preparation_receipt is None and image.image_id == image.image_tag == installed
        assert stdout == stderr == b""
        assert json.loads((selected.metadata_root / image.manifest_path).read_text()) == asdict(image)
    assert sum(call[3] == installed for call in docker.calls) == 2
    assert all(call[:3] == ("docker", "image", "inspect") for call in docker.calls)
    assert not (selected.metadata_root / "codeql-images").exists()


@pytest.mark.parametrize("field,value", [
    ("runtime_image_id", "runtime:latest"), ("source_image_id", "sha256:" + "9" * 64),
    ("build_image_id", 42), ("runtime_user", "0:0"),
    ("codeql_release_id", ""), ("runner_release_id", "bad release"),
    ("runner_source", "target"), ("runner_source", "/tmp/runner.py"), ("runner_source", False),
])
def test_invalid_operator_declarations_are_rejected(field, value):
    settings = settings_value()
    settings["preinstalled_runtimes"][0][field] = value
    with pytest.raises(ValueError):
        parse_codeql_settings(settings)


@pytest.mark.parametrize("mutation", ["unknown", "missing", "duplicate", "many", "table"])
def test_closed_and_bounded_declarations(mutation):
    settings = settings_value()
    rows = settings["preinstalled_runtimes"]
    if mutation == "unknown":
        rows[0]["trusted"] = True
    elif mutation == "missing":
        del rows[0]["runner_release_id"]
    elif mutation == "duplicate":
        rows.append(declaration())
    elif mutation == "many":
        settings["preinstalled_runtimes"] = [declaration()] * 129
    else:
        settings["preinstalled_runtimes"] = rows[0]
    with pytest.raises(ValueError):
        parse_codeql_settings(settings)


def test_declarations_are_frozen_and_detached_from_raw_config():
    value = settings_value()
    settings = parse_codeql_settings(value)
    value["preinstalled_runtimes"][0]["runtime_image_id"] = BASE
    assert settings.preinstalled_runtimes[0].runtime_image_id == INSTALLED_SOURCE
    with pytest.raises(FrozenInstanceError):
        settings.preinstalled_runtimes[0].runtime_image_id = BASE


@pytest.mark.parametrize("mutation", ["missing_environment", "user", "codeql", "runner", "missing_release"])
def test_missing_or_conflicting_binding_never_falls_back(tmp_path, mutation):
    docker = FakeDocker()
    releases = dict(RELEASES)
    value = settings_value()
    if mutation in {"codeql", "runner"}:
        releases["codeql" if mutation == "codeql" else "codeql_runner"] = "different-release"
    elif mutation == "missing_release":
        releases.clear()
    elif mutation == "user":
        value["preinstalled_runtimes"][0]["runtime_user"] = "12345:12345"
    selected = resolver(tmp_path, docker=docker, releases=releases, value=value)
    with pytest.raises(ValueError, match="preinstalled runtime"):
        selected.resolve(build_image_tag="source:fixture",
                         build_image_id="sha256:" + "9" * 64 if mutation == "missing_environment" else SOURCE,
                         runtime_user=USER)
    assert not docker.calls


class DerivedBuildReached(Exception):
    pass


def test_undeclared_environment_derives_under_derive_policy(tmp_path, monkeypatch):
    value = settings_value()
    value["preinstalled_undeclared"] = "derive"
    docker = FakeDocker()
    docker.images.update({"other:fixture": OTHER, OTHER: OTHER})
    selected = resolver(tmp_path, value=value, docker=docker)
    underived = settings_value()
    underived["preinstalled_runtimes"] = []
    derived = resolver(tmp_path, value=underived)
    assert selected.declared_identity(build_image_id=OTHER, runtime_user=USER) == (
        derived.declared_identity(build_image_id=OTHER, runtime_user=USER))
    failing = resolver(tmp_path)
    for build in (SOURCE, BASE):
        declared = selected.declared_identity(build_image_id=build, runtime_user=USER)
        assert declared == failing.declared_identity(build_image_id=build, runtime_user=USER)
        assert declared != derived.declared_identity(build_image_id=build, runtime_user=USER)
    image = selected.resolve(build_image_tag="build:fixture", build_image_id=BASE, runtime_user=USER)[0]
    assert image.schema == runtime.PREINSTALLED_IMAGE_SCHEMA and image.image_id == INSTALLED_BUILD
    assert image.identity == selected.declared_identity(build_image_id=BASE, runtime_user=USER)

    def reached():
        raise DerivedBuildReached
    monkeypatch.setattr(resources, "require_bounded_image_builder", reached)
    docker.calls.clear()
    with pytest.raises(DerivedBuildReached):
        selected.resolve(build_image_tag="other:fixture", build_image_id=OTHER, runtime_user=USER)
    assert all(call[:3] == ("docker", "image", "inspect") for call in docker.calls)
    inspected = {call[3] for call in docker.calls}
    assert "other:fixture" in inspected and not inspected & {INSTALLED_SOURCE, INSTALLED_BUILD}


@pytest.mark.parametrize("conflict", ["user", "codeql", "runner", "source"])
def test_conflicting_declaration_never_derives(tmp_path, conflict):
    docker = FakeDocker()
    releases = dict(RELEASES)
    value = settings_value()
    value["preinstalled_undeclared"] = "derive"
    if conflict == "user":
        value["preinstalled_runtimes"][0]["runtime_user"] = "12345:12345"
    elif conflict in {"codeql", "runner"}:
        releases["codeql" if conflict == "codeql" else "codeql_runner"] = "different-release"
    else:
        value["preinstalled_runtimes"][0]["source_image_id"] = "sha256:" + "9" * 64
    with pytest.raises(ValueError, match="preinstalled runtime"):
        selected = resolver(tmp_path, docker=docker, releases=releases, value=value)
        selected.resolve(build_image_tag="source:fixture", build_image_id=SOURCE, runtime_user=USER)
    assert not docker.calls


def test_missing_environment_error_names_environment_and_user(tmp_path):
    docker = FakeDocker()
    selected = resolver(tmp_path, docker=docker)
    assert selected.settings.preinstalled_undeclared == "fail"
    with pytest.raises(ValueError, match="environment/user declaration") as raised:
        selected.resolve(build_image_tag="other:fixture", build_image_id=OTHER, runtime_user=NOMINAL_USER)
    message = str(raised.value)
    assert f"build_image_id={OTHER}" in message
    assert f"effective_user={runtime.application_runtime_user(NOMINAL_USER)}" in message
    assert not docker.calls


@pytest.mark.parametrize("policy", ["fail", "derive"])
def test_preinstalled_undeclared_policy_accepts_closed_values(policy):
    value = settings_value()
    assert parse_codeql_settings(value).preinstalled_undeclared == "fail"
    value["preinstalled_undeclared"] = policy
    assert parse_codeql_settings(value).preinstalled_undeclared == policy


@pytest.mark.parametrize("key,invalid", [
    ("preinstalled_undeclared", "Derive"), ("preinstalled_undeclared", "warn"),
    ("preinstalled_undeclared", ""), ("preinstalled_undeclared", True),
    ("preinstalled_undeclared", 1), ("preinstalled_undeclared", None),
    ("preinstalled_undeclared", ["derive"]), ("preinstalled_undeclare", "derive"),
])
def test_preinstalled_undeclared_policy_is_closed_and_typed(key, invalid):
    value = settings_value()
    value[key] = invalid
    with pytest.raises(ValueError):
        parse_codeql_settings(value)


@pytest.mark.parametrize("invalid", ["warn", "", True, 1, None])
def test_preinstalled_undeclared_direct_construction_is_validated(invalid):
    with pytest.raises(ValueError, match="preinstalled_undeclared"):
        replace(parse_codeql_settings(settings_value()), preinstalled_undeclared=invalid)


@pytest.mark.parametrize("reference", ["source:fixture", "build:fixture", INSTALLED_BUILD])
@pytest.mark.parametrize("value", [None, "sha256:" + "9" * 64])
def test_actual_image_binding_mismatch_is_rejected(tmp_path, reference, value):
    docker = FakeDocker()
    docker.images[reference] = value
    with pytest.raises((ValueError, RuntimeError)):
        resolver(tmp_path, docker=docker).resolve(
            build_image_tag="build:fixture", build_image_id=BASE, runtime_user=USER)
    assert all(call[:3] == ("docker", "image", "inspect") for call in docker.calls)


def test_legacy_or_preinstalled_record_never_authorizes_an_unavailable_image(tmp_path):
    docker = FakeDocker()
    selected = resolver(tmp_path, docker=docker)
    image = selected.resolve(build_image_tag="source:fixture", build_image_id=SOURCE, runtime_user=USER)[0]
    atomic_json(selected.metadata_root / "codeql-images/legacy/manifest.json",
                {"schema": "appsec-review/codeql-derived-image/2", "image_id": INSTALLED_SOURCE})
    docker.images.pop(INSTALLED_SOURCE)
    with pytest.raises(ValueError, match="missing or differs"):
        selected.resolve(build_image_tag="source:fixture", build_image_id=SOURCE, runtime_user=USER)
    assert (selected.metadata_root / image.manifest_path).is_file()


def test_effective_user_cannot_silently_override_declared_user(tmp_path, monkeypatch):
    selected = resolver(tmp_path)
    image = selected.resolve(build_image_tag="source:fixture", build_image_id=SOURCE, runtime_user=USER)[0]
    monkeypatch.setattr(runtime, "application_runtime_user", lambda _: "12345:12345")
    with pytest.raises(ValueError, match="environment/user"):
        selected.resolve(build_image_tag="source:fixture", build_image_id=SOURCE, runtime_user=USER)
    with pytest.raises(ValueError, match="user changed"):
        runtime.CodeQLExecutor(image=image, run_root=tmp_path, settings=selected.settings,
                               runner=FakeDocker()).execute("inventory", (), scratch_root=tmp_path / "scratch")


def test_executor_rechecks_the_selected_installed_image(tmp_path):
    docker = FakeDocker()
    selected = resolver(tmp_path, docker=docker)
    image = selected.resolve(build_image_tag="source:fixture", build_image_id=SOURCE, runtime_user=USER)[0]
    docker.images.pop(INSTALLED_SOURCE)
    with pytest.raises(ValueError, match="runtime image.*unavailable"):
        runtime.CodeQLExecutor(image=image, run_root=tmp_path, settings=selected.settings,
                               runner=docker).execute("inventory", (), scratch_root=tmp_path / "scratch")
    assert all(call[:3] == ("docker", "image", "inspect") for call in docker.calls)


def test_selected_runtime_identity_changes_without_invalidating_other_environment(tmp_path):
    first = resolver(tmp_path)
    before = first.declared_identity(build_image_id=SOURCE, runtime_user=USER)
    compiled = first.declared_identity(build_image_id=BASE, runtime_user=USER)
    changed = settings_value()
    changed["preinstalled_runtimes"][0]["runtime_image_id"] = "sha256:" + "5" * 64
    second = resolver(tmp_path, value=changed)
    assert second.declared_identity(build_image_id=SOURCE, runtime_user=USER) != before
    assert second.declared_identity(build_image_id=BASE, runtime_user=USER) == compiled
    changed["preinstalled_runtimes"] = []
    assert resolver(tmp_path, value=changed).declared_identity(build_image_id=SOURCE, runtime_user=USER) != before


def test_preinstalled_identity_binds_effective_not_nominal_user(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "application_runtime_user", lambda _: "1000:1000")
    value = settings_value()
    for entry in value["preinstalled_runtimes"]:
        entry["runtime_user"] = "1000:1000"
    selected = resolver(tmp_path, value=value)
    expected = selected.declared_identity(build_image_id=BASE, runtime_user="1000:1000")
    assert selected.declared_identity(build_image_id=BASE, runtime_user=NOMINAL_USER) == expected
    image = selected.resolve(build_image_tag="build:fixture", build_image_id=BASE,
                             runtime_user=NOMINAL_USER)[0]
    assert image.identity == expected and image.runtime_user == "1000:1000"
    value["preinstalled_runtimes"] = []
    legacy = resolver(tmp_path, value=value)
    assert legacy.declared_identity(build_image_id=BASE, runtime_user=NOMINAL_USER) != (
        legacy.declared_identity(build_image_id=BASE, runtime_user="1000:1000"))


def test_runner_source_changes_only_selected_runtime_identity(tmp_path):
    value = settings_value()
    first = resolver(tmp_path, value=value)
    before = first.declared_identity(build_image_id=SOURCE, runtime_user=USER)
    compiled = first.declared_identity(build_image_id=BASE, runtime_user=USER)
    value["preinstalled_runtimes"][0]["runner_source"] = "application"
    selected = resolver(tmp_path, value=value)
    assert selected.declared_identity(build_image_id=SOURCE, runtime_user=USER) != before
    assert selected.declared_identity(build_image_id=BASE, runtime_user=USER) == compiled


@pytest.mark.parametrize("field", ["runner_source", "runner_release_id", "runtime_image_id", "missing"])
def test_executor_rejects_changed_preinstalled_declaration(tmp_path, field):
    docker = FakeDocker()
    selected = resolver(tmp_path, docker=docker)
    image = selected.resolve(build_image_tag="source:fixture", build_image_id=SOURCE, runtime_user=USER)[0]
    value = settings_value()
    if field == "missing":
        value["preinstalled_runtimes"] = []
    else:
        value["preinstalled_runtimes"][0][field] = {
            "runner_source": "application", "runner_release_id": "new-runner",
            "runtime_image_id": "sha256:" + "9" * 64}[field]
    docker.calls.clear()
    with pytest.raises(ValueError, match="declaration changed"):
        runtime.CodeQLExecutor(image=image, run_root=tmp_path, settings=parse_codeql_settings(value),
                               runner=docker).execute("inventory", (), scratch_root=tmp_path / "scratch")
    assert not docker.calls


@pytest.mark.parametrize("invalid", ["missing", "symlink", "escaped_parent"])
def test_application_runner_must_be_present_and_contained(tmp_path, monkeypatch, invalid):
    value = settings_value()
    value["preinstalled_runtimes"][0]["runner_source"] = "application"
    docker = FakeDocker()
    selected = resolver(tmp_path, value=value, docker=docker)
    image = selected.resolve(build_image_tag="source:fixture", build_image_id=SOURCE, runtime_user=USER)[0]
    path = tmp_path / "platform/containers/tools/codeql/codeql_runner.py"
    path.parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / path.name).write_text("unapproved runner")
    if invalid == "symlink":
        path.symlink_to(outside / path.name)
    elif invalid == "escaped_parent":
        path.parent.rmdir()
        path.parent.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(runtime, "application_asset", lambda _: path)
    docker.calls.clear()
    with pytest.raises(ValueError, match="trusted application root"):
        runtime.CodeQLExecutor(image=image, run_root=tmp_path, settings=selected.settings,
                               runner=docker).execute("inventory", (), scratch_root=tmp_path / "scratch")
    assert not docker.calls


def test_application_runner_does_not_expand_native_mount_authority(tmp_path, monkeypatch):
    value = settings_value()
    value["preinstalled_runtimes"][0]["runner_source"] = "application"
    docker = FakeDocker()
    selected = resolver(tmp_path, value=value, docker=docker)
    image = selected.resolve(build_image_tag="source:fixture", build_image_id=SOURCE, runtime_user=USER)[0]
    monkeypatch.setattr(runtime, "native_execution_requested", lambda: True)
    docker.calls.clear()
    with pytest.raises(ValueError, match="unsupported with native execution"):
        selected.resolve(build_image_tag="source:fixture", build_image_id=SOURCE, runtime_user=USER)
    with pytest.raises(ValueError, match="ordinary preinstalled execution"):
        runtime.CodeQLExecutor(image=image, run_root=tmp_path, settings=selected.settings,
                               runner=docker).execute("inventory", (), scratch_root=tmp_path / "scratch")
    assert not docker.calls


def test_no_declaration_keeps_required_bounded_preparation(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_NATIVE_REQUESTED", "1")
    value = settings_value()
    value["preinstalled_runtimes"] = []
    docker = FakeDocker()
    events = SimpleNamespace(write=lambda *args, **kwargs: None)
    with resources.review_resource_scope(tmp_path / "metadata", ResourceBudget(), events):
        with pytest.raises(resources.ImagePreparationUnavailable, match="derived_image_preparation_unavailable"):
            resolver(tmp_path, value=value, docker=docker).resolve(
                build_image_tag="source:fixture", build_image_id=SOURCE, runtime_user=USER)
    assert all(call[:3] == ("docker", "image", "inspect") for call in docker.calls)


@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
@pytest.mark.parametrize("compiled", [False, True])
@pytest.mark.parametrize("runner_source", ["image", "application"])
def test_jobrunner_inventory_database_and_query_use_real_executor_with_fake_engine(
        tmp_path, monkeypatch, mode, compiled, runner_source):
    wrapper_path = tmp_path / "platform/containers/tools/codeql/codeql_runner.py"
    wrapper_path.parent.mkdir(parents=True)
    wrapper_path.write_text("fixture application runner\n")
    def asset(name):
        assert name == "containers/tools/codeql/codeql_runner.py"
        return wrapper_path
    monkeypatch.setattr(runtime, "application_asset", asset)
    bound_paths = []
    def bind(path, runner):
        bound_paths.append(path)
        return str(path)
    docker = FakeDocker(wrapper_path if runner_source == "application" else None)
    monkeypatch.setattr(runtime, "_run", docker)
    monkeypatch.setattr(runtime, "resolve_host_bind_path", bind)
    monkeypatch.setattr(codeql, "load_asset_lock", lambda _: {})
    target = tmp_path / "target"
    target.mkdir()
    name = "main.c" if compiled else "main.py"
    (target / name).write_text("int application_state;\n" if compiled else "application_state = 1\n")
    snapshot = source_fingerprint(target)
    settings = settings_value()
    settings["runtime_user"] = NOMINAL_USER
    entries = settings.pop("preinstalled_runtimes")
    for entry in entries:
        entry["runner_source"] = runner_source
    policy = {"mode": mode, "project_id": "fixture",
              "approved_first_party_projects": ["fixture"], "target_root": str(target),
              "custody": "application_private_v1",
              "releases": {**{name: "fixture-1" for name in (
                  "platform", "validation", "build_toolchain", "extractor_cpp", "extractor_python",
                  "query_cpp_default", "query_python_default")}, **RELEASES}}
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(
        '[runtime]\nruns_dir = "runs"\ndata_dir = "data"\n' + build_capture_toml()
        + _table("review_policy", policy)
        + '\n[jobs.job_codeql_analysis]\nname = "fixture"\nworkers = 1\n'
        + _table("jobs.job_codeql_analysis.settings", settings)
        + "".join(_table("[jobs.job_codeql_analysis.settings.preinstalled_runtimes]", entry)
                  for entry in entries))
    config = load_config(config_path)

    def produce(unit):
        image = codeql._resolve_image(unit, build_image_tag="source:fixture",
                                      build_image_id=SOURCE, runtime_user=NOMINAL_USER)[0]
        result = runtime.CodeQLExecutor(image=image, run_root=unit.job.run_root,
                                       settings=unit.job.config.typed_settings).execute(
            "inventory", ("--output", "extractor-inventory.json"),
            scratch_root=unit.unit_root / "inventory")
        assert result.exit_code == 0 and image.image_id == INSTALLED_SOURCE
        receipts = {}
        if compiled:
            argv = ["cc", "-c", "main.c", "-o", "main.o"]
            protected = codeql._json_artifact(unit.job.run_root, unit.unit_root / "command.json",
                {"schema": "appsec-review/protected-build-command/2", "argv": argv,
                 "environment": {"LANG": "C"}, "working_directory": "/workspace"})
            receipts["build-unit-fixture"] = {
                "recipe": {"configure_commands": [], "build_commands": [argv]},
                "recipe_identity": "fixture-recipe",
                "image": {"image_id": BASE, "image_tag": "build:fixture", "user": NOMINAL_USER,
                          "dependency_hashes": {"target-dependency": "a" * 64}},
                "commands": [{"role": "build", "protected_argv": protected, "image_id": BASE,
                              "argv_sha256": hashlib.sha256(canonical_json(argv)).hexdigest(),
                              "working_directory": "/workspace"}]}
        language = "cpp" if compiled else "python"
        scope = CodeQLScope(SCOPE_SCHEMA, "codeql-unit-" + "1" * 24, language,
                            ("C",) if compiled else ("Python",), "manual" if compiled else "none", ".",
                            ({"path": name, "sha256": file_sha256(target / name),
                              "size_bytes": (target / name).stat().st_size},),
                            "build-unit-fixture" if compiled else None, None,
                            "fixture-environment", compiled)
        database = codeql._database_one(unit, scope, receipts)
        query = codeql._query_one(unit, database, codeql._query_profiles(
            unit.job.config.typed_settings.languages[language])[0])
        assert database["terminal_status"] == query["terminal_status"] == "SUCCEEDED"
        assert not database["database_reused"] and not query["query_reused"]
        assert codeql._database_one(unit, scope, receipts)["database_reused"]
        assert codeql._query_one(unit, database, query["query_profile"])["query_reused"]
        return {"databases": [database], "queries": [query]}

    definition = Job("job_codeql_analysis", "fixture", produce,
                     units=(Unit("execution.scopes", produce),), datasets=DATASETS)
    outcome = JobRunner(config).run(definition, target_root=target, source_fingerprint=snapshot)
    assert outcome["handoff"]["status"] == "ACCEPTED"
    run_root = config.runtime.runs_dir / outcome["status"]["run_id"]
    assert (run_root / "data/configuration/resolved.json").read_bytes() == config.resolved_json
    assert json.loads(config.resolved_json)["jobs"]["job_codeql_analysis"]["settings"][
        "preinstalled_runtimes"] == entries
    assert docker.actions == ["inventory", "database", "query"]
    assert bound_paths.count(wrapper_path) == (3 if runner_source == "application" else 0)
    events, _ = PipelineLog(run_root).read()
    resolved = [row["details"] for row in events if row["event_type"] == "CODEQL_RUNTIME_RESOLVED"]
    assert len(resolved) == 3
    assert all(row["preparation_kind"] == "preinstalled" and row["image_build_performed"] is False
               and row["checkpoint_reused"] is False for row in resolved)
    assert all(row["runner_source"] == runner_source and row["runtime_user"] == USER
               and row["requested_runtime_user"] == NOMINAL_USER for row in resolved)
    spans = [row["details"] for row in events if row["event_type"] == "OPERATION_COMPLETED"
             and row["details"].get("operation_id") == "codeql.runtime_resolution"]
    assert len(spans) == 3 and all(row["work"]["preinstalled_runtimes"] == 1
                                  and row["work"]["builder_launches"] == 0 for row in spans)
    assert not any(call[:3] in {("docker", "image", "tag"), ("docker", "buildx", "build")}
                   for call in docker.calls)
