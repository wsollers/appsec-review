"""Pre-walk JobRunner suite for job_codeql_analysis relocated under T-113.

Covers preinstalled and derived runtime execution through JobRunner against a fake Docker engine.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from appsec_review.codeql import runtime
from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_codeql_analysis import job as codeql
from appsec_review.jobs.job_codeql_analysis.datasets import DATASETS
from appsec_review.jobs.job_codeql_analysis.planning import CodeQLScope, SCOPE_SCHEMA
from appsec_review.observability import PipelineLog
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.storage import canonical_json, file_sha256
from tests.capture_fakes import build_capture_toml
from tests.host_pins_support import fixture_bindings, write_host_pins
from tests.test_codeql_predecessor import _table
from tests.test_codeql_preinstalled import (
    BASE,
    INSTALLED_SOURCE,
    NOMINAL_USER,
    OTHER,
    RELEASES,
    SOURCE,
    USER,
    FakeDocker,
    settings_value,
)

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[3]
DERIVED = "sha256:" + "7" * 64
OTHER_TAG = "appsec-review-project-native:fixture"


@pytest.fixture(autouse=True)
def no_real_processes(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("CodeQL JobRunner integration fixture attempted an external process")
    monkeypatch.setattr(subprocess, "Popen", forbidden)


class DerivingDocker:
    """Fake engine that serves declared runtimes and builds one derived layer for ``OTHER``."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.images = {"source:fixture": SOURCE, SOURCE: SOURCE, OTHER_TAG: OTHER, OTHER: OTHER,
                       INSTALLED_SOURCE: INSTALLED_SOURCE}
        self.runs: list[tuple[str, str, str]] = []
        self.derived_tag: str | None = None

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        assert timeout > 0
        if argv[:3] == ("docker", "image", "inspect"):
            image = self.images.get(argv[3])
            return (0, (image + "\n").encode(), b"", False) if image else (1, b"", b"missing", False)
        if argv[:3] == ("docker", "image", "tag"):
            assert argv[3] in {SOURCE, OTHER}
            self.images[argv[4]] = argv[3]
            return 0, b"", b"", False
        if argv[:3] == ("docker", "buildx", "build"):
            assert argv[argv.index("--network") + 1] == "none"
            arguments = dict(argv[index + 1].split("=", 1)
                             for index, value in enumerate(argv) if value == "--build-arg")
            assert arguments["RUNTIME_USER"] == NOMINAL_USER
            assert self.images[arguments["BUILD_IMAGE"]] == OTHER
            assert self.images[arguments["CODEQL_SOURCE_IMAGE"]] == SOURCE
            context = Path(argv[-1])
            assert (context / "Dockerfile").read_bytes() == (
                ROOT / "containers/tools/codeql/Dockerfile").read_bytes()
            self.derived_tag = argv[argv.index("--tag") + 1]
            self.images[self.derived_tag] = DERIVED
            self.images[DERIVED] = DERIVED
            return 0, b"built", b"", False
        if argv[:3] in {("docker", "volume", "create"), ("docker", "volume", "rm")}:
            return 0, b"", b"", False
        if argv[:3] == ("docker", "volume", "inspect"):
            return 0, b"fixture-generation", b"", False
        if argv[:3] == ("docker", "rm", "--force"):
            return 0, b"", b"", False
        if argv[:2] == ("docker", "run"):
            entrypoint = argv[argv.index("--entrypoint") + 1]
            image = argv[argv.index("--entrypoint") + 2]
            if entrypoint == "chown":
                return 0, b"", b"", False
            assert entrypoint == "python3"
            assert argv[argv.index("--user") + 1] == USER
            assert "--read-only" in argv
            assert argv[argv.index("--tmpfs") + 1].startswith("/tmp:rw,noexec")
            assert not any("dst=/opt/appsec/codeql_runner.py" in value for value in argv)
            action = argv[argv.index("/opt/appsec/codeql_runner.py") + 1]
            mount = next(value for value in argv if value.startswith("type=bind,src=")
                         and value.endswith(",dst=/scratch"))
            scratch = Path(mount.removeprefix("type=bind,src=").removesuffix(",dst=/scratch"))
            assert action == "database"
            mode = argv[argv.index("--mode") + 1]
            self.runs.append((action, mode, image))
            if mode == "manual":
                replay = json.loads((scratch / "protected-replay.json").read_text())
                assert replay["build_image_id"] == OTHER
                assert image == DERIVED
            else:
                assert image == INSTALLED_SOURCE
            database = scratch / "database-export"
            database.mkdir()
            (database / "codeql-database.yml").write_text("fixture: true\n")
            (database / "data.bin").write_bytes(b"database")
            return 0, b"fixture", b"", False
        pytest.fail(f"unexpected Docker operation: {argv}")


def test_jobrunner_derives_runtime_for_undeclared_receipt_image(tmp_path, monkeypatch):
    for name in [name for name in os.environ if name.startswith("APPSEC_NATIVE_")]:
        monkeypatch.delenv(name)
    docker = DerivingDocker()
    monkeypatch.setattr(runtime, "_run", docker)
    monkeypatch.setattr(runtime, "resolve_host_bind_path", lambda path, runner: str(path))
    monkeypatch.setattr(codeql, "load_asset_lock", lambda _: {})
    tools = tmp_path / "containers/tools/codeql"
    tools.mkdir(parents=True)
    for name in ("Dockerfile", "Dockerfile.source", "codeql_runner.py"):
        shutil.copyfile(ROOT / "containers/tools/codeql" / name, tools / name)
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.c").write_text("int application_state;\n")
    (target / "main.py").write_text("application_state = 1\n")
    snapshot = source_fingerprint(target)
    settings = settings_value()
    settings.update(runtime_user=NOMINAL_USER, preinstalled_undeclared="derive")
    entries = settings.pop("preinstalled_runtimes")[:1]
    policy = {"mode": "strict", "project_id": "fixture",
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
        + _table("jobs.job_codeql_analysis.settings", settings))
    host = write_host_pins(tmp_path / "host-pins.toml",
                           images={**fixture_bindings(), "source:fixture": SOURCE},
                           runtimes=entries)
    config = load_config(config_path, host_pins=host)
    assert config.job("job_codeql_analysis").typed_settings.preinstalled_undeclared == "derive"

    def produce(unit):
        argv = ["cc", "-c", "main.c", "-o", "main.o"]
        protected = codeql._json_artifact(unit.job.run_root, unit.unit_root / "command.json",
            {"schema": "appsec-review/protected-build-command/2", "argv": argv,
             "environment": {"LANG": "C"}, "working_directory": "/workspace"})
        receipts = {"build-unit-native": {
            "recipe": {"configure_commands": [], "build_commands": [argv]},
            "recipe_identity": "fixture-recipe",
            "image": {"image_id": OTHER, "image_tag": OTHER_TAG, "user": NOMINAL_USER,
                      "dependency_hashes": {}},
            "commands": [{"role": "build", "protected_argv": protected, "image_id": OTHER,
                          "argv_sha256": hashlib.sha256(canonical_json(argv)).hexdigest(),
                          "working_directory": "/workspace"}]}}

        def record(name):
            return ({"path": name, "sha256": file_sha256(target / name),
                     "size_bytes": (target / name).stat().st_size},)

        python = CodeQLScope(SCOPE_SCHEMA, "codeql-unit-" + "1" * 24, "python", ("Python",), "none",
                             ".", record("main.py"), None, None, "fixture-environment", False)
        native = CodeQLScope(SCOPE_SCHEMA, "codeql-unit-" + "2" * 24, "cpp", ("C",), "manual", ".",
                             record("main.c"), "build-unit-native", None, "fixture-environment", True)
        typed = unit.job.config.typed_settings
        codeql._preflight_runtime_environments(unit, (python, native), receipts, typed)
        databases = [codeql._database_one(unit, scope, receipts) for scope in (python, native)]
        assert [item["terminal_status"] for item in databases] == ["SUCCEEDED", "SUCCEEDED"]
        reused = codeql._database_one(unit, native, receipts)
        assert reused["database_reused"]
        image = json.loads((unit.job.run_root / "data/codeql/scopes" / native.scope_id
                            / "image.json").read_text())
        assert image["schema"] == runtime.IMAGE_SCHEMA and image["preinstalled"] is False
        assert image["image_id"] == DERIVED and image["build_image_id"] == OTHER
        assert image["runtime_user"] == NOMINAL_USER and image["runner_source"] == "image"
        return {"databases": [databases[0], reused], "queries": []}

    definition = Job("job_codeql_analysis", "fixture", produce, units=(Unit("execution.scopes", produce),))
    outcome = JobRunner(config).run(definition, target_root=target, source_fingerprint=snapshot)
    assert outcome["handoff"]["status"] == "ACCEPTED"
    run_root = config.runtime.runs_dir / outcome["status"]["run_id"]
    events, _ = PipelineLog(run_root).read()
    resolved = [row["details"] for row in events if row["event_type"] == "CODEQL_RUNTIME_RESOLVED"]
    assert [(row["preparation_kind"], row["image_build_performed"], row["checkpoint_reused"])
            for row in resolved] == [("preinstalled", False, False), ("derived", True, False),
                                     ("derived", False, True)]
    derived = resolved[1:]
    assert all(row["build_image_id"] == OTHER and row["image_id"] == DERIVED
               and row["runtime_user"] == NOMINAL_USER and row["requested_runtime_user"] == NOMINAL_USER
               and row["runner_source"] == "image" for row in derived)
    assert derived[0]["image_identity"] == derived[1]["image_identity"]
    assert resolved[0]["image_id"] == INSTALLED_SOURCE and resolved[0]["runtime_user"] == USER
    builds = [call for call in docker.calls if call[:3] == ("docker", "buildx", "build")]
    assert len(builds) == 1 and docker.derived_tag is not None
    assert sorted(call[3] for call in docker.calls if call[:3] == ("docker", "image", "tag")) == sorted(
        [SOURCE, OTHER])
    assert docker.runs == [("database", "none", INSTALLED_SOURCE), ("database", "manual", DERIVED)]
    assert not any("requires one exact environment/user declaration" in json.dumps(row)
                   for row in events)


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
        + '\n[jobs.job_codeql_analysis.steps.acceptance]\n'
        + _table("jobs.job_codeql_analysis.settings", settings))
    host = write_host_pins(tmp_path / "host-pins.toml",
                           images={**fixture_bindings(), "source:fixture": SOURCE}, runtimes=entries)
    config = load_config(config_path, host_pins=host)

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
