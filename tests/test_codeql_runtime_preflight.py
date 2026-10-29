"""CodeQL runtime environments are validated together before any scope is admitted."""
from datetime import datetime, timezone
import subprocess
from types import SimpleNamespace

import pytest

from appsec_review.codeql import predecessor, runtime
from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_codeql_analysis import job as codeql
from appsec_review.jobs.job_codeql_analysis.datasets import DATASETS
from appsec_review.jobs.job_codeql_analysis.planning import CodeQLScope, SCOPE_SCHEMA
from appsec_review.runtime import Job, JobRunner, Unit, UnitContext
from tests.capture_fakes import build_capture_toml
from tests.test_codeql_predecessor import _table
from tests.test_codeql_preinstalled import BASE, RELEASES, SOURCE, USER, declaration, settings_value


UNDECLARED_A = "sha256:" + "5" * 64
UNDECLARED_B = "sha256:" + "6" * 64


def _scope(index, language, mode, build_unit_id):
    return CodeQLScope(SCOPE_SCHEMA, f"codeql-unit-{index:024d}", language, (language,), mode, ".",
                       (), build_unit_id, None, "fixture-environment", mode == "manual")


SCOPES = (
    _scope(1, "cpp", "manual", "build-cpp"),
    _scope(2, "java", "manual", "build-java-a"),
    _scope(3, "java", "manual", "build-java-b"),
    _scope(4, "javascript", "none", "build-js"),
    _scope(5, "python", "none", None),
)
RECEIPTS = {
    "build-cpp": {"image": {"image_tag": "build:cpp", "image_id": BASE, "user": USER}},
    "build-java-a": {"image": {"image_tag": "build:java", "image_id": UNDECLARED_A, "user": USER}},
    "build-java-b": {"image": {"image_tag": "build:java", "image_id": UNDECLARED_A, "user": USER}},
    "build-js": {"image": {"image_tag": "build:js", "image_id": UNDECLARED_B}},
}


class FakeEngine:
    """Docker boundary that has no images, so every derived resolution stops as a scope gap."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(tuple(argv))
        if tuple(argv[:3]) == ("docker", "image", "inspect"):
            return 1, b"", b"missing", False
        pytest.fail(f"unexpected Docker operation: {argv}")


@pytest.fixture
def harness(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("runtime preflight fixture attempted an external process")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    engine = FakeEngine()
    monkeypatch.setattr(runtime, "_run", engine)
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("print('fixture')\n")
    snapshot = source_fingerprint(target)
    policy = {
        "mode": "strict", "project_id": "fixture", "approved_first_party_projects": ["fixture"],
        "target_root": str(target), "custody": "application_private_v1",
        "store_authorization": {"tenant_id": "fixture-tenant", "runs_root": str(tmp_path / "runs")},
        "releases": {"platform": "fixture-v1", "validation": "fixture-v1",
                     "build_toolchain": "fixture-v1", **RELEASES},
    }

    def destination(settings):
        path = tmp_path / "appsec-review.toml"
        path.write_text(
            '[runtime]\nruns_dir = "runs"\ndata_dir = "data"\n' + build_capture_toml()
            + '\n[jobs.job_codeql_analysis]\nname = "fixture"\nworkers = 1\n'
            + _table("jobs.job_codeql_analysis.settings",
                     {key: value for key, value in settings.items() if key != "preinstalled_runtimes"})
            + "".join(_table("[jobs.job_codeql_analysis.settings.preinstalled_runtimes]", entry)
                      for entry in settings["preinstalled_runtimes"])
            + _table("review_policy", policy))
        config = load_config(path)
        job = Job(predecessor.JOB, "fixture", lambda context: {},
                  units=(Unit("execution.scopes", lambda context: {}),), datasets=DATASETS)
        runner = JobRunner(config)
        claim = runner.begin_attempt(job, target_root=target, source_fingerprint=snapshot,
                                     now=datetime(2026, 10, 29, tzinfo=timezone.utc))
        context = runner._context_from_claim(job, claim)
        return UnitContext(context, "execution.scopes", "execution", "scopes",
                           context.attempt_root / "steps/execution/tasks/scopes", {"plan.inventory": {}})

    reservations, imports = [], []
    original_reserve = codeql.ResourceAdmission.reserve
    original_import = codeql._import_predecessor_databases

    def reserve(self, request, **kwargs):
        reservations.append((kwargs.get("action"), kwargs.get("scope_id")))
        return original_reserve(self, request, **kwargs)

    def import_databases(*args, **kwargs):
        imports.append(args[1])
        return original_import(*args, **kwargs)

    monkeypatch.setattr(codeql.ResourceAdmission, "reserve", reserve)
    monkeypatch.setattr(codeql, "_import_predecessor_databases", import_databases)
    monkeypatch.setattr(codeql, "_plan_from", lambda unit: SimpleNamespace(scopes=SCOPES))
    monkeypatch.setattr(codeql, "_receipt_map", lambda unit: RECEIPTS)
    monkeypatch.setattr(codeql, "_normalize_one", lambda unit, value: {**value, "observation_count": 0})
    execution = next(item for item in codeql.build_job().units if item.unit_id == "execution.scopes")
    return SimpleNamespace(destination=destination, execute=execution.handler, engine=engine,
                           reservations=reservations, imports=imports)


def _settings(policy):
    value = settings_value()
    value["preinstalled_undeclared"] = policy
    return value


def test_fail_policy_reports_every_undeclared_environment_before_admission(harness):
    unit = harness.destination(_settings("fail"))
    with pytest.raises(ValueError) as raised:
        harness.execute(unit)
    message = str(raised.value)
    assert message.startswith("CodeQL runtime preflight rejected 2 of 4 environment(s) "
                              "(preinstalled_undeclared=fail)")
    java = (f"image_id={UNDECLARED_A} runtime_user={USER} effective_user={USER} "
            f"scopes=[{SCOPES[1].scope_id}, {SCOPES[2].scope_id}]: CodeQL preinstalled runtime requires "
            f"one exact environment/user declaration (build_image_id={UNDECLARED_A}, effective_user={USER})")
    javascript = (f"image_id={UNDECLARED_B} runtime_user={USER} effective_user={USER} "
                  f"scopes=[{SCOPES[3].scope_id}]: CodeQL preinstalled runtime requires one exact "
                  f"environment/user declaration (build_image_id={UNDECLARED_B}, effective_user={USER})")
    assert java in message and javascript in message
    assert BASE not in message and f"image_id={SOURCE}" not in message
    assert SCOPES[0].scope_id not in message and SCOPES[4].scope_id not in message
    assert harness.imports == [] and harness.reservations == [] and harness.engine.calls == []
    assert not list(unit.job.run_root.glob("data/codeql/scopes/*"))


def test_derive_policy_passes_preflight_and_schedules_every_scope(harness):
    unit = harness.destination(_settings("derive"))
    result = harness.execute(unit)
    assert harness.imports == [SCOPES]
    assert sorted(scope for action, scope in harness.reservations if action == "codeql.database") == sorted(
        scope.scope_id for scope in SCOPES)
    inspected = [call[3] for call in harness.engine.calls]
    assert inspected.count(unit.job.config.typed_settings.source_image_tag) == len(SCOPES)
    assert [item["terminal_status"] for item in result["databases"]] == ["FAILED"] * len(SCOPES)
    assert {item["scope"]["scope_id"]: item["gaps"] for item in result["databases"]} == {
        scope.scope_id: [f"CodeQL {scope.language} database producer failed (RuntimeError)"]
        for scope in SCOPES}
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"


def test_without_declarations_every_environment_is_derived_and_scheduled(harness):
    value = _settings("fail")
    value["preinstalled_runtimes"] = []
    unit = harness.destination(value)
    result = harness.execute(unit)
    assert len([action for action, _ in harness.reservations if action == "codeql.database"]) == len(SCOPES)
    assert [item["terminal_status"] for item in result["databases"]] == ["FAILED"] * len(SCOPES)


@pytest.mark.parametrize("conflict", [
    {"runtime_user": "12345:12345"},
    {"codeql_release_id": "codeql-other"},
])
def test_conflicting_declaration_still_fails_preflight_under_derive(harness, conflict):
    value = _settings("derive")
    value["preinstalled_runtimes"].append(declaration(UNDECLARED_A, "sha256:" + "7" * 64, **conflict))
    unit = harness.destination(value)
    with pytest.raises(ValueError) as raised:
        harness.execute(unit)
    message = str(raised.value)
    assert message.startswith("CodeQL runtime preflight rejected 1 of 4 environment(s) "
                              "(preinstalled_undeclared=derive)")
    assert f"image_id={UNDECLARED_A}" in message
    assert SCOPES[1].scope_id in message and SCOPES[2].scope_id in message
    assert UNDECLARED_B not in message
    assert harness.imports == [] and harness.reservations == [] and harness.engine.calls == []


def test_preflight_truncates_a_large_failure_listing(harness):
    unit = harness.destination(_settings("fail"))
    scopes = tuple(_scope(100 + index, "go", "manual", f"build-go-{index}") for index in range(40))
    receipts = {f"build-go-{index}": {"image": {"image_tag": "build:go",
                                                  "image_id": "sha256:" + f"{index:064x}", "user": USER}}
                for index in range(39)}
    receipts["build-go-39"] = {"image": {"image_tag": "build:go", "image_id": "sha256:" + f"{0:064x}",
                                         "user": USER}}
    shared = tuple(_scope(200 + index, "go", "manual", "build-go-0") for index in range(20))
    with pytest.raises(ValueError) as raised:
        codeql._preflight_runtime_environments(unit, scopes + shared, receipts,
                                               unit.job.config.typed_settings)
    message = str(raised.value)
    assert message.startswith("CodeQL runtime preflight rejected 39 of 39 environment(s)")
    assert message.count("runtime_user=") == 32 and message.endswith("... 7 more environments")
    assert ", ... 6 more]" in message


class _Stop(Exception):
    pass


@pytest.mark.parametrize("index", [0, 3, 4])
def test_helper_matches_the_environment_database_one_resolves(harness, monkeypatch, index):
    unit = harness.destination(_settings("fail"))
    settings = unit.job.config.typed_settings
    seen = []

    def resolve(context, **kwargs):
        seen.append(kwargs)
        raise _Stop

    monkeypatch.setattr(codeql, "_resolve_image", resolve)
    scope = SCOPES[index]
    with pytest.raises(_Stop):
        codeql._database_one(unit, scope, RECEIPTS)
    expected = {
        0: ("build:cpp", BASE, USER),
        3: ("build:js", UNDECLARED_B, USER),
        4: (settings.source_image_tag, SOURCE, USER),
    }[index]
    assert codeql._scope_runtime_environment(scope, RECEIPTS, settings) == expected
    assert seen == [{"build_image_tag": expected[0], "build_image_id": expected[1],
                     "runtime_user": expected[2], "scope_id": scope.scope_id, "build_image_derived_from": None}]


def test_helper_keeps_missing_build_unit_an_integrity_failure(harness):
    unit = harness.destination(_settings("derive"))
    with pytest.raises(codeql.FrameworkIntegrityError, match="planned build unit disappeared"):
        codeql._scope_runtime_environment(SCOPES[0], {}, unit.job.config.typed_settings)
