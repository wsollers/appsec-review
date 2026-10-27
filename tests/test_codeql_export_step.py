"""Offline tests for the job_codeql_analysis graph export step (code-graph plan chunk C2)."""
from __future__ import annotations

import copy
from dataclasses import asdict, replace
import importlib.util
import json
from pathlib import Path
import shutil
import tomllib
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

from appsec_review.codeql.runtime import (
    action_timeout, graph_compile_arguments, graph_export_arguments, load_asset_lock,
)
from appsec_review.config import load_config, parse_codeql_settings
from appsec_review.config.assurance import ComponentReleases, ReviewPolicy
from appsec_review.graph.contract import GraphSettings
from appsec_review.indexing.inventory import Claim, FileClaims, runtime_claims, scan_run_tree
from appsec_review.jobs.job_codeql_analysis.datasets import DATASETS
from appsec_review.jobs.job_codeql_analysis.job import (
    FrameworkIntegrityError,
    _database_identity,
    _export_identity,
    _export_one,
    _export_profile,
    _export_scopes,
    _query_identity,
    _query_profiles,
    _validate_config,
    build_job,
)
from appsec_review.jobs.job_codeql_analysis.planning import (
    SCOPE_SCHEMA,
    CodeQLScope,
    export_lock_mismatches,
    plan_graph_exports,
)
from appsec_review.storage import atomic_json, file_sha256


ROOT = Path(__file__).parents[1]
NATIVE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "native" / "exports"
IMAGE = "sha256:" + "1" * 64
JOB = "job_codeql_analysis"


def _runner_module():
    spec = importlib.util.spec_from_file_location(
        "appsec_review_codeql_export_step_runner", ROOT / "containers" / "tools" / "codeql" / "codeql_runner.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNNER = _runner_module()


def _settings(mode: str = "whole_program"):
    """The central settings; these whole-program tests pin the mode, seeded mode has its own tests."""
    settings = load_config(ROOT / "appsec-review.toml").job(JOB).typed_settings
    return replace(settings, export_queries=replace(settings.export_queries, mode=mode))


def _scope(language: str, root: str, unit: str) -> CodeQLScope:
    files = ({"path": f"{root}/main.{'cpp' if language == 'cpp' else 'go'}", "sha256": "a" * 64,
              "size_bytes": 12},)
    return CodeQLScope(SCOPE_SCHEMA, f"codeql-unit-{unit * 24}", language, ("C++",) if language == "cpp"
                       else ("Go",), "manual", root, files, f"build-unit-{unit * 20}", unit * 64, "e" * 64, True)


class Events:
    def __init__(self) -> None:
        self.records: list[tuple[str, dict[str, Any]]] = []

    def write(self, event_type: str, **details: Any) -> None:
        self.records.append((event_type, details))


def _unit(tmp_path: Path, databases: list[dict[str, Any]], settings=None) -> SimpleNamespace:
    run_root = tmp_path / "run"
    job = SimpleNamespace(run_root=run_root, repository_root=ROOT, source_fingerprint="f" * 64,
                          review_policy=ReviewPolicy(releases=ComponentReleases(
                              {"codeql_runner": "fixture-1", "export_cpp": "fixture-1"})),
                          events=Events(), attempt_root=run_root / "data" / "jobs" / JOB / "attempts" / "attempt_0001",
                          config=SimpleNamespace(typed_settings=settings or _settings()))
    outputs = {"database.scopes": {"databases": databases}}
    return SimpleNamespace(job=job, unit_id="export.scopes", output=lambda name: outputs[name])


def _database(tmp_path: Path, scope: CodeQLScope, *, identity: str = "d" * 64,
              status: str = "SUCCEEDED") -> dict[str, Any]:
    run_root = tmp_path / "run"
    root = run_root / "data" / "codeql" / "scopes" / scope.scope_id
    (root / "database" / "db-cpp").mkdir(parents=True, exist_ok=True)
    (root / "database" / "db-cpp" / "default.trap").write_text("database bytes", encoding="utf-8")
    atomic_json(root / "database-checkpoint.json", {"schema": "appsec-review/codeql-database-checkpoint/3",
                                                     "identity": identity, "terminal_status": "SUCCEEDED"})
    image = {"schema": "appsec-review/codeql-derived-image/3", "identity": "a" * 64, "source_image_id": IMAGE,
             "build_image_id": IMAGE, "build_image_tag": "build:local", "image_id": IMAGE,
             "image_tag": "codeql:local", "runtime_user": "10001:10001", "component_release_id": "fixture-1",
             "runner_release_id": "fixture-1", "reused": False, "manifest_path": "manifest.json"}
    atomic_json(root / "image.json", image)
    image_artifact = {"path": (root / "image.json").relative_to(run_root).as_posix(),
                      "sha256": file_sha256(root / "image.json")}
    return {"scope": asdict(scope), "terminal_status": status, "database_identity": identity,
            "database_tree_sha256": "7" * 64, "image": image_artifact, "gaps": []}


@pytest.fixture(autouse=True)
def _cold_compile_cache():
    from appsec_review.jobs.job_codeql_analysis import job as codeql_job
    codeql_job._PRECOMPILED.clear()
    yield
    codeql_job._PRECOMPILED.clear()


class FakeExecutor:
    """Stands in for CodeQLExecutor: checks the staged scratch, then plays back C1's recording."""

    def __init__(self, *, outcome: dict[str, tuple[int | None, bool]] | None = None,
                 tamper: bool = False) -> None:
        self.calls: list[tuple[str, tuple[str, ...], Path]] = []
        self.compiles: list[tuple[str, ...]] = []
        self.compile_outcome: tuple[int | None, bool] = (0, False)
        self.outcome = outcome or {}
        self.tamper = tamper

    def factory(self, image, run_root, settings):
        assert image.image_id == IMAGE and settings.export_queries.row_limit == 200000
        return self

    def execute(self, action: str, argv, *, scratch_root: Path):
        if action == "compile":
            self.compiles.append(tuple(argv))
            assert tuple(argv) == graph_compile_arguments(
                pack="export/pack", columns="export/columns.json", asset_lock="export/assets.lock.json",
                language="cpp", threads=8, ram_mb=8192)
            assert (scratch_root / "export" / "pack" / "qlpack.yml").is_file()
            atomic_json(scratch_root / "executions" / action / "receipt.json",
                        {"schema": "appsec-review/codeql-execution/2", "action": action})
            code, timed_out = self.compile_outcome
            return SimpleNamespace(exit_code=code, timed_out=timed_out, duration_ms=7,
                                   stdout_truncated=False, stderr_truncated=False)
        self.calls.append((action, tuple(argv), scratch_root))
        values = dict(zip(argv[::2], argv[1::2]))
        assert action == "export" and values["--language"] == "cpp"
        assert tuple(argv) == graph_export_arguments(
            database="export/database", pack="export/pack", columns="export/columns.json",
            asset_lock="export/assets.lock.json", language="cpp", output_dir="exports",
            row_limit=200000, max_bytes=268435456, threads=2, ram_mb=4096,
            scope_file="export/scope.csv", seeds_file="export/seeds.csv")
        assert (scratch_root / values["--scope-file"]).read_text(encoding="utf-8") == "whole_program,0\n"
        assert (scratch_root / values["--seeds-file"]).read_text(encoding="utf-8") == ""
        # The staged pack, columns and lock pass the runner's own lock check.
        lock = json.loads((scratch_root / values["--asset-lock"]).read_text(encoding="utf-8"))
        RUNNER._verify_export_pack(lock["export_query_packs"]["cpp"], scratch_root / values["--pack"],
                                   scratch_root / values["--columns"])
        assert (scratch_root / values["--database"] / "db-cpp" / "default.trap").is_file()
        assert not (scratch_root / values["--output-dir"]).exists()
        code, timed_out = self.outcome.get(scratch_root.name, (0, False))
        if code == 0 and not timed_out:
            shutil.copytree(NATIVE, scratch_root / values["--output-dir"])
            if self.tamper:
                path = scratch_root / values["--output-dir"] / "call_sites.json"
                path.write_bytes(path.read_bytes().replace(b"3", b"4", 1))
        receipt = scratch_root / "executions" / action / "receipt.json"
        atomic_json(receipt, {"schema": "appsec-review/codeql-execution/2", "action": action})
        return SimpleNamespace(exit_code=code, timed_out=timed_out, duration_ms=5,
                               stdout_truncated=False, stderr_truncated=False)


def _never(image, run_root, settings):
    raise AssertionError("a reused export checkpoint must not execute CodeQL")


def test_export_writes_exports_and_manifest_publishes_hashes_and_reuses(tmp_path: Path) -> None:
    cpp, go = _scope("cpp", "native", "a"), _scope("go", "svc", "b")
    databases = [_database(tmp_path, cpp), _database(tmp_path, go)]
    unit = _unit(tmp_path, databases)
    executor = FakeExecutor()
    output = _export_scopes(unit, executor_factory=executor.factory)

    assert len(executor.calls) == 1 and executor.calls[0][2].name == cpp.scope_id
    assert output["terminal_status"] == "SUCCEEDED" and output["gaps"] == []
    by_scope = {item["scope_id"]: item for item in output["exports"]}
    exported, skipped = by_scope[cpp.scope_id], by_scope[go.scope_id]
    assert skipped["export_status"] == "NOT_APPLICABLE" and skipped["gaps"] == []
    assert "no hash-pinned CodeQL graph export pack for go" in skipped["reason"]

    run_root = unit.job.run_root
    exports_root = run_root / "data" / "codeql" / "scopes" / cpp.scope_id / "exports"
    assert sorted(path.name for path in exports_root.iterdir()) == sorted(path.name for path in NATIVE.iterdir())
    assert not (exports_root.parent / "export").exists(), "the staged scratch is disposable"
    assert exported["export_status"] == "SUCCEEDED" and exported["export_reused"] is False
    assert exported["export_manifest"] == {
        "path": f"data/codeql/scopes/{cpp.scope_id}/exports/export-manifest.json",
        "sha256": file_sha256(NATIVE / "export-manifest.json"),
        "size_bytes": (NATIVE / "export-manifest.json").stat().st_size}
    assert {item["query_id"]: item["sha256"] for item in exported["export_files"]} == {
        path.stem: file_sha256(path) for path in NATIVE.glob("*.json") if path.name != "export-manifest.json"}
    assert exported["export_count"] == 12 and exported["truncated_queries"] == []
    assert exported["export_pack"]["tree_sha256"] == load_asset_lock(ROOT)["export_query_packs"]["cpp"]["tree_sha256"]
    assert exported["export_execution"]["path"].endswith("/executions/export/receipt.json")
    index = json.loads((run_root / output["artifact"]["path"]).read_text(encoding="utf-8"))
    assert output["artifact"]["path"].endswith("/artifacts/codeql/graph-exports.json")
    assert index["schema"] == output["schema"] == "appsec-review/codeql-graph-exports/1"
    assert [item["scope_id"] for item in index["exports"]] == [cpp.scope_id, go.scope_id]
    assert output["dispositions"] == [
        {"scope_id": cpp.scope_id, "language": "cpp", "action": "export", "terminal_status": "SUCCEEDED"},
        {"scope_id": go.scope_id, "language": "go", "action": "export", "terminal_status": "NOT_APPLICABLE"}]
    export_events = [(name, details) for name, details in unit.job.events.records
                     if details.get("tool_id") == "codeql-graph-export"]
    assert [name for name, _details in export_events] == ["TOOL_INVOCATION_STARTED", "TOOL_INVOCATION_COMPLETED"]
    compile_events = [name for name, details in unit.job.events.records
                      if details.get("tool_id") == "codeql-graph-export-compile"]
    assert compile_events == ["TOOL_INVOCATION_STARTED", "TOOL_INVOCATION_COMPLETED"]
    preparation = [(name, details) for name, details in unit.job.events.records
                   if details.get("operation_id") == "codeql.prepare.export"]
    assert [name for name, _ in preparation] == ["OPERATION_STARTED", "OPERATION_COMPLETED"]
    assert preparation[1][1]["terminal_status"] == "SUCCEEDED"
    assert preparation[1][1]["work"] == {"copy_bytes": len(b"database bytes"), "copy_objects": 1}
    for _, details in preparation:
        assert details["scope_id"] == cpp.scope_id
        assert details["tool_invocation_id"] == export_events[0][1]["tool_invocation_id"]
        assert details["unit_id"] == unit.unit_id

    rerun_unit = _unit(tmp_path, databases)
    rerun = _export_scopes(rerun_unit, executor_factory=_never)
    reused = next(item for item in rerun["exports"] if item["scope_id"] == cpp.scope_id)
    assert reused["export_reused"] is True and rerun["export_reused"] == 1
    assert reused["export_identity"] == exported["export_identity"]
    assert reused["export_files"] == exported["export_files"]
    assert not any(details.get("operation_id") == "codeql.prepare.export"
                   for _, details in rerun_unit.job.events.records)


def test_database_or_pack_change_invalidates_only_the_export_checkpoint(tmp_path: Path) -> None:
    settings = _settings()
    cpp = _scope("cpp", "native", "a")
    database = _database(tmp_path, cpp)
    profile = _export_profile(settings, "cpp")
    assert profile is not None
    identity = _export_identity(database, profile, settings, runner_sha256="9" * 64)
    assert _export_identity({**database, "database_identity": "e" * 64}, profile, settings,
                            runner_sha256="9" * 64) != identity
    assert _export_identity(database, {**profile, "tree_sha256": "0" * 64}, settings,
                            runner_sha256="9" * 64) == identity
    assert _export_identity(database, profile, settings, runner_sha256="new-release") != identity
    assert _export_identity(database, profile, replace(settings, export_queries=replace(
        settings.export_queries, row_limit=10)), runner_sha256="9" * 64) != identity
    # The catalog is read only by the downstream normalizer: it never invalidates an export.
    assert _export_identity(database, {**profile, "catalog_sha256": "0" * 64}, settings,
                            runner_sha256="9" * 64) == identity

    # A changed export pack leaves the database and query identities untouched.
    language = settings.languages["cpp"]
    changed = replace(settings, languages=MappingProxyType({**settings.languages, "cpp": replace(
        language, export_queries=(replace(language.export_queries[0], tree_sha256="0" * 64),))}))
    job_unit = SimpleNamespace(job=SimpleNamespace(source_fingerprint="f" * 64))
    lock = {"sha256": "8" * 64}
    assert _database_identity(job_unit, cpp, image_identity="6" * 64, replay=None, settings=settings,
                              asset_lock=lock) == _database_identity(
        job_unit, cpp, image_identity="6" * 64, replay=None, settings=changed, asset_lock=lock)
    assert [_query_identity(database, item, settings) for item in _query_profiles(language)] == [
        _query_identity(database, item, changed) for item in _query_profiles(changed.languages["cpp"])]

    executor = FakeExecutor()
    _export_scopes(_unit(tmp_path, [database]), executor_factory=executor.factory)
    database_checkpoint = (tmp_path / "run" / "data" / "codeql" / "scopes" / cpp.scope_id /
                           "database-checkpoint.json")
    before = file_sha256(database_checkpoint)
    moved = {**database, "database_identity": "e" * 64}
    output = _export_scopes(_unit(tmp_path, [moved]), executor_factory=executor.factory)
    assert len(executor.calls) == 2 and output["exports"][0]["export_reused"] is False
    assert file_sha256(database_checkpoint) == before


def test_timeout_or_nonzero_exit_is_a_scope_gap_that_spares_siblings(tmp_path: Path) -> None:
    slow, broken, good = _scope("cpp", "one", "a"), _scope("cpp", "two", "b"), _scope("cpp", "three", "c")
    databases = [_database(tmp_path, scope) for scope in (slow, broken, good)]
    executor = FakeExecutor(outcome={slow.scope_id: (None, True), broken.scope_id: (2, False)})
    output = _export_scopes(_unit(tmp_path, databases), executor_factory=executor.factory)

    assert output["terminal_status"] == "COMPLETED_WITH_GAPS"
    by_scope = {item["scope_id"]: item for item in output["exports"]}
    assert by_scope[slow.scope_id]["export_status"] == "FAILED"
    assert by_scope[slow.scope_id]["gaps"] == ["CodeQL graph export timed out"]
    assert by_scope[broken.scope_id]["gaps"] == ["CodeQL graph export exited 2"]
    assert by_scope[good.scope_id]["export_status"] == "SUCCEEDED" and by_scope[good.scope_id]["gaps"] == []
    assert output["export_count"] == 1
    assert sorted(output["gaps"]) == ["CodeQL graph export exited 2", "CodeQL graph export timed out"]
    scopes = tmp_path / "run" / "data" / "codeql" / "scopes"
    assert not (scopes / slow.scope_id / "export-checkpoint.json").exists()
    assert (scopes / good.scope_id / "export-checkpoint.json").is_file()
    failed = [item for item in output["dispositions"] if item["terminal_status"] == "FAILED"]
    assert {item["scope_id"] for item in failed} == {slow.scope_id, broken.scope_id}


def test_failed_database_skips_export_as_a_named_gap(tmp_path: Path) -> None:
    cpp = _scope("cpp", "native", "a")
    output = _export_scopes(_unit(tmp_path, [_database(tmp_path, cpp, status="FAILED")]),
                            executor_factory=_never)
    assert output["exports"][0]["export_status"] == "SKIPPED"
    assert output["gaps"] == ["CodeQL graph export skipped because database creation failed"]
    assert output["terminal_status"] == "COMPLETED_WITH_GAPS"


def test_invalid_fresh_export_is_a_scope_gap_not_a_checkpoint(tmp_path: Path) -> None:
    cpp = _scope("cpp", "native", "a")
    executor = FakeExecutor(tamper=True)
    output = _export_scopes(_unit(tmp_path, [_database(tmp_path, cpp)]), executor_factory=executor.factory)
    value = output["exports"][0]
    assert value["export_status"] == "FAILED"
    assert value["gaps"] == ["CodeQL graph export produced an invalid bounded export (GraphExportIntegrityError)"]
    assert not (tmp_path / "run" / "data" / "codeql" / "scopes" / cpp.scope_id / "export-checkpoint.json").exists()


@pytest.mark.parametrize("change", ["byte", "extra", "missing"])
def test_changed_export_after_checkpoint_is_a_framework_integrity_error(tmp_path: Path, change: str) -> None:
    cpp = _scope("cpp", "native", "a")
    databases = [_database(tmp_path, cpp)]
    executor = FakeExecutor()
    _export_scopes(_unit(tmp_path, databases), executor_factory=executor.factory)
    exports_root = tmp_path / "run" / "data" / "codeql" / "scopes" / cpp.scope_id / "exports"
    if change == "byte":
        path = exports_root / "call_sites.json"
        path.write_bytes(path.read_bytes().replace(b"3", b"4", 1))
    elif change == "extra":
        (exports_root / "notes.json").write_text("{}", encoding="utf-8")
    else:
        (exports_root / "guards.json").unlink()
    with pytest.raises(FrameworkIntegrityError, match="graph export"):
        _export_scopes(_unit(tmp_path, databases), executor_factory=_never)
    with pytest.raises(FrameworkIntegrityError):
        _export_one(_unit(tmp_path, databases), databases[0], executor_factory=_never)


def test_export_sources_are_not_fingerprinted(tmp_path: Path, monkeypatch) -> None:
    from appsec_review.jobs.job_codeql_analysis import job as codeql_job
    settings = _settings()
    drifted = replace(settings, asset_lock_sha256="0" * 64)
    def forbidden(path):
        raise AssertionError("supplied export assets must not be hashed")
    monkeypatch.setattr(codeql_job, "file_sha256", forbidden)
    codeql_job._verify_export_sources(ROOT, _export_profile(drifted, "cpp"), drifted)
    language = settings.languages["cpp"]
    moved = replace(settings, languages=MappingProxyType({**settings.languages, "cpp": replace(
        language, export_queries=(replace(language.export_queries[0], file_count=11),))}))
    codeql_job._verify_export_sources(ROOT, _export_profile(moved, "cpp"), moved)


def test_planning_compares_the_toml_export_block_with_the_lock_entry() -> None:
    settings, lock = _settings(), load_asset_lock(ROOT)
    configured = {name: [asdict(item) for item in value.export_queries]
                  for name, value in settings.languages.items()}
    assert configured["cpp"] == [lock["export_query_packs"]["cpp"]]
    assert export_lock_mismatches(configured, lock) == ()
    changed = copy.deepcopy(configured)
    changed["cpp"][0]["columns_sha256"] = "0" * 64
    assert export_lock_mismatches(changed, lock) == ("cpp",)
    assert export_lock_mismatches({**configured, "cpp": []}, lock) == ("cpp",)
    assert export_lock_mismatches({**configured, "go": configured["cpp"]}, lock) == ("go",)

    cpp, go = _scope("cpp", "native", "a"), _scope("go", "svc", "b")
    planned = plan_graph_exports((cpp, go), enabled=True, export_languages=("cpp",))
    assert [(item["scope_id"], item["disposition"]) for item in planned] == [
        (cpp.scope_id, "PLANNED"), (go.scope_id, "NOT_APPLICABLE")]
    assert planned[1]["reason"] == "no hash-pinned CodeQL graph export pack for go"
    assert {item["disposition"] for item in plan_graph_exports((cpp,), enabled=False,
                                                               export_languages=("cpp",))} == {"NOT_APPLICABLE"}


def _raw_settings() -> dict[str, Any]:
    raw = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    return raw["jobs"][JOB]["settings"]


def test_typed_export_settings_are_strict_and_default_to_the_graph_contract() -> None:
    settings = parse_codeql_settings(_raw_settings())
    assert asdict(settings.export_queries) == {
        "enabled": True, "row_limit": 200000, "max_bytes": 268435456, "timeout_seconds": 1800,
        "mode": "seeded", "seed_depth": 3, "max_seed_depth": 8, "seed_limit": 200,
        "compile_timeout_seconds": 3600, "compile_threads": 8, "compile_ram_mb": 8192}
    assert action_timeout(settings, "export") == settings.export_timeout_seconds == 1800
    assert action_timeout(settings, "compile") == settings.compile_timeout_seconds == 3600
    assert [item.query_id for item in settings.languages["cpp"].export_queries] == ["graph-export-cpp"]
    assert all(not settings.languages[name].export_queries for name in settings.languages if name != "cpp")

    absent = _raw_settings()
    del absent["export_queries"]
    defaults = GraphSettings()
    parsed = parse_codeql_settings(absent).export_queries
    assert (parsed.row_limit, parsed.max_bytes, parsed.timeout_seconds) == (
        defaults.max_facts_per_family_per_scope, defaults.max_export_bytes, defaults.export_timeout_seconds)

    for mutate, message in (
            (lambda value: value["export_queries"].update(row_limt=1), "unknown settings"),
            (lambda value: value["export_queries"].update(row_limit=0), "positive integer"),
            (lambda value: value["export_queries"].update(max_bytes=True), "positive integer"),
            (lambda value: value["export_queries"].update(enabled="yes"), "Boolean"),
            (lambda value: value["export_queries"].update(mode="whole-program"), "mode must be one of"),
            (lambda value: value["export_queries"].update(mode=1), "mode must be one of"),
            (lambda value: value["export_queries"].update(seed_depth=-1), "seed_depth must be a non-negative"),
            (lambda value: value["export_queries"].update(seed_depth=True), "seed_depth must be a non-negative"),
            (lambda value: value["export_queries"].update(seed_depth=4, max_seed_depth=3),
             "seed_depth must not exceed max_seed_depth"),
            (lambda value: value["export_queries"].update(max_seed_depth=9), "must not exceed 8"),
            (lambda value: value["export_queries"].update(seed_limit=0), "seed_limit must be a positive"),
            (lambda value: value["languages"]["go"].update(
                export_queries=copy.deepcopy(value["languages"]["cpp"]["export_queries"])), "only for: cpp"),
            (lambda value: value["languages"]["cpp"]["export_queries"].append(
                copy.deepcopy(value["languages"]["cpp"]["export_queries"][0])), "at most one"),
            (lambda value: value["languages"]["cpp"]["export_queries"][0].pop("catalog_sha256"),
             "differ from the contract"),
            (lambda value: value["languages"]["cpp"]["export_queries"][0].update(
                source_path="/opt/codeql/custom-queries/x"), "rules/codeql-graph-export"),
            (lambda value: value["languages"]["cpp"]["export_queries"][0].update(
                tree_sha256="xyz"), "tree identity"),
    ):
        value = copy.deepcopy(_raw_settings())
        mutate(value)
        with pytest.raises(ValueError, match=message):
            parse_codeql_settings(value)


def test_config_topology_requires_the_ready_execution_step() -> None:
    config = load_config(ROOT / "appsec-review.toml").job(JOB)
    _validate_config(SimpleNamespace(config=config), None)
    steps = {name: value for name, value in config.steps.items() if name != "execution"}
    missing = SimpleNamespace(steps=steps, step=lambda name: steps[name])
    with pytest.raises(ValueError, match="topology"):
        _validate_config(SimpleNamespace(config=missing), None)
    job = build_job()
    units = {unit.unit_id: unit.dependencies for unit in job.units}
    assert units["execution.scopes"] == ("plan.inventory",)
    assert units["acceptance.publish_handoff"] == ("execution.scopes",)
    assert [unit.unit_id.split(".")[0] for unit in job.units] == list(config.steps)


def test_dataset_declarations_account_for_exports_separately_from_scope_material(tmp_path: Path, monkeypatch) -> None:
    from appsec_review.indexing import inventory

    declaration = next(item for item in DATASETS if item.output_kind == "codeql_graph_export")
    assert (declaration.step, declaration.disposition) == ("execution", "artifact_only")
    assert declaration.reason and declaration.query_route
    run = tmp_path / "run"
    scope = run / "data" / "codeql" / "scopes" / "codeql-unit-aaaaaaaaaaaaaaaaaaaaaaaa"
    attempt = run / "data" / "jobs" / JOB / "attempts" / "attempt_0001"
    files = {
        "codeql_graph_export": [scope / "exports" / "call_sites.json", scope / "exports" / "export-manifest.json",
                                attempt / "artifacts" / "codeql" / "graph-exports.json"],
        "codeql_scope_material": [scope / "export-checkpoint.json", scope / "database-checkpoint.json",
                                  scope / "image.json", scope / "database" / "db-cpp" / "a.trap",
                                  scope / "workspace" / "main.cpp", scope / "executions" / "export" / "stdout.bin",
                                  scope / "queries" / "default" / "sarif" / "results.sarif",
                                  scope / "workspace" / "export" / "pack" / "qlpack.yml"],
        "codeql_plan_and_summary": [attempt / "artifacts" / "codeql" / "summary.json"],
    }
    supplied = [scope / "export" / "pack" / "qlpack.yml",
                scope / "export" / "columns.json", scope / "export" / "assets.lock.json"]
    for paths in [*files.values(), supplied]:
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x", encoding="utf-8")
    steps = tuple(load_config(ROOT / "appsec-review.toml").job(JOB).steps)
    claims = runtime_claims({JOB: steps}) + [Claim(JOB, item.step, item.output_kind, item) for item in DATASETS]
    scandir = inventory.os.scandir

    def no_supplied_pack(directory):
        assert Path(directory) != scope / "export" / "pack", "supplied pack was traversed"
        return scandir(directory)

    monkeypatch.setattr(inventory.os, "scandir", no_supplied_pack)
    tree = scan_run_tree(run, FileClaims(claims), max_files=1000)
    assert tree.unaccounted_count == 0 and not tree.scan_errors
    assert tree.file_count == sum(len(paths) for paths in files.values())
    assert {key[2]: group.count for key, group in tree.groups.items()} == {
        kind: len(paths) for kind, paths in files.items()}


def test_precompile_runs_once_for_scopes_sharing_a_cache_and_before_each_export(tmp_path: Path) -> None:
    databases = [_database(tmp_path, _scope("cpp", "native", "a")), _database(tmp_path, _scope("cpp", "other", "b"))]
    executor = FakeExecutor()
    output = _export_scopes(_unit(tmp_path, databases), executor_factory=executor.factory)
    assert output["export_count"] == 2 and len(executor.calls) == 2
    assert len(executor.compiles) == 1, "the second scope must hit the cache the first one warmed"
    assert (tmp_path / "run").exists()
    receipts = sorted((tmp_path / "run").rglob("executions/compile/receipt.json"))
    assert len(receipts) == 1


@pytest.mark.parametrize("outcome,gap", [((None, True), "compile timed out"), ((3, False), "compile exited 3")])
def test_a_failed_precompile_is_a_named_gap_and_never_runs_the_export(tmp_path: Path, outcome, gap) -> None:
    executor = FakeExecutor()
    executor.compile_outcome = outcome
    output = _export_scopes(_unit(tmp_path, [_database(tmp_path, _scope("cpp", "native", "a"))]),
                            executor_factory=executor.factory)
    [item] = output["exports"]
    assert item["export_status"] == "FAILED" and any(gap in value for value in item["gaps"])
    assert executor.calls == [] and output["export_count"] == 0
    assert output["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert not list((tmp_path / "run").rglob("export-checkpoint.json"))
