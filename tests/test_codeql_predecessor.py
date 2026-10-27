from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from types import SimpleNamespace

import pytest

from appsec_review.codeql import predecessor
from appsec_review.codeql.runtime import CodeQLImage, IMAGE_SCHEMA
from appsec_review.config import load_config
from appsec_review.config.assurance import parse_review_policy
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_codeql_analysis import job as codeql
from appsec_review.jobs.job_codeql_analysis.datasets import DATASETS
from appsec_review.jobs.job_codeql_analysis.planning import CodeQLPlan, CodeQLScope, PLAN_SCHEMA, SCOPE_SCHEMA
from appsec_review.runtime import Job, JobRunner, Unit, UnitContext
from appsec_review.storage import atomic_json, file_sha256
from tests.capture_fakes import build_capture_toml
from tests.test_codeql_analysis import _settings_value


SCOPE = "codeql-unit-" + "1" * 24


def _table(name, values):
    scalars = [f"{key} = {json.dumps(value)}" for key, value in values.items()
               if not isinstance(value, dict)]
    children = [_table(f"{name}.{key}", value) for key, value in values.items()
                if isinstance(value, dict)]
    return f"\n[{name}]\n" + "\n".join(scalars) + "\n" + "".join(children)


@pytest.fixture(params=["strict", "first_party_managed"])
def fixture(tmp_path, monkeypatch, request):
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("print('fixture')\n")
    snapshot = source_fingerprint(target)
    settings = _settings_value()
    settings.update(threads=1, ram_mb=2048, concurrency=1)
    for language in settings["languages"].values():
        language["additional_queries"], language["custom_queries"] = [], []
    policy = {
        "mode": request.param, "project_id": "fixture",
        "approved_first_party_projects": ["fixture"], "target_root": str(target),
        "custody": "application_private_v1",
        "store_authorization": {"tenant_id": "fixture-tenant", "runs_root": str(tmp_path / "runs")},
        "releases": {name: "fixture-v1" for name in (
            "platform", "validation", "build_toolchain", "codeql", "codeql_runner",
            "extractor_python", "query_python_default")},
    }
    scope = CodeQLScope(SCOPE_SCHEMA, SCOPE, "python", ("Python",), "none", ".",
                       ({"path": "main.py", "sha256": file_sha256(target / "main.py"),
                         "size_bytes": (target / "main.py").stat().st_size},),
                       None, None, "fixture-environment", False)
    calls = []

    def resolve(self, *, build_image_tag, build_image_id, runtime_user):
        image = CodeQLImage(
            IMAGE_SCHEMA, self.declared_identity(build_image_id=build_image_id, runtime_user=runtime_user),
            self.settings.source_image_id, build_image_id, build_image_tag, build_image_id,
            "fixture:codeql", runtime_user, self.releases.values["codeql"],
            self.releases.values["codeql_runner"], True, "fixture-image.json")
        return image, b"", b""

    def execute(self, action, arguments, *, scratch_root):
        calls.append((action, self.run_root.name, arguments))
        if action == "database":
            database = scratch_root / "database"
            database.mkdir()
            (database / "data.bin").write_bytes(b"fixture database")
            (database / "codeql-database.yml").write_text("fixture: true\n")
            (database / "empty").mkdir()
        elif action == "query":
            assert (scratch_root / "query-database/data.bin").read_bytes() == b"fixture database"
            atomic_json(scratch_root / "sarif/results.sarif", {"version": "2.1.0", "runs": []})
        else:
            pytest.fail(f"unexpected fake action: {action}")
        atomic_json(scratch_root / "executions" / action / "receipt.json", {"action": action})
        return SimpleNamespace(exit_code=0, timed_out=False, duration_ms=1,
                               stdout_truncated=False, stderr_truncated=False)

    monkeypatch.setattr(codeql.CodeQLImageResolver, "resolve", resolve)
    monkeypatch.setattr(codeql.CodeQLExecutor, "execute", execute)
    monkeypatch.setattr(codeql, "load_asset_lock", lambda root: {})

    def config():
        path = tmp_path / "appsec-review.toml"
        path.write_text(
            '[runtime]\nruns_dir = "runs"\ndata_dir = "data"\n' + build_capture_toml()
            + '\n[jobs.job_codeql_analysis]\nname = "fixture"\nworkers = 1\n'
            + _table("jobs.job_codeql_analysis.settings", settings)
            + _table("review_policy", policy))
        return load_config(path)

    def produce(unit):
        value = codeql._database_one(unit, scope, {})
        query = codeql._query_one(unit, value, codeql._query_profiles(
            unit.job.config.typed_settings.languages["python"])[0])
        return {"databases": [value], "queries": [query]}

    job = Job(predecessor.JOB, "fixture", produce, units=(Unit("execution.scopes", produce),),
              datasets=DATASETS)
    original_config = config()
    original = JobRunner(original_config).run(
        job, target_root=target, source_fingerprint=snapshot,
        now=datetime(2026, 10, 24, tzinfo=timezone.utc))
    source = original_config.runtime.runs_dir / original["status"]["run_id"]
    policy["predecessor_databases"] = {
        "run_id": source.name, "handoff_sha256": original["handoff_sha256"], "scope_ids": [SCOPE]}
    policy["releases"]["query_python_default"] = "fixture-v2"
    settings["languages"]["python"]["query_suite"] = "codeql-suites/python-security-and-quality.qls"
    frozen = (source / "data/configuration/resolved.json").read_bytes()

    def destination(definition=None):
        current = config()
        runner = JobRunner(current)
        claim = runner.begin_attempt(
            definition or job, target_root=target, source_fingerprint=snapshot,
            now=datetime(2026, 10, 24, tzinfo=timezone.utc))
        context = runner._context_from_claim(definition or job, claim)
        unit = SimpleNamespace(job=context, unit_id="execution.scopes", runner=runner, claim=claim)
        return unit, current

    return SimpleNamespace(
        source=source, original=original, scope=scope, policy=policy, calls=calls,
        destination=destination, frozen=frozen, settings=settings, job=job)


def _import(fixture, unit):
    return codeql._import_predecessor_databases(
        unit, [fixture.scope], {}, unit.job.config.typed_settings)


def test_selected_database_is_detached_and_only_new_queries_execute(fixture):
    unit, config = fixture.destination()
    receipt = _import(fixture, unit)
    source_database = fixture.source / f"data/codeql/scopes/{SCOPE}/database/data.bin"
    imported = unit.job.run_root / f"data/codeql/scopes/{SCOPE}/database/data.bin"
    assert imported.read_bytes() == source_database.read_bytes()
    assert imported.stat().st_ino != source_database.stat().st_ino
    assert not imported.stat().st_mode & 0o222
    assert (imported.parent / "empty").is_dir()
    assert not list(unit.job.run_root.glob("data/codeql/scopes/*/queries"))
    assert not list(unit.job.run_root.glob("data/codeql/scopes/*/exports"))
    assert not (unit.job.run_root / "data/guidance").exists()
    assert (fixture.source / "data/configuration/resolved.json").read_bytes() == fixture.frozen
    assert (unit.job.run_root / "data/configuration/resolved.json").read_bytes() == config.resolved_json
    value = codeql._database_one(unit, fixture.scope, {})
    assert value["database_reused"] and value["predecessor_import"] == receipt
    profile = codeql._query_profiles(config.job(predecessor.JOB).typed_settings.languages["python"])[0]
    query = codeql._query_one(unit, value, profile)
    assert query["terminal_status"] == "SUCCEEDED" and not query["query_reused"]
    assert [action for action, run, _ in fixture.calls if run == unit.job.run_id] == ["query"]
    assert "codeql-suites/python-security-and-quality.qls" in fixture.calls[-1][2]
    assert codeql._query_one(unit, value, profile)["query_reused"]
    assert len(fixture.calls) == 3
    source_database.chmod(0o600)
    source_database.write_bytes(b"changed predecessor")
    assert imported.read_bytes() == b"fixture database"
    record = json.loads((unit.job.run_root / receipt["path"]).read_text())
    assert record["destination_config_sha256"] == config.resolved_sha256
    assert record["source_handoff_sha256"] == fixture.policy["predecessor_databases"]["handoff_sha256"]


def test_ready_coordinator_imports_before_scheduling_selected_scope(fixture, monkeypatch):
    prepared, _ = fixture.destination()
    unit = UnitContext(
        prepared.job, "execution.scopes", "execution", "scopes",
        prepared.job.attempt_root / "steps/execution/tasks/scopes", {"plan.inventory": {}})
    monkeypatch.setattr(codeql, "_plan_from", lambda value: SimpleNamespace(scopes=[fixture.scope]))
    monkeypatch.setattr(codeql, "_receipt_map", lambda value: {})
    monkeypatch.setattr(codeql, "_normalize_one", lambda context, value: {**value, "observation_count": 0})
    monkeypatch.setattr(codeql, "_export_isolated", lambda context, value, **kwargs: {**value, "gaps": []})
    execution = next(item for item in codeql.build_job().units if item.unit_id == "execution.scopes")
    result = execution.handler(unit)
    assert result["predecessor_import"]
    assert result["databases"][0]["database_reused"]
    assert not result["queries"][0]["query_reused"]
    assert [action for action, run, _ in fixture.calls if run == unit.job.run_id] == ["query"]


def test_supported_destination_lifecycle_accepts_import_and_reuses_new_queries(fixture, monkeypatch):
    def plan(unit):
        value = CodeQLPlan(PLAN_SCHEMA, unit.job.source_fingerprint, ("python",),
                           (fixture.scope,), (), ())
        return {"plan": codeql._json_artifact(
            unit.job.run_root, unit.job.attempt_root / "artifacts/codeql/plan.json", value.as_dict())}

    monkeypatch.setattr(codeql, "_receipt_map", lambda value: {})
    monkeypatch.setattr(codeql, "_normalize_one", lambda context, value: {**value, "observation_count": 0})
    monkeypatch.setattr(codeql, "_export_isolated", lambda context, value, **kwargs: {**value, "gaps": []})
    execution = next(item for item in codeql.build_job().units if item.unit_id == "execution.scopes")
    definition = Job(predecessor.JOB, "fixture", lambda context: {},
                     units=(Unit("plan.inventory", plan), execution), datasets=DATASETS)
    unit, config = fixture.destination(definition)
    for step in definition.units:
        unit.runner.execute_or_reuse_unit(definition, unit.claim, step.unit_id)
    outcome = unit.runner.finalize_attempt(definition, unit.claim)
    assert outcome["handoff"]["status"] == "ACCEPTED"
    output = outcome["result"]["outputs"]["execution.scopes"]
    assert output["databases"][0]["database_reused"]
    assert not output["queries"][0]["query_reused"]
    assert output["predecessor_import"] in outcome["handoff"]["artifacts"]
    assert outcome["handoff"]["resolved_config_sha256"] == config.resolved_sha256
    assert output["queries"][0]["query_profile"]["query_suite"] == (
        "codeql-suites/python-security-and-quality.qls")
    again = unit.runner.run(
        definition, run_id=unit.job.run_id, target_root=unit.job.target_root,
        source_fingerprint=unit.job.source_fingerprint)
    assert again["handoff"]["status"] == "ACCEPTED"
    assert again["result"]["outputs"]["execution.scopes"]["queries"][0]["query_reused"]
    assert [action for action, run, _ in fixture.calls if run == unit.job.run_id] == ["query"]
    assert (fixture.source / "data/configuration/resolved.json").read_bytes() == fixture.frozen
    assert (unit.job.run_root / "data/configuration/resolved.json").read_bytes() == config.resolved_json


def test_re_pinned_handoff_cannot_name_another_source_run(fixture):
    path = fixture.source / "data/jobs/job_codeql_analysis/attempts/attempt_0001/handoff.json"
    handoff = json.loads(path.read_text())
    handoff["run_id"] = "2026-10-24-9999"
    atomic_json(path, handoff)
    fixture.policy["predecessor_databases"]["handoff_sha256"] = file_sha256(path)
    unit, _ = fixture.destination()
    with pytest.raises(ValueError, match="accepted CodeQL attempt"):
        _import(fixture, unit)
    assert len(fixture.calls) == 2


def test_re_pinned_original_claim_cannot_name_another_source_run(fixture):
    attempt = fixture.source / "data/jobs/job_codeql_analysis/attempts/attempt_0001"
    claim_path, handoff_path = attempt / "claim.json", attempt / "handoff.json"
    claim = json.loads(claim_path.read_text())
    claim["run_id"] = "2026-10-24-9999"
    atomic_json(claim_path, claim)
    handoff = json.loads(handoff_path.read_text())
    assert "run_id" not in handoff
    reference = next(item for item in handoff["artifacts"] if item["path"].endswith("/claim.json"))
    reference.update(sha256=file_sha256(claim_path), size_bytes=claim_path.stat().st_size)
    atomic_json(handoff_path, handoff)
    fixture.policy["predecessor_databases"]["handoff_sha256"] = file_sha256(handoff_path)
    unit, _ = fixture.destination()
    with pytest.raises(ValueError, match="original claim is not bound"):
        _import(fixture, unit)
    assert len(fixture.calls) == 2


@pytest.mark.parametrize("change", [
    "tenant", "project", "mode", "store", "target", "material", "scope", "handoff", "release",
    "claim", "source-config", "database", "undeclared-file", "symlink", "bytes", "files", "metadata",
])
def test_incompatible_selection_fails_before_any_new_execution(fixture, change, tmp_path):
    selection = fixture.policy["predecessor_databases"]
    if change == "tenant":
        fixture.policy["store_authorization"]["tenant_id"] = "another-tenant"
    elif change == "project":
        fixture.policy.update(project_id="another-project", approved_first_party_projects=["another-project"])
    elif change == "mode":
        fixture.policy["mode"] = (
            "strict" if fixture.policy["mode"] == "first_party_managed" else "first_party_managed")
    elif change == "store":
        fixture.policy["store_authorization"]["runs_root"] = str(tmp_path / "another-store")
    elif change == "scope":
        selection["scope_ids"] = ["codeql-unit-" + "2" * 24]
    elif change == "handoff":
        selection["handoff_sha256"] = "0" * 64
    elif change == "release":
        del fixture.policy["releases"]["codeql_runner"]
    elif change == "bytes":
        selection["max_bytes"] = 1
    elif change == "metadata":
        selection["metadata_bytes_limit"] = 1
    elif change == "files":
        selection["max_files"] = 1
    elif change == "material":
        fixture.scope = replace(fixture.scope, environment_identity="changed")
    elif change in {"claim", "source-config", "database", "undeclared-file", "symlink"}:
        base = fixture.source / f"data/codeql/scopes/{SCOPE}/database"
        path = {
            "claim": fixture.source / "data/jobs/job_codeql_analysis/attempts/attempt_0001/claim.json",
            "source-config": fixture.source / "data/configuration/resolved.json",
            "database": base / "data.bin", "undeclared-file": base / "extra",
            "symlink": base / "alias",
        }[change]
        if change == "symlink":
            path.symlink_to(base / "data.bin")
        else:
            if path.exists():
                path.chmod(0o600)
            path.write_bytes(b"changed")
    unit, _ = fixture.destination()
    if change == "target":
        unit.job = replace(unit.job, source_fingerprint="other-target")
    with pytest.raises((ValueError, OSError)):
        _import(fixture, unit)
    assert len(fixture.calls) == 2
    assert not list(unit.job.run_root.glob("data/codeql/scopes/*/database"))
    assert not list(unit.job.run_root.glob("data/codeql/.predecessor-*"))


def test_selected_import_never_substitutes_a_fresh_database(fixture):
    unit, _ = fixture.destination()
    with pytest.raises(codeql.FrameworkIntegrityError, match="no completed import"):
        codeql._database_one(unit, fixture.scope, {})
    assert len(fixture.calls) == 2


def test_retry_recopies_compatible_destination_without_retaining_hardlinks(fixture):
    unit, _ = fixture.destination()
    receipt = _import(fixture, unit)
    original = fixture.source / f"data/codeql/scopes/{SCOPE}/database/data.bin"
    imported = unit.job.run_root / f"data/codeql/scopes/{SCOPE}/database/data.bin"
    imported.unlink()
    os.link(original, imported)
    assert _import(fixture, unit) == receipt
    assert imported.stat().st_ino != original.stat().st_ino
    assert not list(unit.job.run_root.glob("data/codeql/.predecessor-*"))


def test_copy_failure_cleans_staging_and_allows_retry(fixture, monkeypatch):
    unit, _ = fixture.destination()
    payload = predecessor._Reader.payload
    with monkeypatch.context() as patch:
        def fail(self, path, limit, destination=None):
            if destination is not None:
                raise OSError("fixture copy failure")
            return payload(self, path, limit, destination)
        patch.setattr(predecessor._Reader, "payload", fail)
        with pytest.raises(OSError, match="fixture copy"):
            _import(fixture, unit)
    assert not list(unit.job.run_root.glob("data/codeql/.predecessor-*"))
    assert not list(unit.job.run_root.glob("data/codeql/scopes/*/database-checkpoint.json"))
    assert _import(fixture, unit)


def test_publication_failure_restores_the_existing_detached_database(fixture, monkeypatch):
    unit, _ = fixture.destination()
    receipt = _import(fixture, unit)
    database = unit.job.run_root / f"data/codeql/scopes/{SCOPE}/database"
    previous_inode = (database / "data.bin").stat().st_ino
    rename = os.replace
    with monkeypatch.context() as patch:
        def fail(source, destination):
            if str(source).endswith("/database") and ".predecessor-" in str(source) and destination == database:
                raise OSError("fixture publication failure")
            return rename(source, destination)
        patch.setattr(predecessor.os, "replace", fail)
        with pytest.raises(OSError, match="fixture publication"):
            _import(fixture, unit)
    assert (database / "data.bin").stat().st_ino == previous_inode
    assert (database / "data.bin").read_bytes() == b"fixture database"
    assert not list(unit.job.run_root.glob("data/codeql/.predecessor-*"))
    assert _import(fixture, unit) == receipt


def test_incompatible_destination_is_not_overwritten(fixture):
    unit, _ = fixture.destination()
    database = unit.job.run_root / f"data/codeql/scopes/{SCOPE}/database"
    database.mkdir(parents=True)
    (database / "data.bin").write_bytes(b"existing different output")
    with pytest.raises(ValueError, match="content changed"):
        _import(fixture, unit)
    assert (database / "data.bin").read_bytes() == b"existing different output"
    assert not (database.parent / "database-checkpoint.json").exists()
    assert not list(unit.job.run_root.glob("data/codeql/.predecessor-*"))


def test_current_frozen_configuration_binding_is_required(fixture):
    unit, _ = fixture.destination()
    claim_path = unit.job.attempt_root / "claim.json"
    claim = json.loads(claim_path.read_text())
    claim["resolved_config_sha256"] = "0" * 64
    atomic_json(claim_path, claim)
    with pytest.raises(ValueError, match="metadata identity"):
        _import(fixture, unit)
    assert not list(unit.job.run_root.glob("data/codeql/scopes/*/database"))


def test_shared_writable_store_is_not_authorized(fixture):
    unit, _ = fixture.destination()
    store = fixture.source.parent
    mode = store.stat().st_mode & 0o777
    try:
        store.chmod(0o777)
        with pytest.raises(ValueError, match="operator-owned"):
            _import(fixture, unit)
    finally:
        store.chmod(mode)


def test_import_deadline_is_checked_during_payload_copy(fixture, monkeypatch):
    unit, _ = fixture.destination()
    payload = predecessor._Reader.payload
    def expired(self, path, limit, destination=None):
        if destination is not None:
            self.deadline = 0
        return payload(self, path, limit, destination)
    monkeypatch.setattr(predecessor._Reader, "payload", expired)
    with pytest.raises(TimeoutError, match="deadline"):
        _import(fixture, unit)
    assert not list(unit.job.run_root.glob("data/codeql/.predecessor-*"))
    leases = json.loads((unit.job.metadata_root / "resource-admission/leases.json").read_text())
    assert not leases["leases"]


@pytest.mark.parametrize("selection", [
    {"run_id": "../run"}, {"handoff_sha256": "unknown"}, {"scope_ids": [SCOPE, SCOPE]},
    {"scope_ids": [{}]}, {"max_bytes": True}, {"metadata_bytes_limit": 1024 ** 3},
])
def test_predecessor_configuration_is_bounded_and_closed(selection, tmp_path):
    value = {"project_id": "fixture", "approved_first_party_projects": ["fixture"],
             "store_authorization": {"tenant_id": "fixture", "runs_root": str(tmp_path)},
             "predecessor_databases": {"run_id": "2026-10-24-0001", "handoff_sha256": "1" * 64,
                                      "scope_ids": [SCOPE], **selection}}
    with pytest.raises(ValueError):
        parse_review_policy(value)
