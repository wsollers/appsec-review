"""Job-local tuning through the shared immutable-configuration mechanism; no live tools."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import BuildEnvironmentSettings, load_config
from appsec_review.config.operational import MaterialConfigurationChange, operational_changes
from appsec_review.runtime import GraphRunner, JobRunner, Unit, UnitContext
from appsec_review.runtime.configuration import configuration_snapshot
from appsec_review.runtime.contracts import (
    Availability, JobContract, MissingPolicy, TargetAccess, accepted_inputs,
)
from appsec_review.runtime.repair import admit_repair, plan_repair
from appsec_review.storage import canonical_json, file_sha256
from appsec_review.storage.shared import verify_handoff
from tests.release_support import write_release
from tests.test_repair_admission import fixture


ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT = "job_build_environment_analysis"
CONNECTIVITY = "job_model_connectivity"
TUNINGS = (
    (ENVIRONMENT, ("settings", "deadline_seconds"), 1, 30, "coverage"),
    ("job_debug_symbol_indexing", ("settings", "reader", "timeout_seconds"), 30, 60, "execution"),
    ("job_dossier_publication", ("settings", "render_timeout_seconds"), 30, 60, "execution"),
    (CONNECTIVITY, ("settings", "timeout_seconds"), 30, 60, "execution"),
    ("job_review_intake", ("settings", "model_preflight", "timeout_seconds"), 30, 60, "execution"),
    ("job_review_prioritization", ("settings", "syntax_metrics_reservation", "cpu"), 1, 2, "execution"),
    ("job_review_prioritization", ("settings", "syntax_metrics_reservation", "memory_mb"), 128, 256, "execution"),
    ("job_review_prioritization", ("settings", "syntax_metrics_reservation", "admission_timeout_seconds"),
     5, 10, "execution"),
    ("job_sanitizer_build", ("settings", "command_timeout_seconds"), 60, 120, "execution"),
    ("job_sanitizer_build", ("settings", "workers"), 1, 2, "execution"),
    ("job_source_history_analysis", ("settings", "github", "timeout_seconds"), 30, 60, "execution"),
    ("job_threat_model_generation", ("settings", "reservation", "cpu"), 1, 2, "execution"),
    ("job_threat_model_generation", ("settings", "reservation", "memory_mb"), 128, 256, "execution"),
    ("job_threat_model_generation", ("settings", "reservation", "admission_timeout_seconds"), 5, 10, "execution"),
)


@pytest.fixture
def shipped():
    return load_config(ROOT / "appsec-review.toml", profile="dev")


def _set(document, path, value):
    for key in path[:-1]:
        document = document[key]
    document[path[-1]] = value


def _job_settings(config, job_id, **updates):
    from appsec_review.config.loader import parse_threat_model_settings

    settings = json.loads(config.resolved_json)["jobs"][job_id]["settings"]
    settings.update(updates)
    original = config.job(job_id)
    if job_id == "job_threat_model_generation":
        typed = parse_threat_model_settings(settings)
    else:
        assert original.typed_settings is None, "this fixture needs the job's real typed-settings parser"
        typed = None
    return replace(original, settings=settings, typed_settings=typed)


def _unit(tmp_path, config, unit_id, outputs=None):
    step, task = unit_id.split(".")
    run_root = tmp_path / "run"
    attempt = run_root / "data" / "jobs" / config.job_id / "attempts" / "attempt_0002"
    root = attempt / "steps" / step / "tasks" / task
    root.mkdir(parents=True)
    context = SimpleNamespace(
        config=config, run_root=run_root, attempt_root=attempt, attempt_id="attempt_0002",
        metadata_root=tmp_path / "metadata", repository_root=ROOT,
        events=SimpleNamespace(write=lambda *args, **kwargs: None),
        review_policy=SimpleNamespace(resources=object()),
    )
    return UnitContext(context, unit_id, step, task, root, outputs or {})


def _handler(job, unit_id):
    return next(unit.handler for unit in job.units if unit.unit_id == unit_id)


@pytest.mark.parametrize("job_id,path,low,high,category", TUNINGS,
                         ids=[row[0].removeprefix("job_") + "." + ".".join(row[1][1:]) for row in TUNINGS])
def test_reviewed_leaves_record_exact_bidirectional_deltas(shipped, job_id, path, low, high, category):
    original = json.loads(shipped.resolved_json)
    before, after = deepcopy(original), deepcopy(original)
    _set(before, ("jobs", job_id, *path), low)
    _set(after, ("jobs", job_id, *path), high)
    assert hashlib.sha256(canonical_json(before)).digest() != hashlib.sha256(canonical_json(after)).digest()
    for left, right, old, new in ((before, after, low, high), (after, before, high, low)):
        assert operational_changes(left, right) == [{
            "job_id": job_id, "path": list(path), "category": category, "before": old, "after": new,
        }]
    assert json.loads(shipped.resolved_json) == original


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "60", [60]], ids=["zero", "negative", "bool", "float", "str", "list"])
def test_declarations_do_not_coerce_unsupported_types(shipped, value):
    before = json.loads(shipped.resolved_json)
    after = deepcopy(before)
    after["jobs"][CONNECTIVITY]["settings"]["timeout_seconds"] = value
    with pytest.raises(MaterialConfigurationChange):
        operational_changes(before, after)


@pytest.mark.parametrize("path,old,new", [
    (("jobs", "job_change_context_analysis", "settings", "review", "fast_review_seconds"), 30, 60),
    (("jobs", "job_fixture", "settings", "model", "model"), "model-a", "model-b"),
    (("jobs", "job_fixture", "settings", "model", "provider"), "provider-a", "provider-b"),
    (("jobs", "job_fixture", "settings", "model", "reasoning"), "low", "high"),
    (("jobs", "job_tree_sitter_ast", "settings", "max_files_per_scope"), 128, 256),
    (("jobs", "job_codeql_analysis", "steps", "execution", "workers"), 1, 2),
    (("jobs", "job_codeql_analysis", "steps", "acceptance", "tasks", "publish_handoff", "workers"), 1, 2),
    (("source", "identity"), "source-a", "source-b"),
    (("rules", "identity"), "rules-a", "rules-b"),
    (("schema", "identity"), "schema-a", "schema-b"),
    (("review_policy", "mode"), "strict", "first_party_managed"),
], ids=["scoring", "model", "provider", "reasoning", "scope", "codeql-step", "codeql-task",
        "source", "rules", "schema", "authority"])
def test_mixed_material_changes_are_not_hidden_by_a_timeout(path, old, new):
    before = {"jobs": {CONNECTIVITY: {"settings": {"timeout_seconds": 30}}}}
    node = before
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = old
    after = deepcopy(before)
    after["jobs"][CONNECTIVITY]["settings"]["timeout_seconds"] = 60
    _set(after, path, new)
    with pytest.raises(MaterialConfigurationChange):
        operational_changes(before, after)


@pytest.mark.parametrize("damage", ["missing", "unknown"])
def test_missing_or_unknown_leaf_still_refuses(shipped, damage):
    before = json.loads(shipped.resolved_json)
    after = deepcopy(before)
    settings = after["jobs"][CONNECTIVITY]["settings"]
    if damage == "missing":
        del settings["timeout_seconds"]
    else:
        settings["timeout_seconds"] = 60
        settings["other_timeout_seconds"] = 60
    with pytest.raises(MaterialConfigurationChange):
        operational_changes(before, after)


@pytest.mark.parametrize("job_id,path,value", [
    (CONNECTIVITY, ("timeout_seconds",), 601),
    ("job_review_intake", ("model_preflight", "timeout_seconds"), 601),
    (ENVIRONMENT, ("deadline_seconds",), 31),
    ("job_dossier_publication", ("render_timeout_seconds",), 601),
    ("job_review_prioritization", ("syntax_metrics_reservation", "cpu"), 257),
    ("job_threat_model_generation", ("reservation", "memory_mb"), 1048577),
], ids=["connectivity", "intake", "environment", "dossier", "syntax-cpu", "threat-memory"])
def test_positive_integer_compatibility_never_replaces_real_job_validation(shipped, job_id, path, value):
    from importlib import import_module

    settings = json.loads(shipped.resolved_json)["jobs"][job_id]["settings"]
    _set(settings, path, value)
    # This deliberately malformed raw input must not carry the previous valid parsed settings.
    config = replace(shipped.job(job_id), settings=settings, typed_settings=None)
    module = import_module(f"appsec_review.jobs.{job_id}.job")
    job = module.build_job(check_models=lambda *args, **kwargs: pytest.fail("no provider call")) \
        if job_id == CONNECTIVITY else module.build_job()
    with pytest.raises(ValueError):
        for validate in job.input_validators:
            validate(SimpleNamespace(config=config), None)


@pytest.mark.parametrize("level", ["step", "task"])
def test_codeql_fixed_worker_validator_remains_authoritative(shipped, level):
    from appsec_review.jobs.job_codeql_analysis.job import build_job

    config = shipped.job("job_codeql_analysis")
    steps = dict(config.steps)
    execution = steps["execution"]
    if level == "step":
        steps["execution"] = replace(execution, workers=2)
    else:
        tasks = dict(execution.tasks)
        tasks["scopes"] = replace(tasks["scopes"], workers=2)
        steps["execution"] = replace(execution, tasks=tasks)
    with pytest.raises(ValueError, match="only action fan-out control"):
        for validate in build_job().input_validators:
            validate(SimpleNamespace(config=replace(config, steps=steps)), None)


def _append_job(path, job_id, name, settings, topology):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(f'\n[jobs.{job_id}]\nname = "{name}"\nworkers = 1\n')
        stream.write(f"\n[jobs.{job_id}.settings]\n")
        for key, value in settings.items():
            stream.write(f"{key} = {json.dumps(value)}\n")
        for step, tasks in topology.items():
            stream.write(f"\n[jobs.{job_id}.steps.{step}]\nworkers = 1\n")
            for task in tasks:
                stream.write(f"\n[jobs.{job_id}.steps.{step}.tasks.{task}]\nworkers = 1\n")


def _retained(root):
    return {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}


def _assert_retained(original):
    assert {path: path.read_bytes() for path in original} == original


def test_new_connectivity_attempt_passes_effective_timeout_without_salvaging_completed_units(tmp_path):
    from appsec_review.jobs.job_model_connectivity.job import TOPOLOGY, build_job

    config, (independent,), _ = fixture(tmp_path)
    independent = replace(independent, contract=JobContract(target_access=TargetAccess.NONE))
    _append_job(config.source_path, CONNECTIVITY, "model_connectivity", {"timeout_seconds": 1}, TOPOLOGY)
    with config.source_path.open("a", encoding="utf-8") as stream:
        stream.write('\n[jobs.job_fixture.settings.model]\nprovider = "fixture"\nmodel = "fixture-model"\n')
    write_release(tmp_path, ("job_fixture", CONNECTIVITY))
    config = load_config(config.source_path)
    calls = []

    def check(provider, names, *, timeout_seconds):
        calls.append(timeout_seconds)
        return {"provider": provider, "transport": True, "method": "fixture", "error": None,
                "models": {name: {"available": timeout_seconds > 1, "detail": "bounded fixture"} for name in names}}

    job = build_job(check_models=check)
    runner = JobRunner(config)
    retained = runner.run(independent)
    run_id = retained["status"]["run_id"]
    root = config.runtime.runs_dir / run_id
    original = _retained(root / "data/configuration")
    with pytest.raises(RuntimeError, match="partial failure"):
        runner.run(job, run_id=run_id)
    old_attempt = root / "data/jobs" / CONNECTIVITY / "attempts/attempt_0001"
    original.update(_retained(old_attempt))
    path = config.source_path
    path.write_text(path.read_text().replace("timeout_seconds = 1\n", "timeout_seconds = 60\n"))
    changed = load_config(path)
    plan = plan_repair(changed, root, (independent, job), "none")
    assert plan["admissible"], plan["refusals"]
    assert plan["decisions"][0]["action"] == "REUSE"
    assert {row["action"] for row in plan["unit_decisions"][CONNECTIVITY].values()} == {"RUN"}
    admit_repair(changed, root, (independent, job), plan)
    result = JobRunner(changed).run(job, run_id=run_id)
    assert calls == [1, 60]
    assert result["status"]["attempt_id"] == "attempt_0002"
    assert result["status"]["status"] == "SUCCEEDED"
    assert set(result["handoff"]["outputs"]) == {
        "connectivity.resolve_models", "connectivity.verify_models", "publication.publish_handoff",
    }
    claim = json.loads((root / "data/jobs" / CONNECTIVITY / "attempts/attempt_0002/claim.json").read_bytes())
    assert claim["resolved_config_sha256"] == changed.resolved_sha256 != config.resolved_sha256
    snapshot = configuration_snapshot(root, claim["resolved_config_sha256"])
    assert snapshot.document["jobs"][CONNECTIVITY]["settings"]["timeout_seconds"] == 60
    assert {row["path"] for row in snapshot.artifacts(root)} >= {
        "data/configuration/resolved.json",
        f"data/configuration/revisions/{changed.resolved_sha256}/resolved.json",
    }
    _assert_retained(original)
    verify_handoff(root, retained["handoff"])
    verify_handoff(root, result["handoff"])


def test_environment_coverage_is_retained_until_explicit_whole_job_and_downstream_execution(tmp_path, monkeypatch):
    from appsec_review.interchange import GapCode, producer_gap
    from appsec_review.jobs.job_build_environment_analysis import job as environment
    from appsec_review.jobs.job_target_catalog.datasets import DATASETS as CATALOG_DATASETS
    from appsec_review.retrieval import INDEX_SCHEMA, IndexBuilder, IndexIdentity, write_manifest
    from appsec_review.runtime.consume import accepted_upstream
    from appsec_review.runtime.inputs import observe_output, read_input_observations
    from appsec_review.storage import atomic_json
    from appsec_review.storage.shared import reference, verify_reference

    config, (catalog, sink, independent), calls = fixture(tmp_path, ("job_target_catalog", "job_sink", "job_independent"))
    _append_job(config.source_path, ENVIRONMENT, "build_environment_analysis",
                {**asdict(BuildEnvironmentSettings()), "deadline_seconds": 1},
                {"environment_analysis": ("analyze_scripts", "publish_handoff")})
    write_release(tmp_path, ("job_target_catalog", ENVIRONMENT, "job_sink", "job_independent"))
    config = load_config(config.source_path)
    target = tmp_path / "target"
    target.mkdir()
    script = target / "setup.sh"
    script.write_bytes(b"CC=clang\n")
    source = "a" * 64
    declarations = tuple(replace(
        item, step="work",
        artifacts=("data/jobs/job_target_catalog/attempts/*/steps/work/tasks/only/catalog.json",)
        if item.output_kind == "catalog_documents" else item.artifacts,
    ) for item in CATALOG_DATASETS)

    def publish_catalog(unit):
        document = unit.unit_root / "catalog.json"
        atomic_json(document, {
            "schema": "appsec-review/target-catalog/1", "source_fingerprint": source,
            "files": [{"path": "setup.sh", "sha256": file_sha256(script), "size_bytes": script.stat().st_size}],
        })
        gap = "synthetic catalog metadata; source indexing is outside this unit regression"
        indexes = []
        for declaration in declarations:
            if declaration.disposition != "indexed":
                continue
            name = declaration.indexes[0]
            shard = "fixture-" + declaration.output_kind
            fingerprint = hashlib.sha256(shard.encode()).hexdigest()
            path = unit.job.run_root / "data/indices" / name / f"{fingerprint}.sqlite"
            builder = IndexBuilder(path, name=name, fingerprint=fingerprint,
                                   target_snapshot=source, shard_id=shard)
            builder.add_coverage("synthetic_catalog", "unavailable", gap)
            indexes.append(IndexIdentity(
                name, INDEX_SCHEMA, builder.build(), fingerprint, path.relative_to(unit.job.run_root).as_posix(),
                {"job": catalog.job_id, "unit": unit.unit_id}, (gap,), shard,
            ))
        manifest = unit.unit_root / "index-manifest.json"
        write_manifest(manifest, run_id=unit.job.run_id, target_snapshot=source,
                       target_root=target, indexes=indexes)
        return {
            "catalog": reference(unit.job.run_root, document),
            "index_manifest": reference(unit.job.run_root, manifest),
            "indexes": [asdict(index) for index in indexes],
            "terminal_status": "COMPLETED_WITH_GAPS",
            "gaps": [producer_gap(GapCode.INPUT_UNAVAILABLE, gap, unit_id=unit.unit_id)],
        }

    def accepted(root):
        upstream = accepted_upstream(root, "job_target_catalog")
        identity = upstream.handoff["outputs"]["work.only"]["catalog"]
        observe_output(root, "job_target_catalog", "catalog_documents", identity)
        return {**json.loads(verify_reference(root, identity).read_bytes()),
                "catalog_handoff_sha256": upstream.sha256}

    real_analysis = environment.analyze_environment
    deadlines = []

    def clocked(catalog, reader, settings):
        deadlines.append(settings.deadline_seconds)
        ticks = iter((0, 2, 3, 4))
        return real_analysis(catalog, reader, settings, clock=lambda: next(ticks))

    monkeypatch.setattr(environment, "load_accepted_catalog", accepted)
    monkeypatch.setattr(environment, "analyze_environment", clocked)
    job = environment.build_job()
    catalog = replace(catalog, units=(Unit("work.only", publish_catalog),),
                      datasets=declarations, contract=JobContract(), strict_gaps=True)
    original_sink = sink.units[0].handler

    def consume_environment(unit):
        upstream = accepted_upstream(unit.job.run_root, ENVIRONMENT)
        identity = upstream.handoff["outputs"]["environment_analysis.publish_handoff"]["artifact"]
        observe_output(unit.job.run_root, ENVIRONMENT, "build_environment", identity)
        return {**original_sink(unit), "environment_sha256": identity["sha256"]}

    sink = replace(sink, units=(Unit("work.only", consume_environment),), contract=JobContract(
        inputs=accepted_inputs(ENVIRONMENT, job.datasets,
                               availability=Availability.REQUIRED, missing=MissingPolicy.REJECT)))
    independent = replace(independent, contract=JobContract())
    jobs = (catalog, job, sink, independent)
    dependencies = {"job_target_catalog": (), ENVIRONMENT: ("job_target_catalog",),
                    "job_sink": (ENVIRONMENT,), "job_independent": ()}
    first = GraphRunner(config, jobs, dependencies=dependencies).run(target_root=target, source_fingerprint=source)
    root = config.runtime.runs_dir / first["run_id"]
    old_attempt = root / "data/jobs" / ENVIRONMENT / "attempts/attempt_0001"
    old_payload = old_attempt / "steps/environment_analysis/tasks/publish_handoff/build-environment.json"
    bounded = json.loads(old_payload.read_bytes())
    assert bounded["bounds"]["deadline_seconds"] == 1
    assert bounded["coverage"] == "partial" and bounded["gaps"] == ["internal_environment_deadline"]
    sink_reads = read_input_observations(root, first["jobs"]["job_sink"]["handoff"])["reads"]
    assert {row["output_kind"] for row in sink_reads} == {"handoff", "build_environment"}
    original = {**_retained(root / "data/configuration"), **_retained(old_attempt)}
    path = config.source_path
    path.write_text(path.read_text().replace("deadline_seconds = 1\n", "deadline_seconds = 30\n"))
    changed = load_config(path)
    preview = plan_repair(changed, root, jobs, source, target_root=target, dependencies=dependencies)
    assert preview["admissible"], preview["refusals"]
    assert {row["action"] for row in preview["decisions"]} == {"REUSE"}
    assert deadlines == [1]
    assert not (root / "data/configuration/revisions").exists()
    _assert_retained(original)
    plan = plan_repair(changed, root, jobs, source, target_root=target, dependencies=dependencies,
                       force_from=ENVIRONMENT)
    assert plan["admissible"], plan["refusals"]
    actions = {row["job_id"]: row["action"] for row in plan["decisions"]}
    assert actions == {"job_target_catalog": "REUSE", ENVIRONMENT: "RUN",
                       "job_sink": "REVALIDATE", "job_independent": "REUSE"}
    assert {row["action"] for row in plan["unit_decisions"][ENVIRONMENT].values()} == {"RUN"}
    admit_repair(changed, root, jobs, plan, target_root=target, dependencies=dependencies)
    GraphRunner(changed, jobs, dependencies=dependencies).run(
        target_root=target, source_fingerprint=source, run_id=first["run_id"], force_from=ENVIRONMENT)
    expanded = json.loads((root / "data/jobs" / ENVIRONMENT /
                           "attempts/attempt_0002/steps/environment_analysis/tasks/publish_handoff/"
                           "build-environment.json").read_bytes())
    assert deadlines == [1, 30]
    assert expanded["bounds"]["deadline_seconds"] == 30
    assert expanded["coverage"] == "complete" and expanded["gaps"] == []
    assert expanded["declarations"][0]["value"] == "clang"
    assert [call for call in calls if call[0] == "job_sink"] == [
        ("job_sink", "work.only", "attempt_0001"), ("job_sink", "work.only", "attempt_0002")]
    assert len([call for call in calls if call[0] == "job_independent"]) == 1
    revision = configuration_snapshot(root, changed.resolved_sha256)
    assert revision.manifest["operational_changes"] == [{
        "job_id": ENVIRONMENT, "path": ["settings", "deadline_seconds"],
        "category": "coverage", "before": 1, "after": 30,
    }]
    _assert_retained(original)


def test_intake_preflight_uses_the_effective_job_timeout(tmp_path, shipped):
    from appsec_review.jobs.job_review_intake.job import build_job

    config = _job_settings(shipped, "job_review_intake", model_preflight={"timeout_seconds": 53})
    required = [{"job_id": "job_fixture", "setting": "settings.model", "provider": "fixture",
                 "model": "fixture-model", "enabled": True}]
    calls = []

    def check(provider, names, *, timeout_seconds):
        calls.append(timeout_seconds)
        return {"provider": provider, "transport": True, "method": "fixture", "error": None,
                "models": {name: {"available": True, "detail": "fixture"} for name in names}}

    unit = _unit(tmp_path, config, "model_preflight.verify_models",
                 {"model_preflight.resolve_models": {"required": required, "not_required": []}})
    result = _handler(build_job(check_models=check), unit.unit_id)(unit)
    assert calls == [53] and result["terminal_status"] == "SUCCEEDED"


def test_history_timeout_reaches_the_http_transport(shipped):
    from appsec_review.jobs.job_source_history_analysis.github import GitHubClient
    from appsec_review.jobs.job_source_history_analysis.job import _github_settings

    settings = json.loads(shipped.resolved_json)["jobs"]["job_source_history_analysis"]["settings"]["github"]
    settings.update(repository="fixture/repository", timeout_seconds=53)
    calls = []

    def transport(url, headers, timeout):
        calls.append(timeout)
        return 200, {}, b"{}"

    client = GitHubClient(_github_settings(settings, None), transport)
    client.request("/repos/fixture/repository")
    assert calls == [53]
    settings["timeout_seconds"] = 301
    with pytest.raises(ValueError, match="bounds"):
        _github_settings(settings, None)


@pytest.mark.parametrize("job_id,table,unit_id", [
    ("job_review_prioritization", "syntax_metrics_reservation", "extract.syntax_metrics"),
    ("job_threat_model_generation", "reservation", "facts.structure"),
], ids=["syntax", "threat"])
def test_resource_values_reach_real_handlers_before_external_admission(tmp_path, shipped, monkeypatch,
                                                                    job_id, table, unit_id):
    from importlib import import_module

    module = import_module(f"appsec_review.jobs.{job_id}.job")
    reservation = {"cpu": 2, "memory_mb": 256, "io_slots": 0, "admission_timeout_seconds": 17}
    config = _job_settings(shipped, job_id, **{table: reservation})
    observed = []

    class AdmissionReached(Exception):
        pass

    class Admission:
        def __init__(self, metadata, resources):
            self.metadata = metadata

        def reserve(self, request, **kwargs):
            observed.append((request, kwargs["timeout_seconds"]))
            raise AdmissionReached

    monkeypatch.setattr(module, "ResourceAdmission", Admission)
    unit = _unit(tmp_path, config, unit_id)
    with pytest.raises(AdmissionReached):
        _handler(module.build_job(), unit_id)(unit)
    assert len(observed) == 1
    request, timeout = observed[0]
    assert (request.cpu, request.memory_mb, request.io_slots, timeout) == (2, 256, 0, 17)


def test_sanitizer_new_attempt_uses_effective_pool_and_command_wait(tmp_path, monkeypatch):
    from appsec_review.jobs.job_sanitizer_build import job as sanitizer
    from tests.sanitizer_support import DockerFake
    from tests.unit.job_sanitizer_build.test_attempt_regressions import _publish_input, _run_handlers
    from tests.unit.job_sanitizer_build.test_handlers import _synthetic_fixture

    _, _, _, root, receipt, unit = _synthetic_fixture(tmp_path)
    upstream = _publish_input(unit, [receipt])
    real_executor, real_pool = sanitizer.BuildContainerExecutor, sanitizer.ThreadPoolExecutor
    waits, workers = [], []

    class CLI(DockerFake):
        def __call__(self, argv, timeout):
            if tuple(argv[:2]) == ("docker", "run"):
                waits.append(timeout)
            return super().__call__(argv, timeout)

    def executor(profile, *, timeout_seconds, output_bytes):
        return real_executor(profile, timeout_seconds=timeout_seconds, output_bytes=output_bytes,
                             runner=CLI(profile))

    class Pool(real_pool):
        def __init__(self, *, max_workers):
            workers.append(max_workers)
            super().__init__(max_workers=max_workers)

    monkeypatch.setattr(sanitizer, "BuildContainerExecutor", executor)
    monkeypatch.setattr(sanitizer, "ThreadPoolExecutor", Pool)
    first, summary = _run_handlers(unit, upstream, None)
    assert first["terminal_status"] == "SUCCEEDED"
    original = _retained(root / "data/jobs/job_sanitizer_build/attempts/attempt_0001")
    original.update(_retained(root / summary["units"][0]["workspace"]))
    unit.job.config.settings = {**unit.job.config.settings, "workers": 2, "command_timeout_seconds": 120}
    second, expanded = _run_handlers(unit, upstream, None, attempt="attempt_0002")
    assert second["terminal_status"] == "SUCCEEDED"
    assert workers == [1, 2] and waits == [60, 60, 120, 120]
    assert summary["units"][0]["workspace"] != expanded["units"][0]["workspace"]
    _assert_retained(original)


def test_debug_symbol_reader_receives_effective_timeout(tmp_path, monkeypatch):
    from tests.unit.job_debug_symbol_indexing.test_extract import _run

    result = _run(tmp_path, monkeypatch, settings={"reader": {"timeout_seconds": 53}})
    assert result.result["terminal_status"] == "SUCCEEDED"
    assert len(result.calls) == 1
    assert result.calls[0][3]["timeout_seconds"] == 53


def test_dossier_renderer_retains_timeout_gap_when_a_later_attempt_gets_more_time(tmp_path):
    from appsec_review.reporting.dossier_render import render_dossier
    from tests.dossier_fixture import make_model, settings

    root = tmp_path / "run"
    model = make_model(root)
    waits = []

    def executor(catalog, run_root):
        timeout = catalog.tool("tool-report-latex").timeout_seconds
        waits.append(timeout)

        def execute(request):
            if timeout == 60:
                (request.scratch_root / "report.pdf").write_bytes(b"%PDF-1.4\n" + b"fixture\n" * 8 + b"%%EOF\n")
            return SimpleNamespace(
                receipt_path="absent-external-receipt.json", exit_code=0 if timeout == 60 else 124,
                timed_out=timeout == 30, oom_killed=False, file_size_limit_reached=False,
                terminal_status="SUCCEEDED" if timeout == 60 else "TIMED_OUT",
            )

        return SimpleNamespace(execute=execute)

    first = render_dossier(root, root / "data/attempt_0001", model, settings=settings(render_timeout_seconds=30),
                           repository_root=ROOT, executor_factory=executor)
    original = _retained(root / "data/attempt_0001")
    second = render_dossier(root, root / "data/attempt_0002", model, settings=settings(render_timeout_seconds=60),
                            repository_root=ROOT, executor_factory=executor)
    assert waits == [30, 60]
    assert first["status"] == "render_failed" and first["files"]["pdf"] is None
    assert any("dossier_render_failed" in gap for gap in first["gap_ids"])
    assert second["status"] == "rendered" and second["files"]["pdf"] is not None
    _assert_retained(original)


@pytest.mark.parametrize("path,old,new,category", [
    (("jobs", "job_tree_sitter_ast", "settings", "workers"), 1, 4, "coverage"),
    (("jobs", "job_codeql_analysis", "settings", "query_timeout_seconds"), 60, 120, "coverage"),
    (("jobs", "job_codeql_analysis", "settings", "export_queries", "compile_threads"), 2, 4, "execution"),
    (("jobs", "job_debug_symbol_indexing", "settings", "reader", "timeout_seconds"), 1, 1.5, "execution"),
    (("jobs", "job_review_prioritization", "settings", "syntax_metrics_reservation", "io_slots"), 0, 1, "execution"),
    (("runtime", "operation_sample_interval_seconds"), 0, 0.25, "execution"),
    (("orchestration", "dagster", "pools", "cpp_analysis"), 1, 4, "execution"),
])
def test_extended_tuning_types_and_categories(path, old, new, category):
    before = {}
    node = before
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = old
    after = deepcopy(before)
    _set(after, path, new)
    change, = operational_changes(before, after)
    assert (change["before"], change["after"], change["category"]) == (old, new, category)
    _set(after, path, True)
    with pytest.raises(MaterialConfigurationChange):
        operational_changes(before, after)


def test_graph_new_attempt_does_not_reuse_or_delete_prior_checkpoint(tmp_path):
    from appsec_review.jobs.job_code_graph_index.scopes import reuse_checkpoint, save_checkpoint
    shard = tmp_path / "retained.sqlite"
    shard.write_bytes(b"retained")
    result = {"scope_id": "cpp-s1", "shards": [
        {"relative_path": "retained.sqlite", "sha256": file_sha256(shard)}]}
    save_checkpoint(tmp_path, "cpp-s1", "identity", result, attempt_id="attempt_0001")
    assert reuse_checkpoint(tmp_path, "cpp-s1", "identity", attempt_id="attempt_0002") is None
    shard.write_bytes(b"changed")
    assert reuse_checkpoint(tmp_path, "cpp-s1", "identity", attempt_id="attempt_0001") is None
    assert shard.read_bytes() == b"changed"



def test_iteration_configuration_reconstructs_pinned_layers_not_live_source(tmp_path, shipped, monkeypatch):
    from appsec_review.runtime.configuration import ConfigurationSnapshot
    from appsec_review.jobs.job_build_iteration.job import load_iteration_configuration
    import appsec_review.runtime.configuration as snapshots

    pinned = tmp_path / "configuration"
    pinned.mkdir()
    (pinned / "appsec-review.toml").write_bytes(shipped.source_path.read_bytes())
    if shipped.host_pins is not None:
        (pinned / "host-pins.toml").write_bytes(shipped.host_pins.content)
    snapshot = ConfigurationSnapshot(pinned, {
        "sources": list(shipped.layers), "resolved_sha256": shipped.resolved_sha256,
        "selection": {"profile": shipped.profile, "overlay": None,
                      "compiler_target": shipped.compiler_target.value},
    }, json.loads(shipped.resolved_json))
    selected = []
    def resolve(root, expected):
        selected.append(expected)
        return snapshot
    monkeypatch.setattr(snapshots, "configuration_snapshot", resolve)
    read = Path.read_bytes
    def guarded(path):
        if path == shipped.source_path:
            raise AssertionError("iteration read current source rather than its pinned revision")
        return read(path)
    monkeypatch.setattr(Path, "read_bytes", guarded)
    effective = load_iteration_configuration(tmp_path, shipped.resolved_sha256)
    assert selected == [shipped.resolved_sha256]
    assert effective.resolved_json == shipped.resolved_json
    assert effective.job("job_language_build").settings == shipped.job("job_language_build").settings


@pytest.mark.parametrize("job_id,unit_id", [
    ("job_clang_static_analysis", "analyze.scopes"),
    ("job_cpp_symbol_index", "index.scopes"),
    ("job_cpg_analysis", "generate.scopes"),
])
def test_analyzer_effective_workers_reach_real_pool(tmp_path, shipped, monkeypatch, job_id, unit_id):
    import importlib
    module = importlib.import_module(f"appsec_review.jobs.{job_id}.job")
    original = shipped.job(job_id)
    settings = dict(original.settings)
    if job_id == "job_cpg_analysis":
        settings["enabled"] = True
    seen = []
    pool_type = module.ThreadPoolExecutor
    class ObservedPool(pool_type):
        def __init__(self, *, max_workers):
            seen.append(max_workers)
            super().__init__(max_workers=max_workers)
    monkeypatch.setattr(module, "ThreadPoolExecutor", ObservedPool)
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda root: ({}, [], {}))
    for workers in (1, 3):
        config = replace(original, settings={**settings, "workers": workers})
        unit = _unit(tmp_path / str(workers), config, unit_id, {"load.accepted_cpp": {"scopes": []}})
        result = _handler(module.build_job(), unit_id)(unit)
        assert result["scope_count"] == 0
    assert seen == [1, 3]
