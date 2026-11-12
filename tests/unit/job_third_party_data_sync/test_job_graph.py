"""job_third_party_data_sync: the unit graph, its validators and the handler wiring, without running it.

Every feed step's parsing lives in its own module and has its own tests here. These tests hold
the job's contract: the 21 units and their order, the schema each unit must return, what
``validate_input``/``validate_output`` refuse, and that each handler passes the right outputs to
the right step function and publishes global metadata. No runner, no feed download, no engine.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_third_party_data_sync import job as sync_job
from appsec_review.jobs.job_third_party_data_sync.job import TOPOLOGY, build_job, validate_input

ROOT = Path(__file__).resolve().parents[3]

EXPECTED_UNIT_SCHEMAS = {
    "nvd_sync.fetch": "appsec-review/nvd-current-pointer/1",
    "nvd_sync.process": "appsec-review/nvd-process/1",
    "nvd_sync.publish": "appsec-review/nvd-publication/1",
    "osv_sync.fetch": "appsec-review/osv-fetch/1",
    "osv_sync.index": "appsec-review/osv-index/2",
    "osv_sync.publish": "appsec-review/osv-publication/1",
    "grype_db_sync.fetch": "appsec-review/grype-fetch/1",
    "grype_db_sync.import": "appsec-review/grype-import/1",
    "grype_db_sync.publish": "appsec-review/grype-publication/1",
    "mitre_sync.fetch": "appsec-review/mitre-fetch/1",
    "mitre_sync.normalize": "appsec-review/mitre-normalize/2",
    "mitre_sync.publish": "appsec-review/mitre-publication/1",
    "kev_sync.fetch": "appsec-review/kev-fetch/1",
    "kev_sync.normalize": "appsec-review/kev-normalize/1",
    "kev_sync.publish": "appsec-review/kev-publication/1",
    "epss_sync.fetch": "appsec-review/epss-fetch/1",
    "epss_sync.normalize": "appsec-review/epss-normalize/1",
    "epss_sync.publish": "appsec-review/epss-publication/1",
    "cve_bin_tool_db_build.resolve_nvd_snapshot": "appsec-review/resolved-nvd-snapshot/1",
    "cve_bin_tool_db_build.build": "appsec-review/cve-bin-tool-build/1",
    "cve_bin_tool_db_build.publish": "appsec-review/cve-bin-tool-publication/1",
}


def _units(**kwargs):
    return {unit.unit_id: unit for unit in build_job(**kwargs).units}


def _job_context(tmp_path: Path, **overrides) -> SimpleNamespace:
    fields = {"run_id": "2026-11-12-0001", "attempt_id": "attempt_0001", "trigger": "schedule",
              "metadata_root": tmp_path / "runs" / "metadata", "run_root": tmp_path / "runs" / "2026-11-12-0001",
              "repository_root": tmp_path, "orchestration": {"dispatch": "fixture"}}
    fields.update(overrides)
    return SimpleNamespace(**fields)


def _unit_context(tmp_path: Path, unit_id: str, outputs: dict | None = None, **job_overrides) -> SimpleNamespace:
    outputs = outputs or {}
    step_id, task_id = unit_id.split(".")
    return SimpleNamespace(job=_job_context(tmp_path, **job_overrides), unit_id=unit_id, step_id=step_id,
                           task_id=task_id, unit_root=tmp_path / "unit" / unit_id, outputs=outputs,
                           output=lambda key: outputs[key])


# --- graph shape ---------------------------------------------------------------------------------

def test_graph_is_the_declared_topology_with_in_step_ordering_and_one_cross_step_edge() -> None:
    units = _units()
    assert set(units) == {f"{step}.{task}" for step, tasks in TOPOLOGY.items() for task in tasks}
    assert len(units) == 21
    for step, tasks in TOPOLOGY.items():
        for previous, task in zip(tasks, tasks[1:]):
            assert units[f"{step}.{task}"].dependencies == (f"{step}.{previous}",), f"{step}.{task}"
    heads = {f"{step}.{tasks[0]}": units[f"{step}.{tasks[0]}"].dependencies for step, tasks in TOPOLOGY.items()}
    assert heads == {"nvd_sync.fetch": (), "osv_sync.fetch": (), "grype_db_sync.fetch": (), "mitre_sync.fetch": (),
                     "kev_sync.fetch": (), "epss_sync.fetch": (),
                     "cve_bin_tool_db_build.resolve_nvd_snapshot": ("nvd_sync.publish",)}


def test_job_identity_contract_and_datasets() -> None:
    job = build_job()
    assert (job.job_id, job.name) == ("job_third_party_data_sync", "third_party_data_sync")
    assert job.strict_gaps is True and job.always_execute is True and job.propagate_handoff is True
    assert job.consumes == () and job.contract is not None and job.contract.inputs == ()
    assert [dataset.output_kind for dataset in job.datasets] == ["feed_sync_work"]
    assert len(job.input_validators) == 1 and len(job.output_validators) == 1


def test_every_unit_accepts_exactly_its_output_schema() -> None:
    for unit_id, unit in _units().items():
        assert len(unit.output_validators) == 1, unit_id
        validator = unit.output_validators[0]
        context = SimpleNamespace(unit_id=unit_id)
        validator(context, {"schema": EXPECTED_UNIT_SCHEMAS[unit_id], "anything": 1})
        with pytest.raises(ValueError, match=f"{unit_id} returned an invalid result schema"):
            validator(context, None)
        with pytest.raises(ValueError, match="invalid result schema"):
            validator(context, {"schema": "appsec-review/other/1"})


# --- validate_input --------------------------------------------------------------------------------

def _real_job_config():
    return load_config(ROOT / "appsec-review.toml").job("job_third_party_data_sync")


def test_validate_input_accepts_the_shipped_configuration_with_roots_inside_the_checkout() -> None:
    context = _job_context(ROOT, config=_real_job_config(), run_root=ROOT / "runs" / "x",
                           metadata_root=ROOT / "runs" / "metadata")
    validate_input(context, None)


def test_validate_input_refuses_a_different_step_set_before_reading_any_setting() -> None:
    config = SimpleNamespace(steps={"nvd_sync": object()}, step=lambda step_id: pytest.fail("settings were read"))
    with pytest.raises(ValueError, match="steps must be exactly"):
        validate_input(_job_context(ROOT, config=config), None)


def test_validate_input_refuses_reordered_tasks_in_a_step() -> None:
    def step(step_id):
        tasks = list(TOPOLOGY[step_id])
        if step_id == "osv_sync":
            tasks.reverse()
        return SimpleNamespace(tasks=tuple(tasks))
    config = SimpleNamespace(steps=dict.fromkeys(TOPOLOGY), step=step)
    with pytest.raises(ValueError, match="osv_sync tasks must be ordered exactly as"):
        validate_input(_job_context(ROOT, config=config), None)


def test_validate_input_refuses_a_feed_root_outside_data_and_metadata_outside_the_runs_dir(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _real_job_config()
    monkeypatch.setattr(sync_job, "_nvd", lambda context: SimpleNamespace(feed_root=tmp_path / "elsewhere"))
    with pytest.raises(ValueError, match="NVD feed_root must be inside"):
        validate_input(_job_context(ROOT, config=config, run_root=ROOT / "runs" / "x",
                                    metadata_root=ROOT / "runs" / "metadata"), None)
    monkeypatch.undo()
    with pytest.raises(ValueError, match="metadata_root must be inside"):
        validate_input(_job_context(ROOT, config=config, run_root=ROOT / "runs" / "x",
                                    metadata_root=tmp_path / "metadata"), None)


# --- validate_output and the result transform ----------------------------------------------------

def test_validate_output_requires_the_result_schema_and_a_receipt_for_every_unit() -> None:
    job = build_job()
    validate = job.output_validators[0]
    context = SimpleNamespace()
    with pytest.raises(ValueError, match="invalid result schema"):
        validate(context, None)
    with pytest.raises(ValueError, match="invalid result schema"):
        validate(context, {"schema": "appsec-review/job-result/1", "units": {}})
    complete = {unit.unit_id: {} for unit in job.units}
    partial = dict(complete)
    partial.pop("epss_sync.publish")
    with pytest.raises(ValueError, match="omitted unit receipts"):
        validate(context, {"schema": "appsec-review/job-result/third-party-data-sync/1", "units": partial})
    validate(context, {"schema": "appsec-review/job-result/third-party-data-sync/1", "units": complete})


def test_result_transform_stamps_the_schema_and_publishes_global_job_metadata(tmp_path: Path) -> None:
    job = build_job()
    context = _job_context(tmp_path)
    result = job.finalize_result(context, {"status": "SUCCEEDED", "steps": {"nvd_sync": "SUCCEEDED"},
                                           "failed_units": [], "skipped_units": [], "units": {}})
    assert result["schema"] == "appsec-review/job-result/third-party-data-sync/1"
    published = json.loads((tmp_path / "runs" / "metadata" / "jobs" / "job_third_party_data_sync.json")
                           .read_text(encoding="utf-8"))
    assert published == {"schema": "appsec-review/global-job-metadata/1", "job_id": "job_third_party_data_sync",
                         "updated_at": published["updated_at"], "run_id": "2026-11-12-0001",
                         "attempt_id": "attempt_0001", "trigger": "schedule", "status": "SUCCEEDED",
                         "steps": {"nvd_sync": "SUCCEEDED"}, "orchestration": {"dispatch": "fixture"},
                         "failed_units": [], "skipped_units": []}
    assert published["updated_at"].endswith("Z")


# --- handler wiring ---------------------------------------------------------------------------------

@pytest.mark.parametrize("feed", ["kev", "epss"])
def test_reference_feed_handlers_pass_outputs_through_and_publish_feed_metadata(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, feed: str) -> None:
    module = getattr(sync_job, f"{feed}_feed")
    settings = object()
    monkeypatch.setattr(sync_job, f"_{feed}", lambda context: settings)
    calls: list[tuple] = []
    monkeypatch.setattr(module, "fetch", lambda s, work, downloader: calls.append(("fetch", s, work, downloader))
                        or {"schema": f"appsec-review/{feed}-fetch/1", "fetched": True})
    monkeypatch.setattr(module, "normalize", lambda s, fetched, work: calls.append(("normalize", s, fetched, work))
                        or {"schema": f"appsec-review/{feed}-normalize/1", "normalized": True})
    monkeypatch.setattr(module, "publish", lambda s, fetched, normalized:
                        calls.append(("publish", s, fetched, normalized)) or {"snapshot_id": "snap"})
    monkeypatch.setattr(module, "verify", lambda s: calls.append(("verify", s)) or {"snapshot_id": "snap", "ok": 1})
    downloader = object()
    units = _units(**{f"{feed}_downloader": downloader})
    step = f"{feed}_sync"

    fetched = units[f"{step}.fetch"].handler(_unit_context(tmp_path, f"{step}.fetch"))
    normalized = units[f"{step}.normalize"].handler(_unit_context(tmp_path, f"{step}.normalize", {f"{step}.fetch": fetched}))
    published = units[f"{step}.publish"].handler(_unit_context(
        tmp_path, f"{step}.publish", {f"{step}.fetch": fetched, f"{step}.normalize": normalized}))

    assert calls[0] == ("fetch", settings, tmp_path / "unit" / f"{step}.fetch" / "work", downloader)
    assert calls[1] == ("normalize", settings, fetched, tmp_path / "unit" / f"{step}.normalize" / "work")
    assert calls[2] == ("publish", settings, fetched, normalized) and calls[3] == ("verify", settings)
    assert published["schema"] == f"appsec-review/{feed}-publication/1"
    assert published["pointer"] == {"snapshot_id": "snap"} and published["identity"] == {"snapshot_id": "snap", "ok": 1}
    metadata = json.loads(Path(published["metadata_path"]).read_text(encoding="utf-8"))
    assert Path(published["metadata_path"]) == tmp_path / "runs" / "metadata" / "feeds" / f"{feed}.json"
    assert metadata["schema"] == "appsec-review/global-feed-metadata/1" and metadata["feed_id"] == feed
    assert (metadata["run_id"], metadata["attempt_id"]) == ("2026-11-12-0001", "attempt_0001")
    assert metadata["pointer"] == {"snapshot_id": "snap"} and metadata["identity"] == {"snapshot_id": "snap", "ok": 1}


def test_nvd_process_refuses_a_snapshot_that_changed_since_fetch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    publisher = SimpleNamespace(verify=lambda: {"snapshot_id": "later", "manifest_sha256": "b" * 64})
    monkeypatch.setattr(sync_job, "_publisher", lambda job, client, clock, pause: publisher)
    unit = _units()["nvd_sync.process"]
    fetched = {"schema": "appsec-review/nvd-current-pointer/1", "snapshot_id": "earlier", "manifest_sha256": "a" * 64}
    with pytest.raises(ValueError, match="NVD current snapshot changed between fetch and process"):
        unit.handler(_unit_context(tmp_path, "nvd_sync.process", {"nvd_sync.fetch": fetched}))
    fetched["snapshot_id"] = "later"
    processed = unit.handler(_unit_context(tmp_path, "nvd_sync.process", {"nvd_sync.fetch": fetched}))
    assert processed == {"schema": "appsec-review/nvd-process/1", "snapshot_id": "later",
                         "manifest_sha256": "a" * 64}


def test_nvd_fetch_passes_the_run_and_attempt_as_the_sync_label_and_the_configured_api_key(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}

    def sync(label, api_key):
        seen.update(label=label, api_key=api_key)
        return {"snapshot_id": "s", "manifest_sha256": "a" * 64}
    publisher = SimpleNamespace(sync=sync, settings=SimpleNamespace(api_key_env="FIXTURE_NVD_KEY"))
    monkeypatch.setattr(sync_job, "_publisher", lambda job, client, clock, pause: publisher)
    monkeypatch.setenv("FIXTURE_NVD_KEY", "secret-fixture")
    result = _units()["nvd_sync.fetch"].handler(_unit_context(tmp_path, "nvd_sync.fetch"))
    assert seen == {"label": "2026-11-12-0001/attempt_0001", "api_key": "secret-fixture"}
    assert result["schema"] == "appsec-review/nvd-fetch/1" and result["snapshot_id"] == "s"


def test_grype_publish_refuses_a_pointer_that_disagrees_with_the_verified_identity(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sync_job, "_grype", lambda context: object())
    monkeypatch.setattr(sync_job.grype_feed, "publish", lambda s, fetched, imported, now: {"snapshot_id": "one"})
    monkeypatch.setattr(sync_job.grype_feed, "verify", lambda s, now: {"snapshot_id": "two"})
    unit = _units()["grype_db_sync.publish"]
    context = _unit_context(tmp_path, "grype_db_sync.publish", {"grype_db_sync.fetch": {}, "grype_db_sync.import": {}})
    with pytest.raises(ValueError, match="Grype current snapshot changed during publication"):
        unit.handler(context)
    monkeypatch.setattr(sync_job.grype_feed, "verify", lambda s, now: {"snapshot_id": "one"})
    published = unit.handler(context)
    assert published["schema"] == "appsec-review/grype-publication/1"
    assert json.loads(Path(published["metadata_path"]).read_text(encoding="utf-8"))["feed_id"] == "grype"


def test_cve_bin_tool_units_bind_the_published_nvd_identity_and_the_injected_runner(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    nvd_settings = SimpleNamespace(feed_root=tmp_path / "data" / "feeds" / "nvd")
    cve_settings = SimpleNamespace(feed_root=tmp_path / "data" / "feeds" / "cve-bin-tool")
    monkeypatch.setattr(sync_job, "_nvd", lambda context: nvd_settings)
    monkeypatch.setattr(sync_job, "_cve", lambda context: cve_settings)
    identity = {"snapshot_id": "nvd-1", "manifest_sha256": "c" * 64}
    calls: list = []
    monkeypatch.setattr(sync_job.cve_db, "resolve_nvd_snapshot",
                        lambda root, pointer: calls.append(("resolve", root, pointer)) or {"resolved": True})
    monkeypatch.setattr(sync_job.cve_db, "build",
                        lambda settings, resolved, work, runner: calls.append(("build", settings, resolved, work, runner))
                        or {"built": True})
    monkeypatch.setattr(sync_job.cve_db, "publish", lambda settings, built: {"snapshot_id": "cve-1"})
    monkeypatch.setattr(sync_job.cve_db, "verify", lambda settings, resolved: {"snapshot_id": "cve-1", "cve_count": 1})
    runner = object()
    units = _units(cve_runner=runner)
    resolved = units["cve_bin_tool_db_build.resolve_nvd_snapshot"].handler(_unit_context(
        tmp_path, "cve_bin_tool_db_build.resolve_nvd_snapshot", {"nvd_sync.publish": {"identity": identity}}))
    built = units["cve_bin_tool_db_build.build"].handler(_unit_context(
        tmp_path, "cve_bin_tool_db_build.build", {"cve_bin_tool_db_build.resolve_nvd_snapshot": resolved}))
    published = units["cve_bin_tool_db_build.publish"].handler(_unit_context(
        tmp_path, "cve_bin_tool_db_build.publish",
        {"cve_bin_tool_db_build.resolve_nvd_snapshot": resolved, "cve_bin_tool_db_build.build": built}))
    assert calls[0] == ("resolve", nvd_settings.feed_root, identity)
    assert calls[1] == ("build", cve_settings, {"resolved": True},
                        tmp_path / "unit" / "cve_bin_tool_db_build.build" / "work", runner)
    assert published["schema"] == "appsec-review/cve-bin-tool-publication/1"
    assert published["identity"]["cve_count"] == 1
    assert json.loads(Path(published["metadata_path"]).read_text(encoding="utf-8"))["feed_id"] == "cve-bin-tool"
