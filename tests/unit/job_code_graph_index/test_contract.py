from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.config.first_party import job_dispositions
from appsec_review.graph.catalog import CATALOG_PATH, load_catalog
from appsec_review.graph.settings import RunConfigurationError
from appsec_review.jobs.job_code_graph_index import JOB_ID, build_job
from appsec_review.jobs.job_code_graph_index.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_code_graph_index.job import (
    TOPOLOGY,
    _status,
    _validate,
    graph_settings,
    verify_catalog_pin,
)
from appsec_review.review.models import IntegrityError

ROOT = Path(__file__).resolve().parents[3]


def test_build_job_contract_units_and_dataset_dispositions() -> None:
    job = build_job()
    assert job.job_id == JOB_ID == "job_code_graph_index"
    assert job.strict_gaps is False or isinstance(job.strict_gaps, bool)
    assert job.contract is CONTRACT
    assert job.consumes == CONSUMES
    assert [unit.unit_id for unit in job.units] == [f"{step}.{task}" for step, task in TOPOLOGY]
    assert {decl.output_kind: decl.disposition for decl in DATASETS} == {
        "code_graph_facts": "indexed",
        "code_graph_stages": "artifact_only",
        "code_graph_checkpoints": "artifact_only",
        "code_graph_summary": "artifact_only",
        "code_graph_scorecard": "artifact_only",
    }
    assert _status([], empty=True) == "NOT_APPLICABLE"
    assert _status(["g1"], empty=False) == "COMPLETED_WITH_GAPS"
    assert _status([], empty=False) == "SUCCEEDED"

    unit_stub = SimpleNamespace(
        job=SimpleNamespace(config=SimpleNamespace(settings={"graph": {"max_call_depth": 4}}))
    )
    assert graph_settings(unit_stub).max_call_depth == 4
    assert job_dispositions({}).record()


def test_input_validator_accepts_configured_job_and_rejects_bad_step_task_or_setting() -> None:
    cfg = load_config(ROOT / "appsec-review.toml").job(JOB_ID)
    _validate(SimpleNamespace(config=cfg), None)

    missing_step = SimpleNamespace(
        steps=tuple(s for s in cfg.steps if s != "crosscheck"),
        step=cfg.step,
        settings=cfg.settings,
    )
    with pytest.raises(ValueError, match="topology does not match"):
        _validate(SimpleNamespace(config=missing_step), None)

    bad_tasks = SimpleNamespace(
        steps=cfg.steps,
        step=lambda name: SimpleNamespace(tasks=("wrong_task",)) if name == "load" else cfg.step(name),
        settings=cfg.settings,
    )
    with pytest.raises(ValueError, match="task configuration mismatch: load"):
        _validate(SimpleNamespace(config=bad_tasks), None)

    bad_settings = replace(cfg, settings=MappingProxyType({**cfg.settings, "unexpected_knob": 1}))
    with pytest.raises(ValueError, match="unknown settings: unexpected_knob"):
        _validate(SimpleNamespace(config=bad_settings), None)


def test_verify_catalog_pin_handles_no_succeeded_missing_invalid_or_mismatched_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog = load_catalog(CATALOG_PATH, release_id="cat-rel-1")

    # No succeeded scopes -> returns early without checking run configuration.
    verify_catalog_pin(tmp_path, catalog, [{"language": "cpp", "export_status": "FAILED"}])

    # RunConfigurationError -> raises IntegrityError.
    monkeypatch.setattr(
        "appsec_review.jobs.job_code_graph_index.job.run_configuration",
        lambda _root: (_ for _ in ()).throw(RunConfigurationError("corrupt config")),
    )
    with pytest.raises(IntegrityError, match="corrupt config"):
        verify_catalog_pin(tmp_path, catalog, [{"language": "cpp", "export_status": "SUCCEEDED"}])

    # None configuration -> raises IntegrityError.
    monkeypatch.setattr(
        "appsec_review.jobs.job_code_graph_index.job.run_configuration",
        lambda _root: None,
    )
    with pytest.raises(IntegrityError, match="no bound configuration"):
        verify_catalog_pin(tmp_path, catalog, [{"language": "cpp", "export_status": "SUCCEEDED"}])

    # Mismatched frozen graph_catalog release -> raises IntegrityError.
    monkeypatch.setattr(
        "appsec_review.jobs.job_code_graph_index.job.run_configuration",
        lambda _root: {"review_policy": {"releases": {"graph_catalog": "other-rel"}}},
    )
    with pytest.raises(IntegrityError, match="differs from the frozen operator declaration"):
        verify_catalog_pin(tmp_path, catalog, [{"language": "cpp", "export_status": "SUCCEEDED"}])

    # Matching frozen graph_catalog release -> passes cleanly.
    monkeypatch.setattr(
        "appsec_review.jobs.job_code_graph_index.job.run_configuration",
        lambda _root: {"review_policy": {"releases": {"graph_catalog": "cat-rel-1"}}},
    )
    verify_catalog_pin(tmp_path, catalog, [{"language": "cpp", "export_status": "SUCCEEDED"}])
    assert catalog.version
    assert json.loads(CATALOG_PATH.read_text(encoding="utf-8"))["schema"]
