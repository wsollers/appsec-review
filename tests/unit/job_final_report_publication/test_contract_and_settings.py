"""Contract, dataset, topology, and settings unit tests for job_final_report_publication."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.engineering_contracts import (
    FINAL_REPORT_HANDOFF_SCHEMA, FINAL_REPORT_SCHEMA,
)
from appsec_review.jobs.job_final_report_publication import JOB_ID, build_job
from appsec_review.jobs.job_final_report_publication.datasets import (
    CONSUMES, CONTRACT, DATASETS,
)
from appsec_review.jobs.job_final_report_publication.job import TOPOLOGY, _validate
from appsec_review.jobs.job_final_report_publication.settings import FinalReportSettings
from appsec_review.orchestration.topology import describe_wave1, wave1_dependencies
from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, MissingPolicy, TargetAccess,
)
from appsec_review.runtime.registry import builtin_registry

ROOT = Path(__file__).resolve().parents[3]


def test_settings_parse_bounds_identity_and_reject_invalid_mappings() -> None:
    lower = FinalReportSettings.from_mapping(
        {"enabled": True, "markdown_evidence_ids": 0, "markdown_gap_ids": 0}
    )
    assert lower == FinalReportSettings(True, 0, 0)
    assert lower.identity() == {"markdown_evidence_ids": 0, "markdown_gap_ids": 0}

    upper = FinalReportSettings.from_mapping(
        {"enabled": False, "markdown_evidence_ids": 256, "markdown_gap_ids": 256}
    )
    assert upper == FinalReportSettings(False, 256, 256)
    assert upper.identity() == {"markdown_evidence_ids": 256, "markdown_gap_ids": 256}

    for bad in (
        None,
        "not-a-mapping",
        {"enabled": True, "markdown_evidence_ids": 8},
        {"enabled": True, "markdown_evidence_ids": 8, "markdown_gap_ids": 16, "extra": 1},
    ):
        with pytest.raises(ValueError, match="documented keys"):
            FinalReportSettings.from_mapping(bad)  # type: ignore[arg-type]

    for bad_enabled in (1, 0, "true", None):
        with pytest.raises(ValueError, match="enabled must be a boolean"):
            FinalReportSettings.from_mapping(
                {"enabled": bad_enabled, "markdown_evidence_ids": 8, "markdown_gap_ids": 16}
            )

    for key in ("markdown_evidence_ids", "markdown_gap_ids"):
        for bad_bound in (True, False, -1, 257, "8", 1.5, None):
            payload = {"enabled": True, "markdown_evidence_ids": 8, "markdown_gap_ids": 16, key: bad_bound}
            with pytest.raises(ValueError, match=f"{key} must be an integer in \\[0, 256\\]"):
                FinalReportSettings.from_mapping(payload)


def test_contract_datasets_registry_topology_and_input_validator_parity() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    job_cfg = config.job(JOB_ID)
    registry = builtin_registry()
    job = registry.build(JOB_ID)

    assert job.job_id == JOB_ID == "job_final_report_publication"
    assert job.name == "final_report_publication"
    assert job.schema_identity == FINAL_REPORT_HANDOFF_SCHEMA
    assert job.contract == CONTRACT
    assert job.datasets == DATASETS
    assert job.consumes == CONSUMES == ("job_final_publication_gate",)
    assert CONTRACT.schedule_after == ("job_final_publication_gate",)
    assert CONTRACT.dispatch == DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access == TargetAccess.ACCEPTED_EVIDENCE
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True

    assert len(CONTRACT.inputs) == 2
    handoff_req, gate_req = CONTRACT.inputs
    assert (
        handoff_req.producer,
        handoff_req.output_kind,
        handoff_req.schema,
        handoff_req.channel,
        handoff_req.authority,
        handoff_req.availability,
        handoff_req.missing,
    ) == (
        "job_final_publication_gate",
        "handoff",
        "appsec-review/job-handoff/2",
        InputChannel.HANDOFF,
        EvidenceAuthority.PRODUCER_EVIDENCE,
        Availability.REQUIRED,
        MissingPolicy.REJECT,
    )
    assert (
        gate_req.producer,
        gate_req.output_kind,
        gate_req.schema,
        gate_req.authority,
    ) == (
        "job_final_publication_gate",
        "publication_gate_decisions",
        "appsec-review/final-publication-gate/2",
        EvidenceAuthority.PRODUCER_EVIDENCE,
    )

    assert len(DATASETS) == 1
    dataset = DATASETS[0]
    assert dataset.output_kind == "final_report_publications"
    assert dataset.step == "acceptance"
    assert dataset.family == "inference_review"
    assert dataset.schema == FINAL_REPORT_SCHEMA
    assert dataset.disposition == "artifact_only"
    assert dataset.artifacts == (
        "data/jobs/job_final_report_publication/attempts/*/steps/load/**",
        "data/jobs/job_final_report_publication/attempts/*/steps/report/**",
        "data/jobs/job_final_report_publication/attempts/*/steps/acceptance/**",
    )

    assert tuple(u.unit_id for u in job.units) == (
        "load.accepted_gate",
        "report.assemble",
        "report.render",
        "acceptance.publish_handoff",
    )
    assert {u.unit_id: u.dependencies for u in job.units} == {
        "load.accepted_gate": (),
        "report.assemble": ("load.accepted_gate",),
        "report.render": ("report.assemble",),
        "acceptance.publish_handoff": ("load.accepted_gate", "report.assemble", "report.render"),
    }

    wave = {item["job_id"]: item for item in describe_wave1(config, registry)["jobs"]}
    assert wave[JOB_ID]["dependencies"] == ["job_final_publication_gate"]
    depended = {dep for item in wave.values() for dep in item["dependencies"]}
    assert JOB_ID not in depended

    without_self = set(registry.job_ids()) - {"job_third_party_data_sync", JOB_ID}
    assert JOB_ID not in (wave1_dependencies(without_self) or {})

    job.input_validators[0](SimpleNamespace(config=job_cfg), None)
    _validate(SimpleNamespace(config=job_cfg), None)

    wrong_steps = SimpleNamespace(
        config=SimpleNamespace(steps={"load": None, "report": None}, step=job_cfg.step, settings=job_cfg.settings)
    )
    with pytest.raises(ValueError, match="final report topology does not match configuration"):
        _validate(wrong_steps, None)

    for bad_step in ("load", "report", "acceptance"):
        def broken_step(name: str, target: str = bad_step):
            if name == target:
                return SimpleNamespace(tasks=("unexpected_task",))
            return job_cfg.step(name)

        wrong_tasks = SimpleNamespace(
            config=SimpleNamespace(steps=TOPOLOGY, step=broken_step, settings=job_cfg.settings)
        )
        with pytest.raises(ValueError, match=f"final report task configuration mismatch: {bad_step}"):
            _validate(wrong_tasks, None)

    wrong_settings = SimpleNamespace(
        config=SimpleNamespace(
            steps=TOPOLOGY,
            step=job_cfg.step,
            settings={"enabled": True, "markdown_evidence_ids": -1, "markdown_gap_ids": 16},
        )
    )
    with pytest.raises(ValueError, match="markdown_evidence_ids"):
        _validate(wrong_settings, None)

    direct = build_job(repository_root=ROOT)
    assert direct.job_id == JOB_ID
