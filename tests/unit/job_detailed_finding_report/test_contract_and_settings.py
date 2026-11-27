"""Contract, dataset, schema, operational, topology, and settings unit tests for job_detailed_finding_report."""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.config.operational import OPERATIONAL_SETTINGS
from appsec_review.indexing import input_matrix
from appsec_review.indexing.input_matrix import job_contract_matrix
from appsec_review.jobs.engineering_contracts import (
    DETAILED_FINDING_REPORT_HANDOFF_SCHEMA,
    DETAILED_FINDING_REPORT_SCHEMA,
    FINAL_PUBLICATION_GATE_SCHEMA,
)
from appsec_review.jobs.job_detailed_finding_report import JOB_ID, build_job
from appsec_review.jobs.job_detailed_finding_report.contracts import (
    DETAILED_FINDING_REPORT_SCHEMA_SHA256,
    GATE_SCHEMA_SHA256,
)
from appsec_review.jobs.job_detailed_finding_report.datasets import (
    CONSUMES,
    CONTRACT,
    DATASETS,
)
from appsec_review.jobs.job_detailed_finding_report.job import TOPOLOGY, _validate
from appsec_review.jobs.job_detailed_finding_report.settings import (
    DEFAULT_IMAGE_ID,
    DEFAULT_IMAGE_TAG,
    DetailedFindingReportSettings,
)
from appsec_review.observability.completion import LANES
from appsec_review.orchestration.topology import describe_wave1, wave1_dependencies
from appsec_review.runtime.contracts import (
    Availability,
    DispatchClass,
    EvidenceAuthority,
    InputChannel,
    MissingPolicy,
    TargetAccess,
)
from appsec_review.runtime.registry import builtin_registry

ROOT = Path(__file__).resolve().parents[3]
IMAGE_TAG = DEFAULT_IMAGE_TAG
IMAGE_ID = "sha256:" + "ab" * 32


def test_schema_files_exist_and_match_pinned_digests() -> None:
    schema_dir = ROOT / "docs" / "schemas" / "detailed-finding-report" / "v1"
    for filename, expected_sha in DETAILED_FINDING_REPORT_SCHEMA_SHA256.items():
        path = schema_dir / filename
        assert path.is_file(), f"missing schema {filename}"
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha

    gate_dir = ROOT / "docs" / "schemas" / "final-report"
    for filename, expected_sha in GATE_SCHEMA_SHA256.items():
        path = gate_dir / filename
        assert path.is_file(), f"missing gate/receipt schema {filename}"
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha


def test_settings_defaults_bounds_identity_and_invalid_inputs() -> None:
    defaults = DetailedFindingReportSettings.defaults()
    assert defaults.enabled is True
    assert defaults.include_backlog is False
    assert defaults.max_fanout_nodes == 12
    assert defaults.max_cfg_nodes == 14
    assert defaults.render_pdf is False
    assert defaults.image_tag == IMAGE_TAG
    assert defaults.image_id == DEFAULT_IMAGE_ID

    base = defaults.as_dict()
    parsed_base = DetailedFindingReportSettings.from_mapping(base)
    assert parsed_base == defaults

    lower = DetailedFindingReportSettings.from_mapping(
        {
            "enabled": True,
            "include_backlog": True,
            "max_fanout_nodes": 3,
            "max_cfg_nodes": 3,
            "render_pdf": True,
            "image_tag": IMAGE_TAG,
            "image_id": IMAGE_ID,
            "render_timeout_seconds": 1,
            "max_pdf_bytes": 1,
        }
    )
    assert lower.identity() == {
        "include_backlog": True,
        "max_fanout_nodes": 3,
        "max_cfg_nodes": 3,
    }
    assert lower.pdf_identity()["image_id"] == IMAGE_ID
    assert lower.settings_sha256() != defaults.settings_sha256()

    upper = DetailedFindingReportSettings.from_mapping(
        {
            "enabled": False,
            "include_backlog": False,
            "max_fanout_nodes": 64,
            "max_cfg_nodes": 64,
            "render_pdf": False,
            "image_tag": IMAGE_TAG,
            "image_id": IMAGE_ID,
            "render_timeout_seconds": 600,
            "max_pdf_bytes": 67108864,
        }
    )
    assert upper.enabled is False
    assert upper.render_pdf is False

    for bad_mapping in (None, "bad", ["list"], {}, {**base, "unknown_setting": 1}):
        with pytest.raises(ValueError, match="documented keys"):
            DetailedFindingReportSettings.from_mapping(bad_mapping)  # type: ignore[arg-type]

    for bool_key in ("enabled", "include_backlog", "render_pdf"):
        for bad_bool in (1, 0, "true", None):
            with pytest.raises(ValueError, match=f"{bool_key} must be a boolean"):
                DetailedFindingReportSettings.from_mapping({**base, bool_key: bad_bool})

    for node_key in ("max_fanout_nodes", "max_cfg_nodes"):
        for bad_val in (True, False, 2, 65, "12", None):
            with pytest.raises(ValueError, match=f"{node_key} must be an integer in \\[3, 64\\]"):
                DetailedFindingReportSettings.from_mapping({**base, node_key: bad_val})

    for bad_timeout in (0, 601, True, "600", None):
        with pytest.raises(ValueError, match="render_timeout_seconds must be an integer in"):
            DetailedFindingReportSettings.from_mapping({**base, "render_timeout_seconds": bad_timeout})

    for bad_bytes in (0, 67108865, False, 1.5, None):
        with pytest.raises(ValueError, match="max_pdf_bytes must be an integer in"):
            DetailedFindingReportSettings.from_mapping({**base, "max_pdf_bytes": bad_bytes})

    for bad_tag in ("", " tag", "-tag", None, 42):
        with pytest.raises(ValueError, match="image_tag must be a nonempty image tag"):
            DetailedFindingReportSettings.from_mapping({**base, "image_tag": bad_tag})

    for bad_id in ("latest", "sha256:abc", "ab" * 32, None):
        with pytest.raises(ValueError, match="image_id must be an immutable sha256 image identity"):
            DetailedFindingReportSettings.from_mapping({**base, "image_id": bad_id})


def test_contract_datasets_registry_operational_and_topology_parity() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    registry = builtin_registry()
    registry.require_matches(config.jobs.keys(), surface="appsec-review.toml")
    job = registry.build(JOB_ID)
    job_cfg = config.job(JOB_ID)

    assert job.job_id == JOB_ID == "job_detailed_finding_report"
    assert job.name == job_cfg.name == "detailed_finding_report"
    assert job.schema_identity == DETAILED_FINDING_REPORT_HANDOFF_SCHEMA
    assert job.strict_gaps is True
    assert job.contract == CONTRACT
    assert job.datasets == DATASETS
    assert job.consumes == CONSUMES == ("job_code_graph_index", "job_final_publication_gate")
    assert CONTRACT.schedule_after == ("job_final_report_publication",)
    assert CONTRACT.dispatch == DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access == TargetAccess.ACCEPTED_EVIDENCE
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True

    assert len(DATASETS) == 1
    ds = DATASETS[0]
    assert ds.output_kind == "detailed_finding_reports"
    assert ds.schema == DETAILED_FINDING_REPORT_SCHEMA
    assert ds.disposition == "artifact_only"

    by_key = {(req.producer, req.output_kind): req for req in CONTRACT.inputs}
    assert set(by_key) == {
        ("job_final_publication_gate", "handoff"),
        ("job_final_publication_gate", "publication_gate_decisions"),
        ("job_code_graph_index", "handoff"),
        ("job_code_graph_index", "alternate_cpg"),
    }
    gate_h = by_key[("job_final_publication_gate", "handoff")]
    assert (gate_h.availability, gate_h.missing, gate_h.channel) == (
        Availability.REQUIRED,
        MissingPolicy.REJECT,
        InputChannel.HANDOFF,
    )
    gate_d = by_key[("job_final_publication_gate", "publication_gate_decisions")]
    assert gate_d.schema == FINAL_PUBLICATION_GATE_SCHEMA
    assert gate_d.authority == EvidenceAuthority.PRODUCER_EVIDENCE

    cg_h = by_key[("job_code_graph_index", "handoff")]
    assert (cg_h.availability, cg_h.missing) == (Availability.OPTIONAL, MissingPolicy.GAP)
    cg_d = by_key[("job_code_graph_index", "alternate_cpg")]
    assert cg_d.schema == "appsec-review/alternate-cpg/1"
    assert cg_d.authority == EvidenceAuthority.PRODUCER_EVIDENCE

    # Verify input_matrix and job_contract_matrix accept our contract and output declarations.
    matrix_sources = {row[0]: row for row in input_matrix.INPUT_SOURCES}
    assert matrix_sources["detailed_finding_reports"] == (
        "detailed_finding_reports",
        ("job_detailed_finding_report",),
        "artifact_only",
        (),
        ("coverage",),
    )
    contract_rows = {row["job_id"]: row for row in job_contract_matrix(config, registry)}
    assert JOB_ID in contract_rows
    assert LANES[JOB_ID] == "detailed_finding_report"

    # Verify operational settings registration.
    op_paths = {
        item.path
        for item in OPERATIONAL_SETTINGS
        if item.job_id == JOB_ID
    }
    assert op_paths == {
        ("settings", "max_cfg_nodes"),
        ("settings", "max_fanout_nodes"),
        ("settings", "max_pdf_bytes"),
        ("settings", "render_timeout_seconds"),
    }

    # Verify topology places job_detailed_finding_report after job_final_report_publication.
    deps = wave1_dependencies(frozenset(registry.job_ids()))
    assert deps is not None
    order = list(deps)
    assert order.index("job_final_report_publication") < order.index(JOB_ID)
    described = describe_wave1(config, registry)
    by_id = {item["job_id"]: item for item in described["jobs"]}
    assert "job_final_report_publication" in by_id[JOB_ID]["dependencies"]
    assert "job_final_publication_gate" in by_id[JOB_ID]["upstream_handoffs"]


def test_input_validator_enforces_step_topology_and_enabled_flag() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    job_cfg = config.job(JOB_ID)
    _validate(SimpleNamespace(config=job_cfg), None)

    # Synthetic empty settings mapping (used by target-independent launch harnesses) is accepted.
    synthetic_cfg = SimpleNamespace(
        steps=job_cfg.steps,
        step=job_cfg.step,
        settings={},
    )
    _validate(SimpleNamespace(config=synthetic_cfg), None)

    disabled_cfg = SimpleNamespace(
        steps=job_cfg.steps,
        step=job_cfg.step,
        settings={**dict(job_cfg.settings), "enabled": False},
    )
    with pytest.raises(ValueError, match="disabled in configuration"):
        _validate(SimpleNamespace(config=disabled_cfg), None)

    bad_steps_cfg = SimpleNamespace(
        steps={"load": job_cfg.step("load")},
        step=job_cfg.step,
        settings=dict(job_cfg.settings),
    )
    with pytest.raises(ValueError, match="topology does not match"):
        _validate(SimpleNamespace(config=bad_steps_cfg), None)

    assert tuple(TOPOLOGY) == ("load", "report", "acceptance")
