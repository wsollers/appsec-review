"""Contract, configuration, topology, and dataset tests for job_binary_evidence_indexing."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.indexing.input_matrix import INPUT_SOURCES
from appsec_review.jobs.job_binary_evidence_indexing import JOB_ID, build_job
from appsec_review.jobs.job_binary_evidence_indexing.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_binary_evidence_indexing.job import SCHEMA, TOPOLOGY, _validate
from appsec_review.orchestration.topology import describe_wave1
from appsec_review.runtime.contracts import (
    Availability,
    DispatchClass,
    EvidenceAuthority,
    MissingPolicy,
    TargetAccess,
)
from appsec_review.runtime.registry import builtin_registry


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_registry_and_central_config_parity() -> None:
    config = load_config(REPO_ROOT / "appsec-review.toml")
    registry = builtin_registry()
    job = registry.build(JOB_ID)
    assert job.job_id == JOB_ID == "job_binary_evidence_indexing"
    assert job.name == "binary_evidence_indexing"
    assert job.schema_identity == SCHEMA == "appsec-review/binary-evidence-index/1"
    assert tuple(u.unit_id for u in job.units) == (
        "load.accepted_publications",
        "index.binaries",
        "acceptance.publish_handoff",
    )
    assert job.units[1].dependencies == ("load.accepted_publications",)
    assert job.units[2].dependencies == ("load.accepted_publications", "index.binaries")

    job_cfg = config.job(JOB_ID)
    assert tuple(job_cfg.steps) == tuple(TOPOLOGY) == ("load", "index", "acceptance")
    for step, tasks in TOPOLOGY.items():
        assert tuple(job_cfg.step(step).tasks) == tasks
    _validate(SimpleNamespace(config=job_cfg), {})


def test_validate_rejects_mismatched_steps_and_tasks() -> None:
    bad_steps = SimpleNamespace(steps=("load", "acceptance"))
    with pytest.raises(ValueError, match="topology does not match central configuration"):
        _validate(SimpleNamespace(config=bad_steps), {})

    for bad_step in TOPOLOGY:
        step_map = {step: SimpleNamespace(tasks=tasks) for step, tasks in TOPOLOGY.items()}
        step_map[bad_step] = SimpleNamespace(tasks=("wrong_task",))
        cfg = SimpleNamespace(steps=tuple(TOPOLOGY), step=step_map.__getitem__)
        with pytest.raises(ValueError, match=f"task configuration mismatch: {bad_step}"):
            _validate(SimpleNamespace(config=cfg), {})


def test_contract_inputs_and_datasets_are_complete() -> None:
    job = build_job()
    assert job.contract is CONTRACT
    assert job.datasets == DATASETS
    assert CONSUMES == CONTRACT.consumes == ("job_review_intake", "job_target_catalog")
    assert CONTRACT.schedule_after == ("job_target_catalog",)
    assert CONTRACT.dispatch == DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access == TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True

    by_pair = {(req.producer, req.output_kind): req for req in CONTRACT.inputs}
    assert set(by_pair) == {
        ("job_review_intake", "handoff"),
        ("job_review_intake", "model_preflight"),
        ("job_review_intake", "binary_evidence"),
        ("job_review_intake", "review_intake"),
        ("job_target_catalog", "handoff"),
    }
    for key in (("job_review_intake", "handoff"), ("job_target_catalog", "handoff")):
        req = by_pair[key]
        assert req.authority == EvidenceAuthority.PRODUCER_EVIDENCE
        assert req.availability == Availability.REQUIRED
        assert req.missing == MissingPolicy.REJECT

    by_kind = {item.output_kind: item for item in DATASETS}
    assert set(by_kind) == {"binary_functions", "binary_pseudo_c", "binary_evidence_summary"}
    assert by_kind["binary_functions"].disposition == "indexed"
    assert by_kind["binary_functions"].indexes == ("binary",)
    assert by_kind["binary_functions"].shard_prefixes == ("binary-",)
    assert by_kind["binary_pseudo_c"].disposition == "artifact_only"
    assert by_kind["binary_evidence_summary"].disposition == "artifact_only"


def test_shared_topology_and_input_matrix_registration() -> None:
    config = load_config(REPO_ROOT / "appsec-review.toml")
    wave = describe_wave1(config, builtin_registry())
    by_id = {entry["job_id"]: entry for entry in wave["jobs"]}
    entry = by_id[JOB_ID]
    assert entry["dependencies"] == ["job_target_catalog"]
    assert set(entry["upstream_handoffs"]) == {"job_review_intake", "job_target_catalog"}
    order = [item["job_id"] for item in wave["jobs"]]
    assert order.index(JOB_ID) < order.index("job_review_data_indexing")
    assert JOB_ID in by_id["job_review_data_indexing"]["upstream_handoffs"]
    assert (
        "binary_decompilation",
        (JOB_ID,),
        "current",
        (),
        ("core", "coverage"),
    ) in INPUT_SOURCES
