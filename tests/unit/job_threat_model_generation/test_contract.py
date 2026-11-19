"""Code-level contract, configuration, dataset, topology and admissibility tests for job_threat_model_generation."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import shutil
from typing import Any

import pytest

from appsec_review.cli import main
from appsec_review.config import JobConfig, StepConfig, TaskConfig, load_config
from appsec_review.indexing.inventory import Claim, FileClaims, compile_glob, runtime_claims
from appsec_review.jobs.job_threat_model_generation import JOB_ID, build_job
from appsec_review.jobs.job_threat_model_generation.datasets import (
    ARTIFACT_DIRECTORY, CONSUMES, CONTRACT, DATASETS, PRODUCER_DATASETS, REASON, STEP,
)
from appsec_review.jobs.job_threat_model_generation.job import (
    ASSEMBLY, DOCUMENT_FILES, INTERACTIONS, LANE_INPUTS, LOAD, NAME, PUBLISH, RENDER, RESOLVE, RESULT_FILE, SCHEMA,
    STRUCTURE, THREATS, TOPOLOGY, UNREAD_INPUTS, VIEW_DIRECTORY,
)
from appsec_review.observability import EventLog
from appsec_review.orchestration.dagster.adapter import _pool_for
from appsec_review.orchestration.topology import describe_wave1
from appsec_review.retrieval import EntityKind
from appsec_review.review import evidence as admissibility
from appsec_review.runtime import JobContext, job_is_enabled
from appsec_review.runtime.contracts import Availability, DispatchClass, MissingPolicy, TargetAccess
from appsec_review.runtime.datasets import RUNTIME_SHARED_NAMESPACES, EvidenceAuthority
from appsec_review.runtime.registry import builtin_registry
from appsec_review.threat_model.contract import DFD_SCHEMA, EVIDENCE_SCHEMA, RESULT_SCHEMA, THREAT_MODEL_SCHEMA, Limits
from appsec_review.threat_model.index_view import DECLARED_INPUTS

ROOT = Path(__file__).resolve().parents[3]
CATALOG = "job_target_catalog"
SETTINGS = "[jobs.job_threat_model_generation.settings]\nenabled = false\n"


def _config(tmp_path: Path, *, enabled: bool = True, edit: Any = None):
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    assert text.count(SETTINGS) == 1
    if enabled:
        text = text.replace(SETTINGS, SETTINGS.replace("false", "true"))
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "appsec-review.toml").write_text(edit(text) if edit else text, encoding="utf-8")
    shutil.copytree(ROOT / "data" / "reference" / "threat-model", tmp_path / "data" / "reference" / "threat-model",
                    dirs_exist_ok=True)
    return load_config(tmp_path / "appsec-review.toml")


def _job_context(tmp_path: Path, job_config: JobConfig) -> JobContext:
    run_root = tmp_path / "runs" / "2026-11-15-0001"
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / "attempt_0001"
    attempt_root.mkdir(parents=True, exist_ok=True)
    return JobContext(
        run_id="2026-11-15-0001",
        attempt_id="attempt_0001",
        trigger="unit",
        repository_root=ROOT,
        run_root=run_root,
        attempt_root=attempt_root,
        metadata_root=run_root / "metadata",
        orchestration={"driver": "unit"},
        config=job_config,
        events=EventLog(attempt_root / "logs" / "events.jsonl"),
        evidence_target_snapshot="target-sha256:" + "7" * 64,
        contract=CONTRACT,
    )


def test_job_registry_topology_and_contract_invariants(tmp_path: Path) -> None:
    config = _config(tmp_path)
    registry = builtin_registry()
    registry.require_matches(config.jobs, surface="threat-model unit")
    jobs = {item["job_id"]: item for item in describe_wave1(config, registry)["jobs"]}
    order = list(jobs)
    assert order.index("job_owasp_control_assessment") < order.index(JOB_ID) < order.index("job_review_data_indexing")
    assert jobs[JOB_ID]["dependencies"] == ["job_owasp_control_assessment"]
    assert JOB_ID in jobs["job_review_data_indexing"]["dependencies"]
    assert jobs[JOB_ID]["upstream_handoffs"] == sorted({producer for producer, _ in DECLARED_INPUTS})
    assert JOB_ID in jobs["job_review_data_indexing"]["upstream_handoffs"]
    indexed_inputs = [item for item in registry.build("job_review_data_indexing").contract.inputs
                      if item.producer == JOB_ID]
    assert {(item.output_kind, item.schema) for item in indexed_inputs} == {
        ("handoff", "appsec-review/job-handoff/2"),
        *((item.output_kind, item.schema) for item in DATASETS),
    }
    assert all(item.authority is EvidenceAuthority.ROUTING_CONTEXT for item in indexed_inputs)

    configured = config.jobs[JOB_ID]
    assert configured.name == NAME == "threat_model_generation" and configured.workers == 2
    assert {step: tuple(configured.step(step).tasks) for step in configured.steps} == dict(TOPOLOGY)

    job = build_job()
    assert job.job_id == JOB_ID and job.name == NAME and job.schema_identity == SCHEMA == RESULT_SCHEMA
    assert job.strict_gaps is True and job.consumes == CONSUMES == CONTRACT.consumes
    assert [unit.unit_id for unit in job.units] == [
        LOAD, STRUCTURE, INTERACTIONS, ASSEMBLY, THREATS, RESOLVE, RENDER, PUBLISH,
    ]
    deps = {unit.unit_id: unit.dependencies for unit in job.units}
    assert deps == {
        LOAD: (),
        STRUCTURE: (LOAD,),
        INTERACTIONS: (LOAD,),
        ASSEMBLY: (STRUCTURE, INTERACTIONS),
        THREATS: (ASSEMBLY,),
        RESOLVE: (THREATS,),
        RENDER: (RESOLVE,),
        PUBLISH: (RENDER,),
    }
    assert not {"inference", "deterministic", "inspection", "provenance"} & set(TOPOLOGY)
    assert {_pool_for(unit.unit_id, JOB_ID) for unit in job.units} == {"application", "lifecycle"}
    assert set(UNREAD_INPUTS) | set(LANE_INPUTS) == set(DECLARED_INPUTS)
    assert set(UNREAD_INPUTS).isdisjoint(LANE_INPUTS)

    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.ACCEPTED_EVIDENCE
    assert CONTRACT.schedule_after == (
        "job_owasp_control_assessment", "job_dependency_intelligence", "job_security_tagging",
    )
    assert {(item.producer, item.output_kind) for item in CONTRACT.inputs if item.output_kind != "handoff"} \
        == set(DECLARED_INPUTS)
    assert set(PRODUCER_DATASETS) == {producer for producer, _ in DECLARED_INPUTS}
    envelopes = {item.producer: item for item in CONTRACT.inputs if item.output_kind == "handoff"}
    assert {producer for producer, item in envelopes.items() if item.availability is Availability.REQUIRED} == {CATALOG}
    assert envelopes[CATALOG].missing is MissingPolicy.REJECT
    assert all(item.missing is MissingPolicy.GAP and item.availability is Availability.OPTIONAL
               for item in CONTRACT.inputs if item is not envelopes[CATALOG])


def test_dataset_declarations_and_file_claim_exactness() -> None:
    assert {item.output_kind for item in DATASETS} == {
        "generated_dfd", "generated_threat_model", "generated_model_evidence", "generated_model_views",
        "threat_model_documents",
    }
    assert all(
        item.step == STEP == "publication"
        and item.disposition == "artifact_only"
        and item.family == "threat_model"
        and item.sensitivity == "internal"
        and item.authority is EvidenceAuthority.ROUTING_CONTEXT
        and item.reason == REASON
        and not item.indexes
        and item.query_route
        for item in DATASETS
    )
    schemas = {item.output_kind: item.schema for item in DATASETS}
    assert schemas == {
        "generated_dfd": DFD_SCHEMA,
        "generated_threat_model": THREAT_MODEL_SCHEMA,
        "generated_model_evidence": EVIDENCE_SCHEMA,
        "generated_model_views": "text/markdown",
        "threat_model_documents": RESULT_SCHEMA,
    }
    prefix = f"data/jobs/{JOB_ID}/attempts/attempt_0001/{ARTIFACT_DIRECTORY}"
    expected_owners = {
        f"{prefix}/{DOCUMENT_FILES['dfd']}": "generated_dfd",
        f"{prefix}/{DOCUMENT_FILES['threat_model']}": "generated_threat_model",
        f"{prefix}/{DOCUMENT_FILES['evidence']}": "generated_model_evidence",
        f"{prefix}/{RESULT_FILE}": "threat_model_documents",
        f"{prefix}/work/inputs.json": "threat_model_documents",
        f"{prefix}/{VIEW_DIRECTORY}/dfd.mmd": "generated_model_views",
        f"{prefix}/{VIEW_DIRECTORY}/threat-model.md": "generated_model_views",
    }
    for rel_path, expected_kind in expected_owners.items():
        matched = [item.output_kind for item in DATASETS
                   if any(compile_glob(pattern).fullmatch(rel_path) for pattern in item.artifacts)]
        assert matched == [expected_kind], (rel_path, matched)

    steps = sorted(TOPOLOGY)
    claims = FileClaims([
        *runtime_claims({JOB_ID: steps}, shared_namespaces=RUNTIME_SHARED_NAMESPACES),
        *(Claim(JOB_ID, item.step, item.output_kind, item) for item in DATASETS),
    ])
    assert claims


def test_default_configuration_has_the_job_disabled_and_a_disabled_job_is_not_dispatched() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    assert config.jobs[JOB_ID].settings["enabled"] is False and not job_is_enabled(config, JOB_ID)
    assert config.jobs[JOB_ID].typed_settings.limits == Limits()
    jobs = {item["job_id"]: item for item in describe_wave1(config, builtin_registry())["jobs"]}
    assert JOB_ID not in jobs
    assert JOB_ID not in jobs["job_review_data_indexing"]["dependencies"]
    assert JOB_ID not in jobs["job_review_data_indexing"]["upstream_handoffs"]
    with pytest.raises(ValueError, match=f"job is disabled by configuration: {JOB_ID}"):
        main(["--config", str(ROOT / "appsec-review.toml"), "run", JOB_ID])


REFUSED = {
    "bound-bool": lambda text: text.replace("max_threats = 4000\nmax_query_rows", "max_threats = true\nmax_query_rows"),
    "bound-missing": lambda text: text.replace("max_evidence_refs_per_element = 8\n", ""),
    "bound-over": lambda text: text.replace("max_flows = 8000\nmax_threats", "max_flows = 100001\nmax_threats"),
    "bound-zero": lambda text: text.replace("max_processes = 200\n", "max_processes = 0\n"),
    "enabled-text": lambda text: text.replace(SETTINGS.replace("false", "true"),
                                              SETTINGS.replace("false", '"yes"')),
    "model-table": lambda text: text.replace(
        "[jobs.job_threat_model_generation.steps.load]",
        "[jobs.job_threat_model_generation.settings.model]\nenabled = false\n\n"
        "[jobs.job_threat_model_generation.steps.load]"),
    "reservation-range": lambda text: text.replace("io_slots = 1\nadmission_timeout_seconds = 600",
                                                    "io_slots = 1\nadmission_timeout_seconds = 0"),
    "reservation-unknown": lambda text: text.replace("admission_timeout_seconds = 600\n",
                                                      "admission_timeout_seconds = 600\ngpu = 1\n"),
    "unknown-key": lambda text: text.replace("max_render_nodes = 120\n", "max_render_nodes = 120\nmax_assets = 5\n"),
}


@pytest.mark.parametrize("case", sorted(REFUSED))
def test_unknown_setting_or_out_of_range_bound_is_refused(tmp_path: Path, case: str) -> None:
    def edit(text: str) -> str:
        edited = REFUSED[case](text)
        assert edited != text
        return edited

    with pytest.raises(ValueError, match="job_threat_model_generation"):
        _config(tmp_path, edit=edit)


def test_validate_config_accepts_matching_topology_and_rejects_mismatched_steps_or_settings(tmp_path: Path) -> None:
    config = _config(tmp_path)
    job = build_job()
    [validator] = job.input_validators
    base = config.jobs[JOB_ID]
    validator(_job_context(tmp_path / "ok", base), None)

    reordered_steps = {step: base.steps[step] for step in reversed(list(base.steps))}
    with pytest.raises(ValueError, match="topology does not match configuration"):
        validator(_job_context(tmp_path / "reordered", replace(base, steps=reordered_steps)), None)

    wrong_tasks = dict(base.steps)
    wrong_tasks["load"] = replace(base.steps["load"],
                                  tasks={"wrong_task": TaskConfig(task_id="wrong_task", workers=1, settings={})})
    with pytest.raises(ValueError, match="topology does not match configuration"):
        validator(_job_context(tmp_path / "wrong-task", replace(base, steps=wrong_tasks)), None)

    bad_settings = {**dict(base.settings), "unknown_flag": 1}
    with pytest.raises(ValueError, match="job_threat_model_generation"):
        validator(_job_context(tmp_path / "bad-settings", replace(base, settings=bad_settings)), None)


def test_generated_entity_kinds_are_indirect_under_review_admissibility() -> None:
    kinds = {kind.value for kind in EntityKind}
    generated = (
        "generated_dfd_element", "generated_flow", "generated_threat", "generated_trust_boundary",
        "generated_entry_point", "threat", "dfd_element", "trust_boundary",
    )
    predicates = sorted(admissibility.Predicate, key=str)
    assert predicates
    for name in generated:
        assert name not in kinds
        for predicate in predicates:
            with pytest.raises(ValueError):
                admissibility.classify(name, predicate)
    assert not any("generated" in kind or "threat" in kind or "dfd" in kind for kind in kinds)
    listed = set(admissibility.DIRECT_KINDS) | set(admissibility.MAPPED_KINDS) | set(admissibility.GRAPH_KINDS)
    unlisted = sorted(set(EntityKind) - listed, key=str)
    assert unlisted
    assert all(admissibility.classify(kind, predicate) is admissibility.Admissibility.INDIRECT
               for kind in unlisted for predicate in predicates)
    assert all(not item.indexes and item.authority is EvidenceAuthority.ROUTING_CONTEXT for item in DATASETS)
