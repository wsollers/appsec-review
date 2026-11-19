"""Pure contract, configuration, and admissibility helpers for job_threat_model_generation.

Whole-job JobRunner integration cases live in
``tests/integration/job_threat_model_generation/test_threat_model_jobrunner.py``; direct
unit-level contract and handler suites live under ``tests/unit/job_threat_model_generation/``.
"""
from __future__ import annotations

from pathlib import Path
import shutil
from typing import Any

import pytest

from appsec_review.cli import main
from appsec_review.config import load_config
from appsec_review.jobs.job_threat_model_generation.datasets import DATASETS
from appsec_review.jobs.job_threat_model_generation.job import TOPOLOGY
from appsec_review.orchestration.topology import describe_wave1
from appsec_review.retrieval import EntityKind
from appsec_review.review import evidence as admissibility
from appsec_review.runtime import job_is_enabled
from appsec_review.runtime.contracts import Availability, MissingPolicy, TargetAccess
from appsec_review.runtime.datasets import EvidenceAuthority
from appsec_review.runtime.registry import builtin_registry
from appsec_review.threat_model.contract import JOB_ID, Limits
from appsec_review.threat_model.index_view import DECLARED_INPUTS

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "threat_model" / "client_server_c"
CATALOG = "job_target_catalog"
SETTINGS = "[jobs.job_threat_model_generation.settings]\nenabled = false\n"


def _config(tmp_path: Path, *, enabled: bool = True, edit: Any = None, profile: str | None = None):
    """The real configuration under ``tmp_path``; the job is enabled only in this copy."""
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    assert text.count(SETTINGS) == 1, "the committed configuration keeps the job disabled"
    if enabled:
        text = text.replace(SETTINGS, SETTINGS.replace("false", "true"))
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "appsec-review.toml").write_text(edit(text) if edit else text, encoding="utf-8")
    shutil.copytree(ROOT / "data" / "reference" / "threat-model", tmp_path / "data" / "reference" / "threat-model")
    if profile is None:
        return load_config(tmp_path / "appsec-review.toml")
    (tmp_path / "profiles").mkdir()
    return load_config(tmp_path / "appsec-review.toml", profile=profile)


def test_job_is_registered_configured_and_in_the_graph_after_owasp_and_before_indexing(tmp_path: Path) -> None:
    from appsec_review.orchestration.dagster.adapter import _pool_for

    config = _config(tmp_path)
    registry = builtin_registry()
    registry.require_matches(config.jobs, surface="threat-model test")
    jobs = {item["job_id"]: item for item in describe_wave1(config, registry)["jobs"]}
    order = list(jobs)
    assert order.index("job_owasp_control_assessment") < order.index(JOB_ID) < order.index("job_review_data_indexing")
    assert jobs[JOB_ID]["dependencies"] == ["job_owasp_control_assessment"]
    assert JOB_ID in jobs["job_review_data_indexing"]["dependencies"]
    assert jobs[JOB_ID]["upstream_handoffs"] == sorted({producer for producer, _ in DECLARED_INPUTS})
    assert JOB_ID in jobs["job_review_data_indexing"]["upstream_handoffs"]

    configured = config.jobs[JOB_ID]
    assert configured.name == "threat_model_generation" and configured.workers == 2
    assert {step: tuple(configured.step(step).tasks) for step in configured.steps} == dict(TOPOLOGY)
    job = registry.build(JOB_ID)
    assert [unit.unit_id for unit in job.units] == [f"{step}.{task}" for step, tasks in TOPOLOGY.items() for task in tasks]
    assert job.strict_gaps is True and job.name == configured.name
    assert not {"inference", "deterministic", "inspection", "provenance"} & set(TOPOLOGY)
    assert {_pool_for(unit.unit_id, JOB_ID) for unit in job.units} == {"application", "lifecycle"}

    contract = job.contract
    assert contract.target_access is TargetAccess.ACCEPTED_EVIDENCE
    assert contract.schedule_after == ("job_owasp_control_assessment", "job_dependency_intelligence",
                                       "job_security_tagging")
    assert {(item.producer, item.output_kind) for item in contract.inputs if item.output_kind != "handoff"} \
        == set(DECLARED_INPUTS)
    envelopes = {item.producer: item for item in contract.inputs if item.output_kind == "handoff"}
    assert {producer for producer, item in envelopes.items() if item.availability is Availability.REQUIRED} == {CATALOG}
    assert envelopes[CATALOG].missing is MissingPolicy.REJECT
    assert all(item.missing is MissingPolicy.GAP and item.availability is Availability.OPTIONAL
               for item in contract.inputs if item is not envelopes[CATALOG])


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


def test_generated_entity_kinds_are_indirect_under_review_admissibility() -> None:
    kinds = {kind.value for kind in EntityKind}
    generated = ("generated_dfd_element", "generated_flow", "generated_threat", "generated_trust_boundary",
                 "generated_entry_point", "threat", "dfd_element", "trust_boundary")
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
