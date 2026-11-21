"""Consumption is derived from typed contracts; scheduling never grants evidence permission."""
from __future__ import annotations

import pytest

from appsec_review.orchestration.topology import upstream_closure, wave1_dependencies
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.contracts import DispatchClass


def _graph():
    registry = builtin_registry()
    ids = set(registry.job_ids())
    dependencies = wave1_dependencies(ids)
    assert dependencies is not None
    return registry, ids, dependencies


@pytest.mark.parametrize("job_id", sorted(builtin_registry().job_ids()))
def test_consumes_are_registered_producers(job_id: str) -> None:
    registry, ids, _ = _graph()
    job = registry.build(job_id)
    assert job.contract is not None and job.consumes == job.contract.consumes
    unknown = sorted(set(job.consumes) - ids)
    assert not unknown, f"{job_id} consumes unregistered jobs: {unknown}"


@pytest.mark.parametrize("job_id", sorted(builtin_registry().job_ids()))
def test_consumes_are_scheduled_before_the_consumer(job_id: str) -> None:
    registry, _, dependencies = _graph()
    job = registry.build(job_id)
    if job_id not in dependencies:
        assert job.contract.dispatch is not DispatchClass.REVIEW_GRAPH
        return
    assert job.contract.dispatch is DispatchClass.REVIEW_GRAPH
    closure = set(upstream_closure(job_id, dependencies, set(dependencies)))
    unscheduled = sorted(set(job.consumes) - closure)
    assert not unscheduled, (
        f"{job_id} declares CONSUMES that the topology does not schedule before it: {unscheduled}")


def test_owasp_upstream_allowlist_names_only_registered_jobs() -> None:
    from appsec_review.owasp_workbench.evidence import UPSTREAM_JOBS
    registry, ids, _ = _graph()
    assert set(UPSTREAM_JOBS) <= ids
    assert "job_target_documents" not in UPSTREAM_JOBS


def test_security_tagging_declares_the_manifest_publishers_it_follows() -> None:
    registry, _, dependencies = _graph()
    job = registry.build("job_security_tagging")
    assert job.consumes == job.contract.consumes
    assert {"job_review_prioritization", "job_code_graph_index", "job_codeql_analysis"} <= set(job.consumes)
    assert set(job.consumes) <= set(upstream_closure(job.job_id, dependencies, set(dependencies)))


def test_owasp_declares_exact_selected_owners_and_source_custody() -> None:
    from appsec_review.jobs.job_owasp_control_assessment.datasets import CONTRACT, SOURCE_SELECTION
    from appsec_review.runtime.contracts import InputChannel
    registry, _, _ = _graph()
    actual = {(item.producer, item.output_kind, item.schema, item.authority)
              for item in CONTRACT.inputs if item.channel is InputChannel.HANDOFF and item.output_kind != "handoff"}
    expected = {(producer, item.output_kind, item.schema, item.authority)
                for producer in CONTRACT.consumes for item in registry.build(producer).datasets
                if any((producer, name) in SOURCE_SELECTION.producer_indexes for name in item.indexes)
                or (producer, item.output_kind) in SOURCE_SELECTION.custody_outputs}
    assert actual == expected


def test_owasp_receipts_only_the_selected_shards_it_opens(tmp_path) -> None:
    from appsec_review.jobs.job_owasp_control_assessment.datasets import CONTRACT, SOURCE_SELECTION
    from appsec_review.runtime.inputs import input_read_scope
    from tests.unit.retrieval.test_selected_manifest import CATALOG, fixture, read
    value = fixture(tmp_path)
    value.context.contract = CONTRACT
    value.context.upstream_handoffs = {CATALOG: value.context.upstream_handoffs[CATALOG]}
    with input_read_scope(value.context) as receipts:
        core = read(value, SOURCE_SELECTION)
        assert core.find(identity=value.source)["results"]
    assert {(item["producer"], item["output_kind"]) for item in receipts.document()["reads"]} == {
        (CATALOG, "source_files")}
    assert all(item["read"] and item["cited"] is None for item in receipts.document()["reads"])


def test_owasp_evidence_import_does_not_depend_on_registry_preload() -> None:
    from pathlib import Path
    import subprocess
    import sys
    result = subprocess.run([
        sys.executable, "-c",
        "from appsec_review.owasp_workbench.evidence import EvidenceResolver, UPSTREAM_JOBS; "
        "from appsec_review.jobs.job_owasp_control_assessment import build_job; "
        "assert UPSTREAM_JOBS == build_job().contract.consumes",
    ], cwd=Path(__file__).resolve().parents[1], text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr


def test_every_input_requirement_matches_its_producer_declaration() -> None:
    """A consumer that names an output kind must name the schema and authority its producer declares today.
    Regression for smoke-cpp run 2026-11-14-0004: owasp_control_assessment__begin failed with
    "producer output contract mismatch: job_debug_symbol_indexing/target_decision" after the producer moved
    its decision schema to /2 while the consumer still required /1; admit_inputs refuses such a claim."""
    from appsec_review.runtime.contracts import Availability, InputChannel
    registry = builtin_registry()
    jobs = {job_id: registry.build(job_id) for job_id in sorted(registry.job_ids())}
    declarations = {job_id: {item.output_kind: item for item in job.datasets} for job_id, job in jobs.items()}
    mismatches = []
    for job_id in sorted(jobs):
        contract = jobs[job_id].contract
        if contract is None:
            continue
        for requirement in contract.inputs:
            if requirement.channel is not InputChannel.HANDOFF or requirement.output_kind == "handoff":
                continue
            declaration = declarations.get(requirement.producer, {}).get(requirement.output_kind)
            if declaration is None:
                if requirement.availability is not Availability.WHEN_DECLARED:
                    mismatches.append(f"{job_id}: {requirement.producer}/{requirement.output_kind} is not declared")
                continue
            if declaration.schema != requirement.schema:
                mismatches.append(f"{job_id}: {requirement.producer}/{requirement.output_kind} requires "
                                  f"{requirement.schema}, producer declares {declaration.schema}")
            elif declaration.authority is not None and declaration.authority != requirement.authority:
                mismatches.append(f"{job_id}: {requirement.producer}/{requirement.output_kind} authority "
                                  f"{requirement.authority.value} vs declared {declaration.authority.value}")
    assert mismatches == []
