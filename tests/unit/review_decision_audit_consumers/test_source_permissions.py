from dataclasses import replace
from importlib import import_module
import subprocess
import sys
from types import SimpleNamespace

import pytest

from appsec_review.jobs.bound_artifacts import artifact_ref, source_context_inputs
from appsec_review.jobs.decision_audit_inputs import ORIGINAL_AUDIT_SOURCES, original_audit_source_inputs
from appsec_review.review.decision_audit.reader import REVIEW_JOB
from appsec_review.runtime.contracts import EvidenceAuthority, InputRequirement, JobContract, MissingPolicy
from appsec_review.runtime.inputs import admit_inputs, input_read_scope, observe_output, selected_handoffs
from appsec_review.storage import atomic_bytes

from .source_permission_fixture import DOSSIER, GATE, HISTORY, POST_BUILD, SCANNER, SourceRun


def job(consumer):
    contract = import_module(f"appsec_review.jobs.{consumer}.datasets").CONTRACT
    return SimpleNamespace(job_id=consumer, contract=contract, consumes=contract.consumes)


def context(run, consumer, pins, *, contract=None):
    return SimpleNamespace(run_root=run.root, evidence_target_snapshot=run.target,
                           config=SimpleNamespace(job_id=consumer),
                           contract=contract or job(consumer).contract, upstream_handoffs=dict(pins))


@pytest.mark.parametrize("consumer", [GATE, DOSSIER], ids=["gate", "dossier"])
@pytest.mark.parametrize("specification", [SCANNER, POST_BUILD], ids=["scanner", "post-build"])
def test_original_audit_shard_reads_use_declared_admitted_lineage_and_real_receipts(tmp_path, consumer, specification):
    run = SourceRun(tmp_path)
    original = run.source(specification)
    review = run.review((original,))
    pins = selected_handoffs(job(consumer), run.root, {REVIEW_JOB: review.sha256})
    assert pins == {REVIEW_JOB: review.sha256, specification[0]: original.accepted.sha256}
    admitted = context(run, consumer, pins)
    admission = admit_inputs(admitted, set(pins))
    requirement = next(row for row in admission["requirements"] if (
        row["producer"], row["output_kind"]) == specification[:2])
    assert requirement["supplied"] is True and requirement["read"] is False
    with input_read_scope(admitted) as reads:
        payload, receipt = run.read_original(original)
        observed = reads.document()
    assert payload == (run.root / original.shard.relative_path).read_bytes()
    assert receipt.reference() == {"path": original.shard.relative_path, "sha256": original.shard.sha256}
    row = next(row for row in observed["reads"] if (
        row["producer"], row["output_kind"]) == specification[:2])
    assert row["handoff_sha256"] == original.accepted.sha256
    assert row["path"] == original.shard.relative_path and row["sha256"] == original.shard.sha256
    assert row["authority"] == "producer_evidence" and row["read"] is True and row["cited"] is None
    assert observed["citation_observation"] == "not_observed"
    assert original.shard.relative_path not in {row["path"] for row in review.handoff["artifacts"]}


@pytest.mark.parametrize("consumer", [GATE, DOSSIER], ids=["gate", "dossier"])
def test_review_lineage_uses_its_original_source_pin_not_the_new_available_attempt(tmp_path, consumer):
    run = SourceRun(tmp_path)
    original = run.source(SCANNER)
    review = run.review((original,))
    newer = run.source(SCANNER, attempt="attempt_0002")
    assert newer.accepted.sha256 != original.accepted.sha256
    pins = selected_handoffs(job(consumer), run.root, {REVIEW_JOB: review.sha256})
    assert pins[SCANNER[0]] == original.accepted.sha256
    admitted = context(run, consumer, pins)
    admit_inputs(admitted, set(pins))
    with input_read_scope(admitted) as reads:
        run.read_original(original)
        rows = reads.document()["reads"]
    assert next(row for row in rows if row["output_kind"] == SCANNER[1])["attempt_id"] == "attempt_0001"


@pytest.mark.parametrize("consumer", [GATE, DOSSIER], ids=["gate", "dossier"])
def test_available_source_without_review_supply_does_not_authorize_a_read(tmp_path, consumer):
    run = SourceRun(tmp_path)
    original = run.source(SCANNER)
    review = run.review((original,), upstream={})
    pins = selected_handoffs(job(consumer), run.root, {REVIEW_JOB: review.sha256})
    assert SCANNER[0] not in pins
    admitted = context(run, consumer, pins)
    admit_inputs(admitted, set(pins))
    with pytest.raises(ValueError, match="undeclared or unsupplied shard producer"):
        with input_read_scope(admitted):
            run.read_original(original)


@pytest.mark.parametrize("consumer", [GATE, DOSSIER], ids=["gate", "dossier"])
def test_source_outside_the_closed_audit_families_is_not_inherited_from_review(tmp_path, consumer):
    run = SourceRun(tmp_path)
    original = run.source(HISTORY)
    review = run.review((original,))
    pins = selected_handoffs(job(consumer), run.root, {REVIEW_JOB: review.sha256})
    assert HISTORY[0] not in pins
    with pytest.raises(ValueError, match="undeclared or unsupplied shard producer"):
        with input_read_scope(context(run, consumer, pins)):
            run.read_original(original)


@pytest.mark.parametrize("consumer", [GATE, DOSSIER], ids=["gate", "dossier"])
def test_foreign_target_source_is_rejected_by_real_input_admission(tmp_path, consumer):
    run = SourceRun(tmp_path)
    original = run.source(SCANNER, target="foreign-target")
    review = run.review((original,))
    pins = selected_handoffs(job(consumer), run.root, {REVIEW_JOB: review.sha256})
    with pytest.raises(ValueError, match="foreign target input"):
        admit_inputs(context(run, consumer, pins), set(pins))


@pytest.mark.parametrize("consumer", [GATE, DOSSIER], ids=["gate", "dossier"])
def test_original_source_pin_from_another_run_cannot_enter_the_claim(tmp_path, consumer):
    foreign = SourceRun(tmp_path / "foreign", run_id="foreign-run").source(SCANNER)
    run = SourceRun(tmp_path / "current")
    review = run.review((), upstream={SCANNER[0]: foreign.accepted.sha256})
    with pytest.raises(ValueError, match="exactly one accepted handoff"):
        selected_handoffs(job(consumer), run.root, {REVIEW_JOB: review.sha256})


@pytest.mark.parametrize("consumer", [GATE, DOSSIER], ids=["gate", "dossier"])
def test_producer_handoff_permission_does_not_replace_original_dataset_permission(tmp_path, consumer):
    run = SourceRun(tmp_path)
    original = run.source(POST_BUILD)
    review = run.review((original,))
    pins = selected_handoffs(job(consumer), run.root, {REVIEW_JOB: review.sha256})
    contract = replace(job(consumer).contract, inputs=tuple(row for row in job(consumer).contract.inputs
                       if (row.producer, row.output_kind) != POST_BUILD[:2]))
    admitted = context(run, consumer, pins, contract=contract)
    admit_inputs(admitted, set(pins))
    with pytest.raises(ValueError, match="undeclared consumption.*build_security"):
        with input_read_scope(admitted):
            run.read_original(original)


@pytest.mark.parametrize("consumer", [GATE, DOSSIER], ids=["gate", "dossier"])
def test_conflicting_verified_lineages_are_not_silently_overwritten(tmp_path, consumer):
    run = SourceRun(tmp_path)
    original = run.source(SCANNER)
    review = run.review((original,))
    newer = run.source(SCANNER, attempt="attempt_0002")
    with pytest.raises(ValueError, match="conflicting supplied input lineages"):
        selected_handoffs(job(consumer), run.root, {REVIEW_JOB: review.sha256, SCANNER[0]: newer.accepted.sha256})


@pytest.mark.parametrize("consumer", [GATE, DOSSIER], ids=["gate", "dossier"])
def test_original_source_raw_streams_are_not_granted_by_index_permission(tmp_path, consumer):
    run = SourceRun(tmp_path)
    original = run.source(SCANNER)
    raw_path = run.root / f"data/jobs/{SCANNER[0]}/attempts/attempt_0002/steps/source_sast/tasks/fixture/scratch/raw.bin"
    atomic_bytes(raw_path, b"synthetic private scanner output")
    raw = artifact_ref(run.root, raw_path)
    source = run.publish(SCANNER[0], {}, attempt="attempt_0002", artifacts=(raw,))
    review = run.review((original,), upstream={SCANNER[0]: source.sha256})
    pins = selected_handoffs(job(consumer), run.root, {REVIEW_JOB: review.sha256})
    with pytest.raises(ValueError, match="undeclared consumption.*static_tool_io"):
        with input_read_scope(context(run, consumer, pins)):
            observe_output(run.root, SCANNER[0], "static_tool_io", raw)


def test_source_selection_is_exact_canonical_and_dossier_duplicates_are_not_widened():
    expected = {(producer, kind) for producer, kinds in ORIGINAL_AUDIT_SOURCES for kind in ("handoff", *kinds)}
    requirements = original_audit_source_inputs()
    assert {(row.producer, row.output_kind) for row in requirements} == expected
    for producer, kinds in ORIGINAL_AUDIT_SOURCES:
        declarations = import_module(f"appsec_review.jobs.{producer}.datasets").DATASETS
        for kind in kinds:
            declaration = next(row for row in declarations if row.output_kind == kind)
            requirement = next(row for row in requirements if (row.producer, row.output_kind) == (producer, kind))
            assert (requirement.schema, requirement.authority) == (declaration.schema, declaration.authority)
            assert declaration.disposition == "indexed"
    original_context = source_context_inputs()
    merged = original_audit_source_inputs(original_context)
    assert len({row.key for row in merged}) == len(merged)
    assert all(next(row for row in merged if row.key == prior.key) == prior for prior in original_context)
    assert source_context_inputs() == original_context
    assert POST_BUILD[0] not in {row.producer for row in original_context}
    assert POST_BUILD[:2] in {(row.producer, row.output_kind) for row in merged}
    from appsec_review.review.lead_families import OBSERVATION_PRODUCERS
    observation_jobs = {row.job for row in OBSERVATION_PRODUCERS if row.family is not None}
    assert observation_jobs <= {producer for producer, _ in ORIGINAL_AUDIT_SOURCES}
    assert ("job_review_data_indexing", ("precomputed_products",)) in ORIGINAL_AUDIT_SOURCES


@pytest.mark.parametrize("change", [{"schema": "unknown/1"}, {"authority": EvidenceAuthority.OPERATIONAL},
                                   {"missing": MissingPolicy.NOT_APPLICABLE}],
                         ids=["schema", "authority", "missing-policy"])
def test_incompatible_duplicate_inputs_fail_instead_of_silently_expanding_permissions(change):
    original = next(row for row in original_audit_source_inputs() if row.output_kind == SCANNER[1])
    with pytest.raises(ValueError, match="conflicting original audit input"):
        original_audit_source_inputs((replace(original, **change),))


def test_only_gate_and_dossier_gain_original_audit_permissions():
    for consumer in (GATE, DOSSIER):
        assert POST_BUILD[0] in job(consumer).consumes
    for consumer in ("job_poc_generation", "job_remediation_planning", "job_remediation_validation"):
        contract = import_module(f"appsec_review.jobs.{consumer}.datasets").CONTRACT
        assert POST_BUILD[0] not in contract.consumes
    with pytest.raises(ValueError, match="duplicate input requirement"):
        JobContract(inputs=(InputRequirement(REVIEW_JOB, "handoff", "appsec-review/job-handoff/2"),) * 2)


@pytest.mark.parametrize("module", [
    "appsec_review.jobs.decision_audit_inputs",
    "appsec_review.jobs.job_dossier_publication.datasets",
], ids=["source-helper-first", "dossier-contract-first"])
def test_new_source_contract_entries_are_safe_in_a_fresh_interpreter(module):
    result = subprocess.run([sys.executable, "-I", "-c", """
import importlib
import sys
importlib.import_module(sys.argv[1])
from appsec_review.jobs.decision_audit_inputs import original_audit_source_inputs
from appsec_review.jobs.job_dossier_publication.datasets import CONTRACT
inputs = original_audit_source_inputs()
assert len(inputs) == 16
assert len({row.key for row in CONTRACT.inputs}) == len(CONTRACT.inputs)
assert "job_post_build_security_assessment" in CONTRACT.consumes
""", module], capture_output=True, text=True, timeout=8, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
