"""Exact ownership of real source/coverage declarations at admission and reader boundaries."""
from dataclasses import asdict, replace
from datetime import datetime, timezone
from importlib import import_module
import json

import pytest

from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.bound_artifacts import artifact_ref, source_context_core, source_context_inputs
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.contracts import JobContract, TargetAccess, accepted_inputs
from appsec_review.runtime.datasets import dataset_contract, shard_owner
from appsec_review.runtime.inputs import observe_shard, read_input_observations
from appsec_review.storage import atomic_json, file_sha256
from tests.downstream_contract_fixture import COVERAGE_SHARDS, configuration
from tests.handoff_fixture import write_fixture_handoff

SNAPSHOT = "target-sha256:" + "7" * 64


def source_case(tmp_path, row=COVERAGE_SHARDS[0], *, invalid=None):
    producer, output, index, shard_id = row
    declarations = import_module(f"appsec_review.jobs.{producer}.datasets").DATASETS
    owner = next(item for item in declarations if item.output_kind == output)
    if invalid == "ambiguous":
        prefix, = owner.shard_prefixes
        declarations += (replace(owner, output_kind="ambiguous_scope", shard_prefixes=(),
                                 shard_suffixes=(shard_id[-len(prefix):],)),)
    elif invalid == "unclaimed":
        index = "source"
    config = configuration(tmp_path, engineering=("job_remediation_planning",))
    runner = JobRunner(config)
    run_id, root = runner.runs.create(datetime(2026, 11, 6, tzinfo=timezone.utc))
    runner._bind_configuration(root)
    target = tmp_path / "source"
    target.mkdir()
    path = root / f"data/indices/{index}/{shard_id}.sqlite"
    gap = f"{output}: fixture scope unavailable"
    builder = IndexBuilder(path, name=index, fingerprint="a" * 64,
                           target_snapshot=SNAPSHOT, shard_id=shard_id)
    builder.add_coverage("fixture", "unavailable", gap)
    shard = IndexIdentity(index, "appsec-review/retrieval-index/2", builder.build(), "a" * 64,
                          path.relative_to(root).as_posix(), {"job": producer, "unit": owner.step + ".fixture"},
                          (gap,), shard_id)
    manifest_path = root / "data/indices/manifests/fixture.json"
    write_manifest(manifest_path, run_id=run_id, target_snapshot=SNAPSHOT, target_root=target, indexes=(shard,))
    manifest = artifact_ref(root, manifest_path)
    attempt = root / f"data/jobs/{producer}/attempts/attempt_0001"
    atomic_json(attempt / "claim.json", {
        "dataset_contract": dataset_contract(producer, sorted({item.step for item in declarations}), declarations)})
    handoff_path = attempt / "handoff.json"
    write_fixture_handoff(root, handoff_path, {
        "job_id": producer, "source_fingerprint": SNAPSHOT,
        "outputs": {owner.step + ".fixture": {"index_identity": asdict(shard), "index_manifest": manifest,
                                            "gaps": [gap], "terminal_status": "COMPLETED_WITH_GAPS"}},
        "artifacts": [artifact_ref(root, path)],
    })
    atomic_json(attempt.parent.parent / "latest.json", {
        "handoff_path": handoff_path.relative_to(root).as_posix(), "handoff_sha256": file_sha256(handoff_path)})
    accepted = accepted_handoff(root, producer)
    assert accepted is not None
    return runner, root, manifest, asdict(shard), declarations, accepted, gap


def reader_job(handler, inputs):
    return Job("job_remediation_planning", "remediation_planning", lambda _: {},
               units=(Unit("assess.propose", handler),),
               contract=JobContract(inputs=inputs, target_access=TargetAccess.ACCEPTED_EVIDENCE))


@pytest.mark.parametrize("row", COVERAGE_SHARDS, ids=[row[1] for row in COVERAGE_SHARDS])
def test_coverage_only_input_is_owned_read_and_reported_as_coverage(tmp_path, row):
    runner, root, manifest, shard, declarations, accepted, gap = source_case(tmp_path, row)
    producer, output, _index, _shard_id = row
    assert shard_owner(declarations, shard["name"], shard["shard_id"]).output_kind == output

    def consume(unit):
        core = source_context_core(unit.job.run_root, manifest)
        coverage = core.coverage()
        assert len(coverage["results"]) == 1
        assert coverage["results"][0]["entity_count"] == 0
        assert any(gap in reason for reason in coverage["coverage_gaps"])
        found = core.find(kind="source_span")
        assert found["results"] == []
        assert any(gap in reason for reason in found["coverage_gaps"])
        return {"gaps": coverage["coverage_gaps"], "terminal_status": "COMPLETED_WITH_GAPS"}

    result = runner.run(reader_job(consume, source_context_inputs()), run_id=root.name,
                        upstream_handoffs={producer: accepted.sha256})
    claim = json.loads((root / result["handoff"]["resolving_paths"]["attempt"] / "claim.json").read_bytes())
    supplied = {item["output_kind"]: item for item in claim["input_admission"]["requirements"]
                if item["producer"] == producer}
    assert supplied[output]["available"] and supplied[output]["supplied"]
    assert all(not value["available"] for kind, value in supplied.items() if kind not in {output, "handoff"})
    assert supplied[output]["coverage"]["disposition"] == "partial"
    reads = read_input_observations(root, result["handoff"])["reads"]
    assert {item["output_kind"] for item in reads} == {output}
    assert all(item["cited"] is None for item in reads)
    assert result["status"]["status"] == "COMPLETED_WITH_GAPS"


@pytest.mark.parametrize("invalid", ("unclaimed", "ambiguous"))
def test_invalid_ownership_is_rejected_during_real_admission(tmp_path, invalid):
    runner, root, _manifest, _shard, declarations, accepted, _gap = source_case(tmp_path, invalid=invalid)
    job = reader_job(lambda _: pytest.fail("invalid ownership reached a consumer"),
                     accepted_inputs("job_tree_sitter_ast", declarations))
    with pytest.raises(ValueError, match=f"no exact dataset owner.*{invalid}"):
        runner.run(job, run_id=root.name, upstream_handoffs={"job_tree_sitter_ast": accepted.sha256})


@pytest.mark.parametrize("boundary", ("source-view", "observed-read"))
@pytest.mark.parametrize("invalid", ("unclaimed", "ambiguous"))
def test_invalid_ownership_cannot_be_caught_as_a_successful_gap(tmp_path, boundary, invalid):
    runner, root, manifest, shard, _declarations, accepted, _gap = source_case(tmp_path, invalid=invalid)

    def consume(unit):
        try:
            if boundary == "source-view":
                source_context_core(unit.job.run_root, manifest)
            else:
                observe_shard(unit.job.run_root, shard)
        except ValueError:
            return {"gaps": ["caught invalid ownership"]}
        pytest.fail("invalid ownership was silently excluded")

    inputs = accepted_inputs("job_tree_sitter_ast", ())
    with pytest.raises(RuntimeError, match=f"no exact dataset owner.*{invalid}"):
        runner.run(reader_job(consume, inputs), run_id=root.name,
                   upstream_handoffs={"job_tree_sitter_ast": accepted.sha256})
    assert not (root / "data/jobs/job_remediation_planning/latest.json").exists()


def test_source_view_uses_complete_pinned_contract_not_current_or_selected_claims(tmp_path):
    runner, root, manifest, shard, declarations, accepted, _gap = source_case(tmp_path)
    # A historical contract can give this shard a still more specific, non-source-context owner.
    coverage = shard_owner(declarations, shard["name"], shard["shard_id"])
    historical = replace(coverage, output_kind="historical_operational_scope",
                         shard_prefixes=(shard["shard_id"],))
    # Publish a separate immutable generation instead of rewriting the first accepted contract.
    first_path = root / accepted.path
    original_bytes = first_path.read_bytes()
    second = first_path.parent.parent / "attempt_0002"
    extended = (*declarations, historical)
    atomic_json(second / "claim.json", {
        "dataset_contract": dataset_contract(accepted.handoff["job_id"],
                                            sorted({item.step for item in extended}), extended)})
    write_fixture_handoff(root, second / "handoff.json", {
        "job_id": accepted.handoff["job_id"], "attempt_id": second.name,
        "source_fingerprint": SNAPSHOT, "outputs": accepted.handoff["outputs"],
        "artifacts": [artifact_ref(root, root / shard["relative_path"])],
    })
    atomic_json(first_path.parent.parent.parent / "latest.json", {
        "handoff_path": (second / "handoff.json").relative_to(root).as_posix(),
        "handoff_sha256": file_sha256(second / "handoff.json")})
    assert source_context_core(root, manifest).indexes == {}
    # A typed attempt supplied the first generation, so even after pointer advancement its
    # metadata resolver must use that exact contract, not the current accepted pointer.
    from appsec_review.runtime.inputs import input_read_scope
    job = reader_job(lambda _: {}, accepted_inputs(accepted.handoff["job_id"], declarations))
    atomic_json(first_path.parent.parent.parent / "latest.json", {
        "handoff_path": accepted.path, "handoff_sha256": accepted.sha256})
    claim = runner.begin_attempt(job, run_id=root.name,
                                 upstream_handoffs={accepted.handoff["job_id"]: accepted.sha256})
    context = runner._context_from_claim(job, claim)
    atomic_json(first_path.parent.parent.parent / "latest.json", {
        "handoff_path": (second / "handoff.json").relative_to(root).as_posix(),
        "handoff_sha256": file_sha256(second / "handoff.json")})
    with input_read_scope(context):
        core = source_context_core(root, manifest)
        assert core.coverage()["results"][0]["shard_id"] == shard["shard_id"]
    assert first_path.read_bytes() == original_bytes
