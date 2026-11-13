"""Mandatory artifact inputs fail at admission, before scanner or container work.

Pre-walk suite shared by job_artifact_indexing and job_artifact_security_analysis, pending
replacement (T-113): every case publishes recorded producers through a real ``JobRunner`` or
``GraphRunner`` (8 to 28 s), so it runs in the integration tier. The admission contract itself is
pinned at code level in ``tests/unit/job_artifact_indexing/test_contract.py``.
"""
import json

import pytest

from appsec_review.jobs.job_artifact_indexing import build_job as indexing_job
from appsec_review.jobs.job_artifact_security_analysis import build_job as security_job
from appsec_review.runtime import JobRunner
from tests.downstream_contract_fixture import configuration
from tests.test_artifact_security_analysis import _fixture


@pytest.mark.parametrize("factory", (indexing_job, security_job), ids=("indexing", "security"))
def test_artifact_consumers_require_supplied_build_handoffs(tmp_path, factory):
    config = configuration(tmp_path)
    target = tmp_path / "source"
    target.mkdir()
    with pytest.raises(ValueError, match="required input unavailable"):
        JobRunner(config).begin_attempt(factory(), target_root=target,
                                        source_fingerprint="fixture", upstream_handoffs={})


@pytest.mark.parametrize("factory,unit", [
    (indexing_job, "load.accepted_builds"), (security_job, "load.accepted_artifacts"),
], ids=("indexing", "security"))
def test_supplied_empty_build_inputs_reach_real_loaders(tmp_path, factory, unit):
    config, run_id, root, target, snapshot, _ = _fixture(tmp_path, no_artifacts=True, seed_accepted=True)
    names = ("job_language_build",) if factory is indexing_job else ("job_language_build", "job_artifact_indexing")
    supplied = {name: json.loads((root / "data/jobs" / name / "latest.json").read_bytes())["handoff_sha256"]
                for name in names}
    job, runner = factory(), JobRunner(config)
    claim = runner.begin_attempt(job, run_id=run_id, target_root=target,
                                 source_fingerprint=snapshot, upstream_handoffs=supplied)
    output = runner.execute_or_reuse_unit(job, claim, unit)
    assert claim["upstream_handoffs"] == supplied
    if factory is indexing_job:
        assert output["receipt_count"] == 0
        assert "no produced artifacts" in output["producer_gaps"]
    else:
        assert output["artifact_count"] == 0


def test_artifact_indexing_reads_catalog_without_undeclared_intake(tmp_path):
    from appsec_review.jobs.job_review_intake import build_job as intake_job
    from appsec_review.jobs.job_target_catalog import build_job as catalog_job
    from appsec_review.runtime import GraphRunner
    from appsec_review.runtime.inputs import read_input_observations
    from appsec_review.storage import atomic_json, file_sha256
    from tests.artifact_input_support import recorded_job
    from tests.integration.job_artifact_indexing.test_artifact_indexing_graph import _seed

    config, target, snapshot, root, receipts, document, _, _ = _seed(
        tmp_path, source_files={"prebuilt.wasm": "\0asm\x01\0\0\0"},
        build_families=("wasm",), publish=False)
    manifest = root / "data/indices/manifests/language-build.json"
    atomic_json(root / "data/inputs/artifact-fixture/job_language_build.json", {
        "document": json.loads(document.read_bytes()),
        "manifest": {"path": manifest.relative_to(root).as_posix(),
                     "sha256": file_sha256(manifest)},
    })
    GraphRunner(config, [intake_job(), catalog_job(), recorded_job(root, "job_language_build")]).run(
        run_id=root.name, target_root=target, source_fingerprint=snapshot)
    result = JobRunner(config).run(indexing_job(), run_id=root.name,
                                   target_root=target, source_fingerprint=snapshot)
    assert "job_review_intake" not in result["handoff"]["upstream_handoff_sha256"]
    reads = read_input_observations(root, result["handoff"])["reads"]
    assert {row["producer"] for row in reads} == {"job_target_catalog", "job_language_build"}
    output = result["handoff"]["outputs"]["acceptance.publish_handoff"]
    indexed = json.loads((root / output["artifact"]["path"]).read_bytes())
    assert indexed["artifact_count"] == len(receipts[0]["artifacts"]) + 1 == 2
    artifact, = indexed["target_artifacts"]
    assert artifact["target_relative_path"] == "prebuilt.wasm"
    assert artifact["sha256"] == file_sha256(target / "prebuilt.wasm")
    assert indexed["target_catalog_handoff_sha256"]


@pytest.mark.parametrize("mutation", ("stale", "tampered", "missing-summary"))
def test_artifact_input_identity_is_checked_before_load(tmp_path, mutation):
    from tests.artifact_input_support import recorded_job
    config, run_id, root, target, snapshot, _ = _fixture(tmp_path, no_artifacts=True, seed_accepted=True)
    pointer = json.loads((root / "data/jobs/job_language_build/latest.json").read_bytes())
    handoff = json.loads((root / pointer["handoff_path"]).read_bytes())
    if mutation == "stale":
        pointer["handoff_sha256"] = "0" * 64
    elif mutation == "tampered":
        summary = root / handoff["outputs"]["acceptance.publish_handoff"]["artifact"]["path"]
        summary.write_bytes(summary.read_bytes() + b"\n")
    else:
        # A newly published generation omits the required receipt dataset, without rewriting history.
        from dataclasses import replace
        from appsec_review.runtime import Unit
        original = (root / pointer["handoff_path"]).read_bytes()
        job = recorded_job(root, "job_language_build")
        incomplete = replace(job, units=(Unit("acceptance.publish_handoff", lambda _: {"gaps": ["no summary"]}),))
        accepted = JobRunner(config).run(incomplete, run_id=run_id, target_root=target, source_fingerprint=snapshot)
        assert (root / pointer["handoff_path"]).read_bytes() == original
        pointer["handoff_sha256"] = accepted["handoff_sha256"]
    with pytest.raises(ValueError, match="stale|changed|mismatch|required input unavailable"):
        JobRunner(config).begin_attempt(indexing_job(), run_id=run_id, target_root=target,
                                        source_fingerprint=snapshot,
                                        upstream_handoffs={"job_language_build": pointer["handoff_sha256"]})
