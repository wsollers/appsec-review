"""Contract, dataset, topology, and configuration tests for job_artifact_security_analysis."""

from __future__ import annotations

from dataclasses import replace
from fnmatch import fnmatch
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_artifact_security_analysis.datasets import (
    CONSUMES,
    CONTRACT,
    DATASETS,
    RAW,
)
from appsec_review.jobs.job_artifact_security_analysis.findings import RECORD_SCHEMA
from appsec_review.jobs.job_artifact_security_analysis.job import (
    CAPABILITIES,
    OBSERVATION_SCHEMA,
    SCHEMA,
    TOPOLOGY,
    _validate_config,
    build_job,
)
from appsec_review.runtime.contracts import (
    Availability,
    CoveragePolicy,
    DispatchClass,
    EvidenceAuthority,
    InputChannel,
    MissingPolicy,
    TargetAccess,
)
from appsec_review.orchestration.topology import upstream_closure, wave1_dependencies
from appsec_review.runtime.inputs import feed_input_identity
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import file_sha256

from .support import ROOT


@pytest.mark.parametrize("origin", ["target-intake", "installer-record"])
def test_actual_scanner_staging_files_have_protected_dataset_custody(tmp_path, monkeypatch, origin):
    from appsec_review.container_runtime import ContainerExecutor
    from appsec_review.jobs.job_artifact_security_analysis.scanners import ContainerScannerRunner
    from .support import RECORD_METADATA

    attempt = tmp_path / "data/jobs/job_artifact_security_analysis/attempts/attempt_0001"
    task = attempt / "steps/analyze/tasks/syft"
    source = tmp_path / "input"
    source.write_bytes(b"{}")
    artifact = {"canonical_identity": "fixture:input", "sha256": file_sha256(source)}
    if origin == "target-intake":
        artifact.update(artifact_origin=origin, target_relative_path="vendor/package-lock.json")
    else:
        artifact["dependency_metadata"] = RECORD_METADATA
    runner = ContainerScannerRunner(ROOT, tmp_path, task)
    monkeypatch.setattr(runner, "identity", lambda *args: {"scanner": "fixture"})

    class Captured(Exception):
        pass

    def execute(executor, request):
        assert request.extra_mounts[0].source == source and request.extra_mounts[0].read_only
        raise Captured

    monkeypatch.setattr(ContainerExecutor, "execute", execute)
    with pytest.raises(Captured):
        runner("syft", source, artifact, 1, 32)
    files = sorted(path for path in task.rglob("*") if path.is_file())
    assert len(files) == 1 and files[0].read_bytes() == b""
    for path in files:
        relative = path.relative_to(tmp_path).as_posix()
        owners = [decl for decl in DATASETS if any(fnmatch(relative, glob) for glob in decl.artifacts)]
        assert [(decl.output_kind, decl.disposition) for decl in owners] == [
            ("artifact_scanner_io", "protected")]


EXPECTED_INPUTS = (
    (
        "job_artifact_indexing",
        "handoff",
        "appsec-review/job-handoff/2",
        Availability.REQUIRED,
        MissingPolicy.REJECT,
    ),
    (
        "job_artifact_indexing",
        "artifact_catalog",
        "appsec-review/retrieval-index/2",
        Availability.OPTIONAL,
        MissingPolicy.GAP,
    ),
    (
        "job_artifact_indexing",
        "archive_members",
        "appsec-review/retrieval-index/2",
        Availability.OPTIONAL,
        MissingPolicy.GAP,
    ),
    (
        "job_artifact_indexing",
        "artifact_relationships",
        "appsec-review/retrieval-index/2",
        Availability.OPTIONAL,
        MissingPolicy.GAP,
    ),
    (
        "job_artifact_indexing",
        "artifact_index_summary",
        "appsec-review/artifact-indexing/1",
        Availability.REQUIRED,
        MissingPolicy.REJECT,
    ),
    (
        "job_language_build",
        "handoff",
        "appsec-review/job-handoff/2",
        Availability.REQUIRED,
        MissingPolicy.REJECT,
    ),
    (
        "job_language_build",
        "topology_refinement_inputs",
        "appsec-review/build-topology-refinement/1",
        Availability.OPTIONAL,
        MissingPolicy.GAP,
    ),
    (
        "job_language_build",
        "build_actions",
        "appsec-review/retrieval-index/2",
        Availability.OPTIONAL,
        MissingPolicy.GAP,
    ),
    (
        "job_language_build",
        "jvm_build_actions",
        "appsec-review/retrieval-index/2",
        Availability.OPTIONAL,
        MissingPolicy.GAP,
    ),
    (
        "job_language_build",
        "language_build_receipts",
        "appsec-review/language-build-handoff/2",
        Availability.REQUIRED,
        MissingPolicy.REJECT,
    ),
    (
        "job_language_build",
        "build_workspaces",
        "application/octet-stream",
        Availability.OPTIONAL,
        MissingPolicy.GAP,
    ),
    (
        "job_third_party_data_sync",
        "feed_snapshot",
        "appsec-review/public-feed-use/1",
        Availability.OPTIONAL,
        MissingPolicy.GAP,
    ),
)


def test_contract_inputs_consumes_and_upstream_producer_parity() -> None:
    actual = tuple(
        (item.producer, item.output_kind, item.schema, item.availability, item.missing)
        for item in CONTRACT.inputs
    )
    assert actual == EXPECTED_INPUTS
    external = [item for item in CONTRACT.inputs if item.channel is InputChannel.EXTERNAL]
    assert len(external) == 1
    assert external[0].producer == "job_third_party_data_sync"
    assert external[0].output_kind == "feed_snapshot"
    assert external[0].authority is EvidenceAuthority.REFERENCE
    assert external[0].coverage is CoveragePolicy.ALLOW_PARTIAL
    handoff_inputs = [item for item in CONTRACT.inputs if item.channel is InputChannel.HANDOFF]
    assert len(handoff_inputs) == len(EXPECTED_INPUTS) - 1
    for item in handoff_inputs:
        assert item.authority is EvidenceAuthority.PRODUCER_EVIDENCE
        assert item.coverage is CoveragePolicy.ALLOW_PARTIAL
    assert CONSUMES == CONTRACT.consumes == ("job_artifact_indexing", "job_language_build")
    assert "job_third_party_data_sync" not in CONSUMES
    assert CONTRACT.schedule_after == ("job_artifact_indexing",)
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True

    registry = builtin_registry()
    for item in handoff_inputs:
        if item.output_kind == "handoff":
            continue
        upstream = registry.build(item.producer)
        matches = [decl for decl in upstream.datasets if decl.output_kind == item.output_kind]
        assert len(matches) == 1
        assert matches[0].schema == item.schema
        assert matches[0].authority is item.authority

    # When maintenance producer job_third_party_data_sync is unselected in a review graph,
    # job_artifact_security_analysis remains schedulable with no upstream dependency on it.
    selected_without_sync = set(registry.job_ids()) - {"job_third_party_data_sync"}
    deps = wave1_dependencies(selected_without_sync)
    assert deps is not None and "job_artifact_security_analysis" in deps
    closure = set(
        upstream_closure("job_artifact_security_analysis", deps, set(deps))
    )
    assert set(CONSUMES) <= closure
    assert "job_third_party_data_sync" not in closure


def test_dataset_declarations_and_job_unit_topology() -> None:
    by_kind = {decl.output_kind: decl for decl in DATASETS}
    assert tuple(by_kind) == (
        "artifact_security_observations",
        "artifact_security_results",
        "artifact_security_acceptance",
        "artifact_scanner_io",
    )

    obs = by_kind["artifact_security_observations"]
    assert obs.step == "index"
    assert obs.family == "scanner_findings"
    assert obs.schema == "appsec-review/retrieval-index/2"
    assert obs.disposition == "indexed"
    assert obs.sensitivity == "internal"
    assert obs.indexes == ("observations",)
    assert obs.shard_prefixes == ("artifact-security",)
    assert "query_artifacts" in (obs.query_route or "")

    res = by_kind["artifact_security_results"]
    assert res.step == "analyze"
    assert res.family == "sbom"
    assert res.schema == OBSERVATION_SCHEMA
    assert res.disposition == "artifact_only"
    assert res.artifacts == ("data/artifact-security/shards/*/*/result.json",)
    assert fnmatch("data/artifact-security/shards/grype/abc/result.json", res.artifacts[0])
    assert not fnmatch("data/artifact-security/shards/grype/result.json", res.artifacts[0])

    acc = by_kind["artifact_security_acceptance"]
    assert acc.step == "acceptance"
    assert acc.family == "sbom"
    assert acc.schema == SCHEMA
    assert acc.disposition == "artifact_only"
    assert acc.artifacts == (
        "data/jobs/job_artifact_security_analysis/attempts/*/artifacts/artifact-security/accepted-analysis.json",
    )

    io_decl = by_kind["artifact_scanner_io"]
    assert io_decl.step == "analyze"
    assert io_decl.family == "scanner_findings"
    assert io_decl.schema == "appsec-review/container-execution/1"
    assert io_decl.disposition == "protected"
    assert io_decl.sensitivity == "sensitive"
    assert io_decl.reason == RAW

    job = build_job()
    assert job.job_id == "job_artifact_security_analysis"
    assert job.name == "artifact_security_analysis"
    assert job.schema_identity == SCHEMA
    assert job.datasets == DATASETS
    assert job.contract == CONTRACT
    assert job.external_input_identity is feed_input_identity
    units = {unit.unit_id: unit for unit in job.units}
    assert tuple(units) == (
        "load.accepted_artifacts",
        *(f"analyze.{capability}" for capability in CAPABILITIES),
        "index.observations",
        "acceptance.publish_handoff",
    )
    assert units["load.accepted_artifacts"].dependencies == ()
    for capability in CAPABILITIES:
        assert units[f"analyze.{capability}"].dependencies == ("load.accepted_artifacts",)
    assert units["index.observations"].dependencies == tuple(
        f"analyze.{capability}" for capability in CAPABILITIES
    )
    assert units["acceptance.publish_handoff"].dependencies == ("index.observations",)


def test_published_analysis_has_a_dataset_with_its_actual_step_and_schema(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    attempt_root = run_root / "data/jobs/job_artifact_security_analysis/attempts/attempt_0001"
    artifact_index = {"path": "data/indices/manifests/artifacts.json", "sha256": "a" * 64}
    observations_index = {"path": "data/indices/manifests/observations.json", "sha256": "b" * 64}
    capabilities = {
        capability: {
            "observation_count": 1,
            "gaps": [],
            "terminal_status": "SUCCEEDED",
            "not_applicable_inputs": {"count": 0, "items": [], "by_reason": {}},
            "installer_records": [],
            "scope_dispositions": [],
        }
        for capability in CAPABILITIES
    }
    outputs = {
        "load.accepted_artifacts": {
            "language_build_handoff_sha256": "c" * 64,
            "artifact_index": artifact_index,
            "artifact_count": 1,
            "producer_gaps": [],
        },
        "index.observations": {
            "observation_count": len(CAPABILITIES),
            "finding_count": 2,
            "record_schema": RECORD_SCHEMA,
            "index_manifest": observations_index,
            "gaps": [],
        },
        **{f"analyze.{capability}": result for capability, result in capabilities.items()},
    }
    context = SimpleNamespace(
        job=SimpleNamespace(
            run_root=run_root, attempt_root=attempt_root, source_fingerprint="d" * 64
        ),
        output=outputs.__getitem__,
    )
    publish = next(unit for unit in build_job().units if unit.unit_id == "acceptance.publish_handoff")

    result = publish.handler(context)

    relative = (
        "data/jobs/job_artifact_security_analysis/attempts/attempt_0001/"
        "artifacts/artifact-security/accepted-analysis.json"
    )
    path = run_root / relative
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document == {
        "schema": SCHEMA,
        "source_fingerprint": "d" * 64,
        "language_build_handoff_sha256": "c" * 64,
        "artifact_index": artifact_index,
        "artifact_count": 1,
        "observation_count": len(CAPABILITIES),
        "finding_count": 2,
        "record_schema": RECORD_SCHEMA,
        "capabilities": capabilities,
        "producer_gaps": [],
        "gaps": [],
        "index_manifest": observations_index,
    }
    assert result == {
        "artifact": {
            "path": relative,
            "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size,
        },
        "index_manifest": observations_index,
        "artifact_count": 1,
        "observation_count": len(CAPABILITIES),
        "finding_count": 2,
        "gaps": [],
        "terminal_status": "SUCCEEDED",
    }
    owners = [
        declaration
        for declaration in DATASETS
        if any(fnmatch(relative, pattern) for pattern in declaration.artifacts)
    ]
    assert [(owner.step, owner.schema) for owner in owners] == [
        ("acceptance", document["schema"])
    ]

    outputs_with_gaps = {
        **outputs,
        "index.observations": {**outputs["index.observations"], "gaps": ["upstream gap"]},
    }
    context_gaps = SimpleNamespace(job=context.job, output=outputs_with_gaps.__getitem__)
    assert publish.handler(context_gaps)["terminal_status"] == "COMPLETED_WITH_GAPS"


def test_validate_config_accepts_shipped_settings_and_rejects_drift() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    job_config = config.job("job_artifact_security_analysis")
    _validate_config(SimpleNamespace(config=job_config), None)

    bad_steps = replace(job_config, steps={k: v for k, v in job_config.steps.items() if k != "index"})
    with pytest.raises(ValueError, match="topology does not match"):
        _validate_config(SimpleNamespace(config=bad_steps), None)

    analyze_step = job_config.step("analyze")
    bad_tasks = replace(
        job_config,
        steps={
            **job_config.steps,
            "analyze": replace(analyze_step, tasks={k: v for k, v in analyze_step.tasks.items() if k != "osv"}),
        },
    )
    with pytest.raises(ValueError, match="task order mismatch: analyze"):
        _validate_config(SimpleNamespace(config=bad_tasks), None)

    missing_setting = replace(
        job_config,
        settings={k: v for k, v in job_config.settings.items() if k != "timeout_seconds"},
    )
    with pytest.raises(ValueError, match="settings are incomplete"):
        _validate_config(SimpleNamespace(config=missing_setting), None)

    for bad_value in (True, 0, -5, "10"):
        bad_bound = replace(job_config, settings={**job_config.settings, "timeout_seconds": bad_value})
        with pytest.raises(ValueError, match="bounds must be positive integers"):
            _validate_config(SimpleNamespace(config=bad_bound), None)

    bad_identities = replace(job_config, settings={**job_config.settings, "scanner_identities": ["x"]})
    with pytest.raises(ValueError, match="scanner identities must be a table"):
        _validate_config(SimpleNamespace(config=bad_identities), None)

    bad_memory = replace(job_config, settings={**job_config.settings, "osv_memory": "not-bytes"})
    with pytest.raises(ValueError, match="osv_memory"):
        _validate_config(SimpleNamespace(config=bad_memory), None)
    assert tuple(TOPOLOGY) == ("load", "analyze", "index", "acceptance")
