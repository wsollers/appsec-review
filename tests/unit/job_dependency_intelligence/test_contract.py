"""Contract, registry, topology, and dataset parity tests for job_dependency_intelligence."""

from __future__ import annotations

from pathlib import Path

from appsec_review.config import load_config
from appsec_review.jobs.engineering_contracts import DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA
from appsec_review.jobs.job_dependency_intelligence import (
    JOB_ID, TOPOLOGY, build_job, load_accepted_dependency_intelligence,
)
from appsec_review.jobs.job_dependency_intelligence.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_evidence_collection.adapters import _syft_parser
from appsec_review.jobs.job_evidence_collection.evidence import build_envelope
from appsec_review.orchestration.topology import wave1_dependencies
from appsec_review.runtime.contracts import (
    DispatchClass, EvidenceAuthority, InputChannel, TargetAccess,
)
from appsec_review.runtime.inputs import feed_input_identity
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import canonical_json


ROOT = Path(__file__).resolve().parents[3]


def test_job_contract_datasets_and_topology_parity() -> None:
    assert JOB_ID == "job_dependency_intelligence"
    assert callable(load_accepted_dependency_intelligence)
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True
    assert CONTRACT.schedule_after == (
        "job_target_catalog",
        "job_language_build",
        "job_artifact_indexing",
        "job_evidence_collection",
        "job_cpp_compiled_analysis",
    )
    assert CONSUMES == CONTRACT.consumes == (
        "job_artifact_indexing",
        "job_cpp_compiled_analysis",
        "job_evidence_collection",
        "job_language_build",
        "job_target_catalog",
    )
    assert len(CONTRACT.inputs) == 33
    external = [req for req in CONTRACT.inputs if req.channel is InputChannel.EXTERNAL]
    assert len(external) == 1
    assert external[0].producer == "job_third_party_data_sync"
    assert external[0].output_kind == "feed_snapshot"
    assert external[0].authority is EvidenceAuthority.REFERENCE
    handoff_reqs = [req for req in CONTRACT.inputs if req.channel is InputChannel.HANDOFF]
    assert len(handoff_reqs) == 32
    assert all(req.authority is EvidenceAuthority.PRODUCER_EVIDENCE for req in handoff_reqs)

    assert len(DATASETS) == 17
    by_kind = {item.output_kind: item for item in DATASETS}
    assert set(by_kind) == {
        "native_discovery",
        "native_component_curation",
        "native_metadata_investigation",
        "native_inference_metrics",
        "native_spdx",
        "native_sbom_provenance",
        "native_sbom_metrics",
        "dependency_context",
        "native_advisory_observations",
        "native_advisory_lookup",
        "scorecard_responses",
        "native_inputs",
        "unity_inventory",
        "native_inference_inputs",
        "native_inference_io",
        "native_sbom_conversion",
        "dependency_intelligence_handoff",
    }
    assert by_kind["dependency_context"].disposition == "indexed"
    assert by_kind["native_advisory_observations"].disposition == "indexed"
    assert by_kind["native_advisory_observations"].indexes == ("observations",)
    assert by_kind["native_advisory_observations"].shard_prefixes == ("native-advisory",)
    assert {k for k, v in by_kind.items() if v.disposition == "protected"} == {
        "native_inputs",
        "native_inference_io",
        "native_sbom_conversion",
    }

    job = build_job()
    assert job.job_id == JOB_ID
    assert job.schema_identity == DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA
    assert job.contract is CONTRACT
    assert job.datasets == DATASETS
    assert job.external_input_identity is feed_input_identity
    expected_units = tuple(
        f"{step}.{task}" for step, tasks in TOPOLOGY.items() for task in tasks
    )
    assert tuple(u.unit_id for u in job.units) == expected_units

    config = load_config(ROOT / "appsec-review.toml")
    registry = builtin_registry()
    registry.require_matches(config.jobs.keys(), surface="test")
    built = registry.build(JOB_ID)
    assert built.job_id == JOB_ID
    deps = wave1_dependencies(set(config.jobs))
    assert deps is not None
    assert deps[JOB_ID] and set(deps[JOB_ID]) <= set(CONTRACT.schedule_after)


def test_structured_syft_identity_survives_parser_and_envelope(tmp_path: Path) -> None:
    snapshot = "f" * 64
    payload = canonical_json({"artifacts": [{
        "id": "native-zlib", "name": "zlib", "version": "1.3.1",
        "purl": "pkg:generic/zlib@1.3.1", "metadata": {"repository": "https://github.com/madler/zlib"},
        "locations": [{"path": "vendor/zlib/zlib.h"}],
    }]})
    records = _syft_parser(payload)
    envelope = build_envelope(
        tool={"id": "tool-syft"}, target_fingerprint=snapshot,
        applicability={}, coverage_scope={}, gaps=[], raw_artifacts=[], parser_identity="test",
        observations=records, cataloged_paths=["vendor/zlib/zlib.h"],
        terminal_status="SUCCEEDED", run_root=tmp_path,
    )
    row = envelope["records"][0]
    assert row["version"] == "1.3.1"
    assert row["purl"] == "pkg:generic/zlib@1.3.1"
    assert row["repository_url"] == "https://github.com/madler/zlib"
    assert row["raw_selector"] == "/artifacts/0"
