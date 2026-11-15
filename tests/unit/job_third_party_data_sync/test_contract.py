"""Contract pins for job_third_party_data_sync: inputs, datasets, topology and registry parity."""
from __future__ import annotations

from pathlib import PurePosixPath

from appsec_review.config import load_config
from appsec_review.jobs import job_third_party_data_sync as package
from appsec_review.jobs.job_third_party_data_sync.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_third_party_data_sync.job import TOPOLOGY, build_job
from appsec_review.orchestration.topology import wave1_dependencies
from appsec_review.runtime.contracts import DispatchClass, EvidenceAuthority, TargetAccess
from appsec_review.runtime.registry import builtin_contracts, builtin_registry

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def _glob_matches(pattern: str, rel_posix: str) -> bool:
    path_parts = PurePosixPath(rel_posix).parts
    pat_parts = PurePosixPath(pattern).parts

    def match(pi: int, qi: int) -> bool:
        if pi == len(pat_parts):
            return qi == len(path_parts)
        token = pat_parts[pi]
        if token == "**":
            return match(pi + 1, qi) or (qi < len(path_parts) and match(pi, qi + 1))
        if qi >= len(path_parts):
            return False
        if token == "*":
            return match(pi + 1, qi + 1)
        return PurePosixPath(path_parts[qi]).match(token) and match(pi + 1, qi + 1)

    return match(0, 0)


def test_package_exports_and_contract_pins() -> None:
    assert package.__all__ == ["build_job"]
    assert CONTRACT.inputs == ()
    assert CONTRACT.schedule_after == ()
    assert CONTRACT.dispatch is DispatchClass.MAINTENANCE
    assert CONTRACT.target_access is TargetAccess.NONE
    assert CONTRACT.always_execute is True
    assert CONTRACT.propagate_handoff is True
    assert CONSUMES == ()


def test_dataset_declaration_pins_and_work_glob_ownership() -> None:
    assert len(DATASETS) == 1
    ds = DATASETS[0]
    assert ds.output_kind == "feed_sync_work"
    assert ds.step == "nvd_sync"
    assert ds.family == "reference_feeds"
    assert ds.schema == "appsec-review/job-result/third-party-data-sync/1"
    assert ds.disposition == "protected"
    assert ds.sensitivity == "sensitive"
    assert ds.authority is EvidenceAuthority.REFERENCE
    assert ds.artifacts == ("data/jobs/job_third_party_data_sync/attempts/*/steps/*/tasks/*/work/**",)
    assert ds.indexes == ()
    assert ds.query_route == "query_dataset_inventory (sanitized identity, hash, status and coverage only)"
    assert ds.reason is not None and "published snapshots are pinned per run" in ds.reason

    for step, tasks in TOPOLOGY.items():
        for task in tasks:
            sample = (
                f"data/jobs/job_third_party_data_sync/attempts/attempt_0001/"
                f"steps/{step}/tasks/{task}/work/payload.bin"
            )
            assert _glob_matches(ds.artifacts[0], sample), sample
    assert not _glob_matches(
        ds.artifacts[0],
        "data/jobs/job_third_party_data_sync/attempts/attempt_0001/handoff.json",
    )


def test_registry_and_shared_topology_parity() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    registry = builtin_registry()
    built = registry.build("job_third_party_data_sync")
    direct = build_job()
    assert built.job_id == direct.job_id == "job_third_party_data_sync"
    assert built.name == direct.name == "third_party_data_sync"
    assert built.datasets == DATASETS
    assert built.contract == CONTRACT
    assert built.strict_gaps is True
    assert tuple(u.unit_id for u in built.units) == tuple(u.unit_id for u in direct.units)

    assert builtin_contracts()["job_third_party_data_sync"] == CONTRACT
    graph = wave1_dependencies(set(config.jobs))
    assert graph is not None and "job_third_party_data_sync" not in graph
