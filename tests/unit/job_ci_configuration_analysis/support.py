"""Lightweight unit-test fixtures for job_ci_configuration_analysis."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
from pathlib import Path
import shutil
from types import SimpleNamespace
from typing import Any, Iterable, Mapping

from appsec_review.config import load_config
from appsec_review.jobs.job_ci_configuration_analysis.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_ci_configuration_analysis.job import TOPOLOGY
from appsec_review.retrieval import EntityKind, EntityRecord, IndexIdentity, LogicalIdentity, write_manifest
from appsec_review.retrieval.index import IndexBuilder
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner
from tests.ci_support import DIGEST, FakeExecutor, checkov_workflow_permissions, zizmor_finding
from tests.container_fixture import copy_containers
from tests.handoff_fixture import write_fixture_handoff


ROOT = Path(__file__).resolve().parents[3]
SOURCE_FP = "a" * 64
_BASE_CONFIG = load_config(ROOT / "appsec-review.toml")
_BASE_RESOLVED_BYTES = _BASE_CONFIG.resolved_json
_BASE_RESOLVED_SHA256 = _BASE_CONFIG.resolved_sha256

__all__ = [
    "DIGEST",
    "FakeExecutor",
    "ROOT",
    "SOURCE_FP",
    "attempt_scope",
    "checkov_workflow_permissions",
    "isolated_config",
    "make_unit_context",
    "seed_accepted_catalog",
    "zizmor_finding",
]


def isolated_config(tmp_path: Path):
    shutil.copy2(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    copy_containers(ROOT, tmp_path)
    return load_config(tmp_path / "appsec-review.toml")


def seed_accepted_catalog(
    run_root: Path,
    target_root: Path,
    *,
    files: list[dict[str, Any]],
    source_fingerprint: str = SOURCE_FP,
    include_context_manifest: bool = True,
    include_stale_ci_index: bool = False,
) -> dict[str, Any]:
    """Write an accepted job_target_catalog handoff (plus retrieval manifest when requested)."""

    def _art(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(path, dict(payload))
        return {
            "path": path.relative_to(run_root).as_posix(),
            "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size,
        }

    cat_attempt = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001"
    part_ref = _art(
        cat_attempt / "artifacts/partition.json",
        {"files": files, "target_artifacts": [], "gaps": []},
    )
    proj_ref = _art(cat_attempt / "artifacts/projects.json", {"projects": []})
    build_ref = _art(cat_attempt / "artifacts/builds.json", {"targets": []})
    cc_ref = _art(cat_attempt / "artifacts/compile_commands.json", {"files": []})
    cat_doc = _art(
        cat_attempt / "steps/publish_catalog/tasks/publish_handoff/target-catalog.json",
        {
            "schema": "appsec-review/target-catalog/1",
            "source_fingerprint": source_fingerprint,
            "artifacts": {
                "repository_discovery.partition_repository": part_ref,
                "repository_discovery.discover_projects": proj_ref,
                "build_discovery.catalog_build_targets": build_ref,
                "build_discovery.discover_compile_commands": cc_ref,
            },
        },
    )

    outputs_payload: dict[str, Any] = {"artifact": cat_doc}
    manifest_path: Path | None = None
    manifest_sha: str | None = None
    if include_context_manifest:
        cat_manifest = run_root / "data/indices/manifests/catalog-attempt_0001.json"
        shard_fp = "f" * 64
        shard_file = run_root / f"data/indices/source/source_files/{shard_fp}.sqlite"
        builder = IndexBuilder(
            shard_file,
            name="source",
            fingerprint=shard_fp,
            target_snapshot=source_fingerprint,
            shard_id="source_files",
        )
        for item in files:
            fid = LogicalIdentity.derive(
                EntityKind.SOURCE_FILE,
                source_fingerprint,
                {"path": item["path"], "sha256": item["sha256"]},
            )
            builder.add_entity(EntityRecord(fid, item["sha256"], item["path"], item["path"], dict(item)))
        builder.add_coverage("catalog", "complete", None)
        shard_sha = builder.build()
        indexes = [
            IndexIdentity(
                "source",
                "appsec-review/retrieval-index/2",
                shard_sha,
                shard_fp,
                shard_file.relative_to(run_root).as_posix(),
                {"job": "job_target_catalog", "producer": "catalog"},
                (),
                "source_files",
            ),
        ]
        if include_stale_ci_index:
            stale_fp = "e" * 64
            stale_file = run_root / f"data/indices/observations/ci_stale/{stale_fp}.sqlite"
            stale_builder = IndexBuilder(
                stale_file,
                name="observations",
                fingerprint=stale_fp,
                target_snapshot=source_fingerprint,
                shard_id="ci_stale",
            )
            stale_builder.add_coverage("stale", "complete", None)
            stale_sha = stale_builder.build()
            indexes.append(
                IndexIdentity(
                    "observations",
                    "appsec-review/retrieval-index/2",
                    stale_sha,
                    stale_fp,
                    stale_file.relative_to(run_root).as_posix(),
                    {"job": "job_ci_configuration_analysis", "producer": "stale"},
                    (),
                    "ci_stale",
                )
            )
        write_manifest(
            cat_manifest,
            run_id=run_root.name,
            target_snapshot=source_fingerprint,
            target_root=target_root,
            indexes=indexes,
        )
        manifest_path = cat_manifest
        manifest_sha = file_sha256(cat_manifest)
        outputs_payload["index_manifest"] = {
            "path": cat_manifest.relative_to(run_root).as_posix(),
            "sha256": manifest_sha,
        }

    cat_handoff = write_fixture_handoff(
        run_root,
        cat_attempt / "handoff.json",
        {
            "job_id": "job_target_catalog",
            "schema_identity": "appsec-review/target-catalog/1",
            "source_fingerprint": source_fingerprint,
            "outputs": {"publish_catalog.publish_handoff": outputs_payload},
        },
    )
    cat_sha = file_sha256(cat_handoff)
    atomic_json(
        cat_attempt.parent.parent / "latest.json",
        {
            "schema": "appsec-review/latest-handoff/1",
            "attempt_id": "attempt_0001",
            "handoff_path": cat_handoff.relative_to(run_root).as_posix(),
            "handoff_sha256": cat_sha,
        },
    )
    return {
        "job_target_catalog": cat_sha,
        "manifest_path": manifest_path,
        "manifest_sha256": manifest_sha,
    }


def make_unit_context(
    tmp_path: Path,
    *,
    unit_id: str = "ci_discovery.discover_definitions",
    repository_root: Path = ROOT,
    target_files: Mapping[str, bytes | str] | None = None,
    settings_override: Mapping[str, Any] | None = None,
    source_fingerprint: str = SOURCE_FP,
    catalog_fingerprint: str | None = None,
    outputs: Mapping[str, Any] | None = None,
    seed_catalog: bool = True,
    include_context_manifest: bool = True,
    include_stale_ci_index: bool = False,
) -> tuple[SimpleNamespace, list[dict[str, Any]], list[tuple[str, dict[str, Any]]]]:
    """Construct a fast, engine-free UnitContext for direct code-level unit calls."""
    run_root = tmp_path / "runs" / "run_0001"
    attempt_root = run_root / "data" / "jobs" / "job_ci_configuration_analysis" / "attempts" / "attempt_0001"
    step_id, task_id = unit_id.split(".", 1)
    unit_root = attempt_root / "steps" / step_id / "tasks" / task_id
    unit_root.mkdir(parents=True, exist_ok=True)

    target_root = tmp_path / "target"
    target_root.mkdir(parents=True, exist_ok=True)
    files_spec = (
        {".github/workflows/ci.yml": "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"}
        if target_files is None
        else dict(target_files)
    )
    catalog_files: list[dict[str, Any]] = []
    for rel, raw in sorted(files_spec.items()):
        data = raw.encode("utf-8") if isinstance(raw, str) else raw
        dest = target_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        catalog_files.append(
            {
                "path": rel,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
            }
        )

    settings: dict[str, Any] = {
        "enabled": True,
        "max_files": 128,
        "max_file_bytes": 1_048_576,
        "max_observations_per_tool": 5_000,
        **(dict(settings_override) if settings_override else {}),
    }

    steps_map: dict[str, Any] = {}
    for s_name, tasks in TOPOLOGY.items():
        task_objs = {t_name: SimpleNamespace(settings={}) for t_name in tasks}
        steps_map[s_name] = SimpleNamespace(tasks=task_objs, task=task_objs.__getitem__)

    job_cfg = SimpleNamespace(
        job_id="job_ci_configuration_analysis",
        settings=settings,
        steps=steps_map,
        step=steps_map.__getitem__,
    )

    config_dir = run_root / "data" / "configuration"
    config_dir.mkdir(parents=True, exist_ok=True)
    resolved_path = config_dir / "resolved.json"
    if not resolved_path.is_file():
        resolved_path.write_bytes(_BASE_RESOLVED_BYTES)
        atomic_json(config_dir / "manifest.json", {"resolved_sha256": _BASE_RESOLVED_SHA256})

    upstream_handoffs: dict[str, str] = {}
    manifest_path: Path | None = None
    manifest_sha: str | None = None
    if seed_catalog:
        seeded = seed_accepted_catalog(
            run_root,
            target_root,
            files=catalog_files,
            source_fingerprint=catalog_fingerprint or source_fingerprint,
            include_context_manifest=include_context_manifest,
            include_stale_ci_index=include_stale_ci_index,
        )
        upstream_handoffs["job_target_catalog"] = seeded["job_target_catalog"]
        manifest_path = seeded["manifest_path"]
        manifest_sha = seeded["manifest_sha256"]

    atomic_json(
        attempt_root / "claim.json",
        {
            "run_id": run_root.name,
            "job_id": "job_ci_configuration_analysis",
            "attempt_id": "attempt_0001",
            "attempt_path": attempt_root.relative_to(run_root).as_posix(),
            "repository_root": str(repository_root),
            "resolved_config_sha256": _BASE_RESOLVED_SHA256,
            "orchestration": {"system": "cli"},
            "upstream_handoffs": upstream_handoffs,
            "dataset_contract": dataset_contract(
                "job_ci_configuration_analysis",
                sorted({d.step for d in DATASETS}),
                DATASETS,
                job_contract=CONTRACT.document(),
            ),
        },
    )

    events: list[tuple[str, dict[str, Any]]] = []
    out_map = dict(outputs or {})
    unit = SimpleNamespace(
        unit_id=unit_id,
        step_id=step_id,
        task_id=task_id,
        unit_root=unit_root,
        output=out_map.__getitem__,
        job=SimpleNamespace(
            run_id=run_root.name,
            attempt_id="attempt_0001",
            run_root=run_root,
            attempt_root=attempt_root,
            repository_root=repository_root,
            target_root=target_root,
            source_fingerprint=source_fingerprint,
            orchestration={"system": "cli"},
            config=job_cfg,
            events=SimpleNamespace(write=lambda event_type, **details: events.append((event_type, details))),
            input_manifest_path=manifest_path,
            input_manifest_sha256=manifest_sha,
        ),
    )
    return unit, catalog_files, events


@contextmanager
def attempt_scope(unit: Any):
    """Activate SharedArtifacts provenance owner for direct unit-handler calls."""
    with publication_scope_for_owner(SharedArtifacts.for_job(unit.job)):
        yield
