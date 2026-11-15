"""Shared test fixtures and installer-record helpers for job_artifact_security_analysis."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace

from appsec_review.config import load_config
from appsec_review.jobs.delivery_scope import scope_fields
from appsec_review.jobs.job_artifact_security_analysis import build_job
from appsec_review.jobs.job_artifact_security_analysis import job as security
from appsec_review.jobs.job_artifact_security_analysis.scanners import ADAPTERS
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.retrieval.index import INDEX_SCHEMA
from appsec_review.runtime import JobRunner
from appsec_review.storage import RunStore, atomic_json, file_sha256
from tests.artifact_input_support import recorded_job
from tests.release_support import declare_releases


ROOT = Path(__file__).resolve().parents[3]

RECORD = "node_modules/.package-lock.json"
RECORD_METADATA = {
    "format": ".package-lock.json",
    "manager": "npm",
    "role": "installed-dependency-record",
}
INSTALLED = (
    ("node_modules/a", "a", "1.0.0", False),
    ("node_modules/b", "b", "2.0.0", True),
    ("node_modules/c/node_modules/a", "a", "1.0.0", False),
)


def _upstream_gaps(no_artifacts: bool, gap_records: bool) -> list:
    """The language-build handoff's gaps: free text, or producer-gap/1 records."""
    if not no_artifacts:
        return []
    if gap_records:
        from appsec_review.interchange import producer_gap

        return [
            producer_gap(
                "producer_reported_gap",
                "no produced artifacts",
                unit_id="acceptance.publish_handoff",
            )
        ]
    return ["no produced artifacts"]


def _fixture(
    tmp_path: Path,
    payload: bytes = b"\0asm\x01\0\0\0",
    *,
    disable_grype: bool = False,
    duplicate_artifact: bool = False,
    no_artifacts: bool = False,
    name: str = "module.wasm",
    kind: str = "wasm-module",
    declared_releases: bool = True,
    artifacts_factory=None,
    seed_accepted: bool = False,
    gap_records: bool = False,
):
    config_path = tmp_path / "appsec-review.toml"
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if declared_releases:
        components = (
            "platform",
            "validation",
            *(adapter.tool_id for adapter in ADAPTERS.values()),
        )
        text = declare_releases(text, **{key: "fixture/1" for key in components})
    if not disable_grype:
        text = text.replace("disable_grype = true", "disable_grype = false")
    config_path.write_text(text, encoding="utf-8")
    config = load_config(config_path)
    run_id, run_root = RunStore(config.runtime.runs_dir).create(datetime.now(timezone.utc))
    target = tmp_path / "target"
    target.mkdir()
    produced = run_root / "data" / "build" / "wasm" / name
    produced.parent.mkdir(parents=True)
    produced.write_bytes(payload)
    artifact = {
        "path": produced.relative_to(run_root).as_posix(),
        "workspace_path": f"build/{name}",
        "sha256": file_sha256(produced),
        "size_bytes": produced.stat().st_size,
        "kind": kind,
        "build_unit_id": "build-unit-fixture",
        "mapping": "exact-workspace-path",
        "mapping_confidence": 1.0,
    }
    artifacts = [] if no_artifacts else [artifact]
    if artifacts_factory is not None:
        artifacts = artifacts_factory(run_root)
    if duplicate_artifact:
        duplicate = run_root / "data" / "build" / "wasm" / "module-copy.wasm"
        duplicate.write_bytes(payload)
        artifacts.append(
            {
                **artifact,
                "path": duplicate.relative_to(run_root).as_posix(),
                "workspace_path": "build/module-copy.wasm",
            }
        )
    fingerprint = "a" * 64
    index_path = run_root / "data" / "indices" / "artifacts" / "catalog-fixture.sqlite"
    builder = IndexBuilder(
        index_path,
        name="artifacts",
        fingerprint="b" * 64,
        target_snapshot=fingerprint,
        shard_id="catalog-fixture",
    )
    index_sha = builder.build()
    index_identity = IndexIdentity(
        "artifacts",
        INDEX_SCHEMA,
        index_sha,
        "b" * 64,
        index_path.relative_to(run_root).as_posix(),
        {"job": "job_artifact_indexing", "unit": "index.fixture"},
        (),
        "catalog-fixture",
    )
    manifest_path = run_root / "data" / "indices" / "manifests" / "artifact-fixture.json"
    write_manifest(
        manifest_path,
        run_id=run_id,
        target_snapshot=fingerprint,
        target_root=target,
        indexes=[] if no_artifacts else [index_identity],
    )
    manifest = {
        "path": manifest_path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(manifest_path),
        "size_bytes": manifest_path.stat().st_size,
    }
    language_manifest_path = manifest_path.with_name("language-fixture.json")
    write_manifest(
        language_manifest_path,
        run_id=run_id,
        target_snapshot=fingerprint,
        target_root=target,
        indexes=[],
    )
    language_document = {
        "schema": "appsec-review/language-build-handoff/2",
        "source_fingerprint": fingerprint,
        "upstream_project_build_handoff_sha256": "c" * 64,
        "receipts": []
        if no_artifacts
        else [
            {
                "build_unit_id": "build-unit-fixture",
                "family": "wasm",
                "fingerprint": "d" * 64,
                "executor_identity": "fixture",
                "capture_identity": "fixture",
                "artifacts": artifacts,
            }
        ],
        "gaps": _upstream_gaps(no_artifacts, gap_records),
    }
    indexing_document = {
        "schema": "appsec-review/artifact-indexing/1",
        "source_fingerprint": fingerprint,
        "artifact_shard_count": 0 if no_artifacts else 1,
        "reused_shard_count": 0,
        "artifact_count": len(artifacts),
        "gaps": ["no produced artifacts"] if no_artifacts else [],
        "index_manifest": manifest,
    }
    seeds = run_root / "data/inputs/artifact-fixture"
    atomic_json(
        seeds / "job_language_build.json",
        {
            "document": language_document,
            "manifest": {
                "path": language_manifest_path.relative_to(run_root).as_posix(),
                "sha256": file_sha256(language_manifest_path),
            },
        },
    )
    atomic_json(
        seeds / "job_artifact_indexing.json",
        {"document": indexing_document, "manifest": manifest},
    )
    if seed_accepted:
        runner = JobRunner(config)
        language = runner.run(
            recorded_job(run_root, "job_language_build"),
            run_id=run_id,
            target_root=target,
            source_fingerprint=fingerprint,
        )
        runner.run(
            recorded_job(run_root, "job_artifact_indexing"),
            run_id=run_id,
            target_root=target,
            source_fingerprint=fingerprint,
            upstream_handoffs={"job_language_build": language["handoff_sha256"]},
        )
    return config, run_id, run_root, target, fingerprint, produced


def _installed_rows(root: Path, prefix: str = "data/build/node") -> list[dict]:
    """An npm installer record row and the verified anchor rows it records."""
    record_file = root / prefix / RECORD
    record_file.parent.mkdir(parents=True, exist_ok=True)
    record_file.write_text(
        json.dumps(
            {
                "name": "app",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app"},
                    "node_modules/mismatch": {"version": "1.0.0"},
                    **{
                        path: {"version": version, **({"dev": True} if dev else {})}
                        for path, _, version, dev in INSTALLED
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    common = {
        "build_unit_id": "build-unit-fixture",
        "mapping": "exact-workspace-path",
        "mapping_confidence": 1.0,
    }
    record = {
        **common,
        "path": record_file.relative_to(root).as_posix(),
        "workspace_path": RECORD,
        "sha256": file_sha256(record_file),
        "size_bytes": record_file.stat().st_size,
        "kind": "resolved-dependency-metadata",
        "scope_role": "runtime_dependency",
        "dependency_metadata": dict(RECORD_METADATA),
    }
    rows = [record]
    for install_path, name, version, dev in INSTALLED:
        manifest = root / prefix / install_path / "package.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({"name": name, "version": version}), encoding="utf-8")
        rows.append(
            {
                **common,
                "path": manifest.relative_to(root).as_posix(),
                "workspace_path": f"{install_path}/package.json",
                "sha256": file_sha256(manifest),
                "size_bytes": manifest.stat().st_size,
                "kind": "package-metadata",
                "scope_role": "build_dependency" if dev else "runtime_dependency",
                "delivery_evidence": {
                    "kind": "npm-installed-record",
                    "workspace_path": RECORD,
                    "sha256": record["sha256"],
                    "entry": install_path,
                },
                "package_metadata": {
                    "format": "package.json",
                    "role": "installed-dependency-package",
                    "ecosystem": "npm",
                    "manager": "npm",
                    "name": name,
                    "version": version,
                    "dev": dev,
                    "optional": False,
                    "dev_optional": False,
                    "install_path": install_path,
                },
            }
        )
    return rows


def _record_handlers(
    root: Path,
    rows: list[dict],
    monkeypatch,
    scan=None,
    capabilities=("syft", "grype", "osv"),
):
    """Run the analyze handlers over hand-built rows with a stubbed scan."""
    artifacts = [
        {
            **row,
            **scope_fields(row),
            "artifact_id": f"artifact-{index:02d}",
            "canonical_identity": f"fixture:{row['workspace_path']}",
        }
        for index, row in enumerate(rows)
    ]
    launched: list[tuple[str, str]] = []

    def fake_scan(unit, artifact, capability, runner):
        launched.append((capability, artifact["workspace_path"]))
        if scan is not None:
            return {"artifact": artifact, "terminal_status": "SUCCEEDED", **scan(capability, artifact)}
        return {"artifact": artifact, "gaps": [], "observation": {}, "terminal_status": "SUCCEEDED"}

    monkeypatch.setattr(security, "_scan_one", fake_scan)
    unit = SimpleNamespace(
        job=SimpleNamespace(run_root=root, tools=SimpleNamespace(disable_grype=False)),
        output=lambda _: {"artifacts": artifacts},
    )
    units = {item.unit_id: item for item in build_job(scanner_runner=lambda *args: None).units}
    return {capability: units[f"analyze.{capability}"].handler(unit) for capability in capabilities}, launched


def _covered_reason(capability: str, sha256: str) -> str:
    return (
        f"{capability} covers this package through one scan of installer record {RECORD} "
        f"(sha256 {sha256[:12]})"
    )
