"""Code-level unit tests for job_dependency_intelligence job.py and integration.py."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import asdict, replace
from importlib import import_module
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_dependency_intelligence import (
    JOB_ID, TOPOLOGY, build_job, load_accepted_dependency_intelligence,
)
from appsec_review.jobs.job_dependency_intelligence.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_dependency_intelligence.integration import (
    NativeSbomInfrastructureError, accepted_framework, collect_unity_inventory,
    convert_syft, gap as sbom_gap, member, publish_sbom, read_json, read_native_file,
    validate_publication,
)
from appsec_review.jobs.job_dependency_intelligence.job import (
    _evidence_packages, _safe_read, _target_dependencies, _validate_config,
)
from appsec_review.jobs.job_dependency_intelligence.native_sbom_contracts import (
    NativeInputIntegrityError, SpdxValidationError,
)
from appsec_review.jobs.job_dependency_intelligence.scorecard import (
    HttpResponse, ScorecardCacheError, ScorecardError,
)
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, write_manifest,
)
from appsec_review.runtime import JobContext, UnitContext
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256
from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner, reference
from tests.handoff_fixture import write_fixture_handoff


ROOT = Path(__file__).resolve().parents[3]
SNAPSHOT = "f" * 64
CREATED = "2026-10-28T00:00:00Z"
_BASE_CONFIG = load_config(ROOT / "appsec-review.toml")


def _write(root: Path, name: str, document: Any) -> dict[str, Any]:
    path = root / "data" / "native-sbom-fixtures" / name
    atomic_json(path, document)
    return reference(root, path)


def _framework(
    root: Path,
    job: str,
    outputs: dict[str, Any],
    artifacts: list[dict[str, Any]],
    *,
    snapshot: str = SNAPSHOT,
    attempt: str = "attempt_0001",
    started_at: str = CREATED,
) -> dict[str, Any]:
    path = root / "data" / "jobs" / job / "attempts" / attempt / "handoff.json"
    declared = import_module(f"appsec_review.jobs.{job}.datasets").DATASETS
    atomic_json(
        path.parent / "claim.json",
        {
            "dataset_contract": dataset_contract(
                job,
                sorted({item.step for item in declared} | {u.split(".")[0] for u in outputs}),
                declared,
            )
        },
    )
    write_fixture_handoff(
        root,
        path,
        {
            "status": "ACCEPTED",
            "job_id": job,
            "run_id": root.name,
            "attempt_id": attempt,
            "source_fingerprint": snapshot,
            "started_at": started_at,
            "outputs": outputs,
            "artifacts": artifacts,
        },
    )
    identity = reference(root, path)
    atomic_json(
        root / "data" / "jobs" / job / "latest.json",
        {"handoff_path": identity["path"], "handoff_sha256": identity["sha256"]},
    )
    return identity


def _manifest(
    root: Path,
    target: Path,
    name: str,
    *,
    observations: list[dict[str, Any]] | None = None,
    producer: str = "tool-syft",
    snapshot: str = SNAPSHOT,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = root / "data" / "indices" / f"{name}.sqlite"
    builder = IndexBuilder(
        path,
        name="observations" if name.startswith("observations") else "artifacts",
        fingerprint="a" * 64,
        target_snapshot=snapshot,
        shard_id=name,
    )
    for idx, obs in enumerate(observations or ()):
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"name": name, "i": idx})
        builder.add_entity(EntityRecord(identity, f"syft-{idx}", "package", "pkg", obs))
    digest = builder.build()
    index = IndexIdentity(
        builder.name,
        "appsec-review/retrieval-index/2",
        digest,
        "a" * 64,
        path.relative_to(root).as_posix(),
        {"producer": producer},
        (),
        name,
    )
    manifest_path = root / "data" / "indices" / f"{name}-manifest.json"
    write_manifest(manifest_path, run_id=root.name, target_snapshot=snapshot, target_root=target, indexes=(index,))
    return reference(root, manifest_path), [reference(root, path), reference(root, manifest_path)]


def _make_job_context(
    tmp_path: Path,
    *,
    target_root: Path | None = None,
    settings_override: dict[str, Any] | None = None,
    repository_root: Path | None = None,
    cache_root: Path | None = None,
    attempt_id: str = "attempt_0001",
) -> tuple[JobContext, Path, list[dict[str, Any]]]:
    repo = repository_root or ROOT
    run_root = tmp_path / "runs" / "2026-10-28-0001"
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / attempt_id
    attempt_root.mkdir(parents=True, exist_ok=True)
    config_dir = run_root / "data" / "configuration"
    config_dir.mkdir(parents=True, exist_ok=True)
    if repository_root is None:
        resolved_doc = json.loads(_BASE_CONFIG.resolved_json)
        sync_steps = resolved_doc.get("jobs", {}).get("job_third_party_data_sync", {}).get("steps", {})
        if "cve_bin_tool_db_build" in sync_steps:
            sync_steps["cve_bin_tool_db_build"]["settings"]["feed_root"] = (
                (tmp_path / "cve-bin-tool-feed").relative_to(repo).as_posix()
            )
        atomic_json(config_dir / "resolved.json", resolved_doc)
        resolved_sha = file_sha256(config_dir / "resolved.json")
    else:
        (config_dir / "resolved.json").write_bytes(_BASE_CONFIG.resolved_json)
        resolved_sha = _BASE_CONFIG.resolved_sha256
    atomic_json(config_dir / "manifest.json", {"resolved_sha256": resolved_sha})
    atomic_json(
        attempt_root / "claim.json",
        {
            "run_id": run_root.name,
            "job_id": JOB_ID,
            "attempt_id": attempt_id,
            "attempt_path": attempt_root.relative_to(run_root).as_posix(),
            "repository_root": str(repo),
            "resolved_config_sha256": resolved_sha,
            "orchestration": {"system": "cli"},
            "dataset_contract": dataset_contract(
                JOB_ID, sorted({d.step for d in DATASETS}), DATASETS, job_contract=CONTRACT.document()
            ),
        },
    )
    def _thaw(val: Any) -> Any:
        if isinstance(val, Mapping):
            return {k: _thaw(v) for k, v in val.items()}
        if isinstance(val, (list, tuple)):
            return [_thaw(x) for x in val]
        return val

    base_job_cfg = _BASE_CONFIG.jobs[JOB_ID]
    merged_settings = _thaw(base_job_cfg.settings)
    rel_cache = (cache_root or (tmp_path / "scorecard-cache")).relative_to(repo).as_posix()
    merged_settings["scorecard"] = {
        **merged_settings["scorecard"],
        "cache_root": rel_cache,
    }
    if settings_override:
        merged_settings.update(settings_override)
    job_cfg = replace(base_job_cfg, settings=merged_settings)
    events: list[dict[str, Any]] = []
    event_log = SimpleNamespace(
        write=lambda event_type, **details: events.append({"event_type": event_type, **details})
    )
    ctx = JobContext(
        run_id=run_root.name,
        attempt_id=attempt_id,
        trigger="manual",
        run_root=run_root,
        attempt_root=attempt_root,
        metadata_root=tmp_path / "metadata",
        repository_root=repo,
        target_root=target_root,
        source_fingerprint=SNAPSHOT,
        config=job_cfg,
        tools=_BASE_CONFIG.tools,
        orchestration={"system": "cli"},
        events=event_log,  # type: ignore[arg-type]
        contract=CONTRACT,
    )
    return ctx, run_root, events


@contextmanager
def _owner_scope(ctx: JobContext):
    with publication_scope_for_owner(SharedArtifacts.for_job(ctx)):
        yield


def _seed_upstreams(
    run_root: Path,
    target: Path,
    *,
    files: dict[str, bytes] | None = None,
    declared_dependencies: list[dict[str, Any]] | None = None,
    source_syft: bool = True,
    syft_gaps: list[str] | None = None,
    catalog_gaps: list[str] | None = None,
    exclusions: list[str] | None = None,
    receipts: list[dict[str, Any]] | None = None,
    receipt_extra_artifacts: list[dict[str, Any]] | None = None,
    language_gaps: list[str] | None = None,
    target_artifacts: list[dict[str, Any]] | None = None,
    artifact_gaps: list[str] | None = None,
    observations: list[dict[str, Any]] | None = None,
) -> None:
    target.mkdir(parents=True, exist_ok=True)
    file_map = files if files is not None else {
        "third_party/zlib/zlib.h": b'#define ZLIB_VERSION "1.3.1"\n',
        "third_party/zlib/README": b"Package: zlib\nVersion: 1.3.1\n",
    }
    catalog_files = []
    for relative, payload in file_map.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        catalog_files.append({"path": relative, "sha256": file_sha256(path), "size_bytes": len(payload)})
    partition = _write(
        run_root,
        "partition.json",
        {
            "schema": "appsec-review/repository-partition/1",
            "source_fingerprint": SNAPSHOT,
            "files": catalog_files,
            "gaps": catalog_gaps or [],
            "configured_exclusions": exclusions or [],
        },
    )
    dependencies = _write(
        run_root,
        "dependencies.json",
        {
            "schema": "appsec-review/dependency-catalog/1",
            "dependencies": declared_dependencies if declared_dependencies is not None else [],
        },
    )
    catalog = _write(
        run_root,
        "catalog.json",
        {
            "schema": "appsec-review/target-catalog/1",
            "source_fingerprint": SNAPSHOT,
            "artifacts": {
                "repository_discovery.partition_repository": partition,
                "component_discovery.catalog_dependencies": dependencies,
            },
        },
    )
    _framework(
        run_root,
        "job_target_catalog",
        {"publish_catalog.publish_handoff": {"artifact": catalog}},
        [partition, dependencies, catalog],
    )
    language = _write(
        run_root,
        "language.json",
        {
            "schema": "appsec-review/language-build-handoff/2",
            "source_fingerprint": SNAPSHOT,
            "receipts": receipts or [],
            "gaps": language_gaps or [],
        },
    )
    _framework(
        run_root,
        "job_language_build",
        {"acceptance.publish_handoff": {"artifact": language}},
        [language, *(receipt_extra_artifacts or [])],
    )
    artifact_manifest, artifact_members = _manifest(run_root, target, "artifact")
    artifact = _write(
        run_root,
        "artifact-index.json",
        {
            "schema": "appsec-review/artifact-indexing/1",
            "source_fingerprint": SNAPSHOT,
            "target_artifacts": target_artifacts or [],
            "gaps": artifact_gaps or [],
            "index_manifest": artifact_manifest,
        },
    )
    _framework(
        run_root,
        "job_artifact_indexing",
        {"acceptance.publish_handoff": {"artifact": artifact, "index_manifest": artifact_manifest}},
        [artifact, *artifact_members],
    )
    obs = observations if observations is not None else (
        [{"package": "zlib", "version": "1.3.1", "purl": "pkg:generic/zlib@1.3.1",
          "repository_url": "https://github.com/madler/zlib", "location": {"path": "third_party/zlib/zlib.h"}}]
        if file_map else []
    )
    evidence_manifest, evidence_members = _manifest(run_root, target, "observations", observations=obs)
    syft = _write(
        run_root,
        "syft.json",
        {
            "artifacts": [],
            "artifactRelationships": [],
            "descriptor": {"name": "syft", "version": "1.52.0"},
            "source": {"id": "test", "name": "fixture", "version": "", "type": "directory", "metadata": {"path": "/target"}},
            "schema": {"version": "16.1.10"},
        },
    )
    envelope = _write(
        run_root,
        "syft-evidence.json",
        {
            "schema": "appsec-review/static-tool-evidence/2",
            "target_fingerprint": SNAPSHOT,
            "source_inventory": syft,
            "raw_artifacts": [syft],
            "exclusions_and_gaps": syft_gaps or [],
        },
    )
    ev_outputs: dict[str, Any] = {"evidence_publication.publish_handoff": {"index_manifest": evidence_manifest}}
    if source_syft:
        ev_outputs["software_inventory.syft_scan"] = {"artifact": envelope, "terminal_status": "SUCCEEDED"}
    _framework(run_root, "job_evidence_collection", ev_outputs, [*evidence_members, syft, envelope])


def _converter(source: dict[str, Any], *, unit: UnitContext) -> dict[str, Any]:
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "fixture",
        "documentNamespace": "https://example.invalid/fixture",
        "creationInfo": {"creators": ["Tool: syft-1.52.0"], "created": CREATED},
        "packages": [],
    }
    path = unit.unit_root / "baseline.spdx.json"
    atomic_json(path, document)
    return {
        "document": document,
        "artifact": reference(unit.job.run_root, path),
        "source_artifact": source,
        "tool_identity": {"tool_id": "tool-syft", "image_id": "sha256:" + "a" * 64},
    }


def _publish_result_as_handoff(ctx: JobContext, result: dict[str, Any]) -> Path:
    claim_path = ctx.attempt_root / "claim.json"
    saved_claim = claim_path.read_bytes()
    artifacts: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for file_path in sorted(ctx.run_root.rglob("*")):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(ctx.run_root).as_posix()
        if rel.endswith("/claim.json") or rel.endswith("/latest.json") or rel.endswith("handoff.json"):
            continue
        ref = reference(ctx.run_root, file_path)
        key = (ref["path"], ref["sha256"])
        if key not in seen:
            seen.add(key)
            artifacts.append(ref)
    handoff_path = ctx.run_root / f"published-{ctx.attempt_id}-handoff.json"
    write_fixture_handoff(
        ctx.run_root,
        handoff_path,
        {
            "status": "ACCEPTED",
            "job_id": JOB_ID,
            "run_id": ctx.run_id,
            "attempt_id": ctx.attempt_id,
            "source_fingerprint": ctx.source_fingerprint,
            "started_at": CREATED,
            "outputs": result["outputs"],
            "artifacts": artifacts,
        },
    )
    claim_path.write_bytes(saved_claim)
    identity = reference(ctx.run_root, handoff_path)
    atomic_json(
        ctx.run_root / "data" / "jobs" / JOB_ID / "latest.json",
        {"handoff_path": identity["path"], "handoff_sha256": identity["sha256"]},
    )
    return handoff_path


def test_full_job_unit_graph_executes_and_validates_publication(tmp_path: Path) -> None:
    target = tmp_path / "target"
    ctx, run_root, events = _make_job_context(tmp_path, target_root=target)
    workspace = run_root / "build"
    ws_hdr = workspace / "vendor" / "zlib" / "zlib.h"
    ws_hdr.parent.mkdir(parents=True, exist_ok=True)
    ws_hdr.write_bytes(b'#define ZLIB_VERSION "1.2.13"\n')
    ws_readme = ws_hdr.parent / "README"
    ws_readme.write_bytes(b"Package: zlib\nVersion: 1.2.13\n")
    protected = _write(
        run_root,
        "commands.json",
        {
            "schema": "appsec-review/protected-compile-commands/1",
            "rows": [
                {"directory": "/workspace", "argv": ["cc", "-c", "-Ivendor/zlib", "-I/target/third_party/zlib", "main.c"]},
                {"directory": "/target/sub", "argv": ["cc", "-c", "sub.c"]},
            ],
        },
    )
    ws_manifest = _write(
        run_root,
        "workspace.json",
        {"files": {"vendor/zlib/zlib.h": file_sha256(ws_hdr), "vendor/zlib/README": file_sha256(ws_readme)}},
    )
    _seed_upstreams(
        run_root,
        target,
        declared_dependencies=[
            {"name": "requests", "version": "2.31.0", "ecosystem": "pypi",
             "repository_url": "https://github.com/psf/requests", "path": "requirements.txt"},
            {"name": "private-dep", "version": "1.0", "ecosystem": "npm",
             "repository_url": "https://internal.corp.example/org/private-dep", "path": "package.json"},
            {"name": "mystery-pkg", "version": "0.1", "ecosystem": "cargo", "path": "Cargo.toml"},
        ],
        receipts=[{
            "family": "native",
            "build_unit_id": "native-fixture",
            "workspace": "build",
            "protected_compile_commands": protected,
            "workspace_manifest": ws_manifest,
            "artifacts": [{"path": "build/lib/libz.so.1", "workspace_path": "lib/libz.so.1",
                           "loader_dependencies": ["libz.so.1"], "loader_soname": "libz.so.1"}],
        }],
        receipt_extra_artifacts=[protected, ws_manifest],
        target_artifacts=[{"path": "bin/app.so", "loader_dependencies": ["libcrypto.so.3"]}],
    )

    scorecard_payload = json.dumps({
        "score": 8.2,
        "date": "2026-10-01",
        "commit": "deadbeef",
        "checks": [{"name": "Maintained", "score": 10, "reason": "active"}],
    }).encode("utf-8")

    def transport(url: str, *, timeout_seconds: int, max_bytes: int) -> HttpResponse:
        if "madler" in url:
            return HttpResponse(404, b'{"message":"not found"}', {})
        return HttpResponse(200, scorecard_payload, {})

    def fake_infer(request, timeout_seconds: int):
        cid = request.summary.get("candidate", {}).get("candidate_id", "")
        if cid:
            return ModelResult({
                "schema": "appsec-review/native-dependency-resolution-proposal/1",
                "candidate_id": cid,
                "repository": None,
                "confidence": 0,
                "evidence_refs": [],
                "rationale": "none",
            })
        raise AssertionError("unexpected model schema")

    ctx_no_native_inf = replace(
        ctx,
        config=replace(
            ctx.config,
            settings={
                **ctx.config.settings,
                "native_inference": {**ctx.config.settings["native_inference"], "enabled": False},
            },
        ),
    )
    job = build_job(infer=fake_infer, scorecard_transport=transport, syft_converter=_converter)
    for validator in job.input_validators:
        validator(ctx_no_native_inf, {})
    with _owner_scope(ctx_no_native_inf):
        result = job.handler(ctx_no_native_inf)
    failed_units = {k: v for k, v in result["units"].items() if v["status"] != "SUCCEEDED"}
    assert not failed_units, failed_units
    assert result["outputs"]["inputs.load_accepted"]["terminal_status"] == "SUCCEEDED"
    assert result["outputs"]["resolution.detect_dependencies"]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["outputs"]["resolution.infer_repositories"]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["outputs"]["scorecards.fetch"]["terminal_status"] == "COMPLETED_WITH_GAPS"
    handoff_out = result["outputs"]["acceptance.publish_handoff"]
    assert handoff_out["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert handoff_out["item_count"] >= 3
    assert handoff_out["scorecard_count"] >= 1
    _publish_result_as_handoff(ctx_no_native_inf, result)
    accepted = load_accepted_dependency_intelligence(run_root)
    assert accepted["sbom"]["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    assert any(g.get("response_artifact") for g in accepted["gaps"] if isinstance(g, dict))

    # Second execution hits the local Scorecard cache populated on the first execution!
    ctx2, run_root2, _ = _make_job_context(
        tmp_path / "run2",
        target_root=target,
        cache_root=ctx_no_native_inf.repository_root / ctx_no_native_inf.config.settings["scorecard"]["cache_root"],
    )
    ctx2 = replace(
        ctx2,
        config=replace(
            ctx2.config,
            settings={**ctx2.config.settings, "native_inference": {**ctx2.config.settings["native_inference"], "enabled": False}},
        ),
    )
    _seed_upstreams(
        run_root2,
        target,
        declared_dependencies=[
            {"name": "requests", "version": "2.31.0", "ecosystem": "pypi",
             "repository_url": "https://github.com/psf/requests", "path": "requirements.txt"},
        ],
    )
    with _owner_scope(ctx2):
        result2 = job.handler(ctx2)
    assert result2["outputs"]["scorecards.fetch"]["cache_hit_count"] >= 1


def test_scorecard_cache_invalidation_and_write_failure_in_job_step(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "target"
    ctx, run_root, _ = _make_job_context(tmp_path, target_root=target)
    ctx = replace(
        ctx,
        config=replace(
            ctx.config,
            settings={**ctx.config.settings, "native_inference": {**ctx.config.settings["native_inference"], "enabled": False}},
        ),
    )
    _seed_upstreams(
        run_root,
        target,
        files={},
        declared_dependencies=[
            {"name": "requests", "version": "2.31.0", "ecosystem": "pypi",
             "repository_url": "https://github.com/psf/requests", "path": "requirements.txt"},
        ],
        source_syft=False,
    )
    payload = json.dumps({"score": 7.5, "checks": []}).encode("utf-8")
    monkeypatch.setattr(
        "appsec_review.jobs.job_dependency_intelligence.scorecard.ScorecardCache.load",
        lambda self, repo: (_ for _ in ()).throw(ScorecardCacheError("corrupt pointer")),
    )
    monkeypatch.setattr(
        "appsec_review.jobs.job_dependency_intelligence.scorecard.ScorecardCache.store",
        lambda self, repo, raw: (_ for _ in ()).throw(ScorecardCacheError("disk full")),
    )
    job = build_job(scorecard_transport=lambda *_a, **_kw: HttpResponse(200, payload, {}))
    with _owner_scope(ctx):
        result = job.handler(ctx)
    kinds = {g["kind"] for g in result["outputs"]["scorecards.fetch"]["gaps"]}
    assert {"scorecard_cache_invalid", "scorecard_cache_write_failure"} <= kinds


def test_validate_config_rejects_invalid_settings(tmp_path: Path) -> None:
    ctx, _, _ = _make_job_context(tmp_path)
    _validate_config(ctx, {})

    bad_steps = replace(ctx, config=replace(ctx.config, steps={"inputs": ctx.config.steps["inputs"]}))
    with pytest.raises(ValueError, match="topology does not match"):
        _validate_config(bad_steps, {})

    bad_tasks_step = replace(ctx.config.steps["inputs"], tasks={})
    bad_tasks = replace(ctx, config=replace(ctx.config, steps={**ctx.config.steps, "inputs": bad_tasks_step}))
    with pytest.raises(ValueError, match="task order mismatch"):
        _validate_config(bad_tasks, {})

    for override, match in [
        ({"dependency_limit": 0}, "deterministic bounds"),
        ({"dependency_limit": True}, "deterministic bounds"),
        ({"sbom_conversion_timeout_seconds": 0}, "SPDX conversion timeout"),
        ({"repository_hosts": []}, "repository host allowlist"),
        ({"repository_hosts": ["github.com", "github.com"]}, "repository host allowlist"),
        ({"model": None}, "model and Scorecard settings are required"),
        ({"model": {"enabled": True}}, "incomplete"),
        ({"model": {**ctx.config.settings["model"], "enabled": "yes"}}, "boolean"),
        ({"model": {**ctx.config.settings["model"], "provider": ""}}, "provider is invalid"),
        ({"model": {**ctx.config.settings["model"], "max_input_tokens": 0}}, "configured bounds"),
        ({"scorecard": {**ctx.config.settings["scorecard"], "max_requests": 0}}, "configured bounds"),
        ({"model": {**ctx.config.settings["model"], "retries": 6}}, "retry bounds"),
        ({"scorecard": {**ctx.config.settings["scorecard"], "retries": -1}}, "retry bounds"),
        ({"scorecard": {**ctx.config.settings["scorecard"], "cache_root": "/abs/path"}}, "repository-relative"),
        ({"scorecard": {**ctx.config.settings["scorecard"], "cache_root": "../escape"}}, "repository-relative"),
        ({"native_advisory_lookup": None}, "native_advisory_lookup settings must be a table"),
        ({"native_advisory_lookup": {"component_limit": 0, "rows_per_component": 1, "match_limit": 1}},
         "native_advisory_lookup bounds"),
        ({"native_advisory_lookup": {"component_limit": 1, "rows_per_component": 1}}, "native_advisory_lookup bounds"),
    ]:
        bad_ctx = replace(ctx, config=replace(ctx.config, settings={**ctx.config.settings, **override}))
        with pytest.raises(ValueError, match=match):
            _validate_config(bad_ctx, {})


def test_safe_read_and_upstream_helper_error_branches(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    with pytest.raises(ValueError, match="missing or outside"):
        _safe_read(run_root, {"path": "missing.json", "sha256": "0" * 64})
    p = run_root / "doc.json"
    p.write_bytes(b'{"a": 1}')
    with pytest.raises(ValueError, match="hash changed"):
        _safe_read(run_root, {"path": "doc.json", "sha256": "0" * 64, "size_bytes": p.stat().st_size})
    ref = reference(run_root, p)
    with pytest.raises(ValueError, match="exceeds its byte bound"):
        _safe_read(run_root, ref, max_bytes=2)
    with pytest.raises(ValueError, match="size changed"):
        _safe_read(run_root, {**ref, "size_bytes": 999})

    # Unsupported dependency catalog schema
    bad_deps = _write(run_root, "bad-deps.json", {"schema": "wrong/1", "dependencies": []})
    cat = _write(run_root, "cat.json", {"artifacts": {"component_discovery.catalog_dependencies": bad_deps}})
    _framework(run_root, "job_target_catalog", {"publish_catalog.publish_handoff": {"artifact": cat}}, [bad_deps, cat])
    with pytest.raises(ValueError, match="dependency catalog schema is unsupported"):
        _target_dependencies(run_root)

    # Evidence packages when index_manifest is missing or non-syft shard is skipped
    _framework(run_root, "job_evidence_collection", {"evidence_publication.publish_handoff": {}}, [])
    pkgs, _ = _evidence_packages(run_root)
    assert pkgs == []
    m_ref, m_members = _manifest(run_root, tmp_path, "observations-other", observations=[{"package": "ignored"}], producer="tool-semgrep")
    _framework(
        run_root, "job_evidence_collection",
        {"evidence_publication.publish_handoff": {"index_manifest": m_ref}},
        m_members, attempt="attempt_0002",
    )
    pkgs2, _ = _evidence_packages(run_root)
    assert pkgs2 == []


def test_convert_syft_and_integration_validation_branches(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "target"
    ctx, run_root, _ = _make_job_context(tmp_path, target_root=target)
    _seed_upstreams(run_root, target)
    unit_root = ctx.attempt_root / "steps" / "publication" / "tasks" / "publish_sbom"
    unit_root.mkdir(parents=True, exist_ok=True)
    unit = UnitContext(ctx, "publication.publish_sbom", "publication", "publish_sbom", unit_root, {})

    assert sbom_gap("input_missing", "scope", "detail")["kind"] == "input_missing"
    with pytest.raises(ValueError, match="unsupported native SBOM gap kind"):
        sbom_gap("not_a_gap", "scope", "detail")

    # member size mismatch & unbound
    ref = _write(run_root, "item.json", {"k": "v"})
    with pytest.raises(NativeInputIntegrityError, match="size binding changed"):
        member({"artifacts": [ref]}, {**ref, "size_bytes": ref["size_bytes"] + 1})
    with pytest.raises(NativeInputIntegrityError, match="not bound"):
        member({"artifacts": []}, ref)

    # read_json limit & non-object
    with pytest.raises(ValueError, match="exceeds its configured byte bound"):
        read_json(run_root, ref, 1)
    arr_path = run_root / "arr.json"
    arr_path.write_bytes(b"[1, 2]")
    arr_ref = reference(run_root, arr_path)
    with pytest.raises(ValueError, match="must be an object"):
        read_json(run_root, arr_ref, 1024)

    # accepted_framework limit
    with pytest.raises(ValueError, match="accepted handoff exceeds its byte bound"):
        accepted_framework(run_root, "job_target_catalog", 5)

    # collect_unity_inventory target_root None & symlink rejection
    no_target_ctx = replace(ctx, target_root=None)
    no_target_unit = UnitContext(no_target_ctx, "inputs.load_accepted", "inputs", "load_accepted", unit_root, {})
    pver = target / "ProjectSettings" / "ProjectVersion.txt"
    pver.parent.mkdir(parents=True, exist_ok=True)
    pver_bytes = b"m_EditorVersion: 2022.3.10f1\n"
    pver.write_bytes(pver_bytes)
    pman = target / "Packages" / "manifest.json"
    pman.parent.mkdir(parents=True, exist_ok=True)
    pman_bytes = b'{"dependencies": {"com.unity.ugui": "1.0.0"}}\n'
    pman.write_bytes(pman_bytes)
    files_list = [
        {
            "domain": "target", "root_id": "target",
            "path": "ProjectSettings/ProjectVersion.txt",
            "sha256": file_sha256(pver), "size_bytes": len(pver_bytes),
        },
        {
            "domain": "target", "root_id": "target",
            "path": "Packages/manifest.json",
            "sha256": file_sha256(pman), "size_bytes": len(pman_bytes),
        },
    ]
    no_root_unity = collect_unity_inventory(no_target_unit, files_list)
    assert any("descriptor_read_unavailable" in g for g in no_root_unity["gaps"])
    good_unity = collect_unity_inventory(unit, files_list)
    assert good_unity["projects"] and good_unity["projects"][0]["configuration_fingerprint"]

    sym_dir = tmp_path / "sym_target"
    sym_dir.mkdir()
    (sym_dir / "ProjectSettings").symlink_to(pver.parent)
    sym_ctx = replace(ctx, target_root=sym_dir)
    sym_unit = UnitContext(sym_ctx, "inputs.load_accepted", "inputs", "load_accepted", unit_root, {})
    sym_unity = collect_unity_inventory(sym_unit, files_list)
    assert any("descriptor_read_unavailable" in g for g in sym_unity["gaps"])

    # read_native_file target_root None & byte mismatch
    with pytest.raises(NativeInputIntegrityError, match="target source root is unavailable"):
        read_native_file(no_target_unit, files_list[0], 1024, {})  # type: ignore[arg-type]
    with pytest.raises(NativeInputIntegrityError, match="native source bytes changed"):
        read_native_file(unit, {**files_list[0], "sha256": "0" * 64}, 1024, {})  # type: ignore[arg-type]

    # convert_syft success + non-zero exit + infrastructure error + oversized source
    syft_src = _write(run_root, "syft-src.json", {"artifacts": []})
    with pytest.raises(NativeInputIntegrityError, match="integrity changed"):
        convert_syft({**syft_src, "sha256": "0" * 64}, unit=unit)

    small_ctx = replace(ctx, config=replace(ctx.config, settings={**ctx.config.settings, "sbom_input_bytes": 2}))
    small_unit = UnitContext(small_ctx, "publication.publish_sbom", "publication", "publish_sbom", unit_root, {})
    with pytest.raises(ValueError, match="exceeds conversion byte bound"):
        convert_syft(syft_src, unit=small_unit)

    valid_spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "converted",
        "documentNamespace": "https://example.invalid/converted",
        "creationInfo": {"creators": ["Tool: syft-1.52.0"], "created": CREATED},
        "packages": [],
    }
    exec_mode = {"fail_exec": False, "exit_code": 0}

    class FakeContainerExec:
        def __init__(self, catalog: Any, r_root: Path):
            self.r_root = r_root

        def resolve_image(self, tool: Any) -> str:
            if exec_mode["fail_exec"]:
                raise RuntimeError("docker down")
            return "sha256:" + "b" * 64

        def execute(self, req: Any) -> Any:
            req.scratch_root.mkdir(parents=True, exist_ok=True)
            atomic_json(req.scratch_root / "baseline.spdx.json", valid_spdx)
            rcpt = self.r_root / "data" / "native-sbom" / "rcpt.json"
            out = self.r_root / "data" / "native-sbom" / "out.txt"
            err = self.r_root / "data" / "native-sbom" / "err.txt"
            atomic_json(rcpt, {"exit_code": exec_mode["exit_code"]})
            atomic_bytes(out, b"")
            atomic_bytes(err, b"")
            code = exec_mode["exit_code"]
            return SimpleNamespace(
                tool_id="tool-syft", image_id="sha256:" + "b" * 64, exit_code=code,
                timed_out=False, oom_killed=False, file_size_limit_reached=False,
                stdout_path=out.relative_to(self.r_root).as_posix(),
                stderr_path=err.relative_to(self.r_root).as_posix(),
                receipt_path=rcpt.relative_to(self.r_root).as_posix(),
                terminal_status="SUCCEEDED" if code == 0 else "FAILED",
            )

    monkeypatch.setattr("appsec_review.jobs.job_dependency_intelligence.integration.ContainerExecutor", FakeContainerExec)
    converted = convert_syft(syft_src, unit=unit)
    assert converted["tool_identity"]["tool_id"] == "tool-syft"

    exec_mode["exit_code"] = 2
    with pytest.raises(RuntimeError, match="Syft SPDX conversion failed"):
        convert_syft(syft_src, unit=unit)

    exec_mode["fail_exec"] = True
    with pytest.raises(NativeSbomInfrastructureError, match="Syft conversion runtime unavailable"):
        convert_syft(syft_src, unit=unit)


def test_collect_inputs_and_publish_sbom_error_and_gap_branches(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "target"
    ctx, run_root, _ = _make_job_context(tmp_path, target_root=target)
    ctx = replace(
        ctx,
        config=replace(
            ctx.config,
            settings={**ctx.config.settings, "native_inference": {**ctx.config.settings["native_inference"], "enabled": False}},
        ),
    )
    protected = _write(
        run_root,
        "commands-gaps.json",
        {
            "schema": "appsec-review/protected-compile-commands/1",
            "rows": [
                {"directory": "/workspace", "argv": []},
                {"directory": "C:/unmapped", "argv": ["cc", "-c", "a.c"]},
            ],
        },
    )
    _seed_upstreams(
        run_root,
        target,
        files={},
        catalog_gaps=["cat-gap"],
        exclusions=["vendor/**"],
        receipts=[{
            "family": "native",
            "build_unit_id": "u1",
            "protected_compile_commands": protected,
            "artifacts": [],
        }],
        receipt_extra_artifacts=[protected],
        language_gaps=["lang-gap"],
        artifact_gaps=["art-gap"],
        syft_gaps=["syft-gap"],
    )
    job = build_job(syft_converter=lambda _s, *, unit: (_ for _ in ()).throw(RuntimeError("conv-boom")))
    monkeypatch.setattr(
        "appsec_review.jobs.job_dependency_intelligence.sbom.build_spdx",
        lambda **_kw: (_ for _ in ()).throw(SpdxValidationError("bad spdx")),
    )
    with _owner_scope(ctx):
        result = job.handler(ctx)
    sbom_out = result["outputs"]["publication.publish_sbom"]
    assert sbom_out["status"] == "FAILED"
    assert sbom_out["artifact"] is None
    gap_kinds = {g["kind"] for g in sbom_out["gaps"]}
    assert {"upstream_partial", "unsupported_metadata", "unmapped_path", "sbom_conversion_failed", "sbom_validation_failed"} <= gap_kinds
    h_path = _publish_result_as_handoff(ctx, result)
    accepted = load_accepted_dependency_intelligence(run_root)
    assert accepted["sbom"]["status"] == "FAILED"

    # Unbound handoff artifact & manifest checks in load_accepted_dependency_intelligence
    handoff_doc = json.loads(h_path.read_bytes())
    pub_path = handoff_doc["outputs"]["acceptance.publish_handoff"]["artifact"]["path"]
    manifest_path = accepted["index_manifest"]["path"]
    no_manifest = {**handoff_doc, "artifacts": [a for a in handoff_doc["artifacts"] if a["path"] != manifest_path]}
    atomic_json(h_path, no_manifest)
    atomic_json(run_root / "data/jobs" / JOB_ID / "latest.json",
                {"handoff_path": h_path.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(h_path)})
    with pytest.raises(ValueError, match="index manifest is not bound"):
        load_accepted_dependency_intelligence(run_root)

    no_pub = {**handoff_doc, "artifacts": [a for a in handoff_doc["artifacts"] if a["path"] != pub_path]}
    atomic_json(h_path, no_pub)
    atomic_json(run_root / "data/jobs" / JOB_ID / "latest.json",
                {"handoff_path": h_path.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(h_path)})
    with pytest.raises(ValueError, match="publication is not bound"):
        load_accepted_dependency_intelligence(run_root)
