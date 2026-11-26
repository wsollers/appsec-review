"""Unit tests for job.py: accepted-input validation, installer-record attribution, _scan_one, index, and loader."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.config.assurance import ComponentReleases, ReviewPolicy
from appsec_review.jobs.delivery_scope import scope_fields
from appsec_review.jobs.job_artifact_indexing import canonical_artifact_identity
from appsec_review.jobs.job_artifact_indexing.job import canonical_target_artifact_identity
from appsec_review.jobs.job_artifact_security_analysis import (
    build_job,
    load_accepted_artifact_security_analysis,
)
from appsec_review.jobs.job_artifact_security_analysis import job as security
from appsec_review.jobs.job_artifact_security_analysis.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_artifact_security_analysis.findings import RECORD_KIND_FINDING, Record
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.retrieval.index import INDEX_SCHEMA
from appsec_review.runtime import execution_safety as safety
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner, put_bytes
from tests.handoff_fixture import write_fixture_handoff

from .support import (
    INSTALLED,
    RECORD,
    RECORD_METADATA,
    ROOT,
    _covered_reason,
    _installed_rows,
    _record_handlers,
)


def _unit_context(
    run_root: Path,
    *,
    settings_override: dict | None = None,
    declared_releases: bool = True,
    disable_grype: bool = False,
    enable_cve_bin_tool: bool = True,
    source_fingerprint: str = "a" * 64,
    outputs: dict | None = None,
    unit_id: str = "analyze.syft",
    attempt_id: str = "attempt_0001",
) -> tuple[SimpleNamespace, list[tuple[str, dict]]]:
    config = load_config(ROOT / "appsec-review.toml")
    job_cfg = config.job("job_artifact_security_analysis")
    settings = {**job_cfg.settings, **(settings_override or {})}
    events: list[tuple[str, dict]] = []
    releases = (
        {
            "platform": "1",
            "validation": "1",
            **{f"tool-{k}": "1" for k in ("blint", "syft", "grype", "osv-scanner", "spotbugs", "cve-bin-tool")},
        }
        if declared_releases
        else {}
    )
    attempt_root = run_root / "data/jobs/job_artifact_security_analysis/attempts" / attempt_id
    attempt_root.mkdir(parents=True, exist_ok=True)
    claim_path = attempt_root / "claim.json"
    if not claim_path.is_file():
        atomic_json(
            claim_path,
            {
                "run_id": run_root.name,
                "job_id": "job_artifact_security_analysis",
                "attempt_id": attempt_id,
                "attempt_path": attempt_root.relative_to(run_root).as_posix(),
                "orchestration": {"system": "cli"},
                "dataset_contract": dataset_contract(
                    "job_artifact_security_analysis", sorted({d.step for d in DATASETS}), DATASETS
                ),
            },
        )
    default_outputs = {
        "load.accepted_artifacts": {
            "language_build_handoff_sha256": "b" * 64,
            "artifact_index": {"path": "data/indices/manifests/art.json", "sha256": "c" * 64},
            "artifacts": [],
            "producer_gaps": [],
        }
    }
    merged = {**default_outputs, **(outputs or {})}
    ctx = SimpleNamespace(
        unit_id=unit_id,
        unit_root=attempt_root / "steps/analyze/tasks/syft",
        job=SimpleNamespace(
            run_id=run_root.name,
            attempt_id=attempt_id,
            run_root=run_root,
            attempt_root=attempt_root,
            repository_root=ROOT,
            target_root=run_root,
            source_fingerprint=source_fingerprint,
            orchestration={"system": "cli"},
            config=SimpleNamespace(job_id="job_artifact_security_analysis", settings=settings),
            tools=SimpleNamespace(disable_grype=disable_grype, enable_cve_bin_tool=enable_cve_bin_tool),
            review_policy=ReviewPolicy(releases=ComponentReleases(values=releases)),
            events=SimpleNamespace(write=lambda name, **kw: events.append((name, kw))),
        ),
        output=merged.__getitem__,
    )
    return ctx, events


def _seed_artifact(
    run_root: Path,
    rel: str = "data/build/u/app.elf",
    payload: bytes = b"\x7fELF\x02\x01" + b"\0" * 32,
    **extra,
) -> dict:
    path = run_root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    base = {
        "path": rel,
        "workspace_path": Path(rel).name,
        "sha256": file_sha256(path),
        "size_bytes": path.stat().st_size,
        "kind": "executable",
        "build_unit_id": "u1",
        "producer": {"build_unit_id": "u1", "family": "native"},
        "canonical_identity": f"asr:native_binary:{Path(rel).stem}",
        "artifact_id": f"artifact-{Path(rel).stem}",
        **extra,
    }
    return {**base, **scope_fields(base)}


@pytest.mark.parametrize("mode", ["native-limit", "stdout-limit", "file-limit", "complete"])
def test_configured_scan_bounds_flow_through_real_runner_and_provenance(tmp_path, monkeypatch, mode):
    from appsec_review.container_runtime import ContainerExecutor
    from appsec_review.jobs.job_artifact_security_analysis.findings import scan_records
    from appsec_review.provenance import validate_observation_provenance

    ctx, _ = _unit_context(tmp_path / "run", settings_override={
        "timeout_seconds": 1, "stream_limit_bytes": 8, "parser_input_limit_bytes": 32})
    artifact = _seed_artifact(ctx.job.run_root)
    ctx.output("load.accepted_artifacts")["artifacts"] = [artifact]
    monkeypatch.setattr(ContainerExecutor, "resolve_image", lambda *args: "sha256:" + "1" * 64)
    payload = b'{"artifacts":[]}' + (b" " * 64 if mode == "native-limit" else b"")
    requests = []

    def execute(executor, request):
        requests.append(request)
        tool = executor.catalog.tool(request.tool_id)
        assert tool.timeout_seconds == 1 and tool.output_bytes == 8
        assert request.file_size_limit_bytes == 32
        scratch = request.scratch_root
        stdout = payload if mode == "stdout-limit" else b""
        (scratch / "stdout.bin").write_bytes(stdout)
        (scratch / "stderr.bin").write_bytes(b"")
        (scratch / "execution.json").write_bytes(b'{"exit_code":0}')
        if mode != "stdout-limit":
            (scratch / "output.json").write_bytes(payload)
        relative = scratch.relative_to(ctx.job.run_root).as_posix()
        return SimpleNamespace(
            stdout_path=relative + "/stdout.bin", stderr_path=relative + "/stderr.bin",
            receipt_path=relative + "/execution.json", stdout_truncated=False, stderr_truncated=False,
            exit_code=0, timed_out=False, file_size_limit_reached=mode == "file-limit")

    monkeypatch.setattr(ContainerExecutor, "execute", execute)
    handler = next(unit.handler for unit in build_job().units if unit.unit_id == "analyze.syft")
    with publication_scope_for_owner(SharedArtifacts.for_job(ctx.job)):
        result = handler(ctx)
        [scan] = result["observations"]
        summary, findings = scan_records(scan)
        validate_observation_provenance(ctx.job.run_root, [summary.payload],
                                        parser_identity=security.PARSER_IDENTITY)
    assert len(requests) == 1 and findings == ()
    reference = scan["native_output"]
    retained = ctx.job.run_root / reference["artifact"]["path"]
    expected = payload[:8] if mode == "stdout-limit" else payload[:32]
    assert retained.read_bytes() == expected
    assert reference["artifact"]["sha256"] == file_sha256(retained)
    assert reference["complete"] is (mode == "complete")
    if mode == "complete":
        assert scan["gaps"] == [] and summary.payload["scan_outcome"] == "completed"
    else:
        assert scan["terminal_status"] == "COMPLETED_WITH_GAPS"
        assert any("native parser input was truncated" in gap for gap in scan["gaps"])
        assert summary.payload["scan_outcome"] == "not_completed"
        if mode == "file-limit":
            assert any("file size limit was reached" in gap for gap in scan["gaps"])


@pytest.mark.parametrize("mode", ["finding", "empty", "error", "bad-record", "malformed"])
def test_blint_native_directory_contract_is_validated_before_assembly(tmp_path, monkeypatch, mode):
    from fnmatch import fnmatch
    from appsec_review.container_runtime import ContainerExecutor
    from appsec_review.jobs.job_artifact_security_analysis.findings import scan_records
    from appsec_review.provenance import validate_observation_provenance

    ctx, _ = _unit_context(tmp_path / "run", unit_id="analyze.blint")
    artifact = _seed_artifact(ctx.job.run_root)
    ctx.output("load.accepted_artifacts")["artifacts"] = [artifact]
    monkeypatch.setattr(ContainerExecutor, "resolve_image", lambda *args: "sha256:" + "1" * 64)
    reports = {
        "finding": b'{"scan_id":"fixture","findings":[{"id":"CHECK_NX","severity":"HIGH","filename":"/target/app"}]}',
        "error": b'{"error":"analysis failed"}',
        "bad-record": b'{"findings":[null]}',
        "malformed": b'{"findings":[',
    }

    def execute(executor, request):
        scratch = request.scratch_root
        (scratch / "app-metadata.json").write_bytes(b'{"file_path":"/target/app","has_nx":false}')
        if mode != "empty":
            (scratch / "findings.json").write_bytes(reports[mode])
        (scratch / "stdout.bin").write_bytes(b"")
        (scratch / "stderr.bin").write_bytes(b"")
        (scratch / "execution.json").write_bytes(b'{"exit_code":0}')
        relative = scratch.relative_to(ctx.job.run_root).as_posix()
        return SimpleNamespace(
            stdout_path=relative + "/stdout.bin", stderr_path=relative + "/stderr.bin",
            receipt_path=relative + "/execution.json", stdout_truncated=False, stderr_truncated=False,
            exit_code=0, timed_out=False)

    monkeypatch.setattr(ContainerExecutor, "execute", execute)
    handler = next(unit.handler for unit in build_job().units if unit.unit_id == "analyze.blint")
    with publication_scope_for_owner(SharedArtifacts.for_job(ctx.job)):
        [scan] = handler(ctx)["observations"]
        summary, findings = scan_records(scan)
        validate_observation_provenance(ctx.job.run_root, [r.payload for r in (summary, *findings)],
                                        parser_identity=security.PARSER_IDENTITY)
    if mode in {"finding", "empty"}:
        assert scan["gaps"] == [] and summary.payload["findings_complete"] is True
        assert len(findings) == (1 if mode == "finding" else 0)
        if findings:
            ref = findings[0].payload["common"]["evidence_refs"][0]
            assert ref["selector"] == {"kind": "json_pointer", "value": "/findings/0"}
            native = ctx.job.run_root / ref["artifact"]["path"]
            assert native.read_bytes() == reports["finding"]
            assert file_sha256(native) == ref["artifact"]["sha256"]
    else:
        assert scan["terminal_status"] == "COMPLETED_WITH_GAPS"
        assert any("parse or execution failure" in gap for gap in scan["gaps"])
        assert summary.payload["findings_complete"] is False and not findings
        [raw] = ctx.unit_root.glob("containers/*/*/findings.json")
        assert raw.read_bytes() == reports[mode]
    for path in sorted(ctx.unit_root.rglob("*")):
        if path.is_file():
            relative = path.relative_to(ctx.job.run_root).as_posix()
            owners = [d for d in DATASETS if any(fnmatch(relative, glob) for glob in d.artifacts)]
            assert [(d.output_kind, d.disposition) for d in owners] == [("artifact_scanner_io", "protected")]


def test_safe_file_and_accepted_artifacts_enforce_lineage_custody_and_target_intake(
    tmp_path: Path, monkeypatch
) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    f = run_root / "data/build/bin"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"abcd")
    good_ref = {
        "path": "data/build/bin",
        "workspace_path": "bin",
        "kind": "executable",
        "sha256": file_sha256(f),
        "size_bytes": 4,
    }
    assert security._safe_file(run_root, good_ref) == f

    sym = run_root / "data/build/sym"
    sym.symlink_to(f)
    for bad in (
        {"path": "../outside", "sha256": good_ref["sha256"]},
        {"path": "data/build/missing", "sha256": good_ref["sha256"]},
        {"path": "data/build/sym", "sha256": good_ref["sha256"]},
        {**good_ref, "sha256": "0" * 64},
        {**good_ref, "size_bytes": 99},
    ):
        with pytest.raises(security.FrameworkIntegrityError):
            security._safe_file(run_root, bad)

    # Build a verified artifact index shard + manifest for _accepted_artifacts
    fp = "a" * 64
    shard = run_root / "data/indices/artifacts/s.sqlite"
    sha = IndexBuilder(shard, name="artifacts", fingerprint="b" * 64, target_snapshot=fp, shard_id="s").build()
    idx_id = IndexIdentity(
        "artifacts", INDEX_SCHEMA, sha, "b" * 64, shard.relative_to(run_root).as_posix(), {"job": "j"}, (), "s"
    )
    manifest_path = run_root / "data/indices/manifests/m.json"
    write_manifest(manifest_path, run_id="r1", target_snapshot=fp, target_root=run_root, indexes=[idx_id])
    manifest_ref = {
        "path": manifest_path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(manifest_path),
        "size_bytes": manifest_path.stat().st_size,
    }
    empty_manifest_path = run_root / "data/indices/manifests/empty.json"
    write_manifest(empty_manifest_path, run_id="r1", target_snapshot=fp, target_root=run_root, indexes=[])
    empty_manifest_ref = {
        "path": empty_manifest_path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(empty_manifest_path),
        "size_bytes": empty_manifest_path.stat().st_size,
    }

    shared_ref = put_bytes(run_root, b"\0asm\x01\0\0\0")
    intake_base = {
        **shared_ref,
        "workspace_path": "vendor/mod.wasm",
        "kind": "wasm",
        "artifact_origin": "target-intake",
        "scope_role": "unknown",
        "source_fingerprint": fp,
        "target_relative_path": "vendor/mod.wasm",
        "producer": {"handoff_sha256": "cat" + "0" * 61},
    }
    intake_row = {
        **intake_base,
        "canonical_identity": canonical_target_artifact_identity(fp, intake_base).value,
    }

    lb_base = {
        "source_fingerprint": fp,
        "language_build_handoff_sha256": "lb" + "0" * 62,
        "receipts": [{"build_unit_id": "u1", "family": "native", "artifacts": [good_ref, good_ref]}],
        "gaps": [{"schema": "appsec-review/producer-gap/1", "reason": "upstream gap"}],
    }
    ai_base = {
        "source_fingerprint": fp,
        "language_build_handoff_sha256": "lb" + "0" * 62,
        "handoff_sha256": "ai" + "0" * 62,
        "target_catalog_handoff_sha256": "cat" + "0" * 61,
        "index_manifest": manifest_ref,
        "target_artifacts": [intake_row],
        "artifact_count": 2,
        "artifact_shard_count": 1,
        "gaps": ["idx gap"],
    }
    monkeypatch.setattr(security, "load_accepted_language_build", lambda r: lb_out)
    monkeypatch.setattr(security, "load_accepted_artifact_index", lambda r: ai_out)

    lb_out, ai_out = lb_base, ai_base
    loaded = security._accepted_artifacts(run_root)
    assert len(loaded["artifacts"]) == 2  # duplicate good_ref deduplicated + 1 target-intake
    assert "upstream gap" in loaded["producer_gaps"] and "idx gap" in loaded["producer_gaps"]

    # Empty artifacts adds explicit unavailable gap
    lb_out = {**lb_base, "receipts": []}
    ai_out = {**ai_base, "target_artifacts": [], "artifact_count": 0, "artifact_shard_count": 0, "index_manifest": empty_manifest_ref}
    empty_loaded = security._accepted_artifacts(run_root)
    assert "no target or produced artifacts were available for artifact security analysis" in empty_loaded["producer_gaps"]

    # Error branches in _accepted_artifacts
    error_pairs = [
        (lb_base, {**ai_base, "language_build_handoff_sha256": "wrong"}, "does not bind"),
        (lb_base, {**ai_base, "source_fingerprint": "wrong"}, "target snapshot differs"),
        (lb_base, {**ai_base, "index_manifest": None}, "manifest is unavailable"),
        ({**lb_base, "receipts": ["bad"]}, ai_base, "receipt is invalid"),
        ({**lb_base, "receipts": [{"artifacts": ["bad"]}]}, ai_base, "artifact identity is invalid"),
        (
            {**lb_base, "receipts": [{"artifacts": [{**good_ref, "scope_role": "supplied_platform"}]}]},
            ai_base,
            "platform content entered",
        ),
        (lb_base, {**ai_base, "target_artifacts": [{**intake_row, "scope_role": "customer"}]}, "intake provenance is invalid"),
        (lb_base, {**ai_base, "target_artifacts": [{**intake_row, "canonical_identity": "wrong"}]}, "index identity changed"),
        (lb_base, {**ai_base, "index_manifest": empty_manifest_ref}, "has no artifacts shard"),
    ]
    for lb_err, ai_err, match in error_pairs:
        lb_out, ai_out = lb_err, ai_err
        with pytest.raises(security.FrameworkIntegrityError, match=match):
            security._accepted_artifacts(run_root)

    # load unit snapshot mismatch
    lb_out, ai_out = lb_base, ai_base
    ctx, _ = _unit_context(run_root, source_fingerprint="f" * 64)
    load_unit = next(u for u in build_job().units if u.unit_id == "load.accepted_artifacts")
    with pytest.raises(security.FrameworkIntegrityError, match="target snapshot differs"):
        load_unit.handler(ctx)


def test_runtime_dependency_and_installer_record_unit_wiring(tmp_path: Path, monkeypatch) -> None:
    payload = tmp_path / "node_modules" / "express" / "package.json"
    payload.parent.mkdir(parents=True)
    payload.write_text('{"name":"express","version":"4.19.2"}', encoding="utf-8")
    addon = tmp_path / "node_modules" / "sharp" / "build" / "Release" / "sharp.node"
    addon.parent.mkdir(parents=True)
    addon.write_bytes(b"\x7fELF-native-addon")
    evidence = {"kind": "npm-installed-record", "entry": "node_modules/express"}
    artifact = {
        "path": "node_modules/express/package.json",
        "workspace_path": "node_modules/express/package.json",
        "kind": "package-metadata",
        "sha256": file_sha256(payload),
        "artifact_id": "runtime-dep",
        "scope_role": "runtime_dependency",
        "delivery_evidence": evidence,
    }
    binary = {
        "path": "node_modules/sharp/build/Release/sharp.node",
        "workspace_path": "node_modules/sharp/build/Release/sharp.node",
        "kind": "native-addon",
        "sha256": file_sha256(addon),
        "artifact_id": "runtime-addon",
        "scope_role": "runtime_dependency",
        "delivery_evidence": {**evidence, "entry": "node_modules/sharp"},
    }
    dev_binary = {**binary, "artifact_id": "dev-addon", "scope_role": "build_dependency"}
    scanned: list[tuple[str, str]] = []

    original_scan = security._scan_one
    monkeypatch.setattr(
        security,
        "classify",
        lambda path, row, **kwargs: (
            {"family": "native", "format": "elf"}
            if row["kind"] == "native-addon"
            else {"family": "node", "format": "json"}
        ),
    )
    monkeypatch.setattr(
        security,
        "_scan_one",
        lambda unit, row, cap, runner: (
            scanned.append((cap, row["artifact_id"]))
            or {"artifact": row, "gaps": [], "terminal_status": "SUCCEEDED"}
        ),
    )
    unit = SimpleNamespace(
        job=SimpleNamespace(run_root=tmp_path, tools=SimpleNamespace(disable_grype=False, enable_cve_bin_tool=True)),
        output=lambda _: {"artifacts": [artifact, binary, dev_binary]},
    )
    units = {item.unit_id: item for item in build_job(scanner_runner=lambda *args: None).units}
    assert units["analyze.packages"].handler(unit)["observation_count"] == 1
    assert units["analyze.native"].handler(unit)["observation_count"] == 0
    assert units["analyze.blint"].handler(unit)["observation_count"] == 1
    assert scanned == [("packages", "runtime-dep"), ("blint", "runtime-addon")]
    with pytest.raises(security.FrameworkIntegrityError, match="scope excludes native"):
        original_scan(unit, artifact, "native", None)

    # Configured disabled grype
    disabled_ctx, events = _unit_context(tmp_path, disable_grype=True, unit_id="analyze.grype")
    disabled_res = units["analyze.grype"].handler(disabled_ctx)
    assert disabled_res["terminal_status"] == "NOT_APPLICABLE"
    assert disabled_res["coverage_disposition"] == "CONFIGURED_DISABLED"
    assert events[0][0] == "TOOL_CONFIGURED_DISABLED"

    # Configured disabled cve-bin-tool: the same named gap shape, keyed to its own tool id
    off_ctx, off_events = _unit_context(tmp_path, enable_cve_bin_tool=False, unit_id="analyze.cve_bin_tool")
    off_res = units["analyze.cve_bin_tool"].handler(off_ctx)
    assert off_res["terminal_status"] == "NOT_APPLICABLE"
    assert off_res["coverage_disposition"] == "CONFIGURED_DISABLED"
    assert off_res["gaps"] == ["cve-bin-tool artifact coverage was configured disabled by tools.enable_cve_bin_tool"]
    assert off_events[0][0] == "TOOL_CONFIGURED_DISABLED" and off_events[0][1]["tool_id"] == "tool-cve-bin-tool"

    # _applicable built-in and adapter branches
    assert security._applicable("inventory", {}) is True
    assert security._applicable("native", {"family": "native"}) is True
    assert security._applicable("jvm", {"family": "jvm"}) is True
    assert security._applicable("wasm", {"family": "wasm"}) is True
    assert security._applicable("packages", {"family": "node"}) is True
    assert security._applicable("unknown_cap", {}) is False
    assert security._applicable("blint", {"format": "elf"}, name="app.elf") is True

    # Non-record finding in _attribute / _matched_anchors returns untouched / []
    unrelated_rec = Record(
        RECORD_KIND_FINDING,
        {"k": "nr"},
        "nnr",
        "cnr",
        "tnr",
        {"capability": "grype", "artifact": {"canonical_identity": "asr:other"}, "package_name": "a", "package_version": "1.0.0"},
    )
    assert security._attribute(unrelated_rec, {}) == unrelated_rec
    assert security._matched_anchors(unrelated_rec, {}) == []

    # SKIPPED_NA propagation inside analyze(osv) + default ContainerScannerRunner instantiation when scanner_runner=None
    monkeypatch.setattr(
        security,
        "_scan_one",
        lambda u, row, cap, runner: {
            "artifact": row,
            "gaps": [],
            "terminal_status": "SKIPPED_NA",
            "not_applicable": {
                "path": row["artifact_id"],
                "tool": "artifact:tool-osv-scanner",
                "disposition": "SKIPPED_NA",
                "reason_code": "OSV_NO_PACKAGE_SOURCES",
                "reason": "no sources",
            },
            "result_artifact": {"relative_path": "r.json"},
            "native_output": {"relative_path": "n.json"},
            "native_reports": [],
            "execution_receipt": {"relative_path": "e.json"},
        },
    )
    monkeypatch.setattr(security, "classify", lambda path, row, **kwargs: {"family": "rust", "format": "lockfile"})
    cargo_file = tmp_path / "Cargo.lock"
    cargo_file.write_text("version = 3\n", encoding="utf-8")
    lock_row = {
        **artifact,
        "path": "Cargo.lock",
        "workspace_path": "Cargo.lock",
        "sha256": file_sha256(cargo_file),
        "artifact_id": "cargo-lock",
    }
    lock_unit = SimpleNamespace(
        job=SimpleNamespace(run_root=tmp_path, tools=SimpleNamespace(disable_grype=False, enable_cve_bin_tool=True)),
        output=lambda _: {"artifacts": [lock_row]},
    )
    na_res = units["analyze.osv"].handler(lock_unit)
    assert na_res["not_applicable_inputs"]["count"] == 1
    assert len(na_res["not_applicable_scan_artifacts"]) == 1

    created_runners: list[tuple] = []
    monkeypatch.setattr(
        security,
        "ContainerScannerRunner",
        lambda *args, **kw: created_runners.append((args, kw)) or (lambda *a: None),
    )
    monkeypatch.setattr(
        security,
        "_scan_one",
        lambda u, row, cap, runner: {"artifact": row, "gaps": [], "terminal_status": "SUCCEEDED"},
    )
    default_ctx, _ = _unit_context(
        tmp_path,
        outputs={"load.accepted_artifacts": {"artifacts": [binary], "producer_gaps": []}},
    )
    monkeypatch.setattr(security, "classify", lambda path, row, **kwargs: {"family": "native", "format": "elf"})
    next(u for u in build_job().units if u.unit_id == "analyze.blint").handler(default_ctx)
    assert len(created_runners) == 1


def test_installer_record_coverage_gaps_and_bounded_attribution(tmp_path: Path, monkeypatch) -> None:
    rows = _installed_rows(tmp_path)
    outputs, launched = _record_handlers(tmp_path, rows, monkeypatch)
    assert launched == [("syft", RECORD), ("grype", RECORD), ("osv", RECORD)]
    record_sha = rows[0]["sha256"]
    for capability in ("syft", "grype"):
        assert outputs[capability]["not_applicable_inputs"]["by_reason"] == {
            _covered_reason(capability, record_sha): 3
        }
    assert outputs["osv"]["not_applicable_inputs"]["count"] == 3
    assert security._artifact_name(rows[0]) == "package-lock.json"
    assert security._artifact_name({**rows[0], "dependency_metadata": {**RECORD_METADATA, "manager": "yarn"}}) == ".package-lock.json"
    assert security._artifact_name({"artifact_origin": "target-intake", "target_relative_path": "sub/Cargo.lock"}) == "Cargo.lock"

    # Absent / mismatched covering record scans anchors directly
    _, launched_absent = _record_handlers(tmp_path / "abs", _installed_rows(tmp_path / "abs")[1:], monkeypatch)
    assert len(launched_absent) == 6  # 3 anchors * (syft, grype)

    # Native addon is not covered by installer record
    addon_root = tmp_path / "addon"
    addon_rows = _installed_rows(addon_root)
    addon = addon_root / "data/build/node/node_modules/a/build/Release/addon.node"
    addon.parent.mkdir(parents=True)
    addon.write_bytes(b"\x7fELF-native-addon")
    addon_rows.append(
        {
            **{k: addon_rows[1][k] for k in ("build_unit_id", "mapping", "mapping_confidence", "scope_role", "delivery_evidence")},
            "path": addon.relative_to(addon_root).as_posix(),
            "workspace_path": "node_modules/a/build/Release/addon.node",
            "sha256": file_sha256(addon),
            "size_bytes": addon.stat().st_size,
            "kind": "native-addon",
        }
    )
    _, addon_launched = _record_handlers(addon_root, addon_rows, monkeypatch, capabilities=("syft", "grype"))
    assert ("syft", "node_modules/a/build/Release/addon.node") in addon_launched

    # Gaps for dev shortfall, unreported syft anchors, and incomplete scans
    gap_outputs, _ = _record_handlers(
        tmp_path,
        rows,
        monkeypatch,
        scan=lambda cap, art: {
            "gaps": [],
            "observation": {"artifacts": [{"name": "a", "version": "1.0.0"}]} if cap == "syft" else {"matches": []},
        },
    )
    assert "1 dev-only packages" in gap_outputs["grype"]["gaps"][0]
    assert "1 of 3 verified packages" in gap_outputs["syft"]["gaps"][0]

    timeout_outputs, _ = _record_handlers(
        tmp_path, rows, monkeypatch, scan=lambda cap, art: {"gaps": [f"{cap} timed out"]}
    )
    assert timeout_outputs["syft"]["installer_records"][0]["scan_outcome"] == "not_completed"

    # Attribution bound (65 anchors -> 64 kept + installed_packages_truncated=65) + unverified + non-grype/osv
    record = {**rows[0], "canonical_identity": "fixture:record"}
    template = rows[1]
    anchors = [
        {
            **template,
            "canonical_identity": f"fixture:anchor-{i:03d}",
            "artifact_id": f"anchor-{i:03d}",
            "package_metadata": {**template["package_metadata"], "install_path": f"node_modules/x{i}/a"},
        }
        for i in range(65)
    ]
    packages = security._record_packages([record, *anchors])
    finding = Record(
        RECORD_KIND_FINDING,
        {"fingerprint": "f"},
        "native",
        "GHSA-aaaa",
        "text",
        {
            "capability": "grype",
            "artifact": {"canonical_identity": "fixture:record"},
            "package_name": "a",
            "package_version": "1.0.0",
        },
    )
    attributed = security._attribute(finding, packages)
    assert len(attributed.payload["installed_packages"]) == 64
    assert attributed.payload["installed_packages_truncated"] == 65
    unverified = security._attribute(
        Record(RECORD_KIND_FINDING, {}, "n", "x", "t", {**finding.payload, "package_name": "other"}),
        packages,
    )
    assert unverified.payload["installed_package_attribution"] == "unverified-record-entry"
    assert security._matched_anchors(finding, packages) == anchors
    assert security._matched_anchors(
        Record(RECORD_KIND_FINDING, {}, "n", "x", "t", {"capability": "syft"}), packages
    ) == []
    assert security._applicable("spotbugs", {"family": "jvm", "format": "jvm-archive"}) is True
    assert security._applicable("unknown-cap", {"family": "native", "format": "elf"}) is False


def test_scan_one_isolates_scanner_failure_and_retains_stopped_diagnostics(tmp_path: Path) -> None:
    """Direct _scan_one failure surface (also exercised under safety.active() by test_review_stop_policy)."""
    run_root = tmp_path / "asa_stop_run"
    ctx, _ = _unit_context(
        run_root,
        settings_override={"stream_limit_bytes": 8, "diagnostic_tail_bytes": 4},
        declared_releases=False,
    )
    artifact = _seed_artifact(run_root)

    def failing_runner(capability, path, art, timeout, limit):
        raise RuntimeError("fixture scanner failure with long diagnostic output")

    res = security._scan_one(ctx, artifact, "syft", failing_runner)
    assert res["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("fixture scanner failure" in g for g in res["gaps"])
    assert any("diagnostic streams were truncated" in g for g in res["gaps"])
    assert res["raw_artifacts"][1]["tail"] is not None


def test_scan_one_covers_checkpoint_reuse_runner_outcomes_and_native_reports(
    tmp_path: Path, request
) -> None:
    run_root = tmp_path / "run"
    ctx, events = _unit_context(run_root, settings_override={"parser_input_limit_bytes": 64})
    scope = publication_scope_for_owner(SharedArtifacts.for_job(ctx.job))
    scope.__enter__()
    request.addfinalizer(lambda: scope.__exit__(None, None, None))
    elf = _seed_artifact(run_root, "data/build/u/app.elf")
    lock = _seed_artifact(run_root, "data/build/u/Cargo.lock", b"version = 3\n", kind="lockfile")

    # Built-in scan executes directly without intra-attempt checkpoint files
    first = security._scan_one(ctx, elf, "native", None)
    assert first["reused"] is False and first["terminal_status"] == "COMPLETED_WITH_GAPS"
    second = security._scan_one(ctx, elf, "native", None)
    assert second["reused"] is False and second["fingerprint"] == first["fingerprint"]

    class _Runner:
        def __init__(self, ident, fn):
            self._ident = ident
            self._fn = fn

        def identity(self, cap, art):
            return self._ident

        def __call__(self, *args):
            return self._fn(*args)

    # Invalid runner.identity return
    bad_runner = _Runner("not-a-mapping", lambda *a: {})
    with pytest.raises(security.FrameworkIntegrityError, match="invalid identity"):
        security._scan_one(ctx, elf, "blint", bad_runner)

    # Executed tool_identity mismatch vs resolved_tool_identity
    mismatch_runner = _Runner(
        {"scanner": "tool-blint", "image": "img1"},
        lambda *a: {"stdout": b"{}", "stderr": b"", "exit_code": 0, "observation": {}, "tool_identity": {"scanner": "tool-blint", "image": "img2"}},
    )
    with pytest.raises(security.FrameworkIntegrityError, match="executed scanner identity differs"):
        security._scan_one(ctx, elf, "blint", mismatch_runner)

    # runner=None for adapter capability (also under safety.active() to exercise stopped.json without parser_payload)
    ctx_no_rel, _ = _unit_context(
        run_root, declared_releases=False, settings_override={"parser_input_limit_bytes": 64}
    )
    no_exec = security._scan_one(ctx_no_rel, elf, "syft", None)
    assert "no pinned executor configured" in no_exec["gaps"][0]
    assert any("scanner supplied no exact parser input" in g for g in no_exec["gaps"])

    # Parser byte bound exceeded, _parser_truncated, parse error, timed_out, exit!=0 (osv missing ecosystem + generic),
    # osv SKIPPED_NA, precondition_gap, blint unanalyzed, raw truncated, native_reports (valid, oversized, invalid)
    receipt_file = run_root / "data/jobs/job_artifact_security_analysis/attempts/attempt_0001/exec.json"
    atomic_json(receipt_file, {"ok": True})
    receipt_ref = {"path": receipt_file.relative_to(run_root).as_posix(), "sha256": file_sha256(receipt_file)}

    oversized = security._scan_one(
        ctx_no_rel,
        elf,
        "syft",
        lambda *a: {"stdout": b"", "stderr": b"", "exit_code": 0, "payload": b"x" * 100},
    )
    assert any("exceeded its configured byte bound" in g for g in oversized["gaps"])

    parse_err = security._scan_one(
        ctx_no_rel, elf, "syft", lambda *a: {"stdout": b"{bad", "stderr": b"", "exit_code": 0}
    )
    assert any("could not be parsed" in g for g in parse_err["gaps"])

    parser_trunc = security._scan_one(
        ctx_no_rel,
        elf,
        "syft",
        lambda *a: {
            "stdout": b"{}",
            "stderr": b"",
            "exit_code": 0,
            "observation": {"_parser_truncated": True},
            "truncated": True,
        },
    )
    assert any("parser or report assembly was truncated" in g for g in parser_trunc["gaps"])
    assert any("scanner output was truncated" in g for g in parser_trunc["gaps"])
    assert any("no verified execution receipt" in g for g in parser_trunc["gaps"])

    skipped_na = security._scan_one(
        ctx_no_rel,
        lock,
        "osv",
        lambda *a: {"stdout": b"No package sources found", "stderr": b"", "exit_code": 128, "payload": b"{}", "execution_receipt": receipt_ref},
    )
    assert skipped_na["terminal_status"] == "SKIPPED_NA"

    precond = security._scan_one(
        ctx_no_rel,
        lock,
        "osv",
        lambda *a: {"stdout": b"", "stderr": b"", "exit_code": None, "precondition_gap": "missing crates.io db"},
    )
    assert "missing crates.io db" in precond["gaps"]

    timed = security._scan_one(
        ctx_no_rel,
        elf,
        "syft",
        lambda *a: {"stdout": b"", "stderr": b"", "exit_code": -9, "timed_out": True},
    )
    assert "syft scanner timed out" in timed["gaps"]

    osv_stderr_gap = security._scan_one(
        ctx_no_rel,
        lock,
        "osv",
        lambda *a: {
            "stdout": b"",
            "stderr": b"unable to fetch OSV database for ecosystem crates.io: offline",
            "exit_code": 127,
        },
    )
    assert any("exited" in g or "crates.io" in g for g in osv_stderr_gap["gaps"])

    blint_findings_path = run_root / "data/jobs/job_artifact_security_analysis/attempts/attempt_0001/findings.json"
    blint_findings_path.write_text('{"findings":[{"id":"CHECK_NX"}]}', encoding="utf-8")
    blint_rel = blint_findings_path.relative_to(run_root).as_posix()
    blint_unanalyzed = security._scan_one(
        ctx_no_rel,
        elf,
        "blint",
        lambda *a: {
            "stdout": b"{}",
            "stderr": b"",
            "exit_code": 0,
            "observation": {"analyzed": False},
            "execution_receipt": receipt_ref,
            "native_reports": {"findings.json": blint_rel},
        },
    )
    assert "blint produced no per-binary analysis report for this artifact" in blint_unanalyzed["gaps"]
    assert "findings.json" in blint_unanalyzed["native_reports"]

    blint_findings_path.write_text(json.dumps({"findings": ["x" * 100]}), encoding="utf-8")
    blint_big_report = security._scan_one(
        ctx_no_rel,
        elf,
        "blint",
        lambda *a: {
            "stdout": b"{}",
            "stderr": b"",
            "exit_code": 0,
            "observation": {"analyzed": True},
            "execution_receipt": receipt_ref,
            "native_reports": {"findings.json": blint_rel},
        },
    )
    assert "blint native findings report exceeded its configured byte bound" in blint_big_report["gaps"]

    with pytest.raises(security.FrameworkIntegrityError, match="unexpected native scanner report source"):
        security._scan_one(
            ctx_no_rel,
            elf,
            "syft",
            lambda *a: {"stdout": b"{}", "stderr": b"", "exit_code": 0, "observation": {}, "native_reports": {"other.json": blint_rel}},
        )

    # Active safety guardian writes stopped.json with parser-input.bin and no-parser-input branch
    envelope = safety.policy(
        "00000000-0000-0000-0000-000000000018",
        {
            "source_commit": "a" * 40,
            "target_commit": "b" * 40,
            "configuration": {
                "base_sha256": "c" * 64,
                "profile": "copilot-prod",
                "profile_sha256": "d" * 64,
                "overlay_sha256": None,
            },
        },
    )
    with safety.AdmissionGuardian(envelope, run_root / "safety_parse", resolved_config_sha256="e" * 64):
        with safety.safety_scope(envelope):
            with pytest.raises(safety.ReviewStopped):
                security._scan_one(
                    ctx_no_rel,
                    elf,
                    "syft",
                    lambda *a: {"stdout": b"{bad", "stderr": b"err", "exit_code": 0, "payload": b"{bad"},
                )
    envelope2 = safety.policy(
        "00000000-0000-0000-0000-000000000019",
        {
            "source_commit": "a" * 40,
            "target_commit": "b" * 40,
            "configuration": {
                "base_sha256": "c" * 64,
                "profile": "copilot-prod",
                "profile_sha256": "d" * 64,
                "overlay_sha256": None,
            },
        },
    )
    with safety.AdmissionGuardian(envelope2, run_root / "safety_none", resolved_config_sha256="e" * 64):
        with safety.safety_scope(envelope2):
            with pytest.raises(safety.ReviewStopped):
                security._scan_one(ctx_no_rel, elf, "syft", None)
    assert any(run_root.rglob("stopped.json"))


def test_index_unit_shard_reuse_and_load_accepted_artifact_security_analysis(
    tmp_path: Path, monkeypatch, request
) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    fp = "a" * 64

    # Upstream artifact manifest
    art_shard = run_root / "data/indices/artifacts/s.sqlite"
    art_sha = IndexBuilder(art_shard, name="artifacts", fingerprint="b" * 64, target_snapshot=fp, shard_id="s").build()
    art_idx = IndexIdentity(
        "artifacts", INDEX_SCHEMA, art_sha, "b" * 64, art_shard.relative_to(run_root).as_posix(), {"job": "j"}, (), "s"
    )
    art_manifest = run_root / "data/indices/manifests/art.json"
    write_manifest(art_manifest, run_id=run_root.name, target_snapshot=fp, target_root=run_root, indexes=[art_idx])
    art_manifest_ref = {"path": art_manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(art_manifest)}

    rows = _installed_rows(run_root)
    artifacts = [
        {
            **row,
            **scope_fields(row),
            "producer": {"build_unit_id": "build-unit-fixture", "family": "node"},
            "artifact_id": f"artifact-{i:02d}",
            "canonical_identity": canonical_artifact_identity(fp, "build-unit-fixture", row).value,
        }
        for i, row in enumerate(rows)
    ]
    receipt_file = run_root / "data/jobs/job_artifact_security_analysis/attempts/attempt_0001/exec.json"
    atomic_json(receipt_file, {"ok": True})
    receipt_ref = {"path": receipt_file.relative_to(run_root).as_posix(), "sha256": file_sha256(receipt_file)}

    ctx_scan, _ = _unit_context(
        run_root,
        outputs={
            "load.accepted_artifacts": {
                "language_build_handoff_sha256": "b" * 64,
                "artifact_index": art_manifest_ref,
                "artifacts": artifacts,
                "producer_gaps": [],
            }
        },
    )
    scope = publication_scope_for_owner(SharedArtifacts.for_job(ctx_scan.job))
    scope.__enter__()
    request.addfinalizer(lambda: scope.__exit__(None, None, None))
    grype_obs = security._scan_one(
        ctx_scan,
        artifacts[0],
        "grype",
        lambda *a: {
            "stdout": b"",
            "stderr": b"",
            "exit_code": 0,
            "payload": json.dumps(
                {
                    "matches": [
                        {
                            "vulnerability": {"id": "GHSA-aaaa", "severity": "High"},
                            "artifact": {"name": "a", "version": "1.0.0"},
                        }
                    ]
                }
            ).encode(),
            "execution_receipt": receipt_ref,
        },
    )

    cap_outputs = {
        f"analyze.{cap}": {"observations": [grype_obs] if cap == "grype" else [], "gaps": []}
        for cap in security.CAPABILITIES
    }
    ctx_index, _ = _unit_context(
        run_root,
        unit_id="index.observations",
        outputs={
            "load.accepted_artifacts": {
                "language_build_handoff_sha256": "b" * 64,
                "artifact_index": art_manifest_ref,
                "artifacts": artifacts,
                "producer_gaps": [],
            },
            **cap_outputs,
        },
    )
    index_unit = next(u for u in build_job().units if u.unit_id == "index.observations")
    first_idx = index_unit.handler(ctx_index)
    assert first_idx["observation_count"] == 1 and first_idx["finding_count"] == 1
    assert first_idx["terminal_status"] == "SUCCEEDED"

    # Second call exercises existing shard reuse via attest_existing() and existing manifest reuse
    second_idx = index_unit.handler(ctx_index)
    assert second_idx["index_identity"]["sha256"] == first_idx["index_identity"]["sha256"]

    with sqlite3.connect(run_root / first_idx["index_identity"]["relative_path"]) as conn:
        rels = conn.execute("SELECT kind, COUNT(*) FROM relations GROUP BY kind").fetchall()
    assert rels == [("OBSERVED_AT", 4)]  # 1 summary->record + 1 finding->record + 2 verified anchors!

    # load_accepted_artifact_security_analysis validation & happy path
    consumer_root = tmp_path / "consumer_run"
    consumer_root.mkdir()
    asa_contract = dataset_contract("job_artifact_security_analysis", sorted({d.step for d in DATASETS}), DATASETS)

    def write_asa_handoff(root: Path, outputs_payload: dict, artifacts_list: list) -> str:
        attempt = root / "data/jobs/job_artifact_security_analysis/attempts/attempt_0001"
        handoff_path = attempt / "handoff.json"
        atomic_json(attempt / "claim.json", {"dataset_contract": asa_contract})
        write_fixture_handoff(
            root,
            handoff_path,
            {
                "run_id": root.name,
                "source_fingerprint": fp,
                "status": "ACCEPTED",
                "job_id": "job_artifact_security_analysis",
                "attempt_id": "attempt_0001",
                "outputs": outputs_payload,
                "artifacts": artifacts_list,
            },
        )
        sha = file_sha256(handoff_path)
        atomic_json(
            root / "data/jobs/job_artifact_security_analysis/latest.json",
            {"handoff_path": handoff_path.relative_to(root).as_posix(), "handoff_sha256": sha},
        )
        return sha

    # Missing artifact identity
    r_missing = tmp_path / "r_missing"
    r_missing.mkdir()
    write_asa_handoff(r_missing, {"acceptance.publish_handoff": {}}, [])
    with pytest.raises(ValueError, match="publication is unavailable"):
        load_accepted_artifact_security_analysis(r_missing)

    # Bad schema
    pub_rel = "data/jobs/job_artifact_security_analysis/attempts/attempt_0001/artifacts/artifact-security/accepted-analysis.json"
    r_bad = tmp_path / "r_bad"
    r_bad.mkdir()
    bad_file = r_bad / pub_rel
    atomic_json(bad_file, {"schema": "wrong/1", "source_fingerprint": fp})
    bad_ref = {"path": pub_rel, "sha256": file_sha256(bad_file), "size_bytes": bad_file.stat().st_size}
    write_asa_handoff(
        r_bad, {"acceptance.publish_handoff": {"artifact": bad_ref}}, [bad_ref]
    )
    with pytest.raises(ValueError, match="schema is unsupported"):
        load_accepted_artifact_security_analysis(r_bad)

    # Valid accepted handoff
    ok_file = consumer_root / pub_rel
    atomic_json(ok_file, {"schema": security.SCHEMA, "source_fingerprint": fp, "finding_count": 3})
    ok_ref = {"path": pub_rel, "sha256": file_sha256(ok_file), "size_bytes": ok_file.stat().st_size}
    sha_ok = write_asa_handoff(
        consumer_root, {"acceptance.publish_handoff": {"artifact": ok_ref}}, [ok_ref]
    )
    accepted_doc = load_accepted_artifact_security_analysis(consumer_root)
    assert accepted_doc["finding_count"] == 3 and accepted_doc["handoff_sha256"] == sha_ok

    # Unbound artifact in handoff
    import appsec_review.runtime.consume as consume_mod

    monkeypatch.setattr(
        consume_mod,
        "accepted_upstream",
        lambda _r, _j: SimpleNamespace(
            handoff={"outputs": {"acceptance.publish_handoff": {"artifact": ok_ref}}, "artifacts": []},
            sha256=sha_ok,
        ),
    )
    with pytest.raises(security.FrameworkIntegrityError, match="not bound to its handoff"):
        load_accepted_artifact_security_analysis(consumer_root)
