"""Unit tests for generated_sources.py: upstream admission, bounds, UTF-8, tamper and gap reporting."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from appsec_review.jobs.job_tree_sitter_ast.datasets import DATASETS
from appsec_review.jobs.job_tree_sitter_ast.generated_sources import load_generated_sources
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner, reference
from tests.handoff_fixture import write_fixture_handoff

SNAPSHOT = "a" * 64


def _json_ref(run: Path, relative: str, document: Any) -> dict[str, Any]:
    path = run / relative
    atomic_json(path, document)
    return {"path": relative, "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _seed_language_build(
    run: Path,
    *,
    source_fingerprint: str = SNAPSHOT,
    receipts: list[Any],
    gaps: list[str] | None = None,
) -> dict[str, Any]:
    doc_ref = _json_ref(run, "fixture/language.json", {
        "schema": "appsec-review/language-build-handoff/2",
        "source_fingerprint": source_fingerprint,
        "receipts": receipts,
        "gaps": gaps or [],
    })
    outputs = {"acceptance.publish_handoff": {"artifact": doc_ref}}
    relative = "data/jobs/job_language_build/attempts/fixture/handoff.json"
    path = write_fixture_handoff(run, run / relative, {
        "source_fingerprint": source_fingerprint,
        "status": "ACCEPTED",
        "job_id": "job_language_build",
        "outputs": outputs,
        "artifacts": [doc_ref],
    })
    ref = {"path": relative, "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
    _json_ref(run, "data/jobs/job_language_build/latest.json", {
        "handoff_path": ref["path"],
        "handoff_sha256": ref["sha256"],
    })
    return ref


def _owner(run: Path) -> SharedArtifacts:
    attempt_root = run / "data/jobs/job_tree_sitter_ast/attempts/attempt_0001"
    actor = {
        "run_id": run.name,
        "job_id": "job_tree_sitter_ast",
        "attempt_id": "attempt_0001",
        "orchestration": {"system": "fixture"},
    }
    atomic_json(attempt_root / "claim.json", {
        **actor,
        "attempt_path": attempt_root.relative_to(run).as_posix(),
        "dataset_contract": dataset_contract(
            "job_tree_sitter_ast", ("load", "plan", "parse", "acceptance"), DATASETS
        ),
    })
    return SharedArtifacts(run, attempt_root, {**actor, "claim": reference(run, attempt_root / "claim.json")})


def test_load_generated_sources_validates_bounds_and_missing_producer(tmp_path: Path) -> None:
    run = tmp_path / "run-empty"
    run.mkdir()
    with pytest.raises(ValueError, match="generated source bounds must be positive"):
        load_generated_sources(
            run, target_snapshot=SNAPSHOT, relevant=False,
            max_files=0, max_file_bytes=100, max_total_bytes=100,
        )

    rows, gaps, sha = load_generated_sources(
        run, target_snapshot=SNAPSHOT, relevant=False,
        max_files=5, max_file_bytes=100, max_total_bytes=100,
    )
    assert (rows, gaps, sha) == ([], [], None)

    rows, gaps, sha = load_generated_sources(
        run, target_snapshot=SNAPSHOT, relevant=True,
        max_files=5, max_file_bytes=100, max_total_bytes=100,
    )
    assert rows == [] and sha is None
    assert gaps == [{"path": "@generated", "reason": "generated_source_producer_unavailable"}]


def test_load_generated_sources_publishes_utf8_and_records_bounds_non_utf8_and_delivery_gaps(tmp_path: Path) -> None:
    run = tmp_path / "run-ok"
    workspace = run / "data/build/node/fixture/workspace"
    workspace.mkdir(parents=True)

    ok_bytes = b"export const generated = 1;\n"
    bad_utf8 = b"\xff\xfe\xfd"
    big_bytes = b"const x = 1;\n" * 20
    extra_bytes = b"export const extra = 2;\n"

    manifest_files: dict[str, str] = {}
    artifacts: list[dict[str, Any]] = []

    def _stage(rel: str, content: bytes, *, role: str = "deliverable", kind: str = "generated-code") -> None:
        file_path = workspace / rel
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(content)
        digest = file_sha256(file_path)
        manifest_files[rel] = digest
        artifacts.append({
            "path": file_path.relative_to(run).as_posix(),
            "workspace_path": rel,
            "sha256": digest,
            "size_bytes": len(content),
            "kind": kind,
            "scope_role": role,
            "artifact_origin": "build-output",
            "build_unit_id": "fixture-build",
            "mapping": "exact-workspace-path",
            "mapping_confidence": 1.0,
        })

    # Out-of-scope supplied_platform -> skipped cleanly
    artifacts.append({
        "path": "platform/ignored.js",
        "workspace_path": "platform/ignored.js",
        "kind": "generated-code",
        "scope_role": "supplied_platform",
        "sha256": "1" * 64,
        "size_bytes": 10,
        "artifact_origin": "build-output",
    })
    # Unsupported suffix & non-source kind -> skipped cleanly
    _stage("dist/bundle.wasm", b"\0asm\x01\0\0\0", role="build_dependency", kind="wasm-module")
    # Oversized single file -> generated_source_file_byte_bound
    _stage("dist/big.js", big_bytes)
    # Valid UTF-8 under unknown delivery role -> published + delivery_gap
    _stage("dist/unknown.js", ok_bytes, role="unknown")
    # Non-UTF-8 -> generated_source_not_utf8 gap
    _stage("dist/bad.js", bad_utf8)
    # Exceeds max_files=2 -> generated_source_lane_bound
    _stage("dist/extra.js", extra_bytes)

    ws_ref = _json_ref(run, "fixture/workspace.json", {
        "schema": "appsec-review/build-workspace-manifest/1",
        "build_unit_id": "fixture-build",
        "files": manifest_files,
    })
    empty_ok_receipt = {
        "schema": "appsec-review/language-build-receipt/1",
        "family": "node",
        "build_unit_id": "empty-succeeded",
        "root": ".",
        "source_fingerprint": SNAPSHOT,
        "terminal_status": "SUCCEEDED",
        "artifacts": [],
    }
    receipt = {
        "schema": "appsec-review/language-build-receipt/1",
        "family": "node",
        "build_unit_id": "fixture-build",
        "root": ".",
        "source_fingerprint": SNAPSHOT,
        "terminal_status": "SUCCEEDED",
        "workspace": workspace.relative_to(run).as_posix(),
        "workspace_manifest": ws_ref,
        "artifacts": artifacts,
        "tool_invocations": [],
        "gaps": [],
    }
    exhausted_tail_receipt = {
        "schema": "appsec-review/language-build-receipt/1",
        "family": "node",
        "build_unit_id": "exhausted-tail",
        "root": ".",
        "source_fingerprint": SNAPSHOT,
        "terminal_status": "SUCCEEDED",
        "artifacts": [{
            "path": (workspace / "dist/extra.js").relative_to(run).as_posix(),
            "workspace_path": "dist/extra.js",
            "sha256": manifest_files["dist/extra.js"],
            "size_bytes": len(extra_bytes),
            "kind": "generated-code",
            "scope_role": "deliverable",
            "artifact_origin": "build-output",
            "build_unit_id": "exhausted-tail",
            "mapping": "exact-workspace-path",
            "mapping_confidence": 1.0,
        }],
    }
    lb_ref = _seed_language_build(
        run,
        receipts=[empty_ok_receipt, receipt, exhausted_tail_receipt],
        gaps=["upstream_build_warning"],
    )

    with publication_scope_for_owner(_owner(run)):
        rows, gaps, build_sha = load_generated_sources(
            run,
            target_snapshot=SNAPSHOT,
            relevant=True,
            max_files=3,
            max_file_bytes=100,
            max_total_bytes=4096,
        )
    assert build_sha == lb_ref["sha256"]
    assert len(rows) == 2
    assert {r["workspace_path"] for r in rows} == {"dist/unknown.js", "dist/extra.js"}
    assert rows[0]["generated"] is True
    assert rows[0]["source_domain"] == "generated"
    reasons = [g["reason"] for g in gaps]
    assert "generated_source_producer_gap: upstream_build_warning" in reasons
    assert "generated_source_file_byte_bound" in reasons
    assert "generated_source_lane_bound" in reasons
    assert "generated_source_not_utf8" in reasons
    assert any("unknown" in r or "scope" in r for r in reasons)


def test_load_generated_sources_reports_unsuccessful_empty_receipt_and_rejects_bad_contracts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Unsuccessful empty receipt -> generated_source_build_unsuccessful
    run_fail = tmp_path / "run-fail"
    _seed_language_build(run_fail, receipts=[{
        "build_unit_id": "bu-failed",
        "terminal_status": "FAILED",
        "artifacts": [],
    }])
    rows, gaps, _ = load_generated_sources(
        run_fail, target_snapshot=SNAPSHOT, relevant=True,
        max_files=5, max_file_bytes=100, max_total_bytes=1000,
    )
    assert rows == []
    assert gaps == [{"path": "bu-failed", "reason": "generated_source_build_unsuccessful"}]

    # Snapshot mismatch
    with pytest.raises(ValueError, match="target snapshot differs"):
        load_generated_sources(
            run_fail, target_snapshot="b" * 64, relevant=True,
            max_files=5, max_file_bytes=100, max_total_bytes=1000,
        )

    # Non-mapping receipt (monkeypatch load_accepted_language_build to test direct guard)
    monkeypatch.setattr(
        "appsec_review.runtime.consume.has_accepted_upstream",
        lambda *_a: True,
    )
    monkeypatch.setattr(
        "appsec_review.jobs.job_tree_sitter_ast.generated_sources.load_accepted_language_build",
        lambda _r: {"source_fingerprint": SNAPSHOT, "receipts": ["not-a-dict"]},
    )
    with pytest.raises(ValueError, match="receipt is invalid"):
        load_generated_sources(
            tmp_path, target_snapshot=SNAPSHOT, relevant=True,
            max_files=5, max_file_bytes=100, max_total_bytes=1000,
        )

    # Non-mapping artifact
    monkeypatch.setattr(
        "appsec_review.jobs.job_tree_sitter_ast.generated_sources.load_accepted_language_build",
        lambda _r: {"source_fingerprint": SNAPSHOT, "receipts": [{"artifacts": ["bad"]}]},
    )
    with pytest.raises(ValueError, match="artifact is invalid"):
        load_generated_sources(
            tmp_path, target_snapshot=SNAPSHOT, relevant=True,
            max_files=5, max_file_bytes=100, max_total_bytes=1000,
        )

    # Supplied platform run path
    monkeypatch.setattr(
        "appsec_review.jobs.job_tree_sitter_ast.generated_sources.load_accepted_language_build",
        lambda _r: {
            "source_fingerprint": SNAPSHOT,
            "receipts": [{"artifacts": [{"path": "data/codeql/scopes/s1/export/columns.json", "workspace_path": "a.js", "kind": "generated-code"}]}],
        },
    )
    with pytest.raises(ValueError, match="supplied platform path"):
        load_generated_sources(
            tmp_path, target_snapshot=SNAPSHOT, relevant=True,
            max_files=5, max_file_bytes=100, max_total_bytes=1000,
        )

    # Unaccepted artifact_origin
    monkeypatch.setattr(
        "appsec_review.jobs.job_tree_sitter_ast.generated_sources.load_accepted_language_build",
        lambda _r: {
            "source_fingerprint": SNAPSHOT,
            "receipts": [{"artifacts": [{
                "path": "data/build/a.js",
                "workspace_path": "a.js",
                "kind": "generated-code",
                "artifact_origin": "untrusted",
                "size_bytes": 5,
            }]}],
        },
    )
    with pytest.raises(ValueError, match="unaccepted origin"):
        load_generated_sources(
            tmp_path, target_snapshot=SNAPSHOT, relevant=True,
            max_files=5, max_file_bytes=100, max_total_bytes=1000,
        )

    # Invalid byte size (bool or negative)
    monkeypatch.setattr(
        "appsec_review.jobs.job_tree_sitter_ast.generated_sources.load_accepted_language_build",
        lambda _r: {
            "source_fingerprint": SNAPSHOT,
            "receipts": [{"artifacts": [{
                "path": "data/build/a.js",
                "workspace_path": "a.js",
                "kind": "generated-code",
                "artifact_origin": "build-output",
                "size_bytes": True,
            }]}],
        },
    )
    with pytest.raises(ValueError, match="byte size is invalid"):
        load_generated_sources(
            tmp_path, target_snapshot=SNAPSHOT, relevant=True,
            max_files=5, max_file_bytes=100, max_total_bytes=1000,
        )

    # Missing workspace_manifest when an artifact was selected
    monkeypatch.setattr(
        "appsec_review.jobs.job_tree_sitter_ast.generated_sources.load_accepted_language_build",
        lambda _r: {
            "source_fingerprint": SNAPSHOT,
            "receipts": [{"artifacts": [{
                "path": "data/build/a.js",
                "workspace_path": "a.js",
                "kind": "generated-code",
                "artifact_origin": "build-output",
                "size_bytes": 5,
            }]}],
        },
    )
    with pytest.raises(ValueError, match="workspace manifest unavailable"):
        load_generated_sources(
            tmp_path, target_snapshot=SNAPSHOT, relevant=True,
            max_files=5, max_file_bytes=100, max_total_bytes=1000,
        )

    # Tampered bytes after _validate_receipts before detached publication
    run_tamper = tmp_path / "run-tamper"
    ws = run_tamper / "data/build/w"
    ws.mkdir(parents=True)
    js_file = ws / "a.js"
    js_file.write_bytes(b"tampered!\n")
    ws_ref = _json_ref(run_tamper, "fixture/ws.json", {"files": {"a.js": hashlib.sha256(b"orig\n").hexdigest()}})
    monkeypatch.setattr(
        "appsec_review.jobs.job_tree_sitter_ast.generated_sources.load_accepted_language_build",
        lambda _r: {
            "source_fingerprint": SNAPSHOT,
            "language_build_handoff_sha256": "c" * 64,
            "receipts": [{
                "build_unit_id": "bu-1",
                "workspace_manifest": ws_ref,
                "artifacts": [{
                    "path": js_file.relative_to(run_tamper).as_posix(),
                    "workspace_path": "a.js",
                    "kind": "generated-code",
                    "artifact_origin": "build-output",
                    "size_bytes": 5,
                    "sha256": hashlib.sha256(b"orig\n").hexdigest(),
                }],
            }],
        },
    )
    monkeypatch.setattr(
        "appsec_review.jobs.job_tree_sitter_ast.generated_sources._validate_receipts",
        lambda _r, _s, recs: ([{"validated_artifacts": [{**recs[0]["artifacts"][0], "canonical_identity": "cid"}]}], []),
    )
    with pytest.raises(ValueError, match="changed before detached publication"):
        load_generated_sources(
            run_tamper, target_snapshot=SNAPSHOT, relevant=True,
            max_files=5, max_file_bytes=100, max_total_bytes=1000,
        )
