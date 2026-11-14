"""A shard reused by path is re-attested in the shared store by the attempt that reuses it."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.retrieval import IndexBuilder
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json
from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner, reference

JOB = "job_tree_sitter_ast"


def _owner(root: Path, attempt: str) -> SharedArtifacts:
    from appsec_review.jobs.job_tree_sitter_ast.datasets import DATASETS
    attempt_root = root / "data/jobs" / JOB / "attempts" / attempt
    actor = {"run_id": root.name, "job_id": JOB, "attempt_id": attempt, "orchestration": {"system": "fixture"}}
    atomic_json(attempt_root / "claim.json", {
        **actor, "attempt_path": attempt_root.relative_to(root).as_posix(),
        "dataset_contract": dataset_contract(JOB, ("load", "plan", "parse", "acceptance"), DATASETS)})
    return SharedArtifacts(root, attempt_root, {**actor, "claim": reference(root, attempt_root / "claim.json")})


def _builder(root: Path) -> IndexBuilder:
    return IndexBuilder(root / "data/indices/analysis" / ("f" * 64 + ".sqlite"), name="analysis",
                        fingerprint="f" * 64, target_snapshot="snap", shard_id="scope-1")


def _receipts(root: Path) -> list[dict]:
    paths = sorted((root / "data/jobs" / JOB / "attempts").glob("*/shared/index-shard/*.json"))
    return [{"attempt": path.parts[-4], **json.loads(path.read_text(encoding="utf-8"))} for path in paths]


def test_build_or_reuse_records_a_computed_receipt_for_the_reusing_attempt(tmp_path: Path) -> None:
    """Regression for smoke-cpp run 2026-11-13-0001: after an implementation change, manifests refused
    shards whose only receipt belonged to the first attempt (tree_sitter_ast, then evidence_collection)."""
    root = tmp_path / "run-1"
    root.mkdir()
    with publication_scope_for_owner(_owner(root, "attempt_0001")):
        sha, reused = _builder(root).build_or_reuse()
    assert not reused
    with publication_scope_for_owner(_owner(root, "attempt_0002")):
        again, reused = _builder(root).build_or_reuse()
    assert reused and again == sha
    receipts = _receipts(root)
    assert [item["attempt"] for item in receipts] == ["attempt_0001", "attempt_0002"]
    assert all(item["mode"] == "computed" and item["object"]["sha256"] == sha for item in receipts)
    assert receipts[0]["computation"] == receipts[1]["computation"]


def test_attest_existing_refuses_changed_bytes_and_missing_shards(tmp_path: Path) -> None:
    root = tmp_path / "run-1"
    root.mkdir()
    with publication_scope_for_owner(_owner(root, "attempt_0001")):
        sha = _builder(root).build()
        with pytest.raises(ValueError, match="differ from the recorded identity"):
            _builder(root).attest_existing("0" * 64)
        assert _builder(root).attest_existing(sha) == sha
    missing = IndexBuilder(root / "data/indices/analysis/none.sqlite", name="analysis", fingerprint="e" * 64,
                           target_snapshot="snap", shard_id="scope-2")
    with pytest.raises(ValueError, match="unavailable"):
        missing.attest_existing()


def test_attest_existing_without_an_owner_only_verifies(tmp_path: Path) -> None:
    builder = IndexBuilder(tmp_path / "shard.sqlite", name="analysis", fingerprint="d" * 64,
                           target_snapshot="snap", shard_id="scope-3")
    sha = builder.build()
    assert builder.attest_existing(sha) == sha
    assert builder.build_or_reuse() == (sha, True)
