"""Partial native receipts must bind admitted products, not merely a well-formed proof."""
from __future__ import annotations

import json

import pytest

from appsec_review.jobs.build_iterations import digest, durable_artifacts
from appsec_review.jobs.job_artifact_indexing.job import ArtifactIndexIntegrityError
from appsec_review.jobs.job_project_build.enforcement import scoped_gaps, validate_enforcement
from appsec_review.storage.shared import reference
from tests.unit.job_artifact_indexing.support import RUN_ID, proven_native_receipt, rewrite_manifest
from tests.unit.job_artifact_indexing.test_handler_wiring import _index_and_read_debug

REASON = "build/app: delivery status is unknown (delivery_fact_unavailable)"


def _partial_receipt(root, *, retained=False):
    receipt = proven_native_receipt(root)
    receipt["image"]["user"] = "10001:10001"
    if retained:
        receipt = durable_artifacts(root, receipt)
    receipt.update(terminal_status="COMPLETED_WITH_GAPS", gaps=scoped_gaps(
        [REASON], "execute.native", receipt["build_unit_id"]))
    return receipt


@pytest.mark.parametrize("mutation", [
    "missing", "empty", "object-missing", "path", "hash", "role", "rejected", "conflicting",
])
def test_partial_native_closure_must_cover_every_admitted_product_before_catalog_publication(tmp_path, mutation):
    root = tmp_path / RUN_ID
    root.mkdir()
    receipt = _partial_receipt(root, retained=True)
    proof = receipt["enforcement"][0]
    closure = proof["closure_manifest"]
    rows = closure["native_artifacts"]
    if mutation == "missing":
        del closure["native_artifacts"]
    elif mutation == "empty":
        rows.clear()
    elif mutation == "object-missing":
        closure["native_artifacts"] = [row for row in rows if row["role"] != "native_object"]
    elif mutation == "path":
        rows[0]["path"] = "data/shared/objects/" + "a" * 64
    elif mutation == "hash":
        rows[0]["sha256"] = "b" * 64
    elif mutation == "role":
        rows[0]["role"] = "executable"
    elif mutation == "rejected":
        rows[0]["rejection"] = "native target mismatch"
    else:
        rows.append({**rows[0], "rejection": "native target mismatch"})
    proof["enforcement_id"] = digest({key: value for key, value in proof.items() if key != "enforcement_id"})
    validate_enforcement(proof, dispatch=receipt)

    with pytest.raises(ArtifactIndexIntegrityError, match="native artifact.*closure"):
        _index_and_read_debug(root, receipt)
    assert not (root / "data/jobs/job_artifact_indexing/latest.json").exists()
    assert not (root / "data/indices/artifacts").exists()
    assert receipt["gaps"][0]["reason"] == REASON


@pytest.mark.parametrize("products", ["retained", "with-source", "source-only"])
def test_partial_native_closure_allows_bound_products_without_covering_unrelated_sources(tmp_path, products):
    root = tmp_path / RUN_ID
    root.mkdir()
    receipt = _partial_receipt(root, retained=products == "retained")
    if products != "retained":
        workspace = root / receipt["workspace"]
        source = workspace / "generated.h"
        source.write_bytes(b"int generated(void);\n")
        artifact = {**reference(root, source), "workspace_path": "generated.h", "kind": "generated-source"}
        files = json.loads((root / receipt["workspace_manifest"]["path"]).read_bytes())["files"]
        files["generated.h"] = artifact["sha256"]
        rewrite_manifest(root, receipt, files)
        if products == "source-only":
            receipt["artifacts"] = []
            proof = receipt["enforcement"][0]
            del proof["closure_manifest"]["native_artifacts"]
            proof["enforcement_id"] = digest({key: value for key, value in proof.items() if key != "enforcement_id"})
        receipt["artifacts"].append(artifact)
    published, result = _index_and_read_debug(root, receipt)
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any(REASON in gap for gap in result["gaps"])
    summary = json.loads((root / published["artifact"]["path"]).read_bytes())
    assert summary["artifact_count"] == len(receipt["artifacts"])
    assert len(result["artifacts"]) == len(receipt["artifacts"])
    assert {item["reference"]["sha256"] for item in result["artifacts"]} == {
        item["sha256"] for item in receipt["artifacts"]}
