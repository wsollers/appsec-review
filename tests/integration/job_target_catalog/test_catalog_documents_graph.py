"""Pre-walk suite pending replacement: target documents through the catalog graph."""
from __future__ import annotations

import json
from pathlib import Path

from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.index import load_verified_manifest
from tests.test_target_document_pipeline import _run


def test_catalog_publishes_northwind_documents_with_queryable_provenance_and_intent(tmp_path: Path) -> None:
    config, target, outcome, run_root = _run(tmp_path)
    attempt = outcome["jobs"]["job_target_catalog"]["status"]["attempt_id"]
    result_path = (run_root / "data" / "jobs" / "job_target_catalog" / "attempts" / attempt /
                   "steps" / "retrieval_indexes" / "tasks" / "build_target_documents" / "result.json")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["item_count"] > 0 and result["link_count"] > 0
    assert not any("no accepted target document" in gap["reason"] for gap in result["gaps"])
    manifest = run_root / "data" / "indices" / "manifests" / f"catalog-{attempt}.json"
    document, _ = load_verified_manifest(run_root, manifest)
    assert "documents" in {item["name"] for item in document["indexes"]}

    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    operations = core.find(kind="document_record", path="backend/openapi.json", indexes=("documents",), limit=50)
    assert operations["results"]
    order_operation = next(item for item in operations["results"]
                           if item["payload"]["fields"].get("route") == "/api/v1/orders/{id}" and
                           item["payload"]["fields"].get("method") == "GET")
    assert order_operation["payload"]["authority"] == "declared"
    source_line = (target / order_operation["location"]["path"]).read_text(encoding="utf-8").splitlines()[
        order_operation["location"]["start_line"] - 1]
    assert source_line.strip() == '"get": {'
    excerpt = core.read_excerpt(identity=order_operation["identity"], context_lines=0)
    assert excerpt["results"][0]["excerpt"].strip() == '"get": {'

    threats = core.find(kind="document_record", path="docs/threat-model.md", indexes=("documents",), limit=50)
    assert threats["results"] and all(item["payload"]["authority"] == "intent" for item in threats["results"])
    route_links = core.trace(identity=order_operation["identity"], relations=("REFERENCES",), depth=1)
    assert any(item["payload"].get("relation") == "mentions_route" and
               item["payload"].get("authority") == "intent" for item in route_links["results"])
    matched = core.search(query="order", indexes=("documents",), limit=10)
    assert matched["results"] and all(item["index"] == "documents" for item in matched["results"])


def test_unmaterialized_openapi_is_a_named_gap_in_accepted_catalog(tmp_path: Path) -> None:
    config, _target, outcome, run_root = _run(tmp_path, openapi_source=True)
    attempt = outcome["jobs"]["job_target_catalog"]["status"]["attempt_id"]
    result_path = (run_root / "data" / "jobs" / "job_target_catalog" / "attempts" / attempt /
                   "steps" / "retrieval_indexes" / "tasks" / "build_target_documents" / "result.json")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert any("backend/openapi.ts: unsupported_format" in gap["reason"] for gap in result["gaps"])
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    response = core.find(kind="document_record", indexes=("documents",), limit=10)
    assert any("unsupported_format" in gap for gap in response["coverage_gaps"])
    assert not any(item["payload"]["document_kind"] == "openapi" for item in response["results"])
