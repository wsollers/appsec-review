from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import shutil

from appsec_review import cli

from appsec_review.config import TargetDocumentSettings, load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_review_data_indexing import build_job as build_indexing
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.review_packages import assemble_review_packages, publish_review_packages, verify_review_packages
from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.mcp.capability import ScopedRetrievalMcpAdapter, issue_capability
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.runner import JobRunner


ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "northwinds_documents"


def _run(tmp_path: Path, *, openapi_source: bool = False, fts_disabled: bool = False):
    config_path = tmp_path / "appsec-review.toml"
    config_text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if fts_disabled:
        config_text = config_text.replace('fts_image_validation = "optional"',
                                          'fts_image_validation = "disabled"')
    config_path.write_text(config_text, encoding="utf-8")
    config = load_config(config_path)
    assert isinstance(config.job("job_target_catalog").typed_settings, TargetDocumentSettings)
    target = tmp_path / "target"
    for source, destination in (
        ("design.md", "docs/design.md"),
        ("threat-model.md", "docs/threat-model.md"),
        ("data-flow-diagram.md", "docs/data-flow-diagram.md"),
        ("openapi.ts" if openapi_source else "openapi.json", "backend/openapi.ts" if openapi_source else "backend/openapi.json"),
        ("postman.json", "tests/postman/collection.json"),
        ("orders.test.ts", "backend/orders.test.ts"),
    ):
        destination_path = target / destination
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(FIXTURES / source, destination_path)
    outcome = GraphRunner(config, [build_intake(), build_catalog()]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    run_root = config.runtime.runs_dir / outcome["run_id"]
    return config, target, outcome, run_root


def test_catalog_publishes_northwind_documents_with_queryable_provenance_and_intent(tmp_path: Path) -> None:
    config, target, outcome, run_root = _run(tmp_path)
    attempt = outcome["jobs"]["job_target_catalog"]["status"]["attempt_id"]
    result_path = (run_root / "data" / "jobs" / "job_target_catalog" / "attempts" / attempt /
                   "steps" / "retrieval_indexes" / "tasks" / "build_target_documents" / "result.json")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["item_count"] > 0 and result["link_count"] > 0
    assert not any("no accepted target document" in gap for gap in result["gaps"])
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
    assert any("backend/openapi.ts: unsupported_format" in gap for gap in result["gaps"])
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    response = core.find(kind="document_record", indexes=("documents",), limit=10)
    assert any("unsupported_format" in gap for gap in response["coverage_gaps"])
    assert not any(item["payload"]["document_kind"] == "openapi" for item in response["results"])


def test_cli_start_graph_includes_document_collection_task(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_bytes((ROOT / "appsec-review.toml").read_bytes())
    target = tmp_path / "target"
    target.mkdir()
    captured = {}

    class CapturedGraph:
        def __init__(self, _config, jobs):
            captured["catalog"] = next(job for job in jobs if job.job_id == "job_target_catalog")

        def run(self, **_kwargs):
            return {"run_id": "fixture", "status": "SUCCEEDED", "decisions": [], "jobs": {}}

    monkeypatch.setattr(cli, "GraphRunner", CapturedGraph)
    monkeypatch.setattr(cli, "source_fingerprint", lambda _target: "target-sha256:" + "a" * 64)
    assert cli.main(["--config", str(config_path), "start", "--target", str(target)]) == 0
    assert "retrieval_indexes.build_target_documents" in {
        unit.unit_id for unit in captured["catalog"].units}


def test_review_data_indexing_carries_document_shard_and_audits_its_dataset(tmp_path: Path) -> None:
    config, target, outcome, run_root = _run(tmp_path, fts_disabled=True)
    JobRunner(config).run(build_indexing(), run_id=outcome["run_id"], target_root=target,
                          source_fingerprint=source_fingerprint(target))
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    operations = core.find(kind="document_record", path="backend/openapi.json", indexes=("documents",))
    assert operations["results"]
    inventory_rows = core.find(kind="dataset", name="job_target_catalog/retrieval_indexes/target_documents",
                               indexes=("inventory",))["results"]
    assert any(row["payload"].get("output_kind") == "target_documents" and
               row["payload"].get("disposition") == "indexed" for row in inventory_rows)
    accepted_manifest = run_root / "data" / "indices" / "manifests"
    assert any("documents" in {index["name"] for index in load_verified_manifest(run_root, path)[0]["indexes"]}
               for path in accepted_manifest.glob("review-data-indexing-*.json"))


def test_document_analysis_publishes_bounded_route_and_boundary_context(tmp_path: Path) -> None:
    config, target, outcome, _run_root = _run(tmp_path, fts_disabled=True)
    JobRunner(config).run(build_indexing(), run_id=outcome["run_id"], target_root=target,
                          source_fingerprint=source_fingerprint(target))
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    rows = []
    cursor = None
    while True:
        page = core.query_precomputed(query_set="document_context", limit=100, cursor=cursor)
        rows.extend(page["results"])
        cursor = page.get("next_cursor")
        if not cursor:
            break
    assert rows
    route = next(item for item in rows if item["payload"]["result"]["key"] == "GET /api/v1/orders/{id}")
    assert route["payload"]["fact_type"] == "route_context"
    assert route["payload"]["result"]["members"]["openapi"]
    assert route["payload"]["result"]["members"]["postman"]
    assert route["payload"]["authority"].startswith("computed from accepted")
    assert "verify behavior" in route["payload"]["result"]["inference_use"]
    boundary = next(item for item in rows if item["payload"]["result"]["key"] == "TB1")
    assert boundary["payload"]["fact_type"] == "boundary_context"
    assert boundary["payload"]["result"]["members"]["dfd"]
    assert boundary["payload"]["result"]["members"]["threat_model"]


def test_document_analysis_reports_missing_declaration_without_finding(tmp_path: Path) -> None:
    config, target, outcome, _run_root = _run(tmp_path, openapi_source=True, fts_disabled=True)
    JobRunner(config).run(build_indexing(), run_id=outcome["run_id"], target_root=target,
                          source_fingerprint=source_fingerprint(target))
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    page = core.query_precomputed(query_set="document_context", limit=100)
    routes = [item for item in page["results"] if item["payload"]["fact_type"] == "route_context"]
    assert routes
    assert all(item["payload"]["coverage_status"] == "partial" for item in routes)
    assert any("no accepted OpenAPI declaration" in gap for item in routes for gap in item["payload"]["gaps"])
    assert all(item["kind"] == "precomputed_fact" for item in routes)


def test_document_hunts_grant_only_accepted_context_and_sources(tmp_path: Path) -> None:
    config, target, outcome, _run_root = _run(tmp_path, fts_disabled=True)
    JobRunner(config).run(build_indexing(), run_id=outcome["run_id"], target_root=target,
                          source_fingerprint=source_fingerprint(target))
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    packages, manifest = assemble_review_packages(core)
    hunts = [item for item in packages if item["kind"] == "document_hunt"]
    assert hunts and manifest["counts"]["document_hunt"] == len(hunts)
    assert all(not item["lead_menu"] for item in hunts)
    selected = next(item for item in hunts if item["scope"]["partition_key"] ==
                    "route:GET /api/v1/orders/{id}")
    assert selected["retrieval"]["query_sets"] == ["document_context"]
    assert any(gap["producer"] == "document_context" and "component" in gap["reason"]
               for gap in selected["coverage_gaps"])
    secret = b"document-package-capability-secret-32"
    token = issue_capability(selected, role="red", round_id="1", secret=secret,
                             expires_at=int(datetime.now(timezone.utc).timestamp()) + 300)
    scoped = ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core), selected, capability=token,
                                       secret=secret, role="red", round_id="1")
    nominated = next(item["entity_id"] for item in selected["evidence"] if item["relation"] == "nominates")
    fact = scoped.call("find", {"identity": nominated})["results"][0]
    subject = fact["payload"]["subject_identity"]
    assert scoped.call("find", {"identity": subject})["results"]
    assert scoped.call("query_precomputed", {"query_set": "document_context", "subject": subject,
                                              "limit": 5})["results"]
    assert verify_review_packages(core, publish_review_packages(core)) == manifest
