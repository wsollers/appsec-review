from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import shutil
import pytest

from appsec_review import cli

from appsec_review.config import TargetDocumentSettings, load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_review_data_indexing import build_job as build_indexing
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.review_packages import assemble_review_packages, publish_review_packages, verify_review_packages
from appsec_review.document_issues import adjudicate, analyze_document_hunts
from appsec_review.jobs.job_document_issue_analysis import build_job as build_document_issues
from appsec_review.jobs.job_document_issue_analysis.job import UNADJUDICATED_GAP
from appsec_review.jobs.job_review_package_assembly import build_job as build_packages
from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.mcp.capability import ScopedRetrievalMcpAdapter, issue_capability
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.runner import JobRunner


ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "northwinds_documents"


def _run(tmp_path: Path, *, openapi_source: bool = False, fts_disabled: bool = False,
         implementation: bool = False, duplicate_route: bool = False,
         releases: dict[str, str] | None = None, assurance_mode: str = "strict",
         include_packages: bool = False):
    config_path = tmp_path / "appsec-review.toml"
    config_text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if fts_disabled:
        config_text = config_text.replace('fts_image_validation = "optional"',
                                          'fts_image_validation = "disabled"')
    if releases is not None:
        marker = "[review_policy.releases]\n"
        assert config_text.count(marker) == 1
        declarations = "".join(f"{key} = {json.dumps(value)}\n" for key, value in sorted(releases.items()))
        config_text = config_text.replace(marker, marker + declarations, 1)
    if assurance_mode == "first_party_managed":
        start = config_text.index("[review_policy]\n")
        end = config_text.index("\n[review_policy.releases]", start)
        config_text = config_text[:start] + (
            '[review_policy]\nmode = "first_party_managed"\nproject_id = "fixture"\n'
            'approved_first_party_projects = ["fixture"]\ncustody = "application_private_v1"\n'
            f'target_root = {json.dumps(str(tmp_path / "target"))}\n') + config_text[end:]
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
    if implementation:
        path = target / "backend" / "orders.routes.ts"
        shutil.copyfile(FIXTURES / "orders.routes.ts", path)
    if duplicate_route:
        (target / "backend" / "duplicate.routes.ts").write_text(
            "router.get('/api/v1/orders/:id', handler);\n", encoding="utf-8")
    jobs = [build_intake(), build_catalog()]
    if include_packages:
        jobs.extend((build_indexing(), build_packages()))
    outcome = GraphRunner(config, jobs).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    run_root = config.runtime.runs_dir / outcome["run_id"]
    return config, target, outcome, run_root


@pytest.mark.parametrize("mode", ("strict", "first_party_managed"))
def test_target_to_package_graph_preserves_managed_work_removal(tmp_path, monkeypatch, mode):
    import appsec_review.indexing.inventory as inventory
    import appsec_review.review_packages as packages
    import appsec_review.runtime.scope as scope
    import appsec_review.runtime.runner as runtime_runner
    from appsec_review.storage.shared import current
    from appsec_review.storage.validation import current_validation

    accepted_shards, hashes, scans, assemblies = set(), [], [], []
    original_publish = JobRunner._publish_attempt_scoped
    original_hash_guard = scope.require_hashable_evidence
    original_scan, original_assemble = inventory.scan_run_tree, packages.assemble_review_packages
    original_prepare = runtime_runner.materialize_attempt_input_manifest

    def prepare(**kwargs):
        assert current() is None
        assert not (kwargs["attempt_root"] / "claim.json").exists()
        validation = current_validation(kwargs["run_root"])
        assert validation is not None
        if mode == "first_party_managed":
            admitted_paths = {(kwargs["run_root"] / path).resolve() for path, _ in validation.admitted}
            assert accepted_shards <= admitted_paths
        else:
            assert not validation.admitted
        return original_prepare(**kwargs)

    def published(runner, job, context, claim, result):
        output = original_publish(runner, job, context, claim, result)
        if job.job_id == "job_target_catalog":
            for artifact in output["handoff"]["artifacts"]:
                if artifact["path"].endswith(".sqlite"):
                    accepted_shards.add((context.run_root / artifact["path"]).resolve())
                    accepted_shards.add((context.run_root / "data/shared/objects" / artifact["sha256"]).resolve())
        return output

    def hash_guard(path):
        original_hash_guard(path)
        if path.resolve() in accepted_shards:
            import sys
            frame, callers = sys._getframe(1), []
            for _ in range(8):
                if frame is None:
                    break
                callers.append(f"{Path(frame.f_code.co_filename).name}:{frame.f_code.co_name}")
                frame = frame.f_back
            hashes.append({"path": str(path), "bytes": path.stat().st_size, "callers": callers})

    def scan(*args, **kwargs):
        scans.append(1)
        return original_scan(*args, **kwargs)

    def assemble(*args, **kwargs):
        assemblies.append(1)
        return original_assemble(*args, **kwargs)

    monkeypatch.setattr(JobRunner, "_publish_attempt_scoped", published)
    monkeypatch.setattr(scope, "require_hashable_evidence", hash_guard)
    monkeypatch.setattr(inventory, "scan_run_tree", scan)
    monkeypatch.setattr(packages, "assemble_review_packages", assemble)
    monkeypatch.setattr(runtime_runner, "materialize_attempt_input_manifest", prepare)
    config, target, outcome, run_root = _run(
        tmp_path, fts_disabled=True, implementation=True, assurance_mode=mode, include_packages=True)
    (tmp_path / "managed-work-counts.json").write_text(json.dumps({
        "mode": mode, "assemblies": len(assemblies), "scratch_scans": len(scans),
        "accepted_shard_hashes": len(hashes), "accepted_shard_hash_bytes": sum(row["bytes"] for row in hashes),
        "hash_calls": hashes,
    }, indent=2), encoding="utf-8")
    assert accepted_shards
    assert len(assemblies) == 1
    assert bool(scans) is (mode == "strict")
    assert bool(hashes) is (mode == "strict"), hashes[:5]
    package_outcome = outcome["jobs"]["job_review_package_assembly"]
    output = package_outcome["result"]["outputs"]["publication.publish_packages"]
    inventory_path = (Path(outcome["jobs"]["job_review_data_indexing"]["attempt_root"]) /
                      "steps/audit/tasks/inventory/inventory.json")
    inventory_rows = json.loads(inventory_path.read_text(encoding="utf-8"))["rows"]
    upstream_receipts = [
        row for row in inventory_rows
        if row["job_id"] in {"job_review_intake", "job_target_catalog"}
        and row["output_kind"] == "step_receipts"
    ]
    assert len(upstream_receipts) == 9
    assert all(row["disposition"] == "protected" and row["coverage"]["state"] == "complete"
               for row in upstream_receipts)
    claim = json.loads((Path(package_outcome["attempt_root"]) / "claim.json").read_text(encoding="utf-8"))
    assert claim["input_manifest_sha256"] == output["accepted_manifest_sha256"]
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"],
                         manifest_path=run_root / claim["input_manifest_path"],
                         manifest_sha256=claim["input_manifest_sha256"])
    manifest = verify_review_packages(core, run_root / output["package_directory"])
    assert manifest["packages"]
    assert manifest["accepted_manifest_sha256"] == core.manifest_sha256
    assert output["package_count"] == len(manifest["packages"])
    assert output["coverage_gap_count"] == len(manifest["coverage_gaps"])
    candidates = core.find(path="backend/orders.routes.ts", limit=1)["results"]
    assert candidates
    located, gap = core.read_source_lines(identity=candidates[0]["identity"])
    assert gap is None
    assert located["lines"] == (target / "backend/orders.routes.ts").read_text(encoding="utf-8").splitlines()


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
            captured["job_ids"] = [job.job_id for job in jobs]

        def run(self, **_kwargs):
            return {"run_id": "fixture", "status": "SUCCEEDED", "decisions": [], "jobs": {}}

    monkeypatch.setattr(cli, "GraphRunner", CapturedGraph)
    monkeypatch.setattr(cli, "source_fingerprint", lambda _target: "target-sha256:" + "a" * 64)
    assert cli.main(["--config", str(config_path), "start", "--target", str(target)]) == 0
    assert "retrieval_indexes.build_target_documents" in {
        unit.unit_id for unit in captured["catalog"].units}
    assert captured["job_ids"][-5:] == [
        "job_review_package_assembly", "job_document_issue_analysis", "job_inference_security_review",
        "job_final_publication_gate", "job_final_report_publication"]


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


@pytest.mark.parametrize("releases,reusable", [
    ({"job_document_issue_analysis": "fixture-doc/1", "validation": "fixture-validation/1"}, True),
    ({"platform": "fixture-platform/1", "validation": "fixture-validation/1"}, True),
    ({}, False),
    ({"job_document_issue_analysis": "fixture-doc/1"}, False),
], ids=("job-release", "platform-release", "missing-releases", "missing-validation"))
def test_document_issue_path_keeps_claims_private_and_resolves_source(
        tmp_path: Path, monkeypatch, releases: dict[str, str], reusable: bool) -> None:
    from appsec_review.storage.shared import SharedArtifacts

    config, target, outcome, run_root = _run(
        tmp_path, fts_disabled=True, implementation=True, releases=releases)
    lookups = []
    original_lookup = SharedArtifacts.lookup

    def lookup(owner, namespace, fingerprint):
        if namespace == "document-issues":
            lookups.append(fingerprint)
        return original_lookup(owner, namespace, fingerprint)

    monkeypatch.setattr(SharedArtifacts, "lookup", lookup)
    fingerprint = source_fingerprint(target)
    runner = JobRunner(config)
    runner.run(build_indexing(), run_id=outcome["run_id"], target_root=target,
               source_fingerprint=fingerprint)
    runner.run(build_packages(), run_id=outcome["run_id"], target_root=target,
               source_fingerprint=fingerprint)
    document_result = runner.run(build_document_issues(), run_id=outcome["run_id"], target_root=target,
                                 source_fingerprint=fingerprint,
                                 orchestration={"system": "dagster", "run_id": "document-producer"})
    output = document_result["result"]["outputs"]["analysis.map_and_adjudicate"]
    ledger_path = run_root / output["artifact"]["path"]
    assert output["artifact"]["path"].startswith("data/shared/objects/")
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    from appsec_review.storage.shared import verify_receipt
    producer = verify_receipt(run_root, output["shared_receipt"])
    assert producer["mode"] == "computed"
    before = ledger_path.read_bytes()
    reused_result = runner.run(build_document_issues(), run_id=outcome["run_id"], target_root=target,
                               source_fingerprint=fingerprint,
                               orchestration={"system": "dagster", "run_id": "document-consumer"})
    reused = reused_result["result"]["outputs"]["analysis.map_and_adjudicate"]
    assert reused["reused"] is reusable
    assert reused["artifact"] == output["artifact"]
    assert len(lookups) == (2 if reusable else 0)
    consumer = verify_receipt(run_root, reused["shared_receipt"])
    if reusable:
        assert consumer["producer_receipt"] == output["shared_receipt"]
    else:
        assert consumer["mode"] == "computed"
    from appsec_review.observability import PipelineLog
    checkpoints = [record for record in PipelineLog(run_root).read()[0]
                   if record["details"].get("action") == "document-issues"]
    assert [record["event_type"] for record in checkpoints] == [
        "CHECKPOINT_MISSED", "CHECKPOINT_REUSED" if reusable else "CHECKPOINT_MISSED"]
    if not reusable:
        assert all(record["details"]["reason"] == "missing_release_identity" for record in checkpoints)
    assert consumer["actor"]["orchestration"]["run_id"] == "document-consumer"
    assert producer["actor"]["orchestration"]["run_id"] == "document-producer"
    assert ledger_path.read_bytes() == before
    assert ledger["findings"] == ledger["scoring_inputs"] == []
    # The job is always partial while findings are unpublished, and it names that gap first.
    pointer = json.loads((run_root / "data/jobs/job_document_issue_analysis/latest.json").read_text(encoding="utf-8"))
    handoff = json.loads((run_root / pointer["handoff_path"]).read_text(encoding="utf-8"))
    published = handoff["outputs"]["analysis.map_and_adjudicate"]
    assert handoff["completion_status"] == published["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert published["gaps"][0] == UNADJUDICATED_GAP
    route = next(item for item in ledger["candidates"] if item["subject"] == "route:GET /api/v1/orders/{id}")
    assert route["mapping_status"] == "unique"
    assert route["state"] == "insufficient_evidence"
    assert route["implementation_evidence"][0]["path"] == "backend/orders.routes.ts"
    assert any(item["mapping_status"] == "unmapped" for item in ledger["candidates"])
    assert any(item["subject"].startswith("boundary:") and item["mapping_status"] == "unmapped"
               for item in ledger["candidates"])

    # A security claim must carry distinct proof lines and independent review decisions.
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    from appsec_review.document_issues import verify_document_issue_ledger
    from appsec_review.storage import atomic_json
    legacy = run_root / "data/document-issues" / ledger["content_sha256"] / "ledger.json"
    atomic_json(legacy, ledger)
    legacy_bytes = legacy.read_bytes()
    assert verify_document_issue_ledger(core, legacy) == ledger
    assert legacy.read_bytes() == legacy_bytes
    proof = dict(route["implementation_evidence"][0], line=5)
    proposed = {**route, "proof_evidence": [proof]}
    proof_ref = f"{proof['entity_id']}:{proof['line']}"
    red = {"decision": "supported", "security_claim": "Order responses expose INTERNAL_SECRET",
           "evidence_refs": [proof_ref]}
    blue = {"decision": "not_refuted", "evidence_refs": [proof_ref],
            "unresolved_refutations": []}
    verifier = {"decision": "independently_supported", "security_claim": red["security_claim"],
                "evidence_refs": [proof_ref]}
    assert adjudicate(proposed, core=core, red=red, blue=blue)["state"] == "insufficient_evidence"
    assert adjudicate(proposed, core=core, red=red, blue={**blue, "unresolved_refutations": ["guard unknown"]},
                      verifier=verifier)["state"] == "insufficient_evidence"
    assert adjudicate(proposed, core=core, red=red, blue=blue, verifier=verifier)["state"] == "supported"
    # The assertion above proves the gate, not a vulnerability in Northwind.
    source = target / "backend/orders.routes.ts"
    source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="accepted source bytes changed"):
        runner.run(build_document_issues(), run_id=outcome["run_id"], target_root=target,
                   source_fingerprint=fingerprint)


def test_document_issue_analysis_rejects_changed_source(tmp_path: Path) -> None:
    import pytest

    config, target, outcome, _ = _run(tmp_path, fts_disabled=True, implementation=True)
    fingerprint = source_fingerprint(target)
    runner = JobRunner(config)
    runner.run(build_indexing(), run_id=outcome["run_id"], target_root=target,
               source_fingerprint=fingerprint)
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    directory = publish_review_packages(core)
    path = target / "backend" / "orders.routes.ts"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="accepted source bytes changed"):
        analyze_document_hunts(core, directory)


def test_document_issue_mapping_preserves_ambiguity(tmp_path: Path) -> None:
    config, target, outcome, _ = _run(tmp_path, fts_disabled=True,
                                      implementation=True, duplicate_route=True)
    fingerprint = source_fingerprint(target)
    JobRunner(config).run(build_indexing(), run_id=outcome["run_id"], target_root=target,
                          source_fingerprint=fingerprint)
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    ledger = analyze_document_hunts(core, publish_review_packages(core))
    route = next(item for item in ledger["candidates"] if item["subject"] == "route:GET /api/v1/orders/{id}")
    assert route["mapping_status"] == "ambiguous"
    assert len(route["implementation_evidence"]) == 2
    assert route["state"] == "insufficient_evidence"
    assert any("implementation mapping ambiguous" in gap["reason"] for gap in route["coverage_gaps"])
