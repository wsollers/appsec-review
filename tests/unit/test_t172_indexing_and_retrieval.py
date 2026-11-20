"""Focused unit tests for T-172: threat-model boundary indexing, OWASP verified gap
separation, 9-language API spec-vs-handler drift, and RetrievalCore query methods."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from appsec_review.document_issues import (
    DRIFT_SCHEMA,
    analyze_api_spec_drift,
    extract_multilang_route_handlers,
)
from appsec_review.indexing import input_matrix, products
from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.job_review_data_indexing.datasets import CONTRACT as INDEXING_CONTRACT
from appsec_review.jobs.job_review_data_indexing.job import PRODUCT_SETS, threat_model_status
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.owasp_workbench.engine import OWASP_GAP_SCHEMA, extract_verified_control_gaps
from appsec_review.retrieval import (
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RetrievalCore,
    SourceLocation,
    index_fingerprint,
    write_manifest,
)
from appsec_review.retrieval.precomputed import FACT_SCHEMA, QUERY_SETS
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff


ROOT = Path(__file__).resolve().parents[2]
RUN_ID = "2026-11-17-0172"
SNAPSHOT = "target-sha256:" + "9" * 64


def _load_schema(rel_path: str) -> dict[str, Any]:
    return json.loads((ROOT / rel_path).read_text(encoding="utf-8"))


def test_t172_nine_language_api_spec_drift_and_schema_validation(tmp_path: Path) -> None:
    drift_schema = _load_schema("docs/schemas/document-issues/document-drift-issue.schema.json")
    runs = tmp_path / "runs"
    run_root = runs / RUN_ID
    (run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001").mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir(parents=True)

    handler_files = [
        ("src/routes.py", '@app.get("/api/users")\ndef list_users():\n    return []\n@app.post("/debug/py")\ndef dbg():\n    return {}\n'),
        ("src/server.ts", 'router.post("/debug/js", (req, res) => res.send("ok"));\n'),
        ("cmd/api/main.go", 'mux.HandleFunc("GET /debug/go", handleDebug)\n'),
        ("src/AdminController.java", '@GetMapping("/debug/java")\npublic String debug() { return "ok"; }\n'),
        ("Controllers/DiagController.cs", '[Route("api/diag")]\npublic class DiagController {\n  [HttpPost("run")]\n  public void Run() {}\n}\n'),
        ("config/routes.rb", "post '/debug/ruby', to: 'debug#run'\n"),
        ("routes/api.php", "Route::delete('/debug/php', [DebugController::class, 'wipe']);\n"),
        ("src/http.rs", '#[get("/debug/rust")]\nasync fn debug_rust() {}\n'),
        ("src/server.cpp", 'CROW_ROUTE(app, "/debug/cpp")([](){ return "ok"; });\n'),
    ]
    doc_files = [
        (
            "api/openapi.yaml",
            "openapi",
            "\n".join([
                "openapi: 3.0.3",
                "paths:",
                "  /api/users:",
                "    get:",
                "      security:",
                "        - bearerAuth: []",
                "  /api/ghost:",
                "    delete:",
                "      summary: never implemented",
            ]),
        ),
        ("schema/api.graphql", "graphql", "type Mutation {\n  deleteAccount(id: ID!): Boolean!\n}\n"),
        ("proto/billing.proto", "protobuf", 'syntax = "proto3";\nservice BillingService {\n  rpc ChargeCard (ChargeReq) returns (ChargeResp);\n}\n'),
    ]

    src_entities: list[EntityRecord] = []
    for rel_path, content in handler_files:
        fp = target / rel_path
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content, encoding="utf-8")
        sha = file_sha256(fp)
        sid = LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"path": rel_path, "sha256": sha})
        loc = SourceLocation(SNAPSHOT, rel_path, sha, 0, fp.stat().st_size, 1, max(1, content.count("\n")), 1, 1,
                             {"native": rel_path}, "fixture-exact", 1.0)
        src_entities.append(EntityRecord(sid, rel_path, rel_path, content, {"path": rel_path}, loc))
        assert extract_multilang_route_handlers(rel_path, content, source_id=sid.value)

    doc_entities: list[EntityRecord] = []
    for rel_path, fmt, content in doc_files:
        fp = target / rel_path
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content, encoding="utf-8")
        sha = file_sha256(fp)
        did = LogicalIdentity.derive(EntityKind.DOCUMENT_RECORD, SNAPSHOT, {"path": rel_path, "sha256": sha})
        loc = SourceLocation(SNAPSHOT, rel_path, sha, 0, fp.stat().st_size, 1, max(1, content.count("\n")), 1, 1,
                             {"native": rel_path}, "fixture-exact", 1.0)
        doc_entities.append(EntityRecord(did, rel_path, rel_path, content, {"path": rel_path, "format": fmt}, loc))

    index_values: list[IndexIdentity] = []
    for idx_name, ents, shard_id in (("source", src_entities, "src-cat"), ("documents", doc_entities, "doc-cat")):
        ifp = index_fingerprint(
            name=idx_name, target_snapshot=SNAPSHOT, producer_artifacts=[{"sha256": "c" * 64}],
            tool_identity={"tool": "fixture", "name": idx_name},
            parser_identity="p/1", normalizer_identity="n/1", mapping_identity="m/1",
        )
        db_path = run_root / "data" / "indices" / idx_name / shard_id / f"{ifp}.sqlite"
        b = IndexBuilder(db_path, name=idx_name, fingerprint=ifp, target_snapshot=SNAPSHOT, shard_id=shard_id)
        for ent in ents:
            b.add_entity(ent)
        b.add_coverage(shard_id, "complete", None)
        db_sha = b.build()
        index_values.append(IndexIdentity(
            idx_name, "appsec-review/retrieval-index/2", db_sha, ifp,
            db_path.relative_to(run_root).as_posix(), {"job": "job_target_catalog"}, (), shard_id,
        ))

    manifest_path = run_root / "data" / "indices" / "manifests" / "fixture.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=target, indexes=index_values)
    mart = {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest_path),
            "size_bytes": manifest_path.stat().st_size}
    handoff_path = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001" / "handoff.json"
    write_fixture_handoff(run_root, handoff_path, {
        "status": "ACCEPTED", "job_id": "fixture", "attempt_id": "attempt_0001", "artifacts": [mart], "outputs": {},
    })
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff_path.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff_path),
        "manifest_path": mart["path"], "manifest_sha256": mart["sha256"],
    })

    core = RetrievalCore(runs, RUN_ID)
    drift_doc = analyze_api_spec_drift(core)
    assert drift_doc["schema"] == DRIFT_SCHEMA
    jsonschema.validate(instance=drift_doc, schema=drift_schema)
    kinds = {item["drift_kind"] for item in drift_doc["mismatches"]}
    assert {"undocumented_route", "unmapped_declared_operation", "missing_auth_middleware"} <= kinds


def test_t172_owasp_verified_control_gaps_require_resolved_evidence_and_assessment() -> None:
    gap_schema = _load_schema("docs/schemas/owasp-workbench/owasp-control-gap.schema.json")
    results = [
        {
            "row_id": "comp-api:owasp-asvs:5.0.0:V2.1.1",
            "component_id": "comp-api",
            "control_identity": "owasp-asvs:5.0.0:V2.1.1",
            "assessment_mode": "assessment",
            "applicability": "applicable",
            "control_status": "not_satisfied",
            "verification_status": "independently_assessed",
            "lead_eligible": True,
            "obligations": [{"family": "auth", "procedure_id": "proc-pw-len"}],
            "observations": [{"cwe_ids": ["CWE-521"], "mechanism": "password_policy"}],
            "evidence_used": [{"identity": "asr:source_file:" + "1" * 64, "location": {"path": "src/auth.py", "start_line": 10, "end_line": 15}}],
            "gaps": [],
        },
        {
            "row_id": "comp-api:owasp-asvs:5.0.0:V3.2.1",
            "component_id": "comp-api",
            "control_identity": "owasp-asvs:5.0.0:V3.2.1",
            "assessment_mode": "assessment",
            "applicability": "applicable",
            "control_status": "cannot_verify",
            "verification_status": "unresolved",
            "lead_eligible": False,
            "obligations": [],
            "observations": [],
            "evidence_used": [],
            "gaps": ["no_resolving_evidence"],
        },
        {
            "row_id": "comp-api:owasp-asvs:5.0.0:V1.1.1",
            "component_id": "comp-api",
            "control_identity": "owasp-asvs:5.0.0:V1.1.1",
            "assessment_mode": "assessment",
            "applicability": "applicable",
            "control_status": "satisfied",
            "verification_status": "independently_assessed",
            "lead_eligible": False,
            "obligations": [],
            "observations": [],
            "evidence_used": [{"identity": "asr:source_file:" + "1" * 64}],
            "gaps": [],
        },
    ]

    summary = extract_verified_control_gaps(RUN_ID, "assessment", results)
    assert summary["schema"] == OWASP_GAP_SCHEMA
    jsonschema.validate(instance=summary, schema=gap_schema)
    assert summary["control_gaps"] == []
    assert summary["coverage_gaps"] == [{
        "row_id": results[0]["row_id"], "code": "unresolved_control_evidence",
        "summary": "accepted evidence resolver is unavailable",
    }]

    qual_summary = extract_verified_control_gaps(
        RUN_ID, "qualification", [{**r, "assessment_mode": "qualification"} for r in results]
    )
    assert qual_summary["control_gaps"] == []


def test_t172_threat_boundaries_product_and_indexing_contract(tmp_path: Path) -> None:
    tb_schema = _load_schema("docs/schemas/indexing/threat-boundary-index.schema.json")
    assert "threat_boundaries" in QUERY_SETS
    assert "threat_boundaries" in PRODUCT_SETS
    upstream_jobs = {(req.producer, req.output_kind) for req in INDEXING_CONTRACT.inputs}
    assert ("job_threat_model_generation", "generated_dfd") in upstream_jobs
    assert ("job_threat_model_generation", "generated_threat_model") in upstream_jobs
    assert ("job_tree_sitter_ast", "tree_sitter_cfg") in upstream_jobs
    assert ("job_code_graph_index", "alternate_cpg") in upstream_jobs
    assert ("job_dependency_intelligence", "sca_reachability") in upstream_jobs
    assert ("job_evidence_collection", "corroborated_sast_evidence") in upstream_jobs
    assert ("job_owasp_control_assessment", "owasp_control_gaps") in upstream_jobs
    assert ("job_review_prioritization", "prioritization_signals") in upstream_jobs
    assert ("job_document_issue_analysis", "document_drift_issues") not in upstream_jobs

    tm_rows = [r for r in input_matrix.INPUT_SOURCES if r[0] == "generated_threat_model"]
    assert tm_rows and tm_rows[0][3] == ("threat_boundaries",)

    run_root = tmp_path / "runs" / RUN_ID
    att = run_root / "data" / "jobs" / "job_threat_model_generation" / "attempts" / "attempt_0001"
    out_dir = att / "outputs"
    out_dir.mkdir(parents=True)
    dfd_doc = {
        "schema": "appsec-review/generated-dfd/1",
        "trust_boundaries": [
            {"id": "tb-edge", "name": "Public Edge", "trust_level": "untrusted-to-app",
             "node_ids": ["proc-api"], "evidence_ids": ["ev-1"]}
        ],
        "nodes": [
            {"id": "ext-client", "kind": "external_entity", "name": "Browser", "trust_boundary_id": None, "evidence_ids": ["ev-1"]},
            {"id": "proc-api", "kind": "process", "name": "API Handler", "trust_boundary_id": "tb-edge", "evidence_ids": ["ev-1"]},
        ],
        "flows": [
            {"id": "flow-1", "source_id": "ext-client", "target_id": "proc-api",
             "crosses_trust_boundary": True, "protocol": "https", "auth_evidence": "none", "evidence_ids": ["ev-1"]}
        ],
        "entry_points": [
            {"id": "ep-login", "name": "POST /login", "node_id": "proc-api",
             "kind": "http_route", "source_path": "src/auth.py", "evidence_ids": ["ev-1"]}
        ],
    }
    tm_doc = {
        "schema": "appsec-review/generated-threat-model/1",
        "threats": [
            {"id": "thr-1", "stride": "Spoofing", "statement": "Unauthenticated POST /login spoofing",
             "target_id": "proc-api", "flow_id": "flow-1", "entry_point_ids": ["ep-login"],
             "priority": "high", "priority_inputs": {"boundary_crossing": True}, "evidence_ids": ["ev-1"]}
        ],
    }
    res_doc = {"schema": "appsec-review/threat-model-generation/1", "counts": {"threats": 1},
               "gaps": [f"upstream coverage gap {i}" for i in range(14)]}
    for fname, payload in (("dfd.json", dfd_doc), ("threat-model.json", tm_doc), ("result.json", res_doc)):
        atomic_json(out_dir / fname, payload)
    named = {
        fname: {"path": (out_dir / fname).relative_to(run_root).as_posix(), "sha256": file_sha256(out_dir / fname)}
        for fname in ("dfd.json", "threat-model.json", "result.json")
    }
    handoff_path = att / "handoff.json"
    write_fixture_handoff(run_root, handoff_path, {
        "status": "ACCEPTED",
        "job_id": "job_threat_model_generation",
        "attempt_id": "attempt_0001",
        "artifacts": list(named.values()),
        "outputs": {"publication.publish_handoff": {"artifacts": named, "counts": {"threats": 1}}},
    })
    atomic_json(run_root / "data" / "jobs" / "job_threat_model_generation" / "latest.json", {
        "attempt_id": "attempt_0001",
        "handoff_path": handoff_path.relative_to(run_root).as_posix(),
        "handoff_sha256": file_sha256(handoff_path),
    })

    tm_state = threat_model_status(run_root)
    assert tm_state["status"] == "accepted"
    ctx = products.ProductContext(
        run_root=run_root, snapshot=SNAPSHOT, shards=ShardSet(run_root, ()), links={}, feeds={},
        owasp={}, max_facts=100, rule_version="1", threat_model=tm_state,
    )
    derived = products._build_threat_boundaries(ctx, ())
    assert len(derived.entities) >= 1
    assert derived.coverage[0][1] == "partial"
    for ent in derived.entities:
        jsonschema.validate(instance=ent.payload["result"], schema=tb_schema)

    assert tm_state["gaps"] == res_doc["gaps"]
    assert all(f"threat_model: {gap}" in derived.gaps for gap in res_doc["gaps"])
    assert any("13 additional gap(s) omitted" in gap for gap in derived.entities[0].payload["gaps"])
    assert "10 additional gap(s) omitted" in derived.coverage[0][2]


def test_unassigned_threat_is_not_attached_to_first_boundary(tmp_path: Path) -> None:
    ctx = products.ProductContext(
        run_root=tmp_path, snapshot=SNAPSHOT, shards=ShardSet(tmp_path, ()), links={}, feeds={},
        owasp={}, max_facts=10, threat_model={
            "status": "accepted", "dfd": {"trust_boundaries": [{"id": "a"}, {"id": "z"}]},
            "threat_model": {"threats": [{"id": "unassigned", "title": "No declared subject"}]},
        },
    )
    derived = products._build_threat_boundaries(ctx, ())
    assert len(derived.entities) == 2
    assert all(not row.payload["result"]["threats"] for row in derived.entities)
    assert "unassigned_threat: unassigned has no declared or source-resolved trust boundary" in derived.gaps
    assert derived.coverage[0][1] == "partial"


def test_bounded_fact_gaps_account_for_omitted_records_and_text() -> None:
    from appsec_review.indexing.derive import fact

    row = fact(SNAPSHOT, "threat_boundaries", "1", {}, name="bounded", text="", result={},
               basis="test", upstream=[], gaps=["x" * 500, *[f"gap-{i}" for i in range(25)]])
    gaps = row.payload["gaps"]
    assert len(gaps) == 20 and all(len(gap) <= 300 for gap in gaps)
    assert "264 characters omitted" in gaps[0]
    assert gaps[-1] == "truncated: 7 additional gap(s) omitted"


def test_t172_retrieval_core_all_ten_query_methods_over_immutable_shards(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    run_root = runs / RUN_ID
    (run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001").mkdir(parents=True)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    src_file = target / "src" / "auth.py"
    src_file.write_text("def check(x):\n    if x is not None:\n        return sink(x)\n", encoding="utf-8")
    src_sha = file_sha256(src_file)
    loc = SourceLocation(SNAPSHOT, "src/auth.py", src_sha, 0, src_file.stat().st_size, 1, 3, 1, 1,
                         {"native": "src/auth.py:1"}, "fixture-exact", 1.0)
    src_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"path": "src/auth.py", "sha256": src_sha}).value
    ast_fn_id = LogicalIdentity.derive(EntityKind.AST_NODE, SNAPSHOT, {"native": "fn:check"}).value
    comp_id = LogicalIdentity.derive(EntityKind.IR_ENTITY, SNAPSHOT, {"native": "comp-api"}).value

    index_values: list[IndexIdentity] = []

    def add_shard(name: str, entities: list[EntityRecord], *, shard_id: str = "default",
                  producer: dict[str, Any] | None = None, coverage_gap: str | None = None) -> None:
        fp = index_fingerprint(
            name=name, target_snapshot=SNAPSHOT, producer_artifacts=[{"sha256": "b" * 64}],
            tool_identity={"tool": "fixture", "name": name, "shard": shard_id},
            parser_identity="p/1", normalizer_identity="n/1", mapping_identity="m/1",
        )
        db_path = run_root / "data" / "indices" / name / shard_id / f"{fp}.sqlite"
        builder = IndexBuilder(db_path, name=name, fingerprint=fp, target_snapshot=SNAPSHOT, shard_id=shard_id)
        for ent in entities:
            builder.add_entity(ent)
        builder.add_coverage(shard_id, "partial" if coverage_gap else "complete", coverage_gap)
        sha = builder.build()
        index_values.append(IndexIdentity(
            name, "appsec-review/retrieval-index/2", sha, fp,
            db_path.relative_to(run_root).as_posix(), producer or {"fixture": name}, (), shard_id,
        ))

    from appsec_review.jobs.job_code_graph_index.alternate_cpg import publish_alternate_cpg
    from appsec_review.jobs.job_tree_sitter_ast.cfg import CFG_SCHEMA, synthesize_file_cfg

    source_bytes = src_file.read_bytes()

    def cst(ordinal, kind, fragment, field=None):
        data = fragment.encode("utf-8")
        start = source_bytes.index(data)
        end = start + len(data)
        return {"ordinal_path": ordinal, "type": kind, "field": field, "named": True,
                "start_byte": start, "end_byte": end,
                "start_line": source_bytes.count(b"\n", 0, start) + 1,
                "end_line": source_bytes.count(b"\n", 0, end) + 1}

    body = "if x is not None:\n        return sink(x)"
    syntax = [
        cst([], "module", source_bytes.decode()),
        cst([0], "function_definition", source_bytes.decode().rstrip()),
        cst([0, 0], "identifier", "check", "name"),
        cst([0, 1], "parameters", "(x)", "parameters"),
        cst([0, 2], "block", body, "body"),
        cst([0, 2, 0], "if_statement", body),
        cst([0, 2, 0, 0], "comparison_operator", "x is not None", "condition"),
        cst([0, 2, 0, 1], "block", "return sink(x)", "consequence"),
        cst([0, 2, 0, 1, 0], "return_statement", "return sink(x)"),
        cst([0, 2, 0, 1, 0, 0], "call", "sink(x)"),
        cst([0, 2, 0, 1, 0, 0, 0], "identifier", "sink", "function"),
    ]
    function, = synthesize_file_cfg(
        syntax, source_bytes, language="python", path="src/auth.py",
        file_sha256=src_sha, source_identity=src_id, ast_identities={(0,): ast_fn_id}).functions
    cfg_payload = {
        "node_type": "function_definition",
        "cfg": {"schema": CFG_SCHEMA, **function.to_summary()},
        "cfg_nodes": [node.to_jsonl_record() for node in function.nodes],
        "cfg_edges": [edge.to_jsonl_record() for edge in function.edges],
    }
    add_shard("analysis", [
        EntityRecord(LogicalIdentity.parse(ast_fn_id), "fn:check", "check", "function check", cfg_payload, loc)
    ], shard_id="tree-sitter-py", producer={"job": "job_tree_sitter_ast"})

    alt_cpg_doc = {
        "schema": "appsec-review/alternate-cpg/1",
        "run_id": RUN_ID,
        "target_snapshot": SNAPSHOT,
        "resolution_tier": "codeql_plus_treesitter",
        "nodes": [
            {"node_id": "cpg:entry", "node_kind": "function", "name": "check", "qualified_name": "check", "language": "python",
             "path": "src/auth.py", "start_line": 1, "end_line": 3, "is_entrypoint": True, "entrypoint_route": "GET /check",
             "sink_class": None, "resolution_tier": "codeql_plus_treesitter"},
            {"node_id": "cpg:sink", "node_kind": "sink", "name": "sink", "qualified_name": "sink", "language": "python",
             "path": "src/auth.py", "start_line": 3, "end_line": 3, "is_entrypoint": False, "entrypoint_route": None,
             "sink_class": "sql_injection", "resolution_tier": "codeql_plus_treesitter"},
        ],
        "edges": [
            {"edge_id": "ce:1", "source_id": "cpg:entry", "target_id": "cpg:sink", "edge_kind": "FN_TO_SINK",
             "resolution_tier": "codeql_plus_treesitter", "confidence": 0.95}
        ],
        "paths": [
            {"path_id": "cp:1", "entry_node_id": "cpg:entry", "sink_node_id": "cpg:sink",
             "source_name": "check", "sink_name": "sink",
             "sink_class": "sql_injection", "hop_count": 1, "node_ids": ["cpg:entry", "cpg:sink"],
             "edge_ids": ["ce:1"], "resolution_tier": "codeql_plus_treesitter", "confidence": 0.95,
             "entrypoint_linked": True, "guards": []}
        ],
        "counts": {"nodes": 2, "edges": 1, "paths": 1},
        "gaps": [],
    }
    attempt_dir = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001"
    _, cpg_idx = publish_alternate_cpg(
        run_root, attempt_dir, alt_cpg_doc, job_id="fixture", unit_id="default", file_shas={"src/auth.py": src_sha}
    )
    index_values.append(cpg_idx)

    tb_id = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, SNAPSHOT, {"set": "threat_boundaries", "k": "1"}).value
    add_shard("precomputed", [
        EntityRecord(LogicalIdentity.parse(tb_id), "tb:1", "Public Edge", "boundary Public Edge", {
            "schema": FACT_SCHEMA, "query_set": "threat_boundaries", "subject_identity": src_id,
            "subject_path": "src/auth.py",
            "result": {"record_kind": "trust_boundary", "boundary_id": "tb-edge", "trust_level": "untrusted",
                       "source_paths": ["src/auth.py"]},
        }, loc)
    ], shard_id="precomputed-tb", producer={"job": "job_review_data_indexing", "query_set": "threat_boundaries"})

    ow_ok = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, SNAPSHOT, {"set": "control_evidence", "k": "ok"}).value
    ow_ind = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, SNAPSHOT, {"set": "control_evidence", "k": "ind"}).value
    add_shard("precomputed", [
        EntityRecord(LogicalIdentity.parse(ow_ok), "ow:ok", "V2.1.1", "absent control", {
            "schema": FACT_SCHEMA, "query_set": "control_evidence", "subject_identity": comp_id,
            "result": {"assessment_mode": "assessment", "component_id": "comp-api",
                       "control_identity": "owasp-asvs:5.0.0:V2.1.1", "applicability": "applicable",
                       "control_status": "not_satisfied", "verified_gap": True, "unresolved_evidence": 0,
                       "verification_status": "independently_assessed",
                       "evidence": [{"source_identity": src_id, "resolved": True}]},
        }),
        EntityRecord(LogicalIdentity.parse(ow_ind), "ow:ind", "V3.2.1", "indeterminate control", {
            "schema": FACT_SCHEMA, "query_set": "control_evidence", "subject_identity": comp_id,
            "result": {"assessment_mode": "assessment", "component_id": "comp-api",
                       "control_identity": "owasp-asvs:5.0.0:V3.2.1", "applicability": "applicable",
                       "control_status": "cannot_verify", "unresolved_evidence": 1, "verified_gap": True,
                       "evidence": []},
        }),
        *[
            EntityRecord(LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, SNAPSHOT, {"owasp": state}),
                         f"ow:{state}", "Unverified control", state, {
                             "schema": FACT_SCHEMA, "query_set": "control_evidence",
                             "subject_identity": comp_id,
                             "result": {"assessment_mode": "assessment", "component_id": "comp-api",
                                        "applicability": "applicable", "control_status": "not_satisfied",
                                        "verification_status": state, "verified_gap": True,
                                        "unresolved_evidence": 0,
                                        "evidence": [] if state == "independently_assessed" else [
                                            {"source_identity": src_id, "resolved": True}]},
                         })
            for state in ("dissent", "independently_assessed", "pending", "rejected", "uncertain", "unresolved")
        ],
    ], shard_id="precomputed-owasp", producer={"job": "job_review_data_indexing", "query_set": "control_evidence"})

    dc_id = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, SNAPSHOT, {"set": "document_context", "k": "1"}).value
    add_shard("precomputed", [
        EntityRecord(LogicalIdentity.parse(dc_id), "dc:1", "POST /debug", "undocumented route", {
            "schema": FACT_SCHEMA, "query_set": "document_context", "subject_identity": src_id,
            "subject_path": "src/auth.py",
            "result": {"kind": "route", "drift_kind": "undocumented_route", "severity": "high"},
            "gaps": ["no accepted OpenAPI declaration for this request"],
        }, loc),
        *[
            EntityRecord(LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, SNAPSHOT, {"doc": str(i)}),
                         f"dc:{i + 2}", "Missing context", "coverage only", {
                             "schema": FACT_SCHEMA, "query_set": "document_context",
                             "subject_identity": src_id, "subject_path": "src/auth.py",
                             "result": result, "gaps": [f"missing declaration {i}"],
                         }, loc)
            for i, result in enumerate(({}, {"drift_kind": "arbitrary gap text"}))
        ],
    ], shard_id="precomputed-doc", producer={"job": "job_review_data_indexing", "query_set": "document_context"},
       coverage_gap="target document coverage is incomplete")

    add_shard("observations", [
        EntityRecord(LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"drift": str(i)}),
                     f"drift:{i}", "Document observation", "drift evidence", payload, loc)
        for i, payload in enumerate((
            {"drift_kind": "missing_auth_middleware", "severity": "high"},
            {"issue_class": "undocumented_route", "gaps": ["unverified claim"]},
            {"drift_kind": "unknown_kind"},
        ))
    ], shard_id="document-drift", producer={"job": "job_document_issue_analysis"},
       coverage_gap="document claims remain unverified")

    pr_id = LogicalIdentity.derive(EntityKind.PRIORITY_ITEM, SNAPSHOT, {"native": "prio:auth"}).value
    add_shard("priority", [
        EntityRecord(LogicalIdentity.parse(pr_id), "file:src/auth.py", "src/auth.py", "priority item",
                     {"scope": "file", "path": "src/auth.py", "score": 92.0}, loc)
    ], shard_id="priority-main", producer={"job": "job_review_prioritization"})

    sca_id = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, SNAPSHOT, {"set": "dependency_advisories", "k": "1"}).value
    add_shard("precomputed", [
        EntityRecord(LogicalIdentity.parse(sca_id), "sca:1", "GHSA-1234", "reachable advisory", {
            "schema": FACT_SCHEMA, "query_set": "dependency_advisories", "subject_identity": src_id,
            "result": {"package_name": "pyjwt", "advisory": "GHSA-1234", "reachability_class": "call_graph_reachable"},
        }, loc)
    ], shard_id="precomputed-sca", producer={"job": "job_review_data_indexing", "query_set": "dependency_advisories"})

    from tests.unit.job_sanitizer_build.test_readiness_publication import readiness_core

    sanitizer_core, _ = readiness_core(tmp_path / "sanitizer")

    manifest_path = run_root / "data" / "indices" / "manifests" / "fixture.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=target, indexes=index_values)
    manifest_art = {"path": manifest_path.relative_to(run_root).as_posix(),
                    "sha256": file_sha256(manifest_path), "size_bytes": manifest_path.stat().st_size}
    handoff_path = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001" / "handoff.json"
    write_fixture_handoff(run_root, handoff_path, {
        "status": "ACCEPTED", "job_id": "fixture", "attempt_id": "attempt_0001",
        "artifacts": [manifest_art], "outputs": {},
    })
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff_path.relative_to(run_root).as_posix(),
        "handoff_sha256": file_sha256(handoff_path),
        "manifest_path": manifest_art["path"], "manifest_sha256": manifest_art["sha256"],
    })

    core = RetrievalCore(runs, RUN_ID)
    assert len(core.query_cfg_function(function_name="check")["results"]) == 1
    assert len(core.query_guard_dominators(path="src/auth.py", line=3, polarity="null_check")["results"]) == 1
    assert len(core.query_cpg_slice(path="src/auth.py", line=3, direction="backward")["results"]) >= 1
    assert len(core.query_call_paths(sink_class="sql_injection", entrypoint_only=True)["results"]) == 1
    assert len(core.query_threat_boundaries(boundary_id="tb-edge", path="src/auth.py")["results"]) == 1

    owasp_res = core.query_owasp_gaps(component_id="comp-api")["results"]
    assert len(owasp_res) == 1
    assert owasp_res[0]["payload"]["result"]["control_identity"] == "owasp-asvs:5.0.0:V2.1.1"
    with pytest.raises(ValueError, match="status must be not_satisfied"):
        core.query_owasp_gaps(status="weak")

    assert len(core.query_doc_drift(drift_kind="undocumented_route", path="src/auth.py")["results"]) == 1
    drift = core.query_doc_drift(path="src/auth.py")
    assert {item["drift_kind"] for item in drift["results"]} == {"undocumented_route", "missing_auth_middleware"}
    assert len(drift["results"]) == 2
    assert any("missing declaration" in gap for gap in drift["coverage_gaps"])
    assert any("unsupported drift kind" in gap for gap in drift["coverage_gaps"])
    assert any("no recognized document drift kind" in gap for gap in drift["coverage_gaps"])
    assert "precomputed/precomputed-doc: target document coverage is incomplete" in drift["coverage_gaps"]
    assert "observations/document-drift: document claims remain unverified" in drift["coverage_gaps"]
    with pytest.raises(ValueError, match="drift_kind must"):
        core.query_doc_drift(drift_kind="arbitrary gap text")
    envelope = core._envelope(tool="query_doc_drift", results=[], gaps=[f"gap-{i}" for i in range(205)],
                              started=core.clock(), request_hash="a" * 64)
    assert len(envelope["coverage_gaps"]) == 200
    assert envelope["coverage_gaps"][-1] == "truncated: 6 additional coverage gap(s) omitted"
    assert envelope["truncated"] is True
    assert len(core.query_engineering_signals(path="src/auth.py", signal_family="priority")["results"]) == 1
    assert len(core.query_sca_reachability(package="pyjwt", reachability_class="call_graph_reachable")["results"]) == 1
    assert len(sanitizer_core.query_sanitizer_readiness(build_unit="unit-1", sanitizer="asan")["results"]) == 1

    adapter = RetrievalMcpAdapter(core)
    mcp_tb = adapter.mcp_result("query_precomputed", {"query_set": "threat_boundaries", "limit": 10})
    assert mcp_tb["isError"] is False
    assert len(mcp_tb["structuredContent"]["results"]) == 1
