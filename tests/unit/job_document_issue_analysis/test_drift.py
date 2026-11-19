"""Producer-shaped regressions for T-5129 and T-5130; no target code is executed."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from appsec_review import document_issues as issues
from appsec_review.indexing.target_documents import collect_target_documents
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity,
    RetrievalCore, SourceLocation, write_manifest,
)
from appsec_review.review_packages import publish_review_packages
from appsec_review.storage import file_sha256
from tests.unit.job_document_issue_analysis.test_document_issues import _build_core


SPEC = b"""openapi: 3.0.3
paths:
  /orders/{id}:
    get:
      security:
        - bearerAuth: []
  /ghost:
    get: {}
"""


def _catalog_core(tmp_path, *, documents=None, sources=None, source_documents=False):
    core, target, snapshot = _build_core(tmp_path, source_files=sources)
    documents = documents if documents is not None else [("api/openapi.yaml", "openapi", SPEC)]
    entities = []
    source_entities = []
    gaps = []
    for path, kind, raw in documents:
        full = target / path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(raw)
        digest = file_sha256(full)
        result = collect_target_documents(target, snapshot, [{"path": path, "sha256": digest, "kind": kind}])
        gaps.extend(f"{gap['path']}: {gap['reason']}: {gap['detail']}" for gap in result.gaps)
        for record in result.records:
            identity = LogicalIdentity.derive(EntityKind.DOCUMENT_RECORD, snapshot, {"record_id": record["id"]})
            location = SourceLocation(snapshot, path, digest, 0, len(raw), record["line"],
                                      record["end_line"], 1, 1, {}, "exact", 1.0)
            payload = {"record_type": "target_document", "document_kind": record["kind"],
                       "subtype": record["subtype"], "authority": record["authority"], "fields": record["fields"]}
            entities.append(EntityRecord(identity, record["id"], record["text"], record["text"], payload, location))
        if source_documents:
            identity = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {"path": path})
            location = SourceLocation(snapshot, path, digest, 0, len(raw), 1, max(1, raw.count(b"\n")),
                                      1, 1, {}, "exact", 1.0)
            source_entities.append(EntityRecord(identity, path, path, path, {"language": None}, location))
    indexes = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
               for item in core.manifest["indexes"] if item["name"] != "documents"]
    for name, rows, shard in [("documents", entities, "catalog-documents"),
                              ("source", source_entities, "catalog-document-sources")]:
        if name == "source" and not rows:
            continue
        fingerprint = hashlib.sha256(shard.encode()).hexdigest()
        db = core.run_root / "data" / "indices" / f"{shard}.sqlite"
        builder = IndexBuilder(db, name=name, fingerprint=fingerprint,
                               target_snapshot=snapshot, shard_id=shard)
        for row in rows:
            builder.add_entity(row)
        builder.add_coverage(shard, "partial" if gaps else "complete", "; ".join(gaps) or None)
        digest = builder.build()
        indexes.append(IndexIdentity(name, "appsec-review/retrieval-index/2", digest, fingerprint,
                                     db.relative_to(core.run_root).as_posix(), {"job": "job_target_catalog"},
                                     tuple(gaps), shard))
    manifest = core.run_root / "data" / "indices" / "catalog-manifest.json"
    write_manifest(manifest, run_id=core.run_id, target_snapshot=snapshot, target_root=target, indexes=indexes)
    return RetrievalCore(core.run_root.parent, core.run_id, manifest_path=manifest,
                         manifest_sha256=file_sha256(manifest)), target, entities


def test_real_catalog_operations_are_read_once_and_keep_provenance(tmp_path, monkeypatch):
    core, target, rows = _catalog_core(tmp_path, source_documents=True)
    assert len(rows) == 2
    reads = []
    original = Path.open

    def observe(path, *args, **kwargs):
        if path == target / "api/openapi.yaml":
            reads.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", observe)
    report = issues.analyze_api_spec_drift(core)
    assert report["specs_parsed"] == 1
    assert len(reads) == 1
    assert [(item["drift_kind"], item["route"]) for item in report["mismatches"]] == [
        ("missing_auth_middleware", "/orders/{id}"), ("unmapped_declared_operation", "/ghost")]
    assert len({item["drift_id"] for item in report["mismatches"]}) == 2
    assert {item["spec_source_id"] for item in report["mismatches"]} == {row.identity.value for row in rows}
    schema = Path(__file__).resolve().parents[3] / "docs/schemas/document-issues/document-drift-issue.schema.json"
    Draft202012Validator(json.loads(schema.read_text())).validate(report)


def test_document_fallback_rejects_changed_accepted_bytes(tmp_path):
    core, target, _ = _catalog_core(tmp_path)
    (target / "api/openapi.yaml").write_bytes(SPEC.replace(b"/ghost", b"/changed"))
    with pytest.raises(ValueError, match="changed"):
        issues.analyze_api_spec_drift(core)


@pytest.mark.parametrize("problem", ["malformed", "missing", "undecodable", "oversized", "symlink"])
def test_document_omissions_are_named_gaps_not_successful_parses(tmp_path, problem):
    raw = b"openapi: [broken" if problem == "malformed" else b"\xff" if problem == "undecodable" else SPEC
    core, target, _ = _catalog_core(tmp_path, documents=[("api/openapi.yaml", "openapi", raw)])
    if problem == "missing":
        (target / "api/openapi.yaml").unlink()
    if problem == "symlink":
        path = target / "api/openapi.yaml"
        path.rename(target / "api/other.yaml")
        path.symlink_to("other.yaml")
    report = issues.analyze_api_spec_drift(core, max_file_bytes=10 if problem == "oversized" else 1048576)
    assert report["specs_parsed"] == 0
    assert report["gaps"]
    assert any("api/openapi.yaml" in gap for gap in report["gaps"])
    assert not report["mismatches"]


def test_document_and_failed_source_reads_share_the_file_bound(tmp_path):
    core, target, _ = _catalog_core(tmp_path, sources=[("a.ts", b"\xff", "TypeScript")])
    report = issues.analyze_api_spec_drift(core, max_files=1)
    assert report["specs_parsed"] == 0
    assert any("bound" in gap for gap in report["gaps"])
    assert any("undecodable" in gap for gap in report["gaps"])


def test_distinct_specs_do_not_share_drift_ids(tmp_path):
    core, _, _ = _catalog_core(tmp_path, documents=[
        ("api/a.yaml", "openapi", SPEC), ("api/b.yaml", "openapi", SPEC)])
    report = issues.analyze_api_spec_drift(core)
    assert report["specs_parsed"] == 2
    assert len(report["mismatches"]) == 4
    assert len({item["drift_id"] for item in report["mismatches"]}) == 4


def test_accepted_json_duplicate_keys_remain_a_parse_gap(tmp_path):
    raw = b"""{
  "openapi": "3.0.3",
  "paths": {},
  "paths": {
    "/orders": {
      "get": {}
    }
  }
}
"""
    core, _, rows = _catalog_core(tmp_path, documents=[("api/openapi.json", "openapi", raw)])
    assert rows
    report = issues.analyze_api_spec_drift(core)
    assert report["specs_parsed"] == 0
    assert not report["mismatches"]
    assert any("parse failed" in gap and "duplicate" in gap for gap in report["gaps"])


def test_unresolved_references_are_not_fetched_or_clean_coverage(tmp_path):
    raw = b"""openapi: 3.0.3
paths:
  /orders:
    get:
      responses:
        '200':
          $ref: https://invalid.example/response.json
"""
    core, _, _ = _catalog_core(tmp_path, documents=[("api/openapi.yaml", "openapi", raw)])
    report = issues.analyze_api_spec_drift(core)
    assert report["specs_parsed"] == 1
    assert any("unresolved specification reference" in gap for gap in report["gaps"])


@pytest.mark.parametrize("padding", ["", "\n" * 40], ids=["adjacent", "distant"])
def test_route_guards_roles_and_anonymous_overrides_are_local(padding):
    text = ("router.get('/secured', requireAuth, requireRole('admin'), secured);\n"
            + padding + "router.get('/plain', plain);\n"
            + "router.get('/public', AllowAnonymous, publicHandler);\n")
    handlers = {item["route"]: item for item in issues.extract_multilang_route_handlers("src/routes.ts", text)}
    assert "requireAuth" in handlers["/secured"]["observed_guards"]
    assert handlers["/secured"]["observed_roles"] == ["admin"]
    assert not handlers["/secured"]["allow_anonymous"]
    assert handlers["/plain"]["observed_guards"] == []
    assert handlers["/plain"]["observed_roles"] == []
    assert not handlers["/plain"]["allow_anonymous"]
    assert handlers["/public"]["allow_anonymous"]


def test_adjacent_python_decorators_belong_only_to_their_handler():
    text = ('@app.get("/private")\n@login_required\ndef private():\n    return "ok"\n'
            '@app.get("/public")\ndef public():\n    return "ok"\n')
    handlers = {item["route"]: item for item in issues.extract_multilang_route_handlers("src/routes.py", text)}
    assert handlers["/private"]["observed_guards"] == ["login_required"]
    assert handlers["/public"]["observed_guards"] == []


@pytest.mark.parametrize(("path", "text"), [
    ("src/routes.java", '@PreAuthorize("admin")\n@GetMapping("/private")\nvoid privateRoute() {}\n'
     '@GetMapping("/public")\nvoid publicRoute() {}\n'),
    ("src/routes.cs", '[Authorize(Roles = "admin")]\n[HttpGet("/private")]\nvoid Private() {}\n'
     '[HttpGet("/public")]\nvoid Public() {}\n'),
])
def test_adjacent_method_annotations_are_not_shared(path, text):
    for source in (text, text.replace("\n", " ")):
        handlers = {item["route"]: item for item in issues.extract_multilang_route_handlers(path, source)}
        assert handlers["/private"]["observed_guards"]
        assert handlers["/private"]["observed_roles"] == ["admin"]
        assert handlers["/public"]["observed_guards"] == []
        assert handlers["/public"]["observed_roles"] == []


def test_route_text_comments_and_other_same_line_calls_are_not_guards():
    text = ("// router.get('/fake', requireAuth);\n"
            "router.get('/public', plain); router.get('/private', requireRole('admin'), secured);\n"
            "router.get('/outer', () => { router.get('/nested', requireAuth, nested); });\n"
            "router.get('/requireAuth', (req, res) => res.send('requireAuth admin AllowAnonymous'));\n")
    handlers = {item["route"]: item for item in issues.extract_multilang_route_handlers("src/routes.ts", text)}
    assert set(handlers) == {"/public", "/private", "/requireAuth", "/outer", "/nested"}
    assert handlers["/private"]["observed_guards"] == ["requireRole"]
    assert handlers["/public"]["observed_guards"] == []
    assert handlers["/outer"]["observed_guards"] == []
    assert handlers["/nested"]["observed_guards"] == ["requireAuth"]
    assert handlers["/requireAuth"]["observed_guards"] == []
    assert handlers["/requireAuth"]["observed_roles"] == []
    assert not handlers["/requireAuth"]["allow_anonymous"]


@pytest.mark.parametrize(("security", "requires_auth"), [
    ([{}, {"bearerAuth": []}], False), ([], False), ([{"bearerAuth": []}], True),
])
def test_optional_auth_and_operation_override(security, requires_auth):
    text = json.dumps({"openapi": "3.0.3", "security": [{"globalAuth": []}], "paths": {
        "/orders": {"get": {"security": security}, "post": {}}}})
    operations = issues._parse_openapi_spec_operations(text, "api/openapi.json", "accepted-document")
    assert operations[0]["requires_auth"] is requires_auth
    assert operations[1]["requires_auth"] is True
    assert operations[1]["declared_security"] == ["globalAuth"]


def test_optional_auth_never_emits_an_auth_or_role_mismatch(tmp_path):
    raw = json.dumps({"openapi": "3.0.3", "paths": {"/orders/{id}": {"get": {
        "security": [{}, {"oauth": ["admin"]}]}}}}, indent=2).encode()
    core, _, _ = _catalog_core(tmp_path, documents=[("api/openapi.json", "openapi", raw)])
    report = issues.analyze_api_spec_drift(core)
    assert report["specs_parsed"] == 1
    assert report["mismatches"] == []


def test_security_alternatives_do_not_union_mandatory_roles():
    raw = json.dumps({"openapi": "3.0.3", "paths": {"/orders": {"get": {
        "security": [{"oauth": ["admin"]}, {"bearer": []}]}}}})
    operations = issues._parse_openapi_spec_operations(raw, "api/openapi.json", "accepted-document")
    assert operations[0]["requires_auth"] is True
    assert operations[0]["declared_roles"] == []
    assert operations[0]["declared_security"] == ["bearer", "oauth", "oauth:admin"]


def test_same_line_registrations_do_not_create_unique_mapping(tmp_path):
    core, _, _ = _build_core(tmp_path, source_files=[
        ("src/orders.ts", b"router.get('/orders/:id', h1); router.get('/orders/:id', h2);\n"
         b'const example = "router.get(\'/orders/:id\', h3)";\n'
         b"// router.get('/orders/:id', h4);\n", "TypeScript")])
    routes, _ = issues._source_lines(core, 10, 1024)
    assert len(routes) == 2
    assert len({route["column"] for route in routes}) == 2
    ledger = issues.analyze_document_hunts(core, publish_review_packages(core))
    candidate = ledger["candidates"][0]
    assert candidate["mapping_status"] == "ambiguous"
    assert len(candidate["implementation_evidence"]) == 2
    assert candidate["state"] == "insufficient_evidence"


def test_documented_get_does_not_hide_undocumented_post(tmp_path):
    spec = b"openapi: 3.0.3\npaths:\n  /orders/{id}:\n    get: {}\n"
    source = b'@app.route("/orders/<id>", methods=["GET", "POST"])\ndef orders():\n    return "ok"\n'
    core, _, _ = _catalog_core(tmp_path, documents=[("api/openapi.yaml", "openapi", spec)],
                               sources=[("src/routes.py", source, "Python")])
    report = issues.analyze_api_spec_drift(core)
    assert report["handlers_scanned"] == 2
    assert [(item["drift_kind"], item["method"]) for item in report["mismatches"]] == [
        ("undocumented_route", "POST")]


def test_any_method_handler_remains_unresolved(tmp_path):
    core, _, _ = _catalog_core(tmp_path, sources=[
        ("src/routes.py", b'path("orders/<id>", orders)\n', "Python")])
    report = issues.analyze_api_spec_drift(core)
    assert any("method" in gap and "src/routes.py" in gap for gap in report["gaps"])


@pytest.mark.parametrize(("kind", "text", "expected"), [
    ("graphql", "type User { id: ID! }\nschema { query: Root mutation: Mutations }\n"
     "type Root { user: User }\ntype Mutations { user: User }",
     [("QUERY", "Root.user"), ("MUTATION", "Mutations.user")]),
    ("protobuf", "package billing;\nservice A { rpc One (Req) returns (Rsp); }\n"
     "service B { rpc Two (Req) returns (Rsp); }",
     [("RPC", "/billing.A/One"), ("RPC", "/billing.B/Two")]),
])
def test_non_http_operation_context_and_identity_are_preserved(tmp_path, kind, text, expected):
    path = "api/schema.graphql" if kind == "graphql" else "api/service.proto"
    operations = issues._parse_graphql_or_proto_operations(
        {"format": kind, "path": path, "source_file_id": "accepted-document"}, text)
    assert [(item["method"], item["route"]) for item in operations] == expected
    assert all(item["spec_path"] == path and item["spec_source_id"] == "accepted-document" for item in operations)
    core, _, _ = _catalog_core(tmp_path, documents=[(path, kind, text.encode())])
    report = issues.analyze_api_spec_drift(core)
    assert report["specs_parsed"] == 1
    assert not report["mismatches"]
    assert any(kind in gap and path in gap and "mapping" in gap for gap in report["gaps"])
