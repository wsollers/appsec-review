from __future__ import annotations

import hashlib
import json
import sqlite3
from types import SimpleNamespace

import pytest

from appsec_review.interchange import validate_unit_output
from appsec_review.jobs.job_target_catalog import job as catalog
from appsec_review.retrieval import EntityKind, LogicalIdentity, RelationKind
from tests.unit.job_target_catalog.support import (
    INDEX_UNITS, PARTITION, capture_indexes, context, handler, partition, source,
)

UNIT = INDEX_UNITS[3]
REQUIRED_KINDS = ("design", "dfd", "openapi", "postman", "threat_model", "unit_test")


@pytest.mark.parametrize("layout", ["compact", "pretty", "crlf"])
def test_openapi_json_structural_operations_survive_catalog_serialization(tmp_path, layout):
    unit = context(tmp_path, UNIT)
    operation = {"operationId": "orders", "parameters": [{"name": "q", "in": "query"}],
                 "responses": {"200": {"description": "ok"}}, "requestBody": {"required": True}}
    spec = {"openapi": "3.0.3",
            "components": {"schemas": {"Example": {"example": {"/orders": {"get": operation}}}}},
            "paths": {"/orders": {"get": operation, "post": {"responses": {}}},
                      "/other": {"get": {"responses": {}}}}}
    text = json.dumps(spec, indent=None if layout == "compact" else 2)
    if layout == "crlf":
        text = text.replace("\n", "\r\n")
    raw = text.encode()
    entry = source(unit, "openapi.json", raw, None)
    unit.outputs[PARTITION] = partition([entry])
    result = handler(UNIT)(unit)
    validate_unit_output(result, unit_id=UNIT, strict_gaps=True)
    assert not any(gap["code"] == "parser_error" for gap in result["gaps"])
    with sqlite3.connect(unit.job.run_root / result["artifact"]["path"]) as db:
        rows = db.execute(
            "SELECT e.identity, e.payload_json, l.start_line, l.end_line, l.start_byte, l.end_byte, "
            "l.file_sha256 FROM entities e JOIN locations l ON l.entity_id=e.identity"
        ).fetchall()
    assert len(rows) == len({row[0] for row in rows}) == 3
    for _, payload, start, end, start_byte, end_byte, digest in rows:
        payload = json.loads(payload)
        assert payload["authority"] == "declared"
        assert digest == entry["sha256"]
        assert raw[start_byte:end_byte] == b"".join(raw.splitlines(keepends=True)[start - 1:end])
        if layout != "compact":
            assert start > next(i for i, line in enumerate(text.splitlines(), 1) if '"paths":' in line)
        fields = payload["fields"]
        if (fields["route"], fields["method"]) == ("/orders", "GET"):
            assert fields["parameters"] == operation["parameters"]
            assert fields["responses"] == ["200"] and fields["request_body"] is True


@pytest.mark.parametrize("setting", ["max_parse_depth", "max_parse_nodes"])
def test_openapi_json_parser_budgets_produce_partial_catalog(tmp_path, setting):
    from dataclasses import replace

    unit = context(tmp_path, UNIT)
    spec = {"openapi": "3.0.3", "paths": {"/orders": {"get": {"responses": {}}}}}
    entry = source(unit, "openapi.json", json.dumps(spec, indent=2).encode(), None)
    unit.job.config.typed_settings = replace(unit.job.config.typed_settings, **{setting: 1})
    unit.outputs[PARTITION] = partition([entry])
    result = handler(UNIT)(unit)
    validate_unit_output(result, unit_id=UNIT, strict_gaps=True)
    assert result["item_count"] == 0
    assert any(gap["code"] == "producer_reported_gap" and gap["scope_id"] == "openapi.json"
               and "parse_error (specification parsing bound reached)" in gap["reason"]
               for gap in result["gaps"])
    with sqlite3.connect(unit.job.run_root / result["artifact"]["path"]) as db:
        assert db.execute("SELECT status FROM coverage WHERE area='target-documents:openapi'").fetchone() == (
            "unavailable",)
        assert db.execute("SELECT status FROM coverage WHERE area='target-documents'").fetchone() == (
            "partial",)


@pytest.mark.parametrize("text", [
    '{"openapi":"3.0.3","paths":{"/x":{"get":{},"get":{}}}}',
    '{"openapi":"3.0.3","paths":{"/x":{"get":{"responses":[]}}}}',
    '{"openapi":"3.0.3","paths":{"/x":{"get":{"parameters":null}}}}',
    'openapi: 3.0.3\npaths:\n  /x:\n    get: {}\n',
], ids=["duplicate-operation", "invalid-responses", "invalid-parameters", "yaml-in-json"])
def test_openapi_unsupported_shapes_remain_gaps_not_facts(tmp_path, text):
    unit = context(tmp_path, UNIT)
    entry = source(unit, "openapi.json", text.encode(), None)
    unit.outputs[PARTITION] = partition([entry])
    result = handler(UNIT)(unit)
    assert result["item_count"] == 0
    assert any(gap["scope_id"] == "openapi.json" and "parse_error" in gap["reason"]
               for gap in result["gaps"])


def test_openapi_record_budget_and_unresolved_references_remain_gaps(tmp_path):
    from dataclasses import replace

    unit = context(tmp_path, UNIT)
    spec = {"openapi": "3.0.3", "paths": {
        "/x": {"get": {"responses": {"200": {"$ref": "https://invalid.example/response"}}}},
        "/y": {"get": {"responses": {}}},
    }}
    entry = source(unit, "openapi.json", json.dumps(spec).encode(), None)
    unit.job.config.typed_settings = replace(unit.job.config.typed_settings, max_records=1)
    unit.outputs[PARTITION] = partition([entry])
    result = handler(UNIT)(unit)
    validate_unit_output(result, unit_id=UNIT, strict_gaps=True)
    assert result["item_count"] == 1
    reasons = [gap["reason"] for gap in result["gaps"]]
    assert any("record_limit" in reason for reason in reasons)
    assert any("unresolved specification reference" in reason for reason in reasons)


def fixture(tmp_path, monkeypatch, *, kinds=REQUIRED_KINDS, records=None, links=(), gaps=()):
    builders = capture_indexes(monkeypatch)
    unit = context(tmp_path, UNIT)
    entry = source(unit, "docs/design.md", "# Café\n\nBoundary.\n".encode(), None)
    unit.outputs[PARTITION] = partition([entry])
    entries = [{"kind": kind, "path": entry["path"]} for kind in kinds]
    if records is None:
        records = [{"id": f"record-{i}", "path": entry["path"], "file_sha256": entry["sha256"],
                    "line": 1 if i == 0 else 3, "end_line": 1 if i == 0 else 3,
                    "kind": kind, "subtype": "heading", "text": "Café" if i == 0 else "Boundary.",
                    "authority": "intent", "fields": {"boundary": "TB1"}}
                   for i, kind in enumerate(kinds)]
    calls = []

    def select(files):
        assert files == [entry]
        calls.append(("select", files))
        return entries

    def collect(target, snapshot, selected, **limits):
        calls.append(("collect", target, snapshot, selected, limits))
        return SimpleNamespace(records=records, links=list(links), gaps=list(gaps))

    monkeypatch.setattr(catalog, "select_document_inventory", select)
    monkeypatch.setattr(catalog, "collect_target_documents", collect)
    return unit, builders, records, entries, calls


def test_document_index_binds_limits_releases_byte_spans_links_and_complete_coverage(tmp_path, monkeypatch):
    links = [{"from": "record-0", "to": "record-1", "exact": True,
              "relation": "mentions_boundary", "authority": "intent"}]
    unit, builders, records, entries, calls = fixture(tmp_path, monkeypatch, links=links)
    fingerprint_calls = []
    real_fingerprint = catalog.index_fingerprint

    def fingerprint(**kwargs):
        fingerprint_calls.append(kwargs)
        return real_fingerprint(**kwargs)

    monkeypatch.setattr(catalog, "index_fingerprint", fingerprint)
    result = handler(UNIT)(unit)
    validate_unit_output(result, unit_id=UNIT, strict_gaps=True)
    settings = unit.job.config.typed_settings
    expected_limits = {name: getattr(settings, name) for name in (
        "max_files", "max_file_bytes", "max_records", "max_chunk_lines",
        "max_chunk_bytes", "max_parse_depth", "max_parse_nodes")}
    assert calls == [("select", unit.outputs[PARTITION]["files"]),
                     ("collect", unit.job.target_root, "fixture-snapshot", entries, expected_limits)]
    [identity] = fingerprint_calls
    assert identity == {
        "name": "documents", "target_snapshot": "fixture-snapshot",
        "producer_artifacts": [unit.outputs[PARTITION]["artifact"]],
        "tool_identity": {"producer": "job_target_catalog", "limits": {
            "files": settings.max_files, "file_bytes": settings.max_file_bytes,
            "records": settings.max_records, "chunk_lines": settings.max_chunk_lines,
            "chunk_bytes": settings.max_chunk_bytes, "parse_depth": settings.max_parse_depth,
            "parse_nodes": settings.max_parse_nodes}},
        "parser_identity": f"{catalog.PARSER_IDENTITY}:fixture/1",
        "normalizer_identity": "retrieval-normalizer/1", "mapping_identity": "source-line-exact/1",
    }
    [builder] = builders
    assert result["item_count"] == 6 and result["link_count"] == 1 and result["gaps"] == []
    raw = (unit.job.target_root / "docs/design.md").read_bytes()
    for row, record in zip(builder.entities, records):
        assert row.identity == LogicalIdentity.derive(
            EntityKind.DOCUMENT_RECORD, "fixture-snapshot", {"record_id": record["id"]})
        assert row.text == record["text"]
        assert row.payload == {"record_type": "target_document", "document_kind": record["kind"],
                               "subtype": "heading", "authority": "intent", "fields": {"boundary": "TB1"}}
        assert raw[row.location.start_byte:row.location.end_byte].decode().strip() in {"# Café", "Boundary."}
        assert row.location.file_sha256 == hashlib.sha256(raw).hexdigest()
        assert row.location.mapping_method == "source-line-exact"
    [relation] = builder.relations
    assert (relation.kind, relation.source_id, relation.target_id, relation.exact, relation.confidence) == (
        RelationKind.REFERENCES, builder.entities[0].identity.value, builder.entities[1].identity.value, True, 1)
    assert relation.payload == {"relation": "mentions_boundary", "authority": "intent"}
    assert builder.coverage == [
        *((f"target-documents:{kind}", "complete", None) for kind in REQUIRED_KINDS),
        ("target-documents", "complete", None)]
    assert result["index_identity"]["schema"] == "appsec-review/retrieval-index/2"
    assert result["artifact"]["path"].startswith("data/indices/documents/")


def test_document_index_reports_missing_kinds_parser_and_inventory_gaps(tmp_path, monkeypatch):
    unit, builders, _, _, _ = fixture(tmp_path, monkeypatch, kinds=("design",), gaps=[
        {"path": "api/openapi.json", "reason": "parse_error", "detail": "invalid JSON"},
        {"path": "", "reason": "bound", "detail": ""}])
    unit.outputs[PARTITION]["gaps"] = [
        {"path": "private", "reason": "excluded_directory"},
        {"path": "huge.md", "reason": "oversized", "detail": "20 MiB"},
    ]
    unit.job.review_policy.releases.values = {}
    result = handler(UNIT)(unit)
    validate_unit_output(result, unit_id=UNIT, strict_gaps=True)
    expected_reasons = [
        *(f"{kind}: no accepted target document" for kind in REQUIRED_KINDS if kind != "design"),
        "api/openapi.json: parse_error (invalid JSON)",
        "<inventory>: bound",
        "source inventory private: excluded_directory",
        "source inventory huge.md: oversized: 20 MiB",
    ]
    assert [gap["reason"] for gap in result["gaps"]] == expected_reasons
    assert list(result["index_identity"]["gaps"]) == expected_reasons
    by_scope = {gap["scope_id"]: gap["gap_id"] for gap in result["gaps"]}
    assert builders[0].coverage == [
        *(
            (f"target-documents:{kind}",
             "partial" if kind == "design" else "unavailable",
             result["gaps"][0]["gap_id"] if kind == "design" else by_scope[f"target-documents:{kind}"])
            for kind in REQUIRED_KINDS
        ),
        ("target-documents", "partial", ",".join(gap["gap_id"] for gap in result["gaps"][:10])),
    ]


@pytest.mark.parametrize("count", [200, 201], ids=["at-bound", "over-bound"])
def test_document_gap_bound_retains_first_two_hundred_and_names_omissions(tmp_path, monkeypatch, count):
    gaps = [{"path": f"file-{i}", "reason": "parse_error", "detail": "invalid"} for i in range(count)]
    unit, builders, _, _, _ = fixture(tmp_path, monkeypatch, gaps=gaps)
    result = handler(UNIT)(unit)
    validate_unit_output(result, unit_id=UNIT, strict_gaps=True)
    expected = [f"file-{i}: parse_error (invalid)" for i in range(200)]
    if count > 200:
        expected.append("target document gaps truncated: 1 additional gap(s)")
    assert [gap["reason"] for gap in result["gaps"]] == expected
    assert builders[0].coverage[-1] == (
        "target-documents", "partial", ",".join(gap["gap_id"] for gap in result["gaps"][:10])
    )


@pytest.mark.parametrize("damage", ["escape", "hash", "line-zero", "missing", "reversed", "too-long"])
def test_document_index_refuses_nonresolving_inventory_records(tmp_path, monkeypatch, damage):
    unit, builders, records, _, _ = fixture(tmp_path, monkeypatch, kinds=("design",))
    path = unit.job.target_root / "docs/design.md"
    if damage == "hash":
        path.write_text("changed")
    elif damage == "missing":
        path.unlink()
    elif damage == "escape":
        records[0]["path"] = "../outside.md"
        (tmp_path / "outside.md").write_bytes(path.read_bytes())
    elif damage == "line-zero":
        records[0]["line"] = 0
    elif damage == "reversed":
        records[0].update(line=2, end_line=1)
    else:
        records[0]["end_line"] = 4
    expected_class = (catalog.CatalogDocumentIntegrityError if damage in {"escape", "hash", "missing"}
                      else catalog.CatalogIntegrityError)
    expected = ("accepted target source hash mismatch: docs/design.md" if damage == "hash" else
                f"accepted target source missing or escaped: {records[0]['path']}" if damage in {"escape", "missing"} else
                "document source location cannot be resolved: docs/design.md")
    with pytest.raises(expected_class, match=expected):
        handler(UNIT)(unit)
    assert builders[0].entities == []
    assert not builders[0].path.exists()


def test_document_index_additional_interface_kind_is_covered_only_when_present(tmp_path, monkeypatch):
    additional = sorted(catalog.ADDITIONAL_INTERFACE_KINDS)[0]
    unit, builders, _, _, _ = fixture(tmp_path, monkeypatch, kinds=(*REQUIRED_KINDS, additional))
    result = handler(UNIT)(unit)
    assert result["item_count"] == 7 and result["gaps"] == []
    assert (f"target-documents:{additional}", "complete", None) in builders[0].coverage


def test_document_index_nonexact_relation_exposes_missing_ambiguity_contract(tmp_path, monkeypatch):
    unit, _, _, _, _ = fixture(tmp_path, monkeypatch, links=[
        {"from": "record-0", "to": "record-1", "exact": False,
         "relation": "mentions_boundary", "authority": "intent"}])
    with pytest.raises(ValueError, match="^non-exact relationships require an ambiguity explanation$"):
        handler(UNIT)(unit)
    assert unit.unit_id == "retrieval_indexes.build_target_documents"
