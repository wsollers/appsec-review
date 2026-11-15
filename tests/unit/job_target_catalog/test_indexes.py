from __future__ import annotations

import hashlib
import json

import pytest

from appsec_review.interchange import GapCode, producer_gap, validate_unit_output
from appsec_review.jobs.job_target_catalog import job as catalog
from appsec_review.retrieval import EntityKind, LogicalIdentity, RelationKind
from tests.unit.job_target_catalog.support import (
    COMPILE, COMPONENTS, DEPENDENCIES, INDEX_UNITS, PARTITION, PROJECTS, SYSTEMS, TARGETS,
    capture_indexes, context, document, handler, partition, source,
)


@pytest.mark.parametrize("with_gap", [False, True], ids=["complete", "structured-gap"])
def test_path_index_preserves_text_locations_scope_and_inventory_gaps(tmp_path, monkeypatch, with_gap):
    builders = capture_indexes(monkeypatch)
    unit = context(tmp_path, INDEX_UNITS[0])
    entry = source(unit, raw="def café():\n    return 1\n".encode(), generated=True)
    excluded = source(unit, "platform.py", scope_role="supplied_platform")
    unknown = source(unit, "README", b"no language", None)
    large = source(unit, "large.py", size_bytes=16 * 1024 * 1024 + 1)
    gaps = [{"path": ".hg", "reason": "excluded_directory"}] if with_gap else []
    unit.outputs[PARTITION] = partition([entry, excluded, unknown, large], gaps)
    result = handler(unit.unit_id)(unit)
    validate_unit_output(result, unit_id=unit.unit_id, strict_gaps=True)
    [builder] = builders
    assert builder.identity == {"name": "source", "fingerprint": result["index_identity"]["fingerprint"],
                                "target_snapshot": "fixture-snapshot"}
    assert result["item_count"] == 4
    assert [row.name for row in builder.entities] == ["src/main.py", "README", "large.py"]
    row = builder.entities[0]
    assert row.text == "def café():\n    return 1\n"
    assert row.location.start_byte == 0 and row.location.end_byte == entry["size_bytes"]
    assert (row.location.start_line, row.location.end_line) == (1, 2)
    assert row.location.file_sha256 == entry["sha256"]
    assert row.location.mapping_method == "inventory-exact"
    assert row.payload["generated"] is True and row.payload["language"] == "Python"
    assert row.identity == LogicalIdentity.derive(EntityKind.SOURCE_FILE, "fixture-snapshot",
                                                 {"path": entry["path"], "sha256": entry["sha256"]})
    assert [row.text for row in builder.entities[1:]] == ["", ""]
    assert [row.location.end_line for row in builder.entities[1:]] == [1, 1]
    expected = [".hg: excluded_directory"] if with_gap else []
    assert [gap["reason"] for gap in result["gaps"]] == expected
    assert list(result["index_identity"]["gaps"]) == expected
    assert builder.coverage == [("target-files", "partial" if with_gap else "complete",
                                 result["gaps"][0]["gap_id"] if with_gap else None)]
    assert result["artifact"]["path"].startswith("data/indices/source/")


@pytest.mark.parametrize("mode", ["empty", "missing", "unicode"])
def test_path_index_empty_and_unreadable_sources_have_resolving_locations(tmp_path, monkeypatch, mode):
    builders = capture_indexes(monkeypatch)
    unit = context(tmp_path, INDEX_UNITS[0])
    entry = source(unit, raw=b"\xff" if mode == "unicode" else b"")
    if mode == "missing":
        (unit.job.target_root / entry["path"]).unlink()
    unit.outputs[PARTITION] = partition([entry])
    result = handler(unit.unit_id)(unit)
    validate_unit_output(result, unit_id=unit.unit_id, strict_gaps=True)
    [row] = builders[0].entities
    assert row.text == "" and row.location.end_line == 1
    assert [gap["reason"] for gap in result["gaps"]] == ([] if mode == "empty" else ["src/main.py: text decode failed"])
    assert builders[0].coverage == [
        ("target-files", "complete" if mode == "empty" else "partial",
         None if mode == "empty" else result["gaps"][0]["gap_id"])]


def test_symbol_index_matches_declarations_and_utf8_byte_offsets(tmp_path, monkeypatch):
    builders = capture_indexes(monkeypatch)
    unit = context(tmp_path, INDEX_UNITS[1])
    raw = "# café\n  def alpha():\nclass Beta:\nvar ignored\nfunction $value() {}\n".encode()
    entry = source(unit, raw=raw, generated=True)
    skipped = source(unit, "platform.py", scope_role="supplied_platform")
    unknown = source(unit, "README", b"class NotASource:\n", None)
    unit.outputs[PARTITION] = partition([entry, skipped, unknown])
    result = handler(unit.unit_id)(unit)
    validate_unit_output(result, unit_id=unit.unit_id, strict_gaps=True)
    [builder] = builders
    assert [row.name for row in builder.entities] == ["alpha", "Beta", "$value"]
    assert result["item_count"] == 3 and result["gaps"] == []
    assert builder.coverage == [("declarations", "complete", None)]
    assert [row.location.start_line for row in builder.entities] == [2, 3, 5]
    assert builder.entities[0].location.start_byte == len("# café\n".encode())
    assert (builder.entities[0].location.start_column, builder.entities[0].location.end_column) == (7, 12)
    for row in builder.entities:
        assert raw[row.location.start_byte:row.location.end_byte].decode().rstrip() == row.text
        assert row.payload["language"] == "Python" and row.payload["generated"] is True
        assert row.location.mapping_method == "source-line-exact"
    file_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, "fixture-snapshot",
                                     {"path": entry["path"], "sha256": entry["sha256"]})
    assert [(rel.kind, rel.source_id, rel.target_id, rel.exact, rel.confidence) for rel in builder.relations] == [
        (RelationKind.DEFINES, file_id.value, row.identity.value, True, 1.0) for row in builder.entities]
    assert result["artifact"]["path"].startswith("data/indices/analysis/")


@pytest.mark.parametrize("mode", ["byte-bound", "missing", "unicode"])
def test_symbol_index_records_file_scoped_bounds_and_decode_gaps(tmp_path, monkeypatch, mode):
    builders = capture_indexes(monkeypatch)
    unit = context(tmp_path, INDEX_UNITS[1])
    entry = source(unit, raw=b"\xff" if mode == "unicode" else b"def value():\n")
    if mode == "byte-bound":
        entry["size_bytes"] = 16 * 1024 * 1024 + 1
    if mode == "missing":
        (unit.job.target_root / entry["path"]).unlink()
    unit.outputs[PARTITION] = partition([entry])
    result = handler(unit.unit_id)(unit)
    validate_unit_output(result, unit_id=unit.unit_id, strict_gaps=True)
    reason = "symbol source byte bound reached" if mode == "byte-bound" else "text decode failed"
    assert [gap["reason"] for gap in result["gaps"]] == [f"src/main.py: {reason}"]
    assert result["item_count"] == 0 and builders[0].entities == []
    assert builders[0].coverage == [("declarations", "partial", result["gaps"][0]["gap_id"])]


def test_symbol_limit_stops_current_file_and_remaining_files_at_fifty_thousand(tmp_path, monkeypatch):
    builders = capture_indexes(monkeypatch)
    unit = context(tmp_path, INDEX_UNITS[1])
    entry = source(unit, raw=b"def value():\n" * 50_001)
    later = source(unit, "later.py", b"def forbidden():\n")
    unit.outputs[PARTITION] = partition([entry, later])
    result = handler(unit.unit_id)(unit)
    validate_unit_output(result, unit_id=unit.unit_id, strict_gaps=True)
    assert result["item_count"] == len(builders[0].entities) == 50_000
    assert [gap["reason"] for gap in result["gaps"]] == ["symbol index bound reached"]
    assert builders[0].entities[-1].location.start_line == 50_000
    assert {row.location.path for row in builders[0].entities} == {"src/main.py"}


def test_component_index_preserves_every_component_and_omits_empty_text_fields(tmp_path, monkeypatch):
    builders = capture_indexes(monkeypatch)
    items = [{"component_id": "component:0001", "root": ".", "manifest": None, "manifest_sha256": None},
             {"component_id": "component:0002", "root": "sub", "manifest": "sub/package.json", "manifest_sha256": "abc"}]
    unit = context(tmp_path, INDEX_UNITS[2], {
        COMPONENTS: {"components": items, "artifact": {"path": "components.json", "sha256": "a" * 64}}})
    result = handler(unit.unit_id)(unit)
    validate_unit_output(result, unit_id=unit.unit_id, strict_gaps=True)
    assert [row.payload for row in builders[0].entities] == items
    assert [row.text for row in builders[0].entities] == [
        "component:0001 .", "component:0002 sub sub/package.json abc"]
    assert result["item_count"] == 2 and result["gaps"] == []
    assert result["index_identity"]["name"] == "components"
    assert builders[0].coverage == [("components", "complete")]


@pytest.mark.parametrize("bad_index", [-1, 0, 1, 2, 3], ids=["valid", "source", "symbols", "components", "documents"])
@pytest.mark.parametrize("damage", ["missing", "hash"])
def test_validate_catalog_verifies_each_index_and_preserves_gap_order(tmp_path, bad_index, damage):
    unit = context(tmp_path, "publish_catalog.validate_catalog")
    for i, unit_id in enumerate(INDEX_UNITS):
        path = unit.job.run_root / f"index-{i}.sqlite"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"index")
        artifact = {"path": path.name, "sha256": hashlib.sha256(b"index").hexdigest()}
        unit.outputs[unit_id] = {
            "artifact": artifact,
            "gaps": [producer_gap(GapCode.PRODUCER_REPORTED_GAP, f"{i}: fixture gap",
                                  unit_id=unit_id, scope_id=f"s-{i}")],
        }
        if i == bad_index:
            if damage == "missing":
                path.unlink()
            else:
                path.write_bytes(b"changed")
    if bad_index >= 0:
        with pytest.raises(catalog.CatalogIntegrityError, match=f"^catalog artifact failed validation: {INDEX_UNITS[bad_index]}$"):
            handler(unit.unit_id)(unit)
    else:
        result = handler(unit.unit_id)(unit)
        validate_unit_output(result, unit_id=unit.unit_id, strict_gaps=True)
        assert result == {
            "status": "VALID",
            "validated": list(INDEX_UNITS),
            "upstream_gaps": [f"{i}: fixture gap" for i in range(4)],
            "gaps": [],
        }


@pytest.mark.parametrize("populated", [False, True], ids=["empty", "populated"])
def test_publish_build_index_manifest_catalog_and_event_wiring(tmp_path, monkeypatch, populated):
    builders = capture_indexes(monkeypatch)
    unit = context(tmp_path, "publish_catalog.publish_handoff")
    artifact_units = (
        PARTITION, "repository_discovery.census_languages", PROJECTS, SYSTEMS, COMPILE,
        TARGETS, COMPONENTS, DEPENDENCIES, *INDEX_UNITS,
    )
    for i, name in enumerate(artifact_units):
        unit.outputs[name] = {"artifact": {"path": f"artifact-{i}", "sha256": "a" * 64, "size_bytes": 1}}
    for name, index_name in zip(INDEX_UNITS, ("source", "analysis", "components", "documents")):
        unit.outputs[name]["index_identity"] = {
            "name": index_name, "schema": "appsec-review/retrieval-index/2",
            "sha256": "a" * 64, "fingerprint": "b" * 64,
            "relative_path": f"data/indices/{index_name}/fixture.sqlite",
            "producer": {"job": "job_target_catalog", "unit": name}, "gaps": [],
        }
    targets = ([{"build_unit_id": "root|cmake", "root": ".", "build_system": "cmake"},
                {"build_unit_id": "generic", "root": "sub"}] if populated else [])
    compile_files = [{"path": "build/compile_commands.json", "sha256": "c" * 64}] if populated else []
    unit.outputs[TARGETS].update(
        targets=targets,
        build_gap_reasons=["build: unavailable"] if not populated else [],
        gaps=[],
    )
    unit.outputs[COMPILE]["files"] = compile_files
    unit.outputs["publish_catalog.validate_catalog"] = {
        "status": "VALID",
        "upstream_gaps": ["upstream: fixture"] if not populated else [],
        "gaps": [],
    }
    calls = []

    def manifest(path, **kwargs):
        calls.append((path, kwargs))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"schema": "appsec-review/index-manifest/2"}))

    monkeypatch.setattr(catalog, "write_manifest", manifest)
    result = handler(unit.unit_id)(unit)
    validate_unit_output(result, unit_id=unit.unit_id, strict_gaps=True)
    doc = document(unit, result)
    assert doc == {
        "schema": "appsec-review/target-catalog/1", "source_fingerprint": "fixture-snapshot",
        "artifacts": {name: unit.outputs[name]["artifact"] for name in artifact_units},
        "validation": {"status": "VALID", "gaps": ["upstream: fixture"] if not populated else []},
        "security_findings": [],
    }
    expected_reasons = [] if populated else [
        "build: unavailable",
        "no build targets discovered",
        "compile_commands.json not present",
    ]
    assert [gap["reason"] for gap in result["gaps"]] == expected_reasons
    assert [row.identity.kind for row in builders[0].entities] == (
        [EntityKind.BUILD_ACTION, EntityKind.BUILD_ACTION, EntityKind.COMPILE_UNIT] if populated else [])
    if populated:
        assert [row.name for row in builders[0].entities] == ["cmake", "generic", "build/compile_commands.json"]
        assert builders[0].entities[-1].payload == {"compile_database_sha256": "c" * 64}
        assert [row.payload for row in builders[0].entities[:2]] == targets
    by_scope = {gap["scope_id"]: gap["gap_id"] for gap in result["gaps"]}
    assert builders[0].coverage == [
        ("build-actions", "complete" if populated else "partial",
         None if populated else by_scope["build-actions"]),
        ("compile-units", "complete" if populated else "unavailable",
         None if populated else by_scope["compile-units"]),
    ]
    [(path, kwargs)] = calls
    assert path == unit.job.run_root / "data/indices/manifests/catalog-attempt_0001.json"
    assert kwargs["target_root"] == unit.job.target_root
    assert kwargs["run_id"] == "fixture-run" and kwargs["target_snapshot"] == "fixture-snapshot"
    assert [index.name for index in kwargs["indexes"]] == ["source", "analysis", "components", "documents", "build"]
    assert tuple(kwargs["indexes"][-1].gaps) == (() if populated else ("build: unavailable",))
    assert result["index_manifest"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert unit.events == [("REVIEW_SCOPE_CATALOGED", {
        "unit_id": unit.unit_id, "source_receipt": unit.outputs[PARTITION]["artifact"],
        "project_receipt": unit.outputs[PROJECTS]["artifact"],
        "build_target_receipt": unit.outputs[TARGETS]["artifact"], "catalog_receipt": result["artifact"],
        "metrics_semantics": "appsec-review/review-metrics-semantics/1",
    })]
