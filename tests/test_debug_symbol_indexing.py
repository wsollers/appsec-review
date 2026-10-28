from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.config import JobConfig, StepConfig, TaskConfig
from appsec_review.config.compiler_target import CompilerTarget
from appsec_review.config.debug_symbols import parse_debug_symbol_settings
from appsec_review.debug_symbols.contract import (
    AddressRange, Extraction, RecordKind, SourceSpan, SymbolRecord,
)
from appsec_review.jobs.job_artifact_indexing.job import canonical_target_artifact_identity
from appsec_review.jobs.job_artifact_indexing import canonical_artifact_identity
from appsec_review.jobs.job_debug_symbol_indexing import build_job, load_accepted_debug_symbols
from appsec_review.observability import EventLog
from appsec_review.retrieval import (
    INDEX_SCHEMA, EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, write_manifest,
)
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import JobContext
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import put_bytes
from tests.handoff_fixture import write_fixture_handoff


SNAPSHOT = "a" * 64
RUN_ID = "2026-10-28-0001"
TOPOLOGY = {"decide": ("target",), "extract": ("clang_dwarf", "msvc_pdb"),
            "acceptance": ("publish_handoff",)}


@pytest.fixture(autouse=True)
def isolated_index_registration(monkeypatch):
    # The retrieval chunk owns central registration; exercise this producer independently.
    from appsec_review.retrieval import index
    if "debug_symbols" not in index.INDEX_NAMES:
        monkeypatch.setattr(index, "INDEX_NAMES", (*index.INDEX_NAMES, "debug_symbols"))


def _ref(root, path):
    return {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _seed(tmp_path, target="clang", *, debug=False, source_bytes=None, produced=False,
          binary_bytes=None, debug_bytes=None, source_path="src/main.cc", run_name="run"):
    root = tmp_path / run_name
    root.mkdir()
    artifacts = []
    for name, kind, content in [
        ("bin/private-program", "executable", binary_bytes if binary_bytes is not None else
         b"MZfixture" if target == "msvc" else b"\x7fELFfixture"),
        *([("symbols/private-program.pdb", "debug-information",
            debug_bytes if debug_bytes is not None else b"Microsoft C/C++ MSF 7.00\r\nfixture")]
          if debug else []),
    ]:
        artifact = {**put_bytes(root, content), "workspace_path": name, "kind": kind,
                    "artifact_origin": "target-intake"}
        artifact["canonical_identity"] = (
            canonical_artifact_identity(SNAPSHOT, "build-unit-1", artifact).value if produced else
            canonical_target_artifact_identity(SNAPSHOT, artifact).value)
        artifacts.append(artifact)
    language_sha = None
    if produced:
        language = root / "data" / "jobs" / "job_language_build" / "accepted-builds.json"
        atomic_json(language, {
            "schema": "appsec-review/language-build-handoff/1", "source_fingerprint": SNAPSHOT,
            "receipts": [{"build_unit_id": "build-unit-1", "terminal_status": "SUCCEEDED",
                          "image": {"image_id": "sha256:" + "d" * 64,
                                    "image_tag": "accepted/compiler:receipt", "user": "10001:10001"},
                          "artifacts": artifacts}]})
        language_handoff = language.parent / "handoff.json"
        write_fixture_handoff(root, language_handoff, {
            "status": "ACCEPTED", "job_id": "job_language_build",
            "outputs": {"acceptance.publish_handoff": {"artifact": _ref(root, language)}},
            "artifacts": [_ref(root, language)]})
        language_sha = file_sha256(language_handoff)
        atomic_json(language.parent / "latest.json", {
            "handoff_path": language_handoff.relative_to(root).as_posix(), "handoff_sha256": language_sha})
    identities = []
    for index_name in ("artifacts", "source"):
        path = root / "data" / "indices" / index_name / f"{index_name}.sqlite"
        builder = IndexBuilder(path, name=index_name, fingerprint="b" * 64,
                               target_snapshot=SNAPSHOT, shard_id=f"catalog-{index_name}")
        if index_name == "artifacts":
            for artifact in artifacts:
                builder.add_entity(EntityRecord(
                    LogicalIdentity.parse(artifact["canonical_identity"]), artifact["sha256"],
                    artifact["workspace_path"], "", artifact))
        else:
            source_ref = put_bytes(root, source_bytes) if source_bytes is not None else None
            source_digest = source_ref["sha256"] if source_ref else "c" * 64
            identity = LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT,
                                               {"path": source_path, "sha256": source_digest})
            from appsec_review.retrieval.model import SourceLocation
            location = SourceLocation(SNAPSHOT, source_path, source_digest, 0,
                                      len(source_bytes or b""), 1, 5, 1, 1, {}, "inventory-exact", 1.0)
            builder.add_entity(EntityRecord(identity, source_path, Path(source_path).name,
                                           source_bytes.decode() if source_bytes else "",
                                           {"path": source_path, "sha256": source_digest}, location))
        builder.add_coverage("fixture", "complete")
        identities.append(IndexIdentity(index_name, INDEX_SCHEMA, builder.build(), "b" * 64,
                                        path.relative_to(root).as_posix(), {}, (), f"catalog-{index_name}"))
    manifest = root / "data" / "indices" / "manifests" / "artifacts.json"
    write_manifest(manifest, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=tmp_path,
                   indexes=identities)
    summary = root / "data" / "jobs" / "job_artifact_indexing" / "accepted-index.json"
    atomic_json(summary, {"schema": "appsec-review/artifact-indexing/1", "source_fingerprint": SNAPSHOT,
                          "target_artifacts": [] if produced else artifacts, "gaps": [],
                          "language_build_handoff_sha256": language_sha,
                          "index_manifest": _ref(root, manifest)})
    handoff = summary.parent / "handoff.json"
    write_fixture_handoff(root, handoff, {"status": "ACCEPTED",
                         "job_id": "job_artifact_indexing",
                         "outputs": {"acceptance.publish_handoff": {
                             "artifact": _ref(root, summary), "index_manifest": _ref(root, manifest)}},
                         "artifacts": [_ref(root, summary), _ref(root, manifest)]})
    atomic_json(summary.parent / "latest.json", {"handoff_path": handoff.relative_to(root).as_posix(),
                                               "handoff_sha256": file_sha256(handoff)})
    settings = parse_debug_symbol_settings({"compiler_target": target})
    config = JobConfig("job_debug_symbol_indexing", "debug_symbol_indexing", 1, None, settings, {
        step: StepConfig(step, 1, {}, {task: TaskConfig(task, 1, {}) for task in tasks})
        for step, tasks in TOPOLOGY.items()
    })
    attempt = root / "data" / "jobs" / config.job_id / "attempts" / "attempt_0001"
    attempt.mkdir(parents=True)
    context = JobContext(RUN_ID, "attempt_0001", "test", tmp_path, root, attempt, root / "metadata",
                         {}, config, EventLog(attempt / "events.jsonl"), source_fingerprint=SNAPSHOT)
    return context, artifacts, identities


def _extractor(calls, *, gaps=()):
    def extract(binary, debug_file, *, target, settings):
        calls.append((binary, debug_file, target, settings))
        return Extraction((
            SymbolRecord("cu:1", RecordKind.COMPILATION_UNIT, "private-unit"),
            SymbolRecord("fn:1", RecordKind.SYMBOL, "private-function",
                         (AddressRange(4096, 4128),), SourceSpan("src/main.cc", 3),
                         "cu:1", {"signature": "int private-function()", "source_identity": "forged"}),
            SymbolRecord("type:1", RecordKind.TYPE_LAYOUT, "private-type",
                         data={"size_bytes": 8, "members": [{"offset": 0}]}),
        ), gaps, "fixture-reader/1")
    return extract


def _shard(context, result):
    manifest_ref = result["outputs"]["acceptance.publish_handoff"]["index_manifest"]
    manifest, _ = load_verified_manifest(context.run_root, context.run_root / manifest_ref["path"],
                                         manifest_ref["sha256"])
    raw = next(item for item in manifest["indexes"] if item["name"] == "debug_symbols")
    return raw, sqlite3.connect(context.run_root / raw["relative_path"])


@pytest.mark.parametrize("target,lane,other", [
    ("clang", "clang_dwarf", "msvc_pdb"), ("msvc", "msvc_pdb", "clang_dwarf"),
])
def test_routes_publish_normalized_evidence_and_preserve_upstream(tmp_path, target, lane, other):
    context, artifacts, upstream = _seed(tmp_path, target, debug=target == "msvc")
    calls = []
    job = build_job(extractor=_extractor(calls))
    result = job.execute(context)
    assert result["failed_units"] == []
    assert len(calls) == 1
    assert calls[0][2] is CompilerTarget(target)
    assert (calls[0][1] is not None) == (target == "msvc")
    skipped = result["outputs"][f"extract.{other}"]
    assert skipped["status"] == "SKIPPED"
    assert skipped["terminal_status"] == "SKIPPED_NA"
    assert job.units[-1].dependencies == ("extract.clang_dwarf", "extract.msvc_pdb")
    decision = result["outputs"]["decide.target"]
    document = json.loads((context.run_root / decision["artifact"]["path"]).read_text())
    assert document["selected_lane"] == lane
    assert document["compiler_target"] == target
    assert len(document["input_fingerprint"]) == 64
    selected = result["outputs"][f"extract.{lane}"]
    assert selected["input_fingerprint"] != decision["input_fingerprint"]
    raw, database = _shard(context, result)
    with database:
        rows = database.execute("SELECT kind, payload_json FROM entities").fetchall()
        assert len(rows) == 3
        payloads = [json.loads(row[1]) for row in rows]
        function = next(item for item in payloads if item["native_key"] == "fn:1")
        assert function["record_kind"] == "symbol"
        assert function["address_ranges"] == [{"start": 4096, "end": 4128}]
        assert function["artifact_identity"] == artifacts[0]["canonical_identity"]
        assert function["artifact_sha256"] == artifacts[0]["sha256"]
        assert "source_identity" not in function
        assert function["parent_key"] == "cu:1"
        assert function["signature"] == "int private-function()"
        assert function["evidence"]["sha256"] == artifacts[0]["sha256"]
        assert database.execute("SELECT COUNT(*) FROM relations").fetchone()[0] >= 4
        assert database.execute("SELECT COUNT(*) FROM coverage WHERE status != 'complete'").fetchone()[0]
    publication = result["outputs"]["acceptance.publish_handoff"]
    manifest = json.loads((context.run_root / publication["index_manifest"]["path"]).read_text())
    assert {(item["name"], item["sha256"]) for item in manifest["indexes"] if item["name"] != "debug_symbols"} == {
        (item.name, item.sha256) for item in upstream}
    assert raw["producer"]["job_id"] == job.job_id
    assert any("source" in gap for gap in publication["gaps"])
    events = [json.loads(line) for line in context.events.path.read_text().splitlines()]
    debug_events = [event for event in events if event["event"].startswith("DEBUG_SYMBOL_")]
    assert {event["event"] for event in debug_events} >= {
        "DEBUG_SYMBOL_TARGET_SELECTED", "DEBUG_SYMBOL_ARTIFACT_COMPLETED", "DEBUG_SYMBOL_INDEX_COMPLETED"}
    for event in debug_events:
        assert event["compiler_target"] == target
        assert event["lane"] == (other if event["event"] == "DEBUG_SYMBOL_LANE_SKIPPED" else lane)
        assert isinstance(event["duration_ms"], int)
        assert isinstance(event["gap_count"], int)
        assert "private" not in json.dumps(event)
    assert {"normalized_symbols", "symbol_coverage", "target_decision", "raw_artifact_refs"} <= {
        dataset.output_kind for dataset in job.datasets}
    assert next(item for item in job.datasets if item.output_kind == "raw_artifact_refs").disposition == "protected"
    assert job.consumes == ("job_artifact_indexing", "job_language_build")


@pytest.mark.parametrize("target", ["clang", "msvc"])
def test_rehash_drift_prevents_extractor_and_publication(tmp_path, target):
    context, artifacts, _ = _seed(tmp_path, target, debug=target == "msvc")
    (context.run_root / artifacts[0]["path"]).write_bytes(b"changed")
    calls = []
    result = build_job(extractor=_extractor(calls)).execute(context)
    assert result["failed_units"] == [f"extract.{'msvc_pdb' if target == 'msvc' else 'clang_dwarf'}"]
    assert calls == []
    assert "acceptance.publish_handoff" not in result["outputs"]
    assert "FrameworkIntegrityError" in context.events.path.read_text()


@pytest.mark.parametrize("reason", ["pdb_guid_age_mismatch", "tool_unavailable", "unsupported_binary_format"])
def test_pair_mismatch_or_missing_tool_is_unavailable_not_empty_success(tmp_path, reason):
    context, _, _ = _seed(tmp_path, "msvc", debug=True)
    def rejected(*args, **kwargs):
        return Extraction((), (reason,), "fixture-reader/1")
    result = build_job(extractor=rejected).execute(context)
    assert result["status"] == "COMPLETED_WITH_GAPS"
    assert reason in " ".join(result["outputs"]["acceptance.publish_handoff"]["gaps"])
    _, database = _shard(context, result)
    with database:
        assert database.execute("SELECT status FROM coverage").fetchall() == [("unavailable",)]
    events = context.events.path.read_text()
    assert "DEBUG_SYMBOL_ARTIFACT_FAILED" in events


def test_missing_pdb_skips_reader_and_names_gap(tmp_path):
    context, _, _ = _seed(tmp_path, "msvc")
    calls = []
    result = build_job(extractor=_extractor(calls)).execute(context)
    assert calls == []
    assert "missing_debug_artifact" in " ".join(result["outputs"]["acceptance.publish_handoff"]["gaps"])


def test_separate_debug_bytes_must_match_accepted_hash_before_reader(tmp_path):
    context, artifacts, _ = _seed(tmp_path, "msvc", debug=True)
    (context.run_root / artifacts[1]["path"]).write_bytes(b"modified debug bytes")
    calls = []
    result = build_job(extractor=_extractor(calls)).execute(context)
    assert calls == []
    assert result["failed_units"] == ["extract.msvc_pdb"]
    assert "acceptance.publish_handoff" not in result["outputs"]


def test_build_artifact_references_come_from_matching_accepted_language_metadata(tmp_path):
    context, artifacts, _ = _seed(tmp_path, produced=True)
    calls = []
    result = build_job(extractor=_extractor(calls)).execute(context)
    assert result["failed_units"] == []
    assert len(calls) == 1
    _, database = _shard(context, result)
    with database:
        payload = json.loads(database.execute("SELECT payload_json FROM entities LIMIT 1").fetchone()[0])
        assert payload["artifact_identity"] == artifacts[0]["canonical_identity"]


def test_post_reader_artifact_drift_does_not_publish_records(tmp_path):
    context, _, _ = _seed(tmp_path)
    def extract(binary, *args, **kwargs):
        binary.write_bytes(b"mutated while extracting")
        return Extraction((SymbolRecord("fn:1", RecordKind.SYMBOL, "unsafe"),), producer="fixture/1")
    result = build_job(extractor=extract).execute(context)
    assert result["failed_units"] == ["extract.clang_dwarf"]
    assert "acceptance.publish_handoff" not in result["outputs"]


def test_escaped_artifact_reference_is_an_integrity_failure(tmp_path):
    from appsec_review.jobs.job_debug_symbol_indexing.job import FrameworkIntegrityError, _probe

    artifact = {"artifact_identity": "fixture", "kind": "executable",
                "reference": {"path": "../outside", "sha256": "a" * 64, "size_bytes": 1}}
    with pytest.raises(FrameworkIntegrityError, match="reference is invalid"):
        _probe(tmp_path, artifact, 1024)


def test_reader_exception_is_an_observable_gap_not_an_integrity_success(tmp_path):
    context, _, _ = _seed(tmp_path)

    def broken_reader(*_args, **_kwargs):
        raise RuntimeError("private diagnostic")

    result = build_job(extractor=broken_reader).execute(context)
    assert result["status"] == "COMPLETED_WITH_GAPS"
    assert "reader_failed: RuntimeError" in " ".join(
        result["outputs"]["acceptance.publish_handoff"]["gaps"])
    events = context.events.path.read_text()
    assert "DEBUG_SYMBOL_ARTIFACT_FAILED" in events
    assert "private diagnostic" not in events


def test_accepted_loader_verifies_handoff_summary_decision_and_manifest(tmp_path):
    context, _, _ = _seed(tmp_path)
    result = build_job(extractor=_extractor([])).execute(context)
    handoff = context.attempt_root / "handoff.json"
    output = result["outputs"]["acceptance.publish_handoff"]
    write_fixture_handoff(context.run_root, handoff, {
        "status": "ACCEPTED",
        "job_id": "job_debug_symbol_indexing",
        "outputs": {"acceptance.publish_handoff": output},
        "artifacts": [output["artifact"], output["index_manifest"]]})
    atomic_json(context.run_root / "data" / "jobs" / "job_debug_symbol_indexing" / "latest.json", {
        "handoff_path": handoff.relative_to(context.run_root).as_posix(), "handoff_sha256": file_sha256(handoff)})
    accepted = load_accepted_debug_symbols(context.run_root)
    assert accepted["compiler_target"] == "clang"
    (context.run_root / accepted["decision"]["path"]).write_text("{}")
    with pytest.raises(ValueError, match="decision"):
        load_accepted_debug_symbols(context.run_root)


def test_decision_is_checked_before_extraction(tmp_path):
    from appsec_review.runtime import UnitContext
    context, _, _ = _seed(tmp_path)
    calls = []
    job = build_job(extractor=_extractor(calls))
    decision_unit = UnitContext(context, "decide.target", "decide", "target",
                                context.attempt_root / "decision", {})
    decision = job.units[0].handler(decision_unit)
    (context.run_root / decision["artifact"]["path"]).write_text("{}")
    extraction_unit = UnitContext(context, "extract.clang_dwarf", "extract", "clang_dwarf",
                                  context.attempt_root / "extraction", {"decide.target": decision})
    with pytest.raises(ValueError, match="decision"):
        job.units[1].handler(extraction_unit)
    assert calls == []


def test_limits_and_reader_failures_publish_named_coverage(tmp_path):
    context, _, _ = _seed(tmp_path)
    settings = parse_debug_symbol_settings({"compiler_target": "clang", "reader": {"max_records": 1}})
    context = replace(context, config=replace(context.config, settings=settings))
    result = build_job(extractor=_extractor([])).execute(context)
    assert "max_records" in " ".join(result["outputs"]["acceptance.publish_handoff"]["gaps"])
    _, database = _shard(context, result)
    with database:
        assert database.execute("SELECT COUNT(*) FROM entities").fetchone()[0] == 0


def test_immutable_shard_reused_and_target_fingerprint_differs(tmp_path):
    context, _, _ = _seed(tmp_path)
    extractor = _extractor([])
    first = build_job(extractor=extractor).execute(context)
    first_index, connection = _shard(context, first)
    connection.close()
    again = build_job(extractor=extractor).execute(context)
    second_index, connection = _shard(context, again)
    connection.close()
    assert first_index["sha256"] == second_index["sha256"]
    assert first_index["fingerprint"] == second_index["fingerprint"]
    altered = parse_debug_symbol_settings({"compiler_target": "msvc"})
    context = replace(context, config=replace(context.config, settings=altered))
    changed = build_job(extractor=extractor).execute(context)
    other_index, connection = _shard(context, changed)
    connection.close()
    assert other_index["fingerprint"] != first_index["fingerprint"]


@pytest.mark.parametrize("algorithm", ["sha256", "md5"])
def test_checksum_binds_source_ranges_to_accepted_source_bytes(tmp_path, algorithm):
    import hashlib
    content = b"int main() {\n  return 0;\n}\n"
    context, artifacts, _ = _seed(tmp_path, source_bytes=content)
    checksum = hashlib.new(algorithm, content).hexdigest()
    def extract(*args, **kwargs):
        return Extraction((SymbolRecord(
            "line:1", RecordKind.SOURCE_RANGE, ranges=(AddressRange(4096, 4100),),
            source=SourceSpan("C:\\private-secret\\src\\main.cc", 2, checksum=checksum,
                              checksum_kind=algorithm)),), producer="fixture/1")
    result = build_job(extractor=extract).execute(context)
    assert result["failed_units"] == []
    _, database = _shard(context, result)
    with database:
        identity, kind, payload_json = database.execute(
            "SELECT identity,kind,payload_json FROM entities").fetchone()
        payload = json.loads(payload_json)
        expected = LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {
            "path": "src/main.cc", "sha256": hashlib.sha256(content).hexdigest()})
        assert payload["source_identity"] == expected.value
        assert payload["source_path"] == "src/main.cc"
        assert payload["source_mapping"] == "checksum-verified"
        assert payload["line"] == 2
        assert kind == "source_span"
        assert "private-secret" not in payload_json
        assert database.execute("SELECT COUNT(*) FROM locations WHERE entity_id=?", (identity,)).fetchone()[0] == 1
        assert database.execute("SELECT COUNT(*) FROM relations WHERE target_id=?", (expected.value,)).fetchone()[0] == 1


def test_unbound_private_paths_never_enter_normalized_sqlite(tmp_path):
    context, _, _ = _seed(tmp_path)
    private = "C:\\private-secret\\build\\main.cc"
    def extract(*args, **kwargs):
        return Extraction((SymbolRecord(
            "source:1", RecordKind.COMPILATION_UNIT, private,
            source=SourceSpan(private, 3), data={"compilation_directory": "C:\\private-secret\\build",
                                                "source_path": private}),), producer="fixture/1")
    result = build_job(extractor=extract).execute(context)
    _, database = _shard(context, result)
    with database:
        rows = database.execute("SELECT name,text,payload_json FROM entities").fetchall()
        assert "private-secret" not in json.dumps(rows)
        assert "private-secret" not in json.dumps(database.execute("SELECT * FROM search_fts").fetchall())
        payload = json.loads(rows[0][2])
        assert payload["source_mapping"] == "unverified"
        assert payload["source_name_sha256"]
        assert payload["line"] == 3
        assert "source_identity" not in payload
    protected_ref = result["outputs"]["extract.clang_dwarf"]["artifact"]
    assert "private-secret" in (context.run_root / protected_ref["path"]).read_text()


def test_checksum_mismatch_or_missing_source_bytes_is_not_exact(tmp_path):
    context, _, _ = _seed(tmp_path, source_bytes=b"accepted bytes")
    def extract(*args, **kwargs):
        return Extraction((SymbolRecord(
            "line:1", RecordKind.SOURCE_RANGE, source=SourceSpan(
                "src/main.cc", 1, checksum="f" * 64, checksum_kind="sha256")),), producer="fixture/1")
    result = build_job(extractor=extract).execute(context)
    _, database = _shard(context, result)
    with database:
        payload = json.loads(database.execute("SELECT payload_json FROM entities").fetchone()[0])
        assert "source_identity" not in payload
        assert payload["source_mapping"] == "unverified"
    assert "source_checksum" in " ".join(result["outputs"]["acceptance.publish_handoff"]["gaps"])


def test_source_binding_can_use_hash_verified_accepted_sqlite_text(tmp_path):
    import hashlib
    content = b"int main() { return 0; }\n"
    context, _, _ = _seed(tmp_path, source_bytes=content)
    checksum = hashlib.sha256(content).hexdigest()
    (context.run_root / "data" / "shared" / "objects" / checksum).unlink()
    def extract(*args, **kwargs):
        return Extraction((SymbolRecord(
            "line:1", RecordKind.SOURCE_RANGE, source=SourceSpan(
                "/untrusted/build/root/main.cc", 1, checksum=checksum, checksum_kind="sha256")),),
            producer="fixture/1")
    result = build_job(extractor=extract).execute(context)
    assert result["status"] == "SUCCEEDED"
    _, database = _shard(context, result)
    with database:
        payload = json.loads(database.execute("SELECT payload_json FROM entities").fetchone()[0])
        assert payload["source_mapping"] == "checksum-verified"
        assert payload["source_path"] == "src/main.cc"


def test_clang_separate_debug_candidate_is_passed_only_from_accepted_catalog(tmp_path):
    context, artifacts, _ = _seed(tmp_path, debug=True)
    calls = []
    def extract(binary, debug_file, *, target, settings):
        calls.append(debug_file)
        if debug_file is None:
            return Extraction((), ("embedded_dwarf_unavailable",), "fixture/1")
        return Extraction((SymbolRecord("fn:1", RecordKind.SYMBOL, "accepted"),), producer="fixture/1")
    result = build_job(extractor=extract).execute(context)
    assert calls == [None, context.run_root / artifacts[1]["path"]]
    assert result["status"] == "SUCCEEDED"


def test_disabled_reader_never_runs_and_has_named_coverage_gap(tmp_path):
    context, _, _ = _seed(tmp_path)
    settings = parse_debug_symbol_settings({"enabled": False, "compiler_target": "clang"})
    context = replace(context, config=replace(context.config, settings=settings))
    calls = []
    result = build_job(extractor=_extractor(calls)).execute(context)
    assert calls == []
    assert "debug_symbol_indexing_disabled" in " ".join(result["outputs"]["acceptance.publish_handoff"]["gaps"])


@pytest.mark.parametrize("settings", [
    {"unknown": True}, {"compiler_target": "gcc"}, {"max_artifacts": 0},
    {"enabled": "true"}, {"reader": {"max_records": True}},
    {"reader": {"timeout_seconds": float("inf")}}, {"reader": {"unknown": 1}},
    {"reader": {"max_records": 10**400}},
    {"reader": {"tools": {"llvm_dwarfdump": {"path": "tool"}}}},
])
def test_settings_are_bounded_and_closed(settings):
    with pytest.raises(ValueError):
        parse_debug_symbol_settings(settings)


def test_settings_defaults_and_unavailable_accepted_loader(tmp_path):
    settings = parse_debug_symbol_settings({})
    assert settings["enabled"] is True
    assert settings["max_artifacts"] == 128
    assert settings["reader"]["max_records"] == 100000
    with pytest.raises(ValueError, match="accepted"):
        load_accepted_debug_symbols(tmp_path)
