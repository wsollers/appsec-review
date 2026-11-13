"""The ``extract.<lane>`` handlers over a frozen decision, with the symbol reader faked at its
boundary: routing, pairing with debug companions, every named coverage gap, the integrity
failures that stop publication, bounds, the written evidence and the emitted events."""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from appsec_review.config.compiler_target import CompilerTarget
from appsec_review.debug_symbols.contract import (
    AddressRange, Extraction, RecordKind, SymbolIntegrityError, SymbolRecord,
)
from appsec_review.jobs.job_debug_symbol_indexing.job import FrameworkIntegrityError
from appsec_review.retrieval import INDEX_SCHEMA
from tests.unit.job_debug_symbol_indexing.support import (
    ELF, MSF, MZ, accepted_inputs, artifact, build_job, decide, events, extracted, extractor, handlers, job_context,
    manifest, payloads, shard, unit,
)


def _run(tmp_path, monkeypatch, *, target="clang", settings=None, artifacts=None, reader=None, gaps=(), lane=None):
    """Decide, then run one extraction lane over ``artifacts`` (default: one binary of the target)."""
    context = job_context(tmp_path, target=target, settings=settings)
    run_root = context.run_root
    if artifacts is None:
        artifacts = [("bin/program", MZ if target == "msvc" else ELF, "executable")]
        if target == "msvc":
            artifacts.append(("symbols/program.pdb", MSF, "debug-information"))
    items = [artifact(run_root, name, content, kind) for name, content, kind in artifacts]
    calls = []
    reader = reader or extractor(calls)
    job = build_job(extractor=reader)
    decision = decide(monkeypatch, job, context, accepted_inputs(items, manifest(run_root), gaps=list(gaps)))
    lane = lane or ("msvc_pdb" if target == "msvc" else "clang_dwarf")
    result = handlers(job)[f"extract.{lane}"](unit(context, f"extract.{lane}", {"decide.target": decision}))
    return SimpleNamespace(context=context, items=items, result=result, calls=calls, decision=decision, job=job,
                           lane=lane)


def _coverage(run):
    with shard(run.context, run.result) as database:
        return database.execute("SELECT area, status, gap FROM coverage ORDER BY area").fetchall()


def _gaps(run, *gaps):
    return [f"{run.items[0]['artifact_identity']}: {gap}" for gap in gaps]


# --- routing ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("target,lane,other", [("clang", "clang_dwarf", "msvc_pdb"), ("msvc", "msvc_pdb", "clang_dwarf")])
def test_selected_lane_extracts_and_the_other_lane_persists_a_skipped_result(tmp_path, monkeypatch, target, lane, other):
    run = _run(tmp_path, monkeypatch, target=target)
    assert run.result["status"] == "COMPLETED" and run.result["terminal_status"] == "SUCCEEDED"
    assert (run.result["record_count"], run.result["artifact_count"], run.result["gaps"]) == (3, 1, [])
    assert len(run.calls) == 1 and run.calls[0][2] is CompilerTarget(target)
    assert (run.calls[0][1] is not None) == (target == "msvc")
    assert run.calls[0][3] == run.context.config.settings["reader"]
    skipped = handlers(run.job)[f"extract.{other}"](unit(run.context, f"extract.{other}", {"decide.target": run.decision}))
    assert skipped == {"status": "SKIPPED", "terminal_status": "SKIPPED_NA", "reason": "unselected_compiler_target",
                       "input_fingerprint": skipped["input_fingerprint"], "indexes": [], "gaps": []}
    assert len({skipped["input_fingerprint"], run.result["input_fingerprint"], run.decision["input_fingerprint"]}) == 3
    assert len(run.calls) == 1, "the skipped lane never calls the reader"
    names = [event["event"] for event in events(run.context)]
    assert names == ["DEBUG_SYMBOL_TARGET_SELECTED", "DEBUG_SYMBOL_ARTIFACT_COMPLETED", "DEBUG_SYMBOL_LANE_SKIPPED"]
    lane_skipped = events(run.context)[-1]
    assert (lane_skipped["lane"], lane_skipped["compiler_target"], lane_skipped["unit_id"]) == (other, target, f"extract.{other}")
    completed = events(run.context)[1]
    assert (completed["lane"], completed["record_count"], completed["artifact_count"], completed["gap_count"]) == (lane, 3, 1, 0)
    for event in events(run.context):
        assert "private" not in json.dumps(event) and isinstance(event["duration_ms"], int)


def test_extraction_publishes_normalized_records_without_private_or_asserted_identity(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch)
    (index,) = run.result["indexes"]
    assert index["name"] == "debug_symbols" and index["schema"] == INDEX_SCHEMA and index["shard_id"] == "symbols-clang_dwarf"
    assert index["fingerprint"] == run.result["input_fingerprint"] and index["gaps"] == ()
    assert index["producer"]["job_id"] == "job_debug_symbol_indexing" and index["producer"]["lane"] == "clang_dwarf"
    rows = payloads(run.context, run.result)
    assert sorted(row["record_kind"] for row in rows) == ["compilation_unit", "symbol", "type_layout"]
    function = next(row for row in rows if row["native_key"] == "fn:1")
    reference = run.items[0]["reference"]
    assert function["address_ranges"] == [{"start": 4096, "end": 4128}]
    assert function["artifact_identity"] == run.items[0]["artifact_identity"]
    assert function["artifact_sha256"] == function["debug_sha256"] == reference["sha256"]
    assert function["evidence"] == function["debug_evidence"] == dict(reference)
    assert "source_identity" not in function and "location" not in function
    assert function["parent_key"] == "cu:1" and function["signature"] == "int private-function()"
    assert function["compiler_target"] == "clang" and function["reader_identity"] == "fixture-reader/1"
    assert "source_mapping" not in function and "line" not in function and function["reader_executions"] == []
    layout = next(row for row in rows if row["native_key"] == "type:1")
    assert layout["size_bytes"] == 8 and layout["members"] == [{"offset": 0}] and layout["parent_key"] is None
    with shard(run.context, run.result) as database:
        kinds = database.execute("SELECT kind, COUNT(*) FROM entities GROUP BY kind ORDER BY kind").fetchall()
        assert kinds == [("compile_unit", 1), ("ir_entity", 1), ("symbol", 1)]
        relations = database.execute("SELECT kind, COUNT(*) FROM relations GROUP BY kind ORDER BY kind").fetchall()
        assert relations == [("CONTAINS", 1), ("DERIVED_FROM", 3)]
        names = sorted(name for (name,) in database.execute("SELECT name FROM entities").fetchall())
    # symbol names are kept; a compilation unit without an accepted source binding is named by hash
    assert names == ["compilation-unit:" + hashlib.sha256(b"private-unit").hexdigest(), "private-function", "private-type"]
    assert _coverage(run) == [(run.items[0]["artifact_identity"], "complete", None)]


def test_extraction_writes_protected_raw_refs_and_coverage_beside_the_decision(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, gaps=["catalog gap"])
    raw = json.loads((run.context.run_root / run.result["artifact"]["path"]).read_text())
    assert run.result["artifact"]["path"].endswith("/artifacts/debug-symbols/raw-refs.json")
    assert raw["schema"] == "appsec-review/debug-symbol-inputs/1" and raw["compiler_target"] == "clang"
    (entry,) = raw["artifacts"]
    assert entry["artifact_identity"] == run.items[0]["artifact_identity"] and entry["binary"] == run.items[0]["reference"]
    assert entry["debug"] is None and entry["reader_executions"] == [] and entry["status"] == "complete"
    assert [record["key"] for record in entry["reader_records"]] == ["cu:1", "fn:1", "type:1"]
    assert "private-function" in json.dumps(entry["reader_records"]), "protected raw refs keep the reader's names"
    coverage = json.loads((run.context.run_root / run.result["coverage"]["path"]).read_text())
    assert run.result["coverage"]["path"].endswith("/artifacts/debug-symbols/coverage.json")
    assert coverage == {"schema": "appsec-review/debug-symbol-coverage/1", "compiler_target": "clang",
                        "coverage": [{"artifact_identity": run.items[0]["artifact_identity"], "status": "complete", "gap": None}]}
    assert run.result["gaps"] == ["catalog gap"] and run.result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert run.result["indexes"][0]["gaps"] == ("catalog gap",)


# --- pairing ---------------------------------------------------------------------------------------

def test_missing_pdb_skips_reader_and_names_gap(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, target="msvc", artifacts=[("bin/program", MZ, "executable")])
    assert run.calls == []
    assert run.result["gaps"] == _gaps(run, "missing_debug_artifact")
    assert _coverage(run) == [(run.items[0]["artifact_identity"], "unavailable", "missing_debug_artifact")]
    assert run.result["record_count"] == 0 and run.result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert [event["event"] for event in events(run.context)][-1] == "DEBUG_SYMBOL_ARTIFACT_FAILED"


def test_clang_tries_embedded_dwarf_first_and_separate_debug_candidates_only_from_the_catalog(tmp_path, monkeypatch):
    calls = []

    def reader(binary, debug_file, *, target, settings):
        calls.append(debug_file)
        if debug_file is None:
            return Extraction((), ("embedded_dwarf_unavailable",), "fixture/1")
        return Extraction((SymbolRecord("fn:1", RecordKind.SYMBOL, "accepted"),), producer="fixture/1")

    run = _run(tmp_path, monkeypatch, reader=reader, artifacts=[
        ("bin/program", ELF, "executable"), ("symbols/program.debug", b"debug bytes", "debug-information")])
    assert calls == [None, run.context.run_root / run.items[1]["reference"]["path"]]
    assert run.result["terminal_status"] == "SUCCEEDED" and run.result["record_count"] == 1
    (row,) = payloads(run.context, run.result)
    assert row["debug_sha256"] == run.items[1]["reference"]["sha256"] != row["artifact_sha256"]
    raw = json.loads((run.context.run_root / run.result["artifact"]["path"]).read_text())
    assert raw["artifacts"][0]["debug"] == run.items[1]["reference"]


def test_embedded_match_stops_the_candidate_search(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, artifacts=[
        ("bin/program", ELF, "executable"), ("symbols/program.debug", b"debug bytes", "debug-information")])
    assert [call[1] for call in run.calls] == [None]
    assert run.result["record_count"] == 3


def test_two_debug_companions_with_records_are_ambiguous(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, target="msvc", artifacts=[
        ("bin/program", MZ, "executable"), ("a.pdb", MSF + b"a", "debug-information"),
        ("b.pdb", MSF + b"b", "debug-information")])
    assert len(run.calls) == 2
    assert run.result["gaps"] == _gaps(run, "ambiguous_debug_artifact")
    assert _coverage(run)[0][1:] == ("unavailable", "ambiguous_debug_artifact")
    assert run.result["record_count"] == 0


def test_debug_candidates_with_their_own_gap_are_not_read(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, target="msvc", settings={"reader": {"max_input_bytes": 10}},
               artifacts=[("bin/program", MZ, "executable"), ("a.pdb", MSF, "debug-information")])
    assert run.calls == []
    assert run.result["gaps"] == _gaps(run, "max_input_bytes")


def test_debug_only_artifacts_are_companions_not_subjects(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, target="msvc", artifacts=[("a.pdb", MSF, "debug-information")])
    assert run.calls == [] and run.result["artifact_count"] == 0
    assert run.result["gaps"] == ["native_binary_unavailable"]
    assert _coverage(run) == [("native-artifacts", "unavailable", "native_binary_unavailable")]
    assert [event["event"] for event in events(run.context)] == ["DEBUG_SYMBOL_TARGET_SELECTED"]


# --- named gaps ------------------------------------------------------------------------------------

@pytest.mark.parametrize("reason", ["pdb_guid_age_mismatch", "tool_unavailable", "unsupported_binary_format"])
def test_pair_mismatch_or_missing_tool_is_unavailable_not_empty_success(tmp_path, monkeypatch, reason):
    run = _run(tmp_path, monkeypatch, target="msvc", reader=lambda *a, **k: Extraction((), (reason,), "fixture-reader/1"))
    assert run.result["gaps"] == _gaps(run, reason)
    assert run.result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert _coverage(run) == [(run.items[0]["artifact_identity"], "unavailable", reason)]
    failed = [event for event in events(run.context) if event["event"] == "DEBUG_SYMBOL_ARTIFACT_FAILED"]
    assert len(failed) == 1 and failed[0]["gap_count"] == 1 and failed[0]["record_count"] == 0


def test_an_empty_extraction_without_reasons_is_debug_symbols_unavailable(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, reader=lambda *a, **k: Extraction((), producer="f/1"))
    assert run.result["gaps"] == _gaps(run, "debug_symbols_unavailable")


def test_reader_exception_is_an_observable_gap_not_an_integrity_success(tmp_path, monkeypatch):
    def broken(*_args, **_kwargs):
        raise RuntimeError("private diagnostic")

    run = _run(tmp_path, monkeypatch, reader=broken)
    assert run.result["gaps"] == _gaps(run, "reader_failed: RuntimeError")
    assert run.result["terminal_status"] == "COMPLETED_WITH_GAPS"
    text = json.dumps(events(run.context))
    assert "DEBUG_SYMBOL_ARTIFACT_FAILED" in text and "private diagnostic" not in text
    assert "private diagnostic" not in (run.context.run_root / run.result["artifact"]["path"]).read_text()


def test_disabled_reader_never_runs_and_has_named_coverage_gap(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, settings={"enabled": False})
    assert run.calls == []
    assert run.result["gaps"] == _gaps(run, "debug_symbol_indexing_disabled")
    assert _coverage(run) == [(run.items[0]["artifact_identity"], "unavailable", "debug_symbol_indexing_disabled")]


def test_probe_gaps_skip_the_reader_and_are_published_per_artifact(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, settings={"reader": {"max_input_bytes": 4}})
    assert run.calls == []
    assert run.result["gaps"] == _gaps(run, "max_input_bytes")
    raw = json.loads((run.context.run_root / run.result["artifact"]["path"]).read_text())
    assert raw["artifacts"][0]["status"] == "unavailable" and raw["artifacts"][0]["reader_records"] == []


def test_invalid_extraction_contract_is_an_integrity_failure(tmp_path, monkeypatch):
    with pytest.raises(FrameworkIntegrityError, match="invalid extraction contract"):
        _run(tmp_path, monkeypatch, reader=lambda *a, **k: {"records": []})


# --- bounds ----------------------------------------------------------------------------------------

def test_max_records_per_artifact_publishes_named_coverage_and_no_rows(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, settings={"reader": {"max_records": 1}})
    assert run.result["gaps"] == _gaps(run, "max_records")
    assert run.result["record_count"] == 0 and payloads(run.context, run.result) == []
    assert _coverage(run) == [(run.items[0]["artifact_identity"], "unavailable", "max_records")]


def test_max_records_total_bounds_the_shard_across_artifacts(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, settings={"reader": {"max_records": 4}},
               artifacts=[("bin/one", ELF + b"1", "executable"), ("bin/two", ELF + b"2", "executable")])
    assert len(run.calls) == 2 and run.result["record_count"] == 3 and run.result["artifact_count"] == 2
    assert run.result["gaps"] == [f"{run.items[1]['artifact_identity']}: max_records_total"]
    assert {(area, status) for area, status, _ in _coverage(run)} == {
        (run.items[0]["artifact_identity"], "complete"), (run.items[1]["artifact_identity"], "unavailable")}


def test_max_output_bytes_is_a_named_gap(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, settings={"reader": {"max_output_bytes": 1}})
    assert run.result["gaps"] == _gaps(run, "max_output_bytes")
    assert run.result["record_count"] == 0


def test_configured_catalog_gaps_and_artifact_gaps_are_merged_sorted_and_unique(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, gaps=["zeta", "alpha", "alpha"], settings={"enabled": False})
    assert run.result["gaps"] == sorted(["alpha", "zeta", *_gaps(run, "debug_symbol_indexing_disabled")])


# --- integrity failures ----------------------------------------------------------------------------

@pytest.mark.parametrize("target", ["clang", "msvc"])
def test_rehash_drift_of_the_binary_prevents_the_reader_and_publication(tmp_path, monkeypatch, target):
    context = job_context(tmp_path, target=target)
    items = [artifact(context.run_root, "bin/program", MZ if target == "msvc" else ELF)]
    if target == "msvc":
        items.append(artifact(context.run_root, "symbols/program.pdb", MSF, "debug-information"))
    calls = []
    job = build_job(extractor=extractor(calls))
    decision = decide(monkeypatch, job, context, accepted_inputs(items, manifest(context.run_root)))
    (context.run_root / items[0]["reference"]["path"]).write_bytes(b"changed")
    lane = "msvc_pdb" if target == "msvc" else "clang_dwarf"
    with pytest.raises(FrameworkIntegrityError, match="binary/debug artifact integrity verification failed"):
        handlers(job)[f"extract.{lane}"](unit(context, f"extract.{lane}", {"decide.target": decision}))
    assert calls == []
    assert not (context.attempt_root / "artifacts" / "debug-symbols" / "raw-refs.json").exists()
    assert not (context.run_root / "data" / "indices" / "debug_symbols").exists()


def test_separate_debug_bytes_must_match_accepted_hash_before_reader(tmp_path, monkeypatch):
    context = job_context(tmp_path, target="msvc")
    items = [artifact(context.run_root, "bin/program", MZ), artifact(context.run_root, "s.pdb", MSF, "debug-information")]
    calls = []
    job = build_job(extractor=extractor(calls))
    decision = decide(monkeypatch, job, context, accepted_inputs(items, manifest(context.run_root)))
    (context.run_root / items[1]["reference"]["path"]).write_bytes(b"modified debug bytes")
    with pytest.raises(FrameworkIntegrityError, match="binary/debug artifact integrity verification failed"):
        handlers(job)["extract.msvc_pdb"](unit(context, "extract.msvc_pdb", {"decide.target": decision}))
    assert calls == []


def test_post_reader_artifact_drift_does_not_publish_records(tmp_path, monkeypatch):
    def mutate(binary, *args, **kwargs):
        binary.write_bytes(b"mutated while extracting")
        return Extraction((SymbolRecord("fn:1", RecordKind.SYMBOL, "unsafe"),), producer="fixture/1")

    with pytest.raises(FrameworkIntegrityError, match="binary artifact integrity"):
        _run(tmp_path, monkeypatch, reader=mutate)
    assert not list(tmp_path.rglob("raw-refs.json")), "nothing is published after an integrity failure"


def test_symbol_integrity_errors_from_the_reader_propagate(tmp_path, monkeypatch):
    def reader(*a, **k):
        raise SymbolIntegrityError("reader custody failed")

    with pytest.raises(SymbolIntegrityError, match="reader custody failed"):
        _run(tmp_path, monkeypatch, reader=reader)


def test_duplicate_record_keys_are_invalid_normalized_records(tmp_path, monkeypatch):
    duplicate = Extraction((SymbolRecord("fn:1", RecordKind.SYMBOL, "a"), SymbolRecord("fn:1", RecordKind.SYMBOL, "b")),
                           producer="fixture/1")
    with pytest.raises(ValueError, match="invalid normalized debug-symbol records"):
        _run(tmp_path, monkeypatch, reader=lambda *a, **k: duplicate)


# --- shard identity --------------------------------------------------------------------------------

def test_immutable_shard_is_reused_for_identical_inputs_and_differs_per_target_or_reader(tmp_path, monkeypatch):
    reader = extractor()
    first = _run(tmp_path / "first", monkeypatch, reader=reader)
    again = handlers(first.job)["extract.clang_dwarf"](unit(first.context, "extract.clang_dwarf",
                                                            {"decide.target": first.decision}))
    assert again["indexes"] == first.result["indexes"], "a second extraction over the same run reuses the shard"
    assert again["input_fingerprint"] == first.result["input_fingerprint"]
    assert len(list((first.context.run_root / "data" / "indices" / "debug_symbols").glob("*.sqlite"))) == 1
    # the decision fingerprint binds the upstream manifest bytes, so another run root is another shard identity
    second = _run(tmp_path / "second", monkeypatch, reader=reader)
    assert second.result["indexes"][0]["fingerprint"] != first.result["indexes"][0]["fingerprint"]
    assert second.result["indexes"][0]["sha256"] != first.result["indexes"][0]["sha256"], "payloads carry the identity"
    other = _run(tmp_path / "msvc", monkeypatch, target="msvc", reader=reader)
    assert other.result["indexes"][0]["fingerprint"] != first.result["indexes"][0]["fingerprint"]
    assert other.result["indexes"][0]["shard_id"] == "symbols-msvc_pdb"


def test_records_of_two_artifacts_are_bound_to_their_own_evidence(tmp_path, monkeypatch):
    run = _run(tmp_path, monkeypatch, artifacts=[("bin/one", ELF + b"1", "executable"), ("bin/two", ELF + b"2", "executable")])
    rows = payloads(run.context, run.result)
    assert run.result["record_count"] == 6 and len(rows) == 6
    by_artifact = {row["artifact_identity"]: row["artifact_sha256"] for row in rows}
    assert by_artifact == {item["artifact_identity"]: item["reference"]["sha256"] for item in run.items}
    assert len({row["native_key"] for row in rows}) == 3, "the same native key is distinct per artifact"
    assert all(AddressRange(**interval) for row in rows for interval in row["address_ranges"])


def test_native_parent_outside_the_extraction_is_a_named_gap(tmp_path, monkeypatch):
    orphan = extracted((SymbolRecord("fn:1", RecordKind.SYMBOL, "f", parent_key="cu:missing"),))
    run = _run(tmp_path, monkeypatch, reader=lambda *a, **k: orphan)
    assert run.result["gaps"] == _gaps(run, "native_parent_unavailable")
    assert _coverage(run) == [(run.items[0]["artifact_identity"], "partial", "native_parent_unavailable")]
    assert run.result["record_count"] == 1
