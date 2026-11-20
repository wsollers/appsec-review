"""Offline parser -> normalization -> publication -> query regressions."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json

import pytest

from appsec_review.debug_symbols.contract import AddressRange, Extraction, RecordKind, SymbolRecord
from appsec_review.debug_symbols.readers import extract_symbols
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.debug_symbols import row_in_scope
from tests.test_debug_symbol_readers import FIXTURES, fixture_runner, settings
from tests.unit.job_debug_symbol_indexing.support import (
    accepted_inputs, artifact, build_job, catalog_shard, decide, handlers, job_context,
    manifest, source_shard, unit,
)


def published(tmp_path, monkeypatch, target, *, transform=lambda result: result):
    context = job_context(tmp_path, target=target)
    binary, debug, output = (("tiny.elf", None, "tiny.dwarf.txt") if target == "clang"
                             else ("tiny.exe", "tiny.pdb", "tiny.pdb.yaml"))
    items = [artifact(context.run_root, binary, (FIXTURES / binary).read_bytes())]
    if debug:
        items.append(artifact(context.run_root, debug, (FIXTURES / debug).read_bytes(), "debug-information"))
    source = source_shard(context.run_root, (FIXTURES / "tiny.c").read_bytes(),
                          path="tests/fixtures/debug_symbols/tiny.c")
    upstream = manifest(context.run_root, [catalog_shard(context.run_root, items), source])
    tool_settings = settings(tmp_path, "llvm_dwarfdump" if target == "clang" else "llvm_pdbutil")

    def reader(binary, debug_file, *, target, settings):
        return transform(extract_symbols(binary, debug_file, target=target, settings=tool_settings,
                                         runner=fixture_runner(output)))

    job = build_job(extractor=reader)
    outputs = {"decide.target": decide(monkeypatch, job, context, accepted_inputs(items, upstream))}
    for name in ("extract.clang_dwarf", "extract.msvc_pdb", "acceptance.publish_handoff"):
        outputs[name] = handlers(job)[name](unit(context, name, outputs))
    reference = outputs["acceptance.publish_handoff"]["index_manifest"]
    return RetrievalCore(context.run_root.parent, context.run_id,
                         manifest_path=context.run_root / reference["path"]), items


@pytest.mark.parametrize("target,upper_u64", [("clang", False), ("msvc", False), ("clang", True)],
                         ids=["clang", "msvc", "clang-u64"])
def test_real_line_rows_resolve_by_function_and_compilation_unit(tmp_path, monkeypatch, target, upper_u64):
    def transform(result):
        if not upper_u64:
            return result
        offset = 2**64 - max(interval.end for row in result.records for interval in row.ranges)
        return replace(result, records=tuple(replace(
            row, ranges=tuple(AddressRange(value.start + offset, value.end + offset) for value in row.ranges))
            for row in result.records))
    core, items = published(tmp_path, monkeypatch, target, transform=transform)
    artifact_id = items[0]["artifact_identity"]
    functions = core.query_debug_symbols(mode="symbol", artifact_identity=artifact_id)["results"]
    entry = next(row for row in functions if row["name"] == "entry")
    lines = core.query_debug_symbols(mode="source_ranges", artifact_identity=artifact_id, limit=100)["results"]
    expected = {row["identity"] for row in lines if any(
        interval["start"] < parent["end"] and parent["start"] < interval["end"]
        for interval in row["payload"]["address_ranges"] for parent in entry["payload"]["address_ranges"])}
    assert expected
    by_function = []
    cursor = None
    while True:
        page = core.query_debug_symbols(mode="source_ranges", subject=entry["identity"], limit=2, cursor=cursor)
        by_function.extend(page["results"])
        cursor = page["pagination"]["next_cursor"]
        if cursor is None:
            break
    assert {row["identity"] for row in by_function} == expected
    assert len(by_function) == len(expected)
    originals = {row["identity"]: row for row in lines}
    for row in by_function:
        assert row["payload"]["address_ranges"] == originals[row["identity"]]["payload"]["address_ranges"]
        assert row["payload"]["source_identity"] == originals[row["identity"]]["payload"]["source_identity"]
        assert row["location"] == originals[row["identity"]]["location"]
        assert row["payload"]["source_range_relation"] == {
            "kind": "address_overlap", "subject_identity": entry["identity"], "ownership": "not_established"}
        assert row_in_scope(row, lambda identity: identity == entry["identity"])
    unit_id = entry["payload"]["parent_identity"]
    by_unit = core.query_debug_symbols(mode="source_ranges", subject=unit_id, limit=100)["results"]
    assert {row["identity"] for row in by_unit} == {row["identity"] for row in lines}
    assert all(row["payload"]["parent_identity"] == unit_id for row in by_unit)


@pytest.mark.parametrize("bound", ["ranges", "prefixes", "shard"])
def test_fragmented_artifact_is_a_named_gap_not_an_extraction_abort(tmp_path, monkeypatch, bound):
    from appsec_review.retrieval import debug_symbol_index
    from tests.unit.job_debug_symbol_indexing.test_extract import _run, _coverage
    from tests.unit.job_debug_symbol_indexing.support import ELF, payloads

    ranges = tuple(AddressRange(number * 2, number * 2 + 1) for number in range(501))
    expected = "address_range_limit"
    if bound != "ranges":
        ranges = (AddressRange(1, 16),)
        monkeypatch.setattr(debug_symbol_index,
                            "MAX_PREFIXES_PER_RECORD" if bound == "prefixes" else "MAX_LOOKUP_ROWS", 2)
        expected = "address_lookup_prefix_limit" if bound == "prefixes" else "address_lookup_row_limit"

    def reader(binary, debug_file, **kwargs):
        record = SymbolRecord("fragmented" if binary.read_bytes().endswith(b"bad") else "good",
                              RecordKind.SYMBOL, ranges=ranges if binary.read_bytes().endswith(b"bad")
                              else (AddressRange(32, 33),))
        return Extraction((record,))

    run = _run(tmp_path, monkeypatch, artifacts=[("bad", ELF + b"bad", "executable"),
                                                ("good", ELF + b"good", "executable")], reader=reader)
    assert run.result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert [row["native_key"] for row in payloads(run.context, run.result)] == ["good"]
    coverage = {identity: (status, gap) for identity, status, gap in _coverage(run)}
    assert coverage[run.items[0]["artifact_identity"]] == ("unavailable", expected)
    assert coverage[run.items[1]["artifact_identity"]] == ("complete", None)
    assert (run.context.run_root / run.result["coverage"]["path"]).is_file()


def test_fragmented_dwarf_parser_output_becomes_scoped_coverage(tmp_path, monkeypatch):
    from appsec_review.debug_symbols._reader_dwarf import parse_dwarf
    from tests.unit.job_debug_symbol_indexing.test_extract import _run
    text = (FIXTURES / "tiny.dwarf.txt").read_text()
    intervals = "\n".join(f"[0x{index * 2:x}, 0x{index * 2 + 1:x})" for index in range(501))
    text = text.replace("DW_AT_high_pc\t(0x000000000040102f)", f"DW_AT_ranges\t(0x00\n{intervals})")
    records, gaps = parse_dwarf(text, {"max_records": 10000, "max_depth": 128})
    assert len(next(record for record in records if record.name == "entry").ranges) == 501
    run = _run(tmp_path, monkeypatch, reader=lambda *a, **k: Extraction(tuple(records), tuple(sorted(gaps))))
    assert run.result["record_count"] == 0
    assert any(gap.endswith(": address_range_limit") for gap in run.result["gaps"])


def test_function_overlap_preserves_ambiguity_and_excludes_another_compilation_unit(tmp_path, monkeypatch):
    def transform(result):
        entry = next(row for row in result.records if row.kind is RecordKind.SYMBOL and row.name == "entry")
        clone = replace(entry, key="overlapping-function", name="overlapping")
        foreign = replace(entry, key="foreign-function", name="foreign", parent_key="foreign-cu")
        end = max(interval.end for row in result.records if row.kind is RecordKind.SOURCE_RANGE
                  for interval in row.ranges)
        boundary = replace(entry, key="boundary-function", name="boundary",
                           ranges=(AddressRange(end, end + 1),))
        unknown = replace(entry, key="public-only", name="unknown", ranges=())
        cu = SymbolRecord("foreign-cu", RecordKind.COMPILATION_UNIT, "other")
        return replace(result, records=(*result.records, clone, foreign, boundary, unknown, cu))

    core, items = published(tmp_path, monkeypatch, "clang", transform=transform)
    functions = {row["name"]: row for row in core.query_debug_symbols(
        mode="symbol", artifact_identity=items[0]["artifact_identity"], limit=100)["results"]}
    original = core.query_debug_symbols(mode="source_ranges", subject=functions["entry"]["identity"])["results"]
    overlapping = core.query_debug_symbols(mode="source_ranges", subject=functions["overlapping"]["identity"])["results"]
    assert original and {row["identity"] for row in original} == {row["identity"] for row in overlapping}
    for name in ("foreign", "boundary", "unknown"):
        result = core.query_debug_symbols(mode="source_ranges", subject=functions[name]["identity"])
        assert not result["results"] and result["coverage_gaps"]


@pytest.mark.parametrize("case", ["overbound-first", "overbound-last", "unique-overbound", "truncated-second"])
def test_companion_identity_survives_index_bounds_through_publication(tmp_path, monkeypatch, case):
    context = job_context(tmp_path)
    root = context.run_root
    # A build-ID-only ELF permits distinct companions with the same verified build ID.
    # Do not bypass either the native verifier or the captured-output parser.
    stripped = (FIXTURES / "stripped.elf").read_bytes()
    assert stripped.count(b".gnu_debuglink\0") == 1
    stripped = stripped.replace(b".gnu_debuglink\0", b".xnu_debuglink\0")
    companion = (FIXTURES / "tiny.debug").read_bytes()
    fragmented = companion + b"\0fragmented-companion"
    bad = artifact(root, "stripped-program", stripped)
    control = artifact(root, "embedded-control", (FIXTURES / "tiny.elf").read_bytes())
    limited = artifact(root, "fragmented.debug", fragmented, "debug-information")
    ordinary = artifact(root, "ordinary.debug", companion, "debug-information")
    companions = ([limited] if case == "unique-overbound" else
                  [ordinary, limited] if case in {"overbound-last", "truncated-second"}
                  else [limited, ordinary])
    items = [bad, *companions, control]
    source = source_shard(root, (FIXTURES / "tiny.c").read_bytes(),
                          path="tests/fixtures/debug_symbols/tiny.c")
    upstream = manifest(root, [catalog_shard(root, items), source])
    native = (FIXTURES / "tiny.dwarf.txt").read_text()
    intervals = "\n".join(f"[0x{index * 2:x}, 0x{index * 2 + 1:x})" for index in range(501))
    fragmented_export = native.replace(
        "DW_AT_high_pc\t(0x000000000040102f)", f"DW_AT_ranges\t(0x00\n{intervals})")
    tool_settings = settings(tmp_path, max_output_bytes=32768)
    parsed = []

    def reader(binary, debug_file, *, target, settings):
        limited_input = debug_file is not None and hashlib.sha256(
            debug_file.read_bytes()).hexdigest() == limited["reference"]["sha256"]
        output = ("x" * 32769 if case == "truncated-second" else fragmented_export) if limited_input else native
        result = extract_symbols(binary, debug_file, target=target, settings=tool_settings,
                                 runner=lambda *a, **k: output)
        parsed.append((hashlib.sha256(binary.read_bytes()).hexdigest(), limited_input, result))
        return result

    job = build_job(extractor=reader)
    outputs = {"decide.target": decide(monkeypatch, job, context, accepted_inputs(items, upstream))}
    for name in ("extract.clang_dwarf", "extract.msvc_pdb", "acceptance.publish_handoff"):
        outputs[name] = handlers(job)[name](unit(context, name, outputs))
    published = outputs["acceptance.publish_handoff"]
    core = RetrievalCore(root.parent, context.run_id, manifest_path=root / published["index_manifest"]["path"])
    coverage = json.loads((root / outputs["extract.clang_dwarf"]["coverage"]["path"]).read_text())
    affected = next(row for row in coverage["coverage"] if row["artifact_identity"] == bad["artifact_identity"])
    ambiguous = case in {"overbound-first", "overbound-last"}
    expected_gap = "output_limit" if case == "truncated-second" else "address_range_limit"
    assert ("ambiguous_debug_artifact" in affected["gap"]) is ambiguous
    assert expected_gap in affected["gap"]
    assert affected["status"] == ("partial" if case == "truncated-second" else "unavailable")
    assert any(gap.endswith(": " + expected_gap) for gap in published["gaps"])
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"
    if case != "truncated-second":
        complete = [result for digest, is_limited, result in parsed
                    if digest == bad["reference"]["sha256"] and is_limited]
        assert len(complete) == 1 and any(len(row.ranges) == 501 for row in complete[0].records)
        assert "variable_locations_not_indexed" in affected["gap"]
        assert not core.query_debug_symbols(mode="symbol", artifact_identity=bad["artifact_identity"])["results"]
    else:
        assert any(not result.records and result.gaps == ("output_limit",)
                   for _, is_limited, result in parsed if is_limited)
        assert core.query_debug_symbols(mode="symbol", artifact_identity=bad["artifact_identity"])["results"]
    raw = json.loads((root / outputs["extract.clang_dwarf"]["artifact"]["path"]).read_text())
    affected_raw = next(row for row in raw["artifacts"] if row["artifact_identity"] == bad["artifact_identity"])
    assert affected_raw["debug"] == (
        None if ambiguous else ordinary["reference"] if case == "truncated-second" else limited["reference"])
    if case != "truncated-second":
        assert affected_raw["reader_records"] == []
    unaffected = core.query_debug_symbols(mode="symbol", artifact_identity=control["artifact_identity"])["results"]
    assert unaffected and all(row["payload"]["debug_sha256"] == control["reference"]["sha256"] for row in unaffected)
    retained_control = next(row for row in raw["artifacts"] if row["artifact_identity"] == control["artifact_identity"])
    assert retained_control["reader_records"] and retained_control["status"] == "partial"
