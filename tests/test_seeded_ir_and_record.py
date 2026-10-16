"""LLVM IR flow parsing and the compact seeded-producer record (docs/architecture/seeded-neighborhoods.md 4, 6)."""
from __future__ import annotations

import json

from appsec_review import seeding
from appsec_review.jobs.job_cpp_compiled_analysis import llvm_ir
from appsec_review.seeding import record
from tests import seeded_clang_support as sc


def _module(stem: str = "util") -> llvm_ir.IrModule:
    return llvm_ir.parse_module((sc.RECORDED / "ir" / f"{stem}.ll").read_text(encoding="utf-8"))


def test_ir_functions_carry_source_lines_blocks_and_calls() -> None:
    functions = {item.name: item for item in _module().functions}
    assert {"copy_field", "checked_len", "clamp_len"} <= set(functions)
    copy = functions["copy_field"]
    assert copy.path == "src/util.cpp" and copy.start_line == 11 and not copy.internal
    assert functions["clamp_len"].internal and functions["clamp_len"].start_line == 3
    # Only calls to functions defined in the module are call edges; declared externals (memcpy) are not.
    assert [call.callee for call in copy.calls] == ["checked_len"]
    assert [(call.line, call.block_id) for call in copy.calls] == [(12, "bb0")]


def test_dominators_and_post_dominators_describe_the_guard_structure() -> None:
    copy = next(item for item in _module().functions if item.name == "copy_field")
    flow = copy.flow()
    assert flow["entry"] == "bb0" and flow["dominators"]["bb0"] is None
    # The block holding line 14 (the copy) is reached only through the guard in the entry block.
    guarded = next(block["id"] for block in flow["blocks"] if block["start_line"] == 14)
    assert flow["dominators"][guarded] is not None
    assert flow["dominators"][guarded] in {"bb0", "bb1"}
    assert all(flow["post_dominators"][block["id"]] is not None or not block["successors"] for block in flow["blocks"])
    assert flow["truncated"] == []


def test_def_use_lists_the_lines_that_read_each_value() -> None:
    copy = next(item for item in _module().functions if item.name == "copy_field")
    defined = [item for item in copy.def_use if item.def_line == 12]
    assert defined and all(item.use_count == len(item.use_lines) or item.use_count >= len(set(item.use_lines))
                           for item in defined)


def test_block_limit_truncates_with_a_named_marker_never_silently() -> None:
    text = (sc.RECORDED / "ir" / "util.ll").read_text(encoding="utf-8")
    flow = next(item for item in llvm_ir.parse_module(text, block_limit=2).functions if item.name == "copy_field").flow()
    # Structure (blocks and edges) is kept so the CFG stays valid; instruction detail past the limit is
    # dropped and the function says so.
    assert flow["truncated"] == ["blocks"]
    assert [block["start_line"] for block in flow["blocks"][2:]] == [None, None]


def test_parsing_is_deterministic() -> None:
    first = json.dumps([item.flow() for item in _module().functions], sort_keys=True)
    assert first == json.dumps([item.flow() for item in _module().functions], sort_keys=True)


SECTION = {"mode": "seeded", "depth": 3, "seed_limit": 200, "seed_count": 3, "resolved_seed_count": 1,
           "neighborhood_function_count": 4, "depth_histogram": {"0": 1}, "status_counts": {"resolved": 1, "unresolved": 2},
           "seeds": [{"path": "a.c", "start_line": 1, "end_line": 1, "status": "resolved"},
                     {"path": "b.c", "start_line": 2, "end_line": 2, "status": "unresolved"},
                     {"path": "c.c", "start_line": 3, "end_line": 3, "status": "unresolved"}],
           "gaps": ["frontier: x"]}


def test_compact_record_is_bounded_and_keeps_only_the_ledger_identity() -> None:
    compact = record.compact_record(SECTION, ledger={"path": "p.json", "sha256": "a" * 64, "size_bytes": 9})
    assert compact["ledger"] == {"path": "p.json", "sha256": "a" * 64}
    assert compact["seeds"][0] == ["a.c", 1, 1, "resolved"] and compact["skipped"] is False
    wide = {**SECTION, "seeds": [{"path": f"f{n}.c", "start_line": n, "end_line": n, "status": "resolved"}
                                 for n in range(record.MAX_RECORD_SEEDS + 50)]}
    assert len(record.compact_record(wide)["seeds"]) == record.MAX_RECORD_SEEDS


def test_unresolved_entries_carry_a_reason_and_resolved_keys_are_exact() -> None:
    reasons = {("b.c", 2, 2): record.REASON_NO_FUNCTION}
    annotated = record.with_reasons(SECTION, reasons)
    assert [entry.get("reason") for entry in annotated["seeds"]] == [None, record.REASON_NO_FUNCTION, record.REASON_NO_FUNCTION]
    assert record.resolved_keys(SECTION) == {("a.c", 1, 1)}
    assert "absence outside it is not evidence" in record.coverage_gap(SECTION)


def test_a_zero_seed_section_is_recognised_as_skipped() -> None:
    assert record.skipped({"gaps": [seeding.NO_SEEDS_GAP]}) and not record.skipped(SECTION)
