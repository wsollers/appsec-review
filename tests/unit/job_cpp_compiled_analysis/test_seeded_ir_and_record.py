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
    complete = next(item for item in llvm_ir.parse_module(text).functions if item.name == "copy_field").flow()
    assert [block["successors"] for block in flow["blocks"]] == [
        block["successors"] for block in complete["blocks"]]
    assert flow["dominators"] == complete["dominators"]
    assert flow["post_dominators"] == complete["post_dominators"]


def test_bounded_flow_keeps_multiline_switch_and_direct_calls():
    text = """
define i32 @f(i32 %x) !dbg !1 {
entry:
  br label %next
next:
  call void @sink(), !dbg !2
  switch i32 %x, label %done [
    i32 0, label %entry
  ]
done:
  ret i32 0
}
!1 = distinct !DISubprogram(name: "f", file: !3, line: 1)
!2 = !DILocation(line: 2, column: 1, scope: !1)
!3 = !DIFile(filename: "f.cpp", directory: "/scratch/source")
"""
    complete = llvm_ir.parse_module(text).functions[0]
    limited = llvm_ir.parse_module(text, block_limit=1).functions[0]
    assert [b.successors for b in limited.blocks] == [("bb1",), ("bb2", "bb0"), ()]
    assert limited.calls == complete.calls
    assert limited.end_line == complete.end_line


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


def test_demangle_metadata_and_ir_edge_cases(monkeypatch) -> None:
    # Demangler branches: short/non-_Z, internal _ZL, nested qualifiers rVK, ctors C1..C3,
    # dtors D0..D2, invalid ctor/dtor at start, invalid lengths, empty N..E, templates.
    assert llvm_ir.demangle("plain_c") is None
    assert llvm_ir.demangle("_Z1") is None
    assert llvm_ir.demangle("_ZL6helperv") == "helper"
    assert llvm_ir.demangle("_ZNK3net6Packet4sizeEv") == "net::Packet::size"
    assert llvm_ir.demangle("_ZN3net6PacketC1Ev") == "net::Packet::Packet"
    assert llvm_ir.demangle("_ZN3net6PacketD0Ev") == "net::Packet::~Packet"
    assert llvm_ir.demangle("_ZNC1Ev") is None
    assert llvm_ir.demangle("_ZND1Ev") is None
    assert llvm_ir.demangle("_ZNE") is None
    assert llvm_ir.demangle("_ZN0aE") is None
    assert llvm_ir.demangle("_ZN99shortE") is None
    assert llvm_ir.demangle("_ZN3foo!E") is None
    assert llvm_ir.demangle("_Zbad") is None
    assert llvm_ir.demangle("_Z4tmplIiEv") is None

    # Helpers and _Metadata edge cases: escaped strings, non-int, absolute DIFile, scope cycle/stop.
    assert llvm_ir._string(None) is None
    assert llvm_ir._string("unquoted") == "unquoted"
    assert llvm_ir._string('"a\\"b\\5Cc"') == 'a"b\\c'
    assert llvm_ir._int("not-an-int") is None
    meta = llvm_ir._Metadata([
        '!1 = !DIFile(filename: "/abs/file.cpp", directory: "/ignored")',
        '!2 = !DIFile(filename: "rel.cpp", directory: "")',
        '!3 = !DINamespace(name: "ns", scope: !6)',
        '!4 = !DICompositeType(tag: DW_TAG_structure_type, name: "Cls", scope: !3)',
        '!5 = distinct !DILexicalBlock(scope: !4)',
        '!6 = distinct !DICompileUnit(language: DW_LANG_C_plus_plus)',
        '!7 = distinct !DISubprogram(name: "method", scope: !5, file: !1, line: 10)',
        '!8 = distinct !DILexicalBlock(scope: !8)',
        '!9 = distinct !DISubprogram(name: "cycled", scope: !8, file: !2, line: 4)',
    ])
    assert meta.location("1") == (None, None)
    assert meta.file_path("3") is None
    assert meta.file_path("1") == "/abs/file.cpp"
    assert meta.file_path("2") == "rel.cpp"
    assert meta.qualified_name("7") == "ns::Cls::method"
    assert meta.qualified_name("9") == "cycled"

    # Dominators with unreachable block and multi-predecessor diamond.
    doms = llvm_ir._dominators(
        ("entry", "left", "right", "merge", "dead"),
        {"entry": ("left", "right"), "left": ("merge",), "right": ("merge",), "merge": (), "dead": ("merge",)},
        "entry",
    )
    assert doms["entry"] is None and doms["merge"] == "entry" and "dead" not in doms

    # parse_module edge cases: no !dbg -> unparsed, multiline switch, llvm.* intrinsic skipped,
    # undemangled _Z counted, indirect call counted, MAX_CALLS and MAX_DEF_USE caps, empty body.
    monkeypatch.setattr(llvm_ir, "MAX_CALLS", 2)
    monkeypatch.setattr(llvm_ir, "MAX_DEF_USE", 1)
    ir_text = "\n".join([
        'define void @no_debug() {',
        '  ret void',
        '}',
        'define void @empty_fn() !dbg !10 {',
        '}',
        'define i32 @complex(i32 %x, ptr %fp) !dbg !11 {',
        'entry:',
        '  ; comment ignored',
        '  %a = add i32 %x, 1, !dbg !12',
        '  %b = add i32 %a, 2, !dbg !12',
        '  %unused = add i32 3, 4, !dbg !12',
        '  %useb = add i32 %b, 5, !dbg !12',
        '  call void @llvm.memcpy.p0.p0.i64(ptr null, ptr null, i64 0, i1 false), !dbg !12',
        '  call void @_Z4tmplIiEv(), !dbg !12',
        '  call void @callee_two(), !dbg !12',
        '  call void @callee_three(), !dbg !12',
        '  call void %fp(i32 %useb), !dbg !12',
        '  switch i32 %a, label %sw.default [',
        '    i32 0, label %sw.zero',
        '  ], !dbg !12',
        'sw.zero:',
        '  br label %sw.default',
        'sw.default:',
        '  ret i32 %a, !dbg !12',
        '}',
        '!10 = distinct !DISubprogram(name: "empty_fn", file: !20, line: 1)',
        '!11 = distinct !DISubprogram(name: "", file: !20, line: 5)',
        '!12 = !DILocation(line: 7, column: 3, scope: !11)',
        '!20 = !DIFile(filename: "src/edge.cpp", directory: "/scratch/source")',
    ])
    parsed = llvm_ir.parse_module(ir_text)
    assert parsed.unparsed == ("no_debug: no debug subprogram",)
    assert parsed.undemangled == 1
    by_name = {fn.linkage_name: fn for fn in parsed.functions}
    assert by_name["empty_fn"].key == "empty_fn"
    assert by_name["empty_fn"].flow()["entry"] is None
    comp = by_name["complex"]
    assert comp.indirect_calls == 1
    assert set(comp.truncated) == {"calls", "def_use"}
    assert len(comp.calls) == 2
    assert len(comp.def_use) == 1
    assert set(comp.blocks[0].successors) == {"bb1", "bb2"}
