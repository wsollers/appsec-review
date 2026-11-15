"""Clang ``debug.DumpCFG`` text parser (docs/architecture/seeded-neighborhoods.md section 6)."""
from __future__ import annotations

from appsec_review.jobs.job_cpp_compiled_analysis.clang_cfg import NO_BLOCK_LINES_GAP, parse_cfgs
from tests import seeded_clang_support as sc


def _module(stem: str, **kwargs):
    return parse_cfgs((sc.RECORDED / "cfg" / f"{stem}.cfg.txt").read_text(encoding="utf-8"), **kwargs)


def test_conditions_and_calls_are_rendered_as_source_expressions() -> None:
    functions = {cfg.name: cfg for cfg in _module("util").functions}
    assert set(functions) == {"clamp_len", "checked_len", "copy_field"}
    clamp = functions["clamp_len"]
    assert clamp.parameters == 1
    branches = {block.condition: block.successors for block in clamp.blocks if block.terminator == "if"}
    assert set(branches) == {"n < 0", "n > 64"} and all(len(targets) == 2 for targets in branches.values())
    copy = functions["copy_field"]
    assert copy.parameters == 3
    assert sorted(call for block in copy.blocks for call in block.calls) == ["checked_len(n)", "memcpy(dst, src, n)"]
    entry = next(block for block in copy.blocks if block.role == "entry")
    exit_block = next(block for block in copy.blocks if block.role == "exit")
    assert entry.successors and exit_block.predecessors and not exit_block.successors


def test_payload_is_deterministic_and_names_the_missing_lines() -> None:
    payload = _module("util").functions[0].to_payload()
    assert payload == _module("util").functions[0].to_payload()
    assert payload["gaps"] == [NO_BLOCK_LINES_GAP] and payload["branches"] == 2


def test_block_limit_is_a_named_cut() -> None:
    cfg = _module("util", block_limit=2).functions[0]
    assert len(cfg.blocks) == 2 and any(cut.startswith("blocks cut at 2") for cut in cfg.truncated)


def test_loops_short_circuits_and_ternaries_keep_their_terminators() -> None:
    text = "\n".join([
        "int g(int a, int b)", " [B3 (ENTRY)]", "   Succs (1): B2", "",
        " [B2]", "   1: a", "   2: [B2.1] (ImplicitCastExpr, LValueToRValue, int)", "   3: 0",
        "   4: [B2.2] > [B2.3]", "   T: while [B2.4]", "   Preds (1): B3", "   Succs (2): B1 B0", "",
        " [B1]", "   1: b", "   2: [B1.1] (ImplicitCastExpr, LValueToRValue, int)", "   T: [B1.2] && ...",
        "   Preds (1): B2", "   Succs (2): B0 B0", "", " [B0 (EXIT)]", "   Preds (2): B1 B2", ""])
    (cfg,) = parse_cfgs(text).functions
    kinds = {block.block_id: (block.terminator, block.condition) for block in cfg.blocks}
    assert kinds["B2"] == ("while", "a > 0") and kinds["B1"] == ("&&", "b")


def test_malformed_input_is_a_gap_never_an_exception() -> None:
    module = parse_cfgs("not a cfg\n [B1]\n   1: x\nvoid (*f)\n [B2 (ENTRY)]\n   Succs (0):\n")
    assert module.functions == () or module.unparsed >= 0
    assert parse_cfgs("").functions == ()


def test_signature_parts_rendering_terminators_and_bounds() -> None:
    from appsec_review.jobs.job_cpp_compiled_analysis import clang_cfg as cc

    # Qualifiers loop, nested template/paren commas, void, and rejected signature forms.
    assert cc._signature_parts("static inline constexpr int ns::fn(int a, Pair<int, int> b)") == (
        "ns::fn", "fn", 2
    )
    assert cc._signature_parts("void empty(void)") == ("empty", "empty", 0)
    assert cc._signature_parts("int no_paren") is None
    assert cc._signature_parts("(int)") is None
    assert cc._signature_parts("   (int a)") is None

    # Missing block/element, cycle protection, cast unwrapping, and depth cap in _render.
    raw = {
        "B1": cc._Raw("B1", None, {
            1: "[B1.2] + [B99.1]",
            2: "[B1.1]",
            3: "[B1.4] (ImplicitCastExpr, int)",
            4: "leaf",
            5: "not_a_ref (ImplicitCastExpr, int)",
        }, [1, 2, 3, 4, 5]),
    }
    assert cc._render(raw, "B99", 1, frozenset(), 0) == "[B99.1]"
    assert "[B1.1]" in cc._render(raw, "B1", 1, frozenset(), 0)
    assert cc._render(raw, "B1", 3, frozenset(), 0) == "leaf"
    assert cc._render(raw, "B1", 5, frozenset(), 0) == "not_a_ref (ImplicitCastExpr, int)"
    assert cc._render(raw, "B1", 1, frozenset(), 24) == "[B1.2] + [B99.1]"

    # _terminator forms: parenthesized, bare keyword without condition, ||, ?, and missing ref.
    assert cc._terminator(raw, "B1", "(CXXConstructExpr)") == ("(CXXConstructExpr)", None)
    assert cc._terminator(raw, "B1", "try") == ("try", None)
    assert cc._terminator(raw, "B1", "[B1.4] || ...") == ("||", "leaf")
    assert cc._terminator(raw, "B1", "[B1.4] ? [B1.4] : 0") == ("?", "leaf")
    assert cc._terminator(raw, "B1", "&& no_ref") == ("&&", None)

    # Leading indented lines before signature, lines before [B...], duplicate block header,
    # MAX_ELEMENTS statement truncation, and unparsed head gap.
    many_stmts = [f"   {idx}: stmt_{idx}()" for idx in range(1, cc.MAX_ELEMENTS + 5)]
    dump = "\n".join([
        "   orphan before signature",
        "bad_sig_without_parens",
        " [B1]",
        "   1: x",
        "int valid(int x)",
        "   line before block header",
        " [B1 (ENTRY)]",
        *many_stmts,
        " [B1]",
        "   T: try",
        "   Succs (1): B0",
        " [B0 (EXIT)]",
        "   Preds (1): B1",
    ])
    parsed = parse_cfgs(dump)
    assert parsed.unparsed == 1
    assert any("source_cfg_unparsed: 1" in gap for gap in parsed.gaps)
    assert len(parsed.functions) == 1
    assert any("B1 statements cut at" in cut for cut in parsed.functions[0].truncated)

    # MAX_FUNCTIONS cap produces source_cfg_limit gap.
    many_fns = "\n".join(
        f"void f{i}()\n [B1 (ENTRY)]\n   1: {i}\n" for i in range(cc.MAX_FUNCTIONS + 2)
    )
    capped = parse_cfgs(many_fns)
    assert len(capped.functions) == cc.MAX_FUNCTIONS
    assert any("source_cfg_limit" in gap for gap in capped.gaps)
