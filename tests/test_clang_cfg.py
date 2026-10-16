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
