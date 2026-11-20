"""Code-level unit tests for job_cpg_analysis.export and job_cpg_analysis.seeded edge cases."""

from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review import seeding
from appsec_review.config.seeding import SeededSettings
from appsec_review.jobs.cpp_seeded import Selection
from appsec_review.jobs.job_cpg_analysis import export, seeded


def _write_csv(directory: Path, kind: str, label: str, header: str, rows: list[str]) -> None:
    (directory / f"{kind}_{label}_header.csv").write_text(header + "\n", encoding="utf-8")
    (directory / f"{kind}_{label}_data.csv").write_text(
        "\n".join(rows) + ("\n" if rows else ""), encoding="utf-8"
    )


def test_export_helpers_and_all_cut_orphan_depth_and_file_size_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert export._int("42") == 42
    assert export._int("not-an-int") is None
    assert export._int(None) is None  # type: ignore[arg-type]
    assert export._text("  hello   \n  world  ") == "hello world"

    # Oversized data CSV triggers MAX_FILE_BYTES gap without reading rows.
    big_dir = tmp_path / "big"
    big_dir.mkdir()
    _write_csv(
        big_dir,
        "nodes",
        "METHOD",
        ":ID,NAME:string,FILENAME:string,CODE:string",
        ['1,fn,src/a.c,"void fn() {}"'],
    )
    monkeypatch.setattr(export, "MAX_FILE_BYTES", 5)
    oversized = export.read_export(big_dir)
    assert oversized.functions == []
    assert any("exceeds 5 bytes" in g for g in oversized.gaps)
    assert any("cpg_export_no_methods" in g for g in oversized.gaps)
    monkeypatch.undo()

    # Custom synthetic CPG covering:
    # - filtered methods (empty name, pseudo <global>, <built-in> path, IS_EXTERNAL=true)
    # - AST cycle / MAX_AST_DEPTH exceeded (else: found = None)
    # - orphan CALL / CONTROL_STRUCTURE / REACHING_DEF outside any method
    # - multiple cut calls (> MAX_CALLS_PER_FUNCTION twice to hit both branches of `"calls" not in cut`)
    # - multiple cut branches (> MAX_BRANCHES_PER_FUNCTION twice to hit both branches of `"branches" not in cut`)
    # - branch without condition edge
    # - unresolved / <unknownFullName> callees vs resolved callee
    cpg_dir = tmp_path / "cpg"
    cpg_dir.mkdir()
    _write_csv(
        cpg_dir,
        "nodes",
        "METHOD",
        ":ID,NAME:string,FULL_NAME:string,SIGNATURE:string,FILENAME:string,LINE_NUMBER:int,LINE_NUMBER_END:int,IS_EXTERNAL:boolean,CODE:string",
        [
            'm0,,empty,(),src/a.c,1,2,false,"{}"',
            'm1,<global>,<global>,(),src/a.c,1,2,false,"{}"',
            'm2,builtin,builtin,(),<includes>,1,2,false,"{}"',
            'm3,ext,ext,(),src/a.c,1,2,true,""',
            'm_ok,work,work:int(int),int(int),src/a.c,10,30,false,"int work(int x) { return x; }"',
        ],
    )
    _write_csv(
        cpg_dir,
        "edges",
        "AST",
        ":START_ID,:END_ID,:TYPE",
        [
            # Valid chain with shared intermediate block so `current in owners` cache hits
            "m_ok,blk1,AST",
            "blk1,c_op,AST",
            "blk1,c_res,AST",
            "blk1,c_unres,AST",
            "blk1,c_unk,AST",
            "blk1,c_cut1,AST",
            "blk1,c_cut2,AST",
            "blk1,br_cond,AST",
            "blk1,br_nocond,AST",
            "blk1,br_cut1,AST",
            "blk1,br_cut2,AST",
            "blk1,id_x,AST",
            # AST cycle exceeding MAX_AST_DEPTH
            "cyc1,cyc2,AST",
            "cyc2,cyc1,AST",
            "cyc1,c_deep,AST",
        ],
    )
    _write_csv(
        cpg_dir,
        "nodes",
        "IDENTIFIER",
        ":ID,CODE:string",
        ['id_x,"x > 0"'],
    )
    _write_csv(
        cpg_dir,
        "nodes",
        "CALL",
        ":ID,NAME:string,METHOD_FULL_NAME:string,LINE_NUMBER:int,CODE:string",
        [
            'c_op,<operator>.addition,<operator>.addition,11,"x + 1"',
            'c_res,helper,helper:void(),12,"helper()"',
            'c_unres,mystery,<unresolvedNamespace>.mystery:void(),13,"mystery()"',
            'c_unk,ptr_call,<unknownFullName>,14,"fp()"',
            'c_cut1,extra1,extra1:void(),15,"extra1()"',
            'c_cut2,extra2,extra2:void(),16,"extra2()"',
            'c_orphan,orphan_fn,orphan:void(),99,"orphan()"',
            'c_deep,deep_fn,deep:void(),99,"deep()"',
        ],
    )
    _write_csv(
        cpg_dir,
        "edges",
        "CONDITION",
        ":START_ID,:END_ID,:TYPE",
        ["br_cond,id_x,CONDITION"],
    )
    _write_csv(
        cpg_dir,
        "nodes",
        "CONTROL_STRUCTURE",
        ":ID,CONTROL_STRUCTURE_TYPE:string,LINE_NUMBER:int,CODE:string",
        [
            'br_cond,IF,17,"if (x > 0)"',
            'br_nocond,ELSE,18,"else"',
            'br_cut1,WHILE,19,"while (1)"',
            'br_cut2,FOR,20,"for (;;)"',
            'br_orphan,IF,88,"if (orphan)"',
        ],
    )
    _write_csv(
        cpg_dir,
        "edges",
        "REACHING_DEF",
        ":START_ID,:END_ID,:TYPE",
        [
            "id_x,c_res,REACHING_DEF",
            "c_orphan,id_x,REACHING_DEF",
        ],
    )

    monkeypatch.setattr(export, "MAX_AST_DEPTH", 3)
    monkeypatch.setattr(export, "MAX_CALLS_PER_FUNCTION", 3)
    monkeypatch.setattr(export, "MAX_BRANCHES_PER_FUNCTION", 2)
    parsed = export.read_export(cpg_dir)
    assert len(parsed.functions) == 1
    fn = parsed.functions[0]
    assert fn.name == "work"
    assert fn.operator_calls == 1
    assert fn.reaching_def_edges == 1
    assert [(c.name, c.callee_resolved) for c in fn.calls] == [
        ("helper", True),
        ("mystery", False),
        ("ptr_call", False),
    ]
    assert [(b.kind, b.condition) for b in fn.branches] == [
        ("IF", "x > 0"),
        ("ELSE", None),
    ]
    assert fn.cut == ["calls", "branches"]
    assert any("work lists a bounded subset of its calls/branches" in g for g in parsed.gaps)


def test_seeded_helpers_cover_selected_files_regex_argv_and_failure_reasons() -> None:
    settings = SeededSettings(mode="seeded", depth=2, seed_limit=10)
    scope_seeds = seeding.ScopeSeeds(
        scope_id="case-native",
        seeds=(
            seeding.Seed("src/b.cpp", 10, 12),
            seeding.Seed("src/a.c", 1, 1),
        ),
        total=2,
    )
    ident = seeded.identity_values(settings, scope_seeds, seeding.SeedPlan(scopes={"case-native": scope_seeds}))
    assert ident["seeded"]["impl"] == seeded.SEEDED_IMPL
    assert ident["seeded"]["seeds"] == [["src/a.c", 1, 1], ["src/b.cpp", 10, 12]]
    assert ident["seeded"]["export_argv"] == list(seeded.EXPORT_ARGV)

    sel = Selection(
        rows=(),
        container_rows=(
            {"file": "/target/source/src/b.cpp"},
            {"file": "/scratch/source/src/a.c"},
        ),
        by_seed={
            ("src/a.c", 1, 1): ("src/a.c",),
            ("src/b.cpp", 10, 12): ("src/b.cpp",),
        },
        reasons={("src/missing.c", 5, 5): "no_compile_unit"},
        gaps=("seed_gap_1",),
    )
    files = seeded.selected_files(sel)
    assert files == ["src/a.c", "src/b.cpp"]
    argv = seeded.argv_for(("c2cpg.sh", "/target/source"), files)
    assert argv[:3] == ("c2cpg.sh", "/target/source", "--exclude-regex")

    assert seeded.reasons(None, False) == {}
    assert seeded.reasons(sel, True) == {("src/missing.c", 5, 5): "no_compile_unit"}
    assert seeded.reasons(sel, False) == {
        ("src/missing.c", 5, 5): "no_compile_unit",
        ("src/a.c", 1, 1): seeding.record.REASON_RUN_FAILED,
        ("src/b.cpp", 10, 12): seeding.record.REASON_RUN_FAILED,
    }
