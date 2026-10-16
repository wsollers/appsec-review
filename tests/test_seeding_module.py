"""The shared seeding module: one implementation of the ledger, neighborhood and unit selection.

Acceptance requirement 1: seed extraction, ledger statuses and the neighborhood walk are implemented once
(``appsec_review.seeding``) and every seeded producer imports them.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from appsec_review import seeding
from appsec_review.seeding import neighborhood, units
from appsec_review.seeding.ledger import Seed

SRC = Path(__file__).resolve().parents[1] / "src" / "appsec_review"
SEEDING = SRC / "seeding"
LEDGER_LITERALS = {"resolved", "unresolved", "file_not_in_database", "over_limit"}


def _definitions(path: Path) -> list[tuple[str, int]]:
    """Names a module defines (functions, classes, upper-case constants) with their line."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            found.append((node.name, node.lineno))
        elif isinstance(node, ast.Assign):
            found.extend((target.id, node.lineno) for target in node.targets if isinstance(target, ast.Name))
    return found


def test_only_the_seeding_package_defines_ledger_statuses() -> None:
    """Fails when a second module defines the ledger vocabulary or builds a ledger entry of its own."""
    distinctive = {"file_not_in_database", "over_limit"}
    offenders: dict[str, list[str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        if SEEDING in path.parents:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and node.value in distinctive:
                offenders.setdefault(str(path.relative_to(SRC)), []).append(f"line {node.lineno}")
            # a collection of the four status words
            if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
                words = {item.value for item in node.elts if isinstance(item, ast.Constant)}
                if len(words & LEDGER_LITERALS) >= 3:
                    offenders.setdefault(str(path.relative_to(SRC)), []).append(f"line {node.lineno}")
    assert not offenders, f"ledger statuses are defined only in appsec_review/seeding/ledger.py: {offenders}"


def test_no_module_outside_seeding_reimplements_the_shared_algorithms() -> None:
    shared = {"expand", "select_units", "extract_seeds", "seeded_section", "skipped_section", "LIMIT_REACHED",
              "DEPTH_REACHED", "FRONTIER", "EXPORT_TRUNCATED", "LEDGER_STATUSES",
              "FILE_NOT_IN_DATABASE", "OVER_LIMIT"}
    offenders = {}
    for path in sorted(SRC.rglob("*.py")):
        if SEEDING in path.parents:
            continue
        clash = [(name, line) for name, line in _definitions(path) if name in shared]
        if clash:
            offenders[str(path.relative_to(SRC))] = clash
    assert not offenders, f"shared seeding algorithms are defined only in appsec_review/seeding: {offenders}"


def test_every_seeded_producer_imports_the_shared_module() -> None:
    expected = {"job_codeql_analysis": "job.py", "job_cpp_compiled_analysis": "seeded.py",
                "job_clang_static_analysis": "seeded.py", "job_cpg_analysis": "seeded.py"}
    for job, name in expected.items():
        text = (SRC / "jobs" / job / name).read_text(encoding="utf-8")
        assert "appsec_review.seeding" in text or "from appsec_review import seeding" in text \
            or "jobs.cpp_seeded" in text, job
    assert "appsec_review import seeding" in (SRC / "jobs" / "cpp_seeded.py").read_text(encoding="utf-8")


def test_ledger_status_words_are_the_documented_four() -> None:
    assert seeding.LEDGER_STATUSES == ("resolved", "unresolved", "file_not_in_database", "over_limit")


def test_implementation_sources_cover_the_whole_package() -> None:
    names = {path.name for path in seeding.implementation_sources()}
    assert {"ledger.py", "neighborhood.py", "units.py", "record.py", "plan.py", "__init__.py"} <= names


# ------------------------------------------------------------------------------ neighborhood


CALLEES = {"main": ["parse"], "parse": ["read", "check"], "check": ["fail"], "read": []}
CALLERS = {"parse": ["main"], "read": ["parse"], "check": ["parse"], "fail": ["check"]}


def test_expand_orders_by_distance_and_names_the_depth_bound() -> None:
    result = neighborhood.expand(["parse"], CALLERS, CALLEES, depth=1, function_limit=10)
    assert dict(result.distance) == {"parse": 0, "check": 1, "main": 1, "read": 1}
    assert result.functions == ("parse", "check", "main", "read")
    assert any(gap.startswith(neighborhood.DEPTH_REACHED) for gap in result.gaps)
    deeper = neighborhood.expand(["parse"], CALLERS, CALLEES, depth=2, function_limit=10)
    assert deeper.distance["fail"] == 2 and not deeper.gaps


def test_expand_function_limit_is_a_named_gap_not_silence() -> None:
    result = neighborhood.expand(["parse"], CALLERS, CALLEES, depth=3, function_limit=2)
    assert len(result.distance) == 2
    assert any(gap.startswith(neighborhood.LIMIT_REACHED) for gap in result.gaps)


def test_expand_marks_unobserved_functions_as_frontier_without_expanding_them() -> None:
    result = neighborhood.expand(["parse"], CALLERS, CALLEES, depth=3, function_limit=10, observed=["parse"])
    assert set(result.distance) == {"parse", "read", "check", "main"}
    assert set(result.unexpanded) == {"read", "check", "main"}
    assert any(gap.startswith(neighborhood.FRONTIER) for gap in result.gaps)
    assert "fail" not in result.distance


def test_expand_is_deterministic_and_validates_bounds() -> None:
    assert neighborhood.expand(["b", "a"], {}, {}, depth=1, function_limit=5) == \
        neighborhood.expand(["a", "b"], {}, {}, depth=1, function_limit=5)
    with pytest.raises(ValueError):
        neighborhood.expand(["a"], {}, {}, depth=-1, function_limit=1)
    assert neighborhood.expand(["a"], {}, {}, depth=1, function_limit=5).histogram() == {"0": 1}


# ------------------------------------------------------------------------------ unit selection


def _row(path: str, *flags: str) -> dict:
    return {"file": f"/scratch/source/{path}", "arguments": ["clang", "-c", *flags, f"/scratch/source/{path}"]}


def _seed(path: str, line: int = 3) -> Seed:
    return Seed(path, line, line)


def test_select_units_picks_the_main_source_and_includers_of_a_header_seed() -> None:
    rows = [_row("src/a.c", "-I/scratch/source/include"), _row("src/b.c", "-I/scratch/source/include"),
            _row("src/c.c")]
    files = {"src/a.c": '#include "net.h"\n', "src/b.c": "int b;\n", "src/c.c": '#include "net.h"\n',
             "include/net.h": "int n;\n"}
    chosen = units.select_units(rows, [_seed("src/b.c"), _seed("include/net.h")], unit_limit=10,
                                include_scan_files=50, read_text=files.get)
    # b.c holds the first seed; only a.c reaches include/net.h through -I (c.c has no include directory)
    assert chosen.selected == (0, 1) and not chosen.uncovered and not chosen.gaps


def test_select_units_never_widens_to_the_whole_program() -> None:
    rows = [_row(f"src/f{i}.c") for i in range(12)]
    chosen = units.select_units(rows, [_seed("src/f3.c"), _seed("src/f7.c"), _seed("src/missing.c")],
                                unit_limit=10, include_scan_files=10, read_text=lambda _: None)
    assert chosen.selected == (3, 7)
    assert chosen.uncovered == (("src/missing.c", 3, 3),)
    assert any(gap.startswith(units.NO_UNIT_FOR_SEED) for gap in chosen.gaps)


def test_select_units_limit_and_scan_budget_are_named_gaps() -> None:
    rows = [_row(f"src/f{i}.c") for i in range(5)]
    limited = units.select_units(rows, [_seed(f"src/f{i}.c") for i in range(5)], unit_limit=2,
                                 include_scan_files=10, read_text=lambda _: None)
    assert len(limited.selected) == 2
    assert any(gap.startswith(units.UNIT_LIMIT_REACHED) for gap in limited.gaps)
    scan = units.select_units(rows, [_seed("include/x.h")], unit_limit=5, include_scan_files=0,
                              read_text=lambda _: "")
    assert scan.selected == () and any(gap.startswith(units.INCLUDE_SCAN_LIMIT) for gap in scan.gaps)
    with pytest.raises(ValueError):
        units.select_units(rows, [], unit_limit=0, include_scan_files=0, read_text=lambda _: None)
