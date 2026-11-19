"""The shared seeding module: one implementation of the ledger, neighborhood and unit selection.

Acceptance requirement 1: seed extraction, ledger statuses and the neighborhood walk are implemented once
(``appsec_review.seeding``) and every seeded producer imports them.
"""

from __future__ import annotations

import ast
from contextlib import contextmanager
from copy import deepcopy
import inspect
from pathlib import Path

import pytest

from appsec_review import seeding
from appsec_review.seeding import neighborhood, plan, units
from appsec_review.seeding.ledger import Seed

SRC = Path(__file__).resolve().parents[1] / "src" / "appsec_review"
SEEDING = SRC / "seeding"
LEDGER_LITERALS = {"resolved", "unresolved", "file_not_in_database", "over_limit"}


def _definitions(path: Path) -> list[tuple[str, int]]:
    """Definition names, disambiguating generic verbs by the shared seeding inputs."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.FunctionDef):
            arguments = {item.arg for item in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}
            if node.name == "expand" and not {"callers", "callees"} <= arguments:
                continue
            if node.name == "select_units" and not {"seeds", "include_scan_files"} <= arguments:
                continue
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            found.append((node.name, node.lineno))
        elif isinstance(node, ast.Assign):
            found.extend((target.id, node.lineno) for target in node.targets
                         if isinstance(target, ast.Name) and target.id.isupper())
    return found


def test_shared_algorithm_guard_detects_copies_not_unrelated_generic_verbs(tmp_path: Path) -> None:
    unrelated = tmp_path / "unrelated.py"
    unrelated.write_text("def expand(value): return value\n"
                         "def select_units(run_root, job, claim): return {}\n"
                         "def adapter():\n    expand = lambda compact, labels: compact\n", encoding="utf-8")
    copied = tmp_path / "copied.py"
    copied.write_text(inspect.getsource(neighborhood.expand) + "\n" + inspect.getsource(units.select_units)
                      + "\nLEDGER_STATUSES = ()\n",
                      encoding="utf-8")
    assert _definitions(unrelated) == [("adapter", 3)]
    assert {name for name, _line in _definitions(copied)} >= {"expand", "select_units", "LEDGER_STATUSES"}


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


def _sources(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


@pytest.mark.parametrize("flag", ("-I", "-isystem", "-iquote", "-idirafter"))
@pytest.mark.parametrize("joined", (False, True), ids=("paired", "joined"))
@pytest.mark.parametrize("relative", (False, True), ids=("absolute", "relative"))
def test_header_seed_supported_include_flags_use_accepted_cwd(
    tmp_path: Path, flag: str, joined: bool, relative: bool,
) -> None:
    _sources(tmp_path, {"src/a.cpp": '#include "h.h"\n', "inc/h.h": "int h;\n"})
    operand = "../inc" if relative else "/scratch/source/inc"
    flags = (flag + operand,) if joined else (flag, operand)
    row = dict(_row("src/a.cpp", *flags), directory="/scratch/source/src")
    before = deepcopy(row)
    seed = _seed("inc/h.h")
    selected = units.select_units([row], [seed], unit_limit=1, include_scan_files=3,
                                  read_text=seeding.source_reader(tmp_path))
    assert selected.selected == (0,)
    assert selected.by_seed == {seed.key: (0,)}
    assert selected.uncovered == () and selected.gaps == ()
    assert row == before


@pytest.mark.parametrize("cwd,operand", (
    ("/scratch/build", "/scratch/source/inc"),
    ("/scratch/build/sub", "../../source/inc"),
))
def test_header_seed_build_cwd_can_resolve_accepted_source(
    tmp_path: Path, cwd: str, operand: str,
) -> None:
    _sources(tmp_path, {"a.cpp": "#include <h.h>\n", "inc/h.h": "int h;"})
    row = dict(_row("a.cpp", "-isystem", operand), directory=cwd)
    selected = units.select_units([row], [_seed("inc/h.h")], unit_limit=1, include_scan_files=2,
                                  read_text=seeding.source_reader(tmp_path))
    assert selected.selected == (0,) and not selected.gaps


@pytest.mark.parametrize("cwd", ("", "src", "/unaccepted"))
def test_header_seed_relative_include_never_guesses_source_cwd(tmp_path: Path, cwd: str) -> None:
    _sources(tmp_path, {"src/a.cpp": '#include "h.h"\n', "inc/h.h": "int h;"})
    row = dict(_row("src/a.cpp", "-I../inc"), directory=cwd)
    result = units.select_units([row], [_seed("inc/h.h")], unit_limit=1, include_scan_files=5,
                                read_text=seeding.source_reader(tmp_path))
    assert result.selected == () and result.uncovered == (("inc/h.h", 3, 3),)


@pytest.mark.parametrize("quoted,expected", ((True, "src/h.h"), (False, "inc/h.h")))
def test_header_seed_respects_quote_and_system_search_order(
    tmp_path: Path, quoted: bool, expected: str,
) -> None:
    directive = '#include "h.h"\n' if quoted else "#include <h.h>\n"
    _sources(tmp_path, {"src/a.cpp": directive, **{f"{directory}/h.h": "int h;"
                                                 for directory in ("src", "quote", "inc", "system", "after")}})
    row = _row("src/a.cpp", "-idirafter/scratch/source/after", "-isystem/scratch/source/system",
               "-iquote/scratch/source/quote", "-I/scratch/source/inc")
    seeds = [_seed(f"{directory}/h.h") for directory in ("src", "quote", "inc", "system", "after")]
    result = units.select_units([row], seeds, unit_limit=1, include_scan_files=10,
                                read_text=seeding.source_reader(tmp_path))
    assert result.by_seed == {_seed(expected).key: (0,)}
    assert len(result.uncovered) == 4


@pytest.mark.parametrize("budget,expected_reads,selected", (
    (0, (), ()),
    (1, ("a.cpp",), ()),
    (2, ("a.cpp", "missing/h.h"), ()),
    (3, ("a.cpp", "missing/h.h", "inc/h.h"), (0,)),
))
def test_header_seed_budget_counts_candidate_misses_and_cache_hits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, budget: int,
    expected_reads: tuple[str, ...], selected: tuple[int, ...],
) -> None:
    main = "#include <h.h>\n#include <h.h>\n"
    _sources(tmp_path, {"a.cpp": main, "inc/h.h": ""})
    row = _row("a.cpp", "-I/scratch/source/missing", "-I/scratch/source/inc")
    reader = seeding.source_reader(tmp_path)
    reads = []
    physical_reads = _observe_file_reads(monkeypatch, tmp_path)

    def observed_read(path: str) -> str | None:
        reads.append(path)
        return reader(path)

    result = units.select_units([row], [_seed("inc/h.h")], unit_limit=1, include_scan_files=budget,
                                read_text=observed_read)
    assert tuple(reads) == expected_reads
    expected_physical = ([("a.cpp", len(main))] if budget else []) + ([("inc/h.h", 0)] if budget == 3 else [])
    assert [(path, count) for path, _size, count in physical_reads] == expected_physical
    assert all(0 <= requested <= plan.MAX_SCAN_BYTES for _path, requested, _count in physical_reads)
    assert result.selected == selected
    assert any(gap.startswith(units.INCLUDE_SCAN_LIMIT) for gap in result.gaps) == (budget < 3)


def test_header_seed_parses_cached_headers_but_resolves_each_tu_separately(tmp_path: Path) -> None:
    _sources(tmp_path, {"a.cpp": '#include "shared.h"\n', "shared.h": "#include <h.h>\n",
                        "left/h.h": '#include "../shared.h"\n', "right/h.h": "int right;"})
    rows = [_row("a.cpp", "-I/scratch/source/left"), _row("a.cpp", "-I/scratch/source/right")]
    reader = seeding.source_reader(tmp_path)
    reads = []

    def observed_read(path: str) -> str | None:
        reads.append(path)
        return reader(path)

    result = units.select_units(rows, [_seed("right/h.h")], unit_limit=2, include_scan_files=4,
                                read_text=observed_read)
    assert result.selected == (1,) and not result.gaps
    assert reads == ["a.cpp", "shared.h", "left/h.h", "right/h.h"]


def test_header_seed_exhaustion_does_not_skip_unknown_shadowing_header(tmp_path: Path) -> None:
    _sources(tmp_path, {"a.cpp": "#include <h.h>\n", "cached/h.h": "", "unread/h.h": ""})
    rows = [_row("a.cpp", "-I/scratch/source/cached"),
            _row("a.cpp", "-I/scratch/source/unread", "-I/scratch/source/cached")]
    result = units.select_units(rows, [_seed("cached/h.h")], unit_limit=2, include_scan_files=2,
                                read_text=seeding.source_reader(tmp_path))
    assert result.selected == (0,)
    assert result.by_seed == {_seed("cached/h.h").key: (0,)}
    assert any(gap.startswith(units.INCLUDE_SCAN_LIMIT) for gap in result.gaps)


def test_header_seed_unit_limit_keeps_highest_priority_before_path_order(tmp_path: Path) -> None:
    _sources(tmp_path, {"a.cpp": '#include "a.h"\n', "a.h": "",
                        "z.cpp": '#include "z.h"\n', "z.h": ""})
    rows = [_row("a.cpp"), _row("z.cpp")]
    seeds = [Seed("a.h", 1, 1, rank=3), Seed("z.h", 1, 1, rank=0)]
    for ordered in (seeds, list(reversed(seeds))):
        result = units.select_units(rows, ordered, unit_limit=1, include_scan_files=4,
                                    read_text=seeding.source_reader(tmp_path))
        assert result.selected == (1,)
        assert result.by_seed == {seeds[1].key: (1,)}
        assert result.uncovered == (seeds[0].key,)
        assert any(gap.startswith(units.UNIT_LIMIT_REACHED) for gap in result.gaps)


def _observe_file_reads(monkeypatch: pytest.MonkeyPatch, root: Path, *,
                        chunk_size: int | None = None,
                        stop_after: int | None = None) -> list[tuple[str, int, int]]:
    original = Path.open
    reads = []

    class ObservedStream:
        def __init__(self, stream, relative: str):
            self.stream = stream
            self.relative = relative

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def read(self, size: int = -1):
            requested = size
            if chunk_size is not None:
                size = min(size, chunk_size) if size >= 0 else chunk_size
            if stop_after is not None:
                size = min(size, max(0, stop_after - self.stream.tell()))
            data = self.stream.read(size)
            reads.append((self.relative, requested, len(data)))
            return data

    @contextmanager
    def observed_open(path: Path, *args, **kwargs):
        with original(path, *args, **kwargs) as stream:
            yield ObservedStream(stream, path.relative_to(root).as_posix()) if root in path.parents else stream

    monkeypatch.setattr(Path, "open", observed_open)
    return reads


@pytest.mark.parametrize("at_limit", (False, True), ids=("tiny", "exact-byte-limit"))
def test_header_seed_short_file_reads_finish_within_byte_and_candidate_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, at_limit: bool,
) -> None:
    prefix, directive = "// € source\n".encode(), b'#include "h.h"\n'
    size = plan.MAX_SCAN_BYTES if at_limit else len(prefix) + len(directive)
    data = prefix + b" " * (size - len(prefix) - len(directive)) + directive
    (tmp_path / "a.cpp").write_bytes(data)
    (tmp_path / "h.h").write_bytes(b"int h;")
    reads = _observe_file_reads(monkeypatch, tmp_path, chunk_size=131071 if at_limit else 5)
    reader = seeding.source_reader(tmp_path)
    candidates = []

    def observed_read(path: str) -> str | None:
        candidates.append(path)
        return reader(path)

    result = units.select_units([_row("a.cpp")], [_seed("h.h")], unit_limit=1,
                                include_scan_files=2, read_text=observed_read)
    assert result.selected == (0,) and not result.gaps
    assert candidates == ["a.cpp", "h.h"]
    for path, expected in (("a.cpp", size), ("h.h", 6)):
        consumed = 0
        chunks = [(requested, count) for file, requested, count in reads if file == path]
        assert chunks
        for requested, count in chunks:
            assert 0 < requested <= plan.MAX_SCAN_BYTES - consumed
            consumed += count
        assert consumed == expected


def test_header_seed_premature_read_end_never_parses_a_prefix_as_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    directive = '#include "h.h"\n'
    _sources(tmp_path, {"a.cpp": directive + "int more_source;\n", "h.h": "int h;"})
    reads = _observe_file_reads(monkeypatch, tmp_path, chunk_size=len(directive), stop_after=len(directive))
    result = units.select_units([_row("a.cpp")], [_seed("h.h")], unit_limit=1,
                                include_scan_files=2, read_text=seeding.source_reader(tmp_path))
    assert result.selected == ()
    assert result.uncovered == (_seed("h.h").key,)
    assert any(gap.startswith("include_scan_incomplete:") for gap in result.gaps)
    assert [(path, count) for path, _requested, count in reads] == [
        ("a.cpp", len(directive)), ("a.cpp", 0)]


@pytest.mark.parametrize("extra", (0, 1), ids=("exact-byte-limit", "over-byte-limit"))
def test_header_seed_source_byte_limit_bounds_actual_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: int,
) -> None:
    directive = b'#include "h.h"\n'
    data = directive + b" " * (plan.MAX_SCAN_BYTES - len(directive) + extra)
    (tmp_path / "a.cpp").write_bytes(data)
    (tmp_path / "h.h").write_bytes(b"int h;")
    reads = _observe_file_reads(monkeypatch, tmp_path)
    result = units.select_units([_row("a.cpp")], [_seed("h.h")], unit_limit=1, include_scan_files=2,
                                read_text=seeding.source_reader(tmp_path))
    if extra:
        assert reads == []
        assert result.selected == ()
        assert any(gap.startswith("include_scan_bytes_limit_reached:") for gap in result.gaps)
    else:
        assert [(path, count) for path, _size, count in reads] == [
            ("a.cpp", plan.MAX_SCAN_BYTES), ("h.h", 6)]
        assert all(0 <= requested <= plan.MAX_SCAN_BYTES for _path, requested, _count in reads)
        assert result.selected == (0,) and not result.gaps


def test_header_seed_oversized_candidate_shadows_later_search_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _sources(tmp_path, {"a.cpp": "#include <h.h>\n", "first/h.h": " " * (plan.MAX_SCAN_BYTES + 1),
                        "later/h.h": ""})
    reads = _observe_file_reads(monkeypatch, tmp_path)
    row = _row("a.cpp", "-I/scratch/source/first", "-I/scratch/source/later")
    result = units.select_units([row], [_seed("first/h.h"), _seed("later/h.h")],
                                unit_limit=1, include_scan_files=2, read_text=seeding.source_reader(tmp_path))
    assert result.by_seed == {_seed("first/h.h").key: (0,)}
    assert result.uncovered == (_seed("later/h.h").key,)
    assert [(path, size) for path, _requested, size in reads] == [("a.cpp", len("#include <h.h>\n"))]
    assert any(gap.startswith("include_scan_bytes_limit_reached:") for gap in result.gaps)


@pytest.mark.parametrize("link_directory", (False, True), ids=("file-symlink", "directory-symlink"))
def test_header_seed_reader_rejects_symlink_aliases_without_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, link_directory: bool,
) -> None:
    _sources(tmp_path, {"real/h.h": "int h;"})
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path / ("real" if link_directory else "real/h.h"), target_is_directory=link_directory)
    reads = _observe_file_reads(monkeypatch, tmp_path)
    assert seeding.source_reader(tmp_path)("alias/h.h" if link_directory else "alias") is None
    assert reads == []
