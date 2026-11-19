"""Choose the translation units a seeded compile-database producer replays.

A seed names a file and a line range. The translation units that can contain it are the unit whose
main source *is* that file, and, for a header seed, every unit that includes the header through the
``#include`` graph. The scan reads at most ``include_scan_files`` files; running out of that budget,
or of ``unit_limit`` units, is a named gap and never widens the selection to the whole program.

A seed that no unit can contain stays ``unresolved`` with that reason; it is not a clean result.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import posixpath
import re

from .ledger import Seed
from .plan import SourceScanIncomplete, SourceScanLimit

SOURCE_ROOT = "/scratch/source/"
_INCLUDE = re.compile(r'^\s*#\s*include\s*([<"])([^>"\n]+)[>"]', re.MULTILINE)
_INCLUDE_FLAGS = ("-I", "-isystem", "-iquote", "-idirafter")
UNIT_LIMIT_REACHED = "unit_limit_reached"
INCLUDE_SCAN_LIMIT = "include_scan_limit_reached"
NO_UNIT_FOR_SEED = "seed_without_translation_unit"


@dataclass(frozen=True, slots=True)
class UnitSelection:
    """Compile-database row indexes to replay, and which seed each serves."""

    selected: tuple[int, ...] = ()
    by_seed: Mapping[tuple[str, int, int], tuple[int, ...]] = field(default_factory=dict)
    uncovered: tuple[tuple[str, int, int], ...] = ()
    gaps: tuple[str, ...] = ()


def relative_source(row: Mapping[str, object]) -> str:
    """Project-relative path of a compile row's main source."""
    return _source_path(str(row["file"]), str(row.get("directory", ""))) or ""


def _source_path(value: str, directory: str) -> str | None:
    if not posixpath.isabs(value):
        if not any(directory == root or directory.startswith(root + "/")
                   for root in (SOURCE_ROOT.rstrip("/"), "/scratch/build")):
            return None
        value = posixpath.join(directory, value)
    normalized = posixpath.normpath(value)
    if normalized == SOURCE_ROOT.rstrip("/"):
        return "."
    return normalized[len(SOURCE_ROOT):] if normalized.startswith(SOURCE_ROOT) else None


def include_directories(row: Mapping[str, object], *, quoted: bool = True) -> tuple[str, ...]:
    """Accepted source include paths in compiler search order; only quotes use ``-iquote``.

    Paired and joined operands are resolved against the row's accepted source/build cwd. External
    system paths and generated build material are not invented as accepted source identities.
    """
    arguments = iter(str(item) for item in row.get("arguments", ()))
    found: dict[str, list[str]] = {flag: [] for flag in _INCLUDE_FLAGS}
    for argument in arguments:
        for flag in _INCLUDE_FLAGS:
            if argument == flag:
                value = next(arguments, "")
            elif argument.startswith(flag):
                value = argument[len(flag):]
            else:
                continue
            relative = _source_path(value, str(row.get("directory", ""))) if value else None
            if relative is not None:
                found[flag].append(relative)
            break
    order = ("-iquote", "-I", "-isystem", "-idirafter") if quoted else ("-I", "-isystem", "-idirafter")
    return tuple(dict.fromkeys(path for flag in order for path in found[flag]))


class _Scanner:
    """Bounded transitive include resolver with a per-header cache."""

    def __init__(self, read_text: Callable[[str], str | None], budget: int) -> None:
        self.read_text = read_text
        self.budget = budget
        self.reads = 0
        self.exhausted = False
        self.gaps: list[str] = []
        self._direct: dict[str, tuple[tuple[str, str], ...] | None] = {}

    def _includes(self, path: str) -> tuple[tuple[str, str], ...] | None:
        if not path or path == "." or posixpath.isabs(path) or path == ".." or path.startswith("../"):
            return None
        if path not in self._direct:
            if self.reads >= self.budget:
                self.exhausted = True
                return None
            self.reads += 1
            try:
                text = self.read_text(path)
            except (SourceScanLimit, SourceScanIncomplete) as error:
                self.gaps.append(str(error))
                # The file exists and shadows later include directories even though its includes
                # are unavailable. Do not select a different same-named header as a substitute.
                self._direct[path] = ()
            else:
                self._direct[path] = (tuple((match.group(1), match.group(2))
                                           for match in _INCLUDE.finditer(text)) if text is not None else None)
        return self._direct[path]

    def direct(self, path: str, directories: Sequence[str],
               quote_directories: Sequence[str]) -> tuple[str, ...]:
        resolved: list[str] = []
        base = posixpath.dirname(path)
        for delimiter, name in self._includes(path) or ():
            search = (base, *quote_directories) if delimiter == '"' else directories
            for directory in search:
                candidate = posixpath.normpath(posixpath.join(directory, name))
                if self._includes(candidate) is not None:
                    resolved.append(candidate)
                    break
                if self.exhausted and candidate not in self._direct:
                    break
        return tuple(resolved)

    def closure(self, main: str, directories: Sequence[str],
                quote_directories: Sequence[str]) -> frozenset[str]:
        seen = {main}
        stack = [main]
        while stack:
            current = stack.pop()
            for header in self.direct(current, directories, quote_directories):
                if header not in seen:
                    seen.add(header)
                    stack.append(header)
        return frozenset(seen)


def select_units(rows: Sequence[Mapping[str, object]], seeds: Iterable[Seed], *, unit_limit: int,
                 include_scan_files: int, read_text: Callable[[str], str | None]) -> UnitSelection:
    """Row indexes (into ``rows``) whose translation unit can contain each seed, bounded.

    ``read_text`` returns a project-relative file's text or ``None``; every invocation, including
    failed candidate probes, counts against ``include_scan_files``. Source contents and misses are
    cached within this selection, not include resolutions, which depend on each row's search paths.
    Rows are scanned in (path, index) order; the unit limit admits matches by (seed rank, seed key)
    before the retained rows are sorted for replay.
    """
    if unit_limit < 1 or include_scan_files < 0:
        raise ValueError("unit_limit must be positive and include_scan_files not negative")
    seed_list = sorted(seeds, key=lambda seed: (seed.rank, seed.key))
    order = sorted(range(len(rows)), key=lambda index: (relative_source(rows[index]), index))
    mains: dict[str, list[int]] = {}
    for index in order:
        mains.setdefault(relative_source(rows[index]), []).append(index)
    matches: dict[tuple[str, int, int], list[int]] = {}
    pending: list[Seed] = []
    for seed in seed_list:
        direct = mains.get(seed.path)
        if direct:
            matches[seed.key] = list(direct)
        else:
            pending.append(seed)
    gaps: list[str] = []
    scanner = _Scanner(read_text, include_scan_files)
    if pending:
        wanted = {seed.path for seed in pending}
        for index in order:
            closure = scanner.closure(relative_source(rows[index]),
                                      include_directories(rows[index], quoted=False),
                                      include_directories(rows[index]))
            for seed in pending:
                if seed.path in closure and seed.path in wanted:
                    matches.setdefault(seed.key, []).append(index)
        if scanner.exhausted:
            gaps.append(f"{INCLUDE_SCAN_LIMIT}: include_scan_files {include_scan_files} was reached; header "
                        "seeds may be missing translation units")
        gaps.extend(scanner.gaps)
    selected: list[int] = []
    for seed in seed_list:
        for index in matches.get(seed.key, ()):
            if index not in selected:
                selected.append(index)
    if len(selected) > unit_limit:
        dropped = selected[unit_limit:]
        selected = selected[:unit_limit]
        gaps.append(f"{UNIT_LIMIT_REACHED}: unit_limit {unit_limit} reached; {len(dropped)} translation "
                    "unit(s) holding seeds were not replayed")
    selected.sort(key=lambda index: (relative_source(rows[index]), index))
    chosen = set(selected)
    by_seed = {key: tuple(index for index in indexes if index in chosen)
               for key, indexes in matches.items()}
    by_seed = {key: value for key, value in by_seed.items() if value}
    uncovered = tuple(seed.key for seed in seed_list if seed.key not in by_seed)
    if uncovered:
        gaps.append(f"{NO_UNIT_FOR_SEED}: {len(uncovered)} seed location(s) lie in no replayed translation "
                    "unit; their neighborhood is not covered")
    return UnitSelection(tuple(selected), dict(sorted(by_seed.items())), uncovered, tuple(gaps))
