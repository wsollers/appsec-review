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
    file = str(row["file"])
    return file[len(SOURCE_ROOT):] if file.startswith(SOURCE_ROOT) else file.lstrip("/")


def include_directories(row: Mapping[str, object]) -> tuple[str, ...]:
    """Project-relative ``-I`` style directories of one compile row (system paths are ignored)."""
    arguments = [str(item) for item in row.get("arguments", ())]
    found: list[str] = []
    for index, argument in enumerate(arguments):
        for flag in _INCLUDE_FLAGS:
            value = None
            if argument == flag and index + 1 < len(arguments):
                value = arguments[index + 1]
            elif argument.startswith(flag) and argument != flag:
                value = argument[len(flag):]
            if value is not None and (value.startswith(SOURCE_ROOT) or value == SOURCE_ROOT.rstrip("/")):
                found.append(posixpath.normpath(value[len(SOURCE_ROOT):] or "."))
            break
    return tuple(dict.fromkeys(found))


class _Scanner:
    """Bounded transitive include resolver with a per-header cache."""

    def __init__(self, read_text: Callable[[str], str | None], budget: int) -> None:
        self.read_text = read_text
        self.budget = budget
        self.reads = 0
        self.exhausted = False
        self._direct: dict[str, tuple[str, ...]] = {}

    def direct(self, path: str, directories: Sequence[str]) -> tuple[str, ...]:
        key = path
        if key not in self._direct:
            if self.reads >= self.budget:
                self.exhausted = True
                return ()
            self.reads += 1
            text = self.read_text(path)
            names = [match.group(2) for match in _INCLUDE.finditer(text or "")] if text else []
            self._direct[key] = tuple(names)
        resolved: list[str] = []
        base = posixpath.dirname(path)
        for name in self._direct[key]:
            for directory in (base, *directories):
                candidate = posixpath.normpath(posixpath.join(directory, name))
                if self.read_text(candidate) is not None:
                    resolved.append(candidate)
                    break
        return tuple(resolved)

    def closure(self, main: str, directories: Sequence[str], limit: int = 2000) -> frozenset[str]:
        seen = {main}
        stack = [main]
        while stack and len(seen) < limit:
            current = stack.pop()
            for header in self.direct(current, directories):
                if header not in seen:
                    seen.add(header)
                    stack.append(header)
        return frozenset(seen)


def select_units(rows: Sequence[Mapping[str, object]], seeds: Iterable[Seed], *, unit_limit: int,
                 include_scan_files: int, read_text: Callable[[str], str | None]) -> UnitSelection:
    """Row indexes (into ``rows``) whose translation unit can contain each seed, bounded.

    ``read_text`` returns a project-relative file's text or ``None``; it is only consulted for header
    seeds and counts against ``include_scan_files``. The result is deterministic: rows are visited in
    (path, index) order.
    """
    if unit_limit < 1 or include_scan_files < 0:
        raise ValueError("unit_limit must be positive and include_scan_files not negative")
    seed_list = sorted(seeds, key=lambda seed: seed.key)
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
            closure = scanner.closure(relative_source(rows[index]), include_directories(rows[index]))
            for seed in pending:
                if seed.path in closure and seed.path in wanted:
                    matches.setdefault(seed.key, []).append(index)
        if scanner.exhausted:
            gaps.append(f"{INCLUDE_SCAN_LIMIT}: include_scan_files {include_scan_files} was reached; header "
                        "seeds may be missing translation units")
    selected: list[int] = []
    for seed in seed_list:
        for index in matches.get(seed.key, ()):
            if index not in selected:
                selected.append(index)
    selected.sort(key=lambda index: (relative_source(rows[index]), index))
    if len(selected) > unit_limit:
        dropped = selected[unit_limit:]
        selected = selected[:unit_limit]
        gaps.append(f"{UNIT_LIMIT_REACHED}: unit_limit {unit_limit} reached; {len(dropped)} translation "
                    "unit(s) holding seeds were not replayed")
    chosen = set(selected)
    by_seed = {key: tuple(index for index in indexes if index in chosen)
               for key, indexes in matches.items()}
    by_seed = {key: value for key, value in by_seed.items() if value}
    uncovered = tuple(seed.key for seed in seed_list if seed.key not in by_seed)
    if uncovered:
        gaps.append(f"{NO_UNIT_FOR_SEED}: {len(uncovered)} seed location(s) lie in no replayed translation "
                    "unit; their neighborhood is not covered")
    return UnitSelection(tuple(selected), dict(sorted(by_seed.items())), uncovered, tuple(gaps))
