"""The bounded call-graph neighborhood of a seed set, shared by every seeded producer.

A producer that sees only a slice of the program (one translation unit's IR, one analyzer run) gives
this module the caller and callee edges it observed. The result is the functions within ``depth``
call steps of the seed functions, nearest first, plus the *named* gaps for every bound that cut the
walk short. A function nobody observed is never "absent"; it is a frontier or an unexpanded bound.

Gap vocabulary (``docs/architecture/seeded-neighborhoods.md`` section 6): ``limit_reached``,
``depth_reached`` and ``frontier``. ``export_truncated`` belongs to row-bounded exports and is
produced by the exporting job, not here.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

LIMIT_REACHED = "limit_reached"
DEPTH_REACHED = "depth_reached"
FRONTIER = "frontier"
EXPORT_TRUNCATED = "export_truncated"
GAP_NAMES = (LIMIT_REACHED, DEPTH_REACHED, FRONTIER, EXPORT_TRUNCATED)


@dataclass(frozen=True, slots=True)
class Neighborhood:
    """Functions within the bounds, each with its minimum call distance from a seed function."""

    distance: Mapping[str, int] = field(default_factory=dict)
    gaps: tuple[str, ...] = ()
    #: callers/callees seen from a function whose own edges the producer did not observe
    unexpanded: tuple[str, ...] = ()

    @property
    def functions(self) -> tuple[str, ...]:
        return tuple(sorted(self.distance, key=lambda name: (self.distance[name], name)))

    def histogram(self) -> dict[str, int]:
        counts: dict[int, int] = {}
        for value in self.distance.values():
            counts[value] = counts.get(value, 0) + 1
        return {str(key): counts[key] for key in sorted(counts)}


def expand(seed_functions: Iterable[str], callers: Mapping[str, Iterable[str]],
           callees: Mapping[str, Iterable[str]], *, depth: int, function_limit: int,
           observed: Iterable[str] | None = None) -> Neighborhood:
    """Breadth-first closure over callers and callees, deterministic and bounded.

    ``observed`` is the set of functions whose edges the producer actually saw (their bodies were
    replayed); a neighbor outside it is a ``frontier`` function: kept as a member (it is one call
    step away) but never expanded. Omit it to treat every function as observed.
    """
    if depth < 0 or function_limit < 1:
        raise ValueError("depth must not be negative and function_limit must be positive")
    seen = None if observed is None else frozenset(observed)
    distance: dict[str, int] = {}
    for name in sorted(set(seed_functions)):
        if len(distance) >= function_limit:
            break
        distance[name] = 0
    dropped_seeds = len(set(seed_functions)) - len(distance)
    gaps: list[str] = []
    if dropped_seeds:
        gaps.append(f"{LIMIT_REACHED}: function_limit {function_limit} reached; {dropped_seeds} seed "
                    "function(s) were not expanded")
    layer = sorted(distance)
    cut_by_limit: set[str] = set()
    frontier: set[str] = set()
    for step in range(depth):
        following: set[str] = set()
        for name in layer:
            if seen is not None and name not in seen:
                frontier.add(name)
                continue
            for neighbor in (*callees.get(name, ()), *callers.get(name, ())):
                if neighbor in distance:
                    continue
                following.add(neighbor)
        layer = []
        for name in sorted(following):
            if len(distance) >= function_limit:
                cut_by_limit.add(name)
                continue
            distance[name] = step + 1
            layer.append(name)
        if not layer:
            break
    else:
        # The depth bound stopped the walk: edges of the last layer were not followed.
        pending = sorted({neighbor for name in layer if seen is None or name in seen
                          for neighbor in (*callees.get(name, ()), *callers.get(name, ()))
                          if neighbor not in distance})
        if pending:
            gaps.append(f"{DEPTH_REACHED}: the walk stopped at depth {depth}; {len(pending)} further "
                        "function(s) lie beyond it, their absence is not evidence")
    if seen is not None:
        frontier.update(name for name in distance if name not in seen)
    if cut_by_limit:
        gaps.append(f"{LIMIT_REACHED}: function_limit {function_limit} reached; {len(cut_by_limit)} "
                    "further function(s) were not added")
    if frontier:
        gaps.append(f"{FRONTIER}: {len(frontier)} neighborhood function(s) were not observed by this "
                    "producer; their callers and callees are absent from it, not nonexistent")
    return Neighborhood(dict(distance), tuple(gaps), tuple(sorted(frontier)))
