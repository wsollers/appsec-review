"""Ready-order execution of CodeQL database, query, normalization, and graph export scopes."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, wait
from typing import Any

from appsec_review.storage.shared import PublicationThreadPoolExecutor


def ready_scopes(
    scopes: Sequence[Any], *, concurrency: int,
    database: Callable[[Any], Any], profiles: Callable[[Any], Sequence[Any]],
    query: Callable[[Any, Any], Any], normalize: Callable[[Any], Any],
    export: Callable[[Any], Any],
) -> dict[str, list[Any]]:
    """Run independent CodeQL scopes concurrently without stage-wide barriers.

    Database creation, query execution, SARIF normalization, and bounded graph export share one
    bounded worker pool. As soon as one scope's database finishes, its query profiles become
    eligible ahead of unstarted databases; once all query normalizations for that scope complete
    (or immediately if the scope has zero query profiles), its bounded graph export becomes
    eligible so seeded export can incorporate CodeQL's own normalized observations for that scope.
    Returned lists remain ordered by plan index and profile order regardless of completion order.
    """
    ready: deque[tuple[str, tuple[int, ...], tuple[Any, ...]]] = deque(
        ("database", (index,), (scope,)) for index, scope in enumerate(scopes)
    )
    running: dict[Future[Any], tuple[str, tuple[int, ...]]] = {}
    outputs: dict[str, list[tuple[tuple[int, ...], Any]]] = {
        "database": [], "query": [], "normalize": [], "export": [],
    }
    databases_by_scope: dict[int, Any] = {}
    pending_normalizations: dict[int, int] = {}
    handlers = {"database": database, "query": query, "normalize": normalize, "export": export}
    if type(concurrency) is not int or concurrency < 1:
        raise ValueError("CodeQL concurrency must be positive")
    with PublicationThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="codeql-scope") as pool:
        while ready or running:
            while ready and len(running) < concurrency:
                kind, identity, args = ready.popleft()
                running[pool.submit(handlers[kind], *args)] = (kind, identity)
            done, _ = wait(running, return_when=FIRST_COMPLETED)
            for future in sorted(done, key=lambda item: running[item]):
                kind, identity = running.pop(future)
                result = future.result()
                outputs[kind].append((identity, result))
                if kind == "database":
                    scope_idx = identity[0]
                    databases_by_scope[scope_idx] = result
                    scope_profiles = list(profiles(result))
                    if not scope_profiles:
                        ready.appendleft(("export", (scope_idx, 0), (result,)))
                    else:
                        pending_normalizations[scope_idx] = len(scope_profiles)
                        children = [
                            ("query", (scope_idx, index), (result, profile))
                            for index, profile in enumerate(scope_profiles)
                        ]
                        ready.extendleft(reversed(children))
                elif kind == "query":
                    ready.appendleft(("normalize", identity, (result,)))
                elif kind == "normalize":
                    scope_idx = identity[0]
                    remaining = pending_normalizations.get(scope_idx, 0) - 1
                    pending_normalizations[scope_idx] = remaining
                    if remaining <= 0:
                        ready.appendleft(("export", (scope_idx, 0), (databases_by_scope[scope_idx],)))
    return {kind: [value for _id, value in sorted(items, key=lambda item: item[0])]
            for kind, items in outputs.items()}
