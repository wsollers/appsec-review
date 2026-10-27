"""Bounded ready-work scheduling; no whole-database barrier."""
from __future__ import annotations

from collections import deque
from concurrent.futures import FIRST_COMPLETED, wait
from typing import Any, Callable, Iterable, Mapping

from appsec_review.storage.shared import PublicationThreadPoolExecutor


def ready_scopes(
    scopes: Iterable[Any], *, concurrency: int,
    database: Callable[[Any], Mapping[str, Any]],
    profiles: Callable[[Mapping[str, Any]], Iterable[Any]],
    query: Callable[[Mapping[str, Any], Any], Mapping[str, Any]],
    normalize: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    export: Callable[[Mapping[str, Any]], Mapping[str, Any]],
) -> dict[str, list[Mapping[str, Any]]]:
    if type(concurrency) is not int or concurrency < 1:
        raise ValueError("CodeQL concurrency must be positive")
    ready = deque(("database", (index, 0), (scope,)) for index, scope in enumerate(scopes))
    completed: dict[str, dict[tuple[int, int], Mapping[str, Any]]] = {
        name: {} for name in ("database", "query", "normalize", "export")}
    functions = {"database": database, "query": query, "normalize": normalize, "export": export}
    with PublicationThreadPoolExecutor(max_workers=concurrency) as pool:
        pending = {}
        while ready or pending:
            while ready and len(pending) < concurrency:
                action, identity, args = ready.popleft()
                future = pool.submit(functions[action], *args)
                pending[future] = action, identity
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in sorted(done, key=lambda item: pending[item]):
                action, identity = pending.pop(future)
                result = future.result()
                completed[action][identity] = result
                if action == "database":
                    children = [("query", (identity[0], index), (result, profile))
                                for index, profile in enumerate(profiles(result))]
                    children.append(("export", identity, (result,)))
                    ready.extendleft(reversed(children))
                elif action == "query":
                    ready.appendleft(("normalize", identity, (result,)))
    return {name: [rows[key] for key in sorted(rows)] for name, rows in completed.items()}
