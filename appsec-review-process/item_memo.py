#!/usr/bin/env python3
"""Per-item memo for loops (brief N item 2, ADR-0014 item 6).

A loop job (build-plan units today; build-resolution units and IR/SAST invocations are the next
call sites) re-executes every item after any change to the job's fingerprint, even when that
change did not touch the item: multi-vuln re-planned 53 units for 41 min.  A memo entry remembers,
per item, which earlier accepted result was produced from exactly the same item inputs.

Rules, shared with :mod:`tool_output_cache`:

- The caller builds the key material from the item's own inputs only: content it hashed itself,
  pinned configuration, the prompt and contract bytes, the model identity, the run and the mode.
  Nothing a model or a target wrote is trusted as key material.
- An entry is a pointer (paths plus the hashes retained when the result was accepted), never the
  result itself.  ``lookup`` hands the entry to the caller's ``accept`` function, which must
  re-read the pointed-to bytes, check their hashes and re-run today's validation; if ``accept``
  raises, the entry is invalidated and the item runs fresh.  A memo hit is never less checked than
  a fresh result.
- The run mode is part of the key.  Tunable ``item_memo``: ``off`` / ``dev`` (default) / ``on``.

Store: ``data/caches/item-memo/`` (git-ignored), capped by ``item_memo_max_entries``.
"""
from __future__ import annotations

from typing import Any, Callable, TypeVar

import tunables
import tool_output_cache as toc

NAMESPACE = "item-memo"
ENTRY_SCHEMA = "appsec-review/item-memo-entry/1"
T = TypeVar("T")


def enabled(mode: str | None = None) -> bool:
    return toc.mode_enabled(tunables.shared("item_memo"), toc.run_mode() if mode is None else mode)


class Memo:
    """One loop's memo. ``material`` must name the loop (job and item kind) and the item."""

    def __init__(self, loop: str, mode: str | None = None) -> None:
        self.loop = loop
        self.mode = toc.run_mode() if mode is None else mode
        self.enabled = enabled(self.mode)
        self.store = toc.Store(NAMESPACE, ENTRY_SCHEMA, "item_memo_max_entries")

    def _material(self, material: dict[str, Any]) -> dict[str, Any]:
        return {"loop": self.loop, "mode": self.mode, "item": material}

    def lookup(self, material: dict[str, Any], accept: Callable[[dict[str, Any]], T]) -> T | None:
        """``accept(entry)`` re-verifies and returns the reusable value; any exception is a miss
        that invalidates the entry."""
        if not self.enabled:
            return None
        full = self._material(material)
        key = toc.key_of(full)
        entry = self.store.get(key, full)
        if entry is None:
            return None
        try:
            return accept(entry)
        except Exception as exc:  # noqa: BLE001 - any failure to re-verify is a miss, never a reuse
            self.store.invalidate(key, f"re-validation failed: {type(exc).__name__}: {exc}"[:500])
            return None

    def record(self, material: dict[str, Any], payload: dict[str, Any]) -> None:
        if not self.enabled:
            return
        full = self._material(material)
        self.store.put(toc.key_of(full), full, {"loop": self.loop, **payload})


# --- helpers for loops whose items are B13 container runs ---------------------------------------------
# A memoised B13 trial stays in the attempt that ran it (B13 binds a trial to its attempt path); the
# caller re-verifies it there with container_execution.load_verified_result. These two checks make sure
# the recorded request is the one today's code would issue and that it ran under a granted decision.

def same_b13_request(recorded: Any, expected: dict[str, Any], *, adapter_id: str) -> None:
    """Raise unless ``recorded`` equals today's ``expected`` request in everything but the attempt
    id (which must be the memoised adapter id), the permission (checked separately) and the mount
    host paths (the content behind them is in the memo key)."""
    if not isinstance(recorded, dict) or set(recorded) != set(expected):
        raise ValueError("recorded B13 request shape differs")
    for key, value in expected.items():
        if key not in ("attempt_id", "permission", "target_mounts") and recorded[key] != value:
            raise ValueError(f"recorded B13 request differs from today's request ({key})")
    if recorded["attempt_id"] != adapter_id:
        raise ValueError("recorded B13 request names another attempt")
    if ([m.get("container_path") for m in recorded["target_mounts"]] !=
            [m["container_path"] for m in expected["target_mounts"]]):
        raise ValueError("recorded B13 request mounts differ")


def recorded_permission_granted(permission: Any, *, run_id: str, job_id: str,
                                requirement: dict[str, Any], registry_ceiling: Any) -> None:
    """Re-evaluate the recorded permission decision at its own recorded time; raise unless it was
    granted for exactly ``requirement``."""
    import permission_capabilities as pc
    if not isinstance(permission, dict) or permission.get("requirement") != requirement:
        raise ValueError("recorded B13 request ran under a different permission requirement")
    decision = permission["decision"]
    context = {"run_id": run_id, "job_id": job_id,
               "source_snapshot_sha256": decision["source_snapshot_sha256"],
               "now": decision["evaluated_at"], "registry_ceiling": registry_ceiling}
    pc.require_granted(decision, requirement=requirement, grants=permission["grants"], context=context)
