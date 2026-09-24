#!/usr/bin/env python3
"""Claude CLI binary resolver (D01 construction follow-up; William, 2026-09-24): resolves the real,
absolute `claude` CLI executable path once per run, from inside the process that actually needs to
dispatch it, and pins the result -- rather than pinning a literal path in `model-config.json`.

Why this exists: D01's first live automatic-dispatch attempt (SAT `20260924T204008Z`) failed with
`FileNotFoundError: ... 'claude'`. `model-config.json`'s `invocation.binary` was the bare name
`"claude"`, resolved via whatever process's own `PATH` happens to run it -- fine for
`code-location.sh run`'s synchronous steps (inherits the interactive shell's PATH), not inside the
long-running `dagster code-server start` daemon that actually executes the job, which does not
carry that same PATH. A first attempt at a fix hardcoded one operator's absolute Windows-side npm
install path directly into `model-config.json`; **William rejected that pin**: "Don't pin a
version. Look it up in the first job. If not found error appropriately." A hardcoded path is
exactly the kind of thing that silently breaks the moment the install moves -- a reinstall, a
different machine, a different operator, a different PATH layout.

The fix: resolve the real absolute path with `shutil.which()` from *inside* whichever process
dispatches the first claude CLI call for a run (today, always
`model_version_registry.resolve_run_model_versions`, itself always the first thing D01's
automatic-dispatch path calls per job -- see `discovery_gate._dispatch_partition_persona`), and pin
the resolved path to the run. Every later call in that same run reuses the pinned value rather than
re-resolving -- the same "resolve once per run, pin, reuse on resume" shape
`model_version_registry.py` already uses for model identity, at William's own prior request, now
applied to the binary path itself. If resolution fails, this module raises `ClaudeBinaryError`
naming exactly the configured name and that it was not found in *this* process -- never silently
falls back to the bare configured name (that fallback is exactly the bug this module fixes), and
never fabricates a path.

Deliberately scoped: this module does not try to resolve the binary from any other process's PATH
(the interactive shell's, the cloud sandbox's) -- only the process that will actually run the
dispatch. If that process's environment is missing the binary, that is the real, actionable
finding, and the error says so plainly rather than papering over it with a value borrowed from a
different process.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from execution_state import atomic_bytes, data_path, identifier  # noqa: E402
import review_cli as rc  # noqa: E402

SCHEMA_ID = "appsec-review/run-claude-binary/1.0"
RECORD_FILENAME = "claude-binary.json"


class ClaudeBinaryError(RuntimeError):
    """The claude CLI binary could not be resolved, or has no pinned record yet, for this run."""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _record_path(run_id: str) -> Path:
    return data_path(run_id, RECORD_FILENAME)


def configured_name() -> str:
    """The name (or, if an operator has set one, an absolute path) `model-config.json`'s
    `invocation.binary` names -- the thing this module looks up, never a hardcoded install path of
    its own. Defaults to `"claude"` when unset."""
    cfg = rc.load_model_config()
    return (cfg.get("invocation") or {}).get("binary") or "claude"


def _resolve(configured: str, *, which_fn=shutil.which) -> str | None:
    candidate = Path(configured)
    if candidate.is_absolute():
        # An operator-set absolute path is honored as-is (still validated -- never assumed): this
        # is not this module reintroducing a pin, since it is model-config.json's own configured
        # value in this process, checked fresh, not a value baked in ahead of time by us.
        return configured if candidate.exists() else None
    return which_fn(configured)


def resolve_claude_binary(run_id: str, *, force: bool = False, which_fn=shutil.which) -> str:
    """The run-scoped entry point. Call this from the first job in a run that is about to dispatch
    a real claude CLI call -- today, `model_version_registry.resolve_run_model_versions` does so
    unconditionally before any persona invocation. If the run already has a pinned record and
    `force` is false, reuses it unchanged (a resumed run, or a later job in the same run, never
    re-resolves). Otherwise resolves in *this* process -- the one actually about to dispatch, so
    its `PATH` is exactly the one that matters -- and pins the resolved absolute path so later
    calls (including from a different process, e.g. `ClaudeCliInvoker.invoke()` running inside the
    same job) reuse it rather than re-resolving redundantly."""
    path = _record_path(run_id)
    if path.exists() and not force:
        return load_claude_binary(run_id)["resolved_path"]
    configured = configured_name()
    resolved = _resolve(configured, which_fn=which_fn)
    if not resolved:
        raise ClaudeBinaryError(
            f"claude CLI binary {configured!r} (model-config.json invocation.binary) was not "
            f"found on PATH in this process (pid {os.getpid()}) -- install it "
            f"(e.g. `npm install -g @anthropic-ai/claude-code`) where the process that dispatches "
            f"this run's jobs can see it, or set model-config.json's invocation.binary to a name "
            f"or absolute path that process can resolve. Resolution is per-run and per-process, "
            f"by design -- never borrowed from any other shell's PATH (see this module's "
            f"docstring for why a hardcoded path was rejected here).")
    record = {
        "schema": SCHEMA_ID,
        "run_id": identifier(run_id),
        "resolved_at": _now(),
        "configured_name": configured,
        "resolved_path": resolved,
    }
    atomic_bytes(path, (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return resolved


def load_claude_binary(run_id: str) -> dict[str, Any]:
    path = _record_path(run_id)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        raise ClaudeBinaryError(
            f"run {run_id!r} has no pinned claude-binary.json yet -- call "
            "resolve_claude_binary(run_id) before dispatching any claude CLI call") from None
    except ValueError:
        raise ClaudeBinaryError(f"run {run_id!r}'s claude-binary.json is not valid JSON") from None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=(
        "Resolve and pin the real claude CLI binary path for a run, from this process's own "
        "PATH. Run this from whichever process/host will actually dispatch the run's jobs (e.g. "
        "in WSL on hal5000, not the cloud sandbox) if you want to pre-pin it ahead of the first "
        "job -- otherwise the first job resolves it itself."))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--force", action="store_true", help="re-resolve even if this run already has a pinned record")
    args = parser.parse_args()

    print(json.dumps({"resolved_path": resolve_claude_binary(args.run_id, force=args.force)}, indent=2))
