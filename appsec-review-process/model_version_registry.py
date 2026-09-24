#!/usr/bin/env python3
"""Model version registry (D01 construction follow-up; William, 2026-09-24): resolves each model
alias this repo's configuration names -- model-config.json's process-wide `default.model`, every
`unbuilt_job_defaults` entry's `model`, and every registry job template's own pinned `model.model`
-- to the concrete model identity the claude CLI actually answers with, once per run, and pins the
result so every persona invocation in that run reads a fixed identity instead of re-resolving a
moving alias mid-run. A `--resume` of an existing run reuses its already-pinned record; only a
fresh run queries.

Why this exists: persona_invocation.py's request schema requires a fully pinned model identity
(`provider`, `family`, `model_id`, `snapshot` with version digits, no alias word) before dispatch,
but model-config.json only ever stored CLI aliases ("claude-sonnet-5", "haiku") -- there was no
real snapshot to put in a request. William's decision: add a step that queries the provider for
the exact current version behind each family alias, store a ref to the family plus the specific
version that answered, and have repeat runs reuse the version their own run resolved (never
re-query mid-run; that is what makes an attempt's model identity stable and re-derivable later,
the way every other pin in this process is).

This module's live query ALSO settles a long-standing open question recorded in
model-config.json's own `invocation.open_questions` since 2026-09-17: the exact
`--output-format` response shape (field names for cost, duration, and -- what this module needs
-- the model that actually answered) has never been confirmed against a real call. `query_alias`
is deliberately defensive about this: it captures every raw stream-json event and the terminal
result verbatim, and only *best-effort* extracts a `model`/`model_id`/`modelId` field from them
(`_extract_identity`). Nothing is lost if today's field-name guesses are wrong; a corrected parser
can always re-read the same captured response.

**Not yet dispatched from the cloud sandbox.** This sandbox's own `claude` binary is a different,
possibly-restricted install from the real target (`review_cli.py`'s proven dispatch path was
confirmed only against the real user install on hal5000 -- see model-config.json's `_notes`), so a
live probe call belongs there, not here, the same way every other live dispatch in this project
has been proven on hal5000 first. See this module's `if __name__ == "__main__"` block for the
command to run there.

**Not yet a registered Dagster job.** William asked for "a job at the start" that does this;
this module is the callable facility that job would wrap, built and structurally tested first (the
same order every other D01 piece has followed). Registering it as a formal `job-graph.json` node
is its own, larger, flagged-not-assumed follow-up: `job-graph.json` is one of exactly three
surfaces AGENTS.md calls out for the "Full protocol" (branch + review, not the fast lane every
other D01 file so far has qualified for), and this session has not yet asked William whether that
step should happen now or stay a follow-up. Until then, callers (the request builder, run-create)
invoke `resolve_run_model_versions` directly, as an ordinary function call early in a run's life --
functionally the same "resolve once per run, pin, reuse on resume" behavior William asked for,
short of the formal job-graph registration.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from execution_state import atomic_bytes, data_path, identifier  # noqa: E402
import claude_binary_resolver as cbr  # noqa: E402
import review_cli as rc  # noqa: E402

SCHEMA_ID = "appsec-review/run-model-versions/1.0"
RECORD_FILENAME = "model-versions.json"
DEFAULT_TIMEOUT_SECONDS = 120
PROBE_PROMPT = "Reply with exactly the single word: OK"
PROBE_EFFORT = "low"


class ModelVersionError(RuntimeError):
    """Querying, writing, or reading the run's pinned model-version record failed."""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def configured_aliases() -> list[str]:
    """Every model alias this repo's own configuration currently names: model-config.json's
    process-wide default, every `unbuilt_job_defaults` entry's model, and every registry job
    template's own pinned `model.model` -- deduplicated, sorted. Not every alias here is
    necessarily used by a given run; querying a few extra is cheap and keeps the run's pinned
    record self-sufficient for whichever jobs it actually dispatches."""
    cfg = rc.load_model_config()
    aliases: set[str] = set()
    default_model = (cfg.get("default") or {}).get("model")
    if default_model:
        aliases.add(default_model)
    for entry in (cfg.get("unbuilt_job_defaults") or {}).values():
        if isinstance(entry, dict) and entry.get("model"):
            aliases.add(entry["model"])
    for path in sorted((ROOT / "registry" / "job-templates").glob("*.json")):
        template = json.loads(path.read_text(encoding="utf-8"))
        model = template.get("model")
        if isinstance(model, dict) and model.get("model"):
            aliases.add(model["model"])
    return sorted(aliases)


def _probe_argv(alias: str, binary: str) -> list[str]:
    """A minimal, cheap, tool-free call: no --add-dir (nothing to read), no allowed tools (nothing
    to run), probe-tier budget cap, low effort. This asks only "what model answers as <alias>
    today", never review work. `binary` is the caller's already-resolved, real absolute path (see
    `claude_binary_resolver.py`) -- this function never re-resolves or falls back to a bare name
    itself, so a resolution failure is never silently masked here."""
    cfg = rc.load_model_config()
    invocation = cfg.get("invocation") or {}
    argv = [binary] + list(invocation.get("fixed_flags") or [])
    argv += ["--model", alias, "--effort", PROBE_EFFORT]
    usd = (cfg.get("budget_max_usd_per_call") or {}).get("probe")
    if usd is not None:
        argv += ["--max-budget-usd", str(usd)]
    argv += ["--allowedTools", ""]
    return argv


def _extract_identity(dispatch: dict[str, Any]) -> dict[str, Any]:
    """Best-effort extraction of a model identity from one real dispatch's captured events.
    Defensive by construction, because the exact response shape is not yet confirmed (see this
    module's docstring): looks for a `model`/`model_id`/`modelId` field on every stream event
    (the init/system event most likely carries it, per Claude Code's usual stream-json shape,
    but nothing here assumes that without seeing it) and on the terminal result event. Never
    raises. `reported_model` is the first value found, in event order then key-name order;
    `extracted_from` names every field that had a value, for a human to sanity-check."""
    candidates: dict[str, str] = {}
    events = dispatch.get("events") or []
    final = dispatch.get("final_result")
    for event in (*events, final):
        if not isinstance(event, dict):
            continue
        for key in ("model", "model_id", "modelId"):
            value = event.get(key)
            if isinstance(value, str) and value and key not in candidates:
                candidates[key] = value
    reported = candidates.get("model") or candidates.get("model_id") or candidates.get("modelId")
    return {"reported_model": reported, "extracted_from": sorted(candidates)}


def query_alias(alias: str, *, binary: str, transcript_path: Path, timeout: int = DEFAULT_TIMEOUT_SECONDS,
                dispatch_fn=rc._dispatch_streaming) -> dict[str, Any]:
    """Issues one minimal probe call for `alias` (or, in a test, calls `dispatch_fn` with the same
    signature as `review_cli._dispatch_streaming` against a fake). `binary` is the caller's
    already-resolved real path (see `resolve_run_model_versions`, `claude_binary_resolver.py`).
    Returns a record with the best-effort extracted identity, plus the full raw events and
    terminal result, so a human (or a later, corrected parser) can always recover the exact model
    identity even if today's field-name guesses are wrong."""
    argv = _probe_argv(alias, binary)
    dispatch = dispatch_fn(argv, PROBE_PROMPT, timeout, transcript_path)
    identity = _extract_identity(dispatch)
    return {
        "alias": alias,
        "queried_at": _now(),
        "argv": argv,
        "identity": identity,
        "returncode": dispatch.get("returncode"),
        "timed_out": dispatch.get("timed_out"),
        "final_result": dispatch.get("final_result"),
        "events": dispatch.get("events"),
    }


def _record_path(run_id: str) -> Path:
    return data_path(run_id, RECORD_FILENAME)


def resolve_run_model_versions(run_id: str, *, aliases: list[str] | None = None, force: bool = False,
                               transcript_dir: Path | None = None,
                               dispatch_fn=rc._dispatch_streaming) -> dict[str, Any]:
    """The run-scoped entry point -- and, per William's 2026-09-24 decision, the *first job* that
    dispatches a real claude CLI call for a run, so it is also where the claude binary itself gets
    resolved and pinned (`claude_binary_resolver.resolve_claude_binary`) rather than trusting a
    hardcoded path: whatever process calls this is the process that will actually dispatch, so
    resolving here captures the right `PATH`. If the run already has a pinned `model-versions.json`
    and `force` is false, loads and returns it unchanged (a resumed run reuses exactly the versions
    its first run resolved -- William's "repeat runs would use the one their job had"). Otherwise
    queries every alias (default: `configured_aliases()`), writes the pinned record, and returns
    it. Each alias's transcript is written under `transcript_dir` (default: the record's own
    directory) as `<alias>.jsonl`, same shape as any other lane's transcript.jsonl."""
    path = _record_path(run_id)
    if path.exists() and not force:
        return load_run_model_versions(run_id)
    aliases = sorted(set(aliases)) if aliases is not None else configured_aliases()
    if not aliases:
        raise ModelVersionError("no model aliases found in model-config.json or any job template")
    binary = cbr.resolve_claude_binary(run_id, force=force)
    transcript_dir = transcript_dir or path.parent
    entries = {}
    for alias in aliases:
        entries[alias] = query_alias(alias, binary=binary, transcript_path=transcript_dir / f"{alias}.jsonl",
                                     dispatch_fn=dispatch_fn)
    record = {
        "schema": SCHEMA_ID,
        "run_id": identifier(run_id),
        "resolved_at": _now(),
        "aliases": entries,
    }
    atomic_bytes(path, (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return record


def load_run_model_versions(run_id: str) -> dict[str, Any]:
    path = _record_path(run_id)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        raise ModelVersionError(
            f"run {run_id!r} has no pinned model-versions.json yet -- call "
            "resolve_run_model_versions(run_id) before dispatching any persona invocation") from None
    except ValueError:
        raise ModelVersionError(f"run {run_id!r}'s model-versions.json is not valid JSON") from None


def model_identity_for(run_id: str, alias: str, *, provider: str = "anthropic") -> dict[str, str]:
    """The `persona-model-identity` object (`provider`, `family`, `model_id`, `snapshot`) for
    `alias` in this run's pinned record -- what the request builder drops into
    `request["model"]`. `family` is the alias itself (the independence rule's model family label);
    `model_id` and `snapshot` are both the CLI's own reported model identity, since a real query
    is not expected to distinguish the two further today. Raises if `alias` was never queried for
    this run, or if its query never yielded an identity (never fabricates a snapshot to fill the
    gap -- persona_invocation.py's model_errors() would reject a guessed alias-like value anyway,
    and a pinned value this process will hash and independence-check must be a real one)."""
    record = load_run_model_versions(run_id)
    entry = (record.get("aliases") or {}).get(alias)
    if entry is None:
        raise ModelVersionError(f"run {run_id!r} never queried model alias {alias!r}")
    reported = (entry.get("identity") or {}).get("reported_model")
    if not reported:
        raise ModelVersionError(
            f"run {run_id!r}'s query for {alias!r} did not yield a model identity (see "
            f"{alias}.jsonl and final_result in model-versions.json for what the CLI actually "
            "returned, and extend _extract_identity's candidate keys once the real shape is known)")
    return {"provider": provider, "family": alias, "model_id": reported, "snapshot": reported}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=(
        "Query the claude CLI for the concrete model identity behind one or more aliases, and "
        "pin them to a run. Run this on hal5000 against the real user claude install, not from "
        "the cloud sandbox (see this module's docstring) -- its output also settles "
        "model-config.json's long-open response-shape question."))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--alias", action="append", help="repeatable; default: every alias model-config.json/job templates name")
    parser.add_argument("--force", action="store_true", help="re-query even if this run already has a pinned record")
    args = parser.parse_args()

    result = resolve_run_model_versions(args.run_id, aliases=args.alias, force=args.force)
    print(json.dumps({alias: entry["identity"] for alias, entry in result["aliases"].items()}, indent=2))
