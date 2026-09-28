"""Every size, count, time and resource value the pipeline uses, in config instead of code.

Two homes:

- per job: a ``tunables`` block in ``registry/job-templates/<job>.json``;
- cross-cutting (shared validation, redaction, lookup tools, container bounds, model invocation):
  ``registry/tunables.json``.

Each entry is ``{"value": ..., "unit": ..., "kind": ..., "description": ..., "scale": ...}``:

- ``unit``: bytes, count, seconds, lines, chars, millicpu, days;
- ``kind``: ``resource`` (container/CPU/memory/time given to a job), ``window`` (how much one call
  returns; the caller narrows its query, so it is not a data cap), ``safety`` (a bound that protects
  memory or the host), ``logged`` (a former cap: exceeding it is recorded by size_log, not refused);
- ``scale``: what the value has to grow with, and what we measured.

``value(job, name)`` and ``shared(name)`` raise if the entry is missing, so code and config cannot
drift silently. ``python3 -B tunables.py doc`` writes docs/processes/tunables.md; ``check`` fails when
that doc is stale or code asks for a name config does not define.
"""
from __future__ import annotations

import json
import re
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
TEMPLATES = ROOT / "registry" / "job-templates"
SHARED = ROOT / "registry" / "tunables.json"
DOC = ROOT.parent / "docs" / "processes" / "tunables.md"
UNITS = {"bytes", "count", "seconds", "lines", "chars", "millicpu", "days", "id"}
KINDS = {"resource", "window", "safety", "logged"}


class TunableMissing(KeyError):
    pass


@lru_cache(maxsize=None)
def _shared() -> dict[str, Any]:
    return json.loads(SHARED.read_text(encoding="utf-8"))["tunables"]


@lru_cache(maxsize=None)
def _job(job: str) -> dict[str, Any]:
    path = TEMPLATES / f"{job}.json"
    return json.loads(path.read_text(encoding="utf-8")).get("tunables", {})


def shared(name: str) -> Any:
    try:
        return _shared()[name]["value"]
    except KeyError:
        raise TunableMissing(f"registry/tunables.json defines no tunable {name!r}") from None


def value(job: str, name: str) -> Any:
    try:
        return _job(job)[name]["value"]
    except KeyError:
        raise TunableMissing(f"registry/job-templates/{job}.json defines no tunable {name!r}") from None


def container_limits(job: str, prefix: str = "container") -> dict[str, int]:
    """The B13 limits block for a job, from ``<prefix>_<limit>`` tunables."""
    names = ("timeout_seconds", "memory_bytes", "cpu_millis", "pids", "tmpfs_bytes",
             "stdout_limit_bytes", "stderr_limit_bytes")
    return {name: value(job, f"{prefix}_{name}") for name in names}


def container_tunables(timeout, memory, cpu, pids, tmpfs, stdout, stderr, *, what: str, prefix: str = "container") -> dict:
    """Helper for writing a job template: the seven container limit entries."""
    rows = [("timeout_seconds", timeout, "seconds", "Wall-clock limit for the container"),
            ("memory_bytes", memory, "bytes", "Memory limit for the container"),
            ("cpu_millis", cpu, "millicpu", "CPU quota (1000 = one core)"),
            ("pids", pids, "count", "Process/thread limit"),
            ("tmpfs_bytes", tmpfs, "bytes", "Size of the in-memory /tmp"),
            ("stdout_limit_bytes", stdout, "bytes", "Captured stdout; beyond this the log is truncated"),
            ("stderr_limit_bytes", stderr, "bytes", "Captured stderr; beyond this the log is truncated")]
    return {f"{prefix}_{name}": {"value": v, "unit": unit, "kind": "resource",
                                 "description": f"{text} ({what}).",
                                 "scale": "Grows with target size; see docs/scale-audit-unreal-engine.md section C."}
            for name, v, unit, text in rows}


# ---- documentation and consistency check ----------------------------------------------------------

def _fmt(entry: dict) -> str:
    v, unit = entry["value"], entry.get("unit", "")
    if unit == "bytes" and isinstance(v, int) and v >= 1024:
        for size, suffix in ((1024 ** 3, "GiB"), (1024 ** 2, "MiB"), (1024, "KiB")):
            if v % size == 0 or v >= size * 10:
                return f"{v / size:g} {suffix}"
    if unit == "seconds" and isinstance(v, int) and v >= 60 and v % 60 == 0:
        return f"{v} s ({v // 60} min)"
    return f"{v} {unit}".strip()


def _errors_for(entries: dict, where: str) -> list[str]:
    errors = []
    for name, entry in entries.items():
        if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
            errors.append(f"{where}: tunable name {name!r} is not snake_case")
        if not isinstance(entry, dict) or "value" not in entry:
            errors.append(f"{where}: {name} has no value"); continue
        if entry.get("unit") not in UNITS:
            errors.append(f"{where}: {name} unit {entry.get('unit')!r} not in {sorted(UNITS)}")
        if entry.get("kind") not in KINDS:
            errors.append(f"{where}: {name} kind {entry.get('kind')!r} not in {sorted(KINDS)}")
        if not str(entry.get("description", "")).strip():
            errors.append(f"{where}: {name} has no description")
    return errors


def render() -> str:
    lines = ["# Tunables", "",
             "Generated by `python3 -B appsec-review-process/tunables.py doc`; do not edit by hand. "
             "`tunables.py check` fails when this file is stale.", "",
             "Every size, count, time and resource value the pipeline uses. Per-job values live in a "
             "`tunables` block in `appsec-review-process/registry/job-templates/<job>.json`; shared ones in "
             "`appsec-review-process/registry/tunables.json`. A change applies the next time a job executes; "
             "a job whose inputs did not change is reused, so force that job or start a fresh run to "
             "apply it to a run in progress.", "",
             "Kinds: **resource** = what a job's container gets; **window** = how much one call returns "
             "(the caller narrows its query; not a data cap); **safety** = protects memory or the host; "
             "**logged** = a former cap, now only recorded by `size_log` (see `orchestrator/size-report.py`). "
             "Scale notes point at [the scale audit](../scale-audit-unreal-engine.md).", ""]

    def table(entries):
        out = ["| Tunable | Value | Kind | What it does | Scale |", "|---|---|---|---|---|"]
        for name in sorted(entries):
            e = entries[name]
            out.append(f"| `{name}` | {_fmt(e)} | {e.get('kind', '')} | {e.get('description', '')} | {e.get('scale', '')} |")
        return out

    lines += ["## Shared (`registry/tunables.json`)", ""] + table(_shared()) + [""]
    lines += ["## Per job", ""]
    for path in sorted(TEMPLATES.glob("*.json")):
        entries = json.loads(path.read_text(encoding="utf-8")).get("tunables")
        if entries:
            lines += [f"### `{path.stem}`", ""] + table(entries) + [""]
    return "\n".join(lines).rstrip() + "\n"


_CALL = re.compile(r"""tunables\.(value|container_limits)\(\s*['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?|tunables\.shared\(\s*['"]([^'"]+)['"]""")


def check() -> list[str]:
    errors = _errors_for(_shared(), "registry/tunables.json")
    for path in sorted(TEMPLATES.glob("*.json")):
        errors += _errors_for(json.loads(path.read_text(encoding="utf-8")).get("tunables", {}), path.name)
    for source in sorted(ROOT.glob("*.py")):
        text = source.read_text(encoding="utf-8")
        for match in _CALL.finditer(text):
            kind, job, name, shared_name = match.groups()
            try:
                if shared_name:
                    shared(shared_name)
                elif kind == "container_limits":
                    container_limits(job, name or "container")
                elif name is not None:          # value(job, <variable>) is checked at run time
                    value(job, name)
            except (TunableMissing, FileNotFoundError) as exc:
                errors.append(f"{source.name}: {exc}")
    if not DOC.is_file() or DOC.read_text(encoding="utf-8") != render():
        errors.append("docs/processes/tunables.md is stale: run python3 -B appsec-review-process/tunables.py doc")
    return errors


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "check"
    if command == "doc":
        DOC.write_text(render(), encoding="utf-8"); print(DOC)
    elif command == "check":
        problems = check()
        print("\n".join(problems) if problems else "tunables: ok")
        sys.exit(1 if problems else 0)
    else:
        sys.exit("usage: tunables.py [doc|check]")
