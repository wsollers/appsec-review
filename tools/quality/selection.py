from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import Config, GateError, relative_path
from .process import run


def parse_changes(output: str) -> tuple[str, ...]:
    fields = output.split("\0")
    if fields.pop() != "":
        raise GateError("git-output", "name-status output is not NUL-terminated")
    paths: set[str] = set()
    index = 0
    while index < len(fields):
        status = fields[index]
        index += 1
        if not status or status[0] not in "ACDMRTUXB":
            raise GateError("git-output", f"unknown change status: {status!r}")
        count = 2 if status[0] in "RC" else 1
        if status[0] in "UXB" or index + count > len(fields):
            raise GateError("git-output", f"unresolved or malformed change: {status}")
        for value in fields[index:index + count]:
            paths.add(relative_path(value))
        index += count
    return tuple(sorted(paths))


def changed_paths(root: Path, base: str, timeout: int) -> tuple[str, ...]:
    revision = run(
        ["git", "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}"], root, timeout,
    ).stdout.strip()
    changed = run(
        ["git", "diff", "--name-status", "-z", "--find-renames", revision, "--"], root, timeout,
    ).stdout
    untracked = run(["git", "ls-files", "--others", "--exclude-standard", "-z"], root, timeout).stdout
    return tuple(sorted(set(parse_changes(changed)) | {relative_path(p) for p in untracked.split("\0") if p}))


@dataclass(frozen=True)
class Selection:
    tests: tuple[str, ...]
    reasons: tuple[str, ...]


def select_tests(config: Config, changes: tuple[str, ...], *, full: bool = False) -> Selection:
    reasons: list[str] = []
    broader = full
    if full:
        reasons.append("explicit full bounded contract set (not the full repository suite)")
    for path in changes:
        relative_path(path)
        if path in config.shared_paths:
            broader = True
            reasons.append(f"shared contract/configuration: {path}")
        elif path.startswith(config.quality_prefixes):
            reasons.append(f"quality infrastructure: {path}")
        elif path.startswith(config.documentation_prefixes) or path == "README.md":
            reasons.append(f"documentation only: {path}")
        else:
            broader = True
            reasons.append(f"unmapped path: {path}; bounded contract fallback, job coverage not claimed")
    tests = config.unit_tests + (config.contract_tests if broader else ())
    if not tests:
        raise GateError("no-tests", "selection must contain offline units")
    return Selection(tests, tuple(reasons or ["no changed paths; quality sentinels still run"]))
