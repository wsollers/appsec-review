"""Every hash-pinned Python requirement of a tool image must be satisfiable from its asset lock.

Tool images install wheels offline with ``--no-index --require-hashes`` from the files the asset
lock fetches. A requirements bump that is not mirrored in the lock (for example a dependency bot
updating only ``requirements.txt``) breaks the image build, so the two must agree on every wheel.
"""

from __future__ import annotations

import json
from pathlib import Path
import re

import pytest


TOOLS = Path(__file__).parents[1] / "containers" / "tools"
REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")
HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirements(path: Path) -> dict[str, tuple[str, set[str]]]:
    pinned: dict[str, tuple[str, set[str]]] = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        match = REQUIREMENT.match(line.strip())
        if match:
            current = _normalize(match.group(1))
            pinned[current] = (match.group(2), set())
        if current is not None:
            pinned[current][1].update(HASH.findall(line))
    return pinned


def _locked_wheels(lock: dict) -> dict[str, list[tuple[str, str]]]:
    wheels: dict[str, list[tuple[str, str]]] = {}
    for artifact in lock.get("artifacts") or ():
        name = str(artifact.get("name", ""))
        if name.endswith(".whl"):
            distribution, version = name.split("-")[:2]
            wheels.setdefault(_normalize(distribution), []).append((version, str(artifact.get("sha256"))))
    return wheels


@pytest.mark.parametrize("requirements", sorted(TOOLS.glob("*/requirements.txt")),
                         ids=lambda path: path.parent.name)
def test_locked_wheels_satisfy_hash_pinned_requirements(requirements: Path) -> None:
    lock = json.loads((requirements.parent / "assets.lock.json").read_text(encoding="utf-8"))
    wheels = _locked_wheels(lock)
    if not wheels:
        pytest.skip("this image does not install requirements from locked wheels")
    mismatches = []
    for name, (version, hashes) in sorted(_requirements(requirements).items()):
        if name not in wheels:
            continue
        locked = wheels[name]
        if not any(lock_version == version and digest in hashes for lock_version, digest in locked):
            mismatches.append(f"{name}=={version} (lock has {', '.join(v for v, _ in locked)})")
    assert not mismatches, "requirements.txt and assets.lock.json disagree: " + "; ".join(mismatches)
