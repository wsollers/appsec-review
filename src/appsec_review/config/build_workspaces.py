"""Disposable build workspace retention; this policy is not a build input identity."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class BuildWorkspacePolicy:
    """Keep the newest N terminal workspaces, plus all held/active workspaces.

    Zero disables automatic deletion, rather than deleting every terminal workspace.
    Durable input snapshots, accepted products and receipts are never swept.
    """

    build_workspace_retention_runs: int = 3

    def __post_init__(self) -> None:
        value = self.build_workspace_retention_runs
        if type(value) is not int or not 0 <= value <= 10000:
            raise ValueError("build_workspace_retention_runs must be an integer in [0, 10000]")

    def view(self) -> dict[str, int]:
        return {"build_workspace_retention_runs": self.build_workspace_retention_runs}


def parse_build_workspaces(value: Any) -> BuildWorkspacePolicy:
    """Parse the central ``[build_workspaces]`` table; the loader owns its wiring."""
    if value is None:
        return BuildWorkspacePolicy()
    if not isinstance(value, Mapping):
        raise ValueError("[build_workspaces] must be a table")
    unknown = set(value) - {"build_workspace_retention_runs"}
    if unknown:
        raise ValueError(f"build_workspaces has unknown keys: {', '.join(sorted(unknown))}")
    return BuildWorkspacePolicy(value.get("build_workspace_retention_runs", 3))
