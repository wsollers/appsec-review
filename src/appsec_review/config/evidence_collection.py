"""Typed ``[jobs.job_evidence_collection.settings]``.

osv-scanner 1.9.2 in ``--experimental-offline`` mode loads every needed ecosystem's whole
``all.zip`` into memory (the npm database alone is 368 MB of JSON), so it runs under its own
container memory limit instead of the uniform scanner policy, and one invocation is launched per
target project with a bounded number of lockfiles.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Any


JOB_ID = "job_evidence_collection"
_PREFIX = f"jobs.{JOB_ID}.settings"
SETTING_KEYS = frozenset({"tool_retries", "osv_memory", "osv_max_lockfiles_per_invocation"})
_MEMORY = re.compile(r"([1-9][0-9]*)([mg])")
# Below 512m osv-scanner cannot hold even a small ecosystem database; above 64g is a typo.
MEMORY_RANGE_BYTES = (512 * 1024 ** 2, 64 * 1024 ** 3)
TOOL_RETRIES_RANGE = (0, 3)
LOCKFILES_PER_INVOCATION_RANGE = (1, 500)


def memory_limit(value: object, field: str) -> str:
    """Validate a container memory limit written as ``<n>m`` or ``<n>g`` within the sane range."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string such as \"3g\"")
    match = _MEMORY.fullmatch(value)
    if not match:
        raise ValueError(f"{field} must look like 512m or 3g: {value!r}")
    size = int(match.group(1)) * (1024 ** 2 if match.group(2) == "m" else 1024 ** 3)
    low, high = MEMORY_RANGE_BYTES
    if not low <= size <= high:
        raise ValueError(f"{field} must be between 512m and 64g")
    return value


def _integer(value: object, field: str, bounds: tuple[int, int]) -> int:
    if type(value) is not int or not bounds[0] <= value <= bounds[1]:
        raise ValueError(f"{field} must be an integer in [{bounds[0]}, {bounds[1]}]")
    return value


@dataclass(frozen=True, slots=True)
class EvidenceCollectionSettings:
    tool_retries: int = 1
    osv_memory: str = "3g"
    osv_max_lockfiles_per_invocation: int = 50

    def __post_init__(self) -> None:
        _integer(self.tool_retries, f"{_PREFIX}.tool_retries", TOOL_RETRIES_RANGE)
        memory_limit(self.osv_memory, f"{_PREFIX}.osv_memory")
        _integer(self.osv_max_lockfiles_per_invocation, f"{_PREFIX}.osv_max_lockfiles_per_invocation",
                 LOCKFILES_PER_INVOCATION_RANGE)


def parse_evidence_collection_settings(settings: Mapping[str, Any]) -> EvidenceCollectionSettings:
    unknown = set(settings) - SETTING_KEYS
    if unknown:
        raise ValueError(f"{_PREFIX} has unknown settings: " + ", ".join(sorted(unknown)))
    return EvidenceCollectionSettings(**{key: settings[key] for key in SETTING_KEYS if key in settings})
