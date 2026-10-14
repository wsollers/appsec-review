"""Central Swift execution and artifact-acceptance policy.

Swift inventory is always allowed. When the typed global toggle is false, every producer excludes
Swift inputs and every consumer rejects Swift-derived material. The run-owned resolved
configuration is authoritative at acceptance boundaries so stale handoffs and indexes cannot
bypass the dispatch policy.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from pathlib import Path, PurePosixPath
from typing import Any

from appsec_review.storage import file_sha256


SWIFT_KNOWN_GAP = (
    "KNOWN_GAP: Swift execution is disabled by tools.enable_swift=false; Swift remains inventoried "
    "but no Swift-derived analysis, evidence, history, build, artifact, finding, or prioritization "
    "input is accepted"
)
SWIFT_ENABLED_GAP = (
    "KNOWN_GAP: Swift execution is enabled, but support remains bounded by available producers and "
    "platforms; CodeQL Swift requires an accepted macOS executor and Tree-sitter requires a pinned "
    "Swift grammar"
)


def is_swift_language(value: object) -> bool:
    return isinstance(value, str) and value.strip().lower() == "swift"


def is_swift_path(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    return PurePosixPath(value.replace("\\", "/")).suffix.lower() == ".swift"


def swift_enabled_from_run(run_root: Path) -> bool:
    """Read the hash-verified immutable run setting; fail closed if it is malformed."""
    configuration = Path(run_root) / "data" / "configuration"
    manifest_path = configuration / "manifest.json"
    resolved_path = configuration / "resolved.json"
    if not manifest_path.exists() and not resolved_path.exists():
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if file_sha256(resolved_path) != manifest.get("resolved_sha256"):
            raise ValueError("run-owned resolved configuration hash mismatch")
        document = json.loads(resolved_path.read_text(encoding="utf-8"))
        value = document.get("tools", {}).get("enable_swift", False)
    except (OSError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("run-owned Swift execution policy is unavailable") from exc
    if not isinstance(value, bool):
        raise ValueError("run-owned tools.enable_swift must be a Boolean")
    return value


def _explicit_swift(value: object, key: str | None = None) -> bool:
    if isinstance(value, Mapping):
        return any(_explicit_swift(item, str(name)) for name, item in value.items())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_explicit_swift(item, key) for item in value)
    name = (key or "").lower()
    if name in {"language", "source_language", "producer_language"} and is_swift_language(value):
        return True
    if name in {"path", "file", "source", "source_path", "relative_path"} and is_swift_path(value):
        return True
    return False


def reject_swift_derived(value: object, *, enabled: bool, context: str) -> None:
    """Reject explicitly typed/path-bound Swift material while the policy is disabled."""
    if not enabled and _explicit_swift(value):
        raise ValueError(f"{context} contains Swift-derived material while tools.enable_swift=false")


def contains_swift_derived(value: object) -> bool:
    return _explicit_swift(value)


def swift_coverage_cell_is_gap(payload: Mapping[str, Any]) -> bool:
    """Allow the durable Swift inventory/KNOWN_GAP row, never a positive analysis claim."""
    if payload.get("record_type") != "coverage_cell" or not is_swift_language(payload.get("language")):
        return False
    lanes = payload.get("lanes")
    if not isinstance(lanes, Mapping):
        return False
    return all(
        name == "source" or (isinstance(cell, Mapping) and cell.get("state") == "unavailable")
        for name, cell in lanes.items()
    )


def filter_swift_files(values: Sequence[Mapping[str, Any]], *, enabled: bool) -> tuple[Mapping[str, Any], ...]:
    if enabled:
        return tuple(values)
    return tuple(item for item in values if not (
        is_swift_language(item.get("language")) or is_swift_path(item.get("path"))))


def swift_inventory_count(values: Sequence[Mapping[str, Any]]) -> int:
    return sum(is_swift_language(item.get("language")) or is_swift_path(item.get("path")) for item in values)
