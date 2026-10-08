from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


REPAIR_SCHEMA = "appsec-review/build-image-repair/1"
_PACKAGE = re.compile(
    r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?(?:=[A-Za-z0-9.+:~_-]+)?$")


def validate_repair_proposal(proposal: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if set(proposal) != {"schema", "system_packages", "reason"}:
        errors.append("repair proposal fields are invalid")
    if proposal.get("schema") != REPAIR_SCHEMA:
        errors.append("repair proposal schema is unsupported")
    packages = proposal.get("system_packages")
    if not isinstance(packages, list) or not packages or len(packages) > 64:
        errors.append("system_packages must contain between 1 and 64 packages")
    elif any(not isinstance(value, str) or len(value) > 128 or not _PACKAGE.fullmatch(value)
             for value in packages):
        errors.append("system_packages contains an invalid apt package specifier")
    elif len(set(packages)) != len(packages):
        errors.append("system_packages contains duplicates")
    reason = proposal.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason.encode("utf-8")) > 4096:
        errors.append("repair reason must be non-empty and at most 4096 bytes")
    return tuple(errors)


def apply_repair(recipe: Mapping[str, Any], proposal: Mapping[str, Any]) -> dict[str, Any]:
    errors = validate_repair_proposal(proposal)
    if errors:
        raise ValueError("; ".join(errors))
    current = sorted({str(value) for value in recipe.get("system_packages", ())})
    proposed = sorted({str(value) for value in proposal["system_packages"]})
    if proposed == current:
        raise ValueError("repair proposal repeated the current system package set")
    return {**recipe, "system_packages": proposed,
            "reason": f"{recipe.get('reason', 'accepted recipe')} Image repair: {proposal['reason']}"}
