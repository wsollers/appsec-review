"""Delivery policy for accepted producer records, never target-declared authority.

Callers must verify the producing handoff before using these helpers. Origin and
directory names do not establish delivery or supplied-platform ownership.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from appsec_review.config.assurance import SCOPE_VERSION, ScopeRole


POLICY_IDENTITY = "appsec-review/delivery-propagation/2"
SCOPE_FIELDS = ("scope_version", "scope_role", "delivery_status", "artifact_origin",
                "analysis_reason", "analysis_lane", "delivery_evidence")
_EVIDENCE = frozenset({
    "compile-database", "llvm-bitcode", "clang-ast", "debug-information",
    "link-map", "object", "test-coverage", "execution-profile", "source-map",
    "native-symbols", "package-integrity",
})
_BUILD_CHAIN = frozenset({"package-metadata", "resolved-dependency-metadata"})
_SUPPLY_CHAIN_CAPABILITIES = frozenset({"inventory", "packages", "syft", "grype", "osv"})
# Production dependencies run with the target, so their machine code also gets blint's binary
# review. Build-only dependencies do not; blint's format gate still decides tool support.
_RUNTIME_NATIVE_KINDS = frozenset({"executable", "shared-library", "native-addon", "native-extension"})
_REASONS = {
    ScopeRole.TARGET_SOURCE: ("target-source-review", "target"),
    ScopeRole.DELIVERABLE: ("accepted-delivery-fact", "target"),
    ScopeRole.SHIPPED_DEPENDENCY: ("accepted-runtime-dependency-fact", "target"),
    ScopeRole.RUNTIME_DEPENDENCY: ("accepted-runtime-dependency-review", "supply_chain"),
    ScopeRole.BUILD_CHAIN: ("target-build-chain-review", "supply_chain"),
    ScopeRole.BUILD_DEPENDENCY: ("accepted-build-dependency-review", "supply_chain"),
    ScopeRole.PLATFORM: ("supplied-platform-excluded", "excluded"),
    ScopeRole.EVIDENCE: ("build-provenance-inventory", "evidence"),
    ScopeRole.UNKNOWN: ("delivery-unknown-candidate-review", "target"),
}


def scope_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize accepted scope, keeping provenance separate from delivery."""
    if row.get("scope_version", SCOPE_VERSION) != SCOPE_VERSION:
        raise ValueError("unsupported delivery scope version")
    default = (ScopeRole.EVIDENCE if row.get("kind") in _EVIDENCE else
               ScopeRole.BUILD_CHAIN if row.get("kind") in _BUILD_CHAIN else ScopeRole.UNKNOWN)
    role = ScopeRole(row.get("scope_role", default.value))
    reason, lane = _REASONS[role]
    result = {
        "scope_version": SCOPE_VERSION, "scope_role": role.value,
        "delivery_status": ("delivered" if role in {ScopeRole.DELIVERABLE, ScopeRole.SHIPPED_DEPENDENCY}
                            else "unknown" if role in {ScopeRole.UNKNOWN, ScopeRole.TARGET_SOURCE}
                            else "not_established"),
        "artifact_origin": row.get("artifact_origin", "accepted-producer"),
        "analysis_reason": reason, "analysis_lane": lane,
    }
    if "delivery_evidence" in row:
        result["delivery_evidence"] = row["delivery_evidence"]
    return result


def delivery_gap(row: Mapping[str, Any]) -> str | None:
    if scope_fields(row)["scope_role"] == ScopeRole.UNKNOWN.value:
        path = row.get("workspace_path") or row.get("target_relative_path") or row.get("path", "")
        return f"{path}: delivery status is unknown (delivery_fact_unavailable)"
    return None


def apply_scope(rows: Sequence[dict[str, Any]]) -> list[str]:
    gaps = []
    for row in rows:
        row.update(scope_fields(row))
        if gap := delivery_gap(row):
            gaps.append(gap)
    return gaps


def analysis_scope(row: Mapping[str, Any], capability: str) -> tuple[bool, str]:
    """Scope gate precedes payload access; format gates still decide tool support."""
    fields = scope_fields(row)
    lane = fields["analysis_lane"]
    allowed = (lane == "target" or
               lane == "supply_chain" and capability in _SUPPLY_CHAIN_CAPABILITIES or
               lane == "supply_chain" and capability == "blint" and
               fields["scope_role"] == ScopeRole.RUNTIME_DEPENDENCY.value and
               row.get("kind") in _RUNTIME_NATIVE_KINDS or
               lane == "evidence" and capability == "inventory")
    return allowed, fields["analysis_reason"]


def source_in_scope(row: Mapping[str, Any]) -> bool:
    return scope_fields(row)["analysis_lane"] in {"target", "supply_chain"}
