"""Frozen build intent, separate from observed target facts and execution proof."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
from types import MappingProxyType
from typing import Any

from appsec_review.storage import canonical_json

SCHEMA = "appsec-review/build-selection-policy/1"
AXES = ("os", "isa", "abi", "sdk", "deployment", "device_kind", "hardware_generation")
_SELECTORS = frozenset({"build_unit_id", "build_system", "declared_platform", "root"})
_ISA = {
    "x86_64": "x86_64", "amd64": "x86_64", "x64": "x86_64",
    "arm64": "arm64", "aarch64": "arm64", "arm64-v8a": "arm64",
    "x86": "x86", "i386": "x86", "i486": "x86", "i586": "x86", "i686": "x86",
    "arm": "armv7", "arm32": "armv7", "armv7": "armv7", "armv7a": "armv7",
    "armeabi-v7a": "armv7", "wasm32": "wasm32",
}
THIRTY_TWO_BIT_ISAS = frozenset({"x86", "armv7", "wasm32"})
DEFAULT_ALLOWED_32BIT_ISAS = ("wasm32",)


@dataclass(frozen=True)
class BuildSelectionPolicy:
    identity: str
    rules: tuple[Mapping[str, Any], ...]
    allowed_32bit_isas: tuple[str, ...] = DEFAULT_ALLOWED_32BIT_ISAS

    def view(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "policy_id": self.identity,
                "ambiguity_policy": "block",
                "allowed_32bit_isas": list(self.allowed_32bit_isas), "rules": [
                    {"selectors": dict(rule["selectors"]), "axes": dict(rule["axes"]),
                     "provenance": rule["provenance"]} for rule in self.rules]}

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.view())).hexdigest()

    def forbids_isa(self, isa: str | None) -> bool:
        return isa in THIRTY_TWO_BIT_ISAS and isa not in self.allowed_32bit_isas

    def select(self, unit: Mapping[str, Any]) -> dict[str, Any]:
        matches = []
        for rule in self.rules:
            selectors = rule["selectors"]
            if all(unit.get(key) == value for key, value in selectors.items()):
                specificity = (int("build_unit_id" in selectors),
                               int("declared_platform" in selectors),
                               int("root" in selectors), len(selectors))
                matches.append((specificity, rule))
        axes = dict.fromkeys(AXES)
        reasons = []
        if matches:
            best = max(value[0] for value in matches)
            for axis in AXES:
                values = {rule["axes"][axis] for score, rule in matches
                          if score == best and axis in rule["axes"]}
                if len(values) > 1:
                    reasons.append(f"selection_ambiguous:{axis}")
                elif values:
                    axes[axis] = next(iter(values))
        else:
            reasons.append("selection_unbound")
        if self.forbids_isa(axes["isa"]):
            reasons.append("32bit_selection_forbidden")
        value = {"build_unit_id": unit["build_unit_id"], "policy_sha256": self.sha256,
                 "required_axes": axes, "reasons": sorted(reasons),
                 "status": "ambiguous" if reasons else "selected"}
        value["selection_id"] = hashlib.sha256(canonical_json(value)).hexdigest()
        return value


def parse_build_selection(value: object = None) -> BuildSelectionPolicy:
    if value is None:
        value = {"schema": SCHEMA, "policy_id": "confirmed-x64/1", "ambiguity_policy": "block",
                 "rules": [{"selectors": {"build_system": system},
                            "axes": {"os": platform, "isa": "x86_64"},
                            "provenance": "confirmed-user-intent"}
                           for platform, systems in (
                               ("windows", ("msbuild", "vcbuild")),
                               ("linux", ("make", "autotools", "cmake")))
                           for system in systems]}
    required = {"schema", "policy_id", "rules", "ambiguity_policy"}
    if (not isinstance(value, Mapping)
            or not required <= set(value) <= required | {"allowed_32bit_isas"}
            or value["schema"] != SCHEMA or value["ambiguity_policy"] != "block"
            or not isinstance(value["policy_id"], str) or not value["policy_id"].strip()
            or not isinstance(value["rules"], list) or len(value["rules"]) > 1024):
        raise ValueError("unsupported build selection policy")
    allowed = value.get("allowed_32bit_isas", list(DEFAULT_ALLOWED_32BIT_ISAS))
    if (not isinstance(allowed, list)
            or any(not isinstance(item, str) or item.lower() not in _ISA
                   or _ISA[item.lower()] not in THIRTY_TWO_BIT_ISAS for item in allowed)):
        raise ValueError("allowed_32bit_isas must list recognized 32-bit ISAs")
    allowed = tuple(sorted({_ISA[item.lower()] for item in allowed}))
    rules = []
    for rule in value["rules"]:
        if (not isinstance(rule, Mapping) or set(rule) != {"selectors", "axes", "provenance"}
                or not isinstance(rule["selectors"], Mapping)
                or not rule["selectors"] or set(rule["selectors"]) - _SELECTORS
                or not isinstance(rule["axes"], Mapping) or set(rule["axes"]) - set(AXES)
                or any(not isinstance(item, str) or not item.strip()
                       for item in (*rule["selectors"].values(), *rule["axes"].values()))
                or not isinstance(rule["provenance"], str) or not rule["provenance"].strip()):
            raise ValueError("invalid build selection rule")
        axes = dict(rule["axes"])
        if "isa" in axes:
            if axes["isa"].lower() not in _ISA:
                raise ValueError("unsupported build selection ISA")
            axes["isa"] = _ISA[axes["isa"].lower()]
        rules.append(MappingProxyType({
            "selectors": MappingProxyType(dict(rule["selectors"])),
            "axes": MappingProxyType(axes), "provenance": rule["provenance"]}))
    return BuildSelectionPolicy(value["policy_id"], tuple(rules), allowed)
