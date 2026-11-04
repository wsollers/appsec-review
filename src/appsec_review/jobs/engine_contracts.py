"""Engine identity augments language families; it never establishes execution."""

from __future__ import annotations

from typing import Any, NotRequired, TypedDict


UNITY_BUILD_SYSTEM = "unity"
UNITY_LANGUAGE_FAMILY = "dotnet"
ENGINE_METADATA_SCHEMA = "appsec-review/engine-metadata/1"
UNITY_FINGERPRINT_SCHEMA = "appsec-review/unity-configuration-fingerprint/1"


class EngineIdentity(TypedDict):
    kind: str
    declared_version: str | None
    declared_revision: str | None


class UnityProject(TypedDict):
    root: str
    engine: EngineIdentity
    markers: list[dict[str, Any]]
    descriptor_facts: dict[str, Any]
    inventory: dict[str, Any]
    gaps: list[str]
    configuration_fingerprint: NotRequired[dict[str, Any]]
