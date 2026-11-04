"""Operator-declared capabilities of an already provisioned Unity editor image.

No license material, command arrays, environment overrides, installation, or repair
instructions belong in this configuration. Image identity is verified by the shared
build executor; editor, target, backend and module declarations are checked at runtime.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields
import hashlib
from pathlib import PurePosixPath
import re
from typing import Any

from appsec_review.storage import canonical_json


VERSION = re.compile(r"(?:20[0-9]{2}|6000)\.[0-9]+\.[0-9]+[abfp][0-9]+")
TARGETS = frozenset({
    "StandaloneLinux64", "StandaloneWindows64", "StandaloneOSX", "Android", "WebGL", "iOS", "tvOS",
})


def _relative_output(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value and len(value) <= 240 and len(path.parts) >= 2 and not path.is_absolute()
                and path.as_posix() == value and all(part not in {".", ".."} for part in path.parts)
                and re.fullmatch(r"[A-Za-z0-9_./-]+", value)
                and path.parts[0] not in {
                    "Assets", "Packages", "ProjectSettings", "Library", "Temp", "Logs", ".git",
                })


@dataclass(frozen=True, slots=True)
class UnityBuildSettings:
    enabled: bool = False
    tag: str = ""
    image_id: str = ""
    user: str = ""
    editor_version: str = ""
    editor_revision: str = ""
    editor_executable: str = ""
    target: str = ""
    architecture: str = ""
    scripting_backend: str = ""
    modules: tuple[str, ...] = ()
    license_ready: bool = False
    execute_method: str = ""
    output_path: str = ""
    timeout_seconds: int = 1800
    output_bytes: int = 1048576
    artifact_count_limit: int = 4096

    def __post_init__(self) -> None:
        for name in ("enabled", "license_ready"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"Unity {name} must be a boolean")
        for field in fields(self):
            if field.name not in {"enabled", "license_ready", "modules", "timeout_seconds",
                                  "output_bytes", "artifact_count_limit"}:
                value = getattr(self, field.name)
                if not isinstance(value, str) or "\0" in value or len(value) > 512:
                    raise ValueError(f"invalid Unity {field.name}")
        if self.tag and (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:-]*", self.tag)
                         or ":" not in self.tag.rsplit("/", 1)[-1]
                         or self.tag.endswith(":latest")):
            raise ValueError("Unity tag requires an explicit non-latest image tag without credentials")
        if self.image_id and not re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_id):
            raise ValueError("invalid Unity image_id")
        if self.user and not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", self.user):
            raise ValueError("Unity user must be numeric non-root")
        if self.editor_version and not VERSION.fullmatch(self.editor_version):
            raise ValueError("invalid Unity editor_version")
        if self.editor_revision and not re.fullmatch(r"[0-9a-f]{7,40}", self.editor_revision):
            raise ValueError("invalid Unity editor_revision")
        if self.editor_executable and (
                not re.fullmatch(r"/[A-Za-z0-9_./-]+", self.editor_executable)
                or ".." in PurePosixPath(self.editor_executable).parts
                or PurePosixPath(self.editor_executable).as_posix() != self.editor_executable):
            raise ValueError("Unity editor_executable requires a canonical absolute container path")
        if self.target and self.target not in TARGETS:
            raise ValueError("unsupported Unity target")
        if self.architecture and self.architecture not in {"x86_64", "arm64", "armv7", "wasm32"}:
            raise ValueError("unsupported Unity architecture")
        if self.scripting_backend and self.scripting_backend not in {"Mono", "IL2CPP"}:
            raise ValueError("unsupported Unity scripting_backend")
        if (not isinstance(self.modules, tuple)
                or any(not isinstance(item, str) or item not in TARGETS for item in self.modules)
                or len(self.modules) != len(set(self.modules))):
            raise ValueError("Unity modules must be unique supported target names")
        if self.execute_method and not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", self.execute_method):
            raise ValueError("Unity execute_method requires a qualified C# static method")
        if self.output_path and not _relative_output(self.output_path):
            raise ValueError("Unity output_path must be a canonical run-workspace-relative build output")
        for name, upper in (("timeout_seconds", 86400), ("output_bytes", 16777216),
                            ("artifact_count_limit", 100000)):
            if type(getattr(self, name)) is not int or not 1 <= getattr(self, name) <= upper:
                raise ValueError(f"invalid Unity {name} bound")

    def view(self) -> dict[str, Any]:
        value = asdict(self)
        value["modules"] = sorted(self.modules)
        return value

    @property
    def identity(self) -> str:
        return hashlib.sha256(canonical_json({
            "schema": "appsec-review/unity-build-settings/1", **self.view(),
        })).hexdigest()


def parse_unity_build_settings(value: Mapping[str, Any] | None) -> UnityBuildSettings:
    if value is None:
        return UnityBuildSettings()
    if not isinstance(value, Mapping) or set(value) - {field.name for field in fields(UnityBuildSettings)}:
        raise ValueError("unknown Unity build settings (credentials and arbitrary commands are prohibited)")
    values = dict(value)
    if "modules" in values:
        if not isinstance(values["modules"], (list, tuple)) or any(
                not isinstance(item, str) for item in values["modules"]):
            raise ValueError("Unity modules must be an array of target names")
        values["modules"] = tuple(sorted(values["modules"]))
    return UnityBuildSettings(**values)
