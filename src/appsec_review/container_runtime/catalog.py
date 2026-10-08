from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import tomllib
from types import MappingProxyType
from typing import Any, Mapping


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class ToolImage:
    tool_id: str
    name: str
    version: str
    tag: str
    executable: str
    user: str
    network: str
    memory: str
    cpus: str
    pids_limit: int
    timeout_seconds: int
    output_bytes: int
    expected_image_id: str | None
    manifest_path: Path
    metadata: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.tool_id.startswith("tool-"):
            raise ValueError(f"not a tool image id: {self.tool_id}")
        if not self.executable.startswith("/"):
            raise ValueError(f"tool executable must be absolute: {self.tool_id}")
        if self.network != "none":
            raise ValueError(f"static tool requests runtime network: {self.tool_id}")
        if not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", self.user):
            raise ValueError(f"tool user must be numeric non-root: {self.tool_id}")
        if self.expected_image_id is not None and not _DIGEST.fullmatch(self.expected_image_id):
            raise ValueError(f"invalid expected image id: {self.tool_id}")
        if min(self.pids_limit, self.timeout_seconds, self.output_bytes) < 1:
            raise ValueError(f"tool limits must be positive: {self.tool_id}")


@dataclass(frozen=True, slots=True)
class ContainerCatalog:
    source: Path
    runtime_policy: Path
    policy: Mapping[str, Any]
    tools: Mapping[str, ToolImage]

    def tool(self, tool_id: str) -> ToolImage:
        try:
            return self.tools[tool_id]
        except KeyError as exc:
            raise KeyError(f"enabled catalog tool is unavailable: {tool_id}") from exc


def load_catalog(repository_root: Path, path: Path | None = None) -> ContainerCatalog:
    root = repository_root.resolve()
    source = (path or root / "containers" / "catalog.toml").resolve(strict=True)
    document = tomllib.loads(source.read_text(encoding="utf-8"))
    if document.get("schema") != "appsec-review/container-catalog/1":
        raise ValueError("unsupported container catalog schema")
    policy = (root / str(document["runtime_policy"])).resolve(strict=True)
    policy_value = tomllib.loads(policy.read_text(encoding="utf-8"))
    if policy_value.get("schema") != "appsec-review/container-runtime-policy/1":
        raise ValueError("unsupported container runtime policy schema")
    required_policy = {
        "network": "none", "read_only": True, "target_mount": "read-only",
        "scratch_mount": "read-write", "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges"],
    }
    if any(policy_value.get(key) != value for key, value in required_policy.items()):
        raise ValueError("container runtime policy weakens the static-scan baseline")
    tools: dict[str, ToolImage] = {}
    for image in document.get("images", []):
        if image.get("state") != "enabled" or image.get("kind") != "tool":
            continue
        tool_id = str(image["id"])
        manifest_path = (root / str(image["tool_manifest"])).resolve(strict=True)
        if root not in manifest_path.parents:
            raise ValueError(f"tool manifest escapes repository: {tool_id}")
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema") != "appsec-review/tool/1" or manifest.get("id") != tool_id:
            raise ValueError(f"tool manifest identity mismatch: {tool_id}")
        if str(manifest.get("version")) != str(image.get("version")):
            raise ValueError(f"tool version mismatch: {tool_id}")
        for key, manifest_key in (
            ("network", "network"), ("user", "user"), ("memory", "memory"),
            ("cpus", "cpus"), ("pids_limit", "pids_limit"),
            ("timeout_seconds", "timeout_seconds"), ("output_bytes", "output_bytes"),
        ):
            if manifest.get(manifest_key) != policy_value.get(key):
                raise ValueError(f"{tool_id} does not match central runtime policy: {key}")
        tools[tool_id] = ToolImage(
            tool_id=tool_id,
            name=str(manifest["name"]),
            version=str(image["version"]),
            tag=str(image["tag"]),
            executable=str(manifest["executable"]),
            user=str(manifest["user"]),
            network=str(manifest["network"]),
            memory=str(manifest["memory"]),
            cpus=str(manifest["cpus"]),
            pids_limit=int(manifest["pids_limit"]),
            timeout_seconds=int(manifest["timeout_seconds"]),
            output_bytes=int(manifest["output_bytes"]),
            expected_image_id=image.get("image_id"),
            manifest_path=manifest_path,
            metadata=MappingProxyType(dict(manifest)),
        )
    return ContainerCatalog(source, policy, MappingProxyType(dict(policy_value)), MappingProxyType(tools))
