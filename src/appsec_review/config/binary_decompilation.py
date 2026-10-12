"""Typed ``[binary_decompilation]`` configuration for the pre-run Ghidra decompilation command."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Mapping


_SIZE = re.compile(r"([1-9][0-9]*)([mg])")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_BINARY_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_LANGUAGE = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_SPEC = re.compile(r"[A-Za-z0-9._-]{1,64}")
_LOADER = re.compile(r"[A-Za-z0-9]{1,64}")
# The JVM needs headroom beyond its heap for the native decompiler processes it spawns.
HEAP_HEADROOM_BYTES = 1024 * 1024 * 1024
# The container needs time to import and export around the analysis itself.
TIMEOUT_MARGIN_SECONDS = 300


def size_bytes(value: str) -> int:
    match = _SIZE.fullmatch(value)
    if not match:
        raise ValueError(f"size must look like 512m or 8g: {value!r}")
    return int(match.group(1)) * (1024 ** 2 if match.group(2) == "m" else 1024 ** 3)


@dataclass(frozen=True, slots=True)
class BinaryRequest:
    """One third-party binary the operator is authorized to analyze."""

    binary_id: str
    path: Path
    sha256: str
    authorization: str
    processor: str | None = None
    compiler_spec: str | None = None
    loader: str | None = None

    def __post_init__(self) -> None:
        if not _BINARY_ID.fullmatch(self.binary_id):
            raise ValueError(f"binary id must be a lowercase slug: {self.binary_id!r}")
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError(f"binary {self.binary_id} needs a lowercase SHA-256")
        if not self.authorization.strip():
            raise ValueError(f"binary {self.binary_id} needs an authorization statement")
        for value, pattern, field in ((self.processor, _LANGUAGE, "processor"),
                                      (self.compiler_spec, _SPEC, "compiler_spec"),
                                      (self.loader, _LOADER, "loader")):
            if value is not None and not pattern.fullmatch(value):
                raise ValueError(f"binary {self.binary_id} has an invalid {field}")
        if self.compiler_spec is not None and self.processor is None:
            raise ValueError(f"binary {self.binary_id} sets compiler_spec without processor")


@dataclass(frozen=True, slots=True)
class BinaryDecompilationSettings:
    tool_id: str = "tool-ghidra"
    # Container limits. These exceed the central scanner policy on purpose: this command runs
    # before a review is submitted, one binary at a time, and never inside a review worker pool.
    memory: str = "8g"
    cpus: int = 4
    pids_limit: int = 1024
    max_heap: str = "6g"
    timeout_seconds: int = 7200
    analysis_timeout_seconds: int = 3600
    decompile_timeout_seconds: int = 60
    # Input and output bounds.
    max_binary_bytes: int = 536870912
    max_functions: int = 50000
    max_function_bytes: int = 262144
    max_pcode_ops: int = 20000
    max_strings: int = 100000
    min_string_length: int = 4
    output_file_bytes: int = 2147483648
    binaries: tuple[BinaryRequest, ...] = ()

    def __post_init__(self) -> None:
        if not re.fullmatch(r"tool-[a-z0-9][a-z0-9.-]*", self.tool_id):
            raise ValueError("binary_decompilation.tool_id must name a catalog tool")
        integers = {
            "cpus": (self.cpus, 1, 64), "pids_limit": (self.pids_limit, 64, 65536),
            "timeout_seconds": (self.timeout_seconds, 60, 172800),
            "analysis_timeout_seconds": (self.analysis_timeout_seconds, 30, 172800),
            "decompile_timeout_seconds": (self.decompile_timeout_seconds, 1, 3600),
            "max_binary_bytes": (self.max_binary_bytes, 1, 8 * 1024 ** 3),
            "max_functions": (self.max_functions, 1, 5_000_000),
            "max_function_bytes": (self.max_function_bytes, 1024, 16 * 1024 ** 2),
            "max_pcode_ops": (self.max_pcode_ops, 1, 5_000_000),
            "max_strings": (self.max_strings, 1, 10_000_000),
            "min_string_length": (self.min_string_length, 1, 1024),
            "output_file_bytes": (self.output_file_bytes, 1024 ** 2, 64 * 1024 ** 3),
        }
        for field, (value, low, high) in integers.items():
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"binary_decompilation.{field} must be an integer in [{low}, {high}]")
        if size_bytes(self.max_heap) + HEAP_HEADROOM_BYTES > size_bytes(self.memory):
            raise ValueError("binary_decompilation.max_heap must leave 1g of container memory free")
        if self.analysis_timeout_seconds + TIMEOUT_MARGIN_SECONDS > self.timeout_seconds:
            raise ValueError("binary_decompilation.timeout_seconds must exceed "
                             f"analysis_timeout_seconds by {TIMEOUT_MARGIN_SECONDS}")
        identifiers = [item.binary_id for item in self.binaries]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("binary_decompilation.binaries ids must be unique")

    def binary(self, binary_id: str) -> BinaryRequest:
        for item in self.binaries:
            if item.binary_id == binary_id:
                return item
        raise KeyError(f"binary is not configured: {binary_id}")

    def semantic_view(self) -> dict[str, Any]:
        """The settings that can change an export. Capacity (memory, CPUs, PIDs) is excluded."""
        return {
            "analysis_timeout_seconds": self.analysis_timeout_seconds,
            "decompile_timeout_seconds": self.decompile_timeout_seconds,
            "max_functions": self.max_functions,
            "max_function_bytes": self.max_function_bytes,
            "max_pcode_ops": self.max_pcode_ops,
            "max_strings": self.max_strings,
            "min_string_length": self.min_string_length,
        }


_SETTING_KEYS = {
    "tool_id", "memory", "cpus", "pids_limit", "max_heap", "timeout_seconds",
    "analysis_timeout_seconds", "decompile_timeout_seconds", "max_binary_bytes", "max_functions",
    "max_function_bytes", "max_pcode_ops", "max_strings", "min_string_length", "output_file_bytes",
}
_BINARY_KEYS = {"id", "path", "sha256", "authorization", "processor", "compiler_spec", "loader"}


def _optional_text(value: Mapping[str, Any], key: str, field: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str):
        raise ValueError(f"{field}.{key} must be a string")
    return item


def parse_binary_decompilation(value: object, repository_root: Path) -> BinaryDecompilationSettings:
    """Parse the ``[binary_decompilation]`` table; an absent table yields the defaults."""
    if value is None:
        return BinaryDecompilationSettings()
    if not isinstance(value, Mapping):
        raise ValueError("[binary_decompilation] must be a table")
    unknown = set(value) - _SETTING_KEYS - {"binaries"}
    if unknown:
        raise ValueError("binary_decompilation has unknown settings: " + ", ".join(sorted(unknown)))
    binaries_value = value.get("binaries", [])
    if not isinstance(binaries_value, list):
        raise ValueError("binary_decompilation.binaries must be an array of tables")
    binaries: list[BinaryRequest] = []
    for index, item in enumerate(binaries_value):
        field = f"binary_decompilation.binaries[{index}]"
        if not isinstance(item, Mapping):
            raise ValueError(f"{field} must be a table")
        unknown_binary = set(item) - _BINARY_KEYS
        if unknown_binary:
            raise ValueError(f"{field} has unknown settings: " + ", ".join(sorted(unknown_binary)))
        for key in ("id", "path", "sha256", "authorization"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise ValueError(f"{field}.{key} must be a non-empty string")
        path = Path(item["path"])
        binaries.append(BinaryRequest(
            binary_id=item["id"],
            path=path.resolve() if path.is_absolute() else (repository_root / path).resolve(),
            sha256=item["sha256"],
            authorization=item["authorization"],
            processor=_optional_text(item, "processor", field),
            compiler_spec=_optional_text(item, "compiler_spec", field),
            loader=_optional_text(item, "loader", field),
        ))
    settings = {key: value[key] for key in _SETTING_KEYS if key in value}
    for key in ("tool_id", "memory", "max_heap"):
        if key in settings and not isinstance(settings[key], str):
            raise ValueError(f"binary_decompilation.{key} must be a string")
    return BinaryDecompilationSettings(**settings, binaries=tuple(binaries))
