"""Versioned identities and records shared by all retrieval producers.

The values in this module are data contracts.  They deliberately do not trust a
producer's filesystem path, display name, or native identifier as an identity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any, Mapping


IDENTITY_SCHEMA = "appsec-review/logical-identity/1"
LOCATION_SCHEMA = "appsec-review/source-location/1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LOGICAL_ID = re.compile(r"^asr:([a-z][a-z0-9_]*):([0-9a-f]{64})$")


class EntityKind(StrEnum):
    SOURCE_FILE = "source_file"
    SOURCE_SPAN = "source_span"
    SYMBOL = "symbol"
    COMPONENT = "component"
    PROJECT = "project"
    BUILD_ACTION = "build_action"
    COMPILE_UNIT = "compile_unit"
    OBJECT_FILE = "object_file"
    LIBRARY = "library"
    EXECUTABLE = "executable"
    BUILD_ARTIFACT = "build_artifact"
    PACKAGE = "package"
    ARCHIVE_MEMBER = "archive_member"
    BYTECODE_MODULE = "bytecode_module"
    MANAGED_ASSEMBLY = "managed_assembly"
    WASM_MODULE = "wasm_module"
    AST_NODE = "ast_node"
    IR_ENTITY = "ir_entity"
    TOOL_OBSERVATION = "tool_observation"
    EVIDENCE_ARTIFACT = "evidence_artifact"
    FINDING_PACKAGE = "finding_package"
    INTERFACE_OPERATION = "interface_operation"


class RelationKind(StrEnum):
    DECLARES = "DECLARES"
    DEFINES = "DEFINES"
    REFERENCES = "REFERENCES"
    CALLS = "CALLS"
    CONTAINS = "CONTAINS"
    GENERATED_FROM = "GENERATED_FROM"
    COMPILES_TO = "COMPILES_TO"
    LINKS_INTO = "LINKS_INTO"
    DEPENDS_ON = "DEPENDS_ON"
    OBSERVED_AT = "OBSERVED_AT"
    DERIVED_FROM = "DERIVED_FROM"
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def normalize_relative_path(value: str) -> str:
    """Return a canonical target-relative POSIX path, rejecting traversal and absolutes."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("relative path is required")
    raw = value.replace("\\", "/")
    if raw.startswith("/") or re.match(r"^[A-Za-z]:", raw):
        raise ValueError("absolute paths are not allowed")
    path = PurePosixPath(raw)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("path traversal or non-canonical path is not allowed")
    return path.as_posix()


@dataclass(frozen=True, slots=True)
class LogicalIdentity:
    kind: EntityKind
    value: str
    schema: str = IDENTITY_SCHEMA

    def __post_init__(self) -> None:
        match = _LOGICAL_ID.fullmatch(self.value)
        if self.schema != IDENTITY_SCHEMA or match is None or match.group(1) != self.kind.value:
            raise ValueError("invalid canonical logical identity")

    @classmethod
    def derive(cls, kind: EntityKind, target_snapshot: str, native_identity: Mapping[str, Any]) -> "LogicalIdentity":
        if not target_snapshot.strip():
            raise ValueError("target snapshot is required")
        digest = hashlib.sha256(canonical_json({
            "schema": IDENTITY_SCHEMA,
            "kind": kind.value,
            "target_snapshot": target_snapshot,
            "native_identity": native_identity,
        })).hexdigest()
        return cls(kind, f"asr:{kind.value}:{digest}")

    @classmethod
    def parse(cls, value: str) -> "LogicalIdentity":
        match = _LOGICAL_ID.fullmatch(value or "")
        if match is None:
            raise ValueError("invalid logical identifier")
        try:
            kind = EntityKind(match.group(1))
        except ValueError as exc:
            raise ValueError("unknown logical identifier kind") from exc
        return cls(kind, value)


@dataclass(frozen=True, slots=True)
class SourceLocation:
    target_snapshot: str
    path: str
    file_sha256: str
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    producer_location: Mapping[str, Any]
    mapping_method: str
    confidence: float
    ambiguous: bool = False
    schema: str = LOCATION_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", normalize_relative_path(self.path))
        if not self.target_snapshot.strip() or not _SHA256.fullmatch(self.file_sha256):
            raise ValueError("location requires target snapshot and file sha256")
        if self.start_byte < 0 or self.end_byte < self.start_byte:
            raise ValueError("invalid byte span")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("invalid line span")
        if self.start_column < 1 or self.end_column < 1:
            raise ValueError("invalid column span")
        if not self.mapping_method.strip() or not 0.0 <= self.confidence <= 1.0:
            raise ValueError("invalid location mapping metadata")

    @property
    def location_id(self) -> str:
        value = asdict(self)
        value.pop("producer_location")
        return "loc:" + hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class EntityRecord:
    identity: LogicalIdentity
    native_id: str
    name: str
    text: str
    payload: Mapping[str, Any]
    location: SourceLocation | None = None


@dataclass(frozen=True, slots=True)
class RelationRecord:
    kind: RelationKind
    source_id: str
    target_id: str
    exact: bool
    confidence: float
    ambiguity: str | None = None
    payload: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        LogicalIdentity.parse(self.source_id)
        LogicalIdentity.parse(self.target_id)
        if not 0 <= self.confidence <= 1:
            raise ValueError("relation confidence must be between zero and one")
        if not self.exact and not self.ambiguity:
            raise ValueError("non-exact relationships require an ambiguity explanation")

    @property
    def relation_id(self) -> str:
        return "rel:" + hashlib.sha256(canonical_json({
            "kind": self.kind.value, "source": self.source_id, "target": self.target_id,
            "exact": self.exact, "ambiguity": self.ambiguity,
        })).hexdigest()


def sanitize_producer_data(value: Any, *, depth: int = 0) -> Any:
    """Bound and redact compile/link/tool metadata before indexing or returning it."""
    secret = re.compile(r"(?i)(authorization|password|passwd|secret|token|api[_-]?key|credential)")
    if depth > 6:
        return "<truncated>"
    if isinstance(value, Mapping):
        result = {}
        for key, child in list(value.items())[:200]:
            name = str(key)[:128]
            result[name] = "<redacted>" if secret.search(name) else sanitize_producer_data(child, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        result = []
        redact_next = False
        for child in list(value)[:500]:
            text = str(child)
            if redact_next:
                result.append("<redacted>")
                redact_next = False
            elif secret.search(text):
                if "=" in text:
                    result.append(text.split("=", 1)[0] + "=<redacted>")
                else:
                    result.append(text[:64])
                    redact_next = True
            else:
                result.append(sanitize_producer_data(child, depth=depth + 1))
        return result
    if isinstance(value, str):
        return "<redacted>" if secret.search(value) else value[:8192]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:8192]
