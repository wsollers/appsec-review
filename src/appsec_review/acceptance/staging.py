"""Closed interchange for invocation-owned acceptance prerequisites."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping


STAGE_ENVIRONMENT = "APPSEC_ACCEPTANCE_STAGE"
CUSTODY_INPUT_FILE = "custody-input.json"
CUSTODY_INPUT_SCHEMA = "appsec-review/acceptance-seed-input/1"
_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}")
_SHA256 = re.compile(r"[a-f0-9]{64}")
_COMMIT = re.compile(r"[a-f0-9]{40,64}")


class StageKind(str, Enum):
    PRODUCER = "producer"
    CONSUMER = "consumer"


@dataclass(frozen=True)
class SeedInputs:
    variant: str
    read_only_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.variant, str) or not _NAME.fullmatch(self.variant):
            raise ValueError("seed inputs require a declared variant")
        if (not self.read_only_paths or any(not isinstance(value, str) for value in self.read_only_paths)
                or len(set(self.read_only_paths)) != len(self.read_only_paths)):
            raise ValueError("seed inputs require unique immutable paths")
        for value in self.read_only_paths:
            if not isinstance(value, str) or not value or "\\" in value:
                raise ValueError("seed input identities use canonical relative logical paths")
            path = PurePosixPath(value)
            if (path.is_absolute() or path.as_posix() != value
                    or any(part in {"..", "."} for part in value.split("/")) or ":" in value):
                raise ValueError("seed input paths must be relative descendants")

    def record(self) -> dict[str, Any]:
        return {"schema": CUSTODY_INPUT_SCHEMA, "variant": self.variant,
                "read_only_paths": list(self.read_only_paths)}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> SeedInputs:
        if (set(value) != {"schema", "variant", "read_only_paths"}
                or value["schema"] != CUSTODY_INPUT_SCHEMA
                or not isinstance(value["read_only_paths"], list)):
            raise ValueError("seed input fields do not match the custody contract")
        return cls(value["variant"], tuple(value["read_only_paths"]))


@dataclass(frozen=True)
class StageDeclaration:
    kind: StageKind
    variant: str
    depends_on: tuple[str, ...] = ()
    seals: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.kind, StageKind) or not _NAME.fullmatch(self.variant):
            raise ValueError("acceptance stage kind and variant must be declared")
        if (len(self.depends_on) > 1
                or any(not isinstance(item, str) or not _NAME.fullmatch(item) for item in self.depends_on)):
            raise ValueError("acceptance stages require at most one explicit predecessor")
        if type(self.seals) is not bool:
            raise ValueError("acceptance stage seal selection must be boolean")
        if self.kind is StageKind.CONSUMER and (len(self.depends_on) != 1 or self.seals):
            raise ValueError("acceptance consumers require one sealed producer and cannot seal")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> StageDeclaration:
        if set(value) - {"kind", "variant", "depends_on", "seals"}:
            raise ValueError("unknown acceptance stage declaration field")
        dependencies = value.get("depends_on", [])
        if not isinstance(dependencies, list):
            raise ValueError("acceptance stage dependencies must be an explicit list")
        try:
            return cls(StageKind(value["kind"]), value["variant"], tuple(dependencies),
                       value.get("seals", False))
        except (KeyError, TypeError) as error:
            raise ValueError("invalid acceptance stage declaration") from error


@dataclass(frozen=True)
class StageContext:
    kind: StageKind
    variant: str
    obligation_id: str
    invocation_id: str
    tested_commit: str
    source_identities: Mapping[str, str]
    workspace_root: Path
    work_root: Path
    seed_root: Path | None = None
    manifest_path: Path | None = None
    manifest_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, StageKind):
            raise ValueError("acceptance stage context kind must be declared")
        if any(not isinstance(value, str) or not _NAME.fullmatch(value)
               for value in (self.variant, self.obligation_id, self.invocation_id)):
            raise ValueError("invalid acceptance stage context identity")
        if not _COMMIT.fullmatch(self.tested_commit):
            raise ValueError("acceptance stage requires its supervisor's exact tested commit")
        if not self.source_identities or any(
                not isinstance(name, str) or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
                for name, digest in self.source_identities.items()):
            raise ValueError("acceptance stage requires pinned source identities")
        root = self.workspace_root
        if not root.is_absolute() or root.resolve() != root:
            raise ValueError("acceptance stage workspace must be canonical")
        for path in (self.work_root, self.seed_root, self.manifest_path):
            if path is not None and (
                    not path.is_absolute() or path.resolve() != path or not path.is_relative_to(root)
                    or path == root):
                raise ValueError("acceptance stage paths must be canonical invocation descendants")
        if self.kind is StageKind.PRODUCER:
            if any(value is not None for value in (
                    self.seed_root, self.manifest_path, self.manifest_sha256)):
                raise ValueError("producer context cannot claim a sealed input")
        else:
            if (self.seed_root is None or self.manifest_path is None
                    or not isinstance(self.manifest_sha256, str)
                    or not _SHA256.fullmatch(self.manifest_sha256)):
                raise ValueError("consumer context requires an exact sealed input")
            if (self.seed_root.is_relative_to(self.work_root)
                    or self.work_root.is_relative_to(self.seed_root)):
                raise ValueError("consumer copy must be independent of its sealed input")

    def record(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value, "variant": self.variant, "obligation_id": self.obligation_id,
            "invocation_id": self.invocation_id, "tested_commit": self.tested_commit,
            "source_identities": dict(self.source_identities),
            "workspace_root": str(self.workspace_root), "work_root": str(self.work_root),
            "seed_root": str(self.seed_root) if self.seed_root is not None else None,
            "manifest_path": str(self.manifest_path) if self.manifest_path is not None else None,
            "manifest_sha256": self.manifest_sha256,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> StageContext:
        fields = {
            "kind", "variant", "obligation_id", "invocation_id", "tested_commit", "source_identities",
            "workspace_root", "work_root", "seed_root", "manifest_path", "manifest_sha256",
        }
        if set(value) != fields:
            raise ValueError("acceptance stage context fields do not match the contract")
        try:
            return cls(
                StageKind(value["kind"]), value["variant"], value["obligation_id"],
                value["invocation_id"], value["tested_commit"], value["source_identities"],
                Path(value["workspace_root"]), Path(value["work_root"]),
                Path(value["seed_root"]) if value["seed_root"] is not None else None,
                Path(value["manifest_path"]) if value["manifest_path"] is not None else None,
                value["manifest_sha256"])
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError("invalid acceptance stage context") from error


def stage_context(environment: Mapping[str, str] | None = None) -> StageContext | None:
    selected = os.environ if environment is None else environment
    raw = selected.get(STAGE_ENVIRONMENT)
    if raw is None:
        return None
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("acceptance stage context must be an object")
    context = StageContext.from_mapping(value)
    if Path(selected["APPSEC_ACCEPTANCE_ROOT"]).resolve() != context.workspace_root:
        raise ValueError("acceptance stage context belongs to a different invocation")
    if selected["APPSEC_ACCEPTANCE_INVOCATION"] != context.invocation_id:
        raise ValueError("acceptance stage invocation identity changed")
    if selected["APPSEC_ACCEPTANCE_TESTED_COMMIT"] != context.tested_commit:
        raise ValueError("acceptance stage tested commit changed")
    return context
