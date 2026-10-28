"""Shared contracts for bounded acceptance lanes, separate from review runs."""
from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path
import re
from typing import Any, Mapping
from uuid import uuid4

from appsec_review.observability.events import EventLog, PipelineLog
from appsec_review.observability.spans import OperationSpan, operation_span


_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}")


class LaneTier(str, Enum):
    HERMETIC = "hermetic"
    TOOL = "tool"
    PROVIDER = "provider"
    CODEQL = "codeql"
    NATIVE = "native"


@dataclass(frozen=True)
class LaneSpec:
    name: str
    nodes: tuple[str, ...]
    tier: LaneTier = LaneTier.HERMETIC
    deadline_seconds: int = 720
    case_deadline_seconds: int = 60
    workers: int = 1
    prerequisites: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.name):
            raise ValueError("lane name must be a bounded lowercase identifier")
        if not isinstance(self.tier, LaneTier):
            raise ValueError("lane tier must be declared")
        if not self.nodes or any(not isinstance(node, str) or not node.strip() for node in self.nodes):
            raise ValueError("lane requires explicit nonempty test selections")
        for name in ("deadline_seconds", "case_deadline_seconds", "workers"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.workers > 2:
            raise ValueError("acceptance lanes allow at most two workers")
        if self.case_deadline_seconds > self.deadline_seconds:
            raise ValueError("case deadline cannot exceed lane deadline")


@dataclass(frozen=True)
class LaneWorkspace:
    repository: Path
    root: Path
    lane: str
    invocation_id: str

    @classmethod
    def create(cls, repository: Path, lane: str) -> LaneWorkspace:
        if not _NAME.fullmatch(lane):
            raise ValueError("lane name must be a bounded lowercase identifier")
        repository = Path(repository).resolve()
        scratch = repository / "test" / "tmp"
        acceptance = scratch / "acceptance"
        if scratch.resolve() != scratch or acceptance.resolve() != acceptance:
            raise ValueError("acceptance output must not traverse a redirected scratch directory")
        invocation_id = f"acceptance-{uuid4().hex}"
        root = acceptance / invocation_id / lane
        root.mkdir(parents=True, exist_ok=False)
        workspace = cls(repository, root, lane, invocation_id)
        workspace.runs_dir.mkdir()
        workspace.driver_root.mkdir()
        (root / "owner.json").write_text(json.dumps({
            "schema": "appsec-review/acceptance-workspace/1",
            "lane": lane,
            "invocation_id": invocation_id,
            "repository": str(repository),
            "runs_dir": str(workspace.runs_dir),
            "production_access": "forbidden",
        }, sort_keys=True) + "\n", encoding="utf-8")
        return workspace

    @property
    def runs_dir(self) -> Path:
        return self.root / "runs"

    @property
    def driver_root(self) -> Path:
        return self.root / "driver"

    @property
    def pipeline(self) -> PipelineLog:
        return PipelineLog(self.driver_root)

    @property
    def events(self) -> EventLog:
        return EventLog(self.driver_root / "events.jsonl", self.pipeline, {
            "run_id": self.invocation_id,
            "job_id": f"acceptance_{self.lane.replace('-', '_')}",
            "attempt_id": "attempt_0001",
            "trigger": "acceptance",
            "orchestrator": "acceptance",
        })

    def emit(self, event_type: str, **details: Any) -> None:
        self.events.write(event_type, namespace="acceptance", lane=self.lane, **details)

    def span(self, stage: str) -> AbstractContextManager[OperationSpan]:
        return operation_span(self.events, stage)

    def environment(self) -> Mapping[str, str]:
        return {
            "APPSEC_ACCEPTANCE_ROOT": str(self.root),
            "APPSEC_ACCEPTANCE_RUNS_DIR": str(self.runs_dir),
            "APPSEC_ACCEPTANCE_INVOCATION": self.invocation_id,
        }

    def require_owned_path(self, path: Path) -> Path:
        resolved = Path(path).resolve()
        if not resolved.is_relative_to(self.root.resolve()):
            raise ValueError("acceptance artifacts must stay inside their invocation workspace")
        return resolved
