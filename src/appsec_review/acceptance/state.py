"""Operator state of one stepwise acceptance walk through ``wave1_review``.

Jobs are walked in the graph's dispatch order. A job moves ``pending`` -> ``launched`` ->
``checked`` (check passed) or ``failed`` (check failed) -> ``accepted``. Only the first job that
is not yet accepted may be launched or accepted, so the answer key is built strictly in order.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

SCHEMA = "appsec-review/stepwise-acceptance/1"
STATUSES = ("pending", "launched", "checked", "failed", "accepted")
_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class StateError(ValueError):
    """A transition the stepwise walk does not allow."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def valid_corpus_tag(tag: str) -> str:
    if not _TAG.fullmatch(tag) or tag in {".", ".."}:
        raise StateError(f"corpus tag is not a safe directory name: {tag!r}")
    return tag


@dataclass
class StepwiseState:
    app_run_id: str
    graph: str
    target: str
    jobs: list[dict[str, Any]]
    topology: list[dict[str, Any]] = field(default_factory=list)
    corpus_tag: str | None = None
    created_at: str = field(default_factory=_now)

    # -- construction and persistence -------------------------------------------------------
    @classmethod
    def create(cls, app_run_id: str, *, target: str, topology: Mapping[str, Any]) -> "StepwiseState":
        jobs = [{"job_id": item["job_id"], "name": item["name"], "status": "pending",
                 "dagster_run_ids": [], "check": None, "handoff_sha256": None, "accepted_at": None}
                for item in topology["jobs"]]
        if not jobs:
            raise StateError("topology names no jobs")
        return cls(app_run_id=app_run_id, graph=str(topology.get("graph", "wave1_review")), target=target,
                   jobs=jobs, topology=[dict(item) for item in topology["jobs"]])

    @staticmethod
    def path_for(state_root: Path, app_run_id: str) -> Path:
        return Path(state_root) / app_run_id / "state.json"

    @classmethod
    def load(cls, path: Path) -> "StepwiseState":
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        if document.get("schema") != SCHEMA:
            raise StateError(f"unsupported stepwise state schema in {path}")
        return cls(app_run_id=document["app_run_id"], graph=document["graph"], target=document["target"],
                   jobs=list(document["jobs"]), topology=list(document.get("topology", [])),
                   corpus_tag=document.get("corpus_tag"), created_at=document["created_at"])

    def as_dict(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "app_run_id": self.app_run_id, "graph": self.graph, "target": self.target,
                "corpus_tag": self.corpus_tag, "created_at": self.created_at, "jobs": self.jobs,
                "topology": self.topology}

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(self.as_dict(), handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(temporary, path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    # -- queries -----------------------------------------------------------------------------
    def job(self, key: str) -> dict[str, Any]:
        for item in self.jobs:
            if key in {item["job_id"], item["name"]}:
                return item
        raise StateError(f"job is not in the {self.graph} walk: {key}")

    def next_job(self) -> dict[str, Any] | None:
        return next((item for item in self.jobs if item["status"] != "accepted"), None)

    def upstream_of(self, job_id: str) -> Sequence[str]:
        for item in self.topology:
            if item["job_id"] == job_id:
                return tuple(item.get("upstream_handoffs", ()))
        raise StateError(f"job has no recorded topology: {job_id}")

    # -- transitions ---------------------------------------------------------------------------
    def _require_next(self, job_id: str) -> dict[str, Any]:
        nxt = self.next_job()
        if nxt is None:
            raise StateError("every job is already accepted")
        if nxt["job_id"] != job_id:
            raise StateError(f"{job_id} is not next; accept {nxt['job_id']} first")
        return nxt

    def record_launch(self, job_id: str, dagster_run_id: str, *, relaunch: bool = False) -> None:
        item = self._require_next(job_id)
        if item["status"] == "checked" and not relaunch:
            raise StateError(f"{job_id} passed its check and awaits acceptance; accept it or relaunch")
        item["dagster_run_ids"].append(dagster_run_id)
        item["status"] = "launched"
        item["check"] = None

    def record_check(self, job_id: str, *, passed: bool, summary: Mapping[str, Any]) -> None:
        item = self.job(job_id)
        if item["status"] == "accepted":
            item["last_recheck"] = {"passed": passed, "checked_at": _now(), **dict(summary)}
            return
        if not item["dagster_run_ids"]:
            raise StateError(f"{job_id} has not been launched")
        item["status"] = "checked" if passed else "failed"
        item["check"] = {"passed": passed, "checked_at": _now(), **dict(summary)}

    def validate_accept(self, job_id: str, *, corpus_tag: str) -> dict[str, Any]:
        """Raise unless ``job_id`` may be accepted now; nothing is written before this passes."""
        valid_corpus_tag(corpus_tag)
        item = self._require_next(job_id)
        if item["status"] != "checked" or not (item.get("check") or {}).get("passed"):
            raise StateError(f"{job_id} has no passing check; run check first")
        if self.corpus_tag is not None and self.corpus_tag != corpus_tag:
            raise StateError(f"this walk is recorded against corpus tag {self.corpus_tag}, not {corpus_tag}")
        return item

    def record_accept(self, job_id: str, *, corpus_tag: str, handoff_sha256: str | None) -> None:
        item = self.validate_accept(job_id, corpus_tag=corpus_tag)
        self.corpus_tag = corpus_tag
        item["status"] = "accepted"
        item["handoff_sha256"] = handoff_sha256
        item["accepted_at"] = _now()

    def mark_seeded(self, through_job: str, *, corpus_tag: str, handoffs: Mapping[str, str | None]) -> None:
        """Mark every job up to ``through_job`` accepted because a known-good seed restored them."""
        valid_corpus_tag(corpus_tag)
        ids = [item["job_id"] for item in self.jobs]
        if through_job not in ids:
            raise StateError(f"job is not in the {self.graph} walk: {through_job}")
        self.corpus_tag = corpus_tag
        for item in self.jobs[:ids.index(through_job) + 1]:
            item.update(status="accepted", handoff_sha256=handoffs.get(item["job_id"]),
                        accepted_at=_now(), seeded=True)

    def accepted_handoffs(self) -> dict[str, str]:
        return {item["job_id"]: item["handoff_sha256"] for item in self.jobs
                if item["status"] == "accepted" and item.get("handoff_sha256")}
