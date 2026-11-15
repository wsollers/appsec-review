from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review.config import load_config
from appsec_review.interchange import validate_unit_output
from appsec_review.jobs.job_change_context_analysis import job
from appsec_review.jobs.job_change_context_analysis.settings import parse_settings
from appsec_review.observability import EventLog
from appsec_review.runtime.handoff import _declared_gap
from appsec_review.runtime.job import JobContext
from appsec_review.runtime.units import UnitContext
from appsec_review.storage import atomic_json, canonical_json


ROOT = Path(__file__).resolve().parents[3]
HEAD = "a" * 40
PARENT = "b" * 40
PRIOR = "c" * 40
T0 = 1_700_000_000
DAY = 86_400
HOUR = 3_600
SOURCE = b"def check(user):\n    return bool(user)\n"


def raw_settings(**overrides: Any) -> dict[str, Any]:
    raw = deepcopy(dict(load_config(ROOT / "appsec-review.toml").job(job.PRODUCER).settings))
    for dotted, value in overrides.items():
        table = raw
        *parents, leaf = dotted.split(".")
        for key in parents:
            table = table[key]
        table[leaf] = value
    return raw


def default_settings(**overrides: Any):
    return parse_settings(raw_settings(**overrides))


def context(
    tmp_path: Path,
    unit_id: str,
    *,
    outputs: dict[str, Any] | None = None,
    overrides: dict[str, Any] | None = None,
    files: dict[str, bytes] | None = None,
    repository_root: Path | None = None,
    target_root: Path | None = ...,  # type: ignore[assignment]
    source_fingerprint: str = "snapshot",
) -> UnitContext:
    config = load_config(ROOT / "appsec-review.toml").job(job.PRODUCER)
    if overrides:
        config = replace(config, settings=raw_settings(**overrides))
    if target_root is ...:
        target = tmp_path / "target"
        target.mkdir(parents=True, exist_ok=True)
        for path, data in (files or {}).items():
            destination = target / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
    else:
        target = target_root
    run = tmp_path / "run"
    attempt = run / f"data/jobs/{job.PRODUCER}/attempts/attempt_0001"
    step, task = unit_id.split(".")
    ctx = JobContext(
        run_id="fixture",
        attempt_id="attempt_0001",
        trigger="unit",
        repository_root=repository_root or ROOT,
        run_root=run,
        attempt_root=attempt,
        metadata_root=run / "metadata",
        orchestration={},
        config=config,
        events=EventLog(run / "events.jsonl"),
        target_root=target,
        source_fingerprint=source_fingerprint,
    )
    return UnitContext(ctx, unit_id, step, task, attempt / "steps" / step / "tasks" / task, outputs or {})


def artifact(unit: UnitContext, name: str, value: Any) -> dict[str, Any]:
    path = unit.job.run_root / "fixture" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        atomic_json(path, value)
    return job._artifact(unit.job.run_root, path)


def document(unit: UnitContext, result: dict[str, Any], key: str = "artifact") -> Any:
    return json.loads((unit.job.run_root / result[key]["path"]).read_text(encoding="utf-8"))


def write_resolved_config(run_root: Path, *, history_overrides: dict[str, Any] | None = None) -> None:
    cfg = load_config(ROOT / "appsec-review.toml")
    history_settings = deepcopy(dict(cfg.job("job_source_history_analysis").settings))
    for dotted, value in (history_overrides or {}).items():
        table = history_settings
        *parents, leaf = dotted.split(".")
        for key in parents:
            table = table[key]
        table[leaf] = value
    resolved = {"jobs": {"job_source_history_analysis": {"settings": history_settings}}}
    dest = run_root / "data" / "configuration"
    dest.mkdir(parents=True, exist_ok=True)
    resolved_path = dest / "resolved.json"
    resolved_bytes = canonical_json(resolved)
    resolved_path.write_bytes(resolved_bytes)
    atomic_json(dest / "manifest.json", {"resolved_sha256": hashlib.sha256(resolved_bytes).hexdigest()})


def handler(unit: UnitContext, **kwargs: Any):
    selected = next(value.handler for value in job.build_job(**kwargs).units if value.unit_id == unit.unit_id)

    def checked(ctx: UnitContext) -> dict[str, Any]:
        output = dict(selected(ctx))
        if "by_source" not in output:
            validate_unit_output(output, unit_id=ctx.unit_id)
            for value in output.get("gaps", ()):
                gap = _declared_gap(value, ctx.unit_id, ())
                assert gap.unit_id == ctx.unit_id
                assert gap.reason == value
        return output

    return checked


def eligible_entry(data: bytes = SOURCE, path: str = "a.py", *, exact: bool = True) -> dict[str, Any]:
    lines = max(1, data.count(b"\n"))
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "exact": exact,
        "source_path": path,
        "source_root": ".",
        "source_id": ".",
        "language": "Python",
        "line_count": lines,
        "span_lines": lines,
        "pinned_revision": HEAD,
    }


def change_entry(
    change_id: str,
    position: int,
    when: int,
    files: list[tuple[str, int, int]],
    *,
    author: str = "author-0001",
    bulk: bool = False,
    parents: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "change_id": change_id,
        "position": position,
        "parents": [PARENT] if parents is None else parents,
        "commit_time": when,
        "effective_time": when,
        "author_time": when,
        "author": author,
        "file_count": len(files),
        "bulk": bulk,
        "files": [
            {
                "path": path,
                "current_path": path,
                "renamed_from": None,
                "added": added,
                "deleted": deleted,
                "binary": False,
            }
            for path, added, deleted in files
        ],
    }
