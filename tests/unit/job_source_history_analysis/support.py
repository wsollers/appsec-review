from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path

from appsec_review.config import load_config
from appsec_review.jobs.job_source_history_analysis import job
from appsec_review.jobs.job_source_history_analysis.sources import GitSource, blob_id
from appsec_review.observability import EventLog
from appsec_review.runtime.job import JobContext
from appsec_review.runtime.units import UnitContext
from appsec_review.runtime.handoff import _declared_gap
from appsec_review.interchange import validate_unit_output
from appsec_review.storage import atomic_json


ROOT = Path(__file__).resolve().parents[3]
HEAD = "a" * 40
PARENT = "b" * 40
STAMP = 1_700_000_000
SOURCE = b"def f(x):\n    return x\n"


def settings():
    return deepcopy(dict(load_config(ROOT / "appsec-review.toml").job("job_source_history_analysis").settings))


def context(tmp_path, unit_id, outputs=None, overrides=None, files=None):
    config = load_config(ROOT / "appsec-review.toml").job("job_source_history_analysis")
    if overrides:
        config = replace(config, settings={**config.settings, **overrides})
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    for path, data in (files or {}).items():
        destination = target / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    run = tmp_path / "run"
    attempt = run / "data/jobs/job_source_history_analysis/attempts/attempt_0001"
    step, task = unit_id.split(".")
    ctx = JobContext(
        run_id="fixture", attempt_id="attempt_0001", trigger="unit", repository_root=ROOT,
        run_root=run, attempt_root=attempt, metadata_root=run / "metadata", orchestration={},
        config=config, events=EventLog(run / "events.jsonl"), target_root=target,
        source_fingerprint="snapshot",
    )
    return UnitContext(ctx, unit_id, step, task, attempt / "steps" / step / "tasks" / task, outputs or {})


def artifact(unit, name, value):
    path = unit.job.run_root / "fixture" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        atomic_json(path, value)
    return job._artifact(unit.job.run_root, path)


def document(unit, result, key="artifact"):
    return json.loads((unit.job.run_root / result[key]["path"]).read_text())


def handler(unit, **kwargs):
    selected = next(value.handler for value in job.build_job(**kwargs).units if value.unit_id == unit.unit_id)

    def checked(context):
        output = selected(context)
        validate_unit_output(output, unit_id=context.unit_id)
        for value in output.get("gaps", ()):
            gap = _declared_gap(value, context.unit_id, ())
            assert gap.unit_id == context.unit_id
            if isinstance(value, str):
                assert gap.code == "producer_reported_gap" and gap.scope_id is None
                assert gap.reason == value
            else:
                assert gap.code == value["code"] and gap.scope_id == value["scope_id"]
        return output

    return checked


def resolved():
    return {
        "identity": "identity", "source": {"source_id": ".", "root": ".", "github_repository": "acme/repo"},
        "git": GitSource("SUCCEEDED", "resolved", ".git", snapshot_commit=HEAD, head_commit=HEAD).as_dict(),
        "github": {"decision": "PENDING", "reason": "awaiting_git_history"},
        "inputs": {"files": [], "components": [{"component_id": "component", "root": "."}],
                   "changelog_exclusions": []},
        "gaps": [], "terminal_status": "SUCCEEDED",
    }


def eligible(data=SOURCE, path="a.py"):
    return {path: {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data), "exact": True,
                   "source_path": path, "source_root": ".", "source_id": ".", "blob_id": blob_id(data, "sha1"),
                   "language": "Python", "line_count": 2, "span_lines": 2, "pinned_revision": HEAD}}


def header(commit=HEAD, when=STAMP):
    return f"\x01{commit}\x1f\x1f{when}\x1f{when}\x1fperson@example.test\0".encode()


def change(commit=HEAD, when=STAMP, path="a.py", added=1, deleted=1, author="author-0001", bulk=False):
    return {"change_id": commit, "position": 0, "effective_time": when, "commit_time": when,
            "author_time": when, "author": author, "parents": [], "bulk": bulk, "file_count": 1,
            "files": [{"path": path, "current_path": path, "added": added, "deleted": deleted,
                       "binary": False, "renamed_from": None}]}


def node(ordinal, kind, start=0, end=len(SOURCE), *, field=None, named=True, row=0, end_row=1, **extra):
    return {"ordinal_path": list(ordinal), "type": kind, "field": field, "named": named,
            "start_byte": start, "end_byte": end, "start_point": [row, 0], "end_point": [end_row, 0],
            "error": False, "missing": False, **extra}


def nodes():
    return [node((), "module"), node((0,), "function_definition"),
            node((0, 0), "identifier", 4, 5, field="name", end_row=0)]
