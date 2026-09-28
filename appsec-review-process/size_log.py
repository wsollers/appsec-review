"""Record how big target-derived data actually gets, instead of capping it (ADR-0013).

Former hard ceilings (file counts, record counts, byte totals) now call ``observe`` and carry on.
Each observation is one small JSON file under ``runs/<run_id>/data/size-observations/`` named by
job and metric, so concurrent workers never contend and a re-run overwrites its own entry.
``orchestrator/size-report.py <run_id>`` prints them. Logging never fails the job.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from typing import Any

from execution_state import data_path

_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def observe(run_id: Any, job: Any, metric: str, value: int, former_limit: int | None = None,
            **detail: Any) -> None:
    record = {"run_id": run_id, "job": job, "metric": metric, "value": value,
              "former_limit": former_limit,
              "over_former_limit": former_limit is not None and value > former_limit,
              "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), **detail}
    if record["over_former_limit"]:
        print(f"size-log: {job} {metric}={value} (former limit {former_limit})", file=sys.stderr)
    try:
        if not isinstance(run_id, str) or not run_id:
            return
        folder = data_path(run_id, "size-observations")
        folder.mkdir(parents=True, exist_ok=True)
        name = _SAFE.sub("_", f"{job}.{metric}")[:200] + ".json"
        (folder / name).write_text(json.dumps(record, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    except Exception as error:  # observation only
        print(f"size-log: could not record {job} {metric}: {error}", file=sys.stderr)
