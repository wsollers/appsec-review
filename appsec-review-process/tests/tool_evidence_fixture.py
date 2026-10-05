"""A real tool-evidence record (ADR-0035) over the code-query fixture index, laid out under a run's ``data/``."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "tests"))

import code_query_fixture as fx
import code_query_mcp
from execution_state import atomic_json, file_hash
import tool_evidence

COMPLETE = ("code_path", {"to": "strcpy", "from": "copy_field"})


def record(data: Path, job: str, attempt: str, tool: str = COMPLETE[0], args: dict | None = None) -> tuple[dict, Path]:
    """(canonical citation, record path) of one answer recorded for ``job``/``attempt`` under ``data``."""
    jobs = data / "jobs"
    ref = "02-code-index/attempts/a1/code-index.json"
    if not (jobs / ref).is_file():
        fx.publish(jobs)
    summary = json.loads((jobs / ref).read_text())
    answer = code_query_mcp.call(code_query_mcp.CodeIndex(jobs, ref, summary), tool, dict(args or COMPLETE[1]))
    index = {"kind": "code-index", "ref": "supporting-evidence:" + ref,
             "summary_sha256": "sha256:" + hashlib.sha256((jobs / ref).read_bytes()).hexdigest(),
             "producer_job": answer["source"]["producer_job"], "producer_attempt": answer["source"]["attempt_id"],
             "database_sha256": answer["source"]["sha256"]}
    value = tool_evidence.build(tool, answer, index=index, job_id=job, attempt_id=attempt,
                                recorded_at="2026-10-05T00:00:00Z")
    path = data / tool_evidence.relative_path(job, attempt, value["citation_id"])
    atomic_json(path, value)
    return tool_evidence.citation(value, "sha256:" + file_hash(path)), path
