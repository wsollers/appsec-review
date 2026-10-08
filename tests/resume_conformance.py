from __future__ import annotations

from pathlib import Path
from typing import Mapping

from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.runtime import GraphRunner, Job


def assert_reuse_without_execution(graph: GraphRunner, target: Path, calls: Mapping[str, int]) -> str:
    """Reusable baseline required of each semantic job added to a resumable graph."""
    fingerprint = source_fingerprint(target)
    first = graph.run(target_root=target, source_fingerprint=fingerprint)
    before = dict(calls)
    second = graph.run(target_root=target, source_fingerprint=fingerprint, run_id=first["run_id"])
    assert dict(calls) == before
    assert all(item["action"] == "REUSE" for item in second["decisions"])
    assert all(item["handoff_sha256"] for item in second["decisions"])
    return first["run_id"]
