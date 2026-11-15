"""Pre-walk suite pending replacement: structured gaps through the whole catalog graph."""
from __future__ import annotations

import json
from pathlib import Path

from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner
from tests.test_wave1_resume import _fixture


def test_catalog_path_index_accepts_structured_inventory_gaps(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    excluded = target / ".hg" / "fixture"
    excluded.mkdir(parents=True)
    (excluded / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")

    outcome = GraphRunner(config, [build_intake(), build_catalog()]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))

    run_root = config.runtime.runs_dir / outcome["run_id"]
    attempt_id = outcome["jobs"]["job_target_catalog"]["status"]["attempt_id"]
    result_path = (run_root / "data/jobs/job_target_catalog/attempts" / attempt_id /
                   "steps/retrieval_indexes/tasks/build_path_index/result.json")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    [gap] = result["gaps"]
    assert gap["schema"] == "appsec-review/producer-gap/1"
    assert gap["scope_id"] == ".hg"
    assert gap["reason"] == ".hg: excluded_directory"
    assert result["index_identity"]["gaps"] == [".hg: excluded_directory"]
