"""Shared GraphRunner publication helper for build-environment integration and repair tests."""
from __future__ import annotations

import json
from pathlib import Path

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_build_environment_analysis.job import (
    JOB_ID,
    build_job,
    environment_contract,
)
from appsec_review.jobs.job_review_intake import build_job as intake_job
from appsec_review.jobs.job_target_catalog import build_job as catalog_job
from appsec_review.runtime import GraphRunner

ROOT = Path(__file__).resolve().parents[3]


def _published(tmp_path: Path, *, reusable: bool = False, mode: str = "strict"):
    config_path = tmp_path / "appsec-review.toml"
    target = tmp_path / "target"
    target.mkdir()
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if reusable:
        from tests.release_support import write_release

        policy = '[review_policy]\nmode = "strict"\napproved_first_party_projects = []'
        assert text.count(policy) == 1 and text.count("[review_policy.releases]\n") == 1
        text = text.replace(
            policy,
            f'[review_policy]\nmode = "{mode}"\nproject_id = "synthetic-environment"\n'
            'approved_first_party_projects = ["synthetic-environment"]\n'
            f'target_root = {json.dumps(str(target))}\ncustody = "application_private_v1"',
        )
        write_release(
            tmp_path,
            ("job_review_intake", "job_target_catalog", JOB_ID, "job_target_analysis_plan"),
        )
    config_path.write_bytes(text.encode("utf-8"))
    config = load_config(config_path)
    (target / "setup.sh").write_bytes(b"SDK_ROOT=tools/sdk\n")
    fingerprint = source_fingerprint(target)
    result = GraphRunner(config, [intake_job(), catalog_job(), build_job()]).run(
        target_root=target,
        source_fingerprint=fingerprint,
    )
    run_root = config.runtime.runs_dir / result["run_id"]
    pointer = json.loads((run_root / "data/jobs" / JOB_ID / "latest.json").read_bytes())
    contract = environment_contract(
        config,
        {"workflow": "wave1_review"},
        {JOB_ID: pointer["handoff_sha256"]},
    )
    return config, run_root, fingerprint, contract
