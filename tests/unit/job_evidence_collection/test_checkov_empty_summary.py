"""Focused unit tests for Checkov zero-resource summaries and gitleaks shard artifact paths."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from types import MappingProxyType

import pytest

from appsec_review.jobs.job_evidence_collection.adapters import (
    _checkov_parser,
    _is_checkov_empty_summary,
    _validate_report,
    checkov_unreported_inputs,
)
from appsec_review.jobs.job_evidence_collection.job import _build_producer_shard
from appsec_review.runtime import UnitContext
from appsec_review.storage import canonical_json, file_sha256

from tests.unit.job_evidence_collection.support import make_unit_context


def test_gitleaks_producer_shard_uses_normalized_artifact_when_raw_path_is_redacted(tmp_path: Path) -> None:
    norm_rel = "data/jobs/job_evidence_collection/attempts/attempt_0001/steps/secrets/tasks/gitleaks_scan/evidence.json"
    unit, _, _ = make_unit_context(
        tmp_path,
        unit_id="secrets.gitleaks_index",
        outputs={},
    )
    run_sh_sha = file_sha256(unit.job.target_root / "run.sh")
    evidence_doc = {
        "tool_id": "tool-gitleaks",
        "records": [{
            "evidence_id": "e" * 64,
            "native_rule_id": "generic-api-key",
            "message": "secret detected",
            "severity": "HIGH",
            "location": {
                "path": "run.sh",
                "source_sha256": run_sh_sha,
                "start_line": 1,
                "end_line": 1,
            },
        }],
    }
    norm_path = unit.job.run_root / norm_rel
    norm_path.parent.mkdir(parents=True, exist_ok=True)
    norm_path.write_bytes(canonical_json(evidence_doc))
    norm_sha = file_sha256(norm_path)

    normalize_out = {
        "terminal_status": "SUCCEEDED",
        "tool_id": "tool-gitleaks",
        "artifact": {"path": norm_rel, "sha256": norm_sha, "size_bytes": norm_path.stat().st_size},
        "normalized_artifact": {"path": norm_rel, "sha256": norm_sha, "size_bytes": norm_path.stat().st_size},
        "not_applicable_inputs": [],
        "gaps": [],
    }
    unit_with_out = UnitContext(
        unit.job, unit.unit_id, unit.step_id, unit.task_id, unit.unit_root,
        MappingProxyType({"secrets.gitleaks_normalize": normalize_out}),
    )
    shard_out = _build_producer_shard(unit_with_out, "secrets.gitleaks_normalize")
    shard_file = unit.job.run_root / shard_out["index_identity"]["relative_path"]
    with sqlite3.connect(shard_file) as db:
        row = db.execute("SELECT payload_json FROM entities WHERE kind = 'evidence_artifact'").fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["artifact"]["path"] == norm_rel
    assert payload["artifact"]["path"] != "<redacted>"


def test_checkov_empty_summary_object_and_list_validate_and_parse_cleanly() -> None:
    empty_summary = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "parsing_errors": 0,
        "resource_count": 0,
        "checkov_version": "3.3.19",
    }
    assert _is_checkov_empty_summary(empty_summary) is True
    raw_single = json.dumps(empty_summary).encode("utf-8")
    assert _validate_report("tool-checkov", raw_single) == []
    assert _checkov_parser(raw_single) == []
    assert checkov_unreported_inputs(raw_single, ["config/app.json", "meta/settings.yaml"]) == [
        "config/app.json",
        "meta/settings.yaml",
    ]

    mixed = [
        empty_summary,
        {
            "check_type": "dockerfile",
            "results": {
                "passed_checks": [{"check_id": "CKV_DOCKER_2", "file_path": "/target/Dockerfile"}],
                "failed_checks": [{
                    "check_id": "CKV_DOCKER_3",
                    "check_name": "Ensure a user for the container has been created",
                    "file_path": "/target/Dockerfile",
                    "file_line_range": [1, 4],
                }],
                "skipped_checks": [],
                "parsing_errors": [],
            },
        },
    ]
    raw_mixed = json.dumps(mixed).encode("utf-8")
    assert _validate_report("tool-checkov", raw_mixed) == []
    parsed = _checkov_parser(raw_mixed)
    assert len(parsed) == 1
    assert parsed[0]["rule_id"] == "CKV_DOCKER_3"
    assert checkov_unreported_inputs(raw_mixed, ["Dockerfile", "config/app.json"]) == ["config/app.json"]


@pytest.mark.parametrize(
    "bad_payload",
    [
        [],
        {"passed": 0, "failed": 1, "skipped": 0, "parsing_errors": 0, "resource_count": 0, "checkov_version": "3.3.19"},
        {"passed": False, "failed": 0, "skipped": 0, "parsing_errors": 0, "resource_count": 0, "checkov_version": "3.3.19"},
        {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "resource_count": 0},
        {"results": {}},
    ],
)
def test_checkov_empty_summary_rejects_nonzero_boolean_or_empty_list(bad_payload: object) -> None:
    assert _is_checkov_empty_summary(bad_payload) is False
    with pytest.raises(ValueError, match="Checkov report|native report requires results"):
        _validate_report("tool-checkov", json.dumps(bad_payload).encode("utf-8"))
