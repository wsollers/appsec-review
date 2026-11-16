"""``AcceptedBuilds.locate`` uses every accepted native build, including one that completed with gaps."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_poc_generation import buildctx
from appsec_review.storage import atomic_bytes


def _receipt(run_root: Path, status: str, files: dict[str, str], **fields) -> dict:
    manifest = run_root / f"data/jobs/job_language_build/{status.lower()}/workspace-manifest.json"
    payload = json.dumps({"files": files}).encode()
    atomic_bytes(manifest, payload)
    return {"family": "native", "terminal_status": status, "build_unit_id": f"build-unit-{status.lower()}",
            "workspace_manifest": {"path": manifest.relative_to(run_root).as_posix(),
                                   "sha256": hashlib.sha256(payload).hexdigest()}, **fields}


@pytest.mark.parametrize("status", ["SUCCEEDED", "COMPLETED_WITH_GAPS"])
def test_an_accepted_native_build_with_gaps_is_still_searched(tmp_path: Path, status: str) -> None:
    """Run 2026-11-16-0003: the only native build was COMPLETED_WITH_GAPS (output-classification heuristics), so every
    remediation plan and PoC was refused with no_native_build although the compile database was bound and valid."""
    run_root = tmp_path / "run"
    receipt = _receipt(run_root, status, {"src/other.cpp": "0" * 64})
    builds = buildctx.AcceptedBuilds(run_root, loader=lambda _root: {"receipts": [receipt]})
    located = builds.locate("src/request.cpp")
    # The build was consulted: the answer names the file, not the absence of a build.
    assert located.code == "no_native_build"
    assert located.reason == "no accepted native build contains src/request.cpp"


@pytest.mark.parametrize("status", ["FAILED", "BLOCKED", "NOT_APPLICABLE"])
def test_a_build_without_products_is_not_an_accepted_build(tmp_path: Path, status: str) -> None:
    run_root = tmp_path / "run"
    receipt = _receipt(run_root, status, {"src/request.cpp": "0" * 64})
    builds = buildctx.AcceptedBuilds(run_root, loader=lambda _root: {"receipts": [receipt]})
    located = builds.locate("src/request.cpp")
    assert (located.code, located.reason) == ("no_native_build", "the run has no successful accepted native build")


@pytest.mark.parametrize("status", ["SUCCEEDED", "COMPLETED_WITH_GAPS"])
def test_a_receipt_that_says_built_is_searched_whatever_its_gaps_did_to_the_status(tmp_path: Path, status: str) -> None:
    run_root = tmp_path / "run"
    receipt = _receipt(run_root, status, {"src/other.cpp": "0" * 64}, build_outcome="built")
    located = buildctx.AcceptedBuilds(run_root, loader=lambda _root: {"receipts": [receipt]}).locate("src/request.cpp")
    assert (located.code, located.reason) == ("no_native_build", "no accepted native build contains src/request.cpp")


@pytest.mark.parametrize("build_outcome", ["failed", "not_run"])
def test_a_receipt_whose_build_did_not_complete_has_no_products_whatever_its_status_says(
        tmp_path: Path, build_outcome: str) -> None:
    """``build_outcome`` is the build's own verdict; a status alone no longer admits a receipt that carries one."""
    run_root = tmp_path / "run"
    receipt = _receipt(run_root, "SUCCEEDED", {"src/request.cpp": "0" * 64}, build_outcome=build_outcome)
    located = buildctx.AcceptedBuilds(run_root, loader=lambda _root: {"receipts": [receipt]}).locate("src/request.cpp")
    assert (located.code, located.reason) == ("no_native_build", "the run has no successful accepted native build")


def test_candidate_parser_accepts_a_claim_no_judge_was_convened_for() -> None:
    from tests.unit.job_poc_generation.test_brief_inputs_and_helpers import _candidate_dict
    from appsec_review.jobs.job_poc_generation.candidates import parse_candidates
    parsed = parse_candidates([_candidate_dict(1, verdict="not_convened")])
    assert parsed[0].judge_verdict == "not_convened"
