"""Dagster acceptance for ``job_inference_security_review`` slice 1 (design "Slice 1 definition of done").

A scripted deterministic ``Infer`` double drives the C6 fixture accepted index set through every R1
unit. The multiprocess runs prove the two lanes overlap and that ``review_teams = 1`` and
``review_teams = 5`` (capacity overlay) publish identical canonical outputs. Further runs prove
selective reuse, shard-scoped invalidation, integrity blocking, lane failure as a ``DEGRADED`` gap,
verifier blindness, and capability isolation.
"""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import shutil

import pytest

pytest.importorskip("dagster")

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from appsec_review.config import load_config
from appsec_review.guidance import load_registry
from appsec_review.review.capability import FORBIDDEN_PARAMETERS, IN_PROCESS_TOOLS, TOOL_SCHEMAS, CellCapability
from appsec_review.review.models import IntegrityError, Role
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import file_sha256
from tests.fixtures.inference_review.acceptance import (
    JOB, ROOT, build_registry, define_job, write_config, write_overlay, write_scenario,
)
from tests.fixtures.inference_review.builder import build_accepted_index_set, shard_path
from tests.fixtures.inference_review.fake_infer import NARRATIVES

R1_UNITS = ("scope.accept_manifest", "scope.assemble_scope", "packages.assemble_lead_packages",
            "packages.assemble_hunt_packages", "lead_review.teams", "hunt_review.teams", "merge.claims",
            "adjudicate.apply_policy", "scoring.score_claims", "completeness.audit",
            "publication.publish_claim_ledger", "publication.publish_handoff")
SCHEMAS = ROOT / "docs" / "schemas" / "inference-security-review"


# ------------------------------------------------------------------------------------------------ helpers


def _prepare(base: Path, logs: Path, monkeypatch, *, teams: int, cells: Path | None = None,
             history_change_count: int = 9, config_overrides=None, config_extra: str = "", **scenario):
    shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True)
    logs.mkdir(parents=True, exist_ok=True)
    fixture = build_accepted_index_set(base, history_change_count=history_change_count)
    if cells is not None:
        shutil.copytree(cells, fixture.run_root / "data" / "jobs" / JOB / "cells")
    config = write_config(base, fixture.runs_dir, overrides=config_overrides, extra=config_extra)
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG_OVERLAY", str(write_overlay(base, teams)))
    monkeypatch.setenv("APPSEC_C7_CONFIG", str(config))
    monkeypatch.setenv("APPSEC_C7_SCENARIO", str(write_scenario(
        logs, fixture.ids, calls=str(logs / "calls.jsonl"), captures=str(logs / "captures"), **scenario)))
    return fixture, config


def _multiprocess(fixture, dagster_root: Path) -> None:
    from dagster import DagsterInstance, execute_job, reconstructable

    dagster_root.mkdir(parents=True, exist_ok=True)
    with DagsterInstance.local_temp(tempdir=str(dagster_root)) as instance:
        result = execute_job(reconstructable(define_job), instance=instance,
                             tags={"appsec/application_run_id": fixture.run_id})
        assert result.success


def _in_process(fixture, *, success: bool = True):
    result = define_job().execute_in_process(tags={"appsec/application_run_id": fixture.run_id},
                                            raise_on_error=False)
    assert result.success is success
    return result


def _attempt(fixture) -> Path:
    return sorted((fixture.run_root / "data" / "jobs" / JOB / "attempts").iterdir())[-1]


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _unit(attempt: Path, unit_id: str) -> Path:
    step, task = unit_id.split(".")
    return attempt / "steps" / step / "tasks" / task


def _handoff(attempt: Path) -> dict:
    return _json(_unit(attempt, "publication.publish_handoff") / "inference-review-handoff.json")


def _canonical(attempt: Path) -> dict:
    handoff = _handoff(attempt)
    ledger = _unit(attempt, "publication.publish_claim_ledger")
    return {"ledger_head": handoff["ledger_head_sha256"], "projection": handoff["projection_sha256"],
            "package_manifest": handoff["package_manifest_sha256"],
            "ledger_bytes": file_sha256(ledger / "claim-ledger.jsonl"),
            "projection_bytes": file_sha256(ledger / "projection.json"),
            "handoff": {**{key: value for key, value in handoff.items() if key != "shards"},
                        "shards": [{key: value for key, value in item.items() if key != "path"}
                                   for item in handoff["shards"]]}}


def _calls(logs: Path) -> list[dict]:
    path = logs / "calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _runner_attempt(config: Path, run_id: str, *, stop_before: str | None = None):
    job = build_registry().build(JOB)
    runner = JobRunner(load_config(config))
    claim = runner.begin_attempt(job, run_id=run_id)
    for unit in job.units:
        if unit.unit_id == stop_before:
            return runner, job, claim
        runner.execute_or_reuse_unit(job, claim, unit.unit_id)
    return runner.finalize_attempt(job, claim), job, claim


def _validator(name: str) -> Draft202012Validator:
    documents = [json.loads(path.read_text()) for path in SCHEMAS.glob("*.schema.json")]
    registry = Registry().with_resources((item["$id"], Resource.from_contents(item)) for item in documents)
    return Draft202012Validator(json.loads((SCHEMAS / f"{name}.schema.json").read_text()), registry=registry)


def _failed_cells(attempt: Path) -> set[str]:
    projection = _json(_unit(attempt, "publication.publish_claim_ledger") / "projection.json")
    return {cell_id for cell_id, records in projection["cells"].items()
            if records[0]["status"] not in {"succeeded", "not_launched"}}


# ------------------------------------------------------------------------------------------------ acceptance


def test_slice1_acceptance_both_lanes_parallel_and_capacity_invariant(tmp_path: Path, monkeypatch) -> None:
    base, logs = tmp_path / "review", tmp_path / "logs-1"
    gate = "{run}/data/jobs/" + JOB + "/attempts/*/steps/hunt_review/tasks/teams/status.json"
    fixture, config = _prepare(base, logs, monkeypatch, teams=1,
                               gate=gate.format(run=(base / "runs" / "2026-10-12-0001").as_posix()))
    _multiprocess(fixture, tmp_path / "dagster-1")
    attempt = _attempt(fixture)

    # Every R1 unit is a visible Dagster op and every unit succeeded.
    graph = define_job().graph
    names = {node.name for node in graph.node_defs}
    assert {f"standalone__inference_security_review__{unit.replace('.', '__')}" for unit in R1_UNITS} <= names
    statuses = {unit: _json(_unit(attempt, unit) / "status.json") for unit in R1_UNITS}
    assert {value["status"] for value in statuses.values()} == {"SUCCEEDED"}
    # Both lanes ran in parallel: lane A could not finish before lane B started (scripted gate).
    lead, hunt = statuses["lead_review.teams"], statuses["hunt_review.teams"]
    stamp = datetime.fromisoformat
    assert stamp(lead["started_at"]) < stamp(hunt["completed_at"]) and stamp(hunt["started_at"]) < stamp(
        lead["completed_at"])
    assert lead["dagster_run_id"] == hunt["dagster_run_id"]

    handoff = _handoff(attempt)
    _validator("handoff").validate(handoff)
    accounting = handoff["accounting"]
    assert accounting["exact"] and handoff["status"] == "DEGRADED" and accounting["review_incomplete"] is False
    states = accounting["claims_by_state"]
    assert all(states[state] >= 1 for state in ("confirmed", "supported", "contradicted", "insufficient_evidence"))
    assert states["duplicate"] == 0
    lanes = {item["lane"]: item for item in accounting["lanes"]}
    assert accounting["duplicate_proposals"] == 1 and lanes["hunt"]["duplicate_proposals"] == 1
    assert sum(lane["cells_by_status"]["failed"] for lane in lanes.values()) >= 1
    assert accounting["gaps_by_class"]["worker_gap"] >= 1
    assert lanes["hunt"]["cells_by_status"]["not_launched"] >= 1 and accounting["gaps_by_class"]["budget_gap"] >= 1
    # The failure-modes lens probes two forbidden capabilities; denials are feedback, not gaps (review protocol v2).
    assert accounting["gaps_by_class"].get("authority_error", 0) == 0
    projection = _json(_unit(attempt, "publication.publish_claim_ledger") / "projection.json")
    not_launched = [records[0] for records in projection["cells"].values() if records[0]["status"] == "not_launched"]
    budget_gaps = {gap["gap_id"] for gap in projection["gaps"] if gap["gap_class"] == "budget_gap"}
    assert not_launched and all(set(record["gap_ids"]) <= budget_gaps for record in not_launched)
    worker_gaps = [gap for gap in projection["gaps"] if gap["gap_class"] == "worker_gap"]
    assert any(gap["subject_id"].startswith("cell-") for gap in worker_gaps)
    for item in handoff["finding_packages"]:
        path = _unit(attempt, "publication.publish_handoff") / "findings" / f"{item['finding_package_id']}.json"
        assert file_sha256(path) == item["sha256"]
        _validator("finding-package").validate(_json(path))
    for item in handoff["score_packages"]:
        _validator("score-package").validate(_json(_unit(attempt, "scoring.score_claims") / "scores" /
                                                    f"{item['score_id']}.json"))
    coverage = _json(fixture.run_root / handoff["coverage_matrix"]["path"])
    assert {row["status"] for row in coverage["rows"]} == {"reviewed", "gap", "not_launched"}
    assert any(row["reason"] == "below_hunt_cutoff" for row in coverage["rows"])
    _assert_ship_block_and_remediation_intake(attempt, handoff)

    _assert_verifier_blind(logs)
    _assert_capabilities_isolated(fixture, attempt)
    _assert_reference_enrichment(fixture, attempt)
    first = _canonical(attempt)

    # Same accepted inputs, five review teams through the capacity overlay: identical canonical outputs.
    logs_5 = tmp_path / "logs-5"
    fixture, config = _prepare(base, logs_5, monkeypatch, teams=5)
    _multiprocess(fixture, tmp_path / "dagster-5")
    assert load_config(config).job(JOB).typed_settings.teams.review_teams == 5
    assert _canonical(_attempt(fixture)) == first
    assert len(_calls(logs_5)) == len(_calls(logs))

    # Re-executing the lane units reuses every unchanged cell; only failed cells are retried.
    failed = _failed_cells(_attempt(fixture))
    before = len(_calls(logs_5))
    outcome, _job, _claim = _runner_attempt(config, fixture.run_id)
    rerun = {item["cell_id"] for item in _calls(logs_5)[before:]}
    assert failed and rerun == failed
    for lane in ("lead_review.teams", "hunt_review.teams"):
        counts = _json(_unit(_attempt(fixture), lane) / "lane.json")["counts"]
        assert counts["cells_run"] == len(failed & set(_json(_unit(_attempt(fixture), lane) / "lane.json")
                                                       ["expected_cells"]))
    assert outcome["status"]["status"] == "COMPLETED_WITH_GAPS"

    # Changing one evidence shard reruns only the cells whose package depends on it.
    cells = tmp_path / "cells-kept"
    shutil.copytree(fixture.run_root / "data" / "jobs" / JOB / "cells", cells)
    logs_shard = tmp_path / "logs-shard"
    fixture, config = _prepare(base, logs_shard, monkeypatch, teams=5, cells=cells, history_change_count=10)
    _runner_attempt(config, fixture.run_id)
    attempt = _attempt(fixture)
    hunt_doc = _json(_unit(attempt, "hunt_review.teams") / "lane.json")
    lead_doc = _json(_unit(attempt, "lead_review.teams") / "lane.json")
    packages = _json(_unit(attempt, "packages.assemble_hunt_packages") / "hunt-packages.json")["packages"]
    native = next(item["package_id"] for item in packages if "history" in " ".join(item["dependency_shards"]))
    native_cells = {row["cell_id"] for row in hunt_doc["capabilities"] if row["package_id"] == native}
    called = {item["cell_id"] for item in _calls(logs_shard)}
    assert native_cells and native_cells <= called
    assert called - native_cells <= failed
    assert lead_doc["counts"]["cells_run"] == len(failed & set(lead_doc["expected_cells"]))
    assert hunt_doc["counts"]["cells_reused"] == 0 and lead_doc["counts"]["cells_reused"] >= 30

    # Tampering with an accepted shard after review blocks publication; no handoff is accepted.
    latest = fixture.run_root / "data" / "jobs" / JOB / "latest.json"
    accepted_before = latest.read_bytes()
    runner, job, claim = _runner_attempt(config, fixture.run_id, stop_before="publication.publish_claim_ledger")
    with shard_path(fixture, "history", "git-history").open("ab") as handle:
        handle.write(b"tampered")
    with pytest.raises(IntegrityError):
        runner.execute_or_reuse_unit(job, claim, "publication.publish_claim_ledger")
    with pytest.raises(ValueError):
        runner.finalize_attempt(job, claim)
    assert latest.read_bytes() == accepted_before


STATUSES = ("ship_blocking", "ship_blocking_pending_distinct_verification", "needs_verification",
            "decision_pending", "not_ship_blocking")


def _findings(attempt: Path, handoff: dict) -> dict[str, dict]:
    root = _unit(attempt, "publication.publish_handoff") / "findings"
    return {item["finding_package_id"]: _json(root / f"{item['finding_package_id']}.json")
            for item in handoff["finding_packages"]}


def _assert_ship_block_and_remediation_intake(attempt: Path, handoff: dict) -> None:
    """Decisions 1, 2, 4 and 8 under the checked-in default (every role on one model profile)."""
    findings = _findings(attempt, handoff)
    summary = handoff["ship_block"]
    assert summary["policy"] == "ship-block-policy/1"
    # The scripted run confirms one critical lane A claim; with the verifier on the red cells' model it
    # is pending distinct verification, never ship_blocking. The two supported claims lack path, guard and
    # exposure evidence, so their severity is unrated (medium-to-critical interval): decision_pending, not the
    # not_ship_blocking the old zero-points scoring gave them.
    assert summary["by_status"] == {"ship_blocking": 0, "ship_blocking_pending_distinct_verification": 1,
                                    "needs_verification": 0, "decision_pending": 2, "not_ship_blocking": 0}
    assert summary["by_lane"]["lead"]["ship_blocking_pending_distinct_verification"] == 1
    assert sum(summary["by_lane"]["hunt"].values()) + sum(summary["by_lane"]["lead"].values()) == len(findings)
    for package in findings.values():
        lane = summary["by_lane"][package["lane"]]
        assert lane[package["ship_block"]["status"]] >= 1
        assert package["ship_block"]["displayed_context"]["decides"] is False
        assert package["independence"]["verifier_model_distinct"] is False
    pending = [item for item in findings.values()
               if item["ship_block"]["status"] == "ship_blocking_pending_distinct_verification"]
    assert [item["ship_block"]["inputs"]["technical_severity"]["rating"] for item in pending] == ["critical"]
    assert pending[0]["ship_block"]["citations"]["score_ids"] == [
        pending[0]["ship_block"]["inputs"]["technical_severity"]["score_id"]]
    assert handoff["verification"]["distinct"] is False and handoff["verification"]["warning"]
    # Decision 4: confirmed packages only in remediation intake; supported ones in the backlog.
    intake = {item["finding_package_id"] for item in handoff["remediation_intake"]}
    backlog = {item["finding_package_id"]: item for item in handoff["verification_backlog"]}
    assert intake == {key for key, item in findings.items() if item["state"] == "confirmed"} and intake
    assert set(backlog) == {key for key, item in findings.items() if item["state"] == "supported"} and backlog
    for key, item in backlog.items():
        assert item["label"] == "unconfirmed" and item["missing_predicates"] == findings[key]["missing_predicates"]
        assert item["missing_predicates"]
    # Decision 8: the handoff names its planned consumers.
    assert [item["job_id"] for item in handoff["planned_consumers"]] == [
        "job_remediation_planning", "job_remediation_validation", "job_final_publication_gate",
        "job_final_report_publication"]


VERIFIER_PROFILE = f"""
[jobs.{JOB}.settings.models.verifier]
provider = "claude-cli"
model = "verifier-test-model"
reasoning = "high"
max_input_tokens = 32000
max_output_tokens = 8000
max_queries = 40
max_turns = 12
timeout_seconds = 600
"""


def test_a_distinct_verifier_profile_moves_the_pending_finding_to_ship_blocking(tmp_path: Path, monkeypatch) -> None:
    """Decision 2 by configuration: roles.independent_verifier.model_profile names a second model."""
    fixture, config = _prepare(tmp_path / "review", tmp_path / "logs", monkeypatch, teams=1,
                               config_overrides={"model_profile": "verifier"}, config_extra=VERIFIER_PROFILE)
    settings = load_config(config).job(JOB).typed_settings
    assert settings.profile_for(Role.INDEPENDENT_VERIFIER).model == "verifier-test-model"
    _in_process(fixture)
    attempt = _attempt(fixture)
    handoff = _handoff(attempt)
    _validator("handoff").validate(handoff)
    assert handoff["verification"]["distinct"] is True and handoff["verification"]["warning"] is None
    assert handoff["ship_block"]["by_status"] == {"ship_blocking": 1, "ship_blocking_pending_distinct_verification": 0,
                                                  "needs_verification": 0, "decision_pending": 2,
                                                  "not_ship_blocking": 0}
    findings = _findings(attempt, handoff)
    [blocking] = [item for item in findings.values() if item["ship_block"]["status"] == "ship_blocking"]
    assert blocking["state"] == "confirmed" and blocking["independence"]["verifier_model_distinct"] is True
    assert blocking["ship_block"]["conditions"]["verifier_model_distinct"] is True
    assert {item["finding_package_id"]: item["ship_block_status"] for item in handoff["remediation_intake"]} == {
        blocking["finding_package_id"]: "ship_blocking"}
    for item in findings.values():
        _validator("finding-package").validate(item)
    captures = sorted((tmp_path / "logs" / "captures").glob("*.json"))
    assert captures and {_json(path)["model"] for path in captures} == {"verifier-test-model"}


def _assert_reference_enrichment(fixture, attempt: Path) -> None:
    """Pinned MITRE validates claim CWEs; advisory leads carry NVD+KEV+EPSS context and stale-feed gaps."""
    schema = json.loads((ROOT / "docs" / "schemas" / "review-packages.schema.json").read_text())
    validator = Draft202012Validator(schema)
    leads, hunts = [], []
    for lane in ("lead", "hunt"):
        document = _json(_unit(attempt, f"packages.assemble_{lane}_packages") / f"{lane}-packages.json")
        assert document["cwe_reference"]["source"] == "mitre_catalog" and document["cwe_reference"]["gap"] is None
        assert {"CWE-120", "CWE-89", "CWE-416"} <= set(document["accepted_cwe_ids"])
        for item in document["packages"]:
            package = _json(fixture.run_root / item["path"])
            validator.validate(package)
            (leads if lane == "lead" else hunts).extend(package["lead_menu"])
    enriched = [lead for lead in leads if lead["advisory_context"]
                and any(advisory["nvd"] and advisory["nvd"][0]["cvss"] for advisory in lead["advisory_context"]["advisories"])
                and lead["advisory_context"]["summary"]["kev_listed"] is True
                and lead["advisory_context"]["summary"]["epss_percentile"] is not None]
    assert [lead["observation_id"] for lead in enriched] == [fixture.ids["dep_high"]]
    assert any(gap.startswith("stale_feed:") for lead in leads if lead["advisory_context"]
               for advisory in lead["advisory_context"]["advisories"] for gap in advisory["gaps"])
    assert any(weakness["source"] == "mitre_catalog" and weakness["abstraction"] for lead in leads
               for weakness in lead["weaknesses"])
    compact = [lead["advisory_summary"] for lead in hunts if lead["advisory_summary"]]
    assert compact and all(set(item) == {"cve_ids", "kev_listed", "epss_percentile", "max_cvss"} for item in compact)
    # impact_class is derived from the pinned catalog's consequences and cites its snapshot (decision 11).
    scoring = _unit(attempt, "scoring.score_claims")
    scores = _json(scoring / "scores.json")
    snapshot = fixture.feed_pins["mitre"]["snapshot_id"]
    assert scores["impact_class"]["rule"] == "cwe-impact-derivation/1"
    assert scores["impact_class"]["catalog"]["status"] == "current"
    assert scores["impact_class"]["catalog"]["snapshot_id"] == snapshot
    derived = []
    for item in scores["scores"]:
        package = _json(scoring / "scores" / item["file"])
        impact = [factor for factor in package["factors"] if factor["factor"] == "impact_class"]
        cited = [citation for citation in package["factor_citations"] if citation["factor"] == "impact_class"]
        if impact and impact[0]["detail"]["basis"] == ["derived"]:
            assert impact[0]["detail"]["catalog_snapshot"] == [snapshot]
            assert cited[0]["references"] and all(reference.startswith(f"mitre-cwe:{snapshot}:")
                                                  for reference in cited[0]["references"])
            derived.append(impact[0]["value"])
    assert derived


def _assert_verifier_blind(logs: Path) -> None:
    captures = sorted((logs / "captures").glob("*.json"))
    assert captures
    markers = [value for key, value in NARRATIVES.items() if key not in {"verifier", "blue"}]
    markers += [NARRATIVES["blue"].split("{claim}")[0]]
    for path in captures:
        text = path.read_text()
        request = json.loads(text)
        assert request["role"] == "independent_verifier"
        assert "statement" not in request["task_input"]["input"]["claim"]
        assert not any(marker in text for marker in markers), path.name
        assert "for the scripted review" not in text            # red relation rationales


def _assert_capabilities_isolated(fixture, attempt: Path) -> None:
    roles = load_registry(ROOT)["roles"]
    guide = "appsec-multi-vuln-guide"
    for lane in ("lead", "hunt"):
        document = _json(_unit(attempt, f"{lane}_review.teams") / "lane.json")
        packages = {item["package_id"]: item for item in _json(
            _unit(attempt, f"packages.assemble_{lane}_packages") / f"{lane}-packages.json")["packages"]}
        for row in document["capabilities"]:
            assert set(row["tools"]) <= set(roles[row["role"]]["tools"]) & IN_PROCESS_TOOLS
            assert set(row["entities"]) <= set(packages[row["package_id"]]["entities"])
            assert not row["entity_prefixes"] and guide not in json.dumps(row)
            # Tools whose schema names a path-like parameter are granted, but that parameter never is.
            assert all(set(TOOL_SCHEMAS[tool]["properties"]) & FORBIDDEN_PARAMETERS <= {"path"} for tool in row["tools"])
            capability = CellCapability.issue(**{key: row[key] for key in (
                "run_id", "manifest_sha256", "package_id", "package_sha256", "round", "tools", "indexes", "entities",
                "entity_prefixes", "max_queries", "max_turns", "page_size", "max_depth", "max_result_bytes")},
                role=Role(row["role"]))
            assert capability.capability_sha256 == row["capability_sha256"]
            outside = fixture.ids["advisory_fact"]           # accepted, but in no package's scope
            assert outside not in row["entities"]
            for request in ({"tool": "find", "parameters": {"path": f"../{guide}/expected.json"}},
                            {"tool": "find", "parameters": {"name": f"/{guide}/expected.json"}},
                            {"tool": "find", "parameters": {"identity": outside}}):
                assert hasattr(capability.authorize(request), "code"), request
    events = [event for lane in ("lead", "hunt") for event in
              _json(_unit(attempt, f"{lane}_review.teams") / "lane.json")["security_events"]]
    assert {event["denial_code"] for event in events} == {"forbidden_parameter", "entity_out_of_scope"}
    receipts = list((fixture.run_root / "data" / "jobs" / JOB / "cells").glob("*/attempt-*.json"))
    assert receipts and not any(guide in path.read_text() for path in receipts)


def test_forcing_a_whole_lane_to_fail_publishes_a_degraded_incomplete_handoff(tmp_path: Path, monkeypatch) -> None:
    fixture, _config = _prepare(tmp_path / "review", tmp_path / "logs", monkeypatch, teams=1,
                                fail_roles=["hypothesis_hunter"])
    _in_process(fixture)
    handoff = _handoff(_attempt(fixture))
    _validator("handoff").validate(handoff)
    lanes = {item["lane"]: item for item in handoff["accounting"]["lanes"]}
    assert handoff["status"] == "DEGRADED" and handoff["accounting"]["review_incomplete"] is True
    assert lanes["hunt"]["outcome"] == "FAILED" and lanes["hunt"]["review_incomplete"] is True
    assert lanes["hunt"]["cells_by_status"]["failed"] == 3 and lanes["hunt"]["claims_total"] == 0
    assert lanes["lead"]["outcome"] == "DEGRADED" and handoff["accounting"]["claims_by_state"]["confirmed"] == 1
    assert handoff["accounting"]["gaps_by_class"]["worker_gap"] >= 4


def test_manifest_naming_an_evaluator_root_fails_startup_and_blocks_publication(tmp_path: Path, monkeypatch) -> None:
    fixture, _config = _prepare(tmp_path / "appsec-multi-vuln-guide" / "review", tmp_path / "logs", monkeypatch,
                                teams=1)
    _in_process(fixture, success=False)
    attempt = _attempt(fixture)
    status = _json(_unit(attempt, "scope.accept_manifest") / "status.json")
    assert status["status"] == "FAILED" and status["error"]["type"] == "IntegrityError"
    assert not (fixture.run_root / "data" / "jobs" / JOB / "latest.json").exists()
    assert not (tmp_path / "logs" / "calls.jsonl").exists()
