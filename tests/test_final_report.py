"""Acceptance and unit tests for ``job_final_publication_gate`` and ``job_final_report_publication``.

The whole chain runs offline: the scripted deterministic ``Infer`` double drives
``job_inference_security_review`` over the fixture accepted index set, then the gate and the report run
through the application runner exactly as a graph run would. No model, container, network or Dagster
is involved.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator
import pytest
from referencing import Registry, Resource

from appsec_review.config import load_config
from appsec_review.indexing.inventory import Claim, FileClaims, runtime_claims, scan_run_tree
from appsec_review.jobs.job_final_publication_gate import classify as gate_classify
from appsec_review.jobs.job_final_publication_gate.datasets import DATASETS as GATE_DATASETS
from appsec_review.jobs.job_final_publication_gate.settings import FinalPublicationGateSettings
from appsec_review.jobs.job_final_report_publication.datasets import DATASETS as REPORT_DATASETS
from appsec_review.jobs.job_final_report_publication.render import code, plain, render_markdown
from appsec_review.jobs.job_final_report_publication.settings import FinalReportSettings
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.orchestration.topology import describe_wave1, wave1_dependencies
from appsec_review.retrieval.core import RetrievalIntegrityError
from appsec_review.review.models import IntegrityError
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import file_sha256
from tests.final_report_support import GATE, REPORT, Chain, job_tables, run_review_chain
from tests.fixtures.inference_review.acceptance import JOB, ROOT
from tests.fixtures.inference_review.fake_infer import NARRATIVES

# A tampered upstream handoff is refused either when the attempt binds it or when a unit re-verifies it.
INTEGRITY = (IntegrityError, RetrievalIntegrityError)
SCHEMAS = ROOT / "docs" / "schemas" / "final-report"
NAMES = ("common", "final-publication-gate", "final-report")
GATE_DOC = ("acceptance.publish_handoff", "final-publication-gate.json")
REPORT_DOC = ("report.assemble", "final-report.json")
REPORT_MD = ("report.render", "final-report.md")


# ---------------------------------------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def chain(tmp_path_factory) -> Chain:
    """One scripted inference review, gate and report, shared read-only by the tests of this module."""
    root = tmp_path_factory.mktemp("final-report")
    return run_review_chain(root / "review", root / "logs")


@pytest.fixture(scope="module")
def failed_hunt_chain(tmp_path_factory) -> Chain:
    """The same chain with every hunt-lane red cell failing: a DEGRADED, review_incomplete review."""
    root = tmp_path_factory.mktemp("final-report-failed")
    return run_review_chain(root / "review", root / "logs", scenario={"fail_roles": ["hypothesis_hunter"]})


@pytest.fixture
def pristine(chain: Chain):
    """The shared chain with its run tree restored before and after a test that tampers with it."""
    chain.restore()
    yield chain
    chain.restore()


def gate_document(chain: Chain) -> dict[str, Any]:
    return chain.read(GATE, *GATE_DOC)


def report_document(chain: Chain) -> dict[str, Any]:
    return chain.read(REPORT, *REPORT_DOC)


def review_handoff(chain: Chain) -> dict[str, Any]:
    reference = gate_document(chain)["inputs"]["review_handoff"]
    return json.loads((chain.run_root / reference["path"]).read_text(encoding="utf-8"))


def validator(name: str) -> Draft202012Validator:
    documents = [json.loads((SCHEMAS / f"{item}.schema.json").read_text()) for item in NAMES]
    registry = Registry().with_resources((item["$id"], Resource.from_contents(item)) for item in documents)
    return Draft202012Validator(json.loads((SCHEMAS / f"{name}.schema.json").read_text()), registry=registry)


# ---------------------------------------------------------------------------------------------- the chain


def test_inference_gate_and_report_run_end_to_end_without_a_model(chain: Chain) -> None:
    for job_id in (JOB, GATE, REPORT):
        handoff = chain.handoff(job_id)
        assert handoff["status"] == "ACCEPTED" and handoff["job_id"] == job_id
    assert chain.handoff(GATE)["upstream_handoff_sha256"] == {JOB: chain.pointer_sha(JOB)}
    assert chain.handoff(REPORT)["upstream_handoff_sha256"] == {GATE: chain.pointer_sha(GATE)}
    # The scripted review is DEGRADED, so the gate and the report publish with named gaps, not as clean.
    assert review_handoff(chain)["status"] == "DEGRADED"
    assert chain.handoff(GATE)["completion_status"] == "COMPLETED_WITH_GAPS"
    assert chain.handoff(REPORT)["completion_status"] == "COMPLETED_WITH_GAPS"
    # Neither job called a model: they take no model settings and the double was only used by the review.
    for job_id in (GATE, REPORT):
        text = job_tables(job_id)
        assert not re.search(r"(?m)^\s*(model|provider|reasoning|models|max_input_tokens)\b", text)


def test_gate_accounts_for_every_package_in_exactly_one_bucket(chain: Chain) -> None:
    gate, review = gate_document(chain), review_handoff(chain)
    ids = [item["finding_package_id"] for item in review["finding_packages"]]
    assert len(ids) == 3 and sorted(ids) == sorted(item["finding_package_id"] for item in gate["packages"])
    buckets = gate["buckets"]
    listed = [identity for bucket in buckets.values() for identity in bucket]
    assert sorted(listed) == sorted(ids) and len(listed) == len(set(listed))
    assert buckets["publishable"] == sorted(item["finding_package_id"] for item in review["remediation_intake"])
    assert buckets["verification_backlog"] == sorted(item["finding_package_id"] for item in review["verification_backlog"])
    assert buckets["withheld"] == []
    counts = gate["package_counts"]
    assert counts == {"total": 3, "publishable": 1, "verification_backlog": 2, "withheld": 0, "exact": True}
    assert {item["bucket"] for item in gate["packages"]} == {"publishable", "verification_backlog"}
    for item in gate["packages"]:
        assert item["bucket"] == ("publishable" if item["state"] == "confirmed" else "verification_backlog")
        assert item["withheld_reasons"] == []


def test_ship_block_and_claim_states_are_projected_verbatim(chain: Chain) -> None:
    gate, review = gate_document(chain), review_handoff(chain)
    assert gate["ship_block"] == {key: review["ship_block"][key] for key in ("policy", "policy_sha256", "by_status", "by_lane")}
    assert gate["accounting"]["claims_by_state"] == review["accounting"]["claims_by_state"]
    assert gate["gap_ids"] == review["gap_ids"]
    for item in gate["packages"]:
        package = json.loads((chain.run_root / item["path"]).read_text(encoding="utf-8"))
        assert file_sha256(chain.run_root / item["path"]) == item["sha256"]
        assert item["ship_block"]["status"] == package["ship_block"]["status"]
        assert item["ship_block"]["reasons"] == package["ship_block"]["reasons"]
        assert item["state"] == package["state"] and item["label"] == package["label"]
        assert item["ship_block"]["technical_severity"] == package["ship_block"]["inputs"]["technical_severity"]["rating"]
    report = report_document(chain)
    statuses = {item["finding_package_id"]: item["ship_block"]["status"]
                for item in [*report["findings"], *report["verification_backlog"], *report["withheld"]]}
    assert statuses == {item["finding_package_id"]: item["ship_block"]["status"] for item in gate["packages"]}
    # Under the checked-in single-model configuration the confirmed critical finding is pending, never blocking.
    assert report["summary"]["ship_block"]["by_status"]["ship_blocking_pending_distinct_verification"] == 1
    assert report["summary"]["ship_block"]["by_status"]["ship_blocking"] == 0


def test_gate_document_is_schema_valid_and_every_binding_is_hash_pinned(chain: Chain) -> None:
    gate = gate_document(chain)
    validator("final-publication-gate").validate(gate)
    assert SchemaSet(SCHEMAS).errors("final-publication-gate", gate) == []
    bound = {item["path"] for item in gate["bindings"]}
    assert {item["path"] for item in gate["inputs"].values()} <= bound
    assert {item["path"] for item in gate["packages"]} <= bound
    review = review_handoff(chain)
    assert {item["path"] for item in review["shards"]} <= bound
    for item in gate["bindings"]:
        assert file_sha256(chain.run_root / item["path"]) == item["sha256"]
    assert gate["unavailable_inputs"]["attack_chain_manifest"]["state"] == "unavailable"
    assert gate["unavailable_inputs"]["poc_status_manifest"]["state"] == "unavailable"


def test_degraded_review_is_surfaced_as_named_limitations_and_not_a_failure(chain: Chain) -> None:
    gate = gate_document(chain)
    by_id = {item["limitation_id"]: item for item in gate["limitations"]}
    assert gate["review"]["status"] == "DEGRADED" and gate["status"] == "PUBLISHABLE_WITH_LIMITATIONS"
    for identity in ("review_degraded", "gaps_recorded", "lane_degraded", "coverage_incomplete",
                     "pending_distinct_verification", "possible_duplicates"):
        assert by_id[identity]["kind"] == "gap", identity
    assert by_id["gaps_recorded"]["count"] == len(gate["gap_ids"]) > 0
    assert "same model" in by_id["pending_distinct_verification"]["statement"]
    # Remediation planning and validation do not exist yet: named limitations, not failures.
    for identity in ("remediation_planning_not_run", "remediation_validation_not_run", "attack_chain_composition_not_run",
                     "poc_lane_not_run"):
        assert by_id[identity]["kind"] == "not_run", identity
    assert [item["limitation_id"] for item in gate["limitations"]] == [
        identity for identity in gate_classify.LIMITATION_ORDER if identity in by_id]
    assert chain.read(GATE, "acceptance.publish_handoff", "status.json")["status"] == "SUCCEEDED"
    outputs = chain.handoff(GATE)["outputs"]["acceptance.publish_handoff"]
    assert outputs["terminal_status"] == "COMPLETED_WITH_GAPS" and outputs["item_count"] == 3
    assert any(gap.startswith("review_degraded:") for gap in outputs["gaps"])
    assert not any("not_run" in gap or gap.startswith("remediation_") for gap in outputs["gaps"])


def test_review_incomplete_is_never_presented_as_complete(failed_hunt_chain: Chain) -> None:
    chain = failed_hunt_chain
    review = review_handoff(chain)
    assert review["status"] == "DEGRADED" and review["accounting"]["review_incomplete"] is True
    gate = gate_document(chain)
    by_id = {item["limitation_id"]: item for item in gate["limitations"]}
    assert gate["review"]["review_incomplete"] is True and by_id["review_incomplete"]["kind"] == "gap"
    assert "no consumer may present this review as complete" in by_id["review_incomplete"]["statement"]
    assert "hunt FAILED" in by_id["lane_degraded"]["statement"]
    report = report_document(chain)
    assert report["status"] == {"review": "DEGRADED", "review_incomplete": True,
                                "publication": "PUBLISHABLE_WITH_LIMITATIONS", "review_complete": False}
    text = chain.unit_file(REPORT, *REPORT_MD).read_text(encoding="utf-8")
    assert "review presented as complete: **no**" in text and "`review_incomplete` (gap)" in text
    validator("final-report").validate(report)
    assert chain.handoff(REPORT)["completion_status"] == "COMPLETED_WITH_GAPS"
    # Package accounting stays exact even with a failed lane.
    counts = gate["package_counts"]
    assert counts["total"] == counts["publishable"] + counts["verification_backlog"] + counts["withheld"]


def test_report_json_is_schema_valid_and_contains_the_required_sections(chain: Chain) -> None:
    report = report_document(chain)
    validator("final-report").validate(report)
    assert SchemaSet(SCHEMAS).errors("final-report", report) == []
    gate = gate_document(chain)
    assert [item["finding_package_id"] for item in report["findings"]] == gate["buckets"]["publishable"]
    assert [item["finding_package_id"] for item in report["verification_backlog"]] == gate["buckets"]["verification_backlog"]
    assert all(item["state"] == "confirmed" for item in report["findings"])
    assert all(item["state"] == "supported" and item["label"] == "not_independently_confirmed"
               for item in report["verification_backlog"])
    # Score dimensions stay separate per score package; nothing is combined into one number.
    for item in [*report["findings"], *report["verification_backlog"]]:
        assert item["scores"]
        for score in item["scores"]:
            assert {"technical_severity", "exploitability_confidence", "environmental_business_impact",
                    "remediation_priority"} <= set(score)
            assert score["technical_severity"]["rating"] in {"low", "medium", "high", "critical", None}
    assert report["attack_chains"] == {"status": "none_available", "reason": report["attack_chains"]["reason"], "items": []}
    assert report["poc_outcomes"]["status"] == "none_available" and report["poc_outcomes"]["items"] == []
    assert "not built" in report["attack_chains"]["reason"] and "plan-only" in report["poc_outcomes"]["reason"]
    assert report["renderers"]["pdf"]["state"] == "not_rendered"
    assert report["provenance"]["gate_handoff"]["sha256"] == chain.pointer_sha(GATE)
    assert report["provenance"]["gate_document"]["sha256"] == file_sha256(
        chain.unit_file(GATE, *GATE_DOC))
    assert report["provenance"]["ledger_head_sha256"] == review_handoff(chain)["ledger_head_sha256"]


def test_report_artifacts_are_hash_pinned_by_the_accepted_handoff(chain: Chain) -> None:
    handoff = chain.handoff(REPORT)
    outputs = handoff["outputs"]
    json_ref, markdown_ref = outputs["acceptance.publish_handoff"]["artifact"], outputs["report.render"]["artifact"]
    assert json_ref["path"].endswith("/final-report.json") and markdown_ref["path"].endswith("/final-report.md")
    for reference in (json_ref, markdown_ref):
        assert file_sha256(chain.run_root / reference["path"]) == reference["sha256"]
    assert {json_ref["path"], markdown_ref["path"]} <= {item["path"] for item in handoff["artifacts"]}
    assert outputs["acceptance.publish_handoff"]["schema"] == "appsec-review/final-report-handoff/1"


def test_markdown_is_the_deterministic_rendering_of_the_json(chain: Chain) -> None:
    report = report_document(chain)
    settings = load_config(chain.config).job(REPORT).settings
    path = chain.unit_file(REPORT, *REPORT_MD)
    rendered = render_markdown(report, evidence_ids=settings["markdown_evidence_ids"], gap_ids=settings["markdown_gap_ids"])
    assert path.read_bytes() == rendered.encode("utf-8")
    assert rendered == render_markdown(copy.deepcopy(report), evidence_ids=settings["markdown_evidence_ids"],
                                       gap_ids=settings["markdown_gap_ids"])
    # A second report attempt over the same accepted gate is byte-identical, JSON and Markdown.
    first = {name: file_sha256(chain.unit_file(REPORT, *item)) for name, item in (("json", REPORT_DOC), ("md", REPORT_MD))}
    chain.run_report()
    assert len(list((chain.run_root / "data" / "jobs" / REPORT / "attempts").iterdir())) == 2
    second = {name: file_sha256(chain.unit_file(REPORT, *item)) for name, item in (("json", REPORT_DOC), ("md", REPORT_MD))}
    assert first == second
    # Display bounds only shorten identifier lists in Markdown; the JSON is not changed by them.
    short = render_markdown(report, evidence_ids=0, gap_ids=0)
    assert short != rendered and "not listed here" in short
    assert "\r" not in rendered and rendered.endswith("\n") and not rendered.endswith("\n\n")


def test_report_holds_no_exploit_code_prompts_queries_or_narratives(chain: Chain) -> None:
    report = report_document(chain)
    text = json.dumps(report) + chain.unit_file(REPORT, *REPORT_MD).read_text(encoding="utf-8")
    for narrative in NARRATIVES.values():
        assert narrative.split("{")[0].strip() not in text
    forbidden = {"rationale", "prompt", "payload", "exploit", "query", "transcript", "narrative", "snippet", "code"}

    def keys(value: Any):
        if isinstance(value, dict):
            for key, item in value.items():
                yield key
                yield from keys(item)
        elif isinstance(value, list):
            for item in value:
                yield from keys(item)

    assert not forbidden & set(keys(report))
    # A finding projection is a closed, whitelisted shape: identifiers, hashes and accepted summaries only.
    projection = json.loads((SCHEMAS / "common.schema.json").read_text())["$defs"]["finding_projection"]
    assert projection["additionalProperties"] is False and set(projection["properties"]) == set(projection["required"])
    assert set(report["findings"][0]) == set(projection["properties"])


def test_every_run_owned_file_the_jobs_write_is_claimed_by_a_dataset(chain: Chain) -> None:
    steps = {job_id: tuple(load_config(chain.config).job(job_id).steps) for job_id in (GATE, REPORT)}
    claims = runtime_claims(steps) + [Claim(GATE, item.step, item.output_kind, item) for item in GATE_DATASETS] + [
        Claim(REPORT, item.step, item.output_kind, item) for item in REPORT_DATASETS]
    tree = scan_run_tree(chain.run_root, FileClaims(claims), max_files=1_000_000)
    mine = [path for path in tree.unaccounted if path.startswith((f"data/jobs/{GATE}", f"data/jobs/{REPORT}"))]
    assert mine == []
    kinds = {key[2] for key in tree.groups if key[0] in {GATE, REPORT}}
    assert {"publication_gate_decisions", "final_report_publications"} <= kinds
    assert [item.disposition for item in (*GATE_DATASETS, *REPORT_DATASETS)] == ["artifact_only", "artifact_only"]


# ---------------------------------------------------------------------------------------------- integrity


def _first(chain: Chain, key: str) -> dict[str, str]:
    return gate_document(chain)["inputs"][key]


def _append(path: Path) -> None:
    with path.open("ab") as stream:
        stream.write(b"\n")


def _rewrite(path: Path) -> None:
    path.write_bytes(path.read_bytes().replace(b"{", b"{ ", 1))


def _tamper_ledger(chain: Chain) -> None:
    _append(chain.run_root / _first(chain, "claim_ledger")["path"])


def _tamper_projection(chain: Chain) -> None:
    _rewrite(chain.run_root / _first(chain, "projection")["path"])


def _tamper_shard(chain: Chain) -> None:
    _append(chain.run_root / review_handoff(chain)["shards"][0]["path"])


def _tamper_coverage(chain: Chain) -> None:
    _rewrite(chain.run_root / _first(chain, "coverage_matrix")["path"])


def _tamper_finding(chain: Chain) -> None:
    _rewrite(chain.run_root / gate_document(chain)["packages"][0]["path"])


def _tamper_score(chain: Chain) -> None:
    gate = gate_document(chain)
    review = gate["inputs"]["review_handoff"]["path"]
    score = chain.run_root / next(item["path"] for item in gate["bindings"] if "/scores/score-" in item["path"])
    assert review and score.is_file()
    _rewrite(score)


def _tamper_review_handoff(chain: Chain) -> None:
    _rewrite(chain.run_root / _first(chain, "review_handoff")["path"])


def _tamper_accepted_handoff(chain: Chain) -> None:
    _rewrite(chain.run_root / _first(chain, "job_handoff")["path"])


def _tamper_package_manifest(chain: Chain) -> None:
    manifests = sorted((chain.run_root / "data" / "jobs" / JOB).glob("attempts/*/steps/packages/tasks/*/assembly/*manifest*.json"))
    assert manifests
    _rewrite(manifests[0])


@pytest.mark.parametrize("tamper", [
    _tamper_ledger, _tamper_projection, _tamper_shard, _tamper_coverage, _tamper_finding, _tamper_score,
    _tamper_review_handoff, _tamper_package_manifest])
def test_gate_fails_on_any_artifact_changed_after_acceptance(pristine: Chain, tamper) -> None:
    copy_ = pristine
    accepted = copy_.pointer_sha(GATE)
    tamper(copy_)
    with pytest.raises(IntegrityError):
        copy_.run_gate()
    assert copy_.pointer_sha(GATE) == accepted                   # no new gate handoff is accepted
    attempt = sorted((copy_.run_root / "data" / "jobs" / GATE / "attempts").iterdir())[-1]
    assert json.loads((attempt / "steps/load/tasks/verify_review/status.json").read_text())["status"] == "FAILED"
    assert not (attempt / "steps/acceptance/tasks/publish_handoff/final-publication-gate.json").exists()


def test_gate_refuses_a_changed_accepted_review_handoff(pristine: Chain) -> None:
    accepted = pristine.pointer_sha(GATE)
    _tamper_accepted_handoff(pristine)
    with pytest.raises(INTEGRITY):
        pristine.run_gate()
    assert pristine.pointer_sha(GATE) == accepted


def test_gate_requires_an_accepted_review_handoff(pristine: Chain) -> None:
    copy_ = pristine
    (copy_.run_root / "data" / "jobs" / JOB / "latest.json").unlink()
    with pytest.raises(IntegrityError, match="accepted job_inference_security_review handoff is required"):
        copy_.run_gate()


def test_gate_rejects_a_handoff_whose_partition_disagrees_with_its_packages(pristine: Chain) -> None:
    """A rewritten (and re-hashed) handoff still fails: the partition and counts are re-derived from the packages."""
    copy_ = pristine
    gate = gate_document(copy_)
    reference = gate["inputs"]["review_handoff"]
    path = copy_.run_root / reference["path"]
    document = json.loads(path.read_text(encoding="utf-8"))
    moved = document["remediation_intake"].pop()
    document["verification_backlog"].append({**moved, "label": "unconfirmed", "missing_predicates": [],
                                             "gap_ids": [], "ship_block_status": "not_ship_blocking"})
    path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    # Re-pin the rewritten document the way a forger would: through the unit result and the handoff.
    handoff_path = copy_.run_root / reference["path"].split("/steps/")[0] / "handoff.json"
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    handoff["outputs"]["publication.publish_handoff"]["artifact"]["sha256"] = file_sha256(path)
    handoff_path.write_text(json.dumps(handoff, sort_keys=True), encoding="utf-8")
    pointer_path = copy_.run_root / "data" / "jobs" / JOB / "latest.json"
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    pointer["handoff_sha256"] = file_sha256(handoff_path)
    pointer_path.write_text(json.dumps(pointer), encoding="utf-8")
    with pytest.raises(IntegrityError, match="partition|ship-block counts|schema"):
        copy_.run_gate()


def test_report_fails_on_any_artifact_the_gate_bound_changing(pristine: Chain) -> None:
    for tamper in (_tamper_finding, _tamper_ledger, _tamper_review_handoff):
        pristine.restore()
        copy_ = pristine
        accepted = copy_.pointer_sha(REPORT)
        tamper(copy_)
        with pytest.raises(IntegrityError, match="changed after acceptance"):
            copy_.run_report()
        assert copy_.pointer_sha(REPORT) == accepted


def test_report_fails_when_the_gate_document_or_gate_handoff_changes(pristine: Chain) -> None:
    copy_ = pristine
    _rewrite(copy_.unit_file(GATE, *GATE_DOC))
    with pytest.raises(IntegrityError, match="changed after acceptance"):
        copy_.run_report()
    pristine.restore()
    attempt = sorted((copy_.run_root / "data" / "jobs" / GATE / "attempts").iterdir())[-1]
    _rewrite(attempt / "handoff.json")
    with pytest.raises(INTEGRITY):
        copy_.run_report()


def test_report_requires_an_accepted_gate_handoff(pristine: Chain) -> None:
    copy_ = pristine
    (copy_.run_root / "data" / "jobs" / GATE / "latest.json").unlink()
    with pytest.raises(IntegrityError, match="accepted job_final_publication_gate handoff is required"):
        copy_.run_report()


def test_report_cannot_publish_a_markdown_that_is_not_the_rendering_of_its_json(pristine: Chain) -> None:
    from appsec_review.runtime.runner import JobRunner
    from tests.final_report_support import environment, report_job

    copy_ = pristine
    job = report_job()
    with environment(copy_.env):
        runner = JobRunner(load_config(copy_.config))
        claim = runner.begin_attempt(job, run_id=copy_.fixture.run_id, upstream_handoffs={GATE: copy_.pointer_sha(GATE)})
        for unit in job.units[:3]:
            runner.execute_or_reuse_unit(job, claim, unit.unit_id)
        attempt = sorted((copy_.run_root / "data" / "jobs" / REPORT / "attempts").iterdir())[-1]
        markdown = attempt / "steps/report/tasks/render/final-report.md"
        markdown.write_text(markdown.read_text(encoding="utf-8") + "\nA sentence the renderer never wrote.\n",
                            encoding="utf-8")
        with pytest.raises(IntegrityError, match="changed after acceptance|not the rendering"):
            runner.execute_or_reuse_unit(job, claim, "acceptance.publish_handoff")


# ---------------------------------------------------------------------------------------------- classification


@pytest.fixture(scope="module")
def verified(chain: Chain) -> dict[str, Any]:
    return chain.read(GATE, "load.verify_review", "verified-review.json")


def _clean(verified: dict[str, Any]) -> dict[str, Any]:
    """A fully complete review: no gaps, no degraded lane, distinct verification, every package scored."""
    value = copy.deepcopy(verified)
    value["review"] = {**value["review"], "status": "COMPLETE", "review_incomplete": False}
    value["accounting"] = {**value["accounting"], "outcome": "COMPLETE", "review_incomplete": False, "gap_ratio": 0.0,
                           "gaps_by_class": {key: 0 for key in value["accounting"]["gaps_by_class"]}}
    value["lanes"] = [{**lane, "outcome": "COMPLETE", "gapped_cells": 0, "gapped_packages": 0, "cells_missing": 0}
                      for lane in value["lanes"]]
    value["coverage"] = {**value["coverage"], "summary": {"reviewed": value["coverage"]["rows"]}}
    value["verification"] = {**value["verification"], "distinct": True, "warning": None}
    value["gap_ids"], value["possible_duplicate_pairs"] = [], 0
    for package in value["packages"]:
        package["ship_block"] = {**package["ship_block"], "status": "not_ship_blocking", "reasons": []}
        package["gap_ids"] = []
    return value


def test_a_clean_review_is_publishable_and_not_run_stages_never_change_that(verified: dict[str, Any]) -> None:
    result = gate_classify.classify(_clean(verified))
    assert result["status"] == "PUBLISHABLE"
    assert {item["kind"] for item in result["limitations"]} == {"not_run"}
    assert [item["limitation_id"] for item in result["limitations"]] == [
        "remediation_planning_not_run", "remediation_validation_not_run", "attack_chain_composition_not_run",
        "poc_lane_not_run"]
    assert result["package_counts"]["exact"] is True


def test_packages_that_reference_unavailable_poc_or_chain_manifests_are_withheld_with_a_reason(
        verified: dict[str, Any]) -> None:
    value = _clean(verified)
    value["packages"][0]["poc"] = {"status": "plan_generated", "result_id": None}
    value["packages"][1]["attack_chains"] = ["chain-" + "a" * 64]
    value["packages"][2]["poc"] = {"status": "verification_succeeded", "result_id": "pocresult-" + "b" * 64}
    value["packages"][2]["attack_chains"] = ["chain-" + "c" * 64]
    result = gate_classify.classify(value)
    reasons = {item["finding_package_id"]: item["withheld_reasons"] for item in result["packages"]}
    assert sorted(len(item) for item in reasons.values()) == [1, 1, 2]
    assert result["package_counts"] == {"total": 3, "publishable": 0, "verification_backlog": 0, "withheld": 3, "exact": True}
    assert len(result["buckets"]["withheld"]) == 3
    withheld = next(item for item in result["limitations"] if item["limitation_id"] == "withheld_packages")
    assert withheld["kind"] == "gap" and withheld["count"] == 3 and result["status"] == "PUBLISHABLE_WITH_LIMITATIONS"
    # A withheld package keeps its accepted ship-block status; withholding never reclassifies it.
    assert [item["ship_block"]["status"] for item in result["packages"]] == [
        item["ship_block"]["status"] for item in value["packages"]]


def test_a_package_outside_the_handoff_partition_is_an_integrity_failure(verified: dict[str, Any]) -> None:
    value = copy.deepcopy(verified)
    value["partition"] = {"confirmed": [], "supported": value["partition"]["supported"]}
    with pytest.raises(IntegrityError, match="not in the handoff partition"):
        gate_classify.classify(value)
    value = copy.deepcopy(verified)
    value["packages"][0]["state"] = "supported" if value["packages"][0]["state"] == "confirmed" else "confirmed"
    with pytest.raises(IntegrityError, match="not in the handoff partition"):
        gate_classify.classify(value)


def test_unrated_unscored_and_empty_reviews_are_named_gaps(verified: dict[str, Any]) -> None:
    value = _clean(verified)
    value["packages"][0]["ship_block"]["reasons"] = ["technical_severity_unrated"]
    value["packages"][1]["scores"] = []
    value["review"]["status"] = "EMPTY"
    result = gate_classify.classify(value)
    by_id = {item["limitation_id"]: item for item in result["limitations"]}
    assert by_id["technical_severity_unrated"]["count"] == 1 and by_id["findings_without_scores"]["count"] == 1
    assert by_id["review_empty"]["kind"] == "gap" and "not evidence" in by_id["review_empty"]["statement"]
    assert result["status"] == "PUBLISHABLE_WITH_LIMITATIONS"


def test_package_counts_reject_a_package_in_no_bucket() -> None:
    with pytest.raises(IntegrityError, match="no bucket"):
        gate_classify.package_counts([{"bucket": "publishable"}, {"bucket": "mystery"}])


def test_a_clean_report_says_the_review_is_complete(chain: Chain, verified: dict[str, Any]) -> None:
    from appsec_review.jobs.engineering_contracts import FINAL_PUBLICATION_GATE_SCHEMA
    from appsec_review.jobs.job_final_report_publication.report import build_report

    clean = _clean(verified)
    gate = gate_classify.gate_document(FINAL_PUBLICATION_GATE_SCHEMA, clean, gate_classify.classify(clean))
    validator("final-publication-gate").validate(gate)
    report = build_report(gate, gate_handoff=gate["inputs"]["job_handoff"], gate_document=gate["inputs"]["review_handoff"])
    validator("final-report").validate(report)
    assert report["status"]["review_complete"] is True and report["status"]["publication"] == "PUBLISHABLE"
    text = render_markdown(report, evidence_ids=8, gap_ids=16)
    assert "review presented as complete: **yes**" in text and "This review is not complete" not in text
    assert "(not_run)" in text and "(gap)" not in text


# ---------------------------------------------------------------------------------------------- rendering


def test_markdown_neutralises_document_text(chain: Chain) -> None:
    report = copy.deepcopy(report_document(chain))
    baseline = render_markdown(report, evidence_ids=8, gap_ids=16)
    separator = chr(0x2028)
    hostile = "```\n<script>alert(1)</script> | [x](http://evil) " + separator + "\n# injected heading"
    report["findings"][0]["title"] = hostile[:200]
    report["limitations"][0]["statement"] = hostile
    text = render_markdown(report, evidence_ids=8, gap_ids=16)
    lines = text.splitlines()
    assert separator not in text and "\n```" not in text
    # Prose is escaped; a title is a single-line code span that its own content cannot close.
    statement = next(line for line in lines if line.startswith("- `review_degraded`"))
    assert "<script>" not in statement and "\\<script\\>" in statement
    title = next(line for line in lines if line.startswith("### 1. "))
    assert title.startswith("### 1. `") and title.endswith("`") and title.count("`") == 2
    # Hostile text adds no heading: the section structure is exactly the baseline's.
    assert not any(line.startswith("# injected") for line in lines)
    assert [line for line in lines if line.startswith("## ")] == [
        line for line in baseline.splitlines() if line.startswith("## ")]
    assert code("a`b\nc") == "`a'b c`" and plain("*x* <b>") == "\\*x\\* \\<b\\>"


# ---------------------------------------------------------------------------------------------- schemas


@pytest.mark.parametrize("name", NAMES)
def test_schemas_are_valid_draft_2020_12_with_the_final_report_id(name: str) -> None:
    schema = json.loads((SCHEMAS / f"{name}.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == f"https://appsec-review.local/schemas/final-report/{name}.schema.json"
    assert {path.name for path in SCHEMAS.glob("*.json")} == {f"{item}.schema.json" for item in NAMES}


def _mutations(document: dict[str, Any], kind: str):
    """Documents that must each violate the schema, with the rule they break."""
    packages = "packages" if kind == "gate" else "findings"
    counts = (lambda value: value["package_counts"]) if kind == "gate" else (
        lambda value: value["summary"]["package_counts"])
    status = (lambda value: value) if kind == "gate" else (lambda value: value["status"])
    key = "status" if kind == "gate" else "publication"

    def edit(change):
        mutated = copy.deepcopy(document)
        change(mutated)
        return mutated

    yield "extra property", edit(lambda value: value.update(narrative="x"))
    yield "bad schema const", edit(lambda value: value.update(schema="appsec-review/final-report/2"))
    yield "missing limitations", edit(lambda value: value.pop("limitations"))
    yield "inexact accounting", edit(lambda value: counts(value).update(exact=False))
    yield "unknown publication status", edit(lambda value: status(value).update({key: "CLEAN"}))
    yield "bad bucket", edit(lambda value: value[packages][0].update(bucket="elsewhere"))
    yield "bad state", edit(lambda value: value[packages][0].update(state="proposed"))
    yield "bad hash", edit(lambda value: value[packages][0].update(sha256="XYZ"))
    yield "extra finding property", edit(lambda value: value[packages][0].update(statement="free text"))
    yield "combined score", edit(lambda value: value[packages][0]["scores"][0].update(combined=7))


def test_closed_validator_agrees_with_jsonschema_on_valid_and_mutated_documents(chain: Chain) -> None:
    closed = SchemaSet(SCHEMAS)
    for name, kind, document in (("final-publication-gate", "gate", gate_document(chain)),
                                 ("final-report", "report", report_document(chain))):
        assert validator(name).is_valid(document) and closed.errors(name, document) == []
        for label, mutated in _mutations(document, kind):
            assert validator(name).is_valid(mutated) is False, (name, label)
            assert closed.errors(name, mutated), (name, label)


def test_the_two_limitation_kinds_are_the_only_ones_a_document_may_carry(chain: Chain) -> None:
    report = report_document(chain)
    report["limitations"][0]["kind"] = "failure"
    assert not validator("final-report").is_valid(report)
    assert SchemaSet(SCHEMAS).errors("final-report", report)


# ---------------------------------------------------------------------------------------------- wiring


def test_registry_topology_and_terminal_job() -> None:
    from appsec_review.config import load_config as load

    config, registry = load(ROOT / "appsec-review.toml"), builtin_registry()
    assert {GATE, REPORT} <= set(registry.job_ids()) and len(registry.job_ids()) == 37
    assert not {"job_remediation_planning", "job_remediation_validation"} & set(registry.job_ids())
    jobs = {item["job_id"]: item for item in describe_wave1(config, registry)["jobs"]}
    assert jobs[GATE]["dependencies"] == [JOB] and jobs[REPORT]["dependencies"] == [GATE]
    assert {GATE, JOB} <= set(jobs[REPORT]["upstream_handoffs"]) and JOB in jobs[GATE]["upstream_handoffs"]
    depended = {dependency for item in jobs.values() for dependency in item["dependencies"]}
    assert set(jobs) - depended == {REPORT}                       # exactly one terminal job
    assert config.job(GATE).name == "final_publication_gate" and config.job(REPORT).name == "final_report_publication"


def test_disabled_gate_makes_the_report_transparent_and_the_review_terminal() -> None:
    registered = {job_id for job_id in builtin_registry().job_ids() if job_id not in {"job_third_party_data_sync", GATE}}
    dependencies = wave1_dependencies(registered)
    assert REPORT not in dependencies and GATE not in dependencies
    depended = {dependency for values in dependencies.values() for dependency in values}
    assert set(dependencies) - depended == {JOB}
    assert REPORT not in wave1_dependencies(registered - {JOB})


def test_cli_graph_places_the_new_jobs_after_the_review() -> None:
    from appsec_review import cli

    # job_poc_generation sits between the gate and the report; it is disabled by default and so absent from the graph
    assert cli.POST_INDEX_JOB_IDS[-4:] == (JOB, GATE, "job_poc_generation", REPORT)


def test_review_data_indexing_does_not_audit_its_own_consumers() -> None:
    from appsec_review.jobs.job_review_data_indexing.job import registry_providers

    job_ids, declarations, _consumes = registry_providers()
    assert not {JOB, GATE, REPORT} & set(job_ids) and not {GATE, REPORT} & set(declarations)


def test_settings_are_typed_and_strictly_validated() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    assert FinalPublicationGateSettings.from_mapping(config.job(GATE).settings) == FinalPublicationGateSettings(True, 10000)
    settings = FinalReportSettings.from_mapping(config.job(REPORT).settings)
    assert settings == FinalReportSettings(True, 8, 16) and settings.identity() == {
        "markdown_evidence_ids": 8, "markdown_gap_ids": 16}
    for bad in ({"enabled": True}, {"enabled": True, "max_packages": 0}, {"enabled": True, "max_packages": 10001},
                {"enabled": "yes", "max_packages": 5}, {"enabled": True, "max_packages": True},
                {"enabled": True, "max_packages": 5, "model": "x"}):
        with pytest.raises(ValueError, match="jobs.job_final_publication_gate.settings"):
            FinalPublicationGateSettings.from_mapping(bad)
    for bad in ({"enabled": True, "markdown_evidence_ids": -1, "markdown_gap_ids": 1},
                {"enabled": True, "markdown_evidence_ids": 1, "markdown_gap_ids": 257},
                {"enabled": 1, "markdown_evidence_ids": 1, "markdown_gap_ids": 1},
                {"enabled": True, "markdown_evidence_ids": 1}):
        with pytest.raises(ValueError, match="jobs.job_final_report_publication.settings"):
            FinalReportSettings.from_mapping(bad)


def test_datasets_and_handoff_contracts_are_declared() -> None:
    from appsec_review.jobs import engineering_contracts as contracts

    assert contracts.FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA == "appsec-review/final-publication-gate-handoff/1"
    assert contracts.FINAL_REPORT_HANDOFF_SCHEMA == "appsec-review/final-report-handoff/1"
    assert contracts.FINAL_PUBLICATION_GATE_SCHEMA == "appsec-review/final-publication-gate/1"
    assert contracts.FINAL_REPORT_SCHEMA == "appsec-review/final-report/1"
    registry = builtin_registry()
    assert registry.build(GATE).consumes == (JOB,) and registry.build(REPORT).consumes == (
        GATE, "job_poc_generation")
    assert registry.build(GATE).schema_identity == contracts.FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA
    assert registry.build(REPORT).schema_identity == contracts.FINAL_REPORT_HANDOFF_SCHEMA
    # The implementation identity covers the package sources, so a code change re-executes the job.
    assert registry.build(GATE).implementation_identity != registry.build(REPORT).implementation_identity
