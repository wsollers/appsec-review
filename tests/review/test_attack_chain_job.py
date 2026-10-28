"""Real cell transport and inference-job publication, including fail-closed enhancement accounting."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import MappingProxyType

import pytest

from appsec_review.config import load_config
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_inference_security_review import build_job, chains, stages
from appsec_review.jobs.job_inference_security_review.job import _taxonomy
from appsec_review.jobs.job_inference_security_review.teams import ReviewContext
from appsec_review.guidance import load_registry
from appsec_review.observability.events import PipelineLog
from appsec_review.review.budget import JobBudget
from appsec_review.review.identity import make_id
from appsec_review.review.ledger import LedgerWriter, merge_shards, project, verify_chain
from appsec_review.review.models import CellStatus, IntegrityError, Role
from appsec_review.review.teams import ReviewTeamSemaphore
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import file_sha256
from tests.fixtures.inference_review.acceptance import JOB, ROOT, write_config
from tests.fixtures.inference_review.builder import build_accepted_index_set
from tests.fixtures.inference_review.fake_infer import ScriptedInfer
from tests.review.test_attack_chains import (
    PRODUCER, SCHEMAS, accepted_core, claims, ledger_claims,
)


class ChainInfer:
    def __init__(self, *, inner=None, candidates="single", fail=None):
        self.inner, self.mode, self.fail, self.requests = inner, candidates, fail, []

    def __call__(self, request, *, timeout_seconds):
        task, payload = request.task_input["task"], request.task_input["input"]
        if not task.startswith("chain_"):
            return self.inner(request, timeout_seconds=timeout_seconds)
        self.requests.append(request)
        if task == self.fail:
            raise RuntimeError("scripted independent challenge outage")
        if task == "chain_composer":
            components = {item["claim_id"]: item for item in payload["components"]}
            pair = next((item for item in payload["admitted_pairs"]
                         if item["from_claim_id"] == claims()[0].claim_id), payload["admitted_pairs"][0])
            left, right = pair["from_claim_id"], pair["to_claim_id"]
            candidate = {"objective": "obtain service write", "component_claim_ids": [left, right],
                         "edges": [{"output_entity": components[left]["affected_entities"][0],
                                    "input_entity": components[right]["affected_entities"][0]}],
                         "prerequisites": [], "rationale": "PRIVATE COMPOSER RATIONALE"}
            candidates = [candidate]
            if self.mode == "caps":
                candidates += [{**candidate, "rationale": "different uncounted rationale"},
                               {**candidate, "objective": "obtain service read"},
                               {**candidate, "component_claim_ids": [left, make_id("claim", 1, {"unknown": True})]}]
            result = {"candidates": candidates, "gaps": []}
        else:
            chain = payload["chain"]
            result = {"chain_id": chain["chain_id"], "gaps": [], "checks": [
                {"edge_index": index, "dimension": item["dimension"], "stance": "holds",
                 "cites": [ref["relation_id"] for ref in item["evidence"]]}
                for index, edge in enumerate(chain["edges"]) for item in edge["obligations"]]}
        return ModelResult(proposal={"schema": "appsec-review/worker-turn/1", "action": "final", "result": result},
                           input_tokens=100, output_tokens=100)


def context(tmp_path, *, extra=False, bounds=None, model=None):
    core = accepted_core(tmp_path / "accepted")
    settings = load_config(ROOT / "appsec-review.toml").job(JOB).typed_settings
    settings = replace(settings, attack_chains=replace(
        settings.attack_chains, continuity_producers=(PRODUCER,), **(bounds or {})))
    if extra:
        settings = replace(settings, models=MappingProxyType({
            **settings.models, "chain_verifier": replace(settings.models["default"], model="chain-distinct-verifier")}),
            roles=MappingProxyType({**settings.roles, Role.INDEPENDENT_VERIFIER: replace(
                settings.roles[Role.INDEPENDENT_VERIFIER], model_profile="chain_verifier")}))
    vocabulary, crosswalk = _taxonomy(ROOT)
    registry = load_registry(ROOT)
    return ReviewContext(
        run_root=core.run_root, run_id=core.run_id, repository_root=ROOT, settings=settings,
        core=core, infer=model or ChainInfer(), receipts_root=core.run_root / "data" / "jobs" / JOB / "cells",
        budget=JobBudget(tmp_path / "budget", settings.budgets),
        semaphore=ReviewTeamSemaphore.for_run(core.run_root, settings.teams.review_teams),
        vocabulary=vocabulary, crosswalk=crosswalk, covers={},
        role_tools={name: tuple(value.get("tools", ())) for name, value in registry["roles"].items()},
        schemas=SCHEMAS, accepted_cwe_ids=frozenset({"CWE-120"}), rule_predicates={},
        source_languages={}, build_unit_languages={}, index_names=("links",), available_sources=())


def workflow(ctx, *, extra=False, seeds=()):
    root = ctx.run_root / "data" / "chain-tests"
    source = LedgerWriter(root / "claims.jsonl", "adjudication")
    ledger_claims(source)
    source.seal()
    before = project(merge_shards([source.path]).events)
    adjudications = [{"claim_id": item.claim_id, "adjudication_id": make_id("adjudication", 1, {"claim": item.claim_id}),
                     "state": "confirmed", "predicates": []} for item in claims()]
    composition = chains.compose(
        ctx, before, adjudications, extra_verifier_claims={item.claim_id for item in claims()} if extra else set(),
        seeds=seeds, out_dir=root / "proposals", ledger_path=root / "compose.jsonl",
        stream="attack_chains.compose_candidates")
    refutations = chains.challenge(ctx, composition, None, kind="refuter", out_dir=root / "refutations",
                                  ledger_path=root / "refute.jsonl", stream="attack_chains.refute_edges")
    verifications = chains.challenge(ctx, composition, refutations, kind="weakest_link_verifier",
                                    out_dir=root / "chains", ledger_path=root / "verify.jsonl",
                                    stream="attack_chains.verify_weakest_links")
    paths = [source.path, root / "compose.jsonl", root / "refute.jsonl", root / "verify.jsonl"]
    projection = project(merge_shards(paths).events)
    manifest = chains.verify_publication(ctx.run_root, projection, verifications["attack_chain_manifest"],
                                         SCHEMAS, ctx.run_id)
    assert projection.claims == before.claims and projection.relations == before.relations
    assert all(event["kind"] in {"chain_proposed", "chain_challenged", "chain_decided", "cell_terminal", "gap_recorded"}
               for path in paths[1:] for event in verify_chain(path))
    return before, projection, manifest, paths, (composition, refutations, verifications)


def test_native_chain_executes_real_independent_cells_and_publishes_bound_artifacts(tmp_path):
    ctx = context(tmp_path, extra=True)
    before, projection, manifest, _paths, documents = workflow(ctx, extra=True)
    assert manifest["items"][0]["status"] == "confirmed"
    assert manifest["accounting"] == {"proposed": 1, "admitted": 1, "assessed": 1, "capped": 0,
                                      "rejected": 0, "deduplicated": 0, "seeds_received": 0, "seeds_rejected": 0}
    [view] = projection.attack_chains.values()
    assert {item.kind for item in view.challenges} == {"refuter", "weakest_link_verifier"}
    assert all(item.status == "succeeded" and item.independent for item in view.challenges)
    assert all(item.receipt for item in view.challenges)
    assert sum(len(document["expected_cells"]) for document in documents) == 3
    for request in ctx.infer.requests[1:]:
        assert "PRIVATE COMPOSER RATIONALE" not in json.dumps(request.task_input)
        assert "composer" not in request.task_input["input"]["chain"]
        assert not request.transcript
    assert ctx.budget.snapshot().retrieval_queries == 27
    assert stages.base_review_projection(projection, {
        key: lane for document in documents for key, lane in document["expected_cells"].items()}).cells == before.cells
    composer = next(record for records in projection.cells.values() for record in records if record.task == "chain_composer")
    receipt = ctx.receipts_root / composer.cell_id / f"attempt-{composer.attempts}.json"
    receipt.write_text("{}")
    with pytest.raises(IntegrityError, match="changed"):
        chains.verify_publication(ctx.run_root, projection, documents[-1]["attack_chain_manifest"], SCHEMAS, ctx.run_id)


def test_caps_seeds_and_unexplored_frontier_are_exact_without_affecting_base_completeness(tmp_path):
    ctx = context(tmp_path, model=ChainInfer(candidates="caps"), bounds={"max_expansions": 1})
    ctx.settings = replace(ctx.settings, rounds=replace(ctx.settings.rounds, max_attack_chains=1))
    left, right = claims()
    seeds = [{"proposal_claims": {"a": left.claim_id, "b": right.claim_id},
              "seed": {"steps": [{"proposal_id": "a"}, {"proposal_id": "b"}],
                       "rationale": "UNTRUSTED SEED SUCCESS"}},
             {"proposal_claims": {}, "seed": {"steps": [{"proposal_id": "unknown"}]}},
             {"proposal_claims": {"a": left.claim_id}, "seed": {"steps": [{"proposal_id": "a"}] * 2}}]
    _before, projection, manifest, paths, documents = workflow(ctx, seeds=seeds)
    assert manifest["accounting"] == {"proposed": 4, "admitted": 2, "assessed": 1, "capped": 1,
                                      "rejected": 1, "deduplicated": 1, "seeds_received": 3, "seeds_rejected": 2}
    ordered = sorted((left.claim_id, right.claim_id))
    assert manifest["exploration"] == {"expanded": 1, "limit": 1, "frontier": [{
        "from_claim_id": ordered[1], "to_claim_id": ordered[0]}], "frontier_truncated": True}
    capped = next(item for item in manifest["items"] if item["disposition"] == "capped")
    assert capped["status"] == "insufficient_evidence"
    assert "UNTRUSTED SEED SUCCESS" not in json.dumps(ctx.infer.requests[0].task_input)
    assert any(record.status is CellStatus.NOT_LAUNCHED for records in projection.cells.values() for record in records)
    lanes = [{"expected_cells": {}, "packages": {}}]
    original = stages.audit(lanes, paths[:1], 0.0)[0].to_json()
    chain_cells = {key: lane for document in documents for key, lane in document["expected_cells"].items()}
    accounting, _full, _merged = stages.audit(lanes, paths, 0.0, additional_cells=chain_cells)
    assert accounting.to_json() == original
    with pytest.raises(IntegrityError, match="chain cell accounting"):
        stages.audit(lanes, paths, 0.0, additional_cells=dict(list(chain_cells.items())[1:]))
    with pytest.raises(IntegrityError, match="chain cell accounting"):
        stages.audit(lanes, paths, 0.0, additional_cells={**chain_cells, "cell-missing": "hunt"})


@pytest.mark.parametrize("fail", ["chain_refuter", "chain_weakest_link_verifier"])
def test_failed_required_independent_challenge_is_not_confirmed_or_base_review_incompleteness(tmp_path, fail):
    ctx = context(tmp_path, extra=True, model=ChainInfer(fail=fail))
    _before, _projection, manifest, paths, documents = workflow(ctx, extra=True)
    assert manifest["items"][0]["status"] == "insufficient_evidence"
    chain_cells = {key: lane for document in documents for key, lane in document["expected_cells"].items()}
    before = stages.audit([{"expected_cells": {}, "packages": {}}], paths[:1], 0.0)[0]
    after = stages.audit([{"expected_cells": {}, "packages": {}}], paths, 0.0, additional_cells=chain_cells)[0]
    assert before.to_json() == after.to_json()


def test_native_resolution_charges_every_query_and_fails_closed_at_its_bound(tmp_path):
    ctx = context(tmp_path, bounds={"max_queries": 1})
    _before, _projection, manifest, _paths, _documents = workflow(ctx)
    assert manifest["items"][0]["status"] == "insufficient_evidence"
    assert ctx.budget.snapshot().retrieval_queries == 2  # one bounded lookup for composer and refuter
    assert any("budget_exhausted" in gap for gap in manifest["gaps"])


def test_chain_challenge_cell_cap_is_explicit_and_never_promoted_to_confirmation(tmp_path):
    ctx = context(tmp_path, extra=True, bounds={"max_challenge_cells": 0})
    _before, projection, manifest, _paths, _documents = workflow(ctx, extra=True)
    assert manifest["items"][0]["status"] == "insufficient_evidence"
    assert {item.status for view in projection.attack_chains.values() for item in view.challenges} == {"not_launched"}
    assert any("not_launched" in limitation for limitation in manifest["items"][0]["limitations"])
    assert [request.task_input["task"] for request in ctx.infer.requests] == ["chain_composer"]


def test_real_inference_job_handoff_publishes_manifest_metrics_and_no_invented_connections(tmp_path_factory, monkeypatch):
    monkeypatch.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
    directory = tmp_path_factory.mktemp("ac") / "r"
    fixture = build_accepted_index_set(directory)
    config = write_config(directory, fixture.runs_dir)
    infer = ChainInfer(inner=ScriptedInfer({"ids": fixture.ids}))
    job = build_job(infer=infer, repository_root=ROOT)
    runner = JobRunner(load_config(config))
    claim = runner.begin_attempt(job, run_id=fixture.run_id)
    outputs = {}
    for unit in job.units:
        outputs[unit.unit_id] = runner.execute_or_reuse_unit(job, claim, unit.unit_id)
    accepted = runner.finalize_attempt(job, claim)
    assert accepted["handoff"]["status"] == "ACCEPTED"
    handoff = chains.read_artifact(fixture.run_root, {
        key: outputs["publication.publish_handoff"]["artifact"][key] for key in ("path", "sha256")})
    assert handoff["schema"] == "appsec-review/inference-review-handoff/3"
    manifest = chains.read_artifact(fixture.run_root, handoff["attack_chain_manifest"])
    assert manifest["items"] and all(item["status"] == "insufficient_evidence" for item in manifest["items"])
    assert any("no_commissioned_native_continuity_producer" in gap for gap in manifest["gaps"])
    paths = [fixture.run_root / output["ledger_shard"]["path"] for output in outputs.values() if "ledger_shard" in output]
    final = project(merge_shards(paths).events)
    base = project(merge_shards([path for path in paths if "attack_chains" not in path.parts]).events)
    assert final.claims == base.claims and final.relations == base.relations
    assert all(not json.loads(path.read_text())["attack_chains"] for path in (
        fixture.run_root / Path(outputs["publication.publish_handoff"]["artifact"]["path"]).parent / "findings"
    ).glob("*.json"))
    assert manifest["accounting"]["admitted"] == len(final.attack_chains)
    events, errors = PipelineLog(fixture.run_root).read()
    assert not errors
    metrics = [item for item in events if item["event_type"].startswith("INFERENCE_REVIEW_ATTACK_CHAIN")]
    assert [item["event_type"] for item in metrics] == [
        "INFERENCE_REVIEW_ATTACK_CHAIN_COMPOSITION_COMPLETED",
        "INFERENCE_REVIEW_ATTACK_CHAIN_CHALLENGE_COMPLETED",
        "INFERENCE_REVIEW_ATTACK_CHAIN_CHALLENGE_COMPLETED",
        "INFERENCE_REVIEW_ATTACK_CHAINS_PUBLISHED"]
    for metric in metrics:
        details = metric["details"]
        assert details["duration_ms"] >= 0
        assert not any(key in details for key in ("chain_id", "claim_id", "evidence", "prompt"))
    assert file_sha256(fixture.run_root / handoff["attack_chain_manifest"]["path"]) == handoff["attack_chain_manifest"]["sha256"]
