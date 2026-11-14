from copy import deepcopy
from dataclasses import replace

import pytest

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.projection import _Projector, link, policy_sha256
from appsec_review.review.decision_audit.publication import AuditUnavailable, publish_bundle
from appsec_review.review.models import CellStatus, IntegrityError, Predicate, RelationKind

from .helpers import BLUE, JUDGE, RED, VERIFIER, digest, document, fixture


def reproject(f, projection):
    f.inputs = replace(f.inputs, projection=projection,
                       origin=replace(f.inputs.origin, projection_sha256=projection.sha256()),
                       projection_document=replace(f.inputs.projection_document, value=projection.to_json()))


@pytest.mark.parametrize("kind", ["split-by-bytes", "single-large", "too-many", "gaps"])
def test_real_reference_capacity_limits(tmp_path, kind):
    f = fixture(tmp_path)
    settings = replace(f.settings, shard_bytes=4096, shard_records=1 if kind == "too-many" else 5000)
    builder = _Projector(f.inputs, settings, f.directory)
    refs = tuple(f.inputs.projection_document.ref(f"ref-{i}") for i in range(600 if kind == "too-many" else 300))
    if kind == "single-large":
        refs = tuple(replace(ref, path="😀" * 1000) for ref in refs)
    kwargs = {"sources": refs, "gaps": tuple(f"gap-{i}" for i in range(257)) if kind == "gaps" else ()}
    if kind == "split-by-bytes":
        context = builder.context(builder.subject(claim="claim"), **kwargs)
        assert len(context.sources) == 256
        assert len(context.continuations) > 1
        assert sum(ref.record_count for ref in context.continuations) == 44
        assert all(ref.byte_count <= 4096 for ref in context.continuations)
    else:
        with pytest.raises(AuditUnavailable):
            builder.context(builder.subject(claim="claim"), **kwargs)


@pytest.mark.parametrize("kind", ["ambiguous", "duplicate-expected", "unexpected-terminal", "missing-terminal",
                                 "verifier-without-claim", "relation-without-producer", "duplicate-finding"])
def test_original_cell_population_constraints(tmp_path, kind):
    f = fixture(tmp_path)
    projection = f.inputs.projection
    if kind == "ambiguous":
        projection = replace(projection, cells={**projection.cells, RED: projection.cells[RED] * 2})
    elif kind == "duplicate-expected":
        f.inputs = replace(f.inputs, additional_expected_cells={RED: "lead"})
    elif kind == "unexpected-terminal":
        lane = deepcopy(f.inputs.lanes[0].value)
        del lane["expected_cells"][BLUE]
        f.inputs = replace(f.inputs, lanes=(replace(f.inputs.lanes[0], value=lane),))
    elif kind == "missing-terminal":
        f.inputs = replace(f.inputs, additional_expected_cells={"expected-missing": "lead"})
    elif kind == "verifier-without-claim":
        projection = replace(projection, cells={**projection.cells, VERIFIER: (
            replace(projection.cells[VERIFIER][0], claim_id=None),)})
    elif kind == "duplicate-finding":
        f.inputs = replace(f.inputs, findings=f.inputs.findings * 2)
    else:
        relations = dict(projection.relations)
        claim = next(iter(relations))
        relations[claim] = (replace(relations[claim][0], producing_cell_id="absent"), *relations[claim][1:])
        projection = replace(projection, relations=relations)
    reproject(f, projection)
    if kind == "missing-terminal":
        result = f.project()
        cells = next(row for row in result.coverage if row.population == c.Population.CELLS)
        assert (cells.expected, cells.emitted, cells.unavailable) == (5, 4, 1)
        assert len([row for row in result.records if isinstance(row, c.DecisionRecord)
                    and row.stage == c.Stage.CELL_EXECUTION]) == 4
    else:
        with pytest.raises(IntegrityError):
            f.project()


@pytest.mark.parametrize("kind", ["missing", "malformed", "unmatched", "unmatched-first", "no-package"])
def test_unrecorded_compact_rationale_stays_absent(tmp_path, kind):
    f = fixture(tmp_path)
    receipt = f.inputs.receipts[RED]
    compact = {"no_claim": ["L1", {"lead": "L2", "why": "recorded reason"}]} if kind == "unmatched-first" else (
        [] if kind == "malformed" else {"no_claim": ["L1"]} if kind == "unmatched" else {})
    f.inputs = replace(f.inputs, receipts={**f.inputs.receipts, RED: replace(
        receipt, value={**receipt.value, "compact_result": compact})},
        packages=() if kind == "no-package" else f.inputs.packages)
    if kind == "malformed":
        with pytest.raises(IntegrityError, match="compact"):
            f.project()
    else:
        row = next(row for row in f.project().records if isinstance(row, c.DecisionRecord)
                   and row.outcome == "explicit_no_claim")
        assert row.context.explanation.text == ("recorded reason" if kind == "unmatched-first" else None)


def test_unknown_lead_population_is_not_complete_empty(tmp_path):
    f = fixture(tmp_path)
    f.inputs = replace(f.inputs, package_sets=())
    row = next(row for row in f.project().coverage if row.population == c.Population.LEADS)
    assert row.expected is None and row.unavailable is None and row.reason == c.CoverageReason.INPUT_UNAVAILABLE


def test_duplicate_original_receipt_proposal_rejected(tmp_path):
    f = fixture(tmp_path)
    receipt = f.inputs.receipts[RED]
    body = deepcopy(receipt.value)
    body["result"]["proposals"] *= 2
    f.inputs = replace(f.inputs, receipts={**f.inputs.receipts, RED: replace(receipt, value=body)})
    with pytest.raises(IntegrityError, match="duplicate proposal"):
        f.project()


@pytest.mark.parametrize("kind", ["predicate", "overlap"])
def test_verifier_reference_limits_are_explicit_not_truncation(tmp_path, kind):
    f = fixture(tmp_path)
    projection = f.inputs.projection
    claim = next(iter(projection.claims))
    base = next(row for row in projection.relations[claim] if row.producing_cell_id == VERIFIER)
    added = []
    for i in range(257):
        predicate = Predicate.AFFECTED_CONSTRUCT if kind == "predicate" else list(Predicate)[i % len(Predicate)]
        row = replace(base, relation_id=f"extra-{i}", predicate=predicate, kind=RelationKind.QUALIFIES,
                      content_sha256=digest(f"content-{i}"), entity_id="asr:source_span:" + digest(str(i)))
        added.append(row)
        if kind == "overlap":
            added.append(replace(row, relation_id=f"other-{i}", producing_cell_id=RED))
    reproject(f, replace(projection, relations={claim: (*projection.relations[claim], *added)}))
    with pytest.raises(AuditUnavailable, match="reference_limit"):
        f.project()


def test_scores_preserve_original_refs_and_do_not_change_scoring(tmp_path):
    f = fixture(tmp_path)
    claim = next(iter(f.inputs.projection.claims))
    scores = [{"score_id": "score-one", "claim_id": claim}]
    f.inputs = replace(f.inputs, scores=replace(f.inputs.scores, value={"scores": scores}))
    result = f.project()
    row = next(row for row in result.records if isinstance(row, c.DecisionRecord) and row.stage == c.Stage.SCORING)
    assert row.context.sources[0].record_id.value == "score-one"
    basis = next(row for row in result.records if isinstance(row, c.DecisionBasisRecord))
    assert [ref.record_id.value for ref in basis.score_refs] == ["score-one"]
    assert f.inputs.scores.value["scores"] == scores


def test_basis_reference_capacity_is_named(tmp_path):
    f = fixture(tmp_path)
    claim = next(iter(f.inputs.projection.claims))
    f.inputs = replace(f.inputs, scores=replace(f.inputs.scores, value={"scores": [
        {"score_id": f"score-{i}", "claim_id": claim} for i in range(257)]}))
    with pytest.raises(AuditUnavailable, match="decision_basis_reference_limit"):
        f.project()


@pytest.mark.parametrize("field,value", [("state", "contradicted"), ("adjudication_id", "foreign")])
def test_finding_cannot_rebind_original_decision(tmp_path, field, value):
    f = fixture(tmp_path)
    finding = f.inputs.findings[0]
    f.inputs = replace(f.inputs, findings=(replace(finding, value={**finding.value, field: value}),))
    with pytest.raises(IntegrityError, match="accepted supported"):
        f.project()


def test_projected_bytes_are_bounded_before_accumulating_large_output(tmp_path):
    settings = DecisionAuditSettings(enabled=True, max_input_bytes=4096, shard_bytes=4096)
    f = fixture(tmp_path, settings=settings)
    with pytest.raises(AuditUnavailable, match="projected_output"):
        f.project()


@pytest.mark.parametrize("kind", ["score-foreign", "score-duplicate", "adjudication-foreign"])
def test_score_and_adjudication_membership_rejects_foreign_claims(tmp_path, kind):
    f = fixture(tmp_path)
    if kind == "adjudication-foreign":
        rows = [*f.inputs.adjudications.value["adjudications"], {"claim_id": "foreign"}]
        f.inputs = replace(f.inputs, adjudications=replace(f.inputs.adjudications, value={"adjudications": rows}))
    else:
        rows = [{"score_id": "score-one", "claim_id": next(iter(f.inputs.projection.claims))}]
        if kind == "score-foreign":
            rows[0]["claim_id"] = "foreign"
        else:
            rows *= 2
        f.inputs = replace(f.inputs, scores=replace(f.inputs.scores, value={"scores": rows}))
    with pytest.raises(IntegrityError):
        f.project()


@pytest.mark.parametrize("continued", [False, True], ids=["inline", "continued"])
def test_original_local_proposal_id_is_scoped_by_its_receipt(tmp_path, continued):
    f = fixture(tmp_path)
    builder = _Projector(f.inputs, f.settings, f.directory)
    one = f.inputs.receipts[RED].ref("p1")
    other = "cell-" + digest("other-red")
    receipt = document(f.root, one.path.replace(RED, other), {
        **f.inputs.receipts[RED].value, "cell_id": other, "attempt_id": f"{other}/attempt-1"})
    two = receipt.ref("p1")
    subject = builder.subject(claim=next(iter(f.inputs.projection.claims)))
    sources = tuple(f.inputs.projection_document.ref(f"ref-{i}") for i in range(256)) if continued else ()
    decision = builder.decision(subject, c.Stage.PROPOSAL_NORMALIZATION, "merged", sources=sources,
                                proposals=(one, two))
    context = decision.context
    proposals = (next(iter(builder.continuations.values())) if continued else context.origin_proposals)
    assert len(proposals) == 2
    assert {row.record_id.value for row in proposals} == {"p1"}
    coverage = tuple(c.CoverageCount(population, int(population == c.Population.DECISIONS),
                                     int(population == c.Population.DECISIONS), 0, 0, None) for population in c.Population)
    publish_bundle(run_root=f.root, attempt_root=f.attempt, origin=f.inputs.origin, settings=f.settings,
                   records=(decision,), coverage=coverage, continuations=builder.continuations)


def test_chain_verifier_terminal_is_preserved_without_fabricating_a_claim(tmp_path):
    f = fixture(tmp_path)
    identity = "cell-" + digest("chain-verifier")
    cell = replace(f.inputs.projection.cells[VERIFIER][0], cell_id=identity, claim_id=None,
                   task="chain_weakest_link_verifier", status=CellStatus.NOT_LAUNCHED, attempts=0,
                   receipt_sha256=None)
    reproject(f, replace(f.inputs.projection, cells={**f.inputs.projection.cells, identity: (cell,)}))
    f.inputs = replace(f.inputs, additional_expected_cells={identity: "hunt"})
    result = f.project()
    row = next(row for row in result.records if isinstance(row, c.DecisionRecord)
               and row.context.subject.cell_id.value == identity)
    assert row.stage == c.Stage.CELL_EXECUTION and row.context.subject.claim_id.value is None
    assert row.context.gap_ids == ("audit:chain_verification_has_no_claim_coverage_contract",)
    coverage = next(row for row in result.coverage if row.population == c.Population.VERIFICATIONS)
    assert (coverage.expected, coverage.emitted, coverage.unavailable) == (2, 1, 1)


def test_judge_keeps_original_package_and_round_after_cross_package_merge(tmp_path):
    f = fixture(tmp_path)
    cell = replace(f.inputs.projection.cells[JUDGE][0], package_id="original-other-package")
    reproject(f, replace(f.inputs.projection, cells={**f.inputs.projection.cells, JUDGE: (cell,)}))
    lane = deepcopy(f.inputs.lanes[0].value)
    next(row for row in lane["capabilities"] if row["cell_id"] == JUDGE)["round"] = 2
    f.inputs = replace(f.inputs, lanes=(replace(f.inputs.lanes[0], value=lane),))
    row = next(row for row in f.project().records if isinstance(row, c.DecisionRecord)
               and row.stage == c.Stage.JUDGE_REVIEW)
    assert row.context.subject.package_id.value == "original-other-package"
    assert row.context.subject.round.value == 2
    assert row.context.subject.adjudication_id.value is None
