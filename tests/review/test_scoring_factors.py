"""score-factors/1 extraction, application_risk_matrix/2, and the scoring stage wiring (decision B1)."""
from __future__ import annotations

from dataclasses import replace
import itertools
import json
from pathlib import Path
import random

import pytest

from appsec_review.jobs.job_inference_security_review import stages
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.retrieval.model import EntityKind, LogicalIdentity
from appsec_review.review.adjudication import adjudicate
from appsec_review.review.claims import normalize_claim
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.ledger import ClaimView, Projection
from appsec_review.review.models import (
    Admissibility, ClaimState, EvidenceRelation, Gap, Lane, Predicate, RelationKind,
)
from appsec_review.review.obligations import ALWAYS_REQUIRED
from appsec_review.review.scoring import (
    ApplicationRiskMatrixV2Provider, ProviderRegistry, ScoreRequest, ScoringProvider, build_provider,
    consumed_factors, default_factor_registry, default_registry, registry_from_settings,
)
from appsec_review.review.scoring.evidence_source import TAGS_PRODUCER_UNAVAILABLE, AcceptedEvidenceSource
from appsec_review.review.scoring.factors import (
    TAGS_NOT_SUPPLIED, Citation, CitationKind, FactorId, FactorInput, FactorSet, FactorValue,
    MissingFactor, ResolvedEntity, TagAssignment, factor_input, locator_path,
)
from appsec_review.review.scoring.risk_model import (
    DEFAULT_MODEL_DOCUMENT, DEFAULT_RISK_MODEL, DimensionModel, RATINGS, RiskModel,
)

ROOT = Path(__file__).parents[2]
SCHEMAS = SchemaSet(ROOT / "docs" / "schemas" / "inference-security-review")
TABLE = {"CWE-120": "high", "CWE-78": "critical", "CWE-200": "medium", "CWE-209": "low"}
SNAP = "target-sha256:" + "2" * 64
SYMBOL = LogicalIdentity.derive(EntityKind.SYMBOL, SNAP, {"n": "copy"}).value
CLAIM = normalize_claim(lane=Lane.LEAD, package_id="p", affected_entities=[SYMBOL], weakness_cwe="CWE-120",
                        security_predicate="unbounded_copy", preconditions=["attacker_controls_request_field"],
                        statement="s", accepted_cwe_ids={"CWE-120"}).claim
ALL = tuple(item for item in FactorId)


def entity(kind: str, native: str = "x") -> str:
    return LogicalIdentity.derive(EntityKind(kind), SNAP, {"n": native}).value


def rel(predicate: Predicate, kind: str = "source_span", *, native: str = "x", claim=CLAIM,
        relation: RelationKind = RelationKind.SUPPORTS, content: str = "0" * 64) -> EvidenceRelation:
    entity_id = entity(kind, native)
    admissibility = Admissibility.DIRECT if kind == "source_span" else Admissibility.DIRECT_FOR_MAPPED_PREDICATE
    body = {"p": predicate.value, "e": entity_id, "k": relation.value, "claim": claim.claim_id}
    return EvidenceRelation(make_id("evidence_relation", 1, body), claim.claim_id, predicate, relation, entity_id,
                            kind, admissibility, "analysis/default", content,
                            "src/copy.c:3-3#b23-55@" + "a" * 64, True, "cell-red", "f" * 64)


def graph_payload(family: str, **result) -> dict:
    return {"family": family, "admissibility": {"direct_eligible": True}, "result": result,
            "scope": {"component_id": "component:0001"}}


def data(relations=(), *, state=ClaimState.CONFIRMED, cwe="CWE-120", entities=None, tags=None, kev=None,
         unresolved=()) -> FactorInput:
    return FactorInput(claim_id=CLAIM.claim_id, adjudication_id="adjudication-" + "1" * 64, claim_state=state,
                       weakness_cwe=cwe, supporting=tuple(relations), entities=entities or {},
                       unresolved=tuple(unresolved), tags=tags, kev_listed=kev)


def extract(value: FactorInput, *factors: FactorId) -> FactorSet:
    return default_factor_registry(TABLE).extract(value, factors or ALL)


# ------------------------------------------------------------------------------------------------ factors


def test_every_factor_is_missing_with_a_reason_when_no_evidence_exists() -> None:
    result = extract(data(cwe=None))
    present = {item.factor for item in result.values}
    assert present == {FactorId.VERIFICATION}
    reasons = {item.factor: item.reason for item in result.missing}
    assert set(reasons) == set(ALL) - {FactorId.VERIFICATION}
    assert all(reason for reason in reasons.values())
    assert reasons[FactorId.EXPOSURE] == TAGS_NOT_SUPPLIED
    assert reasons[FactorId.THREAT] == "no CISA KEV reference input for this claim"
    assert reasons[FactorId.IMPACT_CLASS] == "claim has no weakness CWE"


def test_verification_cites_the_adjudication() -> None:
    for state in (ClaimState.CONFIRMED, ClaimState.SUPPORTED):
        value = extract(data(state=state), FactorId.VERIFICATION).get(FactorId.VERIFICATION)
        assert value.value == state.value
        assert value.citations == (Citation(CitationKind.ADJUDICATION, "adjudication-" + "1" * 64),)
    missing = extract(data(state=ClaimState.CONTRADICTED), FactorId.VERIFICATION)
    assert missing.get(FactorId.VERIFICATION) is None and "not scored" in missing.missing[0].reason


@pytest.mark.parametrize("kind, payload, expected", [
    ("source_span", None, "code_evidence"),
    ("tool_observation", {"producer": "semgrep"}, "tool_observation"),
    ("tool_observation", None, "tool_observation"),
    ("tool_observation", {"producer": "codeql", "query_kind": "path-problem"}, "codeql_path_observation"),
    ("tool_observation", {"producer": "codeql", "rule": {"properties": {"kind": "path-problem"}}},
     "codeql_path_observation"),
    ("tool_observation", {"producer": "codeql", "query_kind": "problem"}, "tool_observation"),
    ("dataflow_path", None, "graph_dataflow_path"),
])
def test_taint_path_basis_and_citations(kind, payload, expected) -> None:
    relation = rel(Predicate.SOURCE_TO_SINK_REACHABILITY, kind)
    entities = {relation.entity_id: ResolvedEntity(relation.entity_id, kind, payload)} if payload else {}
    value = extract(data([relation], entities=entities), FactorId.TAINT_PATH).get(FactorId.TAINT_PATH)
    assert value.value == expected
    assert set(value.citations) == {Citation(CitationKind.EVIDENCE_RELATION, relation.relation_id),
                                    Citation(CitationKind.ENTITY, relation.entity_id)}


def test_taint_path_strongest_basis_wins_and_cites_only_the_winners() -> None:
    weak = rel(Predicate.SOURCE_TO_SINK_REACHABILITY, "source_span")
    strong = rel(Predicate.SOURCE_TO_SINK_REACHABILITY, "dataflow_path")
    other = rel(Predicate.AFFECTED_CONSTRUCT, "dataflow_path", native="y")
    value = extract(data([weak, strong, other]), FactorId.TAINT_PATH).get(FactorId.TAINT_PATH)
    assert value.value == "graph_dataflow_path"
    assert {item.id for item in value.citations} == {strong.relation_id, strong.entity_id}


def test_attacker_control_best_source_class_wins() -> None:
    internal = rel(Predicate.SOURCE_TO_SINK_REACHABILITY, "dataflow_path", native="internal")
    argv = rel(Predicate.ATTACKER_INPUT_CONTROL, "entry_point", native="argv")
    remote = rel(Predicate.ATTACKER_INPUT_CONTROL, "dataflow_path", native="remote")
    entities = {
        internal.entity_id: ResolvedEntity(internal.entity_id, "dataflow_path", graph_payload(
            "dataflow_path", source={"source_class": "internal"})),
        argv.entity_id: ResolvedEntity(argv.entity_id, "entry_point", graph_payload("entry_point",
                                                                                    source_class="argv")),
        remote.entity_id: ResolvedEntity(remote.entity_id, "dataflow_path", graph_payload(
            "dataflow_path", source={"source_class": "remote"})),
    }

    def control(*relations):
        return extract(data(relations, entities=entities), FactorId.ATTACKER_CONTROL).get(FactorId.ATTACKER_CONTROL)

    assert control(internal).value == "internal" and control(internal).detail["source_class"] == ("internal",)
    assert control(internal, argv).value == "local"
    best = control(internal, argv, remote)
    assert best.value == "remote" and {item.id for item in best.citations} == {remote.relation_id, remote.entity_id}
    assert control(rel(Predicate.ATTACKER_INPUT_CONTROL)).value == "direct_unclassified"


def test_attacker_control_needs_a_resolved_payload_for_a_class() -> None:
    path = rel(Predicate.SOURCE_TO_SINK_REACHABILITY, "dataflow_path")
    assert extract(data([path]), FactorId.ATTACKER_CONTROL).get(FactorId.ATTACKER_CONTROL) is None
    ineligible = {path.entity_id: ResolvedEntity(path.entity_id, "dataflow_path", {
        **graph_payload("dataflow_path", source={"source_class": "remote"}),
        "admissibility": {"direct_eligible": False}})}
    assert extract(data([path], entities=ineligible), FactorId.ATTACKER_CONTROL).get(FactorId.ATTACKER_CONTROL) is None
    unclassified = {path.entity_id: ResolvedEntity(path.entity_id, "dataflow_path", graph_payload(
        "dataflow_path", source={"source_class": "unclassified"}))}
    assert extract(data([path], entities=unclassified),
                   FactorId.ATTACKER_CONTROL).get(FactorId.ATTACKER_CONTROL) is None


@pytest.mark.parametrize("kind, expected", [("source_span", "code_evidence"), ("tool_observation", "tool_observation"),
                                            ("guard_fact", "graph_fact"), ("range_fact", "graph_fact")])
def test_guard_absent_basis(kind, expected) -> None:
    relation = rel(Predicate.MISSING_OR_INEFFECTIVE_GUARD, kind)
    value = extract(data([relation]), FactorId.GUARD_ABSENT).get(FactorId.GUARD_ABSENT)
    assert value.value == expected and Citation(CitationKind.EVIDENCE_RELATION, relation.relation_id) in value.citations
    assert extract(data([rel(Predicate.SOURCE_TO_SINK_REACHABILITY)]),
                   FactorId.GUARD_ABSENT).get(FactorId.GUARD_ABSENT) is None


def test_contradicting_relations_never_set_a_factor() -> None:
    against = rel(Predicate.MISSING_OR_INEFFECTIVE_GUARD, "guard_fact", relation=RelationKind.CONTRADICTS)
    assert extract(data([against]), FactorId.GUARD_ABSENT).get(FactorId.GUARD_ABSENT) is None


def tag(name: str, number: int, *, basis: str = "invoked", match: str = "entity") -> TagAssignment:
    return TagAssignment(entity("tag_assignment", f"t{number}"), name, basis, match)


@pytest.mark.parametrize("factor, tags, expected", [
    (FactorId.EXPOSURE, ["surface:entry:cli", "surface:entry:http-public"], "public"),
    (FactorId.EXPOSURE, ["surface:entry:rpc", "surface:entry:env-config"], "internal_network"),
    (FactorId.EXPOSURE, ["surface:entry:file-input"], "local"),
    (FactorId.PRIVILEGE, ["surface:priv:sandboxed", "surface:priv:host"], "elevated"),
    (FactorId.PRIVILEGE, ["surface:priv:sandboxed"], "sandboxed"),
    (FactorId.DATA_SENSITIVITY, ["data:pii", "data:credential"], "secret"),
    (FactorId.DATA_SENSITIVITY, ["data:health"], "sensitive"),
])
def test_tag_factors(factor, tags, expected) -> None:
    assignments = tuple(tag(name, number) for number, name in enumerate(tags))
    value = extract(data(tags=assignments), factor).get(factor)
    assert value.value == expected
    winners = {item.assignment_id for item in assignments if item.tag in value.detail["tag"]}
    assert winners and {item.kind for item in value.citations} == {CitationKind.TAG_ASSIGNMENT}
    assert {item.id for item in value.citations} == winners and value.detail["match"] == ("entity",)


def test_tag_factors_are_missing_not_low_without_matching_tags() -> None:
    empty = extract(data(tags=()), FactorId.EXPOSURE, FactorId.PRIVILEGE, FactorId.DATA_SENSITIVITY)
    assert not empty.values and all("no accepted" in item.reason for item in empty.missing)
    unrelated = extract(data(tags=(tag("surface:boundary:tenant", 1), tag("cwe:79", 2, basis="reported"))),
                        FactorId.EXPOSURE)
    assert unrelated.get(FactorId.EXPOSURE) is None
    reported = extract(data(tags=(tag("surface:entry:http-public", 3, basis="reported"),)), FactorId.EXPOSURE)
    assert reported.get(FactorId.EXPOSURE) is None


def test_impact_class_threat_and_no_epss_field() -> None:
    impact = extract(data(cwe="CWE-78"), FactorId.IMPACT_CLASS).get(FactorId.IMPACT_CLASS)
    assert impact.value == "critical"
    assert impact.citations == (Citation(CitationKind.CONFIGURATION, "cwe_impact_overrides.CWE-78"),)
    assert impact.detail["basis"] == ("override",)
    unmapped = extract(data(cwe="CWE-787"), FactorId.IMPACT_CLASS)
    # No override and no pinned catalog: missing with the catalog gap, never a low value.
    assert unmapped.missing[0].reason.startswith("impact_class not derived: mitre_feed_unavailable")
    assert extract(data(kev=True), FactorId.THREAT).get(FactorId.THREAT).value == "kev_listed"
    assert extract(data(kev=False), FactorId.THREAT).get(FactorId.THREAT).value == "not_listed"
    assert "epss" not in FactorInput.__dataclass_fields__


def test_factor_set_is_deterministic_and_order_independent() -> None:
    relations = [rel(Predicate.SOURCE_TO_SINK_REACHABILITY, "dataflow_path"),
                 rel(Predicate.ATTACKER_INPUT_CONTROL), rel(Predicate.MISSING_OR_INEFFECTIVE_GUARD, "guard_fact")]
    tags = (tag("surface:entry:http-public", 1), tag("data:pii", 2))
    first = extract(data(relations, tags=tags, kev=True))
    shuffled = list(relations)
    random.Random(7).shuffle(shuffled)
    again = default_factor_registry(dict(reversed(list(TABLE.items())))).extract(
        data(shuffled, tags=tuple(reversed(tags)), kev=True), list(reversed(ALL)))
    assert first == again and first.canonical() == again.canonical()
    assert json.dumps(first.canonical(), sort_keys=True) == json.dumps(again.canonical(), sort_keys=True)


def test_factor_values_are_closed_and_cited() -> None:
    with pytest.raises(ValueError, match="not on its scale"):
        FactorValue(FactorId.EXPOSURE, "galactic", (Citation(CitationKind.TAG_ASSIGNMENT, "t"),))
    with pytest.raises(ValueError, match="no citation"):
        FactorValue(FactorId.EXPOSURE, "public", ())
    with pytest.raises(ValueError, match="both present and missing"):
        FactorSet((FactorValue(FactorId.THREAT, "kev_listed", (Citation(CitationKind.REFERENCE_INPUT, "k"),)),),
                  (MissingFactor(FactorId.THREAT, "x"),))


def test_factor_input_counts_only_adjudicated_supporting_relations() -> None:
    counted = rel(Predicate.SOURCE_TO_SINK_REACHABILITY, "dataflow_path")
    uncounted = rel(Predicate.MISSING_OR_INEFFECTIVE_GUARD, "guard_fact")
    predicates = [{"predicate": "source_to_sink_reachability", "supporting": [counted.relation_id]}]
    built = factor_input(claim_id=CLAIM.claim_id, adjudication_id="a", claim_state=ClaimState.SUPPORTED,
                         weakness_cwe="CWE-120", affected_entities=[SYMBOL], predicates=predicates,
                         relations=[counted, uncounted])
    assert built.supporting == (counted,) and built.tags is None
    with pytest.raises(ValueError, match="does not hold"):
        factor_input(claim_id=CLAIM.claim_id, adjudication_id="a", claim_state=ClaimState.SUPPORTED,
                     weakness_cwe=None, affected_entities=[], predicates=predicates, relations=[uncounted])
    assert locator_path("src/a:b.c:3-3#b1-2@" + "a" * 64) == "src/a:b.c"
    assert locator_path("analysis/default:asr:symbol:x") is None


class FakeSource:
    tags_unavailable_reason = "fake tags unavailable"

    def __init__(self, entities, tags):
        self._entities, self._tags, self.calls = entities, tags, []

    def resolve(self, relation):
        self.calls.append(relation.entity_id)
        return self._entities.get(relation.entity_id)

    def tags(self, anchors, paths, components):
        self.seen = (anchors, paths, components)
        return self._tags


def test_factor_input_uses_the_evidence_source_and_records_unresolved_entities() -> None:
    path = rel(Predicate.SOURCE_TO_SINK_REACHABILITY, "dataflow_path")
    span = rel(Predicate.ATTACKER_INPUT_CONTROL)
    resolved = ResolvedEntity(path.entity_id, "dataflow_path", graph_payload(
        "dataflow_path", source={"source_class": "remote"}), "src/copy.c", "component:0001")
    source = FakeSource({path.entity_id: resolved}, (tag("surface:entry:http-public", 1),))
    predicates = [{"supporting": [path.relation_id, span.relation_id]}]
    built = factor_input(claim_id=CLAIM.claim_id, adjudication_id="a", claim_state=ClaimState.CONFIRMED,
                         weakness_cwe="CWE-120", affected_entities=[SYMBOL], predicates=predicates,
                         relations=[path, span], source=source)
    assert built.unresolved == (span.entity_id,) and set(built.entities) == {path.entity_id}
    anchors, paths, components = source.seen
    assert anchors == {SYMBOL, path.entity_id, span.entity_id} and paths == {"src/copy.c"}
    assert components == {"component:0001"}
    factors = extract(built)
    assert factors.get(FactorId.ATTACKER_CONTROL).value == "remote"
    assert factors.get(FactorId.EXPOSURE).value == "public"
    unavailable = FakeSource({}, None)
    built = factor_input(claim_id=CLAIM.claim_id, adjudication_id="a", claim_state=ClaimState.CONFIRMED,
                         weakness_cwe="CWE-120", affected_entities=[SYMBOL], predicates=predicates,
                         relations=[path, span], source=unavailable)
    assert {item.reason for item in extract(built, FactorId.EXPOSURE).missing} == {"fake tags unavailable"}


# ------------------------------------------------------------------------------------------------ evidence source


class FakeCore:
    def __init__(self, entities, excerpts):
        self.entities, self.excerpts = entities, excerpts

    def find(self, *, identity, limit):
        found = self.entities.get(identity)
        return {"results": [found] if found else [], "truncated": False}

    def read_excerpt(self, *, identity, context_lines):
        text = self.excerpts.get(identity)
        return {"results": [{"excerpt": text}] if text is not None else [], "truncated": False}


class FakeStore:
    def __init__(self, rows):
        self.rows = rows

    def entities(self, shards, *, kinds=()):
        return iter(self.rows)


class FakeScope:
    def __init__(self, rows, *, tagging=True):
        from types import SimpleNamespace
        self.components = (SimpleNamespace(identity=entity("component", "svc"), component_id="component:0001",
                                           root="svc"),)
        self.store = FakeStore(rows)
        self._tagging = tagging

    def producer(self, name):
        from types import SimpleNamespace
        assert name == "security_tagging"
        return SimpleNamespace(shards=({"name": "tags"},) if self._tagging else ())

    def component_for(self, path):
        return self.components[0] if path and path.startswith("svc/") else None


def test_accepted_evidence_source_verifies_content_and_matches_tags() -> None:
    from appsec_review.review.evidence import _content_record

    row = {"identity": entity("dataflow_path"), "kind": "dataflow_path", "native_id": "n", "name": "p",
           "payload": graph_payload("dataflow_path", source={"source_class": "argv"}),
           "location": {"path": "svc/a.py"}}
    content = sha256_hex(_content_record(row, "x = argv[1]"))
    relation = rel(Predicate.SOURCE_TO_SINK_REACHABILITY, "dataflow_path", content=content)
    tags = [
        {"identity": "tag-entity", "payload": {"tag": "data:pii", "basis": "invoked",
                                               "subject": {"logical_id": relation.entity_id}}},
        {"identity": "tag-component", "payload": {"tag": "surface:entry:http-public", "basis": "invoked",
                                                  "subject": {"logical_id": "elsewhere",
                                                              "component_id": "component:0001"}}},
        {"identity": "tag-other", "payload": {"tag": "surface:priv:elevated", "basis": "invoked",
                                              "subject": {"logical_id": "o", "component_id": "component:0009"}}},
        {"identity": "tag-broken", "payload": {"tag": "data:pii"}},
    ]
    source = AcceptedEvidenceSource(FakeCore({relation.entity_id: row}, {relation.entity_id: "x = argv[1]"}),
                                    FakeScope(tags))
    resolved = source.resolve(relation)
    assert resolved is not None and resolved.component_id == "component:0001" and resolved.path == "svc/a.py"
    assert source.resolve(replace(relation, content_sha256="1" * 64)) is None          # changed content
    assert AcceptedEvidenceSource(FakeCore({}, {}), FakeScope(tags)).resolve(relation) is None   # vanished
    matched = source.tags({relation.entity_id}, set(), set())
    assert {(item.assignment_id, item.match) for item in matched} == {("tag-entity", "entity")}
    matched = source.tags({relation.entity_id}, {"svc/a.py"}, set())
    assert {(item.assignment_id, item.match) for item in matched} == {("tag-entity", "entity"),
                                                                     ("tag-component", "component")}
    assert source.tags({entity("component", "svc")}, set(), set())[0].assignment_id == "tag-component"
    none = AcceptedEvidenceSource(FakeCore({}, {}), FakeScope(tags, tagging=False))
    assert none.tags(set(), set(), set()) is None and none.tags_unavailable_reason == TAGS_PRODUCER_UNAVAILABLE


# ------------------------------------------------------------------------------------------------ provider


def strong_relations():
    return [rel(Predicate.AFFECTED_CONSTRUCT, native="a"), rel(Predicate.SECURITY_IMPACT, native="b"),
            rel(Predicate.SOURCE_TO_SINK_REACHABILITY, "dataflow_path", native="p"),
            rel(Predicate.ATTACKER_INPUT_CONTROL, "entry_point", native="e"),
            rel(Predicate.MISSING_OR_INEFFECTIVE_GUARD, "guard_fact", native="g")]


def request(factors: FactorSet | None, *, state=ClaimState.CONFIRMED, cwe="CWE-120", **kwargs) -> ScoreRequest:
    return ScoreRequest(claim_id=CLAIM.claim_id, adjudication_id="adjudication-" + "1" * 64, claim_state=state,
                        weakness_cwe=cwe, evidence_relation_ids=("evrel-b", "evrel-a"), environment_sha256=None,
                        policy_sha256="3" * 64, scorer_actor_id="actor-x", factors=factors, **kwargs)


def provider(model: RiskModel = DEFAULT_RISK_MODEL) -> ApplicationRiskMatrixV2Provider:
    return ApplicationRiskMatrixV2Provider(TABLE, model)


def factors_for(value: FactorInput, scorer=None) -> FactorSet:
    scorer = scorer or provider()
    return default_factor_registry(TABLE).extract(value, scorer.consumed_factors)


def test_provider_conforms_and_declares_its_factors() -> None:
    scorer = provider()
    assert isinstance(scorer, ScoringProvider) and consumed_factors(scorer) == frozenset(ALL)
    assert scorer.input_schema()["excluded"] == ["epss"]
    assert scorer.output_schema()["unproduced_dimensions"] == ["remediation_priority"]
    assert consumed_factors(build_provider("application_risk_matrix/1", TABLE)) == frozenset()
    with pytest.raises(ValueError, match="unknown scoring provider implementation"):
        build_provider("application_risk_matrix/9", TABLE)
    with pytest.raises(ValueError, match="takes no risk model"):
        build_provider("application_risk_matrix/1", TABLE, DEFAULT_RISK_MODEL)


def test_confirmed_minimum_evidence_matches_matrix_1_and_supported_needs_more() -> None:
    minimal = [rel(p) for p in ALWAYS_REQUIRED]
    confirmed = provider().score(request(factors_for(data(minimal))))
    assert confirmed.exploitability_confidence.rating == "high" and confirmed.exploitability_confidence.value == 75
    assert confirmed.technical_severity.rating == "high" and confirmed.native["cell"] == ["high", "high"]
    supported = provider().score(request(factors_for(data([rel(Predicate.AFFECTED_CONSTRUCT)],
                                                          state=ClaimState.SUPPORTED)), state=ClaimState.SUPPORTED))
    assert supported.exploitability_confidence.rating == "low"
    assert supported.native["exploitability"]["contributions"] == {"verification": 20}
    assert {"taint_path", "attacker_control", "guard_absent"} <= set(supported.missing_factors)
    assert dict(supported.missing_factor_reasons)["taint_path"].startswith("no counted direct support")


def test_dimensions_stay_separate_and_environmental_needs_its_factors() -> None:
    without = provider().score(request(factors_for(data(strong_relations()))))
    assert without.environmental_business_impact is None and without.remediation_priority is None
    assert {"environmental_business_impact", "remediation_priority"} <= set(without.missing_factors)
    tags = (tag("surface:entry:http-public", 1), tag("data:credential", 2))
    scored = provider().score(request(factors_for(data(strong_relations(), tags=tags))))
    assert scored.environmental_business_impact.scale == "environmental_exposure/1"
    assert scored.environmental_business_impact.rating == "high" and scored.environmental_business_impact.value == 60
    assert scored.technical_severity.scale == "application_risk_matrix/2"
    assert scored.exploitability_confidence.scale == "exploitability_evidence/1"


def test_unmapped_cwe_leaves_technical_severity_null() -> None:
    result = provider().score(request(factors_for(data(strong_relations(), cwe="CWE-787")), cwe="CWE-787"))
    assert result.technical_severity.rating is None and result.native["cell"] is None
    assert {"impact_class", "technical_severity"} <= set(result.missing_factors)
    assert result.exploitability_confidence.rating == "high"


def test_kev_raises_exploitability_one_band_only() -> None:
    weak = [rel(Predicate.AFFECTED_CONSTRUCT)]
    plain = provider().score(request(factors_for(data(weak, state=ClaimState.SUPPORTED, kev=False)),
                                     state=ClaimState.SUPPORTED, kev_listed=False))
    raised = provider().score(request(factors_for(data(weak, state=ClaimState.SUPPORTED, kev=True)),
                                      state=ClaimState.SUPPORTED, kev_listed=True))
    assert (plain.exploitability_confidence.rating, raised.exploitability_confidence.rating) == ("low", "medium")
    assert raised.native["exploitability"]["kev_adjusted"] is True
    assert any("CISA KEV" in item for item in raised.assumptions)
    top = provider().score(request(factors_for(data(strong_relations(), kev=True)), kev_listed=True))
    assert top.exploitability_confidence.rating == "high" and top.native["exploitability"]["kev_adjusted"] is False


def test_provider_rejects_inconsistent_or_absent_factors() -> None:
    registry = ProviderRegistry((provider(),))
    gap = registry.score("application_risk_matrix", request(None))
    assert isinstance(gap, Gap) and "needs the score-factors/1 factors" in gap.reason
    partial = default_factor_registry(TABLE).extract(data(), [FactorId.VERIFICATION])
    assert isinstance(registry.score("application_risk_matrix", request(partial)), Gap)
    supported = factors_for(data(state=ClaimState.SUPPORTED))
    assert "disagrees with the claim state" in provider().validate_inputs(request(supported)).errors[0]
    for state in (ClaimState.CONTRADICTED, ClaimState.INSUFFICIENT_EVIDENCE):
        assert isinstance(registry.score("application_risk_matrix", request(factors_for(data()), state=state)), Gap)


def test_provider_is_deterministic_and_fingerprints_factors_and_config() -> None:
    factors = factors_for(data(strong_relations()))
    first = provider().score(request(factors))
    again = ApplicationRiskMatrixV2Provider(dict(reversed(list(TABLE.items()))), DEFAULT_RISK_MODEL).score(
        request(factors_for(data(list(reversed(strong_relations()))))))
    assert first == again
    weaker = provider().score(request(factors_for(data(strong_relations()[:2]))))
    assert weaker.input_fingerprint != first.input_fingerprint and weaker.score_id != first.score_id
    document = DEFAULT_RISK_MODEL.document()
    document["exploitability"]["bands"] = {"medium": 41, "high": 75}
    retuned = provider(RiskModel.from_document(document)).score(request(factors))
    assert retuned.provider_config_sha256 != first.provider_config_sha256 and retuned.score_id != first.score_id


def test_epss_never_changes_a_v2_result() -> None:
    factors = factors_for(data(strong_relations(), kev=True))
    base = provider().score(request(factors, kev_listed=True))
    for percentile in (0.0, 0.01, 0.5, 0.97, 1.0):
        varied = provider().score(request(factors, kev_listed=True, epss={
            "cve_id": "CVE-2026-0001", "epss": percentile, "percentile": percentile, "score_date": "2026-10-01"}))
        assert varied == base
    assert base.reference_inputs["epss"] is None


# ------------------------------------------------------------------------------------------------ model


def test_default_model_is_valid_and_documented_values_load() -> None:
    assert RiskModel.from_document(DEFAULT_MODEL_DOCUMENT) == DEFAULT_RISK_MODEL
    assert DEFAULT_RISK_MODEL.consumed_factors == frozenset(ALL)


@pytest.mark.parametrize("mutate, message", [
    (lambda d: d["exploitability"]["points"].update({"impact_class": {"low": 1, "medium": 2, "high": 3,
                                                                       "critical": 4}}), "may not use factor"),
    (lambda d: d["exploitability"]["points"].update({"epss": {"x": 1}}), "unknown factor: epss"),
    (lambda d: d["exploitability"]["points"]["taint_path"].pop("code_evidence"), "must give points for exactly"),
    (lambda d: d["exploitability"]["points"]["taint_path"].update(code_evidence=99), "must not decrease"),
    (lambda d: d["exploitability"]["points"]["exposure"].update(local=-1), "between 0 and"),
    (lambda d: d["exploitability"]["points"]["exposure"].update(local=1.5), "integer"),
    (lambda d: d["exploitability"].update(bands={"medium": 75, "high": 75}), "below bands.high"),
    (lambda d: d["exploitability"].update(bands={"medium": 0, "high": 75}), "positive integer"),
    (lambda d: d["exploitability"].update(bands={"medium": 1, "high": 2, "critical": 3}), "exactly medium and high"),
    (lambda d: d["environmental"]["points"].update({"verification": {"supported": 1, "confirmed": 2}}),
     "may not use factor"),
    (lambda d: d["technical_severity"]["high"].update(high="low"), "must not decrease as exploitability rises"),
    (lambda d: d["technical_severity"]["low"].update(high="critical"), "must not decrease as impact class rises"),
    (lambda d: d["technical_severity"].pop("low"), "must map every impact class"),
    (lambda d: d["technical_severity"]["low"].update(high="catastrophic"), "must map every impact class"),
])
def test_invalid_models_are_rejected(mutate, message) -> None:
    document = DEFAULT_RISK_MODEL.document()
    mutate(document)
    with pytest.raises(ValueError, match=message):
        RiskModel.from_document(document)


def test_band_edges_are_inclusive_thresholds() -> None:
    model = DimensionModel("exploitability", {"verification": {"supported": 39, "confirmed": 40},
                                               "guard_absent": {"code_evidence": 35, "tool_observation": 35,
                                                                "graph_fact": 36}},
                           {"medium": 40, "high": 75})

    def rating(state, guard=None):
        relations = [rel(Predicate.MISSING_OR_INEFFECTIVE_GUARD, guard)] if guard else []
        values = default_factor_registry(TABLE).extract(data(relations, state=state), model.factors)
        return model.rate(values)[:2]

    assert rating(ClaimState.SUPPORTED) == ("low", 39)
    assert rating(ClaimState.CONFIRMED) == ("medium", 40)
    assert rating(ClaimState.CONFIRMED, "source_span") == ("high", 75)
    assert rating(ClaimState.SUPPORTED, "source_span") == ("medium", 74)


def _evidence_variants():
    """Every combination of evidence strength for the exploitability factors, weakest to strongest."""
    options = {
        "taint": [None, "source_span", "tool_observation", "dataflow_path"],
        "control": [None, "internal", "direct", "argv", "remote"],
        "guard": [None, "source_span", "guard_fact"],
        "exposure": [None, "surface:entry:cli", "surface:entry:rpc", "surface:entry:http-public"],
    }
    for combo in itertools.product(*options.values()):
        yield dict(zip(options, combo))


def _input_for(variant, state=ClaimState.SUPPORTED) -> FactorInput:
    relations, entities, tags = [], {}, ()
    if variant["taint"]:
        relations.append(rel(Predicate.SOURCE_TO_SINK_REACHABILITY, variant["taint"], native="taint"))
    if variant["control"] == "direct":
        relations.append(rel(Predicate.ATTACKER_INPUT_CONTROL, native="control"))
    elif variant["control"]:
        relation = rel(Predicate.ATTACKER_INPUT_CONTROL, "entry_point", native="control")
        relations.append(relation)
        entities[relation.entity_id] = ResolvedEntity(relation.entity_id, "entry_point", graph_payload(
            "entry_point", source_class=variant["control"]))
    if variant["guard"]:
        relations.append(rel(Predicate.MISSING_OR_INEFFECTIVE_GUARD, variant["guard"], native="guard"))
    if variant["exposure"]:
        tags = (tag(variant["exposure"], 1),)
    return data(relations, state=state, entities=entities, tags=tags)


def test_monotonicity_stronger_evidence_never_lowers_exploitability() -> None:
    scorer = provider()
    order = {"taint": [None, "source_span", "tool_observation", "dataflow_path"],
             "control": [None, "internal", "direct", "argv", "remote"],
             "guard": [None, "source_span", "guard_fact"],
             "exposure": [None, "surface:entry:cli", "surface:entry:rpc", "surface:entry:http-public"]}
    cache = {}

    def points(variant, state):
        key = (tuple(sorted(variant.items(), key=lambda pair: pair[0])), state)
        if key not in cache:
            result = scorer.score(request(factors_for(_input_for(variant, state), scorer), state=state))
            cache[key] = (result.exploitability_confidence.value,
                          RATINGS.index(result.exploitability_confidence.rating),
                          ["low", "medium", "high", "critical"].index(result.technical_severity.rating))
        return cache[key]

    for variant in _evidence_variants():
        for state in (ClaimState.SUPPORTED, ClaimState.CONFIRMED):
            base = points(variant, state)
            if state is ClaimState.SUPPORTED:
                stronger = points(variant, ClaimState.CONFIRMED)
                assert all(b <= s for b, s in zip(base, stronger))
            for name, values in order.items():
                position = values.index(variant[name])
                if position + 1 < len(values):
                    stronger = points({**variant, name: values[position + 1]}, state)
                    assert all(b <= s for b, s in zip(base, stronger)), (variant, name)


# ------------------------------------------------------------------------------------------------ stage wiring


def adjudicated(relations, independent=True):
    decision = adjudicate(CLAIM, relations, independent, {SYMBOL}, ())
    record = stages.adjudication_json(decision)
    projection = Projection(head="h" * 64, claims={CLAIM.claim_id: ClaimView(CLAIM, (), ())},
                            relations={CLAIM.claim_id: tuple(relations)}, gaps=(), cells={})
    return record, projection


def run_stage(tmp_path: Path, relations, *, name="run", references=None, overrides=None, **kwargs):
    record, projection = adjudicated(relations)
    out = tmp_path / name / "scores"
    out.mkdir(parents=True)
    document = stages.score_claims([record], projection, TABLE if overrides is None else overrides, out,
                                   tmp_path / name / "ledger.jsonl", "scoring", SCHEMAS, references=references,
                                   **kwargs)
    packages = {item["file"]: (out / item["file"]).read_bytes() for item in document["scores"]}
    return document, packages


def test_stage_scores_with_factors_and_writes_a_valid_package(tmp_path: Path) -> None:
    document, packages = run_stage(tmp_path, strong_relations())
    assert document["providers"] == ["application_risk_matrix/2"] and len(packages) == 1
    package = json.loads(next(iter(packages.values())))
    SCHEMAS.validate("score-package", package)
    assert package["schema"] == "appsec-review/score-package/2"
    assert package["provider"]["implementation"] == "application_risk_matrix/2"
    assert package["scorer"] == stages.scorer_actor("application_risk_matrix/2")
    factors = {item["factor"]: item["value"] for item in package["factors"]}
    assert factors["taint_path"] == "graph_dataflow_path" and factors["guard_absent"] == "graph_fact"
    assert factors["verification"] == "confirmed" and factors["impact_class"] == "high"
    # Without an evidence source the entry point's class is unknown: control is shown, not classified.
    assert factors["attacker_control"] == "direct_unclassified"
    citations = {item["factor"]: item for item in package["factor_citations"]}
    assert set(citations) == set(factors)
    assert citations["impact_class"]["references"] == ["cwe_impact_overrides.CWE-120"]
    assert set(citations["taint_path"]["evidence_relations"]) <= set(package["evidence_relations"])
    reasons = {item["factor"]: item["reason"] for item in package["missing_factor_reasons"]}
    assert reasons["exposure"] == TAGS_NOT_SUPPLIED and "remediation_priority" in reasons
    assert set(reasons) == set(package["missing_factors"])


def test_stage_uses_the_evidence_source_for_payload_and_tag_factors(tmp_path: Path) -> None:
    relations = strong_relations()
    control = relations[3]
    source = FakeSource({control.entity_id: ResolvedEntity(control.entity_id, "entry_point", graph_payload(
        "entry_point", source_class="remote"))}, (tag("surface:entry:http-public", 1), tag("data:pii", 2)))
    _, packages = run_stage(tmp_path, relations, evidence=source)
    package = json.loads(next(iter(packages.values())))
    factors = {item["factor"]: item["value"] for item in package["factors"]}
    assert factors["attacker_control"] == "remote" and factors["exposure"] == "public"
    assert package["environmental_business_impact"]["rating"] == "high"
    tags = {item["factor"]: item["tag_assignments"] for item in package["factor_citations"]}
    assert tags["exposure"] == [entity("tag_assignment", "t1")]


def test_stage_selects_providers_from_settings(tmp_path: Path) -> None:
    from types import SimpleNamespace

    settings = SimpleNamespace(enabled_providers=("cvss_v4", "application_risk_matrix"), cwe_impact_overrides=TABLE,
                               providers={"application_risk_matrix": SimpleNamespace(
                                   implementation="application_risk_matrix/1", model=None)})
    assert registry_from_settings(settings).ids() == ("application_risk_matrix",)
    document, packages = run_stage(tmp_path, strong_relations(), scoring=settings)
    package = json.loads(next(iter(packages.values())))
    assert document["providers"] == ["application_risk_matrix/1"]
    assert package["factors"] == [] and package["factor_citations"] == []
    assert package["scorer"] == stages.SCORER_ACTOR
    SCHEMAS.validate("score-package", package)


def test_stage_never_scores_unsupported_claims(tmp_path: Path) -> None:
    document, packages = run_stage(tmp_path, [])
    assert document["scores"] == [] and packages == {}


def test_varying_epss_leaves_the_score_package_byte_identical(tmp_path: Path) -> None:
    def references(epss):
        return {CLAIM.claim_id: {"reference_cvss": [], "kev_listed": True, "epss": epss}}

    _, base = run_stage(tmp_path, strong_relations(), name="none", references=references(None))
    for index, percentile in enumerate((0.0, 0.42, 0.97, 1.0)):
        _, varied = run_stage(tmp_path, strong_relations(), name=f"epss{index}", references=references(
            {"cve_id": "CVE-2026-0001", "epss": percentile / 2, "percentile": percentile,
             "score_date": "2026-10-01"}))
        assert varied == base
    package = json.loads(next(iter(base.values())))
    assert package["reference_inputs"]["epss"] is None and package["reference_inputs"]["kev_listed"] is True


def test_scoring_never_promotes_or_changes_claim_state(tmp_path: Path) -> None:
    relations = [rel(Predicate.AFFECTED_CONSTRUCT)]
    record, projection = adjudicated(relations, independent=False)
    assert record["state"] == "supported"
    document, packages = run_stage(tmp_path, relations, evidence=FakeSource({}, (tag("surface:entry:http-public", 1),)))
    package = json.loads(next(iter(packages.values())))
    assert {item["factor"]: item["value"] for item in package["factors"]}["verification"] == "supported"
    assert projection.claims[CLAIM.claim_id].claim.state is ClaimState.PROPOSED
    ledger = (tmp_path / "run" / "ledger.jsonl").read_text(encoding="utf-8")
    assert "state_transition" not in ledger and "transition" not in ledger


def test_default_registry_is_matrix_2(tmp_path: Path) -> None:
    assert default_registry(TABLE).get("application_risk_matrix").implementation_version == "application_risk_matrix/2"
