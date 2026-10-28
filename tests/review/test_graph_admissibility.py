"""R3 graph-fact admissibility (``evidence-admissibility/3``) and its review integration.

docs/architecture/code-graph-precomputation.md sections 6 and 7.5: graph kinds are
``DIRECT_FOR_MAPPED_PREDICATE`` only for the predicate the family's mapping names (with its
source-class condition) and only when the payload re-resolved from the accepted manifest is
direct-eligible; ``flow_summary`` and ineligible facts are ``INDIRECT``.
"""
from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from appsec_review.graph.contract import (
    AUTHORITY, CATALOG_SCHEMA, CROSS_CHECK_RULE, GRAPH_FACT_SCHEMA, NORMALIZE_RULE, Family, GraphFact, SourceClass,
    admissibility, fact_identity,
)
from appsec_review.guidance import load_registry
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, RelationKind as IndexRelation, RelationRecord,
    RetrievalCore, RetrievalLimits, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.review import adjudication, obligations
from appsec_review.review.evidence import (
    ADMISSIBILITY_RULES_VERSION, GRAPH_KINDS, classify, graph_fact_predicates, resolve_relation, satisfies,
)
from appsec_review.review.independence import ActorRecord, verify_independence
from appsec_review.review.models import (
    Admissibility, EvidenceRelation, Gap, Lane, Predicate, RelationKind,
)
from appsec_review.storage import atomic_json, file_sha256

ROOT = Path(__file__).resolve().parents[2]
RUN_ID = "2026-10-12-0001"
SNAPSHOT = "target-sha256:" + "2" * 64
CLAIM = "claim-" + "c" * 64
CELL = "cell-" + "d" * 64
RECEIPT = "e" * 64
SCOPE_ID = "codeql:c/c++:native-main:" + "9" * 16
P = Predicate
# Written out literally (not imported) so the test pins the decided table: user decision A2.
ATTACKER_REACHABLE = {"remote", "local_user", "argv", "environment", "file", "ipc"}
SOURCE = "void copy(char *in) {\n  char buf[8];\n  strcpy(buf, in);\n  if (in) {}\n}\n"


# ------------------------------------------------------------------------------------------------
# Graph-fact construction through the shared contract (also used by test_packages_graph_context)

def graph_payload(family: Family | str, result: Mapping[str, Any], *, exact: bool = True,
                  coverage: str = "complete", cross_check: str = "not_covered",
                  build_unit_id: str = "native-main", component_id: str = "component:0002") -> dict[str, Any]:
    """A contract-valid ``graph-fact/1`` payload whose admissibility block is the computed one."""
    payload: dict[str, Any] = {
        "schema": GRAPH_FACT_SCHEMA, "family": Family(family).value,
        "producer": {"name": "codeql-export", "tool_version": "2.27.0", "export_pack_sha256": "a" * 64,
                     "catalog_version": CATALOG_SCHEMA, "rule_version": NORMALIZE_RULE},
        "scope": {"scope_id": SCOPE_ID, "language": "c/c++", "build_unit_id": build_unit_id,
                  "component_id": component_id},
        "exact": exact, "coverage_status": coverage, "gaps": [] if coverage == "complete" else ["bound reached"],
        "cross_check": {"rule": CROSS_CHECK_RULE, "state": cross_check, "producers": []},
        "result": dict(result), "upstream": [], "authority": AUTHORITY,
    }
    payload["admissibility"] = admissibility(payload)
    return payload


def graph_entity(family: Family | str, native: Mapping[str, Any], result: Mapping[str, Any],
                 location: SourceLocation | None, *, snapshot: str = SNAPSHOT, name: str | None = None,
                 **options: Any) -> EntityRecord:
    """One graph fact as an index entity, validated by ``GraphFact.to_entity``."""
    family = Family(family)
    payload = graph_payload(family, result, **options)
    identity = fact_identity(family, snapshot, {"scope_id": SCOPE_ID, **native})
    return GraphFact(identity, name or f"{family.value}:{identity.value[-8:]}", payload, location).to_entity()


def results_for(family: Family, source_class: str = "remote", *, sink: str | None = None,
                entry: str | None = None) -> dict[str, Any]:
    """A minimal family result honoring the classes graph-fact-admissibility/1 reads."""
    sink = sink or "asr:sink_site:" + "1" * 64
    entry = entry or "asr:entry_point:" + "2" * 64
    return {
        Family.CALL_SITE: {"caller": {"symbol": None, "display": "copy"},
                           "callee": {"symbol": None, "display": "strcpy", "dispatch": "external_undefined",
                                      "candidate_count": 0}},
        Family.SINK_SITE: {"sink_class": "memory_write", "cwe_family": "CWE-787", "argument_index": 0},
        Family.ENTRY_POINT: {"source_class": source_class, "api_or_parameter": {"display": "in"}},
        Family.FLOW_SUMMARY: {"function": {"symbol": None}, "pairs": [], "k_limited": False},
        Family.DATAFLOW_PATH: {"source": {"entry_point": entry, "source_class": source_class},
                               "sink": {"sink_site": sink, "sink_class": "memory_write", "cwe_family": "CWE-787"},
                               "steps": [], "hop_count": 1, "truncated_steps": False},
        Family.GUARD_FACT: {"sink": {"sink_site": sink}, "guard_state": "none", "polarity": "unknown",
                            "constrains_sink_operand": "unknown", "comparison": None,
                            "destination": {"object_bytes": None}},
        Family.RANGE_FACT: {"sink": {"sink_site": sink}, "operand_index": 2, "interval": "unknown"},
    }[family]


def expected_direct(family: Family, source_class: str, eligible: bool) -> set[Predicate]:
    """The decided graph-fact-predicates/1 table, independent of the contract helper."""
    if not eligible:
        return set()
    attacker = source_class in ATTACKER_REACHABLE
    return {
        Family.CALL_SITE: {P.AFFECTED_CONSTRUCT},
        Family.SINK_SITE: {P.AFFECTED_CONSTRUCT},
        Family.ENTRY_POINT: {P.ATTACKER_INPUT_CONTROL} if attacker else set(),
        Family.FLOW_SUMMARY: set(),
        Family.DATAFLOW_PATH: {P.SOURCE_TO_SINK_REACHABILITY} | ({P.ATTACKER_INPUT_CONTROL} if attacker else set()),
        Family.GUARD_FACT: {P.MISSING_OR_INEFFECTIVE_GUARD},
        Family.RANGE_FACT: {P.MISSING_OR_INEFFECTIVE_GUARD},
    }[family]


# ------------------------------------------------------------------------------------------------
# classify truth table


CLASS_SENSITIVE = (Family.ENTRY_POINT, Family.DATAFLOW_PATH)
CELLS = [(family, source_class, eligible)
         for family in Family
         for source_class in ([item.value for item in SourceClass] if family in CLASS_SENSITIVE else ["remote"])
         for eligible in (True, False)]


@pytest.mark.parametrize(("family", "source_class", "eligible"), CELLS,
                         ids=[f"{f.value}-{c}-{'eligible' if e else 'ineligible'}" for f, c, e in CELLS])
def test_classify_truth_table(family: Family, source_class: str, eligible: bool) -> None:
    payload = graph_payload(family, results_for(family, source_class),
                            cross_check="not_covered" if eligible else "disagree")
    if source_class == "unclassified":     # an unclassified source is never direct-eligible
        assert payload["admissibility"]["direct_eligible"] is False
        eligible_now = False
    else:
        assert payload["admissibility"]["direct_eligible"] is eligible
        eligible_now = eligible
    expected = expected_direct(family, source_class, eligible_now)
    for predicate in Predicate:
        want = Admissibility.DIRECT_FOR_MAPPED_PREDICATE if predicate in expected else Admissibility.INDIRECT
        # A tool-rule mapping never widens a graph kind.
        assert classify(family.value, predicate, tuple(Predicate), payload) is want, (family, predicate)


@pytest.mark.parametrize("reason", ["inexact", "partial", "disagree", "partial_cross_check", "unclassified_sink"])
def test_every_ineligibility_condition_makes_a_graph_fact_indirect(reason: str) -> None:
    result = results_for(Family.SINK_SITE)
    options: dict[str, Any] = {}
    if reason == "inexact":
        options["exact"] = False
    elif reason == "partial":
        options["coverage"] = "partial"
    elif reason == "disagree":
        options["cross_check"] = "disagree"
    elif reason == "partial_cross_check":
        options["cross_check"] = "partial"
    else:
        result = {**result, "sink_class": "unclassified"}
    payload = graph_payload(Family.SINK_SITE, result, **options)
    assert payload["admissibility"]["direct_eligible"] is False
    assert {classify("sink_site", predicate, (), payload) for predicate in Predicate} == {Admissibility.INDIRECT}


def test_graph_kinds_without_a_resolved_payload_are_indirect() -> None:
    assert GRAPH_KINDS == {EntityKind(family.value) for family in Family}
    for kind in GRAPH_KINDS:
        assert {classify(kind, predicate, tuple(Predicate)) for predicate in Predicate} == {Admissibility.INDIRECT}


def test_unknown_or_mismatched_graph_payloads_are_default_deny() -> None:
    good = graph_payload(Family.SINK_SITE, results_for(Family.SINK_SITE))
    assert classify("sink_site", P.AFFECTED_CONSTRUCT, (), good) is Admissibility.DIRECT_FOR_MAPPED_PREDICATE
    forged: list[dict[str, Any]] = []
    for mutate in (
        lambda value: value.update(family="call_site"),                         # kind/family mismatch
        lambda value: value.update(family="aliases"),                           # unknown family
        lambda value: value.update(schema="appsec-review/graph-fact/2"),        # unknown schema
        lambda value: value["admissibility"].update(rule="graph-fact-admissibility/0"),
        lambda value: value["admissibility"].update(direct_eligible="true"),    # not the boolean true
        lambda value: value["admissibility"].update(ineligibility_reasons=["cross_check_disagree"]),
        lambda value: value.pop("admissibility"),
        # The published flag lies: the conditions re-check as ineligible.
        lambda value: value["cross_check"].update(state="disagree"),
        lambda value: value.update(exact=False),
    ):
        changed = copy.deepcopy(good)
        mutate(changed)
        forged.append(changed)
    for payload in forged:
        assert {classify("sink_site", predicate, (), payload) for predicate in Predicate} == {
            Admissibility.INDIRECT}, payload
    # A sink payload cited as another graph kind satisfies nothing.
    assert graph_fact_predicates("call_site", good) == frozenset()
    # A graph payload never changes a non-graph kind's classification.
    assert classify("priority_item", P.AFFECTED_CONSTRUCT, (), good) is Admissibility.INDIRECT
    assert classify("tool_observation", P.AFFECTED_CONSTRUCT, (), good) is Admissibility.INDIRECT
    # predicate-admission/2: a source span is direct only for the construct it is.
    assert classify("source_span", P.AFFECTED_CONSTRUCT, (), None) is Admissibility.DIRECT
    assert classify("source_span", P.SECURITY_IMPACT, (), None) is Admissibility.ANALYST_ASSESSED
    with pytest.raises(ValueError):
        classify("graph_fact", P.AFFECTED_CONSTRUCT, (), good)


# ------------------------------------------------------------------------------------------------
# Re-resolution against an accepted manifest


def _location(source: Path, needle: str) -> SourceLocation:
    text = source.read_text(encoding="utf-8")
    start = text.index(needle)
    line = text[:start].count("\n") + 1
    end_line = line + needle.count("\n")
    column = start - (text.rfind("\n", 0, start) + 1) + 1
    end_column = len(needle) - needle.rfind("\n") if "\n" in needle else column + len(needle)
    return SourceLocation(SNAPSHOT, "src/copy.c", file_sha256(source), start, start + len(needle), line, end_line,
                          column, end_column, {}, "codeql-location-exact", 1.0)


def accepted_graph_run(tmp_path: Path, extra: Any = None) -> tuple[Path, dict[str, str]]:
    """A minimal accepted index set whose ``graph`` shard holds eligible and ineligible facts.

    ``extra(ids, add, condition, sink_span, call)`` may add further entities through ``add(key, entity)``.
    """
    runs = tmp_path / "runs"
    run_root = runs / RUN_ID
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    source = target / "src" / "copy.c"
    source.write_text(SOURCE, encoding="utf-8")
    call = _location(source, "strcpy(buf, in)")
    sink_span = _location(source, "buf")
    param = _location(source, "char *in")
    condition = _location(source, "if (in)")
    ids: dict[str, str] = {}
    entities: list[EntityRecord] = []

    def add(key: str, entity: EntityRecord) -> None:
        ids[key] = entity.identity.value
        entities.append(entity)

    span = {"path": "src/copy.c"}
    add("sink", graph_entity(Family.SINK_SITE, {**span, "start_byte": call.start_byte, "end_byte": call.end_byte,
                                                 "sink_class": "memory_write", "argument_index": 0},
                             results_for(Family.SINK_SITE), call))
    add("entry", graph_entity(Family.ENTRY_POINT, {**span, "start_byte": param.start_byte,
                                                   "end_byte": param.end_byte, "source_class": "remote"},
                              results_for(Family.ENTRY_POINT, "remote"), param))
    add("entry_internal", graph_entity(Family.ENTRY_POINT, {**span, "start_byte": param.start_byte,
                                                            "end_byte": param.end_byte, "source_class": "internal"},
                                       results_for(Family.ENTRY_POINT, "internal"), param))
    path_result = results_for(Family.DATAFLOW_PATH, "remote", sink=ids["sink"], entry=ids["entry"])
    add("path", graph_entity(Family.DATAFLOW_PATH, {"source_identity": ids["entry"], "sink_identity": ids["sink"],
                                                    "step_locations_sha256": "3" * 64}, path_result, call))
    add("path_disagree", graph_entity(Family.DATAFLOW_PATH, {"source_identity": ids["entry"],
                                                             "sink_identity": ids["sink"],
                                                             "step_locations_sha256": "4" * 64},
                                      path_result, call, cross_check="disagree"))
    add("guard", graph_entity(Family.GUARD_FACT, {"sink_identity": ids["sink"], "condition_path": "src/copy.c",
                                                  "condition_start_byte": condition.start_byte,
                                                  "condition_end_byte": condition.end_byte},
                              results_for(Family.GUARD_FACT, sink=ids["sink"]), condition))
    add("range", graph_entity(Family.RANGE_FACT, {"sink_identity": ids["sink"], "operand_index": 2},
                              results_for(Family.RANGE_FACT, sink=ids["sink"]), sink_span))
    if extra is not None:
        extra(ids, add, condition, sink_span, call)
    add("summary", graph_entity(Family.FLOW_SUMMARY, {"function_symbol": "asr:symbol:" + "5" * 64,
                                                      "rule_version": NORMALIZE_RULE},
                                results_for(Family.FLOW_SUMMARY), _location(source, SOURCE.rstrip("\n"))))
    add("call", graph_entity(Family.CALL_SITE, {**span, "caller_symbol": "asr:symbol:" + "5" * 64,
                                                "start_byte": call.start_byte, "end_byte": call.end_byte,
                                                "callee_name": "strcpy"}, results_for(Family.CALL_SITE), call))

    fingerprint = index_fingerprint(name="graph", target_snapshot=SNAPSHOT, producer_artifacts=[{"sha256": "a" * 64}],
                                    tool_identity={"tool": "codeql-export"}, parser_identity="p/1",
                                    normalizer_identity=NORMALIZE_RULE, mapping_identity="m/1")
    shard_path = run_root / "data" / "indices" / "graph" / "cpp-native" / f"{fingerprint}.sqlite"
    builder = IndexBuilder(shard_path, name="graph", fingerprint=fingerprint, target_snapshot=SNAPSHOT,
                           shard_id="cpp-native")
    for entity in entities:
        builder.add_entity(entity)
    for entity in entities:
        if entity.identity.kind is EntityKind.GUARD_FACT:
            builder.add_relation(RelationRecord(IndexRelation.GUARDS, entity.identity.value,
                                                entity.payload["result"]["sink"]["sink_site"], True, 1.0))
    builder.add_coverage(f"graph:{SCOPE_ID}:all", "complete", None)
    digest = builder.build()
    identity = IndexIdentity("graph", "appsec-review/retrieval-index/2", digest, fingerprint,
                             shard_path.relative_to(run_root).as_posix(),
                             {"job": "job_code_graph_index", "build_unit_id": "native-main"}, (), "cpp-native")
    manifest = run_root / "data" / "indices" / "manifests" / "fixture.json"
    write_manifest(manifest, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=target, indexes=[identity])
    attempt = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001"
    artifact = {"path": manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest),
                "size_bytes": manifest.stat().st_size}
    handoff = attempt / "handoff.json"
    atomic_json(handoff, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED", "job_id": "fixture",
                          "attempt_id": "attempt_0001", "artifacts": [artifact], "outputs": {}})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff),
        "manifest_path": artifact["path"], "manifest_sha256": artifact["sha256"]})
    return runs, ids


@pytest.fixture()
def graph_run(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    return accepted_graph_run(tmp_path)


def _resolve(core: RetrievalCore, entity_id: str, predicate: Predicate, *,
             kind: RelationKind = RelationKind.SUPPORTS, receipt: str | None = RECEIPT) -> EvidenceRelation | Gap:
    return resolve_relation(core, claim_id=CLAIM, predicate=predicate, kind=kind, entity_id=entity_id,
                            producing_cell_id=CELL, retrieval_receipt_sha256=receipt)


def test_resolved_graph_facts_are_direct_only_for_their_mapped_predicates(graph_run) -> None:
    runs, ids = graph_run
    core = RetrievalCore(runs, RUN_ID)
    table = {"call": {P.AFFECTED_CONSTRUCT}, "sink": {P.AFFECTED_CONSTRUCT}, "entry": {P.ATTACKER_INPUT_CONTROL},
             "entry_internal": set(), "summary": set(),
             "path": {P.SOURCE_TO_SINK_REACHABILITY, P.ATTACKER_INPUT_CONTROL}, "path_disagree": set(),
             "guard": {P.MISSING_OR_INEFFECTIVE_GUARD}, "range": {P.MISSING_OR_INEFFECTIVE_GUARD}}
    for key, direct in table.items():
        for predicate in Predicate:
            relation = _resolve(core, ids[key], predicate)
            assert isinstance(relation, EvidenceRelation), (key, relation)
            assert relation.complete, key
            want = Admissibility.DIRECT_FOR_MAPPED_PREDICATE if predicate in direct else Admissibility.INDIRECT
            assert relation.admissibility is want, (key, predicate)
            assert satisfies(relation) is (predicate in direct)
            assert relation.shard_id == "graph/cpp-native"


def test_model_supplied_eligibility_has_no_effect(graph_run) -> None:
    """The citation's claimed flag is never read: the re-resolved accepted payload decides."""
    runs, ids = graph_run
    core = RetrievalCore(runs, RUN_ID)
    resolved = core.find(identity=ids["path_disagree"], limit=1)["results"][0]
    assert resolved["payload"]["admissibility"]["direct_eligible"] is False
    # What a model might paste into its citation: the same fact with the flag flipped.
    claimed = copy.deepcopy(resolved["payload"])
    claimed["admissibility"] = {"rule": "graph-fact-admissibility/1", "direct_eligible": True,
                                "ineligibility_reasons": []}
    claimed["cross_check"]["state"] = "agree"
    assert classify("dataflow_path", P.SOURCE_TO_SINK_REACHABILITY, (), claimed) is \
        Admissibility.DIRECT_FOR_MAPPED_PREDICATE
    relation = _resolve(core, ids["path_disagree"], P.SOURCE_TO_SINK_REACHABILITY)
    assert isinstance(relation, EvidenceRelation)
    assert relation.admissibility is Admissibility.INDIRECT and not satisfies(relation)
    # The worker-facing relation path (teams._relations) reads only kind, predicate and entity_id.
    from appsec_review.jobs.job_inference_security_review import teams
    from appsec_review.review.models import Role
    cell = SimpleNamespace(spec=SimpleNamespace(role=Role.INDEPENDENT_VERIFIER),
                           record=SimpleNamespace(receipt_sha256=RECEIPT), cell_id=CELL)
    ctx = SimpleNamespace(core=core, rule_predicates={})
    found, gaps = teams._relations(ctx, cell, CLAIM, [{
        "kind": "supports", "predicate": "source_to_sink_reachability", "entity_id": ids["path_disagree"],
        "rationale": "path is direct", "payload": claimed, "admissibility": "direct_for_mapped_predicate"}],
        {ids["path_disagree"]})
    assert not gaps and len(found) == 1 and found[0].admissibility is Admissibility.INDIRECT


def test_satisfies_requires_complete_resolution(graph_run) -> None:
    runs, ids = graph_run
    core = RetrievalCore(runs, RUN_ID, limits=RetrievalLimits(max_excerpt_bytes=4))
    relation = _resolve(core, ids["path"], P.SOURCE_TO_SINK_REACHABILITY)
    assert isinstance(relation, EvidenceRelation)
    assert relation.admissibility is Admissibility.DIRECT_FOR_MAPPED_PREDICATE
    assert relation.complete is False and not satisfies(relation)


def test_a_none_guard_is_direct_support_and_a_contradiction_of_it_is_only_a_qualification(graph_run) -> None:
    runs, ids = graph_run
    core = RetrievalCore(runs, RUN_ID)
    support = _resolve(core, ids["guard"], P.MISSING_OR_INEFFECTIVE_GUARD)
    contra = _resolve(core, ids["guard"], P.MISSING_OR_INEFFECTIVE_GUARD, kind=RelationKind.CONTRADICTS)
    assert isinstance(support, EvidenceRelation) and isinstance(contra, EvidenceRelation)
    assert satisfies(support) and satisfies(contra) and support.relation_id != contra.relation_id
    # A ``none`` guard bounds nothing, so a contradiction needs the facts to show a bound (evidence-admissibility/3).
    assert support.kind is RelationKind.SUPPORTS and support.reason is None
    assert contra.kind is RelationKind.QUALIFIES and contra.reason.startswith("guard_not_shown_to_bound_destination:")


def test_relation_identity_records_the_admissibility_rule_version(graph_run) -> None:
    assert ADMISSIBILITY_RULES_VERSION == "evidence-admissibility/3"
    runs, ids = graph_run
    relation = _resolve(RetrievalCore(runs, RUN_ID), ids["sink"], P.AFFECTED_CONSTRUCT)
    assert isinstance(relation, EvidenceRelation) and relation.relation_id.startswith("evrel-")


# ------------------------------------------------------------------------------------------------
# Policy hash


def test_policy_hash_pins_the_graph_mapping_and_admissibility_version() -> None:
    document = obligations._policy_document()
    assert document["admissibility"] == "evidence-admissibility/3"
    assert document["graph_fact_predicates"]["rule"] == "graph-fact-predicates/1"
    assert document["graph_fact_predicates"]["families"] == {
        "call_site": ["affected_construct"], "sink_site": ["affected_construct"],
        "entry_point": ["attacker_input_control"],
        "dataflow_path": ["attacker_input_control", "source_to_sink_reachability"],
        "guard_fact": ["missing_or_ineffective_guard"], "range_fact": ["missing_or_ineffective_guard"]}
    assert document["graph_fact_predicates"]["attacker_reachable_sources"] == sorted(ATTACKER_REACHABLE)
    assert obligations.POLICY_SHA256 == obligations.sha256_hex(document)
    changed = {**obligations.GRAPH_FACT_PREDICATES, Family.CALL_SITE: frozenset({P.SOURCE_TO_SINK_REACHABILITY})}
    assert obligations.sha256_hex(obligations._policy_document(changed)) != obligations.POLICY_SHA256
    dropped = {key: value for key, value in obligations.GRAPH_FACT_PREDICATES.items() if key is not Family.RANGE_FACT}
    assert obligations.sha256_hex(obligations._policy_document(dropped)) != obligations.POLICY_SHA256
    # The version-1 policy (no admissibility rule, no graph mapping) hashes differently.
    legacy = {key: value for key, value in document.items() if key not in {"admissibility", "graph_fact_predicates"}}
    assert obligations.sha256_hex(legacy) != obligations.POLICY_SHA256
    # The adjudication policy is derived from the obligation policy, so it moves with it.
    assert adjudication.POLICY_SHA256 == obligations.sha256_hex({
        "rules": adjudication.RULES_VERSION, "obligations": obligations.POLICY_SHA256,
        "rows": [row.value for row in adjudication.DecidingRow],
        "contradiction_states": [[p.value, s.value] for p, s in adjudication._CONTRADICTION_STATES],
        "counted_admissibility": ["direct", "direct_for_mapped_predicate"], "requires_complete": True})


def test_package_reuse_basis_includes_the_evidence_rule_versions() -> None:
    from appsec_review.jobs.job_inference_security_review import job
    assert job.EVIDENCE_RULES == {
        "rule_predicates": "tool-rule-predicates/2", "admissibility": "evidence-admissibility/3",
        "predicate_admission": "predicate-admission/2",
        "graph_fact_predicates": "graph-fact-predicates/1",
        "graph_fact_admissibility": "graph-fact-admissibility/1",
        "obligation_policy_sha256": obligations.POLICY_SHA256}


# ------------------------------------------------------------------------------------------------
# Triage ordering, registry and verifier independence


def _support(relations: list[EvidenceRelation]) -> int:
    return len({item.predicate for item in relations if item.kind is RelationKind.SUPPORTS and satisfies(item)})


@pytest.mark.parametrize("active_claim_limit", [1, 2])
def test_triage_orders_graph_cited_hypotheses_above_prose(graph_run, active_claim_limit) -> None:
    from appsec_review.jobs.job_inference_security_review import teams
    runs, ids = graph_run
    core = RetrievalCore(runs, RUN_ID)
    cited = [_resolve(core, ids["path"], P.SOURCE_TO_SINK_REACHABILITY),
             _resolve(core, ids["sink"], P.AFFECTED_CONSTRUCT),
             _resolve(core, ids["guard"], P.MISSING_OR_INEFFECTIVE_GUARD)]
    assert all(isinstance(item, EvidenceRelation) for item in cited)
    # The same team code path counts support: the graph kinds satisfy three construct predicates.
    assert _support(cited) == 3

    def group(claim_id: str, relations: list[EvidenceRelation]) -> dict[str, Any]:
        return {"claim": SimpleNamespace(claim_id=claim_id), "relation_gaps": [], "items": [], "requests": [],
                "relations": relations, "support": _support(relations)}

    # The prose-only hypothesis sorts first by identity, so only support can put the graph one ahead.
    prose, graph = group("claim-" + "0" * 64, []), group("claim-" + "f" * 64, cited)
    ctx = SimpleNamespace(settings=SimpleNamespace(lanes=SimpleNamespace(hunt_max_claims_per_package=1,
                                                                         lead_max_claims_per_package=1)),
                          resolves=lambda identity: True)
    work = SimpleNamespace(lane=Lane.HUNT, package_id="hunt-" + "1" * 64,
                           active_claim_limit=active_claim_limit, round_index=0)
    result = teams.TeamResult(work.package_id, Lane.HUNT, None)
    admitted = teams._triage(ctx, work, [prose, graph], result)
    assert [item["claim"].claim_id for item in admitted] == [graph["claim"].claim_id]
    decisions = {item["claim_id"]: (item["decision"], item["support"]) for item in result.triage}
    assert decisions == {graph["claim"].claim_id: ("admitted", 3), prose["claim"].claim_id: ("over_cap", 0)}


def test_registry_grants_query_code_graph_to_exactly_the_review_roles() -> None:
    registry = load_registry(ROOT)
    granted = {name for name, value in registry["roles"].items() if "query_code_graph" in value.get("tools", ())}
    assert granted == {"hypothesis_hunter", "red_team_analyst", "blue_team_refuter", "independent_verifier",
                       "adjudication_judge"}
    for role in ("independent_scorer", "finding_adjudicator"):
        assert "query_code_graph" not in registry["roles"][role].get("tools", ())


def test_verifier_independence_accepts_graph_facts_it_retrieved_itself(graph_run) -> None:
    runs, ids = graph_run
    core = RetrievalCore(runs, RUN_ID)
    required = {P.AFFECTED_CONSTRUCT, P.ATTACKER_INPUT_CONTROL, P.SOURCE_TO_SINK_REACHABILITY,
                P.MISSING_OR_INEFFECTIVE_GUARD}
    citations = [("sink", P.AFFECTED_CONSTRUCT), ("path", P.ATTACKER_INPUT_CONTROL),
                 ("path", P.SOURCE_TO_SINK_REACHABILITY), ("guard", P.MISSING_OR_INEFFECTIVE_GUARD)]
    verifier = ActorRecord("actor-verifier", "provider-b", "model-b", "conversation-verifier")
    others = [ActorRecord("actor-red", "provider-a", "model-a", "conversation-red")]

    def check(receipt: str | None) -> tuple[bool, list[Gap]]:
        relations = [_resolve(core, ids[key], predicate, receipt=receipt) for key, predicate in citations]
        return verify_independence(verifier, others, b'{"claim": "fresh"}', ["red narrative marker text"],
                                   relations, required, {RECEIPT}, claim_id=CLAIM)

    independent, gaps = check(RECEIPT)          # retrieved through the verifier's own query_code_graph call
    assert independent and gaps == []
    independent, gaps = check(None)             # identities it never retrieved itself
    assert not independent
    assert {gap.predicate for gap in gaps} == required
