"""Unit tests for opt-in T-152 warrant wiring across config, evidence, adjudication, and scoring."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import tomllib
from typing import Any, Mapping

import pytest

from appsec_review.config import (
    CAPACITY_KEYS, InferenceSecurityReviewSettings, WarrantPolicySettings, load_config,
    parse_inference_review_settings, semantic_settings_sha256, semantic_settings_view,
)
from appsec_review.graph.contract import (
    AUTHORITY, CATALOG_SCHEMA, CROSS_CHECK_RULE, GRAPH_FACT_SCHEMA, NORMALIZE_RULE, Family, GraphFact,
    admissibility as graph_admissibility, fact_identity,
)
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind as IndexRelation,
    RelationRecord, RetrievalCore, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.review.adjudication import (
    POLICY_SHA256, WARRANT_POLICY_SHA256, DecidingRow, PredicateOutcome, adjudicate, policy_sha256,
)
from appsec_review.review.evidence import resolve_relation, resolve_warranted_relation
from appsec_review.review.models import (
    Claim, ClaimState, EvidenceRelation, Gap, Lane, Predicate, RelationKind, SecurityPredicate,
)
from appsec_review.review.numeric_reasoning import SCORING_MISSING_REASON
from appsec_review.review.scoring import default_factor_registry
from appsec_review.review.scoring.factors import (
    FactorId, FactorInput, MissingFactor, ResolvedEntity, factor_input,
)
from appsec_review.review.warrants import (
    PredicateWarrant, WarrantReasonCode, WarrantResult, bind_warrant_relation_id,
)
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff

ROOT = Path(__file__).resolve().parents[3]
RUN_ID = "2026-11-13-0153"
SNAPSHOT = "target-sha256:" + "6" * 64
SCOPE_ID = "codeql:c/c++:debug:" + "3" * 16
RECEIPT = "e" * 64
CELL_RED = "cell-" + "1" * 64
CELL_VERIFIER = "cell-" + "2" * 64
CELL_BLUE = "cell-" + "3" * 64
IMPACT_TABLE = {"CWE-787": "high", "CWE-190": "high"}

SOURCE = (
    "int copy_pkt(const char *src, size_t n, size_t alt) {\n"
    "  char dst[16];\n"
    "  char other[32];\n"
    "  if (alt < 4) return -1;\n"
    "  if (n > 16) return -1;\n"
    "  memcpy(dst, src, n);\n"
    "  memcpy(other, src, alt);\n"
    "  return 0;\n"
    "}\n"
)


def _ident(kind: EntityKind, native: str) -> LogicalIdentity:
    return LogicalIdentity.derive(kind, SNAPSHOT, {"native": native})


def _loc(path: Path, rel: str, needle: str) -> SourceLocation:
    text = path.read_text(encoding="utf-8")
    start = text.index(needle)
    line = text[:start].count("\n") + 1
    end_line = line + needle.count("\n")
    col = start - (text.rfind("\n", 0, start) + 1) + 1
    end_col = col + len(needle)
    return SourceLocation(
        SNAPSHOT, rel, file_sha256(path), start, start + len(needle),
        line, end_line, col, end_col, {}, "fixture-exact", 1.0,
    )


def _graph_entity(family: Family, native: Mapping[str, Any], result: Mapping[str, Any],
                  location: SourceLocation) -> EntityRecord:
    payload: dict[str, Any] = {
        "schema": GRAPH_FACT_SCHEMA,
        "family": family.value,
        "producer": {
            "name": "codeql-export", "tool_version": "2.27.0", "export_pack_sha256": "a" * 64,
            "catalog_version": CATALOG_SCHEMA, "rule_version": NORMALIZE_RULE,
        },
        "scope": {
            "scope_id": SCOPE_ID, "language": "c/c++",
            "build_unit_id": "debug", "component_id": "component:0001",
        },
        "exact": True,
        "coverage_status": "complete",
        "gaps": [],
        "cross_check": {"rule": CROSS_CHECK_RULE, "state": "not_covered", "producers": []},
        "result": dict(result),
        "upstream": [],
        "authority": AUTHORITY,
    }
    payload["admissibility"] = graph_admissibility(payload)
    identity = fact_identity(family, SNAPSHOT, {"scope_id": SCOPE_ID, **native})
    return GraphFact(identity, f"{family.value}:{identity.value[-8:]}", payload, location).to_entity()


def _claim(*affected: str, cwe: str = "CWE-787", idx: str = "a") -> Claim:
    return Claim(
        claim_id="claim-" + (idx * 64)[:64],
        lane=Lane.LEAD,
        package_id="package-" + ("b" * 64),
        affected_entities=tuple(sorted(affected)),
        weakness_cwe=cwe,
        security_predicate=SecurityPredicate.MEMORY_CORRUPTION,
        preconditions=(),
        statement="s",
        state=ClaimState.PROPOSED,
    )


def _adjudication_predicates(decision) -> list[dict[str, Any]]:
    return [
        {
            "predicate": item.predicate.value,
            "required": item.required,
            "outcome": item.outcome.value,
            "supporting": list(item.supporting),
            "contradicting": list(item.contradicting),
        }
        for item in decision.predicates
    ]


@pytest.fixture()
def wiring_core(tmp_path: Path) -> tuple[RetrievalCore, dict[str, str]]:
    runs = tmp_path / "runs"
    run_root = runs / RUN_ID
    attempt = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001"
    attempt.mkdir(parents=True)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    src = target / "src" / "pkt.c"
    src.write_text(SOURCE, encoding="utf-8")

    loc_fn = _loc(src, "src/pkt.c", SOURCE.rstrip("\n"))
    loc_dst = _loc(src, "src/pkt.c", "memcpy(dst, src, n)")
    loc_other = _loc(src, "src/pkt.c", "memcpy(other, src, alt)")
    loc_alt = _loc(src, "src/pkt.c", "if (alt < 4)")
    loc_n = _loc(src, "src/pkt.c", "if (n > 16)")
    loc_param = _loc(src, "src/pkt.c", "const char *src")

    ids: dict[str, str] = {}
    analysis_ents: list[EntityRecord] = []
    graph_ents: list[EntityRecord] = []
    graph_rels: list[RelationRecord] = []
    obs_ents: list[EntityRecord] = []
    obs_rels: list[RelationRecord] = []

    def put(bucket: list[EntityRecord], key: str, rec: EntityRecord) -> str:
        ids[key] = rec.identity.value
        bucket.append(rec)
        return rec.identity.value

    put(analysis_ents, "sym_fn",
        EntityRecord(_ident(EntityKind.SYMBOL, "copy_pkt"), "copy_pkt", "copy_pkt", "fn", {}, loc_fn))
    put(analysis_ents, "span_dst",
        EntityRecord(_ident(EntityKind.SOURCE_SPAN, "pkt.c:6"), "pkt.c:6", "memcpy dst", "memcpy", {}, loc_dst))

    # Sink 1: unguarded sink with guard_state="none"
    sink_vuln = put(graph_ents, "sink_vuln", _graph_entity(
        Family.SINK_SITE,
        {"path": "src/pkt.c", "start_byte": loc_dst.start_byte, "end_byte": loc_dst.end_byte,
         "sink_class": "memory_write", "argument_index": 2},
        {"sink_class": "memory_write", "cwe_family": "CWE-787", "argument_index": 2},
        loc_dst,
    ))
    # Sink 2: effectively guarded sink (has effective guard n <= 16, bounding range [0, 8], and non-constraining alt < 4)
    sink_safe = put(graph_ents, "sink_safe", _graph_entity(
        Family.SINK_SITE,
        {"path": "src/pkt.c", "start_byte": loc_other.start_byte, "end_byte": loc_other.end_byte,
         "sink_class": "memory_write", "argument_index": 2},
        {"sink_class": "memory_write", "cwe_family": "CWE-787", "argument_index": 2},
        loc_other,
    ))

    entry = put(graph_ents, "entry", _graph_entity(
        Family.ENTRY_POINT,
        {"path": "src/pkt.c", "start_byte": loc_param.start_byte, "end_byte": loc_param.end_byte,
         "source_class": "remote"},
        {"source_class": "remote", "api_or_parameter": {"display": "src"}},
        loc_param,
    ))
    path_vuln = put(graph_ents, "path_vuln", _graph_entity(
        Family.DATAFLOW_PATH,
        {"source_identity": entry, "sink_identity": sink_vuln, "step_locations_sha256": "1" * 64},
        {"source": {"entry_point": entry, "source_class": "remote"},
         "sink": {"sink_site": sink_vuln, "sink_class": "memory_write", "cwe_family": "CWE-787"},
         "steps": [], "hop_count": 1, "truncated_steps": False},
        loc_dst,
    ))
    path_safe = put(graph_ents, "path_safe", _graph_entity(
        Family.DATAFLOW_PATH,
        {"source_identity": entry, "sink_identity": sink_safe, "step_locations_sha256": "2" * 64},
        {"source": {"entry_point": entry, "source_class": "remote"},
         "sink": {"sink_site": sink_safe, "sink_class": "memory_write", "cwe_family": "CWE-787"},
         "steps": [], "hop_count": 1, "truncated_steps": False},
        loc_other,
    ))

    g_vuln_none = put(graph_ents, "g_vuln_none", _graph_entity(
        Family.GUARD_FACT,
        {"sink_identity": sink_vuln, "condition_path": "src/pkt.c",
         "condition_start_byte": 0, "condition_end_byte": 0},
        {"sink": {"sink_site": sink_vuln, "sink_class": "memory_write"},
         "guard_state": "none", "polarity": "unknown", "condition": None,
         "constrains_sink_operand": "unknown", "comparison": None,
         "destination": {"object_bytes": 16}},
        loc_dst,
    ))
    g_safe_effective = put(graph_ents, "g_safe_effective", _graph_entity(
        Family.GUARD_FACT,
        {"sink_identity": sink_safe, "condition_path": "src/pkt.c",
         "condition_start_byte": loc_n.start_byte, "condition_end_byte": loc_n.end_byte},
        {"sink": {"sink_site": sink_safe, "sink_class": "memory_write"},
         "guard_state": "dominating", "polarity": "false_branch", "condition": None,
         "constrains_sink_operand": True,
         "comparison": {
             "operator": ">", "bound_display": "n > 16",
             "operands": [
                 {"role": "lhs", "kind": "variable", "value": None, "text": "n", "location": None},
                 {"role": "rhs", "kind": "constant", "value": 16, "text": "16", "location": None},
             ],
         },
         "destination": {"object_bytes": 16}},
        loc_n,
    ))
    g_safe_sibling = put(graph_ents, "g_safe_sibling", _graph_entity(
        Family.GUARD_FACT,
        {"sink_identity": sink_safe, "condition_path": "src/pkt.c",
         "condition_start_byte": loc_alt.start_byte, "condition_end_byte": loc_alt.end_byte},
        {"sink": {"sink_site": sink_safe, "sink_class": "memory_write"},
         "guard_state": "dominating", "polarity": "false_branch", "condition": None,
         "constrains_sink_operand": False,
         "comparison": {
             "operator": "<", "bound_display": "alt < 4",
             "operands": [
                 {"role": "lhs", "kind": "variable", "value": None, "text": "alt", "location": None},
                 {"role": "rhs", "kind": "constant", "value": 4, "text": "4", "location": None},
             ],
         },
         "destination": {"object_bytes": 16}},
        loc_alt,
    ))
    r_safe_bounded = put(graph_ents, "r_safe_bounded", _graph_entity(
        Family.RANGE_FACT,
        {"sink_identity": sink_safe, "operand_index": 2},
        {"sink": {"sink_site": sink_safe, "sink_class": "memory_write"},
         "operand_index": 2, "applicability": "integral",
         "type": {"display": "uint32_t", "signed": False, "bits": 32},
         "interval": {"lower": 0, "upper": 8}, "conversions": [], "sign_change": False},
        loc_other,
    ))

    graph_rels.extend([
        RelationRecord(IndexRelation.FLOWS_TO, entry, sink_vuln, True, 1.0),
        RelationRecord(IndexRelation.FLOWS_TO, entry, sink_safe, True, 1.0),
        RelationRecord(IndexRelation.GUARDS, g_vuln_none, sink_vuln, True, 1.0),
        RelationRecord(IndexRelation.GUARDS, g_safe_effective, sink_safe, True, 1.0),
        RelationRecord(IndexRelation.GUARDS, g_safe_sibling, sink_safe, True, 1.0),
        RelationRecord(IndexRelation.DERIVED_FROM, r_safe_bounded, sink_safe, True, 1.0),
    ])

    obs_o1 = put(obs_ents, "obs_o1", EntityRecord(
        _ident(EntityKind.TOOL_OBSERVATION, "sast:int-overflow"),
        "sast:int-overflow", "cpp.int-overflow", "integer overflow", {"rule": "cpp.int-overflow"}, loc_dst,
    ))
    art = put(obs_ents, "art", EntityRecord(
        _ident(EntityKind.EVIDENCE_ARTIFACT, "sarif:1"), "sarif:1", "sarif", "sarif", {"sha256": "c" * 64},
    ))
    obs_rels.append(RelationRecord(IndexRelation.DERIVED_FROM, obs_o1, art, True, 1.0))

    identities: list[IndexIdentity] = []
    for name, shard, ents, rels in (
        ("analysis", "default", analysis_ents, []),
        ("graph", "cpp-debug", graph_ents, graph_rels),
        ("observations", "default", obs_ents, obs_rels),
    ):
        fp = index_fingerprint(
            name=name, target_snapshot=SNAPSHOT, producer_artifacts=[{"sha256": "a" * 64}],
            tool_identity={"tool": "fixture"}, parser_identity="p/1",
            normalizer_identity="n/1", mapping_identity="m/1",
        )
        db = run_root / "data" / "indices" / name / shard / f"{fp}.sqlite"
        builder = IndexBuilder(db, name=name, fingerprint=fp, target_snapshot=SNAPSHOT, shard_id=shard)
        for ent in ents:
            builder.add_entity(ent)
        for rel in rels:
            builder.add_relation(rel)
        builder.add_coverage(f"{name}:{shard}", "complete", None)
        digest = builder.build()
        identities.append(IndexIdentity(
            name, "appsec-review/retrieval-index/2", digest, fp,
            db.relative_to(run_root).as_posix(), {"fixture": name}, (), shard,
        ))

    manifest = run_root / "data" / "indices" / "manifests" / "fixture.json"
    write_manifest(manifest, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=target, indexes=identities)
    artifact = {
        "path": manifest.relative_to(run_root).as_posix(),
        "sha256": file_sha256(manifest),
        "size_bytes": manifest.stat().st_size,
    }
    handoff = attempt / "handoff.json"
    write_fixture_handoff(run_root, handoff, {
        "source_fingerprint": SNAPSHOT, "status": "ACCEPTED", "job_id": "fixture",
        "attempt_id": "attempt_0001", "artifacts": [artifact], "outputs": {},
    })
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff),
        "manifest_path": artifact["path"], "manifest_sha256": artifact["sha256"],
    })
    return RetrievalCore(runs, RUN_ID), ids


# ---------------------------------------------------------------------------
# 1. Configuration and cache-identity versioning
# ---------------------------------------------------------------------------

def test_warrant_policy_defaults_off_and_versions_semantic_hash(tmp_path: Path) -> None:
    raw = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))[
        "jobs"]["job_inference_security_review"]["settings"]
    absent = parse_inference_review_settings({k: v for k, v in raw.items() if k != "warrant_policy"})
    explicit_off = parse_inference_review_settings(raw | {"warrant_policy": {"enabled": False}})
    explicit_on = parse_inference_review_settings(raw | {"warrant_policy": {"enabled": True}})

    assert absent.warrant_policy == WarrantPolicySettings(enabled=False)
    assert semantic_settings_view(absent) == semantic_settings_view(explicit_off)
    assert semantic_settings_sha256(absent) == semantic_settings_sha256(explicit_off)
    assert semantic_settings_sha256(explicit_on) != semantic_settings_sha256(explicit_off)
    assert semantic_settings_view(explicit_on)["settings"]["warrant_policy"] == {"enabled": True}
    assert not any("warrant_policy" in key for key in CAPACITY_KEYS)

    with pytest.raises(FrozenInstanceError):
        setattr(absent.warrant_policy, "enabled", True)
    with pytest.raises(ValueError, match="must be a table"):
        WarrantPolicySettings.from_mapping(True, "jobs.job_inference_security_review.settings.warrant_policy")
    with pytest.raises(ValueError, match="unknown settings: mode"):
        WarrantPolicySettings.from_mapping({"enabled": True, "mode": "strict"}, "warrant_policy")
    with pytest.raises(ValueError, match="enabled must be a Boolean"):
        WarrantPolicySettings.from_mapping({"enabled": "yes"}, "warrant_policy")

    overlay = tmp_path / "capacity.toml"
    overlay.write_text("[jobs.job_inference_security_review.settings.warrant_policy]\nenabled = true\n",
                       encoding="utf-8")
    with pytest.raises(ValueError, match="rejected: .*warrant_policy"):
        load_config(ROOT / "appsec-review.toml", profile="dev", overlay=overlay)


# ---------------------------------------------------------------------------
# 2. End-to-end warranted confirmation, contradiction, and default parity
# ---------------------------------------------------------------------------

def test_opt_in_warrants_confirm_bound_claim_and_preserve_default_policy_when_off(
    wiring_core: tuple[RetrievalCore, dict[str, str]],
) -> None:
    core, ids = wiring_core
    claim = _claim(ids["sink_vuln"], idx="1")
    citations = (
        (Predicate.AFFECTED_CONSTRUCT, ids["sink_vuln"], CELL_RED, "hypothesis_hunter"),
        (Predicate.ATTACKER_INPUT_CONTROL, ids["entry"], CELL_RED, "hypothesis_hunter"),
        (Predicate.SOURCE_TO_SINK_REACHABILITY, ids["path_vuln"], CELL_VERIFIER, "independent_verifier"),
        (Predicate.MISSING_OR_INEFFECTIVE_GUARD, ids["g_vuln_none"], CELL_VERIFIER, "independent_verifier"),
    )

    legacy_relations: list[EvidenceRelation] = []
    warranted_relations: list[EvidenceRelation] = []
    warrants: list[PredicateWarrant] = []
    for predicate, ent_id, cell_id, role in citations:
        leg = resolve_relation(
            core, claim_id=claim.claim_id, predicate=predicate, kind=RelationKind.SUPPORTS,
            entity_id=ent_id, producing_cell_id=cell_id, retrieval_receipt_sha256=RECEIPT, role=role,
        )
        assert isinstance(leg, EvidenceRelation)
        legacy_relations.append(leg)

        war = resolve_warranted_relation(
            core, claim=claim, predicate=predicate, kind=RelationKind.SUPPORTS,
            entity_id=ent_id, producing_cell_id=cell_id, retrieval_receipt_sha256=RECEIPT, role=role,
        )
        assert not isinstance(war, Gap)
        rel_obj, warrant_obj = war
        assert rel_obj.relation_id != leg.relation_id
        assert warrant_obj.relation_id == rel_obj.relation_id
        warranted_relations.append(rel_obj)
        warrants.append(warrant_obj)

    dec_off = adjudicate(claim, legacy_relations, True, {ids["sink_vuln"]}, ())
    dec_on = adjudicate(
        claim, warranted_relations, True, {ids["sink_vuln"]}, (),
        warrants=warrants, warrant_policy_enabled=True,
    )
    assert dec_off.state is ClaimState.CONFIRMED
    assert dec_off.policy_sha256 == POLICY_SHA256 == policy_sha256(warrant_policy_enabled=False)
    assert dec_on.state is ClaimState.CONFIRMED
    assert dec_on.policy_sha256 == WARRANT_POLICY_SHA256 == policy_sha256(warrant_policy_enabled=True)
    assert dec_on.policy_sha256 != dec_off.policy_sha256
    assert dec_on.adjudication_id != dec_off.adjudication_id

    f_in = factor_input(
        claim_id=claim.claim_id, adjudication_id=dec_on.adjudication_id, claim_state=dec_on.state,
        weakness_cwe=claim.weakness_cwe, affected_entities=claim.affected_entities,
        predicates=_adjudication_predicates(dec_on), relations=warranted_relations, warrants=warrants,
    )
    extracted = default_factor_registry(IMPACT_TABLE).extract(
        f_in, (FactorId.VERIFICATION, FactorId.TAINT_PATH, FactorId.GUARD_ABSENT),
    )
    assert extracted.get(FactorId.VERIFICATION).value == "confirmed"
    assert extracted.get(FactorId.TAINT_PATH).value == "graph_dataflow_path"
    assert extracted.get(FactorId.GUARD_ABSENT).value == "graph_fact"


def test_wrong_polarity_and_wrong_sink_citations_downgrade_to_qualifies(
    wiring_core: tuple[RetrievalCore, dict[str, str]],
) -> None:
    core, ids = wiring_core
    claim = _claim(ids["sink_vuln"], idx="2")

    # Existence of affected construct cannot contradict affected_construct.
    contra_construct = resolve_warranted_relation(
        core, claim=claim, predicate=Predicate.AFFECTED_CONSTRUCT, kind=RelationKind.CONTRADICTS,
        entity_id=ids["sink_vuln"], producing_cell_id=CELL_BLUE, retrieval_receipt_sha256=RECEIPT,
        role="blue_team_refuter",
    )
    assert not isinstance(contra_construct, Gap)
    rel_c, war_c = contra_construct
    assert war_c.requested_relation is RelationKind.CONTRADICTS
    assert war_c.effective_relation is RelationKind.QUALIFIES
    assert rel_c.kind is RelationKind.QUALIFIES
    assert rel_c.reason == "warrant_not_established:presence_cannot_contradict_construct"

    # Effective guard on sink_safe cannot refute sink_vuln.
    wrong_sink = resolve_warranted_relation(
        core, claim=claim, predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD, kind=RelationKind.CONTRADICTS,
        entity_id=ids["g_safe_effective"], producing_cell_id=CELL_BLUE, retrieval_receipt_sha256=RECEIPT,
        role="blue_team_refuter",
    )
    assert not isinstance(wrong_sink, Gap)
    rel_s, war_s = wrong_sink
    assert war_s.reason_code is WarrantReasonCode.SINK_MISMATCH
    assert rel_s.kind is RelationKind.QUALIFIES

    decision = adjudicate(
        claim, [rel_c, rel_s], True, {ids["sink_vuln"]}, (),
        warrants=[war_c, war_s], warrant_policy_enabled=True,
    )
    assert decision.state is ClaimState.INSUFFICIENT_EVIDENCE
    assert decision.deciding_row is DecidingRow.INSUFFICIENT_EVIDENCE


# ---------------------------------------------------------------------------
# 3. Safeguard 5: R5 and scoring share one warrant (effective range & numeric O1)
# ---------------------------------------------------------------------------

def test_scoring_reuses_warrant_for_effective_range_and_cherry_picked_sibling(
    wiring_core: tuple[RetrievalCore, dict[str, str]],
) -> None:
    core, ids = wiring_core
    claim = _claim(ids["sink_safe"], idx="3")

    # Cite ONLY r_safe_bounded as SUPPORTS (without citing g_safe_effective in FactorInput.entities).
    # Legacy _effective_guard lacked destination size in FactorInput.entities; the warrant resolves
    # sink_safe's guard_fact in the index and proves r_safe_bounded bounds the 16-byte destination.
    leg_range = resolve_relation(
        core, claim_id=claim.claim_id, predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD,
        kind=RelationKind.SUPPORTS, entity_id=ids["r_safe_bounded"],
        producing_cell_id=CELL_RED, retrieval_receipt_sha256=RECEIPT, role="hypothesis_hunter",
    )
    assert isinstance(leg_range, EvidenceRelation)
    range_entity = core.find(identity=ids["r_safe_bounded"], limit=1)["results"][0]
    legacy_input = FactorInput(
        claim_id=claim.claim_id, adjudication_id="adjudication-" + "9" * 64,
        claim_state=ClaimState.SUPPORTED, weakness_cwe="CWE-787",
        supporting=(leg_range,),
        entities={leg_range.entity_id: ResolvedEntity(leg_range.entity_id, "range_fact", range_entity["payload"])},
    )
    legacy_factor = default_factor_registry(IMPACT_TABLE).extract(legacy_input, (FactorId.GUARD_ABSENT,))
    assert legacy_factor.get(FactorId.GUARD_ABSENT).value == "graph_fact"

    war_range = resolve_warranted_relation(
        core, claim=claim, predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD,
        kind=RelationKind.SUPPORTS, entity_id=ids["r_safe_bounded"],
        producing_cell_id=CELL_RED, retrieval_receipt_sha256=RECEIPT, role="hypothesis_hunter",
    )
    assert not isinstance(war_range, Gap)
    rel_r, w_r = war_range
    assert w_r.reason_code is WarrantReasonCode.EFFECTIVE_GUARD_CANNOT_SUPPORT_MISSING_GUARD
    assert rel_r.kind is RelationKind.QUALIFIES

    # Even if a caller supplies a raw SUPPORTS relation alongside its rejected warrant,
    # GuardAbsentExtractor reuses the warrant and refuses to score guard_absent.
    forced_sup = replace(leg_range)
    bound_rejected = bind_warrant_relation_id(w_r, forced_sup.relation_id)
    warranted_input = FactorInput(
        claim_id=claim.claim_id, adjudication_id="adjudication-" + "9" * 64,
        claim_state=ClaimState.SUPPORTED, weakness_cwe="CWE-787",
        supporting=(forced_sup,),
        entities=legacy_input.entities,
        warrants={forced_sup.relation_id: bound_rejected},
    )
    warranted_factor = default_factor_registry(IMPACT_TABLE).extract(warranted_input, (FactorId.GUARD_ABSENT,))
    assert warranted_factor.get(FactorId.GUARD_ABSENT) is None
    assert isinstance(warranted_factor.missing[0], MissingFactor)


def test_numeric_o1_tool_observation_is_uncounted_in_r5_and_missing_in_scoring(
    wiring_core: tuple[RetrievalCore, dict[str, str]],
) -> None:
    core, ids = wiring_core
    claim = _claim(ids["sink_vuln"], cwe="CWE-190", idx="4")

    r_con, w_con = resolve_warranted_relation(
        core, claim=claim, predicate=Predicate.AFFECTED_CONSTRUCT, kind=RelationKind.SUPPORTS,
        entity_id=ids["sink_vuln"], producing_cell_id=CELL_RED, retrieval_receipt_sha256=RECEIPT,
    )
    r_o1, w_o1 = resolve_warranted_relation(
        core, claim=claim, predicate=Predicate.MISSING_OR_INEFFECTIVE_GUARD, kind=RelationKind.SUPPORTS,
        entity_id=ids["obs_o1"], producing_cell_id=CELL_RED, retrieval_receipt_sha256=RECEIPT,
        rule_predicates=(Predicate.MISSING_OR_INEFFECTIVE_GUARD,),
    )
    assert w_o1.result is WarrantResult.NOT_ESTABLISHED
    assert w_o1.reason_code is WarrantReasonCode.NUMERIC_MACHINE_FACT_REQUIRED
    assert r_o1.kind is RelationKind.QUALIFIES

    decision = adjudicate(
        claim, [r_con, r_o1], True, {ids["sink_vuln"]}, (),
        warrants=[w_con, w_o1], warrant_policy_enabled=True,
    )
    assert decision.state is ClaimState.SUPPORTED
    by_pred = {item.predicate: item for item in decision.predicates}
    assert by_pred[Predicate.MISSING_OR_INEFFECTIVE_GUARD].outcome is PredicateOutcome.UNRESOLVED

    f_in = factor_input(
        claim_id=claim.claim_id, adjudication_id=decision.adjudication_id, claim_state=decision.state,
        weakness_cwe=claim.weakness_cwe, affected_entities=claim.affected_entities,
        predicates=_adjudication_predicates(decision), relations=[r_con, r_o1], warrants=[w_con, w_o1],
    )
    extracted = default_factor_registry(IMPACT_TABLE).extract(f_in, (FactorId.GUARD_ABSENT,))
    assert extracted.get(FactorId.GUARD_ABSENT) is None
    assert extracted.missing[0].reason == SCORING_MISSING_REASON


def test_adjudicate_and_factor_input_fail_closed_on_missing_or_mismatched_warrants(
    wiring_core: tuple[RetrievalCore, dict[str, str]],
) -> None:
    core, ids = wiring_core
    claim = _claim(ids["sink_vuln"], idx="5")
    other_claim = _claim(ids["sink_safe"], idx="6")

    rel_con, war_con = resolve_warranted_relation(
        core, claim=claim, predicate=Predicate.AFFECTED_CONSTRUCT, kind=RelationKind.SUPPORTS,
        entity_id=ids["sink_vuln"], producing_cell_id=CELL_RED, retrieval_receipt_sha256=RECEIPT,
    )
    _, war_other = resolve_warranted_relation(
        core, claim=other_claim, predicate=Predicate.AFFECTED_CONSTRUCT, kind=RelationKind.SUPPORTS,
        entity_id=ids["sink_safe"], producing_cell_id=CELL_RED, retrieval_receipt_sha256=RECEIPT,
    )

    # Without a warrant, warrant_policy_enabled=True refuses to count the relation.
    unwarranted = adjudicate(
        claim, [rel_con], True, {ids["sink_vuln"]}, (), warrants=(), warrant_policy_enabled=True,
    )
    assert unwarranted.state is ClaimState.INSUFFICIENT_EVIDENCE
    assert unwarranted.counted_relation_ids == ()

    # Foreign warrant rejected.
    with pytest.raises(ValueError, match="different claim"):
        adjudicate(claim, [rel_con], True, {ids["sink_vuln"]}, (), warrants=[war_other], warrant_policy_enabled=True)

    # Mismatched predicate on same relation_id rejected.
    tampered_pred = bind_warrant_relation_id(replace(war_con, predicate=Predicate.SECURITY_IMPACT), rel_con.relation_id)
    with pytest.raises(ValueError, match="does not match evidence relation"):
        adjudicate(claim, [rel_con], True, {ids["sink_vuln"]}, (), warrants=[tampered_pred], warrant_policy_enabled=True)

    # factor_input rejects counted supporting relation when its warrant is missing.
    valid_dec = adjudicate(
        claim, [rel_con], True, {ids["sink_vuln"]}, (), warrants=[war_con], warrant_policy_enabled=True,
    )
    with pytest.raises(ValueError, match="without an established support warrant"):
        factor_input(
            claim_id=claim.claim_id, adjudication_id=valid_dec.adjudication_id, claim_state=valid_dec.state,
            weakness_cwe=claim.weakness_cwe, affected_entities=claim.affected_entities,
            predicates=_adjudication_predicates(valid_dec), relations=[rel_con], warrants=(),
        )
