"""Unit tests for ``predicate-warrants/1`` (TRI-B / T-152)."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Mapping

import pytest

from appsec_review.graph.contract import (
    AUTHORITY, CATALOG_SCHEMA, CROSS_CHECK_RULE, GRAPH_FACT_SCHEMA, NORMALIZE_RULE, Family, GraphFact,
    admissibility as graph_admissibility, fact_identity,
)
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind as IndexRelation,
    RelationRecord, RetrievalCore, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.review.evidence import classify
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import (
    Admissibility, Claim, ClaimState, Lane, Predicate, RelationKind, SecurityPredicate,
)
from appsec_review.review.warrants import (
    WARRANT_RULE_VERSION, WARRANT_SCHEMA, WarrantBasis, WarrantCoverage, WarrantReasonCode, WarrantResult,
    WarrantScope, bind_warrant_relation_id, evaluate_warrant, validate_warrant_json, warrant_from_json,
    warrant_json, warrant_satisfies_contradiction, warrant_satisfies_support,
)
from appsec_review.storage import atomic_json, file_sha256

RUN_ID = "2026-11-13-0152"
SNAPSHOT = "target-sha256:" + "5" * 64
SCOPE_DEBUG = "codeql:c/c++:debug:" + "1" * 16
SCOPE_RELEASE = "codeql:c/c++:release:" + "2" * 16
RECEIPT = "f" * 64

SOURCE_A = (
    "int parse_packet(const char *in, size_t n, size_t hdr) {\n"
    "  char dst[16];\n"
    "  char other[32];\n"
    "  if (hdr < 4) return -1;\n"
    "  if (n > 16) return -1;\n"
    "  memcpy(dst, in, n);\n"
    "  memcpy(other, in, hdr);\n"
    "  return 0;\n"
    "}\n"
)
SOURCE_B = (
    "int run_query(const char *user_sql) {\n"
    "  return exec_sql(user_sql);\n"
    "}\n"
)


def _ident(kind: EntityKind, native: str) -> LogicalIdentity:
    return LogicalIdentity.derive(kind, SNAPSHOT, {"native": native})


def _loc(source: Path, rel_path: str, needle: str, *, ambiguous: bool = False) -> SourceLocation:
    text = source.read_text(encoding="utf-8")
    start = text.index(needle)
    line = text[:start].count("\n") + 1
    end_line = line + needle.count("\n")
    col = start - (text.rfind("\n", 0, start) + 1) + 1
    end_col = len(needle) - needle.rfind("\n") if "\n" in needle else col + len(needle)
    return SourceLocation(
        SNAPSHOT, rel_path, file_sha256(source), start, start + len(needle),
        line, end_line, col, end_col, {}, "fixture-exact", 0.5 if ambiguous else 1.0, ambiguous,
    )


def _graph_entity(family: Family, native: Mapping[str, Any], result: Mapping[str, Any],
                  location: SourceLocation | None, *, scope_id: str = SCOPE_DEBUG,
                  build_unit_id: str = "debug") -> EntityRecord:
    payload: dict[str, Any] = {
        "schema": GRAPH_FACT_SCHEMA,
        "family": family.value,
        "producer": {
            "name": "codeql-export", "tool_version": "2.27.0", "export_pack_sha256": "a" * 64,
            "catalog_version": CATALOG_SCHEMA, "rule_version": NORMALIZE_RULE,
        },
        "scope": {
            "scope_id": scope_id, "language": "c/c++",
            "build_unit_id": build_unit_id, "component_id": "component:0001",
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
    identity = fact_identity(family, SNAPSHOT, {"scope_id": scope_id, **native})
    return GraphFact(identity, f"{family.value}:{identity.value[-8:]}", payload, location).to_entity()


def _op(role: str, kind: str, value: Any = None, text: str | None = None) -> dict[str, Any]:
    return {"role": role, "kind": kind, "value": value, "text": text, "location": None}


def _guard_res(sink: str, operator: str | None = ">", lhs: dict[str, Any] | None = None,
               rhs: dict[str, Any] | None = None, *, polarity: str = "false_branch",
               constrains: Any = True, capacity: int | None = 16, state: str = "dominating") -> dict[str, Any]:
    comparison = (
        {"operator": operator, "bound_display": "cmp", "operands": [lhs, rhs]}
        if operator is not None and lhs is not None and rhs is not None
        else None
    )
    return {
        "sink": {"sink_site": sink, "sink_class": "memory_write"},
        "guard_state": state,
        "polarity": polarity,
        "condition": None,
        "constrains_sink_operand": constrains,
        "comparison": comparison,
        "destination": {"object_bytes": capacity},
    }


def _range_res(sink: str, *, lower: Any = 0, upper: Any = 16, bits: int = 32,
               signed: bool = False, operand_index: int = 2, sign_change: bool = False) -> dict[str, Any]:
    return {
        "sink": {"sink_site": sink, "sink_class": "memory_write"},
        "operand_index": operand_index,
        "applicability": "integral",
        "type": {"display": f"{'int' if signed else 'uint'}{bits}_t", "signed": signed, "bits": bits},
        "interval": {"lower": lower, "upper": upper},
        "conversions": [],
        "sign_change": sign_change,
    }


def _claim(*affected: str, cwe: str | None = "CWE-787",
           sec_pred: SecurityPredicate = SecurityPredicate.MEMORY_CORRUPTION,
           idx: str = "1") -> Claim:
    return Claim(
        claim_id="claim-" + (idx * 64)[:64],
        lane=Lane.LEAD,
        package_id="package-" + ("a" * 64),
        affected_entities=tuple(sorted(affected)),
        weakness_cwe=cwe,
        security_predicate=sec_pred,
        preconditions=(),
        statement="untrusted statement prose ignored by validator",
        state=ClaimState.PROPOSED,
    )


def _eval(core: RetrievalCore, claim: Claim, predicate: Predicate, requested: RelationKind,
          entity_id: str, *, role: str | None = "blue_team_refuter",
          tool_mapping: tuple[Predicate, ...] = (),
          scope: WarrantScope | None = None, complete: bool = True):
    entity = core.find(identity=entity_id, limit=1)["results"][0]
    kind = EntityKind(entity["kind"])
    payload = entity.get("payload") if kind in {
        EntityKind.CALL_SITE, EntityKind.SINK_SITE, EntityKind.ENTRY_POINT,
        EntityKind.FLOW_SUMMARY, EntityKind.DATAFLOW_PATH, EntityKind.GUARD_FACT, EntityKind.RANGE_FACT,
    } else None
    adm = classify(kind, predicate, tool_mapping, payload if isinstance(payload, Mapping) else None)
    shard_id = f"{entity['index']}/{entity['shard_id']}"
    loc = entity.get("location")
    locator = (f"{loc['path']}:{loc['start_line']}-{loc['end_line']}#b{loc['start_byte']}-{loc['end_byte']}@{loc['file_sha256']}"
               if loc else f"{shard_id}:{entity_id}")
    return evaluate_warrant(
        core,
        claim=claim,
        predicate=predicate,
        requested_relation=requested,
        entity=entity,
        admissibility=adm,
        complete=complete,
        shard_id=shard_id,
        content_sha256=sha256_hex({"entity": entity_id}),
        locator=locator,
        retrieval_receipt_sha256=RECEIPT,
        role=role,
        scope=scope,
    )


@pytest.fixture(scope="module")
def warrant_fixture(tmp_path_factory: pytest.TempPathFactory) -> tuple[RetrievalCore, dict[str, str]]:
    base = tmp_path_factory.mktemp("warrants")
    runs = base / "runs"
    run_root = runs / RUN_ID
    target = base / "target"
    (target / "src").mkdir(parents=True)
    src_a = target / "src" / "packet.c"
    src_b = target / "src" / "db.c"
    src_a.write_text(SOURCE_A, encoding="utf-8")
    src_b.write_text(SOURCE_B, encoding="utf-8")

    loc_fn_a = _loc(src_a, "src/packet.c", SOURCE_A.rstrip("\n"))
    loc_fn_b = _loc(src_b, "src/db.c", SOURCE_B.rstrip("\n"))
    loc_sink_dst = _loc(src_a, "src/packet.c", "memcpy(dst, in, n)")
    loc_sink_other = _loc(src_a, "src/packet.c", "memcpy(other, in, hdr)")
    loc_cond_hdr = _loc(src_a, "src/packet.c", "if (hdr < 4)")
    loc_cond_n = _loc(src_a, "src/packet.c", "if (n > 16)")
    loc_param = _loc(src_a, "src/packet.c", "const char *in")
    loc_sql = _loc(src_b, "src/db.c", "exec_sql(user_sql)")
    loc_ambig = _loc(src_a, "src/packet.c", "memcpy(dst, in, n)", ambiguous=True)

    ids: dict[str, str] = {}
    analysis_entities: list[EntityRecord] = []
    analysis_relations: list[RelationRecord] = []
    graph_entities: list[EntityRecord] = []
    graph_relations: list[RelationRecord] = []
    obs_entities: list[EntityRecord] = []
    obs_relations: list[RelationRecord] = []
    build_entities: list[EntityRecord] = []
    build_relations: list[RelationRecord] = []

    def put(bucket: list[EntityRecord], key: str, rec: EntityRecord) -> str:
        ids[key] = rec.identity.value
        bucket.append(rec)
        return rec.identity.value

    sym_a = put(analysis_entities, "sym_packet",
                EntityRecord(_ident(EntityKind.SYMBOL, "parse_packet"), "parse_packet", "parse_packet", "fn", {}, loc_fn_a))
    sym_b = put(analysis_entities, "sym_db",
                EntityRecord(_ident(EntityKind.SYMBOL, "run_query"), "run_query", "run_query", "fn", {}, loc_fn_b))
    span_dst = put(analysis_entities, "span_dst",
                   EntityRecord(_ident(EntityKind.SOURCE_SPAN, "packet.c:6"), "packet.c:6", "memcpy dst", "memcpy", {}, loc_sink_dst))
    span_sql = put(analysis_entities, "span_sql",
                   EntityRecord(_ident(EntityKind.SOURCE_SPAN, "db.c:2"), "db.c:2", "exec_sql", "exec_sql", {}, loc_sql))
    span_ambig = put(analysis_entities, "span_ambig",
                     EntityRecord(_ident(EntityKind.SOURCE_SPAN, "packet.c:ambig"), "ambig", "ambig", "memcpy", {}, loc_ambig))
    span_unlinked = put(analysis_entities, "span_unlinked",
                        EntityRecord(_ident(EntityKind.SOURCE_SPAN, "db.c:unlinked"), "unlinked", "unlinked", "fn", {}, loc_fn_b))
    span_fuzzy = put(analysis_entities, "span_fuzzy",
                     EntityRecord(_ident(EntityKind.AST_NODE, "fuzzy-node"), "fuzzy", "fuzzy", "ast", {}))
    analysis_relations.append(RelationRecord(IndexRelation.CONTAINS, sym_a, span_fuzzy, False, 0.5, "heuristic macro"))

    # Sinks:
    # 1) sink_guarded: has BOTH a non-constraining sibling guard (hdr < 4) AND an effective guard (n <= 16)
    sink_guarded = put(graph_entities, "sink_guarded", _graph_entity(
        Family.SINK_SITE,
        {"path": "src/packet.c", "start_byte": loc_sink_dst.start_byte, "end_byte": loc_sink_dst.end_byte,
         "sink_class": "memory_write", "argument_index": 2},
        {"sink_class": "memory_write", "cwe_family": "CWE-787", "argument_index": 2,
         "enclosing_function": {"symbol": sym_a, "display": "parse_packet"}},
        loc_sink_dst,
    ))
    # 2) sink_other: second sink in parse_packet (32-byte buffer, ineffective guard hdr <= 64)
    sink_other = put(graph_entities, "sink_other", _graph_entity(
        Family.SINK_SITE,
        {"path": "src/packet.c", "start_byte": loc_sink_other.start_byte, "end_byte": loc_sink_other.end_byte,
         "sink_class": "memory_write", "argument_index": 2},
        {"sink_class": "memory_write", "cwe_family": "CWE-787", "argument_index": 2,
         "enclosing_function": {"symbol": sym_a, "display": "parse_packet"}},
        loc_sink_other,
    ))
    # 3) sink_unguarded: standalone sink with guard_state="none" and ineffective guard
    sink_unguarded = put(graph_entities, "sink_unguarded", _graph_entity(
        Family.SINK_SITE,
        {"path": "src/packet.c", "start_byte": loc_sink_dst.start_byte + 1, "end_byte": loc_sink_dst.end_byte,
         "sink_class": "memory_write", "argument_index": 2},
        {"sink_class": "memory_write", "cwe_family": "CWE-787", "argument_index": 2},
        loc_sink_dst,
    ))
    # 4) sink_signed: standalone sink whose range_fact has signed int32 [-100, 8]
    sink_signed = put(graph_entities, "sink_signed", _graph_entity(
        Family.SINK_SITE,
        {"path": "src/packet.c", "start_byte": loc_sink_dst.start_byte + 2, "end_byte": loc_sink_dst.end_byte,
         "sink_class": "memory_write", "argument_index": 2},
        {"sink_class": "memory_write", "cwe_family": "CWE-787", "argument_index": 2},
        loc_sink_dst,
    ))
    # 5) sink_release: sink in "release" build_unit_id
    sink_release = put(graph_entities, "sink_release", _graph_entity(
        Family.SINK_SITE,
        {"path": "src/packet.c", "start_byte": loc_sink_dst.start_byte, "end_byte": loc_sink_dst.end_byte,
         "sink_class": "memory_write", "argument_index": 2},
        {"sink_class": "memory_write", "cwe_family": "CWE-787", "argument_index": 2},
        loc_sink_dst, scope_id=SCOPE_RELEASE, build_unit_id="release",
    ))

    n_var = _op("lhs", "variable", None, "n")
    hdr_var = _op("lhs", "variable", None, "hdr")
    c16 = _op("rhs", "constant", 16, "16")
    c64 = _op("rhs", "constant", 64, "64")
    c4 = _op("rhs", "constant", 4, "4")
    dyn = _op("rhs", "other", None, "4u + out.len")

    # Guards on sink_guarded
    g_effective = put(graph_entities, "g_effective", _graph_entity(
        Family.GUARD_FACT,
        {"sink_identity": sink_guarded, "condition_path": "src/packet.c",
         "condition_start_byte": loc_cond_n.start_byte, "condition_end_byte": loc_cond_n.end_byte},
        _guard_res(sink_guarded, ">", n_var, c16, capacity=16),
        loc_cond_n,
    ))
    g_sibling_nonconstraining = put(graph_entities, "g_sibling_nonconstraining", _graph_entity(
        Family.GUARD_FACT,
        {"sink_identity": sink_guarded, "condition_path": "src/packet.c",
         "condition_start_byte": loc_cond_hdr.start_byte, "condition_end_byte": loc_cond_hdr.end_byte},
        _guard_res(sink_guarded, "<", hdr_var, c4, constrains=False, capacity=16),
        loc_cond_hdr,
    ))
    r_wrong_operand = put(graph_entities, "r_wrong_operand", _graph_entity(
        Family.RANGE_FACT,
        {"sink_identity": sink_guarded, "operand_index": 1},
        _range_res(sink_guarded, lower=0, upper=8, operand_index=1),
        loc_sink_dst,
    ))
    r_signed_nonneg = put(graph_entities, "r_signed_nonneg", _graph_entity(
        Family.RANGE_FACT,
        {"sink_identity": sink_guarded, "operand_index": 2},
        _range_res(sink_guarded, lower=0, upper=8, signed=True, operand_index=2),
        loc_sink_dst,
    ))

    # Guards/ranges on sink_unguarded
    g_none = put(graph_entities, "g_none", _graph_entity(
        Family.GUARD_FACT,
        {"sink_identity": sink_unguarded, "condition_path": "src/packet.c",
         "condition_start_byte": 0, "condition_end_byte": 0},
        _guard_res(sink_unguarded, None, None, None, polarity="unknown", constrains="unknown", capacity=16, state="none"),
        loc_sink_dst,
    ))
    g_too_wide = put(graph_entities, "g_too_wide", _graph_entity(
        Family.GUARD_FACT,
        {"sink_identity": sink_unguarded, "condition_path": "src/packet.c",
         "condition_start_byte": 1, "condition_end_byte": 2},
        _guard_res(sink_unguarded, ">", n_var, c64, capacity=16),
        loc_cond_n,
    ))
    g_inconclusive_dyn = put(graph_entities, "g_inconclusive_dyn", _graph_entity(
        Family.GUARD_FACT,
        {"sink_identity": sink_unguarded, "condition_path": "src/packet.c",
         "condition_start_byte": 3, "condition_end_byte": 4},
        _guard_res(sink_unguarded, "<", n_var, dyn, constrains="unknown", capacity=16),
        loc_cond_n,
    ))
    r_overapprox = put(graph_entities, "r_overapprox", _graph_entity(
        Family.RANGE_FACT,
        {"sink_identity": sink_unguarded, "operand_index": 2},
        _range_res(sink_unguarded, lower=0, upper=65535, bits=16, signed=False, operand_index=2),
        loc_sink_dst,
    ))

    # Guard on sink_other
    g_other_effective = put(graph_entities, "g_other_effective", _graph_entity(
        Family.GUARD_FACT,
        {"sink_identity": sink_other, "condition_path": "src/packet.c",
         "condition_start_byte": loc_cond_n.start_byte, "condition_end_byte": loc_cond_n.end_byte},
        _guard_res(sink_other, ">", hdr_var, c16, capacity=32),
        loc_cond_n,
    ))

    # Signed negative-capable sink
    g_signed_upper_only = put(graph_entities, "g_signed_upper_only", _graph_entity(
        Family.GUARD_FACT,
        {"sink_identity": sink_signed, "condition_path": "src/packet.c",
         "condition_start_byte": loc_cond_n.start_byte, "condition_end_byte": loc_cond_n.end_byte},
        _guard_res(sink_signed, ">", n_var, c16, capacity=16),
        loc_cond_n,
    ))
    r_signed_neg = put(graph_entities, "r_signed_neg", _graph_entity(
        Family.RANGE_FACT,
        {"sink_identity": sink_signed, "operand_index": 2},
        _range_res(sink_signed, lower=-100, upper=8, bits=32, signed=True, operand_index=2),
        loc_sink_dst,
    ))

    # Release-scope guard
    g_release = put(graph_entities, "g_release", _graph_entity(
        Family.GUARD_FACT,
        {"sink_identity": sink_release, "condition_path": "src/packet.c",
         "condition_start_byte": loc_cond_n.start_byte, "condition_end_byte": loc_cond_n.end_byte},
        _guard_res(sink_release, ">", n_var, c16, capacity=16),
        loc_cond_n, scope_id=SCOPE_RELEASE, build_unit_id="release",
    ))

    # Flow facts
    entry_remote = put(graph_entities, "entry_remote", _graph_entity(
        Family.ENTRY_POINT,
        {"path": "src/packet.c", "start_byte": loc_param.start_byte, "end_byte": loc_param.end_byte,
         "source_class": "remote"},
        {"source_class": "remote", "api_or_parameter": {"display": "in"}},
        loc_param,
    ))
    entry_unrelated = put(graph_entities, "entry_unrelated", _graph_entity(
        Family.ENTRY_POINT,
        {"path": "src/db.c", "start_byte": 0, "end_byte": 10, "source_class": "remote"},
        {"source_class": "remote", "api_or_parameter": {"display": "user_sql"}},
        loc_fn_b,
    ))
    path_guarded = put(graph_entities, "path_guarded", _graph_entity(
        Family.DATAFLOW_PATH,
        {"source_identity": entry_remote, "sink_identity": sink_guarded, "step_locations_sha256": "7" * 64},
        {"source": {"entry_point": entry_remote, "source_class": "remote"},
         "sink": {"sink_site": sink_guarded, "sink_class": "memory_write", "cwe_family": "CWE-787"},
         "steps": [], "hop_count": 1, "truncated_steps": False},
        loc_sink_dst,
    ))
    path_other = put(graph_entities, "path_other", _graph_entity(
        Family.DATAFLOW_PATH,
        {"source_identity": entry_remote, "sink_identity": sink_other, "step_locations_sha256": "8" * 64},
        {"source": {"entry_point": entry_remote, "source_class": "remote"},
         "sink": {"sink_site": sink_other, "sink_class": "memory_write", "cwe_family": "CWE-787"},
         "steps": [], "hop_count": 1, "truncated_steps": False},
        loc_sink_other,
    ))

    for g_id, s_id in (
        (g_effective, sink_guarded),
        (g_sibling_nonconstraining, sink_guarded),
        (g_none, sink_unguarded),
        (g_too_wide, sink_unguarded),
        (g_inconclusive_dyn, sink_unguarded),
        (g_other_effective, sink_other),
        (g_signed_upper_only, sink_signed),
        (g_release, sink_release),
    ):
        graph_relations.append(RelationRecord(IndexRelation.GUARDS, g_id, s_id, True, 1.0))
    for r_id, s_id in (
        (r_wrong_operand, sink_guarded),
        (r_signed_nonneg, sink_guarded),
        (r_overapprox, sink_unguarded),
        (r_signed_neg, sink_signed),
    ):
        graph_relations.append(RelationRecord(IndexRelation.DERIVED_FROM, r_id, s_id, True, 1.0))
    graph_relations.append(RelationRecord(IndexRelation.FLOWS_TO, entry_remote, sink_guarded, True, 1.0))

    # Tool observations (O1 numeric alert vs non-numeric SQLi alert)
    obs_numeric = put(obs_entities, "obs_numeric", EntityRecord(
        _ident(EntityKind.TOOL_OBSERVATION, "sast:overflow:packet"),
        "sast:overflow", "cpp.overflow", "potential overflow", {"rule": "cpp.overflow"}, loc_sink_dst,
    ))
    obs_sqli = put(obs_entities, "obs_sqli", EntityRecord(
        _ident(EntityKind.TOOL_OBSERVATION, "sast:sqli:db"),
        "sast:sqli", "c.sqli", "sql injection", {"rule": "c.sqli"}, loc_sql,
    ))
    art_id = put(obs_entities, "art_sarif", EntityRecord(
        _ident(EntityKind.EVIDENCE_ARTIFACT, "sarif:main"), "sarif:main", "sarif", "sarif", {"sha256": "b" * 64},
    ))
    obs_relations.append(RelationRecord(IndexRelation.DERIVED_FROM, obs_numeric, art_id, True, 1.0))
    obs_relations.append(RelationRecord(IndexRelation.DERIVED_FROM, obs_sqli, art_id, True, 1.0))

    # Build configuration entities
    cu_bound = put(build_entities, "cu_bound", EntityRecord(
        _ident(EntityKind.COMPILE_UNIT, "cu:packet:debug"),
        "cmd-sha-1", "src/packet.c", "-O0 -fno-stack-protector",
        {"compile_unit_id": "cu-1", "target_path": "src/packet.c",
         "arguments": ["-O0", "-fno-stack-protector"], "build_unit_id": "debug"},
        loc_fn_a,
    ))
    cu_stub = put(build_entities, "cu_stub", EntityRecord(
        _ident(EntityKind.COMPILE_UNIT, "cu:stub"),
        "compile_commands.json", "compile_commands.json", "compile_commands.json",
        {"compile_database_sha256": "c" * 64},
    ))
    cu_other_file = put(build_entities, "cu_other_file", EntityRecord(
        _ident(EntityKind.COMPILE_UNIT, "cu:db:debug"),
        "cmd-sha-2", "src/db.c", "-O2",
        {"compile_unit_id": "cu-2", "target_path": "src/db.c",
         "arguments": ["-O2"], "build_unit_id": "debug"},
        loc_fn_b,
    ))
    ba_truncated = put(build_entities, "ba_truncated", EntityRecord(
        _ident(EntityKind.BUILD_ACTION, "ba:truncated"),
        "cmd-trunc", "gcc", "gcc build",
        {"build_unit_id": "debug", "argv_sha256": "d" * 64, "files": ["src/packet.c"],
         "execution_capture": {"truncated": True}},
    ))
    build_relations.append(RelationRecord(IndexRelation.DERIVED_FROM, cu_bound, ba_truncated, True, 1.0))

    identities: list[IndexIdentity] = []
    for index_name, shard, ents, rels in (
        ("analysis", "default", analysis_entities, analysis_relations),
        ("graph", "cpp-debug", graph_entities, graph_relations),
        ("observations", "default", obs_entities, obs_relations),
        ("build", "default", build_entities, build_relations),
    ):
        fp = index_fingerprint(
            name=index_name, target_snapshot=SNAPSHOT, producer_artifacts=[{"sha256": "a" * 64}],
            tool_identity={"tool": "fixture"}, parser_identity="p/1",
            normalizer_identity="n/1", mapping_identity="m/1",
        )
        db_path = run_root / "data" / "indices" / index_name / shard / f"{fp}.sqlite"
        builder = IndexBuilder(db_path, name=index_name, fingerprint=fp, target_snapshot=SNAPSHOT, shard_id=shard)
        for ent in ents:
            builder.add_entity(ent)
        for rel in rels:
            builder.add_relation(rel)
        builder.add_coverage(f"{index_name}:{shard}", "complete", None)
        digest = builder.build()
        identities.append(IndexIdentity(
            index_name, "appsec-review/retrieval-index/2", digest, fp,
            db_path.relative_to(run_root).as_posix(), {"fixture": index_name}, (), shard,
        ))

    manifest = run_root / "data" / "indices" / "manifests" / "fixture.json"
    write_manifest(manifest, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=target, indexes=identities)
    attempt = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001"
    attempt.mkdir(parents=True)
    art = {
        "path": manifest.relative_to(run_root).as_posix(),
        "sha256": file_sha256(manifest),
        "size_bytes": manifest.stat().st_size,
    }
    handoff = attempt / "handoff.json"
    from tests.handoff_fixture import write_fixture_handoff
    write_fixture_handoff(run_root, handoff, {
        "source_fingerprint": SNAPSHOT, "status": "ACCEPTED", "job_id": "fixture",
        "attempt_id": "attempt_0001", "artifacts": [art], "outputs": {},
    })
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff),
        "manifest_path": art["path"], "manifest_sha256": art["sha256"],
    })
    return RetrievalCore(runs, RUN_ID), ids


# ---------------------------------------------------------------------------
# Schema & canonical serialization contract
# ---------------------------------------------------------------------------

def test_warrant_json_roundtrip_and_tamper_rejection(warrant_fixture) -> None:
    core, ids = warrant_fixture
    claim = _claim(ids["sink_guarded"])
    warrant = _eval(core, claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS, ids["g_effective"])
    rebound = bind_warrant_relation_id(warrant, "evrel-" + "9" * 64)
    doc = warrant_json(rebound)
    assert doc["schema"] == WARRANT_SCHEMA
    assert doc["rule"] == WARRANT_RULE_VERSION
    assert doc["relation_id"] == "evrel-" + "9" * 64
    parsed = warrant_from_json(doc)
    assert parsed == rebound

    tampered = copy.deepcopy(doc)
    tampered["result"] = WarrantResult.NOT_ESTABLISHED.value
    with pytest.raises(ValueError, match="warrant_id does not match"):
        warrant_from_json(tampered)

    extra_key = copy.deepcopy(doc)
    extra_key["unexpected"] = 1
    with pytest.raises(ValueError, match="keys mismatch"):
        validate_warrant_json(extra_key)


# ---------------------------------------------------------------------------
# Safeguard 1: affected_construct presence & subject binding
# ---------------------------------------------------------------------------

def test_affected_construct_bound_presence_supports_but_never_contradicts(warrant_fixture) -> None:
    core, ids = warrant_fixture
    claim = _claim(ids["sym_packet"])

    sup = _eval(core, claim, Predicate.AFFECTED_CONSTRUCT, RelationKind.SUPPORTS, ids["span_dst"], role="red_team_analyst")
    assert warrant_satisfies_support(sup)
    assert sup.basis is WarrantBasis.STRUCTURED_PRESENCE
    assert sup.reason_code is WarrantReasonCode.BOUND_PRESENCE_SUPPORTS_CONSTRUCT

    con = _eval(core, claim, Predicate.AFFECTED_CONSTRUCT, RelationKind.CONTRADICTS, ids["span_dst"], role="blue_team_refuter")
    assert not warrant_satisfies_contradiction(con)
    assert con.effective_relation is RelationKind.QUALIFIES
    assert con.reason_code is WarrantReasonCode.PRESENCE_CANNOT_CONTRADICT_CONSTRUCT


def test_affected_construct_rejects_wrong_subject_and_flags_ambiguous_links(warrant_fixture) -> None:
    core, ids = warrant_fixture
    claim = _claim(ids["sym_packet"])

    wrong = _eval(core, claim, Predicate.AFFECTED_CONSTRUCT, RelationKind.SUPPORTS, ids["span_unlinked"])
    assert wrong.effective_relation is RelationKind.QUALIFIES
    assert wrong.reason_code is WarrantReasonCode.SUBJECT_NOT_BOUND_TO_CLAIM
    assert wrong.coverage is WarrantCoverage.OUT_OF_SCOPE

    fuzzy = _eval(core, claim, Predicate.AFFECTED_CONSTRUCT, RelationKind.SUPPORTS, ids["span_fuzzy"])
    assert fuzzy.effective_relation is RelationKind.QUALIFIES
    assert fuzzy.reason_code is WarrantReasonCode.AMBIGUOUS_SUBJECT_BINDING
    assert fuzzy.coverage is WarrantCoverage.AMBIGUOUS_BINDING

    ambig_loc = _eval(core, claim, Predicate.AFFECTED_CONSTRUCT, RelationKind.SUPPORTS, ids["span_ambig"])
    assert ambig_loc.effective_relation is RelationKind.QUALIFIES
    assert ambig_loc.reason_code is WarrantReasonCode.AMBIGUOUS_SUBJECT_BINDING


# ---------------------------------------------------------------------------
# Safeguard 2: Both guard polarities & sibling-guard consistency
# ---------------------------------------------------------------------------

def test_effective_guard_contradicts_for_permitted_roles_and_cannot_support_missing_guard(warrant_fixture) -> None:
    core, ids = warrant_fixture
    claim = _claim(ids["sink_guarded"])

    blue = _eval(core, claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS,
                 ids["g_effective"], role="blue_team_refuter")
    assert warrant_satisfies_contradiction(blue)
    assert blue.reason_code is WarrantReasonCode.EFFECTIVE_GUARD_BOUNDS_DESTINATION

    red_contra = _eval(core, claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS,
                       ids["g_effective"], role="red_team_analyst")
    assert red_contra.effective_relation is RelationKind.QUALIFIES
    assert red_contra.reason_code is WarrantReasonCode.CONTRADICTION_ROLE_NOT_PERMITTED

    red_support = _eval(core, claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.SUPPORTS,
                        ids["g_effective"], role="red_team_analyst")
    assert not warrant_satisfies_support(red_support)
    assert red_support.effective_relation is RelationKind.QUALIFIES
    assert red_support.reason_code is WarrantReasonCode.EFFECTIVE_GUARD_CANNOT_SUPPORT_MISSING_GUARD


def test_cherry_picked_nonconstraining_sibling_guard_cannot_support_when_sink_is_bounded(warrant_fixture) -> None:
    core, ids = warrant_fixture
    claim = _claim(ids["sink_guarded"])
    cherry = _eval(core, claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.SUPPORTS,
                   ids["g_sibling_nonconstraining"], role="red_team_analyst")
    assert not warrant_satisfies_support(cherry)
    assert cherry.effective_relation is RelationKind.QUALIFIES
    assert cherry.reason_code is WarrantReasonCode.EFFECTIVE_GUARD_CANNOT_SUPPORT_MISSING_GUARD


def test_affirmatively_absent_or_ineffective_guard_supports_and_inconclusive_qualifies_both_ways(warrant_fixture) -> None:
    core, ids = warrant_fixture
    claim = _claim(ids["sink_unguarded"])

    absent = _eval(core, claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.SUPPORTS,
                   ids["g_none"], role="red_team_analyst")
    assert warrant_satisfies_support(absent)
    assert absent.reason_code is WarrantReasonCode.GUARD_ABSENT_AT_BOUND_SINK

    too_wide = _eval(core, claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.SUPPORTS,
                     ids["g_too_wide"], role="red_team_analyst")
    assert warrant_satisfies_support(too_wide)
    assert too_wide.reason_code is WarrantReasonCode.GUARD_INEFFECTIVE_FOR_DESTINATION

    for polarity in (RelationKind.SUPPORTS, RelationKind.CONTRADICTS):
        dyn = _eval(core, claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, polarity,
                    ids["g_inconclusive_dyn"], role="independent_verifier")
        assert dyn.effective_relation is RelationKind.QUALIFIES
        assert dyn.reason_code is WarrantReasonCode.DESTINATION_BOUND_UNPROVED

        over = _eval(core, claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, polarity,
                     ids["r_overapprox"], role="independent_verifier")
        assert over.effective_relation is RelationKind.QUALIFIES
        assert over.reason_code is WarrantReasonCode.DESTINATION_BOUND_UNPROVED


# ---------------------------------------------------------------------------
# Safeguard 3: Sink, operand, flow, and build-scope matching
# ---------------------------------------------------------------------------

def test_sink_mismatch_ambiguous_multi_sink_symbol_and_operand_mismatch(warrant_fixture) -> None:
    core, ids = warrant_fixture

    claim_single = _claim(ids["sink_unguarded"])
    wrong_sink = _eval(core, claim_single, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS,
                       ids["g_other_effective"], role="blue_team_refuter")
    assert wrong_sink.effective_relation is RelationKind.QUALIFIES
    assert wrong_sink.reason_code is WarrantReasonCode.SINK_MISMATCH

    # sym_packet encloses BOTH sink_guarded and sink_other: citing a guard on only one sink is ambiguous!
    claim_multi_sink_symbol = _claim(ids["sym_packet"])
    ambig = _eval(core, claim_multi_sink_symbol, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS,
                  ids["g_effective"], role="blue_team_refuter")
    assert ambig.effective_relation is RelationKind.QUALIFIES
    assert ambig.reason_code is WarrantReasonCode.AMBIGUOUS_SUBJECT_BINDING
    assert ambig.coverage is WarrantCoverage.AMBIGUOUS_BINDING

    claim_guarded = _claim(ids["sink_guarded"])
    wrong_op = _eval(core, claim_guarded, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS,
                     ids["r_wrong_operand"], role="blue_team_refuter")
    assert wrong_op.effective_relation is RelationKind.QUALIFIES
    assert wrong_op.reason_code is WarrantReasonCode.OPERAND_MISMATCH


def test_build_scope_mismatch_and_configuration_enables_warrants(warrant_fixture) -> None:
    core, ids = warrant_fixture
    claim_debug = _claim(ids["sink_guarded"])

    cross_build = _eval(core, claim_debug, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS,
                        ids["g_release"], role="blue_team_refuter")
    assert cross_build.effective_relation is RelationKind.QUALIFIES
    assert cross_build.reason_code is WarrantReasonCode.BUILD_SCOPE_MISMATCH

    wrong_snap = _eval(core, claim_debug, Predicate.AFFECTED_CONSTRUCT, RelationKind.SUPPORTS,
                       ids["sink_guarded"], scope=WarrantScope(target_snapshot="target-sha256:" + "0" * 64))
    assert wrong_snap.effective_relation is RelationKind.QUALIFIES
    assert wrong_snap.reason_code is WarrantReasonCode.BUILD_SCOPE_MISMATCH

    cfg_sup = _eval(core, claim_debug, Predicate.CONFIGURATION_ENABLES, RelationKind.SUPPORTS,
                    ids["cu_bound"], role="red_team_analyst")
    assert warrant_satisfies_support(cfg_sup)
    assert cfg_sup.reason_code is WarrantReasonCode.BOUND_CONFIGURATION_FACT

    cfg_con = _eval(core, claim_debug, Predicate.CONFIGURATION_ENABLES, RelationKind.CONTRADICTS,
                    ids["cu_bound"], role="blue_team_refuter")
    assert warrant_satisfies_contradiction(cfg_con)

    stub = _eval(core, claim_debug, Predicate.CONFIGURATION_ENABLES, RelationKind.SUPPORTS, ids["cu_stub"])
    assert stub.effective_relation is RelationKind.QUALIFIES
    assert stub.reason_code is WarrantReasonCode.CONFIGURATION_FACT_INCONCLUSIVE

    other_cu = _eval(core, claim_debug, Predicate.CONFIGURATION_ENABLES, RelationKind.SUPPORTS, ids["cu_other_file"])
    assert other_cu.effective_relation is RelationKind.QUALIFIES
    assert other_cu.reason_code is WarrantReasonCode.SUBJECT_NOT_BOUND_TO_CLAIM

    trunc_contra = _eval(core, claim_debug, Predicate.CONFIGURATION_ENABLES, RelationKind.CONTRADICTS,
                         ids["ba_truncated"], role="blue_team_refuter")
    assert trunc_contra.effective_relation is RelationKind.QUALIFIES
    assert trunc_contra.reason_code is WarrantReasonCode.CONFIGURATION_FACT_INCONCLUSIVE


def test_flow_and_entry_point_warrants_check_sink_binding_and_polarity(warrant_fixture) -> None:
    core, ids = warrant_fixture
    claim = _claim(ids["sink_guarded"])

    flow_ok = _eval(core, claim, Predicate.SOURCE_TO_SINK_REACHABILITY, RelationKind.SUPPORTS, ids["path_guarded"])
    assert warrant_satisfies_support(flow_ok)
    assert flow_ok.subject_binding.sink_id == ids["sink_guarded"]

    flow_wrong = _eval(core, claim, Predicate.SOURCE_TO_SINK_REACHABILITY, RelationKind.SUPPORTS, ids["path_other"])
    assert flow_wrong.effective_relation is RelationKind.QUALIFIES
    assert flow_wrong.reason_code is WarrantReasonCode.SINK_MISMATCH

    flow_contra = _eval(core, claim, Predicate.SOURCE_TO_SINK_REACHABILITY, RelationKind.CONTRADICTS, ids["path_guarded"])
    assert flow_contra.effective_relation is RelationKind.QUALIFIES
    assert flow_contra.reason_code is WarrantReasonCode.POSITIVE_FACT_CANNOT_CONTRADICT

    entry_ok = _eval(core, claim, Predicate.ATTACKER_INPUT_CONTROL, RelationKind.SUPPORTS, ids["entry_remote"])
    assert warrant_satisfies_support(entry_ok)

    entry_bad = _eval(core, claim, Predicate.ATTACKER_INPUT_CONTROL, RelationKind.SUPPORTS, ids["entry_unrelated"])
    assert entry_bad.effective_relation is RelationKind.QUALIFIES
    assert entry_bad.reason_code is WarrantReasonCode.SUBJECT_NOT_BOUND_TO_CLAIM


# ---------------------------------------------------------------------------
# Safeguards 4 & 5: Numeric machine facts, signedness, mapped non-numeric, uncommissioned
# ---------------------------------------------------------------------------

def test_numeric_weakness_rejects_o1_tool_observation_and_enforces_signedness(warrant_fixture) -> None:
    core, ids = warrant_fixture
    numeric_claim = _claim(ids["sink_guarded"], cwe="CWE-190", sec_pred=SecurityPredicate.INTEGER_ERROR)

    o1 = _eval(core, numeric_claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.SUPPORTS,
               ids["obs_numeric"], role="red_team_analyst",
               tool_mapping=(Predicate.MISSING_OR_INEFFECTIVE_GUARD,))
    assert not warrant_satisfies_support(o1)
    assert o1.effective_relation is RelationKind.QUALIFIES
    assert o1.basis is WarrantBasis.NUMERIC_BOUND_CHECK
    assert o1.reason_code is WarrantReasonCode.NUMERIC_MACHINE_FACT_REQUIRED

    # Signed range [0, 8] on 16-byte destination is safe and contradicts missing_or_ineffective_guard.
    signed_safe = _eval(core, numeric_claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS,
                        ids["r_signed_nonneg"], role="blue_team_refuter")
    assert warrant_satisfies_contradiction(signed_safe)

    # Signed negative-capable [-100, 8] neither bounds via range_fact nor via upper-only guard_fact (n <= 16).
    signed_claim = _claim(ids["sink_signed"], cwe="CWE-195", sec_pred=SecurityPredicate.MEMORY_CORRUPTION)
    neg_range = _eval(core, signed_claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS,
                      ids["r_signed_neg"], role="blue_team_refuter")
    assert neg_range.effective_relation is RelationKind.QUALIFIES
    assert neg_range.reason_code is WarrantReasonCode.DESTINATION_BOUND_UNPROVED

    upper_only = _eval(core, signed_claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS,
                       ids["g_signed_upper_only"], role="blue_team_refuter")
    assert upper_only.effective_relation is RelationKind.QUALIFIES
    assert upper_only.reason_code is WarrantReasonCode.DESTINATION_BOUND_UNPROVED

    # Upper-only guard also does not falsely prove absence of a separate lower-bound check.
    upper_only_sup = _eval(core, signed_claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.SUPPORTS,
                           ids["g_signed_upper_only"], role="red_team_analyst")
    assert upper_only_sup.effective_relation is RelationKind.QUALIFIES
    assert upper_only_sup.reason_code is WarrantReasonCode.DESTINATION_BOUND_UNPROVED


def test_non_numeric_mapped_observation_retained_and_uncommissioned_semantics_remain_qualified(warrant_fixture) -> None:
    core, ids = warrant_fixture
    sqli_claim = _claim(ids["sym_db"], cwe="CWE-89", sec_pred=SecurityPredicate.SQL_INJECTION)

    sqli_obs = _eval(core, sqli_claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.SUPPORTS,
                     ids["obs_sqli"], role="red_team_analyst",
                     tool_mapping=(Predicate.MISSING_OR_INEFFECTIVE_GUARD,))
    assert warrant_satisfies_support(sqli_obs)
    assert sqli_obs.basis is WarrantBasis.MAPPED_TOOL_OBSERVATION
    assert sqli_obs.reason_code is WarrantReasonCode.BOUND_MAPPED_EVIDENCE

    for sec_pred, cwe in (
        (SecurityPredicate.AUTHZ_BYPASS, "CWE-862"),
        (SecurityPredicate.RACE_CONDITION, "CWE-362"),
        (SecurityPredicate.RESOURCE_EXHAUSTION, "CWE-400"),
    ):
        uncomm_claim = _claim(ids["sym_db"], cwe=cwe, sec_pred=sec_pred)
        uncomm = _eval(core, uncomm_claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.SUPPORTS,
                       ids["obs_sqli"], role="red_team_analyst",
                       tool_mapping=(Predicate.MISSING_OR_INEFFECTIVE_GUARD,))
        assert uncomm.effective_relation is RelationKind.QUALIFIES
        assert uncomm.result is WarrantResult.UNCOMMISSIONED
        assert uncomm.reason_code is WarrantReasonCode.UNCOMMISSIONED_SEMANTIC_PREDICATE

    narrative = _eval(core, sqli_claim, Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS,
                      ids["span_sql"], role="blue_team_refuter")
    assert narrative.effective_relation is RelationKind.QUALIFIES
    assert narrative.result is WarrantResult.UNCOMMISSIONED
    assert narrative.reason_code is WarrantReasonCode.INDIRECT_OR_ANALYST_ASSESSED

    impact = _eval(core, sqli_claim, Predicate.SECURITY_IMPACT, RelationKind.SUPPORTS, ids["span_sql"])
    assert impact.effective_relation is RelationKind.QUALIFIES
    assert impact.result is WarrantResult.UNCOMMISSIONED
    assert impact.reason_code is WarrantReasonCode.UNCOMMISSIONED_SEMANTIC_PREDICATE
