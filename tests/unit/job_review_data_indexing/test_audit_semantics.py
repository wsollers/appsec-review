"""Offline producer/reader regressions for T-5173, T-5174 and T-5175."""

from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

from appsec_review.indexing import links, matrix, products
from appsec_review.indexing.derive import Derived, fact, publish_derived
from appsec_review.indexing.inventory import InventoryInputs, build_inventory
from appsec_review.indexing.store import ShardSet, accepted_handoff, as_identity, digest
from appsec_review.jobs.job_review_data_indexing.job import JOB_ID, build_job
from appsec_review.jobs.job_review_data_indexing.datasets import CONTRACT
from appsec_review.jobs.job_owasp_control_assessment.datasets import DATASETS as OWASP_DATASETS
from appsec_review.owasp_workbench.indexes import publish_manifest, publish_shard
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity,
    RetrievalCore, SourceLocation, write_manifest,
)
from appsec_review.retrieval.core import RetrievalLimits
from appsec_review.runtime import UnitContext
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff
from tests.unit.job_review_data_indexing.test_handlers import _seed_unit_run


SNAPSHOT = "target-sha256:" + "9" * 64
OWASP = "job_owasp_control_assessment"
ROOT = Path(__file__).resolve().parents[3]


def _entity(kind, key, payload=None, *, native=None, location=None):
    identity = LogicalIdentity.derive(kind, SNAPSHOT, {"key": key})
    return EntityRecord(identity, native or key, key, key, payload or {}, location)


def _shard(run, index, shard_id, job, entities=(), *, coverage=("complete",), producer=None):
    fp = digest({"index": index, "shard": shard_id})
    path = run / "data" / "indices" / index / shard_id / f"{fp}.sqlite"
    builder = IndexBuilder(path, name=index, fingerprint=fp, target_snapshot=SNAPSHOT, shard_id=shard_id)
    for item in entities:
        builder.add_entity(item)
    for number, status in enumerate(coverage):
        builder.add_coverage(f"scope-{number}", status, None if status == "complete" else f"scope-{number} failed")
    return asdict(IndexIdentity(index, "appsec-review/retrieval-index/2", builder.build(), fp,
                                path.relative_to(run).as_posix(), {"job": job, **(producer or {})}, (), shard_id))


@pytest.mark.parametrize("states,expected", [
    (("unavailable",), "unavailable"), (("partial",), "partial"),
    (("complete", "unavailable"), "partial"), ((), "partial"), (("complete",), "complete"),
])
def test_codeql_language_and_unit_require_actual_coverage(tmp_path, states, expected):
    shard = _shard(tmp_path, "observations", "codeql-python", "job_codeql_analysis",
                   coverage=states, producer={"language": "python", "scope_id": "unit-python"})
    store = ShardSet(tmp_path, [shard])
    language = matrix.language_matrix(store, {})[0]["lanes"]["codeql"]
    unit = matrix.build_unit_matrix(store)[0]["lanes"]["codeql"]
    assert language["state"] == unit["state"] == expected
    if expected != "complete":
        assert "coverage" in language["basis"]
        assert language.get("gaps")


def test_codeql_failed_scope_does_not_contaminate_other_languages_or_units(tmp_path):
    store = ShardSet(tmp_path, [
        _shard(tmp_path, "observations", name, "job_codeql_analysis", coverage=(status,),
               producer={"language": language, "scope_id": name})
        for name, language, status in (("py-ok", "python", "complete"), ("py-failed", "python", "unavailable"),
                                       ("js-ok", "javascript", "complete"))
    ])
    languages = {row["language"]: row["lanes"]["codeql"]["state"] for row in matrix.language_matrix(store, {})}
    units = {row["build_unit_id"]: row["lanes"]["codeql"]["state"] for row in matrix.build_unit_matrix(store)}
    assert languages == {"javascript/typescript": "complete", "python": "partial"}
    assert units == {"js-ok": "complete", "py-failed": "unavailable", "py-ok": "complete"}


@pytest.mark.parametrize("bound,pairs,emitted,omitted", [(1, 1, 0, 3), (3, 1, 3, 0), (4, 2, 3, 3)])
def test_advisory_link_budget_reserves_whole_provenance_bundle(tmp_path, bound, pairs, emitted, omitted):
    records = [_entity(EntityKind.TOOL_OBSERVATION, str(i),
                       {"package": f"pkg-{i}", "advisory": f"CVE-2026-{1000+i}"}) for i in range(pairs)]
    shard = _shard(tmp_path, "observations", "grype", "job_evidence_collection", records)
    store = ShardSet(tmp_path, [shard])
    derived = links.link_rule("package_advisory").build(links.LinkContext(SNAPSHOT, store, bound), store.shards)
    assert len(derived.relations) == emitted
    assert len(derived.entities) == 2 * (emitted // 3)
    assert derived.counts.get("omitted_relations", 0) == omitted
    assert derived.counts["candidate_relations"] == emitted + omitted
    assert derived.counts.get("exact_links", 0) + derived.counts.get("ambiguous_links", 0) == emitted
    assert any("truncated" in gap for gap in derived.gaps) == bool(omitted)


def test_symbol_fanout_applies_relation_not_row_bound(tmp_path):
    location = SourceLocation(SNAPSHOT, "src/app.c", "a" * 64, 0, 10, 1, 1, 1, 11, {}, "exact", 1.0)
    symbol = _entity(EntityKind.SYMBOL, "symbol", location=location)
    nodes = [_entity(EntityKind.AST_NODE, f"node-{i}", {"named": True}, location=location) for i in range(5)]
    shards = [
        _shard(tmp_path, "analysis", "symbols", "job_target_catalog", [symbol]),
        _shard(tmp_path, "analysis", "syntax", "job_tree_sitter_ast", nodes),
    ]
    store = ShardSet(tmp_path, shards)
    derived = links.link_rule("symbol_syntax").build(links.LinkContext(SNAPSHOT, store, 1), store.shards)
    assert len(derived.relations) == 1
    assert derived.counts["candidate_relations"] == 5
    assert derived.counts["omitted_relations"] == 4
    assert derived.relations[0].source_id == min(node.identity.value for node in nodes)


@pytest.mark.parametrize("family", ["representation", "history_code", "finding_source"])
def test_other_link_rules_conserve_emitted_and_omitted_edges(tmp_path, family):
    location = SourceLocation(SNAPSHOT, "src/app.c", "a" * 64, 0, 10, 1, 1, 1, 11, {}, "exact", 1.0)
    if family == "representation":
        shards = [
            _shard(tmp_path, "artifacts", "catalog-a", "job_artifact_indexing",
                   [_entity(EntityKind.BUILD_ARTIFACT, f"artifact-{i}",
                            {"build_unit_id": "case", "sha256": "b" * 64, "workspace_path": f"out-{i}"})
                    for i in range(3)]),
            _shard(tmp_path, "build", "cpp-case-compiled", "job_cpp_compiled_analysis",
                   [_entity(EntityKind.BUILD_ARTIFACT, "compiled", {"sha256": "b" * 64})]),
        ]
    elif family == "history_code":
        shards = [
            _shard(tmp_path, "history", "history", "job_source_history_analysis",
                   [_entity(EntityKind.HISTORY_SIGNAL, "history", native="symbol:fn", location=location)]),
            _shard(tmp_path, "analysis", "syntax", "job_tree_sitter_ast",
                   [_entity(EntityKind.AST_NODE, f"node-{i}", {"named": True}, location=location)
                    for i in range(3)]),
        ]
    else:
        shards = [
            _shard(tmp_path, "source", "catalog-a", "job_target_catalog",
                   [_entity(EntityKind.SOURCE_FILE, "file", location=location)]),
            _shard(tmp_path, "observations", "semgrep", "job_evidence_collection",
                   [_entity(EntityKind.TOOL_OBSERVATION, f"obs-{i}", location=location) for i in range(3)]),
        ]
    store = ShardSet(tmp_path, shards)
    rule = links.link_rule(family)
    result = publish_derived(tmp_path, index="links", shard_id=f"links-{family}", job_id=JOB_ID,
                            unit_id="links.cross_domain", rule=family, rule_version=rule.version,
                            snapshot=SNAPSHOT, inputs={"bound": 1},
                            build=lambda: rule.build(links.LinkContext(SNAPSHOT, store, 1), store.shards))
    assert result["counts"]["relations"] == 1
    assert result["counts"]["omitted_relations"] == 2
    assert result["counts"]["candidate_relations"] == 3
    assert result["terminal_status"] == "PARTIAL"


@pytest.mark.parametrize("count", [16, 17, 40])
def test_threat_nested_bounds_preserve_totals_and_qualify_omissions(tmp_path, count):
    boundary = "network"
    state = {
        "status": "accepted", "handoff_sha256": "b" * 64, "gaps": [],
        "dfd": {
            "boundaries": [{"id": boundary, "elements": ["server"]}],
            "flows": [{"id": f"flow-{i:03}", "source": "client", "target": "server", "crosses": [boundary]}
                      for i in reversed(range(count))],
            "entry_points": [{"id": f"entry-{i:03}", "element_id": "server"} for i in reversed(range(count))],
        },
        "threat_model": {"threats": [{"id": f"threat-{i:03}", "boundaries": [boundary]}
                                    for i in reversed(range(count))]},
    }
    context = products.ProductContext(tmp_path, SNAPSHOT, ShardSet(tmp_path, ()), {}, {}, {}, 100,
                                      threat_model=state)
    rule = products.product_rule("threat_boundaries")
    derived = rule.build(context, ())
    payload = derived.entities[0].payload
    result = payload["result"]
    for total, detail in (("flow_count", "cross_boundary_flows"), ("entry_point_count", "entry_points"),
                          ("threat_count", "threats")):
        assert result[total] == count
        assert len(result[detail]) == 16
    assert result["cross_boundary_flows"][0]["flow_id"] == "flow-000"
    assert payload["coverage_status"] == ("partial" if count > 16 else "complete")
    assert derived.coverage[0][1] == payload["coverage_status"]
    if count > 16:
        assert any(f"{count - 16}" in gap and "cross_boundary_flows" in gap for gap in payload["gaps"])
        assert any("truncated" in gap for gap in derived.gaps)
    jsonschema.validate(result, json.loads((ROOT / "docs/schemas/indexing/threat-boundary-index.schema.json").read_text()))


def test_canonical_threat_producer_flow_counts_survive_index_and_reader(tmp_path):
    from dataclasses import replace
    from appsec_review.threat_model.assemble import Assembly
    from appsec_review.threat_model.contract import Origin, element_id
    from appsec_review.threat_model.documents import build_documents, plain
    from tests.test_threat_model_documents import documents

    seed = documents()
    original = next(flow for flow in seed.dfd["flows"] if flow.crosses)
    boundary = original.crosses[0]
    assembly = Assembly(elements=tuple(seed.dfd["elements"]), boundaries=tuple(seed.dfd["boundaries"]),
                        flows=tuple(replace(original, id=element_id("flow", str(i)), crosses=(boundary,))
                                    for i in range(40)))
    run = tmp_path / "2026-11-19-5174"
    target = tmp_path / "target"
    target.mkdir()
    built = build_documents(Origin(run.name, "attempt_0001", SNAPSHOT, {}), assembly, (), (), ())
    state = {"status": "accepted", "handoff_sha256": "b" * 64, "dfd": plain(built.dfd),
             "threat_model": plain(built.threat_model), "gaps": []}
    context = products.ProductContext(run, SNAPSHOT, ShardSet(run, ()), {}, {}, {}, 100, threat_model=state)
    rule = products.product_rule("threat_boundaries")
    publication = publish_derived(
        run, index="precomputed", shard_id="qs-threat_boundaries", job_id=JOB_ID,
        unit_id="precompute.threat_boundaries", rule=rule.query_set, rule_version=rule.version, snapshot=SNAPSHOT,
        inputs={"threat_model": state["handoff_sha256"]}, build=lambda: rule.build(context, ()),
        producer={"query_set": rule.query_set})
    manifest = run / "data/indices/manifests/test.json"
    write_manifest(manifest, run_id=run.name, target_snapshot=SNAPSHOT, target_root=target,
                   indexes=[as_identity(publication["index_identity"])])
    core = RetrievalCore(tmp_path, run.name, manifest_path=manifest, manifest_sha256=file_sha256(manifest))
    response = core.query_threat_boundaries(boundary_id=boundary, limit=1)
    payload = response["results"][0]["payload"]
    assert payload["result"]["flow_count"] == built.result["counts"]["flows"] == 40
    assert len(payload["result"]["cross_boundary_flows"]) == 16
    assert payload["coverage_status"] == "partial"
    assert any("24 of 40" in gap for gap in payload["gaps"])
    assert response["coverage_gaps"]


def _core(tmp_path, count=80, *, limits=None, shards=1, query_set="threat_boundaries", results=None):
    run = tmp_path / "2026-11-19-5174"
    target = tmp_path / "target"
    target.mkdir()
    count = len(results) if results is not None else count
    records = [fact(SNAPSHOT, query_set, "test/1", {"id": i}, name=f"boundary-{i}",
                    text="boundary", result=results[i] if results is not None else {
                        "boundary_id": f"boundary-{i}", "source_paths": ["src/app.c"]},
                    basis="inert fixture", upstream=[]) for i in range(count)]
    identities = []
    for n in range(shards):
        publication = publish_derived(run, index="precomputed", shard_id=f"qs-threat-{n}", job_id=JOB_ID,
                                      unit_id=f"precompute.{query_set}", rule=query_set,
                                      rule_version="test/1", snapshot=SNAPSHOT, inputs={"n": n},
                                      build=lambda n=n: Derived(entities=records[n::shards],
                                                               coverage=[(query_set, "partial", "fixture gap")]),
                                      producer={"query_set": query_set})
        identities.append(as_identity(publication["index_identity"]))
    manifest = run / "data/indices/manifests/test.json"
    write_manifest(manifest, run_id=run.name, target_snapshot=SNAPSHOT, target_root=target, indexes=identities)
    return RetrievalCore(tmp_path, run.name, manifest_path=manifest, manifest_sha256=file_sha256(manifest),
                         limits=limits or RetrievalLimits()), records


def test_filtered_query_materializes_only_page_and_resumes_without_loss(tmp_path, monkeypatch):
    core, records = _core(tmp_path, shards=2)
    materialized = []
    original = core._entity

    def counted(row, index):
        materialized.append(row["identity"])
        return original(row, index)

    monkeypatch.setattr(core, "_entity", counted)
    first = core.query_threat_boundaries(path="src/app.c", limit=1)
    assert len(materialized) <= 2
    assert first["coverage_gaps"]
    ids = [first["results"][0]["identity"]]
    cursor = first["pagination"]["next_cursor"]
    while cursor:
        response = core.query_threat_boundaries(path="src/app.c", limit=1, cursor=cursor)
        ids.extend(item["identity"] for item in response["results"])
        cursor = response["pagination"]["next_cursor"]
    assert ids == sorted(item.identity.value for item in records)
    with pytest.raises(ValueError, match="cursor"):
        core.query_threat_boundaries(path="other.c", limit=1, cursor=first["pagination"]["next_cursor"])


def test_filtered_python_predicate_scan_budget_has_continuation(tmp_path):
    core, _ = _core(tmp_path, count=12, limits=RetrievalLimits(max_results=3))
    visited = []

    def no_match(payload, result):
        visited.append(result["boundary_id"])
        return False

    cursor = None
    for page in range(4):
        response = core._query_precomputed_filtered("test-filter", "threat_boundaries", {}, no_match,
                                                    limit=1, cursor=cursor)
        assert len(visited) == (page + 1) * 3
        assert response["results"] == []
        cursor = response["pagination"]["next_cursor"]
        assert bool(cursor) == (page < 3)
        if cursor:
            assert response["truncated"] and any("scan bound" in gap for gap in response["coverage_gaps"])
    assert len(set(visited)) == 12


def test_filtered_python_predicate_checks_deadline(tmp_path):
    core, _ = _core(tmp_path, count=12)
    now = [0.0]
    core.clock = lambda: now[0]

    def delayed(payload, result):
        now[0] = 5.0
        return False

    response = core._query_precomputed_filtered("test-deadline", "threat_boundaries", {}, delayed, limit=1)
    assert response["results"] == [] and response["truncated"]
    assert any("execution-time budget exceeded" in gap for gap in response["coverage_gaps"])


def test_bounded_owasp_query_keeps_verification_filters_and_gaps(tmp_path):
    valid = {"assessment_mode": "assessment", "component_id": "api", "control_identity": "asvs:5:V1",
             "applicability": "applicable", "control_status": "not_satisfied",
             "verification_status": "independently_assessed", "unresolved_evidence": 0,
             "evidence": [{"source_identity": _entity(EntityKind.SOURCE_FILE, "src").identity.value, "resolved": True}]}
    core, records = _core(tmp_path, query_set="control_evidence", results=[
        valid, {**valid, "verification_status": "unresolved"}, {**valid, "evidence": []},
        {**valid, "assessment_mode": "qualification"}])
    response = core.query_owasp_gaps(component_id="api", control_id="V1", status="not_satisfied")
    assert [row["identity"] for row in response["results"]] == [records[0].identity.value]
    assert response["coverage_gaps"]
    assert core.query_owasp_gaps(component_id="other")["results"] == []
    with pytest.raises(ValueError, match="not_satisfied"):
        core.query_owasp_gaps(status="satisfied")


def test_filtered_keyset_preserves_byte_withheld_results(tmp_path):
    core, records = _core(tmp_path, count=8)
    sample = core.query_threat_boundaries(limit=3)
    one = core.query_threat_boundaries(limit=1)
    # Leave space for omission diagnostics, but not the original three-result page.
    from dataclasses import replace
    from appsec_review.retrieval.model import canonical_json
    bound = (len(canonical_json(one)) + len(canonical_json(sample))) // 2
    assert bound < len(canonical_json(sample))
    core.limits = replace(core.limits, max_response_bytes=bound)
    identities, cursor = [], None
    for _ in range(12):
        response = core.query_threat_boundaries(limit=3, cursor=cursor)
        identities.extend(row["identity"] for row in response["results"])
        cursor = response["pagination"]["next_cursor"]
        if cursor is None:
            break
    assert cursor is None
    assert identities == sorted(row.identity.value for row in records)


@pytest.mark.parametrize("query_set", ["history_context", "build_provenance"])
@pytest.mark.parametrize("maximum", [1, 4])
def test_composed_product_obeys_final_fact_budget_and_reuses(tmp_path, query_set, maximum):
    ctx, providers, _ = _seed_unit_run(tmp_path, settings_overrides={"max_facts_per_product": maximum})
    run = ctx.run_root
    loc = SourceLocation(SNAPSHOT, "src/app.c", "a" * 64, 0, 10, 1, 1, 1, 11, {}, "exact", 1.0)
    if query_set == "history_context":
        shards = [
            _shard(run, "history", "history-extra", "job_source_history_analysis",
                   [_entity(EntityKind.HISTORY_SIGNAL, "history", {"path": "src/app.c"}, native="file:src/app.c",
                            location=loc)]),
            _shard(run, "priority", "priority-extra", "job_review_prioritization",
                   [_entity(EntityKind.PRIORITY_ITEM, "priority", {"path": "src/app.c", "scope": "file",
                            "features": {}, "score": 0.5}, native="file:src/app.c", location=loc)]),
        ]
    else:
        shards = [
            _shard(run, "artifacts", "catalog-extra", "job_artifact_indexing",
                   [_entity(EntityKind.BUILD_ARTIFACT, "artifact", {"build_unit_id": "u1"})]),
            _shard(run, "build", "build-extra", "job_language_build",
                   [_entity(EntityKind.BUILD_ACTION, "action", {"build_unit_id": "u1", "tool": "cc"})]),
        ]
    doc = run / "data/inputs-fixture.json"
    atomic_json(doc, {"target_snapshot": SNAPSHOT, "shards": shards, "restored_shards": [],
                      "feeds": {}, "owasp": {}})
    unit = next(u for u in build_job(providers=lambda: providers).units if u.unit_id == f"precompute.{query_set}")
    root = ctx.attempt_root / "steps/precompute/tasks" / query_set
    root.mkdir(parents=True)
    context = UnitContext(ctx, unit.unit_id, "precompute", query_set, root, {
        "load.accepted_inputs": {"artifact": {"path": doc.relative_to(run).as_posix(), "sha256": file_sha256(doc)}},
        "links.cross_domain": {"links": []},
    })
    result = unit.handler(context)
    assert result["fact_count"] == result["counts"]["facts"] == min(maximum, 2)
    assert result["counts"]["omitted_facts"] == max(0, 2 - maximum)
    assert result["status"] == "partial"
    assert any("composed" in gap for gap in result["gaps"]) == (maximum == 1)
    retained = list(ShardSet(run, [result["index_identity"]]).entities([result["index_identity"]]))
    assert len(retained) == min(maximum, 2)
    again = unit.handler(context)
    assert again["reused"] and again["index_identity"]["sha256"] == result["index_identity"]["sha256"]


def _owasp_input(run, *, corruption=None):
    member = publish_shard(run, family="control-result", shard_id="controls", records=[{"row_id": "one"}],
                           fingerprint_inputs={}, gaps=["control assessment incomplete"])
    if corruption == "count":
        member["record_count"] = 17
    if corruption == "family":
        member["family"] = "standards"
    manifest = publish_manifest(run, run_id=run.name, shards=[member], accepted_upstream_manifest={},
                                configuration_sha256="c" * 64, assessment_mode="assessment")
    refs = [{"path": r["path"], "sha256": r["sha256"]} for r in (member, manifest)]
    if corruption == "unadmitted":
        refs = refs[1:]
    handoff_path = run / f"data/jobs/{OWASP}/attempts/attempt_0001/handoff.json"
    atomic_json(handoff_path.with_name("claim.json"), {
        "dataset_contract": dataset_contract(OWASP, sorted({d.step for d in OWASP_DATASETS}), OWASP_DATASETS)})
    write_fixture_handoff(run, handoff_path, {
        "job_id": OWASP, "attempt_id": "attempt_0001", "status": "ACCEPTED",
        "completion_status": "COMPLETED_WITH_GAPS", "source_fingerprint": SNAPSHOT,
        "outputs": {}, "artifacts": refs,
    })
    atomic_json(handoff_path.parent.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1", "attempt_id": "attempt_0001",
        "handoff_path": handoff_path.relative_to(run).as_posix(), "handoff_sha256": file_sha256(handoff_path)})
    accepted = accepted_handoff(run, OWASP)
    if corruption == "tampered":
        (run / member["path"]).write_text("{}")
    if corruption == "missing":
        (run / member["path"]).unlink()
    return InventoryInputs(run, run.name, SNAPSHOT, {OWASP: sorted({d.step for d in OWASP_DATASETS})},
                           {OWASP: OWASP_DATASETS}, {}, {OWASP: accepted}, {}, []), handoff_path


def test_inventory_ignores_unadmitted_floating_owasp_pointer(tmp_path):
    run = tmp_path / "2026-11-19-5175"
    inputs, _ = _owasp_input(run)
    inputs.handoffs = {OWASP: None}
    (run / "data/indexes/owasp/accepted.json").write_text("{untrusted malformed pointer")
    result = build_inventory(inputs)
    assert result["audit"]["status"] == "PASSED", result["audit"]
    assert not any(row["store"] == "owasp" and row["disposition"] == "indexed" for row in result["rows"])


def test_inventory_uses_admitted_owasp_bytes_and_records_member_reads(tmp_path):
    run = tmp_path / "2026-11-19-5175"
    inputs, path = _owasp_input(run)
    (run / "data/indexes/owasp/accepted.json").write_text("{untrusted malformed pointer")
    ctx = SimpleNamespace(run_root=run, config=SimpleNamespace(job_id=JOB_ID), contract=CONTRACT,
                          upstream_handoffs={OWASP: file_sha256(path)})
    with input_read_scope(ctx) as reads:
        result = build_inventory(inputs)
    assert result["audit"]["status"] == "PASSED", result["audit"]
    rows = [row for row in result["rows"] if row["store"] == "owasp" and row["disposition"] == "indexed"]
    assert len(rows) == 1 and rows[0]["record_count"] == 1, result["audit"]
    assert rows[0]["coverage"]["state"] == "partial"
    observed = reads.document()["reads"]
    assert sum(record["output_kind"] == "owasp_workbench" for record in observed) >= 2


@pytest.mark.parametrize("corruption", ["count", "family", "unadmitted", "tampered", "missing", "target"])
def test_inventory_rejects_invalid_owasp_members(tmp_path, corruption):
    run = tmp_path / "2026-11-19-5175"
    inputs, _ = _owasp_input(run, corruption=corruption)
    if corruption == "target":
        inputs.target_snapshot = "target-sha256:" + "0" * 64
    result = build_inventory(inputs)
    assert result["audit"]["status"] == "FAILED"
    assert any(row["code"] == "invalid_owasp_publication" for row in result["audit"]["violations"])
    assert not any(row["store"] == "owasp" and row["disposition"] == "indexed" for row in result["rows"])


def test_inventory_owasp_permission_is_not_granted_by_available_handoff(tmp_path):
    run = tmp_path / "2026-11-19-5175"
    inputs, _ = _owasp_input(run)
    context = SimpleNamespace(run_root=run, config=SimpleNamespace(job_id=JOB_ID), contract=CONTRACT,
                              upstream_handoffs={})
    with pytest.raises(ValueError, match="input contract violation.*unsupplied"):
        with input_read_scope(context):
            build_inventory(inputs)
