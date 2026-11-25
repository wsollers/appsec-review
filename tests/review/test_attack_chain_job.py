"""Static per-finding path assessment and accepted manifest -> protected reports. No worker calls."""
from __future__ import annotations

from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.graph.contract import Family
from appsec_review.jobs.job_inference_security_review import chains
from appsec_review.reporting.dossier_render import render_dossier_markdown
from appsec_review.reporting.dossiers import build_dossier
from appsec_review.reporting.executive_report import BoundDossier, _finding_blocks
from appsec_review.retrieval import EntityKind, EntityRecord, LogicalIdentity, RetrievalCore, write_manifest
from appsec_review.review.budget import JobBudget
from appsec_review.review.evidence import resolve_relation
from appsec_review.storage import file_sha256
from appsec_review.review.ledger import LedgerWriter, merge_shards, project, relation_json
from appsec_review.review.models import ClaimState, IntegrityError, Predicate, RelationKind
from tests.dossier_fixture import seed
from tests.fixtures.inference_review.acceptance import JOB, ROOT
from tests.review.test_attack_chains import SCHEMAS, claims
from tests.review.test_graph_admissibility import CELL, RECEIPT, RUN_ID, SNAPSHOT, accepted_graph_run, graph_entity, results_for


class ChainInfer:
    def __init__(self, *, inner=None):
        self.inner, self.requests = inner, []

    def __call__(self, request, *, timeout_seconds):
        assert not request.task_input.get("task", "").startswith("chain_"), "path checking must not launch a model"
        return self.inner(request, timeout_seconds=timeout_seconds)


def stored_alternate(tmp_path, mode):
    from appsec_review.jobs.job_code_graph_index.alternate_cpg import ALTERNATE_CPG_SCHEMA, publish_alternate_cpg
    root = tmp_path / "runs" / RUN_ID
    target = tmp_path / "source"
    target.mkdir()
    source = target / "notes.py"
    source.write_text("# note\n" * 3)
    nodes, hops = [], []
    for i, name in enumerate(("receiveNote", "checkNote", "storeNote")):
        node = {"node_id": f"node:{i}", "name": name, "node_kind": "function" if i < 2 else "sink",
                "resolution_tier": "clangd_semantic", "language": "python", "path": "notes.py",
                "start_line": i + 1, "end_line": i + 1,
                "location": {"confidence": 1.0, "ambiguous": False, "file_sha256": file_sha256(source),
                             "mapping_method": "pinned", "start_byte": i * 7, "end_byte": i * 7 + 6}}
        nodes.append(node)
        if i:
            hops.append({"step_index": i - 1, "edge_id": f"edge:{i}", "source_id": f"node:{i - 1}",
                         "target_id": f"node:{i}", "source_name": nodes[i - 1]["name"], "target_name": name,
                         "edge_kind": "CALLS", "exact": i == 1, "path": "notes.py", "line": i,
                         "resolution_tier": "clangd_semantic" if i == 1 else "syntactic_fallback",
                         "guard_dominators": [{"branch": "true_branch", "guard_expression": "scopePresent"}]})
    path_id = "cpg:path:example"
    record = {"schema": ALTERNATE_CPG_SCHEMA, "record_type": "cpg_path", "path_id": path_id,
              "source_id": "node:0", "sink_id": "node:2", "hop_count": 2, "resolution_tier": "hybrid_fused",
              "entrypoint_linked": True, "hops": hops, "exact": False}
    if mode == "alt_disconnected":
        hops[1]["source_id"] = "node:0"
    if mode == "alt_structured":  # Force the publisher's second, structured record encoding.
        record["producer_note"] = "n" * 9000
    _, shard = publish_alternate_cpg(root, root / "publication", {"run_id": RUN_ID, "target_snapshot": SNAPSHOT,
        "nodes": nodes, "edges": [], "paths": [record]}, job_id="job_code_graph_index", unit_id="fixture")
    manifest = root / "manifest.json"
    write_manifest(manifest, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=target, indexes=[shard])
    core = RetrievalCore(root.parent, RUN_ID, manifest_path=manifest, manifest_sha256=file_sha256(manifest))
    return core, {"ordered": LogicalIdentity.derive(EntityKind.DATAFLOW_PATH, SNAPSHOT, {"cpg_path_id": path_id}).value,
                  "sink": LogicalIdentity.derive(EntityKind.SINK_SITE, SNAPSHOT, {"cpg_node_id": "node:2"}).value}


def fixture(tmp_path, mode):
    def extra(ids, add, condition, sink_span, call):
        steps = []
        for n, (name, loc, role) in enumerate([("receiveNote", condition, "source"), ("checkNote", sink_span, "call"),
                                               ("storeNote", call, "sink")]):
            sym = LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"name": name})
            add(name, EntityRecord(sym, name, name, "", {}))
            steps.append({"n": n, "location": asdict(loc), "role": role, "symbol": sym.value})
        if mode == "ambiguous":
            steps[1]["location"]["ambiguous"] = True
        result = {**results_for(Family.DATAFLOW_PATH, sink=ids["sink"], entry=ids["entry"]), "steps": steps,
                  "hop_count": 5 if mode == "partial" else 2, "truncated_steps": mode == "partial",
                  "guards": [ids["guard"]], "sanitizers": [{"api": "scopeFilter", "location": asdict(condition)}]}
        add("ordered", graph_entity(Family.DATAFLOW_PATH, {"source_identity": ids["entry"], "sink_identity": ids["sink"],
                                                       "step_locations_sha256": "a" * 64}, result, call))

    if mode.startswith("alt_"):
        core, ids = stored_alternate(tmp_path, mode)
    else:
        runs, ids = accepted_graph_run(tmp_path, extra, family=Family.DATAFLOW_PATH)
        core = RetrievalCore(runs, RUN_ID)
    settings = load_config(ROOT / "appsec-review.toml").job(JOB).typed_settings
    ctx = SimpleNamespace(run_root=core.run_root, run_id=RUN_ID, core=core, schemas=SCHEMAS,
                          budget=JobBudget(tmp_path / "budget", settings.budgets),
                          settings=replace(settings, rounds=replace(settings.rounds, max_attack_chains=3)))
    left, right = claims()
    if mode == "different_sink":
        left = replace(left, affected_entities=("asr:sink_site:" + "1" * 64,))
    elif mode != "foreign_sink":
        left = replace(left, affected_entities=(ids["sink"],))
    root = core.run_root / "data" / "check"
    writer = LedgerWriter(root / "input.jsonl", "adjudication")
    for claim in (left, right):
        writer.propose_claim(claim)
        writer.transition(claim.claim_id, ClaimState.PROPOSED, ClaimState.SUPPORTED, reason="adjudication",
                          adjudication_id="adjudication-" + "a" * 64)
        writer.transition(claim.claim_id, ClaimState.SUPPORTED, ClaimState.CONFIRMED, reason="adjudication",
                          adjudication_id="adjudication-" + "b" * 64)
    def resolve(kind):
        return resolve_relation(core, claim_id=left.claim_id, predicate=Predicate.SOURCE_TO_SINK_REACHABILITY,
                                kind=kind, entity_id=ids["ordered"], producing_cell_id=CELL,
                                retrieval_receipt_sha256=RECEIPT)
    relation = resolve(RelationKind.QUALIFIES if mode.startswith("alt_") else RelationKind.SUPPORTS)
    if mode == "changed":
        relation = replace(relation, content_sha256="0" * 64)
    writer.add_relation(relation)
    counter = []
    if mode == "counter":
        contra = resolve(RelationKind.CONTRADICTS)
        writer.add_relation(contra)
        counter.append(contra.relation_id)
    writer.seal()
    projection = project(merge_shards([writer.path]).events)
    cited = [] if mode == "uncited" or mode.startswith("alt_") else [relation.relation_id]
    records = [{"state": "confirmed", "claim_id": left.claim_id, "adjudication_id": "adjudication-" + "b" * 64,
                "counted_relation_ids": cited + counter, "predicates": [{"predicate": relation.predicate.value,
                "supporting": cited, "contradicting": counter}]},
               {"state": "confirmed", "claim_id": right.claim_id, "adjudication_id": "adjudication-" + "b" * 64,
                "counted_relation_ids": [], "predicates": []}]
    compose = chains.compose(ctx, projection, records, extra_verifier_claims=set(), seeds=[{"seed": "untrusted"}],
                             out_dir=root, ledger_path=root / "compose.jsonl", stream="compose")
    refute = chains.challenge(ctx, compose, None, kind="refuter", out_dir=root,
                              ledger_path=root / "refute.jsonl", stream="refute")
    verify = chains.challenge(ctx, compose, refute, kind="weakest_link_verifier", out_dir=root,
                              ledger_path=root / "verify.jsonl", stream="verify")
    assert compose["expected_cells"] == refute["expected_cells"] == verify["expected_cells"] == {}
    manifest = chains.verify_publication(core.run_root, projection, verify["attack_chain_manifest"], SCHEMAS, RUN_ID)
    assert not manifest["items"] and not projection.attack_chains and manifest["exploration"]["expanded"] == 0
    return manifest, relation, core, verify


@pytest.mark.parametrize("mode,status", [("complete", "statically_supported"), ("partial", "unverified"),
                                         ("ambiguous", "unverified"), ("counter", "unverified")])
def test_adjudicated_path_reaches_both_reports_in_producer_order(tmp_path, mode, status):
    manifest, relation, core, verify = fixture(tmp_path, mode)
    [path] = manifest["finding_paths"]
    assert path["status"] == status
    data = seed(tmp_path / "report")
    finding = data["finding"]
    finding.update(claim_id=relation.claim_id, adjudication_id=path["adjudication_id"], direct_evidence=[relation.relation_id])
    data["claim"]["claim_id"] = relation.claim_id
    data["relations"] = [relation_json(relation)]
    data["provenance"].update(source_manifest={"sha256": core.manifest_sha256}, attack_chain_manifest=verify["attack_chain_manifest"])
    dossier = build_dossier(kind="confirmed_finding", finding_paths=[path], **data)
    executive = repr(_finding_blocks(1, finding, BoundDossier(dossier["dossier_id"], dossier["kind"], dossier["finding"], dossier)))
    for report in (executive, render_dossier_markdown(dossier).replace(r"\_", "_")):
        assert report.index("receiveNote") < report.index("checkNote") < report.index("storeNote")
        for text in ("scopeFilter", "src/copy.c:", relation.relation_id, relation.content_sha256, core.manifest_sha256):
            assert text in report
        assert "not a runtime observation" in report and "synthetic_fixture_only" in report
    if mode == "partial":
        middle = [r["assessment"] for r in dossier["finding_path_rows"] if r["stage"] == "Missing transition"]
        assert middle == ["[unverified link]"]
    if mode == "ambiguous":
        assert path["steps"][1]["span"] is None
    if mode == "counter":
        assert path["counter_relations"] and any(r["stage"] == "Counterevidence" for r in dossier["finding_path_rows"])
    with pytest.raises(IntegrityError, match="finding path"):
        build_dossier(kind="confirmed_finding", finding_paths=[{**path, "adjudication_id": "stale"}], **data)


@pytest.mark.parametrize("mode", ["uncited", "foreign_sink", "different_sink", "changed"])
def test_no_discovery_or_promotion_on_bad_binding(tmp_path, mode):
    if mode == "changed":
        with pytest.raises(IntegrityError, match="differs from the adjudicated citation"):
            fixture(tmp_path, mode)
        return
    manifest, *_ = fixture(tmp_path, mode)
    if mode == "uncited":
        assert manifest["finding_paths"] == []
    else:
        [path] = manifest["finding_paths"]
        expected = "statically_contradicted" if mode == "different_sink" else "unverified"
        assert path["steps"] == [] and path["status"] == expected


@pytest.mark.parametrize("mode", ["alt_json", "alt_structured", "alt_disconnected"])
def test_cited_stored_alternate_path_is_static_noncounted_context(tmp_path, mode):
    manifest, relation, core, verify = fixture(tmp_path, mode)
    [path] = manifest["finding_paths"]
    assert path["status"] == "unverified" and path["citation"]["shard_id"] == "analysis/alternate-cpg"
    if mode == "alt_disconnected":
        assert not path["steps"] and any("discontinuous" in gap for gap in path["limitations"])
        return
    assert [s["symbol"] for s in path["steps"]] == ["receiveNote", "checkNote", "storeNote"]
    assert [s["gap_before"] for s in path["steps"]] == [False, False, True]
    assert path["steps"][1]["incoming_edge"]["site"]["start_line"] == 1
    data = seed(tmp_path / "report")
    data["finding"].update(claim_id=relation.claim_id, adjudication_id=path["adjudication_id"], direct_evidence=[])
    data["claim"]["claim_id"] = relation.claim_id
    data["relations"] = [relation_json(relation)]
    data["provenance"].update(source_manifest={"sha256": core.manifest_sha256}, attack_chain_manifest=verify["attack_chain_manifest"])
    dossier = build_dossier(kind="confirmed_finding", finding_paths=[path], **data)
    executive = repr(_finding_blocks(1, data["finding"], BoundDossier(dossier["dossier_id"], dossier["kind"], dossier["finding"], dossier)))
    for report in (executive, render_dossier_markdown(dossier).replace(r"\_", "_").replace(r"\[", "[").replace(r"\]", "]")):
        for text in ("scopePresent", "true_branch", "notes.py:3", "[unverified link]", "syntactic_fallback", relation.content_sha256):
            assert text in report
        assert report.index("receiveNote") < report.index("checkNote") < report.index("storeNote")
    assert dossier["evidence"] == []  # Not a new finding-support citation.
