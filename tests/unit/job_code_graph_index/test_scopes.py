from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from typing import Any

import pytest

from appsec_review.graph.contract import Coverage, Family, GraphFact, GraphSettings, Producer
from appsec_review.graph.normalize import CoverageRow
from appsec_review.jobs.job_code_graph_index.scopes import (
    CHECKPOINT_SCHEMA,
    STAGE_SCHEMA,
    SUCCEEDED,
    _merge_entries,
    _producer_entry,
    analyzer_producer,
    apply_seeded_coverage,
    artifact,
    assign_analyzers,
    assign_secondary,
    bounded_seeded,
    card_producers,
    codeql_version,
    coverage_dicts,
    database_card,
    database_coverage,
    decode_stage,
    encode_stage,
    load_codeql_inputs,
    project_root_key,
    publish_scope,
    read_artifact,
    restored_secondary,
    reuse_checkpoint,
    save_checkpoint,
    scope_root,
    scope_sources,
    secondary_producer,
    unavailable_coverage,
    verify_exports,
    with_gaps,
    write_stage,
)
from appsec_review.retrieval import (
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RelationKind,
    RelationRecord,
    SourceLocation,
    write_manifest,
)
from appsec_review.retrieval.index import INDEX_SCHEMA
from appsec_review.review.models import IntegrityError
from appsec_review.storage import atomic_json, file_sha256
from tests.fixtures.graph.job.builder import SNAPSHOT, SYNTHETIC, stage_run


def test_artifact_read_artifact_and_stage_codec_custody_and_roundtrip(tmp_path: Path) -> None:
    doc_path = tmp_path / "data" / "doc.json"
    atomic_json(doc_path, {"ok": 1})
    ref = artifact(tmp_path, doc_path)
    assert read_artifact(tmp_path, ref) == {"ok": 1}

    # Symlink rejected on artifact() and escaping symlink rejected on read_artifact().
    outside = tmp_path.parent / f"{tmp_path.name}_outside.json"
    atomic_json(outside, {"outside": 1})
    sym = tmp_path / "data" / "sym.json"
    sym.symlink_to(outside)
    try:
        with pytest.raises(IntegrityError, match="outside the run or missing"):
            artifact(tmp_path, sym)
        with pytest.raises(IntegrityError, match="unavailable"):
            read_artifact(tmp_path, {"path": "data/sym.json", "sha256": file_sha256(outside)})
        with pytest.raises(IntegrityError, match="outside the run or missing"):
            artifact(tmp_path, outside)
    finally:
        outside.unlink(missing_ok=True)
    with pytest.raises(IntegrityError, match="unavailable"):
        read_artifact(tmp_path, {"path": "../outside.json", "sha256": ref["sha256"]})
    with pytest.raises(IntegrityError, match="unavailable"):
        read_artifact(tmp_path, {"path": "data/missing.json", "sha256": ref["sha256"]})

    # Tampered sha256 rejected.
    with pytest.raises(IntegrityError, match="changed"):
        read_artifact(tmp_path, {"path": ref["path"], "sha256": "0" * 64})

    # Stage encode/decode round-trip + write_stage + unsupported schema.
    loc = SourceLocation(SNAPSHOT, "src/a.cpp", "a" * 64, 0, 10, 1, 2, 1, 5, {}, "exact", 1.0, False)
    fact = GraphFact(
        LogicalIdentity.derive(EntityKind.CALL_SITE, SNAPSHOT, {"cs": "1"}),
        "call_fn",
        {"family": "call_site"},
        loc,
    )
    sym_ent = EntityRecord(
        LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"s": "1"}),
        "n1",
        "fn",
        "symbol fn",
        {"k": "v"},
        loc,
    )
    rel = RelationRecord(RelationKind.CONTAINS, sym_ent.identity.value, fact.identity.value, True, 1.0, False, {})
    cov = [CoverageRow("cpp-s1", Family.CALL_SITE, Coverage.COMPLETE, (), 1, {"calls": 1})]
    encoded = encode_stage("cpp-s1", [fact], [sym_ent], [rel], cov, {"note": "ok"})
    assert encoded["schema"] == STAGE_SCHEMA
    stage_ref = write_stage(tmp_path, "cpp-s1", "normalized", encoded)
    f_out, s_out, r_out, c_out = decode_stage(read_artifact(tmp_path, stage_ref))
    assert len(f_out) == 1 and len(s_out) == 1 and len(r_out) == 1 and len(c_out) == 1

    with pytest.raises(IntegrityError, match="schema is unsupported"):
        decode_stage({"schema": "bad/1"})

    updated_cov = with_gaps(cov[0], ["g1", "g1"], counts={"disagree": 2, "zero": 0})
    assert updated_cov.status is Coverage.PARTIAL
    assert updated_cov.gaps == ("g1",)
    assert updated_cov.counts["disagree"] == 2 and "zero" not in updated_cov.counts

    with pytest.raises(IntegrityError, match="not a safe path segment"):
        scope_root(tmp_path, "../Bad")


def test_bounded_seeded_variants() -> None:
    bounded = _producer_entry(Producer.CLANGD, {"gaps": [f"gap-{i}" for i in range(8)]})
    assert bounded["gaps"][-1] == "gap_summary_truncated: 4 additional gaps omitted"
    assert len(bounded["gaps"]) == 5
    assert bounded_seeded(None) is None
    assert bounded_seeded("not-a-map") is None
    raw = {
        "mode": "seeded",
        "depth": 3,
        "seed_limit": True,  # bool rejected -> None
        "seed_count": -1,  # negative rejected -> 0
        "resolved_seed_count": 2,
        "neighborhood_function_count": 5,
        "depth_histogram": {"0": 1, "1": False},
        "seeds": [
            "skip-non-map",
            {
                "path": "src/a.cpp",
                "start_line": 10,
                "end_line": False,
                "status": "resolved",
                "functions": ["f1"],
                "sources": [
                    "skip-source",
                    {"scanner": "semgrep", "rule": "r1", "severity": None},
                ],
            },
        ],
        "gaps": ["g1"],
    }
    res = bounded_seeded(raw)
    assert res is not None
    assert res["mode"] == "seeded" and res["depth"] == 3 and res["seed_limit"] is None
    assert res["seed_count"] == 0 and res["resolved_seed_count"] == 2
    assert res["depth_histogram"] == {"0": 1, "1": 0}
    assert len(res["seeds"]) == 1 and res["seeds"][0]["sources"] == [{"rule": "r1", "scanner": "semgrep"}]
    assert bounded_seeded({"depth_histogram": "not-a-map"})["depth_histogram"] == {}


def test_load_codeql_inputs_legacy_and_all_integrity_error_branches(tmp_path: Path) -> None:
    with pytest.raises(IntegrityError, match="accepted job_codeql_analysis handoff is required"):
        load_codeql_inputs(tmp_path, SNAPSHOT)

    staged = stage_run(tmp_path)
    loaded = load_codeql_inputs(staged.run_root, SNAPSHOT)
    assert len(loaded["scopes"]) == 4

    with pytest.raises(IntegrityError, match="different target snapshot"):
        load_codeql_inputs(staged.run_root, "wrong-snapshot")

    attempt = staged.run_root / "data" / "jobs" / "job_codeql_analysis" / "attempts" / "attempt_0001"
    if not attempt.is_dir():
        attempt = next((staged.run_root / "data" / "jobs" / "job_codeql_analysis" / "attempts").iterdir())
    handoff_path = attempt / "handoff.json"
    result_path = attempt / "result.json"
    latest_path = staged.run_root / "data" / "jobs" / "job_codeql_analysis" / "latest.json"
    orig_ho = json.loads(handoff_path.read_text(encoding="utf-8"))
    orig_res = json.loads(result_path.read_text(encoding="utf-8"))
    exp_rel = orig_res["outputs"]["execution.scopes"]["graph_export_artifact"]["path"]
    exp_path = staged.run_root / exp_rel
    orig_exp = json.loads(exp_path.read_text(encoding="utf-8"))

    def _apply(res_doc: dict[str, Any], ho_doc: dict[str, Any], exp_doc: dict[str, Any] | None = None) -> None:
        import shutil
        from tests.handoff_fixture import write_fixture_handoff

        shutil.rmtree(staged.run_root / "data" / "shared", ignore_errors=True)
        exp_to_write = orig_exp if exp_doc is None else exp_doc
        atomic_json(exp_path, exp_to_write)
        exp_sha = file_sha256(exp_path)
        res_doc = json.loads(json.dumps(res_doc))
        if isinstance(res_doc.get("outputs", {}).get("execution.scopes"), dict) and "graph_export_artifact" in res_doc["outputs"]["execution.scopes"]:
            res_doc["outputs"]["execution.scopes"]["graph_export_artifact"]["sha256"] = exp_sha
            res_doc["outputs"]["execution.scopes"]["graph_export_artifact"]["size_bytes"] = exp_path.stat().st_size
        if isinstance(res_doc.get("outputs", {}).get("export.scopes"), dict) and isinstance(res_doc["outputs"]["export.scopes"].get("artifact"), dict):
            res_doc["outputs"]["export.scopes"]["artifact"]["sha256"] = exp_sha
            res_doc["outputs"]["export.scopes"]["artifact"]["size_bytes"] = exp_path.stat().st_size
        atomic_json(result_path, res_doc)
        res_sha = file_sha256(result_path)
        arts = []
        for art in ho_doc.get("artifacts", ()):
            art_copy = dict(art)
            src = staged.run_root / art_copy["path"]
            art_copy["sha256"] = file_sha256(src)
            art_copy["size_bytes"] = src.stat().st_size
            arts.append(art_copy)
        write_fixture_handoff(
            staged.run_root,
            handoff_path,
            {
                "job_id": "job_codeql_analysis",
                "attempt_id": attempt.name,
                "status": "ACCEPTED",
                "completion_status": "SUCCEEDED",
                "source_fingerprint": SNAPSHOT,
                "outputs": {k: v for k, v in res_doc.get("outputs", {}).items() if isinstance(v, dict)},
                "artifacts": arts,
                "resolving_paths": dict(ho_doc["resolving_paths"]),
            },
        )
        latest = json.loads(latest_path.read_text(encoding="utf-8"))
        latest["handoff_sha256"] = file_sha256(handoff_path)
        atomic_json(latest_path, latest)

    # Legacy export.scopes fallback succeeds.
    leg_res = json.loads(json.dumps(orig_res))
    exec_out = leg_res["outputs"].pop("execution.scopes")
    leg_res["outputs"]["export.scopes"] = {"artifact": exec_out["graph_export_artifact"]}
    _apply(leg_res, orig_ho)
    assert len(load_codeql_inputs(staged.run_root, SNAPSHOT)["scopes"]) == 4

    # Invalid execution.scopes (not a Mapping).
    bad_exec = json.loads(json.dumps(orig_res))
    bad_exec["outputs"]["execution.scopes"] = "invalid"
    _apply(bad_exec, orig_ho)
    with pytest.raises(IntegrityError, match="execution.scopes output is invalid"):
        load_codeql_inputs(staged.run_root, SNAPSHOT)

    # Missing both execution.scopes and export.scopes.
    no_scopes_out = json.loads(json.dumps(orig_res))
    no_scopes_out["outputs"].pop("execution.scopes", None)
    _apply(no_scopes_out, orig_ho)
    with pytest.raises(IntegrityError, match="publishes no graph export index"):
        load_codeql_inputs(staged.run_root, SNAPSHOT)

    # Unbound artifact in handoff: execution.scopes omits graph_export_artifact -> read_bound(None, ...).
    unbound_res = json.loads(json.dumps(orig_res))
    unbound_res["outputs"]["execution.scopes"] = {}
    _apply(unbound_res, orig_ho)
    with pytest.raises(IntegrityError, match="does not bind its graph export index"):
        load_codeql_inputs(staged.run_root, SNAPSHOT)

    # Unsupported graph export index schema.
    _apply(orig_res, orig_ho, {**orig_exp, "schema": "wrong/1"})
    with pytest.raises(IntegrityError, match="schema is unsupported"):
        load_codeql_inputs(staged.run_root, SNAPSHOT)

    # Scope absent from accepted plan.
    absent_exp = json.loads(json.dumps(orig_exp))
    absent_exp["exports"][0]["scope_id"] = "not-in-plan"
    _apply(orig_res, orig_ho, absent_exp)
    with pytest.raises(IntegrityError, match="absent from the accepted plan"):
        load_codeql_inputs(staged.run_root, SNAPSHOT)

    # Scope language differs from accepted plan.
    diff_lang_exp = json.loads(json.dumps(orig_exp))
    diff_lang_exp["exports"][0]["language"] = "java"
    _apply(orig_res, orig_ho, diff_lang_exp)
    with pytest.raises(IntegrityError, match="language differs from the accepted plan"):
        load_codeql_inputs(staged.run_root, SNAPSHOT)

    # Succeeded scope with unbound export_manifest.
    bad_man_exp = json.loads(json.dumps(orig_exp))
    for item in bad_man_exp["exports"]:
        if item["export_status"] == SUCCEEDED:
            item["export_manifest"] = {"path": "unbound.json", "sha256": "0" * 64}
            break
    _apply(orig_res, orig_ho, bad_man_exp)
    with pytest.raises(IntegrityError, match="export manifest .* is not bound"):
        load_codeql_inputs(staged.run_root, SNAPSHOT)

    # Succeeded scope missing export_pack.
    no_pack_exp = json.loads(json.dumps(orig_exp))
    for item in no_pack_exp["exports"]:
        if item["export_status"] == SUCCEEDED:
            item["export_pack"] = None
            break
    _apply(orig_res, orig_ho, no_pack_exp)
    with pytest.raises(IntegrityError, match="export pack identity .* is missing"):
        load_codeql_inputs(staged.run_root, SNAPSHOT)

    # Repeated scope in exports.
    dup_exp = json.loads(json.dumps(orig_exp))
    dup_exp["exports"].append(dup_exp["exports"][0])
    _apply(orig_res, orig_ho, dup_exp)
    with pytest.raises(IntegrityError, match="repeats a scope"):
        load_codeql_inputs(staged.run_root, SNAPSHOT)

    # Omitted planned scope.
    omit_exp = json.loads(json.dumps(orig_exp))
    omit_exp["exports"] = omit_exp["exports"][:-1]
    _apply(orig_res, orig_ho, omit_exp)
    with pytest.raises(IntegrityError, match="omits a planned scope"):
        load_codeql_inputs(staged.run_root, SNAPSHOT)


def test_verify_exports_scope_sources_and_codeql_version(tmp_path: Path) -> None:
    staged = stage_run(tmp_path)
    loaded = load_codeql_inputs(staged.run_root, SNAPSHOT)
    syn = next(sc for sc in loaded["scopes"] if sc["scope_id"] == SYNTHETIC)
    settings = GraphSettings()
    assert verify_exports(staged.run_root, syn, settings)

    with pytest.raises(IntegrityError, match="manifest .* is missing"):
        verify_exports(
            staged.run_root,
            {**syn, "export_manifest": {"path": "data/missing.json", "sha256": "0" * 64}},
            settings,
        )
    with pytest.raises(IntegrityError, match="differs from the accepted handoff"):
        verify_exports(
            staged.run_root,
            {**syn, "export_manifest": {**syn["export_manifest"], "sha256": "0" * 64}},
            settings,
        )
    # Corrupt call_sites.json to trigger GraphExportIntegrityError wrapping.
    cs_file = staged.export_dir(SYNTHETIC) / "call_sites.json"
    cs_file.write_text("{corrupt", encoding="utf-8")
    with pytest.raises(IntegrityError, match=f"CodeQL graph export of {SYNTHETIC}"):
        verify_exports(staged.run_root, syn, settings)

    # scope_sources checks.
    assert scope_sources(staged.target, syn["files"])
    with pytest.raises(IntegrityError, match="requires the accepted target root"):
        scope_sources(None, syn["files"])
    with pytest.raises(IntegrityError, match="not target-relative"):
        scope_sources(staged.target, [{"path": "../escape.cpp", "sha256": "0" * 64}])
    with pytest.raises(IntegrityError, match="accepted source file is missing"):
        scope_sources(staged.target, [{"path": "src/missing.cpp", "sha256": "0" * 64}])
    sym_src = staged.target / "src" / "sym.cpp"
    sym_src.symlink_to(staged.target / "src" / "synthetic.cpp")
    with pytest.raises(IntegrityError, match="accepted source file is missing"):
        scope_sources(staged.target, [{"path": "src/sym.cpp", "sha256": "0" * 64}])
    with pytest.raises(IntegrityError, match="changed after acceptance"):
        scope_sources(staged.target, [{"path": "src/synthetic.cpp", "sha256": "0" * 64}])

    # codeql_version: missing dir -> unknown; jobs; pending_jobs; missing version -> unknown; hash mismatch -> IntegrityError.
    assert codeql_version(tmp_path / "empty_run") == "unknown"
    assert codeql_version(staged.run_root) != "unknown"
    cfg_dir = staged.run_root / "data" / "configuration"
    man_path = cfg_dir / "manifest.json"
    res_path = cfg_dir / "resolved.json"
    doc = json.loads(res_path.read_text(encoding="utf-8"))
    cql_cfg = doc["jobs"].pop("job_codeql_analysis")
    doc["pending_jobs"] = {"job_codeql_analysis": cql_cfg}
    atomic_json(res_path, doc)
    man = json.loads(man_path.read_text(encoding="utf-8"))
    man["resolved_sha256"] = file_sha256(res_path)
    atomic_json(man_path, man)
    assert codeql_version(staged.run_root) != "unknown"

    doc["pending_jobs"]["job_codeql_analysis"]["settings"]["version"] = ""
    atomic_json(res_path, doc)
    man["resolved_sha256"] = file_sha256(res_path)
    atomic_json(man_path, man)
    assert codeql_version(staged.run_root) == "unknown"

    man["resolved_sha256"] = "0" * 64
    atomic_json(man_path, man)
    with pytest.raises(IntegrityError, match="resolved configuration hash mismatch"):
        codeql_version(staged.run_root)


def test_secondary_analyzer_restoration_and_assignment(tmp_path: Path) -> None:
    assert secondary_producer({"name": "observations"}) is None
    assert (
        secondary_producer(
            {"name": "analysis", "shard_id": "ir-1", "producer": {"job": "job_cpp_compiled_analysis", "branch": "ir"}}
        )
        is Producer.LLVM_IR
    )
    assert (
        secondary_producer(
            {"name": "analysis", "shard_id": "ast-1", "producer": {"job": "job_cpp_compiled_analysis", "branch": "ast"}}
        )
        is Producer.CLANG_AST
    )
    assert (
        secondary_producer(
            {"name": "analysis", "shard_id": "svf-1", "producer": {"job": "job_svf_alias_analysis"}}
        )
        is Producer.SVF
    )
    assert (
        secondary_producer(
            {"name": "analysis", "shard_id": "svf-coverage-1", "producer": {"job": "job_svf_alias_analysis"}}
        )
        is None
    )
    assert (
        secondary_producer(
            {"name": "analysis", "shard_id": "other", "producer": {"job": "job_other"}}
        )
        is None
    )

    assert analyzer_producer({"name": "analysis"}) is None
    assert (
        analyzer_producer(
            {"name": "observations", "producer": {"job": "job_clang_static_analysis", "project_root": "."}}
        )
        is Producer.CLANG_STATIC
    )
    assert (
        analyzer_producer(
            {"name": "observations", "producer": {"job": "job_cpg_analysis", "project_root": "sub"}}
        )
        is Producer.JOERN_CPG
    )
    assert project_root_key(".") == "" and project_root_key("/sub/dir/") == "sub/dir"

    # Build a dropped SVF shard + accepted handoff for job_svf_alias_analysis to exercise restored_secondary().
    svf_path = tmp_path / "data" / "indices" / "analysis" / "svf-main.sqlite"
    svf_fp = "b" * 64
    builder = IndexBuilder(svf_path, name="analysis", fingerprint=svf_fp, target_snapshot=SNAPSHOT, shard_id="svf-main")
    builder.add_coverage("analysis:svf-main", "complete", None)
    svf_sha = builder.build()
    svf_ident = IndexIdentity(
        "analysis",
        INDEX_SCHEMA,
        svf_sha,
        svf_fp,
        svf_path.relative_to(tmp_path).as_posix(),
        {"job": "job_svf_alias_analysis"},
        (),
        "svf-main",
    )
    foreign_path = tmp_path / "data" / "indices" / "analysis" / "foreign-1.sqlite"
    foreign_builder = IndexBuilder(
        foreign_path, name="analysis", fingerprint=svf_fp, target_snapshot=SNAPSHOT, shard_id="foreign-1"
    )
    foreign_builder.add_coverage("analysis:foreign-1", "complete", None)
    foreign_sha = foreign_builder.build()
    foreign_ident = IndexIdentity(
        "analysis",
        INDEX_SCHEMA,
        foreign_sha,
        svf_fp,
        foreign_path.relative_to(tmp_path).as_posix(),
        {"job": "job_other"},
        (),
        "foreign-1",
    )
    from tests.handoff_fixture import write_fixture_handoff

    man_path = tmp_path / "data" / "indices" / "manifests" / "svf.json"
    write_manifest(man_path, run_id=tmp_path.name, target_snapshot=SNAPSHOT, target_root=tmp_path, indexes=[svf_ident, foreign_ident])
    man_rel = man_path.relative_to(tmp_path).as_posix()
    man_sha = file_sha256(man_path)
    attempt = tmp_path / "data" / "jobs" / "job_svf_alias_analysis" / "attempts" / "attempt_01"
    res = {"schema": "appsec-review/unit-execution/2", "status": "SUCCEEDED",
           "outputs": {"pub.out": {"index_manifest": {"path": man_rel, "sha256": man_sha}}}}
    atomic_json(attempt / "result.json", res)
    res_rel = (attempt / "result.json").relative_to(tmp_path).as_posix()
    ho_path = attempt / "handoff.json"
    write_fixture_handoff(
        tmp_path,
        ho_path,
        {
            "job_id": "job_svf_alias_analysis",
            "attempt_id": "attempt_01",
            "status": "ACCEPTED",
            "completion_status": "SUCCEEDED",
            "source_fingerprint": SNAPSHOT,
            "outputs": res["outputs"],
            "artifacts": [
                {"path": man_rel, "sha256": man_sha, "size_bytes": man_path.stat().st_size},
                {"path": svf_ident.relative_path, "sha256": svf_sha, "size_bytes": svf_path.stat().st_size},
                {"path": foreign_ident.relative_path, "sha256": foreign_sha, "size_bytes": foreign_path.stat().st_size},
                {"path": res_rel, "sha256": file_sha256(attempt / "result.json"), "size_bytes": (attempt / "result.json").stat().st_size},
            ],
            "resolving_paths": {
                "attempt": attempt.relative_to(tmp_path).as_posix(),
                "result": res_rel,
            },
        },
    )
    atomic_json(
        tmp_path / "data" / "jobs" / "job_svf_alias_analysis" / "latest.json",
        {
            "schema": "appsec-review/latest-handoff/1",
            "attempt_id": "attempt_01",
            "handoff_path": ho_path.relative_to(tmp_path).as_posix(),
            "handoff_sha256": file_sha256(ho_path),
        },
    )
    restored = restored_secondary(tmp_path, [])
    assert [r["shard_id"] for r in restored] == ["svf-main"]
    assert restored_secondary(tmp_path, [asdict(svf_ident)]) == []

    # assign_secondary when no native succeeded scope exists.
    go_scope = {"scope_id": "go-s1", "language": "go", "export_status": SUCCEEDED, "files": []}
    assert assign_secondary(tmp_path, [asdict(svf_ident), {"name": "other", "shard_id": "x"}], [go_scope]) == {
        "go-s1": {p.value: [] for p in (Producer.CLANGD, Producer.LLVM_IR, Producer.CLANG_AST, Producer.TREE_SITTER, Producer.SVF)}
    }

    # assign_analyzers matches project_root_key and skips non-analyzer shards.
    cs_shard = {
        "name": "observations",
        "shard_id": "cs-1",
        "sha256": "a" * 64,
        "producer": {"job": "job_clang_static_analysis", "project_root": "/pkg/"},
    }
    assigned_ana = assign_analyzers(
        [cs_shard, {"name": "analysis", "shard_id": "skip", "sha256": "b" * 64}],
        [
            {"scope_id": "cpp-pkg", "language": "cpp", "root": "pkg"},
            {"scope_id": "go-pkg", "language": "go", "root": "pkg"},
        ],
    )
    assert len(assigned_ana["cpp-pkg"]["clang-static"]) == 1
    assert assigned_ana["go-pkg"]["clang-static"] == []


def test_checkpoints_seeded_coverage_database_card_and_publish_scope_edges(tmp_path: Path) -> None:
    scope = {
        "scope_id": "cpp-s1",
        "language": "cpp",
        "root": ".",
        "build_unit_id": "bu-1",
        "database_identity": "db-1",
        "export_status": SUCCEEDED,
        "seeded": {
            "mode": "seeded",
            "depth": 2,
            "seed_count": 3,
            "resolved_seed_count": 2,
            "gaps": ["seed_gap"],
        },
        "inputs": {
            "secondary": {
                "clangd": [{"producer": {"seeded": {"mode": "seeded", "depth": 2, "seed_count": 2, "resolved_seed_count": 2}}}],
                "llvm-ir": [
                    {"producer": {"seeded": {"mode": "seeded", "skipped": True, "seed_count": 0}}},
                    {"producer": {"seeded": {"mode": "seeded", "seed_count": 1, "resolved_seed_count": 0}}},
                ],
            },
            "analyzers": {
                "clang-static": [{"producer": {"seeded": {"mode": "whole_program", "gaps": ["cs_gap"]}}}],
            },
        },
    }
    cov_rows = [
        CoverageRow("cpp-s1", fam, Coverage.UNAVAILABLE if fam is Family.RANGE_FACT else Coverage.COMPLETE, (), 1, {})
        for fam in Family
    ]
    seeded_cov = apply_seeded_coverage(scope, cov_rows)
    assert next(r for r in seeded_cov if r.family is Family.RANGE_FACT).status is Coverage.UNAVAILABLE
    assert next(r for r in seeded_cov if r.family is Family.CALL_SITE).status is Coverage.PARTIAL

    # Check database_coverage variants: all complete, all unavailable, seeded skipped export -> partial.
    all_comp = [CoverageRow("s", fam, Coverage.COMPLETE, (), 1, {}) for fam in Family]
    all_unav = [CoverageRow("s", fam, Coverage.UNAVAILABLE, ("u",), 0, {}) for fam in Family]
    unseeded = {**scope, "seeded": None}
    assert database_coverage(unseeded, all_comp)[0] is Coverage.COMPLETE
    assert database_coverage(unseeded, all_unav)[0] is Coverage.UNAVAILABLE
    skipped_seeded = {
        **scope,
        "export_status": "NOT_APPLICABLE",
        "seeded": {"mode": "seeded", "skipped": True, "seed_count": 0, "resolved_seed_count": 0},
    }
    assert database_coverage(skipped_seeded, all_unav)[0] is Coverage.PARTIAL

    assert _merge_entries(Producer.CLANGD, [])["state"] == "not_run"
    assert _producer_entry(Producer.CODEQL_EXPORT, None, failed=True)["state"] == "failed"
    prods = card_producers(scope)
    assert len(prods) == 7
    joern = next(row for row in prods if row["name"] == Producer.JOERN_CPG.value)
    assert joern["state"] == "not_run" and joern["gaps"]
    intended = card_producers({**scope, "alternate_cpg_succeeded": True})
    assert next(row for row in intended if row["name"] == Producer.JOERN_CPG.value) == joern

    card = database_card(scope, snapshot=SNAPSHOT, coverage=seeded_cov)
    assert card.payload["coverage"] == "partial"

    # Publish symbol-only relations, then verify a later attempt preserves these shards.
    sym1 = EntityRecord(
        LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"s": "1"}), "u1", "f1", "sym f1", {}, None
    )
    sym2 = EntityRecord(
        LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"s": "2"}), "u2", "f2", "sym f2", {}, None
    )
    shards = publish_scope(
        tmp_path,
        scope=scope,
        snapshot=SNAPSHOT,
        identity="ident-1",
        facts=(),
        symbols=[sym1, sym2],
        relations=[RelationRecord(RelationKind.CALLS, sym1.identity.value, sym2.identity.value, True, 1.0, False, {})],
        coverage=seeded_cov,
        catalog_release="cat-1",
        unit_id="correlate.scopes",
        card=card,
    )
    # A whole-job retry publishes into its own attempt, preserving the prior shard bytes.
    retained = {item["relative_path"]: (tmp_path / item["relative_path"]).read_bytes() for item in shards}
    scope = {**scope, "attempt_id": "attempt_0002"}
    shards = publish_scope(
        tmp_path,
        scope=scope,
        snapshot=SNAPSHOT,
        identity="ident-1",
        facts=(),
        symbols=[sym1, sym2],
        relations=[RelationRecord(RelationKind.CALLS, sym1.identity.value, sym2.identity.value, True, 1.0, False, {})],
        coverage=seeded_cov,
        catalog_release="cat-1",
        unit_id="correlate.scopes",
        card=card,
    )
    assert len(shards) == 8

    assert all((tmp_path / path).read_bytes() == data for path, data in retained.items())

    # Orphan relation touching neither fact nor symbol raises IntegrityError.
    miss1 = LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"m": "1"}).value
    miss2 = LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"m": "2"}).value
    with pytest.raises(IntegrityError, match="touches no fact or symbol"):
        publish_scope(
            tmp_path,
            scope=scope,
            snapshot=SNAPSHOT,
            identity="ident-orphan",
            facts=(),
            symbols=[],
            relations=[RelationRecord(RelationKind.CALLS, miss1, miss2, True, 1.0, False, {})],
            coverage=seeded_cov,
            catalog_release="cat-1",
            unit_id="correlate.scopes",
        )

    # save_checkpoint & reuse_checkpoint happy path and invalidations.
    save_checkpoint(tmp_path, "cpp-s1", "ident-1", {"scope_id": "cpp-s1", "shards": shards})
    reused = reuse_checkpoint(tmp_path, "cpp-s1", "ident-1")
    assert reused is not None and reused["checkpoint_reused"] is True
    assert reuse_checkpoint(tmp_path, "cpp-s1", "wrong-ident") is None

    cp_file = scope_root(tmp_path, "cpp-s1") / "checkpoint.json"
    cp_file.write_text("{bad-json", encoding="utf-8")
    assert reuse_checkpoint(tmp_path, "cpp-s1", "ident-1") is None

    # Corrupted metadata is not reused and never authorizes deletion.
    atomic_json(
        cp_file,
        {
            "schema": CHECKPOINT_SCHEMA,
            "identity": "ident-1",
            "result": {"scope_id": "cpp-s1", "shards": [{**shards[0], "sha256": "0" * 64}]},
        },
    )
    assert reuse_checkpoint(tmp_path, "cpp-s1", "ident-1") is None
    assert cp_file.exists()
    assert (tmp_path / shards[0]["relative_path"]).is_file()

    # Symlink checkpoint returns None.
    other = tmp_path / "other.json"
    atomic_json(other, {"ok": 1})
    cp_file.unlink()
    cp_file.symlink_to(other)
    assert reuse_checkpoint(tmp_path, "cpp-s1", "ident-1") is None

    unav = unavailable_coverage({"scope_id": "s-fail", "export_status": "FAILED", "export_gaps": ["g1"]})
    assert len(coverage_dicts(unav)) == 7
