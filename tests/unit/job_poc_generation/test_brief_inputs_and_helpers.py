"""Code-level unit tests for brief, inputs, package, ast_reduce, buildcheck, buildctx, and writer edges."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.jobs.job_poc_generation import ast_reduce, brief, buildcheck, buildctx, inputs, package, policy, writer
from appsec_review.jobs.job_poc_generation.candidates import FIELD, parse_candidates
from appsec_review.jobs.job_poc_generation.settings import PocGenerationSettings
from appsec_review.jobs.job_poc_generation.source import WriterAnswer, assemble
from appsec_review.jobs.job_poc_generation.statuses import (
    ARTIFACT_GENERATED,
    COMPILE_FAILED,
    COMPILE_VERIFIED,
    POLICY_DENIED,
)
from appsec_review.review.models import IntegrityError
from appsec_review.storage import atomic_json, canonical_json
from tests.fixtures.poc_generation import relay
from tests.poc_support import (
    FIXTURES,
    ROOT,
    FakeExecutor,
    ast_document,
    builds,
    manifest_of,
    relay_unit,
    settings,
    settings_table,
)


def _fast_workspace(destination: Path) -> tuple[Path, dict[str, str]]:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(FIXTURES / "relay_source", destination)
    for rel in ("build/CMakeFiles/relay.dir/src/packet.cpp.o", "build/CMakeFiles/relay.dir/src/main.cpp.o"):
        path = destination / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF placeholder " + rel.encode())
    return destination, manifest_of(destination)


def _basis_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "entry": ["asr:entry_point:" + "1" * 64],
        "path": ["asr:call_site:" + "2" * 64, "asr:call_site:" + "3" * 64],
        "trigger": [
            relay.TRIGGER,
            {"field": "flags", "where": "byte 0", "constraint": "non-numeric text", "why": "check"},
        ],
        "input_format": "4-byte header",
        "preconditions": ["local"],
        "expected_observation": "stack-buffer-overflow",
        "unknowns": [],
    }
    base.update(overrides)
    return base


def _candidate_dict(idx: int = 1, *, verdict: str = "red_correct", basis: dict[str, Any] | None = None) -> dict[str, Any]:
    bval = _basis_dict() if basis is None else basis
    hex_id = f"{idx:064x}"
    return {
        "claim_id": f"claim-{hex_id}",
        "package_id": f"finding_lead-{hex_id}",
        "state": "confirmed",
        "judge_verdict": verdict,
        "poc_basis": {"sha256": hashlib.sha256(canonical_json(bval)).hexdigest(), "brief": bval},
        "finding_package": {"finding_package_id": f"finding-{hex_id}", "sha256": "4" * 64},
        "evidence_refs": [f"evrel-{hex_id}"],
    }


def _cfg(**nested_updates: Any) -> PocGenerationSettings:
    table = deepcopy(settings_table())
    for key, val in nested_updates.items():
        if isinstance(val, dict) and isinstance(table.get(key), dict):
            table[key].update(val)
        else:
            table[key] = val
    return PocGenerationSettings.from_mapping(table)


def test_brief_expectation_rows_and_build_brief_trimming_and_gaps(tmp_path: Path) -> None:
    workspace, manifest = _fast_workspace(tmp_path / "ws")
    unit = relay_unit(workspace, manifest)
    headers = buildctx.Headers(unit)

    rows = brief.rows_by_label(
        {
            "items": [
                {"label": "L1", "ref": "asr:entry_point:" + "1" * 64, "summary": "entry"},
                {"label": "L1", "duplicate": True},
                {
                    "nested": [
                        {
                            "label": "C1",
                            "ref": "asr:call_site:" + "2" * 64,
                            "summary": "main -> relay::parse_header (L16)",
                        }
                    ]
                },
            ]
        }
    )
    assert set(rows) == {"L1", "C1"}
    assert rows["L1"].get("duplicate") is not True

    candidate = parse_candidates([_candidate_dict()])[0]
    view = SimpleNamespace(
        document={
            "labels": list(rows.values()),
            "memory": [{"m": i} for i in range(12)],
            "flows": [{"f": i} for i in range(12)],
            "callees": [{"c": i} for i in range(12)],
            "callers": [{"r": i} for i in range(12)],
        }
    )
    built = brief.build_brief(
        candidate,
        finding={"label": "F1", "title": "Overflow", "lane": "lead", "missing_predicates": []},
        package={},
        view=view,
        sink={"name": "relay::parse_header", "path": "src/packet.cpp", "start_line": 8, "end_line": 20},
        unit=unit,
        headers=headers,
        settings=settings(),
        answer_example={"action": "final"},
    )
    assert built.document["answer_shape"] == {"action": "final"}
    assert built.document["declarations"]
    assert any("3" * 64 in gap for gap in built.gaps)
    exp = built.expectation(("poc_a", "poc_b"))
    assert exp.sink_names == ("relay::parse_header",)
    assert "relay::parse_header" in exp.path_calls
    assert len(exp.triggers) == 1
    assert len(exp.unchecked_triggers) == 1

    # Tight max_brief_bytes triggers _trimmed + project_calls="any_project_function" + sink=None + unit=None
    tight_cfg = _cfg(brief={"max_brief_bytes": 400}, policy={"project_calls": "any_project_function"})
    trimmed = brief.build_brief(
        candidate,
        finding={"label": "F1", "title": "Overflow", "lane": "lead"},
        package={},
        view=view,
        sink=None,
        unit=None,
        headers=None,
        settings=tight_cfg,
    )
    assert trimmed.document["limits"]["project_calls"] == "any project function"
    assert trimmed.sink_names == ()
    assert any("reduced to fit" in gap for gap in trimmed.gaps)
    assert any("no prototype" in gap for gap in trimmed.gaps)


def test_inputs_identity_verify_package_sink_and_retrieval_core(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    cand_dict = _candidate_dict(1)
    hex_1 = f"{1:064x}"

    def _write_bound(rel_path: str, doc: Any) -> dict[str, str]:
        full = run_root / rel_path
        atomic_json(full, doc)
        digest = hashlib.sha256(full.read_bytes()).hexdigest()
        return {"path": rel_path, "sha256": digest}

    scope_ref = _write_bound("jobs/rev/scope.json", {"manifest_sha256": "m" * 64, "manifest_path": "idx/manifest.json"})
    pkg_doc = {
        "package_id": f"finding_lead-{hex_1}",
        "neighborhood": {"function": {"name": "relay::parse_header", "path": "src/packet.cpp", "start_line": 8, "end_line": 20}},
    }
    pkg_ref = _write_bound("jobs/rev/pkg1.json", pkg_doc)
    lead_ref = _write_bound(
        "jobs/rev/lead.json",
        {"packages": [{"package_id": f"finding_lead-{hex_1}", "path": pkg_ref["path"], "sha256": pkg_ref["sha256"]}]},
    )
    hunt_ref = _write_bound("jobs/rev/hunt.json", {"packages": []})
    job_handoff_ref = _write_bound(
        "jobs/rev/handoff.json",
        {
            "outputs": {
                "scope.accept_manifest": {"artifact": scope_ref},
                "packages.assemble_lead_packages": {"artifact": lead_ref},
                "packages.assemble_hunt_packages": {"artifact": hunt_ref},
            }
        },
    )
    review_handoff_ref = _write_bound("jobs/rev/review.json", {FIELD: [cand_dict]})
    verified_review_doc = {
        "run_id": "run-1",
        "inputs": {"review_handoff": review_handoff_ref, "job_handoff": job_handoff_ref},
        "review": {"accepted_manifest_sha256": "m" * 64, "status": "SUCCEEDED"},
        "packages": [
            {
                "finding_package_id": f"finding-{hex_1}",
                "sha256": "4" * 64,
                "claim_id": f"claim-{hex_1}",
                "state": "confirmed",
                "direct_evidence": [f"evrel-{hex_1}"],
            }
        ],
        "bindings": [],
    }
    schemas = SchemaSet(ROOT / SCHEMA_DIRECTORY)

    with patch(
        "appsec_review.jobs.job_poc_generation.inputs.load_accepted_review",
        return_value=SimpleNamespace(document=verified_review_doc),
    ):
        verified = inputs.verify_inputs(run_root, review_schemas=schemas)

    assert verified.identity()["manifest_sha256"] == "m" * 64
    loaded_pkg = inputs.load_package(run_root, verified, f"finding_lead-{hex_1}")
    assert loaded_pkg == pkg_doc
    assert inputs.load_package(run_root, verified, "missing") is None
    assert inputs.sink_of(loaded_pkg)["name"] == "relay::parse_header"
    assert inputs.sink_of({}) is None
    assert inputs.sink_of({"neighborhood": {"function": {"name": "", "path": "src/a.cpp"}}}) is None

    with patch("appsec_review.jobs.bound_artifacts.source_context_core", return_value="core-ok") as mocked_core:
        assert inputs.retrieval_core(run_root, verified) == "core-ok"
        mocked_core.assert_called_once()

    # Manifest mismatch and candidate mismatch raise IntegrityError
    bad_manifest_doc = deepcopy(verified_review_doc)
    bad_manifest_doc["review"]["accepted_manifest_sha256"] = "9" * 64
    with patch(
        "appsec_review.jobs.job_poc_generation.inputs.load_accepted_review",
        return_value=SimpleNamespace(document=bad_manifest_doc),
    ):
        with pytest.raises(IntegrityError, match="manifest"):
            inputs.verify_inputs(run_root, review_schemas=schemas)

    bad_pkg_doc = deepcopy(verified_review_doc)
    bad_pkg_doc["packages"] = []
    with patch(
        "appsec_review.jobs.job_poc_generation.inputs.load_accepted_review",
        return_value=SimpleNamespace(document=bad_pkg_doc),
    ):
        with pytest.raises(IntegrityError, match="disagree"):
            inputs.verify_inputs(run_root, review_schemas=schemas)


def test_package_describe_source_file_name_render_readme_and_write_guards(tmp_path: Path) -> None:
    parsed = WriterAnswer.from_result(relay.answer()["result"])
    assert package.source_file_name(parsed, "c").endswith(".c")
    assert package.source_file_name(parsed, "cxx").endswith(".cpp")
    assert package.describe(POLICY_DENIED, None, "denied reason") == "denied reason"
    assert relay.TEST_NAME in package.describe(COMPILE_VERIFIED, parsed, "ok")

    cand = parse_candidates([_candidate_dict()])[0]
    minimal = WriterAnswer(
        test_name="poc_min_test",
        test_source="void poc_min_test() { /* ``` */ }",
        includes=(),
        control_name="poc_min_ctrl",
        control_source="void poc_min_ctrl() {}",
        setup=(),
        expected_observation="",
        breakpoints=(),
        notes="",
    )
    md_none = package.render_readme(
        candidate=cand,
        finding={"title": "Overflow"},
        answer=minimal,
        status=POLICY_DENIED,
        reason="refused",
        source_name="poc_min_test.c",
        source_text=minimal.test_source,
        facts=None,
        violations=[{"rule": "entry_point", "message": "main is forbidden"}],
    )
    assert "No observation was stated." in md_none
    assert "`entry_point`: main is forbidden" in md_none
    assert "````cpp" in md_none  # fence longer than 3 backticks inside source_text

    md_full = package.render_readme(
        candidate=cand,
        finding={"title": "Overflow"},
        answer=parsed,
        status=COMPILE_VERIFIED,
        reason="ok",
        source_name="poc.cpp",
        source_text=parsed.test_source,
        facts={"include_paths": [], "standard": ""},
        violations=(),
    )
    assert "none recorded" in md_full
    assert "## Breakpoints" in md_full
    assert "## Notes from the writer" in md_full

    # write_candidate path custody & immutability guards
    run_root = tmp_path / "run"
    outside_out = tmp_path / "outside"
    with pytest.raises(IntegrityError, match="owned by a producer attempt"):
        package.write_candidate(
            run_root,
            output_root=outside_out,
            candidate=cand,
            finding={"title": "T"},
            answer=parsed,
            status=COMPILE_VERIFIED,
            reason="ok",
            source_text="void f(){}",
            language="cxx",
            compile_record={},
            violations=(),
            policy_verdict="passed",
            provenance={},
            facts=None,
        )

    valid_out = run_root / "data" / "jobs" / "job_poc_generation" / "attempts" / "att-1" / "candidates"
    package.write_candidate(
        run_root,
        output_root=valid_out,
        candidate=cand,
        finding={"title": "T"},
        answer=parsed,
        status=COMPILE_VERIFIED,
        reason="ok",
        source_text="void f(){}",
        language="cxx",
        compile_record={},
        violations=(),
        policy_verdict="passed",
        provenance={},
        facts=None,
    )
    with pytest.raises(IntegrityError, match="immutable"):
        package.write_candidate(
            run_root,
            output_root=valid_out,
            candidate=cand,
            finding={"title": "T"},
            answer=parsed,
            status=COMPILE_VERIFIED,
            reason="ok",
            source_text="void f(){}",
            language="cxx",
            compile_record={},
            violations=(),
            policy_verdict="passed",
            provenance={},
            facts=None,
        )


def test_ast_reduce_cli_and_truncation() -> None:
    assert ast_reduce.main(["--unknown"]) == 2
    assert ast_reduce.main(["--source", "/workspace/poc.cpp"]) == 2

    big_clang_ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            *[
                {
                    "id": f"0x10{idx:02x}",
                    "kind": "FunctionDecl",
                    "name": f"proj_fn_{idx}",
                    "type": {"qualType": "void ()"},
                    "loc": {"offset": idx, "file": "/workspace/include/relay.hpp", "line": idx + 1},
                }
                for idx in range(10)
            ],
            {
                "id": "0x2000",
                "kind": "FunctionDecl",
                "name": "poc_fn",
                "type": {"qualType": "void ()"},
                "loc": {"offset": 100, "file": "/workspace/poc.cpp", "line": 3},
                "inner": [{"kind": "CompoundStmt", "inner": []}],
            },
        ],
    }
    truncated = ast_reduce.reduce_ast(
        big_clang_ast,
        source="/workspace/poc.cpp",
        project_roots=("/workspace/",),
        max_project_declarations=3,
    )
    assert truncated["project_declarations_truncated"] is True
    assert len(truncated["project_declarations"]) == 3

    with patch("appsec_review.jobs.job_poc_generation.ast_reduce._run") as mocked_run:
        mocked_run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps(big_clang_ast).encode())
        rc = ast_reduce.main(
            ["--source", "/workspace/poc.cpp", "--project-root", "/workspace", "--", "clang++", "/workspace/poc.cpp"]
        )
        assert rc == 0

        mocked_run.return_value = SimpleNamespace(returncode=1, stdout=b"not-json")
        rc_err = ast_reduce.main(["--source", "/workspace/poc.cpp", "--", "clang++", "/workspace/poc.cpp"])
        assert rc_err == 0


def test_buildcheck_and_buildctx_error_and_edge_branches(tmp_path: Path) -> None:
    workspace, manifest = _fast_workspace(tmp_path / "ws")
    unit = relay_unit(workspace, manifest)
    cfg = settings()

    assert buildctx._working_directory(["clang++", "-I", "include", "-Isrc", "@args.rsp", "-c", "src/packet.cpp"], "build/sub") == "build/sub"
    assert buildctx._working_directory(["clang++", "-I/workspace/include", "-c", "/workspace/src/packet.cpp"], "build/sub") == "."
    rel_cmd = buildctx.CompileCommand(
        ("clang++", "-I", "include", "-Isrc", "-I/outside", "-c", "src/packet.cpp"),
        "src/packet.cpp",
        "cxx",
        "build/sub",
        "exact",
    )
    inc_headers = buildctx.Headers(relay_unit(workspace, manifest, compile_command=rel_cmd))
    assert inc_headers.resolve("../escape.hpp") is None
    assert inc_headers.resolve("/abs/path.hpp") is None
    assert buildctx.declarations(unit, inc_headers, [], source_bytes=4096, max_files=4, max_lines=20) == []

    #AcceptedBuilds.materialize limits & tamper guards
    acc = builds(unit)
    tampered_manifest = dict(manifest)
    first_rel = sorted(tampered_manifest)[0]
    tampered_manifest[first_rel] = "0" * 64
    with pytest.raises(IntegrityError, match="changed after acceptance"):
        acc.materialize(relay_unit(workspace, tampered_manifest), tmp_path / "tampered", byte_limit=10**8)
    with pytest.raises(IntegrityError, match="outside the workspace"):
        acc.materialize(relay_unit(workspace, {"../escape": "0" * 64}), tmp_path / "esc", byte_limit=10**8)
    with pytest.raises(IntegrityError, match="missing"):
        acc.materialize(relay_unit(workspace, {"no_such_file.cpp": "0" * 64}), tmp_path / "miss", byte_limit=10**8)
    with pytest.raises(ValueError, match="exceeds"):
        acc.materialize(unit, tmp_path / "byte_lim", byte_limit=1)
    small_acc = buildctx.AcceptedBuilds(workspace.parent, loader=lambda _r: {"receipts": []}, file_limit=1)
    with pytest.raises(ValueError, match="bound is 1"):
        small_acc.materialize(unit, tmp_path / "file_lim", byte_limit=10**8)

    # prepare: existing scratch inside workspace refused; existing destination cleaned
    ans = WriterAnswer.from_result(relay.answer()["result"])
    poc_text = assemble(ans, cfg, claim_id="claim-" + "0" * 64, package_id="finding_lead-" + "0" * 64)
    ws_with_scratch = tmp_path / "ws_scratch"
    shutil.copytree(workspace, ws_with_scratch)
    scratch_sub = ws_with_scratch / cfg.build.scratch_directory
    scratch_sub.mkdir()
    (scratch_sub / "preexisting.txt").write_text("collision", encoding="utf-8")
    bad_unit = relay_unit(ws_with_scratch, manifest_of(ws_with_scratch))
    with pytest.raises(ValueError, match="already holds"):
        buildcheck.prepare(builds(bad_unit), bad_unit, tmp_path / "s_bad", name="c1", poc_text=poc_text, settings=cfg)

    # AcceptedBuilds._bound guards (non-mapping, missing file, bad sha256)
    with pytest.raises(IntegrityError, match="lacks its"):
        acc._bound(None, "compile db")
    with pytest.raises(IntegrityError, match="unavailable"):
        acc._bound({"path": "missing.json", "sha256": "0" * 64}, "compile db")
    tampered_file = acc.run_root / "bad_db.json"
    tampered_file.write_text("{}", encoding="utf-8")
    with pytest.raises(IntegrityError, match="changed after acceptance"):
        acc._bound({"path": "bad_db.json", "sha256": "0" * 64}, "compile db")

    scratch_parent = tmp_path / "s_ok"
    (scratch_parent / "c1").mkdir(parents=True)
    (scratch_parent / "c1" / "stale.txt").write_text("stale", encoding="utf-8")
    scratch = buildcheck.prepare(acc, unit, scratch_parent, name="c1", poc_text=poc_text, settings=cfg)
    assert not (scratch.root / "stale.txt").exists()

    # reduced_ast branches: step.error, timed_out, invalid JSON, bad schema
    assert buildcheck.reduced_ast(buildcheck.Step("ast", [], ".", error="boom"))[0] is None
    assert buildcheck.reduced_ast(buildcheck.Step("ast", [], ".", exit_code=124, timed_out=True))[0] is None
    assert buildcheck.reduced_ast(buildcheck.Step("ast", [], ".", exit_code=0, stdout=b"{bad"))[0] is None
    assert buildcheck.reduced_ast(buildcheck.Step("ast", [], ".", exit_code=0, stdout=b'{"schema": "wrong"}'))[0] is None

    # check_build: empty runtime symbols -> ARTIFACT_GENERATED
    empty_rt = FakeExecutor(runtime="")
    out_rt = buildcheck.check_build(empty_rt, acc, unit, scratch, cfg, claim_id="claim-" + "0" * 64)
    assert out_rt.status == ARTIFACT_GENERATED


def test_writer_bounded_truncation_branches() -> None:
    huge_rows = {"status": "ok", "rows": ["x" * 2000 for _ in range(10)]}
    bounded_rows = writer._bounded(huge_rows)
    assert bounded_rows.get("truncated") is True
    assert len(bounded_rows["rows"]) < 10

    huge_text = {"status": "ok", "text": "y" * (writer.MAX_RESPONSE_BYTES + 500)}
    bounded_text = writer._bounded(huge_text)
    assert bounded_text.get("truncated") is True
    assert len(bounded_text["text"]) < writer.MAX_RESPONSE_BYTES + 500


def test_policy_ast_edge_branches() -> None:
    cfg = _cfg(policy={"project_calls": "any_project_function"})
    exp = policy.Expectation(("poc_a", "poc_b"), ("relay::parse_header",), frozenset({"relay::helper"}), (), ())
    ast_doc = {
        "schema": ast_reduce.SCHEMA,
        "source": "/workspace/.appsec-poc/poc.cpp",
        "project_roots": ["/workspace/"],
        "declarations": {
            "0xglobal": {"kind": "VarDecl", "name": "g_secret", "qualified": "relay::g_secret", "file": "/workspace/include/relay.hpp", "line": 4},
            "0xenum": {"kind": "EnumConstantDecl", "name": "kOne", "qualified": "relay::kOne", "file": "/workspace/include/relay.hpp", "line": 5},
            "0xother": {"kind": "NamespaceAliasDecl", "name": "ns", "qualified": "ns", "file": "/workspace/include/relay.hpp", "line": 6},
            "0xprojfn": {"kind": "FunctionDecl", "name": "helper", "qualified": "relay::helper", "file": "/workspace/include/relay.hpp", "line": 7},
            "0xsink": {"kind": "FunctionDecl", "name": "parse_header", "qualified": "relay::parse_header", "file": "/workspace/include/relay.hpp", "line": 8},
        },
        "project_declarations": [],
        "nodes": [
            {"kind": "PragmaCommentDecl", "line": 1},
            {
                "kind": "NamespaceDecl",
                "name": "nested",
                "inner": [
                    {"kind": "LinkageSpecDecl", "inner": [{"kind": "FunctionDecl", "name": "main", "line": 2}]},
                ],
            },
            {
                "kind": "FunctionDecl",
                "name": "poc_a",
                "type": {"qualType": "int (int)"},
                "storageClass": "static",
                "constexpr": True,
                "inner": [
                    {"kind": "ParmVarDecl", "name": "x"},
                    {"kind": "UnusedAttr", "isImplicit": True},
                    {"kind": "TemplateArgument"},
                ],
            },
            {
                "kind": "FunctionDecl",
                "name": "poc_b",
                "type": {"qualType": "void ()"},
                "inner": [
                    {
                        "kind": "CompoundStmt",
                        "inner": [
                            {},
                            {"kind": "FullComment"},
                            {"kind": "UnusedAttr"},
                            {"kind": "OMPParallelDirective"},
                            {"kind": "DeclRefExpr"},
                            {"kind": "MemberExpr", "name": "missing_field"},
                            {"kind": "MemberExpr", "name": "kOne", "referencedMemberDecl": "0xenum"},
                            {"kind": "DeclRefExpr", "referencedDecl": {"id": "0xglobal", "kind": "VarDecl", "name": "g_secret"}},
                            {"kind": "DeclRefExpr", "referencedDecl": {"id": "0xother", "kind": "NamespaceAliasDecl", "name": "ns"}},
                            {"kind": "DeclRefExpr", "referencedDecl": {"id": "0xmissing", "kind": "FunctionDecl", "name": "unknown_fn"}},
                            {"kind": "DeclRefExpr", "referencedDecl": {"id": "0xprojfn", "kind": "FunctionDecl", "name": "helper"}},
                            {"kind": "DeclRefExpr", "referencedDecl": {"id": "0xsink", "kind": "FunctionDecl", "name": "parse_header"}},
                        ],
                    }
                ],
            },
        ],
    }
    found = policy.check_ast(ast_doc, cfg, exp)
    rules = {v.rule for v in found}
    assert {"pragma", "entry_point", "signature", "storage_class", "missing_function", "unsupported_construct", "unresolved_reference", "global_variable"} <= rules
