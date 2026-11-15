"""Unit tests for job_ci_configuration_analysis decoders, helpers, and unit handlers."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.container_runtime import ContainerExecutor
from appsec_review.jobs.job_ci_configuration_analysis.job import (
    CiConfigurationAnalysisFailed,
    SPECS,
    ToolSpec,
    _argv,
    _checkov_source_records,
    _enrich,
    _external_records,
    _generic_external_records,
    _hierarchy,
    _read,
    _scan,
    _source_location,
    _write,
    build_job,
    correlation_key,
)
from tests.unit.job_ci_configuration_analysis.support import (
    FakeExecutor,
    ROOT,
    attempt_scope,
    checkov_workflow_permissions,
    make_unit_context,
    zizmor_finding,
)


SPEC_BY_KEY = {spec.key: spec for spec in SPECS}


def test_argv_read_write_source_location_enrich_and_correlation_helpers(tmp_path: Path) -> None:
    wf = ".github/workflows/ci.yml"
    assert _argv(SPEC_BY_KEY["github_zizmor"], "zizmor", wf) == (
        "zizmor",
        "--offline",
        "--no-exit-codes",
        "--format",
        "json",
        f"/target/{wf}",
    )
    assert _argv(SPEC_BY_KEY["github_actionlint"], "actionlint", wf) == (
        "actionlint",
        "-format",
        "{{json .}}",
        f"/target/{wf}",
    )
    assert _argv(SPEC_BY_KEY["github_checkov"], "checkov", wf) == (
        "checkov",
        "--quiet",
        "--compact",
        "--output",
        "json",
        "--framework",
        "github_actions",
        "--file",
        f"/target/{wf}",
    )
    with pytest.raises(CiConfigurationAnalysisFailed, match="no external CI argv"):
        _argv(ToolSpec("github", "unknown", "tool-unknown", "external"), "bin", wf)

    # _write and _read verify run-root custody and SHA-256 integrity.
    unit, _, _ = make_unit_context(tmp_path / "rw", target_files={wf: "line1\nline2\nline3\n"})
    with attempt_scope(unit):
        ident = _write(unit, "sample.json", {"ok": True})
    assert _read(unit.job.run_root, ident) == {"ok": True}

    outside = tmp_path / "outside.json"
    outside.write_text('{"ok":false}\n', encoding="utf-8")
    with pytest.raises(CiConfigurationAnalysisFailed, match="artifact identity mismatch"):
        _read(unit.job.run_root, {"path": "../../../outside.json", "sha256": "0" * 64})
    with pytest.raises(CiConfigurationAnalysisFailed, match="artifact identity mismatch"):
        _read(unit.job.run_root, {"path": "missing.json", "sha256": "0" * 64})
    with pytest.raises(CiConfigurationAnalysisFailed, match="artifact identity mismatch"):
        _read(unit.job.run_root, {**ident, "sha256": "0" * 64})

    # _source_location covers missing file, explicit byte offsets, and line-offset fallback (including EOF end_line).
    assert _source_location(unit, {"path": "missing.yml", "tool_id": "t"}) is None
    loc_offsets = _source_location(
        unit,
        {
            "path": wf,
            "tool_id": "ci-schema",
            "start_line": 2,
            "end_line": 99,
            "start_column": 1,
            "end_column": 6,
            "start_byte": None,
            "end_byte": None,
        },
    )
    assert loc_offsets is not None and loc_offsets.start_byte == 6 and loc_offsets.end_byte == 18

    # _enrich attaches nearest preceding stage/job/step for matching path only.
    nodes = [
        {"path": "other.yml", "kind": "stage", "name": "wrong", "start_line": 1},
        {"path": wf, "kind": "stage", "name": "stages", "start_line": 1},
        {"path": wf, "kind": "job", "name": "build", "start_line": 2},
        {"path": wf, "kind": "step", "name": "- run: test", "start_line": 3},
    ]
    enriched = _enrich({"path": wf, "start_line": 3}, nodes)
    assert enriched["stage"] == "stages"
    assert enriched["job"] == "build"
    assert enriched["step"] == "- run: test"

    # correlation_key distinguishes ambiguous coarse-mapped findings by provenance and byte range.
    base = {
        "provider": "github",
        "path": wf,
        "start_line": 1,
        "end_line": 3,
        "start_column": 1,
        "end_column": 6,
        "category": "permission-or-authorization",
        "message": "same",
    }
    assert correlation_key(base | {"tool_id": "one"}) == correlation_key(base | {"tool_id": "two"})
    assert correlation_key(base) != correlation_key(base | {"message": "different"})
    amb_a = {
        **base,
        "ambiguous": True,
        "producer_location": {"reason": "a"},
        "mapping_method": "checkov-workflow-scope",
        "confidence": 0.5,
        "start_byte": 0,
        "end_byte": 18,
    }
    amb_b = {**amb_a, "producer_location": {"reason": "b"}}
    assert correlation_key(amb_a) != correlation_key(amb_b)


def test_external_decoders_cover_generic_jsonl_diagnostics_checkov_and_zizmor_dispatch() -> None:
    wf = ".github/workflows/ci.yml"
    spec_a = SPEC_BY_KEY["github_actionlint"]
    spec_c = SPEC_BY_KEY["github_checkov"]
    spec_z = SPEC_BY_KEY["github_zizmor"]

    assert _generic_external_records(spec_a, b"   ", wf) == []
    assert _generic_external_records(spec_a, b"{}", wf) == []

    # JSONL stream with invalid line skipped, diagnostics envelope, and direct finding object.
    jsonl_payload = "\n".join(
        [
            "not-json-banner",
            json.dumps(
                {
                    "diagnostics": [
                        "bad",
                        {
                            "message": "diag msg",
                            "kind": "syntax-check",
                            "location": {"line": 4, "column": 2, "end_line": 4, "end_column": 9},
                        },
                    ]
                }
            ),
            json.dumps({"rule_id": "R1", "description": "line item", "line": 2}),
        ]
    ).encode("utf-8")
    recs_a = _external_records(spec_a, jsonl_payload, wf)
    assert [r["native_rule_id"] for r in recs_a] == ["syntax-check", "R1"]
    assert recs_a[0]["start_line"] == 4 and recs_a[0]["start_column"] == 2

    # Checkov envelope with CKV2_GHA_1 [0, 1] sentinel and clipped range via _external_records + _checkov_source_records.
    raw_c = json.dumps(
        {
            "results": {
                "failed_checks": [
                    checkov_workflow_permissions(wf, name="ci", span=(0, 1)),
                    {
                        "check_id": "CKV_GHA_CLIP",
                        "check_name": "Clipped",
                        "file_abs_path": f"/target/{wf}",
                        "file_path": f"/{wf}",
                        "file_line_range": [2, 20],
                    },
                ]
            }
        }
    ).encode("utf-8")
    parsed_c = _external_records(spec_c, raw_c, wf)
    bound_c = _checkov_source_records(parsed_c, wf, b"line1\nline2\nline3\n")
    assert [r["mapping_method"] for r in bound_c] == ["checkov-workflow-scope", "checkov-line-range-clipped"]
    assert all(r["ambiguous"] is True for r in bound_c)

    # _external_records dispatches tool-zizmor to _zizmor_records, skipping ignored=True findings.
    raw_z = json.dumps(
        [
            {**zizmor_finding(path=wf, row=0, column=0, offset=0, feature="name: ci"), "ignored": True},
            zizmor_finding(path=wf, row=0, column=0, offset=0, feature="name: ci"),
        ]
    ).encode("utf-8")
    recs_z = _external_records(spec_z, raw_z, wf)
    assert len(recs_z) == 1 and recs_z[0]["native_rule_id"] == "artipacked"


def test_scan_isolates_linter_failure_and_stops_active_guardian(tmp_path: Path) -> None:
    """Direct _scan failure surface (also invoked under safety._running by test_review_stop_policy)."""
    wf = ".github/workflows/ci.yml"
    wf_text = "name: ci\non: pull_request_target\npermissions: write-all\n"
    unit, catalog_files, _ = make_unit_context(
        tmp_path / "stop_case",
        unit_id="ci_analysis.github_zizmor_scan",
        target_files={wf: wf_text},
    )
    classified = {"definitions": [{**catalog_files[0], "provider": "github", "definition_id": f"ci:github:{wf}"}]}
    unit.output = {"ci_discovery.classify_providers": classified}.__getitem__
    calls: list[tuple[str, tuple[str, ...]]] = []

    with attempt_scope(unit):
        out = _scan(
            unit,
            SPEC_BY_KEY["github_zizmor"],
            lambda u: FakeExecutor(ROOT, u.job.run_root, calls, exit_code=9),
            None,
        )
    assert out["terminal_status"] == "FAILED"
    assert len(out["gaps"]) == 1
    assert "failed with exit=9" in out["gaps"][0]["reason"]


def test_scan_covers_not_applicable_skipped_na_discovery_static_and_external_error_branches(
    tmp_path: Path,
) -> None:
    wf = ".github/workflows/ci.yml"
    wf_text = "on:\n  pull_request_target:\npermissions: write-all\n"

    # 1. Provider with zero definitions -> NOT_APPLICABLE without SKIPPED_NA.
    u_none, _, _ = make_unit_context(tmp_path / "none", unit_id="ci_analysis.gitlab_checkov_scan")
    u_none.output = {"ci_discovery.classify_providers": {"definitions": []}}.__getitem__
    with attempt_scope(u_none):
        res_none = _scan(u_none, SPEC_BY_KEY["gitlab_checkov"], lambda _u: None, None)
    assert res_none["terminal_status"] == "NOT_APPLICABLE"
    assert "coverage_disposition" not in res_none

    # 2. External linter with unsupported path (.github/actions/*/action.yml for actionlint) -> SKIPPED_NA.
    action_path = ".github/actions/setup/action.yml"
    u_na, na_files, _ = make_unit_context(
        tmp_path / "skipped_na",
        unit_id="ci_analysis.github_actionlint_scan",
        target_files={action_path: "name: custom\nruns:\n  using: composite\n"},
    )
    u_na.output = {
        "ci_discovery.classify_providers": {
            "definitions": [{**na_files[0], "provider": "github", "definition_id": f"ci:github:{action_path}"}]
        }
    }.__getitem__
    with attempt_scope(u_na):
        res_na = _scan(u_na, SPEC_BY_KEY["github_actionlint"], lambda _u: None, None)
    assert res_na["terminal_status"] == "NOT_APPLICABLE"
    assert res_na["coverage_disposition"] == "SKIPPED_NA"

    # 3. Discovery-only spec (other_discovery) -> PARTIAL with PRODUCER_REPORTED_GAP.
    u_disc, disc_files, _ = make_unit_context(
        tmp_path / "disc_only",
        unit_id="ci_analysis.other_discovery_scan",
        target_files={".travis.yml": "language: python\n"},
    )
    u_disc.output = {
        "ci_discovery.classify_providers": {
            "definitions": [{**disc_files[0], "provider": "other", "definition_id": "ci:other:.travis.yml"}]
        }
    }.__getitem__
    with attempt_scope(u_disc):
        res_disc = _scan(u_disc, SPEC_BY_KEY["other_discovery"], lambda _u: None, None)
    assert res_disc["terminal_status"] == "PARTIAL"
    assert "supported_discovery_without_linter" in res_disc["gaps"][0]["reason"]

    # 4. Static scan: oversized file + invalid UTF-8 file + observation truncation.
    u_stat, stat_files, _ = make_unit_context(
        tmp_path / "static_edges",
        unit_id="ci_analysis.github_schema_scan",
        target_files={
            ".github/workflows/a_ok.yml": wf_text,
            ".github/workflows/b_big.yml": "x" * 200,
            ".github/workflows/c_badutf8.yml": b"\xff\xfe\x00",
        },
        settings_override={"max_file_bytes": 120, "max_observations_per_tool": 1},
    )
    u_stat.output = {
        "ci_discovery.classify_providers": {
            "definitions": [{**f, "provider": "github", "definition_id": f"ci:github:{f['path']}"} for f in stat_files]
        }
    }.__getitem__
    with attempt_scope(u_stat):
        res_stat = _scan(u_stat, SPEC_BY_KEY["github_schema"], lambda _u: None, None)
    assert res_stat["terminal_status"] == "PARTIAL"
    assert res_stat["record_count"] == 1
    reasons_stat = [g["reason"] for g in res_stat["gaps"]]
    assert any("max_file_bytes exceeded" in r for r in reasons_stat)
    assert any("static parse unavailable" in r for r in reasons_stat)
    assert any("observation bound reached at 1" in r for r in reasons_stat)

    # 5. External scan: missing container image -> PRODUCER_BLOCKED (FAILED).
    empty_repo = tmp_path / "empty_repo"
    empty_repo.mkdir()
    u_img, img_files, _ = make_unit_context(
        tmp_path / "img_fail",
        unit_id="ci_analysis.github_zizmor_scan",
        repository_root=empty_repo,
        target_files={wf: wf_text},
    )
    u_img.output = {
        "ci_discovery.classify_providers": {
            "definitions": [{**img_files[0], "provider": "github", "definition_id": f"ci:github:{wf}"}]
        }
    }.__getitem__
    with attempt_scope(u_img):
        res_img = _scan(
            u_img,
            SPEC_BY_KEY["github_zizmor"],
            lambda _u: (_ for _ in ()).throw(KeyError("missing image")),
            None,
        )
    assert res_img["terminal_status"] == "FAILED"
    assert res_img["gaps"][0]["code"] == "producer_blocked"

    # 6. External scan: fail_tool injection -> PRODUCER_FAILED (FAILED).
    u_inj, inj_files, _ = make_unit_context(
        tmp_path / "fail_tool",
        unit_id="ci_analysis.github_zizmor_scan",
        target_files={wf: wf_text},
    )
    u_inj.output = {
        "ci_discovery.classify_providers": {
            "definitions": [{**inj_files[0], "provider": "github", "definition_id": f"ci:github:{wf}"}]
        }
    }.__getitem__
    calls: list[tuple[str, tuple[str, ...]]] = []
    with attempt_scope(u_inj):
        res_inj = _scan(
            u_inj,
            SPEC_BY_KEY["github_zizmor"],
            lambda u: FakeExecutor(ROOT, u.job.run_root, calls),
            "tool-zizmor",
        )
    assert res_inj["terminal_status"] == "FAILED"
    assert "injected bounded failure" in res_inj["gaps"][0]["reason"]

    # 7. External scan: malformed zizmor JSON -> PARSER_ERROR (FAILED), and Checkov oversized source -> PARSER_ERROR.
    u_parse, parse_files, _ = make_unit_context(
        tmp_path / "parse_err",
        unit_id="ci_analysis.github_zizmor_scan",
        target_files={wf: wf_text},
    )
    u_parse.output = {
        "ci_discovery.classify_providers": {
            "definitions": [{**parse_files[0], "provider": "github", "definition_id": f"ci:github:{wf}"}]
        }
    }.__getitem__
    with attempt_scope(u_parse):
        res_parse = _scan(
            u_parse,
            SPEC_BY_KEY["github_zizmor"],
            lambda u: FakeExecutor(ROOT, u.job.run_root, calls, stdout=b"{bad-json"),
            None,
        )
    assert res_parse["terminal_status"] == "FAILED"
    assert res_parse["gaps"][0]["code"] == "parser_error"

    u_ckv_big, ckv_files, _ = make_unit_context(
        tmp_path / "ckv_big",
        unit_id="ci_analysis.github_checkov_scan",
        target_files={wf: wf_text},
        settings_override={"max_file_bytes": 5},
    )
    u_ckv_big.output = {
        "ci_discovery.classify_providers": {
            "definitions": [{**ckv_files[0], "provider": "github", "definition_id": f"ci:github:{wf}"}]
        }
    }.__getitem__
    ckv_stdout = json.dumps({"results": {"failed_checks": [checkov_workflow_permissions(wf)]}}).encode("utf-8")
    with attempt_scope(u_ckv_big):
        res_ckv_big = _scan(
            u_ckv_big,
            SPEC_BY_KEY["github_checkov"],
            lambda u: FakeExecutor(ROOT, u.job.run_root, calls, stdout=ckv_stdout),
            None,
        )
    assert res_ckv_big["terminal_status"] == "FAILED"
    assert "max_file_bytes" in res_ckv_big["gaps"][0]["reason"]


def test_hierarchy_error_branches_and_default_executor_factory(tmp_path: Path) -> None:
    unit, files, _ = make_unit_context(
        tmp_path / "hier_edges",
        unit_id="ci_enrichment.build_hierarchy",
        target_files={
            ".github/workflows/big.yml": "x" * 100,
            ".github/workflows/bad.yml": b"\xff\xfe",
        },
        settings_override={"max_file_bytes": 20},
    )
    defs = [{**f, "provider": "github", "definition_id": f"ci:github:{f['path']}"} for f in files]
    unit.output = {"ci_discovery.classify_providers": {"definitions": defs}}.__getitem__
    with attempt_scope(unit):
        hier = _hierarchy(unit)
    assert hier["node_count"] == 0
    assert len(hier["gaps"]) == 2

    # Exercise default executor_factory=None on zero-CI target (clean complete run) AND on a single-file target
    # (where missing local docker image is caught cleanly as PRODUCER_BLOCKED without launching any container).
    job_default = build_job()
    u_clean, _, _ = make_unit_context(tmp_path / "default_factory", target_files={"README.md": "clean\n"})
    with attempt_scope(u_clean):
        result_clean = job_default.handler(u_clean.job)
    pub_clean = result_clean["outputs"]["ci_coverage.publish_handoff"]
    assert pub_clean["coverage_status"] == "complete"
    assert pub_clean["finding_count"] == 0

    empty_repo = tmp_path / "empty_containers"
    empty_repo.mkdir()
    u_def_factory, cat_f, _ = make_unit_context(
        tmp_path / "def_factory_exec",
        unit_id="ci_analysis.github_zizmor_scan",
        repository_root=empty_repo,
        target_files={".github/workflows/ci.yml": "name: ci\n"},
    )
    u_def_factory.output = {
        "ci_discovery.classify_providers": {
            "definitions": [{**cat_f[0], "provider": "github", "definition_id": "ci:github:.github/workflows/ci.yml"}]
        }
    }.__getitem__
    zizmor_unit = next(u for u in job_default.units if u.unit_id == "ci_analysis.github_zizmor_scan")
    with attempt_scope(u_def_factory):
        with pytest.raises(FileNotFoundError, match="containers"):
            zizmor_unit.handler(u_def_factory)
    assert isinstance(ContainerExecutor, type)


def test_full_job_unit_executor_end_to_end_correlates_indexes_and_publishes(tmp_path: Path) -> None:
    """Run all 49 units of build_job().handler in-process with FakeExecutor, including secret redaction,
    duplicate collapsing, ambiguous Checkov findings, truncation gap propagation, and RetrievalCore search."""
    wf = ".github/workflows/ci.yml"
    wf_text = (
        "name: ci\n"
        "on:\n"
        "  pull_request_target:\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: echo ${{ secrets.DEPLOY_SECRET }}\n"
    )
    unit, _, events = make_unit_context(
        tmp_path / "e2e",
        target_files={
            wf: wf_text,
            ".travis.yml": "language: python\n",
            "Jenkinsfile": "pipeline {\n  stage('Build') {\n    sh('make')\n  }\n}\n",
        },
        settings_override={"max_files": 2},
        include_stale_ci_index=True,
    )
    calls: list[tuple[str, tuple[str, ...]]] = []
    actionlint_finding = {
        "message": "leaked ${{ secrets.MY_SECRET }} and api_key=rawsecret999",
        "kind": "expression",
        "location": {"line": 10, "column": 14, "end_line": 10, "end_column": 42},
    }
    stdout_by_tool = {
        "tool-zizmor": json.dumps(
            [zizmor_finding(path=wf, row=8, column=8, offset=90, feature="uses: actions/checkout@v4")]
        ).encode("utf-8"),
        "tool-checkov": json.dumps(
            {"results": {"failed_checks": [checkov_workflow_permissions(wf, name="ci", span=(0, 1))]}}
        ).encode("utf-8"),
        "tool-actionlint": json.dumps([actionlint_finding, actionlint_finding]).encode("utf-8"),
    }
    job = build_job(executor_factory=lambda u: FakeExecutor(ROOT, u.job.run_root, calls, stdout=stdout_by_tool))

    with attempt_scope(unit):
        job.input_validators[0](unit.job, None)
        results = job.handler(unit.job)

    pub = results["outputs"]["ci_coverage.publish_handoff"]
    assert pub["coverage_status"] == "partial"
    assert pub["finding_count"] >= 4

    norm_al = results["outputs"]["ci_normalization.github_actionlint_normalize"]
    assert norm_al["duplicate_observation_count"] == 1
    norm_doc = _read(unit.job.run_root, norm_al["normalized_artifact"])
    msg = norm_doc["records"][0]["message"]
    assert "<redacted>" in msg
    assert "MY_SECRET" not in msg
    assert "rawsecret999" not in msg

    manifest_rel = pub["index_manifest"]["path"]
    manifest_doc = json.loads((unit.job.run_root / manifest_rel).read_text(encoding="utf-8"))
    by_key = {(entry["name"], entry["shard_id"]): entry for entry in manifest_doc["indexes"]}
    assert ("observations", "ci_stale") not in by_key
    assert {("source", "source_files"), ("evidence", "ci_findings"), ("observations", "ci_github_actionlint")} <= set(by_key)

    with sqlite3.connect(unit.job.run_root / by_key[("evidence", "ci_findings")]["relative_path"]) as conn:
        ev_count = conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
    with sqlite3.connect(unit.job.run_root / by_key[("observations", "ci_github_actionlint")]["relative_path"]) as conn:
        obs_count = conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
    assert ev_count >= 4
    assert obs_count == 1
    event_names = {name for name, _ in events}
    assert {"CI_DEFINITIONS_DISCOVERED", "CI_TOOL_SCANNED", "CI_ANALYSIS_PUBLISHED"} <= event_names
