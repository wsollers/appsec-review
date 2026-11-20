"""CI scanner admission and report contracts; only external I/O is faked."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_ci_configuration_analysis.job import (
    SPECS, _coverage, _external_records, _hierarchy, _index, _normalize, _read,
    _scan, _source_location, analysis_bounds, build_job,
)
from tests.unit.job_ci_configuration_analysis.support import (
    FakeExecutor, ROOT, attempt_scope, make_unit_context,
)

PATH = ".github/workflows/ci.yml"
SPECS_BY_KEY = {spec.key: spec for spec in SPECS}
ACTIONLINT = b'{"kind":"syntax-check","message":"diagnostic","line":1,"severity":"HIGH"}'


def _unit(tmp_path, *, spec="github_actionlint", settings=None, content="name: ci\n"):
    unit, files, _ = make_unit_context(
        tmp_path, unit_id=f"ci_analysis.{spec}_scan", target_files={PATH: content},
        settings_override=settings,
    )
    classified = {"definitions": [
        {**item, "provider": "github", "definition_id": f"ci:github:{item['path']}"}
        for item in files
    ], "gap_records": []}
    outputs = {"ci_discovery.classify_providers": classified}
    unit.output = outputs.__getitem__
    return unit, outputs


@pytest.mark.parametrize("spec", ["github_actionlint", "github_checkov"])
@pytest.mark.parametrize("payload", [
    b"{not valid json", b'{"error":"scanner unavailable"}', b'{"message":"scanner unavailable"}',
    b"[null]", b"[{}]", b"null", b'{"unexpected":[]}', b'{"kind":"rule","message":"\xff"}',
], ids=["invalid-json", "error", "message-only", "null-entry", "empty-entry", "null",
        "unknown-object", "invalid-utf8"])
def test_nonempty_malformed_reports_are_not_clean(spec, payload) -> None:
    with pytest.raises(ValueError):
        _external_records(SPECS_BY_KEY[spec], payload, PATH)


@pytest.mark.parametrize("payload", [
    ACTIONLINT + b"\n{broken",
    b"banner\n" + ACTIONLINT,
    b'{"diagnostics":[' + ACTIONLINT + b',false]}',
    b'{"diagnostics":[],"error":"failed"}',
], ids=["truncated-jsonl", "banner", "invalid-diagnostic", "error-with-empty-results"])
def test_actionlint_report_is_parsed_atomically(payload) -> None:
    with pytest.raises(ValueError):
        _external_records(SPECS_BY_KEY["github_actionlint"], payload, PATH)


@pytest.mark.parametrize("payload", [
    {"results": {}},
    {"results": {"failed_checks": {}}},
    {"results": {"failed_checks": [False]}},
    {"results": {"failed_checks": [], "parsing_errors": [PATH]}},
    {"results": {"failed_checks": []}, "summary": {"parsing_errors": 1}},
    {"results": {"failed_checks": []}, "error": "failed"},
], ids=["missing-checks", "invalid-checks", "invalid-finding", "parsing-errors", "error-summary",
        "error-with-empty-results"])
def test_checkov_incomplete_reports_are_not_clean(payload) -> None:
    with pytest.raises(ValueError):
        _external_records(SPECS_BY_KEY["github_checkov"], json.dumps(payload).encode(), PATH)


@pytest.mark.parametrize(("spec", "payload"), [
    ("github_actionlint", b""),
    ("github_actionlint", b"{}"),
    ("github_actionlint", b"[]"),
    ("github_actionlint", ACTIONLINT + b"\n" + ACTIONLINT),
    ("github_checkov", b""),
    ("github_checkov", b"{}"),
    ("github_checkov", b"[]"),
    ("github_checkov", b'{"results":{"failed_checks":[],"parsing_errors":[]},"summary":{"parsing_errors":0}}'),
    ("github_zizmor", b"[]"),
], ids=["actionlint-silent", "actionlint-object", "actionlint-array", "actionlint-jsonl",
        "checkov-silent", "checkov-object", "checkov-array", "checkov-report", "zizmor-array"])
def test_successful_empty_reports_and_native_jsonl_remain_valid(tmp_path, spec, payload) -> None:
    unit, _ = _unit(tmp_path, spec=spec)
    with attempt_scope(unit):
        result = _scan(unit, SPECS_BY_KEY[spec],
                       lambda u: FakeExecutor(ROOT, u.job.run_root, [], stdout=payload), None)
    assert result["terminal_status"] == "SUCCEEDED"
    assert result["gaps"] == []
    assert result["record_count"] == (2 if payload.startswith(ACTIONLINT) else 0)


class ReportExecutor(FakeExecutor):
    def __init__(self, *args, receipt=None, missing=False, output_bytes=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.receipt = receipt or {}
        self.missing = missing
        if output_bytes is not None:
            catalog = self.catalog
            self.catalog = SimpleNamespace(
                tool=lambda tool_id: replace(catalog.tool(tool_id), output_bytes=output_bytes),
            )

    def execute(self, request):
        result = super().execute(request)
        if self.missing:
            (self.run_root / result.stdout_path).unlink()
        return replace(result, **self.receipt)


@pytest.mark.parametrize(("payload", "receipt", "missing", "exit_code", "code"), [
    (b"{broken", {}, False, 0, "parser_error"),
    (b'{"error":"password=private-value"}', {}, False, 0, "parser_error"),
    (ACTIONLINT, {"stdout_truncated": True}, False, 0, "truncated"),
    (ACTIONLINT, {"stderr_truncated": True}, False, 0, "truncated"),
    (b"", {}, True, 0, "parser_error"),
    (b"", {}, False, 1, "parser_error"),
], ids=["malformed", "error", "stdout-truncated", "stderr-truncated", "missing", "failed-empty"])
def test_incomplete_execution_stays_a_gap_through_index_and_coverage(
    tmp_path, payload, receipt, missing, exit_code, code,
) -> None:
    unit, outputs = _unit(tmp_path)
    spec = SPECS_BY_KEY["github_actionlint"]
    with attempt_scope(unit):
        scan = _scan(unit, spec, lambda u: ReportExecutor(
            ROOT, u.job.run_root, [], stdout=payload, receipt=receipt, missing=missing, exit_code=exit_code,
        ), None)
        assert scan["terminal_status"] == "FAILED"
        assert scan["record_count"] == 0
        assert [gap["code"] for gap in scan["gaps"]] == [code]
        assert scan["gaps"][0]["scope_id"] == PATH
        assert "private-value" not in json.dumps(scan["gaps"])
        assert scan["executions"][0]["exit_code"] == exit_code
        outputs["scan"] = scan
        outputs["normalize"] = _normalize(unit, "scan")
        outputs["ci_enrichment.build_hierarchy"] = _hierarchy(unit)
        outputs["index"] = _index(unit, spec, "normalize")
        coverage = _coverage(unit, ("index",))
    assert outputs["index"]["scan_terminal_status"] == "FAILED"
    assert coverage["coverage_status"] == "partial"
    assert coverage["gap_records"] == scan["gaps"]


@pytest.mark.parametrize("spec", ["github_zizmor", "github_checkov", "github_actionlint"])
def test_oversized_external_input_is_rejected_before_image_resolution(tmp_path, spec) -> None:
    unit, _ = _unit(tmp_path, spec=spec, settings={"max_file_bytes": 1}, content="x" * 200)
    resolved = []

    def executor(u):
        resolved.append(True)
        return FakeExecutor(ROOT, u.job.run_root, [], stdout=b"[]")

    with attempt_scope(unit):
        result = _scan(unit, SPECS_BY_KEY[spec], executor, None)
    assert resolved == []
    assert result["executions"] == []
    assert result["terminal_status"] == "FAILED"
    assert result["gaps"][0]["code"] == "producer_reported_gap"
    assert "max_file_bytes" in result["gaps"][0]["reason"]


def _growing_stream(monkeypatch, path, *, limit, data):
    original = Path.open
    reads = []

    class GrowingStream(io.BytesIO):
        def read(self, size=-1):
            reads.append(size)
            assert 0 < size <= limit + 1, "must bound the actual read, not slice afterwards"
            return super().read(size)

    def open_path(self, mode="r", *args, **kwargs):
        if self == path and mode == "rb":
            return GrowingStream(data)
        return original(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_path)
    return reads


@pytest.mark.parametrize("reader", ["static", "hierarchy", "location", "external"])
def test_actual_source_reads_are_bounded_even_if_file_grows_after_stat(tmp_path, monkeypatch, reader) -> None:
    unit, _ = _unit(tmp_path, settings={"max_file_bytes": 16})
    reads = _growing_stream(monkeypatch, unit.job.target_root / PATH, limit=16, data=b"x" * 200)
    with attempt_scope(unit):
        if reader == "location":
            with pytest.raises(ValueError, match="max_file_bytes"):
                _source_location(unit, {"path": PATH, "tool_id": "ci-schema", "start_line": 1,
                                        "end_line": 1, "start_column": 1, "end_column": 2})
        elif reader == "hierarchy":
            result = _hierarchy(unit)
        else:
            spec = SPECS_BY_KEY["github_schema" if reader == "static" else "github_actionlint"]
            result = _scan(unit, spec, lambda _: pytest.fail("oversized source must not launch"), None)
        if reader != "location":
            assert result["gaps"][0]["code"] == "producer_reported_gap"
            assert "max_file_bytes" in result["gaps"][0]["reason"]
    assert reads == [17]


def test_source_location_hashes_the_same_bounded_bytes(tmp_path, monkeypatch) -> None:
    unit, _ = _unit(tmp_path, settings={"max_file_bytes": 9})
    data = b"name: ci\n"
    reads = _growing_stream(monkeypatch, unit.job.target_root / PATH, limit=9, data=data)
    location = _source_location(unit, {"path": PATH, "tool_id": "ci-schema", "start_line": 1,
                                      "end_line": 1, "start_column": 1, "end_column": 8})
    assert location.file_sha256 == hashlib.sha256(data).hexdigest()
    assert data[location.start_byte:location.end_byte] == b"name: ci"
    assert location.ambiguous and location.confidence < 1
    assert (location.start_column, location.end_column) == (1, 9)
    assert reads == [10]


def test_report_file_read_honors_tool_bound_independently_of_receipt(tmp_path, monkeypatch) -> None:
    unit, _ = _unit(tmp_path)
    stdout = unit.unit_root / "scratch/file_0001/raw/stdout.bin"
    reads = _growing_stream(monkeypatch, stdout, limit=32, data=b"x" * 200)
    with attempt_scope(unit):
        result = _scan(unit, SPECS_BY_KEY["github_actionlint"], lambda u: ReportExecutor(
            ROOT, u.job.run_root, [], stdout=b"[]", output_bytes=32,
        ), None)
    assert reads == [33]
    assert result["record_count"] == 0
    assert result["gaps"][0]["code"] == "truncated"


@pytest.mark.parametrize("tools", [[], ["schema"]], ids=["disabled-provider", "static-only"])
def test_configured_tool_subset_survives_real_job_publication(tmp_path, tools) -> None:
    unit, _ = _unit(tmp_path, settings={"providers": {"github": {"tools": tools}}})
    calls = []
    job = build_job(executor_factory=lambda u: FakeExecutor(ROOT, u.job.run_root, calls))
    with attempt_scope(unit):
        job.input_validators[0](unit.job, None)
        result = job.handler(unit.job)
    assert calls == []
    outputs = result["outputs"]
    coverage = outputs["ci_coverage.join_coverage"]
    for spec in [spec for spec in SPECS if spec.provider == "github"]:
        scan = outputs[f"ci_analysis.{spec.key}_scan"]
        expected = "SUCCEEDED" if spec.name in tools else "CONFIGURED_DISABLED"
        assert scan["terminal_status"] == expected
        raw = _read(unit.job.run_root, scan["raw_artifact"])
        assert raw["disabled_by_configuration"] == (spec.name not in tools)
        indexed = outputs[f"ci_observation_publication.{spec.key}_index"]
        assert indexed["disabled_by_configuration"] == (spec.name not in tools)
        joined = next(item for item in coverage["tools"]
                      if item["provider"] == "github" and item["tool_id"] == spec.tool_id)
        assert joined["disabled_by_configuration"] == (spec.name not in tools)
    assert outputs["ci_coverage.publish_handoff"]["coverage_status"] == "complete"


@pytest.mark.parametrize(("spec_key", "path"), [
    ("github_checkov", PATH),
    ("azure_checkov", "azure-pipelines.yml"),
    ("gitlab_checkov", ".gitlab-ci.yml"),
    ("circleci_checkov", ".circleci/config.yml"),
    ("bitbucket_checkov", "bitbucket-pipelines.yml"),
    ("jenkins_structural", "Jenkinsfile"),
    ("teamcity_structural", ".teamcity/settings.kts"),
    ("other_discovery", ".travis.yml"),
])
def test_enabled_provider_settings_match_actual_selectors_and_reported_identity(tmp_path, spec_key, path) -> None:
    spec = SPECS_BY_KEY[spec_key]
    tool_name = spec.tool_id if spec.mode == "discovery" else spec.name
    settings = {"tools": [tool_name]}
    if spec.framework is not None:
        settings["framework"] = spec.framework
    unit, files, _ = make_unit_context(
        tmp_path, unit_id=f"ci_analysis.{spec_key}_scan", target_files={path: "# fixture\n"},
        settings_override={"providers": {spec.provider: settings}},
    )
    unit.output = {"ci_discovery.classify_providers": {
        "definitions": [{**files[0], "provider": spec.provider, "definition_id": f"ci:{spec.provider}:{path}"}],
    }}.__getitem__
    calls = []
    with attempt_scope(unit):
        result = _scan(unit, spec, lambda u: FakeExecutor(ROOT, u.job.run_root, calls), None)
    assert result["disabled_by_configuration"] is False
    raw = _read(unit.job.run_root, result["raw_artifact"])
    assert raw["framework"] == spec.framework
    if spec.mode == "external":
        [(tool_id, argv)] = calls
        assert tool_id == spec.tool_id
        assert argv[argv.index("--framework") + 1] == spec.framework
        assert argv[argv.index("--file") + 1] == f"/target/{path}"
    else:
        assert calls == []
        if spec.mode == "static":
            assert raw["ruleset_identity"] == "ci-static-reviewed-rules/1"
    assert result["terminal_status"] == ("PARTIAL" if spec.mode == "discovery" else "SUCCEEDED")


def test_discovery_only_provider_can_be_disabled_without_a_missing_linter_gap(tmp_path) -> None:
    unit, files, _ = make_unit_context(
        tmp_path, unit_id="ci_analysis.other_discovery_scan", target_files={".travis.yml": "language: python\n"},
        settings_override={"providers": {"other": {"tools": []}}},
    )
    unit.output = {"ci_discovery.classify_providers": {
        "definitions": [{**files[0], "provider": "other", "definition_id": "ci:other:.travis.yml"}],
    }}.__getitem__
    with attempt_scope(unit):
        result = _scan(unit, SPECS_BY_KEY["other_discovery"],
                       lambda _: pytest.fail("disabled discovery has no executor"), None)
    assert result["terminal_status"] == "CONFIGURED_DISABLED"
    assert result["coverage_disposition"] == "CONFIGURED_DISABLED"
    assert result["gaps"] == []


@pytest.mark.parametrize("settings", [
    {"correlation": "different/1"},
    {"ruleset": "different/1"},
    {"providers": {"github": {"framework": "gitlab_ci"}}},
    {"providers": {"jenkins": {"framework": "github_actions"}}},
    {"providers": {"github": {"tools": ["unknown"]}}},
    {"providers": {"github": {"tools": "checkov"}}},
    {"providers": {"github": {"tools": ["checkov", "checkov"]}}},
    {"providers": {"github": {"tool": []}}},
    {"providers": {"unknown": {"tools": []}}},
    {"providers": []},
    {"rulesets": "ci-static-reviewed-rules/1"},
], ids=["correlation", "ruleset", "framework", "unsupported-framework", "tool", "tools-type",
        "duplicate-tools", "unknown-provider-setting", "provider", "providers-type", "unknown-setting"])
def test_unsupported_routing_or_identity_is_rejected_at_admission(tmp_path, settings) -> None:
    unit, _ = _unit(tmp_path, settings=settings)
    job = build_job(executor_factory=lambda _: pytest.fail("invalid settings must not launch"))
    with attempt_scope(unit), pytest.raises(ValueError):
        job.input_validators[0](unit.job, None)


@pytest.mark.parametrize("field", ["max_files", "max_file_bytes", "max_observations_per_tool"])
@pytest.mark.parametrize("value", [True, 1.9, "1"], ids=["boolean", "fractional", "string"])
def test_analysis_bounds_require_actual_integers(field, value) -> None:
    with pytest.raises(ValueError):
        analysis_bounds({field: value})
