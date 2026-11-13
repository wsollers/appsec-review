"""Direct handler and pair-helper tests using canned configuration and provider reports."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.interchange import producer_gap, validate_unit_output
from appsec_review.jobs.job_model_connectivity.job import ModelConnectivityBlocked, _pairs

from .support import PUBLISH, RESOLVE, SCHEMA, VERIFY, context, handler, model, serving, write_configuration


@pytest.mark.parametrize(("items", "expected"), [
    ([], set()),
    ([{"provider": "p", "model": "m"}, {"provider": "p", "model": "m"}], {("p", "m")}),
    ([{"provider": "p", "model": "m"}, {"provider": "q", "model": "m"}], {("p", "m"), ("q", "m")}),
    ([{"provider": 7, "model": 3}, {"provider": "7", "model": "3"}], {("7", "3")}),
], ids=["empty", "duplicate", "different-provider", "string-coercion"])
def test_pairs_are_unique_provider_model_strings(items, expected) -> None:
    assert _pairs(items) == expected


@pytest.mark.parametrize(("item", "missing"), [
    ({"model": "m"}, "provider"), ({"provider": "p"}, "model"),
], ids=["missing-provider", "missing-model"])
def test_pairs_reject_incomplete_records_with_the_missing_field(item, missing) -> None:
    with pytest.raises(KeyError) as error:
        _pairs([item])
    assert error.value.args == (missing,)


def test_resolve_classifies_disabled_jobs_settings_nested_and_shared_pairs(tmp_path: Path) -> None:
    unit = context(tmp_path, RESOLVE)
    document = {"jobs": {
        "job_a": {"settings": {"model": {"provider": "p", "model": "live"}}},
        "job_b": {"settings": {"enabled": False, "model": {"provider": "p", "model": "job-off"}}},
        "job_c": {"settings": {"model": {"provider": "p", "model": "setting-off", "enabled": False}}},
        "job_d": {"settings": {"enabled": True, "models": {"x": {"provider": "q", "model": "nested"}}}},
        "job_e": {"settings": {"model": {"provider": "p", "model": "live"}}},
        "job_f": {"settings": {"model": {"provider": "p", "model": "live", "enabled": False}}},
        "job_g": {"settings": {"model": {"provider": "p", "model": "setting-off", "enabled": False}}},
    }}
    write_configuration(unit.job.run_root, document)
    result = handler(RESOLVE)(unit)
    assert result == {
        "required": [
            model("job_a", "p", "live"),
            {**model("job_d", "q", "nested"), "setting": "settings.models.x"},
            model("job_e", "p", "live"),
        ],
        "not_required": [
            model("job_b", "p", "job-off", reason="job disabled"),
            model("job_c", "p", "setting-off", enabled=False, reason="model setting disabled"),
            model("job_f", "p", "live", enabled=False, reason="model setting disabled"),
            model("job_g", "p", "setting-off", enabled=False, reason="model setting disabled"),
        ],
        "model_count": 2, "not_required_count": 2,
    }
    assert unit.job.events.records == [] and not unit.unit_root.exists()


@pytest.mark.parametrize("document", [{}, {"jobs": {}}, {"jobs": {"job_a": {"settings": {"limit": 1}}}}],
                         ids=["no-jobs", "empty-jobs", "no-models"])
def test_resolve_empty_configuration_has_no_model_requirements(tmp_path: Path, document) -> None:
    unit = context(tmp_path, RESOLVE)
    write_configuration(unit.job.run_root, document)
    assert handler(RESOLVE)(unit) == {
        "required": [], "not_required": [], "model_count": 0, "not_required_count": 0,
    }


def test_resolve_refuses_a_configuration_changed_after_its_manifest(tmp_path: Path) -> None:
    unit = context(tmp_path, RESOLVE)
    write_configuration(unit.job.run_root, {"jobs": {}})
    (unit.job.run_root / "data/configuration/resolved.json").write_text('{"jobs":{"job_tampered":{}}}')
    with pytest.raises(ValueError, match="^run-owned resolved configuration hash mismatch$"):
        handler(RESOLVE)(unit)
    assert not unit.unit_root.exists() and unit.job.events.records == []


@pytest.mark.parametrize("missing", ["manifest.json", "resolved.json"], ids=["manifest", "resolved"])
def test_resolve_missing_input_names_the_configuration_file(tmp_path: Path, missing) -> None:
    unit = context(tmp_path, RESOLVE)
    write_configuration(unit.job.run_root, {"jobs": {}})
    path = unit.job.run_root / "data/configuration" / missing
    path.unlink()
    with pytest.raises(FileNotFoundError) as error:
        handler(RESOLVE)(unit)
    assert error.value.filename == str(path)
    assert unit.job.events.records == []


def test_verify_checks_all_pairs_once_per_provider_and_sorts_the_summary(tmp_path: Path) -> None:
    required = [
        model("job_z", "z", "later"),
        model("job_b", "a", "beta"),
        model("job_a", "a", "alpha"),
        model("job_c", "a", "alpha"),
    ]
    optional = [
        model("job_off", "z", "off", enabled=False, reason="model setting disabled"),
        model("job_shared", "a", "alpha", enabled=False, reason="model setting disabled"),
    ]
    resolved = {"required": required, "not_required": optional}
    original = deepcopy(resolved)
    calls = []
    unit = context(tmp_path, VERIFY, {RESOLVE: resolved}, timeout=600)
    result = handler(VERIFY, check_models=serving(calls))(unit)
    document = json.loads((unit.unit_root / "model-connectivity.json").read_bytes())
    assert calls == [("a", ("alpha", "beta"), 600), ("z", ("later", "off"), 600)]
    assert result == {
        "schema": SCHEMA, "artifact": result["artifact"],
        "providers": ["a", "z"], "verified": ["a/alpha", "a/beta", "z/later", "z/off"],
        "not_required": ["a/alpha", "z/off"], "unavailable_not_required": [],
        "gaps": [], "terminal_status": "SUCCEEDED",
    }
    assert document["required"] == required and document["not_required"] == optional
    assert document["unavailable"] == document["unavailable_not_required"] == document["gaps"] == []
    assert unit.job.events.records == [("MODEL_CONNECTIVITY_COMPLETED", {
        "unit_id": VERIFY, "provider_count": 2, "model_count": 4,
        "unavailable_count": 0, "unavailable_not_required_count": 0,
    })]
    assert resolved == original
    validate_unit_output(result, unit_id=VERIFY, strict_gaps=True)


@pytest.mark.parametrize("availability", [False, None, 1, "true"], ids=["false", "none", "one", "string"])
def test_verify_unavailable_optional_model_yields_a_retryable_scoped_gap(
    tmp_path: Path, availability,
) -> None:
    resolved = {
        "required": [model("job_live", "p", "live")],
        "not_required": [model("job_off", "p", "off", enabled=False, reason="model setting disabled")],
    }
    unit = context(tmp_path, VERIFY, {RESOLVE: resolved})
    calls = []

    def check(provider, names, *, timeout_seconds):
        calls.append((provider, names, timeout_seconds))
        return {"models": {
            "live": {"available": True},
            "off": {"available": availability, "detail": "not listed"},
        }}

    result = handler(VERIFY, check_models=check)(unit)
    document = json.loads((unit.unit_root / "model-connectivity.json").read_bytes())
    assert calls == [("p", ["live", "off"], 37)]
    expected_gap = producer_gap(
        "producer_blocked", "p/off unavailable (not listed); configured by disabled job_off",
        unit_id=VERIFY, scope_id="p/off", retryable=True,
    )
    assert result == {
        "schema": SCHEMA, "artifact": result["artifact"], "providers": ["p"], "verified": ["p/live"],
        "not_required": ["p/off"], "unavailable_not_required": ["p/off"],
        "gaps": [expected_gap], "terminal_status": "COMPLETED_WITH_GAPS",
    }
    assert document["gaps"] == [expected_gap]
    assert document["unavailable"] == []
    assert document["unavailable_not_required"] == [
        {"provider": "p", "model": "off", "detail": "not listed", "jobs": ["job_off"]},
    ]
    assert (expected_gap["schema"], expected_gap["code"], expected_gap["unit_id"],
            expected_gap["scope_id"], expected_gap["retryable"]) == (
        "appsec-review/producer-gap/1", "producer_blocked", VERIFY, "p/off", True,
    )
    assert unit.job.events.records == [("MODEL_CONNECTIVITY_COMPLETED", {
        "unit_id": VERIFY, "provider_count": 1, "model_count": 2,
        "unavailable_count": 0, "unavailable_not_required_count": 1,
    })]
    validate_unit_output(result, unit_id=VERIFY, strict_gaps=True)


def test_verify_required_failures_keep_all_evidence_and_emit_counts_before_raising(tmp_path: Path) -> None:
    resolved = {
        "required": [model("job_z", "z", "missing"), model("job_a", "a", "missing")],
        "not_required": [
            model("job_shared", "a", "missing", enabled=False, reason="model setting disabled"),
            model("job_off", "a", "optional", enabled=False, reason="model setting disabled"),
        ],
    }
    unit = context(tmp_path, VERIFY, {RESOLVE: resolved})
    calls = []

    def check(provider, names, *, timeout_seconds):
        calls.append((provider, names, timeout_seconds))
        return {"models": {name: {"available": False, "detail": f"{provider}/{name} down"} for name in names}}

    with pytest.raises(ModelConnectivityBlocked) as error:
        handler(VERIFY, check_models=check)(unit)
    assert str(error.value) == (
        "model connectivity blocked the review: a/missing (a/missing down); z/missing (z/missing down)"
    )
    assert calls == [("a", ["missing", "optional"], 37), ("z", ["missing"], 37)]
    document = json.loads((unit.unit_root / "model-connectivity.json").read_bytes())
    assert document["schema"] == SCHEMA
    assert document["unavailable"] == [
        {"provider": "a", "model": "missing", "detail": "a/missing down", "jobs": ["job_a", "job_shared"]},
        {"provider": "z", "model": "missing", "detail": "z/missing down", "jobs": ["job_z"]},
    ]
    assert document["unavailable_not_required"] == [
        {"provider": "a", "model": "optional", "detail": "a/optional down", "jobs": ["job_off"]},
    ]
    assert [(gap["code"], gap["unit_id"], gap["scope_id"]) for gap in document["gaps"]] == [
        ("producer_blocked", VERIFY, "a/optional"),
    ]
    assert unit.job.events.records == [("MODEL_CONNECTIVITY_COMPLETED", {
        "unit_id": VERIFY, "provider_count": 2, "model_count": 3,
        "unavailable_count": 2, "unavailable_not_required_count": 1,
    })]
    assert not (unit.unit_root / "model-connectivity-handoff.json").exists()


@pytest.mark.parametrize(("report", "detail"), [
    ({}, "not reported"),
    ({"transport": False, "error": "connection refused"}, "connection refused"),
    ({"models": {"m": {"available": False, "detail": "model denied"}}, "error": "provider error"}, "model denied"),
], ids=["omitted-models", "transport-error", "model-error"])
@pytest.mark.parametrize("required", [False, True], ids=["optional", "required"])
def test_verify_missing_or_failed_provider_reports_preserve_model_scope_and_failure_detail(
    tmp_path: Path, report, detail, required,
) -> None:
    item = model("job_a", "p", "m", enabled=required)
    resolved = {"required": [item] if required else [], "not_required": [] if required else [item]}
    unit = context(tmp_path, VERIFY, {RESOLVE: resolved})
    check = lambda *args, **kwargs: report
    if required:
        with pytest.raises(ModelConnectivityBlocked) as error:
            handler(VERIFY, check_models=check)(unit)
        assert str(error.value) == f"model connectivity blocked the review: p/m ({detail})"
    else:
        result = handler(VERIFY, check_models=check)(unit)
        assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
        assert result["verified"] == []
        assert result["unavailable_not_required"] == ["p/m"]
        assert [(gap["code"], gap["unit_id"], gap["scope_id"]) for gap in result["gaps"]] == [
            ("producer_blocked", VERIFY, "p/m"),
        ]
        validate_unit_output(result, unit_id=VERIFY, strict_gaps=True)
    document = json.loads((unit.unit_root / "model-connectivity.json").read_bytes())
    assert document["providers"] == {"p": report}
    assert document["unavailable" if required else "unavailable_not_required"] == [
        {"provider": "p", "model": "m", "detail": detail, "jobs": ["job_a"]},
    ]
    assert document["unavailable_not_required" if required else "unavailable"] == []
    assert unit.job.events.records == [("MODEL_CONNECTIVITY_COMPLETED", {
        "unit_id": VERIFY, "provider_count": 1, "model_count": len(report.get("models", {})),
        "unavailable_count": int(required), "unavailable_not_required_count": int(not required),
    })]


def test_verify_empty_model_set_succeeds_without_calling_the_provider(tmp_path: Path) -> None:
    unit = context(tmp_path, VERIFY, {RESOLVE: {"required": [], "not_required": []}})
    check = lambda *args, **kwargs: pytest.fail("an empty model set must not contact a provider")
    result = handler(VERIFY, check_models=check)(unit)
    assert result == {
        "schema": SCHEMA, "artifact": result["artifact"], "providers": [], "verified": [],
        "not_required": [], "unavailable_not_required": [], "gaps": [], "terminal_status": "SUCCEEDED",
    }
    assert unit.job.events.records == [("MODEL_CONNECTIVITY_COMPLETED", {
        "unit_id": VERIFY, "provider_count": 0, "model_count": 0,
        "unavailable_count": 0, "unavailable_not_required_count": 0,
    })]
    validate_unit_output(result, unit_id=VERIFY, strict_gaps=True)


def test_verify_propagates_a_raised_provider_error_without_fabricating_evidence(tmp_path: Path) -> None:
    unit = context(tmp_path, VERIFY, {RESOLVE: {
        "required": [model("job_a", "p", "m")], "not_required": [],
    }})
    failure = ConnectionError("provider p unavailable while checking m")

    def check(provider, names, *, timeout_seconds):
        assert (provider, names, timeout_seconds) == ("p", ["m"], 37)
        raise failure

    with pytest.raises(ConnectionError) as error:
        handler(VERIFY, check_models=check)(unit)
    assert error.value is failure
    assert str(error.value) == "provider p unavailable while checking m"
    assert not unit.unit_root.exists() and unit.job.events.records == []


def test_verify_unwired_direct_handler_fails_before_writing_evidence(tmp_path: Path) -> None:
    unit = context(tmp_path, VERIFY, {RESOLVE: {"required": [], "not_required": []}})
    with pytest.raises(AssertionError):
        handler(VERIFY)(unit)
    assert unit.unit_id == VERIFY and not unit.unit_root.exists()
    assert unit.job.events.records == []


@pytest.mark.parametrize(("unit_id", "dependency"), [(VERIFY, RESOLVE), (PUBLISH, VERIFY)],
                         ids=["verify", "publish"])
def test_handler_missing_upstream_output_names_the_dependency(tmp_path: Path, unit_id, dependency) -> None:
    unit = context(tmp_path, unit_id)
    with pytest.raises(KeyError) as error:
        handler(unit_id, check_models=object())(unit)
    assert error.value.args == (f"unit output is unavailable: {dependency}",)
    assert not unit.unit_root.exists() and unit.job.events.records == []


@pytest.mark.parametrize("with_gap", [False, True], ids=["success", "gap"])
def test_publish_preserves_the_verified_summary_without_duplicating_observed_gaps(
    tmp_path: Path, with_gap,
) -> None:
    gap = producer_gap("producer_blocked", "p/off did not answer", unit_id=VERIFY, scope_id="p/off", retryable=True)
    verified = {
        "schema": SCHEMA,
        "artifact": {"path": "verification.json", "sha256": "a" * 64, "size_bytes": 17},
        "providers": ["p"], "verified": ["p/live"], "not_required": ["p/off"],
        "unavailable_not_required": ["p/off"] if with_gap else [],
        "terminal_status": "COMPLETED_WITH_GAPS" if with_gap else "SUCCEEDED",
        "gaps": [gap] if with_gap else [],
    }
    original = deepcopy(verified)
    unit = context(tmp_path, PUBLISH, {VERIFY: verified})
    result = handler(PUBLISH)(unit)
    path = unit.unit_root / "model-connectivity-handoff.json"
    data = path.read_bytes()
    document = json.loads(data)
    assert document == {
        "schema": SCHEMA, "artifact": verified["artifact"], "providers": ["p"], "verified": ["p/live"],
        "not_required": ["p/off"], "unavailable_not_required": ["p/off"] if with_gap else [],
    }
    assert result == {
        "schema": SCHEMA,
        "artifact": {
            "path": path.relative_to(unit.job.run_root).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data),
        },
        "verified": ["p/live"], "not_required": ["p/off"],
        "unavailable_not_required": ["p/off"] if with_gap else [],
        "terminal_status": "SUCCEEDED", "gaps": [],
    }
    assert verified == original and unit.job.events.records == []
    validate_unit_output(result, unit_id=PUBLISH, strict_gaps=True)


@pytest.mark.parametrize(("unit_id", "filename"), [
    (VERIFY, "model-connectivity.json"), (PUBLISH, "model-connectivity-handoff.json"),
], ids=["verify", "publish"])
def test_handler_write_failure_propagates_the_file_scope_without_completion(
    tmp_path: Path, monkeypatch, unit_id, filename,
) -> None:
    from appsec_review.jobs.job_model_connectivity import job as connectivity

    outputs = {
        RESOLVE: {"required": [], "not_required": []},
        VERIFY: {"artifact": {}, "providers": [], "verified": [], "not_required": [],
                 "unavailable_not_required": []},
    }
    unit = context(tmp_path, unit_id, outputs)
    failure = PermissionError(13, "fixture write denied", str(unit.unit_root / filename))

    def write(path, document):
        assert path == unit.unit_root / filename and document["schema"] == SCHEMA
        raise failure

    monkeypatch.setattr(connectivity, "write_json", write)
    with pytest.raises(PermissionError) as error:
        handler(unit_id, check_models=serving([]))(unit)
    assert error.value is failure
    assert error.value.filename == str(unit.unit_root / filename)
    assert unit.job.events.records == [] and not unit.unit_root.exists()
