"""Model discovery, required/optional gating, and preflight handler evidence."""
from __future__ import annotations

import json

import pytest

from appsec_review.config.loader import PENDING_JOBS
from appsec_review.jobs.job_review_intake import job as intake
from tests.unit.job_review_intake.support import ROOT, artifact, configuration, context, handler


def model(job_id="job_a", provider="p", name="m", **extra):
    return {"job_id": job_id, "setting": "settings.model", "provider": provider,
            "model": name, "enabled": True, **extra}


def test_discovery_recurses_mappings_sorts_jobs_and_ignores_pending_jobs_and_scalars(monkeypatch):
    pending = "job_pending_fixture"
    monkeypatch.setattr(intake, "PENDING_JOBS", frozenset({pending}))
    document = {"jobs": {
        "job_z": {"settings": {"models": {"default": {"provider": "p", "model": "d"},
                                         "deep": {"provider": "p", "model": "z", "enabled": False}}}},
        "job_a": {"settings": {"model": {"provider": "p", "model": "a"},
                               "writer": {"provider": "q", "model": "w", "enabled": 0},
                               "bad": {"provider": 7, "model": "ignored"}, "list": [{"model": "ignored"}]}},
        "job_bad": None,
        pending: {"settings": {"model": {"provider": "p", "model": "pending"}}},
    }}
    assert intake.configured_models(document) == [
        model(name="a"), model(provider="q", name="w", setting="settings.writer"),
        model("job_z", name="d", setting="settings.models.default"),
        model("job_z", name="z", setting="settings.models.deep", enabled=False),
    ]


@pytest.mark.parametrize("document", [{}, {"jobs": []}, {"jobs": {"job_a": {"settings": None}}}],
                         ids=["absent", "not-mapping", "scalar-settings"])
def test_discovery_with_no_model_tables_is_empty(document):
    assert intake.configured_models(document) == []
    assert intake.required_models(document) == ([], [])


def test_required_models_distinguishes_disabled_jobs_and_disabled_settings():
    def job(*, enabled=True, model_enabled=True):
        return {"settings": {"enabled": enabled, "model": {
            "provider": "p", "model": "m", "enabled": model_enabled}}}
    required, optional = intake.required_models({"jobs": {
        "job_a": job(), "job_b": job(enabled=False), "job_c": job(model_enabled=False),
        "job_d": job(enabled=False, model_enabled=False)}})
    assert required == [model()]
    assert optional == [
        model("job_b", reason="job disabled"),
        model("job_c", enabled=False, reason="model setting disabled"),
        model("job_d", enabled=False, reason="job disabled"),
    ]


def test_repository_model_tables_are_discovered_without_loading_host_configuration():
    import tomllib
    from appsec_review import inference
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    expected = {key for key, job in document["jobs"].items() if key not in PENDING_JOBS and (
        isinstance(job.get("settings", {}).get("model"), dict)
        or any(isinstance(job.get("settings", {}).get(name), dict) for name in ("writer", "reviewer"))
        or any(isinstance(value, dict) for value in job.get("settings", {}).get("models", {}).values()))}
    result = intake.configured_models(document)
    assert {row["job_id"] for row in result} == expected
    assert {row["provider"] for row in result} <= set(inference.MODEL_CHECKS) & set(inference.PROVIDERS)


def test_pairs_deduplicate_and_normalize_identifiers():
    assert intake._pairs([{"provider": 5, "model": 7}, {"provider": "5", "model": "7"}]) == {("5", "7")}


def test_verification_groups_once_per_provider_and_gates_shared_pairs():
    calls = []
    required = [model("job_z", "z", "b"), model("job_a", "a", "m"), model("job_b", "a", "m")]
    optional = [model("job_c", "a", "m"), model("job_d", "z", "a")]

    def check(provider, names, *, timeout_seconds):
        calls.append((provider, names, timeout_seconds))
        return {"models": {name: {"available": name == "b", "detail": "offline"} for name in names}}

    result = intake.verify_configured_models(check, required, optional, timeout_seconds=13, unit_id="verify")
    assert calls == [("a", ["m"], 13), ("z", ["a", "b"], 13)]
    assert result["schema"] == intake.PREFLIGHT_SCHEMA
    assert result["required"] == required and result["not_required"] == optional
    assert result["unavailable"] == [
        {"provider": "a", "model": "m", "detail": "offline", "jobs": ["job_a", "job_b", "job_c"]}]
    assert result["unavailable_not_required"] == [
        {"provider": "z", "model": "a", "detail": "offline", "jobs": ["job_d"]}]
    [gap] = result["gaps"]
    assert (gap["schema"], gap["code"], gap["scope_id"], gap["unit_id"], gap["retryable"]) == (
        "appsec-review/producer-gap/1", "producer_blocked", "z/a", "verify", True)
    assert gap["reason"] == "z/a unavailable (offline); configured by disabled job_d"


@pytest.mark.parametrize(("report", "detail"), [
    ({}, "not reported"),
    ({"error": "transport failed"}, "transport failed"),
    ({"models": {"m": {"available": 1, "detail": 42}}, "error": "ignored"}, "42"),
    ({"models": {"m": {"available": False, "detail": ""}}, "error": "fallback"}, "fallback"),
], ids=["unreported", "provider-error", "truthy-not-true", "empty-detail"])
def test_unavailable_details_fall_back_without_treating_truthiness_as_success(report, detail):
    result = intake.verify_configured_models(lambda *args, **kwargs: report, [], [model()],
                                            timeout_seconds=1, unit_id="verify")
    assert result["unavailable"] == []
    assert result["unavailable_not_required"] == [
        {"provider": "p", "model": "m", "detail": detail, "jobs": ["job_a"]}]
    assert [(gap["code"], gap["scope_id"]) for gap in result["gaps"]] == [("producer_blocked", "p/m")]


def test_empty_verification_never_calls_a_provider():
    calls = []
    result = intake.verify_configured_models(lambda *a, **k: calls.append(a), [], [],
                                            timeout_seconds=1, unit_id="verify")
    assert calls == []
    assert result == {"schema": intake.PREFLIGHT_SCHEMA, "required": [], "not_required": [],
                      "providers": {}, "unavailable": [], "unavailable_not_required": [], "gaps": []}


def test_resolve_models_reads_hashed_resolved_document_not_base_config(tmp_path):
    unit = context(tmp_path, "model_preflight.resolve_models")
    configuration(unit.job.run_root, {"jobs": {
        "job_a": {"settings": {"model": {"provider": "p", "model": "m"}}},
        "job_b": {"settings": {"model": {"provider": "p", "model": "m"}}},
        "job_c": {"settings": {"model": {"provider": "q", "model": "n", "enabled": False}}},
    }})
    result = handler(unit.unit_id)(unit)
    assert result == {"required": [model(), model("job_b")],
                      "not_required": [model("job_c", "q", "n", enabled=False, reason="model setting disabled")],
                      "model_count": 1}


def test_resolve_models_wiring_passes_run_document_to_selector(tmp_path, monkeypatch):
    unit = context(tmp_path, "model_preflight.resolve_models")
    seen = []
    document = {"fixture": "resolved"}
    monkeypatch.setattr(intake, "resolved_configuration", lambda root: seen.append(root) or document)
    monkeypatch.setattr(intake, "required_models",
                        lambda value: seen.append(value) or ([model(), model("job_b")], [model("job_c")]))
    assert handler(unit.unit_id)(unit) == {
        "required": [model(), model("job_b")], "not_required": [model("job_c")], "model_count": 1}
    assert seen == [unit.job.run_root, document]


def test_unwired_preflight_names_why_nothing_was_checked(tmp_path):
    unit = context(tmp_path, "model_preflight.verify_models", {
        "model_preflight.resolve_models": {"required": [model()], "not_required": []}})
    result = handler(unit.unit_id)(unit)
    assert result == {
        "schema": intake.PREFLIGHT_SCHEMA, "required": [model()], "not_required": [], "providers": {},
        "unavailable": [], "verified": [], "terminal_status": "NOT_APPLICABLE",
        "reason": "no model availability check is wired into this job instance",
    }
    assert unit.events == [] and list(unit.unit_root.iterdir()) == []


@pytest.mark.parametrize("mode", ["available", "optional", "required"])
def test_preflight_writes_evidence_and_events_before_typed_failure_or_success(tmp_path, mode):
    unit = context(tmp_path, "model_preflight.verify_models", {
        "model_preflight.resolve_models": {
            "required": [] if mode == "optional" else [model()],
            "not_required": [model()] if mode == "optional" else []}})
    calls = []

    def check(provider, names, *, timeout_seconds):
        calls.append((provider, names, timeout_seconds))
        return {"models": {"m": {"available": mode == "available", "detail": "probe"}}}

    if mode == "required":
        with pytest.raises(intake.ModelPreflightBlocked, match=r"p/m \(probe\)"):
            handler(unit.unit_id, check_models=check)(unit)
        result = None
    else:
        result = handler(unit.unit_id, check_models=check)(unit)
        document = artifact(unit, result)
        assert document["schema"] == intake.PREFLIGHT_SCHEMA
        assert result["providers"] == ["p"]
        assert result["verified"] == (["p/m"] if mode == "available" else [])
        assert result["terminal_status"] == ("SUCCEEDED" if mode == "available" else "COMPLETED_WITH_GAPS")
        assert [(gap["code"], gap["scope_id"]) for gap in result["gaps"]] == (
            [] if mode == "available" else [("producer_blocked", "p/m")])
    document = json.loads((unit.unit_root / "model-preflight.json").read_text())
    assert document["unavailable"] == (
        [{"provider": "p", "model": "m", "detail": "probe", "jobs": ["job_a"]}] if mode == "required" else [])
    assert calls == [("p", ["m"], 19)]
    assert unit.events == [("MODEL_PREFLIGHT_COMPLETED", {
        "unit_id": unit.unit_id, "provider_count": 1, "model_count": 1,
        "unavailable_count": int(mode == "required"), "unavailable_not_required_count": int(mode == "optional")})]


def test_verify_handler_wiring_passes_check_timeout_and_scope(tmp_path, monkeypatch):
    unit = context(tmp_path, "model_preflight.verify_models", {
        "model_preflight.resolve_models": {"required": [model()], "not_required": []}})
    check = object()
    seen = []
    document = {"schema": intake.PREFLIGHT_SCHEMA, "providers": {"z": {"models": {"b": {"available": True},
                 "a": {"available": True}, "no": {"available": False}}}, "a": {}},
                "unavailable": [], "unavailable_not_required": [], "gaps": []}
    monkeypatch.setattr(intake, "verify_configured_models",
                        lambda *args, **kwargs: seen.append((args, kwargs)) or document)
    result = handler(unit.unit_id, check_models=check)(unit)
    assert seen == [((check, [model()], []), {"timeout_seconds": 19, "unit_id": unit.unit_id})]
    assert artifact(unit, result) == document
    assert result["verified"] == ["z/a", "z/b"] and result["providers"] == ["a", "z"]
