from __future__ import annotations

from dataclasses import FrozenInstanceError, asdict
import json
from pathlib import Path
import tomllib

import pytest

from appsec_review.config import InferenceSecurityReviewSettings, load_config
from appsec_review.config.inference_review import (
    CAPACITY_KEYS,
    DecisionAuditSettings,
    parse_inference_review_settings,
    semantic_settings_sha256,
    semantic_settings_view,
)

ROOT = Path(__file__).resolve().parents[3]
FIELD = "jobs.job_inference_security_review.settings.decision_audit"
BOUNDS = (
    ("max_input_bytes", 4096, 64 * 1024 * 1024),
    ("max_records", 1, 1_000_000),
    ("shard_records", 1, 5000),
    ("shard_bytes", 4096, 8 * 1024 * 1024),
    ("page_size", 1, 200),
    ("max_page_size", 1, 200),
)


def _raw_settings():
    return tomllib.loads((ROOT / "appsec-review.toml").read_text())[
        "jobs"]["job_inference_security_review"]["settings"]


def _audit(**changes):
    return asdict(DecisionAuditSettings()) | changes


def test_absent_table_is_disabled_and_settings_are_frozen():
    settings = DecisionAuditSettings.from_mapping(None, FIELD)
    assert settings.enabled is False
    assert settings.shard_records == 5000
    assert settings.shard_bytes == 8 * 1024 * 1024
    with pytest.raises(FrozenInstanceError):
        setattr(settings, "enabled", True)


def test_new_configuration_enables_audit_without_changing_model_semantics():
    raw = _raw_settings()
    current = parse_inference_review_settings(raw)
    assert current.decision_audit.enabled is True
    assert current.as_document()["decision_audit"] == raw["decision_audit"]
    legacy = parse_inference_review_settings({key: value for key, value in raw.items()
                                              if key != "decision_audit"})
    assert legacy.decision_audit.enabled is False
    assert current.as_document() != legacy.as_document()
    assert semantic_settings_view(current) == semantic_settings_view(legacy)
    assert semantic_settings_sha256(current) == semantic_settings_sha256(legacy)
    assert "decision_audit" not in semantic_settings_view(current)["settings"]
    assert not any("decision_audit" in key for key in CAPACITY_KEYS)


def test_frozen_configuration_keeps_audit_bounds_in_its_own_identity(tmp_path):
    source = (ROOT / "appsec-review.toml").read_text()
    before = "max_records = 100000\nshard_records"
    assert source.count(before) == 1
    path = tmp_path / "audit-config.toml"
    path.write_text(source.replace(before, "max_records = 99999\nshard_records"))
    original = load_config(ROOT / "appsec-review.toml", profile="dev", overlay="")
    changed = load_config(path, profile="dev", overlay="")
    assert original.resolved_sha256 != changed.resolved_sha256
    frozen = json.loads(changed.resolved_json)["jobs"]["job_inference_security_review"]["settings"]
    assert frozen["decision_audit"]["max_records"] == 99999
    original_settings = original.job("job_inference_security_review").typed_settings
    changed_settings = changed.job("job_inference_security_review").typed_settings
    assert isinstance(original_settings, InferenceSecurityReviewSettings)
    assert isinstance(changed_settings, InferenceSecurityReviewSettings)
    assert semantic_settings_sha256(original_settings) == semantic_settings_sha256(changed_settings)


def test_capacity_overlay_cannot_enable_or_disable_audit(tmp_path):
    overlay = tmp_path / "capacity.toml"
    overlay.write_text(f"[{FIELD}]\nenabled = false\n")
    with pytest.raises(ValueError, match="rejected: .*decision_audit"):
        load_config(ROOT / "appsec-review.toml", profile="dev", overlay=overlay)


@pytest.mark.parametrize("name", [name for name, _, _ in BOUNDS])
def test_each_audit_bound_is_serialized_but_does_not_change_model_fingerprints(name):
    raw = _raw_settings()
    original = parse_inference_review_settings(raw)
    changed_value = raw["decision_audit"][name] - 1
    if name == "max_input_bytes":
        changed_value = 32 * 1024 * 1024
    changed = parse_inference_review_settings(
        raw | {"decision_audit": raw["decision_audit"] | {name: changed_value}})
    assert changed.as_document()["decision_audit"][name] == changed_value
    assert original.as_document()["decision_audit"] != changed.as_document()["decision_audit"]
    assert semantic_settings_sha256(original) == semantic_settings_sha256(changed)


@pytest.mark.parametrize("value", [False, 1, "enabled", [], ()], ids=["bool", "int", "str", "list", "tuple"])
def test_non_table_settings_fail(value):
    with pytest.raises(ValueError, match="must be a table"):
        DecisionAuditSettings.from_mapping(value, FIELD)


def test_unknown_and_missing_settings_fail():
    with pytest.raises(ValueError, match="unknown settings: arbitrary"):
        DecisionAuditSettings.from_mapping(_audit(arbitrary=True), FIELD)
    values = _audit()
    del values["max_records"]
    with pytest.raises(ValueError, match="missing settings: max_records"):
        DecisionAuditSettings.from_mapping(values, FIELD)


@pytest.mark.parametrize("value", [0, 1, "true", None], ids=["zero", "one", "string", "null"])
def test_enabled_requires_a_boolean(value):
    with pytest.raises(ValueError, match="enabled must be a Boolean"):
        DecisionAuditSettings.from_mapping(_audit(enabled=value), FIELD)


@pytest.mark.parametrize("name,low,high", BOUNDS, ids=[name for name, _, _ in BOUNDS])
@pytest.mark.parametrize("invalid", ["below", "above", "bool", "float", "string"])
def test_numeric_bounds_and_types_are_rejected(name, low, high, invalid):
    value = {"below": low - 1, "above": high + 1, "bool": True,
             "float": float(low), "string": str(low)}[invalid]
    with pytest.raises(ValueError, match=rf"{name} must be an integer"):
        DecisionAuditSettings.from_mapping(_audit(**{name: value}), FIELD)


@pytest.mark.parametrize("name,low,high", BOUNDS, ids=[name for name, _, _ in BOUNDS])
@pytest.mark.parametrize("edge", ["low", "high"])
def test_boundary_values_are_accepted(name, low, high, edge):
    value = low if edge == "low" else high
    changes = {name: value}
    if name == "max_input_bytes":
        changes["shard_bytes"] = min(value, DecisionAuditSettings().shard_bytes)
    if name == "page_size":
        changes["max_page_size"] = value
    if name == "max_page_size":
        changes["page_size"] = value
    settings = DecisionAuditSettings.from_mapping(_audit(**changes), FIELD)
    assert getattr(settings, name) == value


def test_page_size_cannot_exceed_the_query_ceiling():
    with pytest.raises(ValueError, match="page_size must not exceed max_page_size"):
        DecisionAuditSettings.from_mapping(_audit(page_size=51, max_page_size=50), FIELD)


def test_shards_must_fit_the_reader_input_bound():
    with pytest.raises(ValueError, match="shard_bytes must not exceed max_input_bytes"):
        DecisionAuditSettings.from_mapping(_audit(max_input_bytes=4096, shard_bytes=4097), FIELD)
