from copy import deepcopy

import pytest

from appsec_review.config.owasp import parse_settings


@pytest.fixture
def configured():
    model = {"enabled": False, "provider": "fixture", "model": "fixture", "reasoning": "low",
             "max_input_tokens": 1000, "max_output_tokens": 500, "timeout_seconds": 2, "retries": 0}
    return {"enabled": True, "mode": "qualification", "reviewer_profile": "reviewer",
            "max_evidence_per_component": 60, "max_source_lines": 120, "max_subjects_per_control": 8,
            "max_batches": 10, "max_turns": 4, "max_queries": 8, "asvs_level": 1, "masvs_profile": "L1",
            "max_batch_size": 4, "max_components_per_batch": 2, "max_components": 10,
            "dynamic_authorized": False, "model": model, "models": {"reviewer": deepcopy(model)},
            "standards": {}, "parser_versions": {}}


def test_new_defaults_preserve_positional_callers(settings, configured):
    parsed = parse_settings(configured)
    assert (settings.max_discovery_files, settings.max_discovery_bytes) == (512, 8_388_608)
    assert parsed.max_discovery_files == 512 and parsed.max_discovery_bytes == 8_388_608


@pytest.mark.parametrize("key,maximum", [("max_discovery_files", 4096), ("max_discovery_bytes", 16_777_216)])
@pytest.mark.parametrize("value", [1, "maximum"])
def test_optional_limits_accept_exact_integer_boundaries(configured, key, maximum, value):
    value = maximum if value == "maximum" else value
    configured[key] = value
    assert getattr(parse_settings(configured), key) == value


@pytest.mark.parametrize("key", ["max_discovery_files", "max_discovery_bytes"])
@pytest.mark.parametrize("value", [True, 0, -1, 1.5, "512", None, 16_777_217])
def test_optional_limits_reject_untyped_or_unbounded_values(configured, key, value):
    configured[key] = value
    with pytest.raises(ValueError, match=key):
        parse_settings(configured)


@pytest.mark.parametrize("change", ["unknown", "missing"])
def test_optional_additions_do_not_open_configuration_shape(configured, change):
    if change == "unknown":
        configured["discover_everything"] = True
    else:
        del configured["max_queries"]
    with pytest.raises(ValueError, match="settings missing="):
        parse_settings(configured)
