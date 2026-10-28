from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from appsec_review.jobs.job_openvex_export.contracts import AuthorKind, domain_sha256
from appsec_review.jobs.job_openvex_export.settings import OpenVexExportSettings
from tests.openvex_support import enabled_settings, settings_mapping


def test_exact_disabled_defaults_and_frozen_record() -> None:
    settings = OpenVexExportSettings.from_mapping(settings_mapping())
    assert settings == OpenVexExportSettings()
    assert settings.author_kind == AuthorKind.ORGANIZATION
    assert not settings.enabled and settings.author == settings.action_statement == settings.repository_iri == ""
    with pytest.raises(FrozenInstanceError):
        settings.enabled = True
    with pytest.raises(ValueError, match="disabled"):
        settings.require_enabled()
    enabled_settings().require_enabled()


@pytest.mark.parametrize("name", list(settings_mapping()))
def test_every_key_is_required(name: str) -> None:
    value = settings_mapping()
    del value[name]
    with pytest.raises(ValueError, match="exactly"):
        OpenVexExportSettings.from_mapping(value)


@pytest.mark.parametrize("extra", ["model", "provider", "reasoning", "status", "schema_url", "approval", "workers"])
def test_unknown_settings_are_not_authority(extra: str) -> None:
    with pytest.raises(ValueError, match="exactly"):
        OpenVexExportSettings.from_mapping(settings_mapping(**{extra: "unsafe"}))


@pytest.mark.parametrize("name", ["author", "action_statement", "repository_iri"])
def test_enabled_requires_explicit_issuer_action_repository_even_without_findings(name: str) -> None:
    value = enabled_settings().to_mapping()
    value[name] = ""
    with pytest.raises(ValueError, match=name):
        OpenVexExportSettings.from_mapping(value)


@pytest.mark.parametrize("kind", ["tool", "bot", "", "Organization", True, 1, None])
def test_author_kind_is_closed_even_when_disabled(kind: object) -> None:
    with pytest.raises(ValueError):
        OpenVexExportSettings.from_mapping(settings_mapping(author_kind=kind))


@pytest.mark.parametrize("author", ["Copilot", "GitHub Copilot", "ChatGPT", "bot", "gpt-5", "Claude agent",
                                   "Copilot App", "GitHub Actions", "dependabot[bot]"])
def test_tool_only_author_is_not_an_issuer(author: str) -> None:
    with pytest.raises(ValueError, match="issuing"):
        OpenVexExportSettings.from_mapping(settings_mapping(author=author))


@pytest.mark.parametrize("name", ["author", "role", "action_statement", "repository_iri"])
@pytest.mark.parametrize("value", [" ", "\x00", "unsafe\u202e", "\ud800", "{{author}}", "${TOKEN}",
                                 "{repository}", "%TOKEN%",
                                 "<script>alert(1)</script>", "password=secret",
                                 "https://user:pass@example.test/repo"])
def test_unsafe_nonempty_values_are_invalid_even_when_disabled(name: str, value: str) -> None:
    with pytest.raises(ValueError):
        OpenVexExportSettings.from_mapping(settings_mapping(**{name: value}))


@pytest.mark.parametrize("name", [name for name, value in settings_mapping().items() if type(value) is int])
def test_all_bounds_are_positive_closed_integers(name: str) -> None:
    defaults = settings_mapping()
    maximum = defaults[name]
    assert getattr(OpenVexExportSettings.from_mapping(defaults), name) == maximum
    low = {name: 1}
    if name == "max_total_input_bytes":
        low["max_artifact_bytes"] = 1
    assert getattr(OpenVexExportSettings.from_mapping(settings_mapping(**low)), name) == 1
    for invalid in (0, -1, maximum + 1, True, 1.0, "1", None):
        with pytest.raises(ValueError, match=name):
            OpenVexExportSettings.from_mapping(settings_mapping(**{name: invalid}))


def test_individual_input_must_fit_total_bound() -> None:
    with pytest.raises(ValueError, match="max_total_input_bytes"):
        OpenVexExportSettings.from_mapping(settings_mapping(max_artifact_bytes=2, max_total_input_bytes=1))


@pytest.mark.parametrize("enabled", [0, 1, "false", None])
def test_boolean_is_not_coerced(enabled: object) -> None:
    with pytest.raises(ValueError, match="boolean"):
        OpenVexExportSettings.from_mapping(settings_mapping(enabled=enabled))


def test_utf8_bounds_are_bytes_and_text_is_preserved_exactly() -> None:
    text = "  Restrict the test endpoint.\n\tRequire manual remediation review.  "
    settings = enabled_settings(action_statement=text, author="Issuing Person", author_kind="individual")
    assert settings.action_statement == text
    assert settings.author_kind == AuthorKind.INDIVIDUAL
    assert enabled_settings(author="OpenAI").author == "OpenAI"
    assert enabled_settings(author="é" * 1024).author == "é" * 1024
    assert enabled_settings(action_statement="é" * 4096).action_statement == "é" * 4096
    for overrides in ({"author": "é" * 1025}, {"role": "é" * 1025}, {"action_statement": "é" * 4097},
                      {"action_statement": "éé", "max_action_bytes": 3}):
        with pytest.raises(ValueError, match="UTF-8"):
            enabled_settings(**overrides)


@pytest.mark.parametrize("uri", [
    "https://example.test/repo", "https://example.test:443/repo.git", "urn:example:reviewed-system:one",
    "https://[::1]/repo", "https://example.test/a%20repo",
])
def test_explicit_absolute_allowed_repository_uris(uri: str) -> None:
    assert enabled_settings(repository_iri=uri).repository_iri == uri


@pytest.mark.parametrize("uri", [
    "http://example.test/repo", "file:///tmp/repo", "C:\\repo", "/repo", "example.test/repo", "urn:x:value",
    "https:", "https:///repo", "https://user@example.test/repo", "https://example.test/repo?token=x",
    "https://example.test/repo#main", "https://example.test/repo/tree/main", "urn:example:",
    "https://example.test/%00repo", "https://example.test/%", "https://exämple.test/repo",
    "https://example.test:0/repo", "https://example.test:99999/repo", "https://example.test/repo\\path",
])
def test_repository_is_not_a_local_path_branch_credentials_or_arbitrary_scheme(uri: str) -> None:
    with pytest.raises(ValueError):
        enabled_settings(repository_iri=uri)


def test_settings_identity_is_complete_deterministic_and_detached() -> None:
    settings = enabled_settings()
    mapping = settings.to_mapping()
    assert settings.settings_sha256() == domain_sha256("openvex-settings/1", mapping)
    assert OpenVexExportSettings.from_mapping(dict(reversed(list(mapping.items())))) == settings
    for name in mapping:
        if name == "enabled":
            changed = replace(settings, enabled=False)
        elif name == "author_kind":
            changed = replace(settings, author_kind=AuthorKind.INDIVIDUAL)
        elif type(mapping[name]) is int:
            changed = replace(settings, **{name: mapping[name] - 1})
        else:
            changed = replace(settings, **{name: mapping[name] + "x"})
        assert changed.settings_sha256() != settings.settings_sha256()
    mapping["action_statement"] = "Changed outside the record."
    assert settings.action_statement == "Disable the synthetic test endpoint."


def test_enabled_prerequisites_are_explicit_and_disabled_does_not_dispatch() -> None:
    disabled = OpenVexExportSettings()
    disabled.validate_prerequisites(gate_enabled=False, review_enabled=False)
    enabled = enabled_settings()
    enabled.validate_prerequisites(gate_enabled=True, review_enabled=True)
    for gate, review in ((False, True), (True, False), (False, False), (1, True)):
        with pytest.raises(ValueError):
            enabled.validate_prerequisites(gate_enabled=gate, review_enabled=review)
