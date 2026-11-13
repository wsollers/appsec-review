"""Pre-walk code-level configuration and selection claims, retained without graph execution."""

import json
from pathlib import Path
import re
import tomllib

import pytest

from appsec_review.cli import GRAPH_JOB_IDS
from appsec_review.config import load_config, parse_image_pin_verification_settings
from appsec_review.jobs.job_image_pin_verification.pins import configured_pins
from appsec_review.runtime import active_job_ids


ROOT = Path(__file__).parents[3]
JOB_ID = "job_image_pin_verification"
SECTION = f"[jobs.{JOB_ID}.settings]"


def _settings_source(**overrides: str) -> str:
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    head, rest = source.split(SECTION + "\n", 1)
    body, tail = rest.split("\n[", 1)
    for key, value in overrides.items():
        body, count = re.subn(rf"(?m)^{key} = .*$", f"{key} = {value}", body)
        if count == 0:
            body += f"\n{key} = {value}"
    return head + SECTION + "\n" + body + "\n[" + tail


def test_repository_pins_cover_catalog_images_build_profiles_and_codeql_source() -> None:
    document = json.loads(load_config(ROOT / "appsec-review.toml").resolved_json)
    catalog = tomllib.loads((ROOT / "containers" / "catalog.toml").read_text(encoding="utf-8"))["images"]
    sources = {pin["source"] for pin in configured_pins(catalog, document)}
    enabled = {item["id"] for item in catalog if item.get("state") == "enabled" and not item.get("manual")}
    assert {f"containers/catalog.toml images.{image}.image_id" for image in enabled} <= sources
    assert not any(".tool-report-latex." in source for source in sources)
    profiles = document["jobs"]["job_project_build"]["settings"]["profiles"]
    assert {f"jobs.job_project_build.settings.profiles.{name}.image_id" for name in profiles} <= sources
    assert "jobs.job_codeql_analysis.settings.source_image_id" in sources


def test_configured_pins_cover_enabled_catalog_images_and_enabled_job_settings_only() -> None:
    document = {"jobs": {
        "job_project_build": {"settings": {"profiles": {"native": {
            "tag": "audit-buildenv-cpp:local", "image_id": "sha256:" + "a" * 64, "user": "10001:10001"}}}},
        "job_codeql_analysis": {"settings": {"source_image_tag": "audit-codeql:x",
                                             "source_image_id": "sha256:" + "b" * 64}},
        "job_off": {"settings": {"enabled": False, "tag": "t", "image_id": "sha256:" + "c" * 64}},
    }}
    catalog = [{"id": "tool-x", "state": "enabled", "tag": "fixture/tool-x:1", "image_id": "sha256:" + "d" * 64},
               {"id": "tool-y", "state": "enabled", "tag": "fixture/tool-y:1"},
               {"id": "tool-z", "state": "deferred", "tag": "fixture/tool-z:1"},
               {"id": "tool-m", "state": "enabled", "manual": True, "tag": "fixture/tool-m:1"}]
    pins = configured_pins(catalog, document)
    assert [(pin["source"], pin["tag"], pin["image_id"]) for pin in pins] == [
        ("containers/catalog.toml images.tool-x.image_id", "fixture/tool-x:1", "sha256:" + "d" * 64),
        ("containers/catalog.toml images.tool-y.image_id", "fixture/tool-y:1", None),
        ("jobs.job_codeql_analysis.settings.source_image_id", "audit-codeql:x", "sha256:" + "b" * 64),
        ("jobs.job_project_build.settings.profiles.native.image_id", "audit-buildenv-cpp:local",
         "sha256:" + "a" * 64),
    ]


def test_repository_settings_are_typed_and_enabled_by_default() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    settings = config.job(JOB_ID).typed_settings
    assert settings == parse_image_pin_verification_settings(config.job(JOB_ID).settings)
    assert settings.enabled is True


@pytest.mark.parametrize("key, value, message", [
    ("enabled", '"yes"', "enabled must be a boolean"),
    ("unexpected", "1", "unknown settings: unexpected"),
    ("parallelism", "2", "unknown settings: parallelism"),
    ("pin_mismatch", '"report"', "unknown settings: pin_mismatch"),
], ids=["enabled", "unexpected", "parallelism", "pin-mismatch"])
def test_settings_validation_rejects_bad_values(tmp_path: Path, key: str, value: str, message: str) -> None:
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(_settings_source(**{key: value}), encoding="utf-8")
    with pytest.raises(ValueError, match=re.escape(message)):
        load_config(config_path)


def test_settings_validation_rejects_a_missing_switch() -> None:
    with pytest.raises(ValueError, match="missing settings: enabled"):
        parse_image_pin_verification_settings({})


def test_direct_graph_places_the_gate_between_the_model_gate_and_intake(tmp_path: Path) -> None:
    order = list(GRAPH_JOB_IDS)
    assert order.index("job_model_connectivity") + 1 == order.index(JOB_ID)
    assert order.index(JOB_ID) + 1 == order.index("job_target_acquisition")
    assert order.index("job_target_acquisition") + 1 == order.index("job_review_intake")
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(_settings_source(enabled="false"), encoding="utf-8")
    selected = active_job_ids(load_config(config_path), GRAPH_JOB_IDS)
    assert JOB_ID not in selected
    assert selected[:3] == ("job_model_connectivity", "job_target_acquisition", "job_review_intake")
