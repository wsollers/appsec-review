"""Retained pre-walk host-configuration checks; graph freezing scenarios live in integration."""

import re
import shutil

import pytest

from appsec_review.config import load_config
from appsec_review.config.host_pins import HOST_PINS_PATH, parse_host_pins, serialize_host_pins
from tests.host_pins_support import ROOT, fixture_bindings, write_host_pins


def fixture(tmp_path):
    config = tmp_path / "appsec-review.toml"
    shutil.copyfile(ROOT / "appsec-review.toml", config)
    catalog = tmp_path / "containers/catalog.toml"
    catalog.parent.mkdir()
    shutil.copyfile(ROOT / "containers/catalog.toml", catalog)
    host = write_host_pins(tmp_path / HOST_PINS_PATH)
    target = tmp_path / "target"
    target.mkdir()
    (target / "sample.py").write_text("print('fixture')\n")
    return config, host, target


def test_missing_host_file_is_an_explicit_configuration_failure(tmp_path):
    with pytest.raises(ValueError, match="host pins are missing.*update-image-pins"):
        load_config(ROOT / "appsec-review.toml", host_pins=tmp_path / "missing.toml")


def test_signing_bootstrap_reads_policy_without_requiring_host_inventory(tmp_path, monkeypatch):
    from appsec_review.config.host_pins import HOST_PINS_ENV
    from appsec_review.signing.cli import load_signing_config
    monkeypatch.setenv(HOST_PINS_ENV, str(tmp_path / "missing.toml"))
    signing = load_signing_config(ROOT / "appsec-review.toml")
    assert signing.runtime.repository_root == ROOT
    assert signing.signing.image_enforcement == "disabled"


@pytest.mark.parametrize(("change", "message"), [
    ("image", "invalid host image binding:"),
    ("runtime", "CodeQL preinstalled runtime fields differ from the closed contract"),
    ("schema", "unsupported host-pins schema"),
    ("unknown", "host pins require exactly schema, images and preinstalled_runtimes"),
], ids=["image", "runtime", "schema", "unknown"])
def test_host_schema_is_closed_and_validates_ids_and_declarations(change, message):
    content = serialize_host_pins(fixture_bindings(), [])
    if change == "unknown":
        content = b"unexpected = true\n" + content
    elif change == "schema":
        content = content.replace(b"host-pins/1", b"host-pins/0")
    elif change == "image":
        content = content.replace(b"sha256:", b"tag:", 1)
    else:
        content = content.replace(b"preinstalled_runtimes = []", b'preinstalled_runtimes = [{}]')
    with pytest.raises(ValueError, match=re.escape(message)):
        parse_host_pins(content)


def test_missing_declared_tag_is_not_filled_from_another_host(tmp_path):
    config, host, _ = fixture(tmp_path)
    images = fixture_bindings()
    del images["audit-codeql:custom-2.27.0"]
    write_host_pins(host, images=images)
    with pytest.raises(ValueError, match="no binding.*source_image_id"):
        load_config(config, host_pins=host)


def test_tracked_catalog_carries_no_observed_image_ids() -> None:
    """Observed Docker ids are host-local (T-051), never tracked recipes."""
    from appsec_review.container_runtime.catalog import load_catalog
    catalog = load_catalog(ROOT)
    assert catalog.tools, "the catalog declares tools"
    with_ids = sorted(name for name in catalog.tools if catalog.tool(name).expected_image_id is not None)
    assert with_ids == [], f"tracked recipes must not carry observed image ids: {with_ids}"
    assert "image_id" not in (ROOT / "containers/catalog.toml").read_text(encoding="utf-8")
