"""Typed ``[signing]`` configuration: defaults, strict keys and types, and path resolution."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from appsec_review.config import SigningConfig, load_config, parse_signing
from appsec_review.config.loader import overlay_capacity_keys, profile_override_keys
from appsec_review.config.signing import host_default


ROOT = Path(__file__).parents[1]


def _variant(tmp_path: Path, table: str) -> Path:
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    start = source.index("[signing]\n")
    end = source.index("\n[", start + 1) + 1
    path = tmp_path / "config" / "appsec-review.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source[:start] + table + "\n" + source[end:], encoding="utf-8")
    return path


def test_repository_config_requires_image_signatures_with_documented_defaults() -> None:
    config = load_config(ROOT / "appsec-review.toml")

    assert config.signing == SigningConfig()
    for field in ("openssl", "trusted_keys_dir", "image_signatures_dir"):
        assert getattr(config.signing, field) == Path(host_default(field))
    if os.name != "nt":
        assert config.signing.openssl == Path("/usr/bin/openssl")
        assert config.signing.trusted_keys_dir == Path("/etc/appsec-review/signing/trusted-keys")
        assert config.signing.image_signatures_dir == Path("/var/lib/appsec-review/signing/images")
    assert config.signing.image_enforcement == "required"
    assert config.signing.image_enforced is True
    assert json.loads(config.resolved_json)["signing"] == config.signing.view()


def test_missing_or_empty_table_uses_required_defaults(tmp_path: Path) -> None:
    assert parse_signing(None, tmp_path) == SigningConfig()
    assert parse_signing({}, tmp_path) == SigningConfig()
    assert load_config(_variant(tmp_path, "")).signing == SigningConfig()


def test_relative_directories_resolve_against_the_configuration_directory(tmp_path: Path) -> None:
    path = _variant(tmp_path, '[signing]\ntrusted_keys_dir = "keys/trusted"\n'
                              'image_signatures_dir = "../signatures"\nimage_enforcement = "disabled"\n')
    signing = load_config(path).signing

    assert signing.trusted_keys_dir == (path.parent / "keys" / "trusted").resolve()
    assert signing.image_signatures_dir == (tmp_path / "signatures").resolve()
    assert signing.image_enforcement == "disabled"
    assert signing.image_enforced is False


def test_absolute_directories_are_kept(tmp_path: Path) -> None:
    signatures = str(tmp_path / "sigs") if os.name == "nt" else "/srv/signatures"
    signing = parse_signing({"trusted_keys_dir": str(tmp_path / "keys"),
                             "image_signatures_dir": signatures}, Path("/unused"))

    assert signing.trusted_keys_dir == (tmp_path / "keys").resolve()
    assert signing.image_signatures_dir == Path(signatures)


def test_unknown_keys_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown signing settings: private_key"):
        load_config(_variant(tmp_path, '[signing]\nprivate_key = "/home/me/key.pem"\n'))


@pytest.mark.parametrize("value", ['"optional"', '"Required"', '""', "true", "1"])
def test_bad_enforcement_values_are_rejected(tmp_path: Path, value: str) -> None:
    with pytest.raises(ValueError, match="signing.image_enforcement must be one of: required, disabled"):
        load_config(_variant(tmp_path, f"[signing]\nimage_enforcement = {value}\n"))


@pytest.mark.parametrize("value", ['"openssl"', '"bin/openssl"', '"/usr/../usr/bin/openssl"'])
def test_openssl_must_be_absolute(value: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="signing.openssl must be an absolute path"):
        load_config(_variant(tmp_path, f"[signing]\nopenssl = {value}\n"))


@pytest.mark.parametrize(("key", "value"), [
    ("openssl", 5), ("trusted_keys_dir", ""), ("image_signatures_dir", ["a"]), ("trusted_keys_dir", "   "),
])
def test_path_types_are_validated(key: str, value: object, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=f"signing.{key} must be a non-empty path string"):
        parse_signing({key: value}, tmp_path)


def test_table_must_be_a_table(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"\[signing\] must be a table"):
        parse_signing("required", tmp_path)


def test_dataclass_is_frozen_slotted_and_validates_direct_construction() -> None:
    signing = SigningConfig()
    with pytest.raises(AttributeError):
        signing.image_enforcement = "disabled"  # type: ignore[misc]
    assert not hasattr(signing, "__dict__")
    with pytest.raises(ValueError, match="absolute path"):
        SigningConfig(trusted_keys_dir=Path("relative"))
    with pytest.raises(ValueError, match="image_enforcement"):
        SigningConfig(image_enforcement="off")


def test_profiles_and_overlays_cannot_change_signing() -> None:
    with pytest.raises(ValueError, match="rejected: signing"):
        overlay_capacity_keys({"signing": {"image_enforcement": "disabled"}})
    with pytest.raises(ValueError, match="rejected: signing"):
        profile_override_keys({"signing": {"image_enforcement": "disabled"}})
