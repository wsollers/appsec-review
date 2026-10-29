"""Selection of the configured and process-wide default container image verifier."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import threading

import pytest

from appsec_review import application_paths
from appsec_review.config import SigningConfig
from appsec_review.signing import (
    DisabledImageVerifier, EnvelopeImageVerifier, ImageSignatureVerifier, SignatureVerificationError,
)
from appsec_review.signing import policy
from appsec_review.signing.policy import (
    default_image_verifier, image_verifier_from_config, set_default_image_verifier,
)


ROOT = Path(__file__).parents[2]
OPENSSL_BINARY = "/usr/bin/openssl"
IMAGE = "sha256:" + "c3" * 32

requires_openssl = pytest.mark.skipif(
    not os.path.isfile(OPENSSL_BINARY), reason="system OpenSSL is required")


class FakeVerifier:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def verify(self, image_id: str, *, reference: str | None = None) -> None:
        self.calls.append(image_id)


@pytest.fixture(autouse=True)
def isolated_default(monkeypatch: pytest.MonkeyPatch):
    for name in ("APPSEC_REVIEW_CONFIG", "APPSEC_REVIEW_CONFIG_OVERLAY", "APPSEC_REVIEW_PROFILE"):
        monkeypatch.delenv(name, raising=False)
    set_default_image_verifier(None)
    yield
    set_default_image_verifier(None)


def _config(tmp_path: Path, table: str) -> Path:
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    start = source.index("[signing]\n")
    end = source.index("\n[", start + 1) + 1
    path = tmp_path / "config" / "appsec-review.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source[:start] + table + "\n" + source[end:], encoding="utf-8")
    return path


@requires_openssl
def test_required_enforcement_builds_an_envelope_verifier(tmp_path: Path) -> None:
    signing = SigningConfig(trusted_keys_dir=tmp_path / "keys", image_signatures_dir=tmp_path / "sigs")
    verifier = image_verifier_from_config(signing)

    assert isinstance(verifier, EnvelopeImageVerifier)
    assert isinstance(verifier, ImageSignatureVerifier)
    assert verifier.enforced is True
    assert verifier.trusted_keys_dir == tmp_path / "keys"
    assert verifier.signatures_dir == tmp_path / "sigs"
    assert verifier.openssl.binary == OPENSSL_BINARY
    with pytest.raises(SignatureVerificationError):
        verifier.verify(IMAGE)


def test_only_explicit_disabled_enforcement_builds_the_disabled_verifier() -> None:
    verifier = image_verifier_from_config(SigningConfig(image_enforcement="disabled",
                                                        openssl=Path("/nonexistent/openssl")))

    assert isinstance(verifier, DisabledImageVerifier)
    assert verifier.enforced is False


def test_required_enforcement_fails_closed_without_openssl(tmp_path: Path) -> None:
    with pytest.raises(SignatureVerificationError, match="OpenSSL binary is not an executable file"):
        image_verifier_from_config(SigningConfig(openssl=tmp_path / "missing-openssl"))


def test_factory_requires_typed_configuration() -> None:
    with pytest.raises(SignatureVerificationError, match="typed SigningConfig"):
        image_verifier_from_config({"image_enforcement": "disabled"})  # type: ignore[arg-type]


@requires_openssl
def test_default_resolves_from_the_configured_file_once(tmp_path: Path, monkeypatch) -> None:
    path = _config(tmp_path, '[signing]\ntrusted_keys_dir = "trust"\nimage_signatures_dir = "images"\n')
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG", str(path))

    verifier = default_image_verifier()

    assert isinstance(verifier, EnvelopeImageVerifier)
    assert verifier.trusted_keys_dir == (path.parent / "trust").resolve()
    assert verifier.signatures_dir == (path.parent / "images").resolve()
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG", str(tmp_path / "missing.toml"))
    assert default_image_verifier() is verifier


def test_default_honors_explicitly_disabled_configuration(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG",
                       str(_config(tmp_path, '[signing]\nimage_enforcement = "disabled"\n')))

    assert isinstance(default_image_verifier(), DisabledImageVerifier)


@requires_openssl
def test_default_without_environment_uses_the_application_root_configuration() -> None:
    verifier = default_image_verifier()

    assert isinstance(verifier, EnvelopeImageVerifier)
    assert verifier.trusted_keys_dir == SigningConfig().trusted_keys_dir
    assert verifier.signatures_dir == SigningConfig().image_signatures_dir


def test_override_wins_and_reset_restores_resolution(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG", str(tmp_path / "missing.toml"))
    fake = FakeVerifier()

    set_default_image_verifier(fake)
    assert default_image_verifier() is fake
    default_image_verifier().verify(IMAGE)
    assert fake.calls == [IMAGE]

    set_default_image_verifier(None)
    with pytest.raises(SignatureVerificationError, match="application configuration cannot be loaded"):
        default_image_verifier()


def test_reset_clears_the_cached_default(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG",
                       str(_config(tmp_path / "a", '[signing]\nimage_enforcement = "disabled"\n')))
    first = default_image_verifier()
    set_default_image_verifier(None)

    assert default_image_verifier() is not first


def test_override_must_be_a_verifier() -> None:
    with pytest.raises(TypeError):
        set_default_image_verifier(object())  # type: ignore[arg-type]


def test_default_fails_closed_when_configuration_is_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG", str(tmp_path / "missing.toml"))

    with pytest.raises(SignatureVerificationError, match="application configuration cannot be loaded"):
        default_image_verifier()
    # Nothing was cached: a later valid configuration resolves.
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG",
                       str(_config(tmp_path, '[signing]\nimage_enforcement = "disabled"\n')))
    assert isinstance(default_image_verifier(), DisabledImageVerifier)


def test_default_fails_closed_when_configuration_is_invalid(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG",
                       str(_config(tmp_path, '[signing]\nimage_enforcement = "off"\n')))

    with pytest.raises(SignatureVerificationError, match="image_enforcement"):
        default_image_verifier()


def test_default_fails_closed_when_the_application_root_has_no_configuration(monkeypatch) -> None:
    def unavailable(relative):
        raise FileNotFoundError(f"application file is unavailable: {relative}")

    monkeypatch.setattr(application_paths, "application_asset", unavailable)

    with pytest.raises(SignatureVerificationError, match="application file is unavailable"):
        default_image_verifier()


def test_default_fails_closed_when_the_configured_verifier_cannot_be_built(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG", str(_config(
        tmp_path, f'[signing]\nopenssl = "{tmp_path / "missing-openssl"}"\n')))

    with pytest.raises(SignatureVerificationError, match="OpenSSL binary is not an executable file"):
        default_image_verifier()


def test_concurrent_first_use_resolves_once(monkeypatch) -> None:
    loads = 0
    gate = threading.Barrier(8)

    def load() -> FakeVerifier:
        nonlocal loads
        loads += 1
        return FakeVerifier()

    monkeypatch.setattr(policy, "_load_default", load)

    def resolve(_: int) -> ImageSignatureVerifier:
        gate.wait()
        return default_image_verifier()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(resolve, range(8)))

    assert loads == 1
    assert all(result is results[0] for result in results)
