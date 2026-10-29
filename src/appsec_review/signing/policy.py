"""Select the process-wide container image verifier from the typed ``[signing]`` configuration.

Unlike ``.core`` and ``.images`` this module loads application configuration, so it is not
re-exported from ``appsec_review.signing`` (whose modules stay standard-library only).
"""
from __future__ import annotations

import os
from pathlib import Path
import threading

from appsec_review.config.signing import SigningConfig

from .core import OpenSSL, SignatureVerificationError
from .images import DisabledImageVerifier, EnvelopeImageVerifier, ImageSignatureVerifier


CONFIG_ENVIRONMENT = "APPSEC_REVIEW_CONFIG"
CONFIG_FILE = "appsec-review.toml"

_lock = threading.Lock()
_override: ImageSignatureVerifier | None = None
_default: ImageSignatureVerifier | None = None


def image_verifier_from_config(signing: SigningConfig) -> ImageSignatureVerifier:
    """Build the verifier ``signing`` selects; only an explicit ``"disabled"`` skips verification.

    Raises SignatureVerificationError when enforcement is required and the OpenSSL binary is not an
    absolute executable file.
    """
    if not isinstance(signing, SigningConfig):
        raise SignatureVerificationError("image verifier requires a typed SigningConfig")
    if not signing.image_enforced:
        return DisabledImageVerifier()
    return EnvelopeImageVerifier(signatures_dir=signing.image_signatures_dir,
                                 trusted_keys_dir=signing.trusted_keys_dir,
                                 openssl=OpenSSL(str(signing.openssl)))


def _configuration_path() -> Path:
    configured = os.environ.get(CONFIG_ENVIRONMENT)
    if configured:
        return Path(configured)
    from appsec_review.application_paths import application_asset
    return application_asset(CONFIG_FILE)


def _load_default() -> ImageSignatureVerifier:
    from appsec_review.config import load_config
    try:
        path = _configuration_path()
        signing = load_config(path).signing
    except SignatureVerificationError:
        raise
    except Exception as error:
        raise SignatureVerificationError(
            f"image signature policy is unavailable: application configuration cannot be loaded: {error}"
        ) from error
    return image_verifier_from_config(signing)


def default_image_verifier() -> ImageSignatureVerifier:
    """Return the process-wide image verifier, resolving it once on first use.

    Resolution order:

    1. A verifier installed with ``set_default_image_verifier`` (tests and entry points).
    2. The cached verifier from an earlier successful resolution.
    3. ``[signing]`` of the application configuration, located the way jobs locate it: the path in
       ``APPSEC_REVIEW_CONFIG`` when set and non-empty, otherwise ``appsec-review.toml`` at the
       application root (``application_paths.application_asset``: the source checkout's root).
       It is loaded with ``load_config``, so ``APPSEC_REVIEW_PROFILE`` and
       ``APPSEC_REVIEW_CONFIG_OVERLAY`` apply as usual; neither layer may set ``[signing]``.

    Fails closed: if the configuration cannot be located, read or validated, or the configured
    verifier cannot be constructed, SignatureVerificationError is raised and nothing is cached, so
    verification is never silently disabled. Only ``image_enforcement = "disabled"`` disables it.
    """
    global _default
    with _lock:
        if _override is not None:
            return _override
        if _default is None:
            _default = _load_default()
        return _default


def set_default_image_verifier(verifier: ImageSignatureVerifier | None) -> None:
    """Install ``verifier`` as the process-wide default, or with ``None`` clear any override and cache."""
    global _override, _default
    if verifier is not None and not isinstance(verifier, ImageSignatureVerifier):
        raise TypeError("default image verifier must implement ImageSignatureVerifier")
    with _lock:
        _override = verifier
        if verifier is None:
            _default = None


__all__ = ["CONFIG_ENVIRONMENT", "default_image_verifier", "image_verifier_from_config",
           "set_default_image_verifier"]
