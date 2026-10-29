"""Typed ``[signing]`` configuration: trust anchors, image signatures and image enforcement.

Private keys never appear here or anywhere in the repository. ``trusted_keys_dir`` holds root-owned
public-key PEM trust anchors named ``<key_id hex>.pem``; ``image_signatures_dir`` holds container
image envelopes named ``<image id hex>.json``. A missing table means the defaults below, including
``image_enforcement = "required"``; enforcement is never disabled implicitly.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


DEFAULT_OPENSSL = "/usr/bin/openssl"
DEFAULT_TRUSTED_KEYS_DIR = "/etc/appsec-review/signing/trusted-keys"
DEFAULT_IMAGE_SIGNATURES_DIR = "/var/lib/appsec-review/signing/images"
IMAGE_ENFORCEMENT_REQUIRED = "required"
IMAGE_ENFORCEMENT_DISABLED = "disabled"
IMAGE_ENFORCEMENTS: tuple[str, ...] = (IMAGE_ENFORCEMENT_REQUIRED, IMAGE_ENFORCEMENT_DISABLED)
_KEYS = frozenset({"openssl", "trusted_keys_dir", "image_signatures_dir", "image_enforcement"})


def _absolute(value: object, field: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        raise ValueError(f"signing.{field} must be an absolute path")
    return value


@dataclass(frozen=True, slots=True)
class SigningConfig:
    openssl: Path = Path(DEFAULT_OPENSSL)
    trusted_keys_dir: Path = Path(DEFAULT_TRUSTED_KEYS_DIR)
    image_signatures_dir: Path = Path(DEFAULT_IMAGE_SIGNATURES_DIR)
    image_enforcement: str = IMAGE_ENFORCEMENT_REQUIRED

    def __post_init__(self) -> None:
        for name in ("openssl", "trusted_keys_dir", "image_signatures_dir"):
            _absolute(getattr(self, name), name)
        if self.image_enforcement not in IMAGE_ENFORCEMENTS:
            raise ValueError("signing.image_enforcement must be one of: " + ", ".join(IMAGE_ENFORCEMENTS))

    @property
    def image_enforced(self) -> bool:
        return self.image_enforcement == IMAGE_ENFORCEMENT_REQUIRED

    def view(self) -> dict[str, str]:
        return {"openssl": str(self.openssl), "trusted_keys_dir": str(self.trusted_keys_dir),
                "image_signatures_dir": str(self.image_signatures_dir),
                "image_enforcement": self.image_enforcement}


def _path_value(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"signing.{field} must be a non-empty path string")
    return value


def parse_signing(value: object, repository_root: Path) -> SigningConfig:
    """Parse ``[signing]``; relative directories resolve against the configuration file's directory.

    ``openssl`` must be absolute: the verifier is an OS-owned binary, never one found relative to a
    checkout. Unknown keys and wrong types are rejected by name.
    """
    if value is None:
        return SigningConfig()
    if not isinstance(value, Mapping):
        raise ValueError("[signing] must be a table")
    unknown = set(value) - _KEYS
    if unknown:
        raise ValueError("unknown signing settings: " + ", ".join(sorted(map(str, unknown))))
    settings: dict[str, Any] = {}
    if "openssl" in value:
        openssl = Path(_path_value(value["openssl"], "openssl"))
        if not openssl.is_absolute() or ".." in openssl.parts:
            raise ValueError("signing.openssl must be an absolute path")
        settings["openssl"] = openssl
    for name in ("trusted_keys_dir", "image_signatures_dir"):
        if name in value:
            candidate = Path(_path_value(value[name], name))
            settings[name] = (candidate if candidate.is_absolute() else repository_root / candidate).resolve()
    if "image_enforcement" in value:
        enforcement = value["image_enforcement"]
        if not isinstance(enforcement, str) or enforcement not in IMAGE_ENFORCEMENTS:
            raise ValueError("signing.image_enforcement must be one of: " + ", ".join(IMAGE_ENFORCEMENTS))
        settings["image_enforcement"] = enforcement
    return SigningConfig(**settings)


__all__ = [
    "DEFAULT_IMAGE_SIGNATURES_DIR", "DEFAULT_OPENSSL", "DEFAULT_TRUSTED_KEYS_DIR",
    "IMAGE_ENFORCEMENTS", "IMAGE_ENFORCEMENT_DISABLED", "IMAGE_ENFORCEMENT_REQUIRED",
    "SigningConfig", "parse_signing",
]
