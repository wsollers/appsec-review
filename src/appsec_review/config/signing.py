"""Typed ``[signing]`` configuration: trust anchors, image signatures and image enforcement.

Private keys never appear here or anywhere in the repository. ``trusted_keys_dir`` holds root-owned
public-key PEM trust anchors named ``<key_id hex>.pem``; ``image_signatures_dir`` holds container
image envelopes named ``<image id hex>.json``. A missing table means the defaults below, including
``image_enforcement = "required"``; enforcement is never disabled implicitly.

On a native Windows host the POSIX defaults are replaced by host defaults, both when the table is
missing and when it names exactly a POSIX default (as the repository ``appsec-review.toml`` does):
the Git for Windows OpenSSL and ``%ProgramData%\\appsec-review\\signing\\{trusted-keys,images}``.
Any other drive-less ``/rooted`` path is rejected there.
"""
from __future__ import annotations

from dataclasses import dataclass, field as _field
import ntpath
import os
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping

from appsec_review.signing import core as _core


DEFAULT_OPENSSL = "/usr/bin/openssl"
DEFAULT_TRUSTED_KEYS_DIR = "/etc/appsec-review/signing/trusted-keys"
DEFAULT_IMAGE_SIGNATURES_DIR = "/var/lib/appsec-review/signing/images"
IMAGE_ENFORCEMENT_REQUIRED = "required"
IMAGE_ENFORCEMENT_DISABLED = "disabled"
IMAGE_ENFORCEMENTS: tuple[str, ...] = (IMAGE_ENFORCEMENT_REQUIRED, IMAGE_ENFORCEMENT_DISABLED)
_KEYS = frozenset({"openssl", "trusted_keys_dir", "image_signatures_dir", "image_enforcement"})


def _windows_data_dir(leaf: str) -> str:
    program_data = os.environ.get("ProgramData") or r"C:\ProgramData"
    return ntpath.join(program_data, "appsec-review", "signing", leaf)


def host_default(field_name: str) -> str:
    """The host default for ``openssl``, ``trusted_keys_dir`` or ``image_signatures_dir``."""
    if field_name == "openssl":
        return _core.default_openssl()
    posix = {"trusted_keys_dir": DEFAULT_TRUSTED_KEYS_DIR, "image_signatures_dir": DEFAULT_IMAGE_SIGNATURES_DIR}
    if not _core.windows_host():
        return posix[field_name]
    return _windows_data_dir({"trusted_keys_dir": "trusted-keys", "image_signatures_dir": "images"}[field_name])


_POSIX_DEFAULTS = {"openssl": DEFAULT_OPENSSL, "trusted_keys_dir": DEFAULT_TRUSTED_KEYS_DIR,
                   "image_signatures_dir": DEFAULT_IMAGE_SIGNATURES_DIR}


def _absolute(value: object, field: str) -> Path:
    if not isinstance(value, Path) or not _core.is_absolute_path(str(value)):
        raise ValueError(f"signing.{field} must be an absolute path")
    return value


@dataclass(frozen=True, slots=True)
class SigningConfig:
    openssl: Path = _field(default_factory=lambda: Path(host_default("openssl")))
    trusted_keys_dir: Path = _field(default_factory=lambda: Path(host_default("trusted_keys_dir")))
    image_signatures_dir: Path = _field(default_factory=lambda: Path(host_default("image_signatures_dir")))
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


def _host_path(text: str, field_name: str) -> str:
    """On Windows map an exact POSIX default to the host default and refuse other drive-less roots."""
    if not _core.windows_host():
        return text
    if text == _POSIX_DEFAULTS[field_name]:
        return host_default(field_name)
    windows = PureWindowsPath(text)
    if windows.root and not windows.drive:
        raise ValueError(f"signing.{field_name} must be an absolute path with a drive on Windows: {text}")
    return text


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
        text = _host_path(_path_value(value["openssl"], "openssl"), "openssl")
        parts = PureWindowsPath(text).parts if _core.windows_host() else Path(text).parts
        if not _core.is_absolute_path(text) or ".." in parts:
            raise ValueError("signing.openssl must be an absolute path")
        settings["openssl"] = Path(text)
    for name in ("trusted_keys_dir", "image_signatures_dir"):
        if name in value:
            text = _host_path(_path_value(value[name], name), name)
            candidate = Path(text)
            settings[name] = (candidate if _core.is_absolute_path(text) else repository_root / candidate).resolve()
    if "image_enforcement" in value:
        enforcement = value["image_enforcement"]
        if not isinstance(enforcement, str) or enforcement not in IMAGE_ENFORCEMENTS:
            raise ValueError("signing.image_enforcement must be one of: " + ", ".join(IMAGE_ENFORCEMENTS))
        settings["image_enforcement"] = enforcement
    return SigningConfig(**settings)


__all__ = [
    "DEFAULT_IMAGE_SIGNATURES_DIR", "DEFAULT_OPENSSL", "DEFAULT_TRUSTED_KEYS_DIR",
    "IMAGE_ENFORCEMENTS", "IMAGE_ENFORCEMENT_DISABLED", "IMAGE_ENFORCEMENT_REQUIRED",
    "SigningConfig", "host_default", "parse_signing",
]
