"""Sign and verify the Dagster image and its Python package on the host before Compose starts it.

Every step runs the repository's ``appsec-review signing`` CLI through an injected ``runner`` (by
default :func:`subprocess.run`) and accepts only its JSON report. Any failure raises
:class:`SigningError`; nothing here falls back to an unsigned or unverified image.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import ntpath
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Callable, Mapping


IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
DEFAULT_PRIVATE_KEY = "~/.config/appsec-review/signing/private/operator.pem"
DEFAULT_TRUSTED_KEYS_DIR = "/etc/appsec-review/signing/trusted-keys"
DEFAULT_IMAGE_SIGNATURES_DIR = "/var/lib/appsec-review/signing/images"
DEFAULT_OPENSSL = "/usr/bin/openssl"
WINDOWS_OPENSSL = r"C:\Program Files\Git\mingw64\bin\openssl.exe"
# Written on the host before the image build and copied into the final image stages; never committed.
MODULE_ENVELOPE = Path("deploy") / "dagster" / "signing" / "python-modules.json"
PACKAGE_ROOT = Path("src") / "appsec_review"

Runner = Callable[..., subprocess.CompletedProcess]


def host_defaults(windows: bool | None = None) -> dict[str, str]:
    r"""``APPSEC_SIGNING_*`` path defaults for this host: POSIX paths, or Git for Windows OpenSSL and
    ``%ProgramData%\appsec-review\signing\{trusted-keys,images}`` on native Windows."""
    if not (os.name == "nt" if windows is None else windows):
        return {"APPSEC_SIGNING_TRUSTED_KEYS_DIR": DEFAULT_TRUSTED_KEYS_DIR,
                "APPSEC_SIGNING_IMAGE_SIGNATURES_DIR": DEFAULT_IMAGE_SIGNATURES_DIR,
                "APPSEC_SIGNING_OPENSSL": DEFAULT_OPENSSL}
    signing = ntpath.join(os.environ.get("ProgramData") or r"C:\ProgramData", "appsec-review", "signing")
    openssl = next((candidate for candidate in (
        ntpath.join(root, "Git", "mingw64", "bin", "openssl.exe")
        for root in (os.environ.get("ProgramW6432"), os.environ.get("ProgramFiles")) if root)
        if os.path.isfile(candidate)), WINDOWS_OPENSSL)
    return {"APPSEC_SIGNING_TRUSTED_KEYS_DIR": ntpath.join(signing, "trusted-keys"),
            "APPSEC_SIGNING_IMAGE_SIGNATURES_DIR": ntpath.join(signing, "images"),
            "APPSEC_SIGNING_OPENSSL": openssl}


class SigningError(RuntimeError):
    """A signing or verification step failed; the caller must not build on or launch the image."""


@dataclass(frozen=True)
class SigningSettings:
    python: str
    private_key: Path
    trusted_keys_dir: Path
    image_signatures_dir: Path
    openssl: Path

    @classmethod
    def load(cls, values: Mapping[str, str], *, windows: bool | None = None) -> "SigningSettings":
        """Read ``APPSEC_SIGNING_*`` from ``values`` (the process environment over ``.env``).

        Unset paths take :func:`host_defaults`; a value that is set is always used as given.
        """
        defaults = host_defaults(windows)

        def get(name: str, default: str | None = None) -> str:
            return values.get(name) or (defaults[name] if default is None else default)
        return cls(python=get("APPSEC_SIGNING_PYTHON", sys.executable),
                   private_key=Path(get("APPSEC_SIGNING_PRIVATE_KEY", DEFAULT_PRIVATE_KEY)).expanduser(),
                   trusted_keys_dir=Path(get("APPSEC_SIGNING_TRUSTED_KEYS_DIR")),
                   image_signatures_dir=Path(get("APPSEC_SIGNING_IMAGE_SIGNATURES_DIR")),
                   openssl=Path(get("APPSEC_SIGNING_OPENSSL")))

    def compose_environment(self) -> dict[str, str]:
        """The bind-mount sources Compose interpolates, set to the directories verification used."""
        return {"APPSEC_SIGNING_TRUSTED_KEYS_DIR": str(self.trusted_keys_dir),
                "APPSEC_SIGNING_IMAGE_SIGNATURES_DIR": str(self.image_signatures_dir)}


def signing_cli(settings: SigningSettings, repository: Path, arguments: list[str], *,
                runner: Runner = subprocess.run) -> dict[str, Any]:
    """Run one ``signing`` subcommand from this checkout's ``src`` and return its JSON report."""
    command = [settings.python, "-m", "appsec_review", "signing", *arguments, "--openssl", str(settings.openssl)]
    source = str(repository / "src")
    environment = {**os.environ, "PYTHONPATH": os.pathsep.join(
        item for item in (source, os.environ.get("PYTHONPATH", "")) if item)}
    try:
        completed = runner(command, cwd=repository, env=environment, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, check=False)
    except OSError as error:
        raise SigningError(f"signing {arguments[0]} could not run: {error}") from error
    try:
        report = json.loads(completed.stdout or "")
    except ValueError:
        report = None
    if not isinstance(report, dict):
        detail = (completed.stderr or completed.stdout or "").strip()[-500:]
        raise SigningError(f"signing {arguments[0]} produced no JSON report (exit {completed.returncode}): {detail}")
    if completed.returncode != 0:
        detail = report.get("error") or "; ".join(
            str(row.get("error")) for row in report.get("images", []) if isinstance(row, dict) and row.get("error"))
        raise SigningError(f"signing {arguments[0]} failed (exit {completed.returncode}): {detail or report}")
    return report


def _single_image(report: dict[str, Any], status: str, step: str) -> str:
    rows = report.get("images")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise SigningError(f"{step} did not report exactly one image")
    row = rows[0]
    image_id = row.get("image_id")
    if row.get("status") != status or not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
        raise SigningError(f"{step} did not report a {status} image ID: {row}")
    return image_id


def sign_modules(settings: SigningSettings, repository: Path, *, runner: Runner = subprocess.run) -> Path:
    """Sign ``src/appsec_review`` into the build-context envelope, then verify it against the trust anchors."""
    envelope = repository / MODULE_ENVELOPE
    package = repository / PACKAGE_ROOT
    signing_cli(settings, repository, ["sign-modules", "--private-key", str(settings.private_key),
                                       "--output", str(envelope), "--package-root", str(package)], runner=runner)
    report = signing_cli(settings, repository, ["verify-modules", "--envelope", str(envelope),
                                                "--trusted-keys-dir", str(settings.trusted_keys_dir),
                                                "--package-root", str(package)], runner=runner)
    if report.get("status") != "verified":
        raise SigningError(f"the module envelope did not verify: {report}")
    return envelope


def sign_image(settings: SigningSettings, repository: Path, reference: str, *,
               runner: Runner = subprocess.run) -> str:
    """Sign the image ``reference`` resolves to with the operator key and return its ID."""
    report = signing_cli(settings, repository, ["sign-image", reference, "--private-key", str(settings.private_key),
                                                "--signatures-dir", str(settings.image_signatures_dir)], runner=runner)
    return _single_image(report, "signed", "sign-image")


def verify_image(settings: SigningSettings, repository: Path, reference: str, *,
                 runner: Runner = subprocess.run) -> str:
    """Return the ID ``reference`` resolves to only if a trusted key signed exactly that ID."""
    report = signing_cli(settings, repository, ["verify-image", reference,
                                                "--signatures-dir", str(settings.image_signatures_dir),
                                                "--trusted-keys-dir", str(settings.trusted_keys_dir)], runner=runner)
    image_id = _single_image(report, "verified", "verify-image")
    if IMAGE_ID.fullmatch(reference) and image_id != reference:
        raise SigningError(f"verify-image checked {image_id}, not the requested {reference}")
    return image_id
