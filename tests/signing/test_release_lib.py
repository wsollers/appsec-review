"""Unit tests for the signed third-party manifest of a native release ``lib/`` directory."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from appsec_review.signing.core import OpenSSL, SignatureVerificationError, key_id
from appsec_review.signing.release_lib import (
    RELEASE_LIB_KIND, build_manifest, sign_release_lib, verify_release_lib,
)
from tests.signing._host import OPENSSL_BINARY, symlink

SIGNING_SOURCE = Path(__file__).resolve().parents[2] / "src" / "appsec_review" / "signing"
LIBRARY = {
    "fakepkg/__init__.py": b"VALUE = 1\n",
    "fakepkg/_speedups.cpython-312-x86_64-linux-gnu.so": b"\x7fELF fake extension\n",
    "fakepkg-1.0.dist-info/METADATA": b"Name: fakepkg\nVersion: 1.0\n",
    "fakepkg-1.0.dist-info/RECORD": b"fakepkg/__init__.py,,\n",
    "fakepkg.pth": b"import fakepkg\n",
    "empty.txt": b"",
}
EXCLUDED = {"appsec_review/__init__.py": b"", "appsec_review/__pycache__/x.cpython-312.pyc": b"cached"}

pytestmark = pytest.mark.skipif(not os.path.isfile(OPENSSL_BINARY), reason="system OpenSSL is required")


@pytest.fixture(scope="module")
def signing_key(tmp_path_factory) -> tuple[OpenSSL, Path, Path]:
    root = tmp_path_factory.mktemp("release-lib-keys")
    openssl = OpenSSL(OPENSSL_BINARY)
    private_key = openssl.generate_private_key(root / "private" / "release.pem")
    public_key_pem = openssl.public_key_pem(private_key)
    trusted_dir = root / "trusted-keys"
    trusted_dir.mkdir()
    (trusted_dir / f"{key_id(openssl.public_key_der(public_key_pem)).removeprefix('sha256:')}.pem").write_bytes(
        public_key_pem)
    return openssl, private_key, trusted_dir


def _write(root: Path, files: dict[str, bytes]) -> Path:
    for relpath, data in files.items():
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


@pytest.fixture
def signed(signing_key, tmp_path) -> tuple[Path, Path]:
    openssl, private_key, _ = signing_key
    library = _write(tmp_path / "release" / "lib", {**LIBRARY, **EXCLUDED})
    envelope = tmp_path / "release" / "signing" / "python-release-lib.json"
    envelope.parent.mkdir()
    sign_release_lib(openssl, private_key, library, envelope)
    return library, envelope


def test_manifest_lists_every_third_party_file_with_digest_and_size_but_not_appsec_review(tmp_path) -> None:
    library = _write(tmp_path / "lib", {**LIBRARY, **EXCLUDED})
    subject = build_manifest(library)
    assert subject["excluded"] == ["appsec_review"]
    assert sorted(subject["files"]) == sorted(LIBRARY)
    entry = subject["files"]["fakepkg/__init__.py"]
    assert entry["size"] == len(LIBRARY["fakepkg/__init__.py"]) and len(entry["sha256"]) == 64


def test_signed_release_library_verifies(signing_key, signed) -> None:
    openssl, _, trusted = signing_key
    library, envelope = signed
    assert json.loads(envelope.read_bytes())["statement"]["kind"] == RELEASE_LIB_KIND
    files = verify_release_lib(envelope, library, trusted, openssl)
    assert sorted(files) == sorted(LIBRARY)


def _tamper(library: Path, how: str) -> None:
    if how == "byte":
        path = library / "fakepkg/_speedups.cpython-312-x86_64-linux-gnu.so"
        path.write_bytes(b"\x7fELF fake extensioN\n")
    elif how == "extra":
        (library / "evil.pth").write_bytes(b"import os\n")
    elif how == "missing":
        (library / "fakepkg-1.0.dist-info/RECORD").unlink()
    elif how == "symlink":
        symlink(library / "fakepkg/linked.py", library / "fakepkg/__init__.py")
    elif how == "pycache":
        _write(library, {"fakepkg/__pycache__/__init__.cpython-312.pyc": b"cached"})
    elif how == "pyc":
        _write(library, {"fakepkg/stale.pyc": b"cached"})
    elif how == "fifo":
        if os.name == "nt":
            pytest.skip("FIFOs are not available on Windows")
        os.mkfifo(library / "fakepkg/pipe")
    elif how == "excluded-is-not-a-hole":
        _write(library, {"appsec_review_extra/__init__.py": b""})


@pytest.mark.parametrize("how", ["byte", "extra", "missing", "symlink", "pycache", "pyc", "fifo",
                                 "excluded-is-not-a-hole"])
def test_tampered_release_library_is_refused(signing_key, signed, how) -> None:
    openssl, _, trusted = signing_key
    library, envelope = signed
    _tamper(library, how)
    with pytest.raises(SignatureVerificationError):
        verify_release_lib(envelope, library, trusted, openssl)


@pytest.mark.parametrize("how", ["symlink", "pycache", "pyc", "fifo"])
def test_signing_refuses_unsupported_library_content(signing_key, tmp_path, how) -> None:
    openssl, private_key, _ = signing_key
    library = _write(tmp_path / "lib", LIBRARY)
    _tamper(library, how)
    envelope = tmp_path / "python-release-lib.json"
    with pytest.raises(SignatureVerificationError):
        sign_release_lib(openssl, private_key, library, envelope)
    assert not envelope.exists()


def test_missing_envelope_or_untrusted_key_is_refused(signing_key, signed, tmp_path) -> None:
    openssl, _, trusted = signing_key
    library, envelope = signed
    with pytest.raises(SignatureVerificationError):
        verify_release_lib(tmp_path / "absent.json", library, trusted, openssl)
    empty = tmp_path / "empty-trust"
    empty.mkdir()
    with pytest.raises(SignatureVerificationError):
        verify_release_lib(envelope, library, empty, openssl)


def test_a_module_manifest_is_not_accepted_as_a_library_manifest(signing_key, tmp_path) -> None:
    from appsec_review.signing.modules import sign_modules

    openssl, private_key, trusted = signing_key
    library = _write(tmp_path / "lib", {**LIBRARY, **EXCLUDED})
    envelope = tmp_path / "python-modules.json"
    shutil.rmtree(library / "appsec_review/__pycache__")
    sign_modules(openssl, private_key, library / "appsec_review", envelope)
    with pytest.raises(SignatureVerificationError, match="kind"):
        verify_release_lib(envelope, library, trusted, openssl)


STANDALONE = """\
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("appsec_review_signing_bootstrap", sys.argv[1])
bootstrap = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bootstrap
spec.loader.exec_module(bootstrap)
outcome = "verified"
try:
    files = bootstrap.verify_release_library(envelope=sys.argv[2], library=sys.argv[3],
                                             trusted_keys_dir=sys.argv[4], openssl=sys.argv[5])
except Exception as error:
    outcome = type(error).__name__
print(json.dumps({"outcome": outcome, "path": sys.path,
                  "loaded": sorted(name for name in sys.modules if name.startswith("appsec_review_signing_"))}))
"""


@pytest.mark.parametrize("tamper", [False, True])
def test_standalone_bootstrap_verifies_transiently_and_never_adds_lib_to_sys_path(
        signing_key, signed, tmp_path, tamper) -> None:
    _, _, trusted = signing_key
    library, envelope = signed
    verifier = tmp_path / "verifier"
    verifier.mkdir()
    for name in ("bootstrap.py", "core.py", "modules.py", "import_hook.py", "release_lib.py"):
        shutil.copyfile(SIGNING_SOURCE / name, verifier / name)
    if tamper:
        _tamper(library, "extra")
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", STANDALONE, str(verifier / "bootstrap.py"), str(envelope),
         str(library), str(trusted), OPENSSL_BINARY],
        capture_output=True, text=True, timeout=120, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["outcome"] == ("SignatureVerificationError" if tamper else "verified")
    assert report["loaded"] == ["appsec_review_signing_bootstrap", "appsec_review_signing_core",
                                "appsec_review_signing_import_hook", "appsec_review_signing_modules"]
    assert str(library) not in report["path"]
