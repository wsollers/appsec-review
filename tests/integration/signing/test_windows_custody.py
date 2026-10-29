"""Native Windows key custody: real ``signing keygen`` output on NTFS, then ACLs widened with ``icacls``.

``keygen`` (through the command line, with the real OpenSSL) gives the private key, its directory and
the trust-anchor directory protected ACLs that pass the custody checks, and a verifier loads the
anchor. Granting Everyone (``S-1-1-0``) access with ``icacls`` then makes the paths that check custody
refuse: ``keygen`` into the private-key directory (read grant), and ``TrustedKeys.load`` / image
verification for an anchor file or the anchor directory (write grant; reading an anchor is allowed by
design). Signing with an existing private key does not check its ACL, so it is not exercised here.
No Docker is needed.
"""
from __future__ import annotations

import json
import os
import subprocess

import pytest

from appsec_review import cli
from appsec_review.signing import EnvelopeImageVerifier, SignatureVerificationError, sign_image
from appsec_review.signing.core import TrustedKeys, check_windows_custody


pytestmark = pytest.mark.skipif(os.name != "nt", reason="reads and widens real NTFS ACLs with icacls")

EVERYONE = "*S-1-1-0"
IMAGE_ID = "sha256:" + "5e" * 32


def _icacls(path, *arguments: str) -> None:
    completed = subprocess.run(["icacls", str(path), *arguments], stdin=subprocess.DEVNULL, capture_output=True,
                               text=True, check=False, timeout=60)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def _keygen(capsys, openssl, private_key, trusted_keys_dir) -> tuple[int, dict]:
    code = cli.main(["signing", "keygen", "--openssl", openssl.binary, "--private-key", str(private_key),
                     "--trusted-keys-dir", str(trusted_keys_dir)])
    return code, json.loads(capsys.readouterr().out)


def test_keygen_output_passes_custody_and_widened_acls_are_refused(tmp_path, capsys, openssl):
    private_key = tmp_path / "home" / "private" / "operator.pem"
    anchors = tmp_path / "trusted-keys"
    code, report = _keygen(capsys, openssl, private_key, anchors)
    assert code == 0, report
    anchor = anchors / f"{report['key_id'].removeprefix('sha256:')}.pem"
    assert report["trusted_key"] == str(anchor)
    check_windows_custody(private_key.parent, "private", "private key directory", directory=True)
    check_windows_custody(private_key, "private", "private key", directory=False)
    check_windows_custody(anchors, "anchor", "trusted keys directory", directory=True)
    check_windows_custody(anchor, "anchor", "trusted key", directory=False)
    assert list(TrustedKeys.load(anchors, openssl)) == [report["key_id"]]

    signatures = tmp_path / "image-signatures"
    sign_image(openssl, private_key, IMAGE_ID, signatures)

    def verify() -> None:
        EnvelopeImageVerifier(signatures_dir=signatures, trusted_keys_dir=anchors, openssl=openssl).verify(IMAGE_ID)

    verify()

    # Everyone may read an anchor: a public key is not secret.
    _icacls(anchor, "/grant", f"{EVERYONE}:R")
    assert list(TrustedKeys.load(anchors, openssl)) == [report["key_id"]]
    verify()

    # Everyone may modify the anchor file: every load and verification refuses.
    _icacls(anchor, "/grant", f"{EVERYONE}:W")
    with pytest.raises(SignatureVerificationError,
                       match=r"^trusted key can be modified .*Everyone \(S-1-1-0\) FILE_WRITE_DATA"):
        TrustedKeys.load(anchors, openssl)
    with pytest.raises(SignatureVerificationError, match=r"Everyone \(S-1-1-0\)"):
        verify()
    _icacls(anchor, "/remove:g", EVERYONE)
    verify()

    # Everyone may add files to the anchor directory.
    _icacls(anchors, "/grant", f"{EVERYONE}:W")
    with pytest.raises(SignatureVerificationError,
                       match=r"^trusted keys directory can be modified .*Everyone \(S-1-1-0\) FILE_WRITE_DATA"):
        TrustedKeys.load(anchors, openssl)
    _icacls(anchors, "/remove:g", EVERYONE)
    verify()

    # Everyone may read the private-key directory: keygen refuses to put another key there.
    _icacls(private_key.parent, "/grant", f"{EVERYONE}:R")
    with pytest.raises(SignatureVerificationError, match=r"Everyone \(S-1-1-0\) FILE_READ_DATA"):
        check_windows_custody(private_key.parent, "private", "private key directory", directory=True)
    second = private_key.parent / "second.pem"
    code, refused = _keygen(capsys, openssl, second, tmp_path / "second-anchors")
    assert code == 1 and "Everyone (S-1-1-0)" in refused["error"], refused
    assert "icacls" in refused["error"]
    assert not second.exists()

    # Everyone may read the private key itself: the custody check refuses it.
    _icacls(private_key, "/grant", f"{EVERYONE}:R")
    with pytest.raises(SignatureVerificationError, match=r"Everyone \(S-1-1-0\) FILE_READ_DATA"):
        check_windows_custody(private_key, "private", "private key", directory=False)
