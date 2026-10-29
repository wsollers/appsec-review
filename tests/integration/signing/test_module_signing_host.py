"""The exported standalone bootstrap verifies the real package tree under an isolated interpreter."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

from appsec_review.signing.modules import sign_modules

from .conftest import OPENSSL_BINARY, copy_package, export_bootstrap


EXIT_VERIFICATION_FAILED = 78


def _run(bootstrap: Path, envelope: Path, package: Path, trusted: Path, tmp_path: Path,
         *argv: str) -> subprocess.CompletedProcess[str]:
    scratch = tmp_path / "child-tmp"
    scratch.mkdir(exist_ok=True)
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": str(scratch)}
    command = [sys.executable, "-I", "-S", str(bootstrap / "bootstrap.py"),
               "--envelope", str(envelope), "--package-root", str(package),
               "--trusted-keys", str(trusted), "--openssl", OPENSSL_BINARY, *argv]
    return subprocess.run(command, env=environment, cwd=tmp_path, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, check=False, timeout=300)


def test_isolated_bootstrap_runs_only_the_signed_tree(tmp_path, signing_key):
    package = copy_package(tmp_path / "signed" / "appsec_review")
    envelope = tmp_path / "python-modules.json"
    sign_modules(signing_key.openssl, signing_key.private_key, package, envelope)
    bootstrap = export_bootstrap(tmp_path / "bootstrap")
    trusted = signing_key.trusted_keys_dir

    module = ("--module", "appsec_review.signing.bootstrap", "--", "--help")
    verified = _run(bootstrap, envelope, package, trusted, tmp_path, *module)
    assert verified.returncode == 0, verified.stderr
    assert "Verify a signed package tree" in verified.stdout

    # A modified module and an added unsigned module each refuse to start the program.
    tampered = copy_package(tmp_path / "tampered" / "appsec_review")
    with (tampered / "signing" / "policy.py").open("a", encoding="utf-8") as handle:
        handle.write("\n# tampered\n")
    added = copy_package(tmp_path / "added" / "appsec_review")
    (added / "signing" / "extra.py").write_text("print('unsigned')\n", encoding="utf-8")
    for root in (tampered, added):
        refused = _run(bootstrap, envelope, root, trusted, tmp_path, *module)
        assert refused.returncode == EXIT_VERIFICATION_FAILED, refused
        assert refused.stdout == ""
        assert "signed module verification failed" in refused.stderr
