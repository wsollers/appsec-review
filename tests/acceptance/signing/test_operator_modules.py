"""Operator story: sign a package tree with the CLI and run it only through the verifying bootstrap.

``sign-modules`` signs a copy of ``src/appsec_review`` that carries a small probe module,
``verify-modules`` accepts it, and the bootstrap exported by ``export-bootstrap`` runs the probe
under ``python -I -S``. After one module is modified, ``verify-modules`` fails and the bootstrap
exits 78 before any code from the tree runs.
"""
from __future__ import annotations

from pathlib import Path
import sys

from .conftest import OPENSSL_BINARY, copy_package


EXIT_VERIFICATION_FAILED = 78
PROBE = "_acceptance_probe"
PROBE_SOURCE = '''"""Acceptance probe: records that the bootstrap ran verified code from the signed tree."""
import sys
from pathlib import Path

if __name__ == "__main__":
    Path(sys.argv[1]).write_text("verified:" + __spec__.name + "\\n", encoding="utf-8")
'''


def _bootstrap(operator, bootstrap: Path, envelope: Path, package: Path, marker: Path):
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": operator.environment["TMPDIR"]}
    return operator.run(sys.executable, "-I", "-S", str(bootstrap / "bootstrap.py"),
                        "--envelope", str(envelope), "--package-root", str(package),
                        "--trusted-keys", str(operator.trusted_keys_dir), "--openssl", OPENSSL_BINARY,
                        "--module", f"appsec_review.{PROBE}", "--", str(marker), environment=environment)


def test_operator_signs_modules_and_the_bootstrap_runs_only_the_signed_tree(tmp_path, operator, operator_key):
    package = copy_package(tmp_path / "release" / "appsec_review")
    (package / f"{PROBE}.py").write_text(PROBE_SOURCE, encoding="utf-8")
    envelope = tmp_path / "python-modules.json"

    code, report = operator.signing("sign-modules", "--private-key", str(operator.private_key),
                                    "--output", str(envelope), "--package-root", str(package))
    assert code == 0, report
    assert report["package"] == "appsec_review" and report["key_ids"] == [operator_key]
    assert report["files"] > 1

    verify = ("verify-modules", "--envelope", str(envelope), "--trusted-keys-dir", str(operator.trusted_keys_dir),
              "--package-root", str(package))
    code, report = operator.signing(*verify)
    assert code == 0, report
    assert report["status"] == "verified"

    code, report = operator.signing("export-bootstrap", str(tmp_path / "bootstrap"))
    assert code == 0, report
    bootstrap = Path(report["directory"])
    assert sorted(report["files"]) == sorted(path.name for path in bootstrap.iterdir())

    marker = tmp_path / "probe-ran"
    started = _bootstrap(operator, bootstrap, envelope, package, marker)
    assert started.returncode == 0, started.stderr
    assert marker.read_text(encoding="utf-8") == f"verified:appsec_review.{PROBE}\n"

    # One modified module: the CLI reports the mismatch and the bootstrap runs nothing from the tree.
    marker.unlink()
    with (package / f"{PROBE}.py").open("a", encoding="utf-8") as handle:
        handle.write("Path(sys.argv[1]).write_text('tampered code ran\\n', encoding='utf-8')\n")
    code, report = operator.signing(*verify)
    assert code != 0
    assert report["status"] == "failed" and report["error"]

    refused = _bootstrap(operator, bootstrap, envelope, package, marker)
    assert refused.returncode == EXIT_VERIFICATION_FAILED, refused
    assert refused.stdout == ""
    assert "signed module verification failed" in refused.stderr
    assert not marker.exists()
