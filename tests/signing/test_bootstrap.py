"""Unit tests for the standalone signed-module bootstrap and sitecustomize shim, run in fresh interpreters."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass

import pytest

from appsec_review.signing.core import OpenSSL, key_id
from appsec_review.signing.modules import sign_modules
from tests.signing._host import OPENSSL_BINARY, symlink

SIGNING_SOURCE = Path(__file__).resolve().parents[2] / "src" / "appsec_review" / "signing"
VERIFIER_FILES = ("bootstrap.py", "core.py", "modules.py", "import_hook.py")
STANDALONE_NAMES = ("appsec_review_signing_core", "appsec_review_signing_modules",
                    "appsec_review_signing_import_hook", "appsec_review_signing_bootstrap")
TREE = {
    "__init__.py": b"",
    "helper.py": b"VALUE = 42\n",
    "runner.py": (b"import json, sys\nfrom pathlib import Path\nfrom . import helper\n"
                  b"Path(sys.argv[1]).write_text(json.dumps({'name': __name__, 'argv': sys.argv[1:],"
                  b" 'value': helper.VALUE, 'loader': type(helper.__spec__.loader).__name__,"
                  b" 'main_loader': type(__spec__.loader).__name__,"
                  b" 'dont_write_bytecode': sys.dont_write_bytecode}))\n"),
    "probe.py": b"from . import helper\nprint(type(helper.__spec__.loader).__name__, helper.VALUE)\n",
}
BASE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}

pytestmark = pytest.mark.skipif(not os.path.isfile(OPENSSL_BINARY), reason="system OpenSSL is required")


@dataclass(frozen=True)
class Signed:
    root: Path
    envelope: Path
    trusted: Path


@pytest.fixture(scope="module", autouse=True)
def openssl_scratch(tmp_path_factory) -> Path:
    """Keep OpenSSL message/signature files of child interpreters under the pytest base temp."""
    directory = tmp_path_factory.mktemp("openssl-scratch")
    BASE_ENV["TMPDIR"] = str(directory)
    yield directory
    BASE_ENV.pop("TMPDIR", None)


@pytest.fixture(scope="module")
def signing_key(tmp_path_factory, openssl_scratch) -> tuple[OpenSSL, Path, Path]:
    openssl = OpenSSL(OPENSSL_BINARY, temp_dir=str(openssl_scratch))
    root = tmp_path_factory.mktemp("bootstrap-keys")
    private_key = openssl.generate_private_key(root / "private" / "modules.pem")
    public_key_pem = openssl.public_key_pem(private_key)
    trusted_dir = root / "trusted-keys"
    trusted_dir.mkdir()
    (trusted_dir / f"{key_id(openssl.public_key_der(public_key_pem)).removeprefix('sha256:')}.pem").write_bytes(
        public_key_pem)
    return openssl, private_key, trusted_dir


@pytest.fixture(scope="module")
def verifier_dir(tmp_path_factory) -> Path:
    """A deployed copy of the standalone verifier, outside any verified tree."""
    directory = tmp_path_factory.mktemp("verifier")
    for name in (*VERIFIER_FILES, "sitecustomize_shim.py"):
        shutil.copyfile(SIGNING_SOURCE / name, directory / name)
    return directory


@pytest.fixture
def signed(signing_key, tmp_path) -> Signed:
    openssl, private_key, trusted_dir = signing_key
    root = tmp_path / "site" / "appsec_review"
    for relpath, data in TREE.items():
        (root / relpath).parent.mkdir(parents=True, exist_ok=True)
        (root / relpath).write_bytes(data)
    envelope = tmp_path / "python-modules.json"
    sign_modules(openssl, private_key, root, envelope)
    return Signed(root.resolve(), envelope, trusted_dir)


@pytest.fixture
def standalone(verifier_dir, openssl_scratch, monkeypatch):
    """Load the deployed bootstrap in-process and remove its standalone registrations afterwards."""
    monkeypatch.setattr(sys, "dont_write_bytecode", sys.dont_write_bytecode)
    monkeypatch.setattr(tempfile, "tempdir", str(openssl_scratch))
    spec = importlib.util.spec_from_file_location("appsec_review_signing_bootstrap", verifier_dir / "bootstrap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    yield module
    for name in STANDALONE_NAMES:
        sys.modules.pop(name, None)


def _bootstrap(verifier_dir: Path, signed: Signed, module: str, *module_args: str,
               flags: tuple[str, ...] = ("-I", "-S"), **overrides: str) -> subprocess.CompletedProcess:
    options = {"envelope": str(signed.envelope), "package-root": str(signed.root),
               "trusted-keys": str(signed.trusted), **overrides}
    argv = [sys.executable, *flags, str(verifier_dir / "bootstrap.py")]
    for name, value in options.items():
        argv += [f"--{name}", value]
    argv += ["--module", module, "--", *module_args]
    return subprocess.run(argv, capture_output=True, text=True, timeout=120, env=BASE_ENV, cwd=signed.root.parent)


def _signed_env(signed: Signed, **extra: str) -> dict[str, str]:
    return {**BASE_ENV, "APPSEC_REVIEW_MODULE_SIGNATURE": str(signed.envelope),
            "APPSEC_REVIEW_MODULE_ROOT": str(signed.root), "APPSEC_REVIEW_TRUSTED_KEYS_DIR": str(signed.trusted),
            "APPSEC_REVIEW_OPENSSL": OPENSSL_BINARY, **extra}


def test_bootstrap_runs_only_verified_module_code(verifier_dir, signed, tmp_path):
    marker = tmp_path / "ran.json"
    result = _bootstrap(verifier_dir, signed, "appsec_review.runner", str(marker), "a", "b")
    assert result.returncode == 0, result.stderr
    report = json.loads(marker.read_text())
    assert report == {"name": "__main__", "argv": [str(marker), "a", "b"], "value": 42,
                      "loader": "VerifiedSourceLoader", "main_loader": "VerifiedSourceLoader",
                      "dont_write_bytecode": True}
    assert not list(signed.root.rglob("__pycache__"))


@pytest.mark.parametrize("tamper", ["executed-module", "imported-module", "unlisted-module", "pth-file"])
def test_bootstrap_rejects_tampered_tree_before_running_anything(verifier_dir, signed, tmp_path, tamper):
    marker = tmp_path / "ran.json"
    if tamper == "executed-module":
        (signed.root / "runner.py").write_bytes(TREE["runner.py"] + b"# changed\n")
    elif tamper == "imported-module":
        (signed.root / "helper.py").write_bytes(b"VALUE = 0\n")
    elif tamper == "unlisted-module":
        (signed.root / "extra.py").write_bytes(b"")
    else:
        (signed.root / "hook.pth").write_bytes(b"import os\n")
    result = _bootstrap(verifier_dir, signed, "appsec_review.runner", str(marker))
    assert result.returncode == 78
    assert "signed module verification failed" in result.stderr
    assert not marker.exists()


@pytest.mark.parametrize("failure", ["missing-envelope", "untrusted-key", "outside-package", "not-isolated",
                                     "relative-path", "missing-openssl"])
def test_bootstrap_fails_closed(verifier_dir, signed, tmp_path, failure):
    marker = tmp_path / "ran.json"
    module, flags, overrides = "appsec_review.runner", ("-I", "-S"), {}
    if failure == "missing-envelope":
        overrides["envelope"] = str(tmp_path / "absent.json")
    elif failure == "untrusted-key":
        empty = tmp_path / "no-keys"
        empty.mkdir()
        overrides["trusted-keys"] = str(empty)
    elif failure == "outside-package":
        module = "json.tool"
    elif failure == "not-isolated":
        flags = ("-I",)
    elif failure == "relative-path":
        overrides["package-root"] = "site/appsec_review"
    else:
        overrides["openssl"] = str(tmp_path / "openssl")
    result = _bootstrap(verifier_dir, signed, module, str(marker), flags=flags, **overrides)
    assert result.returncode == 78, result.stderr
    assert "signed module verification failed" in result.stderr
    assert not marker.exists()


def test_bootstrap_verifies_and_runs_the_real_package_tree(verifier_dir, signing_key, tmp_path):
    openssl, private_key, trusted_dir = signing_key
    root = SIGNING_SOURCE.parent
    envelope = tmp_path / "python-modules.json"
    sign_modules(openssl, private_key, root, envelope)
    real = Signed(root, envelope, trusted_dir)
    result = _bootstrap(verifier_dir, real, "appsec_review.signing.core")
    assert result.returncode == 0, result.stderr


def test_activate_from_environment_installs_the_hook_in_a_fresh_interpreter(verifier_dir, signed):
    script = ("import importlib.util, sys\n"
              f"spec = importlib.util.spec_from_file_location('appsec_review_signing_bootstrap', {str(verifier_dir / 'bootstrap.py')!r})\n"
              "bootstrap = importlib.util.module_from_spec(spec)\n"
              "spec.loader.exec_module(bootstrap)\n"
              "finder = bootstrap.activate_from_environment()\n"
              "assert sys.meta_path[0] is finder and sys.path[-1] == str(finder.manifest.root.parent)\n"
              "import appsec_review.probe\n")
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script], capture_output=True, text=True,
                            timeout=120, env=_signed_env(signed, APPSEC_REVIEW_REQUIRE_SIGNED_MODULES="1"))
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["VerifiedSourceLoader 42"]


@pytest.mark.parametrize("environ", [{}, {"APPSEC_REVIEW_REQUIRE_SIGNED_MODULES": "0"},
                                     {"APPSEC_REVIEW_MODULE_ROOT": "/ignored"}])
def test_activate_from_environment_is_not_enforced_without_signature_or_requirement(standalone, environ):
    assert standalone.activate_from_environment(environ) is None
    assert "appsec_review_signing_core" not in sys.modules


@pytest.mark.parametrize("environ, message", [
    ({"APPSEC_REVIEW_REQUIRE_SIGNED_MODULES": "1"},
     "requires APPSEC_REVIEW_MODULE_ROOT, APPSEC_REVIEW_MODULE_SIGNATURE, APPSEC_REVIEW_TRUSTED_KEYS_DIR"),
    ({"APPSEC_REVIEW_MODULE_SIGNATURE": "/release/python-modules.json"},
     "requires APPSEC_REVIEW_MODULE_ROOT, APPSEC_REVIEW_TRUSTED_KEYS_DIR"),
    ({"APPSEC_REVIEW_REQUIRE_SIGNED_MODULES": "yes"}, "must be 0 or 1"),
    ({"APPSEC_REVIEW_MODULE_SIGNATURE": "modules.json", "APPSEC_REVIEW_MODULE_ROOT": os.path.abspath("/r"),
      "APPSEC_REVIEW_TRUSTED_KEYS_DIR": os.path.abspath("/k"), "APPSEC_REVIEW_OPENSSL": "openssl"},
     "must be absolute: APPSEC_REVIEW_MODULE_SIGNATURE, APPSEC_REVIEW_OPENSSL"),
])
def test_activate_from_environment_fails_closed_on_incomplete_configuration(standalone, environ, message):
    with pytest.raises(Exception, match=message) as raised:
        standalone.activate_from_environment(environ)
    assert raised.type is sys.modules["appsec_review_signing_core"].SignatureVerificationError


def test_activate_from_environment_rejects_tampered_tree_without_installing_a_hook(standalone, signed):
    (signed.root / "helper.py").write_bytes(b"VALUE = 0\n")
    meta_path = list(sys.meta_path)
    with pytest.raises(Exception, match="does not match the signed manifest") as raised:
        standalone.activate_from_environment(_signed_env(signed))
    assert raised.type is sys.modules["appsec_review_signing_core"].SignatureVerificationError
    assert sys.meta_path == meta_path


def test_load_verifier_rejects_symlinks_and_foreign_registrations(standalone, verifier_dir, tmp_path):
    linked = tmp_path / "linked"
    linked.mkdir()
    for name in VERIFIER_FILES:
        shutil.copyfile(verifier_dir / name, linked / name)
    (linked / "modules.py").unlink()
    symlink(linked / "modules.py", verifier_dir / "modules.py")
    with pytest.raises(ImportError, match="symbolic link"):
        standalone.load_verifier(linked)
    assert not any(name in sys.modules for name in STANDALONE_NAMES[:3])
    core, modules, import_hook = standalone.load_verifier(verifier_dir)
    assert modules._core is core and import_hook._modules is modules
    assert standalone.load_verifier(verifier_dir) == (core, modules, import_hook)
    (linked / "modules.py").unlink()
    shutil.copyfile(verifier_dir / "modules.py", linked / "modules.py")
    with pytest.raises(ImportError, match="already loaded"):
        standalone.load_verifier(linked)


def _shim(verifier_dir: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", "-S", str(verifier_dir / "sitecustomize_shim.py")],
                          capture_output=True, text=True, timeout=120, env=env)


@pytest.mark.parametrize("case", ["required-without-directory", "signature-without-directory",
                                  "relative-directory", "tampered-tree", "missing-bootstrap"])
def test_sitecustomize_shim_exits_78_on_any_failure(verifier_dir, signed, tmp_path, case):
    env = _signed_env(signed, APPSEC_REVIEW_SIGNING_BOOTSTRAP_DIR=str(verifier_dir))
    if case == "required-without-directory":
        env = {**BASE_ENV, "APPSEC_REVIEW_REQUIRE_SIGNED_MODULES": "1"}
    elif case == "signature-without-directory":
        del env["APPSEC_REVIEW_SIGNING_BOOTSTRAP_DIR"]
    elif case == "relative-directory":
        env["APPSEC_REVIEW_SIGNING_BOOTSTRAP_DIR"] = "verifier"
    elif case == "tampered-tree":
        (signed.root / "helper.py").write_bytes(b"VALUE = 0\n")
    else:
        env["APPSEC_REVIEW_SIGNING_BOOTSTRAP_DIR"] = str(tmp_path)
    result = _shim(verifier_dir, env)
    assert result.returncode == 78
    assert "signed module verification failed; refusing to start" in result.stderr


def test_sitecustomize_shim_is_inert_when_nothing_is_configured(verifier_dir):
    result = _shim(verifier_dir, dict(BASE_ENV))
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("tampered", [False, True])
def test_sitecustomize_shim_activates_before_application_code(verifier_dir, signed, tmp_path, tampered):
    site = tmp_path / "sitecustomize-dir"
    site.mkdir()
    shutil.copyfile(verifier_dir / "sitecustomize_shim.py", site / "sitecustomize.py")
    if tampered:
        (signed.root / "helper.py").write_bytes(b"VALUE = 0\n")
    script = (f"import sys; sys.path.insert(0, {str(site)!r}); import sitecustomize\n"
              "print('continued'); import appsec_review.probe\n")
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script], capture_output=True, text=True,
                            timeout=120, env=_signed_env(signed, APPSEC_REVIEW_SIGNING_BOOTSTRAP_DIR=str(verifier_dir),
                                                         APPSEC_REVIEW_REQUIRE_SIGNED_MODULES="1"))
    if tampered:
        assert result.returncode == 78
        assert result.stdout == ""
    else:
        assert result.returncode == 0, result.stderr
        assert result.stdout.splitlines() == ["continued", "VerifiedSourceLoader 42"]
