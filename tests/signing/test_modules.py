"""Unit tests for signed Python module manifests over an installed package tree."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from appsec_review.signing import core, modules
from appsec_review.signing.core import OpenSSL, SignatureVerificationError, TrustedKeys, key_id
from appsec_review.signing.modules import (
    MODULES_KIND, VerifiedManifest, build_manifest, sign_modules, verify_modules,
)
from tests.signing._host import OPENSSL_BINARY, symlink

PACKAGE = "demo_pkg"
TREE = {
    "__init__.py": b"VALUE = 1\n",
    "core.py": b"def answer():\n    return 42\n",
    "sub/__init__.py": b"",
    "sub/leaf.py": b"LEAF = 'leaf'\n",
    "data/schema.json": b"{\"a\": 1}\n",
    "namespace/item.py": b"ITEM = 3\n",
}

pytestmark = pytest.mark.skipif(not os.path.isfile(OPENSSL_BINARY), reason="system OpenSSL is required")


@pytest.fixture(scope="module")
def openssl() -> OpenSSL:
    return OpenSSL(OPENSSL_BINARY)


@pytest.fixture(scope="module")
def signing_key(openssl, tmp_path_factory) -> tuple[Path, Path]:
    root = tmp_path_factory.mktemp("module-keys")
    private_key = openssl.generate_private_key(root / "private" / "modules.pem")
    public_key_pem = openssl.public_key_pem(private_key)
    trusted_dir = root / "trusted-keys"
    trusted_dir.mkdir()
    (trusted_dir / f"{key_id(openssl.public_key_der(public_key_pem)).removeprefix('sha256:')}.pem").write_bytes(
        public_key_pem)
    return private_key, trusted_dir


def _write_tree(root: Path, files: dict[str, bytes] = TREE) -> Path:
    for relpath, data in files.items():
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


@pytest.fixture
def signed(openssl, signing_key, tmp_path) -> tuple[Path, Path]:
    package_root = _write_tree(tmp_path / "src" / PACKAGE)
    envelope_path = tmp_path / "python-modules.json"
    sign_modules(openssl, signing_key[0], package_root, envelope_path, package=PACKAGE)
    return package_root, envelope_path


def _verify(openssl, signing_key, envelope_path, package_root, package=PACKAGE) -> VerifiedManifest:
    return verify_modules(envelope_path, package_root, signing_key[1], openssl, package=package)


def test_build_manifest_hashes_every_file_sorted_and_skips_bytecode(tmp_path):
    root = _write_tree(tmp_path / PACKAGE)
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "core.cpython-312.pyc").write_bytes(b"bytecode")
    (root / "stale.pyc").write_bytes(b"bytecode")
    subject = build_manifest(root, package=PACKAGE)
    assert subject["package"] == PACKAGE
    assert list(subject["files"]) == sorted(TREE)
    assert subject["files"]["core.py"] == "sha256:" + __import__("hashlib").sha256(TREE["core.py"]).hexdigest()


@pytest.mark.parametrize("name", ["evil.pth", "native.cpython-312-x86_64-linux-gnu.so", "win.PYD"])
def test_build_manifest_rejects_native_and_pth_files(tmp_path, name):
    root = _write_tree(tmp_path / PACKAGE)
    (root / "sub" / name).write_bytes(b"x")
    with pytest.raises(SignatureVerificationError, match="native extension and .pth"):
        build_manifest(root, package=PACKAGE)


def test_build_manifest_rejects_symlinks_and_odd_names(tmp_path):
    root = _write_tree(tmp_path / PACKAGE)
    symlink(root / "link.py", root / "core.py")
    with pytest.raises(SignatureVerificationError, match="symbolic link"):
        build_manifest(root, package=PACKAGE)
    (root / "link.py").unlink()
    symlink(root / "linked_dir", root / "sub", target_is_directory=True)
    with pytest.raises(SignatureVerificationError, match="symbolic link"):
        build_manifest(root, package=PACKAGE)
    (root / "linked_dir").unlink()
    (root / "cafe\u0301.py").write_bytes(b"")
    with pytest.raises(SignatureVerificationError, match="NFC"):
        build_manifest(root, package=PACKAGE)
    (root / "cafe\u0301.py").unlink()
    (root / "back\\slash.py").write_bytes(b"")
    with pytest.raises(SignatureVerificationError, match="unsupported path component"):
        build_manifest(root, package=PACKAGE)


def test_build_manifest_rejects_fifo_and_symlinked_root(tmp_path):
    root = _write_tree(tmp_path / PACKAGE)
    alias = tmp_path / "alias"
    symlink(alias, root, target_is_directory=True)
    with pytest.raises(SignatureVerificationError, match="package root must not be a symbolic link"):
        build_manifest(alias, package=PACKAGE)
    if os.name == "nt":
        pytest.skip("FIFOs are not available on Windows")
    os.mkfifo(root / "pipe")
    with pytest.raises(SignatureVerificationError, match="non-regular"):
        build_manifest(root, package=PACKAGE)


def test_sign_and_verify_roundtrip(openssl, signing_key, signed):
    package_root, envelope_path = signed
    envelope = core.read_envelope(envelope_path)
    assert envelope["statement"]["kind"] == MODULES_KIND
    manifest = _verify(openssl, signing_key, envelope_path, package_root)
    assert manifest.package == PACKAGE
    assert manifest.root == package_root.resolve()
    assert set(manifest.files) == set(TREE)
    assert manifest.expected_digest("sub/leaf.py").startswith("sha256:")
    assert manifest.expected_digest("missing.py") is None
    assert manifest.read_verified("sub/leaf.py") == TREE["sub/leaf.py"]
    with pytest.raises(TypeError):
        manifest.files["evil.py"] = "sha256:" + "0" * 64
    with pytest.raises(AttributeError):
        manifest.package = "other"


def test_verify_accepts_loaded_trusted_keys(openssl, signing_key, signed):
    package_root, envelope_path = signed
    trusted = TrustedKeys.load(signing_key[1], openssl)
    assert verify_modules(envelope_path, package_root, trusted, openssl, package=PACKAGE).package == PACKAGE


def test_modified_file_is_rejected(openssl, signing_key, signed):
    package_root, envelope_path = signed
    (package_root / "core.py").write_bytes(b"def answer():\n    return 0\n")
    with pytest.raises(SignatureVerificationError, match="does not match.*core.py"):
        _verify(openssl, signing_key, envelope_path, package_root)


@pytest.mark.parametrize("relpath", ["sub/added.py", "stray.pyc", "data/new.txt"])
def test_unlisted_file_is_rejected_by_name(openssl, signing_key, signed, relpath):
    package_root, envelope_path = signed
    (package_root / relpath).write_bytes(b"x = 1\n")
    with pytest.raises(SignatureVerificationError, match=f"not in the signed manifest: {relpath}"):
        _verify(openssl, signing_key, envelope_path, package_root)


@pytest.mark.parametrize("relpath", ["evil.pth", "sub/native.abi3.so", "sub/native.pyd"])
def test_added_pth_or_native_file_is_rejected(openssl, signing_key, signed, relpath):
    package_root, envelope_path = signed
    (package_root / relpath).write_bytes(b"import os\n")
    with pytest.raises(SignatureVerificationError, match="native extension and .pth"):
        _verify(openssl, signing_key, envelope_path, package_root)


def test_symlink_is_rejected_even_to_identical_content(openssl, signing_key, signed, tmp_path):
    package_root, envelope_path = signed
    outside = tmp_path / "outside.py"
    outside.write_bytes(TREE["core.py"])
    (package_root / "core.py").unlink()
    symlink(package_root / "core.py", outside)
    with pytest.raises(SignatureVerificationError, match="symbolic link"):
        _verify(openssl, signing_key, envelope_path, package_root)


def test_pycache_directories_are_ignored(openssl, signing_key, signed):
    package_root, envelope_path = signed
    for directory in (package_root / "__pycache__", package_root / "sub" / "__pycache__"):
        directory.mkdir()
        (directory / "anything.cpython-312.pyc").write_bytes(b"not verified")
    assert _verify(openssl, signing_key, envelope_path, package_root).package == PACKAGE


def test_missing_listed_non_root_file_is_allowed(openssl, signing_key, signed):
    package_root, envelope_path = signed
    (package_root / "data" / "schema.json").unlink()
    manifest = _verify(openssl, signing_key, envelope_path, package_root)
    assert manifest.expected_digest("data/schema.json") is not None
    with pytest.raises(SignatureVerificationError, match="missing|cannot be opened"):
        manifest.read_verified("data/schema.json")


def test_missing_root_init_is_rejected(openssl, signing_key, signed):
    package_root, envelope_path = signed
    (package_root / "__init__.py").unlink()
    with pytest.raises(SignatureVerificationError, match="root __init__.py"):
        _verify(openssl, signing_key, envelope_path, package_root)


def test_wrong_package_name_is_rejected(openssl, signing_key, signed):
    package_root, envelope_path = signed
    with pytest.raises(SignatureVerificationError, match="not 'appsec_review'"):
        _verify(openssl, signing_key, envelope_path, package_root, package="appsec_review")


def test_untrusted_or_wrong_kind_envelope_is_rejected(openssl, signing_key, signed, tmp_path):
    package_root, envelope_path = signed
    other_key = openssl.generate_private_key(tmp_path / "other" / "key.pem")
    other_envelope = tmp_path / "other.json"
    sign_modules(openssl, other_key, package_root, other_envelope, package=PACKAGE)
    with pytest.raises(SignatureVerificationError, match="no signature from a trusted key"):
        _verify(openssl, signing_key, other_envelope, package_root)
    image_envelope = tmp_path / "image.json"
    core.write_envelope(image_envelope, core.sign_statement(
        openssl, signing_key[0], core.make_statement("container-image", build_manifest(package_root, package=PACKAGE))))
    with pytest.raises(SignatureVerificationError, match="kind"):
        _verify(openssl, signing_key, image_envelope, package_root)


@pytest.mark.parametrize("bad_files", [
    {"__init__.py": "sha256:" + "0" * 64, "../escape.py": "sha256:" + "0" * 64},
    {"__init__.py": "sha256:" + "0" * 64, "x/__pycache__/y.pyc": "sha256:" + "0" * 64},
    {"__init__.py": "md5:00"},
    {"core.py": "sha256:" + "0" * 64},
    {"__init__.py": "sha256:" + "0" * 64, "a": "sha256:" + "0" * 64, "a/b.py": "sha256:" + "0" * 64},
])
def test_malformed_signed_subjects_are_rejected(openssl, signing_key, signed, tmp_path, bad_files):
    package_root, _ = signed
    envelope_path = tmp_path / "bad.json"
    core.write_envelope(envelope_path, core.sign_statement(
        openssl, signing_key[0], core.make_statement(MODULES_KIND, {"package": PACKAGE, "files": bad_files})))
    with pytest.raises(SignatureVerificationError):
        _verify(openssl, signing_key, envelope_path, package_root)


def test_read_verified_detects_change_after_verification(openssl, signing_key, signed):
    package_root, envelope_path = signed
    manifest = _verify(openssl, signing_key, envelope_path, package_root)
    (package_root / "sub" / "leaf.py").write_bytes(b"LEAF = 'tampered'\n")
    with pytest.raises(SignatureVerificationError, match="does not match"):
        manifest.read_verified("sub/leaf.py")
    with pytest.raises(SignatureVerificationError, match="not in the signed manifest"):
        manifest.read_verified("sub/other.py")
    with pytest.raises(SignatureVerificationError, match="invalid package-relative path"):
        manifest.read_verified("/etc/passwd")
    with pytest.raises(SignatureVerificationError, match="unsupported path component"):
        manifest.read_verified("../outside.py")


def test_read_verified_refuses_symlinked_parent_directory(openssl, signing_key, signed, tmp_path):
    package_root, envelope_path = signed
    manifest = _verify(openssl, signing_key, envelope_path, package_root)
    copy = tmp_path / "copy"
    _write_tree(copy)
    (package_root / "sub").rename(tmp_path / "moved-sub")
    symlink(package_root / "sub", copy / "sub", target_is_directory=True)
    with pytest.raises(SignatureVerificationError, match="cannot be opened safely|not a plain directory"):
        manifest.read_verified("sub/leaf.py")
    (package_root / "core.py").unlink()
    symlink(package_root / "core.py", copy / "core.py")
    with pytest.raises(SignatureVerificationError):
        manifest.read_verified("core.py")


def test_read_verified_lstat_fallback_refuses_symlinked_parent(openssl, signing_key, signed, tmp_path, monkeypatch):
    package_root, envelope_path = signed
    manifest = _verify(openssl, signing_key, envelope_path, package_root)
    monkeypatch.setattr(modules, "_O_DIRECTORY", 0)
    assert manifest.read_verified("sub/leaf.py") == TREE["sub/leaf.py"]
    copy = _write_tree(tmp_path / "copy")
    (package_root / "sub").rename(tmp_path / "moved-sub")
    symlink(package_root / "sub", copy / "sub", target_is_directory=True)
    with pytest.raises(SignatureVerificationError, match="not a plain directory"):
        manifest.read_verified("sub/leaf.py")


def test_modules_and_core_load_standalone_by_file_path_in_isolated_mode(openssl, signing_key, signed):
    package_root, envelope_path = signed
    source = Path(modules.__file__)
    imports = [line.split() for line in source.read_text(encoding="utf-8").splitlines()
               if line.startswith(("import ", "from "))]
    assert imports and all(not words[1].startswith("appsec_review") for words in imports)
    script = (
        "import importlib.util, sys\n"
        "def load(name, path):\n"
        "    spec = importlib.util.spec_from_file_location(name, path)\n"
        "    module = importlib.util.module_from_spec(spec)\n"
        "    sys.modules[name] = module\n"
        "    spec.loader.exec_module(module)\n"
        "    return module\n"
        "core_path, modules_path, envelope, root, keys = sys.argv[1:]\n"
        "try:\n"
        "    load('appsec_review_signing_modules_early', modules_path)\n"
        "except ImportError as error:\n"
        "    assert 'appsec_review_signing_core' in str(error)\n"
        "else:\n"
        "    raise SystemExit('loaded without core')\n"
        "core = load('appsec_review_signing_core', core_path)\n"
        "mods = load('appsec_review_signing_modules', modules_path)\n"
        "assert mods._core is core\n"
        f"manifest = mods.verify_modules(envelope, root, keys, core.OpenSSL({OPENSSL_BINARY!r}), package={PACKAGE!r})\n"
        "assert manifest.read_verified('core.py').startswith(b'def answer')\n"
        "assert not any(name.startswith('appsec_review.') or name == 'appsec_review' for name in sys.modules)\n"
        "print('ok')\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, str(Path(core.__file__)), str(source), str(envelope_path),
         str(package_root), str(signing_key[1])],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_relative_core_import_without_parent_package_raises_import_error():
    with pytest.raises(ImportError):
        exec("from . import core", {"__name__": "standalone", "__package__": ""})


def test_build_manifest_over_real_package_is_fast():
    package_root = Path(__file__).resolve().parents[2] / "src" / "appsec_review"
    started = time.monotonic()
    subject = build_manifest(package_root)
    elapsed = time.monotonic() - started
    assert subject["package"] == "appsec_review"
    assert "__init__.py" in subject["files"]
    assert "signing/modules.py" in subject["files"]
    assert not any("__pycache__" in relpath for relpath in subject["files"])
    assert elapsed < (30.0 if os.name == "nt" else 10.0)
