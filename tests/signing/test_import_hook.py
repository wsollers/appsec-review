"""Unit tests for the verified import hook, run in fresh isolated interpreters."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import textwrap
import types
from dataclasses import dataclass

import pytest

from appsec_review.signing import core, import_hook, modules
from appsec_review.signing.core import OpenSSL, key_id
from appsec_review.signing.import_hook import VerifiedFinder, VerifiedNamespaceLoader, VerifiedSourceLoader
from appsec_review.signing.modules import VerifiedManifest, sign_modules
from tests.signing._host import OPENSSL_BINARY

PACKAGE = "demo_pkg"
TREE = {
    "__init__.py": b"VALUE = 1\n",
    "core.py": b"from . import helper\n\ndef answer():\n    return helper.BASE + 1\n",
    "helper.py": b"BASE = 41\n",
    "boom.py": b"def fail():\n    raise RuntimeError('boom marker')\n",
    "sub/__init__.py": b"from .leaf import LEAF\n",
    "sub/leaf.py": b"LEAF = 'leaf'\n",
    "nsdir/item.py": b"from ..sub import LEAF\nITEM = LEAF + '!'\n",
    "data/schema.json": b"{\"a\": 1}\n",
}

pytestmark = pytest.mark.skipif(not os.path.isfile(OPENSSL_BINARY), reason="system OpenSSL is required")

PRELUDE = f"""\
import importlib, importlib.util, pathlib, sys
sys.dont_write_bytecode = True
def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
core_path, modules_path, hook_path, envelope, root, keys = sys.argv[1:7]
core = _load("appsec_review_signing_core", core_path)
mods = _load("appsec_review_signing_modules", modules_path)
hook = _load("appsec_review_signing_import_hook", hook_path)
assert hook._modules is mods
manifest = mods.verify_modules(envelope, root, keys, core.OpenSSL({OPENSSL_BINARY!r}), package={PACKAGE!r})
ROOT = pathlib.Path(root)
SITE = str(ROOT.parent)
def expect_error(error_type, call, *args, match=""):
    try:
        call(*args)
    except error_type as error:
        assert match in str(error), str(error)
        return error
    raise AssertionError(f"{{call}}{{args}} did not raise {{error_type.__name__}}")
"""


@dataclass(frozen=True)
class Signed:
    root: Path
    envelope: Path
    trusted: Path


@pytest.fixture(scope="module")
def signing_key(tmp_path_factory) -> tuple[OpenSSL, Path, Path]:
    openssl = OpenSSL(OPENSSL_BINARY)
    root = tmp_path_factory.mktemp("import-hook-keys")
    private_key = openssl.generate_private_key(root / "private" / "modules.pem")
    public_key_pem = openssl.public_key_pem(private_key)
    trusted_dir = root / "trusted-keys"
    trusted_dir.mkdir()
    (trusted_dir / f"{key_id(openssl.public_key_der(public_key_pem)).removeprefix('sha256:')}.pem").write_bytes(
        public_key_pem)
    return openssl, private_key, trusted_dir


@pytest.fixture
def signed(signing_key, tmp_path) -> Signed:
    openssl, private_key, trusted_dir = signing_key
    root = tmp_path / "site" / PACKAGE
    for relpath, data in TREE.items():
        (root / relpath).parent.mkdir(parents=True, exist_ok=True)
        (root / relpath).write_bytes(data)
    envelope = tmp_path / "python-modules.json"
    sign_modules(openssl, private_key, root, envelope, package=PACKAGE)
    return Signed(root.resolve(), envelope, trusted_dir)


def _run(signed: Signed, scenario: str, *extra: str) -> None:
    script = PRELUDE + textwrap.dedent(scenario) + "\nprint('ok')\n"
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, core.__file__, modules.__file__, import_hook.__file__,
         str(signed.envelope), str(signed.root), str(signed.trusted), *extra],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == "ok"


def test_verified_imports_packages_namespaces_and_dynamic_imports(signed):
    _run(signed, """
        import inspect, runpy
        finder = hook.install_verified_import_hook(manifest)
        assert sys.meta_path[0] is finder and sys.dont_write_bytecode
        import demo_pkg, demo_pkg.core
        assert demo_pkg.VALUE == 1 and demo_pkg.core.answer() == 42
        assert demo_pkg.__file__ == str(ROOT / "__init__.py") and demo_pkg.__cached__ is None
        assert demo_pkg.__spec__.cached is None and demo_pkg.__spec__.has_location
        assert demo_pkg.__path__ == [str(ROOT)]
        assert isinstance(demo_pkg.__loader__, hook.VerifiedSourceLoader)
        assert demo_pkg.__loader__.get_filename("demo_pkg") == demo_pkg.__file__
        assert demo_pkg.core.__loader__.get_source("demo_pkg.core") == (ROOT / "core.py").read_text()
        assert inspect.getsource(demo_pkg.core.answer).startswith("def answer")
        from demo_pkg import sub
        assert sub.LEAF == "leaf" and sub.__path__ == [str(ROOT / "sub")]
        item = importlib.import_module("demo_pkg.nsdir.item")
        assert item.ITEM == "leaf!"
        namespace = sys.modules["demo_pkg.nsdir"]
        assert namespace.__path__ == [str(ROOT / "nsdir")] and getattr(namespace, "__file__", None) is None
        assert namespace.__spec__.origin is None and namespace.__loader__.is_package("demo_pkg.nsdir")
        assert importlib.import_module(".leaf", "demo_pkg.sub") is sys.modules["demo_pkg.sub.leaf"]
        assert runpy.run_module("demo_pkg.helper")["__file__"] == str(ROOT / "helper.py")
        assert not list(ROOT.rglob("__pycache__"))
        assert not any(name == "appsec_review" or name.startswith("appsec_review.") for name in sys.modules)
        finder.uninstall()
        assert finder not in sys.meta_path
    """)


def test_module_modified_after_verification_fails_to_import(signed):
    _run(signed, """
        (ROOT / "helper.py").write_text("BASE = 0\\n")
        hook.install_verified_import_hook(manifest)
        import demo_pkg
        expect_error(core.SignatureVerificationError, importlib.import_module, "demo_pkg.core", match="helper.py")
        assert "demo_pkg.helper" not in sys.modules and "demo_pkg.core" not in sys.modules
    """)


def test_unlisted_modules_never_fall_back_to_bytecode_or_later_path_entries(signed, tmp_path):
    core_py = signed.root / "core.py"
    tampered = tmp_path / "tampered_core.py"
    tampered.write_bytes(TREE["core.py"].replace(b"+ 1", b"- 1"))
    source_stat = core_py.stat()
    os.utime(tampered, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))
    py_compile.compile(str(tampered), cfile=importlib.util.cache_from_source(str(core_py)), doraise=True,
                       invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
    alternate = tmp_path / "alternate"
    (alternate / PACKAGE).mkdir(parents=True)
    (alternate / PACKAGE / "__init__.py").write_bytes(b"VALUE = 'alternate'\n")
    (alternate / PACKAGE / "alt_only.py").write_bytes(b"ALT = 1\n")
    (alternate / "sourceless_src.py").write_bytes(b"SOURCELESS = 1\n")
    control = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c",
         "import sys; sys.path.insert(0, sys.argv[1]); import demo_pkg.core; print(demo_pkg.core.answer())",
         str(signed.root.parent)], capture_output=True, text=True, timeout=60)
    assert control.stdout.strip() == "40", control.stderr

    _run(signed, """
        import py_compile
        alternate = sys.argv[7]
        (ROOT / "extra.py").write_text("EXTRA = 'unsigned'\\n")
        py_compile.compile(alternate + "/sourceless_src.py", cfile=str(ROOT / "sourceless.pyc"), doraise=True)
        sys.path[:0] = [SITE]
        sys.path.append(alternate)
        finder = hook.install_verified_import_hook(manifest)
        import demo_pkg.core
        assert demo_pkg.core.answer() == 42
        for name in ("demo_pkg.extra", "demo_pkg.sourceless", "demo_pkg.alt_only", "demo_pkg.sub.missing",
                     "demo_pkg.data.schema", "demo_pkg.not-an-identifier"):
            assert expect_error(ModuleNotFoundError, importlib.import_module, name).name == name
        expect_error(ModuleNotFoundError, importlib.util.find_spec, "demo_pkg.extra")
        demo_pkg.__path__.append(alternate + "/demo_pkg")
        expect_error(ModuleNotFoundError, importlib.import_module, "demo_pkg.alt_only")
        finder.uninstall()
        assert importlib.import_module("demo_pkg.alt_only").ALT == 1
        assert importlib.import_module("demo_pkg.sourceless").SOURCELESS == 1
    """, str(alternate))


def test_resources_are_read_through_the_manifest(signed):
    _run(signed, """
        from importlib.resources import files
        hook.install_verified_import_hook(manifest)
        package = files("demo_pkg")
        schema = package.joinpath("data/schema.json")
        assert schema.read_bytes() == b'{"a": 1}\\n' and schema.is_file() and not schema.is_dir()
        assert (files("demo_pkg.data") / "schema.json").read_text(encoding="utf-8") == '{"a": 1}\\n'
        with schema.open("rb") as handle:
            assert handle.read() == b'{"a": 1}\\n'
        with schema.open("r", encoding="utf-8") as handle:
            assert handle.read() == '{"a": 1}\\n'
        assert [child.name for child in files("demo_pkg.sub").iterdir()] == ["__init__.py", "leaf.py"]
        assert package.joinpath("data").is_dir() and package.joinpath("nsdir", "item.py").is_file()
        assert files("demo_pkg.core").joinpath("helper.py").read_bytes() == b"BASE = 41\\n"
        (ROOT / "data" / "unlisted.txt").write_text("unsigned")
        assert [child.name for child in package.joinpath("data").iterdir()] == ["schema.json"]
        expect_error(FileNotFoundError, package.joinpath("data/unlisted.txt").read_bytes)
        expect_error(IsADirectoryError, package.joinpath("data").read_bytes)
        expect_error(ValueError, package.joinpath, "../escape")
        expect_error(ValueError, package.joinpath, "/etc/passwd")
        expect_error(ValueError, schema.open, "wb")
        (ROOT / "data" / "schema.json").write_bytes(b'{"a": 2}\\n')
        expect_error(core.SignatureVerificationError, schema.read_bytes, match="does not match")
        expect_error(core.SignatureVerificationError, schema.read_text, match="does not match")
    """)


def test_traceback_shows_filename_and_verified_source_lines(signed):
    _run(signed, """
        import traceback
        hook.install_verified_import_hook(manifest)
        import demo_pkg.boom
        (ROOT / "boom.py").write_text("def fail():\\n    raise RuntimeError('boom marker')  # changed on disk\\n")
        try:
            demo_pkg.boom.fail()
        except RuntimeError:
            text = traceback.format_exc()
        assert f'File "{ROOT / "boom.py"}", line 2, in fail' in text, text
        assert "raise RuntimeError('boom marker')" in text and "changed on disk" not in text, text
    """)


@pytest.mark.parametrize(("setup", "match"), [
    ("sys.path.insert(0, SITE)\nimport demo_pkg.sub, demo_pkg.nsdir.item", None),
    ("(ROOT / 'helper.py').write_text('BASE = 0\\n')\nsys.path.insert(0, SITE)\nimport demo_pkg.helper",
     "helper.py"),
    ("(ROOT / 'extra.py').write_text('X = 1\\n')\nsys.path.insert(0, SITE)\nimport demo_pkg.extra", "is not signed"),
    ("sys.path.insert(0, sys.argv[7])\nimport demo_pkg", "not the verified __init__.py"),
], ids=["clean", "tampered", "unlisted", "foreign"])
def test_already_imported_claimed_modules_are_reverified(signed, tmp_path, setup, match):
    foreign = tmp_path / "foreign"
    (foreign / PACKAGE).mkdir(parents=True)
    (foreign / PACKAGE / "__init__.py").write_bytes(TREE["__init__.py"])
    if match is None:
        check = """
            finder = hook.install_verified_import_hook(manifest)
            import demo_pkg.core
            assert demo_pkg.core.answer() == 42 and isinstance(demo_pkg.core.__loader__, hook.VerifiedSourceLoader)
        """
    else:
        check = f"""
            expect_error(core.SignatureVerificationError, hook.install_verified_import_hook, manifest, match={match!r})
            assert not any(isinstance(finder, hook.VerifiedFinder) for finder in sys.meta_path)
        """
    _run(signed, setup + "\n" + textwrap.dedent(check), str(foreign))


def _manifest(tmp_path: Path, *relpaths: str) -> VerifiedManifest:
    files = {relpath: "sha256:" + "0" * 64 for relpath in ("__init__.py", *relpaths)}
    return VerifiedManifest(package=PACKAGE, root=tmp_path, files=types.MappingProxyType(files))


def test_finder_resolves_only_from_the_manifest(tmp_path):
    finder = VerifiedFinder(_manifest(tmp_path, "mod.py", "pkg/__init__.py", "ns/deep/x.txt", "amb.py",
                                      "amb/__init__.py"))
    assert finder.find_spec("other") is None and finder.find_spec("demo_pkgx") is None
    root_spec = finder.find_spec(PACKAGE)
    assert isinstance(root_spec.loader, VerifiedSourceLoader) and root_spec.origin == str(tmp_path / "__init__.py")
    assert root_spec.submodule_search_locations == [str(tmp_path)] and root_spec.cached is None
    module_spec = finder.find_spec("demo_pkg.mod", ["/elsewhere"])
    assert module_spec.submodule_search_locations is None and not module_spec.loader.is_package("demo_pkg.mod")
    assert finder.find_spec("demo_pkg.pkg").submodule_search_locations == [str(tmp_path / "pkg")]
    for name in ("demo_pkg.ns", "demo_pkg.ns.deep"):
        spec = finder.find_spec(name)
        assert isinstance(spec.loader, VerifiedNamespaceLoader) and spec.origin is None
    with pytest.raises(ImportError, match="both a package and a module") as raised:
        finder.find_spec("demo_pkg.amb")
    assert not isinstance(raised.value, ModuleNotFoundError)
    for name in ("demo_pkg.missing", "demo_pkg.ns.deep.x", "demo_pkg.a/b", "demo_pkg..mod"):
        with pytest.raises(ModuleNotFoundError):
            finder.find_spec(name)
    with pytest.raises(ImportError, match="cannot handle"):
        module_spec.loader.get_source("demo_pkg.pkg")
    with pytest.raises(TypeError):
        VerifiedFinder(object())


def test_import_hook_loads_standalone_only_after_modules(monkeypatch):
    source = Path(import_hook.__file__)
    imports = [line.split() for line in source.read_text(encoding="utf-8").splitlines()
               if line.startswith(("import ", "from "))]
    assert imports and all(not words[1].startswith("appsec_review") for words in imports)
    monkeypatch.delitem(sys.modules, "appsec_review_signing_modules", raising=False)
    spec = importlib.util.spec_from_file_location("appsec_review_signing_import_hook_probe", source)
    with pytest.raises(ImportError, match="appsec_review_signing_modules"):
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
