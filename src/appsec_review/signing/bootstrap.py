"""Verify a signed package tree, install the verified import hook, then run a module from it.

Stdlib-only and standalone: this file has no package-relative imports and is deployed as a copy
outside the verified tree, in one directory together with copies of ``core.py``, ``modules.py``
and ``import_hook.py``. It loads those siblings by file path and registers them as
``appsec_review_signing_core``, ``appsec_review_signing_modules`` and
``appsec_review_signing_import_hook``. Loaders that load this file by path register it as
``appsec_review_signing_bootstrap``.

Run it as ``python -I -S bootstrap.py --envelope E --package-root R --trusted-keys K --module M
[-- args...]``: nothing from the package executes before the envelope and the whole installed
tree are verified, and every package import afterwards is served only from verified bytes.
Any verification failure is fatal; nothing here reports an unverifiable tree as trusted.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import runpy
import stat
import sys


CORE_NAME = "appsec_review_signing_core"
MODULES_NAME = "appsec_review_signing_modules"
IMPORT_HOOK_NAME = "appsec_review_signing_import_hook"
BOOTSTRAP_NAME = "appsec_review_signing_bootstrap"
VERIFIER_FILES = ((CORE_NAME, "core.py"), (MODULES_NAME, "modules.py"), (IMPORT_HOOK_NAME, "import_hook.py"))

DEFAULT_PACKAGE = "appsec_review"
SIGNATURE_ENV = "APPSEC_REVIEW_MODULE_SIGNATURE"
MODULE_ROOT_ENV = "APPSEC_REVIEW_MODULE_ROOT"
TRUSTED_KEYS_ENV = "APPSEC_REVIEW_TRUSTED_KEYS_DIR"
OPENSSL_ENV = "APPSEC_REVIEW_OPENSSL"
REQUIRE_ENV = "APPSEC_REVIEW_REQUIRE_SIGNED_MODULES"
EXIT_VERIFICATION_FAILED = 78
MAX_SOURCE_BYTES = 4 * 1024 * 1024

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _is_link(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def read_source(path):
    """Read a regular, non-symlink source file once, refusing anything unbounded."""
    path = Path(os.path.abspath(path))
    try:
        if _is_link(os.lstat(path)):
            raise ImportError(f"signing verifier file must not be a symbolic link: {path}")
        descriptor = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_BINARY)
    except OSError as error:
        raise ImportError(f"signing verifier file cannot be opened: {path}: {error}") from error
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ImportError(f"signing verifier file is not a regular file: {path}")
        data = handle.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise ImportError(f"signing verifier file exceeds {MAX_SOURCE_BYTES} bytes: {path}")
    return path, data


def load_source(name, path):
    """Execute exactly the bytes read once from ``path`` as top-level module ``name``."""
    path, data = read_source(path)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None:
        raise ImportError(f"cannot create a module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    module.__cached__ = None
    code = compile(data, str(path), "exec", dont_inherit=True)
    sys.modules[name] = module
    try:
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _same_file(module, path):
    filename = getattr(module, "__file__", None)
    return isinstance(filename, str) and os.path.abspath(filename) == str(path)


def load_verifier(directory):
    """Load ``core``, ``modules`` and ``import_hook`` from ``directory`` under their standalone names.

    Reuses an existing registration only when it was loaded from the same file; a registration from
    anywhere else is refused. A failed load removes every registration it added.
    """
    directory = Path(os.path.abspath(directory))
    try:
        info = os.lstat(directory)
    except OSError as error:
        raise ImportError(f"signing verifier directory cannot be inspected: {directory}: {error}") from error
    if _is_link(info) or not stat.S_ISDIR(info.st_mode):
        raise ImportError(f"signing verifier directory must be a plain directory: {directory}")
    loaded = []
    added = []
    try:
        for name, filename in VERIFIER_FILES:
            path = directory / filename
            existing = sys.modules.get(name)
            if existing is not None:
                if not _same_file(existing, path):
                    raise ImportError(f"{name} is already loaded from somewhere other than {path}")
                loaded.append(existing)
                continue
            loaded.append(load_source(name, path))
            added.append(name)
    except BaseException:
        for name in added:
            sys.modules.pop(name, None)
        raise
    return tuple(loaded)


def _verifier_directory():
    return Path(os.path.abspath(__file__)).parent


def activate(*, envelope, package_root, trusted_keys_dir, openssl=None, package=DEFAULT_PACKAGE):
    """Verify the signed tree and install the import hook before any package code can run.

    ``openssl`` defaults to the host's ``core.default_openssl()``.

    Returns the installed finder. The package's parent directory is appended to ``sys.path`` only
    after the hook is installed; the hook serves the package regardless of path order.
    """
    sys.dont_write_bytecode = True
    core, modules, import_hook = load_verifier(_verifier_directory())
    try:
        verifier = core.OpenSSL(None if openssl is None else os.fspath(openssl))
        verifier.self_test()
        manifest = modules.verify_modules(envelope, package_root, trusted_keys_dir, verifier, package=package)
        finder = import_hook.install_verified_import_hook(manifest)
    except core.SignatureVerificationError:
        raise
    except Exception as error:
        raise core.SignatureVerificationError(f"module signature verification failed: {error}") from error
    site = str(manifest.root.parent)
    if site not in sys.path:
        sys.path.append(site)
    return finder


def _environment_error(message):
    core = load_verifier(_verifier_directory())[0]
    return core.SignatureVerificationError(message)


def activate_from_environment(environ=None):
    """Activate from ``APPSEC_REVIEW_*`` variables; return ``None`` only when nothing requires it."""
    environ = os.environ if environ is None else environ
    require = environ.get(REQUIRE_ENV, "")
    if require not in {"", "0", "1"}:
        raise _environment_error(f"{REQUIRE_ENV} must be 0 or 1, not {require!r}")
    envelope = environ.get(SIGNATURE_ENV, "")
    if not envelope and require != "1":
        return None
    values = {name: environ.get(name, "") for name in (SIGNATURE_ENV, MODULE_ROOT_ENV, TRUSTED_KEYS_ENV)}
    missing = sorted(name for name, value in values.items() if not value)
    if missing:
        raise _environment_error("signed module enforcement requires " + ", ".join(missing))
    openssl = environ.get(OPENSSL_ENV, "") or None
    checked = (*values.items(), (OPENSSL_ENV, openssl)) if openssl else tuple(values.items())
    relative = sorted(name for name, value in checked if not os.path.isabs(value))
    if relative:
        raise _environment_error("signed module paths must be absolute: " + ", ".join(relative))
    return activate(envelope=Path(values[SIGNATURE_ENV]), package_root=Path(values[MODULE_ROOT_ENV]),
                    trusted_keys_dir=Path(values[TRUSTED_KEYS_ENV]), openssl=openssl)


def _parser():
    parser = argparse.ArgumentParser(
        prog="bootstrap.py", description="Verify a signed package tree, then run one of its modules.")
    parser.add_argument("--envelope", required=True, type=Path)
    parser.add_argument("--package-root", required=True, type=Path)
    parser.add_argument("--trusted-keys", required=True, type=Path)
    parser.add_argument("--openssl", help="absolute OpenSSL binary (default: the host default)")
    parser.add_argument("--package", default=DEFAULT_PACKAGE)
    parser.add_argument("--module", required=True)
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" in argv:
        separator = argv.index("--")
        argv, module_args = argv[:separator], argv[separator + 1:]
    else:
        module_args = []
    args = _parser().parse_args(argv)
    try:
        if not sys.flags.isolated or not sys.flags.no_site:
            raise RuntimeError("signed module bootstrap requires Python -I -S")
        openssl = () if args.openssl is None else (Path(args.openssl),)
        for path in (args.envelope, args.package_root, args.trusted_keys, *openssl):
            if not path.is_absolute():
                raise RuntimeError(f"signed module bootstrap paths must be absolute: {path}")
        finder = activate(envelope=args.envelope, package_root=args.package_root,
                          trusted_keys_dir=args.trusted_keys, openssl=args.openssl, package=args.package)
        if not finder.claims(args.module):
            raise RuntimeError(f"module {args.module!r} is not in the verified package {args.package!r}")
    except Exception as error:
        sys.stderr.write(f"appsec-review: signed module verification failed: {error}\n")
        sys.stderr.flush()
        return EXIT_VERIFICATION_FAILED
    sys.argv[:] = [args.module, *module_args]
    runpy.run_module(args.module, run_name="__main__", alter_sys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
