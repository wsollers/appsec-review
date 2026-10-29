"""Image-level ``sitecustomize`` body that enforces signed modules in every interpreter process.

Stdlib-only and standalone: deploy a copy as ``sitecustomize.py``. It loads ``bootstrap.py`` by file
path from the absolute directory in ``APPSEC_REVIEW_SIGNING_BOOTSTRAP_DIR`` and calls
``activate_from_environment()``. Any failure prints a message and ends the process with exit code
78 immediately; the interpreter never continues with unverified modules.
"""
import os
import sys


BOOTSTRAP_DIR_ENV = "APPSEC_REVIEW_SIGNING_BOOTSTRAP_DIR"
EXIT_VERIFICATION_FAILED = 78


def _load_bootstrap(directory):
    import importlib.util
    import stat

    path = os.path.join(directory, "bootstrap.py")
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:  # Windows reparse point
        raise ImportError(f"signing bootstrap must not be a symbolic link: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                         | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ImportError(f"signing bootstrap is not a regular file: {path}")
        data = handle.read()
    spec = importlib.util.spec_from_file_location("appsec_review_signing_bootstrap", path)
    module = importlib.util.module_from_spec(spec)
    module.__cached__ = None
    code = compile(data, path, "exec", dont_inherit=True)
    sys.modules[spec.name] = module
    exec(code, module.__dict__)
    return module


def activate():
    required = os.environ.get("APPSEC_REVIEW_REQUIRE_SIGNED_MODULES", "") == "1"
    directory = os.environ.get(BOOTSTRAP_DIR_ENV, "")
    if not directory:
        if required or os.environ.get("APPSEC_REVIEW_MODULE_SIGNATURE"):
            raise RuntimeError(f"signed module enforcement requires {BOOTSTRAP_DIR_ENV}")
        return None
    if not os.path.isabs(directory):
        raise RuntimeError(f"{BOOTSTRAP_DIR_ENV} must be an absolute path: {directory!r}")
    return _load_bootstrap(directory).activate_from_environment()


def main():
    try:
        activate()
    except BaseException as error:
        try:
            sys.stderr.write(f"appsec-review: signed module verification failed; refusing to start: {error}\n")
            sys.stderr.flush()
        finally:
            os._exit(EXIT_VERIFICATION_FAILED)


if __name__ in {"sitecustomize", "__main__"}:
    main()
