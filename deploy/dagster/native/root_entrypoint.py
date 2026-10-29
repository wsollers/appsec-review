"""Install into a root-controlled, read-only release; never run this checkout as root."""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import runpy
import stat
import sys


ROOT_ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "HOME": "/nonexistent",
}
OPENSSL = Path("/usr/bin/openssl")
SIGNING_BOOTSTRAP_FILES = ("bootstrap.py", "core.py", "modules.py", "import_hook.py")
SIGNING_BOOTSTRAP_MODULE = "appsec_review_signing_bootstrap"


def trusted_path(path: Path, *, directory: bool = False) -> None:
    if not path.is_absolute() or path.resolve() != path:
        raise PermissionError("root entrypoint paths must be canonical and direct")
    for current in (*reversed(path.parents), path):
        metadata = current.lstat()
        if (metadata.st_uid != 0 or metadata.st_mode & 0o022
                or stat.S_ISLNK(metadata.st_mode)):
            raise PermissionError("root code/configuration is writable or owned by a client")
        expected_directory = current != path or directory
        if not (stat.S_ISDIR(metadata.st_mode) if expected_directory else stat.S_ISREG(metadata.st_mode)):
            raise PermissionError("root entrypoint path has an unsupported type")


def signing_paths(root: Path) -> dict[str, Path]:
    """Root-controlled module envelope, trust anchors and standalone verifier of a release."""
    signing = root / "signing"
    paths = {
        "envelope": signing / "python-modules.json",
        "trusted_keys": signing / "trusted-keys",
        "bootstrap": signing / "bootstrap",
    }
    for directory in (signing, paths["trusted_keys"], paths["bootstrap"]):
        trusted_path(directory, directory=True)
    trusted_path(paths["envelope"])
    for name in SIGNING_BOOTSTRAP_FILES:
        trusted_path(paths["bootstrap"] / name)
    for key in sorted(paths["trusted_keys"].iterdir()):
        trusted_path(key)
    return paths


def release_paths(entrypoint: Path) -> tuple[Path, Path]:
    trusted_path(entrypoint)
    root = entrypoint.parent
    library = root / "lib"
    trusted_path(library, directory=True)
    signing = signing_paths(root)
    for path in (root, library, signing["envelope"].parent):
        if not os.statvfs(path).f_flag & os.ST_RDONLY:
            raise PermissionError("root service requires a separately installed read-only release")
    trusted_path(library / "appsec_review" / "__init__.py")
    trusted_path(library / "appsec_review" / "container_runtime" / "image_builder_service.py")
    return root, library


def load_signing_bootstrap(path: Path):
    """Execute the trusted standalone verifier from bytes read once, without following links."""
    trusted_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise PermissionError("signing bootstrap is not a regular file")
        data = handle.read()
    spec = importlib.util.spec_from_file_location(SIGNING_BOOTSTRAP_MODULE, path)
    if spec is None:
        raise PermissionError("signing bootstrap cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    module.__cached__ = None
    sys.modules[SIGNING_BOOTSTRAP_MODULE] = module
    exec(compile(data, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def launch_spec(python: Path, entrypoint: Path, configuration: Path, *, operation: str = "serve",
                prior_configuration: Path | None = None) -> dict:
    """Pure launch specification; it neither installs nor starts privileged software."""
    trusted_path(python)
    if not python.stat().st_mode & 0o111:
        raise PermissionError("root interpreter is not executable")
    root, _ = release_paths(entrypoint)
    trusted_path(configuration)
    if configuration.stat().st_mode & 0o077:
        raise PermissionError("root service configuration must be private")
    if operation not in {"serve", "reserve-lifetime", "reconcile-admission", "release-lifetime",
                         "finalize-commissioning", "reconcile-retired-admission", "release-prior-lifetime",
                         "reconcile-prior-engine"}:
        raise ValueError("unsupported root lifecycle operation")
    if (operation in {"reconcile-retired-admission", "release-prior-lifetime", "reconcile-prior-engine"}) != (
            prior_configuration is not None):
        raise ValueError("retired reconciliation requires its separate prior configuration")
    if prior_configuration is not None:
        trusted_path(prior_configuration)
        if prior_configuration.stat().st_mode & 0o077:
            raise PermissionError("prior root configuration must be private")
    argv = (str(python), "-I", "-S", str(entrypoint), "--config", str(configuration))
    if operation != "serve":
        argv += ("--operation", operation)
    if prior_configuration is not None:
        argv += ("--prior-config", str(prior_configuration))
    return {
        "argv": argv,
        "cwd": str(root),
        "environment": dict(ROOT_ENVIRONMENT),
    }


def main(argv: list[str] | None = None) -> None:
    if os.geteuid() != 0 or not sys.flags.isolated or not sys.flags.no_site:
        raise PermissionError("installed root service requires root and Python -I -S")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--operation", choices=("serve", "reserve-lifetime", "reconcile-admission",
                                               "release-lifetime", "finalize-commissioning",
                                               "reconcile-retired-admission", "release-prior-lifetime",
                                               "reconcile-prior-engine"), default="serve")
    parser.add_argument("--prior-config", type=Path)
    args = parser.parse_args(argv)
    specification = launch_spec(Path(sys.executable), Path(__file__).absolute(), args.config,
                                operation=args.operation, prior_configuration=args.prior_config)
    root, library = release_paths(Path(__file__).absolute())
    signing = signing_paths(root)
    trusted_path(OPENSSL)
    standard_library = list(sys.path)
    for value in standard_library:
        path = Path(value)
        if not path.is_absolute():
            raise PermissionError("root interpreter has a relative import path")
        trusted_path(path if path.exists() else path.parent, directory=not path.is_file())
    os.environ.clear()
    os.environ.update(ROOT_ENVIRONMENT)
    os.chdir(specification["cwd"])
    sys.dont_write_bytecode = True
    # Nothing from lib runs before the signed tree is verified and the import hook serves it.
    bootstrap = load_signing_bootstrap(signing["bootstrap"] / "bootstrap.py")
    bootstrap.activate(envelope=signing["envelope"], package_root=library / "appsec_review",
                       trusted_keys_dir=signing["trusted_keys"], openssl=str(OPENSSL))
    # -S prevents editable-install .pth hooks; only the installed release is added.
    sys.path[:] = [*standard_library, str(library)]
    sys.argv[:] = ["appsec-review-image-builder", "--config", str(args.config)]
    if args.prior_config is not None:
        sys.argv.extend(("--" + args.operation, str(args.prior_config)))
    elif args.operation != "serve":
        sys.argv.append("--" + args.operation)
    runpy.run_module("appsec_review.container_runtime.image_builder_service", run_name="__main__")


if __name__ == "__main__":
    main()
