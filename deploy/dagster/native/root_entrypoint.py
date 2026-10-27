"""Install into a root-controlled, read-only release; never run this checkout as root."""
from __future__ import annotations

import argparse
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


def release_paths(entrypoint: Path) -> tuple[Path, Path]:
    trusted_path(entrypoint)
    root = entrypoint.parent
    library = root / "lib"
    trusted_path(library, directory=True)
    for path in (root, library):
        if not os.statvfs(path).f_flag & os.ST_RDONLY:
            raise PermissionError("root service requires a separately installed read-only release")
    trusted_path(library / "appsec_review" / "__init__.py")
    trusted_path(library / "appsec_review" / "container_runtime" / "image_builder_service.py")
    return root, library


def launch_spec(python: Path, entrypoint: Path, configuration: Path, *, operation: str = "serve") -> dict:
    """Pure launch specification; it neither installs nor starts privileged software."""
    trusted_path(python)
    if not python.stat().st_mode & 0o111:
        raise PermissionError("root interpreter is not executable")
    root, _ = release_paths(entrypoint)
    trusted_path(configuration)
    if configuration.stat().st_mode & 0o077:
        raise PermissionError("root service configuration must be private")
    if operation not in {"serve", "reserve-lifetime", "reconcile-admission", "release-lifetime"}:
        raise ValueError("unsupported root lifecycle operation")
    argv = (str(python), "-I", "-S", str(entrypoint), "--config", str(configuration))
    if operation != "serve":
        argv += ("--operation", operation)
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
                                               "release-lifetime"), default="serve")
    args = parser.parse_args(argv)
    specification = launch_spec(Path(sys.executable), Path(__file__).absolute(), args.config,
                                operation=args.operation)
    _, library = release_paths(Path(__file__).absolute())
    standard_library = list(sys.path)
    for value in standard_library:
        path = Path(value)
        if not path.is_absolute():
            raise PermissionError("root interpreter has a relative import path")
        trusted_path(path if path.exists() else path.parent, directory=not path.is_file())
    os.environ.clear()
    os.environ.update(ROOT_ENVIRONMENT)
    os.chdir(specification["cwd"])
    # -S prevents editable-install .pth hooks; only the installed release is added.
    sys.path[:] = [str(library), *standard_library]
    sys.argv[:] = ["appsec-review-image-builder", "--config", str(args.config)]
    if args.operation != "serve":
        sys.argv.append("--" + args.operation)
    runpy.run_module("appsec_review.container_runtime.image_builder_service", run_name="__main__")


if __name__ == "__main__":
    main()
