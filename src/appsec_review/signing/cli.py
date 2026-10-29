"""The ``appsec-review signing`` command group: operator keys, image signatures and file manifests.

Every command prints one JSON document and exits nonzero when anything failed. Private key material
is never printed. Configuration is loaded only when a command needs a ``[signing]`` value that was
not given on the command line.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
import contextlib
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any

from . import core as _core
from .core import OpenSSL, SignatureVerificationError, _write_new_file, key_id
from .images import EnvelopeImageVerifier, inspect_image_id, sign_image
from .modules import sign_modules, verify_modules
from .release_lib import sign_release_lib, verify_release_lib


DEFAULT_PRIVATE_KEY = Path("~/.config/appsec-review/signing/private/operator.pem")
BOOTSTRAP_FILES = ("bootstrap.py", "core.py", "modules.py", "import_hook.py", "release_lib.py",
                   "sitecustomize_shim.py")
PINNED_ID_SUFFIX = "image_id"

# Replaced by tests so ``docker image inspect`` never runs; OpenSSL keeps using subprocess.run.
_inspect_runner: Callable[..., subprocess.CompletedProcess] = subprocess.run

_FAILURES = (SignatureVerificationError, OSError, ValueError)


def add_parser(commands: argparse._SubParsersAction) -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--openssl", type=Path,
                        help="absolute OpenSSL binary (default: [signing].openssl)")
    signing = commands.add_parser(
        "signing", help="generate operator keys and sign or verify container images and Python modules")
    sub = signing.add_subparsers(dest="signing_command", required=True)

    keygen = sub.add_parser("keygen", parents=[common], help="generate an Ed25519 operator signing key")
    keygen.add_argument("--private-key", type=Path, default=DEFAULT_PRIVATE_KEY,
                        help=f"new private key path (default: {DEFAULT_PRIVATE_KEY}); never overwritten")
    keygen.add_argument("--trusted-keys-dir", type=Path,
                        help="also install the public key there as <key id hex>.pem")

    sign = sub.add_parser("sign-image", parents=[common], help="sign local container image IDs")
    sign.add_argument("references", nargs="*", metavar="REFERENCE")
    sign.add_argument("--all-pinned", action="store_true",
                      help="sign every enabled catalog image and configured image-ID pin that resolves "
                           "locally to exactly its pinned image")
    sign.add_argument("--builder-service-config", type=Path, action="append", default=[], metavar="PATH",
                      help="with --all-pinned, also sign the BuildKit worker, egress proxy and declared "
                           "input image IDs pinned by this bounded builder service operator configuration "
                           "(the file given to image_builder_service --config); may be repeated")
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--signatures-dir", type=Path,
                      help="envelope directory (default: [signing].image_signatures_dir)")

    verify = sub.add_parser("verify-image", parents=[common], help="verify local container image signatures")
    verify.add_argument("references", nargs="+", metavar="REFERENCE")
    verify.add_argument("--signatures-dir", type=Path,
                        help="envelope directory (default: [signing].image_signatures_dir)")
    verify.add_argument("--trusted-keys-dir", type=Path,
                        help="trust anchors (default: [signing].trusted_keys_dir)")

    modules = sub.add_parser("sign-modules", parents=[common],
                             help="sign the file manifest of an installed appsec_review package tree")
    modules.add_argument("--private-key", type=Path, required=True)
    modules.add_argument("--output", type=Path, required=True, metavar="ENVELOPE")
    modules.add_argument("--package-root", type=Path,
                         help="package directory (default: the installed appsec_review package)")

    check = sub.add_parser("verify-modules", parents=[common],
                           help="verify an installed package tree against a signed module manifest")
    check.add_argument("--envelope", type=Path, required=True)
    check.add_argument("--trusted-keys-dir", type=Path, required=True)
    check.add_argument("--package-root", type=Path,
                       help="package directory (default: the installed appsec_review package)")

    release = sub.add_parser("sign-release-lib", parents=[common],
                             help="sign the third-party file manifest of a native release lib directory")
    release.add_argument("--private-key", type=Path, required=True)
    release.add_argument("--output", type=Path, required=True, metavar="ENVELOPE")
    release.add_argument("--lib", type=Path, required=True,
                         help="release lib directory; its top-level appsec_review package is excluded")

    check_release = sub.add_parser("verify-release-lib", parents=[common],
                                   help="verify a native release lib directory against a signed library manifest")
    check_release.add_argument("--envelope", type=Path, required=True)
    check_release.add_argument("--trusted-keys-dir", type=Path, required=True)
    check_release.add_argument("--lib", type=Path, required=True)

    export = sub.add_parser("export-bootstrap",
                            help="copy the standalone module-verification bootstrap files into a directory")
    export.add_argument("directory", type=Path, metavar="DIR")
    return signing


def run(args: argparse.Namespace, load_config: Callable[[], Any]) -> int:
    """Run one ``signing`` subcommand; ``load_config`` returns the application configuration."""
    loaded: list[Any] = []

    def config() -> Any:
        if not loaded:
            loaded.append(load_config())
        return loaded[0]

    handler = _HANDLERS[args.signing_command]
    try:
        report, ok = handler(args, config)
    except _FAILURES as error:
        report, ok = {"error": str(error)}, False
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if ok else 1


def _openssl(args: argparse.Namespace, config: Callable[[], Any]) -> OpenSSL:
    binary = args.openssl if args.openssl is not None else config().signing.openssl
    return OpenSSL(str(binary))


def _package_root(value: Path | None) -> Path:
    if value is not None:
        return value
    import appsec_review
    return Path(appsec_review.__file__).resolve().parent


def _private_parent(path: Path) -> None:
    """Create the private key directory 0700, or require an existing one to be owned and private.

    Windows has no POSIX owner or mode bits: there the directory must still be a real directory (no
    link or reparse point), a new one gets a protected owner-only ACL, and its ACL must pass the
    ``"private"`` custody check (no broad principal may read or write it).
    """
    parent = path.parent
    created = not os.path.lexists(parent)
    if created:
        parent.mkdir(mode=0o700, parents=True)
        os.chmod(parent, 0o700)
    info = os.lstat(parent)
    if _core.is_link_or_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"private key directory must be a real directory: {parent}")
    if _core.windows_host():
        if created:
            _core.apply_windows_acl(parent, "private", directory=True)
        _core.check_windows_custody(parent, "private", "private key directory", directory=True)
        return
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError(f"private key directory is not owned by the current user: {parent}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError(f"private key directory must not be accessible to group or others (0700): {parent}")


def _keygen(args: argparse.Namespace, config: Callable[[], Any]) -> tuple[dict, bool]:
    private_key = Path(os.path.abspath(args.private_key.expanduser()))
    if os.path.lexists(private_key):
        raise FileExistsError(f"private key already exists; refusing to overwrite it: {private_key}")
    openssl = _openssl(args, config)
    _private_parent(private_key)
    openssl.generate_private_key(private_key)
    if _core.windows_host():
        _core.apply_windows_acl(private_key, "private", directory=False)
        _core.check_windows_custody(private_key, "private", "private key", directory=False)
    public_key_pem = openssl.public_key_pem(private_key)
    identity = key_id(openssl.public_key_der(public_key_pem))
    report: dict[str, Any] = {"key_id": identity, "private_key": str(private_key), "trusted_key": None}
    if args.trusted_keys_dir is not None:
        directory = Path(os.path.abspath(args.trusted_keys_dir.expanduser()))
        if not os.path.lexists(directory):
            directory.mkdir(mode=0o755, parents=True)
            os.chmod(directory, 0o755)
            if _core.windows_host():
                _core.apply_windows_acl(directory, "anchor", directory=True)
        elif _core.is_link_or_reparse_point(os.lstat(directory)) or not directory.is_dir():
            raise ValueError(f"trusted keys directory must be a real directory: {directory}")
        trusted = directory / f"{identity.removeprefix('sha256:')}.pem"
        _write_new_file(trusted, public_key_pem, 0o644)
        report["trusted_key"] = str(trusted)
    return report, True


def _inspect(reference: str) -> str:
    return inspect_image_id(reference, runner=_inspect_runner)


def pinned_images(catalog_images: Sequence[Mapping[str, Any]],
                  document: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every image pin the review depends on, as ``{"source", "tag", "image_id"}``.

    Starts from the pin gate's ``configured_pins`` (enabled catalog images, enabled jobs' ``tag`` /
    ``image_id`` and ``source_image_tag`` / ``source_image_id`` pairs) and adds every other
    ``*image_id`` setting of an enabled job or of one of its steps (for example the cve-bin-tool
    step's optional ``image_id``), including those inside arrays of tables (for example CodeQL's
    preinstalled ``build_image_id`` and ``runtime_image_id``). Such a pin's tag is the sibling
    ``<prefix>image_tag`` or ``<prefix>tag`` (or ``image`` for a bare ``image_id``) when present,
    otherwise ``None``.
    """
    from appsec_review.jobs.job_image_pin_verification.pins import configured_pins
    from appsec_review.runtime.selection import resolved_job_is_enabled

    pins = configured_pins(catalog_images, document)
    known = {pin["source"] for pin in pins}

    def walk(value: object, path: str) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if isinstance(key, str) and key.endswith(PINNED_ID_SUFFIX) and isinstance(child, str):
                    source = f"{path}.{key}"
                    if source in known:
                        continue
                    prefix = key[:-len(PINNED_ID_SUFFIX)]
                    names = (f"{prefix}image_tag", f"{prefix}tag") + (("image",) if not prefix else ())
                    tag = next((value[name] for name in names if isinstance(value.get(name), str)), None)
                    pins.append({"source": source, "tag": tag, "image_id": child})
                    known.add(source)
                else:
                    walk(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")

    for job_id, job in sorted(dict(document.get("jobs") or {}).items()):
        if isinstance(job, Mapping) and resolved_job_is_enabled(job_id, job):
            walk(job.get("settings") or {}, f"jobs.{job_id}.settings")
            for step_id, step in sorted(dict(job.get("steps") or {}).items()):
                if isinstance(step, Mapping):
                    walk(step.get("settings") or {}, f"jobs.{job_id}.steps.{step_id}.settings")
    return pins


def configured_image_pins(config: Any) -> list[dict[str, Any]]:
    """Read ``containers/catalog.toml`` and the resolved configuration of ``config`` into pins."""
    import tomllib
    from appsec_review.jobs.job_image_pin_verification.pins import CATALOG

    catalog_path = Path(config.runtime.repository_root) / CATALOG
    images = tomllib.loads(catalog_path.read_text(encoding="utf-8")).get("images", [])
    return pinned_images(images, json.loads(config.resolved_json))


def builder_service_image_pins(path: Path) -> list[dict[str, Any]]:
    """The image IDs a bounded builder service operator configuration pins, as ``pinned_images`` rows.

    Covers the BuildKit ``worker_image_id``, the egress ``proxy_image_id`` when egress is
    commissioned, and every declared ``[[image_builder_service.images]]`` input. The config gives
    only IDs (an input's alias is a Dockerfile name, not a Docker tag), so each ``tag`` is ``None``
    and the ID itself is inspected. Each row also names its ``config`` file.
    """
    from appsec_review.config.image_builder_service import load_image_builder_service

    path = Path(os.path.abspath(path.expanduser()))
    if not path.is_file():
        raise ValueError(f"builder service configuration is not a file: {path}")
    try:
        service = load_image_builder_service(path)
    except ValueError as error:
        raise ValueError(f"invalid builder service configuration {path}: {error}") from error
    entries = [("builder-service:worker", service.worker_image_id)]
    if service.proxy_image_id is not None:
        entries.append(("builder-service:proxy", service.proxy_image_id))
    entries.extend((f"builder-service:input:{image.alias}", image.image_id) for image in service.images)
    return [{"source": source, "tag": None, "image_id": image_id, "config": str(path)}
            for source, image_id in entries]


def _sign_all_pinned(openssl: OpenSSL, private_key: Path, signatures_dir: Path,
                     pins: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    resolved: dict[str, str | Exception] = {}
    signed: dict[str, str] = {}
    results = []
    for pin in pins:
        tag, pinned = pin.get("tag"), pin.get("image_id")
        row: dict[str, Any] = {"source": pin["source"], "tag": tag, "image_id": pinned,
                               "resolved_image_id": None, "envelope": None, "error": None}
        if "config" in pin:
            row["config"] = pin["config"]
        results.append(row)
        if pinned is None:
            row["status"] = "skipped_unpinned"
            row["error"] = "the catalog image has no image_id pin; sign it explicitly with sign-image REFERENCE"
            continue
        reference = tag if tag is not None else pinned
        if reference not in resolved:
            try:
                resolved[reference] = _inspect(reference)
            except SignatureVerificationError as error:
                resolved[reference] = error
        local = resolved[reference]
        if isinstance(local, Exception):
            row["status"], row["error"] = "inspect_failed", str(local)
            continue
        row["resolved_image_id"] = local
        if local != pinned:
            row["status"] = "mismatched"
            row["error"] = f"{reference} resolves to {local}, not the pinned {pinned}; not signed"
            continue
        try:
            if pinned not in signed:
                signed[pinned] = str(sign_image(openssl, private_key, pinned, signatures_dir))
        except _FAILURES as error:
            row["status"], row["error"] = "failed", str(error)
            continue
        row["status"], row["envelope"] = "signed", signed[pinned]
    return results


def _sign_image(args: argparse.Namespace, config: Callable[[], Any]) -> tuple[dict, bool]:
    if bool(args.references) == bool(args.all_pinned):
        raise ValueError("sign-image requires either REFERENCE... or --all-pinned, not both")
    if args.builder_service_config and not args.all_pinned:
        raise ValueError("--builder-service-config requires --all-pinned")
    private_key = args.private_key.expanduser()
    if not private_key.is_file():
        raise ValueError(f"private key is not a file: {private_key}")
    signatures_dir = args.signatures_dir if args.signatures_dir is not None \
        else config().signing.image_signatures_dir
    openssl = _openssl(args, config)
    if args.all_pinned:
        builder_pins = [pin for path in dict.fromkeys(args.builder_service_config)
                        for pin in builder_service_image_pins(path)]
        pins = configured_image_pins(config()) + builder_pins
        results = _sign_all_pinned(openssl, private_key, signatures_dir, pins)
        ok = all(row["status"] in {"signed", "skipped_unpinned"} for row in results)
        return {"signatures_dir": str(signatures_dir), "images": results}, ok
    results = []
    for reference in args.references:
        row: dict[str, Any] = {"reference": reference, "image_id": None, "envelope": None, "error": None}
        results.append(row)
        try:
            row["image_id"] = _inspect(reference)
            row["envelope"] = str(sign_image(openssl, private_key, row["image_id"], signatures_dir))
            row["status"] = "signed"
        except _FAILURES as error:
            row["status"], row["error"] = "failed", str(error)
    return ({"signatures_dir": str(signatures_dir), "images": results},
            all(row["status"] == "signed" for row in results))


def _verify_image(args: argparse.Namespace, config: Callable[[], Any]) -> tuple[dict, bool]:
    # An explicit verification always checks envelopes, whatever [signing].image_enforcement says.
    verifier = EnvelopeImageVerifier(
        signatures_dir=args.signatures_dir if args.signatures_dir is not None
        else config().signing.image_signatures_dir,
        trusted_keys_dir=args.trusted_keys_dir if args.trusted_keys_dir is not None
        else config().signing.trusted_keys_dir,
        openssl=_openssl(args, config))
    results = []
    for reference in args.references:
        row: dict[str, Any] = {"reference": reference, "image_id": None, "error": None}
        results.append(row)
        try:
            row["image_id"] = _inspect(reference)
            verifier.verify(row["image_id"], reference=reference)
            row["status"] = "verified"
        except _FAILURES as error:
            row["status"], row["error"] = "failed", str(error)
    return ({"signatures_dir": str(verifier.signatures_dir),
             "trusted_keys_dir": str(verifier.trusted_keys_dir), "images": results},
            all(row["status"] == "verified" for row in results))


def _sign_modules(args: argparse.Namespace, config: Callable[[], Any]) -> tuple[dict, bool]:
    root = _package_root(args.package_root).resolve()
    output = Path(os.path.abspath(args.output.expanduser()))
    if output.resolve().is_relative_to(root):
        raise ValueError(f"the envelope must be written outside the signed package tree: {output}")
    openssl = _openssl(args, config)
    output.parent.mkdir(parents=True, exist_ok=True)
    envelope = sign_modules(openssl, args.private_key.expanduser(), root, output)
    subject = envelope["statement"]["subject"]
    return {"envelope": str(output), "package": subject["package"], "package_root": str(root),
            "files": len(subject["files"]),
            "key_ids": [item["key_id"] for item in envelope["signatures"]]}, True


def _verify_modules(args: argparse.Namespace, config: Callable[[], Any]) -> tuple[dict, bool]:
    root = _package_root(args.package_root)
    report: dict[str, Any] = {"envelope": str(args.envelope), "package_root": str(root)}
    try:
        manifest = verify_modules(args.envelope, root, args.trusted_keys_dir, _openssl(args, config))
    except _FAILURES as error:
        return {**report, "status": "failed", "error": str(error)}, False
    return {**report, "status": "verified", "package": manifest.package,
            "package_root": str(manifest.root), "files": len(manifest.files)}, True


def _sign_release_lib(args: argparse.Namespace, config: Callable[[], Any]) -> tuple[dict, bool]:
    library = args.lib.resolve()
    output = Path(os.path.abspath(args.output.expanduser()))
    if output.resolve().is_relative_to(library):
        raise ValueError(f"the envelope must be written outside the signed release library: {output}")
    openssl = _openssl(args, config)
    output.parent.mkdir(parents=True, exist_ok=True)
    envelope = sign_release_lib(openssl, args.private_key.expanduser(), library, output)
    return {"envelope": str(output), "lib": str(library),
            "files": len(envelope["statement"]["subject"]["files"]),
            "key_ids": [item["key_id"] for item in envelope["signatures"]]}, True


def _verify_release_lib(args: argparse.Namespace, config: Callable[[], Any]) -> tuple[dict, bool]:
    report: dict[str, Any] = {"envelope": str(args.envelope), "lib": str(args.lib)}
    try:
        files = verify_release_lib(args.envelope, args.lib, args.trusted_keys_dir, _openssl(args, config))
    except _FAILURES as error:
        return {**report, "status": "failed", "error": str(error)}, False
    return {**report, "status": "verified", "files": len(files)}, True


def _write_copy(directory: Path, name: str, data: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            if hasattr(os, "fchmod"):
                os.fchmod(handle.fileno(), 0o644)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, directory / name)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def _export_bootstrap(args: argparse.Namespace, config: Callable[[], Any]) -> tuple[dict, bool]:
    from .core import _read_regular_file

    source = Path(__file__).resolve().parent
    directory = Path(os.path.abspath(args.directory.expanduser()))
    if os.path.lexists(directory):
        if os.path.islink(directory) or not directory.is_dir():
            raise ValueError(f"export directory must be a real directory, not a symbolic link: {directory}")
    else:
        directory.mkdir(mode=0o755, parents=True)
    for name in BOOTSTRAP_FILES:
        target = directory / name
        if os.path.lexists(target) and (os.path.islink(target) or not target.is_file()):
            raise ValueError(f"refusing to replace a symbolic link or non-regular file: {target}")
    contents = {name: _read_regular_file(source / name, 64 * 1024 * 1024, "bootstrap source file")
                for name in BOOTSTRAP_FILES}
    files = {}
    for name, data in contents.items():
        _write_copy(directory, name, data)
        files[name] = "sha256:" + hashlib.sha256(data).hexdigest()
    return {"directory": str(directory), "files": files}, True


_HANDLERS: dict[str, Callable[[argparse.Namespace, Callable[[], Any]], tuple[dict, bool]]] = {
    "keygen": _keygen,
    "sign-image": _sign_image,
    "verify-image": _verify_image,
    "sign-modules": _sign_modules,
    "verify-modules": _verify_modules,
    "sign-release-lib": _sign_release_lib,
    "verify-release-lib": _verify_release_lib,
    "export-bootstrap": _export_bootstrap,
}


__all__ = ["BOOTSTRAP_FILES", "DEFAULT_PRIVATE_KEY", "add_parser", "builder_service_image_pins",
           "configured_image_pins", "pinned_images", "run"]
