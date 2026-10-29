"""Signed manifests over an installed Python package tree.

Stdlib-only and loadable either as ``appsec_review.signing.modules`` or standalone by file path. A
standalone loader must first execute ``core.py`` and register it in ``sys.modules`` as
``appsec_review_signing_core``; this module never searches ``sys.path`` for it.
"""
import hashlib
import importlib.machinery
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import types
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional, Union

if __package__:
    from . import core as _core
else:
    _core = sys.modules.get("appsec_review_signing_core")
    if _core is None:
        raise ImportError("standalone loading requires appsec_review_signing_core in sys.modules")


MODULES_KIND = "python-modules"
DEFAULT_PACKAGE = "appsec_review"
MAX_MODULE_FILE_BYTES = 64 * 1024 * 1024

SignatureVerificationError = _core.SignatureVerificationError

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_IGNORED_DIRECTORY = "__pycache__"
_BYTECODE_SUFFIXES = (".pyc", ".pyo")
_REJECTED_SUFFIXES = tuple(sorted({".so", ".pyd", ".pth", *(suffix.lower() for suffix in
                                                            importlib.machinery.EXTENSION_SUFFIXES)}))
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_PathLike = Union[str, "os.PathLike[str]"]


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _check_name(name: str, where: str) -> None:
    if not name or name in {".", ".."} or "\\" in name or "\x00" in name or "/" in name:
        raise SignatureVerificationError(f"unsupported path component {name!r} in {where}")
    try:
        name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise SignatureVerificationError(f"path component is not valid Unicode in {where}") from error
    if not unicodedata.is_normalized("NFC", name):
        raise SignatureVerificationError(f"path component is not NFC-normalized in {where}")


def _check_relpath(relpath: Any) -> tuple[str, ...]:
    if not isinstance(relpath, str) or not relpath or relpath.startswith("/"):
        raise SignatureVerificationError(f"invalid package-relative path {relpath!r}")
    parts = tuple(relpath.split("/"))
    for part in parts:
        _check_name(part, repr(relpath))
    if _IGNORED_DIRECTORY in parts or relpath.endswith(_BYTECODE_SUFFIXES):
        raise SignatureVerificationError(f"bytecode must not be listed: {relpath}")
    if relpath.lower().endswith(_REJECTED_SUFFIXES):
        raise SignatureVerificationError(f"native extension and .pth files are not supported: {relpath}")
    return parts


def _check_package(package: Any) -> str:
    if not isinstance(package, str) or not package.isidentifier():
        raise SignatureVerificationError(f"invalid package name {package!r}")
    return package


def _package_directory(package_root: _PathLike) -> Path:
    path = Path(os.path.abspath(package_root))
    try:
        info = os.lstat(path)
    except OSError as error:
        raise SignatureVerificationError(f"package root cannot be inspected: {path}: {error}") from error
    if stat.S_ISLNK(info.st_mode):
        raise SignatureVerificationError(f"package root must not be a symbolic link: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise SignatureVerificationError(f"package root must be a directory: {path}")
    return path.resolve(strict=True)


def _walk(root: Path, *, skip_bytecode: bool) -> list[tuple[str, Path]]:
    """Return sorted (relpath, path) for every regular file, rejecting anything unsupported."""
    found: list[tuple[str, Path]] = []
    pending: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    while pending:
        directory, prefix = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = list(iterator)
        except OSError as error:
            raise SignatureVerificationError(f"package directory cannot be listed: {directory}: {error}") from error
        for entry in entries:
            name = entry.name
            parts = (*prefix, name)
            relpath = "/".join(parts)
            _check_name(name, repr(relpath))
            if entry.is_symlink():
                raise SignatureVerificationError(f"symbolic links are not supported in the package: {relpath}")
            if entry.is_dir(follow_symlinks=False):
                if name != _IGNORED_DIRECTORY:
                    pending.append((Path(entry.path), parts))
                continue
            if not entry.is_file(follow_symlinks=False) or name == _IGNORED_DIRECTORY:
                raise SignatureVerificationError(f"package contains a non-regular file: {relpath}")
            if name.lower().endswith(_REJECTED_SUFFIXES):
                raise SignatureVerificationError(f"native extension and .pth files are not supported: {relpath}")
            if skip_bytecode and name.endswith(_BYTECODE_SUFFIXES):
                continue
            found.append((relpath, Path(entry.path)))
    found.sort()
    return found


def _read_file(path: Path) -> bytes:
    return _core._read_regular_file(path, MAX_MODULE_FILE_BYTES, "package file")


def build_manifest(package_root: _PathLike, *, package: str = DEFAULT_PACKAGE) -> dict:
    """Return the ``python-modules`` subject over every regular file of a package source tree."""
    _check_package(package)
    root = _package_directory(package_root)
    files = {relpath: _digest(_read_file(path)) for relpath, path in _walk(root, skip_bytecode=True)}
    if "__init__.py" not in files:
        raise SignatureVerificationError(f"package root has no __init__.py: {root}")
    return {"package": package, "files": files}


def sign_modules(openssl: Any, private_key_path: _PathLike, package_root: _PathLike,
                 envelope_path: _PathLike, *, package: str = DEFAULT_PACKAGE) -> dict:
    subject = build_manifest(package_root, package=package)
    envelope = _core.sign_statement(openssl, private_key_path, _core.make_statement(MODULES_KIND, subject))
    _core.write_envelope(envelope_path, envelope)
    return envelope


@dataclass(frozen=True, eq=False)
class VerifiedManifest:
    """A signature-verified file manifest bound to one resolved installed package root."""

    package: str
    root: Path
    files: Mapping[str, str]

    def expected_digest(self, relpath: str) -> Optional[str]:
        return self.files.get(relpath)

    def read_verified(self, relpath: str) -> bytes:
        """Read a listed file once without following symlinks and return its bytes only if they match."""
        parts = _check_relpath(relpath)
        expected = self.files.get(relpath)
        if expected is None:
            raise SignatureVerificationError(f"file is not in the signed manifest: {relpath}")
        data = _read_beneath(self.root, parts)
        if _digest(data) != expected:
            raise SignatureVerificationError(f"package file does not match the signed manifest: {relpath}")
        return data


def _read_beneath(root: Path, parts: tuple[str, ...]) -> bytes:
    if os.open in os.supports_dir_fd and _O_DIRECTORY and _O_NOFOLLOW:
        return _read_with_dir_fds(root, parts)
    current = root
    for part in parts[:-1]:
        current = current / part
        try:
            info = os.lstat(current)
        except OSError as error:
            raise SignatureVerificationError(f"package directory cannot be inspected: {current}: {error}") from error
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SignatureVerificationError(f"package path component is not a plain directory: {current}")
    return _read_file(current / parts[-1])


def _read_with_dir_fds(root: Path, parts: tuple[str, ...]) -> bytes:
    relpath = "/".join(parts)
    directory_flags = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
    descriptors: list[int] = []
    try:
        try:
            descriptors.append(os.open(root, directory_flags))
            for part in parts[:-1]:
                descriptors.append(os.open(part, directory_flags, dir_fd=descriptors[-1]))
            file_descriptor = os.open(parts[-1], os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=descriptors[-1])
        except OSError as error:
            raise SignatureVerificationError(f"package file cannot be opened safely: {relpath}: {error}") from error
        with os.fdopen(file_descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise SignatureVerificationError(f"package file is not a regular file: {relpath}")
            data = handle.read(MAX_MODULE_FILE_BYTES + 1)
        if len(data) > MAX_MODULE_FILE_BYTES:
            raise SignatureVerificationError(f"package file exceeds {MAX_MODULE_FILE_BYTES} bytes: {relpath}")
        return data
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def _signed_files(statement: dict, package: str) -> dict[str, str]:
    subject = statement.get("subject")
    if not isinstance(subject, dict) or set(subject) != {"package", "files"}:
        raise SignatureVerificationError("module manifest subject must have exactly package and files")
    if subject["package"] != package:
        raise SignatureVerificationError(
            f"module manifest is for package {subject['package']!r}, not {package!r}")
    files = subject["files"]
    if not isinstance(files, dict) or not files:
        raise SignatureVerificationError("module manifest must list at least one file")
    seen_parts: set[tuple[str, ...]] = set()
    for relpath, digest in files.items():
        seen_parts.add(_check_relpath(relpath))
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise SignatureVerificationError(f"invalid digest for {relpath}")
    for parts in seen_parts:
        for depth in range(1, len(parts)):
            if parts[:depth] in seen_parts:
                raise SignatureVerificationError(f"manifest lists a file as a directory: {'/'.join(parts)}")
    if "__init__.py" not in files:
        raise SignatureVerificationError("module manifest does not list the root package __init__.py")
    return dict(files)


def verify_modules(envelope_path: _PathLike, package_root: _PathLike, trusted_keys_dir: Any, openssl: Any, *,
                   package: str = DEFAULT_PACKAGE) -> VerifiedManifest:
    """Verify the envelope, then require every installed file to be listed with a matching digest.

    Listed files may be absent (installers can omit them), except the root ``__init__.py``.
    ``trusted_keys_dir`` may also be an already loaded ``TrustedKeys``.
    """
    _check_package(package)
    if isinstance(trusted_keys_dir, _core.TrustedKeys):
        trusted = trusted_keys_dir
    else:
        trusted = _core.TrustedKeys.load(trusted_keys_dir, openssl)
    statement = _core.verify_envelope(_core.read_envelope(envelope_path), trusted, openssl, kind=MODULES_KIND)
    files = _signed_files(statement, package)
    root = _package_directory(package_root)
    present = set()
    for relpath, path in _walk(root, skip_bytecode=False):
        expected = files.get(relpath)
        if expected is None:
            raise SignatureVerificationError(f"installed package file is not in the signed manifest: {relpath}")
        if _digest(_read_file(path)) != expected:
            raise SignatureVerificationError(f"installed package file does not match the signed manifest: {relpath}")
        present.add(relpath)
    if "__init__.py" not in present:
        raise SignatureVerificationError(f"installed package has no root __init__.py: {root}")
    return VerifiedManifest(package=package, root=root, files=types.MappingProxyType(files))
