"""Signed manifests over the third-party closure of a native release ``lib/`` directory.

The ``appsec_review`` package itself is covered by the ``python-modules`` manifest; this manifest
covers every other regular file under ``lib/`` (dependencies, ``.dist-info`` metadata, native
extensions, ``.pth`` files, data). Unlike the module manifest, every listed file must be present
and every present file must be listed, byte- and size-exact. Bytecode, ``__pycache__`` directories,
symbolic links, reparse points and other non-regular files are refused at signing and at
verification time.

Stdlib-only and loadable either as ``appsec_review.signing.release_lib`` or standalone by file path.
A standalone loader must first execute ``core.py`` and register it in ``sys.modules`` as
``appsec_review_signing_core``; this module never searches ``sys.path`` for it.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import unicodedata
from typing import Any, Union

if __package__:
    from . import core as _core
else:
    _core = sys.modules.get("appsec_review_signing_core")
    if _core is None:
        raise ImportError("standalone loading requires appsec_review_signing_core in sys.modules")


RELEASE_LIB_KIND = "python-release-lib"
EXCLUDED_PACKAGE = "appsec_review"
MAX_RELEASE_FILE_BYTES = 512 * 1024 * 1024

SignatureVerificationError = _core.SignatureVerificationError

_SHA256 = re.compile(r"[0-9a-f]{64}")
_BYTECODE_DIRECTORY = "__pycache__"
_BYTECODE_SUFFIXES = (".pyc", ".pyo")
_PathLike = Union[str, "os.PathLike[str]"]


def _check_name(name: str, where: str) -> None:
    if not name or name in {".", ".."} or "\\" in name or "\x00" in name or "/" in name:
        raise SignatureVerificationError(f"unsupported path component {name!r} in {where}")
    try:
        name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise SignatureVerificationError(f"path component is not valid Unicode in {where}") from error
    if not unicodedata.is_normalized("NFC", name):
        raise SignatureVerificationError(f"path component is not NFC-normalized in {where}")
    if name == _BYTECODE_DIRECTORY or name.lower().endswith(_BYTECODE_SUFFIXES):
        raise SignatureVerificationError(f"bytecode is not allowed in the release library: {where}")


def _check_relpath(relpath: Any) -> tuple[str, ...]:
    if not isinstance(relpath, str) or not relpath or relpath.startswith("/"):
        raise SignatureVerificationError(f"invalid library-relative path {relpath!r}")
    parts = tuple(relpath.split("/"))
    for part in parts:
        _check_name(part, repr(relpath))
    if parts[0] == EXCLUDED_PACKAGE and len(parts) > 1:
        raise SignatureVerificationError(f"the {EXCLUDED_PACKAGE} package is covered by its module manifest: {relpath}")
    return parts


def _library_directory(library: _PathLike) -> Path:
    path = Path(os.path.abspath(library))
    try:
        info = os.lstat(path)
    except OSError as error:
        raise SignatureVerificationError(f"release library cannot be inspected: {path}: {error}") from error
    if _core.is_link_or_reparse_point(info):
        raise SignatureVerificationError(f"release library must not be a symbolic link: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise SignatureVerificationError(f"release library must be a directory: {path}")
    return path.resolve(strict=True)


def _walk(root: Path) -> list[tuple[str, Path, os.stat_result]]:
    """Return sorted (relpath, path, lstat) for every regular file outside the excluded package."""
    found: list[tuple[str, Path, os.stat_result]] = []
    pending: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    while pending:
        directory, prefix = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = list(iterator)
        except OSError as error:
            raise SignatureVerificationError(f"release library directory cannot be listed: {directory}: {error}") \
                from error
        for entry in entries:
            parts = (*prefix, entry.name)
            relpath = "/".join(parts)
            _check_name(entry.name, repr(relpath))
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise SignatureVerificationError(f"release library entry cannot be inspected: {relpath}: {error}") \
                    from error
            if _core.is_link_or_reparse_point(info):
                raise SignatureVerificationError(f"symbolic links are not supported in the release library: {relpath}")
            if stat.S_ISDIR(info.st_mode):
                if not (prefix == () and entry.name == EXCLUDED_PACKAGE):
                    pending.append((Path(entry.path), parts))
                continue
            if not stat.S_ISREG(info.st_mode):
                raise SignatureVerificationError(f"release library contains a non-regular file: {relpath}")
            found.append((relpath, Path(entry.path), info))
    found.sort(key=lambda item: item[0])
    return found


def _read_file(path: Path) -> bytes:
    return _core._read_regular_file(path, MAX_RELEASE_FILE_BYTES, "release library file")


def build_manifest(library: _PathLike) -> dict:
    """Return the ``python-release-lib`` subject over every regular file outside ``appsec_review/``."""
    root = _library_directory(library)
    files = {}
    for relpath, path, _ in _walk(root):
        data = _read_file(path)
        files[relpath] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    return {"excluded": [EXCLUDED_PACKAGE], "files": files}


def sign_release_lib(openssl: Any, private_key_path: _PathLike, library: _PathLike,
                     envelope_path: _PathLike) -> dict:
    subject = build_manifest(library)
    envelope = _core.sign_statement(openssl, private_key_path, _core.make_statement(RELEASE_LIB_KIND, subject))
    _core.write_envelope(envelope_path, envelope)
    return envelope


def _signed_files(statement: dict) -> dict[str, tuple[str, int]]:
    subject = statement.get("subject")
    if not isinstance(subject, dict) or set(subject) != {"excluded", "files"}:
        raise SignatureVerificationError("release library manifest subject must have exactly excluded and files")
    if subject["excluded"] != [EXCLUDED_PACKAGE]:
        raise SignatureVerificationError(f"release library manifest must exclude exactly {EXCLUDED_PACKAGE!r}")
    files = subject["files"]
    if not isinstance(files, dict):
        raise SignatureVerificationError("release library manifest files must be an object")
    signed: dict[str, tuple[str, int]] = {}
    for relpath, entry in files.items():
        _check_relpath(relpath)
        if (not isinstance(entry, dict) or set(entry) != {"sha256", "size"}
                or not isinstance(entry["sha256"], str) or not _SHA256.fullmatch(entry["sha256"])
                or type(entry["size"]) is not int or not 0 <= entry["size"] <= MAX_RELEASE_FILE_BYTES):
            raise SignatureVerificationError(f"invalid release library manifest entry for {relpath}")
        signed[relpath] = (entry["sha256"], entry["size"])
    return signed


def verify_release_lib(envelope_path: _PathLike, library: _PathLike, trusted_keys_dir: Any, openssl: Any) -> dict:
    """Verify the envelope, then require the library closure to equal the signed manifest exactly.

    ``trusted_keys_dir`` may also be an already loaded ``TrustedKeys``. Returns ``{relpath: sha256}``.
    """
    if isinstance(trusted_keys_dir, _core.TrustedKeys):
        trusted = trusted_keys_dir
    else:
        trusted = _core.TrustedKeys.load(trusted_keys_dir, openssl)
    statement = _core.verify_envelope(_core.read_envelope(envelope_path), trusted, openssl, kind=RELEASE_LIB_KIND)
    signed = _signed_files(statement)
    root = _library_directory(library)
    present = set()
    for relpath, path, info in _walk(root):
        expected = signed.get(relpath)
        if expected is None:
            raise SignatureVerificationError(f"release library file is not in the signed manifest: {relpath}")
        if info.st_size != expected[1]:
            raise SignatureVerificationError(f"release library file does not match the signed manifest: {relpath}")
        data = _read_file(path)
        if len(data) != expected[1] or hashlib.sha256(data).hexdigest() != expected[0]:
            raise SignatureVerificationError(f"release library file does not match the signed manifest: {relpath}")
        present.add(relpath)
    missing = sorted(set(signed) - present)
    if missing:
        raise SignatureVerificationError(f"signed release library file is missing: {missing[0]}")
    return {relpath: digest for relpath, (digest, _) in signed.items()}
