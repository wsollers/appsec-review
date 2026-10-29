"""Read npm's own installer record; parse and verify only, never catalog.

npm writes ``<prefix>/node_modules/.package-lock.json`` after an install. The
parsed record, verified against each installed ``package.json``, is the only
basis this module offers for dependency scope. Directory names establish
nothing, and a project ``package-lock.json`` describes intent rather than what
was installed, so it is never used here. Target-controlled content never raises.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any


RECORD_NAME = ".package-lock.json"
MAX_PREFIXES = 32
MAX_RECORD_BYTES = 64 * 1024 * 1024
MAX_PACKAGES = 50_000
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
SUPPORTED_LOCKFILE_VERSIONS = (2, 3)
DISCOVERY_BOUND_GAP = ("npm installer record discovery bound reached; "
                       "remaining prefixes cataloged per-file")

_NAME = re.compile(r"[^/\\\x00-\x1f\x7f.@][^/\\\x00-\x1f\x7f]*")
_SCOPE = re.compile(r"@[^/\\\x00-\x1f\x7f.][^/\\\x00-\x1f\x7f]*")
_FLAGS = (("dev", "dev"), ("optional", "optional"), ("devOptional", "dev_optional"))


@dataclass(frozen=True, slots=True)
class RecordReference:
    workspace_path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class InstalledPackage:
    entry: str
    install_path: str
    name: str
    version: str
    resolved: str | None
    integrity: str | None
    dev: bool
    optional: bool
    dev_optional: bool
    manifest: RecordReference

    @property
    def build_only(self) -> bool:
        """npm omits both flags' packages under ``--omit=dev``."""
        return self.dev or self.dev_optional


@dataclass(frozen=True, slots=True)
class UnverifiedPackage:
    entry: str
    install_path: str
    reason: str


@dataclass(frozen=True, slots=True)
class InstalledRecord:
    prefix: str
    status: str
    reason: str | None
    record: RecordReference | None
    lockfile_version: int | None
    packages: tuple[InstalledPackage, ...]
    unverified: tuple[UnverifiedPackage, ...]

    @property
    def available(self) -> bool:
        return self.status == "available"


class _Unavailable(Exception):
    pass


def record_path(prefix: str) -> str:
    return _join(prefix, "node_modules", RECORD_NAME)


def discover_prefixes(workspace: Path, limit: int | None = None) -> tuple[list[str], list[str]]:
    """Return workspace-relative directories holding a real ``node_modules`` directory.

    Dependency trees are not descended: npm writes one record per install prefix,
    and the prefix's record already describes every nested install path.
    """
    bound = MAX_PREFIXES if limit is None else limit
    prefixes: list[str] = []
    for raw_root, directories, _ in os.walk(workspace, followlinks=False):
        root = Path(raw_root)
        directories[:] = sorted(name for name in directories if not (root / name).is_symlink())
        if "node_modules" in directories:
            if len(prefixes) >= bound:
                return prefixes, [DISCOVERY_BOUND_GAP]
            prefixes.append(_relative(workspace, root))
            directories.remove("node_modules")
    return prefixes, []


def parse_installed_record(workspace: Path, prefix: str = ".") -> InstalledRecord:
    """Parse and verify ``<prefix>/node_modules/.package-lock.json``.

    An unavailable record covers no package; a single invalid entry makes the
    whole record unavailable rather than partially trusted.
    """
    prefix = _normal_prefix(prefix)
    reference: RecordReference | None = None
    version: int | None = None
    try:
        path = workspace / Path(*PurePosixPath(record_path(prefix)).parts)
        try:
            if path.is_symlink() or not path.is_file():
                raise _Unavailable("missing")
            if path.stat().st_size > MAX_RECORD_BYTES:
                raise _Unavailable("bound-exceeded:record-bytes")
            with path.open("rb") as stream:
                data = stream.read(MAX_RECORD_BYTES + 1)
        except OSError as exc:
            raise _Unavailable("unreadable") from exc
        if len(data) > MAX_RECORD_BYTES:
            raise _Unavailable("bound-exceeded:record-bytes")
        reference = RecordReference(record_path(prefix), hashlib.sha256(data).hexdigest(), len(data))
        try:
            document = json.loads(data.decode("utf-8"))
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise _Unavailable("invalid-json") from exc
        if not isinstance(document, Mapping) or not isinstance(document.get("packages"), Mapping):
            raise _Unavailable("invalid-json")
        raw_version = document.get("lockfileVersion")
        if type(raw_version) is not int or raw_version not in SUPPORTED_LOCKFILE_VERSIONS:
            raise _Unavailable(
                f"unsupported-lockfile-version:{_label(json.dumps(raw_version, default=str))}")
        version = raw_version
        entries = document["packages"]
        if len(entries) > MAX_PACKAGES:
            raise _Unavailable("bound-exceeded:packages")
        parsed = [_entry(key, value) for key, value in sorted(entries.items(), key=lambda item: str(item[0]))]
    except _Unavailable as unavailable:
        return InstalledRecord(prefix, "unavailable", str(unavailable), reference, version, (), ())
    packages: list[InstalledPackage] = []
    unverified: list[UnverifiedPackage] = []
    for key, fields in (item for item in parsed if item is not None):
        install_path = _join(prefix, key)
        failure, manifest = _verify(workspace, install_path, fields["name"], fields["version"])
        if failure is not None:
            unverified.append(UnverifiedPackage(key, install_path, failure))
            continue
        assert manifest is not None
        packages.append(InstalledPackage(entry=key, install_path=install_path, manifest=manifest, **fields))
    return InstalledRecord(prefix, "available", None, reference, version, tuple(packages), tuple(unverified))


def _entry(key: Any, value: Any) -> tuple[str, dict[str, Any]] | None:
    if key == "":
        return None
    if not isinstance(key, str) or not isinstance(value, Mapping):
        raise _Unavailable(f"entry-invalid:{_label(key)}")
    if value.get("link") is True:
        return None
    package = _package_name(key)
    if package is None:
        # A folder outside node_modules is a workspace project: target source, never covered.
        return None
    version, name = value.get("version"), value.get("name", package)
    if (not isinstance(version, str) or not version or not isinstance(name, str) or
            _canonical_name(name) is None):
        raise _Unavailable(f"entry-invalid:{_label(key)}")
    fields: dict[str, Any] = {"name": name, "version": version}
    for source in ("resolved", "integrity"):
        item = value.get(source)
        if item is not None and not isinstance(item, str):
            raise _Unavailable(f"entry-invalid:{_label(key)}")
        fields[source] = item
    for source, target in _FLAGS:
        item = value.get(source, False)
        if type(item) is not bool:
            raise _Unavailable(f"entry-invalid:{_label(key)}")
        fields[target] = item
    return key, fields


def _package_name(key: str) -> str | None:
    """Return the last package name of a canonical install key.

    Raises when the key is not canonical; returns None for a key without any
    ``node_modules`` segment (a workspace folder rather than an install path).
    """
    parts = key.split("/")
    if (key.startswith("/") or "\\" in key or
            any(part in {"", ".", ".."} or any(ord(char) < 0x20 for char in part) for part in parts)):
        raise _Unavailable(f"entry-invalid:{_label(key)}")
    if "node_modules" not in parts:
        return None
    index, name = parts.index("node_modules"), None
    while index < len(parts):
        if parts[index] != "node_modules":
            raise _Unavailable(f"entry-invalid:{_label(key)}")
        index += 1
        if index < len(parts) and _SCOPE.fullmatch(parts[index]):
            if index + 1 >= len(parts) or not _NAME.fullmatch(parts[index + 1]):
                raise _Unavailable(f"entry-invalid:{_label(key)}")
            name, index = f"{parts[index]}/{parts[index + 1]}", index + 2
        elif (index < len(parts) and _NAME.fullmatch(parts[index]) and
                parts[index] != "node_modules"):
            name, index = parts[index], index + 1
        else:
            raise _Unavailable(f"entry-invalid:{_label(key)}")
    return name


def _canonical_name(name: str) -> str | None:
    parts = name.split("/")
    if len(parts) == 1 and _NAME.fullmatch(name) and name != "node_modules":
        return name
    if len(parts) == 2 and _SCOPE.fullmatch(parts[0]) and _NAME.fullmatch(parts[1]):
        return name
    return None


def _verify(workspace: Path, install_path: str, name: str,
            version: str) -> tuple[str | None, RecordReference | None]:
    directory = workspace / Path(*PurePosixPath(install_path).parts)
    manifest = directory / "package.json"
    try:
        if directory.is_symlink() or not directory.is_dir():
            return "install-path-missing", None
        if manifest.is_symlink() or not manifest.is_file():
            return "manifest-missing", None
        if manifest.stat().st_size > MAX_MANIFEST_BYTES:
            return "manifest-invalid", None
        with manifest.open("rb") as stream:
            data = stream.read(MAX_MANIFEST_BYTES + 1)
    except OSError:
        return "manifest-invalid", None
    if len(data) > MAX_MANIFEST_BYTES:
        return "manifest-invalid", None
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        return "manifest-invalid", None
    if not isinstance(document, Mapping):
        return "manifest-invalid", None
    if document.get("name") != name:
        return "name-mismatch", None
    if document.get("version") != version:
        return "version-mismatch", None
    return None, RecordReference(_join(install_path, "package.json"),
                                 hashlib.sha256(data).hexdigest(), len(data))


def _normal_prefix(prefix: str) -> str:
    logical = PurePosixPath(prefix.replace("\\", "/"))
    if logical.is_absolute() or ".." in logical.parts:
        raise ValueError("npm install prefix must be workspace-relative")
    return logical.as_posix()


def _join(prefix: str, *parts: str) -> str:
    return PurePosixPath(prefix, *parts).as_posix()


def _relative(workspace: Path, path: Path) -> str:
    return path.relative_to(workspace).as_posix() or "."


def _label(value: Any) -> str:
    """Bound target-controlled text before it enters a gap string."""
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    text = "".join(char if 0x20 <= ord(char) != 0x7f else "?" for char in text)
    return text if len(text) <= 200 else text[:197] + "..."
