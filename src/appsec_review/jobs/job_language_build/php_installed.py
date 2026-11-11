"""Read Composer's own installer record; parse and verify only, never catalog.

``composer install`` and ``composer update`` write ``<prefix>/vendor/composer/installed.json``
after placing each package under ``<prefix>/vendor``. The parsed record, verified against each
installed package directory, is the only basis this module offers for dependency scope. Directory
names establish nothing, and ``composer.json``/``composer.lock`` describe intent rather than what
was installed, so they are never used for coverage (a ``composer.json`` only says where Composer
would keep a ``vendor`` directory). Target-controlled content never raises.

The record carries a dist reference and sometimes a checksum of the downloaded archive, never a
digest of the installed files, so verification is of identity and structure: see
``parse_installed_record``.
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


VENDOR = "vendor"
RECORD_DIRECTORY = "composer"
RECORD_NAME = "installed.json"
MANIFEST_NAME = "composer.json"
PROJECT_FILE = "composer.json"
MAX_PREFIXES = 32
MAX_RECORD_BYTES = 64 * 1024 * 1024
MAX_PACKAGES = 20_000
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_FIELD_CHARS = 1024
DISCOVERY_BOUND_GAP = ("Composer installer record discovery bound reached; "
                       "remaining prefixes cataloged per-file")

# Composer's package-name grammar (``vendor/package``), with the upper case older packages used.
_NAME = re.compile(r"[A-Za-z0-9](?:[_.\-]?[A-Za-z0-9]+)*/[A-Za-z0-9](?:(?:[_.]|-{1,2})?[A-Za-z0-9]+)*")
_DIST_FIELDS = ("type", "reference", "shasum")
_SOURCE_FIELDS = ("type", "reference")


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
    version_normalized: str | None
    package_type: str
    dev: bool
    dist: Mapping[str, str | None] | None
    source: Mapping[str, str | None] | None
    manifest: RecordReference


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
    # ``composer-1`` (a list of packages) or ``composer-2`` (an object naming the dev packages).
    layout: str | None
    packages: tuple[InstalledPackage, ...]
    unverified: tuple[UnverifiedPackage, ...]
    # Entries that install no directory (metapackages, a null ``install-path``).
    without_install: int

    @property
    def available(self) -> bool:
        return self.status == "available"


@dataclass(frozen=True, slots=True)
class _Entry:
    name: str
    version: str
    version_normalized: str | None
    package_type: str
    dev: bool
    dist: Mapping[str, str | None] | None
    source: Mapping[str, str | None] | None
    # Path parts below the prefix; None when the entry installs no directory.
    location: tuple[str, ...] | None


class _Unavailable(Exception):
    pass


def record_path(prefix: str) -> str:
    return _join(prefix, VENDOR, RECORD_DIRECTORY, RECORD_NAME)


def vendor_root(prefix: str) -> str:
    return _join(prefix, VENDOR)


def installer_owned(prefix: str, relative: str) -> bool:
    """Whether a file is Composer's own loader or bookkeeping rather than a package's content.

    ``vendor/autoload.php`` and the files directly in ``vendor/composer`` (the autoloader, the
    record and its PHP twin) are written by Composer itself. Packages of the ``composer`` vendor
    live in subdirectories of ``vendor/composer`` and are not owned by the installer.
    """
    root = vendor_root(prefix)
    return (relative == _join(root, "autoload.php") or
            PurePosixPath(relative).parent.as_posix() == _join(root, RECORD_DIRECTORY))


def discover_prefixes(workspace: Path, limit: int | None = None) -> tuple[list[str], list[str]]:
    """Return workspace-relative directories where Composer would keep a ``vendor`` tree.

    A prefix holds a real ``vendor`` directory and either a ``vendor/composer/installed.json``
    entry or a regular ``composer.json`` beside it. A ``vendor`` directory with neither belongs to
    another tool and is left alone. Vendor trees are not descended. A project that renames its
    vendor directory (``config.vendor-dir``) is not found.
    """
    bound = MAX_PREFIXES if limit is None else limit
    prefixes: list[str] = []
    for raw_root, directories, names in os.walk(workspace, followlinks=False):
        root = Path(raw_root)
        directories[:] = sorted(name for name in directories if not (root / name).is_symlink())
        if VENDOR not in directories:
            continue
        project = root / PROJECT_FILE
        if not (os.path.lexists(root / VENDOR / RECORD_DIRECTORY / RECORD_NAME) or
                PROJECT_FILE in names and project.is_file() and not project.is_symlink()):
            continue
        if len(prefixes) >= bound:
            return prefixes, [DISCOVERY_BOUND_GAP]
        prefixes.append(_relative(workspace, root))
        directories.remove(VENDOR)
    return prefixes, []


def parse_installed_record(workspace: Path, prefix: str = ".") -> InstalledRecord:
    """Parse and verify ``<prefix>/vendor/composer/installed.json``.

    Two layouts are accepted, as Composer writes them (``Composer\\Repository\\FilesystemRepository``):
    Composer 1's JSON list of package objects, and Composer 2's object with a ``packages`` list,
    an optional boolean ``dev`` and an optional ``dev-package-names`` list of strings. Composer 1
    records no dev marking. Each package object needs a ``name`` in Composer's ``vendor/package``
    grammar and a non-empty ``version``; ``version_normalized``, ``type``, ``dist`` and ``source``
    are optional. ``install-path`` (Composer 2) is relative to ``vendor/composer``; without it the
    package is at ``vendor/<name>``, Composer's default. A null ``install-path`` or a
    ``metapackage`` without one installs no directory.

    Any other shape, a wrongly typed or over-long field, a duplicate name or install path, an
    ``install-path`` that is absolute, uses a backslash or an empty or control-character segment,
    leaves the prefix, or names the prefix, ``vendor`` or ``vendor/composer`` itself, or an
    exceeded bound makes the whole record unavailable, so that a partially understood record
    never covers a file.

    A package is verified when: it does not come from a path repository (``dist.type`` ``path``,
    local content under a registry name); its install path is below ``<prefix>/vendor``; that
    path and every directory from ``vendor`` down to it are real directories, not symlinks; and
    it holds a regular ``composer.json`` whose ``name`` equals the recorded name, compared
    without case as Composer does. Installed manifests rarely carry a version, so the version is
    the record's own and is not compared; the installed files' bytes are not compared with
    anything.
    """
    prefix = _normal_prefix(prefix)
    reference: RecordReference | None = None
    layout: str | None = None
    try:
        relative = record_path(prefix)
        path = workspace / Path(*PurePosixPath(relative).parts)
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
        reference = RecordReference(relative, hashlib.sha256(data).hexdigest(), len(data))
        try:
            document = json.loads(data.decode("utf-8"))
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise _Unavailable("invalid-json") from exc
        raw_entries, dev_names, layout = _layout(document)
        if len(raw_entries) > MAX_PACKAGES:
            raise _Unavailable("bound-exceeded:packages")
        entries = [_entry(raw, dev_names) for raw in raw_entries]
        names: set[str] = set()
        locations: set[tuple[str, ...]] = set()
        for entry in entries:
            if entry.name.lower() in names:
                raise _Unavailable(f"duplicate-package:{_label(entry.name)}")
            names.add(entry.name.lower())
            if entry.location is not None:
                if entry.location in locations:
                    raise _Unavailable(f"duplicate-install-path:{_label(entry.name)}")
                locations.add(entry.location)
    except _Unavailable as unavailable:
        return InstalledRecord(prefix, "unavailable", str(unavailable), reference, layout, (), (), 0)
    packages: list[InstalledPackage] = []
    unverified: list[UnverifiedPackage] = []
    placed = [entry for entry in entries if entry.location is not None]
    for entry in sorted(placed, key=lambda item: item.location or ()):
        assert entry.location is not None
        install_path = _join(prefix, *entry.location)
        failure, manifest = _verify(workspace, prefix, install_path, entry)
        if failure is not None:
            unverified.append(UnverifiedPackage(entry.name, install_path, failure))
            continue
        assert manifest is not None
        packages.append(InstalledPackage(
            entry=entry.name, install_path=install_path, name=entry.name, version=entry.version,
            version_normalized=entry.version_normalized, package_type=entry.package_type, dev=entry.dev,
            dist=entry.dist, source=entry.source, manifest=manifest))
    return InstalledRecord(prefix, "available", None, reference, layout, tuple(packages),
                           tuple(unverified), len(entries) - len(placed))


def _layout(document: Any) -> tuple[list[Any], frozenset[str], str]:
    if isinstance(document, list):
        return document, frozenset(), "composer-1"
    if not isinstance(document, Mapping) or not isinstance(document.get("packages"), list):
        raise _Unavailable("unsupported-structure")
    if type(document.get("dev", False)) is not bool:
        raise _Unavailable("dev-flag-invalid")
    names = document.get("dev-package-names", [])
    if (not isinstance(names, list) or len(names) > MAX_PACKAGES or
            not all(isinstance(name, str) and len(name) <= MAX_FIELD_CHARS for name in names)):
        raise _Unavailable("dev-package-names-invalid")
    return document["packages"], frozenset(name.lower() for name in names), "composer-2"


def _entry(raw: Any, dev_names: frozenset[str]) -> _Entry:
    if not isinstance(raw, Mapping):
        raise _Unavailable("entry-invalid:not-an-object")
    name = raw.get("name")
    if not isinstance(name, str) or len(name) > 255 or not _NAME.fullmatch(name):
        raise _Unavailable(f"entry-invalid:{_label(name)}")
    invalid = _Unavailable(f"entry-invalid:{_label(name)}")
    version = raw.get("version")
    if not _text(version) or not version:
        raise invalid
    normalized, package_type = raw.get("version_normalized"), raw.get("type", "library")
    if normalized is not None and not _text(normalized) or not _text(package_type) or not package_type:
        raise invalid
    location: tuple[str, ...] | None
    if "install-path" in raw:
        recorded = raw["install-path"]
        if recorded is None:
            location = None
        elif isinstance(recorded, str):
            location = _location(recorded, invalid)
        else:
            raise invalid
    elif package_type == "metapackage":
        location = None
    else:
        location = (VENDOR, *name.split("/"))
    return _Entry(name, version, normalized, package_type, name.lower() in dev_names,
                  _fields(raw.get("dist"), _DIST_FIELDS, invalid),
                  _fields(raw.get("source"), _SOURCE_FIELDS, invalid), location)


def _text(value: Any) -> bool:
    return (isinstance(value, str) and len(value) <= MAX_FIELD_CHARS and
            all(0x20 <= ord(char) != 0x7f for char in value))


def _fields(value: Any, names: tuple[str, ...], invalid: _Unavailable) -> dict[str, str | None] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise invalid
    result: dict[str, str | None] = {}
    for name in names:
        item = value.get(name)
        if item is not None and not _text(item):
            raise invalid
        result[name] = item
    return result


def _location(recorded: str, invalid: _Unavailable) -> tuple[str, ...]:
    """Resolve an ``install-path`` lexically from ``vendor/composer`` to parts below the prefix."""
    if not recorded or len(recorded) > MAX_FIELD_CHARS or recorded.startswith("/") or "\\" in recorded:
        raise invalid
    parts = [VENDOR, RECORD_DIRECTORY]
    for part in recorded.split("/"):
        if not part or any(ord(char) < 0x20 or ord(char) == 0x7f for char in part):
            raise invalid
        if part == ".":
            # Composer writes ``./semver`` for a package of the ``composer`` vendor.
            continue
        if part != "..":
            parts.append(part)
        elif not parts:
            raise invalid
        else:
            parts.pop()
    # The prefix itself, ``vendor`` and ``vendor/composer`` hold the record: never a package root.
    if tuple(parts) in {(), (VENDOR,), (VENDOR, RECORD_DIRECTORY)}:
        raise invalid
    return tuple(parts)


def _verify(workspace: Path, prefix: str, install_path: str,
            entry: _Entry) -> tuple[str | None, RecordReference | None]:
    assert entry.location is not None
    if entry.dist is not None and entry.dist.get("type") == "path":
        return "path-repository", None
    if entry.location[0] != VENDOR:
        return "install-path-outside-vendor", None
    if not _real_directory(workspace, prefix, install_path):
        return "install-path-missing", None
    manifest = workspace / Path(*PurePosixPath(install_path).parts) / MANIFEST_NAME
    try:
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
    installed = document.get("name")
    if not isinstance(installed, str) or installed.lower() != entry.name.lower():
        return "name-mismatch", None
    return None, RecordReference(_join(install_path, MANIFEST_NAME),
                                 hashlib.sha256(data).hexdigest(), len(data))


def _real_directory(workspace: Path, prefix: str, relative: str) -> bool:
    """Whether every component from the prefix's ``vendor`` down is a directory, not a symlink."""
    base = PurePosixPath(vendor_root(prefix))
    current = workspace / Path(*base.parts)
    try:
        for part in ("", *PurePosixPath(relative).relative_to(base).parts):
            current = current / part if part else current
            if current.is_symlink() or not current.is_dir():
                return False
    except OSError:
        return False
    return True


def _normal_prefix(prefix: str) -> str:
    logical = PurePosixPath(prefix.replace("\\", "/"))
    if logical.is_absolute() or ".." in logical.parts:
        raise ValueError("Composer install prefix must be workspace-relative")
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
