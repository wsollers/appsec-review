"""Read Go's own vendoring record; parse and verify only, never catalog.

``go mod vendor`` removes ``<prefix>/vendor``, copies the packages the main module's builds and
tests need, and writes ``<prefix>/vendor/modules.txt`` listing each vendored module and its
packages. The parsed record, verified against the vendored tree, is the only basis this module
offers for dependency scope. Directory names establish nothing, and ``go.mod``/``go.sum`` describe
intent rather than what was vendored, so they are never used for coverage (``go.mod``/``go.work``
only say where the go command would read a ``vendor`` directory). Target-controlled content never
raises.

The record carries no content digests and Go 1.17+ strips each dependency's ``go.mod``, so there is
no installed manifest to compare a name and version with. Verification is therefore structural:
see ``parse_vendor_record``.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import re

from appsec_review.storage import file_sha256


VENDOR = "vendor"
RECORD_NAME = "modules.txt"
MODULE_ROOT_FILES = ("go.mod", "go.work")
MAX_PREFIXES = 32
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 4096
MAX_MODULES = 20_000
MAX_PACKAGES = 200_000
MAX_TREE_ENTRIES = 500_000
DISCOVERY_BOUND_GAP = ("Go installer record discovery bound reached; "
                       "remaining prefixes cataloged per-file")

# One import-path element: the characters cmd/go accepts (golang.org/x/mod module.CheckImportPath).
_ELEMENT = re.compile(r"[A-Za-z0-9._~+\-]{1,255}")
# A canonical module version, including pseudo-versions and ``+incompatible``.
_VERSION = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
                      r"(?:-[0-9A-Za-z.\-]{1,160})?(?:\+[0-9A-Za-z.\-]{1,64})?")
_GO_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,2}(?:(?:rc|beta|alpha)[0-9]+)?")


@dataclass(frozen=True, slots=True)
class RecordReference:
    workspace_path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class VendoredModule:
    entry: str
    install_path: str
    name: str
    version: str
    replacement_path: str | None
    replacement_version: str | None
    explicit: bool
    go_version: str | None
    packages: tuple[str, ...]
    anchor: RecordReference


@dataclass(frozen=True, slots=True)
class UnverifiedModule:
    entry: str
    install_path: str
    reason: str


@dataclass(frozen=True, slots=True)
class VendorRecord:
    prefix: str
    status: str
    reason: str | None
    record: RecordReference | None
    workspace_mode: bool
    modules: tuple[VendoredModule, ...]
    unverified: tuple[UnverifiedModule, ...]
    # Module and replacement lines that name no vendored package: nothing was copied for them.
    without_packages: int

    @property
    def available(self) -> bool:
        return self.status == "available"


@dataclass(slots=True)
class _Entry:
    path: str
    version: str | None
    replacement_path: str | None = None
    replacement_version: str | None = None
    explicit: bool = False
    go_version: str | None = None
    annotated: bool = False
    packages: list[str] | None = None


class _Unavailable(Exception):
    pass


class _TreeBound(Exception):
    pass


def record_path(prefix: str) -> str:
    return _join(prefix, VENDOR, RECORD_NAME)


def vendor_root(prefix: str) -> str:
    return _join(prefix, VENDOR)


def discover_prefixes(workspace: Path, limit: int | None = None) -> tuple[list[str], list[str]]:
    """Return workspace-relative directories where the go command would read a ``vendor`` tree.

    A prefix holds a real ``vendor`` directory and either a ``vendor/modules.txt`` entry or a
    regular ``go.mod``/``go.work`` beside it. A ``vendor`` directory with neither belongs to
    another tool and is left alone. Go vendor trees are not descended.
    """
    bound = MAX_PREFIXES if limit is None else limit
    prefixes: list[str] = []
    for raw_root, directories, names in os.walk(workspace, followlinks=False):
        root = Path(raw_root)
        directories[:] = sorted(name for name in directories if not (root / name).is_symlink())
        if VENDOR not in directories:
            continue
        if not (os.path.lexists(root / VENDOR / RECORD_NAME) or
                any(name in names and (root / name).is_file() and not (root / name).is_symlink()
                    for name in MODULE_ROOT_FILES)):
            continue
        if len(prefixes) >= bound:
            return prefixes, [DISCOVERY_BOUND_GAP]
        prefixes.append(_relative(workspace, root))
        directories.remove(VENDOR)
    return prefixes, []


def parse_vendor_record(workspace: Path, prefix: str = ".") -> VendorRecord:
    """Parse and verify ``<prefix>/vendor/modules.txt``.

    Accepted line forms, as ``go mod vendor`` writes them and ``cmd/go`` reads them back
    (``cmd/go/internal/modcmd/vendor.go`` ``moduleLine``/``runVendor`` and
    ``cmd/go/internal/modload/vendor.go`` ``readVendorList``; the Go Modules Reference,
    https://go.dev/ref/mod#vendoring, describes the file's purpose but not its syntax):

    - ``## workspace`` as the first line (a ``go work vendor`` tree);
    - ``# <module> <version>``, optionally followed by ``=> <path>`` (a directory replacement)
      or ``=> <module> <version>``;
    - ``# <module> => <path>`` or ``# <module> => <module> <version>``: a replacement that
      provides no package, which may not be followed by package lines;
    - ``## explicit``, ``## explicit; go <version>`` or ``## go <version>``, once, directly after
      its module line;
    - ``<import path>``: a vendored package of the preceding module.

    The go command ignores lines it does not understand. This parser does not: any other line,
    a blank line, a duplicate module or package, a package outside its module's path or inside a
    deeper listed module, an undecodable byte or an exceeded bound makes the whole record
    unavailable, so that a partially understood record never covers a file.

    A module that lists packages is verified when: it is not replaced by a directory; its
    ``vendor/<module path>`` and every listed ``vendor/<import path>`` are real directories
    reached through no symlink; every listed package directory holds a regular ``.go`` file;
    and no other directory of the module's tree (outside nested listed modules) holds a ``.go``
    file. Its anchor is the first ``.go`` file, by name, of its first package. The record has no
    digests, so the bytes of a verified module are not compared with anything.
    """
    prefix = _normal_prefix(prefix)
    reference: RecordReference | None = None
    workspace_mode = False
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
        entries, workspace_mode = _parse(data)
    except _Unavailable as unavailable:
        return VendorRecord(prefix, "unavailable", str(unavailable), reference, workspace_mode, (), (), 0)
    listed = [entry for entry in entries if entry.packages]
    roots = {_join(prefix, VENDOR, entry.path) for entry in listed}
    budget = [MAX_TREE_ENTRIES]
    modules: list[VendoredModule] = []
    unverified: list[UnverifiedModule] = []
    for entry in sorted(listed, key=lambda item: item.path):
        install_path = _join(prefix, VENDOR, entry.path)
        assert entry.packages is not None and entry.version is not None
        try:
            failure, anchor = _verify(workspace, prefix, install_path, entry, roots - {install_path}, budget)
        except _TreeBound:
            failure, anchor = "bound-exceeded:tree-entries", None
        if failure is not None:
            unverified.append(UnverifiedModule(entry.path, install_path, failure))
            continue
        assert anchor is not None
        modules.append(VendoredModule(
            entry=entry.path, install_path=install_path, name=entry.path, version=entry.version,
            replacement_path=entry.replacement_path, replacement_version=entry.replacement_version,
            explicit=entry.explicit, go_version=entry.go_version, packages=tuple(sorted(entry.packages)),
            anchor=anchor))
    return VendorRecord(prefix, "available", None, reference, workspace_mode, tuple(modules),
                        tuple(unverified), len(entries) - len(listed))


def _parse(data: bytes) -> tuple[list[_Entry], bool]:
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    entries: list[_Entry] = []
    seen_modules: set[str] = set()
    seen_packages: set[str] = set()
    workspace_mode = False
    current: _Entry | None = None
    packages = 0
    for number, raw in enumerate(lines, 1):
        if len(raw) > MAX_LINE_BYTES:
            raise _Unavailable(f"bound-exceeded:line-bytes:{number}")
        try:
            line = raw.decode("utf-8")
        except UnicodeError as exc:
            raise _Unavailable(f"invalid-encoding:{number}") from exc
        line = line.removesuffix("\r")
        invalid = _Unavailable(f"line-invalid:{number}")
        if line.startswith("## "):
            if current is None:
                if line != "## workspace" or number != 1:
                    raise invalid
                workspace_mode = True
                continue
            if current.annotated or current.packages:
                raise invalid
            current.annotated = True
            for token in line[3:].split(";"):
                token = token.strip()
                if token == "explicit" and not current.explicit:
                    current.explicit = True
                elif (token.startswith("go ") and current.go_version is None and
                        _GO_VERSION.fullmatch(token[3:])):
                    current.go_version = token[3:]
                else:
                    raise invalid
            continue
        if line.startswith("# "):
            current = _module_line(line, invalid)
            if current.path in seen_modules:
                raise _Unavailable(f"duplicate-module:{number}")
            if len(entries) >= MAX_MODULES:
                raise _Unavailable("bound-exceeded:modules")
            seen_modules.add(current.path)
            entries.append(current)
            continue
        if not _import_path(line):
            raise invalid
        if (current is None or current.version is None or
                not (line == current.path or line.startswith(current.path + "/"))):
            raise _Unavailable(f"package-outside-module:{number}")
        if line in seen_packages:
            raise _Unavailable(f"duplicate-package:{number}")
        packages += 1
        if packages > MAX_PACKAGES:
            raise _Unavailable("bound-exceeded:packages")
        seen_packages.add(line)
        if current.packages is None:
            current.packages = []
        current.packages.append(line)
    owners = {entry.path for entry in entries if entry.packages}
    for entry in entries:
        for package in entry.packages or ():
            parts = package.split("/")
            # The deepest listed module that contains a package provides it.
            if any("/".join(parts[:size]) in owners
                   for size in range(len(entry.path.split("/")) + 1, len(parts) + 1)):
                raise _Unavailable(f"package-outside-module:{_label(package)}")
    return entries, workspace_mode


def _module_line(line: str, invalid: _Unavailable) -> _Entry:
    fields = line[2:].split(" ")
    if not fields or not _import_path(fields[0]):
        raise invalid
    entry = _Entry(fields[0], None)
    rest = fields[1:]
    if rest and rest[0] != "=>":
        if not _VERSION.fullmatch(rest[0]):
            raise invalid
        entry.version, rest = rest[0], rest[1:]
    if not rest:
        if entry.version is None:
            raise invalid
        return entry
    if rest[0] != "=>" or len(rest) not in (2, 3) or not _replacement_path(rest[1]):
        raise invalid
    entry.replacement_path = rest[1]
    if len(rest) == 3:
        if not _import_path(rest[1]) or not _VERSION.fullmatch(rest[2]):
            raise invalid
        entry.replacement_version = rest[2]
    return entry


def _import_path(value: str) -> bool:
    parts = value.split("/")
    return (0 < len(value) <= 1024 and
            all(_ELEMENT.fullmatch(part) and part not in {".", ".."} and not part.endswith(".")
                for part in parts))


def _replacement_path(value: str) -> bool:
    return bool(value) and all(0x20 < ord(char) != 0x7f for char in value)


def _verify(workspace: Path, prefix: str, install_path: str, entry: _Entry, other_roots: set[str],
            budget: list[int]) -> tuple[str | None, RecordReference | None]:
    if entry.replacement_path is not None and entry.replacement_version is None:
        return "local-replacement", None
    if not _real_directory(workspace, prefix, install_path):
        return "install-path-missing", None
    assert entry.packages is not None
    package_dirs: dict[str, str] = {}
    anchor_name: str | None = None
    for package in sorted(entry.packages):
        directory = _join(prefix, VENDOR, package)
        if not _real_directory(workspace, prefix, directory):
            return f"package-missing:{_label(package)}", None
        sources = _go_files(workspace, directory, budget)
        if not sources:
            return f"package-empty:{_label(package)}", None
        if anchor_name is None:
            anchor_name = _join(directory, sources[0])
        package_dirs[directory] = package
    stack = [install_path]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(workspace / Path(*PurePosixPath(directory).parts)) as iterator:
                children = sorted(iterator, key=lambda item: item.name)
        except OSError:
            return "tree-unreadable", None
        source = False
        for child in children:
            budget[0] -= 1
            if budget[0] < 0:
                raise _TreeBound
            try:
                if child.is_symlink():
                    continue
                if child.is_dir(follow_symlinks=False):
                    nested = _join(directory, child.name)
                    if nested not in other_roots:
                        stack.append(nested)
                elif child.is_file(follow_symlinks=False) and child.name.endswith(".go"):
                    source = True
            except OSError:
                return "tree-unreadable", None
        if source and directory not in package_dirs:
            return f"unrecorded-package:{_label(directory)}", None
    assert anchor_name is not None
    anchor = workspace / Path(*PurePosixPath(anchor_name).parts)
    try:
        if anchor.is_symlink() or not anchor.is_file():
            return "anchor-unreadable", None
        return None, RecordReference(anchor_name, file_sha256(anchor), anchor.stat().st_size)
    except OSError:
        return "anchor-unreadable", None


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


def _go_files(workspace: Path, directory: str, budget: list[int]) -> list[str]:
    names: list[str] = []
    try:
        with os.scandir(workspace / Path(*PurePosixPath(directory).parts)) as iterator:
            for child in iterator:
                budget[0] -= 1
                if budget[0] < 0:
                    raise _TreeBound
                if (child.name.endswith(".go") and not child.is_symlink() and
                        child.is_file(follow_symlinks=False)):
                    names.append(child.name)
    except OSError:
        return []
    return sorted(names)


def _normal_prefix(prefix: str) -> str:
    logical = PurePosixPath(prefix.replace("\\", "/"))
    if logical.is_absolute() or ".." in logical.parts:
        raise ValueError("Go vendor prefix must be workspace-relative")
    return logical.as_posix()


def _join(prefix: str, *parts: str) -> str:
    return PurePosixPath(prefix, *parts).as_posix()


def _relative(workspace: Path, path: Path) -> str:
    return path.relative_to(workspace).as_posix() or "."


def _label(value: str) -> str:
    """Bound target-controlled text before it enters a gap string."""
    text = "".join(char if 0x20 <= ord(char) != 0x7f else "?" for char in value)
    return text if len(text) <= 200 else text[:197] + "..."
