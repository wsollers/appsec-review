"""Load-time import hook that executes only signature-verified source from a ``VerifiedManifest``.

Stdlib-only and loadable either as ``appsec_review.signing.import_hook`` or standalone by file path. A
standalone loader must first execute ``core.py`` as ``appsec_review_signing_core`` and ``modules.py``
as ``appsec_review_signing_modules`` in ``sys.modules``; this module never searches ``sys.path``.
Standalone loaders register this module as ``appsec_review_signing_import_hook`` (see
``bootstrap.py``).

The installed finder claims the manifest package and every dotted name below it, resolves them only
from the manifest, and raises for anything it cannot resolve, so no later finder, bytecode cache, or
zip importer is ever consulted for a claimed name. The ``path`` argument and every ``__path__`` are
ignored during resolution: editing a package's ``__path__`` cannot add a source. Data read through
``__file__``-derived paths instead of the verified resource reader is covered only by the startup tree
verification.
"""
import importlib.abc
import importlib.machinery
import importlib.resources.abc
import importlib.util
import io
import linecache
import os
from pathlib import PurePosixPath
import sys
from typing import Any, Optional

if __package__:
    from . import modules as _modules
else:
    _modules = sys.modules.get("appsec_review_signing_modules")
    if _modules is None:
        raise ImportError("standalone loading requires appsec_review_signing_modules in sys.modules")


SignatureVerificationError = _modules.SignatureVerificationError
VerifiedManifest = _modules.VerifiedManifest


class _VerifiedSpec(importlib.machinery.ModuleSpec):
    """A located spec that never names a bytecode cache."""

    @property
    def cached(self) -> None:
        return None

    @cached.setter
    def cached(self, value: Any) -> None:
        pass


def _directory_path(manifest: VerifiedManifest, parts: tuple[str, ...]) -> str:
    return os.path.join(str(manifest.root), *parts)


class _VerifiedTraversable(importlib.resources.abc.Traversable):
    """A manifest-derived resource path whose reads return only verified bytes."""

    def __init__(self, manifest: VerifiedManifest, directories: frozenset, parts: tuple[str, ...]) -> None:
        self._manifest = manifest
        self._directories = directories
        self._parts = parts

    @property
    def _relpath(self) -> str:
        return "/".join(self._parts)

    @property
    def name(self) -> str:
        return self._parts[-1] if self._parts else self._manifest.root.name

    def __repr__(self) -> str:
        return f"<verified resource {self._manifest.package}:{self._relpath or '.'}>"

    def __eq__(self, other: object) -> bool:
        return (isinstance(other, _VerifiedTraversable) and other._manifest is self._manifest
                and other._parts == self._parts)

    def __hash__(self) -> int:
        return hash((id(self._manifest), self._parts))

    def is_dir(self) -> bool:
        return self._parts in self._directories

    def is_file(self) -> bool:
        return self._relpath in self._manifest.files

    def iterdir(self):
        if not self.is_dir():
            raise NotADirectoryError(f"not a verified resource directory: {self!r}")
        depth = len(self._parts)
        children = set()
        for relpath in self._manifest.files:
            parts = tuple(relpath.split("/"))
            if len(parts) > depth and parts[:depth] == self._parts:
                children.add(parts[depth])
        for child in sorted(children):
            yield _VerifiedTraversable(self._manifest, self._directories, (*self._parts, child))

    def joinpath(self, *descendants: Any) -> "_VerifiedTraversable":
        parts = list(self._parts)
        for descendant in descendants:
            descendant = os.fspath(descendant)
            if not isinstance(descendant, str) or "\\" in descendant or "\x00" in descendant:
                raise ValueError(f"unsupported resource path {descendant!r}")
            path = PurePosixPath(descendant)
            if path.is_absolute():
                raise ValueError(f"resource paths must be relative: {descendant!r}")
            for part in path.parts:
                if part == "..":
                    raise ValueError(f"resource paths must not leave the package: {descendant!r}")
                parts.append(part)
        return _VerifiedTraversable(self._manifest, self._directories, tuple(parts))

    def __truediv__(self, child: Any) -> "_VerifiedTraversable":
        return self.joinpath(child)

    def read_bytes(self) -> bytes:
        if self.is_dir():
            raise IsADirectoryError(f"verified resource is a directory: {self!r}")
        if not self.is_file():
            raise FileNotFoundError(f"resource is not in the signed manifest: {self!r}")
        return self._manifest.read_verified(self._relpath)

    def read_text(self, encoding: Optional[str] = None, errors: Optional[str] = None) -> str:
        with self.open("r", encoding=encoding, errors=errors) as handle:
            return handle.read()

    def open(self, mode: str = "r", *args: Any, **kwargs: Any):
        if mode not in {"r", "rb"}:
            raise ValueError(f"verified resources open only in 'r' or 'rb' mode, not {mode!r}")
        stream = io.BytesIO(self.read_bytes())
        if mode == "rb":
            return stream
        return io.TextIOWrapper(stream, *args, **kwargs)


class VerifiedResourceReader(importlib.resources.abc.TraversableResources):
    """``importlib.resources`` reader rooted at one verified package directory."""

    def __init__(self, manifest: VerifiedManifest, directories: frozenset, parts: tuple[str, ...]) -> None:
        self._root = _VerifiedTraversable(manifest, directories, parts)

    def files(self) -> _VerifiedTraversable:
        return self._root


class _ManifestLoader:
    def __init__(self, finder: "VerifiedFinder", fullname: str, directory: tuple[str, ...]) -> None:
        self._finder = finder
        self.name = fullname
        self._directory = directory

    def _check_name(self, fullname: Optional[str]) -> None:
        if fullname is not None and fullname != self.name:
            raise ImportError(f"loader for {self.name!r} cannot handle {fullname!r}", name=fullname)

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> None:
        return None

    def get_resource_reader(self, fullname: str) -> VerifiedResourceReader:
        self._check_name(fullname)
        return VerifiedResourceReader(self._finder.manifest, self._finder.directories, self._directory)


class VerifiedSourceLoader(_ManifestLoader, importlib.abc.ExecutionLoader):
    """Read a listed source file once through the manifest, compile those bytes, and execute them."""

    def __init__(self, finder: "VerifiedFinder", fullname: str, relpath: str, package: bool) -> None:
        parts = tuple(relpath.split("/"))
        super().__init__(finder, fullname, parts[:-1])
        self._relpath = relpath
        self._package = package
        self.path = os.path.join(str(finder.manifest.root), *parts)

    def is_package(self, fullname: str) -> bool:
        self._check_name(fullname)
        return self._package

    def get_filename(self, fullname: Optional[str] = None) -> str:
        self._check_name(fullname)
        return self.path

    def _read(self) -> bytes:
        return self._finder.manifest.read_verified(self._relpath)

    def _compile(self, data: bytes):
        return compile(data, self.path, "exec", dont_inherit=True)

    def get_source(self, fullname: str) -> str:
        self._check_name(fullname)
        return importlib.util.decode_source(self._read())

    def get_code(self, fullname: str):
        self._check_name(fullname)
        return self._compile(self._read())

    def exec_module(self, module: Any) -> None:
        self._check_name(module.__name__)
        data = self._read()
        code = self._compile(data)
        lines = importlib.util.decode_source(data).splitlines(True)
        # An mtime of None keeps checkcache from replacing the verified lines with on-disk content.
        linecache.cache[self.path] = (len(data), None, lines, self.path)
        module.__file__ = self.path
        module.__cached__ = None
        if self._package:
            module.__path__ = [_directory_path(self._finder.manifest, self._directory)]
        exec(code, module.__dict__)


class VerifiedNamespaceLoader(_ManifestLoader, importlib.abc.InspectLoader):
    """Create an empty namespace package pinned to a verified directory with listed descendants."""

    def is_package(self, fullname: str) -> bool:
        self._check_name(fullname)
        return True

    def get_source(self, fullname: str) -> str:
        self._check_name(fullname)
        return ""

    def get_code(self, fullname: str):
        self._check_name(fullname)
        return compile("", "<string>", "exec", dont_inherit=True)

    def exec_module(self, module: Any) -> None:
        self._check_name(module.__name__)
        module.__path__ = [_directory_path(self._finder.manifest, self._directory)]


class VerifiedFinder(importlib.abc.MetaPathFinder):
    """Claim ``manifest.package`` and its descendants and resolve them only from the manifest."""

    def __init__(self, manifest: VerifiedManifest) -> None:
        if not isinstance(manifest, VerifiedManifest):
            raise TypeError("VerifiedFinder requires a VerifiedManifest")
        self.manifest = manifest
        self.package = manifest.package
        directories = {()}
        for relpath in manifest.files:
            parts = tuple(relpath.split("/"))
            for depth in range(1, len(parts)):
                directories.add(parts[:depth])
        self.directories = frozenset(directories)

    def claims(self, fullname: str) -> bool:
        return fullname == self.package or fullname.startswith(self.package + ".")

    def _parts(self, fullname: str) -> tuple[str, ...]:
        parts = tuple(fullname.split("."))[1:]
        if not all(part.isidentifier() for part in parts):
            raise ModuleNotFoundError(f"No module named {fullname!r} in the signed manifest", name=fullname)
        return parts

    def resolve(self, fullname: str) -> tuple[str, Optional[str], tuple[str, ...]]:
        """Return ``(kind, relpath, parts)`` with kind ``package``, ``module`` or ``namespace``."""
        parts = self._parts(fullname)
        files = self.manifest.files
        directory = "/".join(parts)
        init = f"{directory}/__init__.py" if parts else "__init__.py"
        is_package = init in files
        module = f"{directory}.py"
        is_module = bool(parts) and module in files
        if is_package and is_module:
            raise ImportError(f"signed manifest lists both a package and a module for {fullname!r}", name=fullname)
        if is_package:
            return "package", init, parts
        if is_module:
            return "module", module, parts
        if parts in self.directories:
            return "namespace", None, parts
        raise ModuleNotFoundError(f"No module named {fullname!r} in the signed manifest", name=fullname)

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Optional[importlib.machinery.ModuleSpec]:
        if not self.claims(fullname):
            return None
        kind, relpath, parts = self.resolve(fullname)
        if kind == "namespace":
            spec = importlib.machinery.ModuleSpec(
                fullname, VerifiedNamespaceLoader(self, fullname, parts), origin=None, is_package=True)
            spec.submodule_search_locations = [_directory_path(self.manifest, parts)]
            return spec
        loader = VerifiedSourceLoader(self, fullname, relpath, kind == "package")
        spec = _VerifiedSpec(fullname, loader, origin=loader.path, is_package=kind == "package")
        spec.has_location = True
        if kind == "package":
            spec.submodule_search_locations = [_directory_path(self.manifest, parts)]
        return spec

    def invalidate_caches(self) -> None:
        pass

    def uninstall(self) -> None:
        """Remove this finder from ``sys.meta_path``; intended for tests."""
        while self in sys.meta_path:
            sys.meta_path.remove(self)

    def check_imported(self) -> None:
        """Re-verify every already-imported claimed module against the manifest."""
        for name, module in list(sys.modules.items()):
            if module is not None and self.claims(name):
                self._check_imported_module(name, module)

    def _check_imported_module(self, name: str, module: Any) -> None:
        try:
            kind, relpath, parts = self.resolve(name)
        except ImportError as error:
            raise SignatureVerificationError(f"already-imported module {name!r} is not signed: {error}") from error
        filename = getattr(module, "__file__", None)
        if filename is None:
            expected = [_directory_path(self.manifest, parts)]
            if kind != "namespace" or [os.path.realpath(entry) for entry in getattr(module, "__path__", ())] != expected:
                raise SignatureVerificationError(
                    f"already-imported module {name!r} was not loaded from the verified package root")
            return
        if relpath is None or not isinstance(filename, str):
            raise SignatureVerificationError(f"already-imported module {name!r} has no signed source file")
        if os.path.realpath(filename) != os.path.join(str(self.manifest.root), *relpath.split("/")):
            raise SignatureVerificationError(
                f"already-imported module {name!r} was loaded from {filename!r}, not the verified {relpath}")
        self.manifest.read_verified(relpath)


def install_verified_import_hook(manifest: VerifiedManifest) -> VerifiedFinder:
    """Verify already-imported claimed modules, disable bytecode writes, and install the finder first.

    Re-hashing catches modules imported from changed or unlisted sources, but not bytecode that a
    standard loader executed before installation; install the hook before importing the package.
    """
    finder = VerifiedFinder(manifest)
    finder.check_imported()
    sys.dont_write_bytecode = True
    sys.meta_path.insert(0, finder)
    return finder
