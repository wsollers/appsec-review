#!/usr/bin/env python3
"""Advisory symbols -> the names the language uses, read from the vendored dependency (ADR-0023 decision 6).

Reachability is only as good as the mapping from an advisory ("package X, function Y") to the names
application code writes when it brings X in. ``resolve`` turns (ecosystem, package, version,
advisory symbols) into ``{package, symbol, via}`` rows in the vocabulary the CodeQL packs match
(``vulnerableSymbol(package, symbol)``: a Python import module, an npm module specifier, a Java
package + ``Type.method``, a Go import path, a C# namespace + ``Type.Method``), plus the vendored
source roots that decide the ``through-dependency`` tier. One adapter per ecosystem reads the
dependency's OWN manifest in the checkout:

* PyPI: ``*.dist-info``/``*.egg-info`` ``top_level.txt`` and ``RECORD`` -> import modules;
  ``__init__`` ``from .sub import name`` re-exports; dotted symbols split into module + member.
* npm: ``node_modules/<name>/package.json`` ``exports``/``main``/``module`` (ESM vs CJS) -> the
  bare specifier and deep-import subpaths (``pkg/sub`` is matched as its ``default`` export).
* Maven: jars in the checkout (``zipfile`` listing only, nothing is loaded) whose
  ``META-INF/maven/<g>/<a>/pom.properties`` names the coordinates -> class FQNs; shade
  relocations from the embedded ``pom.xml``; multi-release ``META-INF/versions/<n>/``.
* Go: module path vs package import path (OSV symbols carry the import path), ``go.mod``
  ``replace`` directives (imports keep the original path; a local replacement is the vendored
  root), ``vendor/modules.txt`` packages.
* NuGet: ``packages/<id>.<version>/`` (or a ``.nuspec`` with that id) -> assemblies
  (``lib/<tfm>/*.dll`` names, never opened) and target frameworks; namespaces are the assembly
  names (a recorded heuristic).
* Cargo: ``vendor/<crate>/Cargo.toml`` ``[lib] name`` vs crate name (``-`` -> ``_``).
* Packagist: ``vendor/<vendor>/<pkg>/composer.json`` PSR-4 autoload namespaces (hints only).

Every step is recorded (``steps``) and ends up in the engine row's ``resolution``. A dependency
whose manifest is not in the checkout is resolved heuristically, the step says so, and the gap
``dependency-source-absent:<ecosystem>:<package>`` limits the tier to ``direct``. Nothing here
executes or imports target code: files are read as bytes, bounded, never followed through links,
and every emitted name must match ``dep_reachability.SYMBOL`` / ``PACKAGE``.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Callable, Iterable
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dep_reachability

MAX_FILE_BYTES = 1 << 20
MAX_WALK = 200_000
MAX_NAMES = 64
MAX_JAR_ENTRIES = 100_000
SKIP_DIRS = {".git", ".hg", ".svn"}
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")


@dataclass
class Resolution:
    ecosystem: str
    package: str
    version: str | None
    language: str | None
    names: list[dict[str, str]] = field(default_factory=list)
    vendored_roots: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

    def add(self, package: str, symbol: str, via: str) -> None:
        if (not dep_reachability.PACKAGE.fullmatch(package or "") or not dep_reachability.SYMBOL.fullmatch(symbol or "")
                or len(self.names) >= MAX_NAMES):
            return
        row = {"package": package, "symbol": symbol, "via": dep_reachability.clean_text(via, 200)}
        if not any(item["package"] == package and item["symbol"] == symbol for item in self.names):
            self.names.append(row)

    def step(self, text: str) -> None:
        self.steps.append(dep_reachability.clean_text(text, 300))

    def document(self) -> dict[str, Any]:
        return {"ecosystem": self.ecosystem, "package": self.package, "version": self.version,
                "language": self.language, "names": sorted(self.names, key=lambda r: (r["package"], r["symbol"])),
                "vendored_roots": sorted(set(self.vendored_roots)), "steps": self.steps,
                "gaps": sorted(set(self.gaps))}


class Checkout:
    """Bounded, link-free, read-only view of the target checkout (bytes only; nothing executes)."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self._files: list[str] | None = None

    def files(self) -> list[str]:
        if self._files is None:
            found: list[str] = []
            stack = [self.root]
            while stack and len(found) < MAX_WALK:
                folder = stack.pop()
                try:
                    entries = sorted(folder.iterdir(), key=lambda p: p.name)
                except OSError:
                    continue
                for path in entries:
                    if path.is_symlink():
                        continue
                    if path.is_dir():
                        if path.name not in SKIP_DIRS:
                            stack.append(path)
                    elif path.is_file():
                        found.append(path.relative_to(self.root).as_posix())
            self._files = sorted(found)
        return self._files

    def read(self, relative: str) -> bytes | None:
        pure = PurePosixPath(relative)
        if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
            return None
        path = self.root.joinpath(*pure.parts)
        current = self.root
        for part in pure.parts:
            current = current / part
            if current.is_symlink():
                return None
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_bytes()

    def text(self, relative: str) -> str | None:
        data = self.read(relative)
        return data.decode("utf-8", errors="replace") if data is not None else None

    def json(self, relative: str) -> Any:
        text = self.text(relative)
        try:
            return json.loads(text) if text is not None else None
        except ValueError:
            return None

    def path(self, relative: str) -> Path:
        return self.root.joinpath(*PurePosixPath(relative).parts)


def _symbol_parts(symbol: str) -> list[str]:
    return [part for part in re.split(r"::|\.", symbol) if part]


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ---- PyPI ----------------------------------------------------------------------------------------

def _python(result: Resolution, checkout: Checkout, symbols: list[dict[str, Any]]) -> None:
    wanted = _pep503(result.package)
    modules: list[str] = []
    for relative in checkout.files():
        parts = PurePosixPath(relative).parts
        if len(parts) < 2 or not re.search(r"\.(dist|egg)-info\Z", parts[-2]):
            continue
        folder = parts[-2]
        name = re.sub(r"\.(dist|egg)-info\Z", "", folder)
        dist, _, version = name.partition("-") if folder.endswith(".dist-info") else (name.split("-")[0], "", "")
        if _pep503(dist) != wanted or parts[-1] not in ("top_level.txt", "RECORD", "METADATA", "PKG-INFO"):
            continue
        site = "/".join(parts[:-2])
        if version and result.version and version != result.version:
            result.step(f"pypi: {folder} is version {version}, not {result.version}; ignored")
            continue
        if parts[-1] == "top_level.txt":
            for line in (checkout.text(relative) or "").splitlines():
                module = line.strip()
                if _IDENT.fullmatch(module) and module not in modules:
                    modules.append(module)
                    result.step(f"pypi {result.package} -> import {module} ({relative})")
                    result.vendored_roots.append(f"{site}/{module}" if site else module)
        elif parts[-1] == "RECORD" and not modules:
            for line in (checkout.text(relative) or "").splitlines():
                entry = line.split(",", 1)[0]
                top = PurePosixPath(entry).parts[0] if entry else ""
                if (entry.endswith(".py") and top and not top.endswith((".dist-info", ".data")) and
                        top != ".." and (_IDENT.fullmatch(top.removesuffix(".py")))):
                    module = top.removesuffix(".py")
                    if module not in modules:
                        modules.append(module)
                        result.step(f"pypi {result.package} -> import {module} (RECORD {relative})")
                        result.vendored_roots.append(f"{site}/{top}" if site else top)
    if not modules:
        module = re.sub(r"[-.]+", "_", result.package).lower()
        if _IDENT.fullmatch(module):
            modules.append(module)
        result.step(f"pypi {result.package}: no vendored dist-info/egg-info; heuristic import {module}")
        result.gaps.append(f"dependency-source-absent:pypi:{result.package}")
    reexports = _python_reexports(checkout, result.vendored_roots)
    for item in symbols:
        symbol = item["symbol"]
        parts = _symbol_parts(symbol)
        placed = False
        for module in modules:
            if parts[0] == module and len(parts) >= 2:
                rest = parts[1:]
                if len(rest) == 1:
                    result.add(module, rest[0], f"{symbol} is {module}.{rest[0]}")
                else:
                    # a.b.c.d is either submodule a.b.c member d, or (Type c) submodule a.b member c.d
                    result.add(".".join([module, *rest[:-1]]), rest[-1], f"{symbol}: submodule member")
                    result.add(".".join([module, *rest[:-2]]), ".".join(rest[-2:]), f"{symbol}: Type.member")
                if rest[-1] in reexports.get(module, set()):
                    result.add(module, rest[-1], f"{module}/__init__ re-exports {rest[-1]}")
                placed = True
        if not placed:
            for module in modules:
                result.add(module, symbol, f"{symbol} as a member of import {module}")
                if len(parts) >= 2 and parts[-1] in reexports.get(module, set()):
                    result.add(module, parts[-1], f"{module}/__init__ re-exports {parts[-1]}")


def _python_reexports(checkout: Checkout, roots: Iterable[str]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for root in roots:
        module = PurePosixPath(root).name
        text = checkout.text(f"{root}/__init__.py") or ""
        for match in re.finditer(r"^from[ \t]+\.[\w.]*[ \t]+import[ \t]+(?:\(([^)]*)\)|([\w \t,]+))", text, re.M):
            names = {name.strip().split(" as ")[-1].strip() for name in (match.group(1) or match.group(2)).split(",")}
            found.setdefault(module, set()).update(name for name in names if _IDENT.fullmatch(name))
    return found


# ---- npm -----------------------------------------------------------------------------------------

def _npm(result: Resolution, checkout: Checkout, symbols: list[dict[str, Any]]) -> None:
    manifest_path = None
    for relative in checkout.files():
        if relative.endswith(f"node_modules/{result.package}/package.json") or relative == f"node_modules/{result.package}/package.json":
            document = checkout.json(relative)
            if isinstance(document, dict) and document.get("name") == result.package:
                if result.version and document.get("version") not in (None, result.version):
                    result.step(f"npm: {relative} is version {document.get('version')}, not {result.version}; ignored")
                    continue
                manifest_path = relative
                break
    subpaths: list[str] = []
    if manifest_path is None:
        result.step(f"npm {result.package}: no vendored node_modules/{result.package}/package.json; bare specifier only")
        result.gaps.append(f"dependency-source-absent:npm:{result.package}")
    else:
        document = checkout.json(manifest_path)
        root = manifest_path.rsplit("/", 1)[0]
        result.vendored_roots.append(root)
        kind = "ESM" if document.get("type") == "module" or document.get("module") else "CJS"
        result.step(f"npm {result.package}: {manifest_path} ({kind}; main={document.get('main')!s:.60}, "
                    f"module={document.get('module')!s:.60})")
        exports = document.get("exports")
        if isinstance(exports, dict):
            for key in sorted(exports):
                if isinstance(key, str) and key.startswith("./") and key != "./" and "*" not in key:
                    subpaths.append(key[2:])
            result.step(f"npm {result.package}: exports subpaths {', '.join(subpaths[:12]) or 'none'}")
    for item in symbols:
        symbol = item["symbol"]
        parts = _symbol_parts(symbol)
        member = parts[1:] if parts[0] == result.package and len(parts) > 1 else parts
        joined = ".".join(member[-2:]) if len(member) >= 2 else member[-1]
        result.add(result.package, joined, f"{symbol} as {result.package} export {joined}")
        for sub in subpaths:
            if PurePosixPath(sub).name.removesuffix(".js") == member[-1]:
                result.add(f"{result.package}/{sub}", "default", f"deep import {result.package}/{sub} is {member[-1]}")
        if manifest_path is None and len(member) == 1:
            result.add(f"{result.package}/{member[0]}", "default", f"conventional deep import {result.package}/{member[0]}")


# ---- Maven ---------------------------------------------------------------------------------------

def _jar_classes(path: Path) -> tuple[list[str], dict[str, str], dict[str, str], list[int]]:
    """(class FQNs, pom.properties, relocations pattern->shaded, multi-release versions) of a jar."""
    classes, properties, relocations, versions = [], {}, {}, set()
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()[:MAX_JAR_ENTRIES]
        for entry in entries:
            name = entry.filename
            match = re.fullmatch(r"META-INF/versions/([0-9]{1,3})/(.+)\.class", name)
            if match:
                versions.add(int(match.group(1)))
                name = match.group(2) + ".class"
            if name.endswith(".class") and not name.startswith("META-INF/") and "$" not in name:
                classes.append(name[:-6].replace("/", "."))
            elif re.fullmatch(r"META-INF/maven/[^/]+/[^/]+/pom\.properties", name) and entry.file_size < 65536:
                for line in archive.read(entry).decode("utf-8", errors="replace").splitlines():
                    key, _, value = line.partition("=")
                    properties.setdefault(key.strip(), value.strip())
            elif re.fullmatch(r"META-INF/maven/[^/]+/[^/]+/pom\.xml", name) and entry.file_size < MAX_FILE_BYTES:
                text = archive.read(entry).decode("utf-8", errors="replace")
                for block in re.findall(r"<relocation>(.*?)</relocation>", text, re.S):
                    pattern = re.search(r"<pattern>\s*([\w.]+)\s*</pattern>", block)
                    shaded = re.search(r"<shadedPattern>\s*([\w.]+)\s*</shadedPattern>", block)
                    if pattern and shaded:
                        relocations[pattern.group(1)] = shaded.group(1)
    return sorted(set(classes)), properties, relocations, sorted(versions)


def _maven(result: Resolution, checkout: Checkout, symbols: list[dict[str, Any]]) -> None:
    group, _, artifact = result.package.partition(":")
    classes: list[str] = []
    relocations: dict[str, str] = {}
    for relative in checkout.files():
        if not relative.endswith(".jar") or artifact not in PurePosixPath(relative).name:
            continue
        try:
            found, properties, relocated, versions = _jar_classes(checkout.path(relative))
        except (OSError, zipfile.BadZipFile, KeyError):
            result.step(f"maven: {relative} is not a readable jar; ignored")
            continue
        if properties and (properties.get("groupId"), properties.get("artifactId")) != (group, artifact):
            continue
        if result.version and properties.get("version") not in (None, result.version):
            result.step(f"maven: {relative} is version {properties.get('version')}, not {result.version}; ignored")
            continue
        classes, relocations = found, relocated
        result.vendored_roots.append(relative)
        result.step(f"maven {result.package}: {relative} ({len(found)} classes"
                    + (f"; multi-release {versions}" if versions else "")
                    + (f"; shade relocations {sorted(relocated.items())[:4]}" if relocated else "") + ")")
        break
    if not classes:
        result.step(f"maven {result.package}: no vendored jar in the checkout; package split by naming convention")
        result.gaps.append(f"dependency-source-absent:maven:{result.package}")
    by_simple: dict[str, list[str]] = {}
    for fqn in classes:
        by_simple.setdefault(fqn.rsplit(".", 1)[-1], []).append(fqn)

    def emit(fqn: str, member: str, via: str) -> None:
        package, _, simple = fqn.rpartition(".")
        result.add(package, f"{simple}.{member}" if member else simple, via)
        for pattern, shaded in relocations.items():
            if package == pattern or package.startswith(pattern + "."):
                result.add(shaded + package[len(pattern):], f"{simple}.{member}" if member else simple,
                           f"shade relocation {pattern} -> {shaded}")

    for item in symbols:
        symbol, package = item["symbol"], item.get("package")
        parts = _symbol_parts(symbol)
        fqn_candidates = [".".join(parts[:i]) for i in range(len(parts), 0, -1)]
        match = next((fqn for fqn in fqn_candidates if fqn in classes), None)
        if match is not None:
            emit(match, ".".join(parts[len(match.split(".")):]), f"{symbol}: class {match} in the jar")
            continue
        if parts[0] in by_simple:
            for fqn in by_simple[parts[0]]:
                emit(fqn, ".".join(parts[1:]), f"{symbol}: class {parts[0]} is {fqn}")
            continue
        typed = next((i for i, part in enumerate(parts) if part[:1].isupper()), None)
        if typed:
            result.add(".".join(parts[:typed]), ".".join(parts[typed:typed + 2]), f"{symbol}: package/type by naming convention")
        elif package and package != result.package and "." in package and ":" not in package:
            result.add(package, symbol, f"{symbol} in advisory package {package}")


# ---- Go ------------------------------------------------------------------------------------------

def _go(result: Resolution, checkout: Checkout, symbols: list[dict[str, Any]]) -> None:
    module = result.package
    replacements: dict[str, str] = {}
    text = checkout.text("go.mod") or ""
    for line in re.findall(r"^\s*(?:replace\s+)?(\S+)(?:\s+v\S+)?\s+=>\s+(\S+)", text, re.M):
        replacements[line[0]] = line[1]
    if module in replacements:
        target = replacements[module]
        result.step(f"go.mod replace {module} => {target} (imports keep {module})")
        if target.startswith(("./", "../")):
            local = PurePosixPath(target).as_posix().lstrip("./")
            if any(path.startswith(local + "/") for path in checkout.files()):
                result.vendored_roots.append(local)
    vendored = f"vendor/{module}"
    listed = checkout.text("vendor/modules.txt") or ""
    packages = []
    current = None
    for line in listed.splitlines():
        if line.startswith("# "):
            current = line[2:].split()[0]
        elif current == module and line and not line.startswith("#"):
            packages.append(line.strip())
    if any(path.startswith(vendored + "/") for path in checkout.files()):
        result.vendored_roots.append(vendored)
        result.step(f"go {module}: vendored at {vendored} ({len(packages)} package(s) in vendor/modules.txt)")
    elif not result.vendored_roots:
        result.step(f"go {module}: not vendored; call sites only")
        result.gaps.append(f"dependency-source-absent:golang:{module}")
    for item in symbols:
        symbol, package = item["symbol"], item.get("package")
        path = package if package and (package == module or package.startswith(module + "/")) else module
        if package and path != package:
            result.step(f"go: advisory path {package} is outside module {module}; used {module}")
        if packages and path not in packages and path != module:
            result.step(f"go: {path} is not listed in vendor/modules.txt")
        result.add(path, symbol, f"{symbol} in import path {path}")


# ---- NuGet ---------------------------------------------------------------------------------------

def _nuget(result: Resolution, checkout: Checkout, symbols: list[dict[str, Any]]) -> None:
    lower = result.package.lower()
    assemblies, frameworks, root = set(), set(), None
    for relative in checkout.files():
        parts = PurePosixPath(relative).parts
        for index, part in enumerate(parts[:-1]):
            low = part.lower()
            if low == lower or (low.startswith(lower + ".") and re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", low[len(lower) + 1:])):
                version = part[len(result.package) + 1:] if len(part) > len(result.package) else None
                if result.version and version and version != result.version:
                    continue
                if index + 2 < len(parts) and parts[index + 1] == "lib" and relative.endswith(".dll"):
                    frameworks.add(parts[index + 2])
                    assemblies.add(PurePosixPath(relative).stem)
                    root = "/".join(parts[:index + 1])
                elif relative.lower().endswith(".nuspec"):
                    root = root or "/".join(parts[:index + 1])
    if root:
        result.vendored_roots.append(root)
        result.step(f"nuget {result.package}: {root} (assemblies {sorted(assemblies)[:6]}, frameworks {sorted(frameworks)[:6]})")
    else:
        result.step(f"nuget {result.package}: no vendored package folder; namespace = package id (heuristic)")
        result.gaps.append(f"dependency-source-absent:nuget:{result.package}")
    namespaces = sorted(assemblies | {result.package}, key=len, reverse=True)
    for item in symbols:
        symbol = item["symbol"]
        placed = False
        for namespace in namespaces:
            if symbol.startswith(namespace + "."):
                rest = symbol[len(namespace) + 1:].split(".")
                result.add(namespace, ".".join(rest[-2:]) if len(rest) >= 2 else rest[0],
                           f"{symbol}: namespace {namespace} (assembly name)")
                placed = True
                break
        if not placed:
            for namespace in namespaces:
                result.add(namespace, symbol, f"{symbol} in namespace {namespace} (assembly name heuristic)")


# ---- Cargo ---------------------------------------------------------------------------------------

def _cargo(result: Resolution, checkout: Checkout, symbols: list[dict[str, Any]]) -> None:
    lib = result.package.replace("-", "_")
    manifest = None
    for relative in checkout.files():
        if relative.endswith("/Cargo.toml") and PurePosixPath(relative).parent.name in (
                result.package, f"{result.package}-{result.version}" if result.version else result.package):
            text = checkout.text(relative) or ""
            name = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.M)
            if name and name.group(1) == result.package:
                manifest = relative
                section = re.search(r"^\[lib\](.*?)(^\[|\Z)", text, re.M | re.S)
                named = re.search(r'^\s*name\s*=\s*"([A-Za-z_][A-Za-z0-9_]*)"', section.group(1), re.M) if section else None
                if named:
                    lib = named.group(1)
                result.vendored_roots.append(relative.rsplit("/", 1)[0])
                result.step(f"cargo {result.package}: {relative} lib name {lib}")
                break
    if manifest is None:
        result.step(f"cargo {result.package}: not vendored; lib name {lib} by convention")
        result.gaps.append(f"dependency-source-absent:cargo:{result.package}")
    for item in symbols:
        parts = _symbol_parts(item["symbol"])
        if parts and parts[0] in (result.package, result.package.replace("-", "_"), lib):
            parts = parts[1:]
        if parts:
            result.add(lib, "::".join(parts), f"{item['symbol']} as {lib}::{'::'.join(parts)}")


# ---- Packagist (hints only) ------------------------------------------------------------------------

def _composer(result: Resolution, checkout: Checkout, symbols: list[dict[str, Any]]) -> None:
    relative = f"vendor/{result.package}/composer.json"
    document = checkout.json(relative)
    namespaces: list[str] = []
    if isinstance(document, dict):
        autoload = (document.get("autoload") or {}).get("psr-4") or {}
        namespaces = [key.rstrip("\\") for key in autoload if isinstance(key, str) and key.strip("\\")]
        result.vendored_roots.append(f"vendor/{result.package}")
        result.step(f"packagist {result.package}: PSR-4 {namespaces[:6]} (hints only; no CodeQL extractor)")
    else:
        result.step(f"packagist {result.package}: not vendored (hints only)")
        result.gaps.append(f"dependency-source-absent:composer:{result.package}")
    for item in symbols:
        for namespace in namespaces or [result.package.split("/")[-1]]:
            package = namespace.replace("\\", ".")
            result.add(package, item["symbol"].replace("\\", "."), f"{item['symbol']} under namespace {namespace}")


ADAPTERS: dict[str, tuple[str | None, Callable[[Resolution, Checkout, list[dict[str, Any]]], None]]] = {
    "pypi": ("python", _python), "npm": ("javascript", _npm), "maven": ("java", _maven),
    "golang": ("go", _go), "nuget": ("csharp", _nuget), "cargo": ("rust", _cargo),
    "composer": ("php", _composer),
}


def resolve(ecosystem: str, package: str, version: str | None, symbols: list[dict[str, Any]],
            checkout: Checkout | Path) -> dict[str, Any]:
    """The language-level names for validated advisory symbols (``dep_reachability.clean_symbols`` rows)."""
    checkout = checkout if isinstance(checkout, Checkout) else Checkout(Path(checkout))
    language, adapter = ADAPTERS.get(ecosystem, (dep_reachability.ECOSYSTEMS.get(ecosystem, (None, None))[0], None))
    result = Resolution(ecosystem=ecosystem, package=package, version=version, language=language)
    if not symbols:
        result.step("no advisory symbols: package-level presence only")
        result.gaps.append("no-advisory-symbols")
        return result.document()
    if adapter is None:
        for item in symbols:
            result.add(item.get("package") or package, item["symbol"], "native: symbol name as written")
        result.step(f"{ecosystem}: no language resolver (native ecosystems match function names in the CPG)")
        return result.document()
    adapter(result, checkout, symbols)
    if not result.names:
        result.gaps.append(f"symbols-unresolved:{ecosystem}:{package}")
    return result.document()


def tier(witness_call_file: str | None, vendored_roots: Iterable[str]) -> str:
    """``through-dependency`` when the vulnerable call sits inside the vendored dependency source."""
    if witness_call_file:
        for root in vendored_roots:
            if witness_call_file == root or witness_call_file.startswith(root.rstrip("/") + "/"):
                return "through-dependency"
    return "direct"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ecosystem", required=True, choices=sorted(dep_reachability.ECOSYSTEMS))
    parser.add_argument("--package", required=True)
    parser.add_argument("--version")
    parser.add_argument("--symbols", type=Path, required=True, help='JSON [{"package": .., "symbol": ..}]')
    parser.add_argument("--checkout", type=Path, required=True)
    args = parser.parse_args(argv)
    rows, rejected = dep_reachability.clean_symbols(json.loads(args.symbols.read_text()), "reviewed-map")
    if rejected:
        print(f"{rejected} symbol row(s) rejected", file=sys.stderr)
    print(json.dumps(resolve(args.ecosystem, args.package, args.version, rows, args.checkout), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
