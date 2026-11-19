"""Indexed OSV version matching and vulnerable-symbol / native FFI call-site reachability."""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
from typing import Any
from urllib.parse import parse_qsl, unquote

from appsec_review import osv_matching
from appsec_review.jobs.job_dependency_intelligence.resolution import _version_claim
from appsec_review.jobs.job_dependency_intelligence.native_advisories import purl_parts
from appsec_review.storage import file_sha256
from appsec_review.storage.shared import safe_path


REACHABILITY_SCHEMA = "appsec-review/sca-reachability/1"
OSV_MATCHING_MODES = ("index", "exact", "disabled")
REACHABILITY_SYMBOL = "symbol_reachable"
REACHABILITY_IMPORTED = "package_imported"
REACHABILITY_TRANSITIVE = "transitive_only"
REACHABILITY_UNREACHABLE = "unreachable_in_target"
REACHABILITY_UNKNOWN = "unknown"

PURL_TO_OSV_ECOSYSTEM: Mapping[str, str] = {
    "cargo": "crates.io",
    "composer": "Packagist",
    "gem": "RubyGems",
    "golang": "Go",
    "maven": "Maven",
    "npm": "npm",
    "nuget": "NuGet",
    "pypi": "PyPI",
}
DECLARED_TO_OSV_ECOSYSTEM: Mapping[str, str] = {
    "cargo": "crates.io",
    "crates.io": "crates.io",
    "rust": "crates.io",
    "composer": "Packagist",
    "packagist": "Packagist",
    "php": "Packagist",
    "gem": "RubyGems",
    "rubygems": "RubyGems",
    "ruby": "RubyGems",
    "go": "Go",
    "golang": "Go",
    "gomod": "Go",
    "maven": "Maven",
    "gradle": "Maven",
    "java": "Maven",
    "npm": "npm",
    "node": "npm",
    "javascript": "npm",
    "typescript": "npm",
    "nuget": "NuGet",
    "dotnet": "NuGet",
    "csharp": "NuGet",
    "pypi": "PyPI",
    "pip": "PyPI",
    "python": "PyPI",
}

_VENDOR_SEGMENTS = frozenset({
    "third_party", "third-party", "3rdparty", "vendor", "vendored",
    "external", "externals", "deps", "node_modules", ".venv", "venv",
})
_SOURCE_EXTENSIONS = frozenset({
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".go", ".rs", ".rb", ".php", ".java", ".kt", ".cs",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
})
_SOURCE_ECOSYSTEM = {
    suffix: ecosystem
    for ecosystem, suffixes in (
        ("PyPI", (".py", ".pyi")), ("npm", (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")),
        ("Go", (".go",)), ("crates.io", (".rs",)), ("RubyGems", (".rb",)),
        ("Packagist", (".php",)), ("Maven", (".java", ".kt")), ("NuGet", (".cs",)),
        ("native", (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx")),
    )
    for suffix in suffixes
}
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
# Language import extractors (line-oriented, bounded, deterministic)
_JS_IMPORT_RE = re.compile(r"""(?:from|import)\s+['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\)""")
_GO_IMPORT_RE = re.compile(r"""^\s*(?:import\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s+)?["']([^"']+)["']""")
_RUST_USE_RE = re.compile(r"^\s*(?:pub\s+)?(?:use|extern\s+crate)\s+([A-Za-z_][A-Za-z0-9_:]*)")
_RUBY_REQUIRE_RE = re.compile(r"""^\s*require(?:_relative)?\s*\(?\s*['"]([^'"]+)['"]""")
_PHP_USE_RE = re.compile(r"^\s*use\s+([A-Za-z_\\][A-Za-z0-9_\\]*)")
_JAVA_IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z_][A-Za-z0-9_.*]*)\s*;")
_CS_USING_RE = re.compile(r"^\s*using\s+(?:static\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*;")
_C_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]')

# Native FFI boundary patterns across all 8 required ecosystems:
# C/C++ extern "C" & dlopen, Python ctypes/cffi, Java JNI, C# P/Invoke DllImport/LibraryImport,
# Ruby FFI, Rust extern / #[link], Go cgo, PHP FFI.
_FFI_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("python_ctypes", re.compile(
        r"""\bctypes\.(?:CDLL|WinDLL|OleDLL|PyDLL|cdll\.LoadLibrary|windll\.LoadLibrary)\s*\(\s*['"]?([^'")\s,]+)"""
    )),
    ("python_cffi", re.compile(
        r"""\bffi\.(?:dlopen|cdef)\s*\(\s*['"]?([^'")\s,]+)"""
    )),
    ("csharp_pinvoke", re.compile(
        r"""\[\s*(?:DllImport|LibraryImport)\s*\(\s*['"]([^'"]+)['"](?:[^]]*EntryPoint\s*=\s*['"]([^'"]+)['"])?"""
    )),
    ("csharp_nativelibrary", re.compile(
        r"""\bNativeLibrary\.(?:Load|TryLoad)\s*\(\s*['"]([^'"]+)['"]"""
    )),
    ("java_jni", re.compile(
        r"""\bSystem\.(?:loadLibrary|load)\s*\(\s*['"]([^'"]+)['"]|\bNative\.load\s*\(\s*['"]([^'"]+)['"]"""
    )),
    ("java_jni_method", re.compile(
        r"""\b(?:public|private|protected|static|\s)+native\s+[A-Za-z0-9_<>\[\].]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("""
    )),
    ("ruby_ffi", re.compile(
        r"""\b(?:ffi_lib|Fiddle\.dlopen)\s*\(?\s*['":]([^'")\s,]+)|\battach_function\s+:([A-Za-z_][A-Za-z0-9_]*)"""
    )),
    ("rust_extern", re.compile(
        r"""#\[\s*link\s*\(\s*name\s*=\s*['"]([^'"]+)['"]|\bextern\s+"C"\s*(?:\{|\s+fn\s+([A-Za-z_][A-Za-z0-9_]*))"""
    )),
    ("go_cgo", re.compile(
        r"""#cgo\s+[^:\n]*LDFLAGS:[^\n]*-l([A-Za-z0-9_+-]+)|\bC\.([A-Za-z_][A-Za-z0-9_]*)\s*\("""
    )),
    ("php_ffi", re.compile(
        r"""\bFFI::(?:cdef|load)\s*\((?:\s*['"][^'"]*['"]\s*,\s*['"]([^'"]+)['"]|\s*['"]([^'"]+)['"])"""
    )),
    ("cpp_extern_c", re.compile(
        r"""\bextern\s+"C"\s*(?:\{|\s+[A-Za-z_][A-Za-z0-9_*\s]+\b([A-Za-z_][A-Za-z0-9_]*)\s*\()|\b(?:dlopen|dlsym)\s*\(\s*[^,)]*['"]([^'"]+)['"]"""
    )),
)


@dataclass(frozen=True, slots=True)
class DependencyIntelligenceSettings:
    """Typed settings extension for OSV version matching and SCA reachability."""

    osv_version_matching: str = "index"
    reachability_enabled: bool = True
    max_source_files: int = 2000
    max_bytes_per_file: int = 524288
    max_call_sites_per_advisory: int = 32
    max_advisories: int = 5000
    max_osv_candidates_per_package: int = 500

    def __post_init__(self) -> None:
        if self.osv_version_matching not in OSV_MATCHING_MODES:
            raise ValueError(
                f"osv_version_matching must be one of {', '.join(OSV_MATCHING_MODES)}: "
                f"{self.osv_version_matching!r}"
            )
        for field_name in ("max_source_files", "max_bytes_per_file", "max_call_sites_per_advisory",
                           "max_advisories", "max_osv_candidates_per_package"):
            val = getattr(self, field_name)
            if type(val) is not int or val < 1:
                raise ValueError(f"dependency-intelligence {field_name} must be a positive integer")
        if type(self.reachability_enabled) is not bool:
            raise ValueError("dependency-intelligence reachability_enabled must be boolean")

    @classmethod
    def from_settings(cls, settings: Mapping[str, Any] | None) -> "DependencyIntelligenceSettings":
        raw = settings if isinstance(settings, Mapping) else {}
        return cls(
            osv_version_matching=str(raw.get("osv_version_matching", "index"))
            if isinstance(raw.get("osv_version_matching", "index"), str)
            else raw.get("osv_version_matching"),  # type: ignore[arg-type]
            reachability_enabled=raw.get("reachability_enabled", True),
            max_source_files=raw.get("max_source_files", 2000),
            max_bytes_per_file=raw.get("max_bytes_per_file", 524288),
            max_call_sites_per_advisory=raw.get("max_call_sites_per_advisory", 32),
            max_advisories=raw.get("max_advisories", 5000),
            max_osv_candidates_per_package=raw.get("max_osv_candidates_per_package", 500),
        )


OsvSnapshotSource = Mapping[str, Any] | None


def _clean_lib_stem(raw: str) -> str:
    base = raw.strip().replace("\\", "/").rsplit("/", 1)[-1]
    base = re.sub(r"\.(?:so|dll|dylib|a|lib|h|hpp|hh)(?:\.[0-9]+)*$", "", base, flags=re.IGNORECASE)
    if base.lower().startswith("lib") and len(base) > 3:
        return base[3:].casefold()
    return base.casefold()


def _normalize_pkg_token(name: str) -> str:
    cleaned = name.strip().casefold()
    if "/" in cleaned and not cleaned.startswith("@"):
        cleaned = cleaned.rsplit("/", 1)[-1]
    elif cleaned.startswith("@") and "/" in cleaned:
        cleaned = cleaned.split("/", 1)[1]
    if ":" in cleaned:
        cleaned = cleaned.rsplit(":", 1)[-1]
    return re.sub(r"[-_.]+", "_", cleaned).strip("_")


def _candidate_module_stems(package_name: str, purl: str | None, affected_modules: Sequence[str]) -> set[str]:
    stems: set[str] = set()
    for candidate in (package_name, *affected_modules):
        if not candidate:
            continue
        raw = candidate.strip().casefold()
        stems.add(raw)
        norm = _normalize_pkg_token(raw)
        if norm:
            stems.add(norm)
            if norm.startswith("lib") and len(norm) > 3:
                stems.add(norm[3:])
    if purl:
        parsed = purl_parts(purl)
        if parsed is not None:
            norm = _normalize_pkg_token(parsed[1])
            if norm:
                stems.add(norm)
                if norm.startswith("lib") and len(norm) > 3:
                    stems.add(norm[3:])
    return {s for s in stems if len(s) >= 1}


def _is_first_party_source(rel_path: str) -> bool:
    try:
        posix = PurePosixPath(rel_path.replace("\\", "/"))
    except ValueError:
        return False
    if posix.is_absolute() or ".." in posix.parts:
        return False
    lowered_parts = {p.casefold() for p in posix.parts[:-1]}
    if lowered_parts & _VENDOR_SEGMENTS:
        return False
    return posix.suffix.casefold() in _SOURCE_EXTENSIONS


def _python_symbol_uses(
    text: str, rel_path: str, local_modules: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Resolve only immutable, top-level import bindings; ambiguous scopes fail closed."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return [], [], [f"reachability_python_parse_failed:{rel_path}"]
    imports: list[dict[str, Any]] = []
    bindings: dict[str, tuple[str, int]] = {}
    invalid: set[str] = set()
    uncertain = False
    top_level_nodes = {id(node) for node in tree.body}

    def root_name(node: ast.AST) -> str | None:
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        return node.id if isinstance(node, ast.Name) else None

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            top_level = id(node) in top_level_nodes
            relative = isinstance(node, ast.ImportFrom) and bool(node.level)
            for alias in node.names:
                module = (node.module or "") if isinstance(node, ast.ImportFrom) else alias.name
                local_module = module.split(".")[0] in local_modules or relative
                imports.append({
                    "path": rel_path, "line": node.lineno, "module": module,
                    "symbols": [alias.name] if isinstance(node, ast.ImportFrom) else [],
                    "local_module": local_module,
                })
                local = alias.asname or (alias.name if isinstance(node, ast.ImportFrom)
                                        else alias.name.split(".")[0])
                if alias.name == "*":
                    uncertain = True
                    continue
                qualified = f"{module}.{alias.name}" if isinstance(node, ast.ImportFrom) else (
                    alias.name if alias.asname else local)
                if not top_level or local_module or local in bindings:
                    invalid.add(local)
                bindings[local] = (qualified, node.lineno)
        elif isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            name = root_name(node)
            if name:
                invalid.add(name)
        elif isinstance(node, ast.arg):
            invalid.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            invalid.add(node.name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            invalid.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            invalid.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            invalid.add(node.rest)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            invalid.update(node.names)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {
            "exec", "eval", "globals", "locals", "vars", "setattr", "delattr",
        }:
            uncertain = True

    calls: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or uncertain:
            continue
        func = node.func
        members: list[str] = []
        while isinstance(func, ast.Attribute):
            members.append(func.attr)
            func = func.value
        if not isinstance(func, ast.Name) or func.id in invalid or func.id not in bindings:
            continue
        qualified, import_line = bindings[func.id]
        if node.lineno <= import_line:
            continue
        name = ".".join([qualified, *reversed(members)])
        calls.append({"path": rel_path, "line": node.lineno, "qualified_symbol": name})
    gaps = []
    if uncertain or invalid.intersection(bindings):
        gaps.append(f"reachability_python_binding_ambiguous:{rel_path}")
    return imports, calls, gaps


def scan_target_reachability_index(
    *,
    target_root: Path | None,
    partition_files: Sequence[Mapping[str, Any]] = (),
    max_source_files: int = 2000,
    max_bytes_per_file: int = 524288,
) -> dict[str, Any]:
    """Scan bounded first-party target source files for imports, symbol calls, and native FFI boundaries."""
    imports: list[dict[str, Any]] = []
    ffi_sites: list[dict[str, Any]] = []
    bound_calls: list[dict[str, Any]] = []
    gaps: list[str] = []
    source_hashes: dict[str, str] = {}

    if target_root is None or not target_root.is_dir():
        return {"imports": imports, "ffi_sites": ffi_sites,
                "bound_calls": bound_calls, "source_hashes": source_hashes,
                "gaps": ["reachability_target_unavailable"]}

    candidates: dict[str, Mapping[str, Any]] = {}
    for entry in partition_files:
        if entry.get("domain", "target") != "target":
            continue
        rel = str(entry.get("path") or "")
        safe_path(target_root, rel)
        if _is_first_party_source(rel):
            if rel in candidates and candidates[rel] != entry:
                raise ValueError("conflicting accepted reachability source identities")
            candidates[rel] = entry
    if not candidates:
        gaps.append("reachability_partition_empty: no accepted first-party source files")
    if len(candidates) > max_source_files:
        gaps.append(f"reachability_source_files_truncated: {len(candidates) - max_source_files} files not scanned")

    local_modules = {
        part
        for path in candidates if PurePosixPath(path).suffix.casefold() in {".py", ".pyi"}
        for part in (*PurePosixPath(path).parts[:-1], PurePosixPath(path).stem)
    }
    for rel_path in sorted(candidates)[:max_source_files]:
        entry = candidates[rel_path]
        sha = entry.get("sha256")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError("reachability source has no accepted SHA-256")
        full_path = safe_path(target_root, rel_path)
        size = full_path.stat().st_size
        if size != entry.get("size_bytes", size):
            raise ValueError(f"accepted reachability source size changed: {rel_path}")
        if size > max_bytes_per_file:
            gaps.append(f"reachability_source_bytes_exceeded: {rel_path}")
            continue
        with full_path.open("rb") as stream:
            raw = stream.read(max_bytes_per_file + 1)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError(f"accepted reachability source bytes changed: {rel_path}")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            gaps.append(f"reachability_source_encoding_unsupported: {rel_path}")
            continue
        source_hashes[rel_path] = sha
        suffix = PurePosixPath(rel_path).suffix.casefold()
        if suffix in {".py", ".pyi"}:
            python_imports, python_calls, python_gaps = _python_symbol_uses(text, rel_path, local_modules)
            imports.extend(python_imports)
            if suffix == ".py":
                bound_calls.extend(python_calls)
            else:
                gaps.append(f"reachability_symbol_binding_unsupported:{rel_path}")
            gaps.extend(python_gaps)
        else:
            gaps.append(f"reachability_symbol_binding_unsupported:{rel_path}")

        lines = text.splitlines()
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith(("//", "/*", "*")) and "#cgo" not in stripped:
                continue

            for ffi_kind, pattern in _FFI_PATTERNS:
                for match in pattern.finditer(line):
                    groups = [g for g in match.groups() if g]
                    token = groups[0] if groups else ffi_kind
                    extra_sym = groups[1] if len(groups) > 1 else None
                    lib_stem = _clean_lib_stem(token)
                    ffi_sites.append({
                        "path": rel_path,
                        "line": line_no,
                        "ffi_mechanism": ffi_kind,
                        "library_stem": lib_stem,
                        "symbol": extra_sym or token,
                    })

            if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
                for m_js in _JS_IMPORT_RE.finditer(line):
                    mod = m_js.group(1) or m_js.group(2)
                    if mod and not mod.startswith("."):
                        imports.append({"path": rel_path, "line": line_no, "module": mod, "symbols": []})
            elif suffix == ".go":
                m_go = _GO_IMPORT_RE.match(line)
                if m_go and m_go.group(1) != "C":
                    imports.append({"path": rel_path, "line": line_no, "module": m_go.group(1), "symbols": []})
            elif suffix == ".rs":
                m_rs = _RUST_USE_RE.match(line)
                if m_rs:
                    mod_path = m_rs.group(1)
                    parts = [p for p in mod_path.split("::") if p]
                    sym = parts[-1] if len(parts) > 1 else None
                    imports.append({
                        "path": rel_path, "line": line_no, "module": parts[0] if parts else mod_path,
                        "symbols": [sym] if sym and sym != "*" else [],
                    })
            elif suffix == ".rb":
                m_rb = _RUBY_REQUIRE_RE.match(line)
                if m_rb:
                    imports.append({"path": rel_path, "line": line_no, "module": m_rb.group(1), "symbols": []})
            elif suffix == ".php":
                m_php = _PHP_USE_RE.match(line)
                if m_php:
                    ns = m_php.group(1)
                    parts = [p for p in ns.split("\\") if p]
                    imports.append({
                        "path": rel_path, "line": line_no, "module": "\\".join(parts[:2]) if parts else ns,
                        "symbols": [parts[-1]] if len(parts) > 1 else [],
                    })
            elif suffix in {".java", ".kt"}:
                m_java = _JAVA_IMPORT_RE.match(line)
                if m_java:
                    imp = m_java.group(1)
                    parts = imp.split(".")
                    sym = parts[-1] if parts and parts[-1] != "*" else None
                    imports.append({
                        "path": rel_path, "line": line_no, "module": imp,
                        "symbols": [sym] if sym else [],
                    })
            elif suffix == ".cs":
                m_cs = _CS_USING_RE.match(line)
                if m_cs:
                    imports.append({"path": rel_path, "line": line_no, "module": m_cs.group(1), "symbols": []})
            elif suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}:
                m_inc = _C_INCLUDE_RE.match(line)
                if m_inc:
                    hdr = m_inc.group(1)
                    imports.append({
                        "path": rel_path, "line": line_no,
                        "module": _clean_lib_stem(hdr), "raw_header": hdr, "symbols": [],
                    })

    return {"imports": imports, "ffi_sites": ffi_sites,
            "bound_calls": bound_calls, "source_hashes": source_hashes, "gaps": gaps}


def _extract_osv_symbols_and_modules(
    raw_json: str, ecosystem: str, pkg_name: str, affected_index: int,
) -> tuple[list[str], list[str], list[str], str | None]:
    """Extract affected symbols, module paths, CVE aliases, and severity from raw OSV JSON."""
    symbols: set[str] = set()
    modules: set[str] = set()
    cves: set[str] = set()
    severity_label: str | None = None
    try:
        doc = json.loads(raw_json)
    except (ValueError, TypeError):
        return [], [], [], None
    if not isinstance(doc, Mapping):
        return [], [], [], None

    doc_id = str(doc.get("id") or "")
    if _CVE_RE.fullmatch(doc_id):
        cves.add(doc_id.upper())
    for alias in doc.get("aliases") or ():
        if isinstance(alias, str) and _CVE_RE.fullmatch(alias.strip()):
            cves.add(alias.strip().upper())

    db_spec = doc.get("database_specific")
    if isinstance(db_spec, Mapping) and isinstance(db_spec.get("severity"), str):
        severity_label = db_spec["severity"].upper()

    wanted = pkg_name.casefold()
    for index, entry in enumerate(doc.get("affected") or ()):
        if index != affected_index:
            continue
        if not isinstance(entry, Mapping):
            continue
        pkg = entry.get("package")
        if isinstance(pkg, Mapping):
            if pkg.get("ecosystem") and pkg.get("ecosystem") != ecosystem:
                continue
            if str(pkg.get("name") or "").casefold() not in {"", wanted}:
                continue
        eco_spec = entry.get("ecosystem_specific")
        if isinstance(eco_spec, Mapping):
            for imp in eco_spec.get("imports") or ():
                if isinstance(imp, Mapping):
                    path_val = imp.get("path")
                    if isinstance(path_val, str) and path_val.strip():
                        modules.add(path_val.strip())
                    for sym in imp.get("symbols") or ():
                        if isinstance(sym, str) and sym.strip():
                            symbol = sym.strip()
                            if isinstance(path_val, str) and path_val.strip():
                                module = path_val.strip()
                                symbol = symbol if symbol.startswith(module + ".") else f"{module}.{symbol}"
                            symbols.add(symbol)
            for func in eco_spec.get("functions") or eco_spec.get("symbols") or ():
                if isinstance(func, str) and func.strip():
                    symbols.add(func.strip())
    return sorted(symbols), sorted(modules), sorted(cves), severity_label


def _resolve_osv_source(
    repository_root: Path,
    run_root: Path,
    osv_snapshot: OsvSnapshotSource,
    external_input_selection: Mapping[str, Any] | None = None,
) -> tuple[Path | None, Mapping[str, str] | None, str | None]:
    """Consume the claim-selected public feed, never select from a mutable feed pointer."""
    from appsec_review.runtime.inputs import observe_external
    from appsec_review.storage.feed_provenance import consume_pin

    pin = osv_snapshot
    if pin is None:
        selections = [row for row in (external_input_selection or {}).get("inputs", ())
                      if row.get("producer") == "job_third_party_data_sync"
                      and row.get("output_kind") == "feed_snapshot" and row.get("selector") == "osv"]
        if not selections:
            return None, None, "osv_snapshot_not_admitted"
        if len(selections) != 1:
            raise ValueError("conflicting admitted OSV snapshots")
        selected = selections[0]
        if selected["status"] != "available":
            return None, None, f"osv_snapshot_unavailable:{selected['reason']}"
        from appsec_review.graph.settings import run_configuration
        document = run_configuration(run_root)
        if document is None:
            raise ValueError("OSV snapshot has no verified run configuration")
        configured = Path(document["jobs"]["job_third_party_data_sync"]["steps"]["osv_sync"]["settings"]["feed_root"])
        root = configured if configured.is_absolute() else repository_root / configured
        relative = root.relative_to(repository_root).as_posix()
        if not relative.startswith("data/"):
            raise ValueError("OSV snapshot root is outside repository data")
        root = safe_path(repository_root, relative)
        pin = {**selected["identity"], "directory": str(
            safe_path(root, f"snapshots/{selected['identity']['snapshot_id']}"))}
    if not isinstance(pin, Mapping) or pin.get("feed_id") != "osv":
        raise ValueError("OSV input requires an immutable snapshot pin, not a path or callable")
    if (not re.fullmatch(r"[0-9a-f]{64}", str(pin.get("manifest_sha256", "")))
            or not re.fullmatch(r"sha256-[0-9a-f]{24}", str(pin.get("snapshot_id", "")))
            or not isinstance(pin.get("directory"), str)):
        raise ValueError("OSV snapshot pin is missing its manifest identity")
    identity = {key: pin[key] for key in ("feed_id", "snapshot_id", "manifest_sha256")}
    observe_external(run_root, "job_third_party_data_sync", "feed_snapshot",
                     "appsec-review/public-feed-use/1", identity)
    directory = Path(pin["directory"])
    if not directory.is_absolute():
        raise ValueError("OSV snapshot directory must be absolute")
    root = directory.parent.parent
    if directory != safe_path(root, f"snapshots/{pin['snapshot_id']}"):
        raise ValueError("OSV snapshot directory differs from its pin")
    manifest_path = safe_path(directory, "manifest.json")
    raw = manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin["manifest_sha256"]:
        raise ValueError("OSV snapshot manifest hash mismatch")
    manifest = json.loads(raw)
    if manifest.get("feed_id") != "osv" or manifest.get("snapshot_id") != pin["snapshot_id"]:
        raise ValueError("OSV snapshot manifest identity mismatch")
    consume_pin(run_root, pin)
    record = manifest["files"].get("index/osv.sqlite")
    if record is None:
        return None, identity, "osv_snapshot_index_unavailable"
    path = safe_path(directory, "index/osv.sqlite")
    if path.stat().st_size != record["size_bytes"] or file_sha256(path) != record["sha256"]:
        raise ValueError("OSV snapshot index hash mismatch")
    return path, {**identity, "index_sha256": record["sha256"]}, None


def _coordinate_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower() if ecosystem == "NuGet" else name


def _package_coordinate(dep: Mapping[str, Any]) -> tuple[str, str, str, str] | None:
    """Keep namespace, release and instance qualifiers; reject conflicting supplied identity."""
    purl = dep.get("purl") if isinstance(dep.get("purl"), str) else None
    version, grade = _version_claim(dep.get("version"), dep.get("version_kind"))
    release = dep.get("release")
    if isinstance(release, Mapping):
        claimed, release_grade = _version_claim(release)
        if claimed is None or (version is not None and version != claimed):
            return None
        version, grade = claimed, release_grade
    if grade is not None and version is None:
        return None
    version = version or ""
    name = str(dep.get("name") or "").strip()
    declared = str(dep.get("ecosystem") or "").strip().casefold()
    eco = DECLARED_TO_OSV_ECOSYSTEM.get(declared)
    if declared == "native":
        eco = "native"
    instance = ""
    if purl:
        if (not purl.startswith("pkg:") or len(purl) > 4096
                or re.search(r"%(?![0-9a-fA-F]{2})", purl)):
            return None
        body, _, subpath = purl[4:].partition("#")
        body, _, query = body.partition("?")
        kind, slash, path = body.partition("/")
        purl_eco = "native" if kind == "generic" else PURL_TO_OSV_ECOSYSTEM.get(kind)
        if not slash or not purl_eco or (declared and eco != purl_eco):
            return None
        head, at, release = path.rpartition("@")
        if at and head and "/" not in release:
            path, release = head, unquote(release)
            if not release or (version and version != release):
                return None
            version = release
        parts = [unquote(part) for part in path.split("/")]
        if any(not part or part in {".", ".."} or "/" in part for part in parts):
            return None
        full_name = ":".join(parts) if kind == "maven" else "/".join(parts)
        if name and _coordinate_name(purl_eco, name) not in {
            _coordinate_name(purl_eco, full_name), _coordinate_name(purl_eco, parts[-1]),
        }:
            return None
        try:
            qualifiers = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            return None
        if (len(dict(qualifiers)) != len(qualifiers)
                or any(not key or not value for key, value in qualifiers)):
            return None
        name, eco = full_name, purl_eco
        instance = json.dumps([sorted(qualifiers), unquote(subpath)]) if query or subpath else ""
    if not eco or not name or not version:
        return None
    return eco, _coordinate_name(eco, name), version, instance


def _dependency_ecosystem_and_name(dep: Mapping[str, Any]) -> tuple[str | None, str, str | None, str | None]:
    coordinate = _package_coordinate(dep)
    purl = dep.get("purl") if isinstance(dep.get("purl"), str) else None
    if coordinate is not None:
        return *coordinate[:3], purl
    return None, str(dep.get("name") or ""), str(dep.get("version") or "") or None, purl


def _is_direct_dependency(dep: Mapping[str, Any]) -> bool:
    if isinstance(dep.get("direct"), bool):
        return bool(dep["direct"])
    rel = str(dep.get("relationship") or dep.get("scope") or "").strip().casefold()
    if rel in {"transitive", "indirect"}:
        return False
    return True


def _match_osv_indexed(
    sqlite_path: Path,
    dependencies: Sequence[Mapping[str, Any]],
    max_advisories: int,
    *, max_candidates_per_package: int, exact: bool = False,
) -> tuple[list[dict[str, Any]], list[str]]:
    matched: list[dict[str, Any]] = []
    gaps: list[str] = []
    bounds = osv_matching.Bounds(max_advisories_per_package=max_candidates_per_package)
    uri = f"{sqlite_path.as_uri()}?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        osv_matching.require_index(conn)
        for dep in dependencies:
            eco, pkg_name, version, purl = _dependency_ecosystem_and_name(dep)
            if not eco or not pkg_name or not version:
                gaps.append(f"osv_dependency_identity_incomplete:{dep.get('dependency_id', pkg_name)}")
                continue
            dep_id = str(dep.get("dependency_id") or pkg_name)
            direct = _is_direct_dependency(dep)
            result = osv_matching.match_package(conn, eco, pkg_name, version, bounds=bounds)
            gaps.extend(f"osv:{dep_id}:{gap}" for gap in result["gaps"])
            for match in result["matches"]:
                if exact and match["evidence"]["kind"] != "versions":
                    gaps.append(f"osv_exact_range_not_evaluated:{dep_id}:{match['advisory_id']}")
                    continue
                if len(matched) >= max_advisories:
                    gaps.append("osv_advisories_truncated")
                    return matched, gaps
                adv_id = match["advisory_id"]
                raw_json = conn.execute("SELECT raw_json FROM advisory WHERE id = ?", (adv_id,)).fetchone()[0]
                symbols, modules, cves, sev = _extract_osv_symbols_and_modules(
                    raw_json if isinstance(raw_json, str) else "", eco, pkg_name,
                    match["evidence"]["affected_index"],
                )
                matched.append({
                    "advisory_id": str(adv_id),
                    "cve_ids": cves,
                    "package_name": pkg_name,
                    "package_version": version,
                    "purl": purl,
                    "ecosystem": eco,
                    "severity": sev,
                    "direct": direct,
                    "match_source": "osv-exact" if exact else "osv-index",
                    "affected_symbols": symbols,
                    "affected_modules": modules,
                    "dependency_ids": [str(dep["dependency_id"])] if dep.get("dependency_id") else [],
                })
    return matched, gaps


def _qualified_advisory_symbols(advisory: Mapping[str, Any]) -> set[str]:
    modules = [str(module) for module in advisory.get("affected_modules") or () if module]
    symbols: set[str] = set()
    for symbol in advisory.get("affected_symbols") or ():
        if not isinstance(symbol, str) or not symbol:
            continue
        if any(symbol.startswith(module + ".") for module in modules):
            symbols.add(symbol)
        elif len(modules) == 1:
            symbols.add(f"{modules[0]}.{symbol}")
    return symbols


def classify_advisory_reachability(
    advisory: Mapping[str, Any],
    target_index: Mapping[str, Any],
    *,
    max_call_sites: int | None = 32,
) -> tuple[str, list[dict[str, Any]], list[str]]:
    """Classify one advisory against the scanned first-party target reachability index."""
    pkg_name = str(advisory.get("package_name") or "")
    purl = advisory.get("purl") if isinstance(advisory.get("purl"), str) else None
    affected_modules = [str(m) for m in (advisory.get("affected_modules") or ()) if m]
    stems = _candidate_module_stems(pkg_name, purl, affected_modules)

    imports = target_index.get("imports") or ()
    ffi_sites = target_index.get("ffi_sites") or ()

    matched_imports: list[dict[str, Any]] = []

    for imp in imports:
        if (imp.get("local_module") or _SOURCE_ECOSYSTEM.get(PurePosixPath(str(imp["path"])).suffix.casefold())
                != advisory.get("ecosystem")):
            continue
        mod_raw = str(imp.get("module") or "").casefold()
        mod_norm = _normalize_pkg_token(mod_raw)
        mod_parts = {_normalize_pkg_token(p) for p in re.split(r"[./:\\]+", mod_raw) if p}
        if mod_raw in stems or mod_norm in stems or (mod_parts & stems):
            matched_imports.append({
                "path": str(imp["path"]),
                "line": int(imp["line"]),
                "symbol": str(imp.get("module") or pkg_name),
                "kind": "package_import",
                "ffi_mechanism": None,
            })

    ffi_import_sites: list[dict[str, Any]] = []
    ffi_mechanisms: set[str] = set()

    for site in ffi_sites:
        lib_stem = str(site.get("library_stem") or "").casefold()
        sym = str(site.get("symbol") or "")
        lib_match = bool(lib_stem and (lib_stem in stems or _normalize_pkg_token(lib_stem) in stems))
        if lib_match and advisory.get("ecosystem") == "native":
            mech = str(site["ffi_mechanism"])
            ffi_mechanisms.add(mech)
            entry = {
                "path": str(site["path"]),
                "line": int(site["line"]),
                "symbol": sym or pkg_name,
                "kind": "ffi_boundary",
                "ffi_mechanism": mech,
            }
            ffi_import_sites.append(entry)

    symbol_hit_sites: list[dict[str, Any]] = []
    if advisory.get("ecosystem") == "PyPI" and advisory.get("_symbol_binding_allowed", True):
        qualified_symbols = (
            advisory["_qualified_symbols"] if "_qualified_symbols" in advisory
            else _qualified_advisory_symbols(advisory)
        )
        for call in target_index.get("bound_calls") or ():
            qualified = str(call["qualified_symbol"])
            if qualified in qualified_symbols:
                symbol_hit_sites.append({
                    "path": str(call["path"]), "line": int(call["line"]),
                    "symbol": qualified.rsplit(".", 1)[-1], "kind": "symbol_call",
                    "ffi_mechanism": None,
                })

    def _dedupe_sites(sites: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: dict[tuple[str, int, str], dict[str, Any]] = {}
        for item in sites:
            key = (item["path"], item["line"], item["symbol"])
            if key not in seen:
                seen[key] = item
        return [seen[k] for k in sorted(seen)][:max_call_sites]

    if symbol_hit_sites:
        sites = _dedupe_sites(symbol_hit_sites)
        return REACHABILITY_SYMBOL, sites, sorted(ffi_mechanisms)

    if matched_imports or ffi_import_sites:
        sites = _dedupe_sites([*matched_imports, *ffi_import_sites])
        return REACHABILITY_IMPORTED, sites, sorted(ffi_mechanisms)

    if not bool(advisory.get("direct", True)):
        return REACHABILITY_TRANSITIVE, [], []

    return REACHABILITY_UNKNOWN, [], []


def evaluate_sca_reachability(
    *,
    source_fingerprint: str,
    repository_root: Path,
    run_root: Path,
    target_root: Path | None,
    dependencies: Sequence[Mapping[str, Any]],
    scanner_advisories: Sequence[Mapping[str, Any]] = (),
    native_advisory_matches: Sequence[Mapping[str, Any]] = (),
    partition_files: Sequence[Mapping[str, Any]] = (),
    settings: DependencyIntelligenceSettings | None = None,
    osv_snapshot: OsvSnapshotSource = None,
    external_input_selection: Mapping[str, Any] | None = None,
    partition_gaps: Sequence[str] = (),
) -> dict[str, Any]:
    """Match the pinned OSV index and inspect only hash-bound accepted source inventory."""
    cfg = settings or DependencyIntelligenceSettings()
    configured_mode = cfg.osv_version_matching
    actual_mode = configured_mode
    fallback_reason: str | None = None
    osv_candidates: list[dict[str, Any]] = []
    gaps: list[str] = []
    snapshot_identity: Mapping[str, str] | None = None

    if configured_mode != "disabled":
        sqlite_path, snapshot_identity, reason = _resolve_osv_source(
            repository_root, run_root, osv_snapshot, external_input_selection)
        if sqlite_path is not None:
            osv_candidates, osv_gaps = _match_osv_indexed(
                sqlite_path, dependencies, cfg.max_advisories,
                max_candidates_per_package=cfg.max_osv_candidates_per_package,
                exact=configured_mode == "exact")
            gaps.extend(osv_gaps)
        else:
            fallback_reason = reason or "osv_index_unavailable"
            gaps.append(fallback_reason)
    else:
        actual_mode = "disabled"
        gaps.append("osv_matching_disabled")

    deps_by_coordinate: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = {}
    unresolved_names: set[str] = set()
    for dep in dependencies:
        coordinate = _package_coordinate(dep)
        if coordinate is not None:
            deps_by_coordinate.setdefault(coordinate, []).append(dep)
        else:
            unresolved_names.add(_normalize_pkg_token(str(dep.get("name") or "")))

    merged: dict[tuple[str, ...], dict[str, Any]] = {}

    def _merge_candidate(cand: Mapping[str, Any]) -> None:
        adv_id = str(cand.get("advisory_id") or "").strip()
        pkg_name = str(cand.get("package_name") or "").strip()
        pkg_ver = str(cand.get("package_version") or "").strip() or None
        if not adv_id or not pkg_name:
            return
        coordinate = _package_coordinate({
            "name": pkg_name, "version": pkg_ver, "purl": cand.get("purl"),
            "ecosystem": cand.get("ecosystem"),
        })
        matching_deps = deps_by_coordinate.get(coordinate, []) if coordinate else []
        matching_deps = [dep for dep in matching_deps if isinstance(dep.get("dependency_id"), str)
                         and dep["dependency_id"]]
        supplied_ids = cand.get("dependency_ids")
        if supplied_ids:
            matching_deps = [dep for dep in matching_deps
                             if dep["dependency_id"] in supplied_ids]
        resolved = bool(coordinate and matching_deps)
        if coordinate:
            eco, pkg_name, pkg_ver, _ = coordinate
            key = (adv_id, *coordinate, "resolved" if resolved else "unresolved")
        else:
            eco = cand.get("ecosystem") if isinstance(cand.get("ecosystem"), str) else None
            key = (adv_id, eco or "", pkg_name, pkg_ver or "", str(cand.get("purl") or ""), "unresolved")
        if not resolved:
            gaps.append(f"sca_dependency_binding_unresolved:{adv_id}:{pkg_name}")
        competing = [coord for coord in deps_by_coordinate if coordinate and coord[:2] == coordinate[:2]]
        symbol_binding_allowed = (
            resolved and len(competing) == 1 and len(deps_by_coordinate[coordinate]) == 1
            and _normalize_pkg_token(pkg_name) not in unresolved_names
        )
        if resolved and not symbol_binding_allowed:
            gaps.append(f"reachability_package_binding_ambiguous:{adv_id}:{pkg_name}")
        default_direct = (
            any(_is_direct_dependency(d) for d in matching_deps)
            if matching_deps
            else bool(cand.get("direct", True))
        )
        dep_ids = [str(d["dependency_id"]) for d in matching_deps]
        existing = merged.get(key)
        cves = set(cand.get("cve_ids") or ())
        if _CVE_RE.fullmatch(adv_id):
            cves.add(adv_id.upper())
        if existing is None:
            if len(merged) >= cfg.max_advisories:
                gaps.append("sca_advisories_truncated")
                return
            merged[key] = {
                "advisory_id": adv_id,
                "cve_ids": sorted(cves),
                "package_name": pkg_name,
                "package_version": pkg_ver,
                "purl": cand.get("purl") if isinstance(cand.get("purl"), str) else None,
                "ecosystem": eco,
                "severity": cand.get("severity") if isinstance(cand.get("severity"), str) else None,
                "direct": default_direct,
                "match_sources": {str(cand.get("match_source") or "scanner")},
                "affected_symbols": set(cand.get("affected_symbols") or ()),
                "affected_modules": set(cand.get("affected_modules") or ()),
                "dependency_ids": set(dep_ids),
                "_binding_resolved": resolved,
                "_symbol_binding_allowed": symbol_binding_allowed,
                "_qualified_symbols": _qualified_advisory_symbols(cand),
            }
        else:
            existing["cve_ids"] = sorted(set(existing["cve_ids"]) | cves)
            existing["match_sources"].add(str(cand.get("match_source") or "scanner"))
            existing["affected_symbols"].update(cand.get("affected_symbols") or ())
            existing["affected_modules"].update(cand.get("affected_modules") or ())
            existing["_qualified_symbols"].update(_qualified_advisory_symbols(cand))
            existing["dependency_ids"].update(dep_ids)
            existing["direct"] = existing["direct"] or default_direct
            if not existing["severity"] and isinstance(cand.get("severity"), str):
                existing["severity"] = cand["severity"]
            if not existing["purl"] and isinstance(cand.get("purl"), str):
                existing["purl"] = cand["purl"]
            if not existing["ecosystem"] and isinstance(cand.get("ecosystem"), str):
                existing["ecosystem"] = cand["ecosystem"]

    for cand in osv_candidates:
        _merge_candidate(cand)

    for obs in scanner_advisories:
        purl = obs.get("purl") if isinstance(obs.get("purl"), str) else None
        _merge_candidate({
            "advisory_id": obs.get("advisory"),
            "package_name": obs.get("package"),
            "package_version": obs.get("version"),
            "purl": purl,
            "ecosystem": obs.get("ecosystem"),
            "severity": obs.get("severity"),
            "match_source": obs.get("scanner") or "scanner",
            "affected_symbols": obs.get("affected_symbols") or [],
            "affected_modules": obs.get("affected_modules") or [],
        })

    for nat in native_advisory_matches:
        _merge_candidate({
            "advisory_id": nat.get("cve_id"),
            "cve_ids": [str(nat["cve_id"])] if nat.get("cve_id") else [],
            "package_name": nat.get("name"),
            "package_version": nat.get("version"),
            "purl": nat.get("purl"),
            "ecosystem": "native",
            "severity": nat.get("severity"),
            "direct": True,
            "match_source": "native-advisory-lookup",
            "dependency_ids": nat.get("dependency_ids") or [],
        })

    target_index = (
        scan_target_reachability_index(
            target_root=target_root,
            partition_files=partition_files,
            max_source_files=cfg.max_source_files,
            max_bytes_per_file=cfg.max_bytes_per_file,
        )
        if cfg.reachability_enabled
        else {"imports": [], "ffi_sites": [], "bound_calls": [], "source_hashes": {},
              "gaps": ["reachability_disabled"]}
    )
    gaps.extend(str(gap) for gap in partition_gaps)
    gaps.extend(target_index["gaps"])
    gaps.append("static_reachability_only: bounded static symbol use proves neither whole-program runtime "
                "reachability nor code unreachability")

    advisory_records: list[dict[str, Any]] = []
    symbol_reachable_count = 0
    package_imported_count = 0
    transitive_only_count = 0
    unreachable_count = 0
    unknown_count = 0
    ffi_boundary_matches = 0

    for key in sorted(merged):
        item = merged[key]
        prepared = {
            **item,
            "match_sources": sorted(item["match_sources"]),
            "affected_symbols": sorted(item["affected_symbols"]),
            "affected_modules": sorted(item["affected_modules"]),
            "dependency_ids": sorted(d for d in item["dependency_ids"] if d),
        }
        if not prepared["_binding_resolved"]:
            verdict, sites, ffi_mechs = REACHABILITY_UNKNOWN, [], []
        else:
            verdict, sites, ffi_mechs = classify_advisory_reachability(
                prepared, target_index, max_call_sites=None,
            )
            if verdict != REACHABILITY_SYMBOL and prepared["affected_symbols"]:
                gaps.append(f"reachability_symbol_binding_not_established:{prepared['advisory_id']}")
            if ffi_mechs:
                gaps.append(f"reachability_native_symbol_binding_not_established:{prepared['advisory_id']}")
        if len(sites) > cfg.max_call_sites_per_advisory:
            omitted = len(sites) - cfg.max_call_sites_per_advisory
            subject = prepared["purl"] or (
                f"{prepared['ecosystem']}:{prepared['package_name']}@{prepared['package_version']}")
            gaps.append(f"reachability_call_sites_truncated:{prepared['advisory_id']}:{subject}:omitted={omitted}")
            sites = sites[:cfg.max_call_sites_per_advisory]
        sites = [{**site, "file_sha256": target_index["source_hashes"][site["path"]]} for site in sites]
        if verdict == REACHABILITY_SYMBOL:
            symbol_reachable_count += 1
        elif verdict == REACHABILITY_IMPORTED:
            package_imported_count += 1
        elif verdict == REACHABILITY_TRANSITIVE:
            transitive_only_count += 1
        elif verdict == REACHABILITY_UNREACHABLE:
            unreachable_count += 1
        else:
            unknown_count += 1
        if ffi_mechs:
            ffi_boundary_matches += 1

        advisory_records.append({
            "advisory_id": prepared["advisory_id"],
            "cve_ids": prepared["cve_ids"],
            "package_name": prepared["package_name"],
            "package_version": prepared["package_version"],
            "purl": prepared["purl"],
            "ecosystem": prepared["ecosystem"],
            "severity": prepared["severity"],
            "direct": prepared["direct"],
            "match_sources": prepared["match_sources"],
            "affected_symbols": prepared["affected_symbols"],
            "affected_modules": prepared["affected_modules"],
            "reachability": verdict,
            "ffi_mechanisms": ffi_mechs,
            "call_sites": sites,
            "dependency_ids": prepared["dependency_ids"],
        })

    telemetry = {
        "advisories_matched": len(advisory_records),
        "osv_matching_mode": actual_mode,
        "symbol_reachable_count": symbol_reachable_count,
        "ffi_boundary_matches": ffi_boundary_matches,
        "package_imported_count": package_imported_count,
        "transitive_only_count": transitive_only_count,
        "unreachable_in_target_count": unreachable_count,
        "unknown_count": unknown_count,
    }
    return {
        "schema": REACHABILITY_SCHEMA,
        "source_fingerprint": source_fingerprint,
        "configured_osv_mode": configured_mode,
        "osv_matching_mode": actual_mode,
        "osv_fallback_reason": fallback_reason,
        "osv_snapshot": snapshot_identity,
        "coverage": "partial" if gaps else "complete",
        "gaps": sorted(set(gaps)),
        "advisories": advisory_records,
        "telemetry": telemetry,
    }


__all__ = [
    "DependencyIntelligenceSettings",
    "OSV_MATCHING_MODES",
    "OsvSnapshotSource",
    "REACHABILITY_UNKNOWN",
    "REACHABILITY_IMPORTED",
    "REACHABILITY_SCHEMA",
    "REACHABILITY_SYMBOL",
    "REACHABILITY_TRANSITIVE",
    "REACHABILITY_UNREACHABLE",
    "classify_advisory_reachability",
    "evaluate_sca_reachability",
    "scan_target_reachability_index",
]
