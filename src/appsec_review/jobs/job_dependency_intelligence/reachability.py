"""Indexed OSV version matching and vulnerable-symbol / native FFI call-site reachability."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
from typing import Any

from appsec_review import osv_matching
from appsec_review.jobs.job_dependency_intelligence.native_advisories import purl_parts


REACHABILITY_SCHEMA = "appsec-review/sca-reachability/1"
OSV_MATCHING_MODES = ("index", "exact", "disabled")
REACHABILITY_SYMBOL = "symbol_reachable"
REACHABILITY_IMPORTED = "package_imported"
REACHABILITY_TRANSITIVE = "transitive_only"
REACHABILITY_UNREACHABLE = "unreachable_in_target"

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
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CALL_TOKEN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,127})\s*\(")
_MEMBER_CALL_RE = re.compile(r"(?:\.|::|->)\s*([A-Za-z_][A-Za-z0-9_]{1,127})\s*\(")

# Language import extractors (line-oriented, bounded, deterministic)
_PY_FROM_RE = re.compile(r"^\s*from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import\s+(.+)$")
_PY_IMPORT_RE = re.compile(r"^\s*import\s+([A-Za-z_][A-Za-z0-9_.,\s]*)$")
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

    def __post_init__(self) -> None:
        if self.osv_version_matching not in OSV_MATCHING_MODES:
            raise ValueError(
                f"osv_version_matching must be one of {', '.join(OSV_MATCHING_MODES)}: "
                f"{self.osv_version_matching!r}"
            )
        for field_name in ("max_source_files", "max_bytes_per_file", "max_call_sites_per_advisory", "max_advisories"):
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
        )


OsvSnapshotSource = (
    Callable[[Path, Path], Mapping[str, Any]]
    | Mapping[str, Any]
    | Path
    | None
)


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
    symbol_calls: dict[str, list[tuple[str, int]]] = {}

    if target_root is None or not target_root.is_dir():
        return {"imports": imports, "ffi_sites": ffi_sites, "symbol_calls": symbol_calls}

    candidate_paths: list[str] = []
    if partition_files:
        for entry in partition_files:
            rel = str(entry.get("path") or "").replace("\\", "/")
            if _is_first_party_source(rel):
                candidate_paths.append(rel)
    else:
        for file_path in sorted(target_root.rglob("*")):
            if not file_path.is_file():
                continue
            rel = file_path.relative_to(target_root).as_posix()
            if _is_first_party_source(rel):
                candidate_paths.append(rel)
            if len(candidate_paths) >= max_source_files:
                break

    for rel_path in sorted(set(candidate_paths))[:max_source_files]:
        full_path = target_root / rel_path
        if not full_path.is_file():
            continue
        try:
            raw = full_path.read_bytes()[:max_bytes_per_file]
            text = raw.decode("utf-8", errors="replace")
        except OSError:
            continue
        suffix = PurePosixPath(rel_path).suffix.casefold()
        active_ffi_libs: set[str] = set()

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
                    if ffi_kind in {"python_ctypes", "python_cffi", "csharp_pinvoke", "csharp_nativelibrary",
                                    "java_jni", "ruby_ffi", "rust_extern", "go_cgo", "php_ffi", "cpp_extern_c"}:
                        if lib_stem:
                            active_ffi_libs.add(lib_stem)
                    ffi_sites.append({
                        "path": rel_path,
                        "line": line_no,
                        "ffi_mechanism": ffi_kind,
                        "library_stem": lib_stem,
                        "symbol": extra_sym or token,
                        "has_explicit_symbol": bool(extra_sym) or ffi_kind in {
                            "java_jni_method", "go_cgo",
                        } or ("attach_function" in line) or ("extern \"C\"" in line and "fn " in line),
                    })

            if suffix in {".py", ".pyi"}:
                m_from = _PY_FROM_RE.match(line)
                if m_from:
                    mod = m_from.group(1)
                    syms = [s.strip().split(" as ")[0].strip() for s in m_from.group(2).split(",")]
                    imports.append({
                        "path": rel_path, "line": line_no, "module": mod,
                        "symbols": [s for s in syms if s and s != "*"],
                    })
                else:
                    m_imp = _PY_IMPORT_RE.match(line)
                    if m_imp:
                        for part in m_imp.group(1).split(","):
                            mod = part.strip().split(" as ")[0].strip()
                            if mod:
                                imports.append({"path": rel_path, "line": line_no, "module": mod, "symbols": []})
            elif suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
                for m_js in _JS_IMPORT_RE.finditer(line):
                    mod = m_js.group(1) or m_js.group(2)
                    if mod and not mod.startswith("."):
                        imports.append({"path": rel_path, "line": line_no, "module": mod, "symbols": []})
            elif suffix == ".go":
                if stripped == 'import "C"':
                    active_ffi_libs.add("cgo")
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

            for m_call in _CALL_TOKEN_RE.finditer(line):
                sym_name = m_call.group(1)
                bucket = symbol_calls.setdefault(sym_name, [])
                if len(bucket) < 32:
                    bucket.append((rel_path, line_no))
            for m_mem in _MEMBER_CALL_RE.finditer(line):
                sym_name = m_mem.group(1)
                bucket = symbol_calls.setdefault(sym_name, [])
                if len(bucket) < 32:
                    bucket.append((rel_path, line_no))

        if active_ffi_libs:
            bound = sorted(active_ffi_libs)
            for site in ffi_sites:
                if site["path"] == rel_path:
                    existing_bound = set(site.get("bound_libraries") or ())
                    site["bound_libraries"] = sorted(existing_bound | set(bound))

    return {"imports": imports, "ffi_sites": ffi_sites, "symbol_calls": symbol_calls}


def _extract_osv_symbols_and_modules(raw_json: str, ecosystem: str, pkg_name: str) -> tuple[list[str], list[str], list[str], str | None]:
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
    for entry in doc.get("affected") or ():
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
                            symbols.add(sym.strip())
            for func in eco_spec.get("functions") or eco_spec.get("symbols") or ():
                if isinstance(func, str) and func.strip():
                    symbols.add(func.strip().rsplit("::", 1)[-1].rsplit(".", 1)[-1])
    return sorted(symbols), sorted(modules), sorted(cves), severity_label


def _resolve_osv_source(
    repository_root: Path,
    run_root: Path,
    osv_snapshot: OsvSnapshotSource,
) -> tuple[Path | None, Path | None, str | None]:
    """Return ``(sqlite_db_path, raw_records_dir, fallback_reason)``."""
    if osv_snapshot is not None:
        if isinstance(osv_snapshot, Path):
            if osv_snapshot.is_file() and osv_snapshot.suffix == ".sqlite":
                return osv_snapshot, None, None
            idx = osv_snapshot / "index" / "osv.sqlite"
            if idx.is_file():
                return idx, osv_snapshot, None
            if osv_snapshot.is_dir():
                return None, osv_snapshot, "osv_index_sqlite_absent_in_directory"
            return None, None, "osv_snapshot_path_missing"
        if isinstance(osv_snapshot, Mapping):
            directory = Path(str(osv_snapshot.get("directory") or ""))
            idx = directory / "index" / "osv.sqlite"
            if idx.is_file():
                return idx, directory, None
            if directory.is_dir():
                return None, directory, "osv_index_sqlite_absent_in_snapshot"
            return None, None, "osv_snapshot_directory_missing"
        if callable(osv_snapshot):
            resolved = osv_snapshot(repository_root, run_root)
            directory = Path(str(resolved.get("directory") or ""))
            idx = directory / "index" / "osv.sqlite"
            if idx.is_file():
                return idx, directory, None
            if directory.is_dir():
                return None, directory, "osv_index_sqlite_absent_in_resolved_snapshot"
            return None, None, "osv_resolved_snapshot_missing"

    resolved_cfg = run_root / "data" / "configuration" / "resolved.json"
    if not resolved_cfg.is_file():
        return None, None, "run_resolved_configuration_absent"
    try:
        from appsec_review.jobs.job_third_party_data_sync.publication import verify_current
        from appsec_review.jobs.job_third_party_data_sync.steps.osv_sync.feed import OsvSettings
        doc = json.loads(resolved_cfg.read_bytes())
        values = doc["jobs"]["job_third_party_data_sync"]["steps"]["osv_sync"]["settings"]
        osv_settings = OsvSettings.from_mapping(repository_root, values)
        identity = verify_current(osv_settings.feed_root, "osv")
        directory = Path(str(identity["directory"]))
        idx = directory / "index" / "osv.sqlite"
        if idx.is_file():
            return idx, directory, None
        return None, directory if directory.is_dir() else None, "osv_index_sqlite_missing"
    except (OSError, KeyError, ValueError, TypeError) as exc:
        return None, None, f"osv_snapshot_unavailable:{type(exc).__name__}"


def _dependency_ecosystem_and_name(dep: Mapping[str, Any]) -> tuple[str | None, str, str | None, str | None]:
    purl = dep.get("purl") if isinstance(dep.get("purl"), str) else None
    version = str(dep.get("version")).strip() if dep.get("version") else None
    explicit_name = str(dep.get("name") or "").strip()
    if purl:
        parsed = purl_parts(purl)
        if parsed is not None:
            purl_type, pkg_name, purl_ver = parsed
            eco = PURL_TO_OSV_ECOSYSTEM.get(purl_type)
            return eco, explicit_name or pkg_name, version or purl_ver, purl
    raw_eco = str(dep.get("ecosystem") or "").strip().casefold()
    eco = DECLARED_TO_OSV_ECOSYSTEM.get(raw_eco)
    return eco, explicit_name, version, purl


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
) -> list[dict[str, Any]]:
    matched: list[dict[str, Any]] = []
    uri = f"file:{sqlite_path.as_posix()}?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        osv_matching.require_index(conn)
        for dep in dependencies:
            eco, pkg_name, version, purl = _dependency_ecosystem_and_name(dep)
            if not eco or not pkg_name or not version:
                continue
            dep_id = str(dep.get("dependency_id") or pkg_name)
            direct = _is_direct_dependency(dep)
            rows = conn.execute(
                "SELECT DISTINCT a.id, a.withdrawn, a.raw_json "
                "FROM package p JOIN advisory a ON a.id = p.advisory_id "
                "WHERE p.ecosystem = ? AND p.name = ? COLLATE NOCASE "
                "ORDER BY a.id LIMIT 500",
                (eco, pkg_name),
            ).fetchall()
            for adv_id, withdrawn, raw_json in rows:
                verdict = osv_matching.evaluate_record(raw_json, withdrawn, eco, pkg_name, version)
                is_hit = verdict["status"] == "affected"
                if not is_hit and verdict["status"] == "undetermined" and isinstance(raw_json, str):
                    try:
                        raw_doc = json.loads(raw_json)
                        for aff in raw_doc.get("affected") or ():
                            if isinstance(aff, Mapping) and version in (aff.get("versions") or ()):
                                is_hit = True
                                break
                    except (ValueError, TypeError):
                        pass
                if not is_hit:
                    continue
                symbols, modules, cves, sev = _extract_osv_symbols_and_modules(
                    raw_json if isinstance(raw_json, str) else "", eco, pkg_name
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
                    "match_source": "osv-index",
                    "affected_symbols": symbols,
                    "affected_modules": modules,
                    "dependency_ids": [dep_id],
                })
                if len(matched) >= max_advisories:
                    return matched
    return matched


def _match_osv_exact_dir(
    records_dir: Path | None,
    dependencies: Sequence[Mapping[str, Any]],
    max_advisories: int,
) -> list[dict[str, Any]]:
    if records_dir is None or not records_dir.is_dir():
        return []
    dep_lookup: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    for dep in dependencies:
        eco, pkg_name, version, _ = _dependency_ecosystem_and_name(dep)
        if eco and pkg_name and version:
            dep_lookup.setdefault((eco, pkg_name.casefold(), version), []).append(dep)
    if not dep_lookup:
        return []
    matched: list[dict[str, Any]] = []
    for json_file in sorted(records_dir.rglob("*.json"))[:2000]:
        if json_file.name == "manifest.json":
            continue
        try:
            raw_text = json_file.read_text(encoding="utf-8")
            doc = json.loads(raw_text)
        except (OSError, ValueError):
            continue
        if not isinstance(doc, Mapping) or doc.get("withdrawn"):
            continue
        adv_id = str(doc.get("id") or "")
        if not adv_id:
            continue
        for aff in doc.get("affected") or ():
            if not isinstance(aff, Mapping):
                continue
            pkg = aff.get("package")
            if not isinstance(pkg, Mapping):
                continue
            eco = str(pkg.get("ecosystem") or "")
            name = str(pkg.get("name") or "")
            for ver in aff.get("versions") or ():
                if not isinstance(ver, str):
                    continue
                deps = dep_lookup.get((eco, name.casefold(), ver))
                if not deps:
                    continue
                symbols, modules, cves, sev = _extract_osv_symbols_and_modules(raw_text, eco, name)
                for dep in deps:
                    matched.append({
                        "advisory_id": adv_id,
                        "cve_ids": cves,
                        "package_name": name,
                        "package_version": ver,
                        "purl": dep.get("purl") if isinstance(dep.get("purl"), str) else None,
                        "ecosystem": eco,
                        "severity": sev,
                        "direct": _is_direct_dependency(dep),
                        "match_source": "osv-exact",
                        "affected_symbols": symbols,
                        "affected_modules": modules,
                        "dependency_ids": [str(dep.get("dependency_id") or name)],
                    })
                    if len(matched) >= max_advisories:
                        return matched
    return matched


def classify_advisory_reachability(
    advisory: Mapping[str, Any],
    target_index: Mapping[str, Any],
    *,
    max_call_sites: int = 32,
) -> tuple[str, list[dict[str, Any]], list[str]]:
    """Classify one advisory against the scanned first-party target reachability index."""
    pkg_name = str(advisory.get("package_name") or "")
    purl = advisory.get("purl") if isinstance(advisory.get("purl"), str) else None
    affected_symbols = [str(s) for s in (advisory.get("affected_symbols") or ()) if s]
    affected_modules = [str(m) for m in (advisory.get("affected_modules") or ()) if m]
    stems = _candidate_module_stems(pkg_name, purl, affected_modules)

    imports = target_index.get("imports") or ()
    ffi_sites = target_index.get("ffi_sites") or ()
    symbol_calls: Mapping[str, Sequence[tuple[str, int]]] = target_index.get("symbol_calls") or {}

    matched_imports: list[dict[str, Any]] = []
    imported_files: set[str] = set()
    imported_symbols_at_site: list[dict[str, Any]] = []

    for imp in imports:
        mod_raw = str(imp.get("module") or "").casefold()
        mod_norm = _normalize_pkg_token(mod_raw)
        mod_parts = {_normalize_pkg_token(p) for p in re.split(r"[./:\\]+", mod_raw) if p}
        if mod_raw in stems or mod_norm in stems or (mod_parts & stems):
            imported_files.add(str(imp["path"]))
            matched_imports.append({
                "path": str(imp["path"]),
                "line": int(imp["line"]),
                "symbol": str(imp.get("module") or pkg_name),
                "kind": "package_import",
                "ffi_mechanism": None,
            })
            for sym in imp.get("symbols") or ():
                imported_symbols_at_site.append({
                    "path": str(imp["path"]),
                    "line": int(imp["line"]),
                    "symbol": str(sym),
                    "kind": "symbol_call",
                    "ffi_mechanism": None,
                })

    ffi_call_sites: list[dict[str, Any]] = []
    ffi_import_sites: list[dict[str, Any]] = []
    ffi_mechanisms: set[str] = set()

    for site in ffi_sites:
        lib_stem = str(site.get("library_stem") or "").casefold()
        bound_libs = {str(b).casefold() for b in (site.get("bound_libraries") or ())}
        sym = str(site.get("symbol") or "")
        sym_match = bool(affected_symbols and sym in affected_symbols)
        lib_match = bool((lib_stem and (lib_stem in stems or _normalize_pkg_token(lib_stem) in stems))
                         or (bound_libs & stems))
        if sym_match or lib_match:
            mech = str(site["ffi_mechanism"])
            ffi_mechanisms.add(mech)
            entry = {
                "path": str(site["path"]),
                "line": int(site["line"]),
                "symbol": sym or pkg_name,
                "kind": "ffi_boundary",
                "ffi_mechanism": mech,
            }
            if sym_match or site.get("has_explicit_symbol"):
                ffi_call_sites.append(entry)
            else:
                ffi_import_sites.append(entry)
                imported_files.add(str(site["path"]))

    symbol_hit_sites: list[dict[str, Any]] = []
    if affected_symbols:
        for sym in affected_symbols:
            for call_path, call_line in symbol_calls.get(sym, ()):
                if call_path in imported_files or not matched_imports:
                    if matched_imports or ffi_import_sites or ffi_call_sites or (purl and purl.startswith("pkg:generic/")):
                        symbol_hit_sites.append({
                            "path": str(call_path),
                            "line": int(call_line),
                            "symbol": sym,
                            "kind": "symbol_call",
                            "ffi_mechanism": None,
                        })
            for imp_sym in imported_symbols_at_site:
                if imp_sym["symbol"] == sym:
                    symbol_hit_sites.append(imp_sym)
    elif ffi_import_sites:
        for sym_name, locs in symbol_calls.items():
            for call_path, call_line in locs:
                if call_path in imported_files and sym_name not in {
                    "CDLL", "WinDLL", "LoadLibrary", "dlopen", "dlsym", "loadLibrary", "load", "cdef", "require",
                }:
                    ffi_mech = next(iter(sorted(ffi_mechanisms)), None)
                    ffi_call_sites.append({
                        "path": str(call_path),
                        "line": int(call_line),
                        "symbol": sym_name,
                        "kind": "ffi_boundary",
                        "ffi_mechanism": ffi_mech,
                    })

    def _dedupe_sites(sites: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: dict[tuple[str, int, str], dict[str, Any]] = {}
        for item in sites:
            key = (item["path"], item["line"], item["symbol"])
            if key not in seen:
                seen[key] = item
        return [seen[k] for k in sorted(seen)][:max_call_sites]

    if symbol_hit_sites or ffi_call_sites:
        sites = _dedupe_sites([*symbol_hit_sites, *ffi_call_sites, *ffi_import_sites])
        return REACHABILITY_SYMBOL, sites, sorted(ffi_mechanisms)

    if matched_imports or ffi_import_sites:
        sites = _dedupe_sites([*matched_imports, *ffi_import_sites])
        return REACHABILITY_IMPORTED, sites, sorted(ffi_mechanisms)

    if not bool(advisory.get("direct", True)):
        return REACHABILITY_TRANSITIVE, [], []

    return REACHABILITY_UNREACHABLE, [], []


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
) -> dict[str, Any]:
    """Run OSV version matching (index with graceful exact fallback) and symbol/FFI reachability."""
    cfg = settings or DependencyIntelligenceSettings()
    configured_mode = cfg.osv_version_matching
    actual_mode = configured_mode
    fallback_reason: str | None = None
    osv_candidates: list[dict[str, Any]] = []

    if configured_mode == "index":
        sqlite_path, raw_dir, reason = _resolve_osv_source(repository_root, run_root, osv_snapshot)
        if sqlite_path is not None:
            try:
                osv_candidates = _match_osv_indexed(sqlite_path, dependencies, cfg.max_advisories)
                actual_mode = "index"
            except (sqlite3.Error, ValueError, OSError) as exc:
                actual_mode = "exact"
                fallback_reason = f"osv_index_invalid:{type(exc).__name__}:{str(exc)[:160]}"
                osv_candidates = _match_osv_exact_dir(raw_dir, dependencies, cfg.max_advisories)
        else:
            actual_mode = "exact"
            fallback_reason = reason or "osv_index_unavailable"
            osv_candidates = _match_osv_exact_dir(raw_dir, dependencies, cfg.max_advisories)
    elif configured_mode == "exact":
        _, raw_dir, _ = _resolve_osv_source(repository_root, run_root, osv_snapshot)
        osv_candidates = _match_osv_exact_dir(raw_dir, dependencies, cfg.max_advisories)
        actual_mode = "exact"
    else:
        actual_mode = "disabled"

    deps_by_name: dict[str, list[Mapping[str, Any]]] = {}
    for dep in dependencies:
        _, dname, _, _ = _dependency_ecosystem_and_name(dep)
        if dname:
            deps_by_name.setdefault(dname.casefold(), []).append(dep)

    merged: dict[tuple[str, str, str], dict[str, Any]] = {}

    def _merge_candidate(cand: Mapping[str, Any]) -> None:
        adv_id = str(cand.get("advisory_id") or "").strip()
        pkg_name = str(cand.get("package_name") or "").strip()
        pkg_ver = str(cand.get("package_version") or "").strip() or None
        if not adv_id or not pkg_name:
            return
        key = (adv_id, pkg_name.casefold(), pkg_ver or "")
        matching_deps = deps_by_name.get(pkg_name.casefold(), [])
        default_direct = (
            any(_is_direct_dependency(d) for d in matching_deps)
            if matching_deps
            else bool(cand.get("direct", True))
        )
        default_dep_ids = [str(d.get("dependency_id")) for d in matching_deps if d.get("dependency_id")]
        existing = merged.get(key)
        cves = set(cand.get("cve_ids") or ())
        if _CVE_RE.fullmatch(adv_id):
            cves.add(adv_id.upper())
        if existing is None:
            merged[key] = {
                "advisory_id": adv_id,
                "cve_ids": sorted(cves),
                "package_name": pkg_name,
                "package_version": pkg_ver,
                "purl": cand.get("purl") if isinstance(cand.get("purl"), str) else None,
                "ecosystem": cand.get("ecosystem") if isinstance(cand.get("ecosystem"), str) else None,
                "severity": cand.get("severity") if isinstance(cand.get("severity"), str) else None,
                "direct": bool(cand.get("direct", default_direct)),
                "match_sources": {str(cand.get("match_source") or "scanner")},
                "affected_symbols": set(cand.get("affected_symbols") or ()),
                "affected_modules": set(cand.get("affected_modules") or ()),
                "dependency_ids": set(cand.get("dependency_ids") or default_dep_ids),
            }
        else:
            existing["cve_ids"] = sorted(set(existing["cve_ids"]) | cves)
            existing["match_sources"].add(str(cand.get("match_source") or "scanner"))
            existing["affected_symbols"].update(cand.get("affected_symbols") or ())
            existing["affected_modules"].update(cand.get("affected_modules") or ())
            existing["dependency_ids"].update(cand.get("dependency_ids") or default_dep_ids)
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
        eco = PURL_TO_OSV_ECOSYSTEM.get(purl_parts(purl)[0]) if purl and purl_parts(purl) else None
        _merge_candidate({
            "advisory_id": obs.get("advisory"),
            "package_name": obs.get("package"),
            "package_version": obs.get("version"),
            "purl": purl,
            "ecosystem": eco,
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
        else {"imports": [], "ffi_sites": [], "symbol_calls": {}}
    )

    advisory_records: list[dict[str, Any]] = []
    symbol_reachable_count = 0
    package_imported_count = 0
    transitive_only_count = 0
    unreachable_count = 0
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
        verdict, sites, ffi_mechs = classify_advisory_reachability(
            prepared,
            target_index,
            max_call_sites=cfg.max_call_sites_per_advisory,
        )
        if verdict == REACHABILITY_SYMBOL:
            symbol_reachable_count += 1
        elif verdict == REACHABILITY_IMPORTED:
            package_imported_count += 1
        elif verdict == REACHABILITY_TRANSITIVE:
            transitive_only_count += 1
        else:
            unreachable_count += 1
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
    }
    return {
        "schema": REACHABILITY_SCHEMA,
        "source_fingerprint": source_fingerprint,
        "configured_osv_mode": configured_mode,
        "osv_matching_mode": actual_mode,
        "osv_fallback_reason": fallback_reason,
        "advisories": advisory_records,
        "telemetry": telemetry,
    }


__all__ = [
    "DependencyIntelligenceSettings",
    "OSV_MATCHING_MODES",
    "OsvSnapshotSource",
    "REACHABILITY_IMPORTED",
    "REACHABILITY_SCHEMA",
    "REACHABILITY_SYMBOL",
    "REACHABILITY_TRANSITIVE",
    "REACHABILITY_UNREACHABLE",
    "classify_advisory_reachability",
    "evaluate_sca_reachability",
    "scan_target_reachability_index",
]
