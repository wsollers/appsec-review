from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import inspect
import json
from pathlib import Path, PurePosixPath
import re
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping
import xml.etree.ElementTree as ET

from appsec_review import blint_report
from appsec_review.storage import canonical_json
from appsec_review.tool_inputs import (
    C_CPP_SOURCE, NATIVE_BINARIES, SEI_CERT_SOURCE, SOURCE_SUFFIXES,
    semgrep_skip_not_applicable, shellcheck_unsupported_dialect, supports_path,
)


# Supported-input declarations live once in appsec_review.tool_inputs; these names are views.
SOURCE_EXTENSIONS = SOURCE_SUFFIXES
CPP_EXTENSIONS = C_CPP_SOURCE
CPP_TRANSLATION_UNITS = {".c", ".cc", ".cpp", ".cxx"}
MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pyproject.toml",
    "requirements.txt", "poetry.lock", "Pipfile.lock", "go.mod", "go.sum", "Cargo.toml",
    "Cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts", "composer.json",
    "composer.lock", "Gemfile", "Gemfile.lock",
}
BINARY_EXTENSIONS = NATIVE_BINARIES
# Languages of the SEI CERT rule pack (rules/sei-cert); OpenGrep runs that pack only.
SEI_CERT_EXTENSIONS = SEI_CERT_SOURCE
SEI_CERT_RULE_PREFIX = "appsec-review.sei-cert."
SEI_CERT_MOUNT = "/rules-sei-cert"
SEI_CERT_METADATA = ("pack", "cert", "cert_also", "cert_standard", "cert_url", "coverage", "confidence",
                     "precision", "cwe")
SEI_CERT_LIMITATIONS = (
    "SEI CERT rule pack: findings evidence only the implemented subset of each mapped CERT rule; CERT rules "
    "with REQUIRES_* or UNSUPPORTED_* status produce no findings (rules/sei-cert/COVERAGE.md), so an absence "
    "of findings is not CERT conformance",
    "SEI CERT rule pack: C and C++ are analyzed without preprocessing; macro-expanded code is not seen",
)


@dataclass(frozen=True, slots=True)
class ScanCatalog:
    source_fingerprint: str
    handoff_sha256: str
    files: tuple[Mapping[str, Any], ...]
    projects: tuple[Mapping[str, Any], ...]
    artifacts: tuple[Mapping[str, Any], ...] = ()
    target_root: Path | None = None
    compile_commands: tuple[Mapping[str, Any], ...] = ()

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(str(item["path"]) for item in self.files)


@dataclass(frozen=True, slots=True)
class Applicability:
    applicable: bool
    reason: str
    files: tuple[str, ...]
    coverage_kind: str
    gaps: tuple[str, ...] = ()
    families: Mapping[str, tuple[str, ...]] = field(default_factory=lambda: MappingProxyType({}))

    def as_dict(self) -> dict[str, Any]:
        return {"applicable": self.applicable, "reason": self.reason,
                "files": list(self.files), "coverage_kind": self.coverage_kind,
                "gaps": list(self.gaps),
                "families": {key: list(value) for key, value in sorted(self.families.items())}}


Parser = Callable[[bytes], list[dict[str, Any]]]
Selector = Callable[[ScanCatalog], Applicability]
ArgvBuilder = Callable[[str, Applicability], tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class ToolAdapter:
    tool_id: str
    capability: str
    accepted_exit_codes: frozenset[int]
    output_file: str | None
    selector: Selector
    argv_builder: ArgvBuilder
    parser: Parser
    limitations: tuple[str, ...] = ()
    # Assembles ``output_file`` inside the host scratch directory after a successful exit, for tools
    # that write several report files instead of one (blint).
    collector: Callable[[Path], None] | None = None
    # Named degradations a tool reports only on stderr while still exiting successfully.
    stderr_gaps: Callable[[bytes], list[str]] | None = None

    @property
    def parser_identity(self) -> str:
        return hashlib.sha256(inspect.getsource(self.parser).encode()).hexdigest()

    @property
    def adapter_identity(self) -> str:
        value = (self.tool_id, self.capability, sorted(self.accepted_exit_codes), self.output_file,
                 self.limitations, inspect.getsource(self.selector), inspect.getsource(self.argv_builder),
                 self.parser_identity,
                 *(inspect.getsource(item) for item in (self.collector, self.stderr_gaps) if item))
        return hashlib.sha256(repr(value).encode()).hexdigest()

    def applicability(self, catalog: ScanCatalog) -> Applicability:
        return self.selector(catalog)

    def argv(self, executable: str, applicability: Applicability) -> tuple[str, ...]:
        argv = self.argv_builder(executable, applicability)
        if not argv or argv[0] != executable or any("\0" in item for item in argv):
            raise ValueError(f"adapter constructed unsafe argv: {self.tool_id}")
        return argv

    def parse(self, payload: bytes) -> list[dict[str, Any]]:
        try:
            return self.parser(payload)
        except (UnicodeError, json.JSONDecodeError, ET.ParseError, TypeError, ValueError, KeyError) as exc:
            raise ValueError(f"{self.tool_id} output parser failed: {type(exc).__name__}") from exc


def _paths(catalog: ScanCatalog, predicate: Callable[[str, Mapping[str, Any]], bool]) -> tuple[str, ...]:
    return tuple(sorted(str(item["path"]) for item in catalog.files if predicate(str(item["path"]), item)))


def _select_files(kind: str, predicate: Callable[[str, Mapping[str, Any]], bool], *,
                  missing: str, gaps: tuple[str, ...] = ()) -> Selector:
    def select(catalog: ScanCatalog) -> Applicability:
        paths = _paths(catalog, predicate)
        return Applicability(bool(paths), f"catalog contains {len(paths)} {kind} input(s)" if paths else missing,
                             paths, kind, gaps if paths else ())
    return select


def _all_source(catalog: ScanCatalog) -> Applicability:
    paths = _paths(catalog, lambda path, item: supports_path("tool-semgrep", path))
    return Applicability(bool(paths), f"catalog contains {len(paths)} source input(s)" if paths else
                         "target catalog contains no supported source files", paths, "source_files")


def _sei_cert_source(catalog: ScanCatalog) -> Applicability:
    paths = _paths(catalog, lambda path, item: supports_path("tool-opengrep", path))
    kotlin = _paths(catalog, lambda path, item: PurePosixPath(path).suffix.lower() in {".kt", ".kts"})
    gaps = (f"SEI CERT rule pack has no Kotlin rules; {len(kotlin)} Kotlin file(s) are outside its scope",) if kotlin else ()
    return Applicability(bool(paths), f"catalog contains {len(paths)} C, C++, or Java input(s)" if paths else
                         "target catalog contains no C, C++, or Java source for the SEI CERT rule pack",
                         paths, "source_files", gaps)


def _gitleaks(catalog: ScanCatalog) -> Applicability:
    return Applicability(bool(catalog.files), f"catalog contains {len(catalog.files)} bounded files" if catalog.files else
                         "target catalog contains no files", catalog.paths, "cataloged_repository",
                         ("git history is not scanned; coverage is the cataloged worktree",))


def _syft(catalog: ScanCatalog) -> Applicability:
    manifests = _paths(catalog, lambda path, item: PurePosixPath(path).name in MANIFEST_NAMES)
    gaps = ("directory coverage only; no cataloged OCI/archive artifact",)
    return Applicability(bool(catalog.files), "cataloged directory is available" if catalog.files else
                         "target catalog contains no directory inputs", manifests or catalog.paths,
                         "directory", gaps if catalog.files else ())


def _spotbugs(catalog: ScanCatalog) -> Applicability:
    files = tuple(sorted(str(item.get("path")) for item in catalog.artifacts
                         if supports_path("tool-spotbugs", str(item.get("path")))))
    return Applicability(bool(files), "catalog contains accepted JVM bytecode" if files else
                         "no accepted JVM bytecode artifact is present; target code is not compiled by the scanner",
                         files, "jvm_bytecode", () if files else ("JVM source-only coverage is unavailable",))


def _blint(catalog: ScanCatalog) -> Applicability:
    files = tuple(sorted(str(item.get("path")) for item in catalog.artifacts
                         if supports_path("tool-blint", str(item.get("path")))))
    return Applicability(bool(files), "catalog contains accepted native/binary artifacts" if files else
                         "no accepted binary artifact is present", files, "built_binary",
                          () if files else ("source files are not treated as built binaries",))


def _checkov(catalog: ScanCatalog) -> Applicability:
    selected = _paths(catalog, lambda path, item: supports_path("tool-checkov", path))
    reason = (f"catalog contains {len(selected)} candidate Checkov input(s); Checkov decides which it recognizes"
              if selected else "target catalog contains no Terraform, Dockerfile, YAML, or JSON inputs")
    return Applicability(bool(selected), reason, selected, "checkov_typed_configuration")


def _checkov_args(executable: str, selection: Applicability) -> tuple[str, ...]:
    # No --framework restriction and no --quiet: Checkov arbitrates which inputs it recognizes, and
    # only the non-quiet report lists passed checks, which is how a clean input is told from an
    # input Checkov did not recognize (see checkov_unreported_inputs).
    return (executable, "--compact", "--output", "json", "-f", *(_target(path) for path in selection.files))


def _safe_catalog_file(catalog: ScanCatalog, relative: str, *, limit: int) -> bytes | None:
    if catalog.target_root is None:
        return None
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts:
        return None
    candidate = (catalog.target_root / pure).resolve()
    root = catalog.target_root.resolve()
    if root not in candidate.parents or not candidate.is_file() or candidate.stat().st_size > limit:
        return None
    return candidate.read_bytes()


def _cppcheck(catalog: ScanCatalog) -> Applicability:
    files = _paths(catalog, lambda path, item: supports_path("tool-cppcheck", path))
    if not files:
        return Applicability(False, "target catalog contains no C/C++ source files", (), "cpp_source")
    families: dict[str, tuple[str, ...]] = {}
    gaps: list[str] = []
    compile_paths = tuple(sorted(str(item.get("path")) for item in catalog.compile_commands
                                 if PurePosixPath(str(item.get("path"))).name == "compile_commands.json"))
    accepted = None
    if len(compile_paths) == 1:
        payload = _safe_catalog_file(catalog, compile_paths[0], limit=8 * 1024 * 1024)
        try:
            document = json.loads(payload.decode("utf-8")) if payload is not None else None
            if isinstance(document, list) and any(isinstance(item, Mapping) and item.get("file")
                                                  for item in document):
                accepted = compile_paths[0]
        except (UnicodeError, json.JSONDecodeError):
            accepted = None
        if accepted is None:
            gaps.append("cataloged compile_commands.json was invalid or exceeded the 8 MiB acceptance bound")
    elif len(compile_paths) > 1:
        gaps.append("multiple compile_commands.json files were cataloged; no ambiguous build metadata was selected")
    if accepted is not None:
        families["compile_database"] = (accepted,)
        mode = "sanitized compile database"
        coverage = "cpp_compile_database"
    else:
        mode = "defensible source mode"
        coverage = "cpp_source_without_build_context"
        gaps.append("build flags, include paths, and macros are unavailable; Cppcheck source-mode coverage is incomplete")
    return Applicability(True, f"catalog contains {len(files)} C/C++ input(s); using {mode}", files,
                         coverage, tuple(gaps), MappingProxyType(families))


def _cppcheck_args(executable: str, selection: Applicability) -> tuple[str, ...]:
    common = (executable, "--enable=warning,style,performance,portability", "--check-level=normal",
              "--inline-suppr", "--xml", "--xml-version=2", "--output-file=/scratch/output.xml")
    if selection.families.get("compile_database"):
        return (*common, "--project=/inputs/compile_commands.json")
    return (*common, *(_target(path) for path in selection.files))


def _pmd(catalog: ScanCatalog) -> Applicability:
    files = _paths(catalog, lambda path, item: supports_path("tool-pmd", path))
    gaps = (
        "dependency classpath was not constructed or downloaded; rules requiring complete external type resolution may be incomplete",
        "PMD source analysis is not JVM bytecode coverage; SpotBugs requires accepted JVM bytecode",
    )
    return Applicability(bool(files), f"catalog contains {len(files)} Java source input(s)" if files else
                         "target catalog contains no Java source files", files, "java_source_ast",
                         gaps if files else ())


def _pmd_args(executable: str, selection: Applicability) -> tuple[str, ...]:
    return (executable, "check", "--no-cache", "--no-progress", "--format", "json",
            "--report-file", "/scratch/output.json", "--rulesets", "/rules/java-security.xml",
            "--file-list", "/inputs/pmd-files.txt")


def _target(path: str) -> str:
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"catalog path is unsafe: {path}")
    return "/target/" + pure.as_posix()


def _args(*prefix: str, output: str | None = None) -> ArgvBuilder:
    def build(executable: str, selection: Applicability) -> tuple[str, ...]:
        argv = [executable, *prefix]
        if output:
            argv.extend(output.split("\0"))
        argv.extend(_target(path) for path in selection.files)
        return tuple(argv)
    return build


def _gosec_args(executable: str, selection: Applicability) -> tuple[str, ...]:
    """gosec loads Go *packages*: hand it each selected file's package directory, never a file.

    A file argument makes go/packages fail with 'importing dir ".../main.go": cannot find package'.
    Directories are derived from the catalog selection, so every Go package root of any target is
    covered without assuming a layout.
    """
    directories = sorted({PurePosixPath(_target(path)).parent.as_posix() for path in selection.files})
    return (executable, "-fmt=json", "-out=/scratch/output.json", "-no-fail", *directories)


def _blint_args(executable: str, selection: Applicability) -> tuple[str, ...]:
    """blint 3.4.0 has no --format/--output; it writes JSON reports into --reports (blint_report)."""
    return (executable, "--no-banner", "--no-error", "--quiet", "--reports", "/scratch",
            "--src", *(_target(path) for path in selection.files))


def _json(payload: bytes) -> Any:
    if not payload.strip():
        return []
    return json.loads(payload.decode("utf-8"))


def _record(item: Mapping[str, Any], *, rule: Iterable[str], message: Iterable[str],
            severity_keys: Iterable[str] = ("severity", "level"), path_keys: Iterable[str] = ("path", "file", "filename"),
            line_keys: Iterable[str] = ("line", "start_line", "lineNumber"), category: str = "static_analysis") -> dict[str, Any]:
    def first(keys: Iterable[str], default: Any = None) -> Any:
        for key in keys:
            if key in item and item[key] is not None:
                return item[key]
        return default
    location = item.get("location") if isinstance(item.get("location"), Mapping) else {}
    start = item.get("start") if isinstance(item.get("start"), Mapping) else {}
    return {
        "rule_id": first(rule, "unknown"), "message": first(message, ""),
        "severity": first(severity_keys, "UNKNOWN"), "category": item.get("category", category),
        "path": first(path_keys, location.get("path") or location.get("file")),
        "start_line": first(line_keys, start.get("line") or location.get("line") or 1),
        "end_line": item.get("end_line") or item.get("endLine") or 1,
        "component": item.get("component"), "package": item.get("package") or item.get("name"),
        "advisory": item.get("advisory") or item.get("vulnerability") or item.get("id"),
        "language": item.get("language"),
        **{key: item[key] for key in ("secret", "match", "password", "token") if key in item},
    }


def _list_parser(payload: bytes) -> list[dict[str, Any]]:
    value = _json(payload)
    items = value if isinstance(value, list) else value.get(
        "results", value.get("findings", value.get("comments", []))
    )
    return [_record(item, rule=("rule_id", "RuleID", "check_id", "id", "code"),
                    message=("message", "Description", "description", "text")) for item in items]


def _mobsfscan_parser(payload: bytes) -> list[dict[str, Any]]:
    records = []
    for rule_id, result in _json(payload).get("results", {}).items():
        metadata = result.get("metadata", {})
        files = result.get("files") or [{}]
        for item in files:
            lines = item.get("match_lines") or [1, 1]
            records.append({
                "rule_id": rule_id, "message": metadata.get("description") or rule_id,
                "severity": metadata.get("severity"), "category": "source_sast",
                "path": item.get("file_path"), "start_line": lines[0], "end_line": lines[-1],
            })
    return records


def _semgrep_parser(payload: bytes) -> list[dict[str, Any]]:
    """Parse Semgrep CE / OpenGrep JSON, keeping engine errors and skipped targets as coverage gaps."""
    document = _json(payload)
    records: list[dict[str, Any]] = []
    for item in document.get("results", []):
        extra = item.get("extra", {}) if isinstance(item.get("extra"), Mapping) else {}
        rule_id = str(item.get("check_id"))
        record = {
            "rule_id": item.get("check_id"), "message": extra.get("message"),
            "severity": extra.get("severity"), "category": "source_sast",
            "path": item.get("path"), "start_line": item.get("start", {}).get("line"),
            "end_line": item.get("end", {}).get("line"),
        }
        if SEI_CERT_RULE_PREFIX in rule_id:
            # Engines prefix rule IDs with the config directory; keep the pack-owned identity and the
            # rule's CERT mapping so the observation resolves to rules/sei-cert/mappings.
            record["rule_id"] = rule_id[rule_id.index(SEI_CERT_RULE_PREFIX):]
            metadata = extra.get("metadata", {}) if isinstance(extra.get("metadata"), Mapping) else {}
            record["rule_mapping"] = {key: metadata[key] for key in SEI_CERT_METADATA if key in metadata}
        records.append(record)
    for error in document.get("errors", []) if isinstance(document, Mapping) else []:
        if isinstance(error, Mapping):
            location = error.get("path") or error.get("rule_id") or "engine"
            text = " ".join(str(error.get("message") or error.get("type") or "error").split())[:300]
            records.append({"gap_only": True,
                            "coverage_gap": f"engine reported {error.get('level', 'error')} for {location}: {text}"})
    paths = document.get("paths", {}) if isinstance(document, Mapping) else {}
    for skipped in (paths.get("skipped") or []) if isinstance(paths, Mapping) else []:
        if isinstance(skipped, Mapping):
            if semgrep_skip_not_applicable(skipped.get("reason")):
                # No rule or language of the configured packs applies: SKIPPED_NA, not a gap.
                records.append({"gap_only": True, "not_applicable_input": str(skipped.get("path")),
                                "not_applicable_reason": f"engine skipped target: {skipped.get('reason')}"})
                continue
            records.append({"gap_only": True,
                            "coverage_gap": f"engine skipped {skipped.get('path')}: {skipped.get('reason')}"})
    return records


# Semgrep/OpenGrep language names (and aliases) a rule's ``languages`` may use for a file suffix.
SEMGREP_SUFFIX_LANGUAGES: Mapping[str, frozenset[str]] = MappingProxyType({
    ".py": frozenset({"python", "py", "python3"}), ".js": frozenset({"javascript", "js"}),
    ".jsx": frozenset({"javascript", "js"}), ".ts": frozenset({"typescript", "ts"}),
    ".tsx": frozenset({"typescript", "ts"}), ".java": frozenset({"java"}),
    ".kt": frozenset({"kotlin", "kt"}), ".go": frozenset({"go", "golang"}),
    ".rs": frozenset({"rust"}), ".c": frozenset({"c"}), ".h": frozenset({"c", "cpp", "c++"}),
    **{suffix: frozenset({"cpp", "c++"}) for suffix in (".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx")},
    ".cs": frozenset({"csharp", "c#"}), ".rb": frozenset({"ruby"}), ".php": frozenset({"php"}),
    ".swift": frozenset({"swift"}), ".sh": frozenset({"bash", "sh"}),
})
_ALL_FILE_LANGUAGES = frozenset({"generic", "regex", "none"})
_INLINE_LANGUAGES = re.compile(r"(?m)^\s*-?\s*languages:\s*\[([^\]]*)\]")
_BLOCK_LANGUAGES = re.compile(r"(?m)^(\s*)-?\s*languages:\s*\n((?:\1\s+-\s*[^\n]+\n?)+)")


def semgrep_rule_languages(rule_files: Iterable[Path]) -> frozenset[str] | None:
    """Languages declared by the configured rule files, or ``None`` when any file is unreadable or
    declares none (then no dropped input can be attributed to a missing rule language)."""
    languages: set[str] = set()
    for path in rule_files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return None
        found = [item for match in _INLINE_LANGUAGES.finditer(text) for item in match.group(1).split(",")]
        found += [line.strip().lstrip("-").strip() for match in _BLOCK_LANGUAGES.finditer(text)
                  for line in match.group(2).splitlines()]
        found = [item.strip().strip("'\"").lower() for item in found if item.strip()]
        if not found:
            return None
        languages.update(found)
    return frozenset(languages)


def semgrep_unscanned_inputs(payload: bytes, given: Iterable[str], rule_languages: frozenset[str] | None,
                             relative: Callable[[str], str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Inputs handed to Semgrep/OpenGrep that it neither scanned nor reported as skipped.

    Semgrep CE omits ``paths.skipped`` unless verbose, so a dropped file would otherwise vanish. A
    dropped file whose language no configured rule declares is SKIPPED_NA (``no rules for
    language``); any other dropped file is a coverage gap.
    """
    document = _json(payload)
    paths = document.get("paths") if isinstance(document, Mapping) else None
    if not isinstance(paths, Mapping) or not isinstance(paths.get("scanned"), list):
        return (["engine did not report scanned paths; per-file Semgrep coverage is unverified"], [])
    accounted = {relative(str(item)) for item in paths["scanned"]}
    accounted |= {relative(str(item.get("path"))) for item in paths.get("skipped") or []
                  if isinstance(item, Mapping)}
    gaps: list[str] = []
    skipped: list[tuple[str, str]] = []
    dropped = sorted(set(given) - accounted)
    for path in dropped:
        names = SEMGREP_SUFFIX_LANGUAGES.get(PurePosixPath(path).suffix.lower(), frozenset())
        if (rule_languages is not None and names and not names & rule_languages
                and not rule_languages & _ALL_FILE_LANGUAGES):
            language = sorted(names)[0]
            skipped.append((path, f"engine did not scan the input: no rules for language {language} "
                                  "in the configured rule packs"))
        else:
            gaps.append(path)
    if gaps:
        sample = ", ".join(gaps[:20]) + (f" (+{len(gaps) - 20} more)" if len(gaps) > 20 else "")
        return ([f"engine did not scan {len(gaps)} given input(s) whose language has configured rules: {sample}"],
                skipped)
    return [], skipped


def _shellcheck_parser(payload: bytes) -> list[dict[str, Any]]:
    """ShellCheck json1; SC1071 (unsupported shell dialect) is SKIPPED_NA for that file, not a finding."""
    value = _json(payload)
    items = value if isinstance(value, list) else value.get("comments", [])
    records: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, Mapping) and shellcheck_unsupported_dialect(item):
            records.append({"gap_only": True, "not_applicable_input": str(item.get("file")),
                            "not_applicable_reason": "tool-shellcheck reported SC1071: "
                            "ShellCheck only supports sh/bash/dash/ksh scripts"})
            continue
        records.append(_record(item, rule=("rule_id", "RuleID", "check_id", "id", "code"),
                               message=("message", "Description", "description", "text")))
    return records


def _gosec_parser(payload: bytes) -> list[dict[str, Any]]:
    return [_record(item, rule=("rule_id",), message=("details",), path_keys=("file",),
                    line_keys=("line",), category="source_sast") for item in _json(payload).get("Issues", [])]


def _checkov_parser(payload: bytes) -> list[dict[str, Any]]:
    value = _json(payload)
    documents = value if isinstance(value, list) else [value]
    result = []
    for document in documents:
        for item in document.get("results", {}).get("failed_checks", []):
            result.append(_record(item, rule=("check_id",), message=("check_name",),
                                  path_keys=("file_path",), line_keys=("file_line_range",),
                                  category="configuration"))
    for item in result:
        if isinstance(item["start_line"], list):
            lines = item["start_line"]
            item["start_line"] = lines[0] if lines else 1
            item["end_line"] = lines[-1] if lines else 1
    for path in _checkov_parsing_errors(documents):
        result.append({"gap_only": True, "coverage_gap": f"checkov could not parse {path}"})
    return result


def _checkov_parsing_errors(documents: Iterable[Any]) -> list[str]:
    return sorted({str(path) for document in documents if isinstance(document, Mapping)
                   for path in document.get("results", {}).get("parsing_errors", []) or []})


def _checkov_reported_paths(payload: bytes) -> set[str]:
    value = _json(payload)
    documents = value if isinstance(value, list) else [value]
    reported: set[str] = set()
    for document in documents:
        if not isinstance(document, Mapping):
            continue
        results = document.get("results", {})
        for key in ("passed_checks", "failed_checks", "skipped_checks"):
            reported.update(str(item.get("file_path")) for item in results.get(key, []) or []
                            if isinstance(item, Mapping) and item.get("file_path"))
    reported.update(_checkov_parsing_errors(documents))
    return reported


def checkov_unreported_inputs(payload: bytes, inputs: Iterable[str]) -> list[str]:
    """Planned inputs Checkov ran over but reported no check, skip, or parse error for.

    Checkov is the arbiter of what it recognizes: an input it accepted and produced nothing for is
    not applicable to this step. Its report paths are mount-relative with inconsistent roots
    (``/target/x``, ``/../target/x``, or relative to the framework's common root), so an input
    counts as reported when its path ends with any reported path on a component boundary; an
    ambiguous match errs toward "reported", never toward a false not-applicable claim.
    """
    candidates: set[str] = set()
    for reported in _checkov_reported_paths(payload):
        parts = [part for part in PurePosixPath(reported).parts if part not in {"/", "..", "."}]
        if parts:
            candidates.add("/".join(parts))
            if parts[0] == "target" and len(parts) > 1:
                candidates.add("/".join(parts[1:]))
    return sorted(path for path in inputs
                  if not any(path == candidate or path.endswith("/" + candidate) for candidate in candidates))


def _trivy_parser(payload: bytes) -> list[dict[str, Any]]:
    result = []
    for section in _json(payload).get("Results", []):
        for item in section.get("Misconfigurations") or []:
            target = str(section.get("Target", "")).replace("/scratch/inputs/", "")
            result.append({"rule_id": item.get("ID"), "message": item.get("Message") or item.get("Title"),
                           "severity": item.get("Severity"), "category": "configuration",
                           "path": target, "start_line": item.get("CauseMetadata", {}).get("StartLine"),
                           "end_line": item.get("CauseMetadata", {}).get("EndLine")})
    return result


def _syft_parser(payload: bytes) -> list[dict[str, Any]]:
    return [{"rule_id": "software-component", "message": f"{item.get('name')} {item.get('version')}",
             "severity": "INFO", "category": "software_inventory", "package": item.get("name"),
             "component": item.get("id"), "path": next((loc.get("path") for loc in item.get("locations", [])
                                                          if isinstance(loc, Mapping)), None), "start_line": 1}
            for item in _json(payload).get("artifacts", [])]


def _grype_parser(payload: bytes) -> list[dict[str, Any]]:
    return [{"rule_id": item.get("vulnerability", {}).get("id"),
             "message": item.get("vulnerability", {}).get("description") or item.get("vulnerability", {}).get("id"),
             "severity": item.get("vulnerability", {}).get("severity"), "category": "vulnerability_matching",
             "package": item.get("artifact", {}).get("name"), "component": item.get("artifact", {}).get("id"),
             "advisory": item.get("vulnerability", {}).get("id")} for item in _json(payload).get("matches", [])]


def _osv_parser(payload: bytes) -> list[dict[str, Any]]:
    records = []
    for result in _json(payload).get("results", []):
        for package in result.get("packages", []):
            for vulnerability in package.get("vulnerabilities", []):
                records.append({"rule_id": vulnerability.get("id"), "message": vulnerability.get("summary") or vulnerability.get("id"),
                    "severity": "UNKNOWN", "category": "vulnerability_matching", "package": package.get("package", {}).get("name"),
                    "advisory": vulnerability.get("id"), "path": result.get("source", {}).get("path"), "start_line": 1})
    return records


def _spotbugs_parser(payload: bytes) -> list[dict[str, Any]]:
    root = ET.fromstring(payload.decode("utf-8"))
    records = []
    for bug in root.findall(".//BugInstance"):
        source = bug.find("SourceLine")
        records.append({"rule_id": bug.get("type"), "message": (bug.findtext("LongMessage") or bug.get("type")),
                        "severity": bug.get("priority"), "category": "source_sast",
                        "path": source.get("sourcepath") if source is not None else None,
                        "start_line": source.get("start") if source is not None else 1,
                        "end_line": source.get("end") if source is not None else 1})
    return records


BLINT_REPORT = "/scratch/blint-report.json"
TRIVY_EMBEDDED_CHECKS = ("Trivy misconfiguration checks are the set embedded in the pinned Trivy binary; "
                         "the online checks bundle is never fetched (--skip-check-update)")


def _collect_blint(scratch: Path) -> None:
    blint_report.write(scratch, scratch / PurePosixPath(BLINT_REPORT).name)


def _blint_parser(payload: bytes) -> list[dict[str, Any]]:
    """Assembled blint reports; no per-binary metadata at all means nothing was analyzed (a gap)."""
    document = _json(payload)
    records: list[dict[str, Any]] = [
        {"rule_id": item.get("id"), "message": item.get("title") or item.get("id"),
         "severity": item.get("severity"), "category": "binary_hardening",
         "path": item.get("filename") or item.get("exe_name"), "start_line": 1, "end_line": 1}
        for item in document.get("findings", [])]
    if not document.get("analyzed"):
        records.append({"gap_only": True,
                        "coverage_gap": "blint produced no per-binary analysis report for the selected binaries"})
    return records


def _trivy_stderr_gaps(stderr: bytes) -> list[str]:
    text = stderr[-65_536:].decode("utf-8", "replace")
    if "failed to download checks bundle" in text:
        return ["Trivy attempted a checks-bundle download and fell back to its embedded checks"]
    return []


def _cppcheck_parser(payload: bytes) -> list[dict[str, Any]]:
    root = ET.fromstring(payload.decode("utf-8"))
    records = []
    gap_ids = {"missingInclude", "missingIncludeSystem", "noValidConfiguration", "toomanyconfigs"}
    for error in root.findall(".//errors/error"):
        location = error.find("location")
        record = {
            "rule_id": error.get("id", "cppcheck"), "message": error.get("verbose") or error.get("msg", ""),
            "severity": error.get("severity", "UNKNOWN"), "category": "source_sast",
            "path": location.get("file") if location is not None else None,
            "start_line": location.get("line") if location is not None else 1,
            "end_line": location.get("line") if location is not None else 1,
            "language": "C/C++",
        }
        if error.get("id") in gap_ids:
            record["coverage_gap"] = f"Cppcheck {error.get('id')}: {record['message']}"
            record["gap_only"] = True
        records.append(record)
    return records


def _pmd_parser(payload: bytes) -> list[dict[str, Any]]:
    value = _json(payload)
    if value.get("configurationErrors"):
        raise ValueError("PMD reported a ruleset configuration error")
    records: list[dict[str, Any]] = []
    for document in value.get("files", []):
        path = document.get("filename")
        for item in document.get("violations", []):
            priority = item.get("priority")
            pmd_severity = {
                1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW", 5: "LOW",
                "1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "LOW", "5": "LOW",
            }.get(priority, "UNKNOWN")
            records.append({
                "rule_id": item.get("rule", "pmd"), "message": item.get("description", ""),
                "severity": pmd_severity, "category": "source_sast",
                "path": path, "start_line": item.get("beginline", 1), "end_line": item.get("endline", 1),
                "language": "Java",
            })
        for error in document.get("processingErrors", []):
            records.append({"rule_id": "pmd-processing-error", "message": error.get("msg", ""),
                            "severity": "ERROR", "category": "tool_diagnostic", "path": path,
                            "start_line": 1, "end_line": 1,
                            "coverage_gap": f"PMD could not process {path}", "gap_only": True})
    return records


def _phpstan_parser(payload: bytes) -> list[dict[str, Any]]:
    records = []
    for path, value in _json(payload).get("files", {}).items():
        for message in value.get("messages", []):
            records.append({"rule_id": message.get("identifier", "phpstan"), "message": message.get("message"),
                            "severity": "ERROR", "category": "source_sast", "path": path,
                            "start_line": message.get("line", 1)})
    return records


def _phpcs_parser(payload: bytes) -> list[dict[str, Any]]:
    records = []
    for path, value in _json(payload).get("files", {}).items():
        for message in value.get("messages", []):
            records.append({"rule_id": message.get("source", "phpcs"), "message": message.get("message"),
                            "severity": message.get("type", "WARNING"), "category": "source_sast", "path": path,
                            "start_line": message.get("line", 1)})
    return records


def _registry() -> dict[str, ToolAdapter]:
    lang = lambda tool_id, label: _select_files("source_files", lambda p, i: supports_path(tool_id, p),
                                                missing=f"target catalog contains no {label} source")
    dockerfiles = _select_files("dockerfiles", lambda p, i: supports_path("tool-hadolint", p),
                                missing="target catalog contains no Dockerfiles")
    iac = _select_files("iac_files", lambda p, i: supports_path("tool-trivy", p),
                        missing="target catalog contains no supported IaC files")
    workflows = _select_files("workflows", lambda p, i: supports_path("tool-zizmor", p),
                              missing="target catalog contains no GitHub Actions workflows")
    # Every lockfile/manifest osv-scanner extracts offline, in any project root; each input's
    # ecosystem is checked against the synchronized snapshot before launch (job._osv_split_by_snapshot).
    manifests = _select_files("dependency_lockfiles", lambda p, i: supports_path("tool-osv-scanner", p),
                              missing="target catalog contains no lockfile or manifest osv-scanner extracts offline")
    adapters = [
        ToolAdapter("tool-gitleaks", "secrets", frozenset({0, 1}), "/scratch/output.json", _gitleaks,
                    lambda exe, sel: (exe, "dir", "/target", "--no-banner", "--redact", "--report-format", "json",
                                      "--report-path", "/scratch/output.json", "--exit-code", "1"), _list_parser,
                    ("worktree only; git history is excluded",)),
        ToolAdapter("tool-semgrep", "source_sast", frozenset({0}), "/scratch/output.json", _all_source,
                    _args("scan", "--disable-version-check", "--metrics", "off", "--config", "/rules/security.yml",
                          "--config", "/rules/review-signals.yml", "--config", SEI_CERT_MOUNT, "--json",
                          "--output", "/scratch/output.json"), _semgrep_parser,
                    SEI_CERT_LIMITATIONS),
        ToolAdapter("tool-opengrep", "source_sast", frozenset({0}), "/scratch/output.json", _sei_cert_source,
                    _args("scan", "--disable-version-check", "--config", SEI_CERT_MOUNT, "--json",
                          "--output", "/scratch/output.json"), _semgrep_parser,
                    ("runs the SEI CERT rule pack only; the Semgrep security baseline is Semgrep-specific",
                     *SEI_CERT_LIMITATIONS)),
        ToolAdapter("tool-gosec", "source_sast", frozenset({0, 1}), "/scratch/output.json", lang("tool-gosec", "Go"),
                    _gosec_args, _gosec_parser,
                    ("dependency/build context may be incomplete in offline mode",)),
        ToolAdapter("tool-mobsfscan", "source_sast", frozenset({0, 1}), "/scratch/output.json",
                    lang("tool-mobsfscan", "Java, Kotlin, or Swift"), _args("--json", "-o", "/scratch/output.json"), _mobsfscan_parser),
        ToolAdapter("tool-cppcheck", "source_sast", frozenset({0}), "/scratch/output.xml", _cppcheck,
                    _cppcheck_args, _cppcheck_parser,
                    ("source mode is not compiler-backed analysis; compile metadata is sanitized and never executed",)),
        ToolAdapter("tool-pmd", "source_sast", frozenset({0, 4}), "/scratch/output.json", _pmd,
                    _pmd_args, _pmd_parser,
                    ("security-focused ruleset only; general PMD code-quality rules are excluded",)),
        ToolAdapter("tool-shellcheck", "source_sast", frozenset({0, 1}), None, lang("tool-shellcheck", "shell script"),
                    _args("--format", "json1"), _shellcheck_parser),
        ToolAdapter("tool-phpcs", "source_sast", frozenset({0, 1, 2, 3}), None, lang("tool-phpcs", "PHP"),
                    _args("--report=json", "--standard=PSR12"), _phpcs_parser,
                    ("project-specific coding standard is not inferred",)),
        ToolAdapter("tool-phpstan", "source_sast", frozenset({0, 1}), None, lang("tool-phpstan", "PHP"),
                    _args("analyse", "--no-progress", "--error-format=json", "--memory-limit=768M"), _phpstan_parser,
                    ("Composer dependencies are not installed by the scanner",)),
        ToolAdapter("tool-psalm", "source_sast", frozenset({0, 1, 2}), None, lang("tool-psalm", "PHP"),
                    _args("--output-format=json", "--no-progress", "--no-cache"), _list_parser,
                    ("project config and installed dependency stubs may be required",)),
        ToolAdapter("tool-spotbugs", "source_sast", frozenset({0}), "/scratch/output.xml", _spotbugs,
                    _args("-textui", "-xml:withMessages", "-output", "/scratch/output.xml"), _spotbugs_parser),
        ToolAdapter("tool-syft", "software_inventory", frozenset({0}), "/scratch/output.json", _syft,
                    lambda exe, sel: (exe, "dir:/target", "--output", "json=/scratch/output.json"), _syft_parser,
                    ("directory coverage is distinct from built artifact or OCI/archive coverage",)),
        ToolAdapter("tool-osv-scanner", "vulnerability_matching", frozenset({0, 1}), "/scratch/output.json", manifests,
                    lambda exe, sel: (exe, "scan", "--experimental-offline", "--format", "json", "--output",
                                      "/scratch/output.json", *sum((("--lockfile", _target(path)) for path in sel.files), ())), _osv_parser),
        ToolAdapter("tool-grype", "vulnerability_matching", frozenset({0}), "/scratch/output.json", _syft,
                    lambda exe, sel: (exe, "sbom:/inputs/syft.json", "--output", "json", "--file", "/scratch/output.json",
                                      "--only-fixed=false"), _grype_parser),
        ToolAdapter("tool-hadolint", "configuration", frozenset({0, 1}), None, dockerfiles,
                    _args("--format", "json"), _list_parser),
        ToolAdapter("tool-checkov", "configuration", frozenset({0, 1}), None, _checkov,
                    _checkov_args, _checkov_parser),
        ToolAdapter("tool-trivy", "configuration", frozenset({0}), "/scratch/output.json",
                    lambda catalog: Applicability(
                        bool((files := tuple(sorted(set(dockerfiles(catalog).files + iac(catalog).files))))),
                        f"catalog contains {len(files)} configuration input(s)" if files else "target catalog contains no Dockerfile or IaC inputs",
                        files, "configuration_files"),
                    lambda exe, sel: (exe, "config", "--skip-version-check", "--skip-check-update",
                                      "--format", "json", "--output", "/scratch/output.json",
                                      "--exit-code", "0", "/scratch/inputs"), _trivy_parser,
                    (TRIVY_EMBEDDED_CHECKS,), stderr_gaps=_trivy_stderr_gaps),
        ToolAdapter("tool-zizmor", "configuration", frozenset({0, 1}), None, workflows,
                    _args("--offline", "--no-exit-codes", "--format", "json"), _list_parser),
        ToolAdapter("tool-blint", "binary_hardening", frozenset({0}), BLINT_REPORT, _blint,
                    _blint_args, _blint_parser, collector=_collect_blint),
    ]
    return {adapter.tool_id: adapter for adapter in adapters}


ADAPTERS: Mapping[str, ToolAdapter] = MappingProxyType(_registry())


def adapter_registry() -> Mapping[str, ToolAdapter]:
    return ADAPTERS
