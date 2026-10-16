"""Central, typed declarations of the inputs each external analysis tool can process.

Every job that launches a tool per file, per artifact, or per compile unit partitions its candidate
inputs through this table *before* launch. An input outside a tool's declared support is
``SKIPPED_NA`` with ``INPUT_FORMAT_UNSUPPORTED`` and a reason: it is never launched, never a GAP,
and never a tool failure. A supported input on which the tool fails, times out, truncates, or is
unavailable remains a GAP exactly as before.

``recognized_unsupported`` is the narrow fallback for tools whose support cannot be decided exactly
from bounded facts before launch (for example a ShellCheck dialect declared only by a shebang the
job could not read, or an empty lockfile osv-scanner finds no packages in). Only the specific,
documented "unsupported input" report of that tool qualifies; every other error stays a GAP.

Declarations are data, not policy: operators tune *whether* a tool runs in ``appsec-review.toml``;
*which inputs a tool can parse* is a property of the pinned tool adapter and lives here once.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
import re
from types import MappingProxyType
from typing import Any

from appsec_review.applicability import ProcessingDisposition, ReasonCode


SCHEMA = "appsec-review/tool-input-support/1"
MAX_RECORDED_ITEMS = 200

C_CPP_SOURCE = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"})
SOURCE_SUFFIXES = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rs", *C_CPP_SOURCE,
    ".cs", ".rb", ".php", ".swift", ".sh",
})
SEI_CERT_SOURCE = C_CPP_SOURCE | {".java"}
IAC_SUFFIXES = frozenset({".tf", ".tfvars", ".hcl"})
JVM_BYTECODE = frozenset({".jar", ".war", ".ear", ".class"})
NATIVE_BINARIES = frozenset({".dll", ".exe", ".so", ".dylib", ".a", ".o"})
# Compile-database translation units a Clang frontend (clang-tidy, the Clang Static Analyzer,
# clangd) can process. Assembly, CUDA, resource, Fortran, and other compile-database entries are
# outside every Clang-family tool's scope.
CLANG_COMPILE_UNITS = frozenset({".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm", ".i", ".ii"})
# Shells ShellCheck 0.11 parses; any other declared interpreter is reported as SC1071.
SHELLCHECK_DIALECTS = frozenset({"sh", "bash", "dash", "ksh", "busybox"})
# File names that look like Dockerfiles by prefix but carry other content (docs, templates, code).
_DOCKERFILE_EXCLUDED_SUFFIXES = frozenset({
    ".md", ".txt", ".rst", ".adoc", ".json", ".yml", ".yaml", ".toml", ".py", ".go", ".js", ".ts",
    ".sh", ".dockerignore", ".orig", ".bak", ".rej", ".swp", ".tmpl", ".template", ".j2",
    ".jinja", ".jinja2", ".erb", ".in", ".tpl", ".mustache",
})


def _is_dockerfile(path: PurePosixPath) -> bool:
    name = path.name
    if name in {"Dockerfile", "Containerfile"}:
        return True
    lowered = name.lower()
    candidate = (name.startswith(("Dockerfile.", "Containerfile.")) or
                 lowered.endswith(".dockerfile") or lowered.endswith(".containerfile"))
    return candidate and path.suffix.lower() not in _DOCKERFILE_EXCLUDED_SUFFIXES


# Lockfiles and manifests osv-scanner 1.9.2 extracts offline when handed the file itself (``-L``),
# each mapped to the OSV ecosystem whose offline database it needs. Verified against the pinned
# binary: it has no extractor for archives (.jar, .whl), compiled binaries (Go, Rust), package
# metadata (PKG-INFO, composer.json, package.json, Cargo.toml), or go.sum/uv.lock/bun.lock.
OSV_LOCKFILE_ECOSYSTEMS: Mapping[str, str] = MappingProxyType({
    "Cargo.lock": "crates.io",
    "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "go.mod": "Go",
    "pom.xml": "Maven", "gradle.lockfile": "Maven", "buildscript-gradle.lockfile": "Maven",
    "composer.lock": "Packagist",
    "packages.lock.json": "NuGet",
    "Gemfile.lock": "RubyGems",
    "requirements.txt": "PyPI", "poetry.lock": "PyPI", "Pipfile.lock": "PyPI", "pdm.lock": "PyPI",
    "pubspec.lock": "Pub", "mix.lock": "Hex", "renv.lock": "CRAN", "conan.lock": "ConanCenter",
})


def osv_ecosystem(path: str | PurePosixPath) -> str | None:
    """The OSV ecosystem an osv-scanner-extractable lockfile needs, or ``None`` when unsupported."""
    name = PurePosixPath(str(path)).name
    if name in OSV_LOCKFILE_ECOSYSTEMS:
        return OSV_LOCKFILE_ECOSYSTEMS[name]
    # osv-scanner's requirements extractor matches any ``*requirements*.txt`` (dev-requirements.txt).
    if name.endswith(".txt") and "requirements" in name:
        return "PyPI"
    return None


def _is_osv_lockfile(path: PurePosixPath) -> bool:
    return osv_ecosystem(path) is not None


def _is_github_workflow(path: PurePosixPath) -> bool:
    return path.parts[:2] == (".github", "workflows") and path.suffix.lower() in {".yml", ".yaml"}


def _is_github_action_definition(path: PurePosixPath) -> bool:
    return path.parts[:2] == (".github", "actions") and path.name.lower() in {"action.yml", "action.yaml"}


@dataclass(frozen=True, slots=True)
class InputSupport:
    """What one tool consumer accepts. Exactly one of the path, format, or ``any_input`` forms."""

    key: str
    description: str
    suffixes: frozenset[str] = frozenset()
    names: frozenset[str] = frozenset()
    predicate: Callable[[PurePosixPath], bool] | None = None
    formats: frozenset[str] = frozenset()
    any_input: bool = False
    interpreters: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        forms = (bool(self.suffixes or self.names or self.predicate), bool(self.formats), self.any_input)
        if sum(forms) != 1 or not self.key or not self.description:
            raise ValueError(f"tool input support declaration is ambiguous: {self.key}")
        if any(not value.startswith(".") or value != value.lower() for value in self.suffixes):
            raise ValueError(f"tool input suffixes must be lowercase dotted suffixes: {self.key}")

    def supports_path(self, path: str) -> bool:
        if self.any_input:
            return True
        pure = PurePosixPath(path)
        return (pure.suffix.lower() in self.suffixes or pure.name in self.names or
                (self.predicate is not None and self.predicate(pure)))

    def supports_format(self, value: str | None) -> bool:
        return self.any_input or (value is not None and value in self.formats)


@dataclass(frozen=True, slots=True)
class InputDecision:
    """One input a tool was not launched on (or reported as unsupported), with its reason."""

    path: str
    tool: str
    reason_code: ReasonCode
    reason: str
    disposition: ProcessingDisposition = ProcessingDisposition.SKIPPED_NA

    def __post_init__(self) -> None:
        if self.disposition is not ProcessingDisposition.SKIPPED_NA:
            raise ValueError("an unsupported tool input is always SKIPPED_NA")
        if self.reason_code not in {ReasonCode.INPUT_FORMAT_UNSUPPORTED,
                                    ReasonCode.TOOL_REPORTED_UNSUPPORTED_INPUT}:
            raise ValueError("an unsupported tool input requires an input-support reason code")

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.path, "tool": self.tool, "disposition": self.disposition.value,
                "reason_code": self.reason_code.value, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class InputPartition:
    supported: tuple[str, ...]
    not_applicable: tuple[InputDecision, ...] = field(default_factory=tuple)


def not_applicable_summary(decisions: Iterable[InputDecision | Mapping[str, Any]]) -> dict[str, Any]:
    """Bounded, separately counted record of SKIPPED_NA inputs (never merged into gaps)."""
    values = [item.as_dict() if isinstance(item, InputDecision) else dict(item) for item in decisions]
    values.sort(key=lambda item: (str(item["tool"]), str(item["path"])))
    reasons = Counter(str(item["reason"]) for item in values)
    return {"schema": SCHEMA, "disposition": ProcessingDisposition.SKIPPED_NA.value,
            "count": len(values), "by_reason": dict(sorted(reasons.items())),
            "items": values[:MAX_RECORDED_ITEMS], "truncated": len(values) > MAX_RECORDED_ITEMS}


def _shebang_interpreter(head: bytes) -> str | None:
    if not head.startswith(b"#!"):
        return None
    line = head.split(b"\n", 1)[0][2:].decode("utf-8", "replace").strip()
    words = line.split()
    if not words:
        return None
    program = PurePosixPath(words[0]).name
    if program == "env":
        rest = [word for word in words[1:] if not word.startswith("-") and "=" not in word]
        program = PurePosixPath(rest[0]).name if rest else ""
    return program or None


_REGISTRY: dict[str, InputSupport] = {}


def _declare(*values: InputSupport) -> None:
    for value in values:
        if value.key in _REGISTRY:
            raise ValueError(f"duplicate tool input support declaration: {value.key}")
        _REGISTRY[value.key] = value


_declare(
    # Source/configuration scanners of job_evidence_collection (planned by job_target_analysis_plan).
    InputSupport("tool-gitleaks", "any cataloged file", any_input=True),
    InputSupport("tool-syft", "the cataloged directory", any_input=True),
    InputSupport("tool-grype", "the Syft SBOM of the cataloged directory", any_input=True),
    InputSupport("tool-semgrep", "source files of the Semgrep-parsed languages", suffixes=SOURCE_SUFFIXES),
    InputSupport("tool-opengrep", "C, C++, and Java source (SEI CERT rule pack)", suffixes=SEI_CERT_SOURCE),
    InputSupport("tool-gosec", "Go source", suffixes=frozenset({".go"})),
    InputSupport("tool-mobsfscan", "Java, Kotlin, and Swift source",
                 suffixes=frozenset({".java", ".kt", ".swift"})),
    InputSupport("tool-cppcheck", "C and C++ source and headers", suffixes=C_CPP_SOURCE),
    InputSupport("tool-pmd", "Java source", suffixes=frozenset({".java"})),
    InputSupport("tool-shellcheck", "sh, bash, dash, and ksh scripts", suffixes=frozenset({".sh"}),
                 interpreters=SHELLCHECK_DIALECTS),
    InputSupport("tool-phpcs", "PHP source", suffixes=frozenset({".php"})),
    InputSupport("tool-phpstan", "PHP source", suffixes=frozenset({".php"})),
    InputSupport("tool-psalm", "PHP source", suffixes=frozenset({".php"})),
    InputSupport("tool-spotbugs", "accepted JVM bytecode artifacts", suffixes=JVM_BYTECODE),
    InputSupport("tool-blint", "accepted native binary artifacts", suffixes=NATIVE_BINARIES),
    InputSupport("tool-osv-scanner", "lockfiles and manifests osv-scanner extracts offline",
                 predicate=_is_osv_lockfile),
    InputSupport("tool-hadolint", "Dockerfiles and Containerfiles", predicate=_is_dockerfile),
    # Checkov is the arbiter of what it recognizes: every cataloged file is offered, and inputs it
    # reports nothing for are recorded as not applicable (job_evidence_collection).
    InputSupport("tool-checkov", "any cataloged file", any_input=True),
    InputSupport("tool-trivy", "Terraform/HCL files and Dockerfiles",
                 predicate=lambda path: path.suffix.lower() in IAC_SUFFIXES or _is_dockerfile(path)),
    InputSupport("tool-zizmor", "GitHub Actions workflow files", predicate=_is_github_workflow),
    # CI definition linters of job_ci_configuration_analysis.
    InputSupport("ci:tool-actionlint", "GitHub Actions workflow files (not action metadata)",
                 predicate=_is_github_workflow),
    InputSupport("ci:tool-zizmor", "GitHub Actions workflows and action definitions",
                 predicate=lambda path: _is_github_workflow(path) or _is_github_action_definition(path)),
    InputSupport("ci:tool-checkov:github_actions", "GitHub Actions workflow files",
                 predicate=_is_github_workflow),
    InputSupport("ci:tool-checkov:azure_pipelines", "Azure Pipelines definitions",
                 predicate=lambda path: path.suffix.lower() in {".yml", ".yaml"}),
    InputSupport("ci:tool-checkov:gitlab_ci", "GitLab CI definitions",
                 predicate=lambda path: path.suffix.lower() in {".yml", ".yaml"}),
    InputSupport("ci:tool-checkov:circleci_pipelines", "CircleCI configuration",
                 predicate=lambda path: path.suffix.lower() in {".yml", ".yaml"}),
    InputSupport("ci:tool-checkov:bitbucket_pipelines", "Bitbucket Pipelines definitions",
                 predicate=lambda path: path.suffix.lower() in {".yml", ".yaml"}),
    # Produced-artifact scanners of job_artifact_security_analysis, by bounded-magic format.
    InputSupport("artifact:tool-blint", "ELF, PE/.NET, COFF, Mach-O binaries and Android packages",
                 formats=frozenset({"elf", "pe", "dotnet-assembly", "coff", "macho", "android-package"})),
    InputSupport("artifact:tool-spotbugs", "JVM classes and archives",
                 formats=frozenset({"jvm-class", "jvm-archive"})),
    InputSupport("artifact:tool-syft", "any produced artifact file", any_input=True),
    InputSupport("artifact:tool-grype", "any produced artifact file", any_input=True),
    # osv-scanner selects an extractor by file name only; it has no extractor for produced binaries,
    # archives, objects, or package metadata, so those are never launched.
    InputSupport("artifact:tool-osv-scanner", "lockfiles and manifests osv-scanner extracts offline",
                 predicate=_is_osv_lockfile),
    # Clang-family tools over accepted compile databases (clang-tidy, Clang Static Analyzer,
    # clangd-indexer, and the compile database handed to Joern).
    InputSupport("clang:compile-unit", "C, C++, Objective-C, and preprocessed translation units",
                 suffixes=CLANG_COMPILE_UNITS),
)

TOOL_INPUT_SUPPORT: Mapping[str, InputSupport] = MappingProxyType(_REGISTRY)


def support(key: str) -> InputSupport:
    try:
        return TOOL_INPUT_SUPPORT[key]
    except KeyError as exc:
        raise ValueError(f"tool has no declared input support: {key}") from exc


def supports_path(key: str, path: str) -> bool:
    return support(key).supports_path(path)


def partition_paths(key: str, paths: Iterable[str], *,
                    read_head: Callable[[str], bytes | None] | None = None) -> InputPartition:
    """Split candidate paths into launchable inputs and SKIPPED_NA decisions, before launch.

    ``read_head`` returns a bounded prefix of a cataloged file (or ``None`` when unavailable). It is
    consulted only for tools that declare interpreters; an unreadable prefix keeps the input
    launchable so the tool, not this filter, decides (and a real failure stays a GAP).
    """
    declared = support(key)
    supported: list[str] = []
    skipped: list[InputDecision] = []
    for path in paths:
        if not declared.supports_path(path):
            skipped.append(InputDecision(path, key, ReasonCode.INPUT_FORMAT_UNSUPPORTED,
                                         f"{key} supports only {declared.description}"))
            continue
        if declared.interpreters and read_head is not None:
            head = read_head(path)
            interpreter = _shebang_interpreter(head) if head is not None else None
            if interpreter is not None and interpreter not in declared.interpreters:
                skipped.append(InputDecision(
                    path, key, ReasonCode.INPUT_FORMAT_UNSUPPORTED,
                    f"{key} supports only {declared.description}; shebang declares {interpreter}"))
                continue
        supported.append(path)
    return InputPartition(tuple(supported), tuple(skipped))


def partition_artifacts(key: str, items: Iterable[tuple[str, str, str | None]]) -> InputPartition:
    """Split ``(identity, file_path, classified_format)`` produced artifacts by declared support.

    Format-declared tools decide by bounded-magic format; path-declared tools (osv-scanner) decide
    by the artifact's file name. Decisions are recorded against the artifact identity.
    """
    declared = support(key)
    if declared.formats or declared.any_input:
        return partition_formats(key, ((identity, value) for identity, _path, value in items))
    supported: list[str] = []
    skipped: list[InputDecision] = []
    for identity, path, value in items:
        if declared.supports_path(path):
            supported.append(identity)
        else:
            skipped.append(InputDecision(
                identity, key, ReasonCode.INPUT_FORMAT_UNSUPPORTED,
                f"{key} supports only {declared.description}; artifact "
                f"{PurePosixPath(path).name or 'unknown'} is {value or 'unknown'}"))
    return InputPartition(tuple(supported), tuple(skipped))


def partition_formats(key: str, items: Iterable[tuple[str, str | None]]) -> InputPartition:
    """Split ``(identity, classified_format)`` pairs by a tool's declared artifact formats."""
    declared = support(key)
    supported: list[str] = []
    skipped: list[InputDecision] = []
    for identity, value in items:
        if declared.supports_format(value):
            supported.append(identity)
        else:
            skipped.append(InputDecision(
                identity, key, ReasonCode.INPUT_FORMAT_UNSUPPORTED,
                f"{key} supports only {declared.description}; artifact format is {value or 'unknown'}"))
    return InputPartition(tuple(supported), tuple(skipped))


# Recognized, documented "unsupported input" reports. Each entry names the exact tool output that
# qualifies; any other error, exit code, or message remains a GAP.
_SHELLCHECK_UNSUPPORTED_CODES = frozenset({1071})
_OSV_NO_SOURCES = re.compile(r"No package sources found")
_OSV_NO_SOURCES_EXIT = 128
# Semgrep/OpenGrep skip reasons that mean "no rule or language applies to this target", as opposed
# to size, parser, permission, or timeout failures, which stay coverage gaps.
SEMGREP_NOT_APPLICABLE_SKIPS = frozenset({
    "wrong_language", "irrelevant_rule", "excluded_by_config", "cli_include_flags_do_not_match",
    "cli_exclude_flags_match", "semgrepignore_patterns_match", "gitignore_patterns_match",
    "dotfile", "always_skipped",
})


def shellcheck_unsupported_dialect(record: Mapping[str, Any]) -> bool:
    """ShellCheck SC1071: 'ShellCheck only supports sh/bash/dash/ksh scripts'."""
    try:
        return int(record.get("code", record.get("rule_id", -1))) in _SHELLCHECK_UNSUPPORTED_CODES
    except (TypeError, ValueError):
        return False


def osv_reported_no_package_sources(exit_code: int | None, output: bytes) -> bool:
    """osv-scanner's exit-128 'No package sources found' report for an input it has no extractor for."""
    return exit_code == _OSV_NO_SOURCES_EXIT and bool(
        _OSV_NO_SOURCES.search(output[-65_536:].decode("utf-8", "replace")))


_OSV_MISSING_DATABASES = re.compile(r"could not find local databases? for ecosystems?:\s*([^\n]+)")
_DIAGNOSTIC_LINE_LIMIT = 300


def osv_missing_ecosystems(output: bytes) -> tuple[str, ...]:
    """Ecosystems osv-scanner reported it has no offline database for (exit 127 in 1.9.2)."""
    text = output[-65_536:].decode("utf-8", "replace")
    names: list[str] = []
    for match in _OSV_MISSING_DATABASES.finditer(text):
        names.extend(item.strip() for item in match.group(1).split(",") if item.strip())
    return tuple(dict.fromkeys(names))


def osv_missing_ecosystem_gap(ecosystems: Iterable[str], subject: str) -> str:
    """The named data-coverage gap for inputs whose OSV ecosystem is absent from the snapshot."""
    names = ", ".join(sorted(set(ecosystems), key=str.lower))
    return (f"offline OSV snapshot lacks ecosystem {names}; vulnerability matching for {subject} "
            "was not performed (configure jobs.job_third_party_data_sync.steps.osv_sync.settings."
            "ecosystems and re-sync)")


def bounded_diagnostic(output: bytes) -> str:
    """The last meaningful diagnostic line of a tool's stderr, bounded for gap text."""
    lines = [" ".join(line.split()) for line in output[-16_384:].decode("utf-8", "replace").splitlines()]
    lines = [line for line in lines if line]
    return lines[-1][:_DIAGNOSTIC_LINE_LIMIT] if lines else ""


def semgrep_skip_not_applicable(reason: object) -> bool:
    return str(reason or "").strip().lower() in SEMGREP_NOT_APPLICABLE_SKIPS
