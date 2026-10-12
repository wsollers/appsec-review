from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
import re
from types import MappingProxyType
from typing import Any


_SHA = re.compile(r"^[0-9a-f]{64}$")
_IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
_LANGUAGES = {"cpp", "go", "java", "csharp", "javascript", "python", "rust", "actions"}
_LEGACY_MODES = {"manual": "build", "none": "source"}


class CodeQLExecutionMode(str, Enum):
    BUILD = "build"
    SOURCE = "source"
    AUTO = "auto"
    DISABLED = "disabled"


def _execution_mode(value: object, field: str, *, legacy: bool = False) -> CodeQLExecutionMode:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be one of: build, source, auto, disabled")
    normalized = _LEGACY_MODES.get(value, value) if legacy else value
    try:
        return CodeQLExecutionMode(normalized)
    except ValueError as exc:
        raise ValueError(f"{field} must be one of: build, source, auto, disabled") from exc


def _strict_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a Boolean")
    return value


@dataclass(frozen=True, slots=True)
class CodeQLPackQuerySettings:
    query_id: str
    query_suite: str
    query_suite_sha256: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", self.query_id):
            raise ValueError("CodeQL pack query id is invalid")
        suite = PurePosixPath(self.query_suite)
        if suite.is_absolute() or ".." in suite.parts or suite.suffix != ".qls":
            raise ValueError("CodeQL pack query suite is invalid")
        if not _SHA.fullmatch(self.query_suite_sha256):
            raise ValueError("CodeQL pack query suite identity is invalid")


@dataclass(frozen=True, slots=True)
class CodeQLCustomQuerySettings:
    query_id: str
    root: str
    query_pack: str
    query_pack_version: str
    query_suite: str
    query_suite_sha256: str
    query_pack_sha256: str
    query_lock_sha256: str
    tree_sha256: str
    file_count: int

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", self.query_id):
            raise ValueError("CodeQL custom query id is invalid")
        root = PurePosixPath(self.root)
        if (not root.is_absolute() or root.parts[:4] != ("/", "opt", "codeql", "custom-queries") or
                ".." in root.parts):
            raise ValueError("CodeQL custom query root is invalid")
        if not re.fullmatch(r"codeql/[a-z0-9-]+", self.query_pack):
            raise ValueError("CodeQL custom query pack name is invalid")
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", self.query_pack_version):
            raise ValueError("CodeQL custom query pack version is invalid")
        suite = PurePosixPath(self.query_suite)
        if suite.is_absolute() or ".." in suite.parts or suite.suffix != ".qls":
            raise ValueError("CodeQL custom query suite is invalid")
        for name, value in (("suite", self.query_suite_sha256),
                            ("pack", self.query_pack_sha256),
                            ("lock", self.query_lock_sha256), ("tree", self.tree_sha256)):
            if not _SHA.fullmatch(value):
                raise ValueError(f"CodeQL custom query {name} identity is invalid")
        if self.file_count < 1:
            raise ValueError("CodeQL custom query pack must contain files")


_EXPORT_RULES_ROOT = ("rules", "codeql-graph-export")
# C/C++ is the only language with a graph export pack in this change (code-graph plan D5).
_EXPORT_LANGUAGES = frozenset({"cpp"})


def _positive_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


@dataclass(frozen=True, slots=True)
class CodeQLExportQuerySettings:
    """One repository-owned, hash-pinned graph export pack; equals ``export_query_packs.<lang>``."""

    query_id: str
    source_path: str
    query_pack: str
    query_pack_version: str
    query_suite: str
    query_suite_sha256: str
    query_pack_sha256: str
    tree_sha256: str
    file_count: int
    columns_path: str
    columns_sha256: str
    catalog_path: str
    catalog_sha256: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", self.query_id):
            raise ValueError("CodeQL export query id is invalid")
        for name, value in (("source", self.source_path), ("columns", self.columns_path),
                            ("catalog", self.catalog_path)):
            path = PurePosixPath(value)
            if (path.is_absolute() or ".." in path.parts or
                    path.parts[:2] != _EXPORT_RULES_ROOT or len(path.parts) < 3):
                raise ValueError(f"CodeQL export {name} path must be under rules/codeql-graph-export/")
        if not re.fullmatch(r"appsec-review/[a-z0-9-]+", self.query_pack):
            raise ValueError("CodeQL export query pack name is invalid")
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", self.query_pack_version):
            raise ValueError("CodeQL export query pack version is invalid")
        suite = PurePosixPath(self.query_suite)
        if suite.is_absolute() or ".." in suite.parts or suite.suffix != ".qls":
            raise ValueError("CodeQL export query suite is invalid")
        for name, value in (("suite", self.query_suite_sha256), ("pack", self.query_pack_sha256),
                            ("tree", self.tree_sha256), ("columns", self.columns_sha256),
                            ("catalog", self.catalog_sha256)):
            if not _SHA.fullmatch(value):
                raise ValueError(f"CodeQL export {name} identity is invalid")
        if isinstance(self.file_count, bool) or not isinstance(self.file_count, int) or self.file_count < 1:
            raise ValueError("CodeQL export query pack must contain files")


def _default_export_bounds() -> tuple[int, int, int]:
    from appsec_review.graph.contract import GraphSettings

    defaults = GraphSettings()
    return (defaults.max_facts_per_family_per_scope, defaults.max_export_bytes,
            defaults.export_timeout_seconds)


@dataclass(frozen=True, slots=True)
class CodeQLExportSettings:
    """Bounds of the ``export`` step (``jobs.job_codeql_analysis.settings.export_queries``)."""

    enabled: bool = True
    row_limit: int = field(default_factory=lambda: _default_export_bounds()[0])
    max_bytes: int = field(default_factory=lambda: _default_export_bounds()[1])
    timeout_seconds: int = field(default_factory=lambda: _default_export_bounds()[2])

    def __post_init__(self) -> None:
        _strict_bool(self.enabled, "CodeQL export_queries.enabled")
        for name in ("row_limit", "max_bytes", "timeout_seconds"):
            _positive_int(getattr(self, name), f"CodeQL export_queries.{name}")


@dataclass(frozen=True, slots=True)
class CodeQLLanguageSettings:
    enabled: bool
    mode: CodeQLExecutionMode
    platform: str
    extractor_tree_sha256: str
    extractor_file_count: int
    query_pack: str
    query_pack_version: str
    query_suite: str
    query_suite_sha256: str
    query_pack_sha256: str
    query_lock_sha256: str
    source_languages: tuple[str, ...]
    prerequisites: tuple[str, ...]
    additional_queries: tuple[CodeQLPackQuerySettings, ...]
    custom_queries: tuple[CodeQLCustomQuerySettings, ...]
    export_queries: tuple[CodeQLExportQuerySettings, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.mode, CodeQLExecutionMode):
            raise ValueError("CodeQL language mode is invalid")
        if self.enabled == (self.mode is CodeQLExecutionMode.DISABLED):
            raise ValueError("CodeQL language enabled and mode settings conflict")
        if self.platform != "linux-x86_64" or self.extractor_file_count < 1:
            raise ValueError("CodeQL language platform or extractor count is invalid")
        for name, value in (("extractor", self.extractor_tree_sha256),
                            ("suite", self.query_suite_sha256),
                            ("pack", self.query_pack_sha256), ("lock", self.query_lock_sha256)):
            if not _SHA.fullmatch(value):
                raise ValueError(f"CodeQL language {name} identity is invalid")
        if not re.fullmatch(r"codeql/[a-z0-9-]+", self.query_pack):
            raise ValueError("CodeQL query pack name is invalid")
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", self.query_pack_version):
            raise ValueError("CodeQL query pack version is invalid")
        suite = PurePosixPath(self.query_suite)
        if suite.is_absolute() or ".." in suite.parts or suite.suffix != ".qls":
            raise ValueError("CodeQL query suite is invalid")
        if not self.source_languages or any(not value for value in self.source_languages):
            raise ValueError("CodeQL source language coverage is required")
        query_ids = [item.query_id for item in (*self.additional_queries, *self.custom_queries)]
        if len(query_ids) != len(set(query_ids)) or "default" in query_ids:
            raise ValueError("CodeQL custom query ids must be unique and cannot be default")
        if len(self.export_queries) > 1:
            raise ValueError("CodeQL configures at most one graph export pack per language")

    @property
    def runtime_mode(self) -> str | None:
        """Return the existing executor vocabulary when the control is immediately executable."""
        return {CodeQLExecutionMode.BUILD: "manual",
                CodeQLExecutionMode.SOURCE: "none"}.get(self.mode)


@dataclass(frozen=True, slots=True)
class CodeQLAnalysisSettings:
    enabled: bool
    execution_mode: CodeQLExecutionMode
    source_image_tag: str
    source_image_id: str
    version: str
    commit: str
    cli_sha256: str
    license_sha256: str
    asset_lock_sha256: str
    runtime_user: str
    retention: str
    concurrency: int
    inventory_timeout_seconds: int
    database_timeout_seconds: int
    query_timeout_seconds: int
    output_bytes: int
    database_file_limit: int
    database_bytes_limit: int
    sarif_bytes_limit: int
    result_limit: int
    threads: int
    ram_mb: int
    max_paths: int
    languages: Mapping[str, CodeQLLanguageSettings]
    export_queries: CodeQLExportSettings = field(default_factory=CodeQLExportSettings)

    @property
    def export_timeout_seconds(self) -> int:
        """Timeout of the runner ``export`` action (read by ``codeql.runtime.action_timeout``)."""
        return self.export_queries.timeout_seconds

    def __post_init__(self) -> None:
        if self.enabled == (self.execution_mode is CodeQLExecutionMode.DISABLED):
            raise ValueError("CodeQL enabled and execution_mode settings conflict")
        if not self.source_image_tag or any(char.isspace() for char in self.source_image_tag):
            raise ValueError("CodeQL runtime enablement or source image tag is invalid")
        if not _IMAGE.fullmatch(self.source_image_id) or not re.fullmatch(r"[0-9a-f]{40}", self.commit):
            raise ValueError("CodeQL source image or commit identity is invalid")
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", self.version):
            raise ValueError("CodeQL version is invalid")
        for name, value in (("cli", self.cli_sha256), ("license", self.license_sha256),
                            ("asset lock", self.asset_lock_sha256)):
            if not _SHA.fullmatch(value):
                raise ValueError(f"CodeQL {name} identity is invalid")
        if not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", self.runtime_user):
            raise ValueError("CodeQL runtime user must be numeric and non-root")
        if self.retention != "run-owned":
            raise ValueError("CodeQL database retention must remain run-owned")
        limits = (self.concurrency, self.inventory_timeout_seconds, self.database_timeout_seconds,
                  self.query_timeout_seconds, self.output_bytes, self.database_file_limit,
                  self.database_bytes_limit, self.sarif_bytes_limit, self.result_limit,
                  self.threads, self.ram_mb, self.max_paths)
        if min(limits) < 1 or self.concurrency > 16 or self.threads > 32 or self.ram_mb < 2048:
            raise ValueError("CodeQL resource and output limits are invalid")
        if set(self.languages) != _LANGUAGES:
            raise ValueError("CodeQL configured language set is incomplete")
        if set(self.languages["java"].source_languages) != {"Java", "Kotlin"}:
            raise ValueError("CodeQL Java configuration must preserve Kotlin coverage")
        if self.languages["csharp"].source_languages != ("C#",):
            raise ValueError("CodeQL C# configuration must not claim VB or F# coverage")
        if "bundled-typescript" not in self.languages["javascript"].prerequisites:
            raise ValueError("CodeQL TypeScript prerequisite is missing")
        if not {"Cargo.toml", "Cargo.lock", "bundled-rust-indexer"}.issubset(
                self.languages["rust"].prerequisites):
            raise ValueError("CodeQL Rust analyzer/Cargo prerequisites are incomplete")
        if not isinstance(self.export_queries, CodeQLExportSettings):
            raise ValueError("CodeQL export_queries settings are invalid")
        exporting = {name for name, language in self.languages.items() if language.export_queries}
        if not exporting <= _EXPORT_LANGUAGES:
            raise ValueError("CodeQL graph export packs exist only for: " + ", ".join(sorted(_EXPORT_LANGUAGES)))


def parse_codeql_settings(value: Mapping[str, Any]) -> CodeQLAnalysisSettings:
    allowed = {
        "enabled", "execution_mode", "source_image_tag", "source_image_id", "version", "commit",
        "cli_sha256", "license_sha256", "asset_lock_sha256", "runtime_user", "retention",
        "concurrency", "inventory_timeout_seconds", "database_timeout_seconds",
        "query_timeout_seconds", "output_bytes", "database_file_limit", "database_bytes_limit",
        "sarif_bytes_limit", "result_limit", "threads", "ram_mb", "max_paths", "languages",
        "export_queries",
    }
    unknown = set(value) - allowed
    if unknown:
        raise ValueError("jobs.job_codeql_analysis.settings has unknown settings: " +
                         ", ".join(sorted(unknown)))
    enabled = _strict_bool(value.get("enabled"), "CodeQL enabled")
    execution_mode = _execution_mode(value.get("execution_mode", "auto"),
                                     "CodeQL execution_mode")
    languages_value = value.get("languages")
    if not isinstance(languages_value, Mapping):
        raise ValueError("jobs.job_codeql_analysis.settings.languages must be a table")
    languages: dict[str, CodeQLLanguageSettings] = {}
    for language, raw in languages_value.items():
        if language not in _LANGUAGES:
            raise ValueError(f"unknown CodeQL language override target: {language}")
        if not isinstance(raw, Mapping):
            raise ValueError(f"CodeQL language configuration must be a table: {language}")
        language_allowed = {
            "enabled", "mode", "platform", "extractor_tree_sha256", "extractor_file_count",
            "query_pack", "query_pack_version", "query_suite", "query_suite_sha256",
            "query_pack_sha256", "query_lock_sha256", "source_languages", "prerequisites",
            "additional_queries", "custom_queries", "export_queries",
        }
        language_unknown = set(raw) - language_allowed
        if language_unknown:
            raise ValueError(f"CodeQL language {language} has unknown settings: " +
                             ", ".join(sorted(language_unknown)))
        custom_value = raw.get("custom_queries", [])
        additional_value = raw.get("additional_queries", [])
        if not isinstance(additional_value, list) or any(not isinstance(item, Mapping)
                                                         for item in additional_value):
            raise ValueError(f"CodeQL additional queries must be an array of tables: {language}")
        if not isinstance(custom_value, list) or any(not isinstance(item, Mapping)
                                                     for item in custom_value):
            raise ValueError(f"CodeQL custom queries must be an array of tables: {language}")
        custom_queries = tuple(CodeQLCustomQuerySettings(
            query_id=str(item.get("query_id", "")), root=str(item.get("root", "")),
            query_pack=str(item.get("query_pack", "")),
            query_pack_version=str(item.get("query_pack_version", "")),
            query_suite=str(item.get("query_suite", "")),
            query_suite_sha256=str(item.get("query_suite_sha256", "")),
            query_pack_sha256=str(item.get("query_pack_sha256", "")),
            query_lock_sha256=str(item.get("query_lock_sha256", "")),
            tree_sha256=str(item.get("tree_sha256", "")),
            file_count=int(item.get("file_count", 0)),
        ) for item in custom_value)
        export_value = raw.get("export_queries", [])
        if not isinstance(export_value, list) or any(not isinstance(item, Mapping)
                                                     for item in export_value):
            raise ValueError(f"CodeQL export queries must be an array of tables: {language}")
        export_queries = tuple(_export_query(item, language) for item in export_value)
        additional_queries = tuple(CodeQLPackQuerySettings(
            query_id=str(item.get("query_id", "")), query_suite=str(item.get("query_suite", "")),
            query_suite_sha256=str(item.get("query_suite_sha256", "")),
        ) for item in additional_value)
        languages[str(language)] = CodeQLLanguageSettings(
            enabled=_strict_bool(raw.get("enabled"), f"CodeQL {language}.enabled"),
            mode=_execution_mode(raw.get("mode", execution_mode.value),
                                 f"CodeQL {language}.mode", legacy=True),
            platform=str(raw.get("platform", "")),
            extractor_tree_sha256=str(raw.get("extractor_tree_sha256", "")),
            extractor_file_count=int(raw.get("extractor_file_count", 0)),
            query_pack=str(raw.get("query_pack", "")),
            query_pack_version=str(raw.get("query_pack_version", "")),
            query_suite=str(raw.get("query_suite", "")),
            query_suite_sha256=str(raw.get("query_suite_sha256", "")),
            query_pack_sha256=str(raw.get("query_pack_sha256", "")),
            query_lock_sha256=str(raw.get("query_lock_sha256", "")),
            source_languages=tuple(str(item) for item in raw.get("source_languages", ())),
            prerequisites=tuple(str(item) for item in raw.get("prerequisites", ())),
            additional_queries=additional_queries,
            custom_queries=custom_queries,
            export_queries=export_queries,
        )
    return CodeQLAnalysisSettings(
        enabled=enabled,
        execution_mode=execution_mode,
        source_image_tag=str(value.get("source_image_tag", "")),
        source_image_id=str(value.get("source_image_id", "")), version=str(value.get("version", "")),
        commit=str(value.get("commit", "")), cli_sha256=str(value.get("cli_sha256", "")),
        license_sha256=str(value.get("license_sha256", "")),
        asset_lock_sha256=str(value.get("asset_lock_sha256", "")),
        runtime_user=str(value.get("runtime_user", "")), retention=str(value.get("retention", "")),
        concurrency=int(value.get("concurrency", 0)),
        inventory_timeout_seconds=int(value.get("inventory_timeout_seconds", 0)),
        database_timeout_seconds=int(value.get("database_timeout_seconds", 0)),
        query_timeout_seconds=int(value.get("query_timeout_seconds", 0)),
        output_bytes=int(value.get("output_bytes", 0)),
        database_file_limit=int(value.get("database_file_limit", 0)),
        database_bytes_limit=int(value.get("database_bytes_limit", 0)),
        sarif_bytes_limit=int(value.get("sarif_bytes_limit", 0)),
        result_limit=int(value.get("result_limit", 0)), threads=int(value.get("threads", 0)),
        ram_mb=int(value.get("ram_mb", 0)), max_paths=int(value.get("max_paths", 0)),
        languages=MappingProxyType(languages),
        export_queries=_export_settings(value.get("export_queries")),
    )


_EXPORT_QUERY_FIELDS = tuple(CodeQLExportQuerySettings.__dataclass_fields__)


def _export_query(item: Mapping[str, Any], language: str) -> CodeQLExportQuerySettings:
    unknown = set(item) - set(_EXPORT_QUERY_FIELDS)
    missing = set(_EXPORT_QUERY_FIELDS) - set(item)
    if unknown or missing:
        raise ValueError(f"CodeQL {language} export query fields differ from the contract: " +
                         ", ".join(sorted(unknown | missing)))
    values = {name: item[name] for name in _EXPORT_QUERY_FIELDS}
    for name, value in values.items():
        if name == "file_count":
            continue
        if not isinstance(value, str):
            raise ValueError(f"CodeQL {language} export query {name} must be a string")
    return CodeQLExportQuerySettings(**values)


def _export_settings(value: object) -> CodeQLExportSettings:
    if value is None:
        return CodeQLExportSettings()
    if not isinstance(value, Mapping):
        raise ValueError("jobs.job_codeql_analysis.settings.export_queries must be a table")
    unknown = set(value) - {"enabled", "row_limit", "max_bytes", "timeout_seconds"}
    if unknown:
        raise ValueError("jobs.job_codeql_analysis.settings.export_queries has unknown settings: " +
                         ", ".join(sorted(unknown)))
    return CodeQLExportSettings(**dict(value))
