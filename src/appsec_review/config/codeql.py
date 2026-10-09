from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from types import MappingProxyType
from typing import Any


_SHA = re.compile(r"^[0-9a-f]{64}$")
_IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MODES = {"cpp": "manual", "go": "manual", "java": "manual", "csharp": "manual",
          "javascript": "none", "python": "none", "rust": "none", "actions": "none"}


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


@dataclass(frozen=True, slots=True)
class CodeQLLanguageSettings:
    enabled: bool
    mode: str
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

    def __post_init__(self) -> None:
        if not self.enabled or self.mode not in {"manual", "none"}:
            raise ValueError("CodeQL language enablement or mode is invalid")
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


@dataclass(frozen=True, slots=True)
class CodeQLAnalysisSettings:
    enabled: bool
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

    def __post_init__(self) -> None:
        if not self.enabled or not self.source_image_tag or any(char.isspace() for char in self.source_image_tag):
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
        if set(self.languages) != set(_MODES):
            raise ValueError("CodeQL configured language set is incomplete")
        for language, mode in _MODES.items():
            if self.languages[language].mode != mode:
                raise ValueError(f"CodeQL {language} mode is invalid")
        if set(self.languages["java"].source_languages) != {"Java", "Kotlin"}:
            raise ValueError("CodeQL Java configuration must preserve Kotlin coverage")
        if self.languages["csharp"].source_languages != ("C#",):
            raise ValueError("CodeQL C# configuration must not claim VB or F# coverage")
        if "bundled-typescript" not in self.languages["javascript"].prerequisites:
            raise ValueError("CodeQL TypeScript prerequisite is missing")
        if not {"Cargo.toml", "Cargo.lock", "bundled-rust-indexer"}.issubset(
                self.languages["rust"].prerequisites):
            raise ValueError("CodeQL Rust analyzer/Cargo prerequisites are incomplete")


def parse_codeql_settings(value: Mapping[str, Any]) -> CodeQLAnalysisSettings:
    languages_value = value.get("languages")
    if not isinstance(languages_value, Mapping):
        raise ValueError("jobs.job_codeql_analysis.settings.languages must be a table")
    languages: dict[str, CodeQLLanguageSettings] = {}
    for language, raw in languages_value.items():
        if not isinstance(raw, Mapping):
            raise ValueError(f"CodeQL language configuration must be a table: {language}")
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
        additional_queries = tuple(CodeQLPackQuerySettings(
            query_id=str(item.get("query_id", "")), query_suite=str(item.get("query_suite", "")),
            query_suite_sha256=str(item.get("query_suite_sha256", "")),
        ) for item in additional_value)
        languages[str(language)] = CodeQLLanguageSettings(
            enabled=raw.get("enabled") is True, mode=str(raw.get("mode", "")),
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
        )
    return CodeQLAnalysisSettings(
        enabled=value.get("enabled") is True,
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
    )
