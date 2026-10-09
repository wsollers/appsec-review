from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
import tomllib
from types import MappingProxyType
from typing import Any, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from urllib.parse import unquote, urlparse


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    repository_root: Path
    runs_dir: Path
    data_dir: Path
    metadata_dir: Path


@dataclass(frozen=True, slots=True)
class DagsterConfig:
    executor: str = "multiprocess"
    max_concurrent: int = 8
    pool_limits: Mapping[str, int] = MappingProxyType({})

    def __post_init__(self) -> None:
        if self.executor != "multiprocess":
            raise ValueError("Dagster executor must be multiprocess")
        if not 1 <= self.max_concurrent <= 64:
            raise ValueError("Dagster max_concurrent must be between 1 and 64")
        if any(not 1 <= value <= 64 for value in self.pool_limits.values()):
            raise ValueError("Dagster pool limits must be between 1 and 64")


@dataclass(frozen=True, slots=True)
class ScheduleConfig:
    enabled: bool
    cron: str
    timezone: str

    def __post_init__(self) -> None:
        if len(self.cron.split()) != 5:
            raise ValueError("schedule cron must have five fields")
        if self.timezone == "UTC":
            return
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"unknown schedule timezone: {self.timezone}") from exc


@dataclass(frozen=True, slots=True)
class TaskConfig:
    task_id: str
    workers: int
    settings: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", self.task_id):
            raise ValueError(f"invalid task id: {self.task_id}")
        if self.workers < 1:
            raise ValueError("task workers must be positive")


@dataclass(frozen=True, slots=True)
class StepConfig:
    step_id: str
    workers: int
    settings: Mapping[str, Any]
    tasks: Mapping[str, TaskConfig]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", self.step_id):
            raise ValueError(f"invalid step id: {self.step_id}")
        if self.workers < 1:
            raise ValueError("step workers must be positive")

    def task(self, task_id: str) -> TaskConfig:
        try:
            return self.tasks[task_id]
        except KeyError as exc:
            raise KeyError(f"task is not configured: {self.step_id}.{task_id}") from exc


@dataclass(frozen=True, slots=True)
class RustBuildSettings:
    toolchain: str
    target: str | None
    profile: str
    features: tuple[str, ...]
    locked: bool
    offline: bool
    capture_linker: bool
    diagnostic_tail_bytes: int

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", self.toolchain):
            raise ValueError("Rust toolchain selection is invalid")
        if self.target is not None and not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", self.target):
            raise ValueError("Rust target selection is invalid")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", self.profile):
            raise ValueError("Rust profile selection is invalid")
        if len(self.features) > 64 or len(self.features) != len(set(self.features)) or any(
            not re.fullmatch(r"[A-Za-z0-9_.+/-]{1,128}", value) for value in self.features
        ):
            raise ValueError("Rust feature selection is invalid")
        if not 0 <= self.diagnostic_tail_bytes <= 1024 * 1024:
            raise ValueError("Rust diagnostic tail bound is invalid")


@dataclass(frozen=True, slots=True)
class PhpBuildSettings:
    composer_plugins: str
    composer_scripts: str
    require_lockfile: bool
    diagnostic_tail_bytes: int

    def __post_init__(self) -> None:
        if self.composer_plugins not in {"disabled", "sandboxed"}:
            raise ValueError("Composer plugin policy is invalid")
        if self.composer_scripts not in {"disabled", "sandboxed"}:
            raise ValueError("Composer script policy is invalid")
        if not 0 <= self.diagnostic_tail_bytes <= 1024 * 1024:
            raise ValueError("PHP diagnostic tail bound is invalid")


@dataclass(frozen=True, slots=True)
class JvmBuildSettings:
    trace_bytes: int
    provenance_count_limit: int
    diagnostic_tail_bytes: int
    system_path: str
    tool_paths: Mapping[str, str]

    def __post_init__(self) -> None:
        if min(self.trace_bytes, self.provenance_count_limit, self.diagnostic_tail_bytes) < 1:
            raise ValueError("JVM capture limits must be positive")
        if not self.system_path.startswith("/"):
            raise ValueError("JVM system path must be absolute")
        expected = {"javac", "kotlinc", "kapt", "ksp", "java", "jar", "javadoc", "protoc"}
        if set(self.tool_paths) != expected or any(not value.startswith("/") for value in self.tool_paths.values()):
            raise ValueError("JVM tool path selection is invalid")


@dataclass(frozen=True, slots=True)
class GoBuildSettings:
    offline: bool
    capture_trace: bool
    package_catalog: bool
    diagnostic_tail_bytes: int

    def __post_init__(self) -> None:
        if not 0 <= self.diagnostic_tail_bytes <= 1024 * 1024:
            raise ValueError("Go diagnostic tail bound is invalid")


@dataclass(frozen=True, slots=True)
class PythonBuildSettings:
    frontend: str
    require_locked_dependencies: bool
    offline: bool
    capture_native_tools: bool
    diagnostic_tail_bytes: int

    def __post_init__(self) -> None:
        if self.frontend not in {"build", "pip", "setuptools"}:
            raise ValueError("Python package frontend selection is invalid")
        if not 0 <= self.diagnostic_tail_bytes <= 1024 * 1024:
            raise ValueError("Python diagnostic tail bound is invalid")


@dataclass(frozen=True, slots=True)
class NodeBuildSettings:
    package_managers: tuple[str, ...]
    require_lockfile: bool
    network: str
    lifecycle_scripts: str
    capture_source_maps: bool
    diagnostic_tail_bytes: int

    def __post_init__(self) -> None:
        if self.package_managers != ("npm", "pnpm", "yarn"):
            raise ValueError("Node package-manager selection is invalid")
        if not self.require_lockfile or self.network != "denied" or self.lifecycle_scripts != "sandboxed":
            raise ValueError("Node build isolation policy is invalid")
        if not self.capture_source_maps or not 0 <= self.diagnostic_tail_bytes <= 1024 * 1024:
            raise ValueError("Node capture settings are invalid")


@dataclass(frozen=True, slots=True)
class DotnetBuildSettings:
    require_locked_restore: bool
    capture_msbuild_diagnostics: bool
    generated_sources: bool
    allow_publish: bool
    allow_pack: bool
    allow_aot: bool

    def __post_init__(self) -> None:
        if not self.require_locked_restore or not self.capture_msbuild_diagnostics or not self.generated_sources:
            raise ValueError(".NET restore and capture policy is invalid")


@dataclass(frozen=True, slots=True)
class LanguageBuildSettings:
    command_timeout_seconds: int
    output_bytes: int
    artifact_count_limit: int
    dotnet: DotnetBuildSettings
    go: GoBuildSettings
    node: NodeBuildSettings
    python: PythonBuildSettings
    rust: RustBuildSettings
    php: PhpBuildSettings
    jvm: JvmBuildSettings
    wasm: WasmBuildSettings

    def __post_init__(self) -> None:
        if min(self.command_timeout_seconds, self.output_bytes, self.artifact_count_limit) < 1:
            raise ValueError("language-build limits must be positive")


@dataclass(frozen=True, slots=True)
class CppCompiledAnalysisSettings:
    lane: str

    def __post_init__(self) -> None:
        if self.lane != "cpp":
            raise ValueError("C++ compiled-analysis lane must be cpp")


@dataclass(frozen=True, slots=True)
class WasmProducerSettings:
    families: tuple[str, ...]
    tools: tuple[str, ...]
    indicators: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.families or any(value not in {"native", "rust", "node", "wasm"}
                                    for value in self.families):
            raise ValueError("WebAssembly producer families are invalid")
        if not self.tools or any(not re.fullmatch(r"[A-Za-z0-9_.+\-]+", value) for value in self.tools):
            raise ValueError("WebAssembly producer tools are invalid")
        if any(not value or len(value) > 256 for value in self.indicators):
            raise ValueError("WebAssembly producer indicators are invalid")


@dataclass(frozen=True, slots=True)
class WasmBuildSettings:
    command_timeout_seconds: int
    stream_limit_bytes: int
    artifact_count_limit: int
    workspace_file_limit: int
    producers: Mapping[str, WasmProducerSettings]

    def __post_init__(self) -> None:
        if min(self.command_timeout_seconds, self.stream_limit_bytes,
               self.artifact_count_limit, self.workspace_file_limit) < 1:
            raise ValueError("WebAssembly build limits must be positive")
        if not self.producers:
            raise ValueError("WebAssembly producers are required")


@dataclass(frozen=True, slots=True)
class JobConfig:
    job_id: str
    name: str
    workers: int
    schedule: ScheduleConfig | None
    settings: Mapping[str, Any]
    steps: Mapping[str, StepConfig]
    typed_settings: object | None = None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"job_[a-z][a-z0-9_]*", self.job_id):
            raise ValueError(f"invalid job id: {self.job_id}")
        if not self.name.strip():
            raise ValueError("job name is required")
        if self.workers < 1:
            raise ValueError("workers must be positive")

    def step(self, step_id: str) -> StepConfig:
        try:
            return self.steps[step_id]
        except KeyError as exc:
            raise KeyError(f"step is not configured: {self.job_id}.{step_id}") from exc


@dataclass(frozen=True, slots=True)
class AppConfig:
    source_path: Path
    source_sha256: str
    runtime: RuntimeConfig
    jobs: Mapping[str, JobConfig]
    dagster: DagsterConfig = DagsterConfig()

    def job(self, job_id: str) -> JobConfig:
        try:
            return self.jobs[job_id]
        except KeyError as exc:
            raise KeyError(f"job is not configured: {job_id}") from exc


def _path(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty path")
    candidate = Path(value)
    return (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()


def load_config(path: str | Path = "appsec-review.toml") -> AppConfig:
    raw = str(path)
    parsed = urlparse(raw)
    windows_path = bool(re.match(r"^[A-Za-z]:[\\/]", raw))
    if parsed.scheme and parsed.scheme != "file" and not windows_path:
        raise ValueError(f"unsupported configuration URI scheme: {parsed.scheme}")
    if parsed.scheme == "file" and not windows_path:
        file_path = unquote(parsed.path)
        if parsed.netloc:
            file_path = f"//{parsed.netloc}{file_path}"
        if len(file_path) >= 3 and file_path[0] == "/" and file_path[2] == ":":
            file_path = file_path[1:]
        source = Path(file_path).resolve(strict=True)
    else:
        source = Path(path).resolve(strict=True)
    repository_root = source.parent
    source_bytes = source.read_bytes()
    document = tomllib.loads(source_bytes.decode("utf-8"))

    runtime_value = document.get("runtime")
    if not isinstance(runtime_value, dict):
        raise ValueError("[runtime] is required")
    runtime = RuntimeConfig(
        repository_root=repository_root,
        runs_dir=_path(repository_root, runtime_value.get("runs_dir"), "runtime.runs_dir"),
        data_dir=_path(repository_root, runtime_value.get("data_dir"), "runtime.data_dir"),
        metadata_dir=_path(
            repository_root,
            runtime_value.get("metadata_dir", "runs/metadata"),
            "runtime.metadata_dir",
        ),
    )
    if runtime.metadata_dir != runtime.runs_dir / "metadata":
        raise ValueError("runtime.metadata_dir must be the runs/metadata host metadata area")

    jobs_value = document.get("jobs")
    if not isinstance(jobs_value, dict) or not jobs_value:
        raise ValueError("[jobs] must contain at least one job")
    jobs: dict[str, JobConfig] = {}
    for job_id, value in jobs_value.items():
        if not isinstance(value, dict):
            raise ValueError(f"jobs.{job_id} must be a table")
        schedule_value = value.get("schedule")
        schedule = None
        if schedule_value is not None:
            if not isinstance(schedule_value, dict):
                raise ValueError(f"jobs.{job_id}.schedule must be a table")
            schedule = ScheduleConfig(
                enabled=bool(schedule_value.get("enabled", False)),
                cron=str(schedule_value.get("cron", "")),
                timezone=str(schedule_value.get("timezone", "")),
            )
        settings = value.get("settings", {})
        if not isinstance(settings, dict):
            raise ValueError(f"jobs.{job_id}.settings must be a table")
        steps_value = value.get("steps", {})
        if not isinstance(steps_value, dict):
            raise ValueError(f"jobs.{job_id}.steps must be a table")
        steps: dict[str, StepConfig] = {}
        for step_id, step_value in steps_value.items():
            if not isinstance(step_value, dict):
                raise ValueError(f"jobs.{job_id}.steps.{step_id} must be a table")
            step_settings = step_value.get("settings", {})
            tasks_value = step_value.get("tasks", {})
            if not isinstance(step_settings, dict) or not isinstance(tasks_value, dict):
                raise ValueError(f"jobs.{job_id}.steps.{step_id} settings/tasks must be tables")
            tasks: dict[str, TaskConfig] = {}
            for task_id, task_value in tasks_value.items():
                if not isinstance(task_value, dict):
                    raise ValueError(f"jobs.{job_id}.steps.{step_id}.tasks.{task_id} must be a table")
                task_settings = task_value.get("settings", {})
                if not isinstance(task_settings, dict):
                    raise ValueError(
                        f"jobs.{job_id}.steps.{step_id}.tasks.{task_id}.settings must be a table"
                    )
                tasks[task_id] = TaskConfig(
                    task_id=task_id,
                    workers=int(task_value.get("workers", 1)),
                    settings=MappingProxyType(dict(task_settings)),
                )
            steps[step_id] = StepConfig(
                step_id=step_id,
                workers=int(step_value.get("workers", 1)),
                settings=MappingProxyType(dict(step_settings)),
                tasks=MappingProxyType(tasks),
            )
        typed_settings: object | None = None
        if job_id == "job_language_build":
            go_value = settings.get("go")
            if not isinstance(go_value, dict):
                raise ValueError("jobs.job_language_build.settings.go must be a table")
            python_value = settings.get("python")
            if not isinstance(python_value, dict):
                raise ValueError("jobs.job_language_build.settings.python must be a table")
            node_value = settings.get("node")
            if not isinstance(node_value, dict) or not isinstance(node_value.get("package_managers"), list):
                raise ValueError("jobs.job_language_build.settings.node/package_managers must be tables/arrays")
            rust_value = settings.get("rust")
            if not isinstance(rust_value, dict):
                raise ValueError("jobs.job_language_build.settings.rust must be a table")
            features = rust_value.get("features", [])
            if not isinstance(features, list) or any(not isinstance(value, str) for value in features):
                raise ValueError("Rust features must be a string array")
            target_value = rust_value.get("target")
            if target_value is not None and not isinstance(target_value, str):
                raise ValueError("Rust target must be a string when configured")
            php_value = settings.get("php")
            if not isinstance(php_value, dict):
                raise ValueError("jobs.job_language_build.settings.php must be a table")
            jvm_value = settings.get("jvm")
            if not isinstance(jvm_value, dict) or not isinstance(jvm_value.get("tool_paths"), dict):
                raise ValueError("jobs.job_language_build.settings.jvm/tool_paths must be tables")
            dotnet_value = settings.get("dotnet")
            if not isinstance(dotnet_value, dict):
                raise ValueError("jobs.job_language_build.settings.dotnet must be a table")
            wasm_value = settings.get("wasm")
            if not isinstance(wasm_value, dict):
                raise ValueError("jobs.job_language_build.settings.wasm must be a table")
            producer_values = wasm_value.get("producers")
            if not isinstance(producer_values, dict) or not producer_values:
                raise ValueError("jobs.job_language_build.settings.wasm.producers must be a non-empty table")
            producers: dict[str, WasmProducerSettings] = {}
            for producer_name, producer_value in producer_values.items():
                if not isinstance(producer_value, dict):
                    raise ValueError(f"WebAssembly producer must be a table: {producer_name}")
                families = producer_value.get("families")
                tools = producer_value.get("tools")
                indicators = producer_value.get("indicators")
                if (not isinstance(families, list) or not isinstance(tools, list) or
                        not isinstance(indicators, list) or
                        any(not isinstance(item, str) for item in [*families, *tools, *indicators])):
                    raise ValueError(f"WebAssembly producer arrays are invalid: {producer_name}")
                producers[str(producer_name)] = WasmProducerSettings(
                    tuple(families), tuple(tools), tuple(indicators))
            typed_settings = LanguageBuildSettings(
                command_timeout_seconds=int(settings.get("command_timeout_seconds", 0)),
                output_bytes=int(settings.get("output_bytes", 0)),
                artifact_count_limit=int(settings.get("artifact_count_limit", 0)),
                dotnet=DotnetBuildSettings(
                    require_locked_restore=dotnet_value.get("require_locked_restore") is True,
                    capture_msbuild_diagnostics=dotnet_value.get("capture_msbuild_diagnostics") is True,
                    generated_sources=dotnet_value.get("generated_sources") is True,
                    allow_publish=dotnet_value.get("allow_publish") is True,
                    allow_pack=dotnet_value.get("allow_pack") is True,
                    allow_aot=dotnet_value.get("allow_aot") is True,
                ),
                go=GoBuildSettings(
                    offline=go_value.get("offline") is True,
                    capture_trace=go_value.get("capture_trace") is True,
                    package_catalog=go_value.get("package_catalog") is True,
                    diagnostic_tail_bytes=int(go_value.get("diagnostic_tail_bytes", -1)),
                ),
                node=NodeBuildSettings(
                    package_managers=tuple(str(value) for value in node_value["package_managers"]),
                    require_lockfile=node_value.get("require_lockfile") is True,
                    network=str(node_value.get("network", "")),
                    lifecycle_scripts=str(node_value.get("lifecycle_scripts", "")),
                    capture_source_maps=node_value.get("capture_source_maps") is True,
                    diagnostic_tail_bytes=int(node_value.get("diagnostic_tail_bytes", -1)),
                ),
                python=PythonBuildSettings(
                    frontend=str(python_value.get("frontend", "")),
                    require_locked_dependencies=python_value.get("require_locked_dependencies") is True,
                    offline=python_value.get("offline") is True,
                    capture_native_tools=python_value.get("capture_native_tools") is True,
                    diagnostic_tail_bytes=int(python_value.get("diagnostic_tail_bytes", -1)),
                ),
                rust=RustBuildSettings(
                    toolchain=str(rust_value.get("toolchain", "")),
                    target=target_value,
                    profile=str(rust_value.get("profile", "")),
                    features=tuple(features),
                    locked=rust_value.get("locked") is True,
                    offline=rust_value.get("offline") is True,
                    capture_linker=rust_value.get("capture_linker") is True,
                    diagnostic_tail_bytes=int(rust_value.get("diagnostic_tail_bytes", -1)),
                ),
                php=PhpBuildSettings(
                    composer_plugins=str(php_value.get("composer_plugins", "")),
                    composer_scripts=str(php_value.get("composer_scripts", "")),
                    require_lockfile=php_value.get("require_lockfile") is True,
                    diagnostic_tail_bytes=int(php_value.get("diagnostic_tail_bytes", -1)),
                ),
                jvm=JvmBuildSettings(
                    trace_bytes=int(jvm_value.get("trace_bytes", 0)),
                    provenance_count_limit=int(jvm_value.get("provenance_count_limit", 0)),
                    diagnostic_tail_bytes=int(jvm_value.get("diagnostic_tail_bytes", 0)),
                    system_path=str(jvm_value.get("system_path", "")),
                    tool_paths=MappingProxyType({str(key): str(value)
                                                  for key, value in jvm_value["tool_paths"].items()}),
                ),
                wasm=WasmBuildSettings(
                    command_timeout_seconds=int(settings.get("command_timeout_seconds", 0)),
                    stream_limit_bytes=int(settings.get("output_bytes", 0)),
                    artifact_count_limit=int(settings.get("artifact_count_limit", 0)),
                    workspace_file_limit=int(wasm_value.get("workspace_file_limit", 0)),
                    producers=MappingProxyType(producers),
                ),
            )
        elif job_id == "job_cpp_compiled_analysis":
            typed_settings = CppCompiledAnalysisSettings(lane=str(settings.get("lane", "")))
        elif job_id == "job_codeql_analysis":
            from .codeql import parse_codeql_settings
            typed_settings = parse_codeql_settings(settings)
        jobs[job_id] = JobConfig(
            job_id=job_id,
            name=str(value.get("name", "")),
            workers=int(value.get("workers", 1)),
            schedule=schedule,
            settings=MappingProxyType(dict(settings)),
            steps=MappingProxyType(steps),
            typed_settings=typed_settings,
        )
    orchestration = document.get("orchestration", {})
    if not isinstance(orchestration, dict):
        raise ValueError("[orchestration] must be a table")
    dagster_value = orchestration.get("dagster", {})
    if not isinstance(dagster_value, dict):
        raise ValueError("[orchestration.dagster] must be a table")
    pools = dagster_value.get("pools", {})
    if not isinstance(pools, dict):
        raise ValueError("[orchestration.dagster.pools] must be a table")
    return AppConfig(
        source_path=source,
        source_sha256=hashlib.sha256(source_bytes).hexdigest(),
        runtime=runtime,
        jobs=MappingProxyType(jobs),
        dagster=DagsterConfig(executor=str(dagster_value.get("executor", "multiprocess")),
                              max_concurrent=int(dagster_value.get("max_concurrent", 8)),
                              pool_limits=MappingProxyType({str(key): int(value) for key, value in pools.items()})),
    )
