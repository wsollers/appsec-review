#!/usr/bin/env python3
"""Typed, immutable operational configuration for the review runtime.

This module is the only TOML parser used by runtime code.  The tracked file is the baseline;
an immutable run-owned file may add global, step, and task values.  Consumers ask for a resolved
view rather than reading either file themselves.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tomllib
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "appsec-review.toml"
RUN_CONFIG_RELATIVE = Path("data") / "configuration" / "appsec-review.toml"
CONFIG_ENVIRONMENT_VARIABLE = "APPSEC_REVIEW_CONFIG"
MAX_CONFIG_BYTES = 1024 * 1024

_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
_JOB_NAMESPACE = re.compile(r"job_(\d{4})\Z")
_TASK_NAMESPACE = re.compile(r"task_(\d{4})\Z")
_RUNTIME_JOB = re.compile(r"(\d{2})-([a-z][a-z0-9-]*)\Z")
_REDACTED_KEY = re.compile(r"(?:secret|token|password|credential|api_key)", re.IGNORECASE)

SETTING_KEYS = frozenset({
    "worker_pool_size",
    "model",
    "reasoning_level",
    "budget_usd",
    "timeout_seconds",
    "cache_policy",
    "retrieval_max_results",
    "applicability_threshold",
})
GLOBAL_KEYS = SETTING_KEYS
STEP_KEYS = SETTING_KEYS | {"job_id"}
TASK_KEYS = SETTING_KEYS
REASONING_LEVELS = frozenset({"low", "medium", "high", "xhigh", "max"})
CACHE_POLICIES = frozenset({"disabled", "validated_reuse"})


class ConfigurationError(ValueError):
    """A configuration source or requested namespace is invalid."""


@dataclass(frozen=True)
class OperationalDefaults:
    worker_pool_size: int
    model: str
    reasoning_level: str
    budget_usd: float
    timeout_seconds: int
    cache_policy: str
    retrieval_max_results: int
    applicability_threshold: float


@dataclass(frozen=True)
class ResolvedConfiguration:
    values: OperationalDefaults
    job_namespace: str | None
    step_name: str | None
    task_namespace: str | None
    job_id: str | None
    layers: tuple[str, ...]
    fingerprint: str

    def redacted(self) -> Mapping[str, Any]:
        return MappingProxyType(redact({
            "schema": "appsec-review/effective-configuration/1",
            "values": asdict(self.values),
            "job_namespace": self.job_namespace,
            "step_name": self.step_name,
            "task_namespace": self.task_namespace,
            "job_id": self.job_id,
            "layers": list(self.layers),
            "fingerprint": self.fingerprint,
        }))


@dataclass(frozen=True)
class ConfigurationDocument:
    path: Path
    data: Mapping[str, Any]
    locations: Mapping[tuple[str, ...], int]
    sha256: str


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _source_map(text: str) -> dict[tuple[str, ...], int]:
    """Best-effort line locations for useful errors; TOML syntax errors come from tomllib."""
    result: dict[tuple[str, ...], int] = {}
    table: tuple[str, ...] = ()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            table = tuple(part.strip() for part in line[1:-1].split("."))
            result[table] = number
            continue
        if "=" in line:
            result[table + (line.split("=", 1)[0].strip(),)] = number
    return result


def _where(document: ConfigurationDocument, path: tuple[str, ...]) -> str:
    probe = path
    while probe and probe not in document.locations:
        probe = probe[:-1]
    line = document.locations.get(probe)
    return f"{document.path}:{line}" if line else str(document.path)


def _fail(document: ConfigurationDocument, path: tuple[str, ...], message: str) -> None:
    dotted = ".".join(path) or "<root>"
    raise ConfigurationError(f"{_where(document, path)}: {dotted}: {message}")


def known_runtime_job_ids() -> frozenset[str]:
    graph = ROOT / "pipeline" / "job-graph.json"
    known = {"00-run-configuration"}
    if graph.is_file():
        try:
            parsed = json.loads(graph.read_text(encoding="utf-8"))
            known.update((parsed.get("jobs") or {}).keys())
        except (OSError, ValueError, AttributeError):
            pass
    return frozenset(known)


def _validate_setting(document: ConfigurationDocument, path: tuple[str, ...], key: str, value: Any) -> None:
    def integer(low: int, high: int) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high

    if key == "worker_pool_size" and not integer(1, 256):
        _fail(document, path, "must be an integer from 1 through 256 workers")
    if key == "model" and (not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", value)):
        _fail(document, path, "must be a non-empty lowercase model identifier")
    if key == "reasoning_level" and value not in REASONING_LEVELS:
        _fail(document, path, f"must be one of {sorted(REASONING_LEVELS)}")
    if key == "budget_usd" and (isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1000):
        _fail(document, path, "must be a number from 0 through 1000 USD")
    if key == "timeout_seconds" and not integer(1, 604800):
        _fail(document, path, "must be an integer from 1 through 604800 seconds")
    if key == "cache_policy" and value not in CACHE_POLICIES:
        _fail(document, path, f"must be one of {sorted(CACHE_POLICIES)}")
    if key == "retrieval_max_results" and not integer(1, 10000):
        _fail(document, path, "must be an integer from 1 through 10000 results")
    if key == "applicability_threshold" and (isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1):
        _fail(document, path, "must be a number from 0 through 1")


def _validate_keys(document: ConfigurationDocument, path: tuple[str, ...], table: Mapping[str, Any], allowed: frozenset[str]) -> None:
    for key, value in table.items():
        if key not in allowed:
            _fail(document, path + (key,), f"unknown key; allowed keys are {sorted(allowed)}")
        _validate_setting(document, path + (key,), key, value)


def _validate(document: ConfigurationDocument, known_jobs: frozenset[str]) -> None:
    data = document.data
    if not isinstance(data.get("global"), Mapping):
        _fail(document, ("global",), "required table is missing")
    _validate_keys(document, ("global",), data["global"], GLOBAL_KEYS)
    missing = SETTING_KEYS - set(data["global"])
    if missing:
        _fail(document, ("global",), f"missing required defaults {sorted(missing)}")

    identities: dict[str, tuple[str, str]] = {}
    for namespace, jobs in data.items():
        if namespace == "global":
            continue
        match = _JOB_NAMESPACE.fullmatch(namespace)
        if not match:
            _fail(document, (namespace,), "expected a job_#### table")
        if not isinstance(jobs, Mapping) or not jobs:
            _fail(document, (namespace,), "must contain at least one step table")
        for step_name, step in jobs.items():
            step_path = (namespace, step_name)
            if not _NAME.fullmatch(step_name) or _TASK_NAMESPACE.fullmatch(step_name):
                _fail(document, step_path, "step name must be lowercase snake_case")
            if not isinstance(step, Mapping):
                _fail(document, step_path, "step must be a table")
            scalar = {key: value for key, value in step.items() if not key.startswith("task_")}
            _validate_keys(document, step_path, scalar, STEP_KEYS)
            job_id = scalar.get("job_id")
            runtime = _RUNTIME_JOB.fullmatch(job_id) if isinstance(job_id, str) else None
            if runtime is None:
                _fail(document, step_path + ("job_id",), "must be a canonical NN-lowercase-kebab runtime job_id")
            expected_step = runtime.group(2).replace("-", "_")
            if int(match.group(1)) != int(runtime.group(1)) or expected_step != step_name:
                _fail(document, step_path + ("job_id",),
                      f"diverges from table identity; expected job_{int(runtime.group(1)):04d}.{expected_step}")
            if job_id not in known_jobs:
                _fail(document, step_path + ("job_id",), "unknown runtime job_id")
            if job_id in identities:
                _fail(document, step_path + ("job_id",), f"duplicate runtime identity also used by {'.'.join(identities[job_id])}")
            identities[job_id] = (namespace, step_name)
            for task_name, task in step.items():
                if task_name in STEP_KEYS:
                    continue
                if not _TASK_NAMESPACE.fullmatch(task_name):
                    _fail(document, step_path + (task_name,), "expected a task_#### table")
                if not isinstance(task, Mapping):
                    _fail(document, step_path + (task_name,), "task must be a table")
                _validate_keys(document, step_path + (task_name,), task, TASK_KEYS)


def load_document(path: Path | str, *, known_jobs: frozenset[str] | None = None) -> ConfigurationDocument:
    source = Path(path).resolve()
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise ConfigurationError(f"{source}: cannot read configuration: {exc}") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigurationError(f"{source}: configuration exceeds {MAX_CONFIG_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
        data = tomllib.loads(text)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"{source}: invalid TOML: {exc}") from None
    document = ConfigurationDocument(source, _freeze(data), MappingProxyType(_source_map(text)), hashlib.sha256(raw).hexdigest())
    _validate(document, known_jobs or known_runtime_job_ids())
    return document


def resolve_config_uri(uri: str | None, *, default: Path = DEFAULT_CONFIG) -> Path:
    """Resolve the closed local source set: empty/default, plain paths, and local file URIs."""
    if uri is None or not uri.strip():
        return Path(default).absolute()
    value = uri.strip()
    parsed = urlsplit(value)
    # On Windows, urlsplit treats C:\x as the scheme "c".
    if not parsed.scheme or (len(parsed.scheme) == 1 and len(value) > 2 and value[1] == ":"):
        return Path(value).expanduser().absolute()
    if parsed.scheme != "file":
        raise ConfigurationError(f"unsupported configuration URI scheme {parsed.scheme!r}; only local file URIs and paths are allowed")
    if parsed.query or parsed.fragment:
        raise ConfigurationError("configuration file URI must not contain a query or fragment")
    if parsed.netloc not in ("", "localhost"):
        raise ConfigurationError("configuration file URI authority must be empty or localhost")
    path = unquote(parsed.path)
    if os.name == "nt" and re.match(r"/[A-Za-z]:/", path):
        path = path[1:]
    return Path(path).absolute()


def get_global_defaults(*, default_path: Path | str = DEFAULT_CONFIG) -> OperationalDefaults:
    return _as_defaults(dict(load_document(default_path).data["global"]))


def resolve_global_defaults(run_config: ConfigurationDocument | Path | str | None = None,
                            *, default_path: Path | str = DEFAULT_CONFIG) -> OperationalDefaults:
    baseline = load_document(default_path)
    values = dict(baseline.data["global"])
    if run_config is not None:
        overlay = run_config if isinstance(run_config, ConfigurationDocument) else load_document(run_config)
        values.update(overlay.data["global"])
    return _as_defaults(values)


def _as_defaults(values: Mapping[str, Any]) -> OperationalDefaults:
    return OperationalDefaults(
        worker_pool_size=values["worker_pool_size"], model=values["model"],
        reasoning_level=values["reasoning_level"], budget_usd=float(values["budget_usd"]),
        timeout_seconds=values["timeout_seconds"], cache_policy=values["cache_policy"],
        retrieval_max_results=values["retrieval_max_results"],
        applicability_threshold=float(values["applicability_threshold"]),
    )


def _step(document: ConfigurationDocument, job_namespace: str, step_name: str) -> Mapping[str, Any]:
    jobs = document.data.get(job_namespace) or {}
    return jobs.get(step_name) or {}


def resolve_layered(job_namespace: str, step_name: str, task_namespace: str | None = None,
                    run_config: ConfigurationDocument | Path | str | None = None,
                    *, default_path: Path | str = DEFAULT_CONFIG) -> ResolvedConfiguration:
    if not _JOB_NAMESPACE.fullmatch(job_namespace):
        raise ConfigurationError(f"invalid job namespace {job_namespace!r}; expected job_####")
    if not _NAME.fullmatch(step_name) or _TASK_NAMESPACE.fullmatch(step_name):
        raise ConfigurationError(f"invalid step name {step_name!r}; expected lowercase snake_case")
    if task_namespace is not None and not _TASK_NAMESPACE.fullmatch(task_namespace):
        raise ConfigurationError(f"invalid task namespace {task_namespace!r}; expected task_####")

    baseline = load_document(default_path)
    overlay = None if run_config is None else (run_config if isinstance(run_config, ConfigurationDocument) else load_document(run_config))
    base_step = _step(baseline, job_namespace, step_name)
    run_step = {} if overlay is None else _step(overlay, job_namespace, step_name)
    if not base_step and not run_step:
        raise ConfigurationError(f"unknown configuration step {job_namespace}.{step_name}")

    values = dict(baseline.data["global"])
    layers = ["tracked.global"]
    if overlay is not None:
        values.update(overlay.data["global"])
        layers.append("run.global")
    job_ids = {step.get("job_id") for step in (base_step, run_step) if step}
    job_ids.discard(None)
    if len(job_ids) != 1:
        raise ConfigurationError(f"{job_namespace}.{step_name}: runtime job_id is missing or divergent across sources")
    job_id = next(iter(job_ids))
    for label, step in (("tracked.step", base_step), ("run.step", run_step)):
        if step:
            values.update({key: value for key, value in step.items() if key in SETTING_KEYS})
            layers.append(label)
    if task_namespace is not None:
        found = False
        for label, step in (("tracked.task", base_step), ("run.task", run_step)):
            task = step.get(task_namespace) if step else None
            if task:
                values.update(task)
                layers.append(label)
                found = True
        if not found:
            raise ConfigurationError(f"unknown configuration task {job_namespace}.{step_name}.{task_namespace}")
    effective = _as_defaults(values)
    canonical = {
        "values": asdict(effective), "job_namespace": job_namespace, "step_name": step_name,
        "task_namespace": task_namespace, "job_id": job_id,
    }
    fingerprint = "sha256:" + hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return ResolvedConfiguration(effective, job_namespace, step_name, task_namespace, job_id, tuple(layers), fingerprint)


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): ("[REDACTED]" if _REDACTED_KEY.search(str(key)) else redact(item)) for key, item in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(redact(value), sort_keys=True, separators=(",", ":"))


def selected_config_path(*, run_root: Path | None = None, config_uri: str | None = None,
                         environ: Mapping[str, str] | None = None) -> Path:
    if run_root is not None:
        run_path = Path(run_root) / RUN_CONFIG_RELATIVE
        if run_path.is_file():
            return run_path
    if config_uri is not None:
        return resolve_config_uri(config_uri)
    environment = os.environ if environ is None else environ
    override = environment.get(CONFIG_ENVIRONMENT_VARIABLE, "")
    return resolve_config_uri(override or None)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the effective redacted operational configuration.")
    parser.add_argument("--config-uri", default=None)
    parser.add_argument("--run-root", type=Path)
    parser.add_argument("--job-namespace", default="job_0000")
    parser.add_argument("--step", default="run_configuration")
    parser.add_argument("--task")
    args = parser.parse_args(argv)
    selected = selected_config_path(run_root=args.run_root, config_uri=args.config_uri)
    resolved = resolve_layered(args.job_namespace, args.step, args.task, selected)
    print(json.dumps(dict(resolved.redacted()), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except ConfigurationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2)
