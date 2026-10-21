"""Typed configuration for ``job_poc_generation`` (``[jobs.job_poc_generation.settings]``).

Nothing here is a default the job can fall back on: the table must define exactly its documented
keys. The validator, bounds and compile settings are closed lists and numbers, never prose: the
writer's prompt does not restate them, and the deterministic validators are the only authority.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Any

from .statuses import JUDGE_VERDICTS

_TOP = frozenset({"enabled", "workers", "max_candidates", "accepted_judge_verdicts", "models", "roles", "retry",
                  "bounds", "policy", "build", "brief"})
_MODEL = frozenset({"provider", "model", "reasoning", "max_input_tokens", "max_output_tokens", "max_queries",
                    "max_turns", "timeout_seconds"})
_ROLE = frozenset({"model_profile"})
_RETRY = frozenset({"max_attempts", "retry_on_timeout", "retry_on_provider_error", "retry_on_invalid_output"})
_BOUNDS = frozenset({"max_function_lines", "max_file_bytes", "max_includes", "max_list_items", "max_text_chars",
                     "max_string_literal_bytes", "max_loop_iterations", "max_array_elements",
                     "max_violations"})
_POLICY = frozenset({"allowed_std_headers", "project_header_suffixes", "call_allowlist", "type_allowlist",
                     "call_denylist", "project_calls"})
_BUILD = frozenset({"command_timeout_seconds", "output_bytes", "workspace_file_limit", "workspace_bytes_limit",
                    "ast_compilers", "debug_flags", "sanitizer_flags", "runtime_libraries",
                    "runtime_symbol_prefixes", "object_limit", "scratch_directory"})
_BRIEF = frozenset({"view_bytes", "view_source_lines", "view_type_declarations", "declaration_lines",
                    "max_brief_bytes", "max_source_files"})
_DENY_CATEGORIES = ("process", "shell", "network", "dynamic_loading", "file_system", "environment", "control")
PROJECT_CALLS = ("sink_and_path", "any_project_function")
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_HEADER = re.compile(r"[A-Za-z0-9_+./-]{1,128}")
_API = re.compile(r"[A-Za-z_~][A-Za-z0-9_:~\[\]<>=!+*/%&|^,()-]{0,127}")
_FLAG = re.compile(r"-[A-Za-z0-9][A-Za-z0-9_=,+.:/-]{0,127}")
_PATH = re.compile(r"/[A-Za-z0-9_.+/-]{1,200}")
_SCRATCH = re.compile(r"\.[a-z][a-z0-9-]{0,31}")


def _fail(message: str) -> ValueError:
    return ValueError(f"jobs.job_poc_generation.settings {message}")


def _exact(value: Any, keys: frozenset[str], where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        unknown = sorted(set(value) - keys) if isinstance(value, Mapping) else []
        missing = sorted(keys - set(value)) if isinstance(value, Mapping) else sorted(keys)
        raise _fail(f"{where} must define exactly its documented keys (unknown: {unknown}, missing: {missing})")
    return value


def _int(value: Any, where: str, *, low: int = 1, high: int = 2**31) -> int:
    if type(value) is not int or not low <= value <= high:
        raise _fail(f"{where} must be an integer in [{low}, {high}]")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise _fail(f"{where} must be a boolean")
    return value


def _names(value: Any, where: str, pattern: re.Pattern[str], *, limit: int = 512, empty: bool = False
           ) -> tuple[str, ...]:
    if (not isinstance(value, list) or (not value and not empty) or len(value) > limit
            or len(set(value)) != len(value)
            or any(not isinstance(item, str) or not pattern.fullmatch(item) for item in value)):
        raise _fail(f"{where} must be a {'possibly empty ' if empty else 'non-empty '}unique list of well-formed names")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class ModelProfile:
    provider: str
    model: str
    reasoning: str
    max_input_tokens: int
    max_output_tokens: int
    max_queries: int
    max_turns: int
    timeout_seconds: int


@dataclass(frozen=True, slots=True)
class Bounds:
    max_function_lines: int
    max_file_bytes: int
    max_includes: int
    max_list_items: int
    max_text_chars: int
    max_string_literal_bytes: int
    max_loop_iterations: int
    max_array_elements: int
    max_violations: int


@dataclass(frozen=True, slots=True)
class Policy:
    allowed_std_headers: tuple[str, ...]
    project_header_suffixes: tuple[str, ...]
    call_allowlist: tuple[str, ...]
    type_allowlist: tuple[str, ...]
    call_denylist: Mapping[str, tuple[str, ...]]
    project_calls: str


@dataclass(frozen=True, slots=True)
class Build:
    command_timeout_seconds: int
    output_bytes: int
    workspace_file_limit: int
    workspace_bytes_limit: int
    ast_compilers: Mapping[str, str]
    debug_flags: tuple[str, ...]
    sanitizer_flags: tuple[str, ...]
    runtime_libraries: tuple[str, ...]
    runtime_symbol_prefixes: tuple[str, ...]
    object_limit: int
    scratch_directory: str


@dataclass(frozen=True, slots=True)
class Brief:
    view_bytes: int
    view_source_lines: int
    view_type_declarations: int
    declaration_lines: int
    max_brief_bytes: int
    max_source_files: int


@dataclass(frozen=True, slots=True)
class PocGenerationSettings:
    enabled: bool
    workers: int
    max_candidates: int
    accepted_judge_verdicts: tuple[str, ...]
    models: Mapping[str, ModelProfile]
    writer_profile: str
    max_attempts: int
    retry_on_timeout: bool
    retry_on_provider_error: bool
    retry_on_invalid_output: bool
    bounds: Bounds
    policy: Policy
    build: Build
    brief: Brief

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PocGenerationSettings":
        top = _exact(value, _TOP, "")
        models: dict[str, ModelProfile] = {}
        if not isinstance(top["models"], Mapping) or not top["models"]:
            raise _fail("models must define at least one named profile")
        for name, profile in top["models"].items():
            if not isinstance(name, str) or not _NAME.fullmatch(name):
                raise _fail(f"model profile name is invalid: {name!r}")
            body = _exact(profile, _MODEL, f"models.{name}")
            for key in ("provider", "model", "reasoning"):
                if not isinstance(body[key], str) or not body[key].strip():
                    raise _fail(f"models.{name}.{key} must be a non-empty string")
            models[name] = ModelProfile(
                body["provider"], body["model"], body["reasoning"],
                _int(body["max_input_tokens"], f"models.{name}.max_input_tokens"),
                _int(body["max_output_tokens"], f"models.{name}.max_output_tokens"),
                _int(body["max_queries"], f"models.{name}.max_queries", low=0, high=1000),
                _int(body["max_turns"], f"models.{name}.max_turns", high=100),
                _int(body["timeout_seconds"], f"models.{name}.timeout_seconds", high=86400))
        roles = _exact(top["roles"], frozenset({"poc_writer"}), "roles")
        role = _exact(roles["poc_writer"], _ROLE, "roles.poc_writer")
        if role["model_profile"] not in models:
            raise _fail("roles.poc_writer.model_profile must name a model profile")
        retry = _exact(top["retry"], _RETRY, "retry")
        verdicts = _names(top["accepted_judge_verdicts"], "accepted_judge_verdicts", _NAME, limit=8)
        if not set(verdicts) <= set(JUDGE_VERDICTS):
            raise _fail(f"accepted_judge_verdicts must be drawn from {list(JUDGE_VERDICTS)}")
        bounds = _exact(top["bounds"], _BOUNDS, "bounds")
        policy = _exact(top["policy"], _POLICY, "policy")
        denylist = _exact(policy["call_denylist"], frozenset(_DENY_CATEGORIES), "policy.call_denylist")
        build = _exact(top["build"], _BUILD, "build")
        brief = _exact(top["brief"], _BRIEF, "brief")
        if policy["project_calls"] not in PROJECT_CALLS:
            raise _fail(f"policy.project_calls must be one of {list(PROJECT_CALLS)}")
        compilers = build["ast_compilers"]
        if (not isinstance(compilers, Mapping) or set(compilers) != {"c", "cxx"}
                or any(not isinstance(item, str) or not _HEADER.fullmatch(item) for item in compilers.values())):
            raise _fail("build.ast_compilers must name a compiler for c and cxx")
        for key in ("debug_flags", "sanitizer_flags"):
            _names(build[key], f"build.{key}", _FLAG, limit=16)
        return cls(
            _bool(top["enabled"], "enabled"), _int(top["workers"], "workers", high=16),
            _int(top["max_candidates"], "max_candidates", high=1000), verdicts, models, str(role["model_profile"]),
            _int(retry["max_attempts"], "retry.max_attempts", high=5),
            _bool(retry["retry_on_timeout"], "retry.retry_on_timeout"),
            _bool(retry["retry_on_provider_error"], "retry.retry_on_provider_error"),
            _bool(retry["retry_on_invalid_output"], "retry.retry_on_invalid_output"),
            Bounds(**{key: _int(bounds[key], f"bounds.{key}", high=2**28) for key in sorted(_BOUNDS)}),
            Policy(_names(policy["allowed_std_headers"], "policy.allowed_std_headers", _HEADER),
                   _names(policy["project_header_suffixes"], "policy.project_header_suffixes",
                          re.compile(r"\.[A-Za-z0-9]{1,6}"), limit=16),
                   _names(policy["call_allowlist"], "policy.call_allowlist", _API),
                   _names(policy["type_allowlist"], "policy.type_allowlist", _API),
                   {category: _names(denylist[category], f"policy.call_denylist.{category}", _API, empty=True)
                    for category in _DENY_CATEGORIES},
                   str(policy["project_calls"])),
            Build(_int(build["command_timeout_seconds"], "build.command_timeout_seconds", high=7200),
                  _int(build["output_bytes"], "build.output_bytes", high=2**28),
                  _int(build["workspace_file_limit"], "build.workspace_file_limit", high=10**6),
                  _int(build["workspace_bytes_limit"], "build.workspace_bytes_limit", high=2**40),
                  dict(compilers), tuple(build["debug_flags"]), tuple(build["sanitizer_flags"]),
                  _names(build["runtime_libraries"], "build.runtime_libraries", _PATH, limit=64),
                  _names(build["runtime_symbol_prefixes"], "build.runtime_symbol_prefixes", _API, limit=64),
                  _int(build["object_limit"], "build.object_limit", high=100000),
                  _scratch(build["scratch_directory"])),
            Brief(*(_int(brief[key], f"brief.{key}", high=2**24) for key in (
                "view_bytes", "view_source_lines", "view_type_declarations", "declaration_lines",
                "max_brief_bytes", "max_source_files"))))

    @property
    def writer(self) -> ModelProfile:
        return self.models[self.writer_profile]

    def policy_identity(self) -> dict[str, Any]:
        """Everything that can change a validator's verdict; hashed into each candidate's provenance."""
        return {"bounds": {key: getattr(self.bounds, key) for key in sorted(_BOUNDS)},
                "policy": {"allowed_std_headers": sorted(self.policy.allowed_std_headers),
                           "project_header_suffixes": sorted(self.policy.project_header_suffixes),
                           "call_allowlist": sorted(self.policy.call_allowlist),
                           "type_allowlist": sorted(self.policy.type_allowlist),
                           "call_denylist": {key: sorted(item) for key, item in sorted(self.policy.call_denylist.items())},
                           "project_calls": self.policy.project_calls}}

    def build_identity(self) -> dict[str, Any]:
        """The settings that change what the compile check does."""
        return {"debug_flags": list(self.build.debug_flags), "sanitizer_flags": list(self.build.sanitizer_flags),
                "ast_compilers": dict(sorted(self.build.ast_compilers.items())),
                "runtime_libraries": sorted(self.build.runtime_libraries),
                "runtime_symbol_prefixes": sorted(self.build.runtime_symbol_prefixes)}

    def settings_sha256(self) -> str:
        return hashlib.sha256(json.dumps(
            {"policy": self.policy_identity(), "build": self.build_identity(),
             "writer": {"profile": self.writer_profile, **asdict(self.writer)},
             "accepted_judge_verdicts": sorted(self.accepted_judge_verdicts)},
            sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _scratch(value: Any) -> str:
    if not isinstance(value, str) or not _SCRATCH.fullmatch(value):
        raise _fail("build.scratch_directory must be a hidden directory name such as .appsec-poc")
    return value


def matches(name: str, entries: Sequence[str]) -> bool:
    """Whether ``name`` equals an entry, or begins with an entry that ends in ``::``."""
    return any(name == entry or (entry.endswith("::") and name.startswith(entry)) for entry in entries)
