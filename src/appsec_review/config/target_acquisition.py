"""Typed ``[target_acquisition]`` configuration for the user-invoked ``acquire-target`` command.

A review *system* (``[[target_acquisition.systems]]``) is composed of one or more *components*
(``[[target_acquisition.systems.components]]``), because one reviewed system may live in more than one
source-control system. Each component pins one source revision exactly: a Git commit (the default
kind; its submodules follow the gitlinks recorded in that commit), a Perforce submitted changelist, or
a code-review revision (GitLab merge-request head, Gerrit patch set, Azure DevOps pull-request
iteration). Components are acquired in parallel into ``targets/<system>/<component>/`` and reviewed
together as ``targets/<system>``. Credentials never appear here; a table names only the environment
variables that hold them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Mapping


KINDS = ("git", "perforce", "review_export")
PROVIDERS = ("gitlab", "gerrit", "azure_devops")
REVIEW_SOURCES = ("api", "bundle")
SUBMODULE_MODES = ("recursive", "none")

_TARGET_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_REF = re.compile(r"refs/[A-Za-z0-9._/-]{1,240}")
_DEPOT_PATH = re.compile(r"//[A-Za-z0-9_.\-][A-Za-z0-9_.\-/ ]{0,1000}/\.\.\.")
_P4_PORT = re.compile(r"(?:(?:ssl|tcp|ssl4|tcp4|ssl6|tcp6|ssl64|tcp64|ssl46|tcp46):)?"
                      r"[A-Za-z0-9.\-\[\]:]{1,255}:[0-9]{1,5}")
_FINGERPRINT = re.compile(r"(?:[0-9A-F]{2}:){19,31}[0-9A-F]{2}")
_PROJECT = re.compile(r"[A-Za-z0-9_.\-/ ~]{1,512}")
_HTTP_URL = re.compile(r"https?://[A-Za-z0-9.\-\[\]:]{1,255}(?:/[A-Za-z0-9_.\-~/%]*)?")


def _bounded_int(value: Any, field_name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{field_name} must be an integer in [{low}, {high}]")
    return value


@dataclass(frozen=True, slots=True)
class GitSource:
    """A Git repository pinned to one commit; submodules follow that commit's gitlinks."""

    url: str
    commit: str
    submodules: str = "recursive"
    fetch_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PerforceSource:
    """A depot path pinned to one submitted changelist, read with ``p4 print`` (no client workspace)."""

    port: str
    depot_path: str
    changelist: int
    user_env: str
    ticket_env: str = ""
    trust_fingerprint: str = ""


@dataclass(frozen=True, slots=True)
class ReviewExportSource:
    """One code-review revision: its metadata becomes review records and its head a Git checkout."""

    provider: str
    source: str
    api_url: str
    project: str
    repository: str
    change: int
    revision: str
    clone_url: str
    patchset: int | None = None
    iteration: int | None = None
    token_env: str = ""
    username_env: str = ""
    bundle_path: Path | None = None
    bundle_sha256: str = ""
    submodules: str = "recursive"


@dataclass(frozen=True, slots=True)
class TargetRequest:
    """One component of a system; ``target_id`` is the component id."""

    target_id: str
    kind: str
    git: GitSource | None = None
    perforce: PerforceSource | None = None
    review: ReviewExportSource | None = None

    def spec(self) -> dict[str, Any]:
        """The pinned, credential-free request recorded in the acquisition manifest."""
        if self.git is not None:
            return {"kind": "git", "url": self.git.url, "commit": self.git.commit,
                    "submodules": self.git.submodules, "fetch_refs": list(self.git.fetch_refs)}
        if self.perforce is not None:
            item = self.perforce
            return {"kind": "perforce", "port": item.port, "depot_path": item.depot_path,
                    "changelist": item.changelist, "trust_fingerprint": item.trust_fingerprint or None,
                    "user_env": item.user_env, "ticket_env": item.ticket_env or None}
        assert self.review is not None
        item = self.review
        return {"kind": "review_export", "provider": item.provider, "source": item.source,
                "api_url": item.api_url or None, "project": item.project or None,
                "repository": item.repository or None, "change": item.change, "revision": item.revision,
                "patchset": item.patchset, "iteration": item.iteration, "clone_url": item.clone_url,
                "bundle_sha256": item.bundle_sha256 or None, "submodules": item.submodules,
                "token_env": item.token_env or None, "username_env": item.username_env or None}


@dataclass(frozen=True, slots=True)
class SystemRequest:
    """A reviewed system composed of independently pinned components."""

    system_id: str
    components: tuple[TargetRequest, ...]

    def __post_init__(self) -> None:
        if not self.components:
            raise ValueError(f"target_acquisition system {self.system_id} must define components")
        identifiers = [item.target_id for item in self.components]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError(f"target_acquisition system {self.system_id} component ids must be unique")

    def component(self, component_id: str) -> TargetRequest:
        for item in self.components:
            if item.target_id == component_id:
                return item
        raise KeyError(f"component is not configured: {self.system_id}/{component_id}")

    def spec(self) -> dict[str, Any]:
        return {"system": self.system_id,
                "components": {item.target_id: item.spec() for item in self.components}}


@dataclass(frozen=True, slots=True)
class TargetAcquisitionSettings:
    targets_dir: str = "targets"
    records_dir: str = "data/target-acquisitions"
    git_executable: str = "git"
    p4_executable: str = "p4"
    command_timeout_seconds: int = 3600
    http_timeout_seconds: int = 60
    max_http_response_bytes: int = 33554432
    max_review_commits: int = 10000
    max_files: int = 500000
    max_total_bytes: int = 8589934592
    max_file_bytes: int = 536870912
    max_path_bytes: int = 4096
    max_submodule_depth: int = 8
    max_diff_bytes: int = 67108864
    # Permit file:// and local-path Git sources and plain-HTTP loopback review APIs. Tests only.
    allow_local_sources: bool = False
    # Components of one system are acquired concurrently by at most this many workers.
    max_parallel_components: int = 4
    systems: tuple[SystemRequest, ...] = field(default=())

    def __post_init__(self) -> None:
        for name in ("targets_dir", "records_dir"):
            value = getattr(self, name)
            if (not isinstance(value, str) or not value or Path(value).is_absolute() or
                    ".." in Path(value).parts or "\\" in value):
                raise ValueError(f"target_acquisition.{name} must be a relative path inside the repository")
        for name in ("git_executable", "p4_executable"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or value.startswith("-") or "\x00" in value:
                raise ValueError(f"target_acquisition.{name} must name an executable")
        bounds = {
            "command_timeout_seconds": (1, 172800), "http_timeout_seconds": (1, 3600),
            "max_http_response_bytes": (1024, 1024 ** 3), "max_review_commits": (1, 1_000_000),
            "max_files": (1, 50_000_000), "max_total_bytes": (1, 1024 ** 4),
            "max_file_bytes": (1, 64 * 1024 ** 3), "max_path_bytes": (64, 65536),
            "max_submodule_depth": (0, 64), "max_diff_bytes": (1024, 8 * 1024 ** 3),
            "max_parallel_components": (1, 64),
        }
        for name, (low, high) in bounds.items():
            _bounded_int(getattr(self, name), f"target_acquisition.{name}", low, high)
        if type(self.allow_local_sources) is not bool:
            raise ValueError("target_acquisition.allow_local_sources must be a Boolean")
        identifiers = [item.system_id for item in self.systems]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("target_acquisition.systems ids must be unique")

    def system(self, system_id: str) -> SystemRequest:
        for item in self.systems:
            if item.system_id == system_id:
                return item
        raise KeyError(f"system is not configured: {system_id}")


_SETTING_KEYS = {
    "targets_dir", "records_dir", "git_executable", "p4_executable", "command_timeout_seconds",
    "http_timeout_seconds", "max_http_response_bytes", "max_review_commits", "max_files", "max_total_bytes",
    "max_file_bytes", "max_path_bytes", "max_submodule_depth", "max_diff_bytes", "allow_local_sources",
    "max_parallel_components",
}
_KIND_KEYS = {
    "git": {"url", "commit", "submodules", "fetch_refs"},
    "perforce": {"port", "depot_path", "changelist", "user_env", "ticket_env", "trust_fingerprint"},
    "review_export": {"provider", "source", "api_url", "project", "repository", "change", "revision",
                      "patchset", "iteration", "clone_url", "token_env", "username_env", "bundle_path",
                      "bundle_sha256", "submodules"},
}


def _text(item: Mapping[str, Any], key: str, field_name: str, *, required: bool = True,
          pattern: re.Pattern[str] | None = None, default: str = "") -> str:
    value = item.get(key, default)
    if not isinstance(value, str) or "\x00" in value or len(value) > 2048:
        raise ValueError(f"{field_name}.{key} must be a string")
    if required and not value:
        raise ValueError(f"{field_name}.{key} is required")
    if value and pattern is not None and not pattern.fullmatch(value):
        raise ValueError(f"{field_name}.{key} is invalid")
    return value


def _submodules(item: Mapping[str, Any], field_name: str) -> str:
    value = item.get("submodules", "recursive")
    if value not in SUBMODULE_MODES:
        raise ValueError(f"{field_name}.submodules must be one of {', '.join(SUBMODULE_MODES)}")
    return value


def _source_url(value: str, field_name: str) -> str:
    # Credentials never belong in configuration; Git credential helpers or ssh agents supply them.
    from appsec_review.target_acquisition.safety import AcquisitionError, check_git_url
    try:
        check_git_url(value, allow_local=True, field_name=field_name)
    except AcquisitionError as exc:
        raise ValueError(str(exc)) from exc
    return value


def _parse_target(item: Mapping[str, Any], field_name: str, repository_root: Path) -> TargetRequest:
    if not isinstance(item, Mapping):
        raise ValueError(f"{field_name} must be a table")
    target_id = _text(item, "id", field_name, pattern=_TARGET_ID)
    kind = item.get("kind", "git")
    if kind not in KINDS:
        raise ValueError(f"{field_name}.kind must be one of {', '.join(KINDS)}")
    unknown = set(item) - {"id", "kind"} - _KIND_KEYS[kind]
    if unknown:
        raise ValueError(f"{field_name} has unknown settings for kind {kind}: " + ", ".join(sorted(unknown)))
    if kind == "git":
        refs = item.get("fetch_refs", [])
        if (not isinstance(refs, list) or len(refs) > 64 or len(set(refs)) != len(refs) or
                not all(isinstance(ref, str) and _REF.fullmatch(ref) and ".." not in ref for ref in refs)):
            raise ValueError(f"{field_name}.fetch_refs must be unique refs/... names")
        return TargetRequest(target_id, kind, git=GitSource(
            url=_source_url(_text(item, "url", field_name), f"{field_name}.url"),
            commit=_text(item, "commit", field_name, pattern=_COMMIT),
            submodules=_submodules(item, field_name), fetch_refs=tuple(refs)))
    if kind == "perforce":
        depot_path = _text(item, "depot_path", field_name, pattern=_DEPOT_PATH)
        if any(part in {".", ".."} for part in depot_path[2:].split("/")) or "//" in depot_path[2:]:
            raise ValueError(f"{field_name}.depot_path is invalid")
        port = _text(item, "port", field_name, pattern=_P4_PORT)
        fingerprint = _text(item, "trust_fingerprint", field_name, required=False, pattern=_FINGERPRINT)
        if port.startswith("ssl") and not fingerprint:
            raise ValueError(f"{field_name}.trust_fingerprint is required for an ssl: port")
        return TargetRequest(target_id, kind, perforce=PerforceSource(
            port=port, depot_path=depot_path,
            changelist=_bounded_int(item.get("changelist"), f"{field_name}.changelist", 1, 2 ** 31 - 1),
            user_env=_text(item, "user_env", field_name, pattern=_ENV_NAME),
            ticket_env=_text(item, "ticket_env", field_name, required=False, pattern=_ENV_NAME),
            trust_fingerprint=fingerprint))
    provider = item.get("provider")
    if provider not in PROVIDERS:
        raise ValueError(f"{field_name}.provider must be one of {', '.join(PROVIDERS)}")
    source = item.get("source", "api")
    if source not in REVIEW_SOURCES:
        raise ValueError(f"{field_name}.source must be one of {', '.join(REVIEW_SOURCES)}")
    patchset = item.get("patchset")
    iteration = item.get("iteration")
    if provider == "gerrit":
        _bounded_int(patchset, f"{field_name}.patchset", 1, 1_000_000)
    elif patchset is not None:
        raise ValueError(f"{field_name}.patchset applies only to gerrit")
    if provider == "azure_devops":
        _bounded_int(iteration, f"{field_name}.iteration", 1, 1_000_000)
    elif iteration is not None:
        raise ValueError(f"{field_name}.iteration applies only to azure_devops")
    bundle_path: Path | None = None
    bundle_sha256 = _text(item, "bundle_sha256", field_name, required=source == "bundle", pattern=_SHA256)
    api_url = _text(item, "api_url", field_name, required=source == "api", pattern=_HTTP_URL)
    if source == "bundle":
        raw = Path(_text(item, "bundle_path", field_name))
        bundle_path = raw.resolve() if raw.is_absolute() else (repository_root / raw).resolve()
    elif "bundle_path" in item or "bundle_sha256" in item:
        raise ValueError(f"{field_name}.bundle_path and bundle_sha256 apply only to source = \"bundle\"")
    repository = _text(item, "repository", field_name, required=provider == "azure_devops", pattern=_PROJECT)
    if provider != "azure_devops" and repository:
        raise ValueError(f"{field_name}.repository applies only to azure_devops")
    return TargetRequest(target_id, kind, review=ReviewExportSource(
        provider=provider, source=source, api_url=api_url.rstrip("/"),
        project=_text(item, "project", field_name, required=provider != "gerrit", pattern=_PROJECT),
        repository=repository,
        change=_bounded_int(item.get("change"), f"{field_name}.change", 1, 2 ** 31 - 1),
        revision=_text(item, "revision", field_name, pattern=_COMMIT),
        clone_url=_source_url(_text(item, "clone_url", field_name), f"{field_name}.clone_url"),
        patchset=patchset, iteration=iteration,
        token_env=_text(item, "token_env", field_name, required=False, pattern=_ENV_NAME),
        username_env=_text(item, "username_env", field_name, required=False, pattern=_ENV_NAME),
        bundle_path=bundle_path, bundle_sha256=bundle_sha256, submodules=_submodules(item, field_name)))


def parse_target_acquisition(value: object, repository_root: Path) -> TargetAcquisitionSettings:
    """Parse the ``[target_acquisition]`` table; an absent table yields the defaults."""
    if value is None:
        return TargetAcquisitionSettings()
    if not isinstance(value, Mapping):
        raise ValueError("[target_acquisition] must be a table")
    unknown = set(value) - _SETTING_KEYS - {"systems"}
    if unknown:
        raise ValueError("target_acquisition has unknown settings: " + ", ".join(sorted(unknown)))
    systems_value = value.get("systems", [])
    if not isinstance(systems_value, list):
        raise ValueError("target_acquisition.systems must be an array of tables")
    systems = tuple(_parse_system(item, index, repository_root) for index, item in enumerate(systems_value))
    settings = {key: value[key] for key in _SETTING_KEYS if key in value}
    return TargetAcquisitionSettings(**settings, systems=systems)


def _parse_system(item: object, index: int, repository_root: Path) -> SystemRequest:
    field_name = f"target_acquisition.systems[{index}]"
    if not isinstance(item, Mapping):
        raise ValueError(f"{field_name} must be a table")
    unknown = set(item) - {"id", "components"}
    if unknown:
        raise ValueError(f"{field_name} has unknown settings: " + ", ".join(sorted(unknown)))
    system_id = _text(item, "id", field_name, pattern=_TARGET_ID)
    components = item.get("components")
    if not isinstance(components, list) or not components or len(components) > 256:
        raise ValueError(f"{field_name}.components must be a non-empty array of tables")
    return SystemRequest(system_id, tuple(
        _parse_target(component, f"{field_name}.components[{position}]", repository_root)
        for position, component in enumerate(components)))
