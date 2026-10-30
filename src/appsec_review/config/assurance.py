"""Operator-owned customer evidence policy; supplied software is never a target."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
import re
from types import MappingProxyType
from typing import Any, Mapping


SCOPE_VERSION = "appsec-review/delivered-scope/2"
VALIDATION_VERSION = "appsec-review/admission/2"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,199}")


class AssuranceMode(str, Enum):
    STRICT = "strict"
    FIRST_PARTY_MANAGED = "first_party_managed"


class ScopeRole(str, Enum):
    TARGET_SOURCE = "target_source"
    DELIVERABLE = "deliverable"
    SHIPPED_DEPENDENCY = "shipped_dependency"
    # Installed for production use by an installer record; delivery is not established by it.
    RUNTIME_DEPENDENCY = "runtime_dependency"
    BUILD_CHAIN = "build_chain"
    BUILD_DEPENDENCY = "build_dependency"
    PLATFORM = "supplied_platform"
    EVIDENCE = "intermediate_evidence"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ComponentReleases:
    """Opaque declarations, never computed from installed payloads."""

    values: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        values = dict(self.values)
        if any(not isinstance(key, str) or not _ID.fullmatch(key)
               or not isinstance(value, str) or not _ID.fullmatch(value)
               for key, value in values.items()):
            raise ValueError("component release names and IDs must be bounded opaque identifiers")
        object.__setattr__(self, "values", MappingProxyType(values))

    def require(self, *components: str) -> tuple[bool, str | None]:
        missing = sorted(set(components) - self.values.keys())
        return (False, "missing_release_identity") if missing else (True, None)

    def view(self) -> dict[str, str]:
        return dict(sorted(self.values.items()))


@dataclass(frozen=True, slots=True)
class ResourceBudget:
    cpu: int = 8
    memory_mb: int = 10240
    io_slots: int = 1
    staging_memory_mb: int = 512

    def __post_init__(self) -> None:
        for name in ("cpu", "memory_mb", "io_slots", "staging_memory_mb"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"review_policy.resources.{name} must be a positive integer")
        if self.staging_memory_mb >= self.memory_mb:
            raise ValueError("resource memory budget must exceed staging memory")

    def view(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in
                ("cpu", "memory_mb", "io_slots", "staging_memory_mb")}

    @classmethod
    def from_view(cls, value: object) -> "ResourceBudget":
        """Read an exact frozen wire contract, never fill in missing budget fields."""
        if not isinstance(value, dict) or set(value) != {
                "cpu", "memory_mb", "io_slots", "staging_memory_mb"}:
            raise ValueError("resource budget contract requires exact CPU, memory, I/O and staging")
        return cls(**value)

    def matches(self, value: object) -> bool:
        try:
            return self.from_view(value) == self
        except ValueError:
            return False


@dataclass(frozen=True, slots=True)
class ImageBuilderConfig:
    endpoint: str
    release_id: str
    tenant_id: str
    cpu: int = 1
    host_cpu: int = 1
    memory_mb: int = 4096
    host_overhead_mb: int = 512
    max_concurrency: int = 1
    cleanup_timeout_seconds: int = 60
    resource_mode: str = "bounded"
    lifetime_domain: str = "actions"

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, str) or not PurePosixPath(self.endpoint).is_absolute():
            raise ValueError("image builder endpoint must be an absolute operator-owned Unix socket")
        for name in ("release_id", "tenant_id"):
            if not isinstance(getattr(self, name), str) or not _ID.fullmatch(getattr(self, name)):
                raise ValueError(f"image builder {name} must be a bounded declared identifier")
        for name in ("cpu", "host_cpu", "memory_mb", "host_overhead_mb", "max_concurrency",
                     "cleanup_timeout_seconds"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"image builder {name} must be a positive integer")
        if self.cleanup_timeout_seconds > 300:
            raise ValueError("image builder cleanup timeout exceeds 300 seconds")
        if not isinstance(self.resource_mode, str) or self.resource_mode not in {"bounded", "concurrency_only"}:
            raise ValueError("image builder resource_mode must be bounded or concurrency_only")
        if self.resource_mode == "concurrency_only" and self.max_concurrency != 1:
            raise ValueError("concurrency-only image preparation requires exactly one build")
        if not isinstance(self.lifetime_domain, str) or self.lifetime_domain not in {"actions", "engine"} or (
                self.lifetime_domain == "engine" and self.resource_mode != "concurrency_only"):
            raise ValueError("engine-domain lifetime requires explicit concurrency-only policy")

    @property
    def requested_limits(self) -> dict[str, Any]:
        limits = {"cpu": self.cpu, "memory_bytes": self.memory_mb * 1024**2,
                  "host_cpu": self.host_cpu, "host_overhead_bytes": self.host_overhead_mb * 1024**2,
                  "max_log_bytes": 64 * 1024}
        if self.resource_mode == "concurrency_only":
            result = {**{key: None for key in limits if key != "max_log_bytes"},
                      "max_log_bytes": limits["max_log_bytes"], "resource_mode": self.resource_mode}
            if self.lifetime_domain == "engine":
                result["lifetime_domain"] = "engine"
            return result
        return limits

    def build_reservation(self, budget: ResourceBudget) -> tuple[int, int]:
        if self.resource_mode == "concurrency_only":
            if self.lifetime_domain == "engine":
                return budget.cpu, budget.memory_mb - budget.staging_memory_mb
            return (budget.cpu - self.host_cpu,
                    budget.memory_mb - self.host_overhead_mb - budget.staging_memory_mb)
        return self.cpu + self.host_cpu, self.memory_mb + self.host_overhead_mb

    def view(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


def validate_concurrency_only_enforcement(value: object) -> None:
    if not isinstance(value, dict):
        raise ValueError("concurrency-only builder observations are missing")
    for prefix in ("", "host_"):
        if (value.get(prefix + "resource_mode") != "concurrency_only"
                or value.get(prefix + "cpu_quota_us", "missing") is not None
                or value.get(prefix + "memory_max", "missing") is not None
                or type(value.get(prefix + "cpu_period_us")) is not int
                or value[prefix + "cpu_period_us"] <= 0
                or type(value.get(prefix + "swap_max")) is not int
                or value[prefix + "swap_max"] != 0
                or not isinstance(value.get(prefix + "inherited_limits"), list)):
            raise ValueError("concurrency-only builder must prove uncapped CPU/RAM and retained swap policy")


@dataclass(frozen=True, slots=True)
class StoreAuthorization:
    tenant_id: str
    runs_root: str

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, str) or not _ID.fullmatch(self.tenant_id):
            raise ValueError("store authorization requires a bounded tenant ID")
        if not isinstance(self.runs_root, str) or not Path(self.runs_root).is_absolute():
            raise ValueError("store authorization requires an absolute operator-owned runs root")

    def view(self) -> dict[str, str]:
        return {"tenant_id": self.tenant_id, "runs_root": self.runs_root}


@dataclass(frozen=True, slots=True)
class PredecessorDatabases:
    run_id: str
    handoff_sha256: str
    scope_ids: tuple[str, ...]
    max_files: int = 100000
    max_bytes: int = 1024 * 1024 * 1024
    metadata_bytes_limit: int = 4 * 1024 * 1024
    timeout_seconds: int = 600

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}-\d{4}", self.run_id):
            raise ValueError("predecessor selection requires an exact application run ID")
        if not isinstance(self.handoff_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.handoff_sha256):
            raise ValueError("predecessor selection requires an exact accepted handoff SHA")
        if (not isinstance(self.scope_ids, tuple) or not 1 <= len(self.scope_ids) <= 128
                or any(not isinstance(value, str) or not re.fullmatch(r"codeql-unit-[0-9a-f]{24}", value)
                       for value in self.scope_ids)
                or len(self.scope_ids) != len(set(self.scope_ids))):
            raise ValueError("predecessor selection requires unique bounded CodeQL scope IDs")
        for name in ("max_files", "max_bytes", "metadata_bytes_limit", "timeout_seconds"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"predecessor {name} must be a positive integer")

    def view(self) -> dict[str, Any]:
        return {name: list(self.scope_ids) if name == "scope_ids" else getattr(self, name)
                for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class ReviewPolicy:
    mode: AssuranceMode = AssuranceMode.STRICT
    project_id: str | None = None
    approved_first_party_projects: tuple[str, ...] = ()
    target_root: str | None = None
    custody: str | None = None
    releases: ComponentReleases = field(default_factory=ComponentReleases)
    resources: ResourceBudget = field(default_factory=ResourceBudget)
    image_builder: ImageBuilderConfig | None = None
    store_authorization: StoreAuthorization | None = None
    predecessor_databases: PredecessorDatabases | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.mode, AssuranceMode):
            raise ValueError("review_policy.mode must be strict or first_party_managed")
        projects = self.approved_first_party_projects
        if (not isinstance(projects, tuple) or len(projects) != len(set(projects))
                or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in projects)):
            raise ValueError("approved first-party project IDs must be unique bounded identifiers")
        if self.project_id is not None and (
                not isinstance(self.project_id, str) or not _ID.fullmatch(self.project_id)):
            raise ValueError("review_policy.project_id is invalid")
        if self.target_root is not None and (
                not isinstance(self.target_root, str) or not Path(self.target_root).is_absolute()):
            raise ValueError("review_policy.target_root must be an absolute operator-owned path")
        if self.custody not in {None, "application_private_v1"}:
            raise ValueError("review_policy.custody is unsupported")
        if self.store_authorization is not None:
            if not isinstance(self.store_authorization, StoreAuthorization) or self.project_id is None:
                raise ValueError("store authorization requires typed configuration and an operator project ID")
            if (isinstance(self.image_builder, ImageBuilderConfig)
                    and self.image_builder.tenant_id != self.store_authorization.tenant_id):
                raise ValueError("builder tenant differs from operator store authorization")
        if self.predecessor_databases is not None:
            if (not isinstance(self.predecessor_databases, PredecessorDatabases)
                    or self.store_authorization is None or self.project_id not in projects):
                raise ValueError("predecessor databases require an authorized store and approved first-party project")
            if self.predecessor_databases.metadata_bytes_limit * 64 > self.resources.staging_memory_mb * 1024 * 1024:
                raise ValueError("predecessor metadata bound exceeds its staging memory reservation")
        if self.image_builder is not None:
            if not isinstance(self.image_builder, ImageBuilderConfig) or self.project_id is None:
                raise ValueError("image builder requires typed configuration and an operator project binding")
            if (self.image_builder.cpu + self.image_builder.host_cpu > self.resources.cpu or
                    self.image_builder.memory_mb + self.image_builder.host_overhead_mb
                    + self.resources.staging_memory_mb > self.resources.memory_mb):
                raise ValueError("image builder exceeds the aggregate review resource budget")
        if self.mode is AssuranceMode.FIRST_PARTY_MANAGED:
            if self.project_id is None or self.project_id not in projects:
                raise ValueError("managed assurance requires an operator-approved first-party project")
            if self.target_root is None or self.custody != "application_private_v1":
                raise ValueError("managed assurance requires target binding and application-private custody")

    def check_target(self, target: Path | None) -> None:
        if self.mode is AssuranceMode.FIRST_PARTY_MANAGED and (
                target is None or target.resolve() != Path(self.target_root).resolve()):
            raise ValueError("managed assurance target differs from the operator-approved project")

    def view(self) -> dict[str, Any]:
        result = {
            "mode": self.mode.value, "project_id": self.project_id,
            "approved_first_party_projects": list(self.approved_first_party_projects),
            "target_root": self.target_root, "custody": self.custody,
            "scope_version": SCOPE_VERSION, "validation_version": VALIDATION_VERSION,
            "platform_payload_verification": "excluded",
            "releases": self.releases.view(), "resources": self.resources.view(),
        }
        if self.image_builder is not None:
            result["image_builder"] = self.image_builder.view()
        if self.store_authorization is not None:
            result["store_authorization"] = self.store_authorization.view()
        if self.predecessor_databases is not None:
            result["predecessor_databases"] = self.predecessor_databases.view()
        return result


def parse_review_policy(value: object) -> ReviewPolicy:
    if not isinstance(value, dict):
        raise ValueError("review_policy must be a table")
    allowed = {"mode", "project_id", "approved_first_party_projects", "target_root",
               "custody", "releases", "resources", "image_builder", "store_authorization", "predecessor_databases"}
    if set(value) - allowed:
        raise ValueError("review_policy has unknown settings: " + ", ".join(sorted(set(value) - allowed)))
    releases = value.get("releases", {})
    resources = value.get("resources", {})
    projects = value.get("approved_first_party_projects", [])
    builder = value.get("image_builder")
    authorization = value.get("store_authorization")
    predecessor = value.get("predecessor_databases")
    if authorization is not None and (
            not isinstance(authorization, dict) or set(authorization) != {"tenant_id", "runs_root"}):
        raise ValueError("store authorization must specify only tenant_id and runs_root")
    if predecessor is not None:
        if (not isinstance(predecessor, dict) or set(predecessor) - PredecessorDatabases.__dataclass_fields__.keys()
                or not {"run_id", "handoff_sha256", "scope_ids"} <= predecessor.keys()
                or not isinstance(predecessor["scope_ids"], list)):
            raise ValueError("predecessor database selection has invalid or missing settings")
        predecessor = {**predecessor, "scope_ids": tuple(predecessor["scope_ids"])}
    if builder is not None and (
            not isinstance(builder, dict) or set(builder) - ImageBuilderConfig.__dataclass_fields__.keys()
            or not {"endpoint", "release_id", "tenant_id"} <= builder.keys()):
        raise ValueError("review_policy.image_builder has invalid or missing settings")
    if not isinstance(releases, dict) or not isinstance(resources, dict):
        raise ValueError("review_policy releases and resources must be tables")
    if set(resources) - {"cpu", "memory_mb", "io_slots", "staging_memory_mb"}:
        raise ValueError("review_policy.resources has unknown settings")
    if not isinstance(projects, list) or any(not isinstance(item, str) for item in projects):
        raise ValueError("approved_first_party_projects must be an array of project IDs")
    try:
        mode = AssuranceMode(value.get("mode", "strict"))
    except (ValueError, TypeError) as exc:
        raise ValueError("review_policy.mode must be strict or first_party_managed") from exc
    return ReviewPolicy(
        mode=mode, project_id=value.get("project_id"),
        approved_first_party_projects=tuple(projects), target_root=value.get("target_root"),
        custody=value.get("custody"), releases=ComponentReleases(releases),
        resources=ResourceBudget(**resources),
        image_builder=ImageBuilderConfig(**builder) if builder is not None else None,
        store_authorization=StoreAuthorization(**authorization) if authorization is not None else None,
        predecessor_databases=PredecessorDatabases(**predecessor) if predecessor is not None else None,
    )
