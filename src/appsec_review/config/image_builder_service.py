"""Operator-only bounded builder configuration, separate from client policy.

Load with ``python -m appsec_review.container_runtime.image_builder_service --config FILE``.
The file contains one ``[image_builder_service]`` table, with ``[[...grants]]`` and
``[[...images]]`` tables and ``[image_builder_service.admission]`` containing
``metadata_root``, non-root ``uid``, ``gid`` and a fixed ``lease_id`` UUID.
``[image_builder_service.resources]`` uses the same typed ResourceBudget as
review policy. Defaults stay 8 CPU/10240 MiB/1 I/O/512 MiB staging. All four
values must match the frozen client policy; changes require a new confirmed
lifetime, never adoption or enlargement of an existing reservation.
Paths describe a *native Linux* Docker host, not translated
Desktop mounts. Release identifiers are declarations, not payload fingerprints.

The socket parent must be root-owned, non-writable by clients and traversable
by the single granted UID (for example mode 0711); the socket itself is 0600.
Package egress additionally requires a pre-provisioned immutable allowlisting
proxy on an internal, gateway-mode=isolated Docker bridge. Its overhead shares
the host cap. No proxy, daemon, image, network or cgroup is provisioned here.
Reserve lifetime admission before starting these processes; the full operator
configuration and cgroup directory identities are immutable for that lifetime.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path, PurePosixPath
import re
import tomllib

from appsec_review.config.assurance import ImageBuilderConfig, ResourceBudget
from appsec_review.config.native_engine import NativeEngineConfig, parse_native_engine


IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,199}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
NAMESPACE = re.compile(r"[0-9a-f]{24}")


def identifier(value: object) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("invalid bounded identifier")
    return value


def absolute(value: object) -> str:
    if (not isinstance(value, str) or not value.startswith("/") or "\x00" in value
            or any(part in {".", ".."} for part in value.split("/"))
            or str(PurePosixPath(value)) != value or "," in value):
        raise ValueError("expected a canonical absolute Linux path")
    return value


@dataclass(frozen=True)
class BuilderGrant:
    """One exact run authorization; no inferred tenant/project/path ownership."""

    uid: int
    tenant_id: str
    project_id: str
    run_id: str
    run_root: str
    target_snapshot: str
    namespace: str
    client_context_root: str
    service_context_root: str
    allow_network: bool = False

    def __post_init__(self):
        if type(self.uid) is not int or self.uid < 0:
            raise ValueError("grant UID must be a nonnegative integer")
        for name in ("tenant_id", "project_id", "run_id", "target_snapshot"):
            identifier(getattr(self, name))
        if not isinstance(self.namespace, str) or not NAMESPACE.fullmatch(self.namespace):
            raise ValueError("grant requires the exact client namespace")
        for name in ("run_root", "client_context_root", "service_context_root"):
            absolute(getattr(self, name))
        if self.client_context_root != self.service_context_root:
            raise ValueError("translated context mappings are not commissioned")
        if Path(self.run_root).name != self.run_id or type(self.allow_network) is not bool:
            raise ValueError("invalid run or network authorization")


@dataclass(frozen=True)
class BuilderImage:
    """Locally installed image ID and allowed Dockerfile alias."""

    alias: str
    image_id: str
    release_id: str

    def __post_init__(self):
        if (not isinstance(self.alias, str) or len(self.alias) > 200
                or not re.fullmatch(r"[a-z0-9][a-z0-9._/:@-]*", self.alias)):
            raise ValueError("invalid operator image alias")
        if not isinstance(self.image_id, str) or not IMAGE_ID.fullmatch(self.image_id):
            raise ValueError("operator images require immutable local image IDs")
        identifier(self.release_id)


@dataclass(frozen=True)
class BuilderAdmissionConfig:
    metadata_root: str
    uid: int
    gid: int
    lease_id: str

    def __post_init__(self):
        absolute(self.metadata_root)
        if (type(self.uid) is not int or self.uid < 1 or type(self.gid) is not int or self.gid < 0
                or not isinstance(self.lease_id, str) or not re.fullmatch(r"[0-9a-f]{32}", self.lease_id)):
            raise ValueError("admission requires a non-root client UID, GID and exact lease UUID")


@dataclass(frozen=True)
class ImageBuilderServiceConfig:
    endpoint: str
    state_root: str
    release_id: str
    worker_image_id: str
    worker_release_id: str
    host_cgroup: str
    worker_cgroup_parent: str
    docker_endpoint: str
    docker_binary: str
    skopeo_binary: str
    docker_release_id: str
    skopeo_release_id: str
    grants: tuple[BuilderGrant, ...]
    images: tuple[BuilderImage, ...]
    admission: BuilderAdmissionConfig
    resources: ResourceBudget = field(default_factory=ResourceBudget)
    native_engine: NativeEngineConfig | None = None
    cpu: int = 1
    memory_mb: int = 4096
    host_cpu: int = 1
    host_overhead_mb: int = 512
    max_concurrency: int = 1
    cleanup_timeout_seconds: int = 60
    build_timeout_seconds: int = 3600
    owner_idle_seconds: int = 120
    command_timeout_seconds: int = 30
    max_context_bytes: int = 512 * 1024 * 1024
    max_context_files: int = 10000
    max_export_bytes: int = 4 * 1024 * 1024 * 1024
    max_records: int = 10000
    worker_uid: int = 1000
    network_id: str | None = None
    proxy_container_id: str | None = None
    proxy_image_id: str | None = None
    proxy_release_id: str | None = None
    proxy_url: str | None = None
    ip_binary: str = "/usr/sbin/ip"
    ip_release_id: str | None = None
    resource_mode: str = "bounded"

    def __post_init__(self):
        for name in ("endpoint", "state_root", "host_cgroup", "worker_cgroup_parent",
                     "docker_endpoint", "docker_binary", "skopeo_binary", "ip_binary"):
            absolute(getattr(self, name))
        for name in ("release_id", "worker_release_id", "docker_release_id", "skopeo_release_id"):
            identifier(getattr(self, name))
        if self.ip_release_id is not None:
            identifier(self.ip_release_id)
        if not isinstance(self.worker_image_id, str) or not IMAGE_ID.fullmatch(self.worker_image_id):
            raise ValueError("worker requires a locally installed immutable image ID")
        bounds = {
            "cpu": 1, "memory_mb": 4096, "host_cpu": 1, "host_overhead_mb": 512,
            "max_concurrency": 1, "cleanup_timeout_seconds": 60,
            "build_timeout_seconds": 86400, "owner_idle_seconds": 3600,
            "command_timeout_seconds": 60, "max_context_bytes": 512 * 1024 * 1024,
            "max_context_files": 100000, "max_export_bytes": 4 * 1024 * 1024 * 1024,
            "max_records": 10000,
        }
        for name, maximum in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"{name} exceeds the authorized service envelope")
        if type(self.worker_uid) is not int or self.worker_uid < 1:
            raise ValueError("worker must use an unprivileged UID")
        if (not isinstance(self.grants, tuple) or not self.grants
                or any(not isinstance(item, BuilderGrant) for item in self.grants)
                or not isinstance(self.images, tuple)
                or any(not isinstance(item, BuilderImage) for item in self.images)):
            raise ValueError("service requires typed grants and images")
        if not isinstance(self.admission, BuilderAdmissionConfig):
            raise ValueError("service requires a typed persistent admission binding")
        if not isinstance(self.resources, ResourceBudget):
            raise ValueError("service requires a typed aggregate resource budget")
        self.client_policy
        if (self.cpu + self.host_cpu > self.resources.cpu
                or self.memory_mb + self.host_overhead_mb + self.resources.staging_memory_mb
                > self.resources.memory_mb
                or self.max_context_bytes > self.resources.staging_memory_mb * 1024 * 1024):
            raise ValueError("builder worker, host or context exceeds the aggregate/staging budget")
        for grant in self.grants:
            if (grant.uid != self.admission.uid or grant.client_context_root !=
                    str(Path(self.admission.metadata_root) / "bounded-image-contexts")):
                raise ValueError("all builder grants must share the admitted client UID and metadata ledger")
        keys = [(g.uid, g.tenant_id, g.project_id, g.run_id) for g in self.grants]
        if len(keys) != len(set(keys)) or len({i.alias for i in self.images}) != len(self.images):
            raise ValueError("ambiguous grant or image alias")
        network = (self.network_id, self.proxy_container_id, self.proxy_image_id,
                   self.proxy_release_id, self.proxy_url)
        if any(item is not None for item in network):
            if (not all(isinstance(item, str) for item in network)
                    or not re.fullmatch(r"[0-9a-f]{64}", self.network_id)
                    or not re.fullmatch(r"[0-9a-f]{64}", self.proxy_container_id)
                    or not IMAGE_ID.fullmatch(self.proxy_image_id)
                    or not re.fullmatch(r"http://[0-9.]+:[0-9]{1,5}", self.proxy_url)):
                raise ValueError("egress requires an exact isolated network and immutable operator proxy")
            identifier(self.proxy_release_id)
            if self.ip_release_id is None:
                raise ValueError("network verification requires an operator iproute2 release")
        elif any(grant.allow_network for grant in self.grants):
            raise ValueError("package-network grants require a commissioned isolated egress proxy")
        host, workers = Path(self.host_cgroup), Path(self.worker_cgroup_parent)
        if (host == workers or host.is_relative_to(workers) or workers.is_relative_to(host)
                or not host.is_relative_to("/sys/fs/cgroup")
                or not workers.is_relative_to("/sys/fs/cgroup")):
            raise ValueError("host and worker cgroups must be separate cgroup-v2 subtrees")
        for grant in self.grants:
            for protected in (self.state_root, self.endpoint, self.docker_endpoint):
                if (Path(protected).is_relative_to(grant.service_context_root)
                        or Path(protected).is_relative_to(grant.run_root)):
                    raise ValueError("operator state must be outside client context custody")
        if self.native_engine is not None:
            native = self.native_engine
            if not isinstance(native, NativeEngineConfig):
                raise ValueError("native engine requires typed operator policy")
            if native.endpoint in {self.endpoint, self.docker_endpoint}:
                raise ValueError("native broker must have a separate private socket")
            parent = Path(native.execution_cgroup_parent)
            if any(parent.is_relative_to(root) or Path(root).is_relative_to(parent)
                   for root in (self.host_cgroup, self.worker_cgroup_parent)):
                raise ValueError("native executions require a separate bounded cgroup subtree")
            for grant in native.grants:
                matches = [item for item in self.grants if (
                    item.uid, item.tenant_id, item.project_id, item.run_id, item.target_snapshot, item.run_root
                ) == (grant.uid, grant.tenant_id, grant.project_id, grant.run_id, grant.target_snapshot, grant.run_root)]
                if len(matches) != 1:
                    raise ValueError("native grant must match one existing service run grant")
                if any(Path(protected).is_relative_to(root)
                       for protected in (native.endpoint, self.state_root, self.docker_endpoint,
                                         native.gate_binary, native.runtime_python, native.runtime_root)
                       for root in (grant.run_root, grant.target_root)):
                    raise ValueError("native control paths must be outside run and target custody")
            if any(image.allow_isolated_network for image in native.images) and self.network_id is None:
                raise ValueError("native egress requires the existing commissioned isolated proxy network")
            controls = (self.endpoint, self.state_root, self.docker_endpoint, native.endpoint,
                        native.gate_binary, native.runtime_python, native.runtime_root)
            if native.client_contract_root is not None:
                controls += (native.client_contract_root,)
            if any(Path(control).is_relative_to(mount.source_root)
                   or Path(mount.source_root).is_relative_to(control)
                   for mount in native.mounts for control in controls):
                raise ValueError("native mounts cannot expose broker control paths or their ancestors")

    @property
    def client_policy(self) -> ImageBuilderConfig:
        return ImageBuilderConfig(
            self.endpoint, self.release_id, self.grants[0].tenant_id,
            cpu=self.cpu, memory_mb=self.memory_mb, host_cpu=self.host_cpu,
            host_overhead_mb=self.host_overhead_mb, max_concurrency=self.max_concurrency,
            cleanup_timeout_seconds=self.cleanup_timeout_seconds, resource_mode=self.resource_mode)

    @property
    def requested_limits(self) -> dict:
        return self.client_policy.requested_limits


def _typed(cls, value: object):
    if not isinstance(value, dict) or set(value) - {f.name for f in fields(cls)}:
        raise ValueError(f"unknown settings in {cls.__name__}")
    try:
        return cls(**value)
    except TypeError as exc:
        raise ValueError(f"missing or invalid settings in {cls.__name__}") from exc


def load_image_builder_service(path: Path) -> ImageBuilderServiceConfig:
    with path.open("rb") as stream:
        value = tomllib.load(stream)
    if set(value) != {"image_builder_service"} or not isinstance(value["image_builder_service"], dict):
        raise ValueError("expected only [image_builder_service]")
    table = dict(value["image_builder_service"])
    table["resources"] = _typed(ResourceBudget, table.get("resources", {}))
    if "native_engine" in table:
        table["native_engine"] = parse_native_engine(table["native_engine"])
    table["admission"] = _typed(BuilderAdmissionConfig, table.get("admission"))
    for name, cls in (("grants", BuilderGrant), ("images", BuilderImage)):
        if not isinstance(table.get(name), list):
            raise ValueError(f"expected an array of {name}")
        table[name] = tuple(_typed(cls, item) for item in table[name])
    return _typed(ImageBuilderServiceConfig, table)
