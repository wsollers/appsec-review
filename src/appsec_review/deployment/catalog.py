"""Versioned detection rules, not a list of vendors claimed as supported."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import re
from typing import Any

from appsec_review.storage import canonical_json

from .model import CATALOG_SCHEMA, EvidenceClass


@dataclass(frozen=True)
class Signature:
    product: str
    family: str
    image_repositories: tuple[str, ...]
    configuration_format: str
    directives: tuple[str, ...]
    rule: str
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceRule:
    id: str
    format: str
    evidence_class: EvidenceClass
    meaning: str


SIGNATURES = (
    Signature("nginx", "edge_proxy_web", ("nginx", "library/nginx", "docker.io/library/nginx"),
              "nginx", ("listen", "upstream", "server", "proxy_pass", "user"),
              "image.nginx.v1", ("image tags are declarations, not binary versions",
                                 "includes, variables, regex locations and modules are unresolved")),
    Signature("redis", "cache_search", ("redis", "library/redis", "docker.io/library/redis"),
              "redis", ("bind", "port", "tls-port", "requirepass", "aclfile", "protected-mode"),
              "image.redis.v1", ("no implicit default listener", "includes and ACL file contents are unresolved",
                                 "Valkey and Garnet are not identified as Redis")),
    Signature("postgresql", "databases", ("postgres", "library/postgres", "docker.io/library/postgres"),
              "postgresql", ("listen_addresses", "port", "ssl", "password_encryption"),
              "image.postgresql.v1", ("pg_hba.conf and include files are unresolved",
                                      "declarations do not prove authentication or TLS enforcement")),
)

FORMAT_COVERAGE = {
    "compose": ("services", "image", "ports", "expose", "depends_on", "user"),
    "kubernetes": ("Pod", "Deployment", "StatefulSet", "DaemonSet", "Service",
                   "containers", "ports", "selector", "serviceAccountName", "runAsUser"),
    "nginx": SIGNATURES[0].directives,
    "redis": SIGNATURES[1].directives,
    "postgresql": SIGNATURES[2].directives,
}
UNSUPPORTED = {
    "formats": ("helm_templates", "kustomize_overlays", "terraform", "cloudformation", "bicep",
                "ci_deployment_scripts", "dockerfile", "dependency_manifests", "source_listen_calls"),
    "edge_proxy_web": ("apache_httpd", "iis", "envoy", "haproxy", "traefik", "caddy"),
    "databases": ("mysql", "mariadb", "sql_server", "mongodb", "rds", "aurora", "azure_sql", "cloud_sql"),
    "cache_search": ("valkey", "garnet", "memcached", "elasticsearch", "opensearch"),
    "messaging": ("kafka", "rabbitmq", "nats", "sqs", "sns", "service_bus", "pubsub"),
    "storage": ("s3", "azure_blob", "gcs", "smb", "nfs", "volume_permissions"),
    "compute_platform": ("ecs", "ec2", "aks_cloud_metadata", "gke_cloud_metadata", "lambda",
                         "functions", "cloud_run", "container_apps", "network_policy", "ingress"),
    "identity_secrets": ("entra", "cognito", "keycloak", "vault", "kms", "secret_contents"),
    "admin_observability": ("endpoint_authentication", "metrics", "debug", "dashboards"),
}


def evidence_rules() -> tuple[EvidenceRule, ...]:
    rules = [
        EvidenceRule("coverage.unknown-field.v1", "structured", "deployment_declaration", "uninterpreted field"),
        EvidenceRule("descriptor.image.v1", "structured", "deployment_declaration", "literal image reference"),
        EvidenceRule("observation.import.v1", "observations", "observed_listener", "unverified imported measurement"),
    ]
    for signature in SIGNATURES:
        rules.append(EvidenceRule(signature.rule, "structured", "product_hint", "exact declared image repository"))
        fmt = signature.configuration_format
        rules.append(EvidenceRule(f"{fmt}.configuration.v1", fmt, "product_hint", "compatible configuration syntax"))
        rules.append(EvidenceRule(f"{fmt}.coverage.v1", fmt, "deployment_declaration", "uninterpreted directive"))
    for fmt, suffixes in (
        ("compose", ("port", "service", "user", "depends-on")),
        ("kubernetes", ("annotations", "coverage", "resource", "container", "identity",
                        "container-port", "service", "service-port")),
        ("nginx", ("upstream", "upstream-server", "listen", "proxy_pass", "user")),
        ("redis", SIGNATURES[1].directives),
        ("postgresql", SIGNATURES[2].directives),
    ):
        for suffix in suffixes:
            evidence_class: EvidenceClass = (
                "configured_listener" if suffix in {
                    "port", "tls-port", "listen", "container-port", "service-port", "bind", "listen_addresses",
                } else "deployment_declaration"
            )
            rules.append(EvidenceRule(f"{fmt}.{suffix}.v1", fmt, evidence_class,
                                      "literal declaration; effective behavior and enforcement are unverified"))
    return tuple(sorted(rules, key=lambda item: item.id))


def catalog() -> dict[str, Any]:
    import json

    value = json.loads(canonical_json({
        "schema": CATALOG_SCHEMA, "signatures": [asdict(item) for item in SIGNATURES],
        "evidence_rules": [asdict(item) for item in evidence_rules()],
        "formats": FORMAT_COVERAGE, "unsupported": UNSUPPORTED,
    }))
    assert isinstance(value, dict)
    return value


def catalog_sha256() -> str:
    return hashlib.sha256(canonical_json(catalog())).hexdigest()


def identify_image(image: str) -> tuple[str | None, str | None, str | None, str | None]:
    """Exact repository evidence only; ports, banners and basename suffixes never match."""
    if "$" in image or "{{" in image or any(char.isspace() for char in image):
        return None, None, None, None
    if "@" in image and not re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", image):
        return None, None, None, None
    repository_tag = image.split("@", 1)[0]
    tail = repository_tag.rsplit("/", 1)[-1]
    tag = tail.rsplit(":", 1)[1] if ":" in tail else None
    repository = repository_tag.rsplit(":", 1)[0] if tag is not None else repository_tag
    signature = next((item for item in SIGNATURES if repository in item.image_repositories), None)
    if signature is None:
        return None, None, None, None
    match = re.fullmatch(
        r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-(?:alpine(?:\d+(?:\.\d+)*)?|bookworm|bullseye|trixie))?",
        tag or "",
    )
    version = None
    precision = None
    if match:
        parts = [part for part in match.groups() if part is not None]
        version = ".".join(parts)
        precision = ("major", "minor", "patch")[len(parts) - 1]
    return signature.product, version, precision, signature.rule
