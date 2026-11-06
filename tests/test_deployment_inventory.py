from __future__ import annotations

from dataclasses import replace
import hashlib

import pytest

from appsec_review.deployment import (
    Limits, Selection, extract_inventory, resolve_evidence, validate_inventory,
)
from tests.deployment_support import SNAPSHOT, document, fixture


def extract(*sources, **kwargs):
    result = extract_inventory(sources, target_snapshot=SNAPSHOT, **kwargs)
    validate_inventory(result.to_dict())
    return result


def test_compose_configurations_form_source_backed_multiservice_graph():
    sources = [
        fixture("compose.yaml", "compose", variant="production"),
        fixture("nginx.conf", "nginx", service="compose:edge", variant="production"),
        fixture("redis.conf", "redis", service="compose:cache", variant="production"),
        fixture("postgresql.conf", "postgresql", service="compose:database", variant="production"),
    ]
    graph = extract(*sources, selections=[Selection("customer", "production", ("compose.yaml",))])
    assert graph.outcome == "complete"
    services = {item.name: item for item in graph.services}
    assert set(services) == {"edge", "api", "cache", "database"}
    assert (services["edge"].product, services["edge"].declared_version) == ("nginx", "1.27.2")
    assert services["edge"].version_precision == "patch"
    assert services["edge"].identity == "101"
    assert services["database"].product == "postgresql"
    assert services["database"].declared_version == "17.2"
    assert services["database"].version_precision == "minor"
    assert all(item.selection == "selected" and item.selected_variant == "production" for item in services.values())
    proxy = next(item for item in graph.relationships if item.kind == "proxy_backend")
    assert (proxy.source_service_id, proxy.target_service_id, proxy.target_port, proxy.route) == (
        services["edge"].id, services["api"].id, 8080, "/v1/",
    )
    assert proxy.resolution == "resolved"
    assert len(proxy.evidence) >= 3
    assert {(item.source_service_id, item.target_service_id) for item in graph.relationships
            if item.kind == "depends_on"} == {
        (services["edge"].id, services["api"].id),
        (services["api"].id, services["cache"].id),
        (services["api"].id, services["database"].id),
    }
    assert any(item.role == "published" and item.port == 18088 and item.address == "127.0.0.1"
               for item in graph.listeners)
    assert {(item.port, item.address, item.tls) for item in graph.listeners if item.role == "configuration"
            and item.service_id == services["cache"].id} == {
        (6379, "127.0.0.1", False), (6379, "::1", False), (6380, "127.0.0.1", True), (6380, "::1", True),
    }
    assert all(item.effective == "unknown" for item in graph.listeners)
    assert not {"observed_listener", "proven_reachability", "dependency_installed"} & {
        item.evidence_class for item in graph.facts
    }
    by_path = {item.path: item for item in sources}
    for evidence in graph.evidence:
        assert resolve_evidence(evidence, by_path[evidence.path])


def test_kubernetes_selector_named_target_port_and_identity():
    graph = extract(fixture("kubernetes.yaml", "kubernetes"))
    assert graph.outcome == "complete"
    workload = next(item for item in graph.services if item.kind == "kubernetes_workload")
    frontend = next(item for item in graph.services if item.kind == "kubernetes_service")
    assert workload.identity == "serviceAccount:customer:application;uid:1000"
    edge = graph.relationships[0]
    assert (edge.source_service_id, edge.target_service_id, edge.target_port) == (
        frontend.id, workload.id, 8080,
    )
    assert edge.resolution == "resolved"
    assert frontend.product is None
    assert all(item.selection == "unknown" for item in graph.services)
    source = fixture("kubernetes.yaml", "kubernetes")
    for ref in graph.evidence:
        resolve_evidence(ref, source)


@pytest.mark.parametrize(("image", "product", "version", "precision"), [
    ("nginx", "nginx", None, None),
    ("nginx:latest", "nginx", None, None),
    ("nginx:1.27.0-rc1", "nginx", None, None),
    ("nginx:1", "nginx", "1", "major"),
    ("docker.io/library/redis:7.4", "redis", "7.4", "minor"),
    ("postgres:17.2-alpine", "postgresql", "17.2", "minor"),
    ("postgres@sha256:" + "a" * 64, "postgresql", None, None),
    ("customer/nginx:1.2.3", None, None, None),
    ("ghcr.io/vendor/redis:7.4.1", None, None, None),
    ("valkey/valkey:8", None, None, None),
    ("ghcr.io/microsoft/garnet:1", None, None, None),
], ids=["untagged", "latest", "prerelease", "major", "minor", "variant", "digest", "custom", "registry", "valkey", "garnet"])
def test_only_exact_repository_rules_identify_declared_product(image, product, version, precision):
    graph = extract(document(f"services:\n  app:\n    image: {image}\n    expose: [6379]\n"))
    service = graph.services[0]
    assert (service.product, service.declared_version, service.version_precision) == (product, version, precision)
    assert "running_version" in service.unknowns


@pytest.mark.parametrize(("syntax", "expected"), [
    ('"6379"', (None, None, 6379, "tcp")),
    ('"16379:6379"', (None, 16379, 6379, "tcp")),
    ('"127.0.0.1:16379:6379"', ("127.0.0.1", 16379, 6379, "tcp")),
    ('"[::1]:16379:6379/udp"', ("::1", 16379, 6379, "udp")),
], ids=["dynamic-published", "custom", "loopback", "ipv6-udp"])
def test_custom_and_default_ports_are_not_identity_or_exposure(syntax, expected):
    graph = extract(document(f"services:\n  unknown:\n    ports: [{syntax}]\n"))
    service = graph.services[0]
    assert service.product is None
    published = next(item for item in graph.listeners if item.role == "published")
    container = next(item for item in graph.listeners if item.role == "container")
    assert (published.address, published.port, container.port, container.transport) == expected
    assert "reachability" in service.unknowns


def test_overlay_conflicts_do_not_choose_last_image_port_or_selected_variant():
    first = document("services:\n  cache:\n    image: redis:7.2\n    ports: [6379]\n",
                     path="base.yaml", variant="prod")
    second = document("services:\n  cache:\n    image: redis:7.4\n    ports: [6380]\n",
                      path="override.yaml", variant="prod")
    graph = extract(first, second, selections=[Selection("customer", "prod", ("base.yaml", "override.yaml"))])
    service = graph.services[0]
    assert graph.outcome == "partial"
    assert service.declared_version is None and service.image is None
    assert service.selected_variant is None and service.selection == "unknown"
    assert {"image", "declared_version", "overlay"} <= {item.field for item in graph.conflicts}
    assert {item.port for item in graph.listeners if item.role == "container"} == {6379, 6380}
    assert graph.to_dict() == extract(second, first, selections=graph.selections).to_dict()


def test_explicit_rendered_variant_selection_does_not_merge_other_variants():
    template = "services:\n  app:\n    image: nginx:{version}\n"
    prod = document(template.format(version="1.27"), path="prod.yaml", variant="prod")
    dev = document(template.format(version="1.26"), path="dev.yaml", variant="dev")
    graph = extract(prod, dev, selections=[Selection("customer", "prod", ("prod.yaml",))])
    assert {(item.variant, item.selection, item.declared_version) for item in graph.services} == {
        ("prod", "selected", "1.27"), ("dev", "not_selected", "1.26"),
    }


def test_platform_scope_excludes_garnet_without_excluding_customer_redis():
    platform = document("services:\n  platform-cache:\n    image: redis:7.4\n    ports: [6379]\n",
                        path="platform.yaml", scope="analysis_platform")
    target = document("services:\n  redis:\n    image: redis:7.4\n    labels:\n      appsec.scope: excluded\n",
                      path="customer.yaml")
    graph = extract(platform, target)
    assert [item.name for item in graph.services] == ["redis"]
    assert any(item.disposition == "excluded" for item in graph.coverage)
    assert not any(item.path == "platform.yaml" for item in graph.evidence)
    assert graph.outcome == "partial"  # Target labels are unhandled data, not trusted exclusions.
    assert "no_target_sources" in {gap.code for gap in extract(platform).gaps}


@pytest.mark.parametrize(("format", "text", "code"), [
    ("compose", "services:\n  a: {}\n  a: {}\n", "duplicate_key"),
    ("compose", "services: [}", "invalid_yaml"),
    ("compose", "services: []", "expected_mapping"),
    ("compose", "services:\n  a:\n    ports: [true]\n", "expected_scalar"),
    ("compose", "services:\n  a:\n    ports: [65536]\n", "invalid_port"),
    ("compose", "services:\n  a:\n    ports: [0]\n", "invalid_port"),
    ("nginx", "http { server { listen 80; }", "invalid_nginx"),
    ("nginx", 'http { server { listen "80; } }', "invalid_nginx"),
    ("redis", 'port "6379', "invalid_configuration"),
    ("postgresql", "port = not-a-number", "invalid_port"),
    ("redis", "port 1 2", "invalid_port"),
], ids=["duplicate", "yaml", "mapping", "boolean", "high-port", "zero", "braces", "quote", "redis-quote", "pg-port", "args"])
def test_malformed_sources_publish_no_partial_facts(format, text, code):
    graph = extract(document(text, format))
    assert graph.outcome == "malformed"
    assert not graph.services and not graph.evidence and not graph.listeners
    assert code in {item.code for item in graph.gaps}


@pytest.mark.parametrize(("format", "text", "outcome", "code"), [
    ("terraform", 'resource "redis" "cache" {}', "unsupported", "unsupported_format"),
    ("compose", "services: &s {a: {image: nginx}}", "unsupported", "yaml_alias"),
    ("compose", "services: !custom {}", "unsupported", "yaml_tag"),
    ("compose", "services:\n  a:\n    image: ${IMAGE}\n    ports: [\"${PORT}:80\"]", "partial", "dynamic_image"),
    ("nginx", "include conf.d/*.conf;", "partial", "unsupported_directive"),
    ("redis", "include redis.local.conf", "partial", "unsupported_directive"),
    ("postgresql", "include = 'other.conf'", "partial", "unsupported_directive"),
    ("kubernetes", "apiVersion: v1\nkind: Secret\nmetadata:\n  name: credentials", "unsupported", "unsupported_resource"),
], ids=["terraform", "alias", "tag", "dynamic", "nginx-include", "redis-include", "pg-include", "k8s-secret"])
def test_unsupported_or_dynamic_input_is_named_coverage(format, text, outcome, code):
    graph = extract(document(text, format))
    assert graph.outcome == outcome
    assert code in {item.code for item in graph.gaps}


def test_bounds_reject_before_extraction_without_silent_truncation():
    source = fixture("compose.yaml", "compose")
    for limits in (Limits(max_document_bytes=10), Limits(max_total_bytes=10),
                   Limits(max_nodes=5), Limits(max_depth=1), Limits(max_records=2)):
        graph = extract(source, limits=limits)
        assert graph.outcome == "partial"
        assert not graph.services and not graph.listeners and graph.gaps
    graph = extract(source, replace(source, path="other.yaml"), limits=Limits(max_documents=1))
    assert graph.outcome == "partial" and not graph.services


def test_source_digest_mismatch_binary_and_absent_input():
    source = fixture("compose.yaml", "compose")
    changed = replace(source, data=source.data + b"# changed")
    assert extract(changed).outcome == "malformed"
    assert extract(document(b"\xff")).outcome == "malformed"
    assert extract(document(b"\x00")).outcome == "malformed"
    assert extract().outcome == "partial"
    assert extract(source, source).outcome == "malformed"


def test_evidence_preserves_utf8_crlf_and_rejects_changed_bytes_or_offsets():
    source = document("# caf\u00e9\r\nservices:\r\n  app:\r\n    image: nginx:1.27\r\n")
    graph = extract(source)
    ev = next(item for item in graph.evidence if item.rule == "image.nginx.v1")
    assert resolve_evidence(ev, source) == b"    image: nginx:1.27\r\n"
    with pytest.raises(ValueError, match="identity"):
        resolve_evidence(ev, replace(source, data=source.data.replace(b"\r\n", b"\n")))
    with pytest.raises(ValueError, match="line span"):
        resolve_evidence(replace(ev, start_line=1), source)
    assert hashlib.sha256(source.data).hexdigest() == ev.sha256


def test_configuration_defaults_and_secrets_do_not_become_facts():
    graph = extract(document('requirepass "do-not-publish-me"\n', "redis"))
    assert not graph.listeners and graph.services[0].product is None
    assert "port_unknown" in {item.code for item in graph.gaps}
    assert "do-not-publish-me" not in str(graph.to_dict())
    assert not extract(document("port 0\ntls-port 0\n", "redis")).listeners
    configured = extract(document("port 6388\nbind 127.0.0.1\nport 6399\n", "redis"))
    assert any(item.field == "configuration.port" for item in configured.conflicts)
    assert {item.port for item in configured.listeners} == {6388, 6399}


def test_proxy_dynamic_backend_and_missing_configuration_binding_remain_unknown():
    source = document("http { server { listen 8080; location / { proxy_pass http://$backend; } } }",
                      "nginx", service="compose:missing")
    graph = extract(source)
    assert graph.outcome == "partial"
    assert {"dynamic_proxy", "binding_unresolved"} <= {item.code for item in graph.gaps}
    assert not graph.relationships


def test_kubernetes_unmatched_selectors_named_ports_and_namespaces_do_not_join():
    source = fixture("kubernetes.yaml", "kubernetes")
    text = source.data.decode().replace("targetPort: web", "targetPort: missing")
    graph = extract(document(text, "kubernetes"))
    assert graph.relationships[0].resolution == "unresolved"
    text = source.data.decode().replace("port: 80", "port: 80\n      protocol: UDP")
    graph = extract(document(text, "kubernetes"))
    assert graph.relationships[0].resolution == "unresolved"
    assert graph.relationships[0].target_service_id is None
    text = source.data.decode().replace("namespace: customer", "namespace: foreign", 1)
    graph = extract(document(text, "kubernetes"))
    assert graph.relationships[0].resolution == "unresolved"


@pytest.mark.parametrize("kind", ["Deployment", "StatefulSet", "DaemonSet"])
def test_supported_kubernetes_workload_kinds(kind):
    source = fixture("kubernetes.yaml", "kubernetes")
    graph = extract(document(source.data.decode().replace("kind: Deployment", "kind: " + kind), "kubernetes"))
    assert graph.outcome == "complete"
    assert any(f":{kind}:api:http" in item.key for item in graph.services)
    assert graph.relationships[0].target_service_id is not None


def test_kubernetes_pod_host_port_and_container_identity_override():
    graph = extract(document("""
apiVersion: v1
kind: Pod
metadata: {name: api}
spec:
  securityContext: {runAsUser: 1000}
  containers:
    - name: worker
      image: nginx
      securityContext: {runAsUser: 0}
      ports:
        - {containerPort: 8080, hostPort: 18080, hostIP: "127.0.0.1"}
""", "kubernetes"))
    assert graph.outcome == "complete"
    assert graph.services[0].identity == "uid:0"
    assert {(item.role, item.port) for item in graph.listeners} == {("published", 18080), ("container", 8080)}


def test_source_failure_is_atomic_while_other_sources_still_publish():
    good = document("services:\n  good:\n    image: nginx\n", path="good.yaml")
    bad = document("services:\n  first:\n    image: redis\n  second:\n    ports: [false]\n", path="bad.yaml")
    graph = extract(good, bad)
    assert graph.outcome == "partial" and [item.name for item in graph.services] == ["good"]
    assert not any(item.path == "bad.yaml" for item in graph.evidence)
    assert {item.outcome for item in graph.coverage} == {"complete", "malformed"}


def test_repeated_nginx_upstreams_are_ambiguous_and_stream_upstreams_do_not_join_http():
    text = """http {
  upstream backend { server api:8080; }
  upstream backend { server db:5432; }
  server { listen 8088; location / { proxy_pass http://backend; } }
}"""
    graph = extract(document(text, "nginx"))
    assert graph.outcome == "partial" and graph.relationships[0].resolution == "ambiguous"
    assert graph.relationships[0].target_service_id is None
    graph = extract(document("""
stream { upstream backend { server redis:6379; } }
http { server { listen 8088; location / { proxy_pass http://backend; } } }
""", "nginx"))
    assert graph.relationships[0].target == "backend"
    assert graph.relationships[0].target_port is None


def test_nginx_worker_identity_does_not_conflict_with_container_user():
    graph = extract(document("services:\n  edge:\n    image: nginx\n    user: '101'\n"),
                    document("user nginx nginx;", "nginx", "nginx.conf", service="compose:edge"))
    assert graph.services[0].identity == "101" and not graph.conflicts
    assert any("nginx:nginx" in item.detail for item in graph.facts)


@pytest.mark.parametrize("image", ["nginx@bad", "nginx:7@sha256:bad", "user:password@registry/repo", "nginx:bad tag"])
def test_invalid_image_references_do_not_emit_unverified_identity_or_credentials(image):
    graph = extract(document(f"services:\n  app:\n    image: '{image}'\n"))
    assert graph.outcome == "malformed" and not graph.services
    assert "password" not in str(graph.to_dict())


def test_additional_bounds_and_protocol_configurations():
    exposed = extract(document("services:\n  db:\n    ports:\n      - {target: 5432, published: 15432, protocol: sctp}\n"))
    assert {item.transport for item in exposed.listeners} == {"sctp"}
    nested = "http { " * 5 + "}" * 5
    assert extract(document(nested, "nginx"), limits=Limits(max_depth=2)).outcome == "partial"
    assert extract(document("port 6379\n" * 10, "redis"), limits=Limits(max_nodes=2)).outcome == "partial"
    ranges = extract(document('services:\n  app:\n    ports: ["8000-8002:80-82"]\n'))
    assert ranges.outcome == "partial" and not ranges.listeners
    bad_proxy = extract(document("http { server { location / { proxy_pass http://api:0; } } }", "nginx"))
    assert bad_proxy.outcome == "malformed"


def test_cross_deployment_service_names_never_join():
    first = document("services:\n  edge:\n    depends_on: [cache]\n", deployment="one")
    second = document("services:\n  cache:\n    image: redis\n", path="other.yaml", deployment="two")
    graph = extract(first, second)
    assert graph.relationships[0].resolution == "unresolved"
    assert graph.relationships[0].target_service_id is None


@pytest.mark.parametrize("format", ["compose", "redis", "nginx"])
def test_oversized_literals_are_partial_not_invalid_output_or_invented_facts(format):
    literal = "x" * 5000
    text = {"compose": "services:\n  app:\n    image: " + literal,
            "redis": "bind " + literal, "nginx": "user " + literal + ";"}[format]
    graph = extract(document(text, format))
    assert graph.outcome == "partial" and not graph.services
    assert "scalar_limit" in {item.code for item in graph.gaps}


def test_unchanged_evidence_resolves_trailing_blank_lines():
    source = document(b"port 6379\n\n", "redis")
    graph = extract(source)
    assert graph.outcome == "complete"
    assert graph.evidence
    for reference in graph.evidence:
        assert resolve_evidence(reference, source) == source.data[reference.start_byte:reference.end_byte]


@pytest.mark.parametrize("reverse", [False, True], ids=["original-order", "reversed-order"])
@pytest.mark.parametrize("target_port", ["web", "6379"], ids=["named", "numeric"])
def test_duplicate_kubernetes_declarations_cannot_synthesize_selector_join(reverse, target_port):
    source = document("""
apiVersion: v1
kind: Pod
metadata: {name: cache, labels: {app: old}}
spec:
  containers:
    - name: cache
      image: redis
      ports: [{name: web, containerPort: 6379}]
---
apiVersion: v1
kind: Pod
metadata: {name: cache, labels: {app: new}}
spec:
  containers:
    - name: cache
      image: redis
      ports: [{name: other, containerPort: 6380}]
---
apiVersion: v1
kind: Service
metadata: {name: frontend}
spec:
  selector: {app: new}
  ports: [{port: 80, targetPort: web}]
""", "kubernetes")
    declarations = source.data.decode().split("---")
    if reverse:
        declarations[:2] = reversed(declarations[:2])
    source = document("---".join(declarations).replace("targetPort: web", f"targetPort: {target_port}"), "kubernetes")
    graph = extract(source)
    assert graph.outcome == "partial"
    assert {(item.name, item.port) for item in graph.listeners if item.role == "container"} == {
        ("web", 6379), ("other", 6380),
    }
    assert not any(item.resolution == "resolved" for item in graph.relationships)
    assert {item.resolution for item in graph.relationships} == {"ambiguous"}
    assert "duplicate_resource" in {item.code for item in graph.gaps}
    for reference in graph.evidence:
        resolve_evidence(reference, source)


def test_service_account_overflow_returns_valid_outcome():
    source = document(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: cache}\nspec:\n"
        f"  serviceAccountName: {'a' * 4096}\n"
        "  containers: [{name: cache, image: redis}]\n",
        "kubernetes",
    )
    graph = extract(source)
    assert graph.outcome == "malformed"
    assert not graph.services and not graph.evidence
    assert "invalid_service_account" in {item.code for item in graph.gaps}


@pytest.mark.parametrize(("filename", "format"), [
    ("compose.yaml", "compose"), ("kubernetes.yaml", "kubernetes"), ("nginx.conf", "nginx"),
    ("redis.conf", "redis"), ("postgresql.conf", "postgresql"),
], ids=["compose", "kubernetes", "nginx", "redis", "postgresql"])
@pytest.mark.parametrize("ending", [b"\n\n", b"\n\n\n", b"\r\n\r\n", b"\r\n\r\n\r\n"],
                         ids=["lf-one-blank", "lf-two-blanks", "crlf-one-blank", "crlf-two-blanks"])
def test_every_format_preserves_resolving_trailing_blank_line_evidence(filename, format, ending):
    data = fixture(filename, format).data.rstrip(b"\r\n")
    if ending.startswith(b"\r\n"):
        data = data.replace(b"\n", b"\r\n")
    source = document(data + ending, format, filename)
    graph = extract(source)
    assert graph.evidence
    for reference in graph.evidence:
        assert resolve_evidence(reference, source) == source.data[reference.start_byte:reference.end_byte]
    if format in {"redis", "postgresql", "nginx"}:
        assert any(reference.end_byte == len(source.data) for reference in graph.evidence)


def test_duplicate_resource_ambiguity_covers_changed_container_names_and_service_declarations():
    pod = """apiVersion: v1
kind: Pod
metadata: {{name: cache, labels: {{app: cache}}}}
spec:
  containers:
    - name: {container}
      image: redis
      ports: [{{name: web, containerPort: 6379}}]
"""
    frontend = """apiVersion: v1
kind: Service
metadata: {name: frontend}
spec:
  selector: {app: cache}
  ports: [{port: 80, targetPort: web}]
"""
    graph = extract(document("---\n".join([
        pod.format(container="old"), pod.format(container="new"), frontend,
    ]), "kubernetes"))
    assert {(item.kind, "duplicate_declaration" in item.unknowns) for item in graph.services} == {
        ("kubernetes_workload", True), ("kubernetes_service", False),
    }
    assert {item.resolution for item in graph.relationships} == {"ambiguous"}
    assert len([item for item in graph.listeners if item.role == "container"]) == 2
    healthy = pod.format(container="healthy").replace("name: cache, labels:", "name: healthy, labels:")
    graph = extract(document("---\n".join([
        pod.format(container="old"), pod.format(container="new"), healthy, frontend,
    ]), "kubernetes"))
    healthy_id = next(item.id for item in graph.services if item.name == "healthy")
    assert {item.target_service_id for item in graph.relationships if item.resolution == "resolved"} == {healthy_id}
    assert any(item.resolution == "ambiguous" for item in graph.relationships)
    graph = extract(document("---\n".join([pod.format(container="one"), frontend, frontend]), "kubernetes"))
    assert {item.resolution for item in graph.relationships} == {"ambiguous"}
    assert graph.outcome == "partial"


@pytest.mark.parametrize(("account", "valid"), [
    ("a" * 253, True), ("a" * 254, False), ("valid.account-name", True),
    ("Invalid", False), ("namespace/account", False), ("-invalid", False), ("", False),
], ids=["max-name", "over-max-name", "dns-subdomain", "uppercase", "slash", "leading-hyphen", "empty"])
def test_service_account_identifiers_are_bounded_before_identity_assembly(account, valid):
    source = document(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: cache}\nspec:\n"
        f"  serviceAccountName: '{account}'\n"
        "  securityContext: {runAsUser: 1234567890}\n"
        "  containers: [{name: cache, image: redis}]\n",
        "kubernetes",
    )
    graph = extract(source)
    if valid:
        assert graph.outcome == "complete"
        assert graph.services[0].identity == f"serviceAccount:default:{account};uid:1234567890"
    else:
        assert graph.outcome == "malformed" and not graph.services
        assert "invalid_service_account" in {item.code for item in graph.gaps}


def test_constructed_fact_overflow_is_a_valid_partial_outcome_not_truncation():
    source = document(
        "apiVersion: v1\nkind: Service\nmetadata: {name: frontend}\nspec:\n"
        f"  type: {'a' * 4096}\n"
        "  selector: {app: cache}\n  ports: [{port: 80}]\n",
        "kubernetes",
    )
    graph = extract(source)
    assert graph.outcome == "partial" and not graph.services and not graph.facts and not graph.evidence
    assert "scalar_limit" in {item.code for item in graph.gaps}


def test_evidence_line_boundaries_cannot_be_forged_with_midline_offsets():
    source = document(b"port 6379\n\n", "redis")
    reference = extract(source).evidence[0]
    with pytest.raises(ValueError, match="line span"):
        resolve_evidence(replace(reference, start_byte=reference.start_byte + 1), source)
