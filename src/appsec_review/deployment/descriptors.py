"""Literal Compose and Kubernetes declarations; no rendering, overlay merging or execution."""

from __future__ import annotations

import re
from typing import Literal

from yaml.nodes import MappingNode, Node, ScalarNode

from .builder import Builder, Route
from .catalog import identify_image
from .model import Service
from .parsing import ParseError, dynamic, mapping, port, scalar, sequence


def _text(fields: dict[str, Node], key: str, default: str | None = None) -> str | None:
    return scalar(fields[key]) if key in fields else default


def _name(node: Node) -> str:
    value = scalar(node)
    if not value or len(value) > 256 or dynamic(value):
        raise ParseError("invalid_name", "service identity is missing, dynamic or oversized")
    return value


def _image(builder: Builder, service: Service, node: Node) -> None:
    image = scalar(node)
    ev = builder.evidence(node, "descriptor.image.v1")
    if dynamic(image):
        builder.gap("dynamic_image", "image interpolation is unresolved", service=service, evidence=ev)
        return
    if len(image) > 1024 or not re.fullmatch(
        r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?"
        r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
        r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?", image,
    ):
        raise ParseError("invalid_image", "image must be a bounded literal OCI repository reference")
    builder.claim(service, "image", image, ev)
    product, version, precision, rule = identify_image(image)
    if product is None:
        builder.gap("unsupported_image", "image repository has no supported product signature",
                    service=service, evidence=ev)
        return
    assert rule is not None
    ev = builder.evidence(node, rule)
    builder.claim(service, "product", product, ev)
    builder.fact(service, f"image repository declares {product}; runtime identity is unverified", ev)
    if version is not None:
        builder.claim(service, "declared_version", version, ev)
        assert precision is not None
        builder.claim(service, "version_precision", precision, ev)


def _transport(value: str) -> Literal["tcp", "udp", "sctp"]:
    if value.lower() == "tcp":
        return "tcp"
    if value.lower() == "udp":
        return "udp"
    if value.lower() == "sctp":
        return "sctp"
    raise ParseError("invalid_transport", "transport must be TCP, UDP or SCTP")


def _compose_port(builder: Builder, service: Service, node: Node, *, exposed: bool) -> None:
    ev = builder.evidence(node, "compose.port.v1")
    address = published = None
    transport: Literal["tcp", "udp", "sctp"] = "tcp"
    if isinstance(node, MappingNode):
        fields = mapping(node)
        builder.fields(fields, {"target", "published", "host_ip", "protocol", "name"}, node, service)
        if "target" not in fields:
            raise ParseError("missing_port", "long port syntax requires target")
        target = scalar(fields["target"], numeric=True)
        if "published" in fields:
            published = scalar(fields["published"], numeric=True)
        address = _text(fields, "host_ip")
        transport = _transport(_text(fields, "protocol", "tcp") or "")
    else:
        value = scalar(node, numeric=True)
        if dynamic(value):
            builder.gap("dynamic_port", "port interpolation is unresolved", service=service, evidence=ev)
            return
        value, separator, protocol = value.partition("/")
        if separator:
            transport = _transport(protocol)
        # A bracketed IPv6 bind is one field, not a sequence of port separators.
        match = re.fullmatch(r"(?:\[(?P<ipv6>[^\]]+)\]:|(?P<host>[^:]+):)?(?P<pub>\d+):(?P<port>\d+)", value)
        if match:
            address = match["ipv6"] or match["host"]
            published, target = match["pub"], match["port"]
        elif ":" not in value:
            target = value
        else:
            builder.gap("unsupported_port", "port range or syntax is unresolved", service=service, evidence=ev)
            return
    if any(dynamic(value) for value in (target, address or "", published or "")):
        builder.gap("dynamic_port", "port interpolation is unresolved", service=service, evidence=ev)
        return
    if "-" in target or published is not None and "-" in published:
        builder.gap("port_range", "port ranges are not expanded", service=service, evidence=ev)
        return
    target_number = port(target)
    builder.listener(service, None, target_number, ev, role="container", transport=transport)
    if not exposed:
        builder.listener(service, address, port(published) if published is not None else None, ev,
                         role="published", transport=transport)
    if exposed and published is not None:
        raise ParseError("invalid_expose", "expose cannot publish a host port")


def compose(builder: Builder, roots: list[Node]) -> None:
    if len(roots) != 1:
        raise ParseError("compose_documents", "Compose requires one document")
    root = roots[0]
    fields = mapping(root)
    builder.fields(fields, {"services", "name", "version"}, root)
    if "services" not in fields:
        raise ParseError("missing_services", "Compose document has no services")
    for name, node in mapping(fields["services"]).items():
        if not name or len(name) > 128 or dynamic(name):
            raise ParseError("invalid_name", "invalid Compose service name")
        members = mapping(node)
        ev = builder.evidence(node, "compose.service.v1")
        service = builder.service(f"compose:{name}", name, "compose", ev)
        builder.fields(members, {"image", "ports", "expose", "depends_on", "user"}, node, service)
        if "image" in members:
            _image(builder, service, members["image"])
        if "user" in members:
            user = scalar(members["user"], numeric=True)
            ev = builder.evidence(members["user"], "compose.user.v1")
            if dynamic(user):
                builder.gap("dynamic_identity", "user interpolation is unresolved", service=service, evidence=ev)
            else:
                builder.claim(service, "identity", user, ev)
        for name in ("ports", "expose"):
            if name in members:
                for value in sequence(members[name]):
                    _compose_port(builder, service, value, exposed=name == "expose")
        if "depends_on" in members:
            depends = members["depends_on"]
            if isinstance(depends, MappingNode):
                names = mapping(depends)
                for dependency, settings in names.items():
                    details = mapping(settings)
                    builder.fields(details, {"condition", "restart", "required"}, settings, service)
                    builder.edge(service, dependency, None, builder.evidence(settings, "compose.depends-on.v1"),
                                 kind="depends_on")
            else:
                for value in sequence(depends):
                    builder.edge(service, _name(value), None, builder.evidence(value, "compose.depends-on.v1"),
                                 kind="depends_on")


def _metadata(builder: Builder, node: Node) -> tuple[str, str, dict[str, str]]:
    fields = mapping(node)
    builder.fields(fields, {"name", "namespace", "labels", "annotations"}, node)
    if "name" not in fields:
        raise ParseError("missing_name", "Kubernetes resource has no name")
    labels = {key: scalar(value) for key, value in mapping(fields["labels"]).items()} if "labels" in fields else {}
    if "annotations" in fields:
        builder.gap("uninterpreted_annotations", "annotations do not grant scope or deployment authority",
                    evidence=builder.evidence(fields["annotations"], "kubernetes.annotations.v1"))
    namespace = _name(fields["namespace"]) if "namespace" in fields else "default"
    return _name(fields["name"]), namespace, labels


def kubernetes(builder: Builder, roots: list[Node]) -> None:
    seen: set[tuple[str, str, str]] = set()
    for root in roots:
        top = mapping(root)
        builder.fields(top, {"apiVersion", "kind", "metadata", "spec"}, root)
        kind = _text(top, "kind")
        api = _text(top, "apiVersion")
        if kind not in {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Service"}:
            builder.gap("unsupported_resource", "Kubernetes resource kind is not supported",
                        evidence=builder.evidence(root, "kubernetes.coverage.v1"))
            continue
        expected_api = "v1" if kind in {"Pod", "Service"} else "apps/v1"
        if api != expected_api:
            builder.gap("unsupported_api", "Kubernetes API version is not supported",
                        evidence=builder.evidence(root, "kubernetes.coverage.v1"))
            continue
        if "metadata" not in top or "spec" not in top:
            raise ParseError("missing_spec", "Kubernetes resource requires metadata and spec")
        name, namespace, labels = _metadata(builder, top["metadata"])
        resource_key = (namespace, kind, name)
        if resource_key in seen:
            builder.gap("duplicate_resource", "duplicate resource declarations may be overlays",
                        evidence=builder.evidence(root, "kubernetes.resource.v1"))
        seen.add(resource_key)
        spec_node = top["spec"]
        spec = mapping(spec_node)
        if kind == "Service":
            _kubernetes_service(builder, name, namespace, root, spec)
            continue
        if kind != "Pod":
            builder.fields(spec, {"template", "selector", "replicas"}, spec_node)
            if "selector" in spec:
                selector = mapping(spec["selector"])
                builder.fields(selector, {"matchLabels"}, spec["selector"])
                if "matchLabels" in selector:
                    for label in mapping(selector["matchLabels"]).values():
                        scalar(label)
            if "replicas" in spec:
                replicas = scalar(spec["replicas"], numeric=True)
                if not re.fullmatch(r"[0-9]{1,9}", replicas):
                    raise ParseError("invalid_replicas", "replicas must be a nonnegative integer")
            if "template" not in spec:
                raise ParseError("missing_template", "workload requires a pod template")
            template = mapping(spec["template"])
            builder.fields(template, {"metadata", "spec"}, spec["template"])
            if "metadata" in template:
                metadata = mapping(template["metadata"])
                builder.fields(metadata, {"labels", "annotations"}, template["metadata"])
                if "labels" in metadata:
                    labels = {key: scalar(value) for key, value in mapping(metadata["labels"]).items()}
                if "annotations" in metadata:
                    builder.gap("uninterpreted_annotations", "pod annotations are not interpreted",
                                evidence=builder.evidence(metadata["annotations"], "kubernetes.annotations.v1"))
            if "spec" not in template:
                raise ParseError("missing_spec", "pod template requires spec")
            spec_node = template["spec"]
            spec = mapping(spec_node)
        builder.fields(spec, {"containers", "serviceAccountName", "securityContext"}, spec_node)
        if "containers" not in spec:
            raise ParseError("missing_containers", "workload requires containers")
        pod_user = _security_user(builder, spec.get("securityContext"))
        names: set[str] = set()
        for container in sequence(spec["containers"]):
            fields = mapping(container)
            if "name" not in fields:
                raise ParseError("missing_name", "container requires name")
            container_name = _name(fields["name"])
            if container_name in names:
                raise ParseError("duplicate_container", "duplicate container name")
            names.add(container_name)
            ev = builder.evidence(container, "kubernetes.container.v1")
            service = builder.service(f"kubernetes:{namespace}:{kind}:{name}:{container_name}",
                                      name, "kubernetes_workload", ev, namespace)
            builder.labels[service.id] = labels
            builder.fields(fields, {"name", "image", "ports", "securityContext"}, container, service)
            if "image" in fields:
                _image(builder, service, fields["image"])
            account = _text(spec, "serviceAccountName")
            user = _security_user(builder, fields.get("securityContext")) or pod_user
            identity_parts = []
            if account is not None:
                if dynamic(account):
                    builder.gap("dynamic_identity", "service account interpolation is unresolved",
                                service=service, evidence=ev)
                else:
                    identity_parts.append(f"serviceAccount:{namespace}:{account}")
            if user is not None:
                identity_parts.append(f"uid:{user}")
            if identity_parts:
                builder.claim(service, "identity", ";".join(identity_parts),
                              builder.evidence(spec_node, "kubernetes.identity.v1"))
            if "ports" in fields:
                for value in sequence(fields["ports"]):
                    member = mapping(value)
                    builder.fields(member, {"name", "containerPort", "protocol", "hostIP", "hostPort"},
                                   value, service)
                    if "containerPort" not in member:
                        raise ParseError("missing_port", "container port requires containerPort")
                    number = port(scalar(member["containerPort"], numeric=True))
                    ev = builder.evidence(value, "kubernetes.container-port.v1")
                    protocol = _transport(_text(member, "protocol", "TCP") or "")
                    builder.listener(service, None, number, ev, role="container", transport=protocol,
                                     name=_text(member, "name"))
                    if "hostPort" in member:
                        builder.listener(service, _text(member, "hostIP"),
                                         port(scalar(member["hostPort"], numeric=True)), ev,
                                         role="published", transport=protocol)


def _security_user(builder: Builder, node: Node | None) -> str | None:
    if node is None:
        return None
    fields = mapping(node)
    builder.fields(fields, {"runAsUser"}, node)
    if "runAsUser" not in fields:
        return None
    value = scalar(fields["runAsUser"], numeric=True)
    if not re.fullmatch(r"[0-9]{1,10}", value):
        raise ParseError("invalid_user", "runAsUser must be a nonnegative integer")
    return value


def _kubernetes_service(builder: Builder, name: str, namespace: str, root: Node,
                        spec: dict[str, Node]) -> None:
    ev = builder.evidence(root, "kubernetes.service.v1")
    service = builder.service(f"kubernetes:{namespace}:Service:{name}", name, "kubernetes_service", ev, namespace)
    builder.fields(spec, {"selector", "ports", "type", "clusterIP"}, root, service)
    selector = {key: scalar(value) for key, value in mapping(spec["selector"]).items()} if "selector" in spec else {}
    if not selector:
        builder.gap("selector_unknown", "selectorless service endpoints are unresolved", service=service, evidence=ev)
    if "type" in spec:
        builder.fact(service, f"Kubernetes Service declares type {scalar(spec['type'])}; exposure is unproven", ev,
                     "deployment_declaration")
    if "ports" not in spec:
        builder.gap("ports_unknown", "service has no declared ports", service=service, evidence=ev)
        return
    for node in sequence(spec["ports"]):
        fields = mapping(node)
        builder.fields(fields, {"name", "port", "targetPort", "nodePort", "protocol"}, node, service)
        if "port" not in fields:
            raise ParseError("missing_port", "service port requires port")
        value = scalar(fields["port"], numeric=True)
        number = port(value)
        ev = builder.evidence(node, "kubernetes.service-port.v1")
        protocol = _transport(_text(fields, "protocol", "TCP") or "")
        builder.listener(service, _text(spec, "clusterIP"), number, ev, role="service",
                         transport=protocol, name=_text(fields, "name"))
        if "nodePort" in fields:
            builder.listener(service, None, port(scalar(fields["nodePort"], numeric=True)), ev,
                             role="node", transport=protocol)
        target_port = scalar(fields["targetPort"], numeric=True) if "targetPort" in fields else value
        if target_port.isdecimal():
            port(target_port)
        elif not re.fullmatch(r"[a-z][a-z0-9-]{0,14}", target_port):
            raise ParseError("invalid_target_port", "targetPort must be a literal port or port name")
        if selector:
            builder.routes.append(Route(service.id, namespace, selector, target_port, ev, protocol))
        builder.bound()
