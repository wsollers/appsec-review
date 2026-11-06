"""Internal, per-document extraction accumulator. No store, execution or job lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from yaml.nodes import Node

from .model import (
    Evidence, EvidenceClass, Fact, Gap, Inventory, Limits, Listener, Relationship, Service, SourceDocument, identity,
)
from .parsing import ParseError, node_lines


@dataclass(frozen=True)
class Claim:
    service_id: str
    field: str
    value: str
    evidence: str


@dataclass(frozen=True)
class Route:
    service_id: str
    namespace: str
    selector: dict[str, str]
    target_port: str
    evidence: str
    transport: Literal["tcp", "udp", "sctp"]


class Builder:
    def __init__(self, document: SourceDocument, snapshot: str, limits: Limits):
        self.document = document
        self.source = document.reference(snapshot)
        self.limits = limits
        self.graph = Inventory(snapshot)
        self.graph.sources.append(self.source)
        self.claims: list[Claim] = []
        self.labels: dict[str, dict[str, str]] = {}
        self.routes: list[Route] = []
        self.rules: set[str] = set()
        self.lines = document.data.splitlines(keepends=True)
        self.offsets = [0]
        for line in self.lines:
            self.offsets.append(self.offsets[-1] + len(line))

    def bound(self) -> None:
        count = sum(len(getattr(self.graph, name)) for name in (
            "services", "listeners", "relationships", "facts", "evidence", "gaps",
        )) + len(self.claims) + len(self.routes)
        if count > self.limits.max_records:
            raise ParseError("record_limit", "extracted record bound exceeded", "partial")

    def evidence(self, location: Node | tuple[int, int], rule: str) -> str:
        start, end = node_lines(location) if isinstance(location, Node) else location
        if not 1 <= start <= end <= len(self.lines):
            raise ParseError("invalid_span", "parser produced an unresolved source span")
        payload = {
            "source_id": self.source.id, "path": self.source.path, "sha256": self.source.sha256,
            "start_line": start, "end_line": end,
            "start_byte": self.offsets[start - 1], "end_byte": self.offsets[end], "rule": rule,
        }
        value = Evidence(identity("evidence", payload), self.source.id, self.source.path, self.source.sha256,
                         start, end, self.offsets[start - 1], self.offsets[end], rule)
        if value not in self.graph.evidence:
            self.graph.evidence.append(value)
        self.rules.add(rule)
        self.bound()
        return value.id

    def gap(self, code: str, message: str, *, service: Service | None = None,
            evidence: str | None = None) -> None:
        value = Gap(code, message, self.source.id, service.id if service else None,
                    (evidence,) if evidence else ())
        if value not in self.graph.gaps:
            self.graph.gaps.append(value)
        self.bound()

    def fields(self, fields: dict[str, Node], allowed: set[str], node: Node,
               service: Service | None = None) -> None:
        for name in sorted(fields.keys() - allowed):
            self.gap("unsupported_field", f"field not interpreted: {name[:128]}",
                     service=service, evidence=self.evidence(fields[name], "coverage.unknown-field.v1"))

    def service(self, key: str, name: str, kind: Literal[
        "compose", "kubernetes_workload", "kubernetes_service", "configuration",
    ], evidence: str, namespace: str | None = None) -> Service:
        value = Service(identity("service", {
            "snapshot": self.graph.target_snapshot, "deployment": self.document.deployment,
            "variant": self.document.variant, "key": key,
        }), key, name, self.document.deployment, self.document.variant, kind, namespace)
        existing = next((item for item in self.graph.services if item.id == value.id), None)
        if existing is None:
            self.graph.services.append(value)
        else:
            value = existing
        if evidence not in value.evidence:
            value.evidence.append(evidence)
        self.bound()
        return value

    def claim(self, service: Service, name: str, value: str, evidence: str) -> None:
        self.claims.append(Claim(service.id, name, value, evidence))
        if evidence not in service.evidence:
            service.evidence.append(evidence)
        self.bound()

    def fact(self, service: Service, detail: str, evidence: str,
             evidence_class: EvidenceClass = "product_hint") -> None:
        self.graph.facts.append(Fact(service.id, evidence_class, detail, (evidence,)))
        self.bound()

    def listener(self, service: Service, address: str | None, port: int | None, evidence: str | tuple[str, ...], *,
                 transport: Literal["tcp", "udp", "sctp"] = "tcp",
                 role: Literal["container", "published", "service", "node", "configuration"] = "configuration",
                 name: str | None = None, tls: bool | None = None) -> None:
        payload = {
            "service_id": service.id, "address": address, "port": port, "transport": transport,
            "role": role, "name": name, "tls": tls, "evidence_class": "configured_listener",
            "evidence": (evidence,) if isinstance(evidence, str) else evidence,
        }
        refs = (evidence,) if isinstance(evidence, str) else evidence
        self.graph.listeners.append(Listener(identity("listener", payload), service.id, address, port,
                                              transport, role, name, tls, "configured_listener", refs))
        self.bound()

    def edge(self, service: Service, target: str, target_port: int | None, evidence: str, *,
             kind: Literal["depends_on", "proxy_backend", "selects", "routes_to"] = "proxy_backend",
             route: str | None = None) -> None:
        payload = {"source_service_id": service.id, "target": target, "target_port": target_port,
                   "kind": kind, "evidence": [evidence], "route": route}
        self.graph.relationships.append(Relationship(
            identity("relationship", payload), service.id, None, target, target_port, kind, [evidence], route=route,
        ))
        self.bound()
