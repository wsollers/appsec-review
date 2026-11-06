"""Compile bounded, source-backed declarations without selecting effective runtime values."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict
import hashlib
import re

from appsec_review.storage import canonical_json

from .builder import Builder, Claim
from .catalog import FORMAT_COVERAGE, catalog_sha256
from .configuration import nginx, simple_configuration
from .descriptors import compose, kubernetes
from .model import (
    Conflict, Coverage, Fact, Gap, Inventory, Limits, Outcome, Relationship, Selection, Service, SourceDocument, identity,
)
from .parsing import ParseError, yaml_documents


def _outcome(coverage: list[Coverage], gaps: list[Gap]) -> Outcome:
    outcomes = [item.outcome for item in coverage if item.disposition == "analyzed"]
    if not outcomes:
        return "partial"
    if all(item == "malformed" for item in outcomes):
        return "malformed"
    if all(item == "unsupported" for item in outcomes):
        return "unsupported"
    return "partial" if gaps or any(item != "complete" for item in outcomes) else "complete"


def extract_inventory(documents: Sequence[SourceDocument], *, target_snapshot: str,
                      selections: Sequence[Selection] = (), limits: Limits = Limits()) -> Inventory:
    """No I/O. Inputs must already be bounded/admitted by the existing job boundary.

    A source failure is transactional: no facts from that document survive. Missing,
    unsupported and malformed input remains visible in coverage, even alongside successes.
    """
    if not isinstance(target_snapshot, str) or not target_snapshot.strip() or len(target_snapshot) > 256:
        raise ValueError("a bounded target snapshot identity is required")
    graph = Inventory(target_snapshot, catalog_sha256=catalog_sha256())
    if len(documents) > limits.max_documents or sum(len(item.data) for item in documents) > limits.max_total_bytes:
        graph.outcome = "partial"
        graph.gaps.append(Gap("input_limit", "input set exceeds document count or byte bound; nothing analyzed"))
        return graph
    if len(selections) > limits.max_documents or len({item.deployment for item in selections}) != len(selections):
        raise ValueError("at most one bounded selected variant per deployment is allowed")
    graph.selections = sorted(selections, key=lambda item: item.deployment)
    if any(not isinstance(item.sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", item.sha256)
           for item in documents):
        raise ValueError("admitted source references require lowercase SHA-256 identities")
    keys = [(item.deployment, item.variant, item.path, item.scope) for item in documents]
    if len(set(keys)) != len(keys):
        graph.outcome = "malformed"
        graph.gaps.append(Gap("duplicate_source", "duplicate source identity; no input was analyzed"))
        return graph
    builders = []
    record_count = 0
    for document in sorted(documents, key=lambda item: item.reference(target_snapshot).id):
        source = document.reference(target_snapshot)
        graph.sources.append(source)
        if document.scope == "analysis_platform":
            graph.coverage.append(Coverage(source.id, "complete", "excluded", (), ()))
            continue
        builder = None
        try:
            if len(document.data) > limits.max_document_bytes:
                raise ParseError("input_limit", "source exceeds document byte bound", "partial")
            if hashlib.sha256(document.data).hexdigest() != document.sha256:
                raise ParseError("source_identity", "source bytes differ from admitted SHA-256")
            if document.format not in FORMAT_COVERAGE:
                raise ParseError("unsupported_format", "source format has no static extractor", "unsupported")
            text = document.data.decode("utf-8")
            if not text.strip() or "\x00" in text:
                raise ParseError("empty_or_binary", "source is empty or contains NUL")
            builder = Builder(document, target_snapshot, limits)
            if document.format in {"compose", "kubernetes"}:
                roots = yaml_documents(text, limits)
                if document.format == "compose":
                    compose(builder, roots)
                else:
                    kubernetes(builder, roots)
            elif document.format == "nginx":
                nginx(builder, text)
            else:
                simple_configuration(builder, text)
            builder.bound()
            record_count += sum(len(getattr(builder.graph, key)) for key in (
                "services", "listeners", "relationships", "facts", "evidence", "gaps",
            )) + len(builder.routes) + len(builder.claims)
            if record_count > limits.max_records:
                raise ParseError("record_limit", "combined extraction record bound exceeded", "partial")
            status: Outcome
            if not builder.graph.services and builder.graph.gaps:
                status = "unsupported"
            else:
                status = "partial" if builder.graph.gaps else "complete"
            graph.coverage.append(Coverage(source.id, status, "analyzed", tuple(sorted(builder.rules)),
                                           tuple(builder.graph.gaps)))
            builders.append(builder)
        except UnicodeDecodeError:
            gap = Gap("invalid_encoding", "source is not UTF-8", source.id)
            graph.coverage.append(Coverage(source.id, "malformed", "analyzed", (), (gap,)))
        except ParseError as exc:
            gap = Gap(exc.code, exc.message, source.id)
            graph.coverage.append(Coverage(source.id, exc.outcome, "analyzed", (), (gap,)))
    for item in graph.coverage:
        graph.gaps.extend(item.gaps)
    _combine(graph, builders)
    _select(graph, selections)
    try:
        _relationships(graph, builders, limits)
    except ParseError as exc:
        graph.gaps.append(Gap(exc.code, exc.message))
    count = sum(len(getattr(graph, key)) for key in (
        "services", "listeners", "relationships", "facts", "evidence", "conflicts", "gaps",
    ))
    if count > limits.max_records:
        # Do not publish a plausible-looking prefix of an oversized graph.
        graph.services.clear()
        graph.listeners.clear()
        graph.relationships.clear()
        graph.facts.clear()
        graph.evidence.clear()
        graph.conflicts.clear()
        graph.gaps = [Gap("record_limit", "combined graph exceeds record bound; facts discarded")]
        graph.coverage = [Coverage(item.source_id, "partial", item.disposition, (), tuple(graph.gaps))
                          if item.disposition == "analyzed" else item for item in graph.coverage]
    if not any(item.disposition == "analyzed" for item in graph.coverage):
        graph.gaps.append(Gap("no_target_sources", "no customer target configuration was supplied"))
    graph.outcome = _outcome(graph.coverage, graph.gaps)
    _sort(graph)
    return graph


def _combine(graph: Inventory, builders: list[Builder]) -> None:
    services: dict[str, Service] = {}
    claims: dict[tuple[str, str], list[Claim]] = defaultdict(list)
    descriptor_sources: dict[str, list[Builder]] = defaultdict(list)
    config_sources: dict[str, list[Builder]] = defaultdict(list)
    for builder in builders:
        for item in builder.graph.services:
            if item.id not in services:
                services[item.id] = item
            else:
                existing = services[item.id]
                existing.evidence.extend(item.evidence)
                if existing.kind == "configuration" and item.kind != "configuration":
                    existing.kind, existing.name, existing.namespace = item.kind, item.name, item.namespace
            if builder.document.format in {"compose", "kubernetes"}:
                descriptor_sources[item.id].append(builder)
            else:
                config_sources[item.id].append(builder)
        for name in ("listeners", "relationships", "facts", "evidence"):
            getattr(graph, name).extend(getattr(builder.graph, name))
        for claim in builder.claims:
            claims[(claim.service_id, claim.field)].append(claim)
    graph.services = list(services.values())
    for (service_id, field), items in sorted(claims.items()):
        values = sorted({item.value for item in items})
        service = services[service_id]
        if len(values) > 1:
            graph.conflicts.append(Conflict(service_id, field, tuple(values),
                                            tuple(sorted({item.evidence for item in items}))))
            service.unknowns.append(field)
            graph.gaps.append(Gap("conflicting_declarations", f"conflicting declarations for {field}",
                                  service_id=service_id))
        elif not field.startswith("configuration."):
            setattr(service, field, values[0])
    for service in graph.services:
        descriptors = descriptor_sources[service.id]
        if len(descriptors) > 1:
            service.product = service.image = service.declared_version = service.version_precision = None
            service.identity = None
            service.unknowns.append("overlay_order_and_effective_values")
            graph.conflicts.append(Conflict(
                service.id, "overlay", tuple(sorted(item.source.path for item in descriptors)),
                tuple(sorted(set(service.evidence))),
            ))
            graph.gaps.append(Gap("unresolved_overlay", "multiple declarations are not implicitly merged",
                                  service_id=service.id))
        if service.kind == "configuration" and any(item.document.service for item in config_sources[service.id]):
            graph.gaps.append(Gap("binding_unresolved", "configuration binding has no supplied descriptor service",
                                  service_id=service.id))
            service.unknowns.append("configuration_binding")
        # Conflicting repository/version declarations cannot leave a plausible version behind.
        fields = {item.field for item in graph.conflicts if item.service_id == service.id}
        if fields & {"product", "image"}:
            service.declared_version = service.version_precision = None
        if "declared_version" in fields:
            service.version_precision = None
        for name in ("product", "declared_version", "identity"):
            if getattr(service, name) is None:
                service.unknowns.append(name)


def _select(graph: Inventory, selections: Sequence[Selection]) -> None:
    sources = {item.id: item for item in graph.sources}
    evidence = {item.id: item for item in graph.evidence}
    complete_sources = {item.source_id for item in graph.coverage if item.outcome == "complete"}
    valid: dict[str, Selection] = {}
    for selection in selections:
        admitted = {item.path for item in graph.sources if item.scope == "target"
                    and item.deployment == selection.deployment and item.variant == selection.variant}
        if set(selection.paths) <= admitted:
            valid[selection.deployment] = selection
        else:
            graph.gaps.append(Gap("selection_unresolved", "selected paths do not resolve supplied variant sources"))
    for service in graph.services:
        chosen = valid.get(service.deployment)
        if chosen is None:
            service.unknowns.append("selected_variant")
            continue
        if service.variant != chosen.variant:
            service.selection = "not_selected"
            continue
        declared_sources = {evidence[item].source_id for item in service.evidence}
        matching = [sources[item] for item in declared_sources
                    if sources[item].path in chosen.paths and sources[item].format in {"compose", "kubernetes"}]
        if (not matching or any(item.id not in complete_sources for item in matching)
                or "overlay_order_and_effective_values" in service.unknowns):
            service.unknowns.append("selected_variant")
            continue
        service.selection, service.selected_variant = "selected", chosen.variant
        graph.facts.append(Fact(service.id, "selected_deployment",
                                "adapter selected supplied variant; deployed state is not established",
                                tuple(sorted(set(service.evidence)))))


def _relationships(graph: Inventory, builders: list[Builder], limits: Limits) -> None:
    services = {item.id: item for item in graph.services}
    for edge in graph.relationships:
        if edge.resolution == "ambiguous":
            continue
        source = services[edge.source_service_id]
        candidates = [item for item in graph.services if item.deployment == source.deployment
                      and item.variant == source.variant and item.name == edge.target
                      and item.kind in {"compose", "kubernetes_service"}
                      and (source.namespace is None or item.namespace == source.namespace)]
        if len(candidates) == 1:
            edge.target_service_id = candidates[0].id
            edge.resolution = "resolved"
            edge.evidence.extend(candidates[0].evidence)
        elif len(candidates) > 1:
            edge.resolution = "ambiguous"
        else:
            graph.gaps.append(Gap("relationship_unresolved", "backend or dependency has no unique target service",
                                  service_id=source.id, evidence=tuple(edge.evidence)))
    labels: dict[str, list[dict[str, str]]] = defaultdict(list)
    for builder in builders:
        for key, value in builder.labels.items():
            labels[key].append(value)
    for builder in builders:
        for route in builder.routes:
            source = services[route.service_id]
            candidates = [item for item in graph.services if item.kind == "kubernetes_workload"
                          and item.namespace == route.namespace and item.deployment == source.deployment
                          and item.variant == source.variant and len(labels[item.id]) == 1
                          and all(labels[item.id][0].get(key) == value for key, value in route.selector.items())]
            resolved = False
            for target in candidates:
                ports = [item for item in graph.listeners if item.service_id == target.id and item.role == "container"
                         and item.transport == route.transport
                         and (str(item.port) == route.target_port or item.name == route.target_port)]
                for listener in ports:
                    if len(graph.relationships) >= limits.max_records:
                        raise ParseError("record_limit", "relationship expansion exceeds record bound", "partial")
                    proof = sorted(set([route.evidence, *source.evidence, *target.evidence, *listener.evidence]))
                    payload = {
                        "source_service_id": source.id, "target_service_id": target.id, "target": target.key,
                        "target_port": listener.port, "kind": "selects", "evidence": proof,
                    }
                    graph.relationships.append(Relationship(identity("relationship", payload), source.id,
                                                            target.id, target.key, listener.port, "selects",
                                                            proof, resolution="resolved"))
                    resolved = True
            if not resolved:
                payload = {
                    "source_service_id": source.id, "target_service_id": None,
                    "target": identity("selector", route.selector),
                    "target_port": int(route.target_port) if route.target_port.isdecimal() else None,
                    "kind": "selects", "evidence": [route.evidence, *source.evidence],
                }
                graph.relationships.append(Relationship(
                    identity("relationship", payload), source.id, None,
                    identity("selector", route.selector),
                    int(route.target_port) if route.target_port.isdecimal() else None,
                    "selects", [route.evidence, *source.evidence],
                ))
                graph.gaps.append(Gap("selector_unresolved", "selector or target port has no unambiguous workload mapping",
                                      service_id=source.id, evidence=(route.evidence,)))


def _sort(graph: Inventory) -> None:
    for service in graph.services:
        service.evidence = sorted(set(service.evidence))
        service.unknowns = sorted(set(service.unknowns))
    for edge in graph.relationships:
        edge.evidence = sorted(set(edge.evidence))
        payload = asdict(edge)
        payload.pop("id")
        edge.id = identity("relationship", payload)
    for name in ("sources", "services", "listeners", "relationships", "facts", "evidence", "conflicts", "coverage", "gaps"):
        values = {canonical_json(asdict(item)): item for item in getattr(graph, name)}
        setattr(graph, name, [values[key] for key in sorted(values)])
