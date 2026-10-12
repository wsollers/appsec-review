"""Deterministic, bounded tag-cloud rollup over validated assignment records."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from .taxonomy import BASIS_RANK, Vocabulary


CLOUD_SCHEMA = "appsec-review/tag-cloud/1"
FILL = {"confirmed": "solid", "reported": "strong-tint", "invoked": "light-tint",
        "declared": "outline", "derived": "outline"}
RED_NAMESPACES = {"surface", "capec", "attack", "vuln"}
BLUE_NAMESPACES = {"asvs5", "masvs2", "nist53r5", "ssdf", "k8s-pss", "slsa1"}
BLUE_TAGS = {"func:telemetry:audit-log", "infra:cloud:audit-log"}


def _lens(record: Mapping[str, Any]) -> set[str]:
    lenses = set()
    namespace = record["namespace"]
    if namespace in RED_NAMESPACES or (namespace == "func" and record.get("flow_role") in {"source", "sink"}):
        lenses.add("red")
    if (namespace in BLUE_NAMESPACES or record["tag"] in BLUE_TAGS or
            (namespace == "func" and record.get("flow_role") in {"guard", "sanitizer"})):
        lenses.add("blue")
    return lenses


def _component_bucket(subject: Mapping[str, Any]) -> str:
    """Bucket by component, or by ownership status so not-applicable, ambiguous, and unowned differ."""
    component_id = subject.get("component_id")
    if component_id:
        return str(component_id)
    return f"ownership:{subject.get('component_ownership') or 'unrecorded'}"


def build_cloud(vocabulary: Vocabulary, records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Size by distinct subjects and components, never by raw hit count; fill by strongest basis."""
    nodes: dict[str, dict[str, Any]] = {}
    subjects: dict[str, set[str]] = defaultdict(set)
    components: dict[str, set[str]] = defaultdict(set)
    leaves: dict[str, set[str]] = defaultdict(set)
    lenses: dict[str, set[str]] = defaultdict(set)
    rollup_gaps: set[str] = set()
    for record in records:
        namespace = vocabulary.namespaces[record["namespace"]]
        node_id = vocabulary.rollup(record["tag"])
        node = nodes.setdefault(node_id, {
            "node": node_id, "namespace": namespace.name, "family": namespace.family,
            "assignment_count": 0, "strongest_basis": record["basis"], "derived_only": True,
        })
        node["assignment_count"] += 1
        if BASIS_RANK[record["basis"]] > BASIS_RANK[node["strongest_basis"]]:
            node["strongest_basis"] = record["basis"]
        node["derived_only"] = node["derived_only"] and record["basis"] == "derived"
        subjects[node_id].add(record["subject"]["logical_id"])
        components[node_id].add(_component_bucket(record["subject"]))
        leaves[node_id].add(record["tag"])
        lenses[node_id] |= _lens(record)
        if namespace.rollup_gap:
            rollup_gaps.add(f"{namespace.name}: {namespace.rollup_gap}")
    result = []
    for node_id in sorted(nodes, key=lambda key: (nodes[key]["family"], key)):
        node = nodes[node_id]
        fill = "hatched" if node["family"] == "gap" else FILL[node["strongest_basis"]]
        result.append({**node, "fill": fill, "subject_count": len(subjects[node_id]),
                       "component_count": len(components[node_id]), "leaves": sorted(leaves[node_id]),
                       "lenses": sorted(lenses[node_id])})
    families: dict[str, int] = defaultdict(int)
    for node in result:
        families[node["family"]] += 1
    return {"schema": CLOUD_SCHEMA, "vocabulary_sha256": vocabulary.sha256, "size_metric": "component_count",
            "nodes": result, "node_count_by_family": dict(sorted(families.items())),
            "views": {lens: [node["node"] for node in result if lens in node["lenses"]]
                      for lens in ("red", "blue")},
            "rollup_gaps": sorted(rollup_gaps),
            "reading_rule": "An absent node is never evidence that a property is absent; see gap nodes."}
