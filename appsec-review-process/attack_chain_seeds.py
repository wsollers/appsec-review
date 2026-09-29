#!/usr/bin/env python3
"""Lane 14 seeding: link candidates, entry seeds, adjacency and clusters (ADR-0016 decisions 2-5, 8).

Pure bookkeeping, no model call and no Dagster import. The inputs are the accepted
``09-independent-verification`` result (with the latest claim-ledger state per claim when the
caller has it), the code property graph records, the IR facts, the integrated threat model and
the component map. The output (``attack-chain-seeds.schema.json``) holds one workspace per
selected cluster (``attack-chain-workspace.schema.json``); a composer persona is shown exactly one
workspace and may only cite the claims and facts it lists.

* **Link candidates.** Claims whose latest state is verified, narrowed or open. 09 ``VERIFIED`` is
  ``verified``; a ledger state ``narrowed`` is ``narrowed``; ``UNRESOLVED``/``BLOCKED`` and
  undecided are ``open``. ``REFUTED`` and ``superseded`` claims are excluded and listed.
* **Facts.** A fact is a record of an accepted producer, named ``<item id>#<locator>`` (the
  supporting-evidence menu item id plus a record locator), for example
  ``02-code-property-graph#cpg_...`` or ``03-threat-model-dfd-stride#flow:f1``. CPG and IR records
  are deterministic tool records; threat-model and component-map records are ``STRONG_INFERENCE``.
* **Entry seeds.** CPG calls to the external-input family (``recv``/``read``/``fread``/``fgets``/
  ``scanf``/``getenv`` ...), CPG ``argv``/``envp`` identifiers inside ``main``, the first IR memory
  read of ``main`` per file, threat-model elements of kind ``actor``/``external_system``, and
  non-P3 claims whose component sits in a ``public_ingress`` or ``client_device`` zone.
* **Adjacency** between two nodes (claims and entry facts): ``code_fact`` when a CPG/IR record puts
  both in the same function, or a CPG call record goes from one's function to the other's;
  ``model_flow`` when a threat-model flow or a component relationship joins their elements or
  components; ``co_located`` when they share a mapped component and a file (clustering only: it is
  not an edge basis a chain can cite). Seeding never produces ``synthetic`` edges.
* **Clusters.** Connected components with at least one entry seed and one P1 or verified claim,
  ranked by (P1 count, verified count, trust boundaries crossed, cluster id) and cut at
  ``chain_clusters_max``; each kept cluster is cut at ``chain_cluster_claims_max`` claims (P3
  dropped first) and as many facts. Every cut is a gap.
"""
from __future__ import annotations

import bisect
import json
from typing import Any, Iterable

from claim_ledger import _components_for, route_kind
from execution_state import digest

SCHEMA = "appsec-review/attack-chain-seeds/1.0"
WORKSPACE_SCHEMA = "appsec-review/attack-chain-workspace/1.0"
SKIP_NO_SEEDS = "not-applicable-no-chain-seeds"
# ADR-0016 decision 8 defaults; the job template tunables override them.
DEFAULT_BOUNDS = {"chain_clusters_max": 24, "chain_cluster_claims_max": 40, "chain_links_max": 6,
                  "chains_per_cluster_max": 4, "chains_refuted_max": 48, "chain_refutation_batch": 6,
                  "chains_reported_max": 20}
CPG_ITEM = "02-code-property-graph"
IR_ITEM = "02-ir-facts"
TM_ITEM = "03-threat-model-dfd-stride"
CM_ITEM = "01-component-characterization"
DETERMINISTIC_ITEMS = frozenset({CPG_ITEM, IR_ITEM})
INPUT_CALLS = frozenset({"recv", "recvfrom", "recvmsg", "read", "pread", "readv", "fread", "fgets", "gets",
                         "getline", "getdelim", "getc", "fgetc", "getchar", "scanf", "fscanf", "vscanf",
                         "vfscanf", "getenv", "secure_getenv", "ReadFile", "WSARecv", "WSARecvFrom"})
MAIN_FUNCTIONS = frozenset({"main", "wmain", "_tmain"})
MAIN_ARGUMENTS = frozenset({"argv", "envp"})
ENTRY_ELEMENT_KINDS = frozenset({"actor", "external_system"})
ENTRY_ZONE_KINDS = frozenset({"public_ingress", "client_device"})
UNMAPPED = "component-unmapped"
LINK_STATES = {"VERIFIED": "verified", "UNRESOLVED": "open", "BLOCKED": "open"}
TIER_RANK = {"P1": 0, "P2": 1, None: 2, "P3": 3}
TEXT_CHARS = 600
LABEL_CHARS = 300


def _clip(text: Any, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def bounds(overrides: dict[str, Any] | None = None) -> dict[str, int]:
    merged = {**DEFAULT_BOUNDS, **{key: value for key, value in (overrides or {}).items()
                                   if key in DEFAULT_BOUNDS}}
    for key, value in merged.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"attack-chain bound {key} must be a positive integer")
    return merged


def fact_id(item_id: str, locator: str) -> str:
    return f"{item_id}#{locator}"


def _locations(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Every (path, start_line) the claim's own citations name, in citation order, deduplicated."""
    rows, seen = [], set()
    for citation in record.get("citations") or []:
        try:
            locator = json.loads(citation.get("locator_json") or "null")
        except (TypeError, ValueError):
            locator = None
        if not isinstance(locator, dict) or not isinstance(locator.get("path"), str):
            continue
        line = locator.get("start_line")
        line = line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None
        if (locator["path"], line) not in seen:
            seen.add((locator["path"], line)); rows.append({"path": locator["path"], "start_line": line})
    return rows


def claim_citations(record: dict[str, Any]) -> list[dict[str, Any]]:
    """The claim's own citations then its 09 verification citations, canonical objects, by id once."""
    rows, seen = [], set()
    for citation in list(record.get("citations") or []) + list(record.get("verification_citations") or []):
        if citation["citation_id"] not in seen:
            seen.add(citation["citation_id"]); rows.append(citation)
    return rows


def link_candidates(verification: dict[str, Any], ledger_states: dict[str, str] | None = None
                    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(link candidates, excluded claims) from the accepted 09 result."""
    ledger_states = ledger_states or {}
    candidates, excluded = [], []
    for record in sorted(verification.get("verifications") or [], key=lambda row: row["claim_id"]):
        claim_id, status = record["claim_id"], record["status"]
        latest = ledger_states.get(claim_id)
        if status == "REFUTED" or latest in {"refuted", "superseded"}:
            excluded.append({"claim_id": claim_id, "reason": "superseded" if latest == "superseded" else "refuted"})
            continue
        state = LINK_STATES.get(status, "open")
        if state == "open" and latest == "narrowed":
            state = "narrowed"
        source_kind, tier = route_kind(record["route_id"], record["producer"].get("contract_id", ""))
        candidates.append({"claim_id": claim_id, "route_id": record["route_id"], "source_kind": source_kind,
            "tier": tier, "link_state": state, "verification_status": status,
            "hypothesis": _clip(record["hypothesis"], TEXT_CHARS), "confidence": record["confidence"],
            "component_ids": sorted(record["component_ids"]), "locations": _locations(record),
            "citations": claim_citations(record), "entry": False})
    return candidates, excluded


class _Code:
    """Function membership of source lines from CPG METHOD symbols, CPG call callers and IR facts."""

    def __init__(self, cpg_records: Iterable[dict[str, Any]], ir_facts: dict[str, Any] | None,
                 artifacts: dict[str, dict[str, Any]]) -> None:
        self.facts: dict[str, dict[str, Any]] = {}
        self.methods: dict[str, list[tuple[int, str, str]]] = {}     # path -> sorted (line, function, fact)
        self.exact: dict[tuple[str, int], tuple[str, str]] = {}       # (path, line) -> (function, fact)
        self.calls: list[dict[str, Any]] = []
        self.call_index: dict[str, dict[str, Any]] = {}
        self.identifiers: list[dict[str, Any]] = []
        self.entries: list[str] = []
        self.native = False
        self.artifacts = artifacts
        for record in cpg_records:
            self.native = True
            self._cpg(record)
        for rows in self.methods.values():
            rows.sort()
        if ir_facts:
            self._ir(ir_facts)

    def _fact(self, item_id: str, locator: str, kind: str, label: str, path: str | None, line: int | None,
              function: str | None, entry_reason: str | None = None) -> str:
        key = fact_id(item_id, locator)
        artifact = self.artifacts.get(item_id)
        self.facts.setdefault(key, {"fact_id": key, "item_id": item_id, "locator": locator, "kind": kind,
            "label": _clip(label, LABEL_CHARS), "path": path, "line": line,
            "function": _clip(function, 200) if function else None, "component_ids": [], "boundary_ids": [],
            "deterministic": item_id in DETERMINISTIC_ITEMS, "entry": entry_reason is not None,
            "entry_reason": entry_reason,
            "artifact": {"path": artifact["path"], "sha256": artifact["sha256"]} if artifact else None})
        return key

    def _cpg(self, record: dict[str, Any]) -> None:
        kind, path, line = record.get("kind"), record.get("source_path"), record.get("start_line")
        if not isinstance(path, str) or not isinstance(line, int):
            return
        name = str(record.get("name") or "")
        if kind == "symbol" and record.get("label") == "METHOD":
            function = str(record.get("full_name") or name)
            key = self._fact(CPG_ITEM, record["record_id"], "cpg-method",
                             f"function {function} defined at {path}:{line}", path, line, function)
            self.methods.setdefault(path, []).append((line, function, key))
        elif kind in {"call", "memory-operation"} and record.get("caller"):
            caller = str(record["caller"])
            key = fact_id(CPG_ITEM, record["record_id"])
            self.exact.setdefault((path, line), (caller, key))
            row = {"record": record, "caller": caller,
                   "callee": {str(record.get("full_name") or ""), name} - {""}}
            self.calls.append(row)
            self.call_index[record["record_id"]] = row
            if name in INPUT_CALLS:
                self._fact(CPG_ITEM, record["record_id"], "cpg-call",
                           f"call to {name} in {caller} at {path}:{line}", path, line, caller,
                           "external-input call")
                self.entries.append(key)
        elif kind == "identifier" and name in MAIN_ARGUMENTS:
            self.identifiers.append(record)

    def resolve_identifiers(self) -> None:
        """argv/envp identifiers become entry facts only inside main (needs the method spans)."""
        for record in self.identifiers:
            path, line = record["source_path"], record["start_line"]
            function = self.function_at(path, line)
            if function and _short(function[0]) in MAIN_FUNCTIONS:
                key = self._fact(CPG_ITEM, record["record_id"], "cpg-identifier",
                                 f"{record['name']} read in {function[0]} at {path}:{line}", path, line,
                                 function[0], "program argument or environment")
                self.entries.append(key)

    def _ir(self, ir_facts: dict[str, Any]) -> None:
        lines = {row["debug_location_id"]: row["source_line"] for row in ir_facts.get("debug_locations") or []}
        first_main_read: dict[str, tuple[int, dict[str, Any]]] = {}
        for fact in ir_facts.get("facts") or []:
            path, function = fact.get("source_path"), fact.get("function")
            line = lines.get(fact.get("debug_location_id"))
            if not path or not function or not isinstance(line, int):
                continue
            self.native = True
            key = fact_id(IR_ITEM, fact["fact_id"])
            if (path, line) not in self.exact:
                self.exact[(path, line)] = (function, key)
                self._fact(IR_ITEM, fact["fact_id"], "ir-" + fact["kind"],
                           f"IR {fact['kind']} in {function} at {path}:{line}", path, line, function)
            if fact["kind"] == "memory-read" and function in MAIN_FUNCTIONS:
                prior = first_main_read.get(path)
                if prior is None or (line, fact["fact_id"]) < (prior[0], prior[1]["fact_id"]):
                    first_main_read[path] = (line, fact)
        for path, (line, fact) in sorted(first_main_read.items()):
            key = self._fact(IR_ITEM, fact["fact_id"], "ir-memory-read",
                             f"IR memory-read in {fact['function']} at {path}:{line}", path, line,
                             fact["function"], "program argument or environment")
            self.facts[key].update(entry=True, entry_reason="program argument or environment")
            self.entries.append(key)

    def function_at(self, path: str, line: int | None) -> tuple[str, str] | None:
        """(function, evidence fact id) for a source line, or None when no record places it."""
        if line is None:
            return None
        if (path, line) in self.exact:
            function, key = self.exact[(path, line)]
            self._ensure(key)
            return function, key
        rows = self.methods.get(path) or []
        position = bisect.bisect_right(rows, (line, "￿", "￿")) - 1
        if position >= 0:
            return rows[position][1], rows[position][2]
        return None

    def _ensure(self, key: str) -> None:
        if key not in self.facts:   # a CPG call record used as function evidence
            record_id = key.split("#", 1)[1]
            row = self.call_index[record_id]
            self._fact(CPG_ITEM, record_id, "cpg-call", f"call to {row['record'].get('name')} in "
                       f"{row['caller']} at {row['record']['source_path']}:{row['record']['start_line']}",
                       row["record"]["source_path"], row["record"]["start_line"], row["caller"])


def _short(function: str) -> str:
    return function.split("(")[0].split(":")[-1]


class _Graph:
    def __init__(self) -> None:
        self.edges: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    def add(self, a: str, b: str, basis: str, refs: list[str], reason: str) -> None:
        if a == b:
            return
        key = (a, b, basis, "|".join(sorted(refs)))
        if key not in self.edges and (b, a, basis, key[3]) not in self.edges:
            self.edges[key] = {"from": a, "to": b, "basis": basis, "fact_refs": sorted(set(refs)),
                               "reason": _clip(reason, LABEL_CHARS)}


def _union(nodes: Iterable[str], edges: Iterable[dict[str, Any]]) -> dict[str, str]:
    parent = {node: node for node in nodes}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node
    for edge in edges:
        a, b = find(edge["from"]), find(edge["to"])
        if a != b:
            parent[max(a, b)] = min(a, b)
    return {node: find(node) for node in parent}


def build(run_id: str, verification: dict[str, Any], *, ledger_states: dict[str, str] | None = None,
          cpg_records: Iterable[dict[str, Any]] = (), ir_facts: dict[str, Any] | None = None,
          threat_model: dict[str, Any] | None = None, component_map: dict[str, Any] | None = None,
          artifacts: dict[str, dict[str, Any]] | None = None,
          bound_values: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the attack-chain seeds document (pure function of its inputs)."""
    limits = bounds(bound_values)
    artifacts = artifacts or {}
    claims, excluded = link_candidates(verification, ledger_states)
    code = _Code(cpg_records, ir_facts, artifacts)
    code.resolve_identifiers()
    components = list((component_map or {}).get("functional_components") or [])
    model = threat_model or {}
    elements = {row["element_id"]: row for row in model.get("elements") or []}
    zones = {row["zone_id"]: row["kind"] for row in model.get("deployment_zones") or []}
    entry_components = {row["component_id"] for row in elements.values()
                        if row.get("component_id") and zones.get(row.get("zone_id")) in ENTRY_ZONE_KINDS}
    gaps: list[dict[str, Any]] = []
    if not code.native:
        gaps.append({"scope": "input", "id": CPG_ITEM, "reason": "no-native-facts",
                     "detail": "no CPG or IR facts: chains limited to model flows"})
    if not model:
        gaps.append({"scope": "input", "id": TM_ITEM, "reason": "input-missing",
                     "detail": "no integrated threat model: no model_flow edges or threat-model entry seeds"})

    # Nodes: claims and entry facts, with the functions, components and elements they touch.
    nodes: dict[str, dict[str, Any]] = {}
    for claim in claims:
        claim["entry"] = (claim["tier"] != "P3" and bool(set(claim["component_ids"]) & entry_components))
        points = [(row["path"], row["start_line"]) for row in claim["locations"]]
        nodes[claim["claim_id"]] = {"claim": claim, "points": points, "components": set(claim["component_ids"])}
    for key in code.entries:
        fact = code.facts[key]
        fact["component_ids"] = [cid for cid in _components_for(fact["path"], components) if cid != UNMAPPED] \
            if components else []
        nodes[key] = {"fact": fact, "points": [(fact["path"], fact["line"])],
                      "components": set(fact["component_ids"])}
    for element in sorted(elements.values(), key=lambda row: row["element_id"]):
        if element["kind"] in ENTRY_ELEMENT_KINDS:
            key = code._fact(TM_ITEM, "element:" + element["element_id"], "tm-element",
                             f"{element['kind']} {element['name']}", None, None, None,
                             f"threat-model {element['kind']}")
            code.facts[key]["component_ids"] = [element["component_id"]] if element.get("component_id") else []
            nodes[key] = {"fact": code.facts[key], "points": [], "components": set(code.facts[key]["component_ids"]),
                          "elements": {element["element_id"]}}
    for node in nodes.values():
        node.setdefault("elements", set())
        node["elements"] |= {eid for eid, row in elements.items()
                             if row.get("component_id") and row["component_id"] in node["components"]}
        node["functions"] = {}
        for path, line in node["points"]:
            found = code.function_at(path, line)
            if found:
                node["functions"].setdefault((path, found[0]), found[1])

    graph = _Graph()
    by_function: dict[tuple[str, str], list[str]] = {}
    for key in sorted(nodes):
        for function in nodes[key]["functions"]:
            by_function.setdefault(function, []).append(key)
    for (path, function), members in sorted(by_function.items()):
        for index, a in enumerate(members):
            for b in members[index + 1:]:
                refs = [nodes[a]["functions"][(path, function)], nodes[b]["functions"][(path, function)]]
                graph.add(a, b, "code_fact", refs, f"same function {function} in {path}")
    by_name: dict[str, list[tuple[str, str]]] = {}
    for (path, function), members in by_function.items():
        for name in {function, _short(function)}:
            by_name.setdefault(name, []).extend((key, function) for key in members)
    for row in code.calls:
        callers = by_function.get((row["record"]["source_path"], row["caller"]), [])
        if not callers:
            continue
        callees = sorted({pair for name in row["callee"] for pair in by_name.get(name, [])})
        for a in callers:
            for b, function in callees:
                if function != row["caller"]:
                    code._ensure(fact_id(CPG_ITEM, row["record"]["record_id"]))
                    graph.add(a, b, "code_fact", [fact_id(CPG_ITEM, row["record"]["record_id"])],
                              f"{row['caller']} calls {function}")
    by_element: dict[str, list[str]] = {}
    by_component: dict[str, list[str]] = {}
    for key in sorted(nodes):
        for element_id in nodes[key]["elements"]:
            by_element.setdefault(element_id, []).append(key)
        for component_id in nodes[key]["components"] - {UNMAPPED}:
            by_component.setdefault(component_id, []).append(key)
    boundaries: dict[str, set[str]] = {}
    for flow in sorted(model.get("flows") or [], key=lambda row: row["flow_id"]):
        sources, targets = by_element.get(flow["source_element_id"], []), by_element.get(flow["destination_element_id"], [])
        if not sources or not targets:
            continue
        key = code._fact(TM_ITEM, "flow:" + flow["flow_id"], "tm-flow",
                         f"flow {flow['source_element_id']} -> {flow['destination_element_id']}"
                         + (f" crossing {', '.join(flow['boundary_ids'])}" if flow.get("boundary_ids") else ""),
                         None, None, None)
        boundaries[key] = set(flow.get("boundary_ids") or [])
        code.facts[key]["boundary_ids"] = sorted(boundaries[key])
        for a in sources:
            for b in targets:
                graph.add(a, b, "model_flow", [key], f"threat-model flow {flow['flow_id']}")
    for relation in sorted((component_map or {}).get("component_relationships") or [],
                           key=lambda row: row["relationship_id"]):
        if relation["from_component_id"] == relation["to_component_id"]:
            continue
        sources, targets = by_component.get(relation["from_component_id"], []), by_component.get(relation["to_component_id"], [])
        if not sources or not targets:
            continue
        key = code._fact(CM_ITEM, "relationship:" + relation["relationship_id"], "cm-relationship",
                         f"{relation['from_component_id']} {relation['relationship_type']} {relation['to_component_id']}",
                         None, None, None)
        for a in sources:
            for b in targets:
                graph.add(a, b, "model_flow", [key], f"component relationship {relation['relationship_id']}")
    for component_id, members in sorted(by_component.items()):
        for index, a in enumerate(members):
            files_a = {path for path, _line in nodes[a]["points"]}
            for b in members[index + 1:]:
                shared = sorted(files_a & {path for path, _line in nodes[b]["points"]})
                if shared:
                    graph.add(a, b, "co_located", [], f"component {component_id}, file {shared[0]}")

    # Clusters over every edge; only adjacent entry facts and element facts are kept.
    edges = list(graph.edges.values())
    touched = {edge["from"] for edge in edges} | {edge["to"] for edge in edges}
    keep = {key for key, node in nodes.items() if "claim" in node or key in touched}
    roots = _union(keep, [edge for edge in edges if edge["from"] in keep and edge["to"] in keep])
    groups: dict[str, list[str]] = {}
    for key in sorted(keep):
        groups.setdefault(roots[key], []).append(key)
    candidates_seen = eligible = 0
    ranked = []
    for members in groups.values():
        member_set = set(members)
        member_claims = [nodes[key]["claim"] for key in members if "claim" in nodes[key]]
        entries = [key for key in members if ("fact" in nodes[key] and nodes[key]["fact"]["entry"]) or
                   ("claim" in nodes[key] and nodes[key]["claim"]["entry"])]
        strong = [claim for claim in member_claims if claim["tier"] == "P1" or claim["link_state"] == "verified"]
        candidates_seen += 1
        if not entries or not strong:
            continue
        eligible += 1
        cluster_edges = [edge for edge in edges if edge["from"] in member_set and edge["to"] in member_set]
        crossed = set().union(*[boundaries.get(ref, set()) for edge in cluster_edges for ref in edge["fact_refs"]])
        cluster_id = "cluster-" + digest(sorted(members))[:16]
        ranked.append(((-sum(1 for claim in member_claims if claim["tier"] == "P1"),
                        -sum(1 for claim in member_claims if claim["link_state"] == "verified"),
                        -len(crossed), cluster_id), cluster_id, members, sorted(crossed)))
    ranked.sort(key=lambda row: row[0])
    for _key, cluster_id, _members, _crossed in ranked[limits["chain_clusters_max"]:]:
        gaps.append({"scope": "cluster", "id": cluster_id, "reason": "cluster-cap",
                     "detail": f"cluster ranked beyond chain_clusters_max ({limits['chain_clusters_max']})"})
    workspaces = []
    for order, cluster_id, members, crossed in ranked[:limits["chain_clusters_max"]]:
        member_claims = sorted((nodes[key]["claim"] for key in members if "claim" in nodes[key]),
            key=lambda c: (not (c["entry"] or c["tier"] == "P1" or c["link_state"] == "verified"),
                           TIER_RANK.get(c["tier"], 2), c["link_state"] != "verified", c["claim_id"]))
        kept_claims = member_claims[:limits["chain_cluster_claims_max"]]
        dropped = [claim["claim_id"] for claim in member_claims[limits["chain_cluster_claims_max"]:]]
        if dropped:
            gaps.append({"scope": "cluster", "id": cluster_id, "reason": "cluster-claims-cap",
                         "detail": f"{len(dropped)} claim(s) over chain_cluster_claims_max "
                                   f"({limits['chain_cluster_claims_max']}) dropped: {', '.join(dropped[:12])}"
                                   + (" ..." if len(dropped) > 12 else "")})
        member_facts = sorted(key for key in members if "fact" in nodes[key])
        kept_facts = member_facts[:limits["chain_cluster_claims_max"]]
        if len(member_facts) > len(kept_facts):
            gaps.append({"scope": "cluster", "id": cluster_id, "reason": "cluster-facts-cap",
                         "detail": f"{len(member_facts) - len(kept_facts)} entry fact(s) over the cluster cap dropped"})
        kept = {claim["claim_id"] for claim in kept_claims} | set(kept_facts)
        cluster_edges = sorted((edge for edge in edges if edge["from"] in kept and edge["to"] in kept),
                               key=lambda e: (e["from"], e["to"], e["basis"], e["fact_refs"]))
        adjacency = [{"edge_id": "adj-" + digest(edge)[:16], **edge} for edge in cluster_edges]
        refs = sorted({ref for edge in adjacency for ref in edge["fact_refs"]} | set(kept_facts))
        workspaces.append({"schema": WORKSPACE_SCHEMA, "run_id": run_id, "cluster_id": cluster_id,
            "bounds": {"chain_links_max": limits["chain_links_max"],
                       "chains_per_cluster_max": limits["chains_per_cluster_max"]},
            "rank": {"p1_claims": -order[0], "verified_claims": -order[1], "boundaries_crossed": crossed},
            "claims": kept_claims, "facts": [code.facts[key] for key in refs], "adjacency": adjacency})
    entry_facts = sum(1 for node in nodes.values() if "fact" in node and node["fact"]["entry"])
    coverage = {"link_candidates": len(claims), "excluded_claims": len(excluded), "entry_facts": entry_facts,
                "entry_claims": sum(1 for claim in claims if claim["entry"]), "clusters_seen": candidates_seen,
                "clusters_eligible": eligible, "clusters_cut": max(0, eligible - limits["chain_clusters_max"]),
                "clusters_selected": len(workspaces), "native_facts": code.native}
    return {"schema": SCHEMA, "run_id": run_id,
            "verification": {"ledger_head_id": verification.get("ledger_head_id"),
                             "ledger_head_sha256": verification.get("ledger_head_sha256")},
            "bounds": limits, "skip_reason": None if workspaces else SKIP_NO_SEEDS,
            "excluded": excluded, "clusters": workspaces, "gaps": gaps, "coverage": coverage}
