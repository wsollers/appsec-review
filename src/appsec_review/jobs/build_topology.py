"""Accepted target build dependencies, distinct from review jobs and build attempts."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import copy
import hashlib
import heapq
import json
from pathlib import PurePosixPath
import posixpath
import re
import shlex
from typing import Any

from appsec_review.jobs.build_discovery import (
    make_default_build_commands, native_build_capability_gap, recipe_execution_cwd, validate_build_recipe,
)
from appsec_review.storage import canonical_json


BUILD_TOPOLOGY_SCHEMA = "appsec-review/build-topology/1"
VARIANT_FIELDS = ("configuration", "target_arch", "execution_role", "linkage", "toolchain", "abi")
EDGE_KINDS = frozenset({
    "requires_product", "requires_generated_source", "requires_host_tool", "order_only",
})
DISPOSITIONS = frozenset({"independent", "contained", "unsupported", "unresolved"})


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _relative(value: Any) -> bool:
    return (isinstance(value, str) and bool(value) and "\\" not in value and ":" not in value
            and not PurePosixPath(value).is_absolute() and ".." not in PurePosixPath(value).parts
            and PurePosixPath(value).as_posix() == value)


def _hash(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _resolve(root: str, relative: str) -> str | None:
    if "\\" in relative or ":" in relative or PurePosixPath(relative).is_absolute():
        return None
    result = posixpath.normpath(posixpath.join(root, relative))
    return result if _relative(result) else None


def _product_path(value: Any) -> bool:
    if _relative(value):
        return True
    return isinstance(value, str) and any(
        value == root or value.startswith(root + "/") and _relative(value[len(root) + 1:])
        for root in ("/workspace", "/install"))


def _variant(value: Any) -> bool:
    return (isinstance(value, Mapping) and set(value) == set(VARIANT_FIELDS)
            and all(item is None or isinstance(item, str) and bool(item.strip())
                    for item in value.values())
            and value["execution_role"] in {None, "host", "target"})


def _evidence(document: Mapping[str, Any], relationship: str, line: int | None = None,
              declaration: str | None = None) -> dict[str, Any]:
    return {"path": document["path"], "sha256": document["sha256"],
            "relationship": relationship, "line": line, "declaration": declaration}


def _ordered(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return sorted((copy.deepcopy(dict(value)) for value in values), key=canonical_json)


def topology_identity(graph: Mapping[str, Any]) -> str:
    """Structural identity: recipe edits are per-node inputs, not global invalidations."""
    payload = {key: copy.deepcopy(value) for key, value in graph.items() if key != "topology_id"}
    payload["nodes"] = _ordered([
        {key: value for key, value in node.items() if key != "recipe_revision"}
        for node in graph["nodes"]])
    for key in ("edges", "external_requirements", "coverage_gaps"):
        payload[key] = _ordered(graph[key])
    return _digest(payload)


def _cmake_calls(document: Mapping[str, Any]):
    """Read only flat literal calls; dynamic or conditional semantics remain unresolved."""
    text = str(document["content"])
    depth = 0
    pattern = re.compile(r"([A-Za-z_][A-Za-z_0-9]*)[ \t\r\n]*\(([^()]*)\)")
    offset = 0
    while offset < len(text):
        trivia = re.match(r"(?:\s+|#[^\n]*(?:\n|$))*", text[offset:])
        if trivia is not None:
            consumed = trivia.group(0)
            if re.search(r"#\[(=*)\[", consumed):
                yield "unparsed", [], False, _evidence(
                    document, "unparsed", text.count("\n", 0, offset) + 1, consumed.strip())
                return
            offset += len(consumed)
        if offset == len(text):
            return
        match = pattern.match(text, offset)
        if match is None or re.search(r"\[(=*)\[", match.group(0)):
            yield "unparsed", [], False, _evidence(
                document, "unparsed", text.count("\n", 0, offset) + 1, text[offset:].strip())
            return
        name, body = match.group(1).lower(), match.group(2)
        if name in {"endif", "endforeach", "endwhile", "endfunction", "endmacro", "endblock"}:
            depth = max(0, depth - 1)
        try:
            tokens = shlex.split(body, comments=True, posix=True)
        except ValueError:
            tokens = []
        literal = bool(tokens) and not re.search(r"[$;]|#\[\[", body) and depth == 0
        yield name, tokens, literal, _evidence(
            document, name, text.count("\n", 0, match.start()) + 1, match.group(0).strip())
        if name in {"if", "foreach", "while", "function", "macro", "block"}:
            depth += 1
        offset = match.end()


def compile_build_topology(units: Sequence[Mapping[str, Any]], *, source_fingerprint: str,
                           component_relationships: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Compile conservative descriptor declarations, preserving every discovered disposition."""
    nodes: dict[str, dict[str, Any]] = {}
    calls: dict[str, list[Any]] = {}
    make_commands: dict[str, tuple[Mapping[str, Any], str]] = {}
    gaps: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    external: list[dict[str, Any]] = []

    def gap(code: str, ids: Sequence[str], reason: str, evidence=(), *, blocking=True) -> None:
        value = {"code": code, "build_unit_ids": sorted(set(ids)), "reason": reason,
                 "blocking": blocking, "evidence": _ordered(evidence)}
        if value not in gaps:
            gaps.append(value)

    for unit in sorted(units, key=lambda value: str(value["build_unit_id"])):
        uid = str(unit["build_unit_id"])
        if uid in nodes:
            raise ValueError(f"duplicate build unit: {uid}")
        variant = dict(unit.get("build_variant", dict.fromkeys(VARIANT_FIELDS)))
        if not _variant(variant):
            raise ValueError(f"invalid build variant: {uid}")
        markers = list(unit.get("markers", ()))
        package = unit.get("descriptor_package", {})
        accepted = []
        for document in package.get("documents", ()):
            text = document.get("content")
            if (not isinstance(text, str) or not _hash(document.get("sha256"))
                    or hashlib.sha256(text.encode("utf-8")).hexdigest() != document["sha256"]
                    or (str(document["path"]) in {str(item["path"]) for item in markers}
                        and document["sha256"] != next(
                            item["sha256"] for item in markers if item["path"] == document["path"]))):
                gap("descriptor_identity_unresolved", [uid], "descriptor text does not resolve its accepted hash")
                continue
            accepted.append(document)
        own = [item for item in accepted if PurePosixPath(str(item["path"])).parent.as_posix() == unit["root"]
                  and PurePosixPath(str(item["path"])).name == "CMakeLists.txt"]
        calls[uid] = [call for document in own for call in _cmake_calls(document)]
        if unit["build_system"] == "make":
            resolved = make_default_build_commands({
                **unit, "descriptor_package": {**package, "documents": accepted}})
            if resolved is not None:
                make_commands[uid] = resolved
        node = {
            "build_unit_id": uid, "root": unit["root"], "family": unit["family"],
            "build_system": unit["build_system"], "disposition": "unresolved",
            "owner_build_unit_id": None, "variant": variant, "products": [],
            "recipe_revision": _digest(unit["recipe"]) if unit.get("recipe") is not None else None,
            "evidence": _ordered([_evidence(item, "build_descriptor") for item in markers]),
        }
        capability_gap = native_build_capability_gap(unit)
        if capability_gap:
            node["disposition"] = "unsupported"
            gap("unsupported_build_unit", [uid], capability_gap)
        elif any(name == "project" and literal for name, _args, literal, _ev in calls[uid]):
            node.update(disposition="independent", owner_build_unit_id=uid)
        elif unit["build_system"] not in {"cmake", "make", "autotools", "msbuild", "vcbuild"}:
            # Packaging/project markers identify drivers, not their complete dependency topology.
            node.update(disposition="independent", owner_build_unit_id=uid)
        elif unit["build_system"] == "autotools" and any(
                PurePosixPath(str(item["path"])).name in {"configure.ac", "configure.in"} for item in markers):
            node.update(disposition="independent", owner_build_unit_id=uid)
        elif uid in make_commands and unit.get("recipe") is not None and not validate_build_recipe(unit["recipe"], unit):
            marker, commands = make_commands[uid]
            if (re.search(r"(?m)^[@+-]*(?:gcc|g\+\+|clang|clang\+\+|cc|c\+\+|\$\(CC\)|\$\(CXX\))\s+"
                          r"(?![^\n]*(?:--help|--version))\S+", commands)
                    or re.search(r"(?m)^[@+-]*\$\(MAKE\)\s+-C\s+[A-Za-z0-9_./-]+\s*$", commands)):
                node.update(disposition="independent", owner_build_unit_id=uid)
                node["evidence"] = _ordered([*node["evidence"],
                    _evidence(marker, "default_goal_build_driver", declaration=commands)])
        nodes[uid] = node

    owners: dict[str, list[tuple[str, Mapping[str, Any]]]] = {}
    by_root: dict[str, list[str]] = {}
    for uid, node in nodes.items():
        by_root.setdefault(str(node["root"]), []).append(uid)
    for uid in nodes:
        if uid in make_commands:
            marker, commands = make_commands[uid]
            for match in re.finditer(r"(?m)^[@+-]*\$\(MAKE\)\s+-C\s+([A-Za-z0-9_./-]+)\s*$", commands):
                relative = _resolve(str(nodes[uid]["root"]), match.group(1))
                candidates = [candidate for candidate in by_root.get(relative, ())
                              if nodes[candidate]["build_system"] == "make"]
                evidence = _evidence(marker, "recursive_make", declaration=match.group(0))
                if relative is not None and len(candidates) == 1:
                    owners.setdefault(candidates[0], []).append((uid, evidence))
                else:
                    gap("unresolved_owner", [uid], "recursive Make owner does not resolve one accepted unit", [evidence])
        for name, args, literal, evidence in calls[uid]:
            if name not in {"add_subdirectory", "target_link_libraries", "add_dependencies",
                            "add_library", "add_executable", "add_custom_command", "add_custom_target", "include",
                            "unparsed"}:
                continue
            if not literal or name in {"add_custom_command", "add_custom_target", "include"}:
                gap("unresolved_declaration", [uid],
                    f"{name}: dynamic, conditional, included or generator semantics require resolution", [evidence])
                continue
            if name != "add_subdirectory":
                continue
            relative = _resolve(str(nodes[uid]["root"]), args[0])
            candidates = [candidate for candidate in by_root.get(relative, ())
                          if nodes[candidate]["build_system"] == "cmake"]
            if relative is None or len(candidates) != 1:
                gap("unresolved_owner", [uid], f"add_subdirectory does not resolve one accepted unit: {args[0]}",
                    [evidence])
                continue
            owners.setdefault(candidates[0], []).append((uid, evidence))
    for child, values in owners.items():
        owner_ids = {uid for uid, _ev in values}
        if len(owner_ids) != 1 or child in owner_ids:
            nodes[child].update(disposition="unresolved", owner_build_unit_id=None)
            gap("ambiguous_owner", [child, *owner_ids], "build unit has multiple or self owners",
                [ev for _uid, ev in values])
        else:
            nodes[child].update(disposition="contained", owner_build_unit_id=values[0][0])
            nodes[child]["evidence"] = _ordered([*nodes[child]["evidence"], *(ev for _uid, ev in values)])

    def owner(uid: str) -> str | None:
        seen: list[str] = []
        while nodes[uid]["disposition"] == "contained":
            if uid in seen:
                raise ValueError("build ownership cycle: " + " -> ".join([*seen, uid]))
            seen.append(uid)
            uid = nodes[uid]["owner_build_unit_id"]
        return uid if nodes[uid]["disposition"] == "independent" else None

    targets: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for uid, node in nodes.items():
        resolved_owner = owner(uid)
        if node["disposition"] == "contained":
            if resolved_owner is None:
                node.update(disposition="unresolved", owner_build_unit_id=None)
            else:
                node["owner_build_unit_id"] = resolved_owner
        if node["disposition"] == "unresolved":
            gap("unresolved_ownership", [uid], "independent build ownership is not established by supported declarations")
        for name, args, literal, evidence in calls[uid]:
            if name not in {"add_library", "add_executable"} or not literal or not resolved_owner:
                continue
            if any(arg.upper() in {"IMPORTED", "ALIAS", "INTERFACE", "OBJECT"} for arg in args[1:]):
                gap("unresolved_target", [resolved_owner], f"{name}: nonstandard target interface requires resolution",
                    [evidence])
                continue
            variant = dict(nodes[resolved_owner]["variant"])
            if name == "add_library":
                linkage = next((arg.lower() for arg in args[1:] if arg.upper() in {"STATIC", "SHARED", "MODULE"}), None)
                variant["linkage"] = linkage or variant["linkage"]
            product = {"product_id": f"cmake:{args[0]}", "kind": "library" if name == "add_library" else "executable",
                       "interface": f"cmake-target:{args[0]}", "variant": variant}
            nodes[resolved_owner]["products"].append(product)
            nodes[resolved_owner]["evidence"] = _ordered([
                *nodes[resolved_owner]["evidence"], evidence])
            targets.setdefault(args[0], []).append((resolved_owner, product))
    for name, values in targets.items():
        if len(values) > 1:
            gap("ambiguous_target", [uid for uid, _product in values],
                f"target has multiple owner/variant declarations: {name}")
    for uid in nodes:
        consumer = owner(uid)
        for name, args, literal, evidence in calls[uid]:
            if name not in {"target_link_libraries", "add_dependencies"} or not literal or not consumer:
                continue
            consumers = targets.get(args[0], [])
            if len(consumers) != 1 or consumers[0][0] != consumer:
                gap("unresolved_consumer", [consumer], f"target consumer is unknown or ambiguous: {args[0]}",
                    [evidence])
                continue
            for target in args[1:]:
                if target.upper() in {"PUBLIC", "PRIVATE", "INTERFACE", "DEBUG", "OPTIMIZED", "GENERAL"}:
                    if target.upper() in {"DEBUG", "OPTIMIZED", "GENERAL"}:
                        gap("unresolved_variant", [consumer], "configuration-qualified link requires variant resolution",
                            [evidence])
                    continue
                producers = targets.get(target, [])
                if len(producers) != 1:
                    if producers:
                        gap("ambiguous_producer", [consumer], f"target producer is ambiguous: {target}", [evidence])
                    else:
                        external.append({"consumer_build_unit_id": consumer, "interface": target,
                                         "status": "unresolved", "evidence": [evidence]})
                        gap("external_requirement", [consumer],
                            f"declared dependency is not a resolved in-repository target: {target}", [evidence])
                    continue
                producer, product = producers[0]
                if producer == consumer:
                    if args[0] == target:
                        raise ValueError(f"self build dependency: {producer} ({target})")
                    continue  # The owning build system schedules its own internal targets.
                edge = {"producer_build_unit_id": producer, "consumer_build_unit_id": consumer,
                        "kind": "requires_product" if name == "target_link_libraries" else "order_only",
                        "requirement": copy.deepcopy(product) if name == "target_link_libraries" else None,
                        "evidence": [evidence]}
                if edge not in edges:
                    edges.append(edge)
    for relationship in component_relationships:
        if relationship.get("kind") == "depends_on":
            gap("unresolved_component_dependency", [],
                "component dependency is not an evidence-backed build-unit edge: " +
                canonical_json(relationship).decode("utf-8"), blocking=False)
    if nodes:
        gap("incomplete_dependency_discovery", [],
            "only supported direct descriptor declarations are resolved; absence of an edge is not independence",
            blocking=False)
    for node in nodes.values():
        node["products"] = _ordered(node["products"])
    graph = {"schema": "appsec-review/build-topology/1", "source_fingerprint": source_fingerprint,
             "nodes": _ordered(list(nodes.values())), "edges": _ordered(edges),
             "external_requirements": _ordered(external), "coverage_gaps": _ordered(gaps)}
    graph["topology_id"] = topology_identity(graph)
    validate_build_topology(graph)
    return graph


def validate_build_topology(graph: Mapping[str, Any]) -> None:
    """Fail closed on identity, endpoint, ownership, product and cycle errors."""
    if (set(graph) != {"schema", "source_fingerprint", "topology_id", "nodes", "edges",
                       "external_requirements", "coverage_gaps"}
            or graph.get("schema") != "appsec-review/build-topology/1"
            or not isinstance(graph.get("source_fingerprint"), str) or not graph["source_fingerprint"]):
        raise ValueError("unsupported build topology document")
    if any(not isinstance(graph[key], list)
           for key in ("nodes", "edges", "external_requirements", "coverage_gaps")):
        raise ValueError("build topology collections must be lists")
    nodes: dict[str, Mapping[str, Any]] = {}
    for node in graph["nodes"]:
        if (not isinstance(node, Mapping) or set(node) != {
                "build_unit_id", "root", "family", "build_system", "disposition",
                "owner_build_unit_id", "variant", "products", "recipe_revision", "evidence"}):
            raise ValueError("build unit has unsupported or missing fields")
        uid = node.get("build_unit_id")
        if not isinstance(uid, str) or not uid or uid in nodes:
            raise ValueError(f"unknown or duplicate build unit identity: {uid}")
        if (not _relative(node.get("root")) or node.get("disposition") not in DISPOSITIONS
                or not _variant(node.get("variant"))
                or any(not isinstance(node.get(key), str) or not node[key] for key in ("family", "build_system"))
                or node.get("recipe_revision") is not None and not _hash(node["recipe_revision"])):
            raise ValueError(f"invalid build unit: {uid}")
        products = node.get("products")
        if not isinstance(products, list) or any(not _product(product) for product in products):
            raise ValueError(f"invalid product declaration: {uid}")
        if len({item["product_id"] for item in products}) != len(products):
            raise ValueError(f"duplicate products: {uid}")
        nodes[uid] = node
    for uid, node in nodes.items():
        disposition, owner = node["disposition"], node.get("owner_build_unit_id")
        if (disposition == "independent" and owner != uid
                or disposition == "contained" and (owner not in nodes or owner == uid
                                                  or nodes[owner]["disposition"] != "independent")
                or disposition in {"unresolved", "unsupported"} and owner is not None):
            raise ValueError(f"ambiguous or invalid build owner: {uid}")
    for edge in graph["edges"]:
        if (not isinstance(edge, Mapping) or set(edge) != {
                "producer_build_unit_id", "consumer_build_unit_id", "kind", "requirement", "evidence"}):
            raise ValueError("build edge has unsupported or missing fields")
        producer, consumer = edge.get("producer_build_unit_id"), edge.get("consumer_build_unit_id")
        if producer not in nodes or consumer not in nodes:
            raise ValueError(f"unknown build edge endpoint: {producer} -> {consumer}")
        if producer == consumer:
            raise ValueError(f"self build dependency: {producer}")
        if any(nodes[uid]["disposition"] != "independent" for uid in (producer, consumer)):
            raise ValueError("build edge endpoints must resolve to independent owners")
        if edge.get("kind") not in EDGE_KINDS:
            raise ValueError("unknown build relationship")
        requirement = edge.get("requirement")
        if edge["kind"] == "order_only":
            if requirement is not None:
                raise ValueError("order-only edge cannot claim a product")
        elif not _product(requirement) or requirement not in nodes[producer]["products"]:
            raise ValueError("build requirement is not an exact producer product/variant")
        elif (edge["kind"] == "requires_host_tool" and
              (requirement["kind"] != "executable" or requirement["variant"]["execution_role"] != "host")):
            raise ValueError("host-tool requirement must resolve a host executable")
        elif edge["kind"] == "requires_generated_source" and requirement["kind"] != "generated_source":
            raise ValueError("generated-source requirement must resolve generated source")
        _validate_evidence(edge.get("evidence"))
    for node in nodes.values():
        _validate_evidence(node.get("evidence"))
    for value in graph["external_requirements"]:
        if value.get("consumer_build_unit_id") not in nodes or value.get("status") != "unresolved":
            raise ValueError("unknown external requirement consumer or status")
        _validate_evidence(value.get("evidence"))
    for gap in graph["coverage_gaps"]:
        if (not set(gap.get("build_unit_ids", ())) <= set(nodes) or type(gap.get("blocking")) is not bool
                or not gap.get("code") or not gap.get("reason")):
            raise ValueError("invalid topology coverage gap")
        _validate_evidence(gap.get("evidence"), allow_empty=True)
    _topological_order(graph)
    if not _hash(graph.get("topology_id")) or graph["topology_id"] != topology_identity(graph):
        raise ValueError("build topology structural identity changed")


def _product(value: Any) -> bool:
    return (isinstance(value, Mapping) and set(value) == {"product_id", "kind", "interface", "variant"}
            and all(isinstance(value[key], str) and value[key] for key in ("product_id", "interface"))
            and value["kind"] in {"library", "executable", "headers", "package_metadata", "generated_source"}
            and _variant(value["variant"]))


def _validate_evidence(values: Any, *, allow_empty=False) -> None:
    if not isinstance(values, list) or not values and not allow_empty:
        raise ValueError("build relationship requires resolving descriptor evidence")
    for value in values:
        if (not isinstance(value, Mapping) or set(value) != {"path", "sha256", "relationship", "line", "declaration"}
                or not _relative(value.get("path")) or not _hash(value.get("sha256"))
                or not value.get("relationship")
                or value.get("line") is not None and (type(value["line"]) is not int or value["line"] < 1)
                or value.get("line") is not None and not value.get("declaration")):
            raise ValueError("invalid build relationship provenance")


def _topological_order(graph: Mapping[str, Any]) -> list[str]:
    dependencies = {node["build_unit_id"]: set() for node in graph["nodes"]
                    if node["disposition"] == "independent"}
    followers: dict[str, set[str]] = {uid: set() for uid in dependencies}
    for edge in graph["edges"]:
        dependencies[edge["consumer_build_unit_id"]].add(edge["producer_build_unit_id"])
        followers[edge["producer_build_unit_id"]].add(edge["consumer_build_unit_id"])
    ready = [uid for uid in dependencies if not dependencies[uid]]
    heapq.heapify(ready)
    result = []
    while ready:
        uid = heapq.heappop(ready)
        result.append(uid)
        for follower in sorted(followers[uid]):
            dependencies[follower].discard(uid)
            if not dependencies[follower]:
                heapq.heappush(ready, follower)
    if len(result) != len(dependencies):
        pending = set(dependencies) - set(result)
        path: list[str] = []
        uid = min(pending)
        while uid not in path:
            path.append(uid)
            uid = min(dependencies[uid] & pending)
        raise ValueError("build dependency cycle: " + " -> ".join(reversed([*path[path.index(uid):], uid])))
    return result


def topological_order(graph: Mapping[str, Any]) -> list[str]:
    """Order known independent owners; coverage gaps do not imply a complete graph."""
    validate_build_topology(graph)
    return _topological_order(graph)


def ready_build_units(graph: Mapping[str, Any], states: Mapping[str, str], *,
                      products: Sequence[Mapping[str, Any]] = (),
                      verify_product: Callable[[Mapping[str, Any]], bool] | None = None) -> dict[str, Any]:
    """Select pending nodes using verified producer records, never attempt completion alone."""
    order = topological_order(graph)
    nodes = {node["build_unit_id"]: node for node in graph["nodes"]}
    if set(states) - set(nodes):
        raise ValueError("state names an unknown build unit")
    ready = []
    blocked = [{"build_unit_id": uid, "reasons": sorted({
        node["disposition"],
        *(gap["code"] for gap in graph["coverage_gaps"] if gap["blocking"] and uid in gap["build_unit_ids"]),
    })} for uid, node in sorted(nodes.items()) if node["disposition"] in {"unresolved", "unsupported"}]
    for uid in order:
        if states.get(uid, "PENDING") not in {"PENDING", "READY", "BLOCKED_BY_DEPENDENCY"}:
            continue
        reasons = [gap["code"] for gap in graph["coverage_gaps"]
                   if gap["blocking"] and uid in gap["build_unit_ids"]]
        if nodes[uid]["recipe_revision"] is None:
            reasons.append("missing_recipe_revision")
        for edge in graph["edges"]:
            if edge["consumer_build_unit_id"] != uid:
                continue
            producer = edge["producer_build_unit_id"]
            if states.get(producer) != "SUCCEEDED":
                reasons.append(f"producer_not_succeeded:{producer}")
                continue
            if edge["kind"] == "order_only":
                continue
            requirement = edge["requirement"]
            if any(value is None for value in requirement["variant"].values()):
                reasons.append(f"unresolved_product_variant:{producer}")
                continue
            if edge["kind"] == "requires_product" and requirement["kind"] == "library":
                compatibility = ("configuration", "target_arch", "execution_role", "toolchain", "abi")
                if any(nodes[uid]["variant"][key] is None for key in compatibility):
                    reasons.append(f"unresolved_consumer_variant:{producer}")
                    continue
                if any(nodes[uid]["variant"][key] != requirement["variant"][key] for key in compatibility):
                    reasons.append(f"incompatible_consumer_variant:{producer}")
                    continue
            matches = [record for record in products
                       if record.get("producer_build_unit_id") == producer
                       and all(record.get(key) == value for key, value in requirement.items())
                       and record.get("topology_id") == graph["topology_id"]
                       and record.get("recipe_revision") == nodes[producer]["recipe_revision"]
                       and nodes[producer]["recipe_revision"] is not None
                       and _product_path(record.get("path")) and _hash(record.get("sha256"))]
            if verify_product is None:
                reasons.append(f"product_verification_required:{producer}")
            elif not any(verify_product(record) for record in matches):
                reasons.append(f"required_product_unverified:{producer}")
        if reasons:
            blocked.append({"build_unit_id": uid, "reasons": sorted(set(reasons))})
        else:
            ready.append(uid)
    return {"ready": ready, "blocked": blocked}


_compile_graph1 = compile_build_topology
_validate_graph1 = validate_build_topology
_identity_graph1 = topology_identity
_ready_graph1 = ready_build_units
BUILD_TOPOLOGY_SCHEMA = "appsec-review/build-topology/2"
BUNDLE_SCHEMA = "appsec-review/build-topology-evidence/1"
REFINEMENT_SCHEMA = "appsec-review/build-topology-refinement/1"
ENFORCEMENT_SCHEMA = "appsec-review/native-target-enforcement/1"
RULES = "source-scoped-topology/4"
OPERATIONS = frozenset({"managed_compile", "bytecode_transform", "native_aot",
                       "native_compile", "native_link", "package", "prebuilt_import", "unknown"})
PROOF_KINDS = frozenset({"msbuild_selected_mapping", "compiler_explicit_target",
                        "compiler_pinned_default", "go_explicit_target"})
_SOURCE_KEYS = ("build_unit_id", "root", "family", "build_system", "markers", "build_variant",
                "project_type", "descriptor_facts", "engine", "engine_project", "native_components")


def topology_evidence_bundle(units, *, source_fingerprint, environment=None, profiles=None):
    documents = {}
    sources = []
    for unit in sorted(units, key=lambda item: item["build_unit_id"]):
        source = {key: copy.deepcopy(unit[key]) for key in _SOURCE_KEYS if key in unit}
        source["documents"] = []
        package = unit.get("descriptor_package", {})
        source["coverage"] = {"bounds": copy.deepcopy(package.get("bounds", {})),
                              "gaps": copy.deepcopy(package.get("gaps", []))}
        for document in package.get("documents", []):
            if (not _relative(document.get("path")) or not _hash(document.get("sha256"))
                    or not isinstance(document.get("content"), str)
                    or _digest_bytes(document["content"].encode()) != document["sha256"]):
                raise ValueError("topology descriptor does not resolve its accepted bytes")
            key = document["path"]
            if key in documents and documents[key] != document:
                raise ValueError("conflicting accepted declaring document")
            documents[key] = copy.deepcopy(document)
            source["documents"].append({"path": key, "sha256": document["sha256"]})
        source["documents"] = _ordered(source["documents"])
        sources.append(source)
    bundle = {"schema": BUNDLE_SCHEMA, "source_fingerprint": source_fingerprint, "rules": RULES,
              "units": sources, "documents": _ordered(list(documents.values())),
              "environment": copy.deepcopy(environment), "profiles": copy.deepcopy(profiles)}
    if len(canonical_json(bundle)) > 16 * 1024 * 1024:
        raise ValueError("topology evidence exceeds the accepted graph byte budget")
    return bundle


def _digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def bundle_units(bundle):
    if bundle.get("schema") != BUNDLE_SCHEMA or bundle.get("rules") != RULES:
        raise ValueError("unsupported topology evidence bundle")
    documents = {item["path"]: item for item in bundle["documents"]}
    units = []
    for source in bundle["units"]:
        unit = {key: copy.deepcopy(source[key]) for key in _SOURCE_KEYS if key in source}
        selected = []
        for ref in source["documents"]:
            document = documents.get(ref["path"])
            if document is None or document["sha256"] != ref["sha256"]:
                raise ValueError("bundle document binding changed")
            selected.append(copy.deepcopy(document))
        unit["descriptor_package"] = {
            "documents": selected, "gaps": source["coverage"]["gaps"],
            "bounds": source["coverage"]["bounds"]}
        units.append(unit)
    if topology_evidence_bundle(
            units, source_fingerprint=bundle["source_fingerprint"],
            environment=bundle["environment"], profiles=bundle["profiles"]) != bundle:
        raise ValueError("topology bundle is not canonical or has unresolved document identities")
    return units


def _xml_declarations(document):
    import xml.etree.ElementTree as ET
    from xml.parsers import expat
    try:
        root = ET.fromstring(document["content"])
        parser = expat.ParserCreate()
        locations = []
        parser.StartElementHandler = lambda name, attrs: locations.append(parser.CurrentLineNumber)
        parser.Parse(document["content"], True)
    except (ET.ParseError, expat.ExpatError):
        return [{"predicate": "coverage_gap", "value": "unparsed_xml", "condition": None,
                 "line": 1}]
    declarations = []
    location = iter(locations)

    def visit(element, inherited):
        line = next(location)
        tag = element.tag.rsplit("}", 1)[-1]
        own_condition = element.attrib.get("Condition")
        condition = (f"({inherited}) AND ({own_condition})"
                     if inherited is not None and own_condition is not None
                     else own_condition if own_condition is not None else inherited)
        value = (element.text or "").strip()
        if tag in {"ProjectReference", "Import", "PackageReference", "ClCompile", "ClInclude",
                   "Compile", "Reference", "Content", "NativeReference", "EmbeddedResource", "Exec"}:
            value = dict(element.attrib)
        elif tag in {"Configuration", "ProjectConfiguration", "Platform", "Tool"}:
            value = dict(element.attrib)
        if value and tag not in {"Project", "ItemGroup", "PropertyGroup", "ItemDefinitionGroup"}:
            declarations.append({"predicate": tag, "value": value, "condition": condition, "line": line})
        for child in element:
            visit(child, condition)
    visit(root, None)
    declarations.append({"predicate": "project_descriptor", "value": {
        "sdk": root.attrib.get("Sdk"), "kind": PurePosixPath(document["path"]).suffix.lower()},
        "condition": None, "line": 1})
    return declarations


def _node_declarations(document):
    text = document["content"]

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate manifest key")
            value[key] = item
        return value

    try:
        manifest = json.loads(text, object_pairs_hook=unique)
    except ValueError:
        return [{"predicate": "coverage_gap", "value": "node_manifest_unresolved",
                 "condition": "unresolved", "line": 1}]
    if not isinstance(manifest, dict) or not isinstance(manifest.get("scripts", {}), dict):
        return [{"predicate": "coverage_gap", "value": "node_manifest_unresolved",
                 "condition": "unresolved", "line": 1}]
    decoder = json.JSONDecoder()

    def members(start):
        index = start + 1
        while True:
            while text[index].isspace():
                index += 1
            if text[index] == "}":
                return
            key_start = index
            key, index = decoder.raw_decode(text, index)
            while text[index].isspace() or text[index] == ":":
                index += 1
            value_start = index
            value, index = decoder.raw_decode(text, index)
            yield key, value, key_start, value_start
            while text[index].isspace():
                index += 1
            if text[index] == "}":
                return
            index += 1

    result = [{"predicate": "node:lifecycle", "value": {
        "gypfile": manifest.get("gypfile", True)}, "condition": None, "line": 1}]
    for key, _, _, start in members(len(text) - len(text.lstrip())):
        if key == "scripts":
            for name, command, offset, _ in members(start):
                result.append({"predicate": "node:script", "value": {"name": name, "command": command},
                               "condition": None if isinstance(command, str) else "unresolved",
                               "line": text.count("\n", 0, offset) + 1})
    return result


def _document_declarations(document):
    suffix = PurePosixPath(document["path"]).suffix.lower()
    path = PurePosixPath(document["path"])
    if path.name == "package.json":
        return _node_declarations(document)
    if path.name.startswith("Dockerfile"):
        declarations = []
        stage = None
        for line_number, line in enumerate(document["content"].splitlines(), 1):
            instruction = re.fullmatch(r"\s*(FROM|COPY|ARG|ENV|WORKDIR)\s+(.+?)\s*", line, re.I)
            if not instruction:
                continue
            name, raw = instruction[1].upper(), instruction[2]
            if name == "FROM":
                match = re.fullmatch(r"(\S+)(?:\s+AS\s+([A-Za-z0-9_-]+))?", raw, re.I)
                stage = match[2] if match else None
            # Image strings and platform options are declarations, never native compiler evidence.
            declarations.append({"predicate": "container:" + name.lower(),
                "value": {"raw": raw, "stage": stage},
                "condition": "unresolved", "line": line_number})
        return declarations
    if (path.parent.name == "ProjectSettings" and path.name in {
            "ProjectSettings.asset", "EditorBuildSettings.asset", "ProjectVersion.txt"}
            or suffix == ".meta" and "PluginImporter:" in document["content"]):
        declarations = []
        for line_number, line in enumerate(document["content"].splitlines(), 1):
            match = re.fullmatch(r"\s*(m_EditorVersion|scriptingBackend|scriptingDefineSymbols|"
                                 r"apiCompatibilityLevelPerPlatform|m_Enabled|enabled|path|"
                                 r"CPU|OS|first|second|isPreloaded|platformData)\s*:\s*(.*?)\s*", line)
            if match:
                declarations.append({"predicate": "unity:raw_declaration",
                    "value": {"key": match[1], "raw": match[2], "scope": path.as_posix()},
                    "condition": "unresolved", "line": line_number})
        declarations.append({"predicate": "coverage_gap", "value": "unity_platform_plugin_semantics_partial",
                             "condition": "unresolved", "line": 1})
        return declarations
    if suffix in {".vcxproj", ".vcproj", ".csproj", ".vbproj", ".fsproj", ".props", ".targets"}:
        return _xml_declarations(document)
    result = []
    if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}:
        result.append({"predicate": "cpp:translation_unit", "value": suffix,
                       "condition": None, "line": 1})
        for index, line in enumerate(document["content"].splitlines(), 1):
            include = re.match(r'\s*#\s*include\s*([<"])([^>"]+)[>"]', line)
            if include:
                result.append({"predicate": "cpp:include", "value": {
                    "path": include[2], "system": include[1] == "<"}, "condition": None, "line": index})
            elif re.match(r"\s*#\s*(?:if|ifdef|ifndef|elif)\b", line):
                result.append({"predicate": "cpp:condition", "value": line.strip(),
                               "condition": "unresolved", "line": index})
        return result
    if suffix == ".sln":
        for index, line in enumerate(document["content"].splitlines(), 1):
            member = re.match(
                r'\s*Project\("(\{[^"]+\})"\)\s*=\s*"([^"]+)",\s*"([^"]+)",\s*"(\{[^"]+\})"', line)
            mapping = re.match(r"\s*(\{[^}]+\})\.(.+?)\.(ActiveCfg|Build\.0)\s*=\s*(.+?)\s*$", line)
            if member:
                result.append({"predicate": "solution_member", "value": {
                    "type": member[1].lower(), "name": member[2], "path": member[3].replace("\\", "/"),
                    "guid": member[4].lower()}, "condition": None, "line": index})
            elif mapping:
                result.append({"predicate": "solution_mapping", "value": {
                    "guid": mapping[1].lower(), "solution": mapping[2],
                    "kind": mapping[3], "project": mapping[4]}, "condition": None, "line": index})
        return result
    if PurePosixPath(document["path"]).name == "CMakeLists.txt":
        for name, arguments, literal, evidence in _cmake_calls(document):
            result.append({"predicate": "cmake:" + name, "value": arguments,
                           "condition": None if literal else "unresolved",
                           "line": evidence["line"] or 1})
        return result
    text = document["content"]
    for index, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*")):
            continue
        assignment = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*([:+?]?=)\s*(.*)", stripped)
        include = re.match(r"(-?include|sinclude)\s+(.+)", stripped)
        make_rule = (re.match(r"^([^#\s:=][^:=]*?)\s*:(?!=)([^;#]*)(?:;(.*))?$", line)
                     if PurePosixPath(document["path"]).name in {"GNUmakefile", "makefile", "Makefile"}
                     else None)
        if assignment:
            result.append({"predicate": "assignment", "value": {
                "name": assignment[1], "operator": assignment[2], "value": assignment[3]},
                "condition": None, "line": index})
        elif include:
            result.append({"predicate": "include", "value": include[2],
                           "condition": None, "line": index})
        elif make_rule:
            literal = (all(re.fullmatch(r"[A-Za-z0-9_./+\t -]*", value) for value in make_rule.group(1, 2))
                       and not re.search(r"[$%]", make_rule[0]))
            result.append({"predicate": "make:rule", "value": {
                "targets": make_rule[1].split() if literal else [],
                "prerequisites": make_rule[2].split() if literal else [], "raw": line},
                "condition": None if literal else "unresolved", "line": index})
        elif re.match(r"(?:ifn?def|ifeq|ifneq|else|endif)\b", stripped):
            result.append({"predicate": "condition", "value": stripped,
                           "condition": "unresolved", "line": index})
        elif stripped.startswith(("AC_", "AM_")):
            result.append({"predicate": "autotools_declaration", "value": stripped,
                           "condition": "unresolved" if "$" in stripped else None, "line": index})
        if PurePosixPath(document["path"]).name.startswith(("build.gradle", "settings.gradle")):
            include_modules = re.match(r"\s*include\s*(?:\((.*?)\)|(.*))", stripped)
            if include_modules:
                arguments = include_modules[1] if include_modules[1] is not None else include_modules[2]
                modules = re.findall(r"""["'](:[A-Za-z0-9_:-]+)["']""", arguments)
                literal = bool(modules) and not re.sub(r"""["']:[A-Za-z0-9_:-]+["']|[\s,]""", "", arguments)
                result.append({"predicate": "gradle:include", "value": modules,
                               "condition": None if literal else "unresolved", "line": index})
            project_dir = re.search(
                r"""project\s*\(\s*["'](:[^"']+)["']\s*\)\.projectDir\s*=\s*(?:file\s*\(\s*|(?:new\s+)?File\s*\(\s*rootDir\s*,\s*)["']([^"']+)["']\s*\)""",
                stripped)
            if project_dir:
                result.append({"predicate": "gradle:project_dir", "value": {
                    "module": project_dir[1], "path": project_dir[2]},
                    "condition": None, "line": index})
            elif ".projectDir" in stripped:
                result.append({"predicate": "coverage_gap", "value": "gradle_project_dir_dynamic",
                               "condition": "unresolved", "line": index})
            if re.search(r"\bexternalNativeBuild\b|\bndkBuild\b", stripped):
                result.append({"predicate": "android:external_native", "value": stripped,
                               "condition": None, "line": index})
            applied = re.search(r"""apply\s*(?:\(\s*)?from\s*[=:]\s*["']([^"']+)["']""", stripped)
            if applied:
                result.append({"predicate": "gradle:apply_from", "value": applied[1],
                               "condition": None, "line": index})
            for key in ("compileSdk", "minSdk", "targetSdk", "abiFilters"):
                match = re.search(r"\b" + key + r"(?:Version)?\s*(?:[=(]\s*)?([^\n}]+)", stripped)
                if match:
                    value = match[1].strip().rstrip(")")
                    literal = bool(re.fullmatch(r"\d+", value)) if key != "abiFilters" else bool(
                        re.fullmatch(r"""["'][A-Za-z0-9_-]+["'](?:\s*,\s*["'][A-Za-z0-9_-]+["'])*""", value))
                    result.append({"predicate": "android:" + key, "value": value,
                                   "condition": None if literal else "unresolved", "line": index})
            plugin = re.search(r"com\.android\.(application|library)", stripped)
            if plugin:
                result.append({"predicate": "android:plugin", "value": plugin[1],
                               "condition": "apply_false" if re.search(r"\bapply\s+false\b", stripped) else None,
                               "line": index})
            for module in re.findall(r"project\s*\(\s*[\"'](:[^\"']+)", stripped):
                if project_dir:
                    continue
                result.append({"predicate": "gradle:project", "value": module,
                               "condition": None, "line": index})
    return result


def _scoped_documents(unit, facts_by_document):
    available = {item["path"] for item in unit["descriptor_package"]["documents"]}
    scoped = {marker["path"]: {("driver", marker["path"])} for marker in unit.get("markers", [])
              if marker["path"] in available}
    for path in sorted(available):
        candidate = PurePosixPath(path)
        root = PurePosixPath(unit["root"])
        if (candidate.name.startswith("Dockerfile")
                and (candidate.parent == root or candidate.parent in root.parents
                     or candidate.parent == PurePosixPath("."))):
            scoped.setdefault(path, set()).add(("container_context", path))
        if (unit["build_system"] == "unity" and (
                unit["root"] == "." or path.startswith(unit["root"] + "/"))
                and any(fact["predicate"].startswith("unity:") for fact in facts_by_document.get(path, ()))):
            scoped.setdefault(path, set()).add(("unity_declaration", path))
    if unit["build_system"] == "gradle":
        for marker in unit.get("markers", []):
            parent = PurePosixPath(marker["path"]).parent
            for name in ("settings.gradle", "settings.gradle.kts"):
                path = str(parent / name)
                if path in available:
                    scoped.setdefault(path, set()).add(("driver", path))
    pending = [(path, role, subject) for path, scopes in scoped.items() for role, subject in scopes]
    while pending:
        path, inherited_role, inherited_subject = pending.pop()
        for fact in facts_by_document.get(path, []):
            relative, role, subject = None, "imported_descriptor", inherited_subject
            if fact["predicate"] == "solution_member":
                relative = fact["value"]["path"]
                role, subject = "member_declaration", fact["value"]["guid"]
            elif fact["predicate"] == "Import":
                relative = fact["value"].get("Project")
            elif fact["predicate"] == "gradle:apply_from":
                relative = fact["value"]
            elif fact["predicate"] == "gradle:include" and fact["condition"] is None:
                overrides = {item["value"]["module"]: item["value"]["path"]
                             for item in facts_by_document[path] if item["predicate"] == "gradle:project_dir"}
                for module in fact["value"]:
                    directory = overrides.get(module, module.lstrip(":").replace(":", "/"))
                    for name in ("build.gradle", "build.gradle.kts"):
                        resolved = _resolve(str(PurePosixPath(path).parent), directory.rstrip("/") + "/" + name)
                        context = ("module_declaration", module)
                        if resolved in available and context not in scoped.get(resolved, set()):
                            scoped.setdefault(resolved, set()).add(context)
                            pending.append((resolved, *context))
            elif fact["predicate"] in {"ClCompile", "ClInclude", "Compile"}:
                relative = fact["value"].get("Include")
                role = "source_input"
            elif fact["predicate"] in {"cmake:add_library", "cmake:add_executable"}:
                for value in fact["value"][1:]:
                    resolved = _resolve(str(PurePosixPath(path).parent), value.replace("\\", "/"))
                    context = ("source_input", fact["fact_id"])
                    if resolved in available and context not in scoped.get(resolved, set()):
                        scoped.setdefault(resolved, set()).add(context)
                        pending.append((resolved, *context))
            elif fact["predicate"] == "make:rule" and fact["condition"] is None:
                for value in fact["value"]["prerequisites"]:
                    resolved = _resolve(str(PurePosixPath(path).parent), value)
                    context = ("source_input", fact["fact_id"])
                    if resolved in available and context not in scoped.get(resolved, set()):
                        scoped.setdefault(resolved, set()).add(context)
                        pending.append((resolved, *context))
            elif fact["predicate"] in {"cmake:include", "cmake:add_subdirectory"} and fact["value"]:
                relative = fact["value"][0]
                if fact["predicate"] == "cmake:add_subdirectory":
                    relative = relative.rstrip("/") + "/CMakeLists.txt"
            elif fact["predicate"] == "cpp:include" and not fact["value"]["system"]:
                relative = fact["value"]["path"]
                role = "source_input"
            if not isinstance(relative, str):
                continue
            resolved = _resolve(str(PurePosixPath(path).parent), relative.replace("\\", "/"))
            context = (role, subject)
            if resolved in available and context not in scoped.get(resolved, set()):
                scoped.setdefault(resolved, set()).add(context)
                pending.append((resolved, *context))
    return scoped


def compile_build_topology(units, *, source_fingerprint, component_relationships=(),
                           environment=None, profiles=None, hints=()):
    """Compile the complete accepted bundle. Hints have no authority over declaration bytes."""
    bundle = topology_evidence_bundle(units, source_fingerprint=source_fingerprint,
                                      environment=environment, profiles=profiles)
    sources = bundle_units(bundle)
    legacy_inputs = [{**unit, "recipe": None} for unit in sources]
    legacy = _compile_graph1(legacy_inputs, source_fingerprint=source_fingerprint)
    nodes = copy.deepcopy(legacy["nodes"])
    facts, bindings, declarations, relations = [], [], [], []
    seen_facts = set()
    facts_by_document = {}
    for document in bundle["documents"]:
        values = []
        for declaration in _document_declarations(document):
            fact = {**declaration, "path": document["path"], "sha256": document["sha256"],
                    "rule": RULES, "span": [declaration["line"], declaration["line"]]}
            fact["fact_id"] = _digest(fact)
            if fact["fact_id"] not in seen_facts:
                facts.append(fact)
                seen_facts.add(fact["fact_id"])
            values.append(fact)
        facts_by_document[document["path"]] = values
    by_root = {}
    for unit in sources:
        by_root.setdefault(unit["root"], []).append(unit["build_unit_id"])
    for unit in sources:
        uid = unit["build_unit_id"]
        node = next(item for item in nodes if item["build_unit_id"] == uid)
        node["recipe_revision"] = None
        scoped = _scoped_documents(unit, facts_by_document)
        own_facts = [fact for path in scoped for fact in facts_by_document[path]]
        for prefix, code in (("unity:", "unity_declarations_partial"),
                             ("container:", "container_declarations_advisory")):
            if any(fact["predicate"].startswith(prefix) for fact in own_facts):
                legacy["coverage_gaps"].append({
                    "code": code, "build_unit_ids": [uid], "blocking": False,
                    "reason": "scoped source declarations do not establish selected targets or native proof",
                    "evidence": [],
                })
        if node["build_system"] == "make":
            resolved = make_default_build_commands(unit)
            if resolved is not None:
                marker, commands = resolved
                if re.search(r"(?m)^[@+-]*(?:gcc|g\+\+|clang|clang\+\+|cc|c\+\+|\$\(CC\)|\$\(CXX\))\s+\S+", commands):
                    node.update(disposition="independent", owner_build_unit_id=uid)
                    legacy["coverage_gaps"] = [gap for gap in legacy["coverage_gaps"] if not (
                        gap["code"] == "unresolved_ownership" and uid in gap["build_unit_ids"])]
                for match in re.finditer(r"\$\(MAKE\)\s+-C\s+([A-Za-z0-9_./-]+)", commands):
                    path = _resolve(unit["root"], match[1])
                    candidates = by_root.get(path, [])
                    relation = {"consumer_build_unit_id": uid,
                                "producer_build_unit_id": candidates[0] if len(candidates) == 1 else None,
                                "interface": path, "kind": "invokes_unit", "operation": "unknown",
                                "required": False, "condition": None, "resolution": "candidate",
                                "reason": "recursive invocation does not establish whole-unit precedence",
                                "fact_ids": [fact["fact_id"] for fact in own_facts if fact["path"] == marker["path"]]}
                    relation["relation_id"] = _digest(relation)
                    relations.append(relation)
        for fact in own_facts:
            for stage, subject in sorted(scoped[fact["path"]]):
                binding = {"fact_id": fact["fact_id"], "build_unit_id": uid,
                           "subject": subject, "stage": stage,
                           "condition": fact["condition"], "scope_rule": RULES}
                binding["binding_id"] = _digest(binding)
                bindings.append(binding)
        for product in node["products"]:
            role = ("static_archive" if product["variant"]["linkage"] == "static" else
                    "runtime_shared" if product["variant"]["linkage"] == "shared" else None
                    ) if product["kind"] == "library" else "executable"
            declarations.append({**product, "owner_build_unit_id": uid, "role": role,
                                 "origin": "source_declaration", "declared_path": None,
                                 "evidence": copy.deepcopy(node["evidence"])})
        descriptor = any(fact["predicate"] == "project_descriptor" for fact in own_facts)
        if descriptor and node["disposition"] == "unsupported":
            node.update(disposition="independent", owner_build_unit_id=uid)
        for fact in own_facts:
            if fact["predicate"] in {"ProjectReference", "gradle:project"}:
                value = fact["value"]
                relative = value.get("Include") if isinstance(value, Mapping) else value
                if not isinstance(relative, str):
                    continue
                path = _resolve(str(PurePosixPath(fact["path"]).parent), relative.replace("\\", "/"))
                owners = by_root.get(str(PurePosixPath(path).parent), []) if path else []
                producer = owners[0] if len(owners) == 1 else None
                relation = {"consumer_build_unit_id": uid, "producer_build_unit_id": producer,
                            "interface": relative, "kind": "requires_product",
                            "operation": "unknown", "required": True, "condition": fact["condition"],
                            "resolution": "declared_conditional" if fact["condition"] else
                            "candidate" if producer else "unresolved",
                            "reason": "selected operation and product role require binding",
                            "fact_ids": [fact["fact_id"]]}
                relation["relation_id"] = _digest(relation)
                relations.append(relation)
            if fact["predicate"] in {"TargetName", "OutputFile", "ImportLibrary", "ConfigurationType"}:
                role = "import_library" if fact["predicate"] == "ImportLibrary" else "metadata"
                declarations.append({"product_id": _digest({"owner": uid, "fact": fact["fact_id"]}),
                                     "kind": "library" if role == "import_library" else "package_metadata",
                                     "interface": str(fact["value"]), "variant": dict(node["variant"]),
                                     "owner_build_unit_id": uid, "role": role,
                                     "origin": "source_declaration", "declared_path": fact["value"],
                                     "condition": fact["condition"],
                                     "evidence": [{"path": fact["path"], "sha256": fact["sha256"],
                                                   "line": fact["line"], "relationship": fact["predicate"],
                                                   "declaration": str(fact["value"])}]})
    edges = []
    for edge in legacy["edges"]:
        if any(re.search(r"\b(?:DEBUG|OPTIMIZED|GENERAL)\b", evidence["declaration"] or "", re.IGNORECASE)
               for evidence in edge["evidence"]):
            relation = {"consumer_build_unit_id": edge["consumer_build_unit_id"],
                        "producer_build_unit_id": edge["producer_build_unit_id"],
                        "interface": edge["requirement"]["interface"] if edge["requirement"] else None,
                        "kind": edge["kind"], "operation": "native_link", "required": True,
                        "condition": "cmake_configuration_qualified", "resolution": "declared_conditional",
                        "reason": "configuration-qualified declaration is not unconditional scheduling",
                        "fact_ids": [fact["fact_id"] for fact in facts if any(
                            fact["path"] == evidence["path"] and fact["line"] == evidence["line"]
                            for evidence in edge["evidence"])]}
            relation["relation_id"] = _digest(relation)
            relations.append(relation)
        else:
            edges.append(edge)
    graph = {"schema": BUILD_TOPOLOGY_SCHEMA, "source_fingerprint": source_fingerprint,
             "bundle_identity": _digest(bundle), "rules": RULES, "nodes": _ordered(nodes),
             "edges": _ordered(edges), "external_requirements": legacy["external_requirements"],
             "coverage_gaps": legacy["coverage_gaps"], "facts": _ordered(facts),
             "bindings": _ordered(bindings), "declarations": _ordered(declarations),
             "relations": _ordered(relations)}
    graph["topology_id"] = topology_identity(graph)
    validate_build_topology(graph)
    return graph


def topology_identity(graph):
    if graph.get("schema") == "appsec-review/build-topology/1":
        return _identity_graph1(graph)
    return _digest({key: value for key, value in graph.items() if key != "topology_id"})


def validate_build_topology(graph):
    if graph.get("schema") == "appsec-review/build-topology/1":
        return _validate_graph1(graph)
    if len(canonical_json(graph)) > 16 * 1024 * 1024:
        raise ValueError("graph/2 exceeds its 16 MiB byte bound")
    keys = {"schema", "source_fingerprint", "bundle_identity", "rules", "topology_id", "nodes",
            "edges", "external_requirements", "coverage_gaps", "facts", "bindings",
            "declarations", "relations"}
    if (set(graph) != keys or graph.get("schema") != BUILD_TOPOLOGY_SCHEMA
            or graph.get("rules") != RULES or not _hash(graph.get("bundle_identity"))
            or graph.get("topology_id") != topology_identity(graph)):
        raise ValueError("unsupported or changed graph/2 identity")
    view = {key: copy.deepcopy(graph[key]) for key in (
        "schema", "source_fingerprint", "nodes", "edges", "external_requirements", "coverage_gaps")}
    view["schema"] = "appsec-review/build-topology/1"
    view["topology_id"] = _identity_graph1(view)
    _validate_graph1(view)
    if any(node["recipe_revision"] is not None for node in graph["nodes"]):
        raise ValueError("canonical graph cannot contain recipe-dependent bindings")
    facts = {fact["fact_id"]: fact for fact in graph["facts"]}
    if len(facts) != len(graph["facts"]):
        raise ValueError("duplicate source fact")
    for identity, fact in facts.items():
        if identity != _digest({key: value for key, value in fact.items() if key != "fact_id"}):
            raise ValueError("source fact identity changed")
    nodes = {node["build_unit_id"] for node in graph["nodes"]}
    for binding in graph["bindings"]:
        if (binding["fact_id"] not in facts or binding["build_unit_id"] not in nodes
                or binding["binding_id"] != _digest({
                    key: value for key, value in binding.items() if key != "binding_id"})):
            raise ValueError("unresolved source fact binding")
    if len(canonical_json(graph)) > 16 * 1024 * 1024:
        raise ValueError("graph exceeds its byte budget")


def _condition_applies(condition, configuration, platform):
    if condition is None:
        return True
    if not isinstance(condition, str) or len(condition) > 8192:
        return None
    text = condition
    for name, value in (("Configuration", configuration), ("Platform", platform)):
        if value is not None:
            text = text.replace("$(" + name + ")", value)
    token_pattern = re.compile(r"""\s*(==|!=|\(|\)|\bAND\b|\bOR\b|'[^']*'|"[^"]*")""", re.I)
    tokens, offset = [], 0
    while offset < len(text.rstrip()):
        match = token_pattern.match(text, offset)
        if match is None or len(tokens) >= 256:
            return None
        tokens.append(match[1])
        offset = match.end()
    position = 0

    def primary(depth):
        nonlocal position
        if depth > 32 or position >= len(tokens):
            raise ValueError("unsupported selected condition")
        if tokens[position] == "(":
            position += 1
            value = expression(depth + 1)
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError("unclosed selected condition")
            position += 1
            return value
        if position + 2 >= len(tokens):
            raise ValueError("incomplete selected comparison")
        left, operator, right = tokens[position:position + 3]
        if left[0] not in "'\"" or right[0] not in "'\"" or operator not in {"==", "!="}:
            raise ValueError("unsupported selected comparison")
        position += 3
        if "$(" in left or "$(" in right:
            return None
        equal = left[1:-1].casefold() == right[1:-1].casefold()
        return equal if operator == "==" else not equal

    def conjunction(depth):
        nonlocal position
        value = primary(depth)
        while position < len(tokens) and tokens[position].upper() == "AND":
            position += 1
            other = primary(depth)
            value = False if value is False or other is False else None if (
                value is None or other is None) else True
        return value

    def expression(depth):
        nonlocal position
        value = conjunction(depth)
        while position < len(tokens) and tokens[position].upper() == "OR":
            position += 1
            other = conjunction(depth)
            value = True if value is True or other is True else None if (
                value is None or other is None) else False
        return value

    try:
        value = expression(0)
        return value if position == len(tokens) else None
    except ValueError:
        return None


def _node_requested_operations(unit, commands, facts):
    manifest_path = str(PurePosixPath(unit["root"]) / "package.json")
    manifest_facts = [fact for fact in facts if fact["path"] == manifest_path]
    lifecycle = [fact for fact in manifest_facts if fact["predicate"] == "node:lifecycle"]
    scripts = {fact["value"]["name"]: fact for fact in manifest_facts if fact["predicate"] == "node:script"}
    gyp = any(PurePosixPath(ref["path"]) == PurePosixPath(unit["root"]) / "binding.gyp"
              for ref in unit.get("descriptor_package", {}).get("documents", []))
    native, reasons = False, set()

    def script(name, active, arguments=()):
        nonlocal native
        if name not in scripts:
            return
        fact = scripts[name]
        if name in active or len(active) >= 16 or fact["condition"] is not None:
            reasons.add("node_script_effective_operation_unresolved")
            return
        try:
            lexer = shlex.shlex(fact["value"]["command"], posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            lexer.commenters = ""
            argv = list(lexer)
        except ValueError:
            reasons.add("node_script_effective_operation_unresolved")
            return
        if not argv or any(value in {"&&", "||", ";", "|", "&", "(", ")", "<", ">"}
                           or any(character in value for character in ("$", "`", "\n")) for value in argv):
            reasons.add("node_script_effective_operation_unresolved")
            return
        command([*argv, *arguments], (*active, name))

    def command(argv, active=()):
        nonlocal native
        if not argv:
            return
        if argv[0] == "node-gyp":
            if len(argv) > 1 and argv[1] in {"build", "rebuild"}:
                native = True
            elif len(argv) > 1 and argv[1] == "configure":
                reasons.add("node_configuration_stage_unresolved")
            else:
                reasons.add("node_script_effective_operation_unresolved")
            return
        if argv[0] != "npm":
            if argv[0] not in {"tsc", "esbuild", "webpack"}:
                reasons.add("node_script_effective_operation_unresolved")
            return
        delimiter = argv.index("--") if "--" in argv else len(argv)
        control, forwarded = argv[:delimiter], argv[delimiter + 1:]
        if (len(control) < 2 or control[1].startswith("-") or
                any(value in {"--prefix", "--workspace", "--workspaces", "-w", "--global", "-g"}
                    or value.startswith(("--prefix=", "--workspace=")) for value in control[2:])):
            reasons.add("node_requested_lifecycle_unresolved")
            return
        if len(lifecycle) != 1:
            reasons.add("node_manifest_unresolved")
            return
        verb = control[1]
        ignore = "--ignore-scripts" in control or "--ignore-scripts=true" in control
        if "--ignore-scripts=false" in control and ignore:
            reasons.add("node_requested_lifecycle_unresolved")
            return
        requested = None
        if verb in {"run", "run-script"}:
            if len(control) < 3 or control[2].startswith("-") or control[2] not in scripts:
                reasons.add("node_requested_script_uncaptured")
                return
            requested = control[2]
            names = (requested,) if ignore else ("pre" + requested, requested, "post" + requested)
        elif verb in {"pack", "publish", "install", "ci", "rebuild"}:
            if forwarded or any(not value.startswith("-") for value in control[2:]):
                reasons.add("node_dependency_lifecycle_uncaptured")
            names = {
                "pack": ("prepack", "prepare", "postpack"),
                "publish": ("prepublishOnly", "prepack", "prepare", "postpack", "publish", "postpublish"),
                "install": ("preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"),
                "ci": ("preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"),
                "rebuild": ("preinstall", "install", "postinstall", "prepare"),
            }[verb]
            if ignore:
                names = ()
            elif verb in {"install", "ci", "rebuild"} and gyp and not ({"preinstall", "install"} & scripts.keys()):
                gypfile = lifecycle[0]["value"]["gypfile"]
                if gypfile is True:
                    native = True
                elif gypfile is not False:
                    reasons.add("node_manifest_unresolved")
        else:
            reasons.add("node_requested_lifecycle_unresolved")
            return
        for name in names:
            script(name, active, forwarded if name == requested else ())

    for argv in commands:
        command(argv)
    return native, sorted(reasons)


def _selected_operations(unit, graph, recipe, selected):
    uid = unit["build_unit_id"]
    fact_ids = {binding["fact_id"] for binding in graph["bindings"] if binding["build_unit_id"] == uid}
    facts = [fact for fact in graph["facts"] if fact["fact_id"] in fact_ids]
    configuration = unit.get("build_variant", {}).get("configuration")
    platform = "x64" if selected["required_axes"]["isa"] == "x86_64" else None
    commands = [] if recipe is None else [*recipe["configure_commands"], *recipe["build_commands"]]
    property_overrides = {}
    for argv in commands:
        for index, arg in enumerate(argv):
            if re.match(r"(?i)[/-]p:Configuration=", arg):
                configuration = arg.partition("=")[2]
            elif arg in {"--configuration", "-c"} and index + 1 < len(argv):
                configuration = argv[index + 1]
            elif re.match(r"(?i)[/-]p:Platform=", arg):
                platform = arg.partition("=")[2]
            property_arg = re.fullmatch(r"(?i)[/-]p:([A-Za-z][A-Za-z0-9_]*)=(.+)", arg)
            if property_arg:
                name, value = property_arg[1], property_arg[2]
                name = {key.lower(): key for key in (
                    "Configuration", "Platform", "PlatformTarget", "Prefer32Bit", "PublishAot",
                    "NativeAot", "RuntimeIdentifier")}.get(name.lower(), name)
                if name in property_overrides and property_overrides[name] != value:
                    property_overrides[name] = None
                else:
                    property_overrides[name] = value
    kinds, reasons = set(), []
    gradle_modules = set()
    if unit["build_system"] == "gradle":
        requested = {arg.rsplit(":", 1)[0] for argv in commands for arg in argv[1:]
                     if arg.startswith(":") and ":" in arg[1:]}
        included = {module for fact in facts if fact["predicate"] == "gradle:include"
                    for module in fact["value"]}
        gradle_modules = requested or included
        selected_ids = {binding["fact_id"] for binding in graph["bindings"] if binding["build_unit_id"] == uid
                        and (not binding["subject"].startswith(":") or binding["subject"] in gradle_modules)}
        facts = [fact for fact in facts if fact["fact_id"] in selected_ids]
        captured_modules = {binding["subject"] for binding in graph["bindings"]
                            if binding["build_unit_id"] == uid and binding["stage"] == "module_declaration"}
        if gradle_modules - captured_modules:
            reasons.append("requested_gradle_module_uncaptured")
    native_suffixes = {".vcxproj", ".vcproj"}
    managed_suffixes = {".csproj", ".vbproj", ".fsproj"}
    descriptors = [fact for fact in facts if fact["predicate"] == "project_descriptor"]
    members = [fact for fact in facts if fact["predicate"] == "solution_member"]
    mappings = [fact for fact in facts if fact["predicate"] == "solution_mapping"]
    selected_members = []
    for member in members:
        builds = [mapping for mapping in mappings if mapping["value"]["guid"] == member["value"]["guid"]
                  and mapping["value"]["kind"] == "Build.0"
                  and mapping["value"]["solution"] == f"{configuration}|{platform}"]
        if not configuration:
            reasons.append("selected_solution_configuration_unknown")
            continue
        if not builds:
            continue
        mapped_configuration, _, mapped_platform = builds[0]["value"]["project"].partition("|")
        active = [mapping for mapping in mappings if mapping["value"]["guid"] == member["value"]["guid"]
                  and mapping["value"]["kind"] == "ActiveCfg"
                  and mapping["value"]["solution"] == f"{configuration}|{platform}"]
        if len(builds) != 1 or len(active) != 1 or active[0]["value"]["project"] != builds[0]["value"]["project"]:
            reasons.append("selected_solution_mapping_unclosed")
        path = _resolve(str(PurePosixPath(member["path"]).parent), member["value"]["path"])
        captured = [fact for fact in descriptors if fact["path"] == path]
        selected_members.append({"path": path, "configuration": mapped_configuration,
                                 "platform": mapped_platform, "captured": bool(captured),
                                 "subject": member["value"]["guid"],
                                 "fact_ids": [member["fact_id"], *[item["fact_id"] for item in builds]]})
        if not captured:
            kinds.add("unknown")
            reasons.append("selected_member_uncaptured")
        elif PurePosixPath(path).suffix.lower() in native_suffixes:
            kinds.update({"native_compile", "native_link"})
        elif PurePosixPath(path).suffix.lower() in managed_suffixes:
            kinds.add("managed_compile")
        else:
            kinds.add("unknown")
    if not members:
        if any(fact["value"]["kind"] in native_suffixes for fact in descriptors):
            kinds.update({"native_compile", "native_link"})
        elif any(fact["value"]["kind"] in managed_suffixes for fact in descriptors):
            kinds.add("managed_compile")
        elif unit["build_system"] in {"cmake", "make", "autotools"} and any(
                fact["predicate"].startswith(("cmake:", "autotools")) or
                PurePosixPath(fact["path"]).name in {"Makefile", "Makefile.am"} for fact in facts):
            kinds.update({"native_compile", "native_link"})
        elif unit["build_system"] in {"maven", "gradle"} and any(
                PurePosixPath(ref["path"]).name in {"pom.xml", "build.gradle", "build.gradle.kts"}
                for ref in unit.get("descriptor_package", {}).get("documents", [])):
            kinds.add("managed_compile")
        elif unit["family"] == "go" and commands and any(argv[0] == "go" for argv in commands):
            kinds.add("native_compile")
        elif unit["family"] == "rust" and commands and any(argv[0] == "cargo" for argv in commands):
            kinds.add("native_compile")
        elif unit["family"] in {"node", "python", "php"} and commands:
            kinds.add("package")
        else:
            kinds.add("unknown")
    property_facts = facts
    if members:
        paths = {member["path"]: member for member in selected_members if member["captured"]}
        subjects = {member["subject"]: member for member in selected_members if member["captured"]}
        selected_ids = {binding["fact_id"] for binding in graph["bindings"]
                        if binding["build_unit_id"] == uid and binding["subject"] in subjects}
        property_facts = [fact for fact in facts if fact["fact_id"] in selected_ids]
        properties_by_id = {fact["fact_id"]: fact for fact in property_facts}
        for binding in graph["bindings"]:
            if binding["build_unit_id"] == uid and binding["subject"] in subjects:
                fact = properties_by_id[binding["fact_id"]]
                paths.setdefault(fact["path"], subjects[binding["subject"]])
        facts = [fact for fact in facts if fact["fact_id"] in selected_ids
                 or fact["predicate"] in {"solution_member", "solution_mapping"}]
    else:
        paths = {}
    publishing = any(argv and argv[0] == "dotnet" and "publish" in argv for argv in commands)
    override_properties = {"PlatformTarget", "Prefer32Bit", "PublishAot", "NativeAot", "RuntimeIdentifier"}
    property_facts = [{**fact, "value": property_overrides[fact["predicate"]], "condition": None}
                      if fact["predicate"] in override_properties and fact["predicate"] in property_overrides
                      else fact for fact in property_facts]
    existing_properties = {fact["predicate"] for fact in property_facts}
    property_facts += [{"predicate": name, "value": value, "condition": None, "path": "@recipe"}
                       for name, value in property_overrides.items()
                       if name in override_properties and name not in existing_properties]
    for fact in property_facts:
        member = paths.get(fact["path"])
        member_configuration = member["configuration"] if member else configuration
        member_platform = member["platform"] if member else platform
        applicable = _condition_applies(fact["condition"], member_configuration, member_platform)
        if applicable is False:
            continue
        if fact["predicate"] in override_properties and fact["value"] is None:
            kinds.add("unknown")
            reasons.append("contradictory_selected_property_override")
        if fact["predicate"] == "Exec":
            kinds.add("unknown")
            reasons.append("selected_custom_task_operation_unresolved")
        if publishing and fact["predicate"] in {"PublishAot", "NativeAot"} and str(fact["value"]).lower() == "true":
            kinds.add("native_aot" if applicable else "unknown")
        if ("managed_compile" in kinds and fact["predicate"] == "PlatformTarget"
                and str(fact["value"]).lower() == "x86"):
            reasons.append("managed_x86_incompatible" if applicable else "managed_axis_applicability_unknown")
        if "managed_compile" in kinds and fact["predicate"] == "Prefer32Bit" and str(fact["value"]).lower() == "true":
            properties = {item["predicate"]: item["value"] for item in property_facts
                          if (item["path"] == fact["path"] or fact["path"] == "@recipe") and _condition_applies(
                              item["condition"], member_configuration, member_platform) is True}
            output_type = str(properties.get("OutputType", "")).lower()
            raw_target = properties.get("PlatformTarget", member_platform)
            target = str(raw_target).replace(" ", "").lower() if raw_target is not None else None
            framework = str(properties.get("TargetFramework", properties.get("TargetFrameworkVersion", ""))).lower()
            applicable_framework = framework.startswith("v") or bool(re.fullmatch(r"net[1-4][0-9]{1,2}", framework))
            if output_type == "library" or target not in {None, "anycpu"}:
                continue
            if framework.startswith(("netcoreapp", "netstandard")) or re.match(r"net[5-9]\.", framework):
                continue
            reasons.append("managed_prefer32bit_incompatible" if applicable and
                           output_type in {"exe", "winexe"} and target == "anycpu"
                           and applicable_framework else "managed_prefer32bit_applicability_unknown")
    node_native = False
    if unit["family"] == "node" and commands:
        node_native, node_reasons = _node_requested_operations(unit, commands, facts)
        reasons.extend(node_reasons)
        if node_reasons:
            kinds.add("unknown")
    if node_native:
        kinds.add("native_compile")
    direct_native = commands and all(argv[0] in {"clang", "clang++", "gcc", "g++"} for argv in commands)
    if (unit.get("native_components") and not direct_native
            and (unit["family"] != "node" or node_native)):
        kinds.add("unknown")
        reasons.append("native_component_requested_stage_unresolved")
    if any(fact["predicate"] == "android:plugin" and fact["condition"] is None for fact in facts):
        kinds.add("bytecode_transform")
    if unit["build_system"] == "gradle":
        if any(fact["predicate"] == "coverage_gap" for fact in facts):
            reasons.append("gradle_effective_input_unknown")
        native_stage = any(re.search(r"(?:assemble|bundle|build|externalNativeBuild|install)", arg, re.I)
                           for argv in commands for arg in argv[1:] if not arg.startswith("-"))
        if native_stage and any(fact["predicate"] == "android:external_native" for fact in facts):
            kinds.update({"native_compile", "native_link"})
    if commands and all(argv[0] in {"clang", "clang++", "gcc", "g++"} for argv in commands):
        if all("-c" in argv for argv in commands):
            kinds.discard("native_link")
        if any(any(arg in {"--version", "--help", "-E"} for arg in argv) for argv in commands):
            kinds = {"unknown"}
            reasons.append("unsupported_requested_compiler_stage")
    if commands and all(argv[0] == "dotnet" and len(argv) > 1 and argv[1] == "restore" for argv in commands):
        kinds = {"prebuilt_import"}
        reasons = [reason for reason in reasons if not reason.startswith("managed_")]
    for fact in property_facts:
        if fact["predicate"] == "RuntimeIdentifier" and str(fact["value"]).endswith(("-x86", "-arm")):
            member = paths.get(fact["path"])
            applicable = _condition_applies(
                fact["condition"], member["configuration"] if member else configuration,
                member["platform"] if member else platform)
            if applicable is not False:
                reasons.append("32bit_runtime_selection_forbidden" if applicable else
                               "runtime_identifier_applicability_unknown")
    if unit["family"] == "go" and recipe and recipe["environment"].get("CGO_ENABLED") == "1":
        kinds.add("native_link")
    operations = []
    for kind in sorted(kinds):
        operation = {"build_unit_id": uid, "kind": kind, "requested": bool(commands),
                     "basis": sorted(fact_ids), "selected_members": selected_members,
                     "property_overrides": property_overrides,
                     "selected_modules": sorted(gradle_modules),
                     "reasons": sorted(set(reasons))}
        operation["operation_id"] = _digest(operation)
        operations.append(operation)
    contexts = {}
    for binding in graph["bindings"]:
        if binding["build_unit_id"] != uid:
            continue
        member = next((member for member in selected_members
                       if member["subject"] == binding["subject"]), None)
        context = {"configuration": member["configuration"] if member else configuration,
                   "platform": member["platform"] if member else platform}
        contexts.setdefault(binding["fact_id"], []).append(context)
    facts = [{**fact, "selected_contexts": _ordered(contexts.get(fact["fact_id"], []))}
             for fact in facts]
    return operations, facts


def _compiler_axes(target):
    words = target.lower().split("-")
    isa = {"amd64": "x86_64", "x86_64": "x86_64", "aarch64": "arm64",
           "arm64": "arm64", "i686": "x86", "i386": "x86"}.get(words[0])
    android = next((word for word in words if re.fullmatch(r"android\d*", word)), None)
    ios = next((word for word in words if re.fullmatch(r"ios(?:\d+(?:\.\d+)*)?", word)), None)
    platform = ("android" if android else "ios" if ios else "linux" if "linux" in words else
                "windows" if any(word in {"windows", "win32", "mingw32"} for word in words) else None)
    abi = ("android" if android else "apple" if ios else "msvc" if "msvc" in words else
           "gnu" if "gnu" in words else "musl" if "musl" in words else None)
    axes = {"os": platform, "isa": isa, "abi": abi}
    if ios or android:
        version = (ios[3:] if ios else android[7:])
        axes["deployment"] = version or None
    if ios:
        axes["device_kind"] = "simulator" if "simulator" in words else "device"
    return axes


def _native_enforcement(unit, graph, recipe, selection, operation, facts, profiles):
    facts = [fact for fact in facts if not fact["predicate"].startswith(("container:", "unity:"))
             and not (fact["predicate"] == "coverage_gap"
                      and fact["value"] == "unity_platform_plugin_semantics_partial")]
    unresolved, axes, kind = [], {}, "compiler_explicit_target"
    uid = unit["build_unit_id"]
    commands = [] if recipe is None else [*recipe["configure_commands"], *recipe["build_commands"]]
    environment = {} if recipe is None else recipe["environment"]
    closure = {"schema": "appsec-review/effective-input-closure/1", "rules": RULES,
               "commands": commands, "environment": environment,
               "profiles": profiles}
    if any(fact["predicate"] == "make:rule" and fact["condition"] is not None for fact in facts):
        unresolved.append("make_rule_scope_unresolved")
    documents = {ref["path"] for ref in unit.get("descriptor_package", {}).get("documents", [])}
    direct_compilers = bool(commands) and all(argv[0] in {"clang", "clang++", "gcc", "g++"} for argv in commands)
    effective_paths = {fact["path"] for fact in facts}
    if direct_compilers:
        effective_paths = set()
        source_facts = {}
        for fact in graph["facts"]:
            if fact["path"] in documents:
                source_facts.setdefault(fact["path"], []).append(fact)
        command_contexts = [(phase, argv) for phase, key in (
            ("configure", "configure_commands"), ("build", "build_commands")) for argv in recipe[key]]
        for phase, argv in command_contexts:
            for arg in argv[1:]:
                if PurePosixPath(arg).suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}:
                    path = _resolve(recipe_execution_cwd(recipe, phase), arg)
                    if path not in documents:
                        unresolved.append("compiler_source_closure_unknown")
                    elif path:
                        effective_paths.add(path)
        pending = list(effective_paths)
        while pending:
            path = pending.pop()
            accepted = source_facts.get(path, [])
            if not any(fact["predicate"] == "cpp:translation_unit" for fact in accepted):
                unresolved.append("compiler_source_facts_unknown")
            for fact in accepted:
                if fact["predicate"] != "cpp:include":
                    continue
                included = _resolve(str(PurePosixPath(path).parent), fact["value"]["path"])
                if fact["value"]["system"] or included not in documents:
                    unresolved.append("effective_import_unknown")
                elif included not in effective_paths:
                    effective_paths.add(included)
                    pending.append(included)
        selected_ids = {fact["fact_id"] for fact in facts}
        facts = [*facts, *[{**fact, "selected_contexts": []} for fact in graph["facts"]
                          if fact["path"] in effective_paths and fact["fact_id"] not in selected_ids]]
        for argv in commands:
            index = 1
            while index < len(argv):
                arg = argv[index]
                if not arg.startswith("-") and PurePosixPath(arg).suffix.lower() in {".o", ".obj"}:
                    unresolved.append("prebuilt_compiler_input_target_unknown")
                if arg in {"-o", "-target", "--target"}:
                    if index + 1 >= len(argv):
                        unresolved.append("compiler_option_operand_missing")
                    index += 2
                    continue
                if (arg in {"-c", "-g", "-m32", "-m64", "-Wall", "-Wextra", "-Werror"}
                        or re.fullmatch(r"-O[0-3gsz]", arg) or arg.startswith("--target=")
                        or not arg.startswith("-") and PurePosixPath(arg).suffix.lower() in {
                            ".c", ".cc", ".cpp", ".cxx", ".o", ".obj"}):
                    index += 1
                    continue
                unresolved.append("unsupported_effective_compiler_option")
                index += 1
    closure["fact_ids"] = sorted(fact["fact_id"] for fact in facts)
    for fact in facts:
        if fact["path"] not in effective_paths:
            continue
        applicability = [_condition_applies(fact["condition"], context["configuration"], context["platform"])
                         for context in fact["selected_contexts"]]
        if applicability and all(value is False for value in applicability):
            continue
        if any(value is None for value in applicability):
            unresolved.append("effective_input_condition_or_parse_unknown")
        if fact["predicate"] in {"condition", "coverage_gap", "cpp:condition"}:
            unresolved.append("effective_input_condition_or_parse_unknown")
        if fact["predicate"] in {"include", "Import"}:
            value = fact["value"].get("Project") if isinstance(fact["value"], Mapping) else fact["value"]
            path = _resolve(str(PurePosixPath(fact["path"]).parent), str(value).replace("\\", "/"))
            if not path or path not in documents:
                unresolved.append("effective_import_unknown")
    unresolved.extend(unit.get("descriptor_package", {}).get("gaps", []))
    if recipe is None:
        unresolved.append("recipe_missing")
    elif unit["family"] == "go":
        kind = "go_explicit_target"
        axes = {"os": environment.get("GOOS"),
                "isa": "x86_64" if environment.get("GOARCH") == "amd64" else
                "x86" if environment.get("GOARCH") == "386" else None}
        if environment.get("CGO_ENABLED") not in {"0", "1"}:
            unresolved.append("explicit_cgo_mode_missing")
        if environment.get("CGO_ENABLED") == "1":
            unresolved.append("cgo_c_compiler_enforcement_required")
        if any("=" in arg and arg.split("=", 1)[0] in {"GOOS", "GOARCH", "CGO_ENABLED"}
               for argv in commands for arg in argv):
            unresolved.append("go_target_override_unknown")
        if (set(environment) & {"PATH", "LD_PRELOAD", "GCC_EXEC_PREFIX"}
                or any("-toolexec" in arg or "-compiler" in arg for argv in commands for arg in argv)
                or "-toolexec" in environment.get("GOFLAGS", "")):
            unresolved.append("go_toolchain_closure_unknown")
    elif (operation["selected_members"] or unit["build_system"] in {"msbuild", "vcbuild"}) and operation["kind"] != "native_aot":
        kind = "msbuild_selected_mapping"
        platforms = [member["platform"] for member in operation["selected_members"]]
        if any(not member["captured"] for member in operation["selected_members"]):
            unresolved.append("selected_member_uncaptured")
        raw = [arg for argv in commands for arg in argv]
        platform_args = [arg.partition("=")[2] for arg in raw if
                         re.match(r"(?i)[/-]p:Platform=", arg)]
        config_args = [arg.partition("=")[2] for arg in raw if
                       re.match(r"(?i)[/-]p:Configuration=", arg)]
        config_args.extend(raw[index + 1] for index, arg in enumerate(raw[:-1])
                           if arg in {"--configuration", "-c"})
        unresolved.extend(operation["reasons"])
        if not platform_args or not config_args:
            unresolved.append("explicit_msbuild_configuration_platform_missing")
        elif len(set(platform_args)) != 1 or len(set(config_args)) != 1:
            unresolved.append("contradictory_msbuild_overrides")
        else:
            platforms = platforms or platform_args
            axes = {"os": "windows", "isa": "x86_64" if set(platforms) == {"x64"} else "x86"
                    if any(value.lower() == "win32" for value in platforms) else None}
        if not profiles or not isinstance(profiles, Mapping) or profiles.get("windows_capability") is not True:
            unresolved.append("windows_native_capability_unavailable")
        if (not isinstance(profiles, Mapping)
                or profiles.get("schema") != "appsec-review/static-compiler-profile/1"
                or profiles.get("driver_semantics") != "msbuild-mapping/1"
                or not _hash(profiles.get("compiler_sha256"))
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(profiles.get("image_digest")))
                or profiles.get("wrapper_closure") != [] or not profiles.get("provenance")):
            unresolved.append("msbuild_compiler_metadata_unverified")
        else:
            axes.update({key: value for key, value in profiles.get("target_axes", {}).items()
                         if key not in {"os", "isa"}})
            if profiles.get("target_axes", {}).get("os") != "windows":
                unresolved.append("msbuild_compiler_os_unknown")
        for fact in facts:
            applicability = [_condition_applies(fact["condition"], context["configuration"], context["platform"])
                             for context in fact["selected_contexts"]]
            if applicability and all(value is False for value in applicability):
                continue
            if fact["predicate"] in {"AdditionalOptions", "AdditionalDependencies",
                                     "AdditionalIncludeDirectories", "AdditionalLibraryDirectories",
                                     "ExecutablePath", "IncludePath", "LibraryPath", "CustomBuild",
                                     "Exec", "Tool"}:
                unresolved.append("msbuild_effective_option_closure_unknown")
            if fact["predicate"] == "TargetMachine":
                machine = str(fact["value"]).lower()
                if machine in {"machinex86", "1"}:
                    axes["isa"] = "x86"
                elif machine not in {"machinex64", "17"}:
                    unresolved.append("msbuild_link_target_unknown")
        if set(environment) & {"CL", "_CL_", "LINK", "_LINK_", "PATH", "INCLUDE", "LIB", "LIBPATH"}:
            unresolved.append("msbuild_environment_override_unknown")
        if set(operation["property_overrides"]) - {"Configuration", "Platform"}:
            unresolved.append("msbuild_effective_property_override_unknown")
    else:
        metadata = (profiles if isinstance(profiles, Mapping) and
                    profiles.get("schema") == "appsec-review/static-compiler-profile/1" else {})
        pinned_driver = (bool(metadata.get("provenance"))
                         and _hash(metadata.get("compiler_sha256"))
                         and re.fullmatch(r"sha256:[0-9a-f]{64}", str(metadata.get("image_digest")))
                         and metadata.get("wrapper_closure") == []
                         and metadata.get("driver_semantics") == "clang-target/1")
        candidates = []
        for argv in commands:
            if not argv or not pinned_driver or argv[0] != metadata.get("executable"):
                continue
            targets = [arg.split("=", 1)[1] for arg in argv if arg.startswith("--target=")]
            targets += [argv[index + 1] for index, arg in enumerate(argv[:-1]) if arg in {"-target", "--target"}]
            if len(set(targets)) == 1:
                candidates.append(_compiler_axes(targets[0]))
            elif targets:
                unresolved.append("conflicting_compiler_targets")
        if candidates and all(value == candidates[0] for value in candidates):
            axes = candidates[0]
            if len(candidates) != len(commands):
                unresolved.append("uncontrolled_noncompiler_command")
        elif profiles:
            kind = "compiler_pinned_default"
            if (isinstance(profiles, Mapping)
                    and profiles.get("schema") == "appsec-review/static-compiler-profile/1"
                    and _hash(profiles.get("compiler_sha256"))
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", str(profiles.get("image_digest")))
                    and profiles.get("provenance") and profiles.get("wrapper_closure") == []
                    and profiles.get("driver_semantics") in {"clang-target/1", "gcc-default/1"}
                    and commands and all(argv[0] == profiles.get("executable") for argv in commands)):
                axes = dict(profiles.get("target_axes", {}))
            else:
                unresolved.append("static_compiler_profile_unverified")
        else:
            unresolved.append("compiler_target_unknown")
        if any("$" in str(arg) for argv in commands for arg in argv):
            unresolved.append("dynamic_effective_command")
        if set(environment) & {"PATH", "CCC_OVERRIDE_OPTIONS", "COMPILER_PATH", "GCC_EXEC_PREFIX",
                               "LD_PRELOAD", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "SDKROOT"}:
            unresolved.append("uncontrolled_compiler_resolution_or_override")
    if direct_compilers and any(arg == "-m32" for argv in commands for arg in argv):
        axes["isa"] = "x86"
    elif direct_compilers and any(arg == "-m64" for argv in commands for arg in argv):
        if axes.get("isa") in {"x86", "x86_64"}:
            axes["isa"] = "x86_64"
        else:
            unresolved.append("bitness_flag_semantics_unknown")
    from appsec_review.config.build_selection import AXES
    if set(axes) - set(AXES) or any(value is not None and not isinstance(value, str) for value in axes.values()):
        unresolved.append("compiler_profile_axes_malformed")
        axes = {}
    axes = {key: axes.get(key) for key in AXES}
    required = selection["required_axes"]
    incompatible = (axes["isa"] in {"x86", "armv7", "wasm32"} or any(
        value is not None and axes.get(key) is not None and axes[key] != value
        for key, value in required.items()))
    for key in ("os", "isa"):
        if axes[key] is None:
            unresolved.append("native_target_axis_unknown:" + key)
    for key, value in required.items():
        if value is not None and axes.get(key) is None:
            unresolved.append("unenforced_axis:" + key)
    value = {"schema": ENFORCEMENT_SCHEMA, "build_unit_id": uid,
             "operation_id": operation["operation_id"], "required_axes": required,
             "proof_kind": kind, "status": "incompatible" if incompatible else
             "unknown" if unresolved else "proven", "proven_axes": axes,
             "unresolved_inputs": sorted(set(unresolved)), "scope_rule": RULES,
             "source_evidence_refs": sorted(fact["fact_id"] for fact in facts),
             "closure_manifest": closure, "source_fingerprint": graph["source_fingerprint"],
             "catalog_bundle_identity": graph["bundle_identity"],
             "selection_id": selection["selection_id"], "recipe_digest": _digest(recipe) if recipe else None,
             "operation_binding": operation["operation_id"] if recipe else None,
             "profile_identity": _digest(profiles) if profiles else None}
    value["enforcement_id"] = _digest(value)
    return value


_SAME_PROFILES = object()


def refine_build_topology(graph, units, *, policy=None, profiles=None, environment=None, releases=None,
                          bundle_profiles=_SAME_PROFILES):
    """Bind a recipe to the accepted graph.

    ``bundle_profiles`` are the planning profiles bound into the graph's evidence bundle.
    ``profiles`` are the compiler metadata used for enforcement and recorded in the refinement,
    which can be a later approved prepared image's metadata.
    """
    from appsec_review.config.build_selection import parse_build_selection
    validate_build_topology(graph)
    if graph["schema"] != BUILD_TOPOLOGY_SCHEMA:
        raise ValueError("graph/1 is inspectable but requires replanning for graph/2 execution")
    if bundle_profiles is _SAME_PROFILES:
        bundle_profiles = profiles
    if compile_build_topology(units, source_fingerprint=graph["source_fingerprint"],
                              environment=environment, profiles=bundle_profiles) != graph:
        raise ValueError("refinement inputs differ from the complete accepted source bundle")
    policy = parse_build_selection(policy)
    values = []
    for unit in sorted(units, key=lambda item: item["build_unit_id"]):
        fact_ids = {item["fact_id"] for item in graph["bindings"]
                    if item["build_unit_id"] == unit["build_unit_id"]}
        declarations = [fact for fact in graph["facts"]
                        if fact["fact_id"] in fact_ids and fact["condition"] is None]
        platforms = {"android" for fact in declarations if fact["predicate"] == "android:plugin"}
        for fact in declarations:
            if fact["predicate"] in {"TargetFramework", "TargetFrameworks"}:
                for framework in str(fact["value"]).split(";"):
                    match = re.fullmatch(r"net[0-9]+\.[0-9]+-(android|ios)[0-9.]*", framework.strip())
                    if match:
                        platforms.add(match.group(1))
        selection = policy.select({**unit, **({"declared_platform": next(iter(platforms))}
                                              if len(platforms) == 1 else {})})
        if len(platforms) > 1:
            selection["reasons"].append("declared_platform_selection_ambiguous")
            selection["status"] = "ambiguous"
            selection["selection_id"] = _digest({key: value for key, value in selection.items()
                                                if key != "selection_id"})
        recipe = unit.get("recipe")
        operations, facts = _selected_operations(unit, graph, recipe, selection)
        enforcement = [_native_enforcement(unit, graph, recipe, selection, operation, facts, profiles)
                       for operation in operations if operation["kind"] in {
                           "native_compile", "native_link", "native_aot"}]
        requires_native = any(operation["kind"] in {"native_compile", "native_link", "native_aot"}
                              for operation in operations)
        blockers = [reason for reason in selection["reasons"]
                    if reason != "selection_unbound" or requires_native]
        if recipe is None:
            blockers.append("recipe_missing")
        elif errors := validate_build_recipe(recipe, unit):
            blockers.extend("invalid_recipe:" + error for error in errors)
        for operation in operations:
            blockers.extend(operation["reasons"])
            if operation["kind"] == "unknown":
                blockers.append("operation_unknown")
        for proof in enforcement:
            if proof["status"] != "proven":
                blockers.append("unenforced_native_target")
        for relation in graph["relations"]:
            if relation["consumer_build_unit_id"] != unit["build_unit_id"] or not relation["required"]:
                continue
            applicable = _condition_applies(relation["condition"],
                                            unit.get("build_variant", {}).get("configuration"),
                                            "x64" if selection["required_axes"]["isa"] == "x86_64" else None)
            if (relation["operation"] == "native_link"
                    and not any(operation["kind"] == "native_link" for operation in operations)):
                continue
            if applicable is not False and relation["resolution"] != "resolved":
                blockers.append("required_interface_unresolved:" + relation["relation_id"])
        for requirement in graph["external_requirements"]:
            if requirement["consumer_build_unit_id"] == unit["build_unit_id"]:
                blockers.append("required_external_interface_unresolved:" + requirement["interface"])
        for gap in graph["coverage_gaps"]:
            if gap["blocking"] and unit["build_unit_id"] in gap["build_unit_ids"]:
                blockers.append("active_coverage_gap:" + gap["code"])
        capability = native_build_capability_gap(unit)
        if capability:
            blockers.append(capability)
        values.append({"build_unit_id": unit["build_unit_id"], "selection": selection,
                       "recipe_digest": _digest(recipe) if recipe else None,
                       "operations": operations, "enforcement": enforcement,
                       "blockers": sorted(set(blockers))})
    by_unit = {unit["build_unit_id"]: unit for unit in values}
    for edge in graph["edges"]:
        if edge["kind"] == "order_only":
            continue
        consumer = by_unit[edge["consumer_build_unit_id"]]
        producer = by_unit[edge["producer_build_unit_id"]]
        declaration = next((item for item in graph["declarations"] if
                            item["owner_build_unit_id"] == edge["producer_build_unit_id"]
                            and item["product_id"] == edge["requirement"]["product_id"]), None)
        if declaration is None:
            consumer["blockers"].append("required_product_role_unresolved")
            continue
        if any(proof["status"] != "proven" for proof in [
                *producer["enforcement"], *consumer["enforcement"]]):
            consumer["blockers"].append("required_product_target_unproven")
            continue
        producer_axes, consumer_axes = proven_product_axes(producer), proven_product_axes(consumer)
        if declaration["role"] not in {"static_archive", "import_library", "runtime_shared",
                                       "executable", "native_object"}:
            continue
        if edge["kind"] == "requires_host_tool":
            producer_node = next(node for node in graph["nodes"]
                                 if node["build_unit_id"] == edge["producer_build_unit_id"])
            if producer_node["variant"]["execution_role"] != "host" or declaration["role"] != "executable":
                consumer["blockers"].append("required_host_tool_role_unresolved")
            consumer_axes = producer_axes
        required = {"os", "isa"} | ({"abi"} if edge["requirement"]["kind"] == "library" else set())
        required.update(key for key, value in consumer_axes.items() if value is not None)
        for key in sorted(required):
            if producer_axes[key] is None or consumer_axes[key] is None:
                consumer["blockers"].append("required_product_axis_unresolved:" + key)
            elif producer_axes[key] != consumer_axes[key]:
                consumer["blockers"].append("required_product_axis_incompatible:" + key)
    for unit in values:
        unit["blockers"] = sorted(set(unit["blockers"]))
    value = copy.deepcopy({"schema": REFINEMENT_SCHEMA, "graph_identity": graph["topology_id"],
             "bundle_identity": graph["bundle_identity"], "source_fingerprint": graph["source_fingerprint"],
             "rules": RULES, "policy": policy.view(), "environment": environment,
             "profiles": profiles, "releases": dict(releases or {}), "units": values})
    value["refinement_id"] = _digest(value)
    return value


def validate_refinement(graph, refinement):
    validate_build_topology(graph)
    if (not isinstance(refinement, Mapping) or refinement.get("schema") != REFINEMENT_SCHEMA
            or graph["schema"] != BUILD_TOPOLOGY_SCHEMA
            or refinement.get("graph_identity") != graph["topology_id"]
            or refinement.get("bundle_identity") != graph["bundle_identity"]
            or refinement.get("source_fingerprint") != graph["source_fingerprint"]
            or refinement.get("rules") != RULES
            or refinement.get("refinement_id") != _digest({
                key: value for key, value in refinement.items() if key != "refinement_id"})
            or {unit["build_unit_id"] for unit in refinement["units"]} !=
            {node["build_unit_id"] for node in graph["nodes"]}):
        raise ValueError("refinement has changed or foreign accepted identities")
    expected_fields = {"schema", "graph_identity", "bundle_identity", "source_fingerprint", "rules",
                       "policy", "environment", "profiles", "releases", "units", "refinement_id"}
    if set(refinement) != expected_fields or len(refinement["units"]) != len(graph["nodes"]):
        raise ValueError("refinement must exactly cover the immutable whole graph")
    fact_ids = {fact["fact_id"] for fact in graph["facts"]}
    native_kinds = {"native_compile", "native_link", "native_aot"}
    from appsec_review.config.build_selection import AXES
    for unit in refinement["units"]:
        if set(unit) != {"build_unit_id", "selection", "recipe_digest", "operations", "enforcement", "blockers"}:
            raise ValueError("unsupported refinement unit shape")
        operations = {operation["operation_id"]: operation for operation in unit["operations"]}
        if len(operations) != len(unit["operations"]):
            raise ValueError("duplicate selected operation")
        for identity, operation in operations.items():
            if (identity != _digest({key: value for key, value in operation.items() if key != "operation_id"})
                    or operation["build_unit_id"] != unit["build_unit_id"]
                    or set(operation["basis"]) - fact_ids):
                raise ValueError("selected operation has unresolved source or recipe identity")
        if {proof["operation_id"] for proof in unit["enforcement"]} != {
                identity for identity, operation in operations.items() if operation["kind"] in native_kinds}:
            raise ValueError("native enforcement does not cover every selected native operation")
        for proof in unit["enforcement"]:
            if (proof["schema"] != ENFORCEMENT_SCHEMA or proof["proof_kind"] not in PROOF_KINDS
                    or proof["enforcement_id"] != _digest({
                        key: value for key, value in proof.items() if key != "enforcement_id"})
                    or proof["recipe_digest"] != unit["recipe_digest"]
                    or proof["source_fingerprint"] != graph["source_fingerprint"]
                    or proof["catalog_bundle_identity"] != graph["bundle_identity"]
                    or proof["selection_id"] != unit["selection"]["selection_id"]
                    or proof["required_axes"] != unit["selection"]["required_axes"]
                    or set(proof["proven_axes"]) != set(AXES)
                    or set(proof["source_evidence_refs"]) - fact_ids
                    or proof["status"] not in {"proven", "unknown", "incompatible"}
                    or proof["operation_binding"] != (
                        proof["operation_id"] if unit["recipe_digest"] is not None else None)
                    or unit["recipe_digest"] is None and proof["status"] != "unknown"
                    or proof["status"] == "proven" and proof["unresolved_inputs"]):
                raise ValueError("native enforcement identity or recipe binding changed")


def refinement_unit(graph, refinement, uid, recipe=None):
    validate_refinement(graph, refinement)
    unit = next(item for item in refinement["units"] if item["build_unit_id"] == uid)
    if recipe is not None and unit["recipe_digest"] != _digest(recipe):
        raise ValueError("selected recipe has no matching immutable refinement")
    return unit


def proven_product_axes(bound):
    from appsec_review.config.build_selection import AXES
    axes = dict.fromkeys(AXES)
    for proof in bound["enforcement"]:
        if proof["status"] != "proven":
            raise ValueError("unproven native enforcement cannot authorize retained product axes")
        for key, value in proof["proven_axes"].items():
            if key not in axes or value is None:
                continue
            if axes[key] is not None and axes[key] != value:
                raise ValueError("selected native operations disagree on a retained product axis")
            axes[key] = value
    return axes


def verify_product_contract(bound, products):
    from appsec_review.config.build_selection import AXES
    expected = proven_product_axes(bound)
    roles = {"static_archive", "import_library", "runtime_shared", "executable", "native_object",
             "headers", "metadata", "generated_source", "managed_assembly", "package"}
    for product in products:
        role = product.role if hasattr(product, "role") else product.get("role")
        axes = product.axes if hasattr(product, "axes") else product.get("axes")
        if role not in roles or not isinstance(axes, Mapping) or set(axes) != set(AXES):
            raise ValueError("legacy untyped products have no graph/2 reuse or promotion authority")
        if role in {"static_archive", "import_library", "runtime_shared", "executable", "native_object"}:
            required = {"os", "isa"} | ({"abi"} if role != "executable" else set())
            required.update(key for key, value in expected.items() if value is not None)
            for key in sorted(required):
                if expected[key] is None or axes.get(key) != expected[key]:
                    raise ValueError("native retained product axis is unresolved or incompatible: " + key)


def ready_build_units(graph, states, *, products=(), verify_product=None, refinement=None):
    if graph["schema"] == "appsec-review/build-topology/1":
        _validate_graph1(graph)
        return {"ready": [], "blocked": [{"build_unit_id": node["build_unit_id"],
                                         "reasons": ["legacy_graph_requires_accepted_replanning"]}
                                        for node in graph["nodes"]]}
    validate_build_topology(graph)
    if set(states) - {node["build_unit_id"] for node in graph["nodes"]}:
        raise ValueError("state names an unknown build unit")
    if refinement is None:
        return {"ready": [], "blocked": [{"build_unit_id": node["build_unit_id"],
                                         "reasons": ["accepted_refinement_missing"]} for node in graph["nodes"]]}
    validate_refinement(graph, refinement)
    ready, blocked = [], []
    for uid in topological_order(graph):
        if states.get(uid, "PENDING") not in {"PENDING", "READY", "BLOCKED_BY_DEPENDENCY"}:
            continue
        bound = refinement_unit(graph, refinement, uid)
        reasons = list(bound["blockers"])
        for edge in graph["edges"]:
            if edge["consumer_build_unit_id"] != uid:
                continue
            producer = edge["producer_build_unit_id"]
            if states.get(producer) != "SUCCEEDED":
                reasons.append("producer_not_succeeded:" + producer)
            elif edge["kind"] != "order_only":
                requirement = edge["requirement"]
                if any(value is None for value in requirement["variant"].values()):
                    reasons.append("unresolved_product_variant:" + producer)
                    continue
                if edge["kind"] == "requires_product" and requirement["kind"] == "library":
                    consumer_variant = next(node["variant"] for node in graph["nodes"]
                                            if node["build_unit_id"] == uid)
                    compatibility = ("configuration", "target_arch", "execution_role", "toolchain", "abi")
                    if any(consumer_variant[key] is None for key in compatibility):
                        reasons.append("unresolved_consumer_variant:" + producer)
                        continue
                    if any(consumer_variant[key] != requirement["variant"][key] for key in compatibility):
                        reasons.append("incompatible_consumer_variant:" + producer)
                        continue
                producer_bound = refinement_unit(graph, refinement, producer)
                records = [record for record in products if
                           record.get("producer_build_unit_id") == producer
                           and record.get("topology_id") == graph["topology_id"]
                           and record.get("recipe_revision") == producer_bound["recipe_digest"]
                           and _product_path(record.get("path")) and _hash(record.get("sha256"))
                           and all(record.get(key) == value for key, value in edge["requirement"].items())]
                declaration = next((item for item in graph["declarations"] if
                                    item["owner_build_unit_id"] == producer and
                                    item["product_id"] == edge["requirement"]["product_id"]), None)
                required_role = declaration["role"] if declaration else None
                axes = proven_product_axes(producer_bound if edge["kind"] == "requires_host_tool" else bound)
                if required_role == "runtime_shared" and axes["os"] == "windows":
                    required_role = "import_library"
                required_axes = ({"os", "isa"} | ({"abi"} if edge["requirement"]["kind"] == "library" else set())
                                 if required_role in {"static_archive", "import_library", "runtime_shared",
                                                      "executable", "native_object"} else set())
                required_axes.update(key for key, value in axes.items() if value is not None)
                records = [record for record in records if required_role is not None and
                           record.get("role") == required_role and isinstance(record.get("axes"), Mapping)
                           and all(axes[key] is not None and record["axes"].get(key) == axes[key]
                                   for key in required_axes)]
                if verify_product is None or not any(verify_product(record) for record in records):
                    reasons.append("required_product_unverified:" + producer)
        if reasons:
            blocked.append({"build_unit_id": uid, "reasons": sorted(set(reasons))})
        else:
            ready.append(uid)
    for node in graph["nodes"]:
        if node["disposition"] != "independent":
            blocked.append({"build_unit_id": node["build_unit_id"], "reasons": [node["disposition"]]})
    return {"ready": ready, "blocked": blocked}
