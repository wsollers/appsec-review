"""Accepted target build dependencies, distinct from review jobs and build attempts."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import copy
import hashlib
import heapq
from pathlib import PurePosixPath
import posixpath
import re
import shlex
from typing import Any

from appsec_review.jobs.build_discovery import (
    make_default_build_commands, native_build_capability_gap, validate_build_recipe,
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
    graph = {"schema": BUILD_TOPOLOGY_SCHEMA, "source_fingerprint": source_fingerprint,
             "nodes": _ordered(list(nodes.values())), "edges": _ordered(edges),
             "external_requirements": _ordered(external), "coverage_gaps": _ordered(gaps)}
    graph["topology_id"] = topology_identity(graph)
    validate_build_topology(graph)
    return graph


def validate_build_topology(graph: Mapping[str, Any]) -> None:
    """Fail closed on identity, endpoint, ownership, product and cycle errors."""
    if (set(graph) != {"schema", "source_fingerprint", "topology_id", "nodes", "edges",
                       "external_requirements", "coverage_gaps"}
            or graph.get("schema") != BUILD_TOPOLOGY_SCHEMA
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
