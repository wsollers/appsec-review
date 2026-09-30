#!/usr/bin/env python3
"""Mechanical contract fields derived from the schemas, for persona derive steps (ADR-0013).

The model supplies judgment only; Python stamps every mechanical field. Each derive module
(``claim_review_derive``, ``hypothesis_hunt_derive``, ``attack_chain_derive``,
``owasp_validator_derive``, ``poc_fix_derive``) keeps a hand-written ``_ORCHESTRATOR_KEYS`` set of
fields it ignores when the model echoes them. Those fields are already implied by the two schemas
of the contract: a field the final record declares at a position where the persona schema does not
is orchestrator-owned. This module derives that set from the schemas, so a new contract does not
hand-maintain it and an existing list can be checked for drift:

* ``object_properties(node)``: every property an object position declares, through ``$ref``,
  ``allOf`` / ``anyOf`` / ``oneOf`` and ``if`` / ``then`` / ``else`` branches;
* ``at(schema, path)``: the schema node at a property path (``[]`` descends into array items);
* ``object_paths(schema)``: every property path at which a schema declares an object;
* ``orchestrator_fields(final, persona, anchor)``: {path: final-only property names} over every
  object path the two schemas share once the persona wrapper is aligned with the final record;
* ``orchestrator_keys(final, persona, anchor, path)``: those names as one set (all paths, or one),
  the derive list a module strips before it validates a reply;
* ``strip_orchestrator_fields(row, fields, where, notes)``: drop them from a reply row, noting each;
* ``content_id(prefix, identity)``: the ``<prefix>-<24 hex of digest(identity)>`` id rule the
  derive modules use (byte-identical to ``prefix + "-" + execution_state.digest(identity)[:24]``);
* ``unwrap_single(value)``: the one-item list wrapper models send around a single object.

``poc_fix_derive`` and ``hypothesis_hunt_derive`` build their derive lists with ``orchestrator_keys``
(brief L2), so this module is part of those jobs' fingerprints. It imports only the shared-runtime
validator at module level; ``formats`` is loaded by ``content_id`` alone. The other derive modules keep
hand-written lists that ``tests/test_contract_derive.py`` checks against the schemas.
"""
from __future__ import annotations

from typing import Any, Iterable, Sequence

from schema_validate import SchemaStore, UnsupportedSchema, resolve_ref

_BRANCHES = ("allOf", "anyOf", "oneOf")
_CONDITIONAL = ("if", "then", "else")
ITEMS = "[]"


def _load(schema: str | dict, store: SchemaStore) -> tuple[Any, Any]:
    if isinstance(schema, dict):
        return schema, schema
    return resolve_ref(schema, None, store)


def _nodes(node: Any, root: Any, store: SchemaStore, depth: int = 0) -> Iterable[tuple[dict, Any]]:
    """The node and every branch that describes the same instance position."""
    if not isinstance(node, dict):
        return
    if depth > 32:
        raise UnsupportedSchema("schema branches nest deeper than 32 levels")
    yield node, root
    if "$ref" in node:
        target, target_root = resolve_ref(node["$ref"], root, store)
        yield from _nodes(target, target_root, store, depth + 1)
    for key in _BRANCHES:
        for branch in node.get(key, []):
            yield from _nodes(branch, root, store, depth + 1)
    for key in _CONDITIONAL:
        yield from _nodes(node.get(key), root, store, depth + 1)


def object_properties(schema: str | dict, store: SchemaStore | None = None,
                      _root: Any = None) -> set[str]:
    store = store or SchemaStore()
    node, root = _load(schema, store) if _root is None else (schema, _root)
    return {name for sub, _ in _nodes(node, root, store) for name in sub.get("properties", {})}


def at(schema: str | dict, path: Sequence[str], store: SchemaStore | None = None) -> list[tuple[dict, Any]]:
    """Every (schema node, root) describing the instance at ``path``; ``"[]"`` means array items."""
    store = store or SchemaStore()
    frontier = [_load(schema, store)]
    for step in path:
        found = at_nodes(frontier, step, store)
        if not found:
            raise KeyError(f"no schema node at {'/'.join(path)!r}")
        frontier = found
    return frontier


def _properties_at(schema: str | dict, path: Sequence[str], store: SchemaStore) -> set[str]:
    names: set[str] = set()
    for node, root in at(schema, path, store):
        names |= object_properties(node, store, root)
    return names


def object_paths(schema: str | dict, store: SchemaStore | None = None,
                 limit: int = 12) -> list[tuple[str, ...]]:
    """Every property path at which ``schema`` declares an object with properties."""
    store = store or SchemaStore()
    found: list[tuple[str, ...]] = []

    def walk(path: tuple[str, ...], pairs: list[tuple[dict, Any]]) -> None:
        if len(path) > limit:
            return
        names: set[str] = set()
        declared = False
        items: list[tuple[dict, Any]] = []
        for node, root in pairs:
            for sub, sub_root in _nodes(node, root, store):
                declared = declared or "properties" in sub
                names |= set(sub.get("properties", {}))
                if isinstance(sub.get("items"), dict):
                    items.append((sub["items"], sub_root))
        if declared and path not in found:
            found.append(path)
        for name in sorted(names):
            walk(path + (name,), at_nodes(pairs, name, store))
        if items:
            walk(path + (ITEMS,), items)

    walk((), [_load(schema, store)])
    return found


def at_nodes(pairs: list[tuple[dict, Any]], step: str, store: SchemaStore) -> list[tuple[dict, Any]]:
    found: list[tuple[dict, Any]] = []
    for node, root in pairs:
        for sub, sub_root in _nodes(node, root, store):
            child = sub.get("items") if step == ITEMS else sub.get("properties", {}).get(step)
            if isinstance(child, dict):
                found.append((child, sub_root))
    return found


def orchestrator_fields(final: str | dict, persona: str | dict,
                        anchor: tuple[Sequence[str], Sequence[str]] = ((), ()),
                        store: SchemaStore | None = None) -> dict[tuple[str, ...], set[str]]:
    """{persona path: properties the final schema declares there and the persona schema does not}.

    ``anchor`` = (persona prefix, final prefix) aligns a persona schema that wraps the final record
    (for example ``(("chains", "[]"), ())``: each persona chain is one final record). Every object
    path of the persona schema under the persona prefix is compared with the final schema at the
    same relative path; a persona path with no final counterpart is skipped."""
    store = store or SchemaStore()
    persona_prefix, final_prefix = tuple(anchor[0]), tuple(anchor[1])
    final_paths = set(object_paths(final, store))
    out: dict[tuple[str, ...], set[str]] = {}
    for path in object_paths(persona, store):
        if path[:len(persona_prefix)] != persona_prefix:
            continue
        target = final_prefix + path[len(persona_prefix):]
        if target in final_paths:
            out[path] = _properties_at(final, target, store) - _properties_at(persona, path, store)
    return out


def orchestrator_keys(final: str | dict, persona: str | dict,
                      anchor: tuple[Sequence[str], Sequence[str]] = ((), ()),
                      path: Sequence[str] | None = None,
                      store: SchemaStore | None = None) -> frozenset[str]:
    """The orchestrator-owned names of :func:`orchestrator_fields` as one set: the union over every
    shared path, or the names at one persona ``path`` (empty when the schemas do not share it)."""
    found = orchestrator_fields(final, persona, anchor, store)
    if path is not None:
        return frozenset(found.get(tuple(path), ()))
    return frozenset(set().union(*found.values()))


def strip_orchestrator_fields(row: Any, fields: Iterable[str], where: str,
                              notes: list[str]) -> Any:
    """``row`` without the orchestrator-owned keys, each dropped key noted (never an error)."""
    if not isinstance(row, dict):
        return row
    owned = set(fields)
    for key in sorted(owned & set(row)):
        notes.append(f"{where}: ignored orchestrator field {key!r}; Python derives it")
    return {key: value for key, value in row.items() if key not in owned}


def content_id(prefix: str, identity: Any, width: int = 24) -> str:
    from formats import digest
    return f"{prefix}-{digest(identity)[:width]}"


def unwrap_single(value: Any) -> Any:
    return value[0] if isinstance(value, list) and len(value) == 1 else value
