"""Predicate admission: which kind of cited content can bear on which predicate (``predicate-admission/2``).

Three separate questions decide whether a model citation can satisfy an obligation:

* **Authenticity** - the cited identity re-resolves to accepted content (``review.evidence.resolve_relation``
  enforces this; an unresolvable citation is an ``evidence_gap``, never a relation).
* **Relevance and support** - what *kind* of content this is and what it can establish about a
  *specific* predicate. This module is that table. It is closed, versioned application policy, not
  prompt text, and a real citation is not evidence for every predicate just because it is real.

Each ``(entity kind, predicate)`` cell is exactly one of:

``DIRECT``
    The application can establish the proposition from the entity's structured content alone (a
    source span's existence is the existence of the construct at that location).
``ANALYST_ASSESSED``
    Authentic and relevant, but turning the cited text into the proposition needs human-style
    judgment (does this loop bound the copy? does this config line enable the feature?). It is
    recorded and shown, and it never satisfies an obligation by itself.
``INDIRECT``
    Context that may guide search. Nothing about it bears on the proposition.

Principles (every cell below follows them; where unsure the cell is the weaker one):

1. Source-level content (span, AST node, IR entity, symbol) is ``DIRECT`` only for
   ``affected_construct``: the construct is at that location. For input control, reachability and
   guards the text must be read, so it is at best ``ANALYST_ASSESSED``.
2. Component-level content (package, archive member, bytecode/assembly/wasm module) establishes
   component presence (``affected_construct``) and is otherwise ``INDIRECT``: knowing a version is
   present says nothing about attacker input, reachability or guards.
3. Build and configuration kinds (``build_action``, ``compile_unit``) are ``DIRECT`` for
   ``configuration_enables`` because their structured content is the flags, defines and commands
   that configure the build. Produced binaries are ``ANALYST_ASSESSED`` at best: a hardening or
   feature property must be read out of them.
4. No kind is ``DIRECT`` for ``security_impact``: impact follows from the adjudicated claim facts
   (weakness class and the other predicates), not from one cited entity. There is no exception in
   ``predicate-admission/2``.
5. Binary-derived content (``binary_function``, ``binary_call_site``: Ghidra pseudo-C bound to a
   binary hash, a function address and pseudo-C lines) is ``DIRECT`` only for
   ``affected_construct``: the function or call is in that binary at that address. Decompiled text
   is a reconstruction, so flow, input control and guards read from it are ``ANALYST_ASSESSED``,
   and it says nothing about build configuration or impact. Imports and strings name things the
   binary refers to; they are ``INDIRECT`` (outside the table) for every predicate.

``predicate-admission/2`` added principle 5 and its two rows; every ``/1`` cell is unchanged.

A producer's own observation is not decided here: ``tool_observation`` stays mapped by rule identity
(``review.tool_rules``) and graph facts by ``graph-fact-predicates/1``.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from appsec_review.retrieval.model import EntityKind
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import Admissibility, Predicate

VERSION = "predicate-admission/2"

_D, _A, _I = Admissibility.DIRECT, Admissibility.ANALYST_ASSESSED, Admissibility.INDIRECT
_P = Predicate
# Column order of every row below.
COLUMNS: tuple[Predicate, ...] = (
    _P.AFFECTED_CONSTRUCT, _P.ATTACKER_INPUT_CONTROL, _P.SOURCE_TO_SINK_REACHABILITY,
    _P.MISSING_OR_INEFFECTIVE_GUARD, _P.CONFIGURATION_ENABLES, _P.SECURITY_IMPACT,
)
#                                  AC  AIC S2S GRD CFG IMP
_ROWS: dict[EntityKind, tuple[Admissibility, ...]] = {
    # Source-level content: construct existence is structured; everything else needs reading.
    EntityKind.SOURCE_SPAN:      (_D, _A, _A, _A, _A, _A),   # the lines are the construct; config/impact read from text
    EntityKind.AST_NODE:         (_D, _A, _A, _A, _A, _A),   # syntactic structure of the construct
    EntityKind.SYMBOL:           (_D, _A, _A, _A, _I, _A),   # a declaration names a construct; config is not in a symbol
    EntityKind.IR_ENTITY:        (_D, _A, _A, _A, _I, _I),   # lowered form: flow/guards readable, config and impact are not
    # Build and configuration facts: flags, defines and commands are structured configuration.
    EntityKind.BUILD_ACTION:     (_D, _I, _I, _I, _D, _I),   # a recorded compile/link command and its flags
    EntityKind.COMPILE_UNIT:     (_D, _I, _I, _I, _D, _I),   # a unit with its language, flags and defines
    # Build outputs: the thing exists; a property of it must be read out of it.
    EntityKind.OBJECT_FILE:      (_D, _I, _I, _I, _I, _I),
    EntityKind.LIBRARY:          (_D, _I, _I, _I, _I, _I),
    EntityKind.EXECUTABLE:       (_D, _I, _I, _I, _A, _I),   # hardening properties of a binary need interpretation
    EntityKind.BUILD_ARTIFACT:   (_D, _I, _I, _I, _A, _I),
    # Component presence (SBOM, lockfile, inventory): present at a version, nothing more.
    EntityKind.PACKAGE:          (_D, _I, _I, _I, _I, _I),
    EntityKind.ARCHIVE_MEMBER:   (_D, _I, _I, _I, _I, _I),
    EntityKind.BYTECODE_MODULE:  (_D, _I, _I, _I, _I, _I),   # no readable source: prefer indirect
    EntityKind.MANAGED_ASSEMBLY: (_D, _I, _I, _I, _I, _I),
    EntityKind.WASM_MODULE:      (_D, _I, _I, _I, _I, _I),
    # A run-owned tool artifact (decompilation, trace, SARIF): its content is read, not computed.
    EntityKind.EVIDENCE_ARTIFACT: (_D, _A, _A, _A, _A, _A),
    # Binary-derived pseudo-C (principle 5): the function or call exists at that address; the rest is read.
    EntityKind.BINARY_FUNCTION:  (_D, _A, _A, _A, _I, _I),
    EntityKind.BINARY_CALL_SITE: (_D, _A, _A, _A, _I, _I),
}
assert all(len(row) == len(COLUMNS) for row in _ROWS.values())
assert all(row[COLUMNS.index(_P.SECURITY_IMPACT)] is not _D for row in _ROWS.values())   # principle 4
assert set(COLUMNS) == set(Predicate)

ADMISSION_TABLE: Mapping[EntityKind, Mapping[Predicate, Admissibility]] = MappingProxyType({
    kind: MappingProxyType(dict(zip(COLUMNS, row))) for kind, row in _ROWS.items()})
ADMITTED_KINDS: frozenset[EntityKind] = frozenset(ADMISSION_TABLE)


def admission(entity_kind: EntityKind | str, predicate: Predicate | str) -> Admissibility:
    """The table cell for ``(entity_kind, predicate)``; a kind outside the table is ``INDIRECT``."""
    row = ADMISSION_TABLE.get(EntityKind(entity_kind))
    return Admissibility.INDIRECT if row is None else row[Predicate(predicate)]


def table_record() -> dict[str, object]:
    """The canonical table, as pinned by the obligation policy hash."""
    return {"version": VERSION,
            "table": {kind.value: {predicate.value: ADMISSION_TABLE[kind][predicate].value for predicate in COLUMNS}
                      for kind in sorted(ADMISSION_TABLE, key=lambda item: item.value)}}


TABLE_SHA256 = sha256_hex(table_record())

__all__ = ["ADMISSION_TABLE", "ADMITTED_KINDS", "COLUMNS", "TABLE_SHA256", "VERSION", "admission", "table_record"]
