"""Compact model answers and their application-side expansion (review-protocol-v2.md section 6).

A cell answers with a stance plus citations by label. This module validates that compact answer against its
schema and **expands** it into the document the existing validators, normalization, ledger and adjudication
already consume (``red-discovery-result/1``, ``blue-result/1``, ``verifier-result/1``). The expansion fills
everything the model need not say (schema, package echo, role, round, claim ids, lead accounting defaults) and
resolves every label through the cell label table; nothing here sets a claim state, and nothing downstream of
the expansion changes.

The shared layer is role-neutral. :func:`position` and :func:`resolve_position` turn "a stance, cited labels,
a bounded reason" into resolved identities with feedback and the ``unresolved`` rule (a stance whose labels
resolve to nothing is ``unresolved`` and records no relation). The role wrappers below only arrange positions
into their role\'s result document; a further role (an adjudicating reviewer, say) adds a wrapper and a schema
and touches none of the shared code. Which roles may see which other role\'s output is decided where each
request is built (``jobs.job_inference_security_review.teams``), never here.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from appsec_review.review.labels import LabelTable
from appsec_review.review.obligations import Precondition
from appsec_review.review.red_discovery import RESULT_SCHEMA as RED_RESULT_SCHEMA, RedInvocation

COMPACT_SCHEMAS = {"red": "red-compact", "blue": "blue-compact", "verifier": "verifier-compact",
                   "judge": "judge-result-compact"}
BLUE_SCHEMA = "appsec-review/blue-result/1"
VERIFIER_SCHEMA = "appsec-review/verifier-result/1"
JUDGE_RESULT_SCHEMA = "appsec-review/judge-result/1"
UNRESOLVED = "unresolved"
STANCE_ORDER = ("contradicts", "qualifies", "supports", UNRESOLVED)
MAX_FEEDBACK = 20
MAX_TEXT = 2000
DEFAULT_TEXT = "not stated by the analyst"
# How a stance is recorded: the relation kind the proposed relation carries (``unresolved`` records none).
RELATION_KIND = {"supports": "supports", "contradicts": "contradicts", "qualifies": "qualifies"}
POC_TEXT = 240
CLOSED_PRECONDITIONS = frozenset(item.value for item in Precondition)
PREDICATES = ("affected_construct", "attacker_input_control", "source_to_sink_reachability",
              "missing_or_ineffective_guard", "configuration_enables", "security_impact")

SchemaErrors = Callable[[str, Any], list[str]]


@dataclass(slots=True)
class Expansion:
    """An expanded document (``None`` when the compact answer is unusable), feedback and errors."""

    result: dict[str, Any] | None = None
    feedback: list[str] = field(default_factory=list)      # label drops and defaults; shown to the model/receipts
    errors: list[str] = field(default_factory=list)        # a compact answer that cannot be expanded

    def note(self, message: str) -> None:
        if len(self.feedback) < MAX_FEEDBACK:
            self.feedback.append(message[:256])


Expander = Callable[[Mapping[str, Any], LabelTable], Expansion]


# ------------------------------------------------------------------------------------------------
# Shared layer


@dataclass(frozen=True, slots=True)
class Position:
    """A stance on one predicate with the identities its labels resolved to (role-neutral)."""

    predicate: str
    stance: str
    refs: tuple[str, ...]
    why: str | None = None
    requested: str = ""            # the stance the model wrote, when resolution changed it


def text(value: Any, default: str = DEFAULT_TEXT, limit: int = MAX_TEXT) -> str:
    cleaned = " ".join(str(value).split()) if isinstance(value, str) else ""
    return (cleaned or default)[:limit]


def resolve_position(predicate: str, stance: str, tokens: Iterable[Any], why: Any, labels: LabelTable,
                     expansion: Expansion, owner: str) -> Position:
    """Resolve a position\'s citations. A label that does not resolve is dropped with feedback; a stance with
    no resolvable citation becomes ``unresolved``."""
    refs, dropped = labels.resolve_all(tokens)
    for token in dropped:
        expansion.note(f"{owner}: citation {token} does not resolve in this cell and was dropped")
    requested = ""
    if stance != UNRESOLVED and not refs:
        expansion.note(f"{owner}: stance {stance} on {predicate} has no resolvable citation; recorded as unresolved")
        requested, stance = stance, UNRESOLVED
    return Position(predicate, stance, tuple(refs), text(why, "", 1000) or None, requested)


def relations_of(positions: Iterable[Position]) -> list[dict[str, Any]]:
    """``proposed_relations`` of the blue and verifier results: one per resolved citation of a decided stance."""
    found: list[dict[str, Any]] = []
    for item in positions:
        kind = RELATION_KIND.get(item.stance)
        if kind is None:
            continue
        for ref in item.refs:
            relation = {"predicate": item.predicate, "kind": kind, "entity_id": ref,
                        "rationale": text(item.why, f"{kind} {item.predicate} (cited by label)", 1000)}
            if relation not in found:
                found.append(relation)
    return found


def citations_of(positions: Iterable[Position]) -> dict[str, list[str]]:
    cited: dict[str, list[str]] = {}
    for item in positions:
        for ref in item.refs:
            bucket = cited.setdefault(item.predicate, [])
            if ref not in bucket:
                bucket.append(ref)
    return cited


def positions_of(compact: Mapping[str, Any], labels: LabelTable, expansion: Expansion, owner: str) -> list[Position]:
    """The positions of a blue or verifier answer: ``per_predicate`` entries, or the single top-level stance."""
    positions: list[Position] = []
    for predicate in PREDICATES:
        entry = (compact.get("per_predicate") or {}).get(predicate)
        if isinstance(entry, Mapping):
            positions.append(resolve_position(predicate, entry["stance"], entry.get("cites", ()),
                                              entry.get("why") or compact.get("why"), labels, expansion,
                                              f"{owner} {predicate}"))
    if "stance" in compact and compact.get("predicate"):
        positions.append(resolve_position(compact["predicate"], compact["stance"], compact.get("cites", ()),
                                          compact.get("why"), labels, expansion, f"{owner} {compact['predicate']}"))
    return positions


def overall_stance(compact: Mapping[str, Any], positions: Sequence[Position]) -> str:
    """The stance the model wrote at top level when it still stands, else the strongest decided position."""
    declared = compact.get("stance")
    single = [item for item in positions if item.predicate == compact.get("predicate")]
    if declared and single and single[0].stance == declared:
        return declared
    if declared and not single and not positions:
        return UNRESOLVED
    decided = [item.stance for item in positions]
    for stance in STANCE_ORDER:
        if stance in decided:
            return stance
    return UNRESOLVED


def summary_why(compact: Mapping[str, Any], positions: Sequence[Position]) -> str:
    parts = [text(compact.get("why"), "", 1000)] + [item.why or "" for item in positions]
    missing = [text(item, "", 300) for entry in (compact.get("per_predicate") or {}).values()
               for item in entry.get("missing", ())]
    if missing:
        parts.append("missing: " + "; ".join(missing))
    return text(" ".join(part for part in dict.fromkeys(parts) if part), "no reason given", MAX_TEXT)


def _validate(compact: Any, name: str, schema_errors: SchemaErrors, expansion: Expansion) -> bool:
    if not isinstance(compact, Mapping):
        expansion.errors.append("the answer must be a JSON object")
        return False
    errors = schema_errors(name, dict(compact))
    expansion.errors.extend(f"{name}: {item}"[:256] for item in errors)
    return not errors


# ------------------------------------------------------------------------------------------------
# Blue and verifier wrappers


def expand_blue(compact: Mapping[str, Any], labels: LabelTable, *, claim_id: str, task: str,
                schema_errors: SchemaErrors) -> Expansion:
    expansion = Expansion()
    if not _validate(compact, COMPACT_SCHEMAS["blue"], schema_errors, expansion):
        return expansion
    # ``claim`` is advisory: the cell is bound to one claim and the application fills ``claim_id``.
    positions = positions_of(compact, labels, expansion, "blue")
    stance = overall_stance(compact, positions)
    expansion.result = {
        "schema": BLUE_SCHEMA, "claim_id": claim_id, "citations": citations_of(positions),
        "proposed_relations": relations_of(positions), "evidence_requests": [],
        "rationale": summary_why(compact, positions), "task": task, "disposition": stance}
    return expansion


def expand_verifier(compact: Mapping[str, Any], labels: LabelTable, *, claim_id: str,
                    schema_errors: SchemaErrors) -> Expansion:
    expansion = Expansion()
    if not _validate(compact, COMPACT_SCHEMAS["verifier"], schema_errors, expansion):
        return expansion
    positions = positions_of({**compact, "stance": None, "predicate": None}, labels, expansion, "verifier")
    expansion.result = {
        "schema": VERIFIER_SCHEMA, "claim_id": claim_id, "citations": citations_of(positions),
        "proposed_relations": relations_of(positions), "evidence_requests": [],
        "rationale": summary_why(compact, positions), "proposed_disposition": compact["disposition"]}
    return expansion


# ------------------------------------------------------------------------------------------------
# Judge wrapper (docs/architecture/review-judge-and-poc.md section 3.3)


def deshuffle(choice: str, side_map: Mapping[str, str]) -> str:
    """A judge's A/B/both/neither/unresolved in terms of red and blue, through the stored side-to-role map."""
    if choice in side_map:
        return f"{side_map[choice]}_correct"
    return {"both": "partly"}.get(choice, choice)


def expand_judge(compact: Mapping[str, Any], labels: LabelTable, *, claim_id: str, side_map: Mapping[str, str],
                 schema_errors: SchemaErrors) -> Expansion:
    """``judge-result-compact/1`` -> ``judge-result/1`` for one claim, de-shuffled through ``side_map``.

    The judge's citations go through the shared position layer: a label that does not resolve is dropped with
    feedback, and a side named with no resolvable citation becomes ``unresolved`` per predicate. An overall choice of
    A, B or both needs at least one resolvable citation among the predicates; otherwise it is ``unresolved``. The
    map is the application's: the model never sees it and the expanded result names no side letter.
    """
    expansion = Expansion()
    if not _validate(compact, COMPACT_SCHEMAS["judge"], schema_errors, expansion):
        return expansion
    entries = {name: {"stance": entry["verdict"], "cites": entry.get("cites", ()), "why": entry.get("why")}
               for name, entry in (compact.get("per_predicate") or {}).items()}
    positions = positions_of({"per_predicate": entries}, labels, expansion, "judge")
    verdict = compact["verdict"]
    if verdict in ("A", "B", "both") and not any(item.refs for item in positions):
        expansion.note(f"judge: verdict {verdict} has no resolvable citation; recorded as unresolved")
        verdict = UNRESOLVED
    expansion.result = {
        "schema": JUDGE_RESULT_SCHEMA, "claim_id": claim_id, "verdict": deshuffle(verdict, side_map),
        "per_predicate": {item.predicate: {"verdict": deshuffle(item.stance, side_map), "cites": list(item.refs)}
                          for item in positions},
        "citations": citations_of(positions), "reason": text(compact["reason"], "no reason given", MAX_TEXT)}
    return expansion


# ------------------------------------------------------------------------------------------------
# Red wrapper


def _kind(ref: str) -> str:
    return ref.split(":", 2)[1]


def expand_poc_basis(brief: Any, labels: LabelTable, expansion: Expansion, owner: str
                     ) -> tuple[dict[str, Any] | None, list[str], str | None]:
    """``(poc_basis, closed preconditions, attacker entry identity)`` of a claim\'s optional proof-of-concept brief.

    The brief is not code and not evidence. Entry labels must resolve to ``entry_point`` identities and path
    labels to ``call_site`` identities in order; ``unknowns`` are material-gap labels, kept as the gap text. A label
    that does not resolve is dropped with feedback. Free text is bounded; ``preconditions`` that name a member of
    the closed ``preconditions/1`` vocabulary also fill the claim\'s closed precondition field.
    """
    if not isinstance(brief, Mapping):
        return None, [], None
    entry, dropped = labels.resolve_all(brief.get("entry", ()))
    wrong = [ref for ref in entry if _kind(ref) != "entry_point"]
    path, more = labels.resolve_all(brief.get("path", ()))
    wrong += [ref for ref in path if _kind(ref) != "call_site"]
    for token in (*dropped, *more):
        expansion.note(f"{owner}: poc_basis label {token} does not resolve and was dropped")
    if wrong:
        expansion.note(f"{owner}: poc_basis entries must be entry points and path hops call sites; "
                       f"{len(wrong)} other identities were dropped")
    entry = [ref for ref in entry if _kind(ref) == "entry_point"]
    path = [ref for ref in path if _kind(ref) == "call_site"]
    unknowns: list[str] = []
    for token in brief.get("unknowns", ()):
        found = labels.text_of(token)
        if found is None:
            expansion.note(f"{owner}: poc_basis unknown {str(token)[:40]} is not a material gap label and was dropped")
        else:
            unknowns.append(text(found, "", POC_TEXT))
    preconditions = [text(item, "", POC_TEXT) for item in brief.get("preconditions", ())]
    poc = {"entry": entry, "path": path,
           "trigger": [{key: text(item.get(key), "not stated", POC_TEXT) for key in ("field", "where", "constraint", "why")}
                       for item in brief.get("trigger", ())],
           "input_format": text(brief.get("input_format"), "not stated", POC_TEXT),
           "preconditions": preconditions,
           "expected_observation": text(brief.get("expected_observation"), "not stated", POC_TEXT),
           "unknowns": unknowns}
    return poc, [item for item in preconditions if item in CLOSED_PRECONDITIONS], (entry[0] if entry else None)


def expand_red(compact: Mapping[str, Any], labels: LabelTable, *, invocation: RedInvocation,
               schema_errors: SchemaErrors) -> Expansion:
    """``red-compact/1`` -> ``red-discovery-result/1`` for one package\'s lead (or unit) accounting."""
    expansion = Expansion()
    if not _validate(compact, COMPACT_SCHEMAS["red"], schema_errors, expansion):
        return expansion
    echo = invocation.echo()
    expected = list(invocation.lead_ids)
    proposals: list[dict[str, Any]] = []
    refs: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    developing: dict[str, list[str]] = {}
    used_ids: set[str] = set()

    def lead_ref(token: Any, owner: str) -> str | None:
        ref = labels.resolve(token)
        if ref is None or ref not in expected:
            expansion.note(f"{owner}: {str(token)[:40]} is not a lead of this package and was dropped")
            return None
        return ref

    def new_gap(kind: str, scope: str, reason: str) -> str:
        local = f"g{len(gaps) + 1}"
        gaps.append({"local_id": local, "kind": kind, "scope": text(scope, "package", 1000),
                     "reason": text(reason, DEFAULT_TEXT, 1000)})
        return local

    for index, claim in enumerate(compact["claims"], start=1):
        local = claim["id"]
        if local in used_ids or local.startswith("g") and local[1:].isdigit():
            expansion.errors.append(f"claim id {local} is repeated or reserved")
            continue
        used_ids.add(local)
        owner = f"claim {local}"
        sources = [ref for ref in (lead_ref(token, owner) for token in claim["leads"]) if ref]
        evidence_ids: list[str] = []
        counter_ids: list[str] = []
        affected: list[str] = []
        for relation, field_name, bucket in (("supports", "support", evidence_ids), ("qualifies", "counter", counter_ids)):
            for predicate in PREDICATES:
                tokens = (claim.get(field_name) or {}).get(predicate, ())
                found, dropped = labels.resolve_all(tokens)
                for token in dropped:
                    expansion.note(f"{owner}: {field_name} {predicate} citation {token} does not resolve and was dropped")
                for ref in found:
                    name = f"{local}-e{len(refs) + 1}"
                    refs.append({"local_id": name, "entity_id": ref, "shard_id": None, "shard_sha256": None,
                                 "relation": relation, "predicate": predicate,
                                 "locator": {"kind": "unresolved",
                                             "reason": "cited by label; the application re-resolves the identity"}})
                    bucket.append(name)
                    if predicate == "affected_construct" and relation == "supports" and ref not in affected:
                        affected.append(ref)
        explicit, dropped = labels.resolve_all(claim.get("affected", ()))
        for token in dropped:
            expansion.note(f"{owner}: affected {token} does not resolve and was dropped")
        affected = (explicit or affected or sources)[:64]
        if not affected:
            expansion.errors.append(f"{owner} names no affected construct and no resolvable lead")
            continue
        for item in claim.get("missing", ()):
            new_gap("unresolved", labels.text_of(item) or item, f"stated by the analyst for {owner}")
        statement = text(claim["statement"])
        poc, closed, entry_ref = expand_poc_basis(claim.get("poc_basis"), labels, expansion, owner)
        if poc is not None and not poc["entry"]:
            new_gap("unresolved", "no entry point is cited for the proof-of-concept basis; how input reaches the "
                                  "lead is unknown", f"stated by the analyst for {owner}")
        preconditions = list(dict.fromkeys([*claim.get("preconditions", ()), *closed]))
        proposals.append({
            "local_id": local, "source_lead_ids": sources, "affected_entities": affected, "statement": statement,
            "mechanism": text(claim.get("mechanism"), statement),
            "weakness": {"namespace": "CWE", "id": claim["cwe"]} if claim.get("cwe") else None,
            "security_predicate": claim["security_predicate"],
            "attacker_entry": {"entity_id": entry_ref, "control": text(claim.get("entry")),
                               "preconditions": preconditions},
            "trigger": text(claim.get("trigger")), "suspected_consequence": text(claim.get("consequence")),
            "assumptions": [], "evidence_ids": evidence_ids, "counterevidence_ids": counter_ids,
            "obligation_ids": [], "taint_path_ids": [], **({"poc_basis": poc} if poc is not None else {})})
        for ref in sources:
            developing.setdefault(ref, []).append(local)
    accounting = []
    noted: dict[str, tuple[str, str]] = {}
    for group, outcome in (("no_claim", "no_proposal"), ("blocked", "blocked")):
        for item in compact.get(group, ()):
            token, why = (item, None) if isinstance(item, str) else (item["lead"], item.get("why"))
            ref = lead_ref(token, group)
            if ref and ref not in noted:
                noted[ref] = (outcome, text(why, "this bounded lens proposed nothing for the lead" if outcome == "no_proposal"
                                            else "the lens could not assess the lead"))
    for lead in expected:
        if lead in developing:
            accounting.append({"observation_id": lead, "outcome": "proposal", "proposal_ids": developing[lead],
                               "gap_ids": [], "reason": "developed into a proposal"})
        elif lead in noted and noted[lead][0] == "no_proposal":
            accounting.append({"observation_id": lead, "outcome": "no_proposal", "proposal_ids": [], "gap_ids": [],
                               "reason": noted[lead][1]})
        else:
            if lead in noted:
                reason = noted[lead][1]
            else:
                reason = "the answer did not account for this lead"
                expansion.note(f"lead {lead[-12:]} was not accounted for; recorded as blocked with a gap")
            accounting.append({"observation_id": lead, "outcome": "blocked", "proposal_ids": [],
                               "gap_ids": [new_gap("missing" if lead not in noted else "unresolved",
                                                   f"lead {lead}", reason)], "reason": reason})
    if expansion.errors:
        return expansion
    expansion.result = {
        "schema": RED_RESULT_SCHEMA, **echo, "result_status": "partial" if gaps else "completed",
        "lead_accounting": accounting, "proposals": proposals, "proof_obligations": [], "taint_paths": [],
        "chain_seeds": [], "evidence_refs": refs, "evidence_requests": [], "gaps": gaps}
    return expansion


__all__ = ["expand_poc_basis", "BLUE_SCHEMA", "COMPACT_SCHEMAS", "Expander", "Expansion", "JUDGE_RESULT_SCHEMA",
           "PREDICATES", "Position", "VERIFIER_SCHEMA", "citations_of", "deshuffle", "expand_blue", "expand_judge",
           "expand_red", "expand_verifier", "overall_stance", "positions_of",
           "relations_of", "resolve_position", "summary_why", "text"]
