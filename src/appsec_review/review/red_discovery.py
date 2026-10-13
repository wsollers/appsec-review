"""Admission rules and normalization views for ``red-discovery-result/1`` (design decision 10).

``red-discovery-result/1`` (docs/schemas/inference-security-review/red-discovery-result.schema.json)
is the single final-result contract of ``hypothesis_hunter`` and ``red_team_analyst`` cells. The
schema closes the shape; :func:`admission_errors` applies the rules the schema cannot express
(docs/architecture/red-discovery-output.md, "Admission rules for deterministic normalization"):

1. closed limits from the resolved ``settings.red_output`` table (:class:`RedOutputLimits`);
2. the echo checks against the invocation the application issued (:class:`RedInvocation`);
3. local-ID uniqueness, exact lead accounting, reference closure, ordered and acyclic taint and
   chain edges, and citations for every claimed observed taint segment.

Any admission error makes the cell's final result invalid, so the cell ends ``invalid`` with a
``schema_error`` gap (one terminal record, never an exception). The remaining helpers are the
read-only views the review-team handler normalizes: which evidence references a proposal cites,
which relation kind a reference may author, and the evidence requests, named gaps, lead outcomes,
and chain seeds a result carries.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.review.models import Predicate, RelationKind, Role

RESULT_SCHEMA = "appsec-review/red-discovery-result/1"
SCHEMA_NAME = "red-discovery-result"
ADMISSION_RULES_VERSION = "red-discovery-admission/1"
RED_ROLES = frozenset({Role.HYPOTHESIS_HUNTER, Role.RED_TEAM_ANALYST})
LEAD_OUTCOMES = ("proposal", "no_proposal", "blocked")
OBSERVED_EDGE_BASES = frozenset({"accepted_tool_path", "source_mapped_analysis"})
HYPOTHESIS_EDGE_BASIS = "analyst_hypothesis"
MAX_ERRORS = 20

# Red has no contradiction authority (its registry outputs are proposals; contradiction belongs to
# the blue refuters and the blind verifier). Counterevidence a red worker cites is therefore kept as
# a ``qualifies`` relation, separate from support, and ``nominates`` only guides search.
_RELATION_KINDS = {"supports": RelationKind.SUPPORTS, "qualifies": RelationKind.QUALIFIES,
                   "contradicts": RelationKind.QUALIFIES, "nominates": None}
_SUPPORT_RELATIONS = frozenset({"supports", "qualifies", "nominates"})
_COUNTER_RELATIONS = frozenset({"contradicts", "qualifies"})

# Hard ceilings: the schema's own maxItems/maxLength. A configured limit may only tighten them.
_CEILINGS = {"max_result_bytes": 256 * 1024, "max_proposals": 32, "max_obligations": 256,
             "max_taint_paths": 32, "max_path_nodes": 64, "max_chain_seeds": 16, "max_chain_steps": 32,
             "max_evidence_refs": 256, "max_evidence_requests": 64, "max_gaps": 128, "max_text_chars": 4096}
LEAD_ACCOUNTING_CEILING = 1024


@dataclass(frozen=True, slots=True)
class RedOutputLimits:
    """``jobs.job_inference_security_review.settings.red_output``: closed red-discovery-result limits.

    They are semantic (they decide which results are admitted), so they enter the cell validator
    version and therefore every red cell fingerprint.
    """

    max_result_bytes: int = 65_536
    max_proposals: int = 8
    max_obligations: int = 48
    max_taint_paths: int = 8
    max_path_nodes: int = 16
    max_chain_seeds: int = 4
    max_chain_steps: int = 8
    max_evidence_refs: int = 64
    max_evidence_requests: int = 16
    max_gaps: int = 32
    max_text_chars: int = 2_000

    def __post_init__(self) -> None:
        for item in fields(self):
            value, high = getattr(self, item.name), _CEILINGS[item.name]
            if type(value) is not int or not 1 <= value <= high:
                raise ValueError(f"red_output.{item.name} must be an integer between 1 and {high}")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None, field: str = "red_output") -> "RedOutputLimits":
        """Limits from a TOML table; unknown keys are rejected and absent keys keep their default."""
        if value is None:
            return cls()
        if not isinstance(value, Mapping):
            raise ValueError(f"{field} must be a table")
        unknown = sorted(str(key) for key in set(value) - {item.name for item in fields(cls)})
        if unknown:
            raise ValueError(f"{field} has unknown settings: {', '.join(unknown)}")
        try:
            return cls(**dict(value))
        except ValueError as exc:
            raise ValueError(str(exc).replace("red_output.", f"{field}.", 1)) from exc

    def record(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RedInvocation:
    """What the application issued to one red cell; the result's echo is checked against it."""

    role: Role
    round: int
    basis_sha256: str                    # the package's reuse basis, the only package identity shown
    lead_ids: tuple[str, ...]            # every lead (observation id) of the package's lead menu

    def echo(self) -> dict[str, Any]:
        """The echo block the cell is shown and must return verbatim."""
        return {"package": {"basis_sha256": self.basis_sha256}, "role": Role(self.role).value,
                "round_id": str(self.round)}


# ------------------------------------------------------------------------------------------------
# Admission


class _Errors(list):
    def add(self, message: str) -> None:
        if len(self) < MAX_ERRORS:
            self.append(message[:256])


def _ids(items: Iterable[Mapping[str, Any]]) -> list[str]:
    return [str(item.get("local_id")) for item in items]


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def admission_errors(result: Mapping[str, Any], invocation: RedInvocation, limits: RedOutputLimits) -> list[str]:
    """Every admission-rule violation of a schema-valid ``red-discovery-result/1`` (empty = admitted)."""
    errors = _Errors()
    _limits(result, limits, errors)
    _echo(result, invocation, errors)
    tables = _unique(result, errors)
    _lead_accounting(result, invocation, tables, errors)
    _closure(result, tables, errors)
    _taint(result, tables, limits, errors)
    _chains(result, tables, limits, errors)
    if result.get("result_status") == "partial" and not result.get("gaps"):
        errors.add("a partial result must name at least one gap")
    return list(errors)


def _limits(result: Mapping[str, Any], limits: RedOutputLimits, errors: _Errors) -> None:
    size = len(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    if size > limits.max_result_bytes:
        errors.add(f"result is {size} bytes; the limit is {limits.max_result_bytes}")
    for key, limit in (("proposals", limits.max_proposals), ("proof_obligations", limits.max_obligations),
                       ("taint_paths", limits.max_taint_paths), ("chain_seeds", limits.max_chain_seeds),
                       ("evidence_refs", limits.max_evidence_refs),
                       ("evidence_requests", limits.max_evidence_requests), ("gaps", limits.max_gaps)):
        if len(result.get(key, ())) > limit:
            errors.add(f"{key} holds {len(result[key])} items; the limit is {limit}")
    longest = max((len(text) for text in _strings(result)), default=0)
    if longest > limits.max_text_chars:
        errors.add(f"a text value has {longest} characters; the limit is {limits.max_text_chars}")


def _echo(result: Mapping[str, Any], invocation: RedInvocation, errors: _Errors) -> None:
    expected = invocation.echo()
    if result.get("package") != expected["package"]:
        errors.add("package echo does not match the invoked package")
    if result.get("role") != expected["role"]:
        errors.add("role echo does not match the invoked role")
    if result.get("round_id") != expected["round_id"]:
        errors.add("round echo does not match the invoked round")


def _unique(result: Mapping[str, Any], errors: _Errors) -> dict[str, dict[str, Mapping[str, Any]]]:
    """Top-level local IDs share one namespace; node and step IDs are unique within their parent."""
    tables: dict[str, dict[str, Mapping[str, Any]]] = {}
    seen: set[str] = set()
    for key in ("proposals", "proof_obligations", "taint_paths", "chain_seeds", "evidence_refs",
                "evidence_requests", "gaps"):
        table: dict[str, Mapping[str, Any]] = {}
        for item in result.get(key, ()):
            local = str(item["local_id"])
            if local in seen:
                errors.add(f"local id {local} is not unique")
            seen.add(local)
            table.setdefault(local, item)
        tables[key] = table
    for path in result.get("taint_paths", ()):
        if len(set(_ids(path["nodes"]))) != len(path["nodes"]):
            errors.add(f"taint path {path['local_id']} repeats a node id")
    for seed in result.get("chain_seeds", ()):
        if len(set(_ids(seed["steps"]))) != len(seed["steps"]):
            errors.add(f"chain seed {seed['local_id']} repeats a step id")
    return tables


def _lead_accounting(result: Mapping[str, Any], invocation: RedInvocation,
                     tables: Mapping[str, Mapping[str, Mapping[str, Any]]], errors: _Errors) -> None:
    entries = list(result.get("lead_accounting", ()))
    accounted = [str(entry["observation_id"]) for entry in entries]
    expected = set(invocation.lead_ids)
    if len(set(accounted)) != len(accounted):
        errors.add("lead accounting names a lead more than once")
    missing = expected - set(accounted)
    if missing:
        errors.add(f"lead accounting omits {len(missing)} package leads; every lead needs exactly one entry")
    extra = set(accounted) - expected
    if extra:
        errors.add(f"lead accounting names {len(extra)} leads outside the package")
    proposals, gaps = tables["proposals"], tables["gaps"]
    by_lead = {str(entry["observation_id"]): entry for entry in entries}
    for entry in entries:
        lead, outcome = str(entry["observation_id"]), entry["outcome"]
        if outcome == "proposal" and not entry["proposal_ids"]:
            errors.add(f"lead {lead[-12:]} is accounted as proposal without a proposal id")
        if outcome != "proposal" and entry["proposal_ids"]:
            errors.add(f"lead {lead[-12:]} is accounted as {outcome} but names proposals")
        if outcome == "blocked" and not entry["gap_ids"]:
            errors.add(f"lead {lead[-12:]} is blocked without naming a gap")
        for local in entry["proposal_ids"]:
            if local not in proposals:
                errors.add(f"lead accounting names unknown proposal {local}")
            elif lead not in proposals[local]["source_lead_ids"]:
                errors.add(f"lead accounting names proposal {local}, which does not cite that lead")
        for local in entry["gap_ids"]:
            if local not in gaps:
                errors.add(f"lead accounting names unknown gap {local}")
    for local, proposal in proposals.items():
        leads = list(proposal["source_lead_ids"])
        if invocation.role is Role.RED_TEAM_ANALYST and not leads:
            errors.add(f"proposal {local} develops no package lead; a lead analyst proposal names its lead")
        for lead in leads:
            if lead not in expected:
                errors.add(f"proposal {local} names a source lead outside the package")
            elif lead in by_lead and local not in by_lead[lead]["proposal_ids"]:
                errors.add(f"proposal {local} is missing from its source lead's accounting entry")


def _closure(result: Mapping[str, Any], tables: Mapping[str, Mapping[str, Mapping[str, Any]]],
             errors: _Errors) -> None:
    proposals, refs, gaps = tables["proposals"], tables["evidence_refs"], tables["gaps"]
    obligations, paths = tables["proof_obligations"], tables["taint_paths"]

    def refs_exist(owner: str, locals_: Iterable[str], allowed: frozenset[str] | None = None) -> None:
        for local in locals_:
            ref = refs.get(local)
            if ref is None:
                errors.add(f"{owner} cites unknown evidence {local}")
            elif allowed is not None and ref["relation"] not in allowed:
                errors.add(f"{owner} cites evidence {local} whose relation is {ref['relation']}")

    for local, proposal in proposals.items():
        refs_exist(f"proposal {local}", proposal["evidence_ids"], _SUPPORT_RELATIONS)
        refs_exist(f"proposal {local} counterevidence", proposal["counterevidence_ids"], _COUNTER_RELATIONS)
        for item in proposal["obligation_ids"]:
            if obligations.get(item, {}).get("proposal_id") != local:
                errors.add(f"proposal {local} names obligation {item}, which is unknown or another proposal's")
        for item in proposal["taint_path_ids"]:
            if paths.get(item, {}).get("proposal_id") != local:
                errors.add(f"proposal {local} names taint path {item}, which is unknown or another proposal's")
    for local, obligation in obligations.items():
        owner = proposals.get(obligation["proposal_id"])
        if owner is None or local not in owner["obligation_ids"]:
            errors.add(f"obligation {local} is not listed by its proposal")
        refs_exist(f"obligation {local}", obligation["candidate_evidence_ids"])
    for local, path in paths.items():
        owner = proposals.get(path["proposal_id"])
        if owner is None or local not in owner["taint_path_ids"]:
            errors.add(f"taint path {local} is not listed by its proposal")
        for item in path["gap_ids"]:
            if item not in gaps:
                errors.add(f"taint path {local} names unknown gap {item}")
    for local, request in tables["evidence_requests"].items():
        if request["proposal_id"] not in proposals:
            errors.add(f"evidence request {local} names an unknown proposal")
    for local, ref in refs.items():
        locator = ref["locator"]
        if locator.get("kind") == "source_line" and locator["end_line"] < locator["start_line"]:
            errors.add(f"evidence {local} has a source locator that ends before it starts")


def _taint(result: Mapping[str, Any], tables: Mapping[str, Mapping[str, Mapping[str, Any]]],
           limits: RedOutputLimits, errors: _Errors) -> None:
    refs = tables["evidence_refs"]
    for path in result.get("taint_paths", ()):
        local = path["local_id"]
        nodes = {node["local_id"]: (index, node) for index, node in enumerate(path["nodes"])}
        if len(path["nodes"]) > limits.max_path_nodes:
            errors.add(f"taint path {local} has {len(path['nodes'])} nodes; the limit is {limits.max_path_nodes}")
        source, sink = nodes.get(path["source_node"]), nodes.get(path["sink_node"])
        if source is None or source[1]["role"] != "source":
            errors.add(f"taint path {local} does not start at one of its source nodes")
        if sink is None or sink[1]["role"] != "sink":
            errors.add(f"taint path {local} does not end at one of its sink nodes")
        pairs: set[tuple[str, str]] = set()
        forward: dict[str, set[str]] = {}
        for edge in path["edges"]:
            ends = (edge["from_node"], edge["to_node"])
            if ends[0] not in nodes or ends[1] not in nodes:
                errors.add(f"taint path {local} has an edge to an unknown node")
                continue
            if nodes[ends[0]][0] >= nodes[ends[1]][0]:
                errors.add(f"taint path {local} has an edge that is not ordered forward (cycle or back edge)")
            if ends in pairs:
                errors.add(f"taint path {local} repeats an edge")
            pairs.add(ends)
            forward.setdefault(ends[0], set()).add(ends[1])
            for item in edge["evidence_ids"]:
                if item not in refs:
                    errors.add(f"taint path {local} edge cites unknown evidence {item}")
            if edge["basis"] in OBSERVED_EDGE_BASES and not edge["evidence_ids"]:
                errors.add(f"taint path {local} has an observed ({edge['basis']}) edge without a citation")
        if path["basis"] == "reported":
            if any(edge["basis"] == HYPOTHESIS_EDGE_BASIS for edge in path["edges"]):
                errors.add(f"taint path {local} is reported but contains a hypothesized hop")
            if source is not None and sink is not None and not _reaches(forward, path["source_node"], path["sink_node"]):
                errors.add(f"taint path {local} is reported but its edges do not connect source to sink")


def _reaches(forward: Mapping[str, set[str]], start: str, goal: str) -> bool:
    stack, visited = [start], set()
    while stack:
        node = stack.pop()
        if node == goal:
            return True
        if node not in visited:
            visited.add(node)
            stack.extend(forward.get(node, ()))
    return False


def _chains(result: Mapping[str, Any], tables: Mapping[str, Mapping[str, Mapping[str, Any]]],
            limits: RedOutputLimits, errors: _Errors) -> None:
    proposals, refs, gaps = tables["proposals"], tables["evidence_refs"], tables["gaps"]
    for seed in result.get("chain_seeds", ()):
        local = seed["local_id"]
        steps = {step["local_id"]: index for index, step in enumerate(seed["steps"])}
        if len(seed["steps"]) > limits.max_chain_steps:
            errors.add(f"chain seed {local} has {len(seed['steps'])} steps; the limit is {limits.max_chain_steps}")
        for step in seed["steps"]:
            if step["proposal_id"] is not None and step["proposal_id"] not in proposals:
                errors.add(f"chain seed {local} step names an unknown proposal")
        pairs: set[tuple[str, str]] = set()
        for link in seed["links"]:
            ends = (link["from_step"], link["to_step"])
            if ends[0] not in steps or ends[1] not in steps:
                errors.add(f"chain seed {local} links an unknown step")
                continue
            if steps[ends[0]] >= steps[ends[1]]:
                errors.add(f"chain seed {local} has a link that is not ordered forward (cycle or back link)")
            if ends in pairs:
                errors.add(f"chain seed {local} repeats a link")
            pairs.add(ends)
            for item in link["evidence_ids"]:
                if item not in refs:
                    errors.add(f"chain seed {local} link cites unknown evidence {item}")
        for item in seed["gap_ids"]:
            if item not in gaps:
                errors.add(f"chain seed {local} names unknown gap {item}")


# ------------------------------------------------------------------------------------------------
# Normalization views (read-only; the result has already been admitted)


@dataclass(frozen=True, slots=True)
class Citation:
    """One evidence reference a proposal cites, with the relation kind red may author for it."""

    local_id: str
    entity_id: str
    predicate: Predicate
    kind: RelationKind | None            # None: ``nominates`` guides search and never becomes a relation
    shard_id: str | None
    shard_sha256: str | None
    locator: Mapping[str, Any]
    via: str                             # proposal | counterevidence | taint_edge


def relation_kind(relation: str) -> RelationKind | None:
    return _RELATION_KINDS[relation]


def proposal_citations(result: Mapping[str, Any], proposal: Mapping[str, Any]) -> list[Citation]:
    """The references that may become relations for ``proposal``, deduplicated by local id.

    A proposal's ``evidence_ids`` and ``counterevidence_ids`` count, as do the citations of every
    observed (``accepted_tool_path`` or ``source_mapped_analysis``) hop of its own taint paths.
    A hop whose basis is ``analyst_hypothesis`` never becomes a relation: its citations count only
    when the proposal cites them directly.
    """
    refs = {item["local_id"]: item for item in result.get("evidence_refs", ())}
    order: list[tuple[str, str]] = [(local, "proposal") for local in proposal["evidence_ids"]]
    order += [(local, "counterevidence") for local in proposal["counterevidence_ids"]]
    paths = {item["local_id"]: item for item in result.get("taint_paths", ())}
    for path_id in proposal["taint_path_ids"]:
        for edge in paths[path_id]["edges"]:
            if edge["basis"] in OBSERVED_EDGE_BASES:
                order += [(local, "taint_edge") for local in edge["evidence_ids"]]
    citations: dict[str, Citation] = {}
    for local, via in order:
        if local in citations:
            continue
        ref = refs[local]
        citations[local] = Citation(local, str(ref["entity_id"]), Predicate(ref["predicate"]),
                                    relation_kind(ref["relation"]), ref["shard_id"], ref["shard_sha256"],
                                    dict(ref["locator"]), via)
    return list(citations.values())


def hypothesized_hops(result: Mapping[str, Any], proposal: Mapping[str, Any]) -> int:
    paths = {item["local_id"]: item for item in result.get("taint_paths", ())}
    return sum(1 for path_id in proposal["taint_path_ids"] for edge in paths[path_id]["edges"]
               if edge["basis"] == HYPOTHESIS_EDGE_BASIS)


def cited_entities(result: Mapping[str, Any], proposal: Mapping[str, Any]) -> set[str]:
    """Every logical identity ``proposal`` names: affected constructs, entry, path nodes, references."""
    cited = set(proposal["affected_entities"])
    if proposal["attacker_entry"]["entity_id"]:
        cited.add(proposal["attacker_entry"]["entity_id"])
    refs = {item["local_id"]: item for item in result.get("evidence_refs", ())}
    paths = {item["local_id"]: item for item in result.get("taint_paths", ())}
    locals_ = set(proposal["evidence_ids"]) | set(proposal["counterevidence_ids"])
    for path_id in proposal["taint_path_ids"]:
        cited.update(node["entity_id"] for node in paths[path_id]["nodes"] if node["entity_id"])
        locals_.update(item for edge in paths[path_id]["edges"] for item in edge["evidence_ids"])
    cited.update(refs[local]["entity_id"] for local in locals_ if local in refs)
    return cited


def proposal_requests(result: Mapping[str, Any], proposal_id: str) -> list[dict[str, Any]]:
    """The proposal's evidence requests in the ledger request shape (anchors are the scope entities)."""
    return [{"predicate": item["predicate"], "requested_kind": item["requested_kind"],
             "anchors": list(item["scope_entity_ids"])}
            for item in result.get("evidence_requests", ()) if item["proposal_id"] == proposal_id]


def narratives(proposal: Mapping[str, Any]) -> list[str]:
    """Red prose that must never reach a blind verifier request (design R6 markers)."""
    return [str(proposal[key]) for key in ("statement", "mechanism", "trigger", "suspected_consequence")] + [
        str(proposal["attacker_entry"]["control"])]


def lead_outcomes(result: Mapping[str, Any]) -> dict[str, str]:
    return {str(entry["observation_id"]): str(entry["outcome"]) for entry in result.get("lead_accounting", ())}


def named_gaps(result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return list(result.get("gaps", ()))


def chain_seeds(result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return list(result.get("chain_seeds", ()))


def summarize_lead(outcomes: Sequence[str]) -> str:
    """One package lead across its succeeded red cells.

    ``proposal`` when any cell proposed from it, else ``blocked`` when any cell was blocked, else
    ``no_proposal`` when cells looked and proposed nothing (never clean coverage), else
    ``unaccounted`` when no red cell of the package succeeded.
    """
    for outcome in ("proposal", "blocked", "no_proposal"):
        if outcome in outcomes:
            return outcome
    return "unaccounted"


__all__ = ["ADMISSION_RULES_VERSION", "Citation", "LEAD_ACCOUNTING_CEILING", "LEAD_OUTCOMES", "RED_ROLES",
           "RESULT_SCHEMA", "RedInvocation", "RedOutputLimits", "SCHEMA_NAME", "admission_errors", "chain_seeds",
           "cited_entities", "hypothesized_hops", "lead_outcomes", "named_gaps", "narratives", "proposal_citations",
           "proposal_requests", "relation_kind", "summarize_lead"]
