"""Evidence-qualified chains, independent challenges and deterministic weakest-link policy.

An accepted citation is not automatically continuity proof. Counted facts must come from an
explicitly commissioned deterministic index producer and satisfy the closed continuity fact
contract below. Source prose, seed edges and model stances never satisfy that contract.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
import re
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.review.identity import sha256_hex
from appsec_review.review.independence import ActorRecord, model_distinct
from appsec_review.review.models import (
    ChainStatus, ClaimState, ContinuityDimension as Dimension, ContinuityOutcome as Outcome, IntegrityError,
)
from appsec_review.retrieval.model import LogicalIdentity
from appsec_review.storage import canonical_json

CHAIN_SCHEMA = "appsec-review/attack-chain/1"
FACT_SCHEMA = "appsec-review/chain-continuity-fact/1"
POLICY = "attack-chain-continuity/1"
_SHA = re.compile(r"^[0-9a-f]{64}$")
_REL = re.compile(r"^rel:[0-9a-f]{64}$")
_KINDS = {
    Dimension.IDENTITY: frozenset({"SAME_AS", "FLOWS_TO"}),
    Dimension.PRIVILEGE: frozenset({"SUPPORTS", "FLOWS_TO"}),
    Dimension.TRUST_BOUNDARY: frozenset({"FLOWS_TO"}),
    Dimension.ARTIFACT_DEPLOYMENT: frozenset({"GENERATED_FROM", "COMPILES_TO", "LINKS_INTO", "OBSERVED_AT"}),
    Dimension.TEMPORAL: frozenset({"FLOWS_TO", "OBSERVED_AT"}),
}


def document(record: Any) -> dict[str, Any]:
    return json.loads(canonical_json(asdict(record)))


def _id(kind: str, body: Mapping[str, Any]) -> str:
    return f"{kind}-{sha256_hex({'kind': kind, 'version': 1, 'body': dict(body)})}"


def _texts(values: tuple[str, ...]) -> None:
    if (not isinstance(values, tuple) or len(values) > 256
            or any(not isinstance(value, str) or not 1 <= len(value) <= 2000 for value in values)
            or len(set(values)) != len(values)):
        raise ValueError("chain text lists must be unique, bounded strings")


def _actor_valid(actor: ActorRecord) -> None:
    if (not isinstance(actor, ActorRecord) or any(
            not isinstance(getattr(actor, key), str) or not 1 <= len(getattr(actor, key)) <= 200
            for key in ("actor_id", "provider", "model", "conversation_id"))
            or actor.prior_response_sha256 is not None and not _SHA.fullmatch(actor.prior_response_sha256)
            or actor.cache_key is not None and not isinstance(actor.cache_key, str)):
        raise ValueError("chain actors require bounded, explicit model and conversation identities")


@dataclass(frozen=True, slots=True)
class Artifact:
    path: str
    sha256: str

    def __post_init__(self) -> None:
        from appsec_review.retrieval.model import normalize_relative_path
        if normalize_relative_path(self.path) != self.path or not _SHA.fullmatch(self.sha256):
            raise ValueError("chain artifact must be a canonical run-relative path with a SHA-256")


@dataclass(frozen=True, slots=True)
class Component:
    claim_id: str
    adjudication_id: str
    state: ClaimState
    missing_predicates: tuple[str, ...] = ()
    requires_extra_verifier: bool = False

    def __post_init__(self) -> None:
        if self.state not in {ClaimState.SUPPORTED, ClaimState.CONFIRMED}:
            raise ValueError("chain components must be supported or confirmed")
        if (not re.fullmatch(r"claim-[0-9a-f]{64}", self.claim_id)
                or not re.fullmatch(r"adjudication-[0-9a-f]{64}", self.adjudication_id)):
            raise ValueError("chain component identities are required")
        if type(self.requires_extra_verifier) is not bool:
            raise ValueError("requires_extra_verifier must be a boolean")
        _texts(self.missing_predicates)
        if self.state is ClaimState.SUPPORTED and not self.missing_predicates:
            raise ValueError("supported chain components must name their missing confirmation")


@dataclass(frozen=True, slots=True)
class ContinuityEvidence:
    relation_id: str
    index: str
    shard_id: str
    shard_sha256: str
    content_sha256: str
    outcome: Outcome
    reason: str

    def __post_init__(self) -> None:
        if (not _REL.fullmatch(self.relation_id) or not _SHA.fullmatch(self.shard_sha256)
                or not _SHA.fullmatch(self.content_sha256) or not self.index or not self.shard_id
                or not self.reason or len(self.reason) > 256):
            raise ValueError("invalid accepted continuity evidence identity")
        if not isinstance(self.outcome, Outcome):
            raise ValueError("unknown continuity evidence outcome")


@dataclass(frozen=True, slots=True)
class Obligation:
    dimension: Dimension
    evidence: tuple[ContinuityEvidence, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.dimension, Dimension) or not isinstance(self.evidence, tuple) or len(self.evidence) > 32:
            raise ValueError("continuity obligations require a dimension and bounded immutable evidence")

    @property
    def outcome(self) -> Outcome:
        if any(item.outcome is Outcome.CONTRADICTED for item in self.evidence):
            return Outcome.CONTRADICTED
        if any(item.outcome is Outcome.SATISFIED for item in self.evidence):
            return Outcome.SATISFIED
        return Outcome.UNRESOLVED


@dataclass(frozen=True, slots=True)
class Edge:
    from_claim_id: str
    to_claim_id: str
    output_entity: str
    input_entity: str
    obligations: tuple[Obligation, ...]

    def __post_init__(self) -> None:
        LogicalIdentity.parse(self.output_entity)
        LogicalIdentity.parse(self.input_entity)
        if tuple(item.dimension for item in self.obligations) != tuple(Dimension):
            raise ValueError("each chain edge must have all five canonical continuity obligations")
        for item in self.obligations:
            keys = [(ref.index, ref.shard_id, ref.relation_id) for ref in item.evidence]
            if keys != sorted(set(keys)):
                raise ValueError("continuity evidence must be unique and canonically ordered")

    def semantic(self) -> dict[str, Any]:
        return {"from_claim_id": self.from_claim_id, "to_claim_id": self.to_claim_id,
                "output_entity": self.output_entity, "input_entity": self.input_entity}


@dataclass(frozen=True, slots=True)
class Proposal:
    chain_id: str
    objective: str
    environment: str
    components: tuple[Component, ...]
    edges: tuple[Edge, ...]
    prerequisites: tuple[str, ...]
    composer: ActorRecord

    def __post_init__(self) -> None:
        if (not isinstance(self.objective, str) or not 1 <= len(self.objective) <= 1000
                or not isinstance(self.environment, str) or not 1 <= len(self.environment) <= 2000):
            raise ValueError("bounded chain objective and observed environment identity are required")
        _texts(self.prerequisites)
        _actor_valid(self.composer)
        if not isinstance(self.components, tuple) or not isinstance(self.edges, tuple):
            raise ValueError("chain paths must be immutable tuples")
        ids = tuple(item.claim_id for item in self.components)
        if not 2 <= len(ids) <= 8 or len(set(ids)) != len(ids) or len(self.edges) != len(ids) - 1:
            raise ValueError("a chain must be a simple ordered path of 2..8 adjudicated components")
        if tuple((edge.from_claim_id, edge.to_claim_id) for edge in self.edges) != tuple(zip(ids, ids[1:])):
            raise ValueError("chain edges must connect exactly the ordered components")
        if self.chain_id != chain_identity(self.components, self.edges, self.objective, self.environment):
            raise ValueError("chain semantic identity does not match components, edges, objective and environment")

    @property
    def requires_extra_verifier(self) -> bool:
        return any(item.requires_extra_verifier for item in self.components)


def chain_identity(components: Sequence[Component], edges: Sequence[Edge], objective: str, environment: str) -> str:
    return _id("chain", {
        "components": [{"claim_id": item.claim_id, "adjudication_id": item.adjudication_id} for item in components],
        "edges": [edge.semantic() for edge in edges], "objective": objective, "environment": environment})


@dataclass(frozen=True, slots=True)
class Challenge:
    challenge_id: str
    chain_id: str
    kind: str
    actor: ActorRecord
    status: str
    request_sha256: str
    receipt: Artifact | None
    # One re-resolved evidence set per edge; no composer/refuter rationale is stored here.
    edges: tuple[Edge, ...]
    independent: bool
    gaps: tuple[str, ...]

    def __post_init__(self) -> None:
        _actor_valid(self.actor)
        _texts(self.gaps)
        if type(self.independent) is not bool or not isinstance(self.edges, tuple) or not 1 <= len(self.edges) <= 7:
            raise ValueError("chain challenges require bounded edges and explicit boolean independence")
        if self.kind not in {"refuter", "weakest_link_verifier"}:
            raise ValueError("unknown chain challenge kind")
        if self.status not in {"succeeded", "failed", "timed_out", "invalid", "not_launched", "blocked", "canceled"}:
            raise ValueError("unknown chain challenge status")
        if not _SHA.fullmatch(self.request_sha256):
            raise ValueError("challenge request digest is required")
        if self.status == "succeeded" and self.receipt is None:
            raise ValueError("successful challenge requires an immutable cell receipt")
        expected = challenge_identity(self.chain_id, self.kind, self.actor)
        if self.challenge_id != expected:
            raise ValueError("challenge identity mismatch")


@dataclass(frozen=True, slots=True)
class Decision:
    chain_id: str
    status: ChainStatus
    limitations: tuple[str, ...]
    challenge_ids: tuple[str, ...]
    artifact: Artifact
    policy: str = POLICY

    def __post_init__(self) -> None:
        _texts(self.limitations)
        if (not re.fullmatch(r"chain-[0-9a-f]{64}", self.chain_id) or not isinstance(self.status, ChainStatus)
                or not isinstance(self.challenge_ids, tuple)
                or len(self.challenge_ids) > 2 or len(set(self.challenge_ids)) != len(self.challenge_ids)
                or any(not re.fullmatch(r"chain_challenge-[0-9a-f]{64}", value) for value in self.challenge_ids)
                or self.policy != POLICY):
            raise ValueError("chain decision must use canonical identities, a status and the current policy")


def challenge_identity(chain_id: str, kind: str, actor: ActorRecord) -> str:
    return _id("chain_challenge", {"chain_id": chain_id, "kind": kind, "actor": document(actor)})


def independent(actor: ActorRecord, others: Sequence[ActorRecord], *, distinct_model: bool = False) -> bool:
    return (bool(actor.conversation_id) and actor.prior_response_sha256 is None
            and all(actor.actor_id != other.actor_id and actor.conversation_id != other.conversation_id
                    and (actor.cache_key is None or actor.cache_key != other.cache_key) for other in others)
            and (not distinct_model or model_distinct(actor, others)))


def decide(proposal: Proposal, challenges: Sequence[Challenge]) -> tuple[ChainStatus, tuple[str, ...]]:
    """No successful model stance can manufacture evidence or substitute for a required challenge."""
    by_kind: dict[str, Challenge] = {}
    for challenge in challenges:
        if challenge.chain_id != proposal.chain_id or challenge.kind in by_kind:
            raise IntegrityError("challenge is duplicated or belongs to a different chain")
        if tuple(edge.semantic() for edge in challenge.edges) != tuple(edge.semantic() for edge in proposal.edges):
            raise IntegrityError("challenge changed chain endpoints")
        by_kind[challenge.kind] = challenge
    all_edges = [*proposal.edges, *(edge for challenge in challenges for edge in challenge.edges)]
    defeated = [f"{edge.from_claim_id}->{edge.to_claim_id}:{item.dimension.value}:contradicted"
                for edge in all_edges for item in edge.obligations if item.outcome is Outcome.CONTRADICTED]
    if defeated:
        return ChainStatus.REFUTED, tuple(sorted(set(defeated)))
    required = ("refuter", "weakest_link_verifier") if proposal.requires_extra_verifier else ("refuter",)
    failures: list[str] = []
    for kind in required:
        challenge = by_kind.get(kind)
        others = [proposal.composer]
        if kind == "weakest_link_verifier" and "refuter" in by_kind:
            others.append(by_kind["refuter"].actor)
        if challenge is None:
            failures.append(f"{kind}:missing")
        elif challenge.status != "succeeded":
            failures.append(f"{kind}:{challenge.status}")
        elif not challenge.independent or not independent(
                challenge.actor, others, distinct_model=kind == "weakest_link_verifier"):
            failures.append(f"{kind}:independence_not_established")
        elif challenge.gaps:
            failures.extend(f"{kind}:{gap}" for gap in challenge.gaps)
    if failures:
        return ChainStatus.INSUFFICIENT_EVIDENCE, tuple(sorted(set(failures)))
    limitations = [f"component:{item.claim_id}:supported:{','.join(item.missing_predicates)}"
                   for item in proposal.components if item.state is ClaimState.SUPPORTED]
    meaningful = False
    for index, edge in enumerate(proposal.edges):
        for item in edge.obligations:
            supports = item.outcome is Outcome.SATISFIED
            meaningful |= supports
            if not supports:
                limitations.append(f"edge:{index}:{item.dimension.value}:unresolved")
            for kind in required:
                checked = by_kind[kind].edges[index].obligations[list(Dimension).index(item.dimension)]
                if checked.outcome is not Outcome.SATISFIED:
                    limitations.append(f"edge:{index}:{item.dimension.value}:{kind}_lacks_counted_support")
    if not meaningful:
        return ChainStatus.INSUFFICIENT_EVIDENCE, tuple(sorted(set(
            [*limitations, "no_meaningful_accepted_continuity_evidence"])))
    if limitations:
        return ChainStatus.QUALIFIED_SUPPORTED, tuple(sorted(set(limitations)))
    return ChainStatus.CONFIRMED, ()


def _fact_outcome(dimension: Dimension, values: Mapping[str, Any]) -> tuple[Outcome, str]:
    """Evaluate native observed values, never a producer/model's asserted success flag."""
    fields = {
        Dimension.IDENTITY: {"output_identity", "input_identity"},
        Dimension.PRIVILEGE: {"principal_out", "principal_in", "provided", "required"},
        Dimension.TRUST_BOUNDARY: {"destination_zone", "source_zone", "transport_out", "transport_in",
                                   "enforcement_point_out", "enforcement_point_in"},
        Dimension.ARTIFACT_DEPLOYMENT: {"artifact_out", "artifact_in", "deployment_out", "deployment_in",
                                        "configuration_out", "configuration_in"},
        Dimension.TEMPORAL: {"a_start", "a_end", "b_start", "b_end", "output_at", "input_at",
                            "version_out", "version_in", "configuration_out", "configuration_in"},
    }[dimension]
    if set(values) != fields:
        return Outcome.UNRESOLVED, "native_fact_fields_missing_or_unknown"
    if dimension is Dimension.PRIVILEGE:
        provided, required = values["provided"], values["required"]
        if (not isinstance(provided, list) or not isinstance(required, list) or not required
                or len(provided) > 64 or len(required) > 64
                or any(not isinstance(value, str) or not 1 <= len(value) <= 2000 for value in [*provided, *required])
                or len(set(provided)) != len(provided) or len(set(required)) != len(required)
                or not all(isinstance(values[name], str) and 1 <= len(values[name]) <= 2000
                           for name in ("principal_out", "principal_in"))):
            return Outcome.UNRESOLVED, "native_privilege_values_invalid"
        holds = values["principal_out"] == values["principal_in"] and set(required) <= set(provided)
    elif dimension is Dimension.TEMPORAL:
        times = ("a_start", "a_end", "b_start", "b_end", "output_at", "input_at")
        if any(type(values[name]) is not int for name in times):
            return Outcome.UNRESOLVED, "native_temporal_values_invalid"
        if not all(isinstance(values[name], str) and 1 <= len(values[name]) <= 2000 for name in fields - set(times)):
            return Outcome.UNRESOLVED, "native_temporal_identity_missing"
        holds = (values["a_start"] <= values["output_at"] <= values["input_at"] <= values["a_end"]
                 and values["b_start"] <= values["output_at"] <= values["input_at"] <= values["b_end"]
                 and values["version_out"] == values["version_in"]
                 and values["configuration_out"] == values["configuration_in"])
    else:
        if any(not isinstance(value, str) or not 1 <= len(value) <= 2000 for value in values.values()):
            return Outcome.UNRESOLVED, "native_identity_values_missing"
        pairs = {
            Dimension.IDENTITY: (("output_identity", "input_identity"),),
            Dimension.TRUST_BOUNDARY: (("destination_zone", "source_zone"), ("transport_out", "transport_in"),
                                      ("enforcement_point_out", "enforcement_point_in")),
            Dimension.ARTIFACT_DEPLOYMENT: (("artifact_out", "artifact_in"), ("deployment_out", "deployment_in"),
                                           ("configuration_out", "configuration_in")),
        }[dimension]
        holds = all(values[left] == values[right] for left, right in pairs)
    return (Outcome.SATISFIED, "native_values_establish_continuity") if holds else (
        Outcome.CONTRADICTED, "native_values_contradict_continuity")


def _artifact_resolution(core: Any, edge: Edge, values: Mapping[str, Any]) -> bool:
    """Source, build/configuration, artifact and deployment must resolve as one accepted graph."""
    from appsec_review.retrieval.model import EntityKind
    expected = {"artifact_out": {EntityKind.OBJECT_FILE, EntityKind.LIBRARY, EntityKind.EXECUTABLE,
                                 EntityKind.BUILD_ARTIFACT, EntityKind.PACKAGE, EntityKind.MANAGED_ASSEMBLY,
                                 EntityKind.BYTECODE_MODULE, EntityKind.WASM_MODULE},
                "artifact_in": {EntityKind.OBJECT_FILE, EntityKind.LIBRARY, EntityKind.EXECUTABLE,
                                EntityKind.BUILD_ARTIFACT, EntityKind.PACKAGE, EntityKind.MANAGED_ASSEMBLY,
                                EntityKind.BYTECODE_MODULE, EntityKind.WASM_MODULE},
                "deployment_out": {EntityKind.DEPLOYMENT_EVENT}, "deployment_in": {EntityKind.DEPLOYMENT_EVENT},
                "configuration_out": {EntityKind.BUILD_ACTION, EntityKind.COMPILE_UNIT},
                "configuration_in": {EntityKind.BUILD_ACTION, EntityKind.COMPILE_UNIT}}
    for key, kinds in expected.items():
        try:
            identity = LogicalIdentity.parse(values[key])
        except ValueError:
            return False
        if identity.kind not in kinds:
            return False
        found = core.find(identity=identity.value, limit=1)
        if not found["results"] or found.get("truncated") or found.get("coverage_gaps"):
            return False
    for side, source in (("out", edge.output_entity), ("in", edge.input_entity)):
        artifact = values[f"artifact_{side}"]
        response = core.trace(identity=artifact, relations=("GENERATED_FROM", "COMPILES_TO", "LINKS_INTO", "OBSERVED_AT"),
                              depth=min(3, core.limits.max_depth), limit=min(100, core.limits.max_results))
        if response.get("truncated") or response.get("coverage_gaps"):
            return False
        adjacency: dict[str, set[str]] = {}
        deployed = False
        for row in response["results"]:
            if not row.get("exact") or row.get("ambiguity"):
                continue
            left, right = row["source_id"], row["target_id"]
            if row["kind"] == "OBSERVED_AT":
                deployed |= (left, right) == (artifact, values[f"deployment_{side}"])
                continue
            if row["kind"] == "GENERATED_FROM":
                left, right = right, left
            adjacency.setdefault(left, set()).add(right)

        def reaches(start: str) -> bool:
            visited, frontier = {start}, {start}
            for _ in range(3):
                if artifact in frontier:
                    return True
                frontier = {value for current in frontier for value in adjacency.get(current, ())} - visited
                visited.update(frontier)
            return artifact in frontier

        if not deployed or not reaches(source) or not reaches(values[f"configuration_{side}"]):
            return False
    return True


def resolve_edge(core: Any, edge: Edge, environment: str, *, producers: Sequence[str], limit: int,
                 evidence_limit: int, cited_relations: Iterable[str] | None = None) -> tuple[Edge, tuple[str, ...]]:
    """Resolve only bounded accepted index facts, retaining exact shard and native-content hashes.

    The producer allowlist is empty by default: currently indexed source/build facts alone do not
    prove deployed privileges, boundaries or time. Commissioning a native continuity exporter is
    explicit configuration, not something a composer or target document can do.
    """
    response = core.trace(identity=edge.output_entity, relations=tuple(sorted(set.union(*map(set, _KINDS.values())))),
                          depth=1, limit=limit)
    gaps = list(response.get("coverage_gaps", ()))
    if response.get("truncated"):
        gaps.append("continuity_query_truncated")
    shards = {(item["name"], str(item.get("shard_id", "default"))): item for item in core.manifest["indexes"]}
    selected = set(cited_relations) if cited_relations is not None else None
    evidence: dict[Dimension, dict[tuple[str, str, str], ContinuityEvidence]] = {item: {} for item in Dimension}
    configurations: dict[Dimension, list[tuple[tuple[str, str, str], Mapping[str, Any]]]] = {
        Dimension.ARTIFACT_DEPLOYMENT: [], Dimension.TEMPORAL: []}
    for row in response["results"]:
        if selected is not None and row.get("relation_id") not in selected:
            continue
        if (row.get("source_id"), row.get("target_id")) != (edge.output_entity, edge.input_entity):
            continue
        shard = shards.get((row.get("index"), str(row.get("shard_id", "default"))))
        if shard is None:
            raise IntegrityError("continuity query returned a relation outside the accepted manifest")
        provenance = shard.get("producer", {})
        producer = f"{provenance.get('job_id', '')}/{provenance.get('rule_id', '')}"
        payload = row.get("payload")
        if producer not in producers or not isinstance(payload, Mapping) or payload.get("schema") != FACT_SCHEMA:
            continue
        try:
            dimension = Dimension(payload.get("dimension"))
        except ValueError:
            continue
        if (set(payload) != {"schema", "dimension", "observed_scope", "values"}
                or payload["observed_scope"] != environment or row.get("kind") not in _KINDS[dimension]
                or row.get("exact") not in (True, 1) or row.get("ambiguity")
                or not isinstance(payload["values"], Mapping)):
            continue
        outcome, reason = _fact_outcome(dimension, payload["values"])
        if (dimension is Dimension.ARTIFACT_DEPLOYMENT and outcome is not Outcome.UNRESOLVED
                and not _artifact_resolution(core, edge, payload["values"])):
            outcome, reason = Outcome.UNRESOLVED, "source_build_artifact_configuration_deployment_not_connected"
        if response.get("truncated") or gaps:
            outcome, reason = Outcome.UNRESOLVED, "continuity_lookup_incomplete"
        item = ContinuityEvidence(
            row["relation_id"], row["index"], str(row.get("shard_id", "default")),
            shard["sha256"], sha256_hex({key: row.get(key) for key in (
                "relation_id", "kind", "source_id", "target_id", "exact", "ambiguity", "payload")}), outcome, reason)
        key = (item.index, item.shard_id, item.relation_id)
        evidence[dimension][key] = item
        if dimension in configurations and outcome is not Outcome.UNRESOLVED:
            configurations[dimension].append((key, payload["values"]))
    for artifact_key, artifact in configurations[Dimension.ARTIFACT_DEPLOYMENT]:
        for temporal_key, temporal in configurations[Dimension.TEMPORAL]:
            if any(artifact[name] != temporal[name] for name in ("configuration_out", "configuration_in")):
                for dimension, key in ((Dimension.ARTIFACT_DEPLOYMENT, artifact_key), (Dimension.TEMPORAL, temporal_key)):
                    evidence[dimension][key] = replace(evidence[dimension][key], outcome=Outcome.CONTRADICTED,
                                                        reason="artifact_and_temporal_configurations_disagree")
    obligations = []
    for dimension, items in evidence.items():
        if len(items) > evidence_limit:
            gaps.append(f"{dimension.value}:evidence_cap")
            # A bounded prefix cannot prove that omitted accepted evidence agrees.
            items = {key: replace(item, outcome=Outcome.UNRESOLVED, reason="continuity_evidence_cap")
                     for key, item in items.items()}
        obligations.append(Obligation(dimension, tuple(items[key] for key in sorted(items)[:evidence_limit])))
    return Edge(edge.from_claim_id, edge.to_claim_id, edge.output_entity, edge.input_entity, tuple(obligations)), tuple(
        sorted(set(gaps)))


def edge_from_json(value: Mapping[str, Any]) -> Edge:
    result = Edge(value["from_claim_id"], value["to_claim_id"], value["output_entity"], value["input_entity"],
                  tuple(Obligation(Dimension(item["dimension"]), tuple(ContinuityEvidence(
                      **{**ref, "outcome": Outcome(ref["outcome"])}) for ref in item["evidence"]))
                        for item in value["obligations"]))
    if canonical_json(document(result)) != canonical_json(value):
        raise ValueError("noncanonical or unknown edge fields")
    return result


def proposal_from_json(value: Mapping[str, Any]) -> Proposal:
    result = Proposal(
        value["chain_id"], value["objective"], value["environment"],
        tuple(Component(item["claim_id"], item["adjudication_id"], ClaimState(item["state"]),
                        tuple(item["missing_predicates"]), item["requires_extra_verifier"]) for item in value["components"]),
        tuple(edge_from_json(item) for item in value["edges"]), tuple(value["prerequisites"]),
        ActorRecord(**value["composer"]))
    if canonical_json(document(result)) != canonical_json(value):
        raise ValueError("noncanonical or unknown proposal fields")
    return result


def challenge_from_json(value: Mapping[str, Any]) -> Challenge:
    result = Challenge(
        value["challenge_id"], value["chain_id"], value["kind"], ActorRecord(**value["actor"]), value["status"],
        value["request_sha256"], Artifact(**value["receipt"]) if value["receipt"] is not None else None,
        tuple(edge_from_json(item) for item in value["edges"]), value["independent"], tuple(value["gaps"]))
    if canonical_json(document(result)) != canonical_json(value):
        raise ValueError("noncanonical or unknown challenge fields")
    return result


def decision_from_json(value: Mapping[str, Any]) -> Decision:
    result = Decision(value["chain_id"], ChainStatus(value["status"]), tuple(value["limitations"]),
                      tuple(value["challenge_ids"]), Artifact(**value["artifact"]), value["policy"])
    if canonical_json(document(result)) != canonical_json(value) or result.policy != POLICY:
        raise ValueError("noncanonical or unknown chain decision fields")
    return result
