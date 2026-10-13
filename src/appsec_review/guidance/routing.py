"""Deterministic persona, stack-profile, and hunt-panel routing.

Every function here is a pure function of accepted facts and the persona ``covers`` patterns. Each
result records the basis that decided it; a fallback records a ``routing_gap`` (persona or stack)
or a ``coverage_gap`` (an unavailable hunt strategy) instead of silently narrowing review.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from appsec_review.jobs.job_security_tagging.crosswalk import Crosswalk
from appsec_review.jobs.job_security_tagging.taxonomy import Vocabulary, normalize_cwe, split_tag
from appsec_review.review.models import GapClass, HuntStrategy

from .coverage import cover_matches, cover_specificity, crosswalk_tags
from .fragments import GuidanceError


PERSONA_RULE = "persona-routing/1"
STACK_RULE = "stack-routing/1"
PANEL_RULE = "hunt-panel/1"
GENERALIST = "generalist"
GENERIC_STACK = "generic"
LOCATION_NAMESPACES = ("func", "infra", "data")
PARTITION_NAMESPACES = ("cwe", "func", "infra", "data")
DEFAULT_PANEL_FALLBACK = ("business_logic_abuse", GENERALIST)

TagCloud = Iterable[str] | Mapping[str, float]
PersonaCovers = Mapping[str, Sequence[str]]


def _weights(tags: TagCloud) -> dict[str, float]:
    if isinstance(tags, Mapping):
        weights = {str(tag): float(weight) for tag, weight in tags.items()}
        if any(weight < 0 for weight in weights.values()):
            raise GuidanceError("tag cloud weights must be non-negative")
        return weights
    return {str(tag): 1.0 for tag in tags}


def owner(personas: PersonaCovers, tag: str) -> str | None:
    """The single persona whose most specific cover matches ``tag``; ties break by persona id."""
    best: tuple[tuple[int, int], str] | None = None
    for persona in sorted(personas):
        for pattern in personas[persona]:
            if cover_matches(pattern, tag):
                key = cover_specificity(pattern)
                if best is None or key > best[0]:
                    best = (key, persona)
    return None if best is None else best[1]


def _rank(personas: PersonaCovers, weights: Mapping[str, float]) -> list[tuple[str, float, list[str]]]:
    scores: dict[str, float] = {}
    matched: dict[str, list[str]] = {}
    for tag in sorted(weights):
        persona = owner(personas, tag)
        if persona is None or weights[tag] <= 0:
            continue
        scores[persona] = scores.get(persona, 0.0) + weights[tag]
        matched.setdefault(persona, []).append(tag)
    return [(persona, scores[persona], matched[persona])
            for persona in sorted(scores, key=lambda item: (-scores[item], item))]


def route_persona(personas: PersonaCovers, *, lead_cwe: str | None = None,
                  location_tags: Iterable[str] = (), component_tags: TagCloud = ()) -> dict[str, Any]:
    """``persona-routing/1``: lead CWE, then location tags, then the component tag cloud, then
    ``generalist`` with a routing gap. The deciding basis and matched tags are recorded."""
    if GENERALIST not in personas:
        raise GuidanceError("persona routing requires the generalist persona")
    cwe = normalize_cwe(lead_cwe) if lead_cwe else None
    if cwe is not None:
        persona = owner(personas, cwe)
        if persona is not None:
            return {"rule": PERSONA_RULE, "persona": persona, "basis": "lead_cwe",
                    "matched_tags": [cwe], "routing_gap": False}
    location = {tag: 1.0 for tag in location_tags if split_tag(tag)[0] in LOCATION_NAMESPACES}
    ranked = _rank(personas, location)
    if ranked:
        persona, _, tags = ranked[0]
        return {"rule": PERSONA_RULE, "persona": persona, "basis": "location_tags",
                "matched_tags": tags, "routing_gap": False}
    ranked = _rank(personas, _weights(component_tags))
    if ranked:
        persona, _, tags = ranked[0]
        return {"rule": PERSONA_RULE, "persona": persona, "basis": "component_tags",
                "matched_tags": tags, "routing_gap": False}
    return {"rule": PERSONA_RULE, "persona": GENERALIST, "basis": "generalist", "matched_tags": [],
            "routing_gap": True, "gap_class": GapClass.ROUTING_GAP.value,
            "reason": "no_persona_coverage_matched"}


# ---------------------------------------------------------------------------------------------
# stack-routing/1

C_FAMILY = ("lang:c", "lang:cpp", "lang:c-cpp-header")
EMBEDDED_BUILD_FACTS = frozenset({"freestanding", "kernel", "firmware", "no-libc"})
RPC_INTERFACES = frozenset({"grpc", "protobuf", "thrift", "idl"})
SERVICE_COMPONENTS = frozenset({
    "component:administrative-tooling", "component:application-api-server",
    "component:authentication-identity", "component:cryptography-data-protection",
    "component:network", "component:platform-integration", "component:storage",
    "component:web-frontend",
})
MANAGED_STACKS = (
    ("jvm_service", ("lang:java", "lang:kotlin")),
    ("dotnet_service", ("lang:csharp",)),
    ("go_service", ("lang:go",)),
    ("rust_service", ("lang:rust",)),
    ("python_service", ("lang:python",)),
    ("node_web", ("lang:javascript", "lang:typescript")),
    ("php_web", ("lang:php",)),
)
CI_PREFIXES = ("infra:ci:",)
DEPLOYMENT_PREFIXES = ("infra:container:", "infra:kube:", "infra:iac:", "infra:cloud:")
STACK_IDS = ("cpp_rpc_service", "cpp_native_service", "c_systems_embedded",
             *(stack for stack, _ in MANAGED_STACKS), "android", "ios", "wasm", "ci_pipeline",
             "iac_kubernetes", GENERIC_STACK)


def _stack(stack: str, basis: Iterable[str]) -> dict[str, Any]:
    return {"rule": STACK_RULE, "stack": stack, "basis": sorted(set(basis)), "routing_gap": False}


def route_stack(*, languages: TagCloud = (), components: Iterable[str] = (), build_facts: Iterable[str] = (),
                interfaces: Iterable[str] = (), subject_tags: Iterable[str] = ()) -> dict[str, Any]:
    """``stack-routing/1`` from accepted ``lang``, ``component``, build, and interface facts.

    Order: mobile, wasm, C/C++ (embedded, RPC, native), managed-language services (heaviest
    language first, then table order), CI workflow subjects, deployment subjects, ``generic``.
    ``subject_tags`` carries accepted ``func:net:grpc`` and ``infra:*`` subject facts.
    """
    language_weights = _weights(languages)
    langs = {tag for tag, weight in language_weights.items() if weight > 0}
    comps, build, iface, subject = set(components), set(build_facts), set(interfaces), set(subject_tags)
    facts = comps | {f"build:{fact}" for fact in build}
    for platform in ("android", "ios"):
        basis = facts & {f"component:{platform}-mobile", f"build:{platform}"}
        if basis:
            return _stack(platform, basis)
    if "wasm" in build:
        return _stack("wasm", {"build:wasm"})
    c_family = sorted(langs & set(C_FAMILY))
    if c_family:
        embedded = sorted(build & EMBEDDED_BUILD_FACTS)
        if "lang:c" in langs and embedded:
            return _stack("c_systems_embedded", ["lang:c", *(f"build:{fact}" for fact in embedded)])
        rpc = sorted(iface & RPC_INTERFACES)
        if "func:net:grpc" in subject or rpc:
            grpc = ["func:net:grpc"] if "func:net:grpc" in subject else []
            return _stack("cpp_rpc_service", [*c_family, *grpc, *(f"interface:{item}" for item in rpc)])
        return _stack("cpp_native_service", c_family)
    service = sorted(comps & SERVICE_COMPONENTS)
    if service:
        candidates = []
        for position, (stack, stack_langs) in enumerate(MANAGED_STACKS):
            present = [tag for tag in stack_langs if tag in langs]
            if present:
                candidates.append((-sum(language_weights[tag] for tag in present), position, stack, present))
        if candidates:
            _, _, stack, present = min(candidates)
            return _stack(stack, [*present, *service])
    ci = sorted(tag for tag in subject if tag.startswith(CI_PREFIXES))
    if ci:
        return _stack("ci_pipeline", ci)
    deployment = sorted(tag for tag in subject if tag.startswith(DEPLOYMENT_PREFIXES))
    if "component:deployment-operations" in comps:
        deployment.append("component:deployment-operations")
    if deployment:
        return _stack("iac_kubernetes", deployment)
    return {"rule": STACK_RULE, "stack": GENERIC_STACK, "basis": [], "routing_gap": True,
            "gap_class": GapClass.ROUTING_GAP.value, "reason": "no_stack_profile_matched"}


# ---------------------------------------------------------------------------------------------
# hunt-panel/1

# Data sources that unlock a hunt strategy (code-graph-precomputation.md section 7.5). ``sink_up``
# needs accepted sink facts and ``entry_down`` an accepted entry-point catalog; symbol links carry no
# source or sink fact and unlock nothing.
STRATEGY_SOURCES: Mapping[str, tuple[str, ...]] = {
    HuntStrategy.VARIANT.value: ("confirmed_claims",),
    HuntStrategy.SINK_UP.value: ("source_sink_facts",),
    HuntStrategy.ENTRY_DOWN.value: ("entry_point_catalog",),
    HuntStrategy.CONTROL_GAP.value: ("owasp_workbench",),
    HuntStrategy.PERSONA_SWEEP.value: (),
}
DATA_SOURCES = frozenset(source for sources in STRATEGY_SOURCES.values() for source in sources)
# The accepted code-graph family (any coverage state but ``unavailable``) that provides each source.
GRAPH_FAMILY_SOURCES: Mapping[str, str] = {
    "sink_site": "source_sink_facts",
    "entry_point": "entry_point_catalog",
}


def unit_sources(base: Iterable[str], graph_families: Iterable[str]) -> tuple[str, ...]:
    """Run-level sources plus the sources a unit's accepted graph families provide, sorted."""
    return tuple(sorted(set(base) | {GRAPH_FAMILY_SOURCES[family] for family in graph_families
                                     if family in GRAPH_FAMILY_SOURCES}))


def rank_personas(personas: PersonaCovers, unit_tags: TagCloud, *,
                  fallback: Sequence[str] = DEFAULT_PANEL_FALLBACK) -> list[dict[str, Any]]:
    """Personas ranked by matched tag-cloud weight, then the fallback list, then the rest by id."""
    ranked = [{"persona": persona, "score": score, "matched_tags": tags, "basis": "unit_tags"}
              for persona, score, tags in _rank(personas, _weights(unit_tags))]
    seen = {item["persona"] for item in ranked}
    for persona in fallback:
        if persona in personas and persona not in seen:
            ranked.append({"persona": persona, "score": 0.0, "matched_tags": [], "basis": "panel_fallback"})
            seen.add(persona)
    for persona in sorted(set(personas) - seen - {GENERALIST}):
        ranked.append({"persona": persona, "score": 0.0, "matched_tags": [], "basis": "persona_order"})
    return ranked


def hunt_panel(personas: PersonaCovers, *, unit_tags: TagCloud, available_sources: Iterable[str],
               round_index: int = 0, size: int = 3,
               fallback: Sequence[str] = DEFAULT_PANEL_FALLBACK) -> dict[str, Any]:
    """``hunt-panel/1``: choose ``size`` distinct (strategy, persona) pairs for one hunt package.

    Strategy candidates in order: ``variant`` (round >= 1 only), ``sink_up``, ``entry_down``,
    ``control_gap``; the first ``size`` candidates become slots. A slot whose required data source
    is unavailable records a ``coverage_gap`` and falls back to ``persona_sweep``. Remaining slots
    are ``persona_sweep``. Slot ``i`` takes the ``i``-th ranked persona, so pairs are distinct.
    """
    if size < 1:
        raise GuidanceError("hunt panel size must be positive")
    if round_index < 0:
        raise GuidanceError("hunt panel round must be non-negative")
    sources = set(available_sources)
    unknown = sorted(sources - DATA_SOURCES)
    if unknown:
        raise GuidanceError(f"hunt panel data source is unknown: {', '.join(unknown)}")
    candidates = [HuntStrategy.SINK_UP.value, HuntStrategy.ENTRY_DOWN.value, HuntStrategy.CONTROL_GAP.value]
    if round_index >= 1:
        candidates.insert(0, HuntStrategy.VARIANT.value)
    slots: list[str] = []
    gaps: list[dict[str, Any]] = []
    for strategy in candidates[:size]:
        required = STRATEGY_SOURCES[strategy]
        if any(source in sources for source in required):
            slots.append(strategy)
            continue
        gaps.append({"gap_class": GapClass.COVERAGE_GAP.value, "strategy": strategy,
                     "reason": f"required_source_unavailable:{'|'.join(required)}"})
        slots.append(HuntStrategy.PERSONA_SWEEP.value)
    slots += [HuntStrategy.PERSONA_SWEEP.value] * (size - len(slots))
    ranking = rank_personas(personas, unit_tags, fallback=fallback)
    if not ranking:
        raise GuidanceError("hunt panel has no persona to assign")
    cells: list[dict[str, Any]] = []
    used: set[tuple[str, str]] = set()
    cursor = 0
    for slot, strategy in enumerate(slots):
        for offset in range(len(ranking)):
            choice = ranking[(cursor + offset) % len(ranking)]
            if (strategy, choice["persona"]) not in used:
                cursor = (cursor + offset + 1) % len(ranking)
                break
        else:
            raise GuidanceError("hunt panel cannot form distinct (strategy, persona) pairs")
        used.add((strategy, choice["persona"]))
        cells.append({"slot": slot, "strategy": strategy, "persona": choice["persona"],
                      "persona_basis": choice["basis"], "matched_tags": list(choice["matched_tags"])})
    routing_gap = any(cell["persona"] == GENERALIST for cell in cells)
    return {"rule": PANEL_RULE, "round": round_index, "cells": cells, "gaps": gaps,
            "routing_gap": routing_gap, "persona_ranking": [item["persona"] for item in ranking]}


# ---------------------------------------------------------------------------------------------
# Partition

def partition_check(personas: PersonaCovers, vocabulary: Vocabulary,
                    crosswalk: Crosswalk | None = None) -> dict[str, Any]:
    """Every ``cwe``/``func``/``infra``/``data`` tag must be claimed by exactly one persona.

    Closed namespaces contribute every term. The open ``cwe`` catalog contributes every CWE the
    crosswalk names plus every concrete CWE any persona names. A tag matched by covers of two or
    more personas is a double claim even when specificity would pick one owner at routing time.
    """
    universe: set[str] = set()
    for name in PARTITION_NAMESPACES:
        namespace = vocabulary.namespaces.get(name)
        if namespace is not None:
            universe |= set(namespace.terms)
    if crosswalk is not None:
        universe |= {tag for tag in crosswalk_tags(crosswalk) if split_tag(tag)[0] in PARTITION_NAMESPACES}
    universe |= {pattern for patterns in personas.values() for pattern in patterns
                 if not pattern.endswith("*") and pattern.split(":", 1)[0] in PARTITION_NAMESPACES}
    orphans: list[str] = []
    double: dict[str, list[str]] = {}
    for tag in sorted(universe):
        claimants = sorted(persona for persona, patterns in personas.items()
                           if any(cover_matches(pattern, tag) for pattern in patterns))
        if not claimants:
            orphans.append(tag)
        elif len(claimants) > 1:
            double[tag] = claimants
    return {"checked": len(universe), "orphans": orphans, "double_claims": double,
            "ok": not orphans and not double}
