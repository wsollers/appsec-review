"""Deterministic threat enumeration of the generated threat model (T-107, step ``threats.enumerate``).

Applies the threat template catalog to every flow that crosses a trust boundary. Design:
docs/architecture/dfd-and-threat-model-generation.md sections 5.2 and 6.3. A threat here is a
*candidate*: a question the evidence raises, never a finding. It cites the evidence of the flow that
raised it.

Mitigation: the first slice has no mitigation evidence input (no graph guard or sanitizer facts, no
OWASP control results, no configuration observations are read yet), so every candidate carries
``MitigationState.NOT_EXAMINED``. Nothing here ever states that a control is absent, and the
contract has no state that could say so. ``related_controls`` is empty for the same reason.

The crosswalk's attacker positions are copied onto the threat inside ``crosswalk`` as the catalog's
candidates for that template; no threat or flow asserts a position.
"""
from __future__ import annotations

from typing import Any, Mapping

from appsec_review.threat_model.assemble import Assembly
from appsec_review.threat_model.contract import Limits, Mitigation, MitigationState, Threat, ThreatState, element_id
from appsec_review.threat_model.reference import Reference
from appsec_review.threat_model.view import truncated_gap

THREAT_BOUND = "threats.max_threats"


def enumerate_threats(assembly: Assembly, reference: Reference, limits: Limits, *,
                      unit_id: str = "threats.enumerate") -> tuple[tuple[Threat, ...], tuple[Mapping[str, Any], ...]]:
    """One candidate threat per template and crossing flow, sorted by id, with the gaps of this step."""
    kinds = {boundary.id: boundary.kind for boundary in assembly.boundaries}
    threats: dict[str, Threat] = {}
    for flow in assembly.flows:
        direction = flow.attributes.get("direction")
        for boundary in flow.crosses:
            if boundary not in kinds:
                continue
            for template in reference.templates_for(flow.interaction, kinds[boundary], direction):
                identity = element_id("threat", {"template": template.template_id, "flow": flow.id})
                crosswalk = {key: list(values) for key, values in reference.crosswalk_for(template.template_id).items()}
                threats[identity] = Threat(
                    identity, ThreatState.CANDIDATE, template.stride, template.template_id, template.title,
                    template.question, tuple(sorted({flow.source, flow.target})), (flow.id,), flow.crosses,
                    flow.evidence, template.obligations, Mitigation(MitigationState.NOT_EXAMINED), (), crosswalk)
    ordered = tuple(threats[identity] for identity in sorted(threats))
    if len(ordered) <= limits.max_threats:
        return ordered, ()
    return ordered[:limits.max_threats], (truncated_gap(THREAT_BOUND, limits.max_threats, unit_id=unit_id),)
