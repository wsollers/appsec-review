"""Batch-level request assembly for the OWASP inference seam.

Run 2026-11-17-0003 (D-owasp_control_assessment-1) dispatched no control: every batch request
inlined the component context, the evidence excerpts and the proof procedure once per row, so each
package set was 6 to 33 times ``max_input_tokens`` and ``investigate`` stopped before the first call.

This module builds what the worker reads from a batch's finding packages: every evidence record,
component context block and proof procedure appears once per request and rows reference them by
identity. When the request still exceeds the budget it splits the batch down to one row, and a single
row that does not fit is trimmed tier by tier with a named gap that states the estimate and the limit.
Nothing here widens the worker's evidence or tools: trimmed material stays reachable only through the
same bounded expansion by identity the worker already had.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Any, Callable, Mapping, Sequence

from appsec_review.storage import canonical_json

REQUEST_RULE = "appsec-review/owasp-request-assembly/1"
# Package fields that hold batch-shared material and leave the row view.
_HOISTED = frozenset({"routing_context", "graph_context", "limitations", "retrieval_manifest", "guidance",
                      "evidence_references", "proof_obligations", "component"})
_ROW_COMPONENT_KEYS = ("target_id", "project_id", "component_id")
_SHARED_COMPONENT_KEYS = ("roles", "evidence")
# Obligation fields that repeat the control's proof procedure verbatim on every obligation of a row.
_PROCEDURE_KEYS = ("rule_version", "control_identity", "component_id", "procedure", "invariant", "prerequisites",
                   "subject_scope", "criteria", "evidence_mode", "required_categories", "static_limits",
                   "insufficient")
TRIM_TIERS = ("graph_context", "routing_context", "limitations", "uncited_evidence", "excerpts")
READING_RULE = ("Each row cites its evidence by evidence_ids into `evidence`; its component context is under "
                "`components`; the fields of a row's `procedure` apply to every one of its proof_obligations. "
                "`trimmed` names material omitted for the input budget; it stays reachable only through the "
                "retrieve action by identity.")


def estimate_tokens(value: Any) -> int:
    """The workbench token estimate: canonical JSON bytes at 4 bytes per token, rounded up."""
    return (len(canonical_json(value)) + 3) // 4


def _common(values: Sequence[Sequence[str]]) -> list[str]:
    if not values:
        return []
    shared = set(values[0])
    for item in values[1:]:
        shared &= set(item)
    return sorted(shared)


def assemble(packages: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The worker's view of a batch: shared evidence, component context and procedures referenced by id."""
    evidence: dict[str, Any] = {}
    components: dict[str, dict[str, Any]] = {}
    manifests: list[Any] = []
    rows: list[dict[str, Any]] = []
    component_limitations = _common([tuple(str(item) for item in package.get("limitations", ()))
                                     for package in packages])
    for package in packages:
        component = package["component"]
        cid = str(component["component_id"])
        if cid not in components:
            components[cid] = {
                **{key: component[key] for key in _SHARED_COMPONENT_KEYS if key in component},
                "routing_context": list(package.get("routing_context", ())),
                "graph_context": list(package.get("graph_context", ())),
                "limitations": component_limitations,
            }
        manifest = package.get("retrieval_manifest")
        if manifest is not None and manifest not in manifests:
            manifests.append(manifest)
        evidence_ids: list[str] = []
        for record in package.get("evidence_references", ()):
            identity = record.get("evidence_id")
            if not isinstance(identity, str) or not identity:
                # Accepted records carry evidence_id; a record without one is keyed by its own content.
                identity = "content:" + hashlib.sha256(canonical_json(record)).hexdigest()
            evidence.setdefault(identity, record)
            if identity not in evidence_ids:
                evidence_ids.append(identity)
        obligations = list(package.get("proof_obligations", ()))
        procedure: dict[str, Any] = {}
        for key in _PROCEDURE_KEYS:
            encoded = {canonical_json(item[key]) for item in obligations if key in item}
            if obligations and len(encoded) == 1 and all(key in item for item in obligations):
                procedure[key] = obligations[0][key]
        rows.append({
            **{key: value for key, value in package.items() if key not in _HOISTED},
            "component": {key: component[key] for key in _ROW_COMPONENT_KEYS if key in component},
            "evidence_ids": evidence_ids,
            "procedure": procedure,
            "proof_obligations": [{key: value for key, value in item.items() if key not in procedure}
                                  for item in obligations],
            "limitations": [item for item in package.get("limitations", ())
                            if str(item) not in component_limitations],
        })
    view: dict[str, Any] = {
        "rule": REQUEST_RULE, "reading_rule": READING_RULE,
        "evidence": evidence, "components": components, "packages": rows,
    }
    if manifests:
        view["retrieval_manifest"] = manifests[0] if len(manifests) == 1 else manifests
    return view


def _cited(view: Mapping[str, Any]) -> set[str]:
    return {identity for row in view["packages"] for item in row["proof_obligations"]
            for identity in item.get("evidence_ids", ()) if item.get("supported")}


def _apply(view: dict[str, Any], tier: str) -> dict[str, Any] | None:
    """Apply one trim tier in place; the note of what was omitted, or None when the tier had nothing."""
    if tier == "graph_context":
        count = sum(len(item["graph_context"]) for item in view["components"].values())
        if not count:
            return None
        for item in view["components"].values():
            item["graph_context"] = []
        return {"graph_context_records_omitted": count}
    if tier == "routing_context":
        omitted = 0
        for item in view["components"].values():
            kept = [record for record in item["routing_context"]
                    if isinstance(record, Mapping) and record.get("classifies_component")]
            omitted += len(item["routing_context"]) - len(kept)
            item["routing_context"] = kept
        if not omitted:
            return None
        return {"routing_context_records_omitted": omitted, "kept": "component-classifying records"}
    if tier == "limitations":
        count = sum(len(item["limitations"]) for item in view["components"].values())
        if not count:
            return None
        for item in view["components"].values():
            item["limitations"] = []
        return {"component_limitations_omitted": count}
    if tier == "uncited_evidence":
        cited = _cited(view)
        omitted = sorted(identity for identity in view["evidence"] if identity not in cited)
        if not omitted:
            return None
        for identity in omitted:
            del view["evidence"][identity]
        for row in view["packages"]:
            row["evidence_ids"] = [identity for identity in row["evidence_ids"] if identity in cited]
        return {"uncited_evidence_records_omitted": len(omitted)}
    if tier == "excerpts":
        count = 0
        for identity, record in list(view["evidence"].items()):
            if "excerpt" in record:
                view["evidence"][identity] = {**{key: value for key, value in record.items() if key != "excerpt"},
                                              "excerpt_omitted": True}
                count += 1
        if not count:
            return None
        return {"evidence_excerpts_omitted": count, "kept": "typed references and source subjects"}
    raise ValueError(f"unknown trim tier: {tier}")


def trim(view: Mapping[str, Any], *, estimate: Callable[[Mapping[str, Any]], int], budget: int,
         before: int) -> tuple[dict[str, Any], list[str], int]:
    """Trim a one-row view tier by tier until the request fits; the view, the tiers applied, the estimate."""
    trimmed = {**view, "evidence": dict(view["evidence"]),
               "components": {key: dict(value) for key, value in view["components"].items()},
               "packages": [dict(row) for row in view["packages"]]}
    applied: list[str] = []
    notes: dict[str, Any] = {}
    size = before
    for tier in TRIM_TIERS:
        note = _apply(trimmed, tier)
        if note is None:
            continue
        applied.append(tier)
        notes[tier] = note
        trimmed["trimmed"] = {"rule": REQUEST_RULE, "reason": "input_budget", "estimate_before": before,
                              "max_input_tokens": budget, "tiers": list(applied), "omitted": notes}
        size = estimate(trimmed)
        if size <= budget:
            break
    return trimmed, applied, size


@dataclass(frozen=True, slots=True)
class Part:
    """One request-sized slice of a batch: its packages, the view the worker reads and the estimate."""

    packages: tuple[Mapping[str, Any], ...]
    view: Mapping[str, Any]
    estimate: int
    dispatch: bool
    gaps: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def row_ids(self) -> tuple[str, ...]:
        return tuple(str(package.get("row_id", f"row-{index}")) for index, package in enumerate(self.packages))


def plan_parts(packages: Sequence[Mapping[str, Any]], *, estimate: Callable[[Mapping[str, Any]], int],
               budget: int) -> list[Part]:
    """Split a batch until each part's request fits ``budget``; trim a lone row that does not.

    ``estimate`` measures the full request built around a view (guidance, contract, transcript and
    limits included), so the plan uses the same number the dispatch check uses.
    """
    if type(budget) is not int or budget < 1:
        raise ValueError("input token budget must be a positive integer")
    view = assemble(packages)
    size = estimate(view)
    if size <= budget or not packages:
        return [Part(tuple(packages), view, size, True)]
    if len(packages) > 1:
        middle = len(packages) // 2
        return [*plan_parts(packages[:middle], estimate=estimate, budget=budget),
                *plan_parts(packages[middle:], estimate=estimate, budget=budget)]
    row_id = str(packages[0].get("row_id", "row-0"))
    trimmed, tiers, after = trim(view, estimate=estimate, budget=budget, before=size)
    names = ", ".join(tiers) if tiers else "nothing trimmable"
    if after <= budget:
        gap = (f"input_budget: request estimate {size} tokens exceeded max_input_tokens {budget}; trimmed "
               f"{names} to {after} tokens; omitted material stays reachable only through bounded "
               "expansion by identity")
        return [Part((packages[0],), trimmed, after, True, {row_id: (gap,)})]
    gap = (f"input_budget: request estimate {after} tokens exceeds max_input_tokens {budget} after trimming "
           f"{names} (untrimmed estimate {size}); row not dispatched")
    return [Part((packages[0],), trimmed, after, False, {row_id: (gap,)})]


__all__ = ["Part", "READING_RULE", "REQUEST_RULE", "TRIM_TIERS", "assemble", "estimate_tokens", "plan_parts",
           "trim"]
