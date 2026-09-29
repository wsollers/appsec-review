#!/usr/bin/env python3
"""ADR-0013 derive step for the OWASP validator cell (B3).

The model supplies judgement only.  For every evidence / counterevidence citation it replies with a
REDUCED citation (``ref``, ``locator``, ``observed_fact``, ``evidence_mode``, ``limitations``,
``affirmative_contrary_evidence``, optionally a narrowing ``source_kind``, ``test_context`` and
``dereference_ref``).  This module derives everything mechanical from the dispatched input set (the
handoff's ``accepted_inputs`` and the pinned bytes the cell was given):

  citation_id, input_id, source_kind, artifact_path, artifact_sha256 (hashed from the pinned bytes),
  accepted_pointer, freshness, covered_scope, canonical_dereference_id, test_context (only for test
  evidence), derived_output_id, and the candidate's ``result_id``.

A model-supplied value for any derived field is ignored.  A reference that does not resolve to an
input the cell was given is REJECTED: the citation is removed and a fixed-text gap is recorded on its
proof obligation (never silently dropped, never target- or model-controlled text).  Nothing here
weakens ``owasp_validator_result``: the derived record is the unchanged full candidate, and T07
still admits or rejects it independently.
"""
from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Callable, Mapping

from execution_state import digest
from schema_validate import SchemaStore, validate_document

PERSONA_SCHEMA = "owasp-validator-reply.schema.json"
FINAL_SCHEMA = "owasp-control-assessment-result.schema.json"
GROUPS = (("evidence_citations", "evidence"), ("counterevidence_citations", "counter"))
NARROWING_KINDS = ("document", "scanner", "test_evidence")
REJECTIONS = ("UNRESOLVED_REF", "AMBIGUOUS_REF", "PINNED_BYTES_UNAVAILABLE", "PINNED_HASH_MISMATCH",
              "BAD_SHAPE")


def citation_id(fragment_id: str, obligation_id: str, group: str, position: int) -> str:
    """Deterministic and documented to the model so cross-references (contradictions, dissent,
    reported claims, routes) can name a citation that has not been derived yet."""
    return f"citation-{fragment_id}-{obligation_id}-{group}{position}"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Inputs:
    def __init__(self, handoff: Mapping[str, Any], read_pinned: Callable[[str], bytes | None]) -> None:
        self.by_id = {item["input_id"]: item for item in handoff.get("accepted_inputs", [])}
        self.by_path: dict[str, list[dict[str, Any]]] = {}
        for item in self.by_id.values():
            self.by_path.setdefault(item["artifact"]["path"], []).append(item)
        self.read_pinned = read_pinned

    def resolve(self, ref: Any) -> tuple[dict[str, Any] | None, str | None]:
        if not isinstance(ref, str) or not ref:
            return None, "BAD_SHAPE"
        if ref in self.by_id:
            return self.by_id[ref], None
        matches = self.by_path.get(ref, [])
        if len(matches) == 1:
            return matches[0], None
        return None, "AMBIGUOUS_REF" if matches else "UNRESOLVED_REF"


def _entry_citation(entry: Mapping[str, Any], reduced: Mapping[str, Any], inputs: _Inputs,
                    component_id: str) -> tuple[dict[str, Any] | None, str | None]:
    data = inputs.read_pinned(entry["artifact"]["path"])
    if data is None:
        return None, "PINNED_BYTES_UNAVAILABLE"
    if _sha(data) != entry["artifact"]["sha256"]:
        return None, "PINNED_HASH_MISMATCH"
    producer = entry.get("producer")
    kind = "locator" if entry.get("use") == "locator_only" else "canonical_evidence"
    asked = reduced.get("source_kind")
    if kind != "locator" and asked in NARROWING_KINDS:
        kind = asked        # may only narrow what canonical evidence can prove, never widen it
    return {
        "input_id": entry["input_id"], "source_kind": kind,
        "artifact_path": entry["artifact"]["path"], "artifact_sha256": _sha(data),
        "accepted_pointer": None if producer is None else {
            "path": producer["accepted_pointer_path"], "sha256": producer["accepted_pointer_sha256"],
            "job_id": producer["job_id"], "attempt_id": producer["attempt_id"]},
        "freshness": copy.deepcopy(entry["freshness"]), "derived_output_id": None,
        "covered_scope": [component_id],
    }, None


def _derived_citation(output: Mapping[str, Any], inputs: _Inputs, component_id: str
                      ) -> tuple[dict[str, Any] | None, str | None]:
    lineage = output.get("source_lineage") or []
    entries = [inputs.by_id.get(item.get("input_id")) for item in lineage if isinstance(item, dict)]
    if not entries or any(entry is None for entry in entries):
        return None, "UNRESOLVED_REF"
    stale = next((entry for entry in entries if entry["freshness"]["status"] == "stale_accepted"), None)
    artifact = output.get("artifact") or {}
    return {
        "input_id": entries[0]["input_id"], "source_kind": "derived_output",
        "artifact_path": artifact.get("path"), "artifact_sha256": artifact.get("sha256"),
        "accepted_pointer": None, "freshness": copy.deepcopy((stale or entries[0])["freshness"]),
        "derived_output_id": output.get("output_id"), "covered_scope": [component_id],
    }, None


def derive_citation(reduced: Any, *, inputs: _Inputs, derived_outputs: Mapping[str, Any],
                    component_id: str, cid: str) -> tuple[dict[str, Any] | None, str | None, str | None]:
    """(full citation | None, rejection | None, dereference input ref | None)."""
    if not isinstance(reduced, dict) or not all(
            isinstance(reduced.get(key), str) for key in ("locator", "observed_fact", "evidence_mode")):
        return None, "BAD_SHAPE", None
    ref = reduced.get("ref")
    entry, rejection = inputs.resolve(ref)
    output = derived_outputs.get(ref) if isinstance(ref, str) else None
    if entry is not None and output is not None:
        entry, rejection = None, "AMBIGUOUS_REF"
    if entry is not None:
        base, rejection = _entry_citation(entry, reduced, inputs, component_id)
    elif output is not None:
        base, rejection = _derived_citation(output, inputs, component_id)
    else:
        base = None
    if base is None:
        return None, rejection or "UNRESOLVED_REF", None
    limitations = reduced.get("limitations")
    test_context = reduced.get("test_context") if base["source_kind"] == "test_evidence" else None
    citation = {"citation_id": cid, **base, "locator": reduced["locator"],
                "observed_fact": reduced["observed_fact"], "evidence_mode": reduced["evidence_mode"],
                "limitations": [item for item in limitations if isinstance(item, str)]
                if isinstance(limitations, list) else [],
                "canonical_dereference_id": None, "test_context": copy.deepcopy(test_context),
                "affirmative_contrary_evidence": reduced.get("affirmative_contrary_evidence") is True}
    deref = reduced.get("dereference_ref") if base["source_kind"] == "locator" else None
    return citation, None, deref if isinstance(deref, str) else None


def derive_candidate(reply: Any, *, handoff: Mapping[str, Any],
                     read_pinned: Callable[[str], bytes | None]) -> tuple[dict[str, Any], list[str]]:
    """The full T07 candidate from the model's reply, plus fixed-text derive notes."""
    if not isinstance(reply, dict):
        raise ValueError("the validator reply is not a JSON object")
    candidate = copy.deepcopy(reply)
    inputs = _Inputs(handoff, read_pinned)
    derived_outputs = {item["output_id"]: item for item in candidate.get("derived_outputs", [])
                       if isinstance(item, dict) and isinstance(item.get("output_id"), str)}
    notes: list[str] = []
    for fragment in candidate.get("fragment_results", []):
        if not isinstance(fragment, dict):
            continue
        for obligation in fragment.get("proof_obligation_results", []):
            if not isinstance(obligation, dict):
                continue
            derived_here: list[tuple[dict[str, Any], str | None]] = []
            for field, group in GROUPS:
                kept, gaps = [], []
                for position, reduced in enumerate(obligation.get(field) or [], start=1):
                    if isinstance(reduced, dict) and "ref" not in reduced and "citation_id" in reduced:
                        kept.append(reduced)            # already a full citation: T07 admits it as before
                        continue
                    cid = citation_id(str(fragment.get("fragment_id")), str(obligation.get("obligation_id")),
                                      group, position)
                    citation, rejection, deref = derive_citation(
                        reduced, inputs=inputs, derived_outputs=derived_outputs,
                        component_id=str(fragment.get("component_id")), cid=cid)
                    if citation is None:
                        gaps.append(f"reduced-citation-rejected:{group}{position}:{rejection}")
                        notes.append(f"{fragment.get('fragment_id')}/{obligation.get('obligation_id')}: "
                                     f"citation {group}{position} rejected ({rejection})")
                        continue
                    kept.append(citation)
                    derived_here.append((citation, deref))
                obligation[field] = kept
                obligation.setdefault("evidence_gaps", [])
                if isinstance(obligation["evidence_gaps"], list):
                    obligation["evidence_gaps"].extend(gaps)
            for citation, deref in derived_here:
                if deref is None:
                    continue
                target, _ = inputs.resolve(deref)
                match = next((other for other, _d in derived_here
                              if target is not None and other is not citation and
                              other["input_id"] == target["input_id"] and other["source_kind"] != "locator"), None)
                if match is not None:
                    citation["canonical_dereference_id"] = match["citation_id"]
    candidate["result_id"] = "assessment-" + digest(
        {key: value for key, value in candidate.items() if key != "result_id"})[:20]
    return candidate, notes


def handoff_of(package: Any) -> Mapping[str, Any]:
    item = next(item for item in package.inputs if item.role == "handoff")
    return json.loads(item.data.decode("utf-8"))


def make_fill(package: Any) -> Callable[[dict[str, Any], str], list[str]]:
    """The ``ClaudeCliInvoker`` ``fill_result`` hook: derive from the bytes the cell was pinned to."""
    handoff = handoff_of(package)
    pinned = {item.path: item.data for item in package.inputs}

    def fill(envelope: dict[str, Any], result_field: str) -> list[str]:
        value, notes = derive_candidate(envelope.get(result_field), handoff=handoff,
                                        read_pinned=pinned.get)
        envelope[result_field] = value
        return notes

    return fill


def validate_reply(reply: Any, store: SchemaStore | None = None) -> list[str]:
    return validate_document(reply, PERSONA_SCHEMA, store or SchemaStore())
