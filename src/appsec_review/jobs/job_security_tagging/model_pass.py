"""The optional collation model pass (T-5008 stage 4): one bounded, recorded call per first-party component.

Design: ``docs/architecture/collation-pass.md`` section 6. The deterministic facets never depend on this
pass. When ``settings.collation.model_pass.enabled`` is true, the pass sends each component's
deterministic facets (as tag ids and assignment ids), its first-party file list and a bounded set of
source excerpts (labelled ``path:line``) to the configured model through ``appsec_review.inference``
(the recording layer records and replays the call like every other model call), and accepts only a
proposal that validates against the closed ``unit-purpose-proposal/1`` contract: every ``role`` and
``asset`` value in the vocabulary, every claim citing a supplied line or a deterministic assignment id,
a purpose paragraph within its bound. An accepted claim becomes a ``reported`` assignment with the
cited line (hash-verified span) or the cited assignment as evidence. A rejected or failed proposal
leaves the deterministic tags untouched and records a named gap. Nothing here is evidence of a
weakness; tags remain routing data.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict
import hashlib
from pathlib import Path
from typing import Any, Callable

from appsec_review.config.collation import CollationSettings
from appsec_review.retrieval import EntityKind
from appsec_review.storage import canonical_json

from .collation import _lines
from .producers import AcceptedIndexes, Row, Scope, _evidence
from .taxonomy import Vocabulary, assignment, merge_assignments

PROPOSAL_SCHEMA = "appsec-review/unit-purpose-proposal/1"
PURPOSES_SCHEMA = "appsec-review/unit-purposes/1"
WORKER_ID = "unit_purpose"
PRODUCER = "collation-model-pass"
PURPOSE_MAX_CHARS = 600
EXCERPT_LINE_CHARS = 200
HEAD_LINES = 20
_PROPOSAL_KEYS = frozenset({"schema", "component_id", "role", "asset", "purpose", "claims", "unknown"})
_UNKNOWN = frozenset({"role", "asset", "purpose"})


def _failures() -> tuple[type[BaseException], ...]:
    # Imported lazily: guidance.compose imports this job's crosswalk, so a module-level import would cycle.
    from appsec_review.guidance.fragments import GuidanceError
    from appsec_review.inference.errors import ExecutionContractError, ModelOutputError, ModelTimeout, ProviderError
    return (ModelOutputError, ProviderError, ModelTimeout, ExecutionContractError, TimeoutError, ValueError,
            GuidanceError, OSError)


class ProposalRejected(ValueError):
    """The model's proposal violates the closed contract; the deterministic tags stand."""


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _source_rows(indexes: AcceptedIndexes, limit: int) -> dict[str, tuple[Row, Mapping[str, Any]]]:
    rows: dict[str, tuple[Row, Mapping[str, Any]]] = {}
    for identity in indexes.shards("source"):
        found, _truncated = indexes.rows(identity, (EntityKind.SOURCE_FILE.value,), limit)
        for row in found:
            if row.location is not None:
                rows.setdefault(str(row.location["path"]), (row, identity))
    return rows


def _excerpts(paths: Iterable[str], cited: Mapping[str, set[int]], sources: Mapping[str, tuple[Row, Mapping[str, Any]]],
              indexes: AcceptedIndexes, settings: CollationSettings, gaps: list[str], component_id: str
              ) -> tuple[list[dict[str, Any]], dict[str, list[tuple[int, int, int, str]]]]:
    """Bounded ``path:line`` excerpts: the lines the deterministic facets cite, then each file's head."""
    budget = settings.model_pass.max_excerpt_lines
    excerpts: list[dict[str, Any]] = []
    lines_by_path: dict[str, list[tuple[int, int, int, str]]] = {}
    for path in sorted(paths):
        source = sources.get(path)
        if source is None:
            continue
        row, _identity = source
        try:
            data = indexes.source_bytes(row.location)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            gaps.append(f"collation:model_pass_source_unread:{component_id}:{path}: {exc}")
            continue
        if len(data) > settings.max_source_bytes_per_file:
            gaps.append(f"collation:model_pass_source_unread:{component_id}:{path}: exceeds max_source_bytes_per_file")
            continue
        lines = _lines(data)
        lines_by_path[path] = lines
        wanted = sorted({*cited.get(path, set()), *range(1, min(HEAD_LINES, len(lines)) + 1)})
        for number in wanted:
            if len(excerpts) >= budget:
                gaps.append(f"collation:model_pass_excerpt_bound:{component_id}: max_excerpt_lines {budget} reached")
                return excerpts, lines_by_path
            if 1 <= number <= len(lines):
                excerpts.append({"path": path, "line": number, "text": lines[number - 1][3][:EXCERPT_LINE_CHARS]})
    return excerpts, lines_by_path


def _validate(proposal: Any, *, component_id: str, vocabulary: Vocabulary, excerpt_keys: set[tuple[str, int]],
              assignment_ids: set[str]) -> dict[str, Any]:
    if not isinstance(proposal, Mapping) or set(proposal) != _PROPOSAL_KEYS:
        raise ProposalRejected("proposal keys are not the closed unit-purpose-proposal/1 set")
    if proposal["schema"] != PROPOSAL_SCHEMA or proposal["component_id"] != component_id:
        raise ProposalRejected("proposal schema or component identity does not match the request")
    values: dict[str, list[str]] = {}
    for facet, bound in (("role", 11), ("asset", 5)):
        items = proposal[facet]
        if not isinstance(items, list) or len(items) > bound or any(not isinstance(item, str) for item in items):
            raise ProposalRejected(f"{facet} must be a bounded list of vocabulary values")
        terms = vocabulary.namespaces[facet].terms
        unknown = sorted(set(items) - terms)
        if unknown:
            raise ProposalRejected(f"{facet} values outside the vocabulary: {unknown}")
        values[facet] = sorted(set(items))
    purpose = proposal["purpose"]
    if not isinstance(purpose, str) or len(purpose) > PURPOSE_MAX_CHARS or purpose != purpose.strip():
        raise ProposalRejected(f"purpose must be a trimmed string of at most {PURPOSE_MAX_CHARS} characters")
    unknown_facets = proposal["unknown"]
    if not isinstance(unknown_facets, list) or not set(unknown_facets) <= _UNKNOWN:
        raise ProposalRejected("unknown must name only role, asset or purpose")
    claims = proposal["claims"]
    if not isinstance(claims, list) or len(claims) > 32:
        raise ProposalRejected("claims must be a bounded list")
    claimed: dict[str, list[dict[str, Any]]] = {}
    for claim in claims:
        if not isinstance(claim, Mapping) or set(claim) != {"tag", "citations"}:
            raise ProposalRejected("claim keys are not {tag, citations}")
        tag = claim["tag"]
        if tag not in {*values["role"], *values["asset"]}:
            raise ProposalRejected(f"claim names a tag the proposal does not assert: {tag!r}")
        citations = claim["citations"]
        if not isinstance(citations, list) or not citations or len(citations) > 8:
            raise ProposalRejected(f"claim has no bounded citation list: {tag}")
        checked = []
        for citation in citations:
            if not isinstance(citation, Mapping):
                raise ProposalRejected("citation is not an object")
            if set(citation) == {"path", "line"}:
                if (citation["path"], citation["line"]) not in excerpt_keys:
                    raise ProposalRejected(f"citation names a line that was not supplied: {citation}")
            elif set(citation) == {"assignment_id"}:
                if citation["assignment_id"] not in assignment_ids:
                    raise ProposalRejected("citation names an assignment the request did not carry")
            else:
                raise ProposalRejected("citation is neither a supplied line nor a deterministic assignment")
            checked.append(dict(citation))
        claimed.setdefault(tag, []).extend(checked)
    uncited = sorted(tag for tag in {*values["role"], *values["asset"]} if tag not in claimed)
    if uncited:
        raise ProposalRejected(f"asserted values without a claim: {uncited}")
    return {"role": values["role"], "asset": values["asset"], "purpose": purpose, "claims": claimed,
            "unknown": sorted(set(unknown_facets))}


def run_model_pass(*, repository_root: Path, run_root: Path, indexes: AcceptedIndexes, scope: Scope,
                   vocabulary: Vocabulary, rules_sha256: str, settings: CollationSettings,
                   collation: Mapping[str, Any], facet_records: Iterable[Mapping[str, Any]],
                   infer: Callable[..., Any] | None, limit: int, unit_id: str
                   ) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    """``(records, gaps, document)`` of the model pass over the collated components."""
    model_pass = settings.model_pass
    document: dict[str, Any] = {"schema": PURPOSES_SCHEMA, "target_snapshot": scope.target_snapshot,
                                "mode": "enabled" if model_pass.enabled else "disabled",
                                "worker": WORKER_ID, "components": []}
    if not model_pass.enabled:
        return [], [], document
    gaps: list[str] = []
    if infer is None:
        gaps.append("collation:model_pass_unavailable: no inference transport is wired; the deterministic facets stand")
        return [], gaps, document
    from appsec_review.guidance.compose import pin_bundle, render_prompt
    from appsec_review.guidance.fragments import GuidanceError
    from appsec_review.guidance.workers import worker_bundle
    from appsec_review.inference import ModelRequest
    failures = _failures()
    model = dict(model_pass.model or {})
    document["model"] = {key: model.get(key) for key in ("provider", "model", "reasoning")}
    try:
        bundle = worker_bundle(repository_root, WORKER_ID, model=model)
    except GuidanceError as exc:
        gaps.append(f"collation:model_pass_unavailable: guidance assembly failed: {exc}")
        return [], gaps, document
    guidance_sha256 = pin_bundle(run_root, bundle)["bundle_sha256"]
    prompt = render_prompt(bundle)
    document["guidance_bundle_sha256"] = guidance_sha256
    facet_records = list(facet_records)
    sources = _source_rows(indexes, limit)
    records: list[dict[str, Any]] = []
    components = sorted(collation.get("components", ()), key=lambda item: str(item["component_id"]))
    skipped = components[model_pass.max_components:]
    for item in skipped:
        gaps.append(f"collation:model_pass_bound:{item['component_id']}: max_components {model_pass.max_components} reached")
    for item in components[:model_pass.max_components]:
        cid = str(item["component_id"])
        subject = scope.component_subject(cid)
        paths = [file["path"] for file in collation.get("files", ()) if cid in file.get("component_ids", ())]
        if subject is None or not paths:
            document["components"].append({"component_id": cid, "status": "skipped",
                                           "reason": "no first-party file"})
            continue
        own = [record for record in facet_records
               if (record["subject"].get("component_id") == cid or record["subject"].get("path") in paths)]
        assignment_ids = {record["assignment_id"] for record in own}
        cited: dict[str, set[int]] = {}
        for record in own:
            for evidence in record.get("evidence", ()):
                span = evidence.get("span") if isinstance(evidence, Mapping) else None
                if isinstance(span, Mapping) and isinstance(evidence.get("path"), str):
                    cited.setdefault(evidence["path"], set()).add(int(span["start_line"]))
        excerpts, lines_by_path = _excerpts(paths, cited, sources, indexes, settings, gaps, cid)
        summary = {
            "component_id": cid, "files": sorted(paths),
            "deterministic_facets": sorted({(record["tag"], record["assignment_id"]) for record in own}),
            "allowed_values": {"role": sorted(vocabulary.namespaces["role"].terms),
                               "asset": sorted(vocabulary.namespaces["asset"].terms)},
            "excerpts": excerpts, "purpose_max_chars": PURPOSE_MAX_CHARS,
            "cited_line": "every claim cites a supplied path:line or a deterministic assignment_id",
            "guidance_bundle_sha256": guidance_sha256,
        }
        summary["deterministic_facets"] = [{"tag": tag, "assignment_id": aid} for tag, aid in summary["deterministic_facets"]]
        request = ModelRequest(
            schema=PROPOSAL_SCHEMA, persona="", role=bundle["role_id"], guidance=prompt, summary=summary,
            allowed_scanners=(), allowed_build_systems=(), allowed_components=(cid,),
            allowed_paths=tuple(sorted(paths)), allowed_build_units=(), provider=model["provider"],
            model=model["model"], reasoning=model["reasoning"], max_input_tokens=model["max_input_tokens"],
            max_output_tokens=model["max_output_tokens"])
        request_id = _digest({"request": asdict(request), "unit": unit_id})
        entry: dict[str, Any] = {"component_id": cid, "request_id": request_id, "excerpt_lines": len(excerpts),
                                 "guidance_bundle_sha256": guidance_sha256}
        try:
            result = infer(request, timeout_seconds=int(model["timeout_seconds"]))
            accepted = _validate(result.proposal, component_id=cid, vocabulary=vocabulary,
                                 excerpt_keys={(row["path"], row["line"]) for row in excerpts},
                                 assignment_ids=assignment_ids)
        except ProposalRejected as exc:
            gaps.append(f"collation:model_pass_rejected:{cid}: {exc}")
            entry.update(status="rejected", reason=str(exc))
            document["components"].append(entry)
            continue
        except failures as exc:
            gaps.append(f"collation:model_pass_failed:{cid}: {type(exc).__name__}")
            entry.update(status="failed", reason=type(exc).__name__)
            document["components"].append(entry)
            continue
        entry.update(status="accepted", proposal_sha256=_digest(result.proposal), purpose=accepted["purpose"],
                     role=accepted["role"], asset=accepted["asset"], unknown=accepted["unknown"],
                     served_model=result.served_model, served_provider=result.served_provider)
        document["components"].append(entry)
        producer = {"name": PRODUCER, "rule_id": PROPOSAL_SCHEMA, "version": rules_sha256,
                    "guidance_bundle_sha256": guidance_sha256, "request_id": request_id}
        for tag, citations in sorted(accepted["claims"].items()):
            evidence = []
            for citation in citations:
                if "assignment_id" in citation:
                    evidence.append({"ref": citation["assignment_id"], "cited_assignment": True})
                    continue
                row, identity = sources[citation["path"]]
                number = int(citation["line"])
                _n, start, end, text = lines_by_path[citation["path"]][number - 1]
                location = {**row.location, "start_byte": start, "end_byte": end, "start_line": number,
                            "end_line": number, "start_column": 1, "end_column": len(text) + 1,
                            "mapping_method": "collation-model-pass", "confidence": 1.0}
                evidence.append({**_evidence(row, identity), "span": {"start_line": number, "end_line": number},
                                 "location": location, "cited_line": True})
            records.append(assignment(vocabulary=vocabulary, tag=tag, basis="reported", subject=subject,
                                      producer=producer, evidence=evidence, confidence="medium"))
    return merge_assignments(records), sorted(set(gaps)), document


__all__ = ["PROPOSAL_SCHEMA", "PURPOSES_SCHEMA", "PURPOSE_MAX_CHARS", "WORKER_ID", "ProposalRejected", "run_model_pass"]
