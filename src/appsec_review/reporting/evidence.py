"""Boxes for the evidence a review package passes in: lead, location, neighbourhood, build, tags."""
from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence

from .digest import (abbrev, bullets, code, counts_text, field, id_list, scalar, table, val)
from .model import Box, Field, Fields, Item, Para
from .text import bound, clean, sha256_value
from .tokens import BoxKind, Limits


def _dicts(value: Any) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, (list, tuple)) else []


def _strs(value: Any) -> list[str]:
    return [clean(item) for item in value if isinstance(item, str)] if isinstance(value, (list, tuple)) else []


def location_text(location: Any) -> str:
    if not isinstance(location, Mapping):
        return "unresolved"
    path = clean(location.get("source_path") or location.get("path") or "")
    start, end = location.get("start_line"), location.get("end_line")
    if not path:
        return "unresolved"
    if start is None:
        return path
    return f"{path}:{start}" + (f"-{end}" if end not in (None, start) else "")


def _location_field(lead: Mapping[str, Any]) -> str:
    text = location_text(lead.get("location"))
    if text == "unresolved":
        return "unresolved: no source line is cited"
    return text + ("" if lead.get("location_exact", True) else " (not exact)")


def package_title(package: Mapping[str, Any]) -> str:
    leads = _dicts(package.get("lead_menu"))
    if len(leads) == 1:
        lead = leads[0]
        rule = clean(lead.get("rule_id"))
        if rule in ("", "unknown"):
            rule = f"{clean(lead.get('lead_family') or 'unclassified')} lead"
        where = location_text(lead.get("location"))
        return bound(rule if where == "unresolved" else f"{rule} at {where}", 110)[0]
    kind = clean(package.get("kind") or "package")
    return f"{kind} package with {len(leads)} leads"


def lead_boxes(package: Mapping[str, Any], limits: Limits) -> list[Box]:
    leads = _dicts(package.get("lead_menu"))
    if not leads:
        return [Box(BoxKind.GAP, "No lead in this package", items=(Para("The package carries no lead menu."),))]
    boxes: list[Box] = []
    if len(leads) == 1:
        lead = leads[0]
        rows = [field("scanner", lead.get("scanner"), limits, mono=True),
                field("rule", lead.get("rule_id"), limits, mono=True),
                field("family", lead.get("lead_family") or lead.get("category"), limits),
                field("severity", f"{scalar(lead.get('reported_severity'))} (native {scalar(lead.get('native_severity'))})", limits),
                field("location", _location_field(lead), limits, mono=True),
                field("observation", lead.get("observation_id"), limits, mono=True),
                field("component", lead.get("component_id"), limits, mono=True)]
        if lead.get("rule_cwe") or lead.get("weaknesses"):
            rows.append(field("weaknesses", lead.get("rule_cwe") or lead.get("weaknesses"), limits))
        if lead.get("duplicate_of"):
            rows.append(field("duplicate of", lead.get("duplicate_of"), limits, mono=True))
        items: list[Item] = [Fields(tuple(rows))]
        message = lead.get("message") or lead.get("advisory_summary")
        if message:
            text, cut = bound(message, limits.text_chars)
            items.append(Para(text, cut))
        excerpt = _excerpt(lead) or _excerpt(package)
        if excerpt:
            items.append(code(excerpt, limits, caption=location_text(lead.get("location"))))
        else:
            items.append(Para("No source excerpt is carried in this package; the model reads source by identity with read_excerpt.", muted=True))
        boxes.append(Box(BoxKind.EVIDENCE, "Lead and location", meta="finding lead", items=tuple(items)))
    else:
        rows = [(abbrev(lead.get("observation_id")), lead.get("lead_family") or lead.get("category"),
                 lead.get("rule_id"), lead.get("reported_severity"), location_text(lead.get("location")))
                for lead in leads]
        items = [Para(f"{len(leads)} leads are offered to the model together (hunt package).", muted=True),
                 table(("observation", "family", "rule", "severity", "location"), rows, limits,
                       widths=(0.24, 0.16, 0.26, 0.10, 0.20), mono=(True, False, True, False, True))]
        excerpt = _excerpt(package)
        if excerpt:
            items.append(code(excerpt, limits, caption="source excerpt"))
        boxes.append(Box(BoxKind.EVIDENCE, "Leads offered", meta=f"{len(leads)} leads", items=tuple(items)))
    return boxes


def _excerpt(source: Mapping[str, Any]) -> str:
    for key in ("source_excerpt", "excerpt", "source_text"):
        value = source.get(key)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, Mapping):
            text = value.get("text") or value.get("source")
            if isinstance(text, str) and text.strip():
                return text
        if isinstance(value, list) and value and all(isinstance(line, str) for line in value):
            return "\n".join(value)
    return ""


def scope_box(package: Mapping[str, Any], limits: Limits) -> Box:
    scope = package.get("scope") if isinstance(package.get("scope"), Mapping) else {}
    rows = [field("component", scope.get("component_id"), limits, mono=True),
            field("partition", scope.get("partition_key"), limits, mono=True),
            field("build unit", scope.get("build_unit_id"), limits, mono=True),
            field("trust boundary", scope.get("trust_boundary_id"), limits, mono=True),
            field("artifacts in scope", len(_strs(scope.get("artifact_ids"))), limits),
            field("sources in scope", len(_strs(scope.get("source_ids"))), limits)]
    items: list[Item] = [Fields(tuple(rows))]
    obligations = _strs(package.get("proof_obligations"))
    if obligations:
        items.append(Para("Proof obligations the claim must satisfy", muted=True))
        items.append(bullets(obligations, limits))
    return Box(BoxKind.EVIDENCE, "Scope and proof obligations", items=tuple(items))


def neighbourhood_box(package: Mapping[str, Any], extra: Mapping[str, Any] | None, limits: Limits) -> Box | None:
    evidence = _dicts(package.get("evidence")) or _dicts((extra or {}).get("evidence"))
    context = _dicts(package.get("context"))
    compiled = _dicts((extra or {}).get("compiled_context") or package.get("compiled_context"))
    if not (evidence or context or compiled):
        return None
    items: list[Item] = []
    if evidence:
        by_resolution = Counter(clean(row.get("resolution")) for row in evidence)
        by_relation = Counter(clean(row.get("relation")) for row in evidence)
        items.append(Fields((Field("evidence rows", str(len(evidence))),
                             Field("resolution", counts_text(by_resolution)),
                             Field("relation", counts_text(by_relation)))))
        rows = [(abbrev(row.get("entity_id")), row.get("relation"), row.get("resolution"),
                 abbrev(row.get("shard_id"), 8)) for row in evidence]
        items.append(table(("entity", "relation", "resolution", "shard"), rows, limits,
                           widths=(0.40, 0.17, 0.20, 0.19), mono=(True, False, False, True)))
    if context:
        roles = Counter(clean(row.get("role") or row.get("kind")) for row in context)
        items.append(Fields((Field("context entities", f"{len(context)} ({counts_text(roles, 5)})"),)))
    if compiled:
        rows = [(row.get("kind"), row.get("name"), f"{clean(row.get('source_path'))}:{scalar(row.get('line'))}")
                for row in compiled]
        items.append(Para("Compiled facts near the lead", muted=True))
        items.append(table(("kind", "name", "location"), rows, limits, widths=(0.22, 0.32, 0.42),
                           mono=(False, True, True)))
    return Box(BoxKind.EVIDENCE, "Neighbourhood facts", meta=f"{len(evidence)} evidence rows", items=tuple(items))


def build_box(extra: Mapping[str, Any] | None, limits: Limits) -> Box | None:
    build = (extra or {}).get("build_context")
    if not isinstance(build, Mapping):
        return None
    items: list[Item] = []
    facts = _dicts(build.get("command_facts"))
    items.append(Fields((field("build actions", len(_strs(build.get("action_ids"))), limits),
                         field("build artifacts", len(_strs(build.get("artifact_ids"))), limits),
                         field("bindings", len(_dicts(build.get("bindings"))), limits))))
    if facts:
        rows = []
        for fact in facts:
            tokens = [clean(tok.get("safe_value")) if not tok.get("redacted") else "<redacted>"
                      for tok in _dicts(fact.get("ordered_tokens"))]
            rows.append((fact.get("tool_id"), " ".join(tokens)))
        items.append(Para("Normalised command facts", muted=True))
        items.append(table(("tool", "tokens"), rows, limits, widths=(0.18, 0.78), mono=(True, True), max_rows=4))
    env = _dicts(build.get("environment_facts"))
    if env:
        rows = [(row.get("name"), "<redacted>" if row.get("redacted") else row.get("safe_value"), row.get("class")) for row in env]
        items.append(Para("Environment facts", muted=True))
        items.append(table(("name", "value", "class"), rows, limits, widths=(0.26, 0.40, 0.30), mono=(True, True, False)))
    return Box(BoxKind.EVIDENCE, "Build context", items=tuple(items))


def tags_box(extra: Mapping[str, Any] | None, limits: Limits) -> Box | None:
    tags = (extra or {}).get("tag_context")
    if not isinstance(tags, Mapping):
        return None
    cloud = _dicts(tags.get("cloud"))
    if not cloud:
        return None
    rows = [(row.get("tag"), row.get("assignment_count")) for row in cloud]
    return Box(BoxKind.EVIDENCE, "Tags", meta=f"{len(cloud)} tags",
               items=(table(("tag", "assignments"), rows, limits, widths=(0.60, 0.30), mono=(True, False)),))


def gaps_box(package: Mapping[str, Any], limits: Limits) -> Box | None:
    gaps = _dicts(package.get("coverage_gaps"))
    if not gaps:
        return None
    by_state = Counter(clean(gap.get("state")) for gap in gaps)
    by_producer = Counter(clean(gap.get("producer")) for gap in gaps)
    ordered = sorted(gaps, key=lambda gap: (clean(gap.get("producer")), clean(gap.get("reason")), clean(gap.get("gap_id"))))
    rows = [(gap.get("state"), gap.get("producer"), bound(gap.get("reason"), 150)[0]) for gap in ordered]
    items: list[Item] = [
        Para("Coverage the assembly could not provide. A gap is never evidence that the target is clean.", muted=True),
        Fields((Field("gaps", str(len(gaps))), Field("by state", counts_text(by_state)),
                Field("by producer", counts_text(by_producer)))),
        table(("state", "producer", "reason"), rows, limits, widths=(0.12, 0.20, 0.64), mono=(False, False, False),
              max_rows=limits.gaps_per_package)]
    return Box(BoxKind.GAP, "Coverage gaps in the package", meta=f"{len(gaps)} gaps", items=tuple(items))


def provenance_box(package: Mapping[str, Any], echo_basis: str | None, source: str, limits: Limits) -> Box:
    rows = [field("package", package.get("package_id"), limits, mono=True),
            field("assembly rule", package.get("assembly_rule"), limits, mono=True),
            field("lane", package.get("lane"), limits),
            field("source", source, limits, mono=True),
            field("manifest", package.get("manifest_sha256"), limits, mono=True),
            field("input fingerprint", package.get("input_fingerprint"), limits, mono=True),
            field("target snapshot", package.get("target_snapshot"), limits, mono=True)]
    if echo_basis:
        rows.append(field("basis sha256", echo_basis, limits, mono=True))
    rows.append(Field("package sha256", sha256_value(package), mono=True))
    return Box(BoxKind.PROVENANCE, "Package provenance", collapsed=True, items=(Fields(tuple(rows)),))


def package_boxes(package: Mapping[str, Any], extra: Mapping[str, Any] | None, *, source: str,
                  echo_basis: str | None, limits: Limits) -> list[Box]:
    boxes = lead_boxes(package, limits)
    boxes.append(scope_box(package, limits))
    for maybe in (neighbourhood_box(package, extra, limits), build_box(extra, limits), tags_box(extra, limits),
                  gaps_box(package, limits)):
        if maybe is not None:
            boxes.append(maybe)
    boxes.append(provenance_box(package, echo_basis, source, limits))
    return boxes
