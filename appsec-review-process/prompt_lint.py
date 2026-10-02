#!/usr/bin/env python3
"""Prompt guardrails for model-dispatched job templates (prompt/persona/role alignment plan, Phase 0).

Three checks, each used by a test under ``tests/`` and by the ``report`` command:

* ``DISPATCHED`` -- every job template a worker actually sends to a model, the code fingerprint that
  must cover its prompt files (``persona_prompt_assembly.prompt_source_paths``), and the schema the
  model is shown. ``NOT_DISPATCHED`` lists templates that assemble but no call site sends; a test
  holds every renderable template to exactly one of the two.
* ``structure_errors`` -- a task prompt has the plan's fixed headings in order, and its ``## Example``
  JSON validates against the schema the model is shown.
* ``repetition`` -- requirements stated in three or more rendered sections (advisory; enforced only
  for templates the plan has migrated).

    python3 -B appsec-review-process/prompt_lint.py report [job_template_id ...]
"""
from __future__ import annotations

import importlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

import persona_prompt_assembly as ppa
import registry_paths
from schema_validate import SchemaStore, validate_document

# template -> (call site, "module:function" whose result is the job's code fingerprint, the reduced
# schema the worker passes as persona_schema or None for the contract's own result schema).
DISPATCHED: dict[str, tuple[str, str, str | None]] = {
    "01-component-characterization": ("component_characterization.py:_dispatch_persona",
                                      "component_characterization:_code_hashes", None),
    "02-repository-partition-discovery": ("discovery_gate.py:_dispatch_partition_persona",
                                          "discovery_gate:automatic_code", None),
    "02-dev-project-discovery": ("discovery_gate.py:_run_project_automatic", "discovery_gate:automatic_code", None),
    "02-devops-project-discovery": ("discovery_gate.py:_run_project_automatic", "discovery_gate:automatic_code", None),
    "02-sre-operations-topology": ("discovery_gate.py:_run_project_automatic", "discovery_gate:automatic_code", None),
    "02-build-classify": ("build_classify.py:dispatch", "build_classify:_code_hashes", None),
    "02-build-plan": ("build_plan.py:dispatch_unit", "build_plan:_code_hashes", None),
    "hypothesis-hunt-general": ("hypothesis_discovery.py:HunterInvoker", "hypothesis_discovery:_code_hashes",
                                "hypothesis-hunt-persona.schema.json"),
    "hypothesis-hunt-known-list": ("hypothesis_discovery.py:HunterInvoker", "hypothesis_discovery:_code_hashes",
                                   "hypothesis-hunt-persona.schema.json"),
    "attack-chain-composition-cell": ("attack_chain_pool.py:ChainInvoker", "attack_chain_pool:code_hashes",
                                      "attack-chain-composer-persona.schema.json"),
    "attack-chain-refutation-cell": ("attack_chain_pool.py:ChainInvoker", "attack_chain_pool:code_hashes",
                                     "attack-chain-refuter-persona.schema.json"),
    "poc-and-fix-cell": ("poc_fix_pool.py:PocFixInvoker", "poc_fix_pool:code_hashes", "poc-fix-persona.schema.json"),
    "claim-review-pool-cell": ("claim_reviewer_pool.py:ClaimReviewerInvoker", "claim_reviewer_pool:_code_hashes",
                               "claim-review-pool-persona.schema.json"),
    **{f"threat-workbench-{cell}": ("threat_workbench.py:_cell_request", "threat_workbench:code_hashes", None)
       for cell in ("abuse-scenario-analyst", "attack-tree-builder", "deployment-topology-mapper",
                    "pii-user-data-mapper", "supply-chain-specialist")},
}
# Assemble, but no call site sends them to a model (deterministic workers or coordinator records).
NOT_DISPATCHED = frozenset({
    "03-threat-model-dfd-stride", "07-hypothesis-discovery", "10-synthesis-report", "12b-poc-and-fix",
    "14-attack-chain-composition", "14-attack-chain-refutation", "claim-ledger-routing",
    # D4: assembled and pinned in the pool request, but the deterministic invoker sends nothing.
    "intake-review-pool-cell", "intake-review-pool-independent-cell",
})

REQUIRED_HEADINGS = ("Goal", "Inputs", "Output", "Procedure", "Rules", "Example", "Before you finish")
_HEADING = re.compile(r"^## (.+?)\s*$", re.M)
_FENCE = re.compile(r"```json\n(.*?)\n```", re.S)


def load_template(job_template_id: str) -> dict[str, Any]:
    return json.loads(registry_paths.template(job_template_id).read_text(encoding="utf-8"))


def fingerprint(job_template_id: str) -> dict[str, str]:
    """The dispatching worker's code fingerprint for ``job_template_id`` (imports the worker)."""
    module_name, function_name = DISPATCHED[job_template_id][1].split(":")
    function: Callable[..., dict[str, str]] = getattr(importlib.import_module(module_name), function_name)
    return function(job_template_id) if function_name == "automatic_code" else function()


def shown_schema(job_template_id: str) -> str:
    """The result schema file the model is shown for this template."""
    reduced = DISPATCHED[job_template_id][2]
    if reduced:
        return reduced
    contract_id = load_template(job_template_id)["composition"]["output_contract_id"]
    contract = json.loads(registry_paths.contract(contract_id).read_text(encoding="utf-8"))
    return contract["result_schema"]["schema_file"]


def task_prompt_path(job_template_id: str) -> Path | None:
    task = load_template(job_template_id).get("task_prompt")
    return ppa.ROOT.parent / task if task else None


def structure_errors(job_template_id: str, store: SchemaStore | None = None) -> list[str]:
    """Plan section 1.1: fixed headings in order, and a complete ``## Example`` that validates."""
    path = task_prompt_path(job_template_id)
    if path is None:
        return ["template has no task_prompt"]
    text = path.read_text(encoding="utf-8")
    headings = _HEADING.findall(text)
    found = [heading for heading in headings if heading in REQUIRED_HEADINGS]
    errors = [f"missing heading '## {heading}'" for heading in REQUIRED_HEADINGS if heading not in found]
    if not errors and found != list(REQUIRED_HEADINGS):
        errors.append("headings out of order: " + ", ".join(found))
    if "Example" in found:
        start = text.index("## Example")
        following = [match.start() for match in _HEADING.finditer(text, start + 1)]
        block = _FENCE.search(text, start, following[0] if following else len(text))
        if block is None:
            errors.append("'## Example' holds no ```json block")
        else:
            try:
                example = json.loads(block.group(1))
            except ValueError as exc:
                errors.append(f"example is not JSON: {exc}")
            else:
                problems = validate_document(example, shown_schema(job_template_id), store or SchemaStore())
                errors += [f"example does not validate against {shown_schema(job_template_id)}: {problem}"
                           for problem in problems[:10]]
    return errors


# --- repetition (advisory) ------------------------------------------------------------------------

_STOP = frozenset("a an and any are as at be by do does for from has have in into is it its may must "
                  "never no nor not of on only or so such than that the their them then there these they "
                  "this to under was what when where whether which while who with without you your".split())


def _sections(job_template_id: str, persona_id: str | None, role_id: str | None,
              store: SchemaStore) -> list[tuple[str, str]]:
    """(section name, rendered text) for each declared prompt section, rendered one at a time so a
    section's own ``##`` headings (governing rules, a migrated task prompt) do not split it."""
    template = load_template(job_template_id)
    for section, record_id in (("persona", persona_id), ("role", role_id)):
        if record_id is not None:
            template = {**template, "composition": {**template["composition"], section + "_id": record_id}}
    return [(section, ppa.render_section(section, template, store)) for section in template["prompt_sections"]]


def _strings(body: str) -> list[str]:
    fence = _FENCE.search(body)
    if fence:
        try:
            value = json.loads(fence.group(1))
        except ValueError:
            return [body]
        found: list[str] = []

        def walk(node: Any) -> None:
            if isinstance(node, str):
                found.append(node)
            elif isinstance(node, dict):
                for item in node.values():
                    walk(item)
            elif isinstance(node, list):
                for item in node:
                    walk(item)
        walk(value)
        return found
    return [body]


def _clauses(text: str) -> list[tuple[str, frozenset]]:
    rows = []
    for clause in re.split(r"(?<=[.;:!?])\s+|\n+|\s+--\s+", text):
        words = frozenset(word for word in re.findall(r"[a-z][a-z0-9-]+", clause.lower()) if word not in _STOP)
        if len(words) >= 4:
            rows.append((clause.strip(" -*`"), words))
    return rows


def repetition(job_template_id: str, *, threshold: float = 0.6, minimum: int = 3,
               persona_id: str | None = None, role_id: str | None = None,
               store: SchemaStore | None = None) -> list[dict[str, Any]]:
    """Clusters of similar clauses that occur in at least ``minimum`` different rendered sections.
    Two clauses are similar when the smaller one's content words are mostly (``threshold``) inside the
    larger one's (overlap coefficient), which catches a paraphrase that restates a rule in a longer
    sentence. Each cluster: {sections: [...], clauses: [(section, text)]}."""
    rows = [(section, clause, words)
            for section, body in _sections(job_template_id, persona_id, role_id, store or SchemaStore())
            for string in _strings(body) for clause, words in _clauses(string)]
    clusters: list[dict[str, Any]] = []
    seen: set[int] = set()
    for index, (section, clause, words) in enumerate(rows):
        if index in seen:
            continue
        members = [(section, clause)]
        for other in range(index + 1, len(rows)):
            other_section, other_clause, other_words = rows[other]
            if other in seen or other_section == section:
                continue
            if len(words & other_words) / min(len(words), len(other_words)) >= threshold:
                members.append((other_section, other_clause))
                seen.add(other)
        sections = sorted({member[0] for member in members})
        if len(sections) >= minimum:
            clusters.append({"sections": sections, "clauses": members})
    return clusters


def report(templates: list[str]) -> str:
    store = SchemaStore()
    lines = []
    for template in templates:
        lines.append(f"== {template}  (shown schema: {shown_schema(template)})")
        lines += [f"  structure: {error}" for error in structure_errors(template, store)] or ["  structure: ok"]
        for cluster in repetition(template, store=store):
            lines.append(f"  repeated in {len(cluster['sections'])} sections: {cluster['clauses'][0][1][:140]}")
    return "\n".join(lines)


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] != "report":
        print(__doc__)
        sys.exit(2)
    print(report(args[1:] or sorted(DISPATCHED)))
