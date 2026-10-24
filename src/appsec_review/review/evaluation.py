"""Opt-in, source-grounded role experiments; never a production adjudicator.

Cases and answer keys stay outside worker guidance. Each experiment is one bounded, no-tool
turn using the real role bundle and compact schema. Citation checks are a reproducible proxy,
not a claim that a label proves a predicate or that fixture accuracy predicts production recall.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import asdict, fields, is_dataclass
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from appsec_review.config import InferenceSecurityReviewSettings, load_config
from appsec_review.inference import Infer, ModelOutputError, ModelResult, ReviewModelRequest, infer
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet, SCHEMA_DIRECTORY
from appsec_review.review.budget import JobBudget
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import Lane, Role, SecurityPredicate
from appsec_review.storage import atomic_json, file_sha256

CASE_SCHEMA = "appsec-review/guidance-evaluation-cases/1"
REPORT_SCHEMA = "appsec-review/guidance-evaluation/1"
ROLES = {
    "hypothesis_hunter": ("sink_up", "red-compact"),
    "red_team_analyst": ("lead_red_stack", "red-compact"),
    "blue_team_refuter": ("blue_control", "blue-compact"),
    "independent_verifier": ("blind_verifier", "verifier-compact"),
}
VARIANTS = ("full", "without_procedures")
OUTCOMES = {"vulnerable", "safe", "abstain"}


def load_cases(path: Path) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    cases = document.get("cases", [])
    if document.get("schema") != CASE_SCHEMA or not isinstance(cases, list) or not 1 <= len(cases) <= 128:
        raise ValueError("invalid or unbounded evaluation case set")
    seen = set()
    for case in cases:
        if (not re.fullmatch(r"case-[a-zA-Z0-9_-]{1,64}", case["id"])
                or case["id"] in seen or case["expected"] not in OUTCOMES):
            raise ValueError("duplicate case identity or invalid expected outcome")
        seen.add(case["id"])
        SecurityPredicate(case["condition"])
        sources = case["sources"]
        labels = [source["label"] for source in sources]
        if not 1 <= len(sources) <= 32 or len(set(labels)) != len(labels):
            raise ValueError("case sources must have distinct bounded labels")
        if not case["decisive_labels"] or not set(case["decisive_labels"]) <= set(labels):
            raise ValueError("answer key must cite supplied source labels")
        for source in sources:
            if type(source["start_line"]) is not int or source["start_line"] < 1:
                raise ValueError("source line must be positive")
            if not source["text"].strip() or len(source["text"]) > 16000:
                raise ValueError("source excerpt is empty or unbounded")
    return cases


def task_input(case: Mapping[str, Any], role: str) -> dict[str, Any]:
    """Explicit allowlist: neither answer keys nor variant/family names reach a model."""
    sources = [{**source, "sha256": sha256_hex(source["text"]),
                "lines": [f"{source['start_line'] + number}| {line}"
                          for number, line in enumerate(source["text"].splitlines())]}
               for source in case["sources"]]
    labels = [source["label"] for source in sources]
    claim_id = "claim-" + sha256_hex({"condition": case["condition"], "sources": sources})
    value: dict[str, Any] = {
        "task": ROLES[role][0],
        "package": {"source": sources, "leads": [{"label": "L1", "summary": case["question"]}]},
        "turn_protocol": {
            "tool_catalog": [], "instruction": (
                "This is a self-contained, bounded source review. No retrieval tools are granted. "
                "Return one final compact result for your role. If material evidence is missing, "
                "name the gap or evidence request; never assume a missing implementation is safe or unsafe."),
            "final_shape": {"action": "final", "result": "<role compact result>"}},
    }
    if role in ("blue_team_refuter", "independent_verifier"):
        value["claim"] = {
            "claim_id": claim_id, "affected": [{"label": label, "name": case["question"]} for label in labels],
            "weakness_cwe": case["cwe"], "security_predicate": case["condition"], "preconditions": [],
            "required_predicates": ["affected_construct", "attacker_input_control", "source_to_sink_reachability",
                                    "missing_or_ineffective_guard", "security_impact"],
            "hypothesis": {"condition": case["condition"], "affected_labels": labels,
                           "preconditions": [], "weakness_cwe": case["cwe"]}}
    return value


def procedure_variant(bundle: Mapping[str, Any], variant: str) -> dict[str, Any]:
    from appsec_review.guidance.compose import bundle_sha256, section_sha256

    if variant not in VARIANTS:
        raise ValueError(f"unknown evaluation variant: {variant}")
    result = deepcopy(dict(bundle))
    if variant == "without_procedures":
        section = next((item for item in result["sections"] if item["name"] == "procedures"), None)
        if section is None:
            raise ValueError("procedure ablation requires a bundle with a procedures section")
        section["items"] = []
        section["sha256"] = section_sha256(section)
        result["section_sha256"]["procedures"] = section["sha256"]
        result["sha256"] = bundle_sha256(result)
    return result


def _guidance(root: Path, case: Mapping[str, Any], role: str, payload: Mapping[str, Any], variant: str
              ) -> tuple[dict[str, Any], str]:
    from appsec_review.guidance import compose_bundle, render_prompt
    from appsec_review.jobs.job_security_tagging.crosswalk import load_crosswalk
    from appsec_review.jobs.job_security_tagging.taxonomy import load_vocabulary

    taxonomy = root / "data" / "reference" / "taxonomy"
    vocabulary = load_vocabulary(taxonomy / "vocabulary.json", file_sha256(taxonomy / "vocabulary.json"))
    crosswalk = load_crosswalk(taxonomy / "crosswalk.json", file_sha256(taxonomy / "crosswalk.json"), vocabulary)
    bundle = compose_bundle(root, role=role, persona=case["persona"], stack=case["stack"],
                            task=ROLES[role][0], task_input=payload, capability={"granted_tools": []},
                            vocabulary=vocabulary, crosswalk=crosswalk)
    bundle = procedure_variant(bundle, variant)
    return bundle, render_prompt(bundle)


def _citation_list(values: Mapping[str, Any], stance: str) -> list[str]:
    found = []
    for item in values.values():
        if item.get("stance") == stance:
            found.extend(item.get("cites", ()))
    return found


def assess(case: Mapping[str, Any], role: str, proposal: Mapping[str, Any], schemas: SchemaSet) -> dict[str, Any]:
    result = proposal.get("result")
    if proposal.get("action") != "final" or not isinstance(result, Mapping):
        return {"status": "invalid", "errors": ["expected a final compact answer"]}
    errors = schemas.errors(ROLES[role][1], result)
    if errors:
        return {"status": "invalid", "errors": errors}
    citations: list[str] = []
    duplicates = 0
    conclusion_count = 0
    if role in ("hypothesis_hunter", "red_team_analyst"):
        claims = result["claims"]
        relevant = [item for item in claims if item["security_predicate"] == case["condition"]
                    and item.get("cwe") == case["cwe"]]
        decision = "vulnerable" if relevant else "no_claim"
        conclusion_count = len(claims)
        keys = [sha256_hex({"cwe": item.get("cwe"), "condition": item["security_predicate"],
                           "affected": sorted(item.get("affected", [])),
                           "preconditions": sorted(item.get("preconditions", []))}) for item in claims]
        duplicates = len(keys) - len(set(keys))
        citations = [cite for item in relevant for cites in item.get("support", {}).values() for cite in cites]
        named_gap = bool(result.get("blocked")) or any(item.get("missing") or item.get("evidence_requests")
                                                       for item in claims)
        if not claims and result.get("blocked"):
            decision = "abstain"
    elif role == "blue_team_refuter":
        per_predicate = result.get("per_predicate", {})
        decision = "safe" if result.get("stance") == "contradicts" or any(
            item.get("stance") == "contradicts" for item in per_predicate.values()) else "abstain"
        citations = list(result.get("cites", ())) + _citation_list(per_predicate, "contradicts")
        named_gap = bool(result.get("evidence_requests")) or any(item.get("missing")
                                                                 for item in per_predicate.values())
        conclusion_count = int(decision == "safe")
    else:
        disposition = result["disposition"]
        decision = ("vulnerable" if disposition in ("confirmed", "supported") else
                    "abstain" if disposition == "insufficient_evidence" else "safe")
        citations = _citation_list(result["per_predicate"], "supports" if decision == "vulnerable" else "contradicts")
        named_gap = bool(result.get("evidence_requests")) or any(item.get("missing")
                                                                 for item in result["per_predicate"].values())
        conclusion_count = int(decision != "abstain")
    known = {source["label"] for source in case["sources"]}
    grounded = bool(citations) and set(citations) <= known and set(case["decisive_labels"]) <= set(citations)
    correct = decision == case["expected"] and (named_gap if decision == "abstain" else grounded)
    unsupported = conclusion_count if not grounded or decision != case["expected"] else 0
    if role in ("hypothesis_hunter", "red_team_analyst"):
        unsupported = sum(
            case["expected"] != "vulnerable" or item not in relevant
            or not set(case["decisive_labels"]) <= {cite for cites in item.get("support", {}).values() for cite in cites}
            or not {cite for cites in item.get("support", {}).values() for cite in cites} <= known
            for item in claims)
        correct = correct and unsupported < len(claims) if claims else correct
    return {"status": "completed", "decision": decision, "citations": sorted(set(citations)),
            "grounded": grounded, "named_gap": named_gap, "correct": correct, "duplicates": duplicates,
            "conclusions": conclusion_count, "unsupported": unsupported}


def _ratio(numerator: int | float, denominator: int) -> dict[str, Any]:
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else None}


def _settings_document(value: Any) -> Any:
    if is_dataclass(value):
        return {field.name: _settings_document(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {key: _settings_document(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_settings_document(item) for item in value]
    return value


def score(cases: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, Any]], role: str) -> dict[str, Any]:
    expected = {case["id"]: case for case in cases}
    by_id = {}
    for row in rows:
        if row["case_id"] not in expected or row["case_id"] in by_id:
            raise ValueError("unknown or duplicate evaluation response")
        by_id[row["case_id"]] = row
    completed = [row for row in rows if row["status"] == "completed"]
    vulnerable = [case for case in cases if case["expected"] == "vulnerable"]
    incomplete = [case for case in cases if case["expected"] == "abstain"]
    abstained = [row for row in completed if row["decision"] == "abstain"]
    correct = sum(bool(row["correct"]) for row in completed)
    correct_abstentions = sum(bool(row["correct"]) for row in abstained)
    tokens_known = all(row.get("input_tokens") is not None and row.get("output_tokens") is not None for row in rows)
    return {
        "expected_cases": len(cases), "completed": len(completed), "correct_resolutions": correct,
        "gaps": len(cases) - len(completed),
        "recall": _ratio(sum(bool(by_id.get(case["id"], {}).get("correct")) for case in vulnerable),
                         len(vulnerable)) if role != "blue_team_refuter" else None,
        "false_refutation_rate": _ratio(sum(by_id.get(case["id"], {}).get("decision") == "safe"
                                            for case in vulnerable), len(vulnerable)),
        "unsupported_conclusion_rate": _ratio(sum(row["unsupported"] for row in completed),
                                             sum(row["conclusions"] for row in completed)),
        "abstention_precision": _ratio(correct_abstentions, len(abstained)),
        "abstention_recall": _ratio(correct_abstentions, len(incomplete)),
        "duplicate_rate": _ratio(sum(row["duplicates"] for row in completed),
                                 sum(row["conclusions"] for row in completed)),
        "tokens_per_correct_resolution": (
            _ratio(sum(row["input_tokens"] + row["output_tokens"] for row in rows), correct)
            if tokens_known and rows else None),
        "usage_complete": tokens_known and len(rows) == len(cases),
        "monetary_cost": None,
        "cost_gap": "Provider results do not contain billed cost; token usage is reported without guessed prices.",
    }


def run_evaluation(root: Path, cases: Sequence[Mapping[str, Any]], settings: InferenceSecurityReviewSettings,
                   output: Path, *, role: str, variants: Sequence[str] = VARIANTS, live: bool = False,
                   transport: Infer | None = None) -> dict[str, Any]:
    from appsec_review.guidance import pin_bundle

    if transport is None and not live:
        raise ValueError("live inference requires explicit --live; offline scoring never calls a model")
    if role not in ROLES or not variants or len(set(variants)) != len(variants) or not set(variants) <= set(VARIANTS):
        raise ValueError("invalid role or variants")
    output.mkdir(parents=True, exist_ok=False)
    run_root = output
    output = run_root / "data" / "evaluation"
    output.mkdir(parents=True)
    configuration = _settings_document(settings)
    atomic_json(run_root / "data" / "configuration" / "resolved.json", configuration)
    atomic_json(output / "cases.json", {"schema": CASE_SCHEMA, "cases": list(cases)})
    schemas = SchemaSet(root / SCHEMA_DIRECTORY)
    model = settings.profile_for(Role(role))
    if not model.enabled:
        raise ValueError("the configured role model is disabled")
    budget = JobBudget.for_run(run_root, settings.budgets)
    report: dict[str, Any] = {"schema": REPORT_SCHEMA, "role": role, "cases_sha256": sha256_hex(cases),
                              "settings_sha256": sha256_hex(configuration), "variants": {}}
    send = transport or infer
    for variant in variants:
        rows = []
        for case in cases:
            row: dict[str, Any] = {"case_id": case["id"], "input_tokens": None, "output_tokens": None}
            if not budget.reserve(Lane.LEAD) or not budget.cell_launch_allowed():
                row.update(status="not_launched", errors=["configured evaluation budget exhausted"])
                rows.append(row)
                continue
            payload = task_input(case, role)
            bundle, guidance = _guidance(root, case, role, payload, variant)
            pin_bundle(run_root, bundle)
            request = ReviewModelRequest(
                schema="appsec-review/worker-turn/1", role=role, persona=case["persona"],
                stack_profile=case["stack"], guidance_bundle_sha256=bundle["sha256"], guidance_text=guidance,
                task_input=payload, transcript=(), provider=model.provider, model=model.model, reasoning=model.reasoning,
                max_input_tokens=model.max_input_tokens, max_output_tokens=model.max_output_tokens)
            row["guidance_sha256"] = bundle["sha256"]
            atomic_json(output / f"{case['id']}-{variant}-request.json", asdict(request))
            remaining = settings.budgets.timeout_seconds - (budget.clock() - budget.snapshot().started_at)
            estimate = (len(guidance) + len(json.dumps(payload)) + 3) // 4
            if estimate > model.max_input_tokens or remaining < 1:
                row.update(status="not_launched", errors=["request exceeds configured input or time budget"])
                rows.append(row)
                continue
            try:
                answer: ModelResult = send(request, timeout_seconds=min(model.timeout_seconds, int(remaining)))
            except (ModelOutputError, OSError, TimeoutError, ValueError) as error:
                budget.charge(model_turns=1, input_tokens=estimate, output_tokens=model.max_output_tokens)
                row.update(status="error", errors=[f"{type(error).__name__}: {error}"])
            else:
                budget.charge(model_turns=1, input_tokens=answer.input_tokens if answer.input_tokens is not None else estimate,
                              output_tokens=answer.output_tokens if answer.output_tokens is not None else model.max_output_tokens)
                row.update(input_tokens=answer.input_tokens, output_tokens=answer.output_tokens,
                           proposal=dict(answer.proposal), **assess(case, role, answer.proposal, schemas))
            rows.append(row)
            atomic_json(output / f"{case['id']}-{variant}-response.json", row)
            report["variants"][variant] = {"rows": rows, "metrics": score(cases, rows, role)}
            atomic_json(output / "report.json", report)
        report["variants"][variant] = {"rows": rows, "metrics": score(cases, rows, role)}
    atomic_json(output / "report.json", report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--cases", type=Path)
    parser.add_argument("--responses", type=Path, help="Re-score a saved report offline, including its raw proposals")
    parser.add_argument("--output", type=Path, help="New run-owned directory beneath runs/")
    parser.add_argument("--profile", choices=("dev", "prod"), default="dev")
    parser.add_argument("--role", choices=tuple(ROLES), default="independent_verifier")
    parser.add_argument("--variant", choices=(*VARIANTS, "paired"), default="paired")
    parser.add_argument("--live", action="store_true", help="Explicitly authorize configured model calls")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    cases = load_cases(args.cases or root / "tests" / "fixtures" / "review_guidance" / "cases.json")
    if args.responses:
        if args.live:
            parser.error("--responses cannot be combined with --live")
        report = json.loads(args.responses.read_text(encoding="utf-8"))
        if report.get("schema") != REPORT_SCHEMA or report["cases_sha256"] != sha256_hex(cases):
            parser.error("report schema or case hash does not match")
        if report.get("role") not in ROLES:
            parser.error("unknown report role")
        schemas = SchemaSet(root / SCHEMA_DIRECTORY)
        for variant in report["variants"].values():
            by_id = {case["id"]: case for case in cases}
            rows = [{**row, **assess(by_id[row["case_id"]], report["role"], row["proposal"], schemas)}
                    if "proposal" in row else {**row, "status": "invalid", "errors": ["completed response lacks raw proposal"]}
                    if row["status"] == "completed" else row for row in variant["rows"]]
            variant["rows"], variant["metrics"] = rows, score(cases, rows, report["role"])
    else:
        if not args.live or args.output is None:
            parser.error("supply --responses for offline scoring, or --live and a new --output beneath runs/")
        output = args.output.resolve()
        if not output.is_relative_to(root / "runs") or output == root / "runs":
            parser.error("live evaluation output must be a new descendant of runs/")
        settings = load_config(root / "appsec-review.toml", profile=args.profile).job(
            "job_inference_security_review").typed_settings
        if not isinstance(settings, InferenceSecurityReviewSettings):
            raise ValueError("inference review settings are unavailable")
        report = run_evaluation(root, cases, settings, output, role=args.role,
                                variants=VARIANTS if args.variant == "paired" else (args.variant,), live=True)
    print(json.dumps({name: value["metrics"] for name, value in report["variants"].items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
