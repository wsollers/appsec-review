"""MANUAL ONLY: live multi-turn acceptance against the synthetic competence corpus.

Not part of implicit collection. Do not run as a repair/merge/completion gate.
After explicit user authorization, from the Linux repository root:

    .venv/bin/python -m tests.acceptance.test_prompt_competence --live \
        --config appsec-review.toml --profile dev \
        --provider claude-cli --model claude-haiku-5-5 \
        --cases tests/fixtures/review_guidance/competence_cases.json \
        --output runs/competence-live-YYYYMMDD-unique

The provider/model arguments assert the identities resolved from that config; they do not
override it. Change them to the explicitly selected configured profile. For explicit pytest
invocation, set APPSEC_REVIEW_LIVE_COMPETENCE=1 and APPSEC_REVIEW_COMPETENCE_ARGS to a JSON
array of the same arguments (including --live), then select this file.

Reports preserve config/corpus/model/bundle/manifest identities, raw requests and answers,
production receipts and evaluation.score metrics. Synthetic source contracts are fixtures,
not observations of a deployed target. Citation matching is a proxy, not proof of semantic
correctness. Inspect the responses and coverage gaps before making any quality claim.
No acceptance thresholds or production-efficacy claims are inferred from scripted unit tests.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
from typing import Sequence

import pytest

from appsec_review.config import InferenceSecurityReviewSettings, load_config
from appsec_review.review.budget import JobBudget
from appsec_review.review.competence import LIMITATION, REPORT_SCHEMA, ROLE, ROLE_TASKS, run_competence_case
from appsec_review.review.evaluation import load_cases, score
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import Lane, Role
from appsec_review.storage import atomic_json, file_sha256
from tests.review.test_prompt_competence import ROOT, accepted_corpus


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--profile", choices=("dev", "prod"), required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--role", choices=[role.value for role in ROLE_TASKS], default=ROLE.value)
    parser.add_argument("--variant", choices=("full", "without_procedures"), default="full")
    parser.add_argument("--turn-cap", type=int, help="tighten, never increase, the configured per-cell turn cap")
    return parser


def run_acceptance(argv: Sequence[str]) -> dict:
    parser = argument_parser()
    args = parser.parse_args(argv)
    if not args.live:
        parser.error("live providers require explicit --live authorization")
    output = args.output.resolve()
    if output == ROOT / "runs" or not output.is_relative_to(ROOT / "runs"):
        parser.error("output must be a new descendant of this repository's runs/")
    config = load_config(args.config.resolve(), profile=args.profile)
    settings = config.job("job_inference_security_review").typed_settings
    if not isinstance(settings, InferenceSecurityReviewSettings):
        raise ValueError("inference review settings are unavailable")
    role = Role(args.role)
    lane = Lane.HUNT if role is Role.HYPOTHESIS_HUNTER else Lane.LEAD
    model = settings.profile_for(role)
    if (model.provider, model.model) != (args.provider, args.model):
        parser.error("--provider/--model must match the resolved role profile")
    if not model.enabled or model.max_queries < 1 or model.max_turns < 2:
        parser.error("the selected role profile must enable bounded multi-turn retrieval")
    turn_cap = model.max_turns if args.turn_cap is None else args.turn_cap
    if not 2 <= turn_cap <= model.max_turns:
        parser.error("--turn-cap must be between 2 and the configured role's max_turns")
    cases = load_cases(args.cases)
    output.mkdir(parents=True, exist_ok=False)
    configuration = json.loads(config.resolved_json)
    atomic_json(output / "data" / "configuration" / "resolved.json", configuration)
    atomic_json(output / "data" / "competence" / "cases.json", {"cases": cases})
    budget = JobBudget.for_run(output, settings.budgets)
    rows = []
    report = {
        "schema": REPORT_SCHEMA, "execution": "live", "limitation": LIMITATION, "role": role.value,
        "variant": args.variant, "turn_cap": turn_cap,
        "profile": args.profile, "configuration_sha256": sha256_hex(configuration),
        "config_file_sha256": file_sha256(args.config),
        "settings_sha256": sha256_hex(settings.as_document()),
        "cases_sha256": sha256_hex(cases), "corpus_file_sha256": file_sha256(args.cases),
        "model": asdict(model), "rows": rows,
    }
    for case in cases:
        if not budget.reserve(lane) or not budget.cell_launch_allowed():
            rows.append({"case_id": case["id"], "status": "not_launched",
                         "input_tokens": None, "output_tokens": None,
                         "errors": ["configured acceptance budget exhausted"]})
        else:
            corpus = accepted_corpus(
                output / "data" / "corpus" / case["id"], case,
                max_turns=turn_cap, max_queries=model.max_queries, role=role)
            result = run_competence_case(
                ROOT, case, settings, core=corpus.core, capability=corpus.capability,
                view=corpus.view, source_labels=corpus.labels,
                output=corpus.core.run_root / "data" / "experiment", live=True, budget=budget,
                variant=args.variant)
            rows.append(dict(result.row))
        report["metrics"] = score(cases, rows, role.value)
        atomic_json(output / "data" / "competence" / "report.json", report)
    return report


@pytest.mark.skipif(os.environ.get("APPSEC_REVIEW_LIVE_COMPETENCE") != "1",
                    reason="manual live-provider acceptance requires explicit authorization")
def test_live_prompt_competence():
    arguments = json.loads(os.environ["APPSEC_REVIEW_COMPETENCE_ARGS"])
    report = run_acceptance(arguments)
    assert report["execution"] == "live"
    assert len(report["rows"]) == report["metrics"]["expected_cases"]
    assert report["metrics"]["gaps"] == 0, "inspect saved provider failures and named coverage gaps"
    assert {"recall", "false_refutation_rate", "unsupported_conclusion_rate", "abstention_precision",
            "abstention_recall", "duplicate_rate", "tokens_per_correct_resolution"} <= report["metrics"].keys()


if __name__ == "__main__":
    import sys

    result = run_acceptance(sys.argv[1:])
    print(json.dumps(result["metrics"], indent=2))
