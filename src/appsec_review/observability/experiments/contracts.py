"""Closed JSON contracts for offline, revision-bound quality experiments."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any, Literal, TypedDict, cast

from jsonschema import Draft202012Validator

from appsec_review.storage import canonical_json

INPUT_SCHEMA = "appsec-review/quality-experiment/1"
OUTPUT_SCHEMA = "appsec-review/quality-experiment-snapshot/1"
NORMALIZER = "source-root-cause-exact/1"


class Group(TypedDict):
    source_revision: str
    scope_sha256: str
    context_condition: Literal["source_only", "build_context"]
    configuration_sha256: str
    guidance_sha256: str
    model_sha256: str
    agent_sha256: str
    tools_sha256: str
    decoding_sha256: str
    normalizer_version: str
    stage: Literal["candidate", "verified", "reproduced"]
    task: Literal["discovery", "triage"]
    positive_event: str
    warning_set_sha256: str | None


class Location(TypedDict):
    path: str
    start_line: int
    end_line: int


class Confidence(TypedDict):
    kind: Literal["verbal_score", "token_probability", "token_margin", "vote_fraction", "probability"]
    raw: str | float
    target: str
    calibrated: bool
    calibration_version: str | None


class Report(TypedDict):
    raw_report_id: str
    cwe: str
    cause_key: str
    source_symbol: str | None
    sink_symbol: str | None
    locations: list[Location]
    severity: str
    confidence: Confidence | None
    evidence_ids: list[str]


class Launch(TypedDict):
    run_id: str
    source_run_id: str
    run_index: int
    started_at: str
    group: Group


class Decision(TypedDict):
    warning_id: str
    decision: Literal["retain", "reject", "abstain"]


class Usage(TypedDict):
    input_tokens: int | None
    output_tokens: int | None
    wall_seconds: float | None
    cost: str | None
    currency: str | None
    cost_kind: Literal["observed", "estimated", "unavailable"]
    evidence_ids: list[str]
    missing_reason: str | None


class Completion(TypedDict):
    run_id: str
    status: Literal["complete", "failed", "partial", "cancelled"]
    completed_at: str
    raw_artifact_sha256: str
    reports: list[Report]
    decisions: list[Decision]
    usage: Usage
    coverage: list[dict[str, Any]]
    error_ids: list[str]


class Match(TypedDict):
    run_id: str
    raw_report_id: str
    root_cause_id: str
    evidence_ids: list[str]


class Matching(TypedDict):
    schema: Literal["appsec-review/quality-matching/1"]
    revision: str
    normalizer_version: str
    overrides: list[Match]


class Label(TypedDict):
    population_id: str
    subject_id: str
    outcome: Literal["tp", "fp", "unresolved", "out_of_scope"]
    is_real_bug: bool | None
    is_rank1_critical: bool | None
    adjudicator_id: str
    method: Literal["independent_human", "independent_external"]
    evidence_ids: list[str]
    adjudicated_at: str


class Labels(TypedDict):
    schema: Literal["appsec-review/quality-adjudications/1"]
    revision: str
    matching_snapshot_id: str
    labels: list[Label]


class Experiment(TypedDict):
    schema: Literal["appsec-review/quality-experiment/1"]
    experiment_id: str
    launches: list[Launch]
    completions: list[Completion]
    warning_sets: list[dict[str, Any]]
    matching: Matching
    adjudications: Labels
    inference_policy: dict[str, Any] | None


def object_schema(**properties: Any) -> dict[str, Any]:
    return {"type": "object", "additionalProperties": False,
            "required": list(properties), "properties": properties}


def array_schema(items: Any, maximum: int = 10000) -> dict[str, Any]:
    return {"type": "array", "items": items, "maxItems": maximum}


def nullable(value: Any) -> dict[str, Any]:
    return {"anyOf": [value, {"type": "null"}]}


def enum(*values: str) -> dict[str, Any]:
    return {"enum": list(values)}


TEXT = {"type": "string", "minLength": 1, "maxLength": 2048}
HASH = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
COUNT = {"type": "integer", "minimum": 0}
NUMBER = {"type": "number", "minimum": 0}
TIME = {"type": "string", "format": "date-time"}
IDS = array_schema(TEXT)
LOCATION = object_schema(path=TEXT, start_line={"type": "integer", "minimum": 1},
                         end_line={"type": "integer", "minimum": 1})
CONFIDENCE = object_schema(
    kind=enum("verbal_score", "token_probability", "token_margin", "vote_fraction", "probability"),
    raw={"anyOf": [TEXT, {"type": "number"}]}, target=TEXT, calibrated={"type": "boolean"},
    calibration_version=nullable(TEXT))
GROUP = object_schema(
    source_revision=TEXT, scope_sha256=HASH, context_condition=enum("source_only", "build_context"),
    configuration_sha256=HASH, guidance_sha256=HASH, model_sha256=HASH, agent_sha256=HASH,
    tools_sha256=HASH, decoding_sha256=HASH, normalizer_version={"const": NORMALIZER},
    stage=enum("candidate", "verified", "reproduced"), task=enum("discovery", "triage"),
    positive_event=TEXT, warning_set_sha256=nullable(HASH))
REPORT = object_schema(
    raw_report_id=TEXT, cwe={"type": "string", "pattern": "^CWE-[0-9]+$"}, cause_key=TEXT,
    source_symbol=nullable(TEXT), sink_symbol=nullable(TEXT),
    locations={**array_schema(LOCATION, 100), "minItems": 1}, severity=TEXT,
    confidence=nullable(CONFIDENCE), evidence_ids={**IDS, "minItems": 1})
LAUNCH = object_schema(
    run_id=TEXT, source_run_id=TEXT, run_index={"type": "integer", "minimum": 1, "maximum": 100000},
    started_at=TIME, group=GROUP)
USAGE = object_schema(
    input_tokens=nullable(COUNT), output_tokens=nullable(COUNT), wall_seconds=nullable(NUMBER),
    cost=nullable({"type": "string", "pattern": "^(0|[1-9][0-9]*)(\\.[0-9]+)?$", "maxLength": 40}),
    currency=nullable({"type": "string", "pattern": "^[A-Z]{3}$"}),
    cost_kind=enum("observed", "estimated", "unavailable"), evidence_ids=IDS, missing_reason=nullable(TEXT))
COVERAGE = object_schema(
    unit=TEXT, analyzed=nullable(COUNT), eligible=nullable(COUNT), evidence_ids=IDS, missing_reason=nullable(TEXT))
COMPLETION = object_schema(
    run_id=TEXT, status=enum("complete", "failed", "partial", "cancelled"), completed_at=TIME,
    raw_artifact_sha256=HASH, reports=array_schema(REPORT),
    decisions=array_schema(object_schema(warning_id=TEXT, decision=enum("retain", "reject", "abstain"))),
    usage=USAGE, coverage=array_schema(COVERAGE, 100), error_ids=IDS)
MATCHING = object_schema(
    schema={"const": "appsec-review/quality-matching/1"}, revision=TEXT,
    normalizer_version={"const": NORMALIZER}, overrides=array_schema(object_schema(
        run_id=TEXT, raw_report_id=TEXT, root_cause_id=HASH, evidence_ids={**IDS, "minItems": 1}), 100000))
LABEL = object_schema(
    population_id=HASH, subject_id=TEXT, outcome=enum("tp", "fp", "unresolved", "out_of_scope"),
    is_real_bug=nullable({"type": "boolean"}), is_rank1_critical=nullable({"type": "boolean"}),
    adjudicator_id=TEXT, method=enum("independent_human", "independent_external"),
    evidence_ids={**IDS, "minItems": 1}, adjudicated_at=TIME)
ADJUDICATIONS = object_schema(
    schema={"const": "appsec-review/quality-adjudications/1"}, revision=TEXT,
    matching_snapshot_id=HASH, labels=array_schema(LABEL, 100000))
INPUT = object_schema(
    schema={"const": INPUT_SCHEMA}, experiment_id=TEXT, launches=array_schema(LAUNCH, 512),
    completions=array_schema(COMPLETION, 512), warning_sets=array_schema(object_schema(
        warning_set_sha256=HASH, warning_ids={**IDS, "uniqueItems": True}), 512),
    matching=MATCHING, adjudications=ADJUDICATIONS,
    inference_policy=nullable(object_schema(
        policy_id=TEXT, predeclared_at=TIME, design=enum("fixed_sample", "sequential"),
        sampling_unit=TEXT, dependence_method=TEXT, planned_runs={"type": "integer", "minimum": 1},
        evidence_ids={**IDS, "minItems": 1})))

RATIO = object_schema(numerator=nullable(NUMBER), denominator=nullable(NUMBER),
                      value=nullable(NUMBER), status=enum("measured", "empty_denominator", "unavailable"),
                      reason=nullable(TEXT))
QUALITY = object_schema(
    tp=COUNT, fp=COUNT, unresolved=COUNT, out_of_scope=COUNT, precision=RATIO,
    false_discovery_rate=RATIO, pending_lower=RATIO, pending_upper=RATIO, adjudication_coverage=RATIO)
SUMMARY = object_schema(value=nullable(NUMBER), valid_count=COUNT, total_count=COUNT)
TRANSITION = object_schema(
    previous_run_id=nullable(TEXT), status=enum("valid", "unavailable"), reason=nullable(TEXT),
    previous_size=nullable(COUNT), current_size=nullable(COUNT), shared=nullable(COUNT), union=nullable(COUNT),
    new_to_previous=nullable(COUNT), dropped=nullable(COUNT), reappearing=nullable(COUNT),
    jaccard=RATIO, retention=RATIO)
TRIAGE = object_schema(
    warning_count=COUNT, retained=COUNT, rejected=COUNT, abstained=COUNT,
    tp=COUNT, fp=COUNT, tn=COUNT, fn=COUNT, known_positive=COUNT, known_negative=COUNT,
    unresolved_inputs=COUNT, out_of_scope_inputs=COUNT, abstained_tp=COUNT, abstained_fp=COUNT,
    tp_retention=RATIO, fp_removal=RATIO, false_positive_rate=RATIO,
    decision_coverage=RATIO, abstention_rate=RATIO, suppression_rate=RATIO,
    rejection_precision=RATIO)
USAGE_TOTAL = object_schema(
    observed_sum=nullable(NUMBER), total=nullable(NUMBER), missing_run_ids=IDS)
COST_TOTAL = object_schema(
    observed_sum=nullable(TEXT), total=nullable(TEXT), currency=nullable(TEXT),
    missing_run_ids=IDS, incompatible_currency={"type": "boolean"},
    per_unique_tp=nullable(TEXT), reason=nullable(TEXT))
RUN_METRICS = object_schema(
    run_id=TEXT, source_run_id=TEXT, run_index=COUNT, comparison_group_id=HASH,
    frozen_group_id=HASH, label_population_id=HASH, status=enum("pending", "complete", "failed", "partial", "cancelled"),
    launch_sha256=HASH, completion_sha256=nullable(HASH), raw_artifact_sha256=nullable(HASH),
    raw_report_count=nullable(COUNT), duplicate_report_count=nullable(COUNT),
    set_size=nullable(COUNT), diagnostic_set_size=nullable(COUNT), subject_ids=IDS,
    first_seen=nullable(COUNT), quality=nullable(QUALITY), triage=nullable(TRIAGE),
    transition=TRANSITION, ror_5=SUMMARY)
MEMBERSHIP = object_schema(
    run_id=TEXT, source_run_id=TEXT, comparison_group_id=HASH, unit=enum("root_cause", "warning"),
    raw_report_id=nullable(TEXT), subject_id=TEXT, included={"type": "boolean"},
    outcome=enum("tp", "fp", "unresolved", "out_of_scope"), evidence_ids=IDS,
    confidence=nullable(CONFIDENCE))
RECURRENCE = object_schema(
    subject_id=TEXT, outcome=enum("tp", "fp", "unresolved", "out_of_scope"),
    run_ids=IDS, frequency=RATIO)
GROUP_METRICS = object_schema(
    comparison_group_id=HASH, frozen_group_id=HASH, group=GROUP, unit=enum("root_cause", "warning"),
    source_run_ids=IDS, included_run_ids=IDS, completed_run_ids=IDS,
    counts=object_schema(attempted=COUNT, complete=COUNT, failed=COUNT, partial=COUNT, cancelled=COUNT,
                         pending=COUNT, completed_empty=COUNT),
    completion_rate=RATIO, empty_run_rate=RATIO, mps=SUMMARY, empty_pair_count=COUNT,
    ror=SUMMARY, distinct=nullable(QUALITY), occurrences=nullable(QUALITY), macro_run_precision=SUMMARY,
    unique_tp_yield=nullable(COUNT), unique_tp_per_completed_run=RATIO, recurrence=array_schema(RECURRENCE, 100000),
    input_tokens=USAGE_TOTAL, output_tokens=USAGE_TOTAL, wall_seconds=USAGE_TOTAL,
    cost=COST_TOTAL, triage=nullable(TRIAGE), open_world_recall=RATIO)
OUTPUT = object_schema(
    schema={"const": OUTPUT_SCHEMA}, experiment_id=TEXT, source_sha256=HASH, source=INPUT,
    matching_snapshot_id=HASH, normalizer_version=TEXT, matching_revision=TEXT,
    label_snapshot_id=HASH, label_revision=TEXT, runs=array_schema(RUN_METRICS, 512),
    groups=array_schema(GROUP_METRICS, 512), membership=array_schema(MEMBERSHIP, 5120000),
    inference=object_schema(status={"const": "not_certified"}, lower_confidence_bound={"type": "null"},
                            reason=enum("not_predeclared", "inference_not_implemented"),
                            pending_bounds={"const": "not_confidence_intervals"},
                            repeated_findings={"const": "not_independent_evidence"}))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def input_schema() -> dict[str, Any]:
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", **deepcopy(INPUT)}


def output_schema() -> dict[str, Any]:
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", **deepcopy(OUTPUT)}


def validate(value: Any, schema: dict[str, Any]) -> None:
    # JSON's finite number/type boundary also rejects NaN/Infinity accepted by Python's decoder.
    try:
        json.dumps(value, allow_nan=False)
    except (ValueError, TypeError) as encoding_error:
        raise ValueError(f"quality document must contain finite JSON values: {encoding_error}") from encoding_error
    errors = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).iter_errors(value)
    error = next(errors, None)
    if error is not None:
        path = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise ValueError(f"invalid quality document at {path}: {error.message}")


def load_experiment(value: Any) -> Experiment:
    validate(value, INPUT)
    return cast(Experiment, deepcopy(value))


def population_id(group: Group) -> str:
    """Truth is conditional on source, scope, positive event and the evaluation unit."""
    return digest({"source_revision": group["source_revision"], "scope_sha256": group["scope_sha256"],
                   "positive_event": group["positive_event"], "task": group["task"],
                   "warning_set_sha256": group["warning_set_sha256"]})


def root_cause_id(group: Group, report: Report) -> str:
    """Conservative exact matching; wording, severity and confidence never change identity."""
    locations = sorted({(row["path"], row["start_line"], row["end_line"]) for row in report["locations"]})
    return digest({"normalizer": NORMALIZER, "source": group["source_revision"], "cwe": report["cwe"],
                   "cause_key": report["cause_key"], "source_symbol": report["source_symbol"],
                   "sink_symbol": report["sink_symbol"], "locations": locations})
