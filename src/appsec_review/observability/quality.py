"""Immutable, revision-bound quality observations derived from existing offline scorers."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from appsec_review.acceptance.scoring_model import SCORING_SCHEMA
from appsec_review.review.evaluation import REPORT_SCHEMA, score
from appsec_review.review.identity import sha256_hex
from appsec_review.storage import canonical_json, protected_json

SCHEMA = "appsec-review/quality-trend/1"
_IDENTITIES = ("corpus", "configuration", "prompts", "model")


def _ratio(numerator: int, denominator: int) -> dict[str, Any]:
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else None,
            "status": "measured" if denominator else "empty_denominator"}


def _identity(implementation_sha: str, identities: Mapping[str, Any]) -> dict[str, Any]:
    if not re.fullmatch("[0-9a-f]{40}", implementation_sha):
        raise ValueError("quality artifact requires an implementation commit SHA")
    values = {key: identities.get(key) for key in _IDENTITIES}
    for key, value in values.items():
        if value is not None and (not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value)):
            raise ValueError(f"invalid quality identity: {key}")
    return {"implementation_sha": implementation_sha, **values}


def evaluation_trend(report: Mapping[str, Any], cases: Sequence[Mapping[str, Any]], *,
                     variant: str, implementation_sha: str,
                     model_sha256: str | None = None) -> dict[str, Any]:
    if report.get("schema") != REPORT_SCHEMA or report.get("cases_sha256") != sha256_hex(cases):
        raise ValueError("evaluation report schema or corpus identity mismatch")
    if len(cases) > 128 or variant not in report.get("variants", {}):
        raise ValueError("unknown variant or unbounded case corpus")
    if not cases or len({case["id"] for case in cases}) != len(cases):
        raise ValueError("empty or duplicate evaluation corpus")
    rows = report["variants"][variant]["rows"]
    metrics = score(cases, rows, report["role"])
    guidance = [row.get("guidance_sha256") for row in rows]
    prompts = sha256_hex(sorted(set(guidance))) if guidance and all(
        isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) for value in guidance) else None
    identities = _identity(implementation_sha, {
        "corpus": report["cases_sha256"], "configuration": report.get("settings_sha256"),
        "prompts": prompts, "model": model_sha256,
    })
    predicted = [row for row in rows if row["status"] == "completed" and row["decision"] == "vulnerable"]
    metrics["precision"] = _ratio(sum(bool(row["correct"]) for row in predicted), len(predicted))
    metrics["precision_semantics"] = "case_resolution_precision_not_findings_precision"
    metrics["retrieval_failure"] = {"value": None, "status": "not_measured_by_single_turn_evaluator"}
    return {"schema": SCHEMA, "identity": identities, "source_schema": REPORT_SCHEMA,
            "source_sha256": hashlib.sha256(canonical_json(report)).hexdigest(),
            "role": report["role"], "variant": variant, "case_count": len(cases),
            "status": "missing_results" if metrics["gaps"] else "complete",
            "metrics": metrics}


def acceptance_trend(report: Mapping[str, Any], *, producer: str, implementation_sha: str,
                     identities: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("schema") != SCORING_SCHEMA:
        raise ValueError("unsupported acceptance scoring schema")
    matches = [row for row in report.get("producers", []) if row["producer"] == producer]
    if len(matches) != 1:
        raise ValueError("missing or duplicate producer score")
    row = matches[0]
    case_ids = [case["id"] for case in report["cases"]]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("duplicate acceptance case identities")
    return {
        "schema": SCHEMA, "identity": _identity(implementation_sha, identities),
        "source_schema": SCORING_SCHEMA, "source_sha256": hashlib.sha256(canonical_json(report)).hexdigest(),
        "role": producer, "variant": "acceptance", "case_count": len(case_ids),
        "status": "missing_results" if report.get("gaps") else "complete",
        "metrics": {"precision": _ratio(row["tp"], row["tp"] + row["fp"]),
                    "recall": _ratio(row["tp"], row["tp"] + row["fn"]),
                    "abstention_precision": None, "unsupported_conclusion_rate": None,
                    "retrieval_failure": None, "usage_complete": False,
                    "unavailable_reason": "not_measured_by_acceptance_scorer"},
    }


def competence_trend(report: Mapping[str, Any], cases: Sequence[Mapping[str, Any]], *,
                     implementation_sha: str) -> dict[str, Any]:
    """Adapt published multi-turn results without rerunning or replacing their evaluator."""
    from appsec_review.review.competence import REPORT_SCHEMA as COMPETENCE_SCHEMA, ROLE

    if (report.get("schema") != COMPETENCE_SCHEMA or report.get("execution") not in {"scripted", "live"}
            or report.get("role") != ROLE.value):
        raise ValueError("unsupported competence report schema or execution mode")
    rows = report.get("rows")
    if not isinstance(rows, list) or len(rows) > 128:
        raise ValueError("competence rows must be a bounded list")
    model = report.get("model")
    mode = "competence-" + report["execution"]
    adapted = {"schema": REPORT_SCHEMA, "role": report["role"], "cases_sha256": report["cases_sha256"],
               "settings_sha256": report.get("configuration_sha256") or report.get("settings_sha256"),
               "variants": {mode: {"rows": rows}}}
    result = evaluation_trend(adapted, cases, variant=mode, implementation_sha=implementation_sha,
                              model_sha256=sha256_hex(model) if isinstance(model, Mapping) and model else None)
    result.update(source_schema=COMPETENCE_SCHEMA,
                  source_sha256=hashlib.sha256(canonical_json(report)).hexdigest(),
                  execution=report["execution"])
    for field in ("queries", "denials"):
        values = [row.get("counts", {}).get(field) for row in rows]
        known = bool(rows) and len(rows) == len(cases) and all(type(value) is int and value >= 0 for value in values)
        result["metrics"]["retrieval_" + field] = {
            "value": sum(values) if known else None, "status": "measured" if known else "unavailable"}
    result["metrics"]["retrieval_failure"] = {
        "value": None, "status": "not_separately_measured; denials_are_not_failures"}
    if any(row.get("settings_sha256") not in {None, report.get("settings_sha256")} for row in rows):
        result["identity"]["configuration"] = None
        result["status"] = "mixed_configuration_identities"
    return result


def publish_trend(directory: Path, trend: Mapping[str, Any]) -> dict[str, str]:
    if trend.get("schema") != SCHEMA:
        raise ValueError("unsupported quality trend schema")
    digest = hashlib.sha256(canonical_json(trend)).hexdigest()
    path = Path(directory) / (digest + ".json")
    try:
        protected_json(path, trend)
    except FileExistsError:
        if path.read_bytes() != canonical_json(trend):
            raise ValueError("quality artifact identity collision")
        return {"status": "duplicate", "sha256": digest, "path": str(path)}
    return {"status": "published", "sha256": digest, "path": str(path)}


# Identities that fix WHAT was measured: two observations are comparable only when these agree.
_FIXED = ("role", "variant", "case_count", "source_schema")
# Identities that are the independent variables of a comparison: a change is named, not refused.
_VARIABLES = ("implementation_sha", "configuration", "prompts", "model")
_LOWER_IS_BETTER = frozenset({"unsupported_conclusion_rate", "duplicate_rate"})
_THRESHOLD_METRICS = frozenset({"precision", "recall", "abstention_precision", "abstention_recall",
                                "unsupported_conclusion_rate", "duplicate_rate"})


def _result(status: str, *, changed: Sequence[str] = (), unknown: Sequence[str] = (),
            checks: Mapping[str, str] | None = None, deltas: Mapping[str, Any] | None = None,
            reason: str | None = None) -> dict[str, Any]:
    return {"status": status, "reason": reason, "changed": list(changed), "unknown": list(unknown),
            "checks": dict(checks or {}), "deltas": dict(deltas or {})}


def compare_trends(baseline: Mapping[str, Any], candidate: Mapping[str, Any], *,
                   thresholds: Mapping[str, float]) -> dict[str, Any]:
    """Compare two observations of the same corpus, naming what changed between them.

    Comparable means the same corpus, role, variant, case count and scorer (``source_schema``).
    The implementation commit and the configuration, prompt and model identities are the independent
    variables: a difference is reported in ``changed`` and the comparison proceeds, so a prompt or
    model change can be judged. An identity that is unknown on either side is listed in ``unknown``;
    it is neither equal nor different, and the caller must not attribute a delta to it.

    ``status`` is ``duplicate``, ``incomparable`` (with ``reason``), ``missing_results``,
    ``regression``, ``incomplete`` or ``passed``. ``deltas`` holds ``candidate - baseline`` per
    thresholded metric, ``None`` when either side is unavailable.
    """
    for trend in (baseline, candidate):
        if trend.get("schema") != SCHEMA:
            raise ValueError("unsupported quality trend schema")
    for metric, maximum_regression in thresholds.items():
        if (metric not in _THRESHOLD_METRICS or type(maximum_regression) not in (int, float)
                or not 0 <= maximum_regression <= 1):
            raise ValueError("invalid deterministic regression threshold")
    if canonical_json(baseline) == canonical_json(candidate):
        return _result("duplicate")
    left, right = baseline["identity"], candidate["identity"]
    if not left.get("corpus") or left.get("corpus") != right.get("corpus"):
        return _result("incomparable", reason="corpus_differs_or_unknown")
    differing = [key for key in _FIXED if baseline.get(key) != candidate.get(key)]
    if differing:
        return _result("incomparable", reason="differs:" + ",".join(differing))
    if "mixed_configuration_identities" in (baseline["status"], candidate["status"]):
        return _result("incomparable", reason="mixed_configuration_identities")
    unknown = [key for key in _VARIABLES if not left.get(key) or not right.get(key)]
    changed = [key for key in _VARIABLES if key not in unknown and left[key] != right[key]]
    if baseline["status"] != "complete" or candidate["status"] != "complete":
        return _result("missing_results", changed=changed, unknown=unknown)
    checks, deltas = {}, {}
    for metric, maximum_regression in sorted(thresholds.items()):
        a, b = baseline["metrics"].get(metric), candidate["metrics"].get(metric)
        a, b = a.get("value") if isinstance(a, Mapping) else None, b.get("value") if isinstance(b, Mapping) else None
        if a is None or b is None:
            checks[metric], deltas[metric] = "unavailable_or_empty_denominator", None
        else:
            regression = b - a if metric in _LOWER_IS_BETTER else a - b
            checks[metric] = "passed" if regression <= maximum_regression else "regression"
            deltas[metric] = b - a
    status = "regression" if "regression" in checks.values() else (
        "incomplete" if not checks or any(value != "passed" for value in checks.values()) else "passed")
    return _result(status, changed=changed, unknown=unknown, checks=checks, deltas=deltas)


def run_identities(run_root: Path) -> dict[str, str | None]:
    """Configuration and prompt identities read from a run's own frozen records.

    ``configuration`` is the SHA-256 the run's configuration manifest records for ``resolved.json``,
    re-checked against the file; ``prompts`` hashes the sorted guidance-bundle identities pinned under
    ``data/guidance``. An absent or inconsistent record yields ``None`` for that identity, never a guess.
    """
    run_root = Path(run_root)
    identities: dict[str, str | None] = {"configuration": None, "prompts": None}
    configuration = run_root / "data" / "configuration"
    try:
        recorded = json.loads((configuration / "manifest.json").read_text(encoding="utf-8")).get("resolved_sha256")
        actual = hashlib.sha256((configuration / "resolved.json").read_bytes()).hexdigest()
        if isinstance(recorded, str) and recorded == actual:
            identities["configuration"] = actual
    except (OSError, ValueError, AttributeError):
        pass
    guidance = run_root / "data" / "guidance"
    if guidance.is_dir():
        bundles = sorted(item.name for item in guidance.iterdir()
                         if item.is_dir() and re.fullmatch("[0-9a-f]{64}", item.name))
        if bundles:
            identities["prompts"] = sha256_hex(bundles)
    return identities


def check_supplied_identities(supplied: Mapping[str, Any], recorded: Mapping[str, str | None]) -> None:
    """A supplied identity that contradicts the run's own record is an error, not an annotation."""
    for key, value in sorted(recorded.items()):
        given = supplied.get(key)
        if value is not None and given is not None and given != value:
            raise ValueError(f"supplied {key} identity does not match the run's frozen record")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--implementation-sha", required=True)
    parser.add_argument("--model-sha256")
    parser.add_argument("--variant", default="full")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run", type=Path,
                        help="run directory whose frozen configuration and guidance identities must agree "
                             "with the report's recorded identities")
    args = parser.parse_args(argv)
    report = json.loads(args.report.read_text())
    cases = json.loads(args.cases.read_text())["cases"]
    if report.get("schema") == REPORT_SCHEMA:
        result = evaluation_trend(report, cases, variant=args.variant,
                                  implementation_sha=args.implementation_sha, model_sha256=args.model_sha256)
    else:
        result = competence_trend(report, cases, implementation_sha=args.implementation_sha)
        if args.model_sha256 and args.model_sha256 != result["identity"]["model"]:
            parser.error("model identity assertion does not match the recorded competence model")
    if args.run is not None:
        try:
            check_supplied_identities(result["identity"], run_identities(args.run))
        except ValueError as error:
            parser.error(str(error))
    print(json.dumps(publish_trend(args.output, result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
