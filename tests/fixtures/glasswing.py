"""Small deterministic experiment inputs, not empirical effectiveness evidence."""
from copy import deepcopy

from appsec_review.observability.experiments.contracts import (
    INPUT_SCHEMA, NORMALIZER, digest, population_id, root_cause_id,
)


def group(**changes):
    return {
        "source_revision": "fixture-source-v1", "scope_sha256": "1" * 64,
        "context_condition": "source_only", "configuration_sha256": "2" * 64,
        "guidance_sha256": "3" * 64, "model_sha256": "4" * 64, "agent_sha256": "5" * 64,
        "tools_sha256": "6" * 64, "decoding_sha256": "7" * 64,
        "normalizer_version": NORMALIZER, "stage": "verified", "task": "discovery",
        "positive_event": "genuine in-scope vulnerability", "warning_set_sha256": None, **changes,
    }


def report(name):
    return {
        "raw_report_id": name, "cwe": "CWE-20", "cause_key": name,
        "source_symbol": "input", "sink_symbol": "consume",
        "locations": [{"path": "fixture.c", "start_line": 1, "end_line": 2}],
        "severity": "high", "confidence": None, "evidence_ids": ["fixture-source:1-2"],
    }


def usage(**changes):
    return {
        "input_tokens": 10, "output_tokens": 5, "wall_seconds": 3, "cost": "2.00",
        "currency": "USD", "cost_kind": "observed", "evidence_ids": ["fixture-usage-receipt"],
        "missing_reason": None, **changes,
    }


def experiment(sets, *, groups=None, outcomes=None):
    groups = groups or [group() for _ in sets]
    launches, completions = [], []
    for index, (names, identity) in enumerate(zip(sets, groups, strict=True), 1):
        run_id = f"run-{index}"
        launches.append({
            "run_id": run_id, "source_run_id": f"source-{index}", "run_index": index,
            "started_at": f"2026-11-06T00:{index:02d}:00Z", "group": deepcopy(identity),
        })
        if names == "pending":
            continue
        status = names if isinstance(names, str) else "complete"
        completions.append({
            "run_id": run_id, "status": status, "completed_at": f"2026-11-06T01:{index:02d}:00Z",
            "raw_artifact_sha256": digest({"fixture": names, "run_id": run_id}),
            "reports": [] if isinstance(names, str) else [report(name) for name in names],
            "decisions": [], "usage": usage(), "coverage": [],
            "error_ids": [] if status == "complete" else [f"fixture-{status}"],
        })
    matching = {"schema": "appsec-review/quality-matching/1", "revision": "matching-1",
                "normalizer_version": NORMALIZER, "overrides": []}
    document = {
        "schema": INPUT_SCHEMA, "experiment_id": "synthetic-fixture", "launches": launches,
        "completions": completions, "warning_sets": [], "matching": matching,
        "adjudications": {"schema": "appsec-review/quality-adjudications/1", "revision": "labels-1",
                         "matching_snapshot_id": digest(matching), "labels": []},
        "inference_policy": None,
    }
    for identity in groups:
        for name, outcome in (outcomes or {}).items():
            add_label(document, identity, root_cause_id(identity, report(name)), outcome)
    return document


def add_label(document, identity, subject_id, outcome):
    label = {
        "population_id": population_id(identity), "subject_id": subject_id, "outcome": outcome,
        "is_real_bug": True if outcome == "tp" else False if outcome == "fp" else None,
        "is_rank1_critical": None, "adjudicator_id": "fixture-independent-reviewer",
        "method": "independent_human", "evidence_ids": ["fixture-adjudication"],
        "adjudicated_at": "2026-11-06T02:00:00Z",
    }
    if label not in document["adjudications"]["labels"]:
        document["adjudications"]["labels"].append(label)


def triage_experiment():
    warning_ids = ["f1", "f2", "f3", "t1", "t2", "t3", "u"]
    warning_set = {"warning_ids": warning_ids}
    identity = group(task="triage", warning_set_sha256=digest(warning_set))
    document = experiment([[]], groups=[identity])
    document["warning_sets"] = [{"warning_set_sha256": digest(warning_set), **warning_set}]
    document["completions"][0]["decisions"] = [
        {"warning_id": warning, "decision": decision} for warning, decision in (
            ("t1", "retain"), ("t2", "reject"), ("t3", "abstain"),
            ("f1", "retain"), ("f2", "reject"), ("f3", "abstain"), ("u", "retain"))
    ]
    for warning in warning_ids:
        if warning != "u":
            add_label(document, identity, warning, "tp" if warning.startswith("t") else "fp")
    return document
