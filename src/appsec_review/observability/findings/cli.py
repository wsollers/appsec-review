"""Operator entry point of the finding-metrics domain: ``python -m appsec_review.observability.findings``.

Offline, derived commands. None launches a review, calls a model, contacts a crash
service or reads a target:

* ``snapshot``     read one accepted run and publish its ``finding-snapshot/1`` into a history store;
                   without ``--units`` the reviewed source files are derived from the run
* ``scorecard``    build and print the scorecard of one stored snapshot from whatever independent
                   inputs are supplied (answer key, prior run, outcomes, leads, crash evidence, ...);
                   with ``--run`` the lead records, their key labels and the entry-point catalogue
                   are derived from the run
* ``crash-ingest`` parse operator-exported crash files into a content-addressed ``crash-evidence/1``
* ``audit-sample`` draw the reproducible sample of removed leads for human labelling
* ``decision-audit`` query one accepted protected audit using closed, bounded operator templates

Exit status: 0 on success, 2 for an unusable input (named on stderr). A figure that cannot be
computed is printed as ``n/a`` with its reason; it never changes the exit status.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
from pathlib import Path
import sys
from typing import Any

from appsec_review.storage import canonical_json

from . import coverage_adapter, history, labels, lead_adapter, lifecycle, run_adapter, scorecard, slices
from .crash import bind_all, corroborate, ingest, metrics as crash_metrics, missed_buckets, publish_evidence

UNITS_SCHEMA = "appsec-review/reviewed-units/1"
MAX_INPUT_BYTES = 64 * 1024 * 1024


def _read_json(path: Path) -> Any:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"{path.name} exceeds the input size bound")
    return json.loads(path.read_text(encoding="utf-8"))


def _units(path: Path | None) -> tuple[dict[str, Any] | None, dict[str, str] | None]:
    if path is None:
        return None, None
    document = _read_json(path)
    if (not isinstance(document, Mapping) or document.get("schema") != UNITS_SCHEMA
            or set(document) != {"schema", "reviewed", "unreviewed"}
            or not isinstance(document["reviewed"], Mapping) or not isinstance(document["unreviewed"], Mapping)):
        raise ValueError(f"{path.name} is not a {UNITS_SCHEMA} document")
    return dict(document["reviewed"]), dict(document["unreviewed"])


def _snapshot(args: argparse.Namespace) -> int:
    reviewed, unreviewed = _units(args.units)
    unit_gaps: list[str] = []
    if args.units is None:
        derived = coverage_adapter.coverage_from_run(args.run, loader=coverage_adapter.load_coverage_documents)
        reviewed, unreviewed, unit_gaps = derived["reviewed"], derived["unreviewed"], derived["unit_gaps"]
    rules = slices.load_rules(_read_json(args.slice_rules)) if args.slice_rules else None
    built = run_adapter.snapshot_from_run(
        args.run, target_id=args.target_id, source_revision=args.source_revision, reviewed_units=reviewed,
        unreviewed_units=unreviewed, annotate=(lambda record: slices.annotate(record, rules)) if rules else None,
        loader=run_adapter.load_run, unit_gaps=unit_gaps)
    receipt = history.publish_snapshot(args.history, built)
    print(json.dumps({**receipt, "run_id": built["run_id"], "findings": len(built["findings"]),
                      "gaps": built["gaps"], "slice_rules_sha256": rules.sha256 if rules else None}, sort_keys=True))
    return 0


def _stored(root: Path, target_id: str, run_id: str, stage: str) -> tuple[dict[str, Any], dict[str, Any]]:
    loaded = history.load_history(root, target_id)
    matches = [row["sha256"] for row in loaded["snapshots"] if row["run_id"] == run_id and row["stage"] == stage]
    if len(matches) != 1:
        raise ValueError(f"history holds {len(matches)} {stage} snapshots of run {run_id!r}; publish one first")
    return loaded, history.read_snapshot(root, target_id, matches[0])


def _crash(args: argparse.Namespace, snapshot: Mapping[str, Any]) -> tuple[dict[str, Any] | None, Any]:
    if args.crash_evidence is None:
        return None, None
    evidence = _read_json(args.crash_evidence)
    reviewed = snapshot["reviewed_units"]
    bindings = bind_all(evidence, debug_ids=frozenset(args.debug_id), revision=args.crash_revision,
                        known_functions={location["function"] for item in snapshot["findings"]
                                         for location in item["locations"] if location["function"]} or None,
                        known_paths=None if reviewed is None else frozenset(reviewed))
    corroboration = corroborate(snapshot, evidence, bindings)
    return (crash_metrics(evidence, bindings, corroboration, missed_buckets(snapshot, evidence, bindings)),
            corroboration["labels"])


def _scorecard(args: argparse.Namespace) -> int:
    loaded, snapshot = _stored(args.history, args.target_id, args.run_id, "published")
    classified = None
    if args.prior_run_id != "none":
        prior_sha = (history.latest_prior(loaded, stage="published", before_run_id=args.run_id)
                     if args.prior_run_id is None else
                     next((row["sha256"] for row in loaded["snapshots"]
                           if row["run_id"] == args.prior_run_id and row["stage"] == "published"), None))
        if args.prior_run_id is not None and prior_sha is None:
            raise ValueError(f"history holds no published snapshot of prior run {args.prior_run_id!r}")
        if prior_sha is not None:
            classified = lifecycle.classify(history.read_snapshot(args.history, args.target_id, prior_sha), snapshot,
                                            previously_fixed=history.previously_fixed(loaded))
    key = None
    if args.key is not None:
        from appsec_review.acceptance.scoring import load_scoring_key
        key = load_scoring_key(args.key)
    outcomes = None
    if args.outcomes is not None:
        if args.as_of is None:
            raise ValueError("--outcomes needs --as-of (the evaluation date); the clock is never read")
        outcomes = labels.admit_outcomes(_read_json(args.outcomes), as_of=args.as_of)
    triage_section = None
    if args.run_summary is not None:
        triage_section = _read_json(args.run_summary).get("triage_reduction")
    crash, crash_labels = _crash(args, snapshot)
    leads = _read_json(args.leads) if args.leads else None
    lead_labels = _read_json(args.lead_labels) if args.lead_labels else None
    input_gaps: list[str] = []
    if args.run is not None:
        if args.leads is not None or args.lead_labels is not None:
            raise ValueError("--run derives the lead records and labels; give it or --leads/--lead-labels, not both")
        if args.run.name != args.run_id:
            raise ValueError(f"--run names run {args.run.name!r}, not --run-id {args.run_id!r}")
        derived = lead_adapter.leads_from_run(args.run, key=key, loader=lead_adapter.load_lead_documents)
        leads, lead_labels = derived["leads"], derived["labels"]
        input_gaps.extend(derived["gaps"])
    entry_points = _read_json(args.entry_points) if args.entry_points else None
    if args.run is not None and args.entry_points is None:
        coverage = coverage_adapter.coverage_from_run(args.run, loader=coverage_adapter.load_coverage_documents)
        entry_points = coverage["entry_points"]
        input_gaps.extend(coverage["entry_gaps"])
    inputs = scorecard.Inputs(
        triage_reduction=triage_section, leads=leads, lead_labels=lead_labels, input_gaps=tuple(input_gaps),
        answer_key=key, outcomes=outcomes, lifecycle=classified,
        ages=history.ages(loaded) if classified is not None else None,
        entry_points=entry_points,
        crash=crash, crash_labels=crash_labels, reviewed_kloc=args.reviewed_kloc, budget=args.budget)
    document = scorecard.build(snapshot, inputs)
    if args.output is not None:
        args.output.write_bytes(canonical_json(document))
    print(json.dumps(document, indent=1, sort_keys=True) if args.json
          else "\n".join(scorecard.render_lines(document)))
    return 0


def _crash_ingest(args: argparse.Namespace) -> int:
    sources = []
    for item in args.source:
        adapter, separator, name = item.partition("=")
        if not separator or not adapter or not name:
            raise ValueError("--source takes ADAPTER=PATH")
        path = Path(name)
        files = sorted(entry for entry in path.iterdir() if entry.is_file()) if path.is_dir() else [path]
        for entry in files:
            if entry.is_symlink() or not entry.is_file():
                raise ValueError("a crash source must be a regular file, not a link")
            if entry.stat().st_size > MAX_INPUT_BYTES:
                raise ValueError("a crash source exceeds the input size bound")
            sources.append((adapter, entry.name, entry.read_bytes()))
    evidence = ingest(sources, roots=tuple(args.strip_root))
    receipt = publish_evidence(args.output, evidence)
    print(json.dumps({**receipt, "counts": evidence["counts"]}, sort_keys=True))
    return 0


def _audit_sample(args: argparse.Namespace) -> int:
    sample = labels.export_audit_sample(_read_json(args.leads), seed=args.seed, size=args.size)
    if args.output.exists():
        raise ValueError(f"{args.output.name} already exists; a drawn sample is never overwritten")
    args.output.write_bytes(canonical_json(sample))
    print(json.dumps({"eligible": sample["eligible"], "sampled": len(sample["sample"]),
                      "sample_sha256": sample["sample_sha256"]}, sort_keys=True))
    return 0


def _decision_audit(args: argparse.Namespace) -> int:
    from appsec_review.review.decision_audit.query import Query, execute
    from appsec_review.review.decision_audit.reader import load_decision_audit
    query = Query(args.template, lead_id=args.lead_id, claim_id=args.claim_id,
                  predicate=args.predicate, stage=args.stage, role=args.role)
    audit = load_decision_audit(args.run)
    print(json.dumps(execute(audit, query, limit=args.limit, cursor=args.cursor), sort_keys=True, indent=1))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="python -m appsec_review.observability.findings",
                                   description="Finding metrics: offline, derived, reported and never asserted.")
    commands = root.add_subparsers(dest="command", required=True)

    snapshot = commands.add_parser("snapshot", help="publish one accepted run's finding snapshot")
    snapshot.add_argument("--run", type=Path, required=True, help="run directory (runs/<run-id>)")
    snapshot.add_argument("--target-id", required=True, help="stable target name, [a-z0-9][a-z0-9._-]*")
    snapshot.add_argument("--source-revision", required=True, help="the reviewed commit or changelist")
    snapshot.add_argument("--history", type=Path, required=True, help="finding-history store root")
    snapshot.add_argument("--units", type=Path, help=f"{UNITS_SCHEMA} file: units reviewed and not reviewed; "
                                                     "default: derived from the run")
    snapshot.add_argument("--slice-rules", type=Path, help="finding-slice-rules/1 file for ownership and build slices")
    snapshot.set_defaults(handler=_snapshot)

    card = commands.add_parser("scorecard", help="print the scorecard of one stored snapshot")
    card.add_argument("--history", type=Path, required=True)
    card.add_argument("--target-id", required=True)
    card.add_argument("--run-id", required=True)
    card.add_argument("--prior-run-id", help="prior run to compare with; default the latest earlier run; "
                                             "'none' to skip the comparison")
    card.add_argument("--key", type=Path, help="answer key (expectations.toml) for a corpus run")
    card.add_argument("--run-summary", type=Path, help="the run's telemetry summary.json (triage_reduction section)")
    card.add_argument("--run", type=Path, help="run directory (runs/<run-id>): derive the lead records, and with "
                                               "--key their labels, from the run instead of --leads/--lead-labels; "
                                               "also the entry-point catalogue unless --entry-points is given")
    card.add_argument("--leads", type=Path, help="lead records for labelled triage effectiveness")
    card.add_argument("--lead-labels", type=Path)
    card.add_argument("--outcomes", type=Path, help="developer-outcomes/1 file")
    card.add_argument("--as-of", help="evaluation date (YYYY-MM-DD) for outcome expiry")
    card.add_argument("--entry-points", type=Path, help="entry-point catalogue with review status")
    card.add_argument("--crash-evidence", type=Path, help="crash-evidence/1 file from crash-ingest")
    card.add_argument("--debug-id", action="append", default=[], help="debug identifier of the reviewed build")
    card.add_argument("--crash-revision", help="version or changelist of the reviewed build, as crashes record it")
    card.add_argument("--reviewed-kloc", type=float)
    card.add_argument("--budget", type=int, default=scorecard.DEFAULT_BUDGET)
    card.add_argument("--json", action="store_true", help="print the finding-metrics/1 document")
    card.add_argument("--output", type=Path, help="also write the canonical document here")
    card.set_defaults(handler=_scorecard)

    crash = commands.add_parser("crash-ingest", help="parse exported crash files; no network, no raw dumps kept")
    crash.add_argument("--source", action="append", required=True, metavar="ADAPTER=PATH",
                       help="an exported file or a directory of them, with the adapter that reads it")
    crash.add_argument("--strip-root", action="append", default=[], help="build-machine path prefix to remove")
    crash.add_argument("--output", type=Path, required=True, help="directory for the content-addressed evidence")
    crash.set_defaults(handler=_crash_ingest)

    audit = commands.add_parser("audit-sample", help="draw the reproducible audit sample of removed leads")
    audit.add_argument("--leads", type=Path, required=True)
    audit.add_argument("--seed", required=True)
    audit.add_argument("--size", type=int, required=True)
    audit.add_argument("--output", type=Path, required=True)
    audit.set_defaults(handler=_audit_sample)

    from appsec_review.review.decision_audit.contracts import Stage
    from appsec_review.review.decision_audit.query import Template
    from appsec_review.review.models import Predicate, Role
    decisions = commands.add_parser("decision-audit", help="bounded protected operator query; not a worker grant")
    decisions.add_argument("--run", type=Path, required=True, help="accepted run directory, never a manifest path")
    decisions.add_argument("--template", choices=[item.value for item in Template], required=True)
    decisions.add_argument("--lead-id")
    decisions.add_argument("--claim-id")
    decisions.add_argument("--predicate", choices=[item.value for item in Predicate])
    decisions.add_argument("--stage", choices=[item.value for item in Stage])
    decisions.add_argument("--role", choices=[item.value for item in Role],
                           help="record attribution filter only; does not authorize access")
    decisions.add_argument("--limit", type=int, help="bounded by accepted policy max_page_size")
    decisions.add_argument("--cursor", help="continuation from this exact accepted manifest and query")
    decisions.set_defaults(handler=_decision_audit)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.handler(args)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        # RuntimeError covers the verified readers' integrity errors: an unverifiable run is named,
        # never turned into an empty snapshot.
        print(f"finding-metrics: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


__all__ = ["MAX_INPUT_BYTES", "UNITS_SCHEMA", "main", "parser"]
