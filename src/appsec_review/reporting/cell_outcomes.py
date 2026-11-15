"""Per-role cell outcomes and model-call durations of an inference security review run (T-5028, step one).

Reads three run-owned sources and changes nothing but the optional output file:

* the sealed lane ledgers (``steps/<lane>/tasks/teams/ledger.jsonl``) for each cell's role, task, lane and
  package, from its ``cell_terminal`` record;
* every cell attempt receipt (``cells/<cell-id>/attempt-N.json``) for the attempt's status, the reason it
  ended, its turn, query and token counts and the retrieval tool errors its turns recorded;
* every model execution receipt (``data/inference-executions/*/*/*.json``) for wall time per model call by
  outcome and failure code.

A cell whose lane has not sealed yet has no ledger record; its attempts are counted under the role
``unattributed`` so a partial run still reports honestly. Nothing here is evidence about the target: the
report describes where the run spent its cells.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA = "appsec-review/cell-outcomes/1"
REVIEW_JOB = "job_inference_security_review"
UNATTRIBUTED = "unattributed"


def _quantiles(values: Sequence[float]) -> dict[str, float]:
    if not values:
        return {"n": 0}
    ordered = sorted(values)
    pick = lambda q: ordered[min(len(ordered) - 1, int(len(ordered) * q))]  # noqa: E731
    return {"n": len(ordered), "p50": pick(0.5), "p90": pick(0.9), "max": ordered[-1],
            "sum": round(sum(ordered), 3)}


def _ledger_cells(attempt_root: Path) -> dict[str, dict[str, Any]]:
    cells: dict[str, dict[str, Any]] = {}
    for ledger in sorted(attempt_root.glob("steps/*/tasks/teams/ledger.jsonl")):
        with ledger.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                record = json.loads(line)
                body = record.get("body", record)
                if (record.get("kind") or body.get("kind")) != "cell_terminal":
                    continue
                cell = body["cell"]
                cells[cell["cell_id"]] = {"role": cell.get("role"), "task": cell.get("task"), "lane": cell.get("lane"),
                                          "package_id": cell.get("package_id"), "status": cell.get("status")}
    return cells


def _attempt_receipts(job_root: Path):
    for path in sorted(job_root.glob("cells/*/attempt-*.json")):
        yield json.loads(path.read_text(encoding="utf-8"))


def _execution_receipts(run_root: Path):
    for path in sorted((run_root / "data" / "inference-executions").glob("*/*/*.json")):
        yield json.loads(path.read_text(encoding="utf-8"))


def summarize(run_root: Path, attempt_id: str = "attempt_0001") -> dict[str, Any]:
    """Build the report document for ``run_root`` (``runs/<run-id>``)."""
    run_root = Path(run_root)
    job_root = run_root / "data" / "jobs" / REVIEW_JOB
    attempt_root = job_root / "attempts" / attempt_id
    ledger = _ledger_cells(attempt_root)

    roles: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "attempts": 0, "cells": set(), "outcomes": Counter(), "reasons": Counter(), "output_tokens": 0,
        "turns": [], "queries": [], "retrieval_errors": Counter()})
    packages: dict[str, Counter] = defaultdict(Counter)
    for receipt in _attempt_receipts(job_root):
        cell_id = receipt["cell_id"]
        meta = ledger.get(cell_id)
        role = (meta or {}).get("role") or UNATTRIBUTED
        bucket = roles[role]
        bucket["attempts"] += 1
        bucket["cells"].add(cell_id)
        status = receipt.get("status") or "unknown"
        bucket["outcomes"][status] += 1
        if status != "succeeded":
            bucket["reasons"][receipt.get("reason") or receipt.get("gap_class") or status] += 1
        counts = receipt.get("counts") or {}
        bucket["output_tokens"] += int(counts.get("output_tokens") or 0)
        bucket["turns"].append(int(counts.get("turns") or len(receipt.get("turns") or [])))
        bucket["queries"].append(int(counts.get("queries") or 0))
        for turn in receipt.get("turns") or []:
            for retrieval in turn.get("retrievals") or []:
                if retrieval.get("status") == "tool_error":
                    bucket["retrieval_errors"][f"{retrieval.get('tool')}:{retrieval.get('error_class')}"] += 1
        if meta:
            packages[meta["package_id"]][status] += 1

    executions: dict[str, list[float]] = defaultdict(list)
    failure_codes: Counter = Counter()
    models: Counter = Counter()
    for receipt in _execution_receipts(run_root):
        executions[receipt.get("status") or "unknown"].append(float(receipt.get("elapsed_ms") or 0) / 1000.0)
        if receipt.get("failure_code"):
            failure_codes[receipt["failure_code"]] += 1
        models[f"{receipt.get('served_provider')}/{receipt.get('served_model')}"] += 1

    def _role_document(bucket: dict[str, Any]) -> dict[str, Any]:
        return {"attempts": bucket["attempts"], "cells": len(bucket["cells"]),
                "outcomes": dict(sorted(bucket["outcomes"].items())),
                "reasons": dict(bucket["reasons"].most_common()),
                "output_tokens": bucket["output_tokens"],
                "turns": _quantiles(bucket["turns"]), "queries": _quantiles(bucket["queries"]),
                "retrieval_errors": dict(bucket["retrieval_errors"].most_common())}

    return {
        "schema": SCHEMA,
        "run_id": run_root.name,
        "attempt_id": attempt_id,
        "ledger_cells": len(ledger),
        "roles": {role: _role_document(bucket) for role, bucket in sorted(roles.items())},
        "packages": {"count": len(packages),
                     "attempts_per_package": _quantiles([sum(c.values()) for c in packages.values()]),
                     "succeeded_per_package": _quantiles([c.get("succeeded", 0) for c in packages.values()]),
                     "without_success": sum(1 for c in packages.values() if not c.get("succeeded"))},
        "model_calls": {"by_status": {status: _quantiles(values) for status, values in sorted(executions.items())},
                        "failure_codes": dict(failure_codes.most_common()),
                        "served": dict(models.most_common())},
    }


def render(document: Mapping[str, Any]) -> str:
    lines = [f"cell outcomes for {document['run_id']} ({document['attempt_id']}); ledger cells {document['ledger_cells']}"]
    for role, info in document["roles"].items():
        outcomes = ", ".join(f"{k} {v}" for k, v in info["outcomes"].items())
        lines.append(f"  {role}: {info['attempts']} attempts over {info['cells']} cells; {outcomes}; "
                     f"output tokens {info['output_tokens']}; turns p50 {info['turns'].get('p50', 0)} "
                     f"p90 {info['turns'].get('p90', 0)}")
        for reason, count in list(info["reasons"].items())[:6]:
            lines.append(f"      {count:5d} {reason}")
        for error, count in list(info["retrieval_errors"].items())[:4]:
            lines.append(f"      {count:5d} retrieval tool_error {error}")
    pk = document["packages"]
    lines.append(f"  packages {pk['count']}; attempts per package p50 {pk['attempts_per_package'].get('p50', 0)} "
                 f"max {pk['attempts_per_package'].get('max', 0)}; packages without a succeeded cell {pk['without_success']}")
    for status, q in document["model_calls"]["by_status"].items():
        lines.append(f"  model calls {status}: n {q['n']} p50 {q.get('p50', 0):.0f}s p90 {q.get('p90', 0):.0f}s "
                     f"max {q.get('max', 0):.0f}s total {q.get('sum', 0) / 3600:.1f}h")
    if document["model_calls"]["failure_codes"]:
        lines.append("  failure codes: " + ", ".join(f"{k} {v}" for k, v in document["model_calls"]["failure_codes"].items()))
    lines.append("  served: " + ", ".join(f"{k} {v}" for k, v in document["model_calls"]["served"].items()))
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="cell-outcomes", description=__doc__.splitlines()[0])
    parser.add_argument("--run", required=True, help="run directory, e.g. runs/2026-11-15-0005")
    parser.add_argument("--attempt", default="attempt_0001")
    parser.add_argument("--write", action="store_true",
                        help="also write data/verification/cell-outcomes.json and .txt under the run")
    args = parser.parse_args(argv)
    run_root = Path(args.run)
    if not (run_root / "data" / "jobs" / REVIEW_JOB).is_dir():
        parser.error(f"{run_root} has no {REVIEW_JOB} data")
    document = summarize(run_root, args.attempt)
    text = render(document)
    if args.write:
        out = run_root / "data" / "verification"
        out.mkdir(parents=True, exist_ok=True)
        (out / "cell-outcomes.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (out / "cell-outcomes.txt").write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0
