"""The cell-outcomes report (T-5028, step one) over a synthetic run tree: ledger join, reasons, retrieval errors,
unattributed attempts from an unsealed lane, per-package counts and model-call quantiles."""
from __future__ import annotations

import json
from pathlib import Path

from appsec_review.reporting.cell_outcomes import REVIEW_JOB, SCHEMA, UNATTRIBUTED, main, render, summarize

ATTEMPT = "attempt_0001"


def _ledger_record(cell_id: str, role: str, status: str, package_id: str) -> dict:
    return {"schema": "appsec-review/ledger-event/1", "kind": "cell_terminal", "stream": "lead_review.teams",
            "body": {"cell": {"cell_id": cell_id, "role": role, "task": f"{role}_task", "lane": "lead",
                              "package_id": package_id, "status": status, "attempts": 1}}}


def _attempt(cell_id: str, status: str, *, reason=None, gap_class=None, turns=1, queries=0, output_tokens=100,
             retrieval_error=None) -> dict:
    retrievals = []
    if retrieval_error:
        retrievals.append({"index": 0, "status": "tool_error", "tool": retrieval_error[0], "error_class": retrieval_error[1]})
    return {"schema": "appsec-review/cell-attempt-receipt/1", "cell_id": cell_id, "status": status, "reason": reason,
            "gap_class": gap_class, "counts": {"turns": turns, "queries": queries, "output_tokens": output_tokens},
            "turns": [{"turn": index + 1, "retrievals": retrievals if index == 0 else []} for index in range(turns)]}


def _execution(status: str, elapsed_ms: int, failure_code=None) -> dict:
    return {"schema": "appsec-review/model-execution-receipt/1", "status": status, "elapsed_ms": elapsed_ms,
            "failure_code": failure_code, "served_provider": "claude-cli", "served_model": "claude-haiku-5-5"}


def _build_run(tmp_path: Path) -> Path:
    run = tmp_path / "runs" / "2026-11-15-0005"
    job = run / "data" / "jobs" / REVIEW_JOB
    ledger = job / "attempts" / ATTEMPT / "steps" / "lead_review" / "tasks" / "teams" / "ledger.jsonl"
    ledger.parent.mkdir(parents=True)
    records = [_ledger_record("cell-red1", "red_team_analyst", "invalid", "pkg-a"),
               _ledger_record("cell-red2", "red_team_analyst", "succeeded", "pkg-a"),
               _ledger_record("cell-blue1", "blue_team_refuter", "succeeded", "pkg-b")]
    ledger.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    attempts = {
        "cell-red1": [_attempt("cell-red1", "invalid", reason="final_result_rejected", gap_class="schema_error",
                               turns=3, queries=10, output_tokens=2000, retrieval_error=("expand", "KeyError")),
                      _attempt("cell-red1", "timed_out", reason="cell_budget_exceeded:cell_token_cap",
                               gap_class="budget_gap", turns=6, queries=20, output_tokens=7000)],
        "cell-red2": [_attempt("cell-red2", "succeeded", turns=2, queries=3, output_tokens=500)],
        "cell-blue1": [_attempt("cell-blue1", "succeeded", output_tokens=300)],
        # The hunt lane has not sealed: this cell has no ledger record yet.
        "cell-hunt1": [_attempt("cell-hunt1", "invalid", reason="final_result_rejected", gap_class="schema_error")],
    }
    for cell_id, receipts in attempts.items():
        for index, receipt in enumerate(receipts, start=1):
            path = job / "cells" / cell_id / f"attempt-{index}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(receipt), encoding="utf-8")
    executions = [_execution("SUCCEEDED", 10_000), _execution("SUCCEEDED", 30_000), _execution("SUCCEEDED", 60_000),
                  _execution("TIMED_OUT", 120_000, "provider_timeout"), _execution("FAILED", 5_000, "model_token_cap")]
    for index, receipt in enumerate(executions, start=1):
        path = run / "data" / "inference-executions" / "guidance" / f"invocation-{index}" / f"{index:06d}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(receipt), encoding="utf-8")
    return run


def test_summary_joins_roles_reasons_retrieval_errors_and_model_calls(tmp_path: Path) -> None:
    run = _build_run(tmp_path)
    document = summarize(run)
    assert document["schema"] == SCHEMA and document["run_id"] == "2026-11-15-0005" and document["ledger_cells"] == 3

    red = document["roles"]["red_team_analyst"]
    assert red["attempts"] == 3 and red["cells"] == 2
    assert red["outcomes"] == {"invalid": 1, "succeeded": 1, "timed_out": 1}
    assert red["reasons"] == {"final_result_rejected": 1, "cell_budget_exceeded:cell_token_cap": 1}
    assert red["retrieval_errors"] == {"expand:KeyError": 1}
    assert red["output_tokens"] == 9500 and red["turns"]["max"] == 6 and red["queries"]["p50"] == 10

    blue = document["roles"]["blue_team_refuter"]
    assert blue["outcomes"] == {"succeeded": 1} and blue["reasons"] == {} and blue["retrieval_errors"] == {}

    unattributed = document["roles"][UNATTRIBUTED]
    assert unattributed["attempts"] == 1 and unattributed["reasons"] == {"final_result_rejected": 1}

    packages = document["packages"]
    assert packages["count"] == 2 and packages["attempts_per_package"]["max"] == 3 and packages["without_success"] == 0

    calls = document["model_calls"]
    assert calls["by_status"]["SUCCEEDED"] == {"n": 3, "p50": 30.0, "p90": 60.0, "max": 60.0, "sum": 100.0}
    assert calls["by_status"]["TIMED_OUT"]["n"] == 1 and calls["failure_codes"] == {"provider_timeout": 1, "model_token_cap": 1}
    assert calls["served"] == {"claude-cli/claude-haiku-5-5": 5}


def test_render_names_every_role_and_main_writes_the_verification_files(tmp_path: Path, capsys) -> None:
    run = _build_run(tmp_path)
    text = render(summarize(run))
    assert "red_team_analyst: 3 attempts over 2 cells" in text
    assert "retrieval tool_error expand:KeyError" in text and UNATTRIBUTED in text
    assert "model calls SUCCEEDED: n 3 p50 30s p90 60s" in text

    assert main(["--run", str(run), "--write"]) == 0
    printed = capsys.readouterr().out
    assert printed.strip() == text
    written = json.loads((run / "data" / "verification" / "cell-outcomes.json").read_text(encoding="utf-8"))
    assert written["roles"]["red_team_analyst"]["attempts"] == 3
    assert (run / "data" / "verification" / "cell-outcomes.txt").read_text(encoding="utf-8") == text + "\n"


def test_an_empty_run_reports_nothing_rather_than_failing(tmp_path: Path) -> None:
    run = tmp_path / "runs" / "2026-01-01-0001"
    (run / "data" / "jobs" / REVIEW_JOB).mkdir(parents=True)
    document = summarize(run)
    assert document["roles"] == {} and document["ledger_cells"] == 0
    assert document["packages"] == {"count": 0, "attempts_per_package": {"n": 0}, "succeeded_per_package": {"n": 0},
                                    "without_success": 0}
    assert document["model_calls"] == {"by_status": {}, "failure_codes": {}, "served": {}}
    assert "packages 0" in render(document)


def _plan_document(status: str, **summary: int) -> dict:
    base = {"areas": 0, "reached": 0, "not_reached": 0, "agents": 0, "unassigned": 0, "functions_assigned": 0,
            "entry_points_assigned": 0}
    attempts = [{"turn": 1, "errors": ["N9 is not an id of the brief"], "usage": {"output_tokens": 900}},
                {"turn": 2, "valid": status == "planned", "usage": {"output_tokens": 1100}}]
    return {"schema": "appsec-review/hunt-plan/1", "status": status,
            "plan_id": "plan-" + "a" * 64 if status == "planned" else None,
            "gap": None if status == "planned" else "hunt_plan_unavailable:empty_plan",
            "attempts": attempts if status != "disabled" else [], "summary": {**base, **summary}}


def test_hunt_planner_is_reported_under_its_own_role_from_the_plan_artifact(tmp_path: Path) -> None:
    """The planner (T-5030) runs outside the lane ledgers: its attempts, tokens and outcome come from hunt-plan.json."""
    run = _build_run(tmp_path)
    plan = (run / "data" / "jobs" / REVIEW_JOB / "attempts" / ATTEMPT / "steps" / "packages" / "tasks"
            / "plan_hunt_campaign" / "hunt-plan.json")
    plan.parent.mkdir(parents=True)
    plan.write_text(json.dumps(_plan_document("planned", areas=3, reached=2, not_reached=1, agents=4, unassigned=2)))
    document = summarize(run)
    planner = document["roles"]["hunt_planner"]
    assert (planner["attempts"], planner["cells"], planner["outcomes"], planner["reasons"]) == (1, 1, {"succeeded": 1}, {})
    assert planner["output_tokens"] == 2000 and planner["turns"]["max"] == 2 and planner["queries"]["max"] == 0
    assert document["hunt_plan"] == {"plan_id": "plan-" + "a" * 64, "status": "planned", "gap": None, "areas": 3,
                                     "reached": 2, "not_reached": 1, "agents": 4, "unassigned": 2,
                                     "functions_assigned": 0, "entry_points_assigned": 0}
    text = render(document)
    assert "hunt_planner: 1 attempts over 1 cells; succeeded 1; output tokens 2000" in text
    assert f"hunt plan plan-{'a' * 64}: planned; areas 3 (reached 2, not reached 1); agents 4; unassigned 2" in text
    # A fallen-back plan is a failed planner attempt whose reason is the named gap.
    plan.write_text(json.dumps(_plan_document("fallback")))
    document = summarize(run)
    assert document["roles"]["hunt_planner"]["outcomes"] == {"failed": 1}
    assert document["roles"]["hunt_planner"]["reasons"] == {"hunt_plan_unavailable:empty_plan": 1}
    assert "gap hunt_plan_unavailable:empty_plan" in render(document)
    # A disabled planner is absent, not a zero row.
    plan.write_text(json.dumps(_plan_document("disabled")))
    document = summarize(run)
    assert "hunt_planner" not in document["roles"] and document["hunt_plan"] is None
    assert "hunt plan" not in render(document)
