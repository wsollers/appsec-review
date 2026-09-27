#!/usr/bin/env python3
"""Run and attest the live Go, Java, and PHP source-SAST path."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

EXPECTED = {"gosec": "go", "spotbugs": "java", "phpstan": "php", "psalm": "php", "phpcs": "php"}


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def _sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", required=True)
    args = parser.parse_args()

    runs_root = args.runs_root.resolve()
    os.environ["APPSEC_RUNS_ROOT"] = str(runs_root)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import source_sast

    accepted = source_sast.run(args.run_id, args.dagster_run_id)
    attempt = runs_root / args.run_id / "data" / "jobs" / source_sast.JOB / "attempts" / accepted["attempt_id"]
    result_path = attempt / source_sast.RESULT
    result = _json(result_path)
    receipt = _json(attempt / source_sast.RECEIPTS)
    tools = {row["tool_id"]: row for row in result["tools"]}
    missing = sorted(set(EXPECTED) - set(tools))
    if missing:
        raise RuntimeError("language SAST qualification did not execute: " + ", ".join(missing))

    executions = []
    receipts = {row["tool_id"]: row for row in receipt["tools"]}
    for tool_id, language in sorted(EXPECTED.items()):
        record = receipts[tool_id]
        trial = attempt / record["trial_path"]
        request = _json(trial / "logs" / "container" / "request.json")
        terminal = _json(trial / "logs" / "container" / "container-result.json")
        if request.get("network") != {"mode": "none", "destinations": []}:
            raise RuntimeError(f"{tool_id} did not use the offline boundary")
        if terminal.get("execution_status") != "OK" and not (
                terminal.get("cause") == "CONTAINER_EXIT_NONZERO" and
                terminal.get("exit_code") in source_sast.language_adapters.HIT_EXIT_CODES[tool_id]):
            raise RuntimeError(f"{tool_id} did not reach an accepted terminal state")
        identity = tools[tool_id]
        executions.append({"language": language, "tool_id": tool_id, "version": identity["version"],
            "image_id": identity["image_id"], "image_digest": identity["image_digest"],
            "records": identity["records"], "network_mode": "none",
            "raw_result_sha256": record["raw_result_sha256"],
            "container_result_sha256": _sha(trial / "logs" / "container" / "container-result.json")})

    language_gaps = [gap for gap in result["coverage_gaps"]
                     if gap.startswith(("go SAST", "java SAST", "php SAST"))]
    if language_gaps:
        raise RuntimeError("language SAST qualification retained execution gaps")
    summary = {"schema": "appsec-review/source-sast-language-live-qualification/1.0",
        "run_id": args.run_id, "attempt_id": accepted["attempt_id"],
        "source_sast_sha256": _sha(result_path), "accepted_envelope_sha256": "sha256:" + accepted["envelope_sha256"],
        "status": accepted["status"], "executions": executions,
        "lead_count": len(result["leads"]),
        "lead_counts_by_language": {language: sum(row["records"] for row in executions if row["language"] == language)
                                    for language in ("go", "java", "php")},
        "remaining_coverage_gaps": result["coverage_gaps"],
        "claim_ceiling": "STATIC_ANALYSIS_LEADS_NOT_FINDINGS"}
    summary_path = runs_root / args.run_id / "qualification" / "source-sast-languages-live.json"
    _write(summary_path, summary)
    print(json.dumps({**summary, "summary_path": str(summary_path), "summary_sha256": _sha(summary_path)},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
