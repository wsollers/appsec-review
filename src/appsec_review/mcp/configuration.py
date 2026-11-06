"""Print a client configuration for explicit operator selection; never install it."""

from __future__ import annotations

import json
from typing import Any, Sequence

from appsec_review.mcp.operator import validate_selection
from appsec_review.mcp.stdio import parser


def client_configuration(*, run_id: str, runs_dir: str = "runs",
                         manifest_sha256: str | None = None,
                         dagster_endpoint: str | None = None) -> dict[str, Any]:
    validate_selection(run_id, manifest_sha256)
    if not isinstance(runs_dir, str) or not runs_dir or "\x00" in runs_dir:
        raise ValueError("runs directory is required")
    args = ["--runs-dir", runs_dir, "--run-id", run_id]
    if manifest_sha256 is not None:
        args.extend(["--manifest-sha256", manifest_sha256])
    if dagster_endpoint is not None:
        from appsec_review.mcp.dagster import DagsterReader
        DagsterReader(dagster_endpoint, run_id)
        args.extend(["--dagster-endpoint", dagster_endpoint])
    return {"mcpServers": {"appsec-review": {"command": "appsec-review-mcp", "args": args}}}


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser()
    arguments.prog = "python -m appsec_review.mcp.configuration"
    args = arguments.parse_args(argv)
    try:
        configuration = client_configuration(run_id=args.run_id, runs_dir=str(args.runs_dir),
                                             manifest_sha256=args.manifest_sha256,
                                             dagster_endpoint=args.dagster_endpoint)
    except ValueError:
        arguments.error("invalid explicit selection or trusted endpoint")
    print(json.dumps(configuration, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
