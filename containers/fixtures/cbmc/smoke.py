"""Manual image smoke: source and GOTO checks plus a real bounded counterexample."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


def check_result(completed: subprocess.CompletedProcess[str], *, success: bool) -> None:
    expected_code = 0 if success else 10
    if completed.returncode != expected_code:
        raise RuntimeError(f"CBMC exited {completed.returncode}, expected {expected_code}: {completed.stderr}")
    records = json.loads(completed.stdout)
    expected_status = "success" if success else "failure"
    statuses = [record["cProverStatus"] for record in records if "cProverStatus" in record]
    if statuses != [expected_status]:
        raise RuntimeError(f"unexpected CBMC terminal statuses: {statuses}")
    properties = [prop for record in records for prop in record.get("result", [])]
    if not properties:
        raise RuntimeError("CBMC produced no property results")
    if success:
        if any(prop.get("status") != "SUCCESS" for prop in properties):
            raise RuntimeError("CBMC did not discharge every fixture property")
    elif not any(
        prop.get("status") == "FAILURE"
        and prop.get("description") == "cbmc fixture index bound"
        and prop.get("trace")
        for prop in properties
    ):
        raise RuntimeError("CBMC produced no counterexample trace for the fixture index bound")


def main() -> None:
    source = Path(__file__).resolve().parent
    options = [
        "--unwind", "8", "--unwinding-assertions", "--bounds-check",
        "--pointer-check", "--signed-overflow-check", "--json-ui",
    ]
    for filename, extra, success in (
        ("bounded.c", [], True),
        ("bounded.c", ["-DINDEX_BOUND=5", "--trace"], False),
    ):
        completed = subprocess.run(
            ["cbmc", str(source / filename), *options, *extra],
            capture_output=True, text=True, check=False, timeout=30,
        )
        Path(f"source-{'safe' if success else 'unsafe'}.json").write_text(completed.stdout, encoding="utf-8")
        check_result(completed, success=success)
    for filename in ("bounded.c", "simple.cpp"):
        binary = Path(filename).stem + ".goto"
        instrumented = Path(filename).stem + "-instrumented.goto"
        subprocess.run(["goto-cc", str(source / filename), "-o", binary], check=True, timeout=30)
        subprocess.run(
            ["goto-instrument", "--bounds-check", "--pointer-check", binary, instrumented],
            check=True, timeout=30,
        )
        completed = subprocess.run(
            ["cbmc", instrumented, *options], capture_output=True, text=True, check=False, timeout=30,
        )
        Path(binary + ".json").write_text(completed.stdout, encoding="utf-8")
        check_result(completed, success=True)
    print("CBMC functional smoke passed")


if __name__ == "__main__":
    main()
