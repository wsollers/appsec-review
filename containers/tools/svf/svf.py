#!/usr/bin/env python3
"""Bounded SVF runner for one accepted C/C++ scope (tool-svf image).

``svf.py version`` prints the tool version. ``svf.py run <plan.json> <result.json>``:

1. compiles every compile unit a planned module needs to bitcode with clang-18 (the compiler of
   record) from the read-only container compile database, at -O0 with debug information;
2. links each planned module with LLVM 21's llvm-link (a single-unit module is linked too, so the
   bitcode upgrade and its debug-information diagnostics are uniform);
3. runs the repository-owned ``svf-alias-export`` driver per module under a wall-clock bound.

Every failure is recorded per compile unit or per module; nothing aborts sibling modules. The target
is never executed: only clang, llvm-link and the analyzer run.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


TOOL_VERSION = "3.3.0"
PLAN_SCHEMA = "appsec-review/svf-plan/1"
RESULT_SCHEMA = "appsec-review/svf-run/1"
DRIVER = "/opt/svf/bin/svf-alias-export"
LLVM_LINK = "/opt/svf/bin/llvm-link-21"
EXTAPI = "/opt/svf/lib/extapi.bc"
ANDERSEN_TIME_LIMIT_EXIT = 101
DEBUG_INFO_WARNING = "ignoring invalid debug info"
_DROP_FLAGS = {"-c", "-S", "-emit-llvm", "-fsyntax-only", "-MD", "-MMD", "-M", "-MM", "-MP", "-g"}
_DROP_WITH_VALUE = {"-o", "-MF", "-MT", "-MQ"}
_DROP_PREFIXES = ("-O", "-g", "-flto", "-fprofile", "-fsanitize", "-Werror", "-fdebug-prefix-map",
                  "-ffile-prefix-map", "-fmacro-prefix-map", "-save-temps")


def _tail(data: bytes, limit: int = 4096) -> str:
    return data.decode("utf-8", "replace")[-limit:]


def bitcode_argv(arguments: list[str], output: str) -> list[str]:
    """Rewrite one compile command to produce -O0 debug bitcode, keeping every semantic flag."""
    compiler = "clang++-18" if str(arguments[0]).endswith("++") else "clang-18"
    result = [compiler]
    skip = False
    for value in arguments[1:]:
        if skip:
            skip = False
            continue
        if value in _DROP_WITH_VALUE:
            skip = True
            continue
        if value in _DROP_FLAGS or value.startswith(_DROP_PREFIXES) or value.startswith("-o"):
            continue
        result.append(value)
    return [*result, "-c", "-emit-llvm", "-g", "-O0", "-Xclang", "-disable-O0-optnone",
            "-Wno-everything", "-o", output]


def _run(argv: list[str], cwd: str, timeout: int) -> dict[str, Any]:
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp", "LANG": "C.UTF-8",
                   "LC_ALL": "C.UTF-8", "TZ": "UTC", "LD_LIBRARY_PATH": "/opt/svf/lib"}
    try:
        completed = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=timeout, check=False, env=environment)
    except subprocess.TimeoutExpired as exc:
        return {"exit_code": None, "timeout": True, "stderr": _tail(exc.stderr or b"")}
    return {"exit_code": completed.returncode, "timeout": False, "stderr": _tail(completed.stderr)}


def _compile(rows: list[dict[str, Any]], indexes: set[int], bounds: dict[str, int], scratch: Path) -> dict[int, dict[str, Any]]:
    out = scratch / "bitcode"
    out.mkdir(parents=True, exist_ok=True)
    results: dict[int, dict[str, Any]] = {}
    for index in sorted(indexes):
        row = rows[index]
        output = out / f"tu-{index:04d}.bc"
        record = _run(bitcode_argv([str(item) for item in row["arguments"]], str(output)),
                      str(row["directory"]), bounds["compile_timeout_seconds"])
        record.update({"index": index, "file": row["file"],
                       "bitcode": str(output) if record["exit_code"] == 0 and output.is_file() else None})
        results[index] = record
    return results


def _module(module: dict[str, Any], compiled: dict[int, dict[str, Any]], bounds: dict[str, int],
            scratch: Path) -> dict[str, Any]:
    module_id = str(module["module_id"])
    root = scratch / "modules" / module_id
    root.mkdir(parents=True, exist_ok=True)
    gaps: list[str] = []
    inputs = []
    for index in module["compile_indexes"]:
        record = compiled[int(index)]
        if record["bitcode"] is None:
            gaps.append(f"missing_bitcode: compile unit {index} ({record['file']}) did not produce bitcode")
        else:
            inputs.append(record["bitcode"])
    base = {"module_id": module_id, "kind": module["kind"], "label": module.get("label", ""),
            "compile_indexes": list(module["compile_indexes"]), "linked_inputs": len(inputs)}
    if not inputs:
        return {**base, "status": "no_bitcode", "gaps": gaps, "debug_info_warnings": 0}
    linked = root / "module.bc"
    link = _run([LLVM_LINK, "-o", str(linked), *inputs], str(scratch), bounds["link_timeout_seconds"])
    warnings = link["stderr"].count(DEBUG_INFO_WARNING)
    if link["timeout"] or link["exit_code"] != 0 or not linked.is_file():
        return {**base, "status": "link_failed", "gaps": [*gaps, "link_failed: " + link["stderr"][-2048:]],
                "debug_info_warnings": warnings}
    size = linked.stat().st_size
    if size > bounds["max_module_bitcode_bytes"]:
        linked.unlink()
        return {**base, "status": "too_large", "bitcode_bytes": size, "debug_info_warnings": warnings,
                "gaps": [*gaps, f"module bitcode is {size} bytes, over the {bounds['max_module_bitcode_bytes']}-byte bound"]}
    output = root / "alias.json"
    request = root / "request.json"
    request.write_text(json.dumps({
        "module": str(linked), "output": str(output), "extapi": EXTAPI,
        "bounds": {key: bounds[key] for key in ("field_limit", "max_sites", "max_pts_size", "max_indirect_calls",
                                                "max_targets_per_call", "max_unmodeled_names",
                                                "andersen_time_limit_seconds")},
    }), encoding="utf-8")
    analysis = _run([DRIVER, str(request)], str(root), bounds["module_timeout_seconds"])
    linked.unlink()
    if analysis["exit_code"] == ANDERSEN_TIME_LIMIT_EXIT:
        return {**base, "status": "andersen_time_limit", "bitcode_bytes": size, "debug_info_warnings": warnings,
                "gaps": [*gaps, f"Andersen exceeded its {bounds['andersen_time_limit_seconds']}-second limit"]}
    if analysis["timeout"] or analysis["exit_code"] != 0 or not output.is_file():
        reason = "timed out" if analysis["timeout"] else f"exited with status {analysis['exit_code']}"
        return {**base, "status": "analysis_failed", "bitcode_bytes": size, "debug_info_warnings": warnings,
                "gaps": [*gaps, f"analysis {reason}: {analysis['stderr'][-2048:]}"]}
    if output.stat().st_size > bounds["max_module_output_bytes"]:
        return {**base, "status": "analysis_failed", "bitcode_bytes": size, "debug_info_warnings": warnings,
                "gaps": [*gaps, f"analysis output exceeded the {bounds['max_module_output_bytes']}-byte bound"]}
    return {**base, "status": "analyzed", "bitcode_bytes": size, "debug_info_warnings": warnings,
            "gaps": gaps, "output": output.relative_to(scratch).as_posix()}


def run(plan_path: Path, result_path: Path) -> int:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if plan.get("schema") != PLAN_SCHEMA:
        raise SystemExit("unsupported plan schema")
    scratch = plan_path.parent
    rows = json.loads((scratch / "compile_commands.json").read_text(encoding="utf-8"))
    bounds = {key: int(value) for key, value in plan["bounds"].items()}
    needed = {int(index) for module in plan["modules"] for index in module["compile_indexes"]}
    if any(index < 0 or index >= len(rows) for index in needed):
        raise SystemExit("plan names a compile unit outside the compile database")
    compiled = _compile(rows, needed, bounds, scratch)
    modules = [_module(module, compiled, bounds, scratch) for module in plan["modules"]]
    partial = result_path.with_suffix(".partial")
    partial.write_text(json.dumps({
        "schema": RESULT_SCHEMA, "tool_version": TOOL_VERSION,
        "compile": [{key: value for key, value in record.items() if key != "bitcode"}
                    | {"produced": record["bitcode"] is not None} for record in compiled.values()],
        "modules": modules,
    }, sort_keys=True), encoding="utf-8")
    partial.replace(result_path)
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["version"]:
        print(f"appsec-svf {TOOL_VERSION}")
        return 0
    if len(argv) == 4 and argv[1] == "run":
        return run(Path(argv[2]), Path(argv[3]))
    print("usage: svf.py version | svf.py run <plan.json> <result.json>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
