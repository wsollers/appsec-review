"""Compiler admission and bounded native CBMC JSON, independent of Docker and the runtime."""

from collections.abc import Mapping, Sequence
import json
from pathlib import PurePosixPath
import re
from typing import Any


IMPLEMENTATION = "appsec-review/cbmc-analysis/1"
CHECKS = ("--bounds-check", "--pointer-check", "--pointer-overflow-check",
          "--signed-overflow-check", "--div-by-zero-check", "--unwinding-assertions")
ASSUMPTIONS = (
    "Symbolic function-entry inputs; caller preconditions and attacker reachability are not established.",
    "Original accepted translation unit; CBMC initialization and library models, not native execution.",
    "Only the recorded properties, compile-argument projection and unwind limits were analyzed.",
    "Neither bounded passes nor counterexample candidates confirm or dismiss a finding.",
)


class CompileRejected(ValueError):
    """The accepted native command cannot be faithfully admitted to this frontend."""


class OutputRejected(ValueError):
    """The native output is incomplete, inconsistent or outside its declared bounds."""


def _include(value: str) -> str:
    path = PurePosixPath(value)
    if ".." in path.parts or "\\" in value or "\0" in value or value.startswith("@"):
        raise CompileRejected("include path is not a canonical accepted-source path")
    if not path.is_absolute():
        path = PurePosixPath("/target/source") / path
    if path != PurePosixPath("/target/source") and PurePosixPath("/target/source") not in path.parents:
        raise CompileRejected("include path is outside the accepted source snapshot")
    return str(path)


def compile_argv(row: Mapping[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    source = str(row["file"])
    if not source.startswith("/target/source/") or ".." in PurePosixPath(source).parts:
        raise CompileRejected("translation unit is outside the accepted source snapshot")
    suffix = PurePosixPath(source).suffix.lower()
    if suffix not in {".c", ".cc", ".cpp", ".cxx", ".c++"}:
        raise CompileRejected("translation unit is not supported C/C++")
    is_cpp = suffix != ".c"
    cpp_std: str | None = None
    arguments = row.get("arguments")
    if (not isinstance(arguments, (list, tuple)) or not arguments
            or any(not isinstance(v, str) or not v or any(c in v for c in "\0\r\n") for v in arguments)):
        raise CompileRejected("compile arguments are malformed")
    admitted: list[str] = []
    replaced: list[str] = []
    position = 1
    sources = 0
    while position < len(arguments):
        value = arguments[position]
        position += 1
        if value == source:
            sources += 1
        elif value in {"-o", "-MF", "-MT", "-MQ"}:
            if position == len(arguments):
                raise CompileRejected(f"{value} has no operand")
            replaced.extend((value, arguments[position]))
            position += 1
        elif value in {"-c", "-MD", "-MMD", "-MP"} or re.fullmatch(r"-g(?:[0-3]|gdb[0-3]?)?", value):
            replaced.append(value)
        elif value.startswith("-W") and not value.startswith(("-Wa,", "-Wl,", "-Wp,")):
            replaced.append(value)
        elif value in {"-D", "-U", "-I", "-isystem", "-iquote", "-include", "-imacros"}:
            if position == len(arguments):
                raise CompileRejected(f"{value} has no operand")
            operand = arguments[position]
            position += 1
            admitted.extend((value, operand if value in {"-D", "-U"} else _include(operand)))
        elif value.startswith(("-D", "-U")) and len(value) > 2:
            admitted.append(value)
        elif value.startswith("-I") and len(value) > 2:
            admitted.append("-I" + _include(value[2:]))
        elif value.startswith("-std="):
            if is_cpp:
                if re.fullmatch(r"-std=(?:c|gnu)\+\+(?:98|03)", value):
                    cpp_std = value
                    admitted.append(value)
                else:
                    raise CompileRejected(
                        f"unsupported C++ language standard for CBMC goto-cc (only C++98/03 is supported): {value[:160]}"
                    )
            elif re.fullmatch(
                r"-std=(?:c|gnu)(?:89|90|99|11|17|18|2x|23)|-std=iso9899:(?:1990|199409|1999|2011|2017|2018)",
                value,
            ):
                admitted.append(value)
            else:
                raise CompileRejected(f"unsupported C language standard for CBMC goto-cc: {value[:160]}")
        elif value in {"-m32", "-m64", "-pthread", "-funsigned-char", "-fsigned-char",
                       "-O0", "-O1", "-O2", "-O3", "-Os", "-Og"}:
            admitted.append(value)
        else:
            raise CompileRejected(f"unsupported semantic compiler argument: {value[:160]}")
    if sources != 1:
        raise CompileRejected("compile command must name exactly the selected source")
    if is_cpp and cpp_std is None:
        raise CompileRejected(
            "C++ translation unit omits explicit -std=c++98/-std=c++03 and defaults to modern C++17, "
            "which CBMC goto-cc does not support"
        )
    return ("/usr/bin/goto-cc", "-c", *admitted, source, "-o", "/scratch/unit.goto"), tuple(replaced)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OutputRejected(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def native_json(data: bytes, max_bytes: int) -> list[dict[str, Any]]:
    if len(data) > max_bytes:
        raise OutputRejected("native JSON exceeds the output bound")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_object)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise OutputRejected("native output is not complete UTF-8 JSON") from exc
    if not isinstance(value, list) or not value or any(not isinstance(row, dict) for row in value):
        raise OutputRejected("native JSON must be a nonempty array of records")
    return value


def source_position(value: Any) -> tuple[str, int] | None:
    if not isinstance(value, Mapping):
        return None
    file, line = value.get("file"), value.get("line")
    if (not isinstance(file, str) or not file.startswith("/target/source/")
            or "\\" in file or ".." in PurePosixPath(file).parts
            or not isinstance(line, (str, int)) or isinstance(line, bool)
            or not re.fullmatch(r"[1-9][0-9]{0,8}", str(line))):
        return None
    return file.removeprefix("/target/source/"), int(line)


_GOTO_FUNCTION_SEPARATOR = "^" * 44
_GOTO_END_FUNCTION = re.compile(r"^(?:[ ]+|[ ]*(?:[0-9]+:[ ]+)+)END_FUNCTION$")
_GOTO_LOCATION_COMMENT = re.compile(r"^        // [0-9]+(?: (.*))?$")
_GOTO_SOURCE_LOCATION = re.compile(r"^file (.+) line ([1-9][0-9]{0,8})(?: column [0-9]+)?(?: function .*)?$")


def goto_functions_output(data: bytes, max_bytes: int, *, max_instructions: int) -> list[dict[str, Any]]:
    if len(data) > max_bytes:
        raise OutputRejected("GOTO function output exceeds the output bound")
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise OutputRejected("GOTO function output is not valid UTF-8") from exc
    lines = text.splitlines()
    first = next((line for line in lines if line.strip()), "")
    if not first.startswith("Reading GOTO program from "):
        raise OutputRejected("GOTO function output is missing program header")
    functions: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_instructions = 0
    index = 0
    while index < len(lines):
        if lines[index] != _GOTO_FUNCTION_SEPARATOR:
            index += 1
            continue
        index += 1
        while index < len(lines) and not lines[index].strip():
            index += 1
        if index >= len(lines):
            raise OutputRejected("incomplete GOTO function header")
        header = lines[index]
        if " /* " not in header or not header.endswith(" */"):
            raise OutputRejected("invalid GOTO function header")
        name = header.split(" /* ", 1)[0]
        if not name or len(name) > 2048 or any(c in name for c in "\0\r\n") or name in seen:
            raise OutputRejected("invalid or duplicate GOTO function name")
        seen.add(name)
        is_internal = name.startswith("__CPROVER_")
        index += 1
        instruction_count = 0
        spans: dict[str, list[int]] = {}
        ended = False
        while index < len(lines) and lines[index] != _GOTO_FUNCTION_SEPARATOR:
            line = lines[index]
            index += 1
            if _GOTO_END_FUNCTION.fullmatch(line) is not None:
                ended = True
                continue
            match = _GOTO_LOCATION_COMMENT.match(line)
            if match is None or is_internal:
                continue
            total_instructions += 1
            if total_instructions > max_instructions:
                raise OutputRejected("GOTO instruction bound exceeded")
            instruction_count += 1
            detail = match.group(1) or ""
            loc_match = _GOTO_SOURCE_LOCATION.match(detail)
            if loc_match is not None:
                position = source_position({"file": loc_match.group(1), "line": int(loc_match.group(2))})
                if position is not None:
                    path, line_no = position
                    span = spans.setdefault(path, [line_no, line_no])
                    span[0], span[1] = min(span[0], line_no), max(span[1], line_no)
        if not ended:
            raise OutputRejected(f"incomplete GOTO function body: {name[:160]}")
        functions.append({
            "name": name,
            "isBodyAvailable": True,
            "isInternal": is_internal,
            "instructionCount": instruction_count,
            "sourceSpans": spans,
        })
    return [{"functions": functions}]


def function_entries(records: Sequence[Mapping[str, Any]], seeds: Sequence[Mapping[str, Any]], *,
                     max_instructions: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    tables = [record["functions"] for record in records if "functions" in record]
    if len(tables) != 1 or not isinstance(tables[0], list):
        raise OutputRejected("GOTO output must contain exactly one function table")
    ranges: dict[str, dict[str, list[int]]] = {}
    count = 0
    seen: set[str] = set()
    for function in tables[0]:
        if not isinstance(function, dict) or not isinstance(function.get("name"), str):
            raise OutputRejected("invalid GOTO function")
        name = function["name"]
        if not name or len(name) > 2048 or any(c in name for c in "\0\r\n") or name in seen:
            raise OutputRejected("invalid or duplicate GOTO function name")
        seen.add(name)
        if function.get("isBodyAvailable") is not True or function.get("isInternal") is not False:
            continue
        if "instructionCount" in function and "sourceSpans" in function:
            instruction_count = function["instructionCount"]
            source_spans = function["sourceSpans"]
            if (not isinstance(instruction_count, int) or isinstance(instruction_count, bool)
                    or instruction_count < 0 or not isinstance(source_spans, dict)):
                raise OutputRejected("invalid compact GOTO function summary")
            count += instruction_count
            if count > max_instructions:
                raise OutputRejected("GOTO instruction bound exceeded")
            for path, span in source_spans.items():
                if (not isinstance(path, str) or not isinstance(span, list) or len(span) != 2
                        or any(not isinstance(v, int) or isinstance(v, bool) or v < 1 for v in span)
                        or span[0] > span[1]):
                    raise OutputRejected("invalid compact GOTO source span")
                position = source_position({"file": f"/target/source/{path}", "line": span[0]})
                if position is None:
                    raise OutputRejected("compact GOTO source span is outside accepted source")
                ranges.setdefault(name, {})[position[0]] = [span[0], span[1]]
            continue
        instructions = function.get("instructions")
        if not isinstance(instructions, list):
            raise OutputRejected("GOTO function body has no instruction array")
        count += len(instructions)
        if count > max_instructions:
            raise OutputRejected("GOTO instruction bound exceeded")
        for instruction in instructions:
            if not isinstance(instruction, dict):
                raise OutputRejected("invalid GOTO instruction")
            position = source_position(instruction.get("sourceLocation"))
            if position is not None:
                path, line = position
                span = ranges.setdefault(name, {}).setdefault(path, [line, line])
                span[0], span[1] = min(span[0], line), max(span[1], line)
    entries: dict[str, dict[str, Any]] = {}
    unresolved = []
    for seed in seeds:
        candidates = [
            (span[1] - span[0], name, span) for name, locations in ranges.items()
            if (span := locations.get(str(seed["path"]))) is not None
            and span[0] <= seed["start_line"] <= seed["end_line"] <= span[1]
        ]
        candidates.sort()
        if not candidates or (len(candidates) > 1 and candidates[0][0] == candidates[1][0]):
            unresolved.append({**seed, "reason": "function_missing" if not candidates else "function_ambiguous"})
            continue
        _, name, span = candidates[0]
        entry = entries.setdefault(name, {"function": name, "seeds": [], "ranges": ranges[name]})
        entry["seeds"].append(dict(seed))
    return [entries[key] for key in sorted(entries)], unresolved


def judgment(records: Sequence[Mapping[str, Any]], exit_code: int | None, *,
             max_properties: int, max_trace_steps: int = 24, max_trace_value_chars: int = 200) -> dict[str, Any]:
    terminals = [row["cProverStatus"] for row in records if "cProverStatus" in row]
    groups = [row["result"] for row in records if "result" in row]
    if len(terminals) != 1 or len(groups) != 1 or not isinstance(groups[0], list):
        raise OutputRejected("CBMC must produce one terminal status and one property array")
    properties = groups[0]
    if not 1 <= len(properties) <= max_properties:
        raise OutputRejected("CBMC property count is empty or exceeds its bound")
    if not isinstance(terminals[0], str) or (exit_code, terminals[0]) not in {(0, "success"), (10, "failure")}:
        raise OutputRejected("CBMC exit code and terminal status are inconsistent")
    normalized = []
    ids = set()
    for ordinal, prop in enumerate(properties):
        if (not isinstance(prop, dict) or not isinstance(prop.get("property"), str)
                or not prop["property"] or prop["property"] in ids
                or not isinstance(prop.get("status"), str)
                or prop.get("status") not in {"SUCCESS", "FAILURE", "UNKNOWN", "NOT_CHECKED"}):
            raise OutputRejected("invalid, duplicate or unrecognized CBMC property")
        ids.add(prop["property"])
        trace = prop.get("trace", [])
        if not isinstance(trace, list):
            raise OutputRejected("CBMC trace must be an array")
        if any(not isinstance(step, dict) for step in trace):
            raise OutputRejected("CBMC trace contains a malformed step")
        visible = [step for step in trace if not step.get("hidden") and step.get("stepType") in {
            "assignment", "assumption", "failure", "function-call", "function-return"}]
        selected = visible if len(visible) <= max_trace_steps else visible[:max_trace_steps - 1] + visible[-1:]
        preview = []
        for step in selected:
            value = step.get("value")
            value = value.get("data") if isinstance(value, dict) else value
            preview.append({"kind": step["stepType"], "lhs": str(step.get("lhs", ""))[:max_trace_value_chars],
                            "value": str(value)[:max_trace_value_chars] if value is not None else None,
                            "source": source_position(step.get("sourceLocation"))})
        property_id = prop["property"]
        kind = ("unwinding" if ".unwind." in property_id else
                "missing_body" if ".no-body." in property_id or "no body for" in str(prop.get("description", "")).lower()
                else "safety")
        normalized.append({
            "property_id": property_id[:2048], "description": str(prop.get("description", ""))[:1000],
            "status": prop["status"], "kind": kind, "trace_steps": len(trace),
            "trace": preview, "trace_omitted": len(trace) - len(preview),
            "source": source_position(prop.get("sourceLocation")), "ordinal": ordinal,
        })
    failed = [p for p in normalized if p["status"] == "FAILURE"]
    if (exit_code == 0 and any(p["status"] != "SUCCESS" for p in normalized)) or (exit_code == 10 and not failed):
        raise OutputRejected("CBMC property statuses contradict its terminal status")
    gaps = []
    if any(str(row.get("messageType", "")).upper() in {"WARNING", "ERROR"} for row in records):
        gaps.append("engine_reported_model_warning")
    if any(p["status"] in {"UNKNOWN", "NOT_CHECKED"} for p in normalized):
        gaps.append("properties_not_checked")
    if any(p["kind"] == "unwinding" for p in failed):
        gaps.append("unwinding_incomplete")
    if any(p["kind"] == "missing_body" for p in failed):
        gaps.append("external_function_body_missing")
    candidates = [p for p in failed if p["kind"] == "safety" and p["trace_steps"] > 0]
    if any(p["kind"] == "safety" and not p["trace_steps"] for p in failed):
        gaps.append("failed_property_without_trace")
    result = "counterexample_candidate" if candidates else "bounded_pass" if exit_code == 0 and not gaps else "inconclusive"
    return {"judgment": result, "properties": normalized, "property_count": len(normalized),
            "candidate_count": len(candidates), "gaps": gaps,
            "retry_unwind": bool(failed) and all(p["kind"] == "unwinding" for p in failed) and not
            any(reason != "unwinding_incomplete" for reason in gaps)}
