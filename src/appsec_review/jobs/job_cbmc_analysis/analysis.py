"""Attempt-owned, budgeted GOTO/CBMC execution over verified accepted source copies."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
import hashlib
import math
from pathlib import Path, PurePosixPath
import re
import time
from typing import Any

from appsec_review.config.cbmc import CbmcSettings
from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, load_catalog
from appsec_review.container_runtime.executor import ImageUnavailableError, Mount
from appsec_review.jobs.cpp_index_scopes import IndexScope
from appsec_review.signing.core import SignatureVerificationError
from appsec_review.storage import file_sha256, run_artifact, verify_run_artifact
from .protocol import (
    ASSUMPTIONS, CHECKS, CompileRejected, OutputRejected, compile_argv, function_entries, judgment, native_json,
)

TOOL_ID = "tool-cbmc"


class BudgetExhausted(RuntimeError):
    pass


class ExecutionIncomplete(RuntimeError):
    pass


def stage_source(scope: IndexScope, destination: Path, settings: CbmcSettings) -> None:
    """Only accepted files reach the mount; unlisted files and symlink ancestors cannot supply headers."""
    if len(scope.files) > settings.max_source_files:
        raise CompileRejected("accepted source file count exceeds the staging bound")
    total = 0
    for item in sorted(scope.files, key=lambda row: row["scratch_path"]):
        relative = PurePosixPath(str(item["scratch_path"]))
        if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("source",):
            raise ValueError("invalid accepted source-map path")
        source = scope.case_root / str(relative)
        if scope.case_root.resolve() not in source.resolve().parents:
            raise ValueError("accepted source escapes its case root")
        cursor = source
        while cursor != scope.case_root:
            if cursor.is_symlink():
                raise ValueError("symlink in accepted source path")
            cursor = cursor.parent
        remaining = settings.max_source_bytes - total
        if source.stat().st_size > remaining:
            raise CompileRejected("accepted source bytes exceed the staging bound")
        with source.open("rb") as stream:
            data = stream.read(remaining + 1)
        if len(data) > remaining:
            raise CompileRejected("accepted source bytes exceed the staging bound")
        total += len(data)
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("accepted source bytes changed before CBMC staging")
        target = destination / str(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o444)


def seed_locations(scope: IndexScope, seeds: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    mapped = {str(item["scratch_path"]).removeprefix("source/"): item for item in scope.files}
    result = []
    for seed in seeds:
        source = mapped.get(str(seed["path"]))
        if source is None:
            raise ValueError("selected seed is outside the accepted source mapping")
        result.append({"path": source["target_path"], "file_sha256": source["sha256"],
                       "start_line": seed["start_line"], "end_line": seed["end_line"],
                       "observation_ids": list(seed["observation_ids"])})
    return result


def map_native_locations(result: dict[str, Any], scope: IndexScope, target: Path) -> None:
    sources = {str(item["scratch_path"]).removeprefix("source/"): item for item in scope.files}
    line_counts: dict[str, int] = {}

    def resolve(position):
        if position is None or position[0] not in sources:
            return None
        path, line = position
        source = sources[path]
        if path not in line_counts:
            data = (target / source["scratch_path"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != source["sha256"]:
                raise ValueError("CBMC staged source changed after input verification")
            line_counts[path] = len(data.splitlines())
        if line > line_counts[path]:
            return None
        return {"path": source["target_path"], "line": line, "file_sha256": source["sha256"]}

    for prop in result["properties"]:
        prop["source"] = resolve(prop["source"])
        for step in prop["trace"]:
            step["source"] = resolve(step["source"])
    unmapped = [prop for prop in result["properties"]
                if prop["status"] == "FAILURE" and prop["kind"] == "safety" and prop["source"] is None]
    if unmapped:
        result["gaps"].append("failed_property_source_unresolved")
        result["candidate_count"] = sum(
            prop["status"] == "FAILURE" and prop["kind"] == "safety" and prop["trace_steps"] > 0
            and prop["source"] is not None for prop in result["properties"])
        result["judgment"] = "counterexample_candidate" if result["candidate_count"] else "inconclusive"
        result["retry_unwind"] = False


class Analysis:
    def __init__(self, unit: Any, settings: CbmcSettings, *,
                 executor_factory: Callable[..., Any] | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.unit, self.settings, self.factory, self.clock = unit, settings, executor_factory, clock
        self.deadline = clock() + settings.total_timeout_seconds
        self.root = unit.job.attempt_root / "artifacts" / "cbmc"
        self.calls: list[dict[str, Any]] = []
        self.function_count = 0
        self.counter = 0

    def execute(self, target: Path, argv: tuple[str, ...], *, goto: Mapping[str, Any] | None = None,
                file_bound: int | None = None, expected_counterexample: bool = False):
        remaining = math.floor(self.deadline - self.clock())
        if remaining <= 3:
            raise BudgetExhausted("total CBMC analysis budget exhausted")
        timeout = min(self.settings.command_timeout_seconds, remaining)
        if timeout <= 3:
            raise BudgetExhausted("insufficient command budget for bounded process cleanup")
        invocation = ("/usr/bin/timeout", "--signal=TERM", "--kill-after=2s", str(timeout - 3), *argv)
        self.counter += 1
        scratch = self.root / "executions" / f"{self.counter:05d}"
        scratch.mkdir(parents=True, exist_ok=False)
        mounts = ()
        if goto is not None:
            source = verify_run_artifact(self.unit.job.run_root, goto)
            mounts = (Mount(source, "/inputs/unit.goto"),)
        if self.factory is not None:
            executor = self.factory(self.unit, timeout)
        else:
            catalog = load_catalog(self.unit.job.repository_root)
            tool = replace(catalog.tool(TOOL_ID), timeout_seconds=timeout,
                           output_bytes=self.settings.max_output_bytes,
                           expected_image_id=self.settings.image_id)
            if tool.tag != self.settings.tag:
                raise ValueError("CBMC job tag does not match the catalog recipe")
            executor = ContainerExecutor(replace(catalog, tools={**catalog.tools, TOOL_ID: tool}),
                                         self.unit.job.run_root)
        expected = {0, 124}
        if expected_counterexample:
            expected.add(10)
        elif argv[0] == "/usr/bin/goto-cc":
            expected.update({1, 6, 64})
        result = executor.execute(ExecutionRequest(
            TOOL_ID, invocation, target, scratch, working_directory="/target/source",
            extra_mounts=mounts,
            file_size_limit_bytes=file_bound or self.settings.max_output_bytes,
            accepted_exit_codes=frozenset(expected),
        ))
        if result.image_id != self.settings.image_id:
            raise ValueError("CBMC execution did not use the admitted image ID")
        receipt = run_artifact(self.unit.job.run_root, self.unit.job.run_root / result.receipt_path)
        output = run_artifact(self.unit.job.run_root, self.unit.job.run_root / result.stdout_path)
        self.calls.append({"receipt": receipt, "stdout": output, "argv": list(invocation),
                           "image_id": result.image_id, "timeout_seconds": timeout})
        if (result.timed_out or result.oom_killed or result.file_size_limit_reached
                or result.stdout_truncated or result.stderr_truncated):
            raise ExecutionIncomplete("tool execution timed out, was killed, or exceeded an output/resource bound")
        if result.exit_code == 124:
            raise ExecutionIncomplete("tool reached its bounded command deadline")
        data = verify_run_artifact(self.unit.job.run_root, output).read_bytes()
        if len(data) > self.settings.max_output_bytes:
            raise ExecutionIncomplete("tool stdout exceeds the configured bound")
        return result, data, scratch, output

    def record(self, scope: IndexScope, seeds: Sequence[Mapping[str, Any]], result: str, reason: str,
               **extra: Any) -> dict[str, Any]:
        return {
            "scope_id": scope.scope_id, "project_id": scope.project_id, "judgment": result,
            "reason": reason, "seed_locations": seed_locations(scope, seeds),
            "seed_observation_ids": sorted({identity for seed in seeds for identity in seed["observation_ids"]}),
            "function": None, "properties": [], "property_count": 0, "candidate_count": 0,
            "omitted_properties": 0,
            "unwind_limits_attempted": [], "assumptions": list(ASSUMPTIONS),
            "image_id": self.settings.image_id, "gaps": [], **extra,
        }

    def translation_unit(self, scope: IndexScope, row: Mapping[str, Any],
                         seeds: Sequence[Mapping[str, Any]], target: Path) -> list[dict[str, Any]]:
        first_call = len(self.calls)
        try:
            argv, replaced = compile_argv(row)
            result, compiler_output, scratch, _ = self.execute(target, argv, file_bound=self.settings.max_goto_bytes)
            binary = scratch / "unit.goto"
            if result.exit_code != 0:
                raise ExecutionIncomplete(f"GOTO compilation failed with exit {result.exit_code}")
            compiler_output += (self.unit.job.run_root / result.stderr_path).read_bytes()
            if re.search(rb"(?i)\bwarning\b|ignor(?:e|ing).{0,30}option|unsupported.{0,30}option", compiler_output):
                raise ExecutionIncomplete("GOTO compiler reported a warning or ignored an option")
            if (not binary.is_file() or binary.is_symlink()
                    or not 1 <= binary.stat().st_size <= self.settings.max_goto_bytes):
                raise ExecutionIncomplete("compiler omitted or exceeded the bounded GOTO artifact")
            goto = run_artifact(self.unit.job.run_root, binary)
            result, data, _, _ = self.execute(target, (
                "/usr/bin/goto-instrument", "--show-goto-functions", "--json-ui", "/inputs/unit.goto"), goto=goto)
            if result.exit_code != 0:
                raise ExecutionIncomplete(f"GOTO function discovery failed with exit {result.exit_code}")
            entries, unresolved = function_entries(native_json(data, self.settings.max_output_bytes),
                                                   seeds, max_instructions=self.settings.max_instructions)
        except (CompileRejected, OutputRejected, ExecutionIncomplete, BudgetExhausted,
                ImageUnavailableError, SignatureVerificationError, OSError) as exc:
            kind = "not_attempted" if isinstance(exc, (CompileRejected, BudgetExhausted)) else "inconclusive"
            return [self.record(scope, seeds, kind, str(exc)[:500],
                                executions=self.calls[first_call:], gaps=[type(exc).__name__])]
        records = [self.record(scope, [seed], "not_attempted", seed["reason"], gaps=[seed["reason"]])
                   for seed in unresolved]
        for entry in entries:
            if self.function_count >= self.settings.max_functions:
                records.append(self.record(scope, entry["seeds"], "not_attempted", "function budget exhausted",
                                           function=entry["function"], gaps=["function_budget"]))
                continue
            self.function_count += 1
            record = self.record(scope, entry["seeds"], "inconclusive", "no accepted result",
                                 function=entry["function"], goto=goto,
                                 accepted_compile_database=dict(scope.compile_database),
                                 normalized_compile_arguments=list(row["arguments"]),
                                 admitted_compile_arguments=list(argv),
                                 replaced_build_arguments=list(replaced),
                                 executions=list(self.calls[first_call:]))
            rounds = []
            for bound in self.settings.unwind_limits:
                call_start = len(self.calls)
                try:
                    result, data, _, output = self.execute(
                        target, ("/usr/bin/cbmc", "/inputs/unit.goto", "--function", entry["function"],
                                 "--unwind", str(bound), *CHECKS, "--trace", "--json-ui"),
                        goto=goto, expected_counterexample=True)
                    parsed = judgment(native_json(data, self.settings.max_output_bytes), result.exit_code,
                                      max_properties=self.settings.max_properties,
                                      max_trace_steps=self.settings.max_trace_steps,
                                      max_trace_value_chars=self.settings.max_trace_value_chars)
                    map_native_locations(parsed, scope, target)
                    rounds.append({"unwind": bound, "output": output, "judgment": parsed["judgment"]})
                    record.update(parsed, native_output=output, reason="conditional function-entry analysis")
                    if not parsed["retry_unwind"]:
                        break
                except (OutputRejected, ExecutionIncomplete, BudgetExhausted, ImageUnavailableError,
                        SignatureVerificationError, OSError) as exc:
                    record.update(judgment="inconclusive", reason=str(exc)[:500], gaps=[type(exc).__name__])
                    break
                finally:
                    record["executions"].extend(self.calls[call_start:])
            record["unwind_limits_attempted"] = [round_["unwind"] for round_ in rounds]
            record["rounds"] = rounds
            record.pop("retry_unwind", None)
            properties = sorted(record["properties"], key=lambda prop: (
                prop["status"] != "FAILURE", prop["kind"] != "safety" or prop["source"] is None,
                prop["property_id"]))
            record["omitted_properties"] = max(0, len(properties) - self.settings.max_property_summaries)
            record["properties"] = properties[:self.settings.max_property_summaries]
            records.append(record)
        return records
