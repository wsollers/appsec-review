"""Shared SVF test fixture: an accepted scope over containers/fixtures/svf and a replaying executor.

The recorded documents under ``recorded/`` are real ``tool-svf`` output for that fixture (``plan.json``
module ``m-app`` = callbacks.c + guard.c + main.c linked, ``m-plugin`` = plugin.c alone). The fake
executor maps the job's planned modules onto them in plan order, so job tests exercise the real
driver contract without Docker.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
from types import MappingProxyType, SimpleNamespace
from typing import Any, Callable

from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.cpp_index_scopes import IndexScope
from appsec_review.runtime import UnitContext
from appsec_review.storage import file_sha256


ROOT = Path(__file__).parents[3]
SOURCE = ROOT / "containers" / "fixtures" / "svf" / "source"
RECORDED = Path(__file__).parent / "recorded"
DIGEST = "sha256:" + "d" * 64
FILES = ("callbacks.c", "guard.c", "main.c", "plugin.c")
LINK_COMMANDS = [{"output_path": "build/app", "input_paths": ["build/callbacks.o", "build/guard.o", "build/main.o"],
                  "receipt": "", "command_sha256": ""}]
SETTINGS = {
    "enabled": True, "workers": 1, "max_modules_per_scope": 8, "max_module_bitcode_bytes": 67108864,
    "max_module_output_bytes": 8388608, "max_output_bytes": 1048576, "field_limit": 64, "max_sites": 2000,
    "max_pts_size": 64, "max_indirect_calls": 200, "max_targets_per_call": 16, "max_unmodeled_names": 16,
    "compile_timeout_seconds": 60, "link_timeout_seconds": 60, "module_timeout_seconds": 120,
    "andersen_time_limit_seconds": 60, "max_objects_per_module": 500, "max_accessors_per_object": 64,
}


def scope(run_root: Path, *, root: str = "native") -> IndexScope:
    case_root = run_root / "data" / "cpp" / "projects" / "case-svf"
    accepted = []
    by_relative = {}
    commands = []
    for name in FILES:
        target = case_root / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / name, target)
        item = {"target_path": f"{root}/{name}", "scratch_path": f"source/{name}", "sha256": file_sha256(target)}
        accepted.append(item)
        by_relative[name] = item
        commands.append({"target_path": f"{root}/{name}", "output_path": f"build/{Path(name).stem}.o",
                         "arguments": ["clang-18", "-std=c11", "-c", f"/scratch/source/{name}"]})
    database = case_root / "build" / "normalized-compile-commands.json"
    database.parent.mkdir(parents=True, exist_ok=True)
    database.write_text(json.dumps(commands), encoding="utf-8")
    return IndexScope(
        scope_id="cpp-scope-svf", case_id="case-svf", project_id="cpp:native", root=root,
        case_snapshot="a" * 64, case_root=case_root, files=tuple(accepted), compile_commands=tuple(commands),
        compile_database={"path": database.relative_to(run_root).as_posix(), "sha256": file_sha256(database),
                          "size_bytes": database.stat().st_size},
        _by_relative=by_relative,
    )


def unit(run_root: Path, settings: dict[str, Any] | None = None, *, job_id: str = "job_svf_alias_analysis",
         repository_root: Path | None = None) -> UnitContext:
    attempt = run_root / "data" / "jobs" / job_id / "attempts" / "attempt_0001"
    unit_root = attempt / "steps" / "analyze" / "tasks" / "scopes"
    unit_root.mkdir(parents=True, exist_ok=True)
    job = SimpleNamespace(run_root=run_root, repository_root=repository_root or run_root.parent,
                          target_root=run_root.parent / "target",
                          source_fingerprint="f" * 64, config=SimpleNamespace(settings=settings or dict(SETTINGS)),
                          attempt_id="attempt_0001")
    return UnitContext(job, "analyze.scopes", "analyze", "scopes", unit_root, MappingProxyType({}))


class ReplayExecutor:
    """Replays the recorded tool-svf run; ``mutate`` may rewrite the result or module documents."""

    def __init__(self, run_root: Path, *, exit_code: int = 0, timed_out: bool = False,
                 mutate: Callable[[dict[str, Any], dict[str, dict[str, Any]]], None] | None = None,
                 raise_error: Exception | None = None, write_result: bool = True):
        self.run_root = run_root
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.mutate = mutate
        self.raise_error = raise_error
        self.write_result = write_result
        self.requests: list[Any] = []

    def execute(self, request):
        if self.raise_error is not None:
            raise self.raise_error
        self.requests.append(request)
        scratch = request.scratch_root
        plan = json.loads((scratch / "plan.json").read_text(encoding="utf-8"))
        recorded = json.loads((RECORDED / "result.json").read_text(encoding="utf-8"))
        documents = {name: json.loads((RECORDED / "modules" / name / "alias.json").read_text(encoding="utf-8"))
                     for name in ("m-app", "m-plugin")}
        by_recorded = {item["module_id"]: item for item in recorded["modules"]}
        modules = []
        outputs: dict[str, dict[str, Any]] = {}
        for planned in plan["modules"]:
            source = "m-app" if planned["kind"] == "link" else "m-plugin"
            item = dict(by_recorded[source])
            item.update({"module_id": planned["module_id"], "kind": planned["kind"], "label": planned["label"],
                         "compile_indexes": planned["compile_indexes"],
                         "output": f"modules/{planned['module_id']}/alias.json"})
            modules.append(item)
            outputs[planned["module_id"]] = json.loads(json.dumps(documents[source]))
        result = {**recorded, "modules": modules}
        if self.mutate is not None:
            self.mutate(result, outputs)
        for module_id, document in outputs.items():
            path = scratch / "modules" / module_id / "alias.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(document), encoding="utf-8")
        if self.write_result:
            (scratch / "result.json").write_text(json.dumps(result), encoding="utf-8")
        raw = scratch / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        (raw / "stdout.bin").write_bytes(b"")
        (raw / "stderr.bin").write_bytes(b"")
        receipt = scratch / "execution.json"
        receipt.write_text("{}", encoding="utf-8")
        relative = lambda path: path.relative_to(self.run_root).as_posix()
        return ExecutionResult(
            "appsec-review/container-execution/1", "tool-svf", "appsec-review/tool-svf:3.3.0", DIGEST, DIGEST,
            "argv", (), {}, "start", "end", self.exit_code, self.timed_out, False, False, False,
            relative(raw / "stdout.bin"), relative(raw / "stderr.bin"), relative(receipt),
            request.file_size_limit_bytes, False,
        )
