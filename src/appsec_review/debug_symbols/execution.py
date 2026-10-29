"""Receipt-bound compiler-image execution with an approved offline LLVM compatibility image."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
import hashlib
import math
from pathlib import Path
import re
import time
from typing import TYPE_CHECKING, Any

from appsec_review.config.assurance import ComponentReleases
from appsec_review.container_runtime.catalog import ContainerCatalog, load_catalog
from appsec_review.container_runtime.executor import (
    ContainerExecutor, ExecutionRequest, ImageUnavailableError, Mount,
)
from appsec_review.debug_symbols._reader_binary import ReaderFailure
from appsec_review.debug_symbols._container_export import ARGUMENTS
from appsec_review.debug_symbols.contract import SymbolIntegrityError
from appsec_review.storage import atomic_bytes, file_sha256
from appsec_review.storage.shared import safe_path

if TYPE_CHECKING:
    from appsec_review.runtime import UnitContext


_LAUNCHER = Path(__file__).with_name("_container_export.py")
_DRIVER = "/opt/appsec/debug-symbol-export.py"
_TOOL_ID = "tool-native-cpp"
_GAPS = {42: "tool_unavailable", 43: "tool_failed", 44: "tool_timeout",
         45: "output_limit", 46: "export_configuration_invalid", 125: "image_incompatible",
         126: "tool_unavailable", 127: "tool_unavailable"}
_COMPATIBLE = {"tool_unavailable", "image_unavailable", "image_incompatible"}


def build_image_identity(image: object) -> dict[str, str]:
    if (not isinstance(image, Mapping)
            or not isinstance(image.get("image_id"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", image["image_id"]) is None
            or not isinstance(image.get("user"), str)
            or re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", image["user"]) is None):
        raise SymbolIntegrityError("accepted build reader image identity is invalid")
    return {"image_id": image["image_id"], "user": image["user"]}


def execution_plan(repository_root: Path, releases: ComponentReleases = ComponentReleases()) -> dict[str, Any]:
    catalog = load_catalog(repository_root)
    tool = catalog.tool(_TOOL_ID)
    if tool.expected_image_id is None or "/usr/bin/python3" not in (
            tool.executable, *tool.additional_executables):
        raise SymbolIntegrityError("managed debug-symbol reader image is not pinned or approved")
    release = releases.values.get("job_debug_symbol_indexing", releases.values.get("platform"))
    return {"schema": "appsec-review/debug-symbol-execution-plan/2",
            "release_id": release,
            "reuse_allowed": release is not None,
            "reuse_unavailable_reason": None if release is not None else "missing_release_identity",
            "runtime_policy": dict(catalog.policy),
            "reader_policy": {"executable": tool.executable,
                              "additional_executables": list(tool.additional_executables),
                              "cpus": tool.cpus, "memory": tool.memory,
                              "pids_limit": tool.pids_limit, "timeout_seconds": tool.timeout_seconds,
                              "output_bytes": tool.output_bytes},
            "fallback": {"image_id": tool.expected_image_id, "user": tool.user}}


class ContainerExporter:
    def __init__(self, unit: UnitContext, plan: Mapping[str, Any],
                 build_image: Mapping[str, Any] | None, key: str, *,
                 executor_factory: Callable[[ContainerCatalog, Path], ContainerExecutor] | None = None):
        self.unit = unit
        self.plan = plan
        self.catalog = load_catalog(unit.job.repository_root)
        if execution_plan(unit.job.repository_root, unit.job.review_policy.releases) != plan:
            raise SymbolIntegrityError("debug-symbol execution plan changed")
        self.build_image = build_image_identity(build_image) if build_image is not None else None
        # Provision a private bind source, not a customer evidence object. The deployed
        # package is verified at startup; exact byte comparison protects staging custody.
        self.payload = _LAUNCHER.read_bytes()
        relative = (unit.unit_root / "provisioning" / "debug-symbol-export.py").relative_to(
            unit.job.run_root).as_posix()
        self.launcher = safe_path(unit.job.run_root, relative)
        atomic_bytes(self.launcher, self.payload)
        self.launcher.chmod(0o444)
        self.scratch = unit.job.attempt_root / "artifacts" / "debug-symbols" / "executions" / key
        self.factory = executor_factory or ContainerExecutor
        self.attempts: list[dict[str, Any]] = []
        self.identity = ""

    def _ref(self, path: Path) -> dict[str, Any]:
        try:
            relative = path.relative_to(self.unit.job.run_root).as_posix()
            verified = safe_path(self.unit.job.run_root, relative)
            if not verified.is_file():
                raise ValueError("execution evidence is not a file")
            return {"path": relative, "sha256": file_sha256(verified),
                    "size_bytes": verified.stat().st_size}
        except (OSError, ValueError) as exc:
            raise SymbolIntegrityError("debug-symbol execution evidence integrity failed") from exc

    def _event(self, event: str, name: str, environment: str, started: float, **details) -> None:
        target = self.unit.job.config.settings.get("compiler_target", "clang")
        self.unit.job.events.write(
            event, unit_id=self.unit.unit_id, compiler_target=target,
            lane="clang_dwarf" if target == "clang" else "msvc_pdb",
            reader=name, environment=environment, record_count=0, artifact_count=1,
            gap_count=int(details.get("outcome", "succeeded") != "succeeded"),
            duration_ms=max(0, int((time.monotonic() - started) * 1000)), **details)

    def __call__(self, name: str, arguments: Sequence[str], source: Path, *,
                 timeout_seconds: float, max_output_bytes: int) -> bytes:
        if name not in ARGUMENTS or tuple(arguments) != ARGUMENTS[name]:
            raise SymbolIntegrityError("unapproved debug-symbol export command")
        if self.launcher.read_bytes() != self.payload:
            raise SymbolIntegrityError("debug-symbol launcher identity changed")
        started = time.monotonic()
        candidates: list[tuple[str, Mapping[str, Any]]] = []
        if self.build_image is not None:
            candidates.append(("build", self.build_image))
        if self.build_image != self.plan["fallback"]:
            candidates.append(("catalog", self.plan["fallback"]))
        for environment, image in candidates:
            remaining = timeout_seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise ReaderFailure("tool_timeout")
            template = self.catalog.tool(_TOOL_ID)
            tool = replace(template, tag=image["image_id"], expected_image_id=image["image_id"],
                           user=image["user"], timeout_seconds=min(
                               template.timeout_seconds, math.ceil(remaining) + 3),
                           output_bytes=min(template.output_bytes, 4096))
            catalog = replace(self.catalog, tools={**self.catalog.tools, tool.tool_id: tool})
            scratch = self.scratch / environment
            request = ExecutionRequest(
                tool_id=tool.tool_id,
                argv=("/usr/bin/python3", "-I", "-S", "-B", _DRIVER, name,
                      str(max_output_bytes), str(remaining)),
                target_root=source, scratch_root=scratch,
                extra_mounts=(Mount(self.launcher, _DRIVER, True, supplied_platform=True),),
                working_directory="/scratch", file_size_limit_bytes=max_output_bytes + 1,
                environment={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/tmp"},
                accepted_exit_codes=frozenset({0, *_GAPS}),
            )
            attempt: dict[str, Any] = {
                "environment": environment, "image_id": image["image_id"],
                "release_id": self.plan["release_id"],
                "launcher_assurance": "supplied_platform_excluded"}
            attempt_started = time.monotonic()
            result = None
            try:
                result = self.factory(catalog, self.unit.job.run_root).execute(request)
            except ValueError as exc:
                self._event("DEBUG_SYMBOL_READER_COMPLETED", name, environment, attempt_started,
                            image_id=image["image_id"], outcome="identity_rejected", output_bytes=0)
                raise SymbolIntegrityError("debug-symbol container identity or isolation changed") from exc
            except ImageUnavailableError:
                outcome = "image_unavailable"
            except Exception:
                self.attempts.append({**attempt, "outcome": "execution_failed"})
                self._event("DEBUG_SYMBOL_READER_COMPLETED", name, environment, attempt_started,
                            image_id=image["image_id"], outcome="execution_failed")
                raise
            finally:
                if scratch.is_dir():
                    scratch.chmod(0o700)
            if result is not None:
                if result.image_id != image["image_id"]:
                    raise SymbolIntegrityError("debug-symbol executed image differs from accepted image")
                receipt = safe_path(self.unit.job.run_root, result.receipt_path)
                attempt["execution"] = self._ref(receipt)
                outcome = ("tool_timeout" if result.timed_out else "tool_oom" if result.oom_killed
                           else "output_limit" if result.file_size_limit_reached
                           else "succeeded" if result.exit_code == 0
                           else _GAPS.get(result.exit_code, "tool_failed"))
                for field, path in (("output", scratch / "export.bin"),
                                    ("diagnostics", scratch / "export.stderr")):
                    if path.exists():
                        attempt[field] = self._ref(path)
                        if path.stat().st_size > max_output_bytes:
                            outcome = "output_limit"
            attempt["outcome"] = outcome
            self.attempts.append(attempt)
            self._event("DEBUG_SYMBOL_READER_COMPLETED", name, environment, attempt_started,
                        image_id=image["image_id"], outcome=outcome,
                        output_bytes=attempt.get("output", {}).get("size_bytes", 0))
            if outcome == "succeeded":
                if "output" not in attempt:
                    raise SymbolIntegrityError("successful debug-symbol export has no retained output")
                if self.launcher.read_bytes() != self.payload:
                    raise SymbolIntegrityError("debug-symbol launcher identity changed")
                self.identity = f"{name}@{image['image_id']}:{self.plan['release_id'] or 'undeclared'}"
                with safe_path(self.unit.job.run_root, attempt["output"]["path"]).open("rb") as stream:
                    data = stream.read(max_output_bytes + 1)
                if (len(data) != attempt["output"]["size_bytes"]
                        or hashlib.sha256(data).hexdigest() != attempt["output"]["sha256"]):
                    raise SymbolIntegrityError("debug-symbol retained export changed")
                return data
            if environment == "build" and outcome in _COMPATIBLE and len(candidates) > 1:
                self._event("DEBUG_SYMBOL_READER_FALLBACK", name, environment, attempt_started,
                            reason=outcome)
                continue
            raise ReaderFailure(outcome)
        raise ReaderFailure("tool_unavailable")
