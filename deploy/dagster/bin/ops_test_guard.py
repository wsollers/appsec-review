"""Exact pytest scope, collection proof and owned wall-clock supervision."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


CONTROL_ENV = "APPSEC_FOCUSED_TEST_CONTROL"
VALUE_OPTIONS = {"-k", "-m", "--maxfail", "--tb", "--durations", "--durations-min",
                 "--capture", "--color", "--shuffle-seed"}
FLAG_OPTIONS = {"-q", "-v", "-s", "-x", "--showlocals", "--disable-warnings",
                "--strict-markers", "--strict-config"}


@dataclass(frozen=True)
class Limits:
    max_tests: int = 200
    expect_tests: int | None = None
    collection_seconds: float = 30.0
    timeout_seconds: float = 120.0

    def __post_init__(self) -> None:
        import math

        if self.max_tests < 1 or self.expect_tests is not None and not 1 <= self.expect_tests <= self.max_tests:
            raise ValueError("expected collection must be positive and no greater than --max-tests")
        if any(not math.isfinite(value) or value <= 0
               for value in (self.collection_seconds, self.timeout_seconds)):
            raise ValueError("collection and total time bounds must be finite and positive")


def exact_selector(root: Path, selection: str, *, allow_heavy: bool) -> str:
    file, separator, node = selection.partition("::")
    if (not file or any(char in file for char in "*?[]")
            or any(char in selection for char in "\n\r\0")
            or separator and (not node or any(not part for part in node.split("::")))):
        raise ValueError(f"not an exact test file/node selector: {selection!r}")
    path = root / file
    resolved = path.resolve()
    if (not resolved.is_relative_to(root / "tests") or not resolved.is_file()
            or resolved.suffix != ".py" or path.absolute() != resolved):
        raise ValueError(f"selector must name an existing, unredirected test file under tests/: {selection!r}")
    relative = resolved.relative_to(root).as_posix()
    parts = resolved.relative_to(root / "tests").parts
    heavy = parts[0] in {"integration", "acceptance", "live"} or "_live" in resolved.stem
    if heavy and not allow_heavy:
        raise ValueError(f"heavy-tier selector requires explicit --allow-heavy: {selection!r}")
    if parts[0] == "acceptance":
        raise ValueError("bounded acceptance requires --acceptance PROFILE, not focused pytest")
    return relative + ("::" + node if separator else "")


def focused_arguments(root: Path, arguments: list[str], *, allow_heavy: bool = False) -> tuple[list[str], list[str]]:
    """Parse only supported options, consuming their operands before interpreting selectors."""
    normalized, selectors = [], []
    index = 0
    while index < len(arguments):
        item = arguments[index]
        option, equals, value = item.partition("=")
        if option in VALUE_OPTIONS:
            if not equals:
                index += 1
                if index == len(arguments):
                    raise ValueError(f"{option} requires an argument")
                value = arguments[index]
            normalized.extend([option, value])
        elif item in FLAG_OPTIONS or re.fullmatch(r"-[qv]{2,3}", item):
            normalized.append(item)
        elif item.startswith("-"):
            raise ValueError(f"unsupported focused pytest option {item!r}; scope/report/worker options belong to run-tests")
        else:
            selector = exact_selector(root, item, allow_heavy=allow_heavy)
            if selector in selectors:
                raise ValueError(f"duplicate test selector: {selector}")
            selectors.append(selector)
            normalized.append(selector)
        index += 1
    if not selectors:
        raise ValueError("focused tests require at least one exact existing test file or node ID")
    return normalized, selectors


def matches(selector: str, node: str) -> bool:
    return node == selector or node.startswith(selector + "::") or node.startswith(selector + "[")


def check_collection(root: Path, nodes: list[str], selectors: list[str], limits: Limits,
                     *, allow_heavy: bool) -> None:
    if not nodes or len(nodes) != len(set(nodes)):
        raise ValueError("collection is empty or contains duplicate node IDs")
    if len(nodes) > limits.max_tests or limits.expect_tests is not None and len(nodes) != limits.expect_tests:
        raise ValueError(f"unexpected collection count {len(nodes)}; expected={limits.expect_tests}, max={limits.max_tests}")
    for node in nodes:
        if exact_selector(root, node, allow_heavy=allow_heavy) != node or "::" not in node:
            raise ValueError(f"collection contains a noncanonical node: {node!r}")
        if selectors and not any(matches(selector, node) for selector in selectors):
            raise ValueError(f"collected node outside requested selectors: {node}")
    for selector in selectors:
        if not any(matches(selector, node) for node in nodes):
            raise ValueError(f"selector collected no tests: {selector}")


def pytest_configure(config) -> None:
    import pytest

    class CollectionGuard:
        @pytest.hookimpl(wrapper=True, tryfirst=True)
        def pytest_collection_modifyitems(self, session):
            result = yield
            verify_collection(session)
            return result

    config.pluginmanager.register(CollectionGuard(), "focused-collection-proof")


def verify_collection(session) -> None:
    """Check after all item modifiers, before xdist publishes its collection to the scheduler."""
    import pytest

    control = json.loads(os.environ[CONTROL_ENV])
    # The xdist controller does not collect tests; each worker must independently match the proof.
    if getattr(session.config.option, "dist", "no") != "no" and not hasattr(session.config, "workerinput"):
        return
    nodes = sorted(item.nodeid for item in session.items)
    output = Path(control["manifest"])
    proof = Path(control["proof_directory"]) / f"{os.getpid()}.json"
    try:
        root = Path(control["root"])
        for item in session.items:
            if Path(item.path).resolve() != (root / item.nodeid.split("::", 1)[0]).resolve():
                raise ValueError(f"collected item path differs from node ID: {item.nodeid}")
        check_collection(root, nodes, control["selectors"], Limits(**control["limits"]),
                         allow_heavy=control["allow_heavy"])
        if control["stage"] == "execute":
            if nodes != json.loads(output.read_text(encoding="utf-8"))["nodes"]:
                raise ValueError("execution collection differs from inspected preflight")
            proof.write_text(json.dumps({"verified": True, "count": len(nodes)}), encoding="utf-8")
        else:
            output.write_text(json.dumps({"nodes": nodes, "count": len(nodes)}, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as error:
        if control["stage"] == "execute":
            proof.write_text(json.dumps({"verified": False, "reason": str(error)}), encoding="utf-8")
        # pytest calls collection_finish even on error; xdist must never schedule rejected nodes.
        session.items.clear()
        session.shouldstop = f"focused collection refused: {error}"
        raise pytest.UsageError(str(error)) from error


def supervise(command: list[str], root: Path, environment: dict[str, str], directory: Path,
              log: Path, *, deadline: float, cleanup_seconds: float) -> dict:
    """Reuse the acceptance runner's gated subreaper/Job Object, never a shared/name-matched PID."""
    from appsec_review.runtime.resources import process_identity
    from ops_tests import _GATE, _WindowsJob, _stop_linux_tree

    directory.mkdir(parents=True, exist_ok=False)
    exit_path = directory / "exit.json"
    bootstrap = sys._base_executable if os.name == "nt" else command[0]
    gate = [bootstrap, "-B", "-c", _GATE, str(exit_path), command[0], *command[3:]]
    started = time.monotonic()
    result = {"command": command, "exit_code": None, "outcome": "error", "cleanup": {"confirmed": True}}
    process = job = None
    generation = None
    execution_end = deadline - cleanup_seconds
    try:
        with log.open("wb") as stream:
            if time.monotonic() >= execution_end:
                raise TimeoutError("no execution budget remains")
            if os.name == "nt":
                job = _WindowsJob()
            elif sys.platform != "linux":
                raise ValueError("owned test supervision requires Linux/WSL or a Windows Job Object")
            process = subprocess.Popen(gate, cwd=root, env=environment, stdin=subprocess.PIPE,
                                       stdout=stream, stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
            result["cleanup"] = {"confirmed": False, "pid": process.pid}
            if job:
                job.assign(process)
            else:
                generation = process_identity(process.pid)
                if generation is None or os.getpgid(process.pid) != process.pid:
                    raise ValueError("owned subreaper identity could not be established")
            while not (directory / "gate.json").is_file():
                if process.poll() is not None:
                    raise ValueError("test gate exited before opening")
                if time.monotonic() >= execution_end:
                    raise TimeoutError("gate startup deadline exceeded")
                time.sleep(0.01)
            assert process.stdin is not None
            process.stdin.write(b"go\n")
            process.stdin.flush()
            while not exit_path.is_file():
                if process.poll() is not None:
                    raise ValueError("test gate exited without a completion receipt")
                if time.monotonic() >= execution_end:
                    raise TimeoutError("hard test deadline exceeded")
                time.sleep(0.01)
            result.update(outcome="completed", exit_code=json.loads(exit_path.read_bytes())["exit_code"])
    except TimeoutError as error:
        result.update(outcome="timeout", reason=str(error))
    except (OSError, ValueError) as error:
        result.update(outcome="error", reason=f"{type(error).__name__}: {error}")
    finally:
        if process is not None:
            try:
                if job:
                    job.terminate()
                    while job.count() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    remaining = job.count()
                elif generation is not None and process_identity(process.pid) == generation:
                    observed, remaining = _stop_linux_tree(process, generation, deadline)
                    result["cleanup"]["observed_processes"] = observed
                    if result["outcome"] == "completed" and observed > 1:
                        result.update(outcome="error", reason="test left descendants running")
                else:
                    remaining = -1 if generation is not None else 0
                    if process.poll() is None:
                        process.kill()
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
                result["cleanup"].update(confirmed=remaining == 0, remaining_processes=remaining)
            except (OSError, subprocess.TimeoutExpired) as error:
                result["cleanup"].update(confirmed=False, reason=str(error))
            finally:
                if process.stdin:
                    process.stdin.close()
        if job:
            job.close()
    if time.monotonic() > deadline:
        result.update(outcome="timeout", reason="deadline including cleanup exceeded")
    if not result["cleanup"]["confirmed"]:
        result.update(outcome="error", reason="owned process cleanup unconfirmed")
    result["elapsed_seconds"] = time.monotonic() - started
    (directory / "supervisor.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result
