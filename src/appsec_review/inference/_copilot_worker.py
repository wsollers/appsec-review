"""Synchronous worker ownership of a single event loop and its authenticated SDK transport."""
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
from dataclasses import dataclass
import math
import os
from pathlib import Path
import tempfile
import threading
import time

from .errors import ExecutionContractError, FailureCategory, ModelTimeout, ProviderError, failure_category


_CLEANUP_SECONDS = 5
_CATALOG_TTL_SECONDS = 300
_catalog_clock = time.monotonic
_startup_clock = time.monotonic
_local = threading.local()


class _UnconfirmedTeardown(ExecutionContractError):
    """Never reuse a worker whose SDK cleanup could not be confirmed."""


@asynccontextmanager
async def _managed(manager, label: str):
    """Treat an interrupted/failed SDK exit as unconfirmed cleanup, never as success."""
    entered = False
    body_error = None
    try:
        async with manager as value:
            entered = True
            try:
                yield value
            except BaseException as error:
                body_error = error
                raise
    except BaseException as error:
        if not entered or error is body_error:
            raise
        failure = _cleanup_failure(f"Copilot {label} teardown failed")
        cancellation = next((item for item in (body_error, error) if item is not None and
                             failure_category(item) is FailureCategory.CANCELLED), None)
        if cancellation is not None:
            cancellation.add_note(str(failure))
            raise cancellation from failure
        raise failure from error
    if body_error is not None:
        # An SDK context manager may not suppress cancellation or an application failure.
        raise body_error


def auth_home() -> Path:
    return Path(os.environ.get("APPSEC_COPILOT_HOME") or
                Path.home() / ".config" / "appsec-review" / "copilot").expanduser().resolve()


@asynccontextmanager
async def _client():
    try:
        from copilot import CopilotClient
    except ImportError as exc:
        raise ProviderError("Copilot SDK is unavailable; install appsec-review[copilot]",
                            code="sdk_unavailable") from exc
    home = auth_home()
    if not home.is_dir():
        raise ProviderError("Copilot worker login is missing", code="authentication_missing")
    # Git's identity must never become the inference identity, even when inherited from CI.
    environment = {key: value for key, value in os.environ.items()
                   if key not in {"GH_TOKEN", "GITHUB_TOKEN", "COPILOT_GITHUB_TOKEN",
                                  "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY"}}
    environment["COPILOT_HOME"] = str(home)
    environment["COPILOT_SKIP_CLI_DOWNLOAD"] = "1"
    environment["COPILOT_GITHUB_TELEMETRY_DISABLED"] = "true"
    async with _managed(_private_directory("appsec-copilot-"), "transport directory") as working:
        client = CopilotClient(
            mode="empty", base_directory=str(home), working_directory=working,
            env=environment, use_logged_in_user=True,
        )
        # Register stop before startup: cancellation can interrupt __aenter__ after spawning the CLI.
        async with _managed(_stopping(client), "client"):
            await client.start()
            status = await client.get_auth_status()
            if not status.isAuthenticated:
                raise ProviderError("Copilot worker subscription login is required in APPSEC_COPILOT_HOME",
                                    code="authentication_missing")
            yield client


@asynccontextmanager
async def _private_directory(prefix):
    with tempfile.TemporaryDirectory(prefix=prefix) as path:
        yield path


@asynccontextmanager
async def _stopping(client):
    try:
        yield
    finally:
        await client.stop()


def _cleanup_failure(message: str, *, pending_tasks: int = 0) -> ExecutionContractError:
    from appsec_review.runtime import execution_safety as safety
    from appsec_review.runtime.resources import quarantine_resources
    error = _UnconfirmedTeardown(message)
    try:
        quarantine_resources("copilot_teardown_unconfirmed")
    except Exception as failure:
        error.add_note(f"Copilot resource quarantine failed ({type(failure).__name__})")
    try:
        safety.retain_failure("copilot.cleanup", error, pending_tasks=pending_tasks, category="contract")
    except Exception as failure:
        error.add_note(f"Copilot cleanup evidence publication failed ({type(failure).__name__})")
    return error


def _cleanup_over(original: BaseException | None, cleanup: BaseException):
    if original is not None and failure_category(original) is FailureCategory.CANCELLED:
        original.add_note(str(cleanup))
        raise original from cleanup
    raise cleanup from original


def _cancel_tasks(loop, tasks, deadline):
    if not tasks:
        return
    for task in tasks:
        task.cancel()
    done, pending = loop.run_until_complete(asyncio.wait(tasks, timeout=max(0, deadline - time.monotonic())))
    if pending:
        raise _cleanup_failure("Copilot teardown exceeded its cancellation bound", pending_tasks=len(pending))
    for task in done:
        try:
            task.result()
        except asyncio.CancelledError as cancelled:
            if isinstance(cancelled.__cause__, _UnconfirmedTeardown):
                raise cancelled.__cause__
        except _UnconfirmedTeardown:
            raise
        except BaseException as error:
            raise _cleanup_failure("Copilot cancellation cleanup failed") from error


@dataclass
class ConnectionObservation:
    client_reused: bool | None = None
    client_cold_start_ms: int | None = None


class _Worker:
    def __init__(self):
        self.loop = None
        self.stack = AsyncExitStack()
        self.client = None
        self.catalog = {}
        self.home = None
        self.expires = 0.0
        self.transport_tasks = set()
        self.poisoned = False

    async def connection(self, observation: ConnectionObservation | None):
        if observation is not None:
            observation.client_reused = self.client is not None
            if observation.client_reused:
                observation.client_cold_start_ms = 0
        if self.client is not None:
            # A cached catalog must not make a dead connection look healthy.
            await self.client.ping()
        else:
            started = _startup_clock()
            before = asyncio.all_tasks()
            self.home = auth_home()
            try:
                self.client = await self.stack.enter_async_context(_client())
                self.catalog = {item.id: item for item in await self.client.list_models()}
                self.expires = _catalog_clock() + _CATALOG_TTL_SECONDS
            finally:
                self.transport_tasks = asyncio.all_tasks() - before
                if observation is not None:
                    observation.client_cold_start_ms = int((_startup_clock() - started) * 1000)
        return self.client, self.catalog

    def close(self, deadline):
        loop = self.loop
        if loop is None:
            return
        self.loop, self.client, self.catalog = None, None, {}
        self.transport_tasks.clear()
        stack, self.stack = self.stack, AsyncExitStack()
        try:
            close = loop.create_task(stack.aclose())
            done, _ = loop.run_until_complete(asyncio.wait({close}, timeout=max(0, deadline - time.monotonic())))
            if not done:
                raise _cleanup_failure("Copilot client teardown exceeded its cancellation bound")
            close.result()
        except _UnconfirmedTeardown:
            self.poisoned = True
            raise
        except BaseException as error:
            self.poisoned = True
            raise _cleanup_failure("Copilot client teardown failed") from error
        finally:
            try:
                _cancel_tasks(loop, asyncio.all_tasks(loop), deadline)
            except BaseException:
                self.poisoned = True
                raise
            finally:
                loop.close()

    def run(self, operation, timeout_seconds, *, one_shot=False):
        from appsec_review.runtime import execution_safety as safety
        deadline = time.monotonic() + timeout_seconds
        try:
            if self.poisoned:
                raise ExecutionContractError("Copilot worker teardown is unconfirmed")
            safety.check_running()
            if self.client is not None and (_catalog_clock() >= self.expires or self.home != auth_home()):
                # list_models caches until disconnect in the pinned SDK. Rotating just the
                # adapter's dict would silently reuse expired availability/authorization data.
                self.close(min(deadline, time.monotonic() + _CLEANUP_SECONDS))
                safety.check_running()
            if self.loop is None:
                self.loop = asyncio.new_event_loop()
            if time.monotonic() >= deadline:
                raise ModelTimeout("Copilot call timed out")
            task = self.loop.create_task(operation)
        except BaseException:
            operation.close()
            raise

        async def bounded():
            while not task.done():
                safety.check_running()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ModelTimeout("Copilot call timed out")
                await asyncio.wait({task}, timeout=min(0.1, remaining))
            try:
                safety.check_running()
            except BaseException as stop:
                # The STOP poll can race a task that already raised a cleanup failure.
                # Observe that failure as well, preserving cancellation as control flow.
                try:
                    task.result()
                except BaseException as error:
                    cleanup = error if isinstance(error, _UnconfirmedTeardown) else error.__cause__
                    if isinstance(cleanup, _UnconfirmedTeardown):
                        _cleanup_over(stop, cleanup)
                raise
            return task.result()

        try:
            result = self.loop.run_until_complete(bounded())
        except TimeoutError as error:
            original = (error.__cause__ if isinstance(error.__cause__, _UnconfirmedTeardown)
                        else ModelTimeout("Copilot call timed out"))
        except ConnectionError:
            original = ProviderError("Copilot connection failed", code="network", retryable=True)
        except BaseException as error:
            original = error
        else:
            original = None

        cleanup_deadline = time.monotonic() + _CLEANUP_SECONDS
        try:
            # Startup RPC readers belong to the client, not the session. Leave them running
            # until stop; never let an unfinished request/abort task escape into another turn.
            _cancel_tasks(self.loop, asyncio.all_tasks(self.loop) - self.transport_tasks, cleanup_deadline)
        except BaseException as cleanup:
            self.poisoned = True
            try:
                self.close(cleanup_deadline)
            finally:
                _cleanup_over(original, cleanup)
        if original is not None:
            if isinstance(original, _UnconfirmedTeardown) or isinstance(original.__cause__, _UnconfirmedTeardown):
                self.poisoned = True
            try:
                self.close(cleanup_deadline)
            except BaseException as cleanup:
                _cleanup_over(original, cleanup)
            raise original
        if one_shot:
            self.close(min(deadline, cleanup_deadline))
        return result


@contextmanager
def worker_scope():
    """Own a lazy synchronous Copilot transport for one worker on this thread; close on exit.

    Standalone send/models calls are one-shot. Scopes never inherit another thread's
    client or session, including when a caller copies its context into a thread pool.
    """
    previous = getattr(_local, "worker", None)
    worker = _local.worker = _Worker()
    try:
        yield
    except BaseException as original:
        try:
            worker.close(time.monotonic() + _CLEANUP_SECONDS)
        except BaseException as cleanup:
            _cleanup_over(original, cleanup)
        raise
    else:
        worker.close(time.monotonic() + _CLEANUP_SECONDS)
    finally:
        _local.worker = previous


def _run(operation, timeout_seconds: int):
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0):
        operation.close()
        raise ExecutionContractError("Copilot timeout_seconds must be finite and positive")
    worker = getattr(_local, "worker", None)
    if worker is not None:
        return worker.run(operation, timeout_seconds)
    with worker_scope():
        return _local.worker.run(operation, timeout_seconds, one_shot=True)


async def _connection(observation: ConnectionObservation | None = None):
    return await _local.worker.connection(observation)
