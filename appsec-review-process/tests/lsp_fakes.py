"""Test doubles for lsp_service: an in-process JSON-RPC language server over os.pipe() pairs, a launcher
that hands it out instead of a container, and an in-thread daemon spawner. No Docker, no subprocess."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import lsp_driver  # noqa: E402
import lsp_service  # noqa: E402

CAPS = {"definitionProvider": True, "referencesProvider": True, "hoverProvider": True, "callHierarchyProvider": True,
        "documentSymbolProvider": True}


def _uri(path: str) -> str:
    return "file://" + lsp_service.CONTAINER_ROOT + "/" + path


def _range(line: int, start: int = 0, end: int = 4) -> dict[str, Any]:
    return {"start": {"line": line, "character": start}, "end": {"line": line, "character": end}}


class FakeServer:
    """Answers at the asked position: definition there, two references, one caller, one callee, a hover.
    ``diagnostics`` sends clangd's pp_file_not_found for every opened file."""

    def __init__(self, diagnostics: bool = False, version: str = "1.2"):
        self.diagnostics, self.version = diagnostics, version
        self.requests: list[str] = []

    def answer(self, method: str, params: dict[str, Any]) -> Any:
        if method == "initialize":
            return {"capabilities": CAPS, "serverInfo": {"name": "fakels", "version": self.version}}
        position = params.get("position") or {}
        uri = (params.get("textDocument") or {}).get("uri") or (params.get("item") or {}).get("uri")
        line = position.get("line", 0)
        path = uri.split(lsp_service.CONTAINER_ROOT + "/", 1)[-1] if uri else "main.py"
        if method == "textDocument/definition":
            return [{"uri": uri, "range": _range(line, position.get("character", 0))}]
        if method == "textDocument/references":
            return [{"uri": uri, "range": _range(line + 3, 4)}, {"uri": uri, "range": _range(line, 4)},
                    {"uri": "file:///usr/include/stdio.h", "range": _range(1)}]
        if method == "textDocument/hover":
            return {"contents": {"kind": "markdown", "value": f"def {path}:{line + 1}()"}}
        if method == "textDocument/prepareCallHierarchy":
            return [{"name": "fn", "kind": 12, "uri": uri, "range": _range(line), "selectionRange": _range(line)}]
        if method == "callHierarchy/incomingCalls":
            return [{"from": {"name": "caller", "kind": 12, "uri": params["item"]["uri"], "range": _range(line + 5),
                              "selectionRange": _range(line + 5)}, "fromRanges": [_range(line + 6)]}]
        if method == "callHierarchy/outgoingCalls":
            return [{"to": {"name": "callee", "kind": 12, "uri": params["item"]["uri"], "range": _range(0),
                            "selectionRange": _range(0)}, "fromRanges": [_range(line + 1)]}]
        if method == "shutdown":
            return None
        raise KeyError(method)

    def run(self, inbound, outbound) -> None:
        def write(message):
            outbound.write(lsp_driver.encode(message))
            outbound.flush()
        try:
            while True:
                message = lsp_driver.read_frame(inbound, 1 << 24)
                if message is None:
                    return
                method, ident = message.get("method"), message.get("id")
                if ident is None:
                    if method == "exit":
                        return
                    if method == "textDocument/didOpen" and self.diagnostics:
                        uri = message["params"]["textDocument"]["uri"]
                        write({"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics",
                               "params": {"uri": uri, "diagnostics": [{"code": "pp_file_not_found", "message": "x"}]}})
                    continue
                if method is None:
                    continue
                self.requests.append(method)
                try:
                    write({"jsonrpc": "2.0", "id": ident, "result": self.answer(method, message.get("params") or {})})
                except KeyError:
                    write({"jsonrpc": "2.0", "id": ident, "error": {"code": -32601, "message": "no"}})
        except (OSError, ValueError, lsp_driver.ProtocolError):
            return
        finally:
            for stream in (outbound, inbound):
                try:
                    stream.close()
                except OSError:
                    pass


class PipeProcess:
    """A Popen look-alike whose other end is a FakeServer thread in this process."""

    def __init__(self, server: FakeServer):
        to_server_r, to_server_w = os.pipe()
        from_server_r, from_server_w = os.pipe()
        err_r, err_w = os.pipe()
        self.stdin = os.fdopen(to_server_w, "wb")
        self.stdout = os.fdopen(from_server_r, "rb")
        self.stderr = os.fdopen(err_r, "rb")
        os.close(err_w)
        self.thread = threading.Thread(target=server.run, args=(os.fdopen(to_server_r, "rb"),
                                                                  os.fdopen(from_server_w, "wb")), daemon=True)
        self.thread.start()

    def wait(self, timeout: float | None = None) -> int:
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise subprocess.TimeoutExpired("fake", timeout)
        return 0

    def kill(self) -> None:
        try:
            self.stdin.close()
        except OSError:
            pass


class FakeLauncher:
    """Counts starts; ``fail`` makes that many starts raise; ``delay`` widens the race window."""

    def __init__(self, *, fail: int = 0, delay: float = 0.0, diagnostics: bool = False):
        self.lock = threading.Lock()
        self.starts, self.fail, self.delay, self.diagnostics = 0, fail, delay, diagnostics
        self.running: set[str] = set()
        self.stopped: list[str] = []
        self.mounts: list[tuple[str, str]] = []
        self.servers: list[FakeServer] = []

    def start(self, server, name, scratch, mounts):
        with self.lock:
            self.starts += 1
            failing = self.fail > 0
            if failing:
                self.fail -= 1
        time.sleep(self.delay)
        if failing:
            raise RuntimeError("image failed to start")
        fake = FakeServer(diagnostics=self.diagnostics)
        self.servers.append(fake)
        self.mounts = list(mounts)
        with self.lock:
            self.running.add(name)
        return PipeProcess(fake), name

    def alive(self, container_id: str) -> bool:
        return container_id in self.running

    def stop(self, container_id: str) -> bool:
        with self.lock:
            self.running.discard(container_id)
            self.stopped.append(container_id)
        return True


class ThreadSpawner:
    """Runs ``lsp_service.serve`` in a daemon thread (the production spawner starts a detached process)."""

    def __init__(self, launcher: FakeLauncher, native_units=None):
        self.launcher, self.native_units = launcher, native_units
        self.stop = threading.Event()
        self.threads: list[threading.Thread] = []

    def __call__(self, run_id, base, server, lock, idle_seconds):
        thread = threading.Thread(target=lsp_service.serve, args=(run_id, base, server, lock),
                                  kwargs={"launcher": self.launcher, "native_units": self.native_units,
                                          "idle_seconds": idle_seconds, "stop": self.stop}, daemon=True)
        self.threads.append(thread)
        thread.start()

    def shutdown(self) -> None:
        self.stop.set()
        for thread in self.threads:
            thread.join(10)


IMAGE = {"digest": "sha256:" + "a" * 64, "digest_kind": "image-id"}
SNAPSHOT = "sha256:" + "b" * 64
CONTAINER_LIMITS = {"timeout_seconds": 3600, "memory_bytes": 1 << 30, "cpu_millis": 1000, "pids": 128,
                    "tmpfs_bytes": 1 << 26, "stdout_limit_bytes": 1 << 20, "stderr_limit_bytes": 1 << 20}


def python_spec(target: Path, server_key: str = "python", variant: str = "default",
                build_input: dict[str, Any] | None = None) -> dict[str, Any]:
    ready = {"server_key": server_key, "variant": variant,
             "build_input": build_input or {"kind": "none", "sha256": None}}
    return lsp_service.spec(ready, image=IMAGE, source_snapshot_sha256=SNAPSHOT, target=target,
                            limits={"request_seconds": 5.0, "total_seconds": 30.0}, container_limits=CONTAINER_LIMITS)


PROJECT = {"main.py": "def helper():\n    return 1\n\n\ndef main():\n    helper()\n",
           "util.py": "def tool(x):\n    return x\n"}


def write_project(root: Path, files: dict[str, str] = PROJECT) -> Path:
    for path, text in files.items():
        target = root.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root
