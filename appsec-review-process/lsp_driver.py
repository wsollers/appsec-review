#!/usr/bin/env python3
"""Headless, bounded Language Server Protocol client (stdlib only; brief C step 4).

Starts one language server over stdio inside a compiler image, runs ``initialize``/``initialized``,
opens the files the queries name, answers a closed set of questions and shuts the server down:

    definition | references | hover | documentSymbol | workspaceSymbol | incomingCalls | outgoingCalls

Every answer is a locator into the checkout, never a finding. Server output is untrusted data:
locations are re-rooted and dropped (and counted) when they leave ``--root``; names are stripped
of control characters and truncated; server logs and stderr are never copied into the output.
Every failure (server missing, crash, timeout, oversized or malformed message, unsupported
capability, file outside the root or over the size cap) becomes a ``gaps`` record, never an
exception: the document is always written and the exit status is 0 (2 only for a usage error).

Positions: query and output ``line`` is 1-based (as in citations); ``character`` is the LSP
0-based UTF-16 column.

    python3 lsp_driver.py --server gopls --root /workspace/go \\
        --query '{"method": "documentSymbol", "path": "main.go"}'

docs/language-servers.md §4 lists the presets and limits. ``LiveServer`` keeps one initialized server
open for many queries (``lsp_service``'s broker); with ``uri_root`` the server sees the checkout at that
container path (``/workspace``) while files are read from ``root`` on the host, and ``process`` takes an
already started process (a ``docker run --interactive`` child, or a test double speaking over pipes).
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import quote, unquote, urlparse

SCHEMA = "appsec-review/lsp-query-result/1"
METHODS = ("definition", "references", "hover", "documentSymbol", "workspaceSymbol", "incomingCalls", "outgoingCalls")
CAPABILITY = {"definition": "definitionProvider", "references": "referencesProvider", "hover": "hoverProvider",
              "documentSymbol": "documentSymbolProvider", "workspaceSymbol": "workspaceSymbolProvider",
              "incomingCalls": "callHierarchyProvider", "outgoingCalls": "callHierarchyProvider"}
DEFAULT_LIMITS = {"total_seconds": 120.0, "request_seconds": 30.0, "settle_seconds": 0.0,
                  "max_message_bytes": 16 * 1024 * 1024, "max_results": 2000, "max_file_bytes": 2 * 1024 * 1024,
                  "max_queries": 200}
MAX_HEADER_BYTES = 8192
NAME_LIMIT = 200
HOVER_LIMIT = 2000
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
LANGUAGE_IDS = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".cs": "csharp", ".go": "go", ".java": "java", ".js": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".jsx": "javascriptreact", ".ts": "typescript", ".mts": "typescript",
    ".cts": "typescript", ".tsx": "typescriptreact", ".json": "json", ".php": "php", ".py": "python",
    ".rs": "rust", ".rb": "ruby",
}
# Presets per compiler image (docs/language-servers.md §2). {state} is --state-dir.
SERVERS: dict[str, dict[str, Any]] = {
    "clangd": {"argv": ["clangd", "--background-index=false", "--log=error", "--pch-storage=memory"]},
    "gopls": {"argv": ["gopls", "serve"]},
    # The JVM takes user.home from the password database, not HOME; a host uid has no entry.
    "jdtls": {"argv": ["jdtls", "-data", "{state}/jdtls-workspace"], "settle_seconds": 10.0,
              "env": {"JAVA_TOOL_OPTIONS": "-Duser.home={state}/home"}},
    "pylsp": {"argv": ["pylsp"]},
    "basedpyright": {"argv": ["basedpyright-langserver", "--stdio"]},
    "typescript-language-server": {
        "argv": ["typescript-language-server", "--stdio"],
        "initialization_options": {"tsserver": {"path": "/opt/node-lsp/node_modules/typescript/lib"}}},
    "vscode-json-language-server": {"argv": ["vscode-json-language-server", "--stdio"]},
    "rust-analyzer": {"argv": ["rust-analyzer"], "settle_seconds": 5.0,
                      "initialization_options": {"cargo": {"buildScripts": {"enable": False}},
                                                 "procMacro": {"enable": False}}},
    "csharp-ls": {"argv": ["csharp-ls"], "settle_seconds": 5.0},
    "phpactor": {"argv": ["phpactor", "language-server"], "settle_seconds": 3.0,
                 "initialization_options": {"indexer.enabled_watchers": [], "language_server.diagnostics_on_update": False}},
}


class ProtocolError(RuntimeError):
    """The server violated framing or a limit; the session cannot continue."""


def clean(text: Any, limit: int = NAME_LIMIT) -> str | None:
    if not isinstance(text, str):
        return None
    value = _CONTROL.sub(" ", text).strip()
    return value[:limit] or None


def encode(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body


def read_frame(stream: Any, max_bytes: int) -> dict[str, Any] | None:
    """One framed JSON-RPC message; None at clean EOF; ProtocolError on anything malformed."""
    header = b""
    while not header.endswith(b"\r\n\r\n"):
        byte = stream.read(1)
        if not byte:
            if header:
                raise ProtocolError("stream ended inside a message header")
            return None
        header += byte
        if len(header) > MAX_HEADER_BYTES:
            raise ProtocolError("message header exceeds the size cap")
    length = None
    for line in header[:-4].split(b"\r\n"):
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            try:
                length = int(value.strip())
            except ValueError:
                raise ProtocolError("Content-Length is not an integer") from None
    if length is None or length < 0:
        raise ProtocolError("message has no Content-Length")
    if length > max_bytes:
        raise ProtocolError(f"message of {length} bytes exceeds max_message_bytes")
    body = b""
    while len(body) < length:
        chunk = stream.read(length - len(body))
        if not chunk:
            raise ProtocolError("stream ended inside a message body")
        body += chunk
    try:
        message = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProtocolError("message body is not UTF-8 JSON") from None
    if not isinstance(message, dict):
        raise ProtocolError("message is not a JSON object")
    return message


class Session:
    """One server process: a reader thread frames stdout into a queue; stderr is drained and counted."""

    def __init__(self, argv: list[str], root: Path, limits: dict[str, Any], env: dict[str, str], *,
                 cwd: Path | None = None, process: Any = None, root_uri: str | None = None):
        self.limits, self.root = limits, root
        self.root_uri = root_uri or root.as_uri()
        self.process = process if process is not None else subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(cwd or root), env=env)
        self.inbox: queue.Queue = queue.Queue()
        self.stderr_bytes = 0
        self.next_id = 0
        self.notifications = 0
        self.unresolved_includes: dict[str, int] = {}   # uri -> clangd pp_file_not_found diagnostics
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._drain, daemon=True).start()

    def _read(self) -> None:
        try:
            while True:
                message = read_frame(self.process.stdout, self.limits["max_message_bytes"])
                self.inbox.put(("eof", None) if message is None else ("message", message))
                if message is None:
                    return
        except ProtocolError as exc:
            self.inbox.put(("protocol", str(exc)))
        except (OSError, ValueError):
            self.inbox.put(("eof", None))

    def _drain(self) -> None:
        try:
            while True:
                chunk = self.process.stderr.read(65536)
                if not chunk:
                    return
                self.stderr_bytes += len(chunk)
        except (OSError, ValueError):
            return

    def send(self, payload: dict[str, Any]) -> None:
        try:
            self.process.stdin.write(encode(payload))
            self.process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            raise ProtocolError("server closed its input") from None

    def notify(self, method: str, params: Any) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def _answer_server_request(self, message: dict[str, Any]) -> None:
        method, params = message.get("method"), message.get("params")
        if method == "workspace/configuration":
            items = params.get("items") if isinstance(params, dict) else None
            result: Any = [None] * (len(items) if isinstance(items, list) else 0)
        elif method in ("client/registerCapability", "client/unregisterCapability",
                        "window/workDoneProgress/create", "window/showMessageRequest"):
            result = None
        elif method == "workspace/workspaceFolders":
            result = [{"uri": self.root_uri, "name": self.root.name or "root"}]
        else:
            self.send({"jsonrpc": "2.0", "id": message["id"],
                       "error": {"code": -32601, "message": "method not supported by lsp_driver"}})
            return
        self.send({"jsonrpc": "2.0", "id": message["id"], "result": result})

    def request(self, method: str, params: Any, timeout: float) -> dict[str, Any]:
        """The response object for one request, or ProtocolError/TimeoutError."""
        self.next_id += 1
        ident = self.next_id
        self.send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"{method} timed out")
            try:
                kind, value = self.inbox.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError(f"{method} timed out") from None
            if kind == "eof":
                raise ProtocolError("server exited")
            if kind == "protocol":
                raise ProtocolError(value)
            if "method" in value and "id" in value:
                self._answer_server_request(value)
            elif "method" in value:
                self._notification(value)
            elif value.get("id") == ident:
                return value

    def drain_notifications(self, seconds: float) -> None:
        deadline = time.monotonic() + max(0.0, seconds)
        while (remaining := deadline - time.monotonic()) > 0:
            try:
                kind, value = self.inbox.get(timeout=remaining)
            except queue.Empty:
                return
            if kind != "message":
                self.inbox.put((kind, value))
                return
            if "method" in value and "id" in value:
                self._answer_server_request(value)
            elif "method" in value:
                self._notification(value)

    def _notification(self, message: dict[str, Any]) -> None:
        """Counted; only the numeric/enumerated diagnostic code of clangd's missing-include error is kept."""
        self.notifications += 1
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        if message.get("method") == "textDocument/publishDiagnostics" and isinstance(params.get("uri"), str):
            missing = sum(1 for item in params.get("diagnostics") or [] if isinstance(item, dict)
                          and item.get("code") == "pp_file_not_found")
            self.unresolved_includes[params["uri"]] = missing

    def close(self) -> int | None:
        try:
            self.process.stdin.close()
        except OSError:
            pass
        try:
            code = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            try:
                code = self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                code = None
        for stream in (self.process.stdout, self.process.stderr):
            try:
                stream.close()
            except OSError:
                pass
        return code


class Driver:
    def __init__(self, root: Path, limits: dict[str, Any], uri_root: str | None = None):
        self.root, self.limits = root, limits
        self.uri_root = PurePosixPath(uri_root) if uri_root else None
        self.gaps: list[dict[str, Any]] = []
        self.opened: set[str] = set()

    def root_uri(self) -> str:
        return ("file://" + quote(self.uri_root.as_posix())) if self.uri_root else self.root.as_uri()

    def uri(self, relative: str) -> str:
        """The URI the server knows ``relative`` by (its container path when ``uri_root`` is set)."""
        if self.uri_root:
            return "file://" + quote((self.uri_root / relative).as_posix())
        return self.root.joinpath(*PurePosixPath(relative).parts).as_uri()

    def gap(self, kind: str, detail: str, query_index: int | None = None) -> None:
        record = {"kind": kind, "detail": clean(detail, 300) or kind}
        if query_index is not None:
            record["query_index"] = query_index
        self.gaps.append(record)

    # --- paths ---------------------------------------------------------------------------------
    def resolve(self, relative: Any) -> tuple[str, Path] | None:
        if not isinstance(relative, str) or not relative or "\x00" in relative:
            return None
        pure = PurePosixPath(relative.replace("\\", "/"))
        if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
            return None
        path = self.root.joinpath(*pure.parts)
        try:
            real = path.resolve(strict=True)
            real.relative_to(self.root)
        except (OSError, ValueError):
            return None
        if not real.is_file():
            return None
        return pure.as_posix(), real

    def relative_uri(self, uri: Any) -> str | None:
        if not isinstance(uri, str):
            return None
        parsed = urlparse(uri)
        if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
            return None
        if self.uri_root is not None:
            pure = PurePosixPath(unquote(parsed.path))
            try:
                relative_pure = pure.relative_to(self.uri_root)
            except ValueError:
                return None
            if not relative_pure.parts or any(part in ("", ".", "..") for part in relative_pure.parts):
                return None
            return relative_pure.as_posix() if self.resolve(relative_pure.as_posix()) else None
        path = Path(unquote(parsed.path))
        try:
            relative = path.resolve().relative_to(self.root)
        except (OSError, ValueError):
            return None
        return relative.as_posix() if relative.parts else None

    def location(self, uri: Any, range_: Any) -> dict[str, Any] | None:
        path = self.relative_uri(uri)
        start = range_.get("start") if isinstance(range_, dict) else None
        end = range_.get("end") if isinstance(range_, dict) else None
        values = [point.get(key) if isinstance(point, dict) else None
                  for point in (start, end) for key in ("line", "character")]
        if path is None or not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in values):
            return None
        return {"path": path, "start_line": values[0] + 1, "start_character": values[1],
                "end_line": values[2] + 1, "end_character": values[3]}

    # --- documents -----------------------------------------------------------------------------
    def open(self, session: Session, relative: str, real: Path) -> bool:
        if relative in self.opened:
            return True
        size = real.stat().st_size
        if size > self.limits["max_file_bytes"]:
            self.gap("file-too-large", f"{relative}: {size} bytes exceeds max_file_bytes")
            return False
        text = real.read_bytes().decode("utf-8", errors="replace")
        session.notify("textDocument/didOpen", {"textDocument": {
            "uri": self.uri(relative), "languageId": LANGUAGE_IDS.get(real.suffix.lower(), "plaintext"),
            "version": 1, "text": text}})
        self.opened.add(relative)
        return True


def _capable(capabilities: dict[str, Any], method: str) -> bool:
    value = capabilities.get(CAPABILITY[method])
    return value is not None and value is not False


def _locations(driver: Driver, result: Any) -> tuple[list[dict[str, Any]], int]:
    items = result if isinstance(result, list) else ([result] if isinstance(result, dict) else [])
    found, outside = [], 0
    for item in items:
        if not isinstance(item, dict):
            continue
        uri = item.get("targetUri", item.get("uri"))
        range_ = item.get("targetSelectionRange", item.get("targetRange", item.get("range")))
        location = driver.location(uri, range_)
        if location is None:
            outside += 1
        else:
            found.append(location)
    return found, outside


def _symbols(driver: Driver, result: Any, default_path: str | None) -> tuple[list[dict[str, Any]], int]:
    found, outside = [], 0

    def walk(items: Any, container: str | None) -> None:
        nonlocal outside
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            name = clean(item.get("name"))
            if "location" in item:  # SymbolInformation / WorkspaceSymbol
                loc = item["location"] if isinstance(item["location"], dict) else {}
                location = driver.location(loc.get("uri"), loc.get("range", {"start": {"line": 0, "character": 0},
                                                                         "end": {"line": 0, "character": 0}}))
                parent = clean(item.get("containerName"))
            else:  # DocumentSymbol (hierarchical)
                location = driver.location(driver.uri(default_path) if default_path else None, item.get("range"))
                parent = container
            if location is None or name is None:
                outside += 1
            else:
                kind = item.get("kind")
                row = {"name": name, "kind": kind if isinstance(kind, int) else None, **location}
                if parent:
                    row["container"] = parent
                found.append(row)
            if "children" in item:
                walk(item["children"], name)

    walk(result, None)
    return found, outside


def _calls(driver: Driver, result: Any, direction: str) -> tuple[list[dict[str, Any]], int]:
    found, outside = [], 0
    key = "from" if direction == "incomingCalls" else "to"
    for item in result if isinstance(result, list) else []:
        peer = item.get(key) if isinstance(item, dict) else None
        if not isinstance(peer, dict):
            continue
        location = driver.location(peer.get("uri"), peer.get("selectionRange", peer.get("range")))
        name = clean(peer.get("name"))
        if location is None or name is None:
            outside += 1
            continue
        ranges = item.get("fromRanges") if isinstance(item.get("fromRanges"), list) else []
        lines = sorted({r["start"]["line"] + 1 for r in ranges if isinstance(r, dict) and
                        isinstance(r.get("start"), dict) and isinstance(r["start"].get("line"), int)})
        found.append({"name": name, "kind": peer.get("kind") if isinstance(peer.get("kind"), int) else None,
                      **location, "call_lines": lines})
    return found, outside


def _hover_text(result: Any) -> str | None:
    """Hover contents (MarkupContent, MarkedString or a list of them) as control-stripped, capped text."""
    contents = result.get("contents") if isinstance(result, dict) else None
    items = contents if isinstance(contents, list) else [contents]
    parts = [item if isinstance(item, str) else item.get("value") for item in items
             if isinstance(item, str) or isinstance(item, dict)]
    text = "\n".join(part for part in parts if isinstance(part, str))
    value = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]+", " ", text).strip()
    return value[:HOVER_LIMIT] or None


def _sort(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {json.dumps(row, sort_keys=True): row for row in rows}
    return sorted(unique.values(), key=lambda r: (r["path"], r["start_line"], r["start_character"],
                                                  r.get("name") or "", json.dumps(r, sort_keys=True)))


def _code(response: dict[str, Any]) -> str:
    """Only the numeric JSON-RPC code is kept; the server's message text is untrusted."""
    error = response.get("error")
    code = error.get("code") if isinstance(error, dict) else None
    return str(code) if isinstance(code, int) and not isinstance(code, bool) else "unknown"


def _position(query: dict[str, Any]) -> dict[str, int] | None:
    line, character = query.get("line"), query.get("character", 0)
    if (not isinstance(line, int) or isinstance(line, bool) or line < 1 or
            not isinstance(character, int) or isinstance(character, bool) or character < 0):
        return None
    return {"line": line - 1, "character": character}


def run_query(session: Session, driver: Driver, index: int, query: Any,
              capabilities: dict[str, Any], deadline: float) -> dict[str, Any]:
    entry: dict[str, Any] = {"query_index": index, "query": query if isinstance(query, dict) else None,
                             "status": "GAP", "results": [], "dropped_outside_root": 0, "truncated": False}
    method = query.get("method") if isinstance(query, dict) else None
    if method not in METHODS:
        driver.gap("invalid-query", f"query {index}: method must be one of {', '.join(METHODS)}", index)
        return entry
    if not _capable(capabilities, method):
        driver.gap("unsupported", f"query {index}: server does not advertise {CAPABILITY[method]}", index)
        return entry
    timeout = min(driver.limits["request_seconds"], deadline - time.monotonic())
    document = None
    if method != "workspaceSymbol":
        resolved = driver.resolve(query.get("path"))
        if resolved is None:
            driver.gap("path-outside-root", f"query {index}: path is not a regular file under the root", index)
            return entry
        relative, real = resolved
        if not driver.open(session, relative, real):
            return entry
        document = {"uri": driver.uri(relative)}
    if method in ("definition", "references", "hover", "incomingCalls", "outgoingCalls"):
        position = _position(query)
        if position is None:
            driver.gap("invalid-query", f"query {index}: line (1-based) and character (0-based) are required", index)
            return entry
    if method == "definition":
        response = session.request("textDocument/definition", {"textDocument": document, "position": position}, timeout)
    elif method == "references":
        response = session.request("textDocument/references", {
            "textDocument": document, "position": position,
            "context": {"includeDeclaration": bool(query.get("include_declaration", True))}}, timeout)
    elif method == "hover":
        response = session.request("textDocument/hover", {"textDocument": document, "position": position}, timeout)
        if "error" in response:
            driver.gap("server-error", f"query {index}: hover returned error code {_code(response)}", index)
            return entry
        text = _hover_text(response.get("result"))
        rows = [{"path": relative, "start_line": position["line"] + 1, "start_character": position["character"],
                 "text": text}] if text else []
        return _finish(driver, entry, rows, 0)
    elif method == "documentSymbol":
        response = session.request("textDocument/documentSymbol", {"textDocument": document}, timeout)
    elif method == "workspaceSymbol":
        text = query.get("query")
        if not isinstance(text, str) or len(text) > 256:
            driver.gap("invalid-query", f"query {index}: workspaceSymbol needs a query string (<=256 chars)", index)
            return entry
        response = session.request("workspace/symbol", {"query": text}, timeout)
    else:
        prepared = session.request("textDocument/prepareCallHierarchy",
                                   {"textDocument": document, "position": position}, timeout)
        if "error" in prepared:
            driver.gap("server-error", f"query {index}: prepareCallHierarchy returned error code {_code(prepared)}",
                       index)
            return entry
        items = prepared.get("result") if isinstance(prepared.get("result"), list) else []
        rows, outside = [], 0
        for item in items[:10]:
            timeout = min(driver.limits["request_seconds"], deadline - time.monotonic())
            response = session.request(f"callHierarchy/{method}", {"item": item}, timeout)
            if "error" in response:
                driver.gap("server-error", f"query {index}: callHierarchy/{method} returned error code "
                                           f"{_code(response)}", index)
                continue
            found, dropped = _calls(driver, response.get("result"), method)
            rows.extend(found)
            outside += dropped
        return _finish(driver, entry, rows, outside)
    if "error" in response:
        driver.gap("server-error", f"query {index}: {method} returned error code {_code(response)}", index)
        return entry
    result = response.get("result")
    if method in ("definition", "references"):
        rows, outside = _locations(driver, result)
    else:
        rows, outside = _symbols(driver, result, query.get("path") if method == "documentSymbol" else None)
    return _finish(driver, entry, rows, outside)


def _finish(driver: Driver, entry: dict[str, Any], rows: list[dict[str, Any]], outside: int) -> dict[str, Any]:
    rows = _sort(rows)
    cap = driver.limits["max_results"]
    entry.update(status="OK", results=rows[:cap], dropped_outside_root=outside, truncated=len(rows) > cap)
    if len(rows) > cap:
        driver.gap("truncated", f"query {entry['query_index']}: {len(rows)} results capped at {cap}",
                   entry["query_index"])
    return entry


def initialize(session: Session, driver: Driver, initialization_options: Any,
               timeout: float) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """``initialize`` + ``initialized``: (server capabilities, cleaned serverInfo), or None with a gap."""
    root_uri = driver.root_uri()
    root_path = driver.uri_root.as_posix() if driver.uri_root else str(driver.root)
    response = session.request("initialize", {
        "processId": None if driver.uri_root else os.getpid(), "rootUri": root_uri, "rootPath": root_path,
        "workspaceFolders": [{"uri": root_uri, "name": driver.root.name or "root"}],
        "initializationOptions": initialization_options,
        "capabilities": {
            "workspace": {"configuration": True, "workspaceFolders": True, "symbol": {}},
            "textDocument": {"definition": {"linkSupport": True}, "references": {},
                             "hover": {"contentFormat": ["plaintext", "markdown"]},
                             "documentSymbol": {"hierarchicalDocumentSymbolSupport": True},
                             "callHierarchy": {}, "synchronization": {}, "publishDiagnostics": {}}}},
        timeout)
    result = response.get("result")
    if "error" in response or not isinstance(result, dict):
        driver.gap("initialize-failed", "initialize returned an error or no result")
        return None
    capabilities = result.get("capabilities") if isinstance(result.get("capabilities"), dict) else {}
    info = result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else {}
    session.notify("initialized", {})
    return capabilities, {"name": clean(info.get("name")), "version": clean(info.get("version"), 80)}


class LiveServer:
    """One initialized server answering many queries until ``stop`` (``lsp_service``'s broker daemon).

    ``ask`` never raises for a server fault: each answer is a ``results[]`` entry plus the gaps that
    query produced; a protocol failure marks the server dead and every later answer is a gap."""

    def __init__(self, argv: list[str], root: Path, *, limits: dict[str, Any] | None = None,
                 initialization_options: Any = None, env: dict[str, str] | None = None, cwd: Path | None = None,
                 uri_root: str | None = None, process: Any = None):
        self.limits = {**DEFAULT_LIMITS, **(limits or {})}
        self.argv, self.options, self.env, self.cwd, self.process = argv, initialization_options, env, cwd, process
        self.driver = Driver(Path(root).resolve(), self.limits, uri_root)
        self.session: Session | None = None
        self.capabilities: dict[str, Any] = {}
        self.info: dict[str, Any] = {}
        self.alive = False
        self.index = 0

    def start(self) -> bool:
        try:
            self.session = Session(self.argv, self.driver.root, self.limits, dict(self.env or os.environ),
                                   cwd=self.cwd, process=self.process, root_uri=self.driver.root_uri())
        except OSError as exc:
            self.driver.gap("server-start-failed", f"{type(exc).__name__}: {exc.strerror or exc}")
            return False
        try:
            started = initialize(self.session, self.driver, self.options, self.limits["request_seconds"] * 2)
        except (TimeoutError, ProtocolError) as exc:
            self.driver.gap("initialize-failed", str(exc))
            started = None
        if started is None:
            self.session.close()
            return False
        self.capabilities, self.info = started
        if self.limits["settle_seconds"] > 0:
            self.session.drain_notifications(self.limits["settle_seconds"])
        self.alive = True
        return True

    def ask(self, query: Any) -> dict[str, Any]:
        """{"entry": the results[] entry, "gaps": [...], "unresolved_includes": n for the queried file}."""
        before = len(self.driver.gaps)
        index, self.index = self.index, self.index + 1
        entry = {"query_index": index, "query": query if isinstance(query, dict) else None, "status": "GAP",
                 "results": [], "dropped_outside_root": 0, "truncated": False}
        if not self.alive or self.session is None:
            self.driver.gap("server-unavailable", "the server is not running", index)
        else:
            try:
                entry = run_query(self.session, self.driver, index, query, self.capabilities,
                                  time.monotonic() + self.limits["request_seconds"] * 3)
            except TimeoutError as exc:
                self.driver.gap("timeout", f"query {index}: {exc}", index)
            except ProtocolError as exc:
                self.driver.gap("protocol", str(exc), index)
                self.alive = False
        path = query.get("path") if isinstance(query, dict) else None
        uri = self.driver.uri(path) if isinstance(path, str) and self.driver.resolve(path) else None
        missing = self.session.unresolved_includes.get(uri, 0) if (self.session and uri) else 0
        return {"entry": entry, "gaps": self.driver.gaps[before:], "unresolved_includes": missing}

    def stop(self) -> int | None:
        if self.session is None:
            return None
        if self.alive:
            try:
                self.session.request("shutdown", None, min(5.0, self.limits["request_seconds"]))
                self.session.notify("exit", None)
            except (TimeoutError, ProtocolError):
                pass
        self.alive = False
        return self.session.close()


def drive(argv: list[str], root: Path, queries: list[Any], *, limits: dict[str, Any] | None = None,
          initialization_options: Any = None, server_name: str = "custom",
          env: dict[str, str] | None = None) -> dict[str, Any]:
    """Run one bounded session and return the result document (never raises for server faults)."""
    limits = {**DEFAULT_LIMITS, **(limits or {})}
    root = root.resolve()
    driver = Driver(root, limits)
    document: dict[str, Any] = {"schema": SCHEMA, "server": {"name": server_name, "argv": list(argv)},
                                "root": str(root), "limits": limits, "status": "FAILED",
                                "capabilities": {}, "results": [], "gaps": driver.gaps}
    if len(queries) > limits["max_queries"]:
        driver.gap("invalid-query", f"{len(queries)} queries exceed max_queries; extra queries skipped")
        queries = queries[:limits["max_queries"]]
    if not root.is_dir():
        driver.gap("root-missing", "root is not a directory")
        return document
    if not argv or shutil.which(argv[0], path=(env or os.environ).get("PATH")) is None:
        driver.gap("server-missing", f"language server executable not found: {argv[0] if argv else '(none)'}")
        return document
    deadline = time.monotonic() + limits["total_seconds"]
    try:
        session = Session(argv, root, limits, dict(env or os.environ))
    except OSError as exc:
        driver.gap("server-start-failed", f"{type(exc).__name__}: {exc.strerror or exc}")
        return document
    initialized = False
    try:
        started = initialize(session, driver, initialization_options,
                             min(limits["request_seconds"] * 2, deadline - time.monotonic()))
        if started is None:
            return document
        capabilities, document["server"]["info"] = started
        document["capabilities"] = {method: _capable(capabilities, method) for method in METHODS}
        initialized = True
        for index, query in enumerate(queries):
            if isinstance(query, dict) and query.get("method") != "workspaceSymbol":
                resolved = driver.resolve(query.get("path"))
                if resolved is not None:
                    driver.open(session, *resolved)
        settle = limits["settle_seconds"]
        if settle > 0:
            session.drain_notifications(min(settle, max(0.0, deadline - time.monotonic())))
        for index, query in enumerate(queries):
            if time.monotonic() >= deadline:
                driver.gap("timeout", f"total_seconds reached before query {index}", index)
                document["results"].append({"query_index": index, "query": query if isinstance(query, dict) else None,
                                            "status": "GAP", "results": [], "dropped_outside_root": 0,
                                            "truncated": False})
                continue
            try:
                document["results"].append(run_query(session, driver, index, query,
                                                     capabilities, deadline))
            except TimeoutError as exc:
                driver.gap("timeout", f"query {index}: {exc}", index)
                document["results"].append({"query_index": index, "query": query if isinstance(query, dict) else None,
                                            "status": "GAP", "results": [], "dropped_outside_root": 0,
                                            "truncated": False})
    except TimeoutError as exc:
        driver.gap("timeout", str(exc))
    except ProtocolError as exc:
        driver.gap("protocol", str(exc))
    finally:
        if initialized:
            try:
                session.request("shutdown", None, min(5.0, limits["request_seconds"]))
                session.notify("exit", None)
            except (TimeoutError, ProtocolError):
                pass
        exit_code = session.close()
        document["server"]["exit_code"] = exit_code
        document["server"]["stderr_bytes"] = session.stderr_bytes
        document["server"]["notifications"] = session.notifications
    answered = [row for row in document["results"] if row["status"] == "OK"]
    if initialized and len(answered) == len(queries) and not driver.gaps:
        document["status"] = "OK"
    elif initialized and (answered or not queries):
        document["status"] = "OK_WITH_GAPS"
    return document


def _environment(state: Path) -> dict[str, str]:
    env = dict(os.environ)
    home = env.get("HOME")
    if not home or not os.access(home, os.W_OK):
        env["HOME"] = str(state / "home")
    env.setdefault("XDG_CACHE_HOME", str(state / "cache"))
    for key in ("HOME", "XDG_CACHE_HOME"):
        Path(env[key]).mkdir(parents=True, exist_ok=True)
    return env


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    chosen = parser.add_mutually_exclusive_group(required=True)
    chosen.add_argument("--server", choices=sorted(SERVERS))
    chosen.add_argument("--command", help="JSON argv array for a server not in the presets")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--query", action="append", default=[], help="one JSON query object (repeatable)")
    parser.add_argument("--queries-file", type=Path, help="JSON array of query objects")
    parser.add_argument("--initialization-options", help="JSON value overriding the preset's options")
    parser.add_argument("--extra-arg", action="append", default=[], help="appended to the server argv")
    parser.add_argument("--state-dir", type=Path, default=Path("/scratch/lsp-state"))
    parser.add_argument("--out", type=Path, help="write the JSON document here (default stdout)")
    for key, value in DEFAULT_LIMITS.items():
        parser.add_argument("--" + key.replace("_", "-"), type=type(value), default=None)
    args = parser.parse_args(argv)
    try:
        queries = [json.loads(text) for text in args.query]
        if args.queries_file:
            loaded = json.loads(args.queries_file.read_text(encoding="utf-8"))
            if not isinstance(loaded, list):
                raise ValueError("queries file must hold a JSON array")
            queries.extend(loaded)
        preset = SERVERS.get(args.server or "", {})
        if args.command:
            command = json.loads(args.command)
            if not isinstance(command, list) or not command or not all(isinstance(w, str) for w in command):
                raise ValueError("--command must be a non-empty JSON array of strings")
        else:
            command = [word.replace("{state}", str(args.state_dir)) for word in preset["argv"]]
        options = (json.loads(args.initialization_options) if args.initialization_options is not None
                   else preset.get("initialization_options"))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    limits = {key: getattr(args, key) for key in DEFAULT_LIMITS if getattr(args, key) is not None}
    if "settle_seconds" not in limits and "settle_seconds" in preset:
        limits["settle_seconds"] = preset["settle_seconds"]
    try:
        args.state_dir.mkdir(parents=True, exist_ok=True)
        env = _environment(args.state_dir)
    except OSError:
        env = dict(os.environ)
    for key, value in preset.get("env", {}).items():
        env.setdefault(key, value.replace("{state}", str(args.state_dir)))
    result = drive(command + list(args.extra_arg), args.root, queries, limits=limits,
                   initialization_options=options, server_name=args.server or "custom", env=env)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
