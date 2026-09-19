#!/usr/bin/env python3
"""Small JSON-RPC smoke probe for stdio language servers.

The probe sends initialize, initialized, shutdown, and exit. It treats one
well-formed initialize response as success and keeps all writes in /scratch.
"""
from __future__ import annotations

import argparse
import json
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path


def encode(payload: dict) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body


def read_message(proc: subprocess.Popen[bytes], timeout: float) -> dict | None:
    assert proc.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    buffer = b""

    while time.monotonic() < deadline:
        remaining = max(0.1, deadline - time.monotonic())
        events = selector.select(remaining)
        if not events:
            continue
        chunk = proc.stdout.read1(4096)
        if not chunk:
            return None
        buffer += chunk
        header_end = buffer.find(b"\r\n\r\n")
        if header_end == -1:
            continue
        headers = buffer[:header_end].decode("ascii", errors="replace").split("\r\n")
        content_length = None
        for header in headers:
            name, _, value = header.partition(":")
            if name.lower() == "content-length":
                content_length = int(value.strip())
                break
        if content_length is None:
            raise RuntimeError("language server response missing Content-Length")
        body_start = header_end + 4
        if len(buffer) < body_start + content_length:
            continue
        return json.loads(buffer[body_start : body_start + content_length])
    return None


def send(proc: subprocess.Popen[bytes], payload: dict) -> None:
    assert proc.stdin is not None
    proc.stdin.write(encode(payload))
    proc.stdin.flush()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--root", default="/workspace")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--initialization-options-json", default=None)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("missing language server command")

    root = Path(args.root).resolve()
    env = os.environ.copy()
    env.setdefault("HOME", "/tmp/home")
    env.setdefault("XDG_CACHE_HOME", "/scratch/.cache")

    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(root),
        env=env,
    )
    try:
        initialize_options = {}
        if args.initialization_options_json:
            initialize_options = json.loads(args.initialization_options_json)
        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": None,
                "rootUri": root.as_uri(),
                "capabilities": {},
                "initializationOptions": initialize_options,
                "workspaceFolders": [{"uri": root.as_uri(), "name": root.name}],
            },
        }
        send(proc, initialize)
        response = None
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            message = read_message(proc, max(0.1, deadline - time.monotonic()))
            if message is None:
                break
            if message.get("id") == 1:
                response = message
                break
        if response is None:
            stderr = b""
            if proc.stderr is not None:
                try:
                    stderr = proc.stderr.read1(4096)
                except Exception:
                    stderr = b""
            print(f"{args.name}: no initialize response", file=sys.stderr)
            if stderr:
                print(stderr.decode("utf-8", errors="replace"), file=sys.stderr)
            return 1
        if response.get("id") != 1 or "result" not in response:
            print(f"{args.name}: unexpected initialize response: {response}", file=sys.stderr)
            return 1
        send(proc, {"jsonrpc": "2.0", "method": "initialized", "params": {}})
        send(proc, {"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": None})
        read_message(proc, min(5.0, args.timeout))
        send(proc, {"jsonrpc": "2.0", "method": "exit", "params": None})
        print(f"{args.name}: initialized")
        return 0
    finally:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
