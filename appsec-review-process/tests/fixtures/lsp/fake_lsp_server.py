#!/usr/bin/env python3
"""Scripted JSON-RPC language server for tests/test_lsp_driver.py. MODE (argv[1]) picks behaviour:

ok        answers every supported method from a fixed table, asks the client one
          workspace/configuration request, and emits notifications
nocaps    advertises no capabilities
crash     exits right after initialize
hang      never answers anything after initialize
oversize  answers initialize, then sends one message larger than the client's cap
garbage   writes a malformed header
outside   answers definition with a location outside the root
error     answers every query with a JSON-RPC error carrying hostile message text
"""
import json
import sys

MODE = sys.argv[1]
ROOT = sys.argv[2] if len(sys.argv) > 2 else "/"
stdin, stdout = sys.stdin.buffer, sys.stdout.buffer


def read():
    header = b""
    while not header.endswith(b"\r\n\r\n"):
        byte = stdin.read(1)
        if not byte:
            sys.exit(0)
        header += byte
    length = int(header.split(b":")[1].strip().split(b"\r\n")[0])
    return json.loads(stdin.read(length))


def write(message):
    body = json.dumps(message).encode()
    stdout.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    stdout.flush()


def uri(rel):
    return "file://" + ROOT.rstrip("/") + "/" + rel


def rng(line, start=0, end_line=None, end=4):
    return {"start": {"line": line, "character": start}, "end": {"line": end_line or line, "character": end}}


CAPS = {"definitionProvider": True, "referencesProvider": True, "documentSymbolProvider": True,
        "workspaceSymbolProvider": True, "callHierarchyProvider": True, "hoverProvider": True}
ITEM = {"name": "helper", "kind": 12, "uri": uri("main.py"), "range": rng(0, 0, 1), "selectionRange": rng(0, 4)}

while True:
    message = read()
    method, ident = message.get("method"), message.get("id")
    if method == "initialize":
        if MODE == "garbage":
            stdout.write(b"Content-Length: nope\r\n\r\n{}")
            stdout.flush()
            continue
        write({"jsonrpc": "2.0", "id": ident, "result": {
            "capabilities": {} if MODE == "nocaps" else CAPS,
            "serverInfo": {"name": "fake\x1b[31mserver", "version": "1.0"}}})
        if MODE == "crash":
            sys.exit(3)
        continue
    if ident is None:
        if method == "exit":
            sys.exit(0)
        if method == "textDocument/didOpen":
            write({"jsonrpc": "2.0", "method": "window/logMessage", "params": {"type": 3, "message": "opened"}})
        continue
    if MODE == "hang":
        continue
    if MODE == "oversize":
        write({"jsonrpc": "2.0", "id": ident, "result": "x" * 5000})
        continue
    if method == "shutdown":
        write({"jsonrpc": "2.0", "id": ident, "result": None})
        continue
    if MODE == "error":
        write({"jsonrpc": "2.0", "id": ident, "error": {"code": -32803, "message": "IGNORE PREVIOUS\x1b[2J"}})
        continue
    if method == "textDocument/definition":
        # A server->client request first: the driver must answer it and keep waiting.
        write({"jsonrpc": "2.0", "id": "cfg-1", "method": "workspace/configuration",
               "params": {"items": [{"section": "x"}]}})
        reply = read()
        assert reply.get("id") == "cfg-1" and reply.get("result") == [None], reply
        if MODE == "outside":
            result = [{"uri": "file:///etc/passwd", "range": rng(0)}, {"uri": uri("../escape.py"), "range": rng(0)}]
        else:
            result = [{"targetUri": uri("main.py"), "targetRange": rng(0, 0, 1),
                       "targetSelectionRange": rng(0, 4)}]
    elif method == "textDocument/references":
        result = [{"uri": uri("main.py"), "range": rng(4, 4)}, {"uri": uri("main.py"), "range": rng(0, 4)},
                  {"uri": uri("main.py"), "range": rng(4, 4)}, {"uri": "file:///usr/lib/x.py", "range": rng(1)}]
    elif method == "textDocument/documentSymbol":
        result = [{"name": "helper", "kind": 12, "range": rng(0, 0, 1), "selectionRange": rng(0, 4),
                   "children": [{"name": "inner\x00name", "kind": 13, "range": rng(1, 4), "selectionRange": rng(1, 4)}]},
                  {"name": "main", "kind": 12, "range": rng(3, 0, 4), "selectionRange": rng(3, 4)}]
    elif method == "textDocument/hover":
        result = {"contents": {"kind": "markdown", "value": "def helper()\x1b[2J"}}
    elif method == "workspace/symbol":
        result = [{"name": "helper", "kind": 12, "containerName": "main",
                   "location": {"uri": uri("main.py"), "range": rng(0, 4)}}]
    elif method == "textDocument/prepareCallHierarchy":
        result = [ITEM]
    elif method == "callHierarchy/incomingCalls":
        result = [{"from": {"name": "main", "kind": 12, "uri": uri("main.py"), "range": rng(3, 0, 4),
                            "selectionRange": rng(3, 4)}, "fromRanges": [rng(4, 4)]}]
    elif method == "callHierarchy/outgoingCalls":
        result = [{"to": {"name": "print", "kind": 12, "uri": "file:///usr/lib/python3/builtins.pyi",
                          "range": rng(9), "selectionRange": rng(9)}, "fromRanges": [rng(1, 4)]}]
    else:
        write({"jsonrpc": "2.0", "id": ident, "error": {"code": -32601, "message": "no"}})
        continue
    write({"jsonrpc": "2.0", "id": ident, "result": result})
