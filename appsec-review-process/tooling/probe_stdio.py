"""Bounded LSP/MCP protocol probe with separate raw streams and a capability receipt."""
import argparse
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time


def probe(command, out, mode, root, timeout=60, initialization=None, call=None):
    out = Path(out); out.mkdir(parents=True, exist_ok=False)
    messages = queue.Queue(maxsize=1000)
    transcript = []
    def send(proc, message):
        transcript.append(message)
        body = json.dumps(message).encode()
        proc.stdin.write((b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
                         if mode == 'lsp' else body + b'\n')
        proc.stdin.flush()
    def drain(pipe, name):
        total = 0
        try:
            with (out / name).open('wb') as log:
                while True:
                    if name == 'stderr.log':
                        data = pipe.read1(4096)
                    elif mode == 'mcp':
                        data = pipe.readline(1048577)
                    else:
                        header = b''
                        while not header.endswith(b'\r\n\r\n'):
                            c = pipe.read(1)
                            if not c: break
                            header += c
                            if len(header) > 8192: raise ValueError('oversized LSP header')
                        if not header: break
                        length = next(int(line.split(b':', 1)[1]) for line in header.split(b'\r\n')
                                      if line.lower().startswith(b'content-length:'))
                        if length > 1048576: raise ValueError('oversized LSP body')
                        data = header + pipe.read(length)
                    if not data: break
                    total += len(data)
                    if total > 4 * 1024 * 1024: raise ValueError('probe stream limit')
                    log.write(data); log.flush()
                    if name == 'stdout.log':
                        body = data.split(b'\r\n\r\n', 1)[1] if mode == 'lsp' else data
                        messages.put_nowait(json.loads(body))
        except Exception as exc:
            messages.put_nowait({'probe_error': str(exc)})
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    threads = [threading.Thread(target=drain, args=(pipe, name), daemon=True)
               for pipe, name in [(proc.stdout, 'stdout.log'), (proc.stderr, 'stderr.log')]]
    for thread in threads: thread.start()
    deadline = time.monotonic() + timeout
    def receive(expected):
        while True:
            message = messages.get(timeout=max(.01, deadline-time.monotonic()))
            if 'probe_error' in message: raise RuntimeError(message['probe_error'])
            if message.get('id') == expected and 'method' not in message:
                if 'error' in message: raise RuntimeError(str(message['error']))
                return message['result']
            if 'id' in message and 'method' in message:
                # Explicitly refuse server-initiated workspace edits/configuration side effects.
                send(proc, {'jsonrpc': '2.0', 'id': message['id'], 'error': {'code': -32601, 'message': 'probe has no client handlers'}})
    receipt = {'status': 'FAILED', 'command': command, 'mode': mode, 'root': root}
    try:
        params = {'processId': None, 'rootUri': Path(root).as_uri(), 'capabilities': {},
                  'initializationOptions': initialization or {}} if mode == 'lsp' else {
                      'protocolVersion': '2024-11-05', 'capabilities': {},
                      'clientInfo': {'name': 'appsec-tooling-probe', 'version': '1.0'}}
        send(proc, {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': params})
        receipt['initialize'] = receive(1)
        send(proc, {'jsonrpc': '2.0', 'method': 'initialized' if mode == 'lsp' else 'notifications/initialized', 'params': {}})
        if mode == 'lsp':
            send(proc, {'jsonrpc': '2.0', 'id': 2, 'method': 'shutdown', 'params': None})
            receive(2)
            send(proc, {'jsonrpc': '2.0', 'method': 'exit', 'params': None})
        else:
            send(proc, {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})
            receipt['tools'] = receive(2)
            if not receipt['tools'].get('tools'): raise RuntimeError('empty MCP tools list')
            if call:
                send(proc, {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': call})
                receipt['call'] = receive(3)
                if receipt['call'].get('isError'): raise RuntimeError('MCP tool call failed')
        receipt['status'] = 'PASS'
    except Exception as exc:
        receipt['error'] = repr(exc)
    finally:
        proc.stdin.close()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait(timeout=5)
        for thread in threads: thread.join(timeout=5)
        receipt['exit_code'] = proc.returncode
        if mode == 'lsp' and proc.returncode != 0:
            receipt.update(status='FAILED', error='language server did not shut down successfully')
        (out / 'requests.json').write_text(json.dumps(transcript, indent=2))
        (out / 'receipt.json').write_text(json.dumps(receipt, indent=2))
    return receipt


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True); p.add_argument('--mode', choices=['lsp','mcp'], required=True)
    p.add_argument('--root', default='/workspace'); p.add_argument('--initialization-json')
    p.add_argument('--timeout', type=int, default=60)
    p.add_argument('--call-json'); p.add_argument('command', nargs=argparse.REMAINDER)
    a = p.parse_args()
    command = a.command[1:] if a.command[:1] == ['--'] else a.command
    result = probe(command, a.out, a.mode, a.root, timeout=a.timeout,
                   initialization=json.loads(a.initialization_json) if a.initialization_json else None,
                   call=json.loads(a.call_json) if a.call_json else None)
    print(json.dumps({'status': result['status'], 'mode': a.mode, 'receipt': a.out + '/receipt.json'}))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
