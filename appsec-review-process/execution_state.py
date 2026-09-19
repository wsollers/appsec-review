"""Run-owned persistence and bounded subprocess execution. No target commands are inferred.

Completed attempts are append-only. OS advisory locks are never deleted or stolen.
The caller holds the job lock across pre/work/post (Dagster uses its in-process executor).
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
RUNS = Path(os.environ.get('APPSEC_RUNS_ROOT', ROOT / 'runs'))


class Blocked(RuntimeError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,119}', value):
        raise ValueError(f'invalid identifier: {value!r}')
    if value.upper().split('.')[0] in {'CON', 'PRN', 'AUX', 'NUL', *[f'COM{i}' for i in range(10)], *[f'LPT{i}' for i in range(10)]}:
        raise ValueError('reserved identifier')
    return value


def beneath(root, path):
    root, path = Path(root).absolute(), Path(path).absolute()
    # Reject links, including in existing ancestors, rather than following an in-root alias.
    try:
        path.relative_to(root)
        path.resolve().relative_to(root.resolve())
    except ValueError:
        raise ValueError(f'path escapes owning root: {path}') from None
    for part in [path, *path.parents]:
        if part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction()) or (part.exists() and getattr(part.lstat(), 'st_reparse_tag', 0)):
            raise ValueError(f'linked path forbidden: {part}')
        if part == root:
            break
    return path


def run_path(run_id):
    return beneath(RUNS, RUNS / identifier(run_id))


def data_path(run_id, *parts):
    root = run_path(run_id) / 'data'
    return beneath(root, root.joinpath(*parts))


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def file_hash(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def atomic_json(path, value):
    atomic_bytes(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())


def atomic_bytes(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name('.' + uuid.uuid4().hex[:12] + '.tmp')
    try:
        with temp.open('xb') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        if os.name != 'nt':
            fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        temp.unlink(missing_ok=True)


def emergency(exc):
    print(f'EMERGENCY_EVIDENCE_FAILURE: {type(exc).__name__}: {exc}; fail closed, resume under the job lock', file=sys.stderr, flush=True)


class Lock:
    """Nonblocking process-owned lock. Kernel releases it on crash, including Windows."""
    def __init__(self, path):
        self.path, self.stream = Path(path), None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = self.path.open('a+b')
        self.stream.seek(0, 2)
        if self.stream.tell() == 0:
            self.stream.write(b'\0')
            self.stream.flush()
        self.stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            self.stream = None
            raise Blocked(f'active lock: {self.path}; retry after owner exits; never delete lock files') from None
        return self

    def __exit__(self, *args):
        if self.stream:
            self.stream.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
            self.stream.close()
            self.stream = None


def event(path, kind, **details):
    with Path(path).open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'time': now(), 'event': kind, **details}, sort_keys=True) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def tree_hashes(root):
    root = Path(root)
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            beneath(root, Path(directory) / name)
        for name in sorted(files):
            p = Path(directory) / name
            if p.is_file():
                result[p.relative_to(root).as_posix()] = file_hash(p)
    return dict(sorted(result.items()))


def redact_argv(argv):
    result, hide = [], False
    for arg in argv:
        arg = re.sub(r'://[^/\s]+:[^/@\s]+@', '://[REDACTED]@', arg)
        if hide:
            result.append('[REDACTED]')
            hide = False
        elif re.search(r'(?i)(password|token|secret|api[-_]?key)', arg):
            key, sep, value = arg.partition('=')
            result.append(key + '=[REDACTED]' if sep else (key if key.startswith('-') else '[REDACTED]'))
            hide = not sep
        else:
            result.append(arg)
    return result


class ProcessTree:
    """Job Object on Windows; process session on POSIX. Kill descendants on every exit."""
    def __init__(self):
        self.handle = None
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes
            class IO(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulonglong) for n in ('r', 'w', 'o', 'rb', 'wb', 'ob')]
            class BASIC(ctypes.Structure):
                _fields_ = [('process', ctypes.c_longlong), ('job', ctypes.c_longlong), ('flags', wintypes.DWORD), ('min', ctypes.c_size_t), ('max', ctypes.c_size_t), ('active', wintypes.DWORD), ('affinity', ctypes.c_size_t), ('priority', wintypes.DWORD), ('scheduling', wintypes.DWORD)]
            class EXT(ctypes.Structure):
                _fields_ = [('basic', BASIC), ('io', IO), ('pml', ctypes.c_size_t), ('jml', ctypes.c_size_t), ('ppmu', ctypes.c_size_t), ('pjmu', ctypes.c_size_t)]
            self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
            self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            self.kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
            self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            self.handle = self.kernel.CreateJobObjectW(None, None)
            info = EXT(); info.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE
            if not self.handle or not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise OSError('cannot establish Windows process-tree isolation')

    def assign(self, proc):
        self.proc = proc
        if self.handle and not self.kernel.AssignProcessToJobObject(self.handle, int(proc._handle)):
            proc.kill(); proc.wait()
            raise OSError('cannot assign child to Windows Job Object')

    def close(self):
        if self.handle:
            self.kernel.TerminateJobObject(self.handle, 1)
            self.kernel.CloseHandle(self.handle)
            self.handle = None
        elif getattr(self, 'proc', None):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.proc.pid, signal.SIGKILL)


def execute(argv, cwd, log_dir, timeout, cancel=None, env=None, observer=None):
    """Two bounded draining threads; no captured-output accumulation or shell interpolation.

    UI observes byte counts only, avoiding raw secret leakage. Raw streams remain local.
    Logging errors signal the parent immediately and terminate the complete process tree.
    """
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) for x in argv):
        raise ValueError('argv must be a nonempty string array')
    log_dir = Path(log_dir); log_dir.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    metadata = dict(argv=redact_argv(argv), cwd=str(cwd), started_at=now(), timeout_seconds=timeout,
                    exit_code=None, signal=None, timed_out=False, cancelled=False)
    errors = []; failed = threading.Event(); threads = []; proc = None; tree = ProcessTree()
    write_lock = threading.Lock()
    def drain(pipe, name):
        try:
            with (log_dir / (name + '.log')).open('wb') as stream:
                while chunk := pipe.read1(65536):
                    stream.write(chunk); stream.flush()
                    with write_lock:
                        event(log_dir / 'events.jsonl', 'STREAM', stream=name, bytes=len(chunk))
                    if observer:
                        observer(name, len(chunk))
                os.fsync(stream.fileno())
        except BaseException as exc:
            errors.append(exc); failed.set(); emergency(exc)
        finally:
            pipe.close()
    try:
        event(log_dir / 'events.jsonl', 'START', **metadata)
        # A trusted gate waits until the Windows Job Object is assigned before starting work.
        gate = Path(__file__).with_name('process_gate.py')
        command = [sys.executable, '-B', str(gate), *argv]
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=os.name != 'nt')
        tree.assign(proc)
        proc.stdin.write(b'1'); proc.stdin.flush()
        for pipe, name in ((proc.stdout, 'stdout'), (proc.stderr, 'stderr')):
            t = threading.Thread(target=drain, args=(pipe, name), daemon=True); t.start(); threads.append(t)
        while proc.poll() is None:
            if failed.is_set():
                raise OSError('stream logging failed')
            if cancel is not None and cancel.is_set():
                metadata['cancelled'] = True
                raise InterruptedError('cancelled')
            if time.monotonic() - start > timeout:
                metadata['timed_out'] = True
                raise TimeoutError(f'process timeout after {timeout}s')
            time.sleep(.025)
        metadata['exit_code'] = proc.returncode
        metadata['signal'] = -proc.returncode if proc.returncode < 0 else None
    except BaseException as exc:
        metadata['error'] = f'{type(exc).__name__}: {exc}'
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            metadata['cancelled'] = True
    finally:
        tree.close()
        if proc:
            proc.stdin.close()
            proc.wait(timeout=10)
            metadata['exit_code'] = proc.returncode
        for thread in threads:
            thread.join(timeout=10)
        if errors or any(t.is_alive() for t in threads):
            metadata['error'] = 'diagnostic stream failed or did not close'
        metadata.update(ended_at=now(), duration_seconds=time.monotonic() - start)
        try:
            for name in ('stdout', 'stderr'):
                (log_dir / (name + '.log')).touch(exist_ok=True)
            event(log_dir / 'events.jsonl', 'END', **metadata)
            atomic_json(log_dir / 'command.json', metadata)
        except BaseException as exc:
            emergency(exc)
            raise
    return metadata
