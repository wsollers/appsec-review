"""``sanitizer_report``: ASan, UBSan, TSan (and MSan, HWASan, LSan) text reports in one log file.

Documentation relied on: the Clang AddressSanitizer, ThreadSanitizer and UndefinedBehaviorSanitizer
manuals and the sanitizers wiki. Confirmed there: the ASan header ``==PID==ERROR: AddressSanitizer:
<bug-type> on address 0x... at pc ...`` (older releases print ``==PID== ERROR: AddressSanitizer
<bug-type> ...``), the access line ``READ of size N at 0x... thread T0``, symbolized frames
``#0 0x... in function file:line[:col]``, the stacks that follow the first one (``freed by``,
``previously allocated by``), the ``SUMMARY:`` line; the TSan header ``WARNING: ThreadSanitizer: data
race (pid=N)``, its access line ``Write of size N at 0x... by thread T1:`` and frames
``#0 function file:line (module+0xoffset)``; the UBSan line ``file:line:col: runtime error: ...``.

Not confirmed against documentation, implemented from the formats these tools are known to print
and parsed defensively: unsymbolized frames ``#0 0x... (module+0xoffset)`` and the ``(BuildId: hex)``
suffix, the deadly-signal headers (``SEGV on unknown address``, ``ABRT``, ``BUS``, ``FPE``, ``ILL``) with
``The signal is caused by a READ|WRITE memory access.``, the allocator headers (``attempting
double-free``, ``attempting free on address which was not malloc()-ed``, ``requested allocation size``,
``allocator is out of memory``), the MSan, HWASan and LSan headers, and UBSan stack frames under
``print_stacktrace=1``. A header whose bug type is not in the closed list keeps its stack and is
classified ``unknown`` with gap ``unknown_bug_type``.

Kept per block: the bug type, access direction, address class, and the first stack (the crashing
one). Dropped: the message text, every later stack, shadow-memory dumps, thread names, process ids,
allocation sizes and the faulting address itself. The parser is line-oriented, reads only the bytes
it is handed and executes nothing.
"""
from __future__ import annotations

from collections.abc import Sequence
import re
from typing import Any

from ..contracts import MAX_FRAMES
from .records import (SANITIZER_BUG_TYPES, build_frame, build_report, input_digest, module_name)

NAME = "sanitizer_report"
MAX_BLOCKS = 1000                 # reports per log file; beyond it every report carries blocks_truncated
MAX_LINE_CHARS = 8192             # a longer line is not a header, an access line or a frame

_PID = re.compile(r"^==\d+==\s*")
_HEADER = re.compile(r"^(?:ERROR|WARNING): (AddressSanitizer|HWAddressSanitizer|LeakSanitizer|MemorySanitizer"
                     r"|ThreadSanitizer|UndefinedBehaviorSanitizer):? (.*)$")
_UBSAN = re.compile(r"^(\S.*?):(\d{1,9}):\d{1,9}: runtime error: ")
_FRAME = re.compile(r"^#\d{1,6}\s+(.*)$")
_PC = re.compile(r"^0x[0-9a-fA-F]+\s*(.*)$")
_BUILD_ID = re.compile(r"\s*\(BuildId: ([0-9a-fA-F]{2,128})\)\s*$")
_MODULE = re.compile(r"\s*\(([^()]+)\+0x([0-9a-fA-F]{1,16})\)\s*$")
_LOCATION = re.compile(r"^(.+?):(\d{1,9})(?::\d{1,9})?$")
_ADDRESS = re.compile(r"\bon (?:unknown address |address )?0x([0-9a-fA-F]{1,16})\b")
_ACCESS = re.compile(r"^(?:(?:Atomic |atomic )?(READ|WRITE|Read|Write|read|write) of size \d+ at 0x([0-9a-fA-F]{1,16})"
                     r"|The signal is caused by a (READ|WRITE) memory access)")
_SIGNALS = {"abrt": "SIGABRT", "bus": "SIGBUS", "fpe": "SIGFPE", "ill": "SIGILL", "segv": "SIGSEGV"}
_PHRASES = (("attempting double-free", "double-free"), ("attempting free on address which was not malloc", "bad-free"),
            ("allocator is out of memory", "out-of-memory"), ("out of memory", "out-of-memory"),
            ("requested allocation size", "allocation-size-too-big"), ("data race", "data-race"),
            ("detected memory leaks", "memory-leak"), ("thread leak", "thread-leak"),
            ("signal-unsafe call", "signal-unsafe-call"))
_NO_NAME = ("<null>", "??", "<unknown>")


def _bug_type(rest: str) -> tuple[str | None, str | None]:
    """``(sanitizer bug type or None, signal or None)`` from the text after the tool name."""
    lowered = rest.lower()
    for phrase, bug_type in _PHRASES:
        if lowered.startswith(phrase):
            return bug_type, None
    token = lowered.split(" ", 1)[0].rstrip(":")
    return (token if token in SANITIZER_BUG_TYPES else None), _SIGNALS.get(token)


def _frame(text: str, roots: Sequence[str], gaps: set[str], modules: list[dict[str, Any]]) -> dict[str, Any]:
    counter = _PC.match(text)
    body = counter.group(1) if counter else text
    body = body[3:] if body.startswith("in ") else body
    build = _BUILD_ID.search(body)
    body = body[:build.start()] if build else body
    module = _MODULE.search(body)
    body = (body[:module.start()] if module else body).strip().removesuffix("(<unknown module>)").strip()
    function, path, line = body or None, None, None
    head, _, tail = body.rpartition(" ")
    location = _LOCATION.match(tail)
    if location and location.group(1) not in _NO_NAME:
        function, path, line = head.strip() or None, location.group(1), int(location.group(2))
    elif location:
        function = head.strip() or None
    name = module.group(1) if module else None
    if build and module_name(name) is not None:
        modules.append({"name": module_name(name), "debug_id": None, "code_id": build.group(1).lower()})
    frame, named = build_frame(module=name, function=None if function in _NO_NAME else function, path=path,
                               line=line, offset=module.group(2) if module else None, roots=roots)
    gaps |= named
    return frame


def _report(block: dict[str, Any], source: str, roots: Sequence[str], truncated: bool) -> dict[str, Any]:
    gaps: set[str] = {"blocks_truncated"} if truncated else set()
    modules: list[dict[str, Any]] = []
    frames = [_frame(text, roots, gaps, modules) for text in block["stack"]]
    if not frames and block["location"] is not None:       # a UBSan line without a printed stack
        frame, named = build_frame(path=block["location"][0], line=block["location"][1], roots=roots)
        frames, gaps = [frame], gaps | named
    if block["bug_type"] is None and block["signal"] is None:
        gaps.add("unknown_bug_type")
    return build_report(adapter=NAME, source_sha256=source, signal=block["signal"], access=block["access"],
                        address=block["address"], sanitizer_bug_type=block["bug_type"], frames=frames,
                        modules=modules, gaps=gaps)


def parse_sanitizer_report(data: bytes, *, roots: Sequence[str] = ()) -> list[dict[str, Any]]:
    """One ``crash-report/1`` record per ``ERROR:``/``WARNING:`` block or UBSan ``runtime error`` line."""
    source = input_digest(data)
    blocks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    truncated = False
    for raw in bytes(data).decode("utf-8", errors="replace").splitlines():
        line = _PID.sub("", raw.strip()) if len(raw) <= MAX_LINE_CHARS else ""
        header = _HEADER.match(line)
        undefined = None if header else _UBSAN.match(line)
        if header or undefined:
            if len(blocks) == MAX_BLOCKS:
                truncated = True
                break
            bug_type, signal = _bug_type(header.group(2)) if header else ("undefined-behavior", None)
            found = _ADDRESS.search(header.group(2)) if header else None
            current = {"bug_type": bug_type, "signal": signal, "access": None, "stack": [], "phase": "header",
                       "address": int(found.group(1), 16) if found else None,
                       "location": (undefined.group(1), int(undefined.group(2))) if undefined else None}
            blocks.append(current)
            continue
        if current is None or current["phase"] == "done":
            continue
        frame = _FRAME.match(line)
        if frame:
            current["phase"] = "stack"
            if len(current["stack"]) <= MAX_FRAMES:        # one past the bound names the truncation
                current["stack"].append(frame.group(1))
        elif current["phase"] == "stack" or line.startswith("SUMMARY:"):
            current["phase"] = "done"                      # only the first stack is the crashing one
        else:
            access = _ACCESS.match(line)
            if access and current["access"] is None:
                current["access"] = (access.group(1) or access.group(3)).lower()
                if access.group(2) and current["address"] is None:
                    current["address"] = int(access.group(2), 16)
    if not blocks:
        raise ValueError("crash input holds no sanitizer report")
    return [_report(block, source, roots, truncated) for block in blocks]


__all__ = ["MAX_BLOCKS", "MAX_LINE_CHARS", "NAME", "parse_sanitizer_report"]
