"""``stackwalk_json``: stackwalker JSON already produced from a minidump (finding-metrics.md section 7.2).

Documentation relied on: the rust-minidump ``minidump-processor/json-schema.md`` (the schema of
``minidump-stackwalk --json``). Confirmed there: ``crash_info.type`` (string), ``crash_info.address``
(hex string), ``crash_info.assertion`` (string); ``system_info.os`` and ``cpu_arch``;
``crashing_thread.frames[]`` with ``module``, ``function``, ``file``, ``line``, ``offset`` (the
instruction address), ``module_offset``, ``trust``, ``missing_symbols`` and ``inlines[]`` (``function``,
``file``, ``line``; listed before their real frame); frame 0 is the innermost frame; ``modules[]``
with ``filename``, ``debug_id``, ``code_id``, ``version``; ``main_module`` is an index into ``modules``.
Every field is optional and nullable.

Not confirmed, therefore not read: an access-type field (the direction of a fault is taken only from
a ``type`` that states it, such as ``EXCEPTION_ACCESS_VIOLATION_WRITE``; a POSIX ``SIGSEGV`` therefore
classifies as ``unknown`` with gap ``no_access_type``), the exact spelling of ``__fastfail`` subcodes
inside ``type``, and any changelist, configuration or crash-time field. Crashpad annotations
(``crashpad_info``) are never read: they are free-form and may carry personal data.

Dropped at parse time: every thread other than the crashing one, thread names, the process id,
``lsb_release``, ``mac_boot_args``, memory maps, handles, registers, the assertion message, absolute
instruction addresses, module paths and symbol URLs. This adapter reads the bytes it is handed and
nothing else: no file system, no network, no subprocess, and it never walks a minidump.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..contracts import MAX_FRAMES
from .records import (build_frame, build_report, clean_identifier, clean_text, dig, input_digest,
                      load_json_object, module_name, parse_hex)

NAME = "stackwalk_json"
_NARROW = ("x86", "arm")


def _frames(thread: Any, roots: Sequence[str], gaps: set[str]) -> list[dict[str, Any]] | None:
    listed = dig(thread, "frames")
    if not isinstance(listed, list):
        return None
    frames: list[dict[str, Any]] = []
    for item in listed:
        if len(frames) > MAX_FRAMES:          # one past the bound, so the record names the truncation
            break
        inlines = dig(item, "inlines")
        for entry in [*(inlines if isinstance(inlines, list) else ()), item]:
            frame, named = build_frame(module=dig(item, "module"), function=dig(entry, "function"),
                                       path=dig(entry, "file"), line=dig(entry, "line"),
                                       offset=dig(item, "module_offset"), roots=roots)
            frames.append(frame)
            gaps |= named
    return frames


def parse_stackwalk_json(data: bytes, *, roots: Sequence[str] = ()) -> list[dict[str, Any]]:
    """One ``crash-report/1`` record from one stackwalker JSON document."""
    source = input_digest(data)
    document = load_json_object(data)
    if not any(isinstance(document.get(key), expected) for key, expected in (
            ("crash_info", dict), ("crashing_thread", dict), ("modules", list), ("threads", list))):
        raise ValueError("crash input is not a stackwalker document")
    gaps: set[str] = set()
    listed = document.get("modules") if isinstance(document.get("modules"), list) else []
    modules = [{"name": module_name(dig(item, "filename")), "debug_id": clean_identifier(dig(item, "debug_id")),
                "code_id": clean_identifier(dig(item, "code_id"))} for item in listed]
    main = document.get("main_module")
    version = (dig(listed[main], "version")
               if isinstance(main, int) and not isinstance(main, bool) and 0 <= main < len(listed) else None)
    assertion, _ = clean_text(dig(document, "crash_info", "assertion"))
    return [build_report(
        adapter=NAME, source_sha256=source, signal=dig(document, "crash_info", "type"),
        address=parse_hex(dig(document, "crash_info", "address")),
        bits=32 if dig(document, "system_info", "cpu_arch") in _NARROW else 64,
        assertion=assertion is not None, frames=_frames(document.get("crashing_thread"), roots, gaps),
        modules=[item for item in modules if any(part is not None for part in item.values())],
        version=version, platform=dig(document, "system_info", "os"), gaps=gaps)]


__all__ = ["NAME", "parse_stackwalk_json"]
