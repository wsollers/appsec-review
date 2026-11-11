"""``sentry_event``: one exported Sentry event payload (finding-metrics.md section 7.2).

Documentation relied on: the Sentry developer documentation of the event payload interfaces.
Confirmed there: the Stack Trace interface (``frames`` ordered oldest to newest, the last frame is
the one that raised; frame attributes ``function``, ``raw_function``, ``filename``, ``abs_path``,
``lineno``, ``package`` (the dynamic library path for native code), ``instruction_addr`` and
``image_addr`` as ``0x`` hex strings), the Debug Meta interface (``debug_meta.images[]`` with ``type``,
``debug_id``, ``code_id``, ``code_file``, ``debug_file``) and that a stack trace lives in an exception
or in a thread, never at the top level of an event.

Not confirmed (the Exception interface page could not be retrieved); implemented from the field
names in the task brief and parsed defensively: ``exception.values[]`` ordering (the last value is
taken as the crash), ``mechanism.meta.signal.name`` / ``code_name``, ``mechanism.meta.mach_exception.name``,
``mechanism.data.relevant_address``, the exception ``type`` carrying a native exception code,
``threads.values[].crashed``, top-level ``release`` (string, or an object with ``version``), ``dist``,
``platform``, ``timestamp`` (epoch seconds or ISO string), ``contexts.os.name``, and ``groupID`` /
``fingerprint`` as the source's own grouping. The API-serialized event shape (``entries[]`` with
camel-case frame fields) is not this format and is refused as unparseable.

Dropped at parse time and never read: ``user``, ``request``, ``breadcrumbs``, ``tags``, ``extra``,
``server_name``, ``environment``, ``contexts.device`` and every other context, ``message``, ``logentry``,
the exception ``value`` text, frame ``vars`` and source context lines, and every thread but the
crashed one. A native exception ``type`` is kept as the signal only when it is an upper-case code
token; any other text is dropped.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
import re
from typing import Any

from ..contracts import MAX_FRAMES, digest
from .records import (build_frame, build_report, clean_identifier, dig, input_digest, load_json_object,
                      module_name, normalize_seen, parse_hex)

NAME = "sentry_event"
_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}(?: ?/ ?[A-Z][A-Z0-9_]{2,63})?$")
_UNKNOWN_FUNCTIONS = ("<unknown>", "<redacted>", "?")


def _values(section: Any) -> list[Any]:
    values = section.get("values") if isinstance(section, dict) else section
    return values if isinstance(values, list) else []


def _crash_stack(event: dict[str, Any]) -> tuple[Any, Any]:
    """``(exception value or None, frames oldest-first or None)`` of the crash."""
    exceptions = [item for item in _values(event.get("exception")) if isinstance(item, dict)]
    for item in reversed(exceptions):
        if isinstance(dig(item, "stacktrace", "frames"), list):
            return item, item["stacktrace"]["frames"]
    for thread in _values(event.get("threads")):
        if dig(thread, "crashed") is True and isinstance(dig(thread, "stacktrace", "frames"), list):
            return (exceptions[-1] if exceptions else None), thread["stacktrace"]["frames"]
    return (exceptions[-1] if exceptions else None), None


def _signal(value: Any) -> Any:
    for candidate in (dig(value, "mechanism", "meta", "signal", "name"),
                      dig(value, "mechanism", "meta", "mach_exception", "name"), dig(value, "type")):
        if isinstance(candidate, str) and _CODE.match(candidate.strip()):
            code = dig(value, "mechanism", "meta", "signal", "code_name")
            first = candidate.strip()
            return f"{first} / {code}" if isinstance(code, str) and _CODE.match(code) and "/" not in first else first
    return None


def _seen(value: Any) -> str | None:
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return normalize_seen(value) if isinstance(value, str) else None
    except (ValueError, OverflowError, OSError):
        return None


def _frames(listed: list[Any], roots: Sequence[str], gaps: set[str]) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    for item in reversed(listed):             # Sentry lists oldest first; the record is innermost first
        if len(frames) > MAX_FRAMES:
            break
        function = dig(item, "function")
        instruction, image = parse_hex(dig(item, "instruction_addr")), parse_hex(dig(item, "image_addr"))
        frame, named = build_frame(
            module=dig(item, "package"), function=None if function in _UNKNOWN_FUNCTIONS else function,
            path=dig(item, "abs_path") or dig(item, "filename"), line=dig(item, "lineno"),
            offset=instruction - image if instruction is not None and image is not None and instruction >= image
            else None, roots=roots)
        frames.append(frame)
        gaps |= named
    return frames


def parse_sentry_event(data: bytes, *, roots: Sequence[str] = ()) -> list[dict[str, Any]]:
    """One ``crash-report/1`` record from one Sentry event payload."""
    source = input_digest(data)
    event = load_json_object(data)
    if not any(isinstance(event.get(key), (dict, list)) for key in ("exception", "threads", "debug_meta")):
        raise ValueError("crash input is not a Sentry event payload")
    gaps: set[str] = set()
    value, listed = _crash_stack(event)
    images = dig(event, "debug_meta", "images")
    modules = [{"name": module_name(dig(item, "code_file")) or module_name(dig(item, "debug_file")),
                "debug_id": clean_identifier(dig(item, "debug_id")), "code_id": clean_identifier(dig(item, "code_id"))}
               for item in (images if isinstance(images, list) else ())]
    release = event.get("release")
    fingerprint = event.get("fingerprint")
    grouping = event.get("groupID")
    if grouping is None and isinstance(fingerprint, list) and fingerprint and fingerprint != ["{{ default }}"] \
            and all(isinstance(item, str) for item in fingerprint):
        grouping = digest({"sentry_fingerprint": fingerprint})
    seen = _seen(event.get("timestamp"))
    return [build_report(
        adapter=NAME, source_sha256=source, signal=_signal(value),
        address=parse_hex(dig(value, "mechanism", "data", "relevant_address")),
        frames=None if listed is None else _frames(listed, roots, gaps),
        modules=[item for item in modules if any(part is not None for part in item.values())],
        version=dig(release, "version") if isinstance(release, dict) else release, changelist=event.get("dist"),
        platform=dig(event, "contexts", "os", "name") or event.get("platform"), bucket=grouping,
        first_seen=seen, last_seen=seen, gaps=gaps)]


__all__ = ["NAME", "parse_sentry_event"]
