"""The normalized crash record ``appsec-review/crash-report/1`` (finding-metrics.md section 7.3, T-072).

Doctrine:

* Crash bytes, module names, symbols, annotations and messages are untrusted data. Nothing here
  evaluates them, and none of them becomes a metric key. Error messages never echo input content.
* A crash source contains process memory and personal data. The record below is everything that is
  kept: there is no field for a user, device, host or session identifier, an address of a person or
  machine, an environment, a command line, a breadcrumb, a tag or a free-text message, and
  ``normalize_report`` refuses any field it does not name.
* Build-machine path prefixes are never stored: a frame's file is a target-relative path or ``None``.
* An unsymbolicated frame is kept as module and offset with a named gap. A bound hit is a named gap
  or a ``ValueError``, never a silent subset.
* The fault classification is a deterministic review ordering. It is never a severity and never an
  exploitability claim.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

from ..contracts import (CRASH_EVIDENCE_SCHEMA, CRASH_REPORT_SCHEMA, FAULT_ORDER, MAX_CRASH_REPORTS, MAX_FRAMES,
                         FaultClass, digest, is_sha256, normalize_path)

MAX_MODULES = 256                 # per crash report
MAX_FUNCTION_CHARS = 512          # per frame function
MAX_NAME_CHARS = 256              # per module name
MAX_LABEL_CHARS = 128             # version, changelist, configuration, platform, signal, identifiers
MAX_INPUT_BYTES = 16 * 1024 * 1024   # per crash source file
BUCKET_FRAMES = 5                 # symbolicated frames hashed into a derived bucket id
NEAR_NULL_LIMIT = 0x10000         # 64 KiB: a faulting read below this is a near-null read

ACCESS_TYPES = ("read", "write", "execute")
ADDRESS_CLASSES = ("near_null", "non_canonical", "arbitrary")
FAILURE_KINDS = ("unparseable", "too_large", "unknown_adapter")

# Sanitizer bug types, closed. The first tuple are memory errors (``sanitizer_memory_error``).
SANITIZER_MEMORY_BUG_TYPES = (
    "alloc-dealloc-mismatch", "bad-free", "container-overflow", "double-free", "dynamic-stack-buffer-overflow",
    "global-buffer-overflow", "heap-buffer-overflow", "heap-use-after-free", "intra-object-overflow",
    "memcpy-param-overlap", "negative-size-param", "new-delete-type-mismatch", "stack-buffer-overflow",
    "stack-buffer-underflow", "stack-use-after-return", "stack-use-after-scope", "tag-mismatch",
    "use-after-poison", "use-of-uninitialized-value")
SANITIZER_BUG_TYPES = tuple(sorted((
    *SANITIZER_MEMORY_BUG_TYPES, "allocation-size-too-big", "data-race", "lock-order-inversion", "memory-leak",
    "out-of-memory", "segv", "signal-unsafe-call", "stack-overflow", "thread-leak", "undefined-behavior",
    "unknown-crash")))

GAPS = ("blocks_truncated", "modules_truncated", "no_access_type", "no_crashing_thread", "no_fault_address",
        "no_fault_signal", "stack_truncated", "text_truncated", "unknown_bug_type", "unknown_build",
        "unrelativized_paths", "unsymbolicated_frames")

REPORT_FIELDS = ("schema", "adapter", "source_sha256", "bucket_id", "occurrences", "first_seen", "last_seen",
                 "build", "fault", "frames", "gaps")
BUILD_FIELDS = ("modules", "version", "changelist", "configuration", "platform")
MODULE_FIELDS = ("name", "debug_id", "code_id")
FAULT_FIELDS = ("class", "signal", "access", "address_class", "sanitizer_bug_type")
FRAME_FIELDS = ("module", "function", "file", "line", "offset", "symbolicated")
EVIDENCE_FIELDS = ("schema", "reports", "failures", "counts", "sha256")
EVIDENCE_COUNTS = ("files", "parsed", "failed", "duplicate_files", "reports", "buckets")

ADAPTER_NAME = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
_BUCKET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_IDENTIFIER = re.compile(r"^[0-9A-Za-z][0-9A-Za-z-]{0,127}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_HEX = re.compile(r"^(?:0[xX])?([0-9a-fA-F]{1,16})$")
_OFFSET = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]{0,15})$")
_DRIVE = re.compile(r"^[A-Za-z]:/")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?$")
_ABORT = re.compile(r"(?<![A-Z0-9])(?:SIGABRT|ABRT|ABORT)(?![A-Z0-9])")
_OOM = re.compile(r"OUT_OF_MEMORY|NO_MEMORY|COMMITMENT_LIMIT|(?<![A-Z0-9])OOM(?![A-Z0-9])")
_STACK_COOKIE_FAST_FAIL = ("FAST_FAIL_STACK_COOKIE_CHECK_FAILURE", "FAST_FAIL_GS_COOKIE_INIT",
                           "FAST_FAIL_LEGACY_GS_VIOLATION")
_HEAP_FAST_FAIL = ("FAST_FAIL_HEAP_METADATA_CORRUPTION", "FAST_FAIL_CORRUPT_LIST_ENTRY")


# ------------------------------------------------------------------------- untrusted input helpers

def input_digest(data: Any) -> str:
    """The SHA-256 of one crash source file, after its size bound (16 MiB) is checked."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("crash input must be bytes")
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("crash input exceeds the bounded file size")
    return hashlib.sha256(data).hexdigest()


def load_json_object(data: bytes) -> dict[str, Any]:
    """A JSON object from untrusted bytes with the standard library; the error never echoes content."""
    try:
        value = json.loads(bytes(data).decode("utf-8"))
    except (ValueError, RecursionError):
        raise ValueError("crash input is not a JSON document") from None
    if not isinstance(value, dict):
        raise ValueError("crash input is not a JSON object")
    return value


def dig(value: Any, *keys: str) -> Any:
    """``value[k1][k2]...`` through nested objects; ``None`` as soon as a level is not an object."""
    for key in keys:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def clean_text(value: Any, limit: int = MAX_FUNCTION_CHARS) -> tuple[str | None, bool]:
    """``(text, truncated)``: an untrusted string as one bounded line, or ``None`` when nothing remains.

    Control characters and every kind of line break become spaces and whitespace is collapsed. The
    text is carried as inert data; ``truncated`` tells the adapter to record ``text_truncated``.
    """
    if not isinstance(value, str):
        return None, False
    text = " ".join(_CONTROL.sub(" ", value).split())
    if not text:
        return None, False
    return (text[:limit].rstrip(), True) if len(text) > limit else (text, False)


def module_name(value: Any) -> str | None:
    """The base name of a module path (either separator); the directory is never kept."""
    text, _ = clean_text(value, 4096)
    if text is None:
        return None
    parts = [part for part in re.split(r"[/\\]", text) if part.strip()]
    return parts[-1].strip()[:MAX_NAME_CHARS].rstrip() or None if parts else None


def clean_identifier(value: Any) -> str | None:
    """A debug or code identifier (hexadecimal with dashes, at most 128 characters), else ``None``."""
    return value if isinstance(value, str) and _IDENTIFIER.match(value) else None


def clean_label(value: Any) -> str | None:
    """A version, changelist, configuration, platform or signal as one short line, else ``None``."""
    text, truncated = clean_text(value, MAX_LABEL_CHARS)
    return None if truncated else text


def parse_hex(value: Any) -> int | None:
    """A 64-bit unsigned integer from a hexadecimal string (``0x`` optional) or an integer; else ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value < 1 << 64 else None
    match = _HEX.match(value.strip()) if isinstance(value, str) and len(value) <= 32 else None
    return int(match.group(1), 16) if match else None


def hex_offset(value: Any) -> str | None:
    """The canonical ``0x...`` form (lower case, no padding) of a module offset; else ``None``."""
    number = parse_hex(value)
    return None if number is None else hex(number)


def _root_prefix(root: Any) -> str:
    if not isinstance(root, str) or not root or _CONTROL.search(root):
        raise ValueError("a path root must be a non-empty single-line string")
    prefix = root.replace("\\", "/").rstrip("/") + "/"
    body = prefix[3:] if _DRIVE.match(prefix) else prefix
    if not body.strip("/"):
        raise ValueError("a path root must name a directory below the file-system or drive root")
    return prefix


def relativize(path: Any, roots: Sequence[str]) -> str | None:
    """A crash source's file path as a target-relative POSIX path, or ``None``.

    ``roots`` are the operator-supplied build-machine prefixes, for example ``["/home/builder/src/",
    "C:/build/"]``. Backslashes compare as ``/`` and a root that starts with a drive letter compares
    case-insensitively. The first root that matches is stripped; its remainder is the result when it
    is a valid target-relative path and ``None`` when it would escape (``..``). An absolute path that
    no root matches is ``None``: the build-machine prefix is never stored. A path that is already
    relative is kept when it does not escape.
    """
    if isinstance(roots, (str, bytes)) or not isinstance(roots, Sequence):
        raise ValueError("path roots must be a sequence of strings")
    prefixes = [_root_prefix(root) for root in roots]
    if not isinstance(path, str) or not path or len(path) > 4096 or _CONTROL.search(path):
        return None
    text = path.replace("\\", "/")
    for prefix in prefixes:
        matched = (text.casefold().startswith(prefix.casefold()) if _DRIVE.match(prefix)
                   else text.startswith(prefix))
        if matched:
            return _relative(text[len(prefix):])
    return None if text.startswith("/") else _relative(text)   # a drive path fails normalize_path


def _relative(text: str) -> str | None:
    try:
        return normalize_path(text)
    except ValueError:
        return None


# -------------------------------------------------------------------------- fault classification

def address_class(address: int | None, bits: int = 64) -> str | None:
    """``near_null`` (below 64 KiB), ``non_canonical`` (64-bit only: bits 47..63 not all equal) or
    ``arbitrary``; ``None`` for an unknown address."""
    if bits not in (32, 64):
        raise ValueError("address width must be 32 or 64 bits")
    if address is None:
        return None
    if isinstance(address, bool) or not isinstance(address, int) or not 0 <= address < 1 << bits:
        raise ValueError("fault address is outside the address width")
    if address < NEAR_NULL_LIMIT:
        return "near_null"
    if bits == 64 and 0x0000_8000_0000_0000 <= address < 0xFFFF_8000_0000_0000:
        return "non_canonical"
    return "arbitrary"


def access_from_signal(signal: str | None) -> str | None:
    """The access type a signal name states (``EXCEPTION_ACCESS_VIOLATION_WRITE`` and alike), else ``None``."""
    if not isinstance(signal, str):
        return None
    text = signal.upper()
    if "ACCESS_VIOLATION" not in text and "IN_PAGE_ERROR" not in text:
        return None
    for suffix, access in (("_WRITE", "write"), ("_EXEC", "execute"), ("_READ", "read")):
        if suffix in text:
            return access
    return None


def _status(signal: str | None) -> str | None:
    if not signal:
        return None
    text = signal.upper()
    if "FAST_FAIL_" in text:           # __fastfail: the subcode decides, not STATUS_STACK_BUFFER_OVERRUN
        if any(code in text for code in _STACK_COOKIE_FAST_FAIL):
            return "stack_cookie"
        if any(code in text for code in _HEAP_FAST_FAIL):
            return "heap_corruption"
        return "abort" if "FAST_FAIL_FATAL_APP_EXIT" in text else None
    if "STACK_BUFFER_OVERRUN" in text or "STACK_COOKIE" in text or "STACK_CHK_FAIL" in text:
        return "stack_cookie"
    if "HEAP_CORRUPTION" in text:
        return "heap_corruption"
    if "STACK_OVERFLOW" in text:
        return "stack_overflow"
    if _OOM.search(text):
        return "out_of_memory"
    return "abort" if _ABORT.search(text) else None


def classify_fault(signal: str | None, access: str | None, address: int | None,
                   sanitizer_bug_type: str | None, *, assertion: bool = False) -> FaultClass:
    """The deterministic fault class of one crash. The first rule that applies decides:

    1. Sanitizer bug type: a ``SANITIZER_MEMORY_BUG_TYPES`` member -> ``sanitizer_memory_error``;
       ``undefined-behavior`` -> ``sanitizer_undefined``; ``data-race`` -> ``sanitizer_race``;
       ``stack-overflow`` -> ``stack_overflow``; ``out-of-memory`` and ``allocation-size-too-big`` ->
       ``out_of_memory``. Every other bug type (``segv``, ``unknown-crash``, leaks, lock order) says
       nothing about the fault and falls through.
    2. Signal names a ``__fastfail`` subcode (``FAST_FAIL_*``): a stack-cookie code -> ``stack_cookie``;
       a heap-metadata or list-entry code -> ``heap_corruption``; ``FAST_FAIL_FATAL_APP_EXIT`` is an
       abort (rule 7); any other subcode falls through *without* rule 3, because Windows raises
       ``STATUS_STACK_BUFFER_OVERRUN`` for every fast-fail.
    3. Signal contains ``STACK_BUFFER_OVERRUN``, ``STACK_COOKIE`` or ``STACK_CHK_FAIL`` -> ``stack_cookie``;
       ``HEAP_CORRUPTION`` -> ``heap_corruption``; ``STACK_OVERFLOW`` -> ``stack_overflow``;
       ``OUT_OF_MEMORY``, ``NO_MEMORY``, ``COMMITMENT_LIMIT`` or the word ``OOM`` -> ``out_of_memory``.
    4. ``assertion=True`` -> ``assertion`` (before the access rules: an assertion is often raised by a
       deliberate write to a null address).
    5. Access, as given or else as the signal states it: ``write`` -> ``write_access_violation``;
       ``execute`` -> ``execute_access_violation``.
    6. ``read`` with a known address below 64 KiB -> ``near_null_read``; any other read -> ``wild_read``.
    7. Signal contains the word ``SIGABRT``, ``ABRT`` or ``ABORT`` (or rule 2's fatal app exit) -> ``abort``.
    8. Anything else, including an access fault of unknown direction -> ``unknown``.

    The result orders crashes for review (``FAULT_ORDER``). It is never a severity and never a claim
    that a crash is exploitable.
    """
    if signal is not None and not isinstance(signal, str):
        raise ValueError("fault signal must be a string or null")
    if access is not None and access not in ACCESS_TYPES:
        raise ValueError("fault access is outside its closed vocabulary")
    if sanitizer_bug_type is not None and sanitizer_bug_type not in SANITIZER_BUG_TYPES:
        raise ValueError("sanitizer bug type is outside its closed vocabulary")
    if address is not None and (isinstance(address, bool) or not isinstance(address, int) or address < 0):
        raise ValueError("fault address must be a non-negative integer or null")
    if sanitizer_bug_type in SANITIZER_MEMORY_BUG_TYPES:
        return FaultClass.SANITIZER_MEMORY_ERROR
    if sanitizer_bug_type == "undefined-behavior":
        return FaultClass.SANITIZER_UNDEFINED
    if sanitizer_bug_type == "data-race":
        return FaultClass.SANITIZER_RACE
    if sanitizer_bug_type == "stack-overflow":
        return FaultClass.STACK_OVERFLOW
    if sanitizer_bug_type in ("out-of-memory", "allocation-size-too-big"):
        return FaultClass.OUT_OF_MEMORY
    status = _status(signal)
    if status is not None and status != "abort":
        return FaultClass(status)
    if assertion:
        return FaultClass.ASSERTION
    access = access or access_from_signal(signal)
    if access == "write":
        return FaultClass.WRITE_ACCESS_VIOLATION
    if access == "execute":
        return FaultClass.EXECUTE_ACCESS_VIOLATION
    if access == "read":
        near = address is not None and address < NEAR_NULL_LIMIT
        return FaultClass.NEAR_NULL_READ if near else FaultClass.WILD_READ
    return FaultClass.ABORT if status == "abort" else FaultClass.UNKNOWN


def review_rank(report: Mapping[str, Any]) -> int:
    """The index of the report's fault class in ``FAULT_ORDER``: review ordering, never a severity."""
    return FAULT_ORDER.index(report["fault"]["class"])


# --------------------------------------------------------------------------------- the record

def normalize_seen(value: Any) -> str | None:
    """An ISO date (``YYYY-MM-DD``) or datetime (``YYYY-MM-DDTHH:MM:SS`` with optional fraction and
    offset) in canonical form: an offset is converted to ``Z`` and the fraction is dropped."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("crash report seen time must be an ISO date or datetime string or null")
    try:
        if _DATE.match(value):
            datetime.fromisoformat(value)
            return value
        if _DATETIME.match(value):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return parsed.strftime("%Y-%m-%dT%H:%M:%S")
            return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError):
        pass
    raise ValueError("crash report seen time must be an ISO date or datetime string or null")


def seen_key(value: str) -> datetime:
    """The ordering key of a canonical seen time; a time without an offset is ordered as UTC."""
    return datetime.fromisoformat(value.rstrip("Z"))


def bucket_digest(frames: Sequence[Mapping[str, Any]], fault_class: str, source_sha256: str) -> str:
    """The derived bucket id: the functions of the first five symbolicated frames, plus the fault class.

    A symbolicated frame without a function name (a sanitizer ``file:line`` report) contributes its
    file and line instead. A stack with no symbolicated frame is grouped by the module and offset of
    its first five frames, and a report about which nothing is known by its own source, so unrelated
    crashes never share a bucket merely because nothing about them is known.
    """
    top = [frame for frame in frames if frame["symbolicated"]][:BUCKET_FRAMES]
    if top:
        return digest({"fault_class": fault_class, "functions": [
            frame["function"] if frame["function"] is not None else [frame["file"], frame["line"]] for frame in top]})
    offsets = [[frame["module"], frame["offset"]] for frame in frames[:BUCKET_FRAMES]]
    if any(item != [None, None] for item in offsets):
        return digest({"fault_class": fault_class, "offsets": offsets})
    return digest({"fault_class": fault_class, "source_sha256": source_sha256})


def _exact(value: Any, fields: Sequence[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise ValueError(f"crash {name} must be an object with exactly its named fields")
    return value


def _line(value: Any, limit: int, name: str) -> str | None:
    if value is None:
        return None
    if (not isinstance(value, str) or not value or len(value) > limit or value != value.strip()
            or _CONTROL.search(value)):
        raise ValueError(f"crash {name} must be a bounded single-line string or null")
    return value


def _choice(value: Any, vocabulary: Sequence[str], name: str) -> str | None:
    if value is not None and (not isinstance(value, str) or value not in vocabulary):
        raise ValueError(f"crash {name} is outside its closed vocabulary")
    return value


def _identifier(value: Any, name: str) -> str | None:
    if value is not None and clean_identifier(value) is None:
        raise ValueError(f"crash {name} must be an identifier or null")
    return value


def _module(value: Any) -> dict[str, Any]:
    item = _exact(value, MODULE_FIELDS, "module")
    name = _line(item["name"], MAX_NAME_CHARS, "module name")
    if name is not None and ("/" in name or "\\" in name):
        raise ValueError("crash module name must be a base name")
    return {"name": name, "debug_id": _identifier(item["debug_id"], "module debug_id"),
            "code_id": _identifier(item["code_id"], "module code_id")}


def _frame(value: Any) -> dict[str, Any]:
    item = _exact(value, FRAME_FIELDS, "frame")
    module = _line(item["module"], MAX_NAME_CHARS, "frame module")
    if module is not None and ("/" in module or "\\" in module):
        raise ValueError("crash frame module must be a base name")
    file = item["file"]
    if file is not None and _relative(file if isinstance(file, str) else "") != file:
        raise ValueError("crash frame file must be a canonical target-relative path or null")
    line = item["line"]
    if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
        raise ValueError("crash frame line must be a positive integer or null")
    offset = item["offset"]
    if offset is not None and (not isinstance(offset, str) or not _OFFSET.match(offset)):
        raise ValueError("crash frame offset must be a canonical hexadecimal string or null")
    function = _line(item["function"], MAX_FUNCTION_CHARS, "frame function")
    if item["symbolicated"] is not (function is not None or file is not None):
        raise ValueError("crash frame is symbolicated exactly when it has a function or a file")
    return {"module": module, "function": function, "file": file, "line": line, "offset": offset,
            "symbolicated": item["symbolicated"]}


def normalize_report(value: Any) -> dict[str, Any]:
    """Validate and canonicalize one ``crash-report/1`` record; unknown or missing fields are refused.

    ``bucket_id`` may be ``None``: it is then derived with ``bucket_digest``. A stack longer than
    ``MAX_FRAMES`` keeps its innermost frames with gap ``stack_truncated``; a module list longer than
    ``MAX_MODULES`` keeps the first by name with gap ``modules_truncated``. Gaps the record itself
    shows (``unsymbolicated_frames``, ``no_crashing_thread``, ``unknown_build``) are added. A frame is
    ``symbolicated`` exactly when it has a function or a file. The input is not mutated, and the
    result normalizes to itself.
    """
    report = _exact(value, REPORT_FIELDS, "report")
    if report["schema"] != CRASH_REPORT_SCHEMA:
        raise ValueError("unsupported crash report schema")
    adapter = report["adapter"]
    if not isinstance(adapter, str) or not ADAPTER_NAME.match(adapter):
        raise ValueError("crash report adapter is not an adapter name")
    if not is_sha256(report["source_sha256"]):
        raise ValueError("crash report source_sha256 must be a SHA-256")
    occurrences = report["occurrences"]
    if isinstance(occurrences, bool) or not isinstance(occurrences, int) or occurrences < 1:
        raise ValueError("crash report occurrences must be a positive integer")
    first, last = normalize_seen(report["first_seen"]), normalize_seen(report["last_seen"])
    if first is not None and last is not None and seen_key(last) < seen_key(first):
        raise ValueError("crash report last_seen precedes first_seen")

    gaps_in = report["gaps"]
    if not isinstance(gaps_in, (list, tuple)) or any(not isinstance(gap, str) or gap not in GAPS for gap in gaps_in):
        raise ValueError("crash report gaps are outside their closed vocabulary")
    gaps = set(gaps_in)

    build = _exact(report["build"], BUILD_FIELDS, "build")
    if not isinstance(build["modules"], (list, tuple)):
        raise ValueError("crash build modules must be a list")
    modules = sorted({(item["name"] or "", item["debug_id"] or "", item["code_id"] or ""): item
                      for item in (_module(item) for item in build["modules"])}.items())
    if len(modules) > MAX_MODULES:
        modules = modules[:MAX_MODULES]
        gaps.add("modules_truncated")
    labels = {name: _line(build[name], MAX_LABEL_CHARS, f"build {name}") for name in BUILD_FIELDS[1:]}

    fault = _exact(report["fault"], FAULT_FIELDS, "fault")
    fault_class = _choice(fault["class"], FAULT_ORDER, "fault class")
    if fault_class is None:
        raise ValueError("crash fault class is required")

    frames_in = report["frames"]
    if not isinstance(frames_in, (list, tuple)):
        raise ValueError("crash report frames must be a list")
    if len(frames_in) > MAX_FRAMES:
        gaps.add("stack_truncated")
    frames = [_frame(item) for item in frames_in[:MAX_FRAMES]]
    if not frames:
        gaps.add("no_crashing_thread")
    if any(not frame["symbolicated"] for frame in frames):
        gaps.add("unsymbolicated_frames")
    if (labels["version"] is None and labels["changelist"] is None
            and all(item["debug_id"] is None and item["code_id"] is None for _, item in modules)):
        gaps.add("unknown_build")

    bucket_id = report["bucket_id"]
    if bucket_id is None:
        bucket_id = bucket_digest(frames, fault_class, report["source_sha256"])
    elif not isinstance(bucket_id, str) or not _BUCKET_ID.match(bucket_id):
        raise ValueError("crash report bucket_id must be a short identifier or null")
    return {
        "schema": CRASH_REPORT_SCHEMA, "adapter": adapter, "source_sha256": report["source_sha256"],
        "bucket_id": bucket_id, "occurrences": occurrences, "first_seen": first, "last_seen": last,
        "build": {"modules": [item for _, item in modules], **labels},
        "fault": {"class": fault_class, "signal": _line(fault["signal"], MAX_LABEL_CHARS, "fault signal"),
                  "access": _choice(fault["access"], ACCESS_TYPES, "fault access"),
                  "address_class": _choice(fault["address_class"], ADDRESS_CLASSES, "fault address_class"),
                  "sanitizer_bug_type": _choice(fault["sanitizer_bug_type"], SANITIZER_BUG_TYPES,
                                                "sanitizer bug type")},
        "frames": frames, "gaps": sorted(gaps),
    }


def source_bucket(value: Any) -> str | None:
    """A source's own grouping as a bucket id: itself when it is a short identifier, else its digest."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        value = str(value)
    if isinstance(value, str) and _BUCKET_ID.match(value):
        return value
    if isinstance(value, str) and value:
        return digest({"source_bucket": value})
    return None


def build_report(*, adapter: str, source_sha256: str, signal: Any = None, access: str | None = None,
                 address: int | None = None, bits: int = 64, sanitizer_bug_type: str | None = None,
                 assertion: bool = False, frames: Iterable[Mapping[str, Any]] | None = None,
                 modules: Iterable[Mapping[str, Any]] = (), version: Any = None, changelist: Any = None,
                 configuration: Any = None, platform: Any = None, bucket: Any = None, occurrences: int = 1,
                 first_seen: str | None = None, last_seen: str | None = None,
                 gaps: Iterable[str] = ()) -> dict[str, Any]:
    """The one constructor adapters use: classifies the fault, names the standard gaps and normalizes.

    ``frames`` is ``None`` when the source has no crashing thread. ``signal`` and the build labels
    are untrusted text and are reduced to one short line or dropped. ``address`` only decides the
    address class and the fault class; the address itself is not stored.
    """
    named = set(gaps)
    signal = clean_label(signal)
    if address is not None and not 0 <= address < 1 << bits:
        address = None
    access = access or access_from_signal(signal)
    if signal is None and sanitizer_bug_type is None:
        named.add("no_fault_signal")
    fault_class = classify_fault(signal, access, address, sanitizer_bug_type, assertion=assertion)
    if address is None:
        named.add("no_fault_address")
    elif access is None and fault_class is FaultClass.UNKNOWN:
        named.add("no_access_type")
    return normalize_report({
        "schema": CRASH_REPORT_SCHEMA, "adapter": adapter, "source_sha256": source_sha256,
        "bucket_id": source_bucket(bucket), "occurrences": occurrences, "first_seen": first_seen,
        "last_seen": last_seen,
        "build": {"modules": list(modules), "version": clean_label(version), "changelist": clean_label(changelist),
                  "configuration": clean_label(configuration), "platform": clean_label(platform)},
        "fault": {"class": fault_class.value,
                  "signal": signal, "access": access, "address_class": address_class(address, bits),
                  "sanitizer_bug_type": sanitizer_bug_type},
        "frames": [] if frames is None else list(frames), "gaps": sorted(named),
    })


def build_frame(*, module: Any = None, function: Any = None, path: Any = None, line: Any = None,
                offset: Any = None, roots: Sequence[str] = ()) -> tuple[dict[str, Any], set[str]]:
    """``(frame, gaps)`` from untrusted frame values: base-name module, one-line function, relativized
    file, positive line, canonical offset. A file dropped for want of a root is ``unrelativized_paths``."""
    gaps: set[str] = set()
    text, truncated = clean_text(function, MAX_FUNCTION_CHARS)
    if truncated:
        gaps.add("text_truncated")
    file = relativize(path, roots)
    if file is None and isinstance(path, str) and path.strip():
        gaps.add("unrelativized_paths")
    line = line if isinstance(line, int) and not isinstance(line, bool) and line >= 1 and file is not None else None
    return ({"module": module_name(module), "function": text, "file": file, "line": line,
             "offset": hex_offset(offset), "symbolicated": text is not None or file is not None}, gaps)


# ------------------------------------------------------------------------------- the evidence

def check_evidence(value: Any) -> dict[str, Any]:
    """A ``crash-evidence/1`` document's shape and integrity; raises ``ValueError`` for anything else.

    Every report must be in normal form, buckets must be unique per adapter, and ``sha256`` must be
    the digest of the reports, so a consumer never works from an edited or partial document.
    """
    if not isinstance(value, Mapping) or value.get("schema") != CRASH_EVIDENCE_SCHEMA:
        raise ValueError("unsupported crash evidence schema")
    if set(value) != set(EVIDENCE_FIELDS):
        raise ValueError("crash evidence has missing or unknown fields")
    reports, failures, totals = value["reports"], value["failures"], value["counts"]
    if not isinstance(reports, list) or len(reports) > MAX_CRASH_REPORTS:
        raise ValueError("crash evidence reports must be a bounded list")
    if any(normalize_report(report) != report for report in reports):
        raise ValueError("crash evidence holds a report that is not in normal form")
    keys = {(report["adapter"], report["bucket_id"]) for report in reports}
    if len(keys) != len(reports):
        raise ValueError("crash evidence repeats a bucket")
    if not isinstance(failures, list) or any(
            not isinstance(item, Mapping) or set(item) != {"file_sha256", "adapter", "error"}
            or not is_sha256(item["file_sha256"]) or item["error"] not in FAILURE_KINDS for item in failures):
        raise ValueError("crash evidence failures are invalid")
    if (not isinstance(totals, Mapping) or set(totals) != set(EVIDENCE_COUNTS)
            or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in totals.values())
            or totals["buckets"] != len(reports) or totals["failed"] != len(failures)):
        raise ValueError("crash evidence counts are invalid")
    if value["sha256"] != digest(reports):
        raise ValueError("crash evidence digest does not match its reports")
    return dict(value)


__all__ = [
    "ACCESS_TYPES", "ADAPTER_NAME", "ADDRESS_CLASSES", "BUCKET_FRAMES", "BUILD_FIELDS", "EVIDENCE_COUNTS",
    "EVIDENCE_FIELDS", "FAILURE_KINDS", "FAULT_FIELDS", "FRAME_FIELDS", "GAPS", "MAX_FUNCTION_CHARS",
    "MAX_INPUT_BYTES", "MAX_LABEL_CHARS", "MAX_MODULES", "MAX_NAME_CHARS", "MODULE_FIELDS", "NEAR_NULL_LIMIT",
    "REPORT_FIELDS", "SANITIZER_BUG_TYPES", "SANITIZER_MEMORY_BUG_TYPES", "access_from_signal", "address_class",
    "bucket_digest", "build_frame", "build_report", "check_evidence", "classify_fault", "clean_identifier",
    "clean_label", "clean_text", "dig", "hex_offset", "input_digest", "load_json_object", "module_name",
    "normalize_report", "normalize_seen", "parse_hex",
    "relativize", "review_rank", "seen_key", "source_bucket",
]
