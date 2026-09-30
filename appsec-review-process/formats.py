#!/usr/bin/env python3
"""Python side of schemas/common/formats.schema.json: one producer and one checker per format.

* ``check(kind, value)`` / ``is_valid(kind, value)``: validate against the shared definition
  (the schema file is the single source; nothing here repeats a pattern);
* ``utc_now()`` / ``utc_second(dt|str)``: the ``utc_timestamp`` form;
* ``sha256_hex(...)`` / ``sha256_ref(...)``: digest of bytes or a file, or a digest string
  re-formed into the bare / prefixed form;
* ``canonical_json(value)`` / ``digest(value)``: byte-identical to ``execution_state.digest``.

A schema references a kind as ``{"$ref": "common/formats.schema.json#/$defs/<kind>"}`` (``ref()``).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from schema_validate import SCHEMAS_DIR, SchemaStore, validate_document

FORMATS_SCHEMA = "common/formats.schema.json"
_STORE = SchemaStore()


class FormatError(ValueError):
    def __init__(self, kind: str, value: Any, why: str = "") -> None:
        super().__init__(f"{value!r} is not a valid {kind}" + (f": {why}" if why else ""))
        self.kind, self.value = kind, value


def kinds() -> list[str]:
    return sorted(json.loads((SCHEMAS_DIR / FORMATS_SCHEMA).read_text(encoding="utf-8"))["$defs"])


def ref(kind: str) -> dict[str, str]:
    """The ``$ref`` object a schema uses for ``kind``."""
    if kind not in kinds():
        raise KeyError(f"unknown format kind {kind!r}")
    return {"$ref": f"{FORMATS_SCHEMA}#/$defs/{kind}"}


def check(kind: str, value: Any) -> Any:
    """Return ``value`` when it is a valid ``kind``; raise FormatError otherwise."""
    errors = validate_document(value, ref(kind)["$ref"], _STORE)
    if errors:
        raise FormatError(kind, value, "; ".join(errors))
    return value


def is_valid(kind: str, value: Any) -> bool:
    try:
        check(kind, value)
        return True
    except FormatError:
        return False


# ---- instants ---------------------------------------------------------------------------------

def utc_now() -> str:
    """Now as utc_timestamp, e.g. ``2026-09-29T14:13:25Z``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_second(value: datetime | str) -> str:
    """A time-zone-aware instant (datetime or ISO-8601 string) as utc_timestamp. Sub-second digits
    are truncated, never rounded; a naive, blank or unparseable value raises FormatError."""
    instant = value
    if isinstance(value, str):
        if not value or value != value.strip():
            raise FormatError("utc_timestamp", value, "empty or surrounding whitespace")
        try:
            instant = datetime.fromisoformat(value[:-1] + "+00:00" if value[-1] in "Zz" else value)
        except ValueError:
            raise FormatError("utc_timestamp", value, "unparseable timestamp") from None
    if not isinstance(instant, datetime):
        raise FormatError("utc_timestamp", value, "not a datetime or string")
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise FormatError("utc_timestamp", value, "naive timestamp (no time zone)")
    return instant.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- digests ----------------------------------------------------------------------------------

def _hex_of(value: bytes | bytearray | Path | str) -> str:
    if isinstance(value, (bytes, bytearray)):
        return hashlib.sha256(value).hexdigest()
    if isinstance(value, Path):
        with value.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    if isinstance(value, str):
        text = value[7:] if value[:7].lower() == "sha256:" else value
        lowered = text.lower()
        if len(lowered) != 64 or any(c not in "0123456789abcdef" for c in lowered):
            raise FormatError("sha256_hex", value, "not a 64-hex SHA-256 digest")
        return lowered
    raise FormatError("sha256_hex", value, "expected bytes, a Path or a digest string")


def sha256_hex(value: bytes | bytearray | Path | str) -> str:
    """Bare 64-hex digest of bytes / a file, or re-formed from ``sha256:<hex>`` / upper-case hex."""
    return _hex_of(value)


def sha256_ref(value: bytes | bytearray | Path | str) -> str:
    """``sha256:<hex>`` of bytes / a file, or re-formed from a bare or prefixed digest string."""
    return "sha256:" + _hex_of(value)


def canonical_json(value: Any) -> bytes:
    """Sorted keys, no whitespace, ASCII escapes: the bytes ``execution_state.digest`` hashes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: Any) -> str:
    """Bare hex SHA-256 of ``canonical_json(value)``; equal to ``execution_state.digest``."""
    return hashlib.sha256(canonical_json(value)).hexdigest()
