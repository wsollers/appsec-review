"""Closed JSON schemas generated from the versioned domain records, not job contracts."""

from __future__ import annotations

from dataclasses import MISSING, fields, is_dataclass
import json
import re
import types
from typing import Any, Literal, Union, get_args, get_origin, get_type_hints

from jsonschema import Draft202012Validator

from appsec_review.retrieval.model import normalize_relative_path

from .model import (
    CATALOG_SCHEMA, EVIDENCE_SCHEMA, OBSERVATION_SCHEMA, SCHEMA, Inventory, Limits, identity,
)
from .parsing import ParseError


def record_schema(record: type) -> dict[str, Any]:
    """Dataclass fields are all required on the wire, including explicit null unknowns."""
    definitions: dict[str, Any] = {}

    def shape(annotation: Any) -> dict[str, Any]:
        origin, args = get_origin(annotation), get_args(annotation)
        if origin in (Union, types.UnionType):
            return {"anyOf": [shape(item) for item in args]}
        if origin is Literal:
            return {"enum": list(args)}
        if origin in (list, tuple):
            return {"type": "array", "maxItems": 50_000, "items": shape(args[0])}
        if annotation is str:
            return {"type": "string", "maxLength": 4096}
        if annotation is int:
            return {"type": "integer"}
        if annotation is bool:
            return {"type": "boolean"}
        if annotation is type(None):
            return {"type": "null"}
        if isinstance(annotation, type) and is_dataclass(annotation):
            name = annotation.__name__
            if name not in definitions:
                definitions[name] = {}
                hints = get_type_hints(annotation)
                properties = {item.name: shape(hints[item.name]) for item in fields(annotation)}
                for item in fields(annotation):
                    if item.name == "schema" and item.default is not MISSING:
                        properties[item.name] = {"const": item.default}
                definitions[name] = {
                    "type": "object", "additionalProperties": False,
                    "properties": properties, "required": list(properties),
                }
            return {"$ref": f"#/$defs/{name}"}
        raise TypeError(f"unsupported domain schema annotation: {annotation}")

    root = shape(record)
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", **root, "$defs": definitions}


def inventory_schema() -> dict[str, Any]:
    from .catalog import SIGNATURES, evidence_rules

    value = record_schema(Inventory)
    definitions = value["$defs"]
    definitions["Inventory"]["properties"]["schema"] = {"const": SCHEMA}
    definitions["Inventory"]["properties"]["catalog_schema"] = {"const": CATALOG_SCHEMA}
    definitions["Evidence"]["properties"]["schema"] = {"const": EVIDENCE_SCHEMA}
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    definitions["Inventory"]["properties"]["catalog_sha256"] = digest.copy()
    for name in ("Source", "Evidence"):
        definitions[name]["properties"]["sha256"] = digest.copy()
    for name in ("start_line", "end_line"):
        definitions["Evidence"]["properties"][name]["minimum"] = 1
    for name in ("start_byte", "end_byte"):
        definitions["Evidence"]["properties"][name]["minimum"] = 0
    definitions["Source"]["properties"]["size_bytes"]["minimum"] = 0
    definitions["Service"]["properties"]["product"] = {"enum": [None, *(item.product for item in SIGNATURES)]}
    definitions["Evidence"]["properties"]["rule"] = {"enum": [item.id for item in evidence_rules()]}
    definitions["Coverage"]["properties"]["rules"]["items"] = definitions["Evidence"]["properties"]["rule"]
    definitions["Listener"]["properties"]["port"] = {
        "anyOf": [{"type": "integer", "minimum": 1, "maximum": 65535}, {"type": "null"}],
    }
    return value


def validate_inventory(value: dict[str, Any]) -> None:
    """Reject unknown fields, dangling evidence and platform evidence entering target facts."""
    errors = list(Draft202012Validator(inventory_schema()).iter_errors(value))
    if errors:
        raise ValueError(f"invalid deployment inventory at {list(errors[0].absolute_path)}")
    groups = {}
    for name in ("sources", "services", "listeners", "relationships", "evidence"):
        groups[name] = {item["id"]: item for item in value[name]}
        if len(groups[name]) != len(value[name]):
            raise ValueError(f"duplicate deployment {name} identity")
    for item in value["sources"]:
        payload = {key: entry for key, entry in item.items() if key != "id"}
        if (item["target_snapshot"] != value["target_snapshot"]
                or normalize_relative_path(item["path"]) != item["path"]
                or "\\" in item["path"] or item["id"] != identity("source", payload)):
            raise ValueError("invalid deployment source identity")
    for item in value["services"]:
        if item["id"] != identity("service", {
            "snapshot": value["target_snapshot"], "deployment": item["deployment"],
            "variant": item["variant"], "key": item["key"],
        }):
            raise ValueError("invalid deployment service identity")
        if not item["evidence"] or (
            item["selection"] == "selected" and (
                item["selected_variant"] is None or item["selected_variant"] != item["variant"]
            )
        ) or (item["selection"] != "selected" and item["selected_variant"] is not None):
            raise ValueError("invalid deployment service selection or missing evidence")
    for item in value["evidence"]:
        source = groups["sources"].get(item["source_id"])
        if (source is None or source["scope"] != "target" or source["target_snapshot"] != value["target_snapshot"]
                or (source["path"], source["sha256"]) != (item["path"], item["sha256"])
                or not 0 <= item["start_byte"] < item["end_byte"] <= source["size_bytes"]
                or item["end_line"] < item["start_line"] or item["authority"] != "target_declaration"):
            raise ValueError("unresolved or out-of-scope deployment evidence")
    for name in ("services", "listeners", "relationships", "facts", "conflicts", "gaps"):
        for item in value[name]:
            for key in ("service_id", "source_service_id", "target_service_id"):
                if item.get(key) is not None and item[key] not in groups["services"]:
                    raise ValueError("unresolved deployment service")
            if any(ref not in groups["evidence"] for ref in item.get("evidence", ())):
                raise ValueError("unresolved deployment evidence reference")
    for item in value["coverage"]:
        if item["source_id"] not in groups["sources"]:
            raise ValueError("unresolved coverage source")
        source = groups["sources"][item["source_id"]]
        if (item["disposition"] == "excluded") != (source["scope"] == "analysis_platform"):
            raise ValueError("coverage exclusion differs from admitted scope")
        for gap in item["gaps"]:
            if any(ref not in groups["evidence"] for ref in gap["evidence"]):
                raise ValueError("unresolved coverage evidence")
    for item in value["listeners"]:
        if not item["evidence"] or item["evidence_class"] != "configured_listener":
            raise ValueError("static listeners require declaration evidence")
    for item in value["facts"]:
        if not item["evidence"]:
            raise ValueError("static facts require declaration evidence")
        if item["evidence_class"] in {"observed_listener", "proven_reachability", "dependency_installed"}:
            raise ValueError("static inventory cannot assert runtime or installed-package facts")
        if item["evidence_class"] == "selected_deployment" and (
            groups["services"][item["service_id"]]["selection"] != "selected"
        ):
            raise ValueError("selected deployment fact has no selected service")


def bounded_json(data: bytes, limits: Limits) -> Any:
    """Bound syntax before recursive JSON decoding; reject duplicates and nonfinite values."""
    if len(data) > limits.max_document_bytes:
        raise ParseError("input_limit", "JSON input exceeds byte bound", "partial")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError("invalid_encoding", "JSON input is not UTF-8") from exc
    depth = tokens = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            tokens += 1
        elif char in "[{":
            depth += 1
            tokens += 1
        elif char in "]}":
            depth -= 1
        elif char in ":,":
            tokens += 1
        if depth > limits.max_depth or tokens > limits.max_nodes:
            raise ParseError("syntax_limit", "JSON syntax bound exceeded", "partial")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for name, value in items:
            if name in result:
                raise ParseError("duplicate_key", "duplicate JSON field")
            result[name] = value
        return result

    def constant(value: str) -> None:
        raise ParseError("invalid_number", "nonfinite JSON values are forbidden")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, ParseError):
            raise
        raise ParseError("invalid_json", "malformed JSON document") from exc


def observations_schema() -> dict[str, Any]:
    from .observations import ObservationBatch

    value = record_schema(ObservationBatch)
    definitions = value["$defs"]
    definitions["ObservationBatch"]["properties"]["schema"] = {"const": OBSERVATION_SCHEMA}
    definitions["ObservedEndpoint"]["properties"]["port"] = {"type": "integer", "minimum": 1, "maximum": 65535}
    for name in ("observed_at", "expires_at"):
        definitions["ObservedEndpoint"]["properties"][name]["pattern"] = (
            r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)$"
        )
    return value


def catalog_schema() -> dict[str, Any]:
    from .catalog import FORMAT_COVERAGE, UNSUPPORTED, EvidenceRule, Signature

    value = record_schema(Signature)
    signature_ref = value.pop("$ref")
    rule_schema = record_schema(EvidenceRule)
    value["$defs"].update(rule_schema["$defs"])
    strings = {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 256},
               "uniqueItems": True, "maxItems": 256}
    value.update({
        "type": "object", "additionalProperties": False,
        "required": ["schema", "signatures", "evidence_rules", "formats", "unsupported"],
        "properties": {
            "schema": {"const": CATALOG_SCHEMA},
            "signatures": {"type": "array", "maxItems": 256, "items": {"$ref": signature_ref}},
            "evidence_rules": {"type": "array", "maxItems": 1024, "items": {"$ref": rule_schema["$ref"]}},
            "formats": {"type": "object", "additionalProperties": False,
                        "required": list(FORMAT_COVERAGE), "properties": {key: strings for key in FORMAT_COVERAGE}},
            "unsupported": {"type": "object", "additionalProperties": False,
                            "required": list(UNSUPPORTED), "properties": {key: strings for key in UNSUPPORTED}},
        },
    })
    return value


def valid_service_id(value: str) -> bool:
    return re.fullmatch(r"deployment:service:[0-9a-f]{64}", value) is not None
