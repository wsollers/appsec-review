"""Machine-readable public MCP tool schema."""

from __future__ import annotations

from typing import Any

from .owasp import QUERY_TOOL_SCHEMA


IDENTITY = {"type": "string", "pattern": "^asr:[a-z][a-z0-9_]*:[0-9a-f]{64}$"}
INDEX = {"type": "string", "enum": ["source", "observations", "components", "build", "compiled", "analysis", "evidence"]}

TOOLS: tuple[dict[str, Any], ...] = (
    {"name": "search", "description": "Full-text search accepted immutable evidence indexes.",
     "inputSchema": {"type": "object", "additionalProperties": False, "required": ["query"], "properties": {
         "query": {"type": "string", "minLength": 1, "maxLength": 4096},
         "indexes": {"type": "array", "items": INDEX, "uniqueItems": True},
         "kinds": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
         "limit": {"type": "integer", "minimum": 1, "maximum": 100}, "cursor": {"type": "string", "maxLength": 4096},
     }}},
    {"name": "find", "description": "Find entities using exact structured filters.",
     "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
         "identity": IDENTITY, "kind": {"type": "string"}, "name": {"type": "string", "maxLength": 4096},
         "path": {"type": "string", "maxLength": 4096}, "indexes": {"type": "array", "items": INDEX, "uniqueItems": True},
         "limit": {"type": "integer", "minimum": 1, "maximum": 100}, "cursor": {"type": "string", "maxLength": 4096},
     }}},
    {"name": "read_excerpt", "description": "Read a hash-verified excerpt for an indexed source identity.",
     "inputSchema": {"type": "object", "additionalProperties": False, "required": ["identity"], "properties": {
         "identity": IDENTITY, "context_lines": {"type": "integer", "minimum": 0, "maximum": 20},
     }}},
    {"name": "trace", "description": "Traverse bounded typed relationships from one logical identity.",
     "inputSchema": {"type": "object", "additionalProperties": False, "required": ["identity"], "properties": {
         "identity": IDENTITY, "relations": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
         "depth": {"type": "integer", "minimum": 1, "maximum": 8},
         "limit": {"type": "integer", "minimum": 1, "maximum": 100},
     }}},
    {"name": "resolve_evidence", "description": "Resolve an observation, evidence artifact, or finding package to supporting identities.",
     "inputSchema": {"type": "object", "additionalProperties": False, "required": ["identity"], "properties": {
         "identity": IDENTITY, "limit": {"type": "integer", "minimum": 1, "maximum": 100},
     }}},
    {"name": "coverage", "description": "Report explicit accepted-index coverage and gaps.",
     "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
         "indexes": {"type": "array", "items": INDEX, "uniqueItems": True},
     }}},
    QUERY_TOOL_SCHEMA,
)
