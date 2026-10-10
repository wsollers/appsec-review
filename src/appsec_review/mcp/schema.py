"""Machine-readable public MCP tool schema."""

from __future__ import annotations

from typing import Any

from .owasp import QUERY_TOOL_SCHEMA


IDENTITY = {"type": "string", "pattern": "^asr:[a-z][a-z0-9_]*:[0-9a-f]{64}$"}
INDEX = {"type": "string", "enum": ["source", "observations", "components", "build", "artifacts", "build_security", "compiled", "analysis", "evidence", "history", "tags"]}

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
    {"name": "query_artifacts", "description": "Query accepted produced artifacts and linked indexed evidence by exact facets.",
     "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
         "artifact_identity": IDENTITY,
         "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
         "kind": {"type": "string", "maxLength": 128},
         "format": {"type": "string", "maxLength": 4096},
         "language": {"type": "string", "maxLength": 4096},
         "runtime": {"type": "string", "maxLength": 4096},
         "platform": {"type": "string", "maxLength": 4096},
         "architecture": {"type": "string", "maxLength": 4096},
         "build_unit": {"type": "string", "maxLength": 4096},
         "project": {"type": "string", "maxLength": 4096},
         "component": {"type": "string", "maxLength": 4096},
         "producing_build_action": IDENTITY,
         "package": {"type": "string", "maxLength": 4096},
         "purl": {"type": "string", "maxLength": 4096},
         "scanner": {"type": "string", "maxLength": 4096},
         "tool": {"type": "string", "maxLength": 4096},
         "coverage_status": {"type": "string", "enum": ["complete", "partial", "unavailable", "stale"]},
         "shard": {"type": "string", "pattern": "^[A-Za-z0-9_.-]{1,128}$"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 100},
         "cursor": {"type": "string", "maxLength": 4096},
     }}},
    {"name": "query_build_security", "description": "Query accepted post-build security shards by exact scope.",
     "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
         "project": {"type": "string", "maxLength": 4096},
         "build_root": {"type": "string", "maxLength": 4096},
         "build_action": {"type": "string", "maxLength": 4096},
         "configuration": {"type": "string", "maxLength": 4096},
         "compile_unit": {"type": "string", "maxLength": 4096},
         "linked_artifact": {"type": "string", "maxLength": 4096},
         "producer": {"type": "string", "maxLength": 4096},
         "shard": {"type": "string", "maxLength": 128},
         "limit": {"type": "integer", "minimum": 1, "maximum": 100},
         "cursor": {"type": "string", "maxLength": 4096},
     }}},
    {"name": "query_ci_configuration", "description": "Query accepted CI observations and canonical findings by exact provider and hierarchy facets.",
     "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
         "provider": {"type": "string", "maxLength": 4096},
         "pipeline": {"type": "string", "maxLength": 4096},
         "workflow": {"type": "string", "maxLength": 4096},
         "stage": {"type": "string", "maxLength": 4096},
         "job": {"type": "string", "maxLength": 4096},
         "step": {"type": "string", "maxLength": 4096},
         "tool": {"type": "string", "maxLength": 4096},
         "rule": {"type": "string", "maxLength": 4096},
         "category": {"type": "string", "maxLength": 4096},
         "canonical_finding": {"type": "string", "maxLength": 4096},
         "shard": {"type": "string", "maxLength": 128},
         "limit": {"type": "integer", "minimum": 1, "maximum": 100},
         "cursor": {"type": "string", "maxLength": 4096},
     }}},
    {"name": "query_codeql", "description": "Query accepted CodeQL observations by exact language, scope, rule, and source facets.",
     "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
         "language": {"type": "string", "maxLength": 128},
         "source_language": {"type": "string", "maxLength": 128},
         "scope": {"type": "string", "maxLength": 128},
         "build_unit": {"type": "string", "maxLength": 128},
         "rule": {"type": "string", "maxLength": 4096},
         "level": {"type": "string", "maxLength": 128},
         "path": {"type": "string", "maxLength": 4096},
         "shard": {"type": "string", "pattern": "^codeql-[A-Za-z0-9_.-]{1,120}$"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 100},
         "cursor": {"type": "string", "maxLength": 4096},
     }}},
    QUERY_TOOL_SCHEMA,
)
