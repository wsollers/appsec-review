"""Package and role scoped read-only MCP entry point for review workers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Mapping

from appsec_review.graph.contract import GRAPH_INDEX, QUERY_CODE_GRAPH
from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.retrieval.graph import request_error as graph_request_error
from appsec_review.retrieval.model import canonical_json


_REVIEW_TOOLS = frozenset({"find", "read_excerpt", "query_precomputed", QUERY_CODE_GRAPH})
# Canonical review roles (code-graph-precomputation.md 5.4) plus the earlier short aliases.
_ROLE_TOOLS = {
    "hypothesis_hunter": _REVIEW_TOOLS,
    "red_team_analyst": _REVIEW_TOOLS,
    "blue_team_refuter": _REVIEW_TOOLS,
    "independent_verifier": _REVIEW_TOOLS,
    "red": _REVIEW_TOOLS,
    "blue": _REVIEW_TOOLS,
    "verifier": _REVIEW_TOOLS,
}
_GRAPH_ARGUMENTS = frozenset({"mode", "subject", "depth", "sink_class", "source_class", "limit", "cursor"})


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def issue_capability(package: Mapping[str, Any], *, role: str, round_id: str, secret: bytes,
                     expires_at: int) -> str:
    if role not in _ROLE_TOOLS or not round_id or len(secret) < 32:
        raise ValueError("invalid review capability parameters")
    body = {"schema": "appsec-review/review-capability/1", "run_id": package["run_id"],
            "manifest_sha256": package["manifest_sha256"], "package_id": package["package_id"],
            "package_sha256": hashlib.sha256(canonical_json(package)).hexdigest(),
            "role": role, "round_id": round_id, "tools": sorted(_ROLE_TOOLS[role]),
            "indexes": package["retrieval"]["indexes"], "query_sets": package["retrieval"]["query_sets"],
            "entity_ids": package["retrieval"]["entity_ids"],
            "max_page_size": package["retrieval"]["max_page_size"],
            "max_pages": package["retrieval"]["max_pages"],
            "max_depth": package["retrieval"]["max_depth"],
            "max_response_bytes": package["retrieval"]["max_response_bytes"],
            "expires_at": expires_at}
    payload = canonical_json(body)
    return _encode(payload + hmac.new(secret, payload, hashlib.sha256).digest())


class ScopedRetrievalMcpAdapter:
    """Every dispatch checks a bound grant before the ordinary retrieval adapter runs."""

    def __init__(self, adapter: RetrievalMcpAdapter, package: Mapping[str, Any], *,
                 capability: str, secret: bytes, role: str, round_id: str):
        if len(secret) < 32:
            raise ValueError("review capability secret is too short")
        self._adapter, self._package = adapter, package
        self._capability, self._secret = capability, secret
        self._role, self._round_id = role, round_id

    def _grant(self) -> Mapping[str, Any]:
        try:
            raw = _decode(self._capability)
            payload, signature = raw[:-32], raw[-32:]
            if not hmac.compare_digest(signature, hmac.new(self._secret, payload, hashlib.sha256).digest()):
                raise ValueError
            grant = json.loads(payload)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid review capability") from exc
        package, core = self._package, self._adapter.core
        if (grant.get("schema") != "appsec-review/review-capability/1" or
            grant.get("role") != self._role or grant.get("round_id") != self._round_id or
            grant.get("expires_at", 0) <= time.time() or
            grant.get("run_id") != core.run_id or grant.get("run_id") != package.get("run_id") or
            grant.get("manifest_sha256") != core.manifest_sha256 or
            grant.get("manifest_sha256") != package.get("manifest_sha256") or
            grant.get("package_id") != package.get("package_id") or
            grant.get("package_sha256") != hashlib.sha256(canonical_json(package)).hexdigest() or
            set(grant.get("tools", ())) != _ROLE_TOOLS.get(self._role) or
            grant.get("entity_ids") != package["retrieval"]["entity_ids"] or
            grant.get("indexes") != package["retrieval"]["indexes"] or
            grant.get("query_sets") != package["retrieval"]["query_sets"] or
            grant.get("max_page_size") != package["retrieval"]["max_page_size"] or
            grant.get("max_pages") != package["retrieval"]["max_pages"] or
            grant.get("max_depth") != package["retrieval"]["max_depth"] or
            grant.get("max_response_bytes") != package["retrieval"]["max_response_bytes"]):
            raise ValueError("review capability binding mismatch")
        return grant

    def _unwrap_cursor(self, cursor: str, name: str, arguments: Mapping[str, Any]) -> tuple[str, int]:
        try:
            raw = _decode(cursor)
            payload, signature = raw[:-32], raw[-32:]
            if not hmac.compare_digest(signature, hmac.new(self._secret, payload, hashlib.sha256).digest()):
                raise ValueError
            value = json.loads(payload)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid package cursor") from exc
        query = {key: item for key, item in arguments.items() if key != "cursor"}
        if (value.get("capability") != hashlib.sha256(self._capability.encode()).hexdigest() or
            value.get("query") != hashlib.sha256(canonical_json([name, query])).hexdigest() or
            not isinstance(value.get("inner"), str) or
            not isinstance(value.get("page"), int) or value["page"] < 2):
            raise ValueError("package cursor binding mismatch")
        return value["inner"], value["page"]

    def _wrap_cursor(self, cursor: str, name: str, arguments: Mapping[str, Any], page: int) -> str:
        query = {key: item for key, item in arguments.items() if key != "cursor"}
        payload = canonical_json({"capability": hashlib.sha256(self._capability.encode()).hexdigest(),
                                  "query": hashlib.sha256(canonical_json([name, query])).hexdigest(),
                                  "inner": cursor, "page": page})
        return _encode(payload + hmac.new(self._secret, payload, hashlib.sha256).digest())

    def call(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        grant = self._grant()
        if name not in grant["tools"] or not isinstance(arguments, Mapping):
            raise ValueError("tool is outside review capability")
        args = dict(arguments)
        entities = set(grant["entity_ids"])
        if name in {"find", "read_excerpt"}:
            if args.get("identity") not in entities or set(args) - ({"identity", "context_lines"} if name == "read_excerpt" else {"identity"}):
                raise ValueError("entity is outside review package")
        elif name == "query_precomputed":
            if (args.get("query_set") not in grant["query_sets"] or args.get("subject") not in entities or
                args.get("path") is not None or set(args) - {"query_set", "subject", "limit", "cursor"}):
                raise ValueError("query is outside review package")
            if args.get("limit", 20) > grant["max_page_size"]:
                raise ValueError("page exceeds review capability")
        elif name == QUERY_CODE_GRAPH:
            if (GRAPH_INDEX not in grant["indexes"] or args.get("subject") not in entities or
                set(args) - _GRAPH_ARGUMENTS or graph_request_error(args)):
                raise ValueError("query is outside review package")
            if args.get("limit", 20) > grant["max_page_size"] or args.get("depth", 1) > grant["max_depth"]:
                raise ValueError("page or depth exceeds review capability")
        page = 1
        if args.get("cursor") is not None:
            args["cursor"], page = self._unwrap_cursor(args["cursor"], name, arguments)
            if page > grant["max_pages"]:
                raise ValueError("review capability page bound exceeded")
        result = self._adapter.call(name, args)
        if len(canonical_json(result)) > grant["max_response_bytes"]:
            raise ValueError("retrieval response exceeds review capability")
        # Refuse publication if a producer result contains a different top-level identity.
        if any(item.get("identity") not in entities for item in result.get("results", ())):
            raise ValueError("retrieval result escaped review package")
        next_cursor = result.get("pagination", {}).get("next_cursor")
        if next_cursor:
            result["pagination"]["next_cursor"] = self._wrap_cursor(next_cursor, name, arguments, page + 1)
        return result
