from __future__ import annotations

import time

import pytest

from appsec_review.mcp.capability import ScopedRetrievalMcpAdapter, issue_capability


SECRET = b"s" * 32


class Core:
    run_id = "2026-10-10-0001"
    manifest_sha256 = "a" * 64


class Adapter:
    core = Core()

    def call(self, name, arguments):
        if name == "query_precomputed":
            return {"results": [{"identity": arguments["subject"]}],
                    "pagination": {"next_cursor": "core-cursor"}}
        return {"results": [{"identity": arguments["identity"]}],
                "pagination": {"next_cursor": None}}


def _package(name: str, entity: str) -> dict:
    return {"run_id": Core.run_id, "manifest_sha256": Core.manifest_sha256,
            "package_id": name, "retrieval": {"indexes": ["precomputed"],
                "query_sets": ["scanner_correlation"], "entity_ids": [entity],
                "max_page_size": 2, "max_pages": 2, "max_depth": 2,
                "max_response_bytes": 131072}}


def _scope(package: dict, *, role: str = "red") -> ScopedRetrievalMcpAdapter:
    token = issue_capability(package, role=role, round_id="1", secret=SECRET,
                             expires_at=int(time.time()) + 300)
    return ScopedRetrievalMcpAdapter(Adapter(), package, capability=token, secret=SECRET,
                                     role=role, round_id="1")


def test_capability_denies_cross_package_identity_and_unbounded_tools() -> None:
    scope = _scope(_package("first", "asr:precomputed_fact:" + "1" * 64))
    assert scope.call("find", {"identity": "asr:precomputed_fact:" + "1" * 64})["results"]
    with pytest.raises(ValueError, match="outside review package"):
        scope.call("find", {"identity": "asr:precomputed_fact:" + "2" * 64})
    with pytest.raises(ValueError, match="outside review capability"):
        scope.call("search", {"query": "password"})
    with pytest.raises(ValueError, match="outside review package"):
        scope.call("query_precomputed", {"query_set": "scanner_correlation",
                                         "subject": "asr:precomputed_fact:" + "2" * 64})


def test_cursor_is_bound_to_package_role_and_query() -> None:
    entity = "asr:precomputed_fact:" + "1" * 64
    first = _scope(_package("first", entity))
    query = {"query_set": "scanner_correlation", "subject": entity, "limit": 1}
    cursor = first.call("query_precomputed", query)["pagination"]["next_cursor"]
    assert first.call("query_precomputed", {**query, "cursor": cursor})["results"]
    other = _scope(_package("other", entity))
    with pytest.raises(ValueError, match="cursor binding"):
        other.call("query_precomputed", {**query, "cursor": cursor})
    with pytest.raises(ValueError, match="cursor binding"):
        first.call("query_precomputed", {**query, "limit": 2, "cursor": cursor})
    verifier = _scope(_package("first", entity), role="verifier")
    with pytest.raises(ValueError, match="cursor binding"):
        verifier.call("query_precomputed", {**query, "cursor": cursor})


def test_capability_rejects_modified_package_and_expiry() -> None:
    package = _package("first", "asr:precomputed_fact:" + "1" * 64)
    token = issue_capability(package, role="red", round_id="1", secret=SECRET,
                             expires_at=int(time.time()) + 300)
    altered = {**package, "package_id": "other"}
    scope = ScopedRetrievalMcpAdapter(Adapter(), altered, capability=token, secret=SECRET,
                                      role="red", round_id="1")
    with pytest.raises(ValueError, match="binding"):
        scope.call("find", {"identity": package["retrieval"]["entity_ids"][0]})
    expired = issue_capability(package, role="red", round_id="1", secret=SECRET,
                               expires_at=int(time.time()) - 1)
    scope = ScopedRetrievalMcpAdapter(Adapter(), package, capability=expired, secret=SECRET,
                                      role="red", round_id="1")
    with pytest.raises(ValueError, match="binding"):
        scope.call("find", {"identity": package["retrieval"]["entity_ids"][0]})
