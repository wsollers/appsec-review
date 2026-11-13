from __future__ import annotations

import hashlib
import io
import json
import urllib.error

import pytest

from appsec_review.jobs.job_source_history_analysis import github
from .support import HEAD, PARENT


API = "https://api.example.test"
PATH = "/repos/acme/repo/commits/" + HEAD + "/pulls"


def settings(**overrides):
    return github.GitHubSettings(**{
        "api_base": API, "repository": "acme/repo", "token": None, "max_requests": 20,
        "timeout_seconds": 5, "per_page": 2, "max_pages": 10, "max_records": 10, **overrides})


def client(responses, **overrides):
    seen = []

    def transport(url, headers, timeout):
        seen.append((url.removeprefix(API), headers, timeout))
        value = responses[url.removeprefix(API)] if isinstance(responses, dict) else responses
        if isinstance(value, Exception):
            raise value
        status, response_headers, body = value
        return status, response_headers, body if isinstance(body, bytes) else json.dumps(body).encode()
    result = github.GitHubClient(settings(**overrides), transport)
    return result, seen


@pytest.mark.parametrize("overrides,message", [
    ({"api_base": "http://host"}, "API base"), ({"api_base": "https://user@host"}, "API base"),
    ({"repository": "a/../b"}, "owner/name"), ({"max_requests": 0}, "bounds"),
    ({"timeout_seconds": 301}, "bounds"), ({"per_page": True}, "per_page"),
    ({"max_pages": 0}, "max_pages"), ({"max_records": 1000001}, "max_records"),
], ids=["scheme", "userinfo", "repository", "requests", "timeout", "page-size", "pages", "records"])
def test_settings_refuse_invalid_authority_and_bounds(overrides, message):
    with pytest.raises(ValueError, match=message):
        settings(**overrides)


def test_client_request_headers_hash_decode_budget_and_transport_errors(monkeypatch):
    instance, seen = client((200, {"LINK": "value"}, b'{"a":1}'), token="fixture", max_requests=1)
    response = instance.request("/x")
    assert response.body == {"a": 1} and response.headers == {"link": "value"}
    assert response.sha256 == hashlib.sha256(b'{"a":1}').hexdigest()
    assert seen[0][0] == "/x" and seen[0][2] == 5
    assert seen[0][1]["Authorization"] == "Bearer fixture"
    assert instance.statuses == {"200": 1}
    with pytest.raises(github.BudgetExhausted, match="budget exhausted"):
        instance.request("/y")
    for data in (b"", b"\xff", b"not-json"):
        assert client((200, {}, data))[0].get("/x") == (200, None)
    with pytest.raises(ValueError, match="github_transport_unavailable:OSError"):
        client(OSError("offline"))[0].request("/x")
    monkeypatch.setattr(github, "MAX_RESPONSE_BYTES", 1)
    with pytest.raises(ValueError, match="exceeds its bound"):
        client((200, {}, b"ab"))[0].request("/x")


def test_default_transport_is_bounded_and_refuses_redirects(monkeypatch):
    requests = []

    class Response(io.BytesIO):
        status = 200
        headers = {"x": "y"}

    class Opener:
        def open(self, request, timeout):
            requests.append((request, timeout))
            return Response(b'{"a":1}')

    monkeypatch.setattr(github.urllib.request, "build_opener", lambda handler: Opener())
    assert github.default_transport(API + "/x", {"Accept": "json"}, 5) == (200, {"x": "y"}, b'{"a":1}')
    assert requests[0][0].get_method() == "GET" and requests[0][1] == 5
    assert github._NoRedirect().redirect_request(None, None, 302, "", {}, "https://other") is None

    def denied(self, request, timeout):
        raise urllib.error.HTTPError(request.full_url, 403, "denied", {"x": "z"}, io.BytesIO(b"denied"))

    monkeypatch.setattr(Opener, "open", denied)
    assert github.default_transport(API + "/x", {}, 5) == (403, {"x": "z"}, b"denied")


@pytest.mark.parametrize("suffix,expected", [
    ("?per_page=2&page=2", (2, None)),
    ("?per_page=2&page=1", (None, "github_pagination_cycle")),
    ("?per_page=2&page=3", (None, "github_pagination_malformed")),
    ("?per_page=3&page=2", (None, "github_pagination_malformed")),
    ("?per_page=2&page=x", (None, "github_pagination_malformed")),
    ("?per_page=2&page=2&extra=x", (None, "github_pagination_malformed")),
    ("?per_page=2&page=2&page=3", (None, "github_pagination_malformed")),
    ("?per_page=2&page=2&bad", (None, "github_pagination_malformed")),
], ids=["next", "cycle", "jump", "size", "non-number", "extra", "duplicate", "malformed"])
def test_next_link_validation(suffix, expected):
    assert github._next_page(f'<{API}{PATH}{suffix}>; rel="next"', settings(), PATH, 1) == expected


def test_next_links_validate_origin_collection_and_numeric_repository():
    assert github._next_page(None, settings(), PATH, 1) == (None, None)
    assert github._next_page('<x>; rel="last"', settings(), PATH, 1) == (None, None)
    link = f'<{API}{PATH}?per_page=2&page=2>; rel="next"'
    assert github._next_page(link + "," + link, settings(), PATH, 1) == (None, "github_pagination_malformed")
    for target in ("https://other" + PATH, API + "/other", API + PATH + "#fragment"):
        assert github._next_page(f'<{target}>; rel="next"', settings(), PATH, 1) == (
            None, "github_pagination_malformed")
    assert github._next_page(f'<{API}/repositories/123/commits/{HEAD}/pulls?per_page=2&page=2>; rel="next"',
                             settings(), PATH, 1) == (2, None)


def test_paginate_deduplicates_and_preserves_receipts():
    instance, seen = client({
        PATH + "?per_page=2&page=1": (200, {"Link": f'<{API}{PATH}?per_page=2&page=2>; rel="next"'},
                                     [{"id": 1}, {"id": 2}]),
        PATH + "?per_page=2&page=2": (200, {}, [{"id": 2}, {"id": 3}])})
    result = github.paginate(instance, PATH, key="id")
    assert result.records == [{"id": 1}, {"id": 2}, {"id": 3}]
    assert result.complete and result.duplicates == 1 and len(seen) == 2
    evidence = result.evidence()
    assert evidence["path"] == PATH and evidence["record_count"] == 3 and evidence["gap"] is None
    assert [page["page"] for page in evidence["pages"]] == [1, 2]
    assert github._record_key({"id": True}, "id").startswith("sha256:")
    assert github._record_key({"a": 1, "b": 2}, "id") == github._record_key({"b": 2, "a": 1}, "id")


@pytest.mark.parametrize("response,overrides,gap", [
    ((429, {}, b""), {}, "github_rate_limited"),
    ((403, {"x-ratelimit-remaining": "0"}, b""), {}, "github_rate_limited"),
    ((500, {}, []), {}, "github_page_unavailable"),
    ((200, {}, {}), {}, "github_page_unavailable"),
    ((200, {}, [1]), {}, "github_page_malformed"),
    ((200, {}, [{"id": 1}, {"id": 2}]), {"max_records": 1}, "github_pagination_bound_reached"),
    (OSError("offline"), {}, "github_page_unavailable"),
], ids=["rate", "rate-header", "status", "shape", "record", "records-bound", "transport"])
def test_paginate_names_failure_and_collection_scope(response, overrides, gap):
    result = github.paginate(client(response, **overrides)[0], PATH, key="id")
    assert not result.complete and result.gap == gap and result.path == PATH
    assert result.evidence()["path"] == PATH


def test_pagination_page_and_request_bounds():
    response = (200, {"link": f'<{API}{PATH}?per_page=2&page=2>; rel="next"'}, [])
    for override, gap in [({"max_pages": 1}, "github_pagination_bound_reached"),
                          ({"max_requests": 1}, "github_request_budget_exhausted")]:
        result = github.paginate(client(response, **override)[0], PATH, key="id")
        assert result.gap == gap and result.path == PATH and not result.complete


@pytest.mark.parametrize("response,gap,retriable", [
    ((401, {}, {}), "github_permission_denied", False),
    ((403, {}, {}), "github_permission_denied", False),
    ((404, {}, {}), "github_snapshot_commit_not_found", False),
    ((503, {}, {}), "github_snapshot_commit_not_found", True),
    ((200, {}, {"sha": PARENT}), "github_snapshot_commit_not_found", False),
    ((429, {}, {}), "github_rate_limited", True),
    (OSError("offline"), "github_snapshot_unavailable", True),
], ids=["unauthorized", "denied", "missing", "server", "wrong-sha", "rate", "transport"])
def test_snapshot_enrichment_gaps_bind_requested_commit(response, gap, retriable):
    instance, seen = client(response)
    result = github.enrich(instance, HEAD, [HEAD])
    assert result["gaps"] == [gap] and result["retriable"] is retriable and result["facts"] == {}
    assert result["missing_commit_count"] == 1 and seen[0][0].endswith("/commits/" + HEAD)


def test_enrichment_direct_push_and_merged_review_timeline():
    pull = {"number": 7, "merged_at": "2024-01-03T00:00:00Z", "created_at": "2024-01-01T00:00:00Z",
            "merge_commit_sha": HEAD, "user": {"login": "author"}, "head": {"sha": PARENT},
            "labels": [{"name": "Security<script>"}, None, {"name": 2}]}
    paths = {
        f"/repos/acme/repo/commits/{HEAD}": (200, {}, {"sha": HEAD}),
        PATH + "?per_page=2&page=1": (200, {}, [pull]),
        f"/repos/acme/repo/commits/{PARENT}/pulls?per_page=2&page=1": (200, {}, []),
        "/repos/acme/repo/pulls/7": (200, {}, {"merged_by": {"login": "author"}, "head": {"sha": PARENT}}),
        "/repos/acme/repo/pulls/7/reviews?per_page=2&page=1": (200, {}, [
            {"id": 1, "state": "APPROVED", "user": {"login": "author"}, "commit_id": PARENT},
            {"id": 2, "state": "APPROVED", "user": {"login": "other"}, "commit_id": PARENT,
             "submitted_at": "2024-01-02T00:00:00Z"}]),
        f"/repos/acme/repo/commits/{PARENT}": (200, {}, {
            "commit": {"committer": {"date": "2024-01-02T00:00:00Z"}}}),
    }
    result = github.enrich(client(paths)[0], HEAD, [HEAD, PARENT])
    first, direct = result["facts"][HEAD], result["facts"][PARENT]
    assert result["gaps"] == [] and result["indeterminate_count"] == 0
    assert first["labels"] == ["securityscript"] and first["self_merged"] is True
    assert first["approved_by_other"] is True and first["review_bypass"] is False and first["approval_stale"] is False
    assert first["head_committed_at"] == "2024-01-02T00:00:00Z"
    assert first["approvals"] == [{"submitted_at": "2024-01-02T00:00:00Z", "commit_id": PARENT}]
    assert direct["direct_push"] is True and direct["pull_request"] is None
    assert "login" not in json.dumps(result) and "script>" not in json.dumps(result)
    review_path = "/repos/acme/repo/pulls/7/reviews?per_page=2&page=1"
    original = paths[review_path]
    paths[review_path] = (200, {}, [original[2][0]])
    self_approved = github.enrich(client(paths)[0], HEAD, [HEAD])["facts"][HEAD]
    assert self_approved["approved_by_other"] is False and self_approved["review_bypass"] is True
    assert self_approved["approvals"] == [] and self_approved["self_merged"] is True
    paths[review_path] = original
    paths["/repos/acme/repo/pulls/7/reviews?per_page=2&page=1"][2][1]["commit_id"] = HEAD
    stale = github.enrich(client(paths)[0], HEAD, [HEAD])["facts"][HEAD]
    assert stale["approval_stale"] is True and stale["review_bypass"] is True


@pytest.mark.parametrize("stage", ["pulls", "detail", "reviews", "head"])
def test_incomplete_review_never_claims_bypass_or_direct_push(stage):
    pull = {"number": 7, "merged_at": "x", "user": {"login": "author"}, "head": {"sha": PARENT}}
    responses = {
        f"/repos/acme/repo/commits/{HEAD}": (200, {}, {"sha": HEAD}),
        PATH + "?per_page=2&page=1": (200, {}, [pull]),
        "/repos/acme/repo/pulls/7": (200, {}, {"head": {"sha": PARENT}}),
        "/repos/acme/repo/pulls/7/reviews?per_page=2&page=1": (200, {}, []),
    }
    limit = {"pulls": 1, "detail": 2, "reviews": 3, "head": 4}[stage]
    instance, _ = client(responses, max_requests=limit)
    result = github.enrich(instance, HEAD, [HEAD, PARENT])
    fact = result["facts"][HEAD]
    assert "github_request_budget_exhausted" in result["gaps"]
    assert fact["review_bypass"] is None and fact["status"] == "indeterminate"
    assert fact["direct_push"] is (None if stage == "pulls" else False)
    assert fact["evidence"]["pulls"]["path"] == PATH
    assert PARENT not in result["facts"]


def test_review_failure_can_continue_to_next_commit_and_invalid_head_has_no_timestamp():
    pull = {"number": 7, "merged_at": "x", "user": {"login": "author"}, "head": {"sha": PARENT}}
    responses = {
        f"/repos/acme/repo/commits/{HEAD}": (200, {}, {"sha": HEAD}),
        PATH + "?per_page=2&page=1": (200, {}, [pull]),
        "/repos/acme/repo/pulls/7": (200, {}, {}),
        "/repos/acme/repo/pulls/7/reviews?per_page=2&page=1": (500, {}, []),
        f"/repos/acme/repo/commits/{PARENT}/pulls?per_page=2&page=1": (200, {}, []),
        f"/repos/acme/repo/commits/{PARENT}": (404, {}, {}),
    }
    result = github.enrich(client(responses)[0], HEAD, [HEAD, PARENT])
    assert result["facts"][HEAD]["status"] == "indeterminate"
    assert result["facts"][HEAD]["evidence"]["reviews"]["path"] == "/repos/acme/repo/pulls/7/reviews"
    assert result["facts"][PARENT]["direct_push"] is True
    assert result["gaps"] == ["github_page_unavailable", "github_review_history_incomplete"]
    responses["/repos/acme/repo/pulls/7/reviews?per_page=2&page=1"] = (200, {}, [])
    result = github.enrich(client(responses)[0], HEAD, [HEAD])
    assert result["facts"][HEAD]["head_committed_at"] is None
    assert result["facts"][HEAD]["evidence"]["head_commit"] == {"status": 404}


def test_enrichment_follows_late_pull_and_approval_pages_and_deduplicates():
    pulls = PATH
    reviews = "/repos/acme/repo/pulls/7/reviews"
    responses = {
        f"/repos/acme/repo/commits/{HEAD}": (200, {}, {"sha": HEAD}),
        pulls + "?per_page=2&page=1": (200, {"Link": f'<{API}{pulls}?per_page=2&page=2>; rel="next"'}, [{"number": 1}]),
        pulls + "?per_page=2&page=2": (200, {"Link": f'<{API}{pulls}?per_page=2&page=3>; rel="next"'}, [{"number": 2}]),
        pulls + "?per_page=2&page=3": (200, {}, [
            {"number": 7, "merged_at": "x", "merge_commit_sha": HEAD, "user": {"login": "private-author"}},
            {"number": 1}]),
        "/repos/acme/repo/pulls/7": (200, {}, {"head": {"sha": "h7"}}),
        reviews + "?per_page=2&page=1": (200, {"Link": f'<{API}{reviews}?per_page=2&page=2>; rel="next"'},
                                       [{"id": 1, "state": "COMMENTED"}]),
        reviews + "?per_page=2&page=2": (200, {}, [
            {"id": 2, "state": "APPROVED", "commit_id": "h7", "user": {"login": "private-reviewer"}},
            {"id": 1, "state": "COMMENTED"}]),
    }
    result = github.enrich(client(responses)[0], HEAD, [HEAD])
    fact = result["facts"][HEAD]
    assert result["gaps"] == [] and fact["pull_request"] == 7 and fact["review_bypass"] is False
    assert fact["approved_by_other"] is True and fact["evidence"]["reviews"]["complete"] is True
    assert fact["evidence"]["pulls"]["duplicate_count"] == fact["evidence"]["reviews"]["duplicate_count"] == 1
    assert [page["page"] for page in fact["evidence"]["pulls"]["pages"]] == [1, 2, 3]
    assert "private-author" not in json.dumps(result) and "private-reviewer" not in json.dumps(result)
    responses[pulls + "?per_page=2&page=3"][2].reverse()
    assert github.enrich(client(responses)[0], HEAD, [HEAD])["facts"][HEAD]["pull_request"] == 7
    responses[reviews + "?per_page=2&page=2"] = (
        200, {"Link": f'<{API}{reviews}?per_page=2&page=1>; rel="next"'}, [])
    cycled = github.enrich(client(responses)[0], HEAD, [HEAD])["facts"][HEAD]
    assert cycled["gap"] == "github_pagination_cycle"
    assert cycled["evidence"]["reviews"]["path"] == reviews and cycled["review_bypass"] is None


@pytest.mark.parametrize("bounds", [{"max_pages": 1}, {"max_records": 1}], ids=["pages", "records"])
def test_enrichment_collection_bounds_cannot_claim_direct_push(bounds):
    responses = {
        f"/repos/acme/repo/commits/{HEAD}": (200, {}, {"sha": HEAD}),
        PATH + "?per_page=2&page=1": (
            200, {"Link": f'<{API}{PATH}?per_page=2&page=2>; rel="next"'}, [{"number": 1}, {"number": 2}]),
    }
    result = github.enrich(client(responses, **bounds)[0], HEAD, [HEAD])
    assert result["gaps"] == ["github_pagination_bound_reached"]
    assert result["facts"][HEAD]["direct_push"] is None and result["facts"][HEAD]["review_bypass"] is None
    assert result["facts"][HEAD]["evidence"]["pulls"]["path"] == PATH


@pytest.mark.parametrize("response,gap", [
    ((403, {"X-RateLimit-Remaining": "0"}, {}), "github_rate_limited"),
    ((502, {}, b"oops"), "github_page_unavailable"),
], ids=["rate", "page-failure"])
def test_second_page_failure_never_turns_partial_pull_list_into_direct_push(response, gap):
    responses = {
        f"/repos/acme/repo/commits/{HEAD}": (200, {}, {"sha": HEAD}),
        PATH + "?per_page=2&page=1": (200, {"Link": f'<{API}{PATH}?per_page=2&page=2>; rel="next"'}, [{"number": 1}]),
        PATH + "?per_page=2&page=2": response,
    }
    instance, seen = client(responses)
    result = github.enrich(instance, HEAD, [HEAD, PARENT] if gap == "github_rate_limited" else [HEAD])
    assert result["gaps"] == [gap] and result["retriable"] is True
    assert result["facts"][HEAD]["direct_push"] is None and result["facts"][HEAD]["review_bypass"] is None
    assert result["facts"][HEAD]["evidence"]["pulls"]["path"] == PATH
    assert PARENT not in result["facts"] and not any(PARENT in request[0] for request in seen)


def test_review_record_bound_never_claims_approval():
    responses = {
        f"/repos/acme/repo/commits/{HEAD}": (200, {}, {"sha": HEAD}),
        PATH + "?per_page=2&page=1": (200, {}, [{"number": 7, "merged_at": "x"}]),
        "/repos/acme/repo/pulls/7": (200, {}, {}),
        "/repos/acme/repo/pulls/7/reviews?per_page=2&page=1": (200, {}, [
            {"id": 1, "state": "COMMENTED"}, {"id": 2, "state": "APPROVED", "user": {"login": "lead"}}]),
    }
    result = github.enrich(client(responses, max_records=1)[0], HEAD, [HEAD])
    fact = result["facts"][HEAD]
    assert fact["approved_by_other"] is None and fact["review_bypass"] is None
    assert result["gaps"] == ["github_pagination_bound_reached", "github_review_history_incomplete"]
    assert fact["evidence"]["reviews"]["path"] == "/repos/acme/repo/pulls/7/reviews"
