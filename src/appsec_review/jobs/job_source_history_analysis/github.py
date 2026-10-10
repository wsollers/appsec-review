"""Bounded GitHub REST enrichment for commits already present in the bound local history.

Only derived review-process facts are retained: whether a commit arrived through a pull request,
whether someone other than the author approved it, whether the approval covered the merged head,
whether the author merged it, sanitized label names, and the review timeline (creation, merge,
final-head commit time, and each other-reviewer approval's time and reviewed commit).  Titles,
bodies, comments, and account names are never stored.  The repository identity and API host come
only from central configuration.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


Transport = Callable[[str, Mapping[str, str], int], tuple[int, Mapping[str, str], bytes]]
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_LABEL = re.compile(r"[^A-Za-z0-9 _.:/+-]")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})")
_OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def default_transport(url: str, headers: Mapping[str, str], timeout: int) -> tuple[int, Mapping[str, str], bytes]:
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read(MAX_RESPONSE_BYTES + 1)


@dataclass(frozen=True, slots=True)
class GitHubSettings:
    api_base: str
    repository: str
    token: str | None
    max_requests: int
    timeout_seconds: int

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlsplit(self.api_base)
        if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
            raise ValueError("GitHub API base must be an https URL without query or fragment")
        if not _REPOSITORY.fullmatch(self.repository) or ".." in self.repository:
            raise ValueError("GitHub repository must be owner/name")
        if not 1 <= self.max_requests <= 100_000 or not 1 <= self.timeout_seconds <= 300:
            raise ValueError("GitHub enrichment bounds are invalid")


class BudgetExhausted(RuntimeError):
    pass


class GitHubClient:
    def __init__(self, settings: GitHubSettings, transport: Transport | None = None):
        self.settings = settings
        self.transport = transport or default_transport
        self.requests = 0
        self.statuses: dict[str, int] = {}

    def get(self, path: str) -> tuple[int, Any]:
        if self.requests >= self.settings.max_requests:
            raise BudgetExhausted("github request budget exhausted")
        self.requests += 1
        url = self.settings.api_base.rstrip("/") + path
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "appsec-review-source-history/1"}
        if self.settings.token:
            headers["Authorization"] = f"Bearer {self.settings.token}"
        status, response_headers, body = self.transport(url, headers, self.settings.timeout_seconds)
        bucket = str(status)
        self.statuses[bucket] = self.statuses.get(bucket, 0) + 1
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("github response exceeds its bound")
        lowered = {str(key).lower(): str(value) for key, value in response_headers.items()}
        if status in {403, 429} and (lowered.get("x-ratelimit-remaining") == "0" or status == 429):
            raise BudgetExhausted("github_rate_limited")
        try:
            return status, json.loads(body.decode("utf-8")) if body else None
        except (UnicodeError, json.JSONDecodeError):
            return status, None


def _labels(pull: Mapping[str, Any]) -> list[str]:
    values = []
    for label in pull.get("labels", ()) if isinstance(pull.get("labels"), list) else ():
        if isinstance(label, Mapping) and isinstance(label.get("name"), str):
            values.append(_LABEL.sub("", label["name"])[:64].lower())
    return sorted(set(value for value in values if value))


def _timestamp(value: Any) -> str | None:
    return value if isinstance(value, str) and _TIMESTAMP.fullmatch(value) else None


def _object_id(value: Any) -> str | None:
    return value if isinstance(value, str) and _OBJECT_ID.fullmatch(value) else None


def enrich(client: GitHubClient, snapshot_commit: str, commits: list[str]) -> dict[str, Any]:
    """Collect per-commit review facts newest-first until the request budget is spent."""
    repository = urllib.parse.quote(client.settings.repository, safe="/")
    gaps: list[str] = []
    retriable = False
    facts: dict[str, dict[str, Any]] = {}
    pulls: dict[int, dict[str, Any]] = {}
    try:
        status, body = client.get(f"/repos/{repository}/commits/{snapshot_commit}")
        if status in {401, 403}:
            return {"facts": {}, "gaps": ["github_permission_denied"], "retriable": False,
                    "requests": client.requests, "statuses": client.statuses}
        if status != 200 or not isinstance(body, Mapping) or body.get("sha") != snapshot_commit:
            return {"facts": {}, "gaps": ["github_snapshot_commit_not_found"], "retriable": status >= 500,
                    "requests": client.requests, "statuses": client.statuses}
        for commit in commits:
            status, body = client.get(f"/repos/{repository}/commits/{commit}/pulls?per_page=10")
            if status != 200 or not isinstance(body, list):
                gaps.append("github_commit_pulls_unavailable")
                retriable = retriable or status >= 500
                continue
            merged = [item for item in body if isinstance(item, Mapping) and item.get("merged_at")]
            chosen = next((item for item in merged if item.get("merge_commit_sha") == commit),
                          merged[0] if merged else None)
            if chosen is None or not isinstance(chosen.get("number"), int):
                facts[commit] = {"pull_request": None, "direct_push": True, "review_bypass": True, "labels": []}
                continue
            number = int(chosen["number"])
            if number not in pulls:
                pulls[number] = _pull_facts(client, repository, number, chosen)
            facts[commit] = {"pull_request": number, "direct_push": False, **pulls[number]}
    except BudgetExhausted as exc:
        gaps.append("github_rate_limited" if str(exc) == "github_rate_limited" else "github_request_budget_exhausted")
        retriable = retriable or str(exc) == "github_rate_limited"
    missing = [commit for commit in commits if commit not in facts]
    if missing and "github_request_budget_exhausted" not in gaps and "github_rate_limited" not in gaps:
        gaps.append("github_commit_pulls_unavailable")
    return {"facts": facts, "gaps": sorted(set(gaps)), "retriable": retriable, "missing_commit_count": len(missing),
            "requests": client.requests, "statuses": dict(sorted(client.statuses.items()))}


def _pull_facts(client: GitHubClient, repository: str, number: int, summary: Mapping[str, Any]) -> dict[str, Any]:
    labels = _labels(summary)
    author = (summary.get("user") or {}).get("login") if isinstance(summary.get("user"), Mapping) else None
    head = (summary.get("head") or {}).get("sha") if isinstance(summary.get("head"), Mapping) else None
    status, detail = client.get(f"/repos/{repository}/pulls/{number}")
    merged_by = None
    if status == 200 and isinstance(detail, Mapping):
        merged_by = (detail.get("merged_by") or {}).get("login") if isinstance(detail.get("merged_by"), Mapping) else None
        head = (detail.get("head") or {}).get("sha", head) if isinstance(detail.get("head"), Mapping) else head
    status, reviews = client.get(f"/repos/{repository}/pulls/{number}/reviews?per_page=100")
    reviews_known = status == 200 and isinstance(reviews, list)
    approvals = [item for item in (reviews if reviews_known else ())
                 if isinstance(item, Mapping) and item.get("state") == "APPROVED" and
                 isinstance(item.get("user"), Mapping) and item["user"].get("login") != author]
    approved = bool(approvals)
    stale = approved and head is not None and all(item.get("commit_id") != head for item in approvals)
    head_committed_at = None
    if _object_id(head):
        status, commit = client.get(f"/repos/{repository}/commits/{head}")
        if status == 200 and isinstance(commit, Mapping) and isinstance(commit.get("commit"), Mapping):
            committer = commit["commit"].get("committer")
            head_committed_at = _timestamp(committer.get("date")) if isinstance(committer, Mapping) else None
    timeline = sorted(({"submitted_at": _timestamp(item.get("submitted_at")), "commit_id": _object_id(item.get("commit_id"))}
                       for item in approvals), key=lambda item: (item["submitted_at"] or "", item["commit_id"] or ""))
    return {"labels": labels, "approved_by_other": approved if reviews_known else None,
            "approval_stale": stale if reviews_known else None,
            "self_merged": (merged_by == author) if merged_by and author else None,
            "review_bypass": (not approved or stale) if reviews_known else None,
            "created_at": _timestamp(summary.get("created_at")), "merged_at": _timestamp(summary.get("merged_at")),
            "head_sha": _object_id(head), "head_committed_at": head_committed_at,
            "approvals": timeline if reviews_known else None}
