"""Bounded GitHub REST enrichment for commits already present in the bound local history.

Only derived review-process facts are retained: whether a commit arrived through a pull request,
whether someone other than the author approved it, whether the approval covered the merged head,
whether the author merged it, and sanitized label names.  Titles, bodies, comments, and account
names are never stored.  The repository identity and API host come only from central configuration.

Associated pull requests and reviews are paginated collections. Every page is requested until the
``Link`` header has no ``next`` relation; each page's request path, status, and response SHA-256 are
retained. A next link must name the same collection and exactly the following page. Bound
exhaustion, a failed or rate-limited page, or a malformed or cyclic link leaves the collection
incomplete, and any conclusion that needs the complete collection (``direct_push``,
``review_bypass``, approval state) is published as ``None`` (indeterminate), never as ``True``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


Transport = Callable[[str, Mapping[str, str], int], tuple[int, Mapping[str, str], bytes]]
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_LABEL = re.compile(r"[^A-Za-z0-9 _.:/+-]")
_LINK = re.compile(r'\s*<([^<>]*)>\s*((?:;\s*[A-Za-z]+\s*=\s*"?[^";,]*"?\s*)*)')
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
PAGINATION_IDENTITY = "appsec-review/github-link-pagination/1"


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
    per_page: int = 100
    max_pages: int = 100
    max_records: int = 10_000

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlsplit(self.api_base)
        if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
            raise ValueError("GitHub API base must be an https URL without query or fragment")
        if not _REPOSITORY.fullmatch(self.repository) or ".." in self.repository:
            raise ValueError("GitHub repository must be owner/name")
        if not 1 <= self.max_requests <= 100_000 or not 1 <= self.timeout_seconds <= 300:
            raise ValueError("GitHub enrichment bounds are invalid")
        for name, value, high in (("per_page", self.per_page, 100), ("max_pages", self.max_pages, 10_000),
                                  ("max_records", self.max_records, 1_000_000)):
            if type(value) is not int or not 1 <= value <= high:
                raise ValueError(f"GitHub pagination bound is invalid: {name}")

    def pagination(self) -> dict[str, Any]:
        return {"identity": PAGINATION_IDENTITY, "per_page": self.per_page, "max_pages": self.max_pages,
                "max_records": self.max_records}


class BudgetExhausted(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: Any
    sha256: str


class GitHubClient:
    def __init__(self, settings: GitHubSettings, transport: Transport | None = None):
        self.settings = settings
        self.transport = transport or default_transport
        self.requests = 0
        self.statuses: dict[str, int] = {}

    def get(self, path: str) -> tuple[int, Any]:
        response = self.request(path)
        return response.status, response.body

    def request(self, path: str) -> Response:
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
        digest = hashlib.sha256(body).hexdigest()
        try:
            return Response(status, lowered, json.loads(body.decode("utf-8")) if body else None, digest)
        except (UnicodeError, json.JSONDecodeError):
            return Response(status, lowered, None, digest)


@dataclass(slots=True)
class Collection:
    """Every record of one paginated collection, or an explicit reason it is incomplete."""

    path: str
    records: list[Mapping[str, Any]] = field(default_factory=list)
    pages: list[dict[str, Any]] = field(default_factory=list)
    complete: bool = False
    gap: str | None = None
    duplicates: int = 0

    def evidence(self) -> dict[str, Any]:
        return {"path": self.path, "complete": self.complete, "gap": self.gap, "record_count": len(self.records),
                "duplicate_count": self.duplicates, "pages": list(self.pages)}


def _next_page(link: str | None, settings: GitHubSettings, path: str, page: int) -> tuple[int | None, str | None]:
    """Return the next page number named by a ``Link`` header, or a gap when the link is unusable.

    The link must stay on the configured API host, name the same collection (GitHub may address the
    repository by numeric id), keep the requested page size, and advance by exactly one page.
    """
    if not link:
        return None, None
    targets = []
    for match in _LINK.finditer(link):
        relations = re.findall(r'rel\s*=\s*"?([^";,]*)"?', match.group(2))
        if any("next" in relation.split() for relation in relations):
            targets.append(match.group(1))
    if not targets:
        return None, None
    if len(targets) != 1:
        return None, "github_pagination_malformed"
    base = urllib.parse.urlsplit(settings.api_base)
    target = urllib.parse.urlsplit(targets[0])
    prefix = base.path.rstrip("/")
    if (target.scheme, target.netloc) != (base.scheme, base.netloc) or target.fragment or \
            not target.path.startswith(prefix + "/"):
        return None, "github_pagination_malformed"
    relative = target.path[len(prefix):]
    suffix = path.split("/", 4)[4] if path.startswith("/repos/") and path.count("/") >= 4 else None
    if relative != path and not (suffix and re.fullmatch(r"/repositories/[0-9]{1,20}/" + re.escape(suffix), relative)):
        return None, "github_pagination_malformed"
    try:
        query = urllib.parse.parse_qs(target.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return None, "github_pagination_malformed"
    if set(query) != {"per_page", "page"} or any(len(values) != 1 for values in query.values()):
        return None, "github_pagination_malformed"
    if query["per_page"][0] != str(settings.per_page) or not re.fullmatch(r"[1-9][0-9]{0,6}", query["page"][0]):
        return None, "github_pagination_malformed"
    following = int(query["page"][0])
    if following <= page:
        return None, "github_pagination_cycle"
    if following != page + 1:
        return None, "github_pagination_malformed"
    return following, None


def _record_key(record: Mapping[str, Any], key: str) -> str:
    value = record.get(key)
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{key}:{value}"
    return "sha256:" + hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


STOP_GAPS = frozenset({"github_rate_limited", "github_request_budget_exhausted"})
RETRIABLE_GAPS = frozenset({"github_rate_limited", "github_page_unavailable"})


def paginate(client: GitHubClient, path: str, *, key: str) -> Collection:
    """Request every page of ``path``; records are deduplicated by ``key`` in first-seen order.

    Never raises for budget or rate exhaustion: the collection records the gap, and a gap in
    :data:`STOP_GAPS` tells the caller to stop issuing requests.
    """
    settings = client.settings
    collection = Collection(path)
    seen: set[str] = set()
    page = 1
    while True:
        if len(collection.pages) >= settings.max_pages:
            collection.gap = "github_pagination_bound_reached"
            return collection
        request_path = f"{path}?per_page={settings.per_page}&page={page}"
        try:
            response = client.request(request_path)
        except BudgetExhausted as exc:
            collection.gap = "github_rate_limited" if str(exc) == "github_rate_limited" else "github_request_budget_exhausted"
            return collection
        except ValueError:
            collection.gap = "github_page_unavailable"
            return collection
        body = response.body
        collection.pages.append({"page": page, "request": request_path, "status": response.status,
                                 "response_sha256": response.sha256,
                                 "record_count": len(body) if isinstance(body, list) else None,
                                 "link_sha256": hashlib.sha256(response.headers.get("link", "").encode()).hexdigest()})
        if response.status != 200 or not isinstance(body, list):
            collection.gap = "github_page_unavailable"
            return collection
        for record in body:
            if not isinstance(record, Mapping):
                collection.gap = "github_page_malformed"
                return collection
            identity = _record_key(record, key)
            if identity in seen:
                collection.duplicates += 1
                continue
            seen.add(identity)
            collection.records.append(record)
            if len(collection.records) > settings.max_records:
                collection.gap = "github_pagination_bound_reached"
                return collection
        following, gap = _next_page(response.headers.get("link"), settings, path, page)
        if gap is not None:
            collection.gap = gap
            return collection
        if following is None:
            collection.complete = True
            return collection
        page = following


def _labels(pull: Mapping[str, Any]) -> list[str]:
    values = []
    for label in pull.get("labels", ()) if isinstance(pull.get("labels"), list) else ():
        if isinstance(label, Mapping) and isinstance(label.get("name"), str):
            values.append(_LABEL.sub("", label["name"])[:64].lower())
    return sorted(set(value for value in values if value))


def _indeterminate(gap: str, evidence: Mapping[str, Any], **known: Any) -> dict[str, Any]:
    """A commit whose review history is incomplete: no conclusion that needs all of it is drawn."""
    return {"pull_request": None, "direct_push": None, "review_bypass": None, "labels": [], **known,
            "status": "indeterminate", "gap": gap, "evidence": dict(evidence)}


def enrich(client: GitHubClient, snapshot_commit: str, commits: list[str]) -> dict[str, Any]:
    """Collect per-commit review facts newest-first until the request budget is spent."""
    repository = urllib.parse.quote(client.settings.repository, safe="/")
    gaps: list[str] = []
    retriable = False
    facts: dict[str, dict[str, Any]] = {}
    pulls: dict[int, dict[str, Any]] = {}
    snapshot: dict[str, Any] = {}

    def result(override: list[str] | None = None) -> dict[str, Any]:
        missing = [commit for commit in commits if commit not in facts]
        if override is None and missing and not STOP_GAPS & set(gaps):
            gaps.append("github_commit_pulls_unavailable")
        indeterminate = sum(1 for value in facts.values() if value.get("review_bypass") is None)
        return {"facts": facts if override is None else {}, "gaps": sorted(set(override if override is not None else gaps)),
                "retriable": retriable, "missing_commit_count": len(missing), "indeterminate_count": indeterminate,
                "pagination": client.settings.pagination(), "snapshot_response": snapshot,
                "requests": client.requests, "statuses": dict(sorted(client.statuses.items()))}

    try:
        response = client.request(f"/repos/{repository}/commits/{snapshot_commit}")
    except BudgetExhausted as exc:
        retriable = str(exc) == "github_rate_limited"
        return result(["github_rate_limited" if retriable else "github_request_budget_exhausted"])
    snapshot.update({"status": response.status, "response_sha256": response.sha256})
    if response.status in {401, 403}:
        return result(["github_permission_denied"])
    if response.status != 200 or not isinstance(response.body, Mapping) or response.body.get("sha") != snapshot_commit:
        retriable = response.status >= 500
        return result(["github_snapshot_commit_not_found"])
    for commit in commits:
        associated = paginate(client, f"/repos/{repository}/commits/{commit}/pulls", key="number")
        evidence = {"pulls": associated.evidence()}
        if not associated.complete:
            gap = associated.gap or "github_page_unavailable"
            gaps.append(gap)
            retriable = retriable or gap in RETRIABLE_GAPS
            facts[commit] = _indeterminate(gap, evidence)
            if gap in STOP_GAPS:
                break
            continue
        merged = sorted((item for item in associated.records
                         if item.get("merged_at") and isinstance(item.get("number"), int)
                         and not isinstance(item.get("number"), bool)),
                        key=lambda item: int(item["number"]))
        # Prefer the pull request whose merge produced this commit; otherwise the lowest number.
        chosen = next((item for item in merged if item.get("merge_commit_sha") == commit),
                      merged[0] if merged else None)
        if chosen is None:
            facts[commit] = {"pull_request": None, "direct_push": True, "review_bypass": True, "labels": [],
                             "status": "complete", "evidence": evidence}
            continue
        number = int(chosen["number"])
        if number not in pulls:
            pulls[number] = _pull_facts(client, repository, number, chosen)
        pull = pulls[number]
        facts[commit] = {**{key: value for key, value in pull.items() if key != "evidence"},
                         "pull_request": number, "direct_push": False,
                         "evidence": {**evidence, **pull["evidence"]}}
        if pull["status"] != "complete":
            gap = str(pull["gap"])
            gaps.extend((gap, "github_review_history_incomplete"))
            retriable = retriable or gap in RETRIABLE_GAPS
            if gap in STOP_GAPS:
                break
    return result()


def _pull_facts(client: GitHubClient, repository: str, number: int, summary: Mapping[str, Any]) -> dict[str, Any]:
    labels = _labels(summary)
    author = (summary.get("user") or {}).get("login") if isinstance(summary.get("user"), Mapping) else None
    head = (summary.get("head") or {}).get("sha") if isinstance(summary.get("head"), Mapping) else None
    try:
        detail = client.request(f"/repos/{repository}/pulls/{number}")
    except BudgetExhausted as exc:
        gap = "github_rate_limited" if str(exc) == "github_rate_limited" else "github_request_budget_exhausted"
        return _indeterminate(gap, {"pull_detail": {"status": None}}, labels=labels,
                              approved_by_other=None, approval_stale=None, self_merged=None)
    except ValueError:
        detail = Response(0, {}, None, "")
    merged_by = None
    if detail.status == 200 and isinstance(detail.body, Mapping):
        body = detail.body
        merged_by = (body.get("merged_by") or {}).get("login") if isinstance(body.get("merged_by"), Mapping) else None
        head = (body.get("head") or {}).get("sha", head) if isinstance(body.get("head"), Mapping) else head
    reviews = paginate(client, f"/repos/{repository}/pulls/{number}/reviews", key="id")
    evidence = {"pull_detail": {"status": detail.status, "response_sha256": detail.sha256},
                "reviews": reviews.evidence()}
    self_merged = (merged_by == author) if merged_by and author else None
    if not reviews.complete:
        # Approval state needs every review: an approval may sit on a page that was not read.
        return _indeterminate(reviews.gap or "github_page_unavailable", evidence, labels=labels,
                              approved_by_other=None, approval_stale=None, self_merged=self_merged)
    approvals = [item for item in reviews.records
                 if item.get("state") == "APPROVED" and isinstance(item.get("user"), Mapping)
                 and item["user"].get("login") != author]
    approved = bool(approvals)
    stale = approved and head is not None and all(item.get("commit_id") != head for item in approvals)
    return {"labels": labels, "approved_by_other": approved, "approval_stale": stale, "self_merged": self_merged,
            "review_bypass": not approved or stale, "status": "complete", "evidence": evidence}
