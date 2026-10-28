"""GitLab, Gerrit, and Azure DevOps review exports.

A review export has two parts. Read-only API responses (or an operator-supplied, hash-pinned bundle
of the same responses) are kept verbatim as the ``appsec-review/review-export-bundle/1`` bundle and
normalized into the ``appsec-review/review-records/1`` export that ``job_change_context_analysis``
already reads. The reviewed head revision is then checked out with Git, and the base-to-head patch
is recorded beside it.

Every response is untrusted. The pinned revision (and patch set or iteration) must match what the
server reports, or nothing is published. Free text (titles, descriptions, names, e-mail addresses)
never reaches the review records.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import base64
import json
import re
from typing import Any
from urllib.parse import quote
import urllib.error
import urllib.request

from .safety import AcquisitionError, check_http_url, scrub


# The export schema ``job_change_context_analysis.sources`` reads; kept literal so acquisition does
# not import the job package.
REVIEW_EXPORT_SCHEMA = "appsec-review/review-records/1"
BUNDLE_SCHEMA = "appsec-review/review-export-bundle/1"
GERRIT_PREFIX = b")]}'"
_OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_GERRIT_TIME = re.compile(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(\.\d{1,9})?")
PAGE_SIZE = 100


@dataclass(frozen=True, slots=True)
class ReviewMetadata:
    """What the review server reports about the pinned revision, already checked against the pin."""

    provider: str
    change: int
    head: str
    base: str | None
    fetch_ref: str
    state: str
    records: dict[str, dict[str, Any]]
    gaps: tuple[dict[str, str], ...]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        raise AcquisitionError(f"review API redirected ({code}); redirects are refused", status="REFUSED")


Fetcher = Callable[[str], Any]


def http_fetcher(*, headers: Mapping[str, str], timeout: int, max_bytes: int, allow_local: bool,
                 secrets: tuple[str, ...]) -> Fetcher:
    """GET JSON with the configured authorization header, no redirects, and a response size bound."""
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}) if allow_local else
                                         urllib.request.ProxyHandler())

    def fetch(url: str) -> Any:
        check_http_url(url, allow_local=allow_local)
        request = urllib.request.Request(url, headers={"Accept": "application/json", **headers}, method="GET")
        try:
            with opener.open(request, timeout=timeout) as response:
                data = response.read(max_bytes + 1)
        except urllib.error.HTTPError as exc:
            raise AcquisitionError(f"review API returned HTTP {exc.code} for {scrub(_path(url), secrets)}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise AcquisitionError(f"review API request failed: {scrub(str(getattr(exc, 'reason', exc)), secrets)}") from None
        if len(data) > max_bytes:
            raise AcquisitionError("review API response exceeds max_http_response_bytes")
        if data.startswith(GERRIT_PREFIX):
            data = data[len(GERRIT_PREFIX):]
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AcquisitionError(f"review API returned invalid JSON for {_path(url)}") from exc

    return fetch


def _path(url: str) -> str:
    return url.split("?", 1)[0]


def auth_headers(provider: str, token: str, username: str) -> dict[str, str]:
    if not token:
        return {}
    if provider == "gitlab":
        return {"PRIVATE-TOKEN": token}
    user = username if provider == "gerrit" else (username or "")
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode("ascii")}


# --- API collection: the exact responses a bundle holds -------------------------------------------------------


def collect(provider: str, fetch: Fetcher, *, api_url: str, project: str, repository: str, change: int,
            patchset: int | None, iteration: int | None, max_commits: int,
            authenticated: bool = False) -> dict[str, Any]:
    """Fetch the provider's responses for one change. The result is the bundle's ``responses``."""
    if provider == "gitlab":
        base = f"{api_url}/api/v4/projects/{quote(project, safe='')}/merge_requests/{change}"
        return {"merge_request": fetch(base), "approvals": fetch(f"{base}/approvals"),
                "commits": _paged(fetch, f"{base}/commits?per_page={PAGE_SIZE}&page={{page}}", max_commits)}
    if provider == "gerrit":
        # Gerrit serves authenticated REST under /a/; anonymous reads use the plain paths.
        prefix = f"{api_url}/a" if authenticated and not api_url.endswith("/a") else api_url
        options = "&".join(f"o={item}" for item in ("ALL_REVISIONS", "ALL_COMMITS", "DETAILED_LABELS",
                                                    "DETAILED_ACCOUNTS"))
        identifier = quote(f"{project}~{change}", safe="~") if project else str(change)
        return {"change": fetch(f"{prefix}/changes/{identifier}?{options}")}
    base = (f"{api_url}/{quote(project, safe='')}/_apis/git/repositories/{quote(repository, safe='')}"
            f"/pullrequests/{change}")
    version = "api-version=7.1"
    commits = _paged(fetch, f"{base}/commits?{version}&$top={PAGE_SIZE}&$skip={{skip}}", max_commits, key="value")
    return {"pull_request": fetch(f"{base}?{version}"),
            "iteration": fetch(f"{base}/iterations/{iteration}?{version}"), "commits": commits}


def _paged(fetch: Fetcher, template: str, limit: int, *, key: str | None = None) -> dict[str, Any]:
    items: list[Any] = []
    page = 1
    truncated = False
    while True:
        response = fetch(template.format(page=page, skip=(page - 1) * PAGE_SIZE))
        batch = response.get(key) if key and isinstance(response, Mapping) else response
        if not isinstance(batch, list):
            raise AcquisitionError("review API returned a malformed commit list")
        items.extend(batch)
        if len(items) >= limit:
            truncated = len(items) > limit or len(batch) == PAGE_SIZE
            items = items[:limit]
            break
        if len(batch) < PAGE_SIZE:
            break
        page += 1
    return {"items": items, "truncated": truncated}


# --- Normalization ----------------------------------------------------------------------------------------------


def _object_id(value: Any) -> str | None:
    return value if isinstance(value, str) and _OBJECT_ID.fullmatch(value) else None


def _gerrit_time(value: Any) -> str | None:
    match = _GERRIT_TIME.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return None
    return f"{match.group(1)}T{match.group(2)}{match.group(3) or ''}Z"


def _identity(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, Mapping) else None


def _commit_items(responses: Mapping[str, Any]) -> tuple[list[Any], bool]:
    commits = responses.get("commits")
    if not isinstance(commits, Mapping) or not isinstance(commits.get("items"), list):
        raise AcquisitionError("review export bundle has no commit list", status="REFUSED")
    return commits["items"], commits.get("truncated") is True


def normalize(provider: str, responses: Mapping[str, Any], *, change: int, revision: str,
              patchset: int | None, iteration: int | None) -> ReviewMetadata:
    if provider == "gitlab":
        return _gitlab(responses, change, revision)
    if provider == "gerrit":
        return _gerrit(responses, change, revision, patchset)
    return _azure(responses, change, revision, iteration)


_RECORD_KEYS = ("pull_request", "created_at", "merged_at", "head_sha", "head_committed_at", "approvals",
                "self_merged")
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})")


def _timestamp(value: Any) -> str | None:
    return value if isinstance(value, str) and _RFC3339.fullmatch(value) else None


def _records(commits: list[str], raw: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """One raw export record per reviewed commit; only typed fields survive, never free text."""
    record = {key: raw.get(key) for key in _RECORD_KEYS}
    for key in ("created_at", "merged_at", "head_committed_at"):
        record[key] = _timestamp(record[key])
    if record["self_merged"] not in (True, False):
        record["self_merged"] = None
    if isinstance(record["approvals"], list):
        record["approvals"] = [{"submitted_at": _timestamp(item.get("submitted_at")), "commit_id": None}
                               for item in record["approvals"]]
    return {commit: json.loads(json.dumps(record)) for commit in sorted(set(commits))}


def _gitlab(responses: Mapping[str, Any], change: int, revision: str) -> ReviewMetadata:
    mr = responses.get("merge_request")
    if not isinstance(mr, Mapping) or mr.get("iid") != change:
        raise AcquisitionError("GitLab merge request does not match the configured change", status="REFUSED")
    if mr.get("sha") != revision:
        raise AcquisitionError(f"GitLab merge request head is {mr.get('sha')!r}, not the pinned revision",
                               status="REFUSED")
    author = _identity(mr.get("author"), "id")
    approvals_doc = responses.get("approvals")
    approvals = None
    if isinstance(approvals_doc, Mapping) and isinstance(approvals_doc.get("approved_by"), list):
        approvals = [{"submitted_at": None, "commit_id": None} for item in approvals_doc["approved_by"]
                     if _identity(_identity(item, "user"), "id") not in (None, author)]
    items, truncated = _commit_items(responses)
    commit_ids = [_object_id(_identity(item, "id")) for item in items]
    head_date = next((_identity(item, "committed_date") for item in items if _identity(item, "id") == revision), None)
    merged_by = _identity(mr.get("merge_user") or mr.get("merged_by"), "id")
    state = str(mr.get("state", "unknown"))
    raw = {"pull_request": change, "created_at": mr.get("created_at"),
           "merged_at": mr.get("merged_at") if state == "merged" else None, "head_sha": revision,
           "head_committed_at": head_date, "approvals": approvals,
           "self_merged": (merged_by == author) if state == "merged" and merged_by is not None else None}
    gaps = _common_gaps(raw, approvals, truncated, commit_ids)
    if approvals:
        gaps.append({"path": ".", "reason": "review_approval_times_unavailable",
                     "detail": "GitLab approvals carry no time or commit; stale approval cannot be assessed"})
    diff_refs = mr.get("diff_refs") if isinstance(mr.get("diff_refs"), Mapping) else {}
    return ReviewMetadata("gitlab", change, revision, _object_id(diff_refs.get("base_sha")),
                          f"refs/merge-requests/{change}/head", state,
                          _records([item for item in commit_ids if item], raw), tuple(gaps))


def _gerrit(responses: Mapping[str, Any], change: int, revision: str, patchset: int | None) -> ReviewMetadata:
    doc = responses.get("change")
    if not isinstance(doc, Mapping) or doc.get("_number") != change:
        raise AcquisitionError("Gerrit change does not match the configured change", status="REFUSED")
    revisions = doc.get("revisions") if isinstance(doc.get("revisions"), Mapping) else {}
    pinned = revisions.get(revision)
    if not isinstance(pinned, Mapping) or pinned.get("_number") != patchset:
        raise AcquisitionError(f"Gerrit patch set {patchset} is not revision {revision}", status="REFUSED")
    commit = pinned.get("commit") if isinstance(pinned.get("commit"), Mapping) else {}
    parents = commit.get("parents") if isinstance(commit.get("parents"), list) else []
    base = _object_id(_identity(parents[0], "commit")) if parents else None
    owner = _identity(doc.get("owner"), "_account_id")
    labels = doc.get("labels") if isinstance(doc.get("labels"), Mapping) else {}
    review_label = labels.get("Code-Review") if isinstance(labels.get("Code-Review"), Mapping) else None
    approvals = None
    if review_label is not None and isinstance(review_label.get("all"), list):
        values = review_label.get("values") if isinstance(review_label.get("values"), Mapping) else {}
        top = max((int(key.strip()) for key in values if key.strip().lstrip("+-").isdigit()), default=2)
        approvals = [{"submitted_at": _gerrit_time(_identity(item, "date")), "commit_id": None}
                     for item in review_label["all"]
                     if _identity(item, "value") == top and _identity(item, "_account_id") not in (None, owner)]
    status = str(doc.get("status", "UNKNOWN"))
    submitter = _identity(doc.get("submitter"), "_account_id")
    raw = {"pull_request": change, "created_at": _gerrit_time(doc.get("created")),
           "merged_at": _gerrit_time(doc.get("submitted")) if status == "MERGED" else None, "head_sha": revision,
           "head_committed_at": _gerrit_time(_identity(commit.get("committer"), "date")), "approvals": approvals,
           "self_merged": (submitter == owner) if status == "MERGED" and submitter is not None else None}
    commit_ids = [_object_id(key) for key in revisions]
    gaps = _common_gaps(raw, approvals, False, commit_ids)
    shard = f"{change % 100:02d}"
    return ReviewMetadata("gerrit", change, revision, base, f"refs/changes/{shard}/{change}/{patchset}",
                          status.lower(), _records([item for item in commit_ids if item], raw), tuple(gaps))


def _azure(responses: Mapping[str, Any], change: int, revision: str, iteration: int | None) -> ReviewMetadata:
    pr = responses.get("pull_request")
    if not isinstance(pr, Mapping) or pr.get("pullRequestId") != change:
        raise AcquisitionError("Azure DevOps pull request does not match the configured change", status="REFUSED")
    it = responses.get("iteration")
    if not isinstance(it, Mapping) or it.get("id") != iteration:
        raise AcquisitionError("Azure DevOps iteration does not match the configured iteration", status="REFUSED")
    head = _identity(it.get("sourceRefCommit"), "commitId")
    if head != revision:
        raise AcquisitionError(f"Azure DevOps iteration {iteration} source commit is {head!r}, not the pinned "
                               "revision", status="REFUSED")
    base = _object_id(_identity(it.get("commonRefCommit"), "commitId")) or \
        _object_id(_identity(it.get("targetRefCommit"), "commitId"))
    author = _identity(pr.get("createdBy"), "id")
    reviewers = pr.get("reviewers")
    approvals = None
    if isinstance(reviewers, list):
        approvals = [{"submitted_at": None, "commit_id": None} for item in reviewers
                     if _identity(item, "vote") in (10, 5) and _identity(item, "id") not in (None, author)]
    items, truncated = _commit_items(responses)
    commit_ids = [_object_id(_identity(item, "commitId")) for item in items]
    head_date = next((_identity(_identity(item, "committer"), "date") for item in items
                      if _identity(item, "commitId") == revision), None)
    status = str(pr.get("status", "unknown"))
    closed_by = _identity(pr.get("closedBy"), "id")
    raw = {"pull_request": change, "created_at": pr.get("creationDate"),
           "merged_at": pr.get("closedDate") if status == "completed" else None, "head_sha": revision,
           "head_committed_at": head_date, "approvals": approvals,
           "self_merged": (closed_by == author) if status == "completed" and closed_by is not None else None}
    gaps = _common_gaps(raw, approvals, truncated, commit_ids)
    if approvals:
        gaps.append({"path": ".", "reason": "review_approval_times_unavailable",
                     "detail": "Azure DevOps reviewer votes carry no time or commit; stale approval cannot be assessed"})
    return ReviewMetadata("azure_devops", change, revision, base, f"refs/pull/{change}/merge", status,
                          _records([item for item in commit_ids if item], raw), tuple(gaps))


def _common_gaps(raw: Mapping[str, Any], approvals: list[Any] | None, truncated: bool,
                 commit_ids: list[str | None]) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []
    if approvals is None:
        gaps.append({"path": ".", "reason": "review_approvals_unavailable"})
    if truncated:
        gaps.append({"path": ".", "reason": "review_commits_truncated", "detail": "max_review_commits reached"})
    if any(item is None for item in commit_ids):
        gaps.append({"path": ".", "reason": "review_commit_ids_rejected"})
    if raw.get("head_sha") not in commit_ids:
        gaps.append({"path": ".", "reason": "review_head_not_in_commit_list"})
    if raw.get("merged_at") is None:
        gaps.append({"path": ".", "reason": "review_not_merged",
                     "detail": "open or abandoned review; merge-time metrics are unavailable"})
    return gaps


def review_records_document(metadata: ReviewMetadata) -> dict[str, Any]:
    """The ``appsec-review/review-records/1`` export ``job_change_context_analysis`` reads."""
    return {"schema": REVIEW_EXPORT_SCHEMA, "records": {key: dict(value) for key, value in
                                                        sorted(metadata.records.items())}}


def bundle_document(provider: str, change: int, responses: Mapping[str, Any]) -> dict[str, Any]:
    return {"schema": BUNDLE_SCHEMA, "provider": provider, "change": change, "responses": dict(responses)}


def read_bundle(document: Any, provider: str, change: int) -> Mapping[str, Any]:
    if (not isinstance(document, Mapping) or document.get("schema") != BUNDLE_SCHEMA or
            document.get("provider") != provider or document.get("change") != change or
            not isinstance(document.get("responses"), Mapping)):
        raise AcquisitionError("review export bundle does not match the configured provider and change",
                               status="REFUSED")
    return document["responses"]
