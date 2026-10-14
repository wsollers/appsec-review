"""Bounded OpenSSF Scorecard API client with an injectable HTTPS transport."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import ssl
import time
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from appsec_review.jobs.engineering_contracts import SCORECARD_RECORD_SCHEMA
from appsec_review.storage import (LockUnavailable, atomic_bytes, atomic_json, bounded_file_lock,
                                   file_sha256)


CACHE_POINTER_SCHEMA = "appsec-review/openssf-scorecard-cache-pointer/1"


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    body: bytes
    headers: Mapping[str, str]


class Transport(Protocol):
    def __call__(self, url: str, *, timeout_seconds: int, max_bytes: int) -> HttpResponse: ...


def https_get(url: str, *, timeout_seconds: int, max_bytes: int) -> HttpResponse:
    class _NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
            return None
    request = Request(url, method="GET", headers={"Accept": "application/json",
                                                   "User-Agent": "appsec-review-dependency-intelligence/1"})
    try:
        opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
        with opener.open(request, timeout=timeout_seconds) as response:
            payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise ValueError("response byte bound exceeded")
            return HttpResponse(int(response.status), payload, dict(response.headers.items()))
    except HTTPError as exc:
        payload = exc.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise ValueError("response byte bound exceeded") from exc
        return HttpResponse(int(exc.code), payload, dict(exc.headers.items()))


class ScorecardError(RuntimeError):
    def __init__(self, kind: str, detail: str, *, response: HttpResponse | None = None, url: str | None = None):
        super().__init__(detail)
        self.kind = kind
        self.response = response
        self.url = url


class ScorecardCacheError(RuntimeError):
    """The local cache exists but cannot be trusted."""


def _repository_parts(repository: Mapping[str, str]) -> tuple[str, str, str]:
    host, owner, name = (str(repository.get(key, "")) for key in ("host", "owner", "name"))
    if not host or not owner or not name or any("/" in value or ".." in value for value in (host, owner, name)):
        raise ScorecardError("unsupported_host", "repository identity is invalid")
    return host.lower(), owner, name


def repository_cache_key(repository: Mapping[str, str]) -> str:
    """Return a stable forge/repository key without placing untrusted names in paths."""
    host, owner, name = _repository_parts(repository)
    return hashlib.sha256(f"{host}/{owner.casefold()}/{name.casefold()}".encode()).hexdigest()


class ScorecardCache:
    """Freshness-bounded, content-addressed cache for exact Scorecard response bytes."""

    def __init__(self, root: Path, *, max_age_seconds: int, max_response_bytes: int,
                 lock_timeout_seconds: int = 5,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        if not all(type(value) is int and value > 0 for value in
                   (max_age_seconds, max_response_bytes, lock_timeout_seconds)):
            raise ValueError("Scorecard cache bounds must be positive integers")
        self.root = Path(root)
        self.max_age_seconds = max_age_seconds
        self.max_response_bytes = max_response_bytes
        self.lock_timeout_seconds = lock_timeout_seconds
        self.clock = clock

    def _pointer_path(self, key: str) -> Path:
        return self.root / "entries" / f"{key}.json"

    def load(self, repository: Mapping[str, str]) -> tuple[bytes | None, dict[str, Any]]:
        key = repository_cache_key(repository)
        pointer_path = self._pointer_path(key)
        if not pointer_path.is_file():
            return None, {"status": "miss", "repository_key": key}
        try:
            if pointer_path.is_symlink() or pointer_path.stat().st_size > 65536:
                raise ValueError("cache pointer is unsafe or exceeds its byte bound")
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            if pointer.get("schema") != CACHE_POINTER_SCHEMA or pointer.get("repository_key") != key:
                raise ValueError("pointer schema or repository key mismatch")
            fetched_at = datetime.fromisoformat(str(pointer["fetched_at"]).replace("Z", "+00:00"))
            if fetched_at.tzinfo is None:
                raise ValueError("cache timestamp has no timezone")
            age = (self.clock().astimezone(timezone.utc) - fetched_at.astimezone(timezone.utc)).total_seconds()
            if age < -300:
                raise ValueError("cache timestamp is in the future")
            if age > self.max_age_seconds:
                return None, {"status": "stale", "repository_key": key,
                              "fetched_at": pointer["fetched_at"], "age_seconds": int(age)}
            blob = pointer.get("response")
            if not isinstance(blob, Mapping):
                raise ValueError("cache response identity is missing")
            path = (self.root / str(blob.get("path", ""))).resolve()
            root = self.root.resolve()
            if root not in path.parents or not path.is_file() or path.is_symlink():
                raise ValueError("cache blob is missing or outside the cache")
            if path.stat().st_size != blob.get("size_bytes") or path.stat().st_size > self.max_response_bytes:
                raise ValueError("cache blob size mismatch")
            if file_sha256(path) != blob.get("sha256"):
                raise ValueError("cache blob hash mismatch")
            return path.read_bytes(), {"status": "hit", "repository_key": key,
                                       "fetched_at": pointer["fetched_at"], "age_seconds": max(0, int(age)),
                                       "response_sha256": blob["sha256"]}
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ScorecardCacheError(f"invalid Scorecard cache entry: {type(exc).__name__}") from exc

    def store(self, repository: Mapping[str, str], payload: bytes) -> dict[str, Any]:
        if len(payload) > self.max_response_bytes:
            raise ScorecardCacheError("Scorecard response exceeds cache byte bound")
        key = repository_cache_key(repository)
        digest = hashlib.sha256(payload).hexdigest()
        blob_path = self.root / "blobs" / f"sha256-{digest}.json"
        fetched_at = self.clock().astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        try:
            with bounded_file_lock(self.root / "locks" / f"{key}.lock", self.lock_timeout_seconds):
                if blob_path.is_file():
                    if blob_path.is_symlink() or file_sha256(blob_path) != digest:
                        raise ScorecardCacheError("content-addressed Scorecard cache blob mismatch")
                else:
                    atomic_bytes(blob_path, payload)
                pointer = {"schema": CACHE_POINTER_SCHEMA, "repository_key": key,
                           "repository": {field: str(repository[field]) for field in ("host", "owner", "name")},
                           "fetched_at": fetched_at,
                           "response": {"path": blob_path.relative_to(self.root).as_posix(),
                                        "sha256": digest, "size_bytes": len(payload)}}
                atomic_json(self._pointer_path(key), pointer)
        except LockUnavailable as exc:
            raise ScorecardCacheError("Scorecard cache writer lock timed out") from exc
        return {"status": "refresh", "repository_key": key, "fetched_at": fetched_at,
                "age_seconds": 0, "response_sha256": digest}


class ScorecardClient:
    def __init__(self, *, base_url: str, allowed_hosts: Sequence[str], max_requests: int,
                 max_response_bytes: int, timeout_seconds: int, retries: int,
                 transport: Transport = https_get, sleeper: Callable[[float], None] = time.sleep):
        parsed = urlparse(base_url)
        hosts = {str(item).lower() for item in allowed_hosts}
        if parsed.scheme != "https" or not parsed.hostname or parsed.hostname.lower() not in hosts:
            raise ValueError("Scorecard base URL must use an allowlisted HTTPS host")
        if parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
            raise ValueError("Scorecard base URL contains unsupported authority or query data")
        if not all(type(value) is int and value >= 0 for value in
                   (max_requests, max_response_bytes, timeout_seconds, retries)):
            raise ValueError("Scorecard bounds must be non-negative integers")
        if not max_requests or not max_response_bytes or not timeout_seconds or retries > 5:
            raise ValueError("Scorecard request, byte, timeout and retry bounds are invalid")
        self.base_url = base_url.rstrip("/")
        self.max_requests, self.max_response_bytes = max_requests, max_response_bytes
        self.timeout_seconds, self.retries = timeout_seconds, retries
        self.transport, self.sleeper = transport, sleeper
        self.requests = 0

    def fetch(self, repository: Mapping[str, str]) -> tuple[dict[str, Any], bytes]:
        if self.requests >= self.max_requests:
            raise ScorecardError("bounds", "Scorecard request bound exhausted")
        host, owner, name = _repository_parts(repository)
        url = f"{self.base_url}/projects/{quote(host, safe='')}/{quote(owner, safe='')}/{quote(name, safe='')}"
        response: HttpResponse | None = None
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            if self.requests >= self.max_requests:
                raise ScorecardError("bounds", "Scorecard request bound exhausted")
            self.requests += 1
            try:
                response = self.transport(url, timeout_seconds=self.timeout_seconds,
                                          max_bytes=self.max_response_bytes)
            except (OSError, URLError, socket.timeout, TimeoutError, ValueError) as exc:
                last_error = exc
                if attempt < self.retries:
                    self.sleeper(min(1.0, 0.1 * (2 ** attempt)))
                    continue
                kind = "bounds" if "bound" in str(exc).lower() else "request_failure"
                raise ScorecardError(kind, f"Scorecard request failed: {type(exc).__name__}") from exc
            if response.status == 429:
                if attempt < self.retries:
                    self.sleeper(min(1.0, 0.1 * (2 ** attempt)))
                    continue
                raise ScorecardError("rate_limit", "Scorecard API rate limited the request",
                                     response=response, url=url)
            if response.status == 404:
                raise ScorecardError("not_found", "no Scorecard exists for the repository",
                                     response=response, url=url)
            if response.status < 200 or response.status >= 300:
                if response.status >= 500 and attempt < self.retries:
                    self.sleeper(min(1.0, 0.1 * (2 ** attempt)))
                    continue
                raise ScorecardError("request_failure", f"Scorecard API returned HTTP {response.status}",
                                     response=response, url=url)
            break
        if response is None:  # pragma: no cover - loop guarantees response or exception
            raise ScorecardError("request_failure", str(last_error or "Scorecard request failed"))
        return self.normalize(repository, response.body, url=url, response=response)

    def normalize(self, repository: Mapping[str, str], payload: bytes, *, url: str | None = None,
                  response: HttpResponse | None = None) -> tuple[dict[str, Any], bytes]:
        """Validate and normalize exact response bytes from HTTP or the verified cache."""
        host, owner, name = _repository_parts(repository)
        request_url = url or \
            f"{self.base_url}/projects/{quote(host, safe='')}/{quote(owner, safe='')}/{quote(name, safe='')}"
        if len(payload) > self.max_response_bytes:
            raise ScorecardError("bounds", "Scorecard response byte bound exceeded")
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ScorecardError("malformed_response", "Scorecard response is not UTF-8 JSON",
                                 response=response, url=request_url) from exc
        if not isinstance(document, Mapping):
            raise ScorecardError("malformed_response", "Scorecard response is not an object",
                                 response=response, url=request_url)
        score = document.get("score")
        checks = document.get("checks")
        if (not isinstance(score, (int, float)) or isinstance(score, bool) or not 0 <= score <= 10 or
                not isinstance(checks, list)):
            raise ScorecardError("malformed_response", "Scorecard response lacks a bounded score/check list",
                                 response=response, url=request_url)
        normalized = {
            "schema": SCORECARD_RECORD_SCHEMA, "repository": dict(repository), "request_url": request_url,
            "score": float(score), "date": document.get("date"), "commit": document.get("commit"),
            "check_count": len(checks),
            "checks": [{"name": str(item.get("name", ""))[:256],
                        "score": item.get("score"), "reason": str(item.get("reason", ""))[:2048]}
                       for item in checks[:1000] if isinstance(item, Mapping)],
            "context_only": True, "security_finding": False,
        }
        if len(checks) > 1000:
            raise ScorecardError("bounds", "Scorecard check count bound exceeded",
                                 response=response, url=request_url)
        return normalized, payload


__all__ = ["HttpResponse", "ScorecardCache", "ScorecardCacheError", "ScorecardClient", "ScorecardError",
           "Transport", "https_get", "repository_cache_key"]
