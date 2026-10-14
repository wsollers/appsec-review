"""Bounded OpenSSF Scorecard API client with an injectable HTTPS transport."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import json
import socket
import ssl
import time
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from appsec_review.jobs.engineering_contracts import SCORECARD_RECORD_SCHEMA


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
        host, owner, name = (str(repository.get(key, "")) for key in ("host", "owner", "name"))
        if not host or not owner or not name or any("/" in value or ".." in value for value in (host, owner, name)):
            raise ScorecardError("unsupported_host", "repository identity is invalid")
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
        if len(response.body) > self.max_response_bytes:
            raise ScorecardError("bounds", "Scorecard response byte bound exceeded")
        try:
            document = json.loads(response.body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ScorecardError("malformed_response", "Scorecard response is not UTF-8 JSON",
                                 response=response, url=url) from exc
        if not isinstance(document, Mapping):
            raise ScorecardError("malformed_response", "Scorecard response is not an object",
                                 response=response, url=url)
        score = document.get("score")
        checks = document.get("checks")
        if (not isinstance(score, (int, float)) or isinstance(score, bool) or not 0 <= score <= 10 or
                not isinstance(checks, list)):
            raise ScorecardError("malformed_response", "Scorecard response lacks a bounded score/check list",
                                 response=response, url=url)
        normalized = {
            "schema": SCORECARD_RECORD_SCHEMA, "repository": dict(repository), "request_url": url,
            "score": float(score), "date": document.get("date"), "commit": document.get("commit"),
            "check_count": len(checks),
            "checks": [{"name": str(item.get("name", ""))[:256],
                        "score": item.get("score"), "reason": str(item.get("reason", ""))[:2048]}
                       for item in checks[:1000] if isinstance(item, Mapping)],
            "context_only": True, "security_finding": False,
        }
        if len(checks) > 1000:
            raise ScorecardError("bounds", "Scorecard check count bound exceeded", response=response, url=url)
        return normalized, response.body


__all__ = ["HttpResponse", "ScorecardClient", "ScorecardError", "Transport", "https_get"]
