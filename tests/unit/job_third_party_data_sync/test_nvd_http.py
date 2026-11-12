from __future__ import annotations

from email.message import Message
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
from pathlib import Path
import threading
import urllib.error

import pytest

from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync import feed
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.models import NvdSettings


class Response(io.BytesIO):
    def __init__(self, body: bytes, *, status: int = 200, headers: dict[str, str] | None = None,
                 interrupt: bool = False):
        super().__init__(body)
        self.status = status
        self.headers = {"Content-Length": str(len(body)), "ETag": '"fixture"', **(headers or {})}
        self.interrupt = interrupt

    def read(self, size: int = -1) -> bytes:
        if self.interrupt and self.tell():
            raise TimeoutError("connection stalled")
        return super().read(size)


def responses(monkeypatch, values):
    pending = iter(values)
    requests = []

    def open_url(request, *, timeout):
        requests.append(request)
        value = next(pending)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(feed.urllib.request, "urlopen", open_url)
    return requests


def client(**kwargs) -> feed.HttpNvdClient:
    return feed.HttpNvdClient(pause=lambda _: None, **kwargs)


@pytest.mark.parametrize("interrupt", [False, True])
def test_download_resumes_truncated_or_stalled_response(monkeypatch, tmp_path: Path, interrupt: bool):
    requests = responses(monkeypatch, [
        Response(b"abc", headers={"Content-Length": "6"}, interrupt=interrupt),
        Response(b"def", status=206, headers={"Content-Range": "bytes 3-5/6"}),
    ])
    target = tmp_path / "feed.gz"
    assert client().download("https://nvd.example/feed.gz", target) == 6
    assert target.read_bytes() == b"abcdef"
    assert requests[1].get_header("Range") == "bytes=3-"
    assert requests[1].get_header("If-range") == '"fixture"'
    assert requests[1].get_header("Accept-encoding") == "identity"
    assert not target.with_suffix(".gz.partial").exists()


def test_download_restarts_when_server_ignores_range(monkeypatch, tmp_path: Path):
    requests = responses(monkeypatch, [
        Response(b"abc", headers={"Content-Length": "6"}),
        Response(b"abcdef", headers={"ETag": '"new"'}),
    ])
    target = tmp_path / "feed.gz"
    assert client().download("https://nvd.example/feed.gz", target) == 6
    assert requests[1].get_header("Range") == "bytes=3-"
    assert target.read_bytes() == b"abcdef"


def test_download_without_validator_restarts_instead_of_appending(monkeypatch, tmp_path: Path):
    requests = responses(monkeypatch, [
        Response(b"abc", headers={"Content-Length": "6", "ETag": ""}),
        Response(b"abcdef"),
    ])
    target = tmp_path / "feed.gz"
    assert client().download("https://nvd.example/feed.gz", target) == 6
    assert requests[1].get_header("Range") is None
    assert target.read_bytes() == b"abcdef"


def test_weak_etag_uses_last_modified_for_if_range(monkeypatch, tmp_path: Path):
    modified = "Wed, 21 Oct 2026 07:15:13 GMT"
    requests = responses(monkeypatch, [
        Response(b"abc", headers={"Content-Length": "6", "ETag": 'W/"fixture"',
                                  "Last-Modified": modified}),
        Response(b"def", status=206, headers={"Content-Range": "bytes 3-5/6",
                                            "ETag": 'W/"fixture"', "Last-Modified": modified}),
    ])
    assert client().download("https://nvd.example/feed.gz", tmp_path / "feed.gz") == 6
    assert requests[1].get_header("If-range") == modified


@pytest.mark.parametrize("headers", [
    {"Content-Range": "bytes 2-4/6"},
    {"Content-Range": "bytes 3-5/7"},
    {"Content-Range": "bytes 3-5/6", "ETag": '"changed"'},
    {"Content-Range": "bytes 3-5/6", "Content-Length": "4"},
    {"Content-Range": "invalid"},
])
def test_download_rejects_changed_identity_or_invalid_range(monkeypatch, tmp_path: Path, headers):
    requests = responses(monkeypatch, [
        Response(b"abc", headers={"Content-Length": "6"}),
        Response(b"def", status=206, headers=headers),
    ])
    target = tmp_path / "feed.gz"
    with pytest.raises(ValueError, match="partial response|identity or byte range"):
        client().download("https://nvd.example/feed.gz", target)
    assert len(requests) == 2
    assert not target.exists()
    assert target.with_suffix(".gz.partial").read_bytes() == b"abc"


def test_retry_budget_exhaustion_never_completes_partial_download(monkeypatch, tmp_path: Path):
    requests = responses(monkeypatch, [
        Response(b"a", headers={"Content-Length": "6"}),
        Response(b"b", status=206, headers={"Content-Length": "5", "Content-Range": "bytes 1-5/6"}),
    ])
    target = tmp_path / "feed.gz"
    with pytest.raises(http.client.IncompleteRead):
        client(max_attempts=2).download("https://nvd.example/feed.gz", target)
    assert len(requests) == 2
    assert not target.exists()
    assert target.with_suffix(".gz.partial").read_bytes() == b"ab"


def test_new_invocation_does_not_trust_old_partial_bytes(monkeypatch, tmp_path: Path, caplog):
    requests = responses(monkeypatch, [Response(b"abcdef")])
    target = tmp_path / "feed.gz"
    target.with_suffix(".gz.partial").write_bytes(b"unverified")
    assert client().download("https://nvd.example/feed.gz", target) == 6
    assert requests[0].get_header("Range") is None
    assert "Discarding an unverified NVD partial" in caplog.text


@pytest.mark.parametrize("declared", [True, False])
def test_download_enforces_exact_byte_bound(monkeypatch, tmp_path: Path, declared: bool):
    response = Response(b"1234567")
    if not declared:
        response.headers.pop("Content-Length")
    requests = responses(monkeypatch, [response])
    target = tmp_path / "feed.gz"
    with pytest.raises(ValueError, match="byte bound"):
        client(max_download_bytes=6).download("https://nvd.example/feed.gz", target)
    assert len(requests) == 1
    assert not target.exists()
    partial = target.with_suffix(".gz.partial")
    assert not partial.exists() or partial.stat().st_size <= 6


def test_exact_byte_bound_is_accepted(monkeypatch, tmp_path: Path):
    responses(monkeypatch, [Response(b"123456")])
    assert client(max_download_bytes=6).download("https://nvd.example/feed.gz", tmp_path / "feed.gz") == 6


def test_metadata_truncation_is_retried(monkeypatch):
    requests = responses(monkeypatch, [
        Response(b"abc", headers={"Content-Length": "6"}), Response(b"abcdef"),
    ])
    assert client().get_bytes("https://nvd.example/feed.meta") == b"abcdef"
    assert len(requests) == 2


def test_metadata_size_detects_truncation_without_content_length(monkeypatch, tmp_path: Path):
    first = Response(b"abc")
    first.headers.pop("Content-Length")
    requests = responses(monkeypatch, [
        first, Response(b"def", status=206, headers={"Content-Range": "bytes 3-5/6"}),
    ])
    target = tmp_path / "feed.gz"
    assert client().download("https://nvd.example/feed.gz", target, expected_size=6) == 6
    assert requests[1].get_header("Range") == "bytes=3-"
    assert target.read_bytes() == b"abcdef"


def test_http_length_cannot_override_official_metadata(monkeypatch, tmp_path: Path):
    responses(monkeypatch, [Response(b"abc")])
    with pytest.raises(ValueError, match="disagrees with feed metadata"):
        client().download("https://nvd.example/feed.gz", tmp_path / "feed.gz", expected_size=6)
    assert not (tmp_path / "feed.gz").exists()


def test_metadata_size_bounds_downloads_without_content_length(monkeypatch, tmp_path: Path):
    response = Response(b"1234567")
    response.headers.pop("Content-Length")
    responses(monkeypatch, [response])
    target = tmp_path / "feed.gz"
    with pytest.raises(ValueError, match="expected total length"):
        client().download("https://nvd.example/feed.gz", target, expected_size=6)
    assert not target.exists()
    assert target.with_suffix(".gz.partial").stat().st_size == 0


def test_retry_after_is_respected_and_nonretryable_http_errors_fail(monkeypatch):
    headers = Message()
    headers["Retry-After"] = "3"
    error = urllib.error.HTTPError("https://nvd.example/feed.meta", 429, "busy", headers, None)
    requests = responses(monkeypatch, [error, Response(b"ok")])
    delays = []
    transport = feed.HttpNvdClient(retry_delay_seconds=1, pause=delays.append)
    assert transport.get_bytes("https://nvd.example/feed.meta") == b"ok"
    assert delays == [3] and len(requests) == 2
    responses(monkeypatch, [
        urllib.error.HTTPError("https://nvd.example/feed.meta", 403, "forbidden", Message(), None),
    ])
    with pytest.raises(urllib.error.HTTPError):
        transport.get_bytes("https://nvd.example/feed.meta")
    assert delays == [3]


def test_retry_after_above_budget_is_not_silently_shortened(monkeypatch):
    headers = Message()
    headers["Retry-After"] = "600"
    error = urllib.error.HTTPError("https://nvd.example/feed.meta", 429, "busy", headers, None)
    responses(monkeypatch, [error])
    delays = []
    with pytest.raises(urllib.error.HTTPError):
        feed.HttpNvdClient(pause=delays.append).get_bytes("https://nvd.example/feed.meta")
    assert delays == []


@pytest.mark.parametrize("setting,value", [
    ("max_attempts", 0), ("max_attempts", 11),
    ("download_timeout_seconds", 0), ("request_timeout_seconds", float("inf")),
    ("retry_delay_seconds", -1), ("retry_delay_seconds", float("nan")),
    ("retry_delay_seconds", 61), ("retry_max_delay_seconds", 3601),
])
def test_retry_settings_are_bounded(tmp_path: Path, setting, value):
    with pytest.raises(ValueError, match="NVD"):
        NvdSettings.from_mapping(tmp_path, {"feed_root": "data/feeds/nvd", setting: value})


def test_real_http_truncation_resumes_from_the_written_offset(tmp_path: Path):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.headers.get("Range"), self.headers.get("If-Range")))
            if len(requests) == 1:
                self.send_response(200)
                self.send_header("Content-Length", "6")
                body = b"abc"
            else:
                self.send_response(206)
                self.send_header("Content-Length", "3")
                self.send_header("Content-Range", "bytes 3-5/6")
                body = b"def"
            self.send_header("ETag", '"fixture"')
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = tmp_path / "feed.gz"
            assert client().download(f"http://127.0.0.1:{server.server_port}/feed.gz", target) == 6
            assert target.read_bytes() == b"abcdef"
            assert requests == [(None, None), ("bytes=3-", '"fixture"')]
        finally:
            server.shutdown()
            thread.join(timeout=5)
