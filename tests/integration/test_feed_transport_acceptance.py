"""Loopback TLS through the real KEV downloader, normalizer and atomic publisher.

The certificate is test-only. No public feed, database-building tool or daemon is used.
Both invalid-JSON and valid-JSON prefix truncation must fail transport length checking before
normalization or publication. Headerless streaming remains bounded by the configured byte limit.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import threading
import time
import urllib.error

import pytest

from appsec_review.acceptance.lanes import LaneWorkspace
from appsec_review.jobs.job_third_party_data_sync.publication import verify_current
from appsec_review.jobs.job_third_party_data_sync.steps.kev_sync import feed
from appsec_review.observability import write_run_metrics
from tests.fixtures.reference_feeds import kev_document, kev_entry


ROOT = Path(__file__).resolve().parents[2]
TLS = ROOT / "tests" / "fixtures" / "acceptance_feeds"
PAYLOAD = json.dumps(kev_document([kev_entry("CVE-2026-0001")]), sort_keys=True).encode()
VALID_JSON_PREFIX = json.dumps(kev_document([]), sort_keys=True).encode()
BYTE_LIMIT = len(PAYLOAD) + 32


@contextmanager
def _https_feed():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append({"path": self.path, "user_agent": self.headers.get("User-Agent"),
                             "tls": self.connection.version()})
            if self.path == "/status":
                self.send_response(503)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = PAYLOAD
            declared = len(body)
            if self.path == "/interrupted":
                body = PAYLOAD[: len(PAYLOAD) // 2]
            elif self.path == "/valid-json-interrupted":
                body = VALID_JSON_PREFIX
                declared = len(body) * 2
            elif self.path.startswith("/oversize"):
                body = b"x" * (BYTE_LIMIT + 1)
                declared = len(body)
            self.send_response(200)
            if self.path not in {"/oversize-stream", "/stream"}:
                self.send_header("Content-Length", str(declared))
            self.send_header("ETag", '"acceptance-kev"')
            self.send_header("Last-Modified", "Tue, 27 Oct 2026 00:00:00 GMT")
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
            if self.path in {"/interrupted", "/valid-json-interrupted"}:
                self.connection.shutdown(socket.SHUT_WR)

        def log_message(self, *_args):
            pass

    class Server(ThreadingHTTPServer):
        daemon_threads = False

        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(2)
            return connection, address

    server = Server(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(TLS / "localhost.crt.pem", TLS / "localhost.test-key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02},
                              name="acceptance-kev-https", daemon=True)
    worker.start()
    try:
        assert worker.is_alive()
        yield f"https://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        assert not worker.is_alive(), "owned HTTPS server did not stop"


def _settings(workspace, url):
    return feed.KevSettings.from_mapping(workspace.root, {
        "feed_root": str(workspace.root / "feeds" / "kev"), "url": url,
        "allowed_hosts": ["127.0.0.1"], "max_source_bytes": BYTE_LIMIT,
        "max_records": 2, "timeout_seconds": 2,
    })


def _cycle(settings, work):
    fetched = feed.fetch(settings, work)
    normalized = feed.normalize(settings, fetched, work)
    feed.publish(settings, fetched, normalized)
    return fetched, feed.verify(settings)


def _complete(workspace, started, **details):
    elapsed = time.monotonic() - started
    workspace.emit("ACCEPTANCE_CASE_COMPLETED", outcome="passed", duration_ms=elapsed * 1000,
                   **details)
    metrics = write_run_metrics(workspace.driver_root)
    assert metrics["schema"] == "appsec-review/run-metrics/6" and metrics["event_count"] > 0
    records = [json.loads(line) for line in
               (workspace.driver_root / "data" / "logs" / "pipeline.jsonl").read_text(
                   encoding="utf-8").splitlines()]
    operations = [row["details"] for row in records if row["event_type"] == "OPERATION_COMPLETED"]
    assert operations and all(row["duration_ms"] > 0 and "resources" in row for row in operations)
    assert elapsed < 15, f"local feed case exceeded 15 seconds: {elapsed:.3f}s; {workspace.root}"


@pytest.mark.parametrize("path", ["/ok", "/stream"], ids=["declared-exact", "stream-exact"])
def test_real_https_fetch_publishes_hash_pinned_tiny_kev(acceptance_workspace, monkeypatch, path):
    workspace = LaneWorkspace.create(acceptance_workspace.root, "feed-tls-success")
    monkeypatch.setenv("SSL_CERT_FILE", str(TLS / "localhost.crt.pem"))
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    started = time.monotonic()
    with workspace.span("acceptance.feed_tls_success"), _https_feed() as (url, requests):
        settings = replace(_settings(workspace, url + path), max_source_bytes=len(PAYLOAD))
        fetched, verified = _cycle(settings, workspace.root / "fetch")
        source = fetched["source"]
        assert source["url"] == settings.url
        assert source["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
        assert source["size_bytes"] == len(PAYLOAD)
        assert source["etag"] == '"acceptance-kev"' and source["last_modified"]
        assert Path(source["path"]).is_relative_to(workspace.root)
        directory = Path(verified["directory"])
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["source"]["sha256"] == source["sha256"]
        assert "reference context" in manifest["limitations"][0]
        with sqlite3.connect(f"file:{(directory / 'index' / 'kev.sqlite').as_posix()}?mode=ro",
                             uri=True) as db:
            assert db.execute("SELECT cve_id FROM kev").fetchall() == [("CVE-2026-0001",)]
        assert len(requests) == 1
        assert requests[0]["path"] == path
        assert requests[0]["user_agent"] == "appsec-review-kev-sync/1"
        assert requests[0]["tls"].startswith("TLS")
        assert verified["record_count"] == 1
    _complete(workspace, started, source_bytes=len(PAYLOAD), tls_requests=len(requests))


@pytest.mark.parametrize(("path", "error", "message"), [
    ("/interrupted", ValueError, "Content-Length mismatch"),
    ("/valid-json-interrupted", ValueError, "Content-Length mismatch"),
    ("/oversize-declared", ValueError, "byte bound"),
    ("/oversize-stream", ValueError, "byte bound"),
    ("/status", urllib.error.HTTPError, "503"),
])
def test_real_https_failure_preserves_last_good_pointer(
        acceptance_workspace, monkeypatch, path, error, message):
    workspace = LaneWorkspace.create(acceptance_workspace.root, "feed-tls-failure")
    monkeypatch.setenv("SSL_CERT_FILE", str(TLS / "localhost.crt.pem"))
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    started = time.monotonic()
    with workspace.span("acceptance.feed_tls_failure"), _https_feed() as (url, requests):
        settings = _settings(workspace, url + "/ok")
        _, accepted = _cycle(settings, workspace.root / "last-good")
        pointer = settings.feed_root / "current.json"
        original = pointer.read_bytes()
        snapshots = sorted((settings.feed_root / "snapshots").iterdir())
        try:
            with pytest.raises(error, match=message) as rejected:
                _cycle(replace(settings, url=url + path), workspace.root / "failed-fetch")
        finally:
            if path == "/valid-json-interrupted":
                partial = workspace.root / "failed-fetch" / "known_exploited_vulnerabilities.json"
                workspace.emit("ACCEPTANCE_CONTENT_LENGTH_CHECK",
                               declared_bytes=len(VALID_JSON_PREFIX) * 2,
                               received_bytes=partial.stat().st_size if partial.is_file() else None,
                               pointer_unchanged=pointer.read_bytes() == original)
        if path == "/interrupted":
            partial = workspace.root / "failed-fetch" / "known_exploited_vulnerabilities.json"
            assert partial.read_bytes() == PAYLOAD[: len(PAYLOAD) // 2]
        elif path == "/valid-json-interrupted":
            assert partial.read_bytes() == VALID_JSON_PREFIX
            assert str(rejected.value) == (
                f"download Content-Length mismatch: expected {len(VALID_JSON_PREFIX) * 2} bytes, "
                f"received {len(VALID_JSON_PREFIX)}: {url}{path}")
        assert pointer.read_bytes() == original
        assert sorted((settings.feed_root / "snapshots").iterdir()) == snapshots
        assert verify_current(settings.feed_root, "kev")["manifest_sha256"] == accepted["manifest_sha256"]
        assert [row["path"] for row in requests] == ["/ok", path]
        assert all(row["tls"].startswith("TLS") for row in requests)
        workspace.emit("ACCEPTANCE_FAILURE_REJECTED", case=path, expected_error=error.__name__,
                       rejection_stage="download",
                       publication_pointer_sha256=hashlib.sha256(original).hexdigest())
    _complete(workspace, started, failure_case=path, tls_requests=len(requests))
