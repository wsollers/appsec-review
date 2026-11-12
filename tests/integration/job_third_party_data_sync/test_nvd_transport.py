"""Real NVD HTTP retry/range behavior, gzip parsing and bootstrap/incremental publication."""
from __future__ import annotations

from datetime import timedelta
import gzip
import hashlib
import json
import sqlite3
from urllib.parse import parse_qs, urlsplit

import pytest

from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync import feed
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.models import NvdSettings
from tests.fixtures.reference_feeds import FIXED_NOW, nvd_vulnerability

from .support import Response, https_server


def bootstrap_routes():
    raw = json.dumps({"format": "NVD_CVE", "version": "2.0",
                      "vulnerabilities": [nvd_vulnerability("CVE-2026-0001")]}).encode()
    compressed = gzip.compress(raw, mtime=0)
    metadata = (f"lastModifiedDate:2026-10-08T00:00:00.000Z\nsize:{len(raw)}\n"
                f"gzSize:{len(compressed)}\nsha256:{hashlib.sha256(raw).hexdigest()}\n").encode()
    return {
        "/nvdcve-2.0-2026.meta": Response(metadata),
        "/nvdcve-2.0-2026.json.gz": Response(compressed),
    }


def publisher(root, base, monkeypatch):
    monkeypatch.setattr(feed, "FEED_BASE", base)
    monkeypatch.setattr(feed, "API_BASE", base + "/api")
    settings = NvdSettings.from_mapping(root, {
        "feed_root": "feeds/nvd", "first_year": 2026, "page_size": 1,
        "request_timeout_seconds": 2, "download_timeout_seconds": 2,
        "max_attempts": 2, "retry_delay_seconds": 0,
        "max_download_bytes": 8192, "max_api_response_bytes": 8192,
        "request_delay_with_key_seconds": 0, "request_delay_without_key_seconds": 0,
    })
    return feed.NvdPublisher(settings, clock=lambda: FIXED_NOW)


def test_bootstrap_and_paginated_incremental_https_build_real_index(tmp_path, monkeypatch):
    routes = bootstrap_routes()

    def page(handler):
        index = int(parse_qs(urlsplit(handler.path).query)["startIndex"][0])
        assert index in (0, 1)
        record = nvd_vulnerability(f"CVE-2026-{index + 1:04d}", modified="2026-10-12T00:30:00.000",
                                   status="Rejected" if index == 0 else "Analyzed")
        return Response(json.dumps({"format": "NVD_CVE", "version": "2.0", "startIndex": index,
                                    "resultsPerPage": 1, "totalResults": 2,
                                    "vulnerabilities": [record]}).encode())

    routes["/api"] = page
    with https_server(routes, monkeypatch) as (base, requests):
        sync = publisher(tmp_path, base, monkeypatch)
        first = sync.sync("bootstrap")
        sync.clock = lambda: FIXED_NOW + timedelta(hours=1)
        second = sync.sync("incremental")
        verified = sync.verify()
        assert first["snapshot_id"] != second["snapshot_id"]
        assert verified["chain_length"] == 2 and verified["index"]["record_count"] == 2
        directory = sync.root / "snapshots" / second["snapshot_id"]
        manifest = json.loads((directory / "manifest.json").read_bytes())
        assert manifest["schema"] == feed.MANIFEST_SCHEMA
        assert manifest["mode"] == "incremental" and manifest["parent_snapshot_id"] == first["snapshot_id"]
        with sqlite3.connect(f"file:{directory}/index/nvd.sqlite?mode=ro", uri=True) as db:
            assert db.execute("SELECT cve_id, status FROM cve ORDER BY cve_id").fetchall() == [
                ("CVE-2026-0001", "Rejected"), ("CVE-2026-0002", "Analyzed")]
        assert len(requests) == 4
        assert all(tls.startswith("TLS") for _, _, tls in requests)
        assert all(headers["User-Agent"] == feed.USER_AGENT for _, headers, _ in requests)
        assert directory.is_relative_to(tmp_path)


def test_real_truncated_gzip_resumes_at_verified_offset(tmp_path, monkeypatch):
    routes = bootstrap_routes()
    payload = routes["/nvdcve-2.0-2026.json.gz"].body
    offset = len(payload) // 2

    def interrupted(handler):
        if handler.headers.get("Range") is None:
            return Response(payload[:offset], headers=(("Content-Length", str(len(payload))), ("ETag", '"nvd"')))
        assert handler.headers["Range"] == f"bytes={offset}-"
        assert handler.headers["If-Range"] == '"nvd"'
        return Response(payload[offset:], status=206, headers=(
            ("Content-Range", f"bytes {offset}-{len(payload) - 1}/{len(payload)}"), ("ETag", '"nvd"'),
        ))

    routes["/nvdcve-2.0-2026.json.gz"] = interrupted
    with https_server(routes, monkeypatch) as (base, requests):
        sync = publisher(tmp_path, base, monkeypatch)
        sync.sync("resumed")
        assert sync.verify()["index"]["record_count"] == 1
        cached = sync.root / "downloads/nvdcve-2.0-2026.json.gz"
        assert cached.read_bytes() == payload and not cached.with_suffix(".gz.partial").exists()
        assert len(requests) == 3


def test_real_invalid_api_payload_keeps_last_good_snapshot_and_failure_receipt(tmp_path, monkeypatch):
    routes = {**bootstrap_routes(), "/api": Response(b"not json")}
    with https_server(routes, monkeypatch) as (base, requests):
        sync = publisher(tmp_path, base, monkeypatch)
        first = sync.sync("good")
        pointer = sync.root / "current.json"
        before = pointer.read_bytes()
        sync.clock = lambda: FIXED_NOW + timedelta(hours=1)
        with pytest.raises(json.JSONDecodeError):
            sync.sync("malformed")
        assert pointer.read_bytes() == before
        assert sync.verify()["snapshot_id"] == first["snapshot_id"]
        attempts = [json.loads(path.read_bytes()) for path in sorted(sync.root.glob("staging/*/attempt.json"))]
        assert any(record["status"] == "FAILED" for record in attempts)
        assert len(requests) == 3
