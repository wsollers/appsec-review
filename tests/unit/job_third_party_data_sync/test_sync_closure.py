"""Offline regressions for the remaining audited synchronization cases."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import gzip
import io
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import shutil
import threading
import tomllib
from types import SimpleNamespace
import urllib.parse
import urllib.request
import zipfile

import pytest

from appsec_review.jobs.job_third_party_data_sync import job, publication
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync import feed as nvd
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.models import NvdSettings
from appsec_review.jobs.job_third_party_data_sync.steps.osv_sync import feed as osv
from appsec_review.jobs.job_third_party_data_sync.steps.mitre_sync import feed as mitre
from appsec_review.jobs.job_third_party_data_sync.steps.cve_bin_tool_db_build import database as cve
from tests.fixtures.reference_feeds import cwe_xml, kev_document, kev_entry, kev_settings
from tests.unit.job_third_party_data_sync.test_nvd_sync_job import FakeClient, vulnerability
from tests.unit.job_third_party_data_sync.test_osv_feed import _settings, _fetched, _record
from tests.unit.job_third_party_data_sync.test_cve_bin_tool_database import write_databases


@pytest.fixture(autouse=True)
def private_offline_only(tmp_path, monkeypatch):
    from appsec_review.storage import feed_provenance

    original = feed_provenance.check_root

    def check(root, *args, **kwargs):
        assert Path(root).resolve().is_relative_to(tmp_path.resolve()), "host feed store forbidden"
        return original(root, *args, **kwargs)

    def forbidden(*args, **kwargs):
        raise AssertionError("network/native/provider operation forbidden")

    monkeypatch.setattr(feed_provenance, "check_root", check)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


NOW = datetime(2026, 10, 8, 2, tzinfo=timezone.utc)


def _publisher(tmp_path, client=None, **settings):
    client = client or FakeClient(json.dumps({
        "format": "NVD_CVE", "version": "2.0",
        "vulnerabilities": [vulnerability("CVE-2026-1000")],
    }).encode())
    return nvd.NvdPublisher(
        NvdSettings.from_mapping(tmp_path, {
            "feed_root": str(tmp_path / "nvd"), "first_year": 2026,
            "request_delay_with_key_seconds": 0, "request_delay_without_key_seconds": 0, **settings,
        }), client=client, clock=lambda: NOW, pause=lambda _: None)


def test_bootstrap_watermark_covers_snapshot_to_clock_gap(tmp_path):
    class Client(FakeClient):
        starts = []

        def get_bytes(self, url, api_key=None):
            if url.endswith(".meta"):
                return super().get_bytes(url, api_key)
            start = nvd.parse_time(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["lastModStartDate"][0])
            self.starts.append(start)
            records = [vulnerability("CVE-2026-1001")] if start <= NOW - timedelta(hours=1) else []
            return json.dumps({"format": "NVD_CVE", "version": "2.0", "startIndex": 0,
                               "resultsPerPage": len(records), "totalResults": len(records),
                               "vulnerabilities": records}).encode()

    client = Client(json.dumps({"format": "NVD_CVE", "version": "2.0",
                               "vulnerabilities": [vulnerability("CVE-2026-1000")]}).encode())
    publisher = _publisher(tmp_path, client)
    first = publisher.sync("bootstrap")
    assert nvd.parse_time(first["cursor"]) == NOW - timedelta(hours=2)
    publisher.clock = lambda: NOW + timedelta(hours=1)
    publisher.sync("incremental")
    assert client.starts == [NOW - timedelta(hours=2)]
    receipt = publisher.verify()
    with sqlite3.connect(publisher.root / "snapshots" / receipt["snapshot_id"] / "index/nvd.sqlite") as db:
        assert db.execute("SELECT cve_id FROM cve ORDER BY cve_id").fetchall() == [
            ("CVE-2026-1000",), ("CVE-2026-1001",)]


@pytest.mark.parametrize("defect", [
    "short", "oversized", "total-drift", "duplicate-page", "boolean", "nonterminal-short",
], ids=["short", "oversized", "total-drift", "duplicate-page", "boolean", "nonterminal-short"])
def test_bad_api_window_preserves_admitted_pointer(tmp_path, defect):
    publisher = _publisher(tmp_path, page_size=1)
    publisher.sync("bootstrap")
    before = (publisher.root / "current.json").read_bytes()
    pages = [
        {"format": "NVD_CVE", "version": "2.0", "startIndex": 0, "resultsPerPage": 1,
         "totalResults": 2, "vulnerabilities": [vulnerability("CVE-2026-2000")]},
        {"format": "NVD_CVE", "version": "2.0", "startIndex": 1, "resultsPerPage": 1,
         "totalResults": 2, "vulnerabilities": [vulnerability("CVE-2026-2001")]},
    ]
    if defect == "short":
        pages[0].update(totalResults=1, vulnerabilities=[])
    elif defect == "oversized":
        pages[0].update(resultsPerPage=2, vulnerabilities=[
            vulnerability("CVE-2026-2000"), vulnerability("CVE-2026-2001")])
    elif defect == "total-drift":
        pages[1]["totalResults"] = 1
    elif defect == "duplicate-page":
        pages[1]["vulnerabilities"] = pages[0]["vulnerabilities"]
    elif defect == "boolean":
        pages[0].update(totalResults=True, resultsPerPage=True)
    else:
        publisher = _publisher(tmp_path, page_size=2)
    iterator = iter(pages)
    publisher.client = SimpleNamespace(get_bytes=lambda *args: json.dumps(next(iterator)).encode())
    publisher.clock = lambda: NOW + timedelta(hours=1)
    with pytest.raises(ValueError, match="NVD API"):
        publisher.sync("invalid-window")
    assert (publisher.root / "current.json").read_bytes() == before
    assert publisher.verify()["index"]["record_count"] == 1


@pytest.mark.parametrize("payload", [
    b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[{}]',
    b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[{} {}]}',
    b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[{},]}',
    b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[]} trailing',
    b'{"format":"other","version":"2.0","vulnerabilities":[]}',
    b'{"version":"2.0","vulnerabilities":[]}',
    b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[],"vulnerabilities":[]}',
    b'{"format":"NVD_CVE","version":"2.0","totalResults":1,"vulnerabilities":[]}',
], ids=["open-envelope", "missing-comma", "trailing-comma", "trailing-data",
        "format", "missing-format", "duplicate-field", "wrong-count"])
def test_year_parser_rejects_incomplete_documents(payload):
    with pytest.raises(ValueError):
        list(nvd.iter_vulnerabilities(io.BytesIO(payload)))


def test_year_parser_validates_suffix_across_small_reads():
    payload = json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2026-1234"}}],
                          "padding": "x" * 65530, "format": "NVD_CVE",
                          "version": "2.0", "totalResults": 1}).encode()

    class Chunks(io.BytesIO):
        def read1(self, n=-1):
            return super().read1(min(n, 3))

    assert list(nvd.iter_vulnerabilities(Chunks(payload))) == [{"cve": {"id": "CVE-2026-1234"}}]


@pytest.mark.parametrize("order", ["old-first", "new-first"], ids=["old-first", "new-first"])
def test_osv_newest_revision_replaces_all_associations(tmp_path, order):
    old = _record("GHSA-one", ("PyPI", "old"), modified="2026-01-01T00:00:00Z",
                  aliases=("CVE-2026-0001",))
    new = _record("GHSA-one", ("npm", "new"), modified="2026-02-01T00:00:00Z",
                  aliases=("CVE-2026-0002",), withdrawn="2026-02-01T00:00:00Z")
    records = [old, new] if order == "old-first" else [new, old]
    fetched = _fetched(tmp_path, {name: {"a.json": record} for name, record in zip(("PyPI", "npm"), records)})
    settings = _settings(tmp_path)
    result = osv.index(settings, fetched, tmp_path / "index")
    pointer = osv.publish(settings, fetched, result)
    assert osv.verify(settings)["snapshot_id"] == pointer["snapshot_id"]
    with sqlite3.connect(result["database_path"]) as db:
        raw, withdrawn = db.execute("SELECT raw_json, withdrawn FROM advisory").fetchone()
        assert json.loads(raw) == new and withdrawn == new["withdrawn"]
        assert db.execute("SELECT ecosystem, name FROM package").fetchall() == [("npm", "new")]
        assert db.execute("SELECT alias FROM alias").fetchall() == [("CVE-2026-0002",)]
        from appsec_review.osv_matching import match_package
        matched = match_package(db, "npm", "new", "1.0.0")
        assert matched["status"] == "complete" and matched["matches"] == []
        assert matched["withdrawn_count"] == 1


@pytest.mark.parametrize("modified", [None, "invalid", "2026-01-01T00:00:00Z"],
                         ids=["missing", "malformed", "equal-conflict"])
def test_osv_ambiguous_revisions_fail_without_publication(tmp_path, modified):
    first = _record("GHSA-one", ("PyPI", "old"))
    second = _record("GHSA-one", ("npm", "new"), modified=modified)
    fetched = _fetched(tmp_path, {"PyPI": {"a.json": first}, "npm": {"a.json": second}})
    settings = _settings(tmp_path)
    with pytest.raises(ValueError, match="OSV"):
        osv.index(settings, fetched, tmp_path / "index")
    assert not (settings.feed_root / "current.json").exists()


def _mitre_input(tmp_path, xml):
    sources = {
        "enterprise_attack": {"kind": "attack", "version": "19.2"},
        "capec": {"kind": "capec", "version": "3.9"}, "cwe": {"kind": "cwe", "version": "4.20"},
    }
    configured = {name: {**value, "url": f"https://cwe.mitre.org/{name}"} for name, value in sources.items()}
    settings = mitre.MitreSettings.from_mapping(tmp_path, {
        "feed_root": str(tmp_path / "mitre"), "source_selections": list(sources), "sources": configured,
    })
    for name in ("enterprise_attack", "capec"):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps({"type": "bundle", "objects": [{"type": "attack-pattern", "id": name}]}))
        sources[name]["path"] = str(path)
    path = tmp_path / "cwe.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("cwe.xml", xml)
    sources["cwe"]["path"] = str(path)
    return settings, {"sources": sources}


@pytest.mark.parametrize("xml", [
    '<unrelated><Weakness ID="79"/></unrelated>',
    '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7"><Weakness ID="79"/></Weakness_Catalog>',
    '<Weakness_Catalog xmlns="urn:foreign" Version="4.20"><Weakness ID="79"/></Weakness_Catalog>',
    '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Version="4.19"><Weakness ID="79"/></Weakness_Catalog>',
], ids=["root", "missing-version", "namespace", "version"])
def test_cwe_requires_catalog_identity(tmp_path, xml):
    settings, fetched = _mitre_input(tmp_path, xml)
    with pytest.raises(ValueError, match="CWE"):
        mitre.normalize(settings, fetched, tmp_path / "normalized")
    assert not (settings.feed_root / "current.json").exists()


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"],
                         ids=["utf8", "utf16", "utf16le", "utf16be"])
def test_cwe_rejects_declarations_after_prefix_in_supported_encodings(tmp_path, encoding):
    xml = '<!--' + "x" * 66000 + '--><!DOCTYPE Weakness_Catalog [<!ENTITY x "expanded">]>'
    xml += cwe_xml({"CWE-79": ("Fixture", "Base")})
    settings, fetched = _mitre_input(tmp_path, xml.encode(encoding))
    with pytest.raises(ValueError, match="prohibited DTD"):
        mitre.normalize(settings, fetched, tmp_path / "normalized")


def test_cwe_character_truncation_is_counted_in_published_metadata(tmp_path):
    settings, fetched = _mitre_input(tmp_path, cwe_xml({
        "CWE-79": ("Fixture", "Base", [(["Availability"], ["x" * 129])]),
    }))
    normalized = mitre.normalize(settings, fetched, tmp_path / "normalized")
    assert normalized["consequence_truncated_weaknesses"] == 1
    pointer = mitre.publish(settings, fetched, normalized)
    identity = mitre.verify(settings)
    assert identity["snapshot_id"] == pointer["snapshot_id"]
    manifest = json.loads((Path(identity["directory"]) / "manifest.json").read_text())
    assert manifest["consequence_truncated_weaknesses"] == 1
    with sqlite3.connect(normalized["database_path"]) as db:
        assert json.loads(db.execute("SELECT impacts_json FROM cwe_consequence").fetchone()[0]) == ["x" * 128]


@pytest.mark.parametrize("defect", ["count", "foreign", "null-source", "orphan", "negative"],
                         ids=["count", "foreign", "null-source", "orphan", "negative"])
def test_cve_range_facts_are_verified_from_actual_rows(tmp_path, defect):
    directory = tmp_path / "database"
    write_databases(directory)
    record_path = directory / "build.json"
    record = json.loads(record_path.read_text())
    if defect == "count":
        record["range_count"] = 99
    elif defect == "negative":
        record["layer_records"] = -1
    else:
        with sqlite3.connect(directory / "cve.db") as db:
            db.execute("INSERT INTO cve_range(cve_number, data_source) VALUES (?, ?)",
                       ("CVE-2026-9999" if defect == "orphan" else "CVE-2026-0000",
                        None if defect == "null-source" else "OTHER" if defect == "foreign" else "NVD"))
        record["range_count"] = 1
    record_path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="cve-bin-tool"):
        cve._check(directory, "3.4")


@pytest.mark.parametrize("redirect", ["http://allowed.example/b", "https://other.example/b",
                                     "https://user:pass@allowed.example/b", "https://allowed.example/b"],
                         ids=["downgrade", "foreign-host", "credentials", "same-host"])
def test_redirect_policy_checks_every_hop_before_transport(tmp_path, monkeypatch, redirect):
    requested = []

    class Transport(urllib.request.HTTPSHandler, urllib.request.HTTPHandler):
        def https_open(self, request):
            requested.append(request.full_url)
            if request.full_url != "https://allowed.example/a":
                response = urllib.response.addinfourl(io.BytesIO(b"fixture"), {}, request.full_url, 200)
                response.msg = "OK"
                return response
            headers = {"location": redirect}
            response = io.BytesIO(b"")
            return self.parent.error("http", request, response, 302, "Found", headers)

        http_open = https_open

    original = urllib.request.build_opener
    monkeypatch.setattr(urllib.request, "HTTPSHandler", Transport)
    monkeypatch.setattr(urllib.request, "build_opener", original)
    if redirect == "https://allowed.example/b":
        receipt = publication.HttpDownloader().download(
            "https://allowed.example/a", tmp_path / "download", max_bytes=100, allowed_hosts=("allowed.example",))
        assert receipt["url"] == requested[0] and receipt["effective_url"] == redirect
        assert receipt["redirects"] == [redirect] and requested == ["https://allowed.example/a", redirect]
    else:
        with pytest.raises(ValueError, match="redirect|HTTPS|source"):
            publication.HttpDownloader().download("https://allowed.example/a", tmp_path / "download",
                                                  max_bytes=100, allowed_hosts=("allowed.example",))
        assert requested == ["https://allowed.example/a"]


def test_interleaved_publication_verifies_its_own_transaction(tmp_path, monkeypatch):
    from appsec_review.jobs.job_third_party_data_sync.steps.kev_sync import feed as kev
    from tests.test_feed_provenance import owner, proof
    from tests.test_shared_layout_provenance import provenance_scope

    settings = kev_settings(tmp_path / "data/feeds/kev")
    first_owner, second_owner = owner(tmp_path, "first"), owner(tmp_path, "second")
    inputs = []
    for number in (1, 2):
        work = tmp_path / str(number)
        work.mkdir()
        path = work / "kev.json"
        path.write_text(json.dumps(kev_document([kev_entry(f"CVE-2026-{number:04d}")])))
        fetched = {"source": {"path": str(path), "url": settings.url}}
        inputs.append((fetched, kev.normalize(settings, fetched, work)))
    first_published, second_published = threading.Event(), threading.Event()
    real_publish = kev.publish

    def interleaved(*args, **kwargs):
        pointer = real_publish(*args, **kwargs)
        first_published.set()
        assert second_published.wait(2)
        return pointer

    monkeypatch.setattr(kev, "publish", interleaved)
    monkeypatch.setattr(job, "_kev", lambda context: settings)
    unit = SimpleNamespace(
        job=SimpleNamespace(metadata_root=tmp_path / "metadata", run_id="run", attempt_id="attempt"),
        output=lambda name: inputs[0][0 if name.endswith("fetch") else 1])
    handler = next(item for item in job.build_job().units if item.unit_id == "kev_sync.publish").handler

    def competing():
        assert first_published.wait(2)
        try:
            with provenance_scope(second_owner):
                return real_publish(settings, *inputs[1])
        finally:
            second_published.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(competing)
        with provenance_scope(first_owner):
            result = handler(unit)
        other = future.result(timeout=2)
    assert result["pointer"]["snapshot_id"] != other["snapshot_id"]
    for key in ("snapshot_id", "manifest_sha256"):
        assert result["identity"][key] == result["pointer"][key]
    metadata = json.loads(Path(result["metadata_path"]).read_text())
    assert metadata["identity"]["snapshot_id"] == result["pointer"]["snapshot_id"]
    assert json.loads((settings.feed_root / "current.json").read_text())["snapshot_id"] == other["snapshot_id"]
    selected = proof(first_owner, result["identity"]["provenance"])
    assert selected["manifest"]["sha256"] == result["pointer"]["manifest_sha256"]
    assert result["pointer"]["snapshot_id"] in selected["manifest"]["path"]


@pytest.mark.parametrize("consumer", ["evidence", "artifact"], ids=["evidence", "artifact"])
def test_osv_scanners_use_frozen_custom_root(tmp_path, monkeypatch, consumer):
    from appsec_review.jobs.job_evidence_collection import job as evidence
    from appsec_review.jobs.job_evidence_collection.adapters import Applicability, adapter_registry
    from appsec_review.jobs.job_artifact_security_analysis.scanners import ContainerScannerRunner

    settings = _settings(tmp_path, feed_root="data/feeds/custom-osv", ecosystems=["npm"])
    fetched = _fetched(tmp_path, {"npm": {"a.json": _record("OSV-one", ("npm", "fixture"))}})
    pointer = osv.publish(settings, fetched, osv.index(settings, fetched, tmp_path / "index"))
    run = tmp_path / "run"
    config = run / "data/configuration/resolved.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"jobs": {"job_third_party_data_sync": {"steps": {"osv_sync": {
        "settings": {"feed_root": "data/feeds/custom-osv", "ecosystems": ["npm"]}}}}}}))
    default = tmp_path / "data/feeds/osv"
    default.mkdir()
    (default / "current.json").write_text("MUST NOT READ DEFAULT STORE")
    if consumer == "evidence":
        unit = SimpleNamespace(job=SimpleNamespace(repository_root=tmp_path, run_root=run),
                               unit_root=tmp_path / "unit")
        selected = Applicability(True, "fixture", ("package-lock.json",), "dependency_lockfiles")
        _, mounts, environment, gap = evidence._prerequisites(unit, adapter_registry()["tool-osv-scanner"], selected)
        assert gap is None and len(mounts) == 1
        assert mounts[0].source.is_relative_to(settings.feed_root / "snapshots" / pointer["snapshot_id"])
        assert environment
    else:
        root = Path(__file__).resolve().parents[3]
        import tomlkit
        catalog_path = root / "containers/catalog.toml"
        catalog = tomllib.loads(catalog_path.read_text())
        catalog["images"] = [item for item in catalog["images"] if item["id"] == "tool-osv-scanner"]
        target_catalog = tmp_path / "containers/catalog.toml"
        target_catalog.parent.mkdir()
        target_catalog.write_text(tomlkit.dumps(catalog))
        for name in (catalog["runtime_policy"], catalog["images"][0]["tool_manifest"]):
            destination = tmp_path / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, destination)
        runner = ContainerScannerRunner(tmp_path, run, tmp_path / "scratch")
        # The only external image operation is replaced; selection/verification remain real.
        monkeypatch.setattr(runner.executor, "resolve_image", lambda tool: "sha256:" + "a" * 64)
        identity = runner.identity("osv", {})
        assert "unavailable" not in identity
        assert identity["rules"]["snapshot_id"] == pointer["snapshot_id"]
        assert set(runner._osv_ecosystems) == {"npm"}


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"],
                         ids=["utf8", "utf16", "utf16le", "utf16be"])
def test_cwe_supported_encodings_keep_valid_catalogs(tmp_path, encoding):
    settings, fetched = _mitre_input(tmp_path, cwe_xml({"CWE-79": ("Fixture", "Base")}).encode(encoding))
    assert mitre.normalize(settings, fetched, tmp_path / "normalized")["source_counts"]["cwe"] == 1


def test_cwe_never_inherits_jacoco_doctype_exception(tmp_path):
    xml = '<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">'
    xml += cwe_xml({"CWE-79": ("Fixture", "Base")})
    settings, fetched = _mitre_input(tmp_path, xml)
    with pytest.raises(ValueError, match="prohibited DTD"):
        mitre.normalize(settings, fetched, tmp_path / "normalized")


@pytest.mark.parametrize("source", ["enterprise_attack", "capec", "cwe"], ids=["attack", "capec", "cwe"])
def test_mitre_required_source_cannot_publish_no_entries(tmp_path, source):
    settings, fetched = _mitre_input(tmp_path, cwe_xml({} if source == "cwe" else {"CWE-79": ("Fixture", "Base")}))
    if source != "cwe":
        Path(fetched["sources"][source]["path"]).write_text('{"type":"bundle","objects":[]}')
    with pytest.raises(ValueError, match="required MITRE source contains no entries"):
        mitre.normalize(settings, fetched, tmp_path / "normalized")
    assert not (settings.feed_root / "current.json").exists()


def test_cve_nonzero_ranges_are_measured_not_just_declared(tmp_path):
    directory = tmp_path / "database"
    write_databases(directory)
    with sqlite3.connect(directory / "cve.db") as db:
        db.execute("INSERT INTO cve_range(cve_number,data_source,vendor,product,version) "
                   "VALUES ('CVE-2026-0000','NVD','fixture','package','1.0')")
    path = directory / "build.json"
    path.write_text(json.dumps({**json.loads(path.read_text()), "range_count": 1}))
    assert cve._check(directory, "3.4") == {"cve_count": 1, "range_count": 1, "layer_records": 1}


def test_cve_missing_range_columns_are_refused(tmp_path):
    directory = tmp_path / "database"
    write_databases(directory)
    with sqlite3.connect(directory / "cve.db") as db:
        db.execute("ALTER TABLE cve_range DROP COLUMN product")
    with pytest.raises(ValueError, match="cve_range schema"):
        cve._check(directory, "3.4")


@pytest.mark.parametrize("empty", [False, True], ids=["boundary-repeat", "empty"])
def test_nvd_separate_windows_allow_boundary_duplicates_and_empty_results(tmp_path, empty):
    publisher = _publisher(tmp_path, max_window_days=1)
    publisher.sync("bootstrap")
    publisher.clock = lambda: NOW + timedelta(days=1)
    calls = []

    def page(url, key=None):
        calls.append(url)
        records = [] if empty else [vulnerability("CVE-2026-2000")]
        return json.dumps({"format": "NVD_CVE", "version": "2.0", "startIndex": 0,
                           "totalResults": len(records), "resultsPerPage": len(records),
                           "vulnerabilities": records}).encode()

    publisher.client = SimpleNamespace(get_bytes=page)
    pointer = publisher.sync("windows")
    manifest = json.loads((publisher.root / "snapshots" / pointer["snapshot_id"] / "manifest.json").read_text())
    assert len(calls) == len(manifest["layers"]) == 2
    assert manifest["layers"][1]["pages"][0]["duplicate_count"] == (0 if empty else 1)
    assert publisher.verify()["index"]["record_count"] == (1 if empty else 2)
