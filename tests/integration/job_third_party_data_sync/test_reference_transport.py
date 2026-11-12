"""Real TLS, decompression, SQLite normalization and publication for each reference input kind."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.jobs.job_third_party_data_sync.steps.epss_sync import feed as epss
from appsec_review.jobs.job_third_party_data_sync.steps.mitre_sync import feed as mitre
from appsec_review.jobs.job_third_party_data_sync.steps.osv_sync import feed as osv
from tests.fixtures.reference_feeds import cwe_xml, epss_bytes

from .support import LoopbackDownloader, Response, assert_work_contract, https_server, work_path, zip_bytes


def prepare(kind, root, base, routes):
    if kind == "epss":
        routes["/epss.csv.gz"] = Response(epss_bytes([("CVE-2026-0001", 0.42, 0.97)]))
        settings = epss.EpssSettings.from_mapping(root, {
            "feed_root": "feeds/epss", "url": base + "/epss.csv.gz", "allowed_hosts": ["127.0.0.1"],
            "timeout_seconds": 2, "max_source_bytes": 4096, "max_uncompressed_bytes": 8192,
        })
        return epss, settings, None, "/epss.csv.gz", b"not gzip", ValueError, "gzip"
    if kind == "osv":
        record = {"id": "PYSEC-fixture", "affected": [{"package": {"ecosystem": "PyPI", "name": "fixture"}}]}
        routes["/osv-vulnerabilities/PyPI/all.zip"] = Response(zip_bytes("PYSEC-fixture.json", json.dumps(record).encode()))
        settings = osv.OsvSettings.from_mapping(root, {
            "feed_root": "feeds/osv", "ecosystems": ["PyPI"], "timeout_seconds": 2,
            "max_archive_bytes": 4096, "max_uncompressed_bytes": 8192,
        })
        return (osv, settings, LoopbackDownloader(base), "/osv-vulnerabilities/PyPI/all.zip",
                zip_bytes("bad.json", b"{}"), ValueError, "no id")
    sources = {}
    for name, source_kind, external_id in (
        ("enterprise_attack", "attack", "T1001"), ("capec", "capec", "CAPEC-1"), ("cwe", "cwe", "CWE-120"),
    ):
        path = "/" + name + (".zip" if source_kind == "cwe" else ".json")
        sources[name] = {"kind": source_kind, "url": "https://raw.githubusercontent.com" + path,
                         "version": "4.20" if source_kind == "cwe" else "fixture"}
        payload = (zip_bytes("cwe.xml", cwe_xml({"CWE-120": ("Buffer copy", "Base")}).encode())
                   if source_kind == "cwe" else json.dumps({
                       "type": "bundle", "objects": [{"type": "attack-pattern", "name": "Fixture",
                                                    "external_references": [{"external_id": external_id}]}],
                   }).encode())
        routes[path] = Response(payload)
    settings = mitre.MitreSettings.from_mapping(root, {
        "feed_root": "feeds/mitre", "sources": sources, "source_selections": list(sources),
        "timeout_seconds": 2, "max_source_bytes": 4096, "max_uncompressed_bytes": 8192,
    })
    return mitre, settings, LoopbackDownloader(base), "/enterprise_attack.json", b"{}", ValueError, "not a bundle"


def cycle(kind, module, settings, downloader, root):
    step = f"{kind}_sync"
    fetch_work = work_path(root, f"{step}.fetch")
    fetched = module.fetch(settings, fetch_work, downloader)
    assert_work_contract(root, f"{step}.fetch", fetched)
    task = "index" if kind == "osv" else "normalize"
    normalize = module.index if kind == "osv" else module.normalize
    normalized = normalize(settings, fetched, work_path(root, f"{step}.{task}"))
    assert_work_contract(root, f"{step}.{task}", normalized)
    pointer = module.publish(settings, fetched, normalized)
    verified = module.verify(settings)
    assert verified["snapshot_id"] == pointer["snapshot_id"]
    assert Path(verified["directory"]).is_relative_to(root)
    return verified


@pytest.mark.parametrize("kind", ["epss", "mitre", "osv"])
def test_real_reference_bytes_publish_queryable_artifacts(tmp_path, monkeypatch, kind):
    routes = {}
    with https_server(routes, monkeypatch) as (base, requests):
        module, settings, downloader, *_ = prepare(kind, tmp_path, base, routes)
        verified = cycle(kind, module, settings, downloader, tmp_path)
        directory = Path(verified["directory"])
        with sqlite3.connect(f"file:{directory}/index/{kind}.sqlite?mode=ro", uri=True) as db:
            if kind == "epss":
                assert db.execute("SELECT cve_id, epss, percentile FROM epss").fetchall() == [
                    ("CVE-2026-0001", 0.42, 0.97)]
            elif kind == "osv":
                assert db.execute("SELECT advisory_id, ecosystem, name FROM package").fetchall() == [
                    ("PYSEC-fixture", "PyPI", "fixture")]
            else:
                assert db.execute("SELECT source, external_id FROM entry ORDER BY source").fetchall() == [
                    ("capec", "CAPEC-1"), ("cwe", "CWE-120"), ("enterprise_attack", "T1001")]
        assert len(requests) == (3 if kind == "mitre" else 1)
        assert all(tls.startswith("TLS") for _, _, tls in requests)
        assert verified["record_count"] == (3 if kind == "mitre" else 1)
        manifest = json.loads((directory / "manifest.json").read_bytes())
        assert set(manifest["files"]) == {
            f"index/{kind}.sqlite",
            *({"sources/epss_scores.csv.gz"} if kind == "epss" else
              {"sources/PyPI.zip"} if kind == "osv" else
              {"sources/enterprise_attack.json", "sources/capec.json", "sources/cwe.zip"}),
        }


@pytest.mark.parametrize("kind", ["epss", "mitre", "osv"])
def test_real_malformed_response_preserves_previous_publication(tmp_path, monkeypatch, kind):
    routes = {}
    with https_server(routes, monkeypatch) as (base, requests):
        module, settings, downloader, path, malformed, error, message = prepare(kind, tmp_path, base, routes)
        accepted = cycle(kind, module, settings, downloader, tmp_path)
        pointer = settings.feed_root / "current.json"
        before = pointer.read_bytes()
        snapshots = sorted((settings.feed_root / "snapshots").iterdir())
        routes[path] = Response(malformed)
        with pytest.raises(error, match=message):
            cycle(kind, module, settings, downloader, tmp_path / "retry")
        assert pointer.read_bytes() == before
        assert sorted((settings.feed_root / "snapshots").iterdir()) == snapshots
        assert module.verify(settings)["snapshot_id"] == accepted["snapshot_id"]
        assert len(requests) == (6 if kind == "mitre" else 2)
