from __future__ import annotations

from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import zipfile

from appsec_review.config import load_config
from appsec_review.jobs.job_third_party_data_sync import build_job
from appsec_review.jobs.job_third_party_data_sync.steps.osv_sync.feed import OsvSettings, lookup_package
from appsec_review.runtime import JobRunner


ROOT = Path(__file__).parents[1]


def _nvd_record() -> dict:
    return {"cve": {"id": "CVE-2026-1000", "sourceIdentifier": "fixture", "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-01T00:00:00.000", "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "fixture"}], "weaknesses": [], "metrics": {}}}


class NvdClient:
    def __init__(self):
        self.raw = json.dumps({"format": "NVD_CVE", "version": "2.0", "vulnerabilities": [_nvd_record()]},
                              separators=(",", ":")).encode()
        self.compressed = gzip.compress(self.raw, mtime=0)

    def get_bytes(self, url, api_key=None):
        if url.endswith(".meta"):
            return (f"lastModifiedDate:2026-10-08T00:00:00.000Z\nsize:{len(self.raw)}\n"
                    f"gzSize:{len(self.compressed)}\nsha256:{hashlib.sha256(self.raw).hexdigest()}\n").encode()
        return json.dumps({"format": "NVD_CVE", "version": "2.0", "startIndex": 0, "resultsPerPage": 0,
                           "totalResults": 0, "vulnerabilities": []}).encode()

    def download(self, url, destination, api_key=None):
        destination.write_bytes(self.compressed)
        return len(self.compressed)


class FeedDownloader:
    def download(self, url, destination, *, max_bytes, allowed_hosts):
        destination.parent.mkdir(parents=True, exist_ok=True)
        if "osv-vulnerabilities" in url:
            with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("PYSEC-2026-1.json", json.dumps({"id": "PYSEC-2026-1", "modified": "2026-01-01T00:00:00Z",
                    "aliases": ["CVE-2026-1000"], "affected": [{"package": {"ecosystem": "PyPI", "name": "fixture"}}]}))
        elif "cwec_" in url:
            with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("cwec.xml", '<Weakness_Catalog Version="4.20"><Weaknesses><Weakness ID="79" Name="XSS"/></Weaknesses></Weakness_Catalog>')
        else:
            external = "CAPEC-1" if "stix-capec" in url else "T1001"
            destination.write_text(json.dumps({"type": "bundle", "objects": [{"type": "attack-pattern",
                "id": "attack-pattern--fixture", "name": "Fixture", "external_references": [{"external_id": external}]}]}),
                encoding="utf-8")
        payload = destination.read_bytes()
        return {"url": url, "sha256": hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload),
                "etag": None, "last_modified": None, "retrieved_at": "2026-10-08T00:00:00.000Z"}


def cve_runner(settings, input_dir, output_dir):
    with sqlite3.connect(output_dir / "cve.db") as connection:
        connection.execute("CREATE TABLE cve_severity(cve_number TEXT, data_source TEXT)")
        connection.execute("INSERT INTO cve_severity VALUES ('CVE-2026-1000', 'NVD')")
        connection.execute("CREATE TABLE cve_range(cve_number TEXT, data_source TEXT)")
        connection.execute("INSERT INTO cve_range VALUES ('CVE-2026-1000', 'NVD')")
    with sqlite3.connect(output_dir / "version_map.db") as connection:
        connection.execute("CREATE TABLE latest_update_sqlite(datestamp DATETIME PRIMARY KEY)")
        connection.execute("INSERT INTO latest_update_sqlite VALUES (1)")
    (output_dir / "build.json").write_text(json.dumps({"tool_version": "3.4", "sources": ["NVD"],
        "cve_count": 1, "range_count": 1, "layer_records": 1}), encoding="utf-8")
    return {"image": settings.image, "image_id": "sha256:fixture", "tool_version": settings.tool_version}


def test_complete_job_runs_all_units_and_places_global_and_run_metadata(tmp_path: Path) -> None:
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8").replace("first_year = 2002", "first_year = 2026")
    text = re.sub(r'\nsha256 = "[0-9a-f]{64}"', "", text)
    (tmp_path / "appsec-review.toml").write_text(text, encoding="utf-8")
    shutil.copytree(ROOT / "tools", tmp_path / "tools")
    instant = datetime(2026, 10, 8, tzinfo=timezone.utc)
    outcome = JobRunner(load_config(tmp_path / "appsec-review.toml")).run(
        build_job(client=NvdClient(), clock=lambda: instant, pause=lambda _: None,
                  osv_downloader=FeedDownloader(), mitre_downloader=FeedDownloader(), cve_runner=cve_runner),
        now=instant,
    )

    assert outcome["status"]["status"] == "SUCCEEDED"
    assert set(outcome["result"]["steps"].values()) == {"SUCCEEDED"}
    assert len(outcome["result"]["units"]) == 12
    metadata = tmp_path / "runs" / "metadata"
    assert {path.name for path in (metadata / "feeds").glob("*.json")} == {
        "nvd.json", "osv.json", "mitre.json", "cve-bin-tool.json"
    }
    assert (metadata / "jobs" / "job_third_party_data_sync.json").is_file()
    attempt = Path(outcome["attempt_root"])
    assert (attempt / "result.json").is_file()
    assert len(list((attempt / "steps").glob("*/tasks/*/status.json"))) == 12
    settings = OsvSettings.from_mapping(tmp_path, load_config(tmp_path / "appsec-review.toml").job(
        "job_third_party_data_sync").step("osv_sync").settings)
    lookup = lookup_package(settings, "PyPI", "fixture", limit=1)
    assert lookup["items"][0]["advisory_id"] == "PYSEC-2026-1"
    assert lookup["snapshot_id"] == outcome["result"]["outputs"]["osv_sync.publish"]["identity"]["snapshot_id"]
