"""Real offline Grype import: policy receipts, invalid DB rejection and supplied-fixture lineage."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

from appsec_review.config.grype import GrypeSettings
from appsec_review.jobs.job_third_party_data_sync.steps.grype_db_sync import feed
from appsec_review.storage import file_sha256
from tests.fixtures.grype import Downloader, NOW

from .support import ROOT, assert_work_contract, work_path


def test_real_grype_rejects_synthetic_non_sqlite_database(grype_executor):
    executor = grype_executor
    settings = GrypeSettings.from_mapping(executor.run_root, {"run_timeout_seconds": 30})
    fetched = feed.fetch(settings, work_path(executor.run_root, "grype_db_sync.fetch"), Downloader(), now=NOW)
    work = work_path(executor.run_root, "grype_db_sync.import")
    with pytest.raises(RuntimeError, match="Grype db failed validation"):
        feed.import_database(settings, fetched, work, executor, now=NOW)
    receipt = json.loads((work / "import/execution.json").read_bytes())
    assert receipt["exit_code"] != 0 and not receipt["timed_out"]
    assert receipt["limits"]["network"] == "none"
    assert receipt["limits"]["root_filesystem"] == "read-only"
    assert receipt["limits"]["cap_drop"] == ["ALL"]
    assert receipt["limits"]["no_new_privileges"] is True
    assert receipt["limits"]["timeout_seconds"] == 30
    assert receipt["limits"]["user"].split(":")[0] != "0"
    assert {entry["target"]: entry["read_only"] for entry in receipt["mounts"]} == {
        "/target": True, "/scratch": False,
    }
    assert not (settings.feed_root / "current.json").exists()


def test_real_grype_import_publish_and_fixture_provenance(grype_executor):
    """An operator-supplied tiny fresh v6 archive; never consume the deployment's feed cache."""
    executor = grype_executor
    selected = os.environ.get("APPSEC_TEST_GRYPE_DB_ARCHIVE")
    if not selected:
        pytest.skip("missing APPSEC_TEST_GRYPE_DB_ARCHIVE: tiny fresh v6 fixture plus .provenance.json")
    source = Path(selected).resolve(strict=True)
    for forbidden in (ROOT / "runs", ROOT / "data/feeds", ROOT / "targets"):
        assert not source.is_relative_to(forbidden), "integration must not consume production or target data"
    assert source.is_file() and source.stat().st_size <= 8 * 1024 * 1024
    provenance = json.loads(source.with_name(source.name + ".provenance.json").read_bytes())
    tool = executor.catalog.tool("tool-grype")
    assert provenance["tool_id"] == tool.tool_id
    assert provenance["tool_version"] == tool.version
    assert provenance["image_id"] == tool.expected_image_id, "fixture pin drift: regenerate the fixture"
    assert provenance["input_sha256"] == file_sha256(source)
    now = datetime.now(timezone.utc)
    settings = GrypeSettings.from_mapping(executor.run_root, {
        "run_timeout_seconds": 30, "max_archive_bytes": 8 * 1024 * 1024,
        "max_database_bytes": 32 * 1024 * 1024, "max_uncompressed_bytes": 64 * 1024 * 1024,
    })
    # Only acquisition is a fixture: extraction, all three Grype calls and publication are real.
    downloader = Downloader(archive=source.read_bytes(), built=provenance["built"],
                            schemaVersion=provenance["schema_version"])
    fetched = feed.fetch(settings, work_path(executor.run_root, "grype_db_sync.fetch"), downloader, now=now)
    imported = feed.import_database(settings, fetched, work_path(executor.run_root, "grype_db_sync.import"),
                                    executor, now=now)
    assert_work_contract(executor.run_root, "grype_db_sync.import", imported)
    status = json.loads(Path(imported["status_path"]).read_bytes())
    normalized = json.dumps({key: status[key] for key in ("schemaVersion", "built", "valid", "path")},
                            sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(normalized).hexdigest() == provenance["output_sha256"]
    pointer = feed.publish(settings, fetched, imported, now=now)
    identity = feed.verify(settings, now=now, expected_image_id=tool.expected_image_id)
    assert identity["snapshot_id"] == pointer["snapshot_id"]
    assert identity["verified_files"] == 5
    manifest = json.loads((Path(identity["directory"]) / "manifest.json").read_bytes())
    assert manifest["schema"] == feed.SNAPSHOT_SCHEMA
    assert set(manifest["files"]) == feed._FILES
    copied = Path(imported["status_path"]).with_suffix(".provenance.json")
    shutil.copyfile(source.with_name(source.name + ".provenance.json"), copied)
