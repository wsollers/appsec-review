from __future__ import annotations

import hashlib
import io
from datetime import timedelta
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(Path(__file__).resolve().parent))

import dependency_snapshot_registry as snapshots
import dependency_snapshot_sync as syncer
import permission_capabilities as pc
import sca_nvd_snapshot
from test_sca_nvd_snapshot import Publisher, T0


class Response(io.BytesIO):
    status = 200
    def __enter__(self): return self
    def __exit__(self, *_args): self.close()


class SnapshotSyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.root = Path(self.temporary.name)
        self.run = "run-sync"; self.source = "sha256:" + "a" * 64; self.now = "2026-09-27T12:00:00Z"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            data = b"offline database\n"; item = tarfile.TarInfo("database/data.bin"); item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
        self.archive = buffer.getvalue()

    def tearDown(self): self.temporary.cleanup()

    def spec(self, kind):
        return {"database_kind": kind, "url": f"https://mirror.example/{kind}.tar.gz",
            "sha256": "sha256:" + hashlib.sha256(self.archive).hexdigest(), "bytes": len(self.archive),
            "archive": "tar.gz", "metadata": {"database_kind": kind, "vendor_build": "vendor-1",
                "schema_version": "6", "snapshot_id": kind + "-20260927", "data_timestamp": self.now},
            "required_paths": ["database/data.bin"], "max_extracted_bytes": 1024 * 1024, "max_files": 10}

    def grants(self):
        parameters = {name: None for name in pc.PARAMETER_NAMES}
        parameters.update({"scheme": "https", "host": "mirror.example", "port": 443})
        return [{"schema": "appsec-review/permission-grant/1.0", "grant_id": "grant-db-sync",
            "effect": "ALLOW", "authority": {"name": "Fixture Owner", "role": "engagement-owner"},
            "issued_at": "2026-09-27T00:00:00Z", "expires_at": "2026-09-28T00:00:00Z",
            "binding": {"run_id": self.run, "source_snapshot_sha256": self.source, "job_id": syncer.JOB},
            "justification": "Fetch exact pinned offline vulnerability mirrors.",
            "capabilities": [{"kind": "fixed-network-destination", "version": "1.0", "origin": "operator",
                "parameters": parameters}]}]

    def call(self, kind, **over):
        return syncer.sync_one(self.spec(kind), self.grants(), run_id=self.run,
            source_snapshot_sha256=self.source, now=self.now, registry_root=self.root / "registry",
            opener=over.get("opener", lambda *_args, **_kwargs: Response(self.archive)))

    def test_grype_and_osv_publish_versioned_immutable_snapshots_from_staging(self):
        for kind in ("grype-db", "osv"):
            with self.subTest(kind=kind):
                result = self.call(kind)
                self.assertTrue(Path(result["data_root"], "database/data.bin").is_file())
                self.assertEqual(snapshots.resolve(kind, self.root / "registry", max_age_seconds=0,
                    now=snapshots._time(self.now, "now"))["snapshot_id"], kind + "-20260927")
        self.assertEqual(list((self.root / "registry/staging").iterdir()), [])

    def test_permission_hash_required_content_and_extraction_bounds_fail_closed(self):
        called = False
        def opener(*_args, **_kwargs):
            nonlocal called; called = True; return Response(self.archive)
        with self.assertRaisesRegex(syncer.SyncBlocked, "permission grant"):
            syncer.sync_one(self.spec("grype-db"), [], run_id=self.run, source_snapshot_sha256=self.source,
                now=self.now, registry_root=self.root / "registry", opener=opener)
        self.assertFalse(called)
        bad = {**self.spec("grype-db"), "sha256": "sha256:" + "0" * 64}
        with self.assertRaisesRegex(syncer.SyncBlocked, "pinned declaration"):
            syncer.sync_one(bad, self.grants(), run_id=self.run, source_snapshot_sha256=self.source,
                now=self.now, registry_root=self.root / "registry", opener=lambda *_a, **_k: Response(self.archive))
        missing = {**self.spec("grype-db"), "required_paths": ["missing.db"]}
        with self.assertRaisesRegex(syncer.SyncBlocked, "required database content"):
            syncer.sync_one(missing, self.grants(), run_id=self.run, source_snapshot_sha256=self.source,
                now=self.now, registry_root=self.root / "registry", opener=lambda *_a, **_k: Response(self.archive))
        bounded = {**self.spec("grype-db"), "max_extracted_bytes": 1}
        with self.assertRaisesRegex(syncer.SyncBlocked, "extracted byte limit"):
            syncer.sync_one(bounded, self.grants(), run_id=self.run, source_snapshot_sha256=self.source,
                now=self.now, registry_root=self.root / "registry", opener=lambda *_a, **_k: Response(self.archive))

    def test_periodic_extension_calls_nvd_then_dependency_publishers(self):
        calls = []
        result = syncer.sync_periodic_references(nvd_sync=lambda **kw: calls.append(kw) or {"snapshot_id": "nvd-1"},
            nvd_kwargs={"coordinator_id": "periodic"}, dependency_specs=[self.spec("grype-db")],
            grants=self.grants(), run_id=self.run, source_snapshot_sha256=self.source, now=self.now,
            registry_root=self.root / "registry", opener=lambda *_a, **_k: Response(self.archive))
        self.assertEqual(calls, [{"coordinator_id": "periodic"}])
        self.assertEqual(result["dependencies"][0]["database_kind"], "grype-db")

    def test_file_snapshot_retains_the_exact_vendor_archive_at_a_fixed_cache_path(self):
        spec = {**self.spec("osv"), "archive": "file",
                "target_path": "osv-scanner/OSS-Fuzz/all.zip",
                "required_paths": ["osv-scanner/OSS-Fuzz/all.zip"]}
        result = syncer.sync_one(spec, self.grants(), run_id=self.run,
            source_snapshot_sha256=self.source, now=self.now, registry_root=self.root / "registry",
            opener=lambda *_args, **_kwargs: Response(self.archive))
        retained = Path(result["data_root"], "osv-scanner", "OSS-Fuzz", "all.zip")
        self.assertEqual(retained.read_bytes(), self.archive)

        unsafe = {**spec, "target_path": "../all.zip", "required_paths": ["../all.zip"]}
        with self.assertRaisesRegex(syncer.SyncBlocked, "unsafe path"):
            syncer.sync_one(unsafe, self.grants(), run_id=self.run,
                source_snapshot_sha256=self.source, now=self.now, registry_root=self.root / "registry",
                opener=lambda *_args, **_kwargs: Response(self.archive))

    def test_grype_zstd_archive_is_activated_before_registration(self):
        spec = {**self.spec("grype-db"), "archive": "tar.zst",
                "required_paths": ["grype/db/6/vulnerability.db", "grype/db/6/import.json"]}

        def activate(_archive, destination, declared):
            self.assertEqual(declared, spec)
            cache = destination / "grype/db/6"; cache.mkdir(parents=True)
            (cache / "vulnerability.db").write_bytes(b"db")
            (cache / "import.json").write_bytes(b"{}\n")

        with mock.patch.object(syncer, "_activate_grype", side_effect=activate) as called:
            result = syncer.sync_one(spec, self.grants(), run_id=self.run,
                source_snapshot_sha256=self.source, now=self.now, registry_root=self.root / "registry",
                opener=lambda *_args, **_kwargs: Response(self.archive))
        self.assertEqual(called.call_count, 1)
        self.assertTrue(Path(result["data_root"], "grype/db/6/import.json").is_file())

    def test_nvd_warning_window_is_usable_and_hard_ceiling_still_fails(self):
        nvd = self.root / "nvd"; Publisher(nvd).sync(T0)
        result, warnings = sca_nvd_snapshot.resolve_snapshot_window(nvd, warn_age=timedelta(hours=1),
            max_age=timedelta(hours=4), now=T0 + timedelta(hours=2))
        self.assertTrue(result.usable); self.assertEqual(len(warnings), 1)
        failed, warnings = sca_nvd_snapshot.resolve_snapshot_window(nvd, warn_age=timedelta(hours=1),
            max_age=timedelta(hours=4), now=T0 + timedelta(hours=5))
        self.assertEqual((failed.outcome, failed.reason, warnings), ("FAILED", "SNAPSHOT_TOO_OLD", ()))


if __name__ == "__main__": unittest.main()
