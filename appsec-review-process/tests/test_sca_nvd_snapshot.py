"""Tests for the read-only NVD snapshot binding (V09, ADR-0010 G3).

Every snapshot here is published by `nvd_feed.sync` itself through its injectable offline
`fetch`/`fetch_file`/`clock` seams, so the layout under test is the publisher's real layout and
cannot drift from it. Wrong states are then made by editing exactly one thing. Nothing is
downloaded; `socket.socket` is replaced by a raiser for the scenario sweep.
"""
from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import execution_state  # noqa: E402
import nvd_feed  # noqa: E402  (fixture builder only; the module under test never imports it)
import sca_nvd_snapshot as binding  # noqa: E402
from schema_validate import validate_document  # noqa: E402

T0 = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)
CAPTURED = "2026-09-19T12:00:05+00:00"
NOW = T0 + timedelta(hours=6)
MAX_AGE = timedelta(hours=24)


def vulnerability(identifier):
    return {"cve": {"id": identifier, "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-01T00:00:00.000"}}


class Publisher:
    """Drives the real publisher offline."""
    def __init__(self, root):
        self.root = root
        self.document = json.dumps({"format": "NVD_CVE", "version": "2.0",
                                    "vulnerabilities": [vulnerability("CVE-2026-1000")]},
                                   separators=(",", ":")).encode()
        self.compressed = gzip.compress(self.document, mtime=0)
        self.fail_after_pages = None
        self.pages = 0

    def fetch(self, url, api_key=None):
        if url.endswith(".meta"):
            return (f"lastModifiedDate:{nvd_feed.timestamp(T0)}\nsize:{len(self.document)}\n"
                    f"gzSize:{len(self.compressed)}\nsha256:{hashlib.sha256(self.document).hexdigest()}\n").encode()
        if self.fail_after_pages is not None and self.pages >= self.fail_after_pages:
            raise OSError("offline fixture: refresh interrupted")
        self.pages += 1
        index = int(url.split("startIndex=")[1].split("&")[0])
        total = 2 if self.fail_after_pages is not None else 1
        return json.dumps({"format": "NVD_CVE", "version": "2.0", "startIndex": index,
                           "resultsPerPage": 1, "totalResults": total,
                           "vulnerabilities": [vulnerability(f"CVE-2026-{2000 + self.pages}")]},
                          separators=(",", ":")).encode()

    def fetch_file(self, url, destination, api_key=None):
        Path(destination).write_bytes(self.compressed)
        return len(self.compressed)

    def sync(self, instant, captured=CAPTURED):
        with patch.object(nvd_feed, "FIRST_YEAR", 2026), patch.object(nvd_feed, "now", lambda: captured):
            return nvd_feed.sync(self.root, "offline-fixture", clock=lambda: instant, fetch=self.fetch,
                                 fetch_file=self.fetch_file, pause=lambda _: None)


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def manifest_path(root, snapshot_id=None):
    snapshot_id = snapshot_id or read(root / "current.json")["snapshot_id"]
    return root / "snapshots" / snapshot_id / "manifest.json"


def edit_pointer(root, **fields):
    pointer = read(root / "current.json")
    pointer.update(fields)
    write(root / "current.json", pointer)


def edit_manifest(root, mutate, rebind="none", snapshot_id=None):
    """rebind: 'none' edits only the manifest; 'pointer' also re-hashes it into current.json;
    'full' re-derives snapshot id, directory, and pointer the way an attacker with write access
    to the whole publication root could."""
    path = manifest_path(root, snapshot_id)
    manifest = read(path)
    mutate(manifest)
    if rebind == "full":
        manifest["snapshot_id"] = binding.snapshot_id_of(manifest)
        target = root / "snapshots" / manifest["snapshot_id"]
        if target != path.parent:
            path.parent.rename(target)
        path = target / "manifest.json"
    write(path, manifest)
    if rebind in ("pointer", "full"):
        edit_pointer(root, snapshot_id=manifest["snapshot_id"],
                     manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cursor=manifest["cursor"])
    return manifest


def first_blob(manifest):
    layer = manifest["layers"][0]
    return layer["blob"] if "blob" in layer else layer["pages"][0]["blob"]


def tree_state(root):
    state = {}
    for path in sorted(Path(root).rglob("*")):
        info = path.lstat()
        state[str(path.relative_to(root))] = (info.st_mode, info.st_size, info.st_mtime_ns,
                                              path.read_bytes() if path.is_file() and not path.is_symlink() else None)
    return state


# --- scenarios: name -> (mutation applied to a published bootstrap+incremental root, outcome, reason)
def _blob_file(root):
    return root / first_blob(read(manifest_path(root)))["path"]


def s_pointer_missing(root):
    (root / "current.json").unlink()


def s_root_missing(root):
    shutil.rmtree(root)


def s_publisher_never_ran(root):
    shutil.rmtree(root)
    (root / "locks").mkdir(parents=True)


def s_snapshot_missing(root):
    shutil.rmtree(manifest_path(root).parent)


def s_pointer_names_absent_snapshot(root):
    edit_pointer(root, snapshot_id="sha256-0123456789abcdef")


def s_manifest_missing(root):
    manifest_path(root).unlink()


def s_blob_missing(root):
    _blob_file(root).unlink()


def s_parent_blob_missing(root):
    parent = read(manifest_path(root))["parent_snapshot_id"]
    (root / first_blob(read(manifest_path(root, parent)))["path"]).unlink()


def s_parent_snapshot_missing(root):
    shutil.rmtree(root / "snapshots" / read(manifest_path(root))["parent_snapshot_id"])


def s_blob_tampered_same_size(root):
    blob = _blob_file(root)
    data = bytearray(blob.read_bytes())
    data[-1] ^= 0xFF
    blob.write_bytes(bytes(data))


def s_blob_truncated(root):
    blob = _blob_file(root)
    blob.write_bytes(blob.read_bytes()[:-3])


def s_blob_is_directory(root):
    blob = _blob_file(root)
    blob.unlink()
    blob.mkdir()


def s_blob_symlink(root):
    blob = _blob_file(root)
    copy = root / "staging" / "copy.json.gz"
    shutil.copy(blob, copy)
    blob.unlink()
    blob.symlink_to(copy)


def s_extra_file_in_snapshot(root):
    (manifest_path(root).parent / "unlisted.json.gz").write_bytes(b"x")


def s_snapshot_dir_symlink(root):
    directory = manifest_path(root).parent
    moved = root / "staging" / "moved"
    directory.rename(moved)
    directory.symlink_to(moved, target_is_directory=True)


def s_pointer_symlink(root):
    pointer = root / "current.json"
    moved = root / "staging" / "current.json"
    pointer.rename(moved)
    pointer.symlink_to(moved)


def s_pointer_garbage(root):
    (root / "current.json").write_text("{not json")


def s_pointer_duplicate_key(root):
    text = (root / "current.json").read_text()
    (root / "current.json").write_text(text.replace("{", '{"feed_id": "nvd",', 1))


def s_pointer_traversal(root):
    edit_pointer(root, snapshot_id="../../outside")


def s_pointer_extra_property(root):
    edit_pointer(root, note="x")


def s_pointer_sha_edited(root):
    edit_pointer(root, manifest_sha256="0" * 64)


def s_pointer_snapshot_id_edited_to_parent(root):
    edit_pointer(root, snapshot_id=read(manifest_path(root))["parent_snapshot_id"])


def s_pointer_cursor_edited(root):
    edit_pointer(root, cursor="2026-09-20T00:00:00.000Z")


def s_pointer_cursor_not_a_time(root):
    edit_pointer(root, cursor="yesterday")


def _set(key, value):
    def mutate(manifest):
        manifest[key] = value
    return mutate


def _blob_field(key, value):
    def mutate(manifest):
        first_blob(manifest)[key] = value
    return mutate


def s_manifest_captured_at_only(root):
    edit_manifest(root, _set("captured_at", "2026-09-20T00:00:00+00:00"))


def s_manifest_cursor_only(root):
    edit_manifest(root, _set("cursor", "2026-09-20T00:00:00.000Z"))


def s_manifest_timestamp_and_pointer_hash(root):
    edit_manifest(root, _set("captured_at", "2026-09-20T00:00:00+00:00"), rebind="pointer")


def s_manifest_snapshot_id_field(root):
    edit_manifest(root, _set("snapshot_id", "sha256-0123456789abcdef"), rebind="none")
    edit_pointer(root, manifest_sha256=hashlib.sha256(manifest_path(root).read_bytes()).hexdigest())


def s_manifest_schema_invalid(root):
    edit_manifest(root, _set("unexpected", True), rebind="full")


def s_manifest_timestamp_unparseable(root):
    edit_manifest(root, _set("captured_at", "not-a-time"), rebind="full")


def s_manifest_blob_sha_only(root):
    edit_manifest(root, _blob_field("sha256", "0" * 64), rebind="full")


def s_manifest_blob_size_only(root):
    edit_manifest(root, _blob_field("size_bytes", 1), rebind="full")


def s_manifest_blob_path_traversal(root):
    edit_manifest(root, _blob_field("path", "../outside.json.gz"), rebind="full")


def s_manifest_blob_path_absolute(root):
    edit_manifest(root, _blob_field("path", "/etc/passwd"), rebind="full")


def s_manifest_blob_path_and_sha(root):
    def mutate(manifest):
        first_blob(manifest).update(sha256="0" * 64, path="blobs/sha256-" + "0" * 64 + ".json.gz")
    edit_manifest(root, mutate, rebind="full")


def s_manifest_layer_without_blob(root):
    def mutate(manifest):
        manifest["layers"][0] = {"kind": "api-last-modified", "start": "x", "end": "y"}
    edit_manifest(root, mutate, rebind="full")


def s_manifest_layer_unknown_kind(root):
    def mutate(manifest):
        manifest["layers"][0]["kind"] = "mystery"
    edit_manifest(root, mutate, rebind="full")


def s_parent_manifest_edited(root):
    parent = read(manifest_path(root))["parent_snapshot_id"]
    edit_manifest(root, _set("cursor", "2026-09-19T13:00:00.000Z"), snapshot_id=parent)


def s_chain_discontinuous(root):
    def mutate(manifest):
        manifest["coverage"]["last_modified_start"] = "2026-09-19T12:30:00.000Z"
    edit_manifest(root, mutate, rebind="full")


def s_chain_cycle(root):
    current = read(manifest_path(root))
    edit_manifest(root, _set("parent_snapshot_id", current["snapshot_id"]), rebind="full")


def s_bootstrap_with_parent_missing_mode(root):
    edit_manifest(root, _set("parent_snapshot_id", None), rebind="full")


def s_manifest_timestamp_in_future(root):
    edit_manifest(root, _set("captured_at", "2026-12-01T00:00:00+00:00"), rebind="full")


SCENARIOS = {
    "pointer_missing": (s_pointer_missing, "BLOCKED", "POINTER_MISSING"),
    "data_root_missing": (s_root_missing, "BLOCKED", "DATA_ROOT_MISSING"),
    "publisher_never_ran": (s_publisher_never_ran, "BLOCKED", "POINTER_MISSING"),
    "snapshot_missing": (s_snapshot_missing, "BLOCKED", "SNAPSHOT_MISSING"),
    "pointer_names_absent_snapshot": (s_pointer_names_absent_snapshot, "BLOCKED", "SNAPSHOT_MISSING"),
    "partial_manifest_missing": (s_manifest_missing, "FAILED", "MANIFEST_MISSING"),
    "partial_blob_missing": (s_blob_missing, "FAILED", "BLOB_MISSING"),
    "partial_parent_blob_missing": (s_parent_blob_missing, "FAILED", "BLOB_MISSING"),
    "partial_parent_snapshot_missing": (s_parent_snapshot_missing, "FAILED", "CHAIN_INVALID"),
    "blob_tampered_same_size": (s_blob_tampered_same_size, "FAILED", "BLOB_HASH_MISMATCH"),
    "blob_truncated": (s_blob_truncated, "FAILED", "BLOB_SIZE_MISMATCH"),
    "blob_is_directory": (s_blob_is_directory, "FAILED", "READ_ERROR"),
    "blob_symlink": (s_blob_symlink, "FAILED", "UNSAFE_PATH"),
    "extra_file_in_snapshot": (s_extra_file_in_snapshot, "FAILED", "SNAPSHOT_FILE_SET_MISMATCH"),
    "snapshot_dir_symlink": (s_snapshot_dir_symlink, "FAILED", "UNSAFE_PATH"),
    "pointer_symlink": (s_pointer_symlink, "FAILED", "UNSAFE_PATH"),
    "pointer_garbage": (s_pointer_garbage, "FAILED", "POINTER_INVALID"),
    "pointer_duplicate_key": (s_pointer_duplicate_key, "FAILED", "POINTER_INVALID"),
    "pointer_traversal": (s_pointer_traversal, "FAILED", "POINTER_INVALID"),
    "pointer_extra_property": (s_pointer_extra_property, "FAILED", "POINTER_INVALID"),
    "pointer_cursor_not_a_time": (s_pointer_cursor_not_a_time, "FAILED", "POINTER_INVALID"),
    "field_pointer_manifest_sha256": (s_pointer_sha_edited, "FAILED", "MANIFEST_HASH_MISMATCH"),
    "field_pointer_snapshot_id": (s_pointer_snapshot_id_edited_to_parent, "FAILED", "MANIFEST_HASH_MISMATCH"),
    "field_pointer_cursor": (s_pointer_cursor_edited, "FAILED", "POINTER_MANIFEST_MISMATCH"),
    "field_manifest_captured_at": (s_manifest_captured_at_only, "FAILED", "MANIFEST_HASH_MISMATCH"),
    "field_manifest_cursor": (s_manifest_cursor_only, "FAILED", "MANIFEST_HASH_MISMATCH"),
    "field_manifest_timestamp_with_pointer_rehash": (s_manifest_timestamp_and_pointer_hash, "FAILED", "SNAPSHOT_ID_MISMATCH"),
    "field_manifest_snapshot_id": (s_manifest_snapshot_id_field, "FAILED", "SNAPSHOT_ID_MISMATCH"),
    "field_blob_sha256": (s_manifest_blob_sha_only, "FAILED", "MANIFEST_INVALID"),
    "field_blob_size": (s_manifest_blob_size_only, "FAILED", "BLOB_SIZE_MISMATCH"),
    "field_blob_path_traversal": (s_manifest_blob_path_traversal, "FAILED", "UNSAFE_PATH"),
    "field_blob_path_absolute": (s_manifest_blob_path_absolute, "FAILED", "UNSAFE_PATH"),
    "field_blob_path_and_sha": (s_manifest_blob_path_and_sha, "FAILED", "BLOB_MISSING"),
    "field_parent_manifest": (s_parent_manifest_edited, "FAILED", "SNAPSHOT_ID_MISMATCH"),
    "manifest_schema_invalid": (s_manifest_schema_invalid, "FAILED", "MANIFEST_INVALID"),
    "manifest_timestamp_unparseable": (s_manifest_timestamp_unparseable, "FAILED", "MANIFEST_INVALID"),
    "manifest_layer_without_blob": (s_manifest_layer_without_blob, "FAILED", "MANIFEST_INVALID"),
    "manifest_layer_unknown_kind": (s_manifest_layer_unknown_kind, "FAILED", "MANIFEST_INVALID"),
    "chain_discontinuous": (s_chain_discontinuous, "FAILED", "CHAIN_INVALID"),
    "chain_cycle": (s_chain_cycle, "FAILED", "CHAIN_INVALID"),
    "chain_incremental_without_parent": (s_bootstrap_with_parent_missing_mode, "FAILED", "CHAIN_INVALID"),
    "manifest_timestamp_in_future": (s_manifest_timestamp_in_future, "FAILED", "TIMESTAMP_IN_FUTURE"),
}


class Base(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "data" / "feeds" / "nvd"
        self.publisher = Publisher(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def publish_chain(self):
        self.publisher.sync(T0)
        return self.publisher.sync(T0 + timedelta(hours=2), "2026-09-19T14:00:05+00:00")

    def resolve(self, now=NOW, max_age=MAX_AGE):
        return binding.resolve_snapshot(self.root, max_age=max_age, now=now)

    def assert_refused(self, result, outcome, reason):
        self.assertEqual((result.outcome, result.reason), (outcome, reason), result.detail)
        self.assertIsNone(result.identity)
        self.assertIsNone(result.fingerprint_component)
        self.assertEqual(result.gaps, ())
        self.assertFalse(result.usable)


class HappyPathTests(Base):
    def test_bootstrap_snapshot_resolves_ok_with_schema_valid_identity(self):
        pointer = self.publisher.sync(T0)
        result = self.resolve()
        self.assertEqual((result.outcome, result.reason, result.pointer_reads), ("OK", "VERIFIED_FRESH", 1))
        identity = result.identity
        self.assertEqual(validate_document(identity, "vulnerability-database-identity.schema.json"), [])
        manifest = read(manifest_path(self.root))
        self.assertEqual(identity["snapshot_id"], pointer["snapshot_id"])
        self.assertEqual(identity["manifest_sha256"], pointer["manifest_sha256"])
        self.assertEqual(identity["manifest_sha256"], execution_state.file_hash(manifest_path(self.root)))
        self.assertEqual(identity["retrieved_at"], "2026-09-19T12:00:05.000Z")
        self.assertEqual(identity["cursor"], manifest["cursor"])
        self.assertEqual(identity["age_seconds"], 6 * 3600)
        self.assertEqual(identity["max_age_seconds"], 24 * 3600)
        self.assertEqual(identity["freshness"], "fresh")
        self.assertEqual(identity["match_basis"], "cpe")
        self.assertEqual(identity["file_count"], 1)
        self.assertEqual(identity["total_bytes"], len(self.publisher.compressed))
        self.assertEqual(identity["chain_snapshot_ids"], [pointer["snapshot_id"]])
        self.assertTrue(any("coverage gap" in item and "never 'no known vulnerabilities'" in item
                            for item in identity["limitations"]))

    def test_incremental_chain_verifies_parent_and_counts_every_blob(self):
        pointer = self.publish_chain()
        self.assertEqual(nvd_feed.verify(self.root)["chain_length"], 2)
        identity = self.resolve().identity
        self.assertEqual(identity["snapshot_mode"], "incremental")
        self.assertEqual(identity["chain_snapshot_ids"], [pointer["snapshot_id"], identity["parent_snapshot_id"]])
        self.assertEqual(identity["file_count"], 2)
        self.assertEqual(identity["total_bytes"], sum(path.stat().st_size for path in (self.root / "blobs").iterdir()))
        self.assertEqual(identity["age_seconds"], 4 * 3600)

    def test_stale_snapshot_is_ok_with_gaps_with_age_and_policy_recorded(self):
        self.publisher.sync(T0)
        result = self.resolve(now=T0 + timedelta(hours=30))
        self.assertEqual((result.outcome, result.reason), ("OK_WITH_GAPS", "VERIFIED_STALE"))
        self.assertEqual(result.identity["freshness"], "stale")
        self.assertEqual(len(result.gaps), 1)
        gap = result.gaps[0]
        self.assertEqual((gap["id"], gap["age_seconds"], gap["max_age_seconds"]),
                         ("nvd-snapshot-older-than-policy", 30 * 3600, 24 * 3600))
        self.assertIsNotNone(result.fingerprint_component)

    def test_age_exactly_at_policy_is_fresh_and_one_second_over_is_stale(self):
        self.publisher.sync(T0)
        self.assertEqual(self.resolve(now=T0 + MAX_AGE).outcome, "OK")
        self.assertEqual(self.resolve(now=T0 + MAX_AGE + timedelta(seconds=1)).outcome, "OK_WITH_GAPS")

    def test_orphan_blob_from_a_failed_refresh_is_a_producible_state_and_not_a_failure(self):
        self.publisher.sync(T0)
        before = set((self.root / "blobs").iterdir())
        self.publisher.fail_after_pages = 1
        with self.assertRaisesRegex(OSError, "refresh interrupted"):
            self.publisher.sync(T0 + timedelta(hours=2))
        self.assertEqual(len(set((self.root / "blobs").iterdir()) - before), 1, "publisher left no orphan blob")
        result = self.resolve()
        self.assertEqual(result.outcome, "OK")
        self.assertEqual(result.identity["file_count"], 1)

    def test_unbound_pointer_published_at_is_not_used_for_anything(self):
        self.publisher.sync(T0)
        before = self.resolve()
        edit_pointer(self.root, published_at="1999-01-01T00:00:00+00:00")
        after = self.resolve()
        self.assertEqual(after.outcome, "OK")
        self.assertEqual(after.identity, before.identity)

    def test_documented_limit_consistent_rewrite_of_the_whole_root_is_not_detectable(self):
        """Nothing outside the publication root anchors it. This pins the honest limit stated in
        the doc: integrity against corruption, not authentication of the publisher."""
        self.publisher.sync(T0)
        self.assertEqual(self.resolve(now=T0 + timedelta(hours=30)).outcome, "OK_WITH_GAPS")
        edit_manifest(self.root, _set("cursor", "2026-09-20T17:00:00.000Z"), rebind="full")
        edit_manifest(self.root, _set("captured_at", "2026-09-20T17:00:00+00:00"), rebind="full")
        self.assertEqual(self.resolve(now=T0 + timedelta(hours=30)).outcome, "OK")


class RequiredInputTests(Base):
    def test_every_safety_input_is_required(self):
        parameters = inspect.signature(binding.resolve_snapshot).parameters
        for name in ("data_root", "max_age", "now"):
            self.assertIs(parameters[name].default, inspect.Parameter.empty, name)
        with self.assertRaises(TypeError):
            binding.resolve_snapshot(max_age=MAX_AGE, now=NOW)
        with self.assertRaises(TypeError):
            binding.resolve_snapshot(self.root, now=NOW)
        with self.assertRaises(TypeError):
            binding.resolve_snapshot(self.root, max_age=MAX_AGE)
        with self.assertRaises(TypeError):
            binding.resolve_snapshot(self.root, MAX_AGE, NOW)

    def test_none_and_wrong_types_are_rejected_not_defaulted(self):
        for kwargs, error, text in [
            ({"data_root": None}, TypeError, "data_root must be a non-empty path"),
            ({"data_root": ""}, TypeError, "data_root must be a non-empty path"),
            ({"max_age": None}, TypeError, "max_age must be a datetime.timedelta"),
            ({"max_age": 86400}, TypeError, "max_age must be a datetime.timedelta"),
            ({"max_age": timedelta(0)}, ValueError, "max_age must be greater than zero"),
            ({"now": None}, TypeError, "now must be a datetime.datetime"),
            ({"now": datetime(2026, 9, 20)}, ValueError, "now must be timezone-aware"),
        ]:
            arguments = {"data_root": self.root, "max_age": MAX_AGE, "now": NOW, **kwargs}
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(error, text):
                binding.resolve_snapshot(arguments.pop("data_root"), **arguments)

    def test_environment_root_is_ignored(self):
        self.publisher.sync(T0)
        with patch.dict(os.environ, {"APPSEC_NVD_ROOT": str(self.root)}):
            result = binding.resolve_snapshot(self.root.parent / "absent", max_age=MAX_AGE, now=NOW)
        self.assert_refused(result, "BLOCKED", "DATA_ROOT_MISSING")


class ScenarioTests(Base):
    """One generated test per wrong state; see SCENARIOS."""

    def run_scenario(self, name):
        mutate, outcome, reason = SCENARIOS[name]
        self.publish_chain()
        self.assertEqual(self.resolve().outcome, "OK")
        mutate(self.root)
        self.assert_refused(self.resolve(), outcome, reason)

    def test_error_details_say_what_is_enforced(self):
        expected = {
            "partial_blob_missing": "listed by the snapshot chain but absent; the snapshot is partial",
            "extra_file_in_snapshot": "must contain exactly manifest.json; unexpected entries: ['unlisted.json.gz']",
            "field_pointer_cursor": "is not the manifest cursor",
            "field_blob_sha256": "blob.path is not the content address of",
            "field_blob_size": "bytes, the manifest records 1",
            "field_blob_path_traversal": "must be blobs/sha256-<64 hex>.json.gz relative to the NVD root",
            "manifest_timestamp_in_future": "is later than now",
            "snapshot_missing": "does not exist",
            "chain_discontinuous": "does not start at the cursor of its parent",
        }
        for name, text in expected.items():
            with self.subTest(name=name):
                self.tearDown()
                self.setUp()
                self.publish_chain()
                SCENARIOS[name][0](self.root)
                self.assertIn(text, self.resolve().detail)


def _scenario_test(name):
    def test(self):
        self.run_scenario(name)
    return test


for _name in SCENARIOS:
    setattr(ScenarioTests, f"test_scenario_{_name}", _scenario_test(_name))


class LeaseTests(Base):
    def lease_states(self):
        lease = self.root / "locks" / "lease.json"
        record = read(lease)
        fresh = {**record, "status": "RUNNING",
                 "lease_expires_at": nvd_feed.timestamp(nvd_feed.utcnow() + timedelta(minutes=3))}
        stale = {**record, "status": "RUNNING", "lease_expires_at": "2001-01-01T00:00:00.000Z"}
        return {"held-fresh": json.dumps(fresh), "held-expired": json.dumps(stale),
                "corrupt": "{not json", "empty": ""}

    def test_held_stale_or_corrupt_lease_never_changes_the_result_and_is_never_touched(self):
        self.publisher.sync(T0)
        baseline = self.resolve()
        lease = self.root / "locks" / "lease.json"
        for name, text in self.lease_states().items():
            with self.subTest(lease=name):
                lease.write_text(text)
                before = tree_state(self.root)
                self.assertEqual(self.resolve(), baseline)
                self.assertEqual(tree_state(self.root), before)

    def test_reader_succeeds_while_the_publisher_holds_the_kernel_writer_lock(self):
        self.publisher.sync(T0)
        baseline = self.resolve()
        with nvd_feed.WriterLease(self.root, "attempt-held", "coordinator-held", None):
            self.assertEqual(read(self.root / "locks" / "lease.json")["status"], "RUNNING")
            self.assertEqual(self.resolve(), baseline)
            with self.assertRaises(execution_state.Blocked):
                execution_state.Lock(self.root / "locks" / "writer.lock").__enter__()

    def test_lease_directory_replaced_by_junk_does_not_matter(self):
        self.publisher.sync(T0)
        baseline = self.resolve()
        shutil.rmtree(self.root / "locks")
        (self.root / "locks").write_text("junk")
        self.assertEqual(self.resolve(), baseline)

    def test_module_source_never_names_the_lease_or_lock(self):
        source = Path(binding.__file__).read_text()
        for name in ("lease.json", "writer.lock", "locks", "flock", "msvcrt"):
            self.assertNotIn(name, source)


class PointerSwapTests(Base):
    def test_pointer_swapped_mid_read_never_mixes_generations(self):
        first = self.publisher.sync(T0)
        real_hash = binding._hash_file
        state = {"swapped": False}

        def swapping_hash(path):
            if not state["swapped"]:
                state["swapped"] = True
                self.publisher.sync(T0 + timedelta(hours=2), "2026-09-19T14:00:05+00:00")
            return real_hash(path)

        with patch.object(binding, "_hash_file", swapping_hash):
            result = self.resolve()
        second = read(self.root / "current.json")
        self.assertNotEqual(first["snapshot_id"], second["snapshot_id"])
        self.assertEqual(result.outcome, "OK")
        self.assertEqual(result.pointer_reads, 2)
        self.assertEqual(result.identity, self.resolve().identity)
        self.assertEqual((result.identity["snapshot_id"], result.identity["manifest_sha256"]),
                         (second["snapshot_id"], second["manifest_sha256"]))

    def test_pointer_that_keeps_moving_yields_one_fully_verified_generation_after_bounded_reads(self):
        self.publisher.sync(T0)
        real_verify = binding._verify_once
        calls = []

        def verify_then_publish(root, pointer_bytes):
            verified = real_verify(root, pointer_bytes)
            calls.append(json.loads(pointer_bytes))
            hours = 2 * len(calls)
            self.publisher.sync(T0 + timedelta(hours=hours), f"2026-09-19T{12 + hours}:00:05+00:00")
            return verified

        with patch.object(binding, "_verify_once", verify_then_publish):
            result = self.resolve(now=T0 + timedelta(hours=10))
        self.assertEqual(result.pointer_reads, binding.MAX_POINTER_READS)
        self.assertEqual(len(calls), binding.MAX_POINTER_READS)
        verified = calls[-1]
        self.assertEqual(result.outcome, "OK")
        self.assertEqual((result.identity["snapshot_id"], result.identity["manifest_sha256"], result.identity["cursor"]),
                         (verified["snapshot_id"], verified["manifest_sha256"], verified["cursor"]))
        self.assertNotEqual(read(self.root / "current.json")["snapshot_id"], verified["snapshot_id"])

    def test_pointer_swapped_to_a_corrupt_generation_fails_closed(self):
        self.publisher.sync(T0)
        real_hash = binding._hash_file
        state = {"swapped": False}

        def swapping_hash(path):
            if not state["swapped"]:
                state["swapped"] = True
                self.publisher.sync(T0 + timedelta(hours=2), "2026-09-19T14:00:05+00:00")
                edit_pointer(self.root, manifest_sha256="0" * 64)
            return real_hash(path)

        with patch.object(binding, "_hash_file", swapping_hash):
            self.assert_refused(self.resolve(), "FAILED", "MANIFEST_HASH_MISMATCH")


class FingerprintTests(Base):
    def test_same_snapshot_same_component_regardless_of_now_and_policy_within_freshness(self):
        self.publisher.sync(T0)
        components = {self.resolve(now=T0 + timedelta(hours=hours), max_age=timedelta(hours=limit)).fingerprint_component
                      for hours, limit in [(1, 24), (2, 24), (23, 24), (24, 24), (5, 6), (5, 1000)]}
        self.assertEqual(len(components), 1)

    def test_component_contains_snapshot_id_and_manifest_hash_and_excludes_clock_fields(self):
        pointer = self.publisher.sync(T0)
        result = self.resolve()
        component = json.loads(result.fingerprint_component)
        self.assertEqual(component["snapshot_id"], pointer["snapshot_id"])
        self.assertEqual(component["manifest_sha256"], pointer["manifest_sha256"])
        self.assertEqual(component["content_sha256"], result.identity["content_sha256"])
        self.assertEqual(component["match_basis"], "cpe")
        for excluded in ("age_seconds", "evaluated_at", "max_age_seconds", "retrieved_at"):
            self.assertNotIn(excluded, component)
        self.assertEqual(result.fingerprint_component, binding.fingerprint_component(result.identity))

    def test_crossing_the_freshness_boundary_changes_the_component_exactly_once(self):
        self.publisher.sync(T0)
        fresh = self.resolve(now=T0 + timedelta(hours=1)).fingerprint_component
        stale = self.resolve(now=T0 + timedelta(hours=25)).fingerprint_component
        staler = self.resolve(now=T0 + timedelta(days=400)).fingerprint_component
        self.assertNotEqual(fresh, stale)
        self.assertEqual(stale, staler)

    def test_new_snapshot_changes_the_component(self):
        self.publisher.sync(T0)
        first = self.resolve().fingerprint_component
        self.publisher.sync(T0 + timedelta(hours=2), "2026-09-19T14:00:05+00:00")
        self.assertNotEqual(first, self.resolve().fingerprint_component)

    def test_component_refuses_a_record_that_is_not_a_valid_identity(self):
        self.publisher.sync(T0)
        identity = self.resolve().identity
        for broken in (None, {}, {**identity, "match_basis": "purl"}, {**identity, "extra": 1},
                       {key: value for key, value in identity.items() if key != "content_sha256"}):
            with self.subTest(broken=broken), self.assertRaisesRegex(ValueError, "identity record violates"):
                binding.fingerprint_component(broken)


class InvariantTests(Base):
    def sweep(self):
        """Yields (name, Resolution) for every scenario plus the usable states."""
        for name, (mutate, _, _) in SCENARIOS.items():
            self.tearDown()
            self.setUp()
            self.publish_chain()
            mutate(self.root)
            before = tree_state(self.root) if self.root.exists() else None
            result = self.resolve()
            self.assertEqual(tree_state(self.root) if self.root.exists() else None, before, f"{name}: resolver wrote")
            yield name, result
        self.tearDown()
        self.setUp()
        self.publish_chain()
        before = tree_state(self.root)
        yield "fresh", self.resolve()
        yield "stale", self.resolve(now=T0 + timedelta(days=30))
        self.assertEqual(tree_state(self.root), before, "resolver wrote on a usable snapshot")

    def test_only_ok_and_ok_with_gaps_ever_yield_identity_or_fingerprint_and_nothing_is_written(self):
        seen = set()
        for name, result in self.sweep():
            with self.subTest(name=name):
                seen.add(result.outcome)
                self.assertIn(result.outcome, binding.OUTCOMES)
                usable = result.outcome in ("OK", "OK_WITH_GAPS")
                self.assertEqual(result.identity is not None, usable)
                self.assertEqual(result.fingerprint_component is not None, usable)
        self.assertEqual(seen, set(binding.OUTCOMES))

    def test_resolution_cannot_be_constructed_in_a_contradictory_state(self):
        with self.assertRaisesRegex(ValueError, "only for OK and OK_WITH_GAPS"):
            binding.Resolution("FAILED", "READ_ERROR", "x", {"a": 1}, "c", (), 1)
        with self.assertRaisesRegex(ValueError, "only for OK and OK_WITH_GAPS"):
            binding.Resolution("OK", "VERIFIED_FRESH", "x", None, None, (), 1)
        with self.assertRaisesRegex(ValueError, "does not belong to outcome"):
            binding.Resolution("OK", "POINTER_MISSING", "x", {"a": 1}, "c", (), 1)
        with self.assertRaisesRegex(ValueError, "named gap"):
            binding.Resolution("OK_WITH_GAPS", "VERIFIED_STALE", "x", {"a": 1}, "c", (), 1)

    def test_every_reason_is_reachable_or_documented(self):
        reached = {reason for _, _, reason in SCENARIOS.values()} | {"VERIFIED_FRESH", "VERIFIED_STALE"}
        self.assertEqual(set(binding.REASONS), reached)
        doc = (ROOT.parent / "docs" / "sca-nvd-snapshot-binding.md").read_text()
        for reason in binding.REASONS:
            self.assertIn(f"`{reason}`", doc)


class NoNetworkTests(Base):
    FORBIDDEN = {"socket", "ssl", "urllib", "http", "requests", "ftplib", "smtplib", "telnetlib", "asyncio",
                 "subprocess", "multiprocessing", "xmlrpc", "socketserver", "ctypes", "importlib",
                 "nvd_feed", "execution_state", "reference_snapshots"}
    ALLOWED = {"__future__", "dataclasses", "datetime", "hashlib", "json", "os", "pathlib", "re", "stat",
               "schema_validate"}

    def imported(self, path):
        names = set()
        for node in ast.walk(ast.parse(Path(path).read_text())):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0)
                names.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"__import__", "eval", "exec", "compile"})
        return names

    def test_module_imports_are_an_allowlist_with_nothing_network_capable(self):
        names = self.imported(binding.__file__)
        self.assertEqual(names & self.FORBIDDEN, set())
        self.assertEqual(names - self.ALLOWED, set())
        self.assertEqual(self.imported(ROOT / "schema_validate.py") & self.FORBIDDEN, set())
        source = Path(binding.__file__).read_text()
        for call in ("os.system", "os.popen", "os.exec", "os.spawn", "os.fork"):
            self.assertNotIn(call, source)

    def test_importing_the_module_in_a_clean_interpreter_loads_no_network_module(self):
        script = ("import sys; sys.path.insert(0, sys.argv[1]); import sca_nvd_snapshot; "
                  "bad = sorted(set(sys.modules) & {'socket', '_socket', 'ssl', '_ssl', 'urllib.request', 'http.client', "
                  "'subprocess', 'ftplib', 'requests', 'asyncio', 'nvd_feed', 'execution_state'}); print(bad)")
        done = subprocess.run([sys.executable, "-B", "-I", "-c", script, str(ROOT)], capture_output=True, text=True, check=True)
        self.assertEqual(done.stdout.strip(), "[]")

    def test_socket_is_never_touched_in_any_scenario(self):
        def refuse(*args, **kwargs):
            raise AssertionError("the NVD snapshot binding opened a socket")

        roots = []
        for name, (mutate, outcome, reason) in SCENARIOS.items():
            directory = Path(self.temporary.name) / name / "data" / "nvd"
            publisher = Publisher(directory)
            publisher.sync(T0)
            publisher.sync(T0 + timedelta(hours=2), "2026-09-19T14:00:05+00:00")
            mutate(directory)
            roots.append((directory, outcome, reason))
        self.publish_chain()
        with patch.object(socket, "socket", refuse), patch.object(socket, "create_connection", refuse), \
                patch.object(socket, "getaddrinfo", refuse):
            for directory, outcome, reason in roots:
                result = binding.resolve_snapshot(directory, max_age=MAX_AGE, now=NOW)
                self.assertEqual((result.outcome, result.reason), (outcome, reason))
            self.assertEqual(self.resolve().outcome, "OK")
            self.assertEqual(self.resolve(now=T0 + timedelta(days=9)).outcome, "OK_WITH_GAPS")


class PublisherParityTests(Base):
    """The re-implemented read helpers must agree with the publisher they are bound to."""

    def test_snapshot_id_rule_matches_the_publisher(self):
        self.publish_chain()
        manifest = read(manifest_path(self.root))
        unsigned = {key: value for key, value in manifest.items() if key != "snapshot_id"}
        self.assertEqual(binding.snapshot_id_of(manifest), nvd_feed._snapshot_id(unsigned))
        self.assertEqual(binding.snapshot_id_of(manifest), manifest["snapshot_id"])

    def test_constants_match_the_publisher(self):
        self.assertEqual(binding.MANIFEST_SCHEMA_ID, nvd_feed.SCHEMA)
        self.publisher.sync(T0)
        self.assertEqual(self.resolve().identity["publisher_manifest_schema"], nvd_feed.SCHEMA)

    def test_beneath_agrees_with_execution_state(self):
        self.publisher.sync(T0)
        link = self.root / "link"
        link.symlink_to(self.root / "blobs", target_is_directory=True)
        for candidate in (self.root / "blobs" / "x", self.root / ".." / "x", Path("/etc/passwd"),
                          link / "x", self.root, self.root / "snapshots" / ".." / ".." / "y"):
            outcomes = []
            for function in (binding.beneath, execution_state.beneath):
                try:
                    outcomes.append(str(function(self.root, candidate)))
                except ValueError as exc:
                    outcomes.append("ValueError: " + str(exc))
            self.assertEqual(outcomes[0], outcomes[1], candidate)

    def test_binding_agrees_with_publisher_verify_on_the_states_both_check(self):
        self.publish_chain()
        self.assertEqual(nvd_feed.verify(self.root)["snapshot_id"], self.resolve().identity["snapshot_id"])
        s_blob_tampered_same_size(self.root)
        with self.assertRaisesRegex(ValueError, "blob integrity"):
            nvd_feed.verify(self.root)
        self.assertEqual(self.resolve().outcome, "FAILED")



class IdentityBindingTests(Base):
    """A returned or persisted identity record is not an authority. `freshness` enters the input
    fingerprint, so it must be bound to the numbers it is derived from, the identity inside a
    Resolution must not be editable after the component was computed, and a record read back from
    disk is only accepted by re-verifying the snapshot."""

    STALE_NOW = T0 + timedelta(days=30)

    def setUp(self):
        super().setUp()
        self.publish_chain()
        self.fresh = self.resolve()
        self.stale = self.resolve(now=self.STALE_NOW)
        self.assertEqual((self.fresh.outcome, self.stale.outcome), ("OK", "OK_WITH_GAPS"))

    def copy(self, resolution):
        import copy
        return copy.deepcopy(resolution.identity)

    def test_stale_identity_relabelled_fresh_cannot_obtain_the_fresh_component(self):
        forged = self.copy(self.stale)
        forged["freshness"] = "fresh"
        with self.assertRaisesRegex(ValueError, "freshness must be 'stale'"):
            binding.fingerprint_component(forged)

    def test_each_derived_field_is_bound_to_what_it_is_derived_from(self):
        cases = {
            "freshness": ("fresh", "freshness must be 'stale'"),
            "age_seconds": (1, "age_seconds must equal evaluated_at minus cursor"),
            "max_age_seconds": (10 ** 9, "freshness must be 'fresh'"),
            "evaluated_at": ("2026-09-19T12:00:01.000Z", "age_seconds must equal|must not be later"),
            "cursor": ("2026-10-19T00:00:00.000Z", "age_seconds must equal|must not be later"),
            "snapshot_id": ("sha256-0123456789abcdef", "snapshot_id must appear in chain_snapshot_ids"),
        }
        for field, (value, message) in cases.items():
            forged = self.copy(self.stale)
            self.assertNotEqual(forged[field], value, field)
            forged[field] = value
            with self.assertRaisesRegex(ValueError, message, msg=field):
                binding.fingerprint_component(forged)

    def test_consistently_forged_age_is_self_consistent_and_that_is_why_verify_identity_exists(self):
        # Edit evaluated_at, age_seconds and freshness together: the record now agrees with itself.
        forged = self.copy(self.stale)
        forged.update(evaluated_at=self.fresh.identity["evaluated_at"], age_seconds=self.fresh.identity["age_seconds"],
                      max_age_seconds=self.fresh.identity["max_age_seconds"], freshness="fresh")
        self.assertEqual(binding.identity_consistency_errors(forged), [])
        self.assertEqual(binding.fingerprint_component(forged), self.fresh.fingerprint_component)
        # ...so a consumer of a PERSISTED record must go through verify_identity, which ignores the
        # record's own freshness and re-derives it at the caller's `now`.
        verified = binding.verify_identity(forged, self.root, max_age=MAX_AGE, now=self.STALE_NOW)
        self.assertEqual((verified.outcome, verified.identity["freshness"]), ("OK_WITH_GAPS", "stale"))
        self.assertEqual(verified.fingerprint_component, self.stale.fingerprint_component)

    def test_identity_inside_a_resolution_is_read_only_at_every_depth(self):
        for mutate in (lambda i: i.__setitem__("freshness", "fresh"), lambda i: i.update(freshness="fresh"),
                       lambda i: i.pop("freshness"), lambda i: i["limitations"].append("x"),
                       lambda i: i["chain_snapshot_ids"].clear(), lambda i: i.__delitem__("snapshot_id")):
            with self.assertRaisesRegex(TypeError, "read-only"):
                mutate(self.stale.identity)
        self.assertEqual(self.stale.identity["freshness"], "stale")
        self.assertEqual(binding.fingerprint_component(self.stale.identity), self.stale.fingerprint_component)

    def test_a_copy_is_an_ordinary_editable_json_document(self):
        duplicate = self.copy(self.fresh)
        self.assertIs(type(duplicate), dict)
        self.assertIs(type(duplicate["limitations"]), list)
        duplicate["limitations"].append("edited copy")
        self.assertEqual(json.loads(json.dumps(self.fresh.identity)), json.loads(json.dumps(self.copy(self.fresh))))
        self.assertEqual(binding.validate_document(self.fresh.identity, binding.IDENTITY_SCHEMA_FILE), [])

    def test_resolution_refuses_a_component_that_is_not_its_identitys(self):
        with self.assertRaisesRegex(ValueError, "does not belong to this identity"):
            binding.Resolution("OK", "VERIFIED_FRESH", "x", self.copy(self.fresh), self.stale.fingerprint_component, (), 1)
        with self.assertRaisesRegex(ValueError, "freshness contradicts the outcome"):
            binding.Resolution("OK", "VERIFIED_FRESH", "x", self.copy(self.stale), self.stale.fingerprint_component, (), 1)

    def test_verify_identity_has_no_optional_inputs(self):
        record = self.copy(self.fresh)
        for kwargs in ({}, {"max_age": MAX_AGE}, {"now": NOW}):
            with self.assertRaises(TypeError):
                binding.verify_identity(record, self.root, **kwargs)
        with self.assertRaises(TypeError):
            binding.verify_identity(record, max_age=MAX_AGE, now=NOW)

    def test_verify_identity_rejects_a_record_for_any_other_snapshot_content(self):
        for field, value in (("snapshot_id", None), ("manifest_sha256", "0" * 64), ("content_sha256", "1" * 64),
                             ("file_count", 99), ("total_bytes", 1), ("retrieved_at", "2026-01-01T00:00:00.000Z")):
            record = self.copy(self.fresh)
            if field == "snapshot_id":      # keep it self-consistent so only verify_identity can object
                value = record["chain_snapshot_ids"][-1] if record["chain_snapshot_ids"][-1] != record["snapshot_id"] else record["chain_snapshot_ids"][0]
            self.assertNotEqual(record[field], value, field)
            record[field] = value
            with self.assertRaisesRegex(binding.IdentityMismatch, f"'{field}' does not match the verified snapshot", msg=field):
                binding.verify_identity(record, self.root, max_age=MAX_AGE, now=NOW)

    def test_verify_identity_fails_closed_when_the_snapshot_no_longer_verifies(self):
        record = self.copy(self.fresh)
        s_blob_tampered_same_size(self.root)
        with self.assertRaisesRegex(binding.IdentityMismatch, "does not verify now: BLOB_HASH_MISMATCH"):
            binding.verify_identity(record, self.root, max_age=MAX_AGE, now=NOW)

    def test_every_identity_field_is_either_snapshot_bound_or_rederived(self):
        schema = binding._STORE.load(binding.IDENTITY_SCHEMA_FILE)
        rederived = {"evaluated_at", "age_seconds", "max_age_seconds", "freshness"}
        self.assertEqual(set(binding._SNAPSHOT_BOUND_FIELDS) | rederived, set(schema["properties"]))
        self.assertEqual(set(binding._SNAPSHOT_BOUND_FIELDS) & rederived, set())


if __name__ == "__main__":
    unittest.main()
