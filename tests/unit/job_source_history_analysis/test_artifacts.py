from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_source_history_analysis import job
from appsec_review.runtime import consume
from .support import artifact, context


def test_verified_reader_bounds_drain_and_hash(tmp_path):
    unit = context(tmp_path, "acquire.git_history")
    reference = artifact(unit, "raw", b"abcdef")
    with job._verified_stream(unit.job.run_root, reference) as reader:
        assert reader.read(2) == b"ab"
        for size in (-1, None, job.CHUNK_BYTES + 1):
            with pytest.raises(ValueError, match="bounded chunks only"):
                reader.read(size)
    assert reader.stream.closed and reader.digest.hexdigest() == hashlib.sha256(b"abcdef").hexdigest()
    with pytest.raises(ValueError, match="raw artifact identity mismatch"):
        with job._verified_stream(unit.job.run_root, {**reference, "sha256": "wrong"}) as reader:
            assert reader.read(6) == b"abcdef"


@pytest.mark.parametrize("damage", ["escape", "size", "missing", "symlink"])
def test_verified_reader_refuses_untrusted_file_identity(tmp_path, damage):
    unit = context(tmp_path, "acquire.git_history")
    reference = artifact(unit, "raw", b"x")
    if damage == "escape":
        reference["path"] = "../outside"
    elif damage == "size":
        reference["size_bytes"] = 2
    elif damage == "missing":
        reference["path"] = "missing"
    else:
        link = unit.job.run_root / "link"
        link.symlink_to(unit.job.run_root / reference["path"])
        reference["path"] = "link"
    with pytest.raises(ValueError, match="raw artifact identity mismatch"):
        job._VerifiedReader(unit.job.run_root, reference)


def test_read_refuses_path_or_hash_and_retain_is_bounded(tmp_path):
    unit = context(tmp_path, "acquire.git_history")
    reference = artifact(unit, "value.json", {"ok": 1})
    for changed in ({**reference, "path": "../bad"}, {**reference, "sha256": "wrong"}):
        with pytest.raises(ValueError, match="artifact identity mismatch"):
            job._read(unit.job.run_root, changed)
    source, destination = unit.job.run_root / "source", unit.job.run_root / "protected/raw"
    source.write_bytes(b"abc")
    result = job._retain(unit.job.run_root, source, destination, 3)
    assert result["size_bytes"] == 3 and not source.exists() and destination.read_bytes() == b"abc"
    source.write_bytes(b"abcd")
    with pytest.raises(job.HistoryBoundError, match="git_output_limit_reached"):
        job._retain(unit.job.run_root, source, destination, 3)
    assert source.exists() and not destination.with_name(".raw.tmp").exists()
    source.unlink()
    source.symlink_to(destination)
    with pytest.raises(ValueError, match="not a regular run-owned file"):
        job._retain(unit.job.run_root, source, destination, 3)


@pytest.mark.parametrize("damage", ["changed", "missing", "escape", "symlink"])
def test_changelog_bounded_reader_integrity_refusals(tmp_path, damage):
    target = tmp_path / "target"
    target.mkdir()
    path = target / "ChangeLog"
    path.write_bytes(b"abc")
    item = {"path": "ChangeLog", "sha256": hashlib.sha256(b"abc").hexdigest()}
    assert job._read_bounded(target, item, 2) == (b"ab", 3)
    if damage == "changed":
        path.write_bytes(b"abd")
    elif damage == "missing":
        path.unlink()
    elif damage == "escape":
        item["path"] = "../outside"
    else:
        path.unlink()
        path.symlink_to(tmp_path / "outside")
    with pytest.raises(job.ChangelogIntegrityError, match="accepted target"):
        job._read_bounded(target, item, 2)


def test_accepted_upstream_helpers_and_input_identity(tmp_path, monkeypatch):
    unit = context(tmp_path, "publish.publish_handoff")
    calls = []
    monkeypatch.setattr(consume, "accepted_upstream", lambda root, key, **kwargs:
                        calls.append((root, key, kwargs)) or SimpleNamespace(as_tuple=lambda: ({"ok": 1}, "pin")))
    assert job._accepted_handoff(tmp_path, "job_target_catalog") == ({"ok": 1}, "pin")
    assert calls == [(tmp_path, "job_target_catalog", {})]
    monkeypatch.setattr(consume, "has_accepted_upstream", lambda *args: False)
    monkeypatch.setattr(job, "history_identity", lambda *args: ("identity", args))
    assert job._run_history_identity(tmp_path, unit.job.run_root) == ("identity", (tmp_path,))
    monkeypatch.setattr(consume, "has_accepted_upstream", lambda *args: True)
    monkeypatch.setattr(job, "_load_inputs", lambda root: {"components": [{"root": "nested"}]})
    assert job._run_history_identity(tmp_path, unit.job.run_root) == ("identity", (tmp_path, ("nested",)))


@pytest.mark.parametrize("kind", ["absent", "valid", "wrong-history", "missing-hotspots", "wrong-hotspots", "stale"])
def test_load_accepted_history_and_hotspots_verify_schema_and_snapshot(tmp_path, monkeypatch, kind):
    unit = context(tmp_path, "publish.publish_handoff")
    hotspots = artifact(unit, "hotspots.json", {
        "schema": "wrong" if kind == "wrong-hotspots" else job.HOTSPOT_SCHEMA,
        "target_snapshot": "other" if kind == "stale" else "snapshot", "entries": []})
    history = artifact(unit, "history.json", {
        "schema": "wrong" if kind == "wrong-history" else job.SCHEMA, "target_snapshot": "snapshot",
        "hotspots": {} if kind == "missing-hotspots" else {"artifact": hotspots},
        "sources": {"git": {"reason": "no_bound_history"}}})
    handoff = {"outputs": {"publish.publish_handoff": {"artifact": history}}}
    monkeypatch.setattr(consume, "accepted_upstream", lambda *args, **kwargs:
                        None if kind == "absent" else SimpleNamespace(as_tuple=lambda: (handoff, "pin")))
    monkeypatch.setattr(job, "swift_enabled_from_run", lambda root: False)
    if kind in {"wrong-history", "wrong-hotspots", "stale"}:
        with pytest.raises(ValueError, match="unsupported"):
            job.load_accepted_hotspots(unit.job.run_root)
    else:
        value = job.load_accepted_hotspots(unit.job.run_root)
        if kind == "absent":
            assert value is None
        elif kind == "missing-hotspots":
            assert value == {"schema": job.HOTSPOT_SCHEMA, "status": "unavailable", "reason": "no_bound_history",
                             "entries": [], "handoff_sha256": "pin"}
        else:
            assert value == {"schema": job.HOTSPOT_SCHEMA, "target_snapshot": "snapshot", "entries": [],
                             "handoff_sha256": "pin"}


def test_rank_candidate_order_and_reason_are_explicit():
    assert job._ranking_candidates({
        "b": {"rank_eligibility": "eligible", "churn_lines": 2},
        "a": {"rank_eligibility": "eligible", "churn_lines": 2},
        "c": {"rank_eligibility": "excluded", "churn_lines": 9}}) == ["a", "b"]
    assert job._reason("unavailable:why") == "why" and job._reason("complete") == "complete"
