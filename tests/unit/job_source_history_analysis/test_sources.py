from __future__ import annotations

import hashlib
import json

import pytest

from appsec_review.jobs.job_source_history_analysis import discovery, sources
from .support import HEAD, PARENT


def metadata(root, *, config="", head=HEAD):
    directory = root / ".git"
    (directory / "objects/info").mkdir(parents=True)
    (directory / "refs/heads").mkdir(parents=True)
    (directory / "HEAD").write_text(head + "\n")
    (directory / "config").write_text(config)
    (directory / "refs/heads/main").write_text(HEAD + "\n")
    return directory


def test_source_resolution_head_main_packed_refs_and_observations(tmp_path):
    directory = metadata(tmp_path, config='[include]\npath=ignored\n[core]\nrepositoryformatversion=0\n',
                         head="ref: refs/heads/main")
    (directory / "refs/heads/main").unlink()
    (directory / "packed-refs").write_text(f"# comment\n^{PARENT}\n{HEAD} refs/heads/main\n")
    (directory / "shallow").write_text(f"{PARENT}\n{PARENT}\n")
    (directory / "refs/replace").mkdir()
    (directory / "refs/replace/ignored").write_text(PARENT)
    (directory / "info").mkdir()
    (directory / "info/grafts").write_text(PARENT)
    (directory / "objects/info/alternates").write_text("# comment\n\n../objects\n")
    value = sources.resolve_git_source(tmp_path)
    assert value.decision == "SUCCEEDED" and value.snapshot_commit == value.head_commit == HEAD
    assert value.mainline_ref == "refs/heads/main" and value.shallow == (PARENT,)
    assert value.observations == (
        "config_includes_ignored", "relative_alternates_inside_target", "replace_refs_ignored", "grafts_ignored")
    assert value.as_dict()["shallow"] == [PARENT]
    (directory / "HEAD").write_text(PARENT)
    assert sources.resolve_git_source(tmp_path).mainline_ref is None
    assert sources.resolve_git_source(tmp_path).snapshot_commit == PARENT
    (directory / "HEAD").write_text("unresolved")
    assert sources.resolve_git_source(tmp_path).snapshot_commit == HEAD
    assert "head_unresolved_using_mainline" in sources.resolve_git_source(tmp_path).observations
    (directory / "packed-refs").unlink()
    absent = sources.resolve_git_source(tmp_path)
    assert (absent.decision, absent.reason) == ("SKIPPED_NA", "no_commits")
    assert absent.observations[-1] == "mainline_not_found_using_head"


@pytest.mark.parametrize("damage,reason", [
    ("objects", "history_source_outside_target"), ("commondir", "linked_worktree_not_supported"),
    ("format", "unsupported_object_format"), ("partialclone", "partial_clone_objects_missing"),
    ("refstorage", "unsupported_ref_storage"), ("alternates", "alternates_unresolvable"),
    ("shallow", "shallow_file_invalid"),
], ids=["objects", "commondir", "format", "partialclone", "refstorage", "alternates", "shallow"])
def test_unsupported_git_sources_are_named_with_scope(tmp_path, damage, reason):
    directory = metadata(tmp_path)
    if damage == "objects":
        (directory / "objects").rename(directory / "saved")
        (directory / "objects").symlink_to(directory / "saved", target_is_directory=True)
    elif damage == "commondir":
        (directory / "commondir").write_text("../other")
    elif damage in {"format", "partialclone", "refstorage"}:
        key, value = {"format": ("objectformat", "other"), "partialclone": ("partialclone", "origin"),
                      "refstorage": ("refstorage", "reftable")}[damage]
        (directory / "config").write_text(f"[extensions]\n{key}={value}\n")
    elif damage == "alternates":
        (directory / "objects/info/alternates").write_text("/outside")
    else:
        (directory / "shallow").write_text("invalid")
    result = sources.resolve_git_source(tmp_path)
    assert (result.decision, result.reason, result.git_dir) == ("GAP", reason, ".git")


def test_metadata_reads_bound_symlinks_ref_paths_and_blob_ids(tmp_path):
    file = tmp_path / "metadata"
    assert sources._read(file) is None
    file.write_bytes(b"abcd")
    assert sources._read(file, 4) == b"abcd"
    with pytest.raises(ValueError, match="exceeds its bound: metadata"):
        sources._read(file, 3)
    link = tmp_path / "link"
    link.symlink_to(file)
    with pytest.raises(ValueError, match="symlinks"):
        sources._read(link)
    for ref in ("../escape", "refs/heads/../bad", "refs//bad"):
        with pytest.raises(ValueError, match="ref name is unsafe"):
            sources._resolve_ref(tmp_path, ref, "sha1")
    assert sources.blob_id(b"hello\n", "sha1") == "ce013625030ba8dba906f756967f9e9ca394464a"
    assert sources.blob_id(b"x", "sha256") == hashlib.sha256(b"blob 1\0x").hexdigest()
    assert sources._config_keys(b'#x\nkey=x\n[remote "origin"]\nurl=x\n[CORE]\nbare="true" #x\n') == (
        {"core.bare": "true"}, False)


def test_git_directory_locations_and_sha256(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    assert sources.locate_git_dir(target) == (None, "no_git_metadata")
    dot = target / ".git"
    dot.write_text("invalid")
    assert sources.locate_git_dir(target) == (None, "gitfile_unreadable")
    dot.write_text("gitdir: ../outside\n")
    assert sources.locate_git_dir(target) == (None, "history_source_outside_target")
    stored = target / "stored"
    stored.mkdir()
    dot.write_text("gitdir: stored\n")
    assert sources.locate_git_dir(target) == (stored, "gitfile")
    dot.unlink()
    dot.symlink_to(stored)
    assert sources.locate_git_dir(target) == (None, "history_source_outside_target")
    other = tmp_path / "sha256"
    directory = metadata(other, config="[extensions]\nobjectformat=sha256\n", head="a" * 64)
    (directory / "refs/heads/main").write_text("a" * 64)
    result = sources.resolve_git_source(other)
    assert result.object_format == "sha256" and result.snapshot_commit == "a" * 64


def test_metadata_discovery_is_bounded_sorted_and_detects_nested_identity(tmp_path, monkeypatch):
    metadata(tmp_path / "b")
    metadata(tmp_path / "a")
    metadata(tmp_path / "deep/nested")
    assert sources.metadata_roots(tmp_path) == ["a", "b"]
    assert sources.metadata_roots(tmp_path, ("deep/nested",)) == ["a", "b", "deep/nested"]
    before = sources.history_identity(tmp_path)
    pinned = sources.history_identity(tmp_path, ("deep/nested",))
    (tmp_path / "deep/nested/.git/HEAD").write_text(PARENT)
    assert sources.history_identity(tmp_path) == before
    assert sources.history_identity(tmp_path, ("deep/nested",)) != pinned
    assert sources.history_identity(None) == sources.history_identity(None)
    assert sources.history_identity(tmp_path, ("../bad",)) != before
    with pytest.raises(ValueError, match="root is unsafe"):
        sources.metadata_roots(tmp_path, ("../bad",))
    (tmp_path / "link").symlink_to(tmp_path / "a", target_is_directory=True)
    with pytest.raises(ValueError, match="root escapes"):
        sources.metadata_roots(tmp_path, ("link",))
    monkeypatch.setattr(sources, "MAX_SOURCES", 1)
    with pytest.raises(ValueError, match="source_count_bound"):
        sources.metadata_roots(tmp_path)
    monkeypatch.setattr(sources, "MAX_DISCOVERY_ENTRIES", 1)
    for known in ((), ("a", "b")):
        with pytest.raises(ValueError, match="discovery_bound"):
            sources.metadata_roots(tmp_path, known)


@pytest.mark.parametrize("url,api,expected", [
    ("https://github.com/acme/widget.git", "https://api.github.com", "acme/widget"),
    ("git@github.com:acme/widget.git", "https://api.github.com", "acme/widget"),
    ("ssh://git@github.com/acme/widget.git", "https://api.github.com", "acme/widget"),
    ("https://enterprise/acme/widget.git", "https://enterprise/api/v3", "acme/widget"),
    ("https://github.com.attacker/acme/widget", "https://api.github.com", None),
    ("https://github.com@attacker.invalid/acme/widget", "https://api.github.com", None),
    ("https://token@github.com/acme/widget", "https://api.github.com", None),
    ("https://github.com/acme/../widget", "https://api.github.com", None),
    ("https://github.com:444/acme/widget", "https://api.github.com", None),
    ("https://[invalid/acme/widget", "https://api.github.com", None),
    ("ext::helper", "https://api.github.com", None),
], ids=["https", "scp", "ssh", "enterprise", "host", "userinfo-host", "user", "dot-path", "port", "ipv6", "helper"])
def test_remote_discovery_never_uses_target_endpoints(url, api, expected):
    assert discovery.github_repository(url, api) == expected


def test_pinned_metadata_and_safe_roots(tmp_path):
    file = tmp_path / "record.json"
    file.write_text('{"value":1}')
    digest = hashlib.sha256(file.read_bytes()).hexdigest()
    assert discovery.read_pinned(tmp_path, "record.json", digest) == {"value": 1}
    for path in ("../bad", "/absolute", "a\\b", "a//b"):
        with pytest.raises(ValueError, match="path is unsafe"):
            discovery.read_pinned(tmp_path, path, digest)
        with pytest.raises(ValueError, match="root is unsafe"):
            discovery._safe_root(tmp_path, path)
    with pytest.raises(ValueError, match="identity mismatch"):
        discovery.read_pinned(tmp_path, "record.json", "bad")
    internal = tmp_path / "internal"
    internal.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        discovery.read_pinned(tmp_path, "internal/record.json", digest)
    link = tmp_path / "link"
    link.symlink_to(tmp_path.parent)
    with pytest.raises(ValueError, match="escapes its owner"):
        discovery.read_pinned(tmp_path, "link/record.json", digest)
    with pytest.raises(ValueError, match="root escapes"):
        discovery._safe_root(tmp_path, "link")
    assert discovery._safe_root(tmp_path, ".") == tmp_path


def test_discovery_uses_origin_and_pin_not_newer_main(tmp_path):
    target = tmp_path / "target"
    directory = metadata(target, config='[remote "origin"]\nurl=https://github.com/acme/origin.git\n', head=PARENT)
    assert discovery.origin_url(target) == "https://github.com/acme/origin.git"
    direct = discovery.discover_sources(target=target, repository=tmp_path, acquisition=None,
                                       components=[{"root": ".", "component_id": "c"}],
                                       api_base="https://api.github.com")
    assert direct[0]["github_repository"] == "acme/origin"
    assert direct[0]["git"]["snapshot_commit"] == PARENT and direct[0]["component_id"] == "c"
    acquisition = {"schema": "appsec-review/target-acquisition/1", "target_id": "target",
                   "identity": {"kind": "git", "commit": PARENT}, "spec": {"url": "https://github.com/acme/pin.git"}}
    values = discovery.discover_sources(target=target, repository=tmp_path, acquisition=acquisition, components=[],
                                       api_base="https://api.github.com", acquisition_sha256="pin")
    assert values[0]["github_repository"] == "acme/pin" and values[0]["manifest_sha256"] == "pin"
    assert values[0]["git"]["snapshot_commit"] == PARENT and values[0]["git"]["mainline_ref"] is None
    (directory / "config").write_text('[remote "origin"]\nurl=x\nurl=y\n')
    assert discovery.origin_url(target) == ""


@pytest.mark.parametrize("kind,pin,decision,reason", [
    ("perforce", HEAD, "GAP", "history_backend_unsupported:perforce"),
    ("git", "bad", "GAP", "acquisition_revision_invalid"),
    ("git", PARENT, "GAP", "acquisition_revision_mismatch"),
    ("git", HEAD, "SUCCEEDED", "resolved"),
    ("review_export", HEAD, "SUCCEEDED", "resolved"),
], ids=["backend", "invalid-pin", "mismatched-pin", "git", "review-export"])
def test_acquisition_discovery_refusals_do_not_fall_back(tmp_path, kind, pin, decision, reason):
    target = tmp_path / "target"
    metadata(target)
    value = {"schema": "appsec-review/target-acquisition/1", "target_id": "t",
             "identity": {"kind": kind, "commit": pin, "revision": pin}}
    found = discovery.discover_sources(target=target, repository=tmp_path, acquisition=value, components=[],
                                       api_base="https://api.github.com")[0]
    assert (found["source_id"], found["git"]["decision"], found["git"]["reason"]) == ("t", decision, reason)
    assert found["github_repository"] is None


def test_system_manifests_pin_each_lane_and_reject_identity_and_count(tmp_path):
    target = tmp_path / "target"
    metadata(target / "a")
    metadata(target / "b")
    manifest = {"identity": {"kind": "git", "commit": HEAD}, "target_path": "target/a"}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    acquisition = {"schema": "appsec-review/target-system-acquisition/1",
                   "components": {"a": {"manifest": "manifest.json",
                                        "manifest_sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
                                  "b": {}},
                   "identity": {"a": {"identity": manifest["identity"]}}, "spec": {"components": {"c": {}}}}
    values = discovery.discover_sources(target=target, repository=tmp_path, acquisition=acquisition,
                                       components=[], api_base="https://api.github.com")
    assert [item["source_id"] for item in values] == ["a", "b", "c"]
    assert values[0]["git"]["decision"] == "SUCCEEDED" and values[0]["git"]["git_dir"] == "a/.git"
    assert [(item["source_id"], item["git"]["reason"]) for item in values[1:]] == [
        ("b", "acquisition_source_unavailable:KeyError"), ("c", "acquisition_source_unavailable:KeyError")]
    for value, error in [({"schema": "wrong"}, "schema is unsupported"),
                         ({"schema": acquisition["schema"], "components": {}}, "count is invalid")]:
        with pytest.raises(ValueError, match=error):
            discovery.discover_sources(target=target, repository=tmp_path, acquisition=value,
                                       components=[], api_base="https://api.github.com")
