"""Rule-pack verification, customer prerequisite hashing isolation, and checkpoint identity tests."""

from __future__ import annotations

from dataclasses import replace
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from appsec_review.config.assurance import ComponentReleases
from appsec_review.container_runtime import load_catalog
from appsec_review.jobs.job_evidence_collection import job
from appsec_review.jobs.job_evidence_collection.adapters import ScanCatalog, adapter_registry
from appsec_review.rulepacks.sei_cert.pack import PackError, verify_pack

from .support import DIGEST, ROOT, make_unit_context


def _append(relative: str, data: str = "\n"):
    def mutate(pack: Path) -> None:
        with (pack / relative).open("a", encoding="utf-8") as stream:
            stream.write(data)

    return mutate


def _remove(relative: str):
    return lambda pack: (pack / relative).unlink()


def _add(relative: str, data: str = "{}\n"):
    return lambda pack: (pack / relative).write_text(data, encoding="utf-8")


def _symlink(pack: Path) -> None:
    (pack / "mappings" / "c-alias.json").symlink_to("c.json")


def _fifo(pack: Path) -> None:
    try:
        os.mkfifo(pack / "fixtures" / "c" / "pipe.c")
    except OSError as exc:
        if exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            pytest.skip("test filesystem does not support FIFOs")
        raise


def _duplicate_lock_key(pack: Path) -> None:
    lock = pack / "pack.lock.json"
    text = lock.read_text(encoding="utf-8")
    lock.write_text(
        text.replace("{\n", '{\n  "schema": "appsec-review/sei-cert-rule-pack-lock/1",\n', 1),
        encoding="utf-8",
    )


PACK_MUTATIONS = {
    "rule-changed": (_append("rules/c/msc30-c.yml", "# changed\n"), "locked file changed: rules/c/msc30-c.yml"),
    "rule-removed": (_remove("rules/c/msc30-c.yml"), "locked file is missing: rules/c/msc30-c.yml"),
    "rule-added": (
        _add("rules/c/extra.yml", "rules: []\n"),
        "unexpected file not recorded in pack.lock.json: rules/c/extra.yml",
    ),
    "mapping-changed": (_append("mappings/c.json"), "locked file changed: mappings/c.json"),
    "mapping-removed": (_remove("mappings/c.json"), "locked file is missing: mappings/c.json"),
    "mapping-added": (_add("mappings/extra.json"), "unexpected file not recorded in pack.lock.json: mappings/extra.json"),
    "source-index-changed": (
        _append("sources/cert-source-index.json"),
        "locked file changed: sources/cert-source-index.json",
    ),
    "source-index-removed": (
        _remove("sources/cert-source-index.json"),
        "locked file is missing: sources/cert-source-index.json",
    ),
    "source-index-added": (
        _add("sources/extra.json"),
        "unexpected file not recorded in pack.lock.json: sources/extra.json",
    ),
    "fixture-changed": (_append("fixtures/c/msc30-c.c", "/* changed */\n"), "locked file changed: fixtures/c/msc30-c.c"),
    "fixture-removed": (_remove("fixtures/c/msc30-c.c"), "locked file is missing: fixtures/c/msc30-c.c"),
    "fixture-added": (
        _add("fixtures/c/extra.c", "int x;\n"),
        "unexpected file not recorded in pack.lock.json: fixtures/c/extra.c",
    ),
    "manifest-changed": (_append("pack.json"), "locked file changed: pack.json"),
    "manifest-removed": (_remove("pack.json"), "pack.json is missing"),
    "coverage-doc-changed": (_append("COVERAGE.md", "extra\n"), "locked file changed: COVERAGE.md"),
    "coverage-doc-removed": (_remove("COVERAGE.md"), "locked file is missing: COVERAGE.md"),
    "unexpected-root-file": (_add("NOTES.txt", "note\n"), "unexpected file not recorded in pack.lock.json: NOTES.txt"),
    "symlink": (_symlink, "symlinks are not allowed in the pack: mappings/c-alias.json"),
    "fifo": (_fifo, "non-regular file is not allowed in the pack: fixtures/c/pipe.c"),
    "duplicate-lock-key": (_duplicate_lock_key, "pack.lock.json: duplicate JSON key 'schema'"),
}


def test_unmodified_sei_cert_pack_identity_labels_both_digests(tmp_path: Path) -> None:
    pack = tmp_path / "sei-cert"
    shutil.copytree(ROOT / "rules" / "sei-cert", pack)
    lock_bytes = (pack / "pack.lock.json").read_bytes()
    lock = json.loads(lock_bytes)
    record = verify_pack(pack).as_record()
    assert record["verified"] is True and record["verified_scope"] == "complete-pack"
    assert record["tree_sha256"] == lock["tree_sha256"]
    assert record["tree_scope"].startswith("complete-pack")
    assert record["tree_file_count"] == len(lock["files"])
    assert record["rule_files_sha256"] == lock["rule_files_sha256"] != record["tree_sha256"]
    assert record["rule_files_scope"].startswith("executable-rules-subset")
    assert record["rule_file_count"] == len(json.loads((pack / "pack.json").read_text(encoding="utf-8"))["rule_files"])
    assert record["lock_sha256"] == hashlib.sha256(lock_bytes).hexdigest()
    assert (record["id"], record["version"]) == (lock["pack"], lock["version"])


@pytest.mark.parametrize("case", sorted(PACK_MUTATIONS))
def test_sei_cert_pack_change_is_rejected_by_strict_verifier(tmp_path: Path, case: str) -> None:
    pack = tmp_path / "sei-cert"
    shutil.copytree(ROOT / "rules" / "sei-cert", pack)
    mutate, message = PACK_MUTATIONS[case]
    mutate(pack)
    with pytest.raises(PackError) as raised:
        verify_pack(pack)
    assert message in raised.value.problems


@pytest.mark.parametrize("case", sorted(PACK_MUTATIONS))
def test_customer_prerequisites_never_hash_supplied_pack(tmp_path: Path, case: str, monkeypatch) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(ROOT / "rules", repo / "rules")
    PACK_MUTATIONS[case][0](repo / "rules" / "sei-cert")
    unit, _, _ = make_unit_context(tmp_path, unit_id="source_sast.semgrep_scan", repository_root=repo)
    catalog = ScanCatalog("target", "handoff", ({"path": "main.cpp", "language": "C++"},), (), ())

    def forbidden(path):
        raise AssertionError("supplied pack must not be fingerprinted")

    monkeypatch.setattr(job, "file_sha256", forbidden)
    for tool_id in ("tool-semgrep", "tool-opengrep"):
        adapter = adapter_registry()[tool_id]
        _, mounts, _, failure = job._prerequisites(unit, adapter, adapter.applicability(catalog))
        assert failure is None
        assert all(mount.supplied_platform for mount in mounts)
        assert job._extra_identity(mounts) == {}


def test_missing_rule_bundles_block_prerequisites_cleanly(tmp_path: Path) -> None:
    empty_repo = tmp_path / "empty_repo"
    empty_repo.mkdir()
    unit, _, _ = make_unit_context(tmp_path, unit_id="source_sast.semgrep_scan", repository_root=empty_repo)
    catalog = ScanCatalog(
        "target",
        "handoff",
        (
            {"path": "main.cpp", "language": "C++", "sha256": "1" * 64},
            {"path": "Main.java", "language": "Java", "sha256": "2" * 64},
        ),
        (),
        (),
    )
    for tool_id, expected in (
        ("tool-semgrep", "supplied Semgrep rule bundle is unavailable"),
        ("tool-gitleaks", "supplied gitleaks rule bundle is unavailable"),
        ("tool-pmd", "supplied PMD security rules are unavailable"),
    ):
        adapter = adapter_registry()[tool_id]
        _, _, _, failure = job._prerequisites(unit, adapter, adapter.applicability(catalog))
        assert failure == expected

    # Semgrep rules present, SEI CERT rules missing -> SEI CERT unavailable
    shutil.copytree(ROOT / "rules" / "semgrep", empty_repo / "rules" / "semgrep")
    semgrep = adapter_registry()["tool-semgrep"]
    _, _, _, sei_fail = job._prerequisites(unit, semgrep, semgrep.applicability(catalog))
    assert sei_fail == "supplied SEI CERT rule pack is unavailable"


def test_declared_rule_release_changes_checkpoint_without_reading_supplied_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(ROOT / "rules", repo / "rules")
    unit, _, _ = make_unit_context(tmp_path, unit_id="source_sast.semgrep_scan", repository_root=repo)
    catalog = ScanCatalog("target", "handoff", ({"path": "main.cpp", "language": "C++", "sha256": "a" * 64},), (), ())
    adapter = adapter_registry()["tool-semgrep"]
    selection, mounts, _, failure = job._prerequisites(unit, adapter, adapter.applicability(catalog))
    assert failure is None

    def forbidden(path):
        raise AssertionError("supplied pack must not be fingerprinted")

    monkeypatch.setattr(job, "file_sha256", forbidden)
    original = job._checkpoint_identity(unit, adapter, catalog, selection, DIGEST, mounts)
    _append("mappings/c.json")(repo / "rules" / "sei-cert")
    assert job._checkpoint_identity(unit, adapter, catalog, selection, DIGEST, mounts) == original
    unit.job.review_policy = replace(
        unit.job.review_policy,
        releases=ComponentReleases({**unit.job.review_policy.releases.values, "rules_tool-semgrep": "fixture-2"}),
    )
    assert job._checkpoint_identity(unit, adapter, catalog, selection, DIGEST, mounts) != original


def test_container_manifests_and_pmd_rules_are_hash_locked_to_runtime_policy() -> None:
    catalog = load_catalog(ROOT)
    assert {"tool-cppcheck", "tool-pmd"} <= set(catalog.tools)
    for tool_id in ("tool-cppcheck", "tool-pmd"):
        tool = catalog.tool(tool_id)
        assert tool.user == "10001:10001" and tool.network == "none"
        assert tool.expected_image_id is None
    lock = json.loads((ROOT / "rules" / "pmd" / "rules.lock.json").read_text(encoding="utf-8"))
    actual = hashlib.sha256((ROOT / "rules" / "pmd" / "java-security.xml").read_bytes()).hexdigest()
    assert lock["sha256"] == actual
