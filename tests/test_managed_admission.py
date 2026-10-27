from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config.assurance import parse_review_policy
from appsec_review.storage.admission import create_admission
from appsec_review.storage.atomic import atomic_json, file_sha256
from appsec_review.storage.shared import put_private_file, verify_handoff, verify_reference
from appsec_review.storage.validation import validation_scope


def admitted_fixture(tmp_path: Path, before_admission=None, *, attempt_id="one", named=False):
    root = tmp_path / "run"
    root.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    policy = parse_review_policy({
        "mode": "first_party_managed", "project_id": "fixture",
        "approved_first_party_projects": ["fixture"],
        "target_root": str(target), "custody": "application_private_v1",
    })
    configuration = root / "data" / "configuration"
    atomic_json(configuration / "resolved.json", {"review_policy": policy.view()})
    atomic_json(configuration / "manifest.json", {
        "resolved_sha256": file_sha256(configuration / "resolved.json")})
    source = root / "builder-output"
    source.write_bytes(b"evidence")
    ref = put_private_file(root, source)
    if named:
        from appsec_review.storage.shared import _link
        ref = _link(root, root / ref["path"], "data/indices/source/fixture.sqlite", ref["sha256"])
    attempt = root / "data" / "jobs" / "fixture" / "attempts" / attempt_id
    attempt.mkdir(parents=True)
    handoff = {
        "schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
        "job_id": "fixture", "attempt_id": attempt_id, "source_fingerprint": "target",
        "artifacts": [ref], "resolving_paths": {"attempt": attempt.relative_to(root).as_posix()},
    }
    context = SimpleNamespace(run_root=root, target_root=target, review_policy=policy,
                              source_fingerprint="target")
    if before_admission is not None:
        before_admission(root / ref["path"])
    handoff["validation_record"] = create_admission(context, handoff)
    return root, source, ref, handoff


def test_managed_admission_detaches_builder_and_removes_rehash(tmp_path, monkeypatch):
    root, source, ref, handoff = admitted_fixture(tmp_path)
    source.write_bytes(b"changed!")
    assert (root / ref["path"]).read_bytes() == b"evidence"
    import appsec_review.storage.validation as validation
    def forbidden(path):
        raise AssertionError("accepted managed payload must not be rehashed")
    monkeypatch.setattr(validation, "file_sha256", forbidden)
    with validation_scope(root):
        verify_handoff(root, handoff)
        verify_reference(root, ref)
    # A second independent consumer authenticates persistent admission, not process memory.
    with validation_scope(root):
        verify_handoff(root, handoff)
        verify_reference(root, ref)


def test_managed_admission_rejects_missing_output(tmp_path):
    root, _, ref, handoff = admitted_fixture(tmp_path)
    (root / ref["path"]).unlink()
    with pytest.raises(ValueError, match="unavailable"):
        verify_handoff(root, handoff)


def test_frozen_configuration_reuses_only_exact_operation_bytes(tmp_path, monkeypatch):
    from appsec_review.storage import admission

    root, _, _, _ = admitted_fixture(tmp_path)
    path = root / "data/configuration/resolved.json"
    original_payload = path.read_bytes()
    original_loads = admission.json.loads
    decoded = []

    def loads(payload, *args, **kwargs):
        if payload == original_payload:
            decoded.append(payload)
        return original_loads(payload, *args, **kwargs)

    monkeypatch.setattr(admission.json, "loads", loads)
    with validation_scope(root):
        policy, digest = admission._frozen(root)
        policy["project_id"] = "caller-mutation"
        repeated, repeated_digest = admission._frozen(root)
        assert repeated["project_id"] == "fixture"
        assert repeated_digest == digest
        assert len(decoded) == 1
    with validation_scope(root):
        assert admission._frozen(root) == (repeated, digest)
        assert len(decoded) == 2
        changed = original_payload.replace(b'"project_id":"fixture"', b'"project_id":"changed"')
        assert changed != original_payload and len(changed) == len(original_payload)
        path.write_bytes(changed)
        with pytest.raises(ValueError, match="configuration identity mismatch"):
            admission._frozen(root)


def test_cached_configuration_still_checks_current_manifest_pin(tmp_path):
    from appsec_review.storage import admission

    root, _, _, _ = admitted_fixture(tmp_path)
    with validation_scope(root):
        admission._frozen(root)
        atomic_json(root / "data/configuration/manifest.json", {"resolved_sha256": "0" * 64})
        with pytest.raises(ValueError, match="configuration identity mismatch"):
            admission._frozen(root)


@pytest.mark.parametrize("damage", ("output", "binding", "key", "record"))
def test_operation_authentication_reuse_preserves_all_current_checks(tmp_path, monkeypatch, damage):
    import json
    from appsec_review.storage import admission

    root, _, ref, handoff = admitted_fixture(tmp_path)
    original_hmac = admission.hmac.new
    authentications = []

    def authenticate(*args, **kwargs):
        authentications.append(1)
        return original_hmac(*args, **kwargs)

    monkeypatch.setattr(admission.hmac, "new", authenticate)
    with validation_scope(root):
        first = admission._read_admission(root, handoff)
        first["policy"]["project_id"] = "caller-mutation"
        second = admission._read_admission(root, handoff)
        assert second["policy"]["project_id"] == "fixture"
        assert len(authentications) == 1
    with validation_scope(root):
        admission._read_admission(root, handoff)
        assert len(authentications) == 2
        if damage == "output":
            (root / ref["path"]).chmod(0o644)
            error = "writable"
        elif damage == "binding":
            handoff["attempt_id"] = "different-attempt"
            error = "mismatch"
        elif damage == "key":
            key = root.parent / "metadata/evidence-admission/authentication.key"
            key.write_bytes(b"x" * 32)
            error = "authentication failed"
        else:
            path = root.parent / "metadata" / handoff["validation_record"]["path"]
            value = json.loads(path.read_bytes())
            value["authentication"] = "0" * 64
            atomic_json(path, value)
            handoff["validation_record"]["sha256"] = file_sha256(path)
            error = "authentication failed"
        with pytest.raises(ValueError, match=error):
            admission._read_admission(root, handoff)


def test_large_admission_records_do_not_expand_operation_authentication_cache(tmp_path):
    import hashlib
    import json
    from appsec_review.storage import admission
    from appsec_review.storage.atomic import canonical_json

    root, _, _, handoff = admitted_fixture(tmp_path)
    path = root.parent / "metadata" / handoff["validation_record"]["path"]
    body = json.loads(path.read_bytes())
    body.pop("authentication")
    body["padding"] = "x" * admission._DOCUMENT_CACHE_BYTES
    signature = admission.hmac.new(
        admission._key(root, create=False), canonical_json(body), hashlib.sha256).hexdigest()
    atomic_json(path, {**body, "authentication": signature})
    handoff["validation_record"]["sha256"] = file_sha256(path)
    with validation_scope(root) as operation:
        admission._read_admission(root, handoff)
        admission._read_admission(root, handoff)
        assert ("admission-authentication", "latest", "") not in operation.records


def test_named_reference_uses_only_authenticated_exact_pin(tmp_path, monkeypatch):
    from appsec_review.storage import shared, validation
    root, _, ref, handoff = admitted_fixture(tmp_path, named=True)
    path = root / ref["path"]
    original = shared.file_sha256

    def no_payload_hash(candidate):
        if candidate == path:
            pytest.fail("authenticated named payload was rehashed")
        return original(candidate)

    with validation_scope(root):
        verify_handoff(root, handoff)
        with monkeypatch.context() as patch:
            patch.setattr(shared, "file_sha256", no_payload_hash)
            patch.setattr(validation, "file_sha256", no_payload_hash)
            assert shared.reference(root, path, expected_sha256=ref["sha256"]) == ref
            shared.consume_named(root, path, namespace="index-shard", expected_sha256=ref["sha256"])
        with pytest.raises(ValueError, match="integrity"):
            shared.reference(root, path, expected_sha256="0" * 64)
    path.chmod(0o644)
    path.write_bytes(b"changed!")
    with pytest.raises(ValueError, match="integrity"):
        shared.reference(root, path, expected_sha256=ref["sha256"])


def test_managed_admission_rejects_writable_output(tmp_path):
    root, _, ref, handoff = admitted_fixture(tmp_path)
    (root / ref["path"]).chmod(0o644)
    with pytest.raises(ValueError, match="writable"):
        verify_handoff(root, handoff)


def test_standalone_inventory_preserves_authenticated_admission_scope(tmp_path, monkeypatch):
    from appsec_review.indexing import inventory
    from appsec_review.indexing.store import AcceptedHandoff
    from appsec_review.storage import validation
    root, _, ref, handoff = admitted_fixture(tmp_path)
    path = root / ref["path"]
    handoff_path = root / "data/jobs/fixture/attempts/one/handoff.json"
    atomic_json(handoff_path, handoff)
    accepted = AcceptedHandoff("fixture", handoff, file_sha256(handoff_path),
                               handoff_path.relative_to(root).as_posix())
    original = inventory.file_sha256

    def no_payload_hash(candidate):
        if candidate == path:
            pytest.fail("inventory rehashed authenticated evidence")
        return original(candidate)

    monkeypatch.setattr(inventory, "file_sha256", no_payload_hash)
    monkeypatch.setattr(validation, "file_sha256", no_payload_hash)
    inputs = inventory.InventoryInputs(
        root, root.name, "target", {"fixture": []}, {"fixture": []}, {},
        {"fixture": accepted},
        {}, [], managed_publications=True)
    result = inventory.build_inventory(inputs)
    codes = {item["code"] for item in result["audit"]["violations"]}
    assert "artifact_hash_mismatch" not in codes
    assert "undeclared_job" in codes
    assert validation.current_validation(root) is None


@pytest.mark.parametrize("field,value", [("source_fingerprint", "other"), ("attempt_id", "other")])
def test_managed_admission_rejects_target_or_producer_rebinding(tmp_path, field, value):
    root, _, _, handoff = admitted_fixture(tmp_path)
    handoff[field] = value
    with pytest.raises(ValueError, match="mismatch"):
        verify_handoff(root, handoff)


def test_legacy_handoff_stays_strict_under_managed_configuration(tmp_path):
    root, _, ref, handoff = admitted_fixture(tmp_path)
    del handoff["validation_record"]
    path = root / ref["path"]
    path.chmod(0o644)
    path.write_bytes(b"changed!")
    with pytest.raises(ValueError, match="integrity"):
        verify_handoff(root, handoff)


def test_legacy_claim_is_rejected_before_managed_input_handling(tmp_path, monkeypatch):
    import json
    from appsec_review.config import load_config
    from appsec_review.runtime import Job, JobRunner, Unit
    from appsec_review.storage import admission, validation
    from tests.test_job_runtime import write_config

    target = tmp_path / "target"
    target.mkdir()
    config_path = write_config(tmp_path)
    with config_path.open("a", encoding="utf-8") as stream:
        stream.write(
            '\n[review_policy]\nmode = "first_party_managed"\nproject_id = "fixture"\n'
            'approved_first_party_projects = ["fixture"]\ncustody = "application_private_v1"\n'
            f'target_root = {json.dumps(str(target))}\n')
    config = load_config(config_path)

    def forbidden(*args, **kwargs):
        pytest.fail("legacy claim reached managed admission, input validation or execution")

    job = Job("job_fixture", "fixture", forbidden,
              units=(Unit("work.only", forbidden, input_validators=(forbidden,)),))
    runner = JobRunner(config)
    claim = runner.begin_attempt(job, target_root=target, source_fingerprint="target")
    del claim["review_policy"]
    run_root = config.runtime.runs_dir / claim["run_id"]
    atomic_json(run_root / claim["attempt_path"] / "claim.json", claim)
    monkeypatch.setattr(admission, "admit_upstreams", forbidden)

    with pytest.raises(ValueError, match="legacy attempt requires strict re-admission"):
        runner._context_from_claim(job, claim)
    with pytest.raises(ValueError, match="legacy attempt requires strict re-admission"):
        runner.execute_or_reuse_unit(job, claim, "work.only")
    assert validation.current_validation(run_root) is None


def test_admission_detaches_preexisting_hardlink_and_writable_descriptor(tmp_path):
    import os
    aliases = []
    def open_alias(path):
        alias = tmp_path / "writable-alias"
        os.link(path, alias)
        aliases.append((alias, path.open("r+b")))
    root, _, ref, _ = admitted_fixture(tmp_path, open_alias)
    alias, descriptor = aliases[0]
    try:
        descriptor.write(b"changed!")
        descriptor.flush()
        assert alias.read_bytes() == b"changed!"
        assert (root / ref["path"]).read_bytes() == b"evidence"
        assert alias.stat().st_ino != (root / ref["path"]).stat().st_ino
    finally:
        descriptor.close()


@pytest.fixture
def aliased_publication(tmp_path):
    import os
    from appsec_review.storage import admission, shared

    root, _, ref, previous = admitted_fixture(tmp_path)
    paths = [root / ref["path"], root / "data/indices/alias.sqlite",
             root / "data/indices/independent.sqlite"]
    paths[0].chmod(0o600)
    paths[1].parent.mkdir(parents=True, exist_ok=True)
    os.link(paths[0], paths[1])
    paths[2].write_bytes(paths[0].read_bytes())
    paths[2].chmod(0o600)
    frozen = admission._frozen(root)[0]
    policy = parse_review_policy({key: value for key, value in frozen.items()
        if key not in {"scope_version", "validation_version", "platform_payload_verification"}})
    context = SimpleNamespace(run_root=root, target_root=Path(policy.target_root),
                              review_policy=policy, source_fingerprint="target")
    handoff = {key: value for key, value in previous.items() if key != "validation_record"}
    handoff["artifacts"] = [shared.reference(root, path) for path in paths]
    return root, context, handoff, paths


@pytest.mark.parametrize("independent_mode,copies,links", [(0o600, 1, 2), (0o640, 2, 1)])
def test_equal_publication_payloads_share_only_fresh_detached_custody(
        aliased_publication, independent_mode, copies, links):
    from contextlib import ExitStack
    from appsec_review.observability import EventLog, PipelineLog, aggregate_run_metrics
    from appsec_review.observability.spans import operation_span

    root, context, handoff, paths = aliased_publication
    paths[2].chmod(independent_mode)
    original_inodes = {path.stat().st_ino for path in paths}
    events = EventLog(root / "events.jsonl", PipelineLog(root), {"run_id": root.name})
    with ExitStack() as stack:
        descriptors = [stack.enter_context(path.open("r+b")) for path in paths]
        with operation_span(events, "fixture.admission") as span:
            handoff["validation_record"] = create_admission(context, handoff)
        assert span.counters["copy_objects"] == copies
        assert span.counters["copy_bytes"] == copies * len(b"evidence")
        assert span.counters["custody_alias_objects"] == links
        for descriptor in descriptors:
            descriptor.write(b"changed!")
            descriptor.flush()
        for path in paths:
            assert path.read_bytes() == b"evidence"
            assert path.stat().st_ino not in original_inodes
            assert path.stat().st_mode & 0o222 == 0
        assert paths[0].stat().st_ino == paths[1].stat().st_ino
        assert bool(paths[2].stat().st_ino == paths[0].stat().st_ino) == (copies == 1)
        assert paths[2].stat().st_mode & 0o777 == independent_mode & ~0o222
    verify_handoff(root, handoff)
    assert aggregate_run_metrics(root)["work_counters"]["custody_alias_objects"] == links
    assert not list(root.rglob(".admit-*"))


def test_grouped_admission_rejects_changed_member_before_detachment(aliased_publication, monkeypatch):
    from appsec_review.storage import admission

    root, context, handoff, paths = aliased_publication
    paths[2].write_bytes(b"changed!")
    before = [path.stat().st_ino for path in paths]
    def forbidden(*args, **kwargs):
        pytest.fail("corrupt publication reached detachment")
    monkeypatch.setattr(admission, "_detach_payload", forbidden)
    with pytest.raises(ValueError, match="integrity"):
        create_admission(context, handoff)
    assert [path.stat().st_ino for path in paths] == before
    assert not list(root.rglob(".admit-*"))


def test_grouped_admission_link_failure_has_no_receipt_or_temporary_leak(
        aliased_publication, monkeypatch):
    from appsec_review.storage import admission

    root, context, handoff, paths = aliased_publication
    records = root.parent / "metadata/evidence-admission" / root.name
    before = set(records.iterdir())
    original_link = admission.os.link
    def fail_link(source, destination, *args, **kwargs):
        if Path(source).name.startswith(".admit-"):
            raise OSError("injected detached alias link failure")
        return original_link(source, destination, *args, **kwargs)
    monkeypatch.setattr(admission.os, "link", fail_link)
    with pytest.raises(OSError, match="injected detached alias"):
        create_admission(context, handoff)
    assert "validation_record" not in handoff
    assert set(records.iterdir()) == before
    assert all(path.read_bytes() == b"evidence" for path in paths)
    assert not list(root.rglob(".admit-*"))


@pytest.mark.parametrize("field", [2, 5], ids=["different-device", "different-group"])
def test_grouped_admission_copies_incompatible_alias_destinations(
        aliased_publication, monkeypatch, field):
    import os
    from appsec_review.observability import EventLog, PipelineLog
    from appsec_review.observability.spans import operation_span

    root, context, handoff, paths = aliased_publication
    original_stat = Path.stat
    def different_destination(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if path.name.startswith(".admit-") and path.parent == paths[1].parent:
            fields = list(result)
            fields[field] += 1
            return os.stat_result(fields)
        return result
    monkeypatch.setattr(Path, "stat", different_destination)
    events = EventLog(root / "events.jsonl", PipelineLog(root), {"run_id": root.name})
    with operation_span(events, "fixture.admission") as span:
        handoff["validation_record"] = create_admission(context, handoff)
    assert span.counters["copy_objects"] == 3
    assert span.counters.get("custody_alias_objects", 0) == 0
    assert len({path.stat().st_ino for path in paths}) == 3
    verify_handoff(root, handoff)
    assert not list(root.rglob(".admit-*"))


@pytest.mark.parametrize("separate_device", [False, True])
def test_detached_inode_and_all_parent_syncs_precede_admission(
        aliased_publication, monkeypatch, separate_device):
    import os
    import stat
    from appsec_review.storage import admission, shared

    root, context, handoff, paths = aliased_publication
    events = []
    original_stat, original_sync = Path.stat, os.fsync
    original_replace, original_publish = os.replace, shared.immutable_bytes

    def destination_stat(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if separate_device and path.name.startswith(".admit-") and path.parent == paths[1].parent:
            values = list(result)
            values[2] += 1
            return os.stat_result(values)
        return result

    def sync(descriptor):
        metadata = os.fstat(descriptor)
        events.append(("directory" if stat.S_ISDIR(metadata.st_mode) else "inode",
                       Path(os.readlink(f"/proc/self/fd/{descriptor}")), metadata.st_mode))
        return original_sync(descriptor)

    def replace(source, destination):
        result = original_replace(source, destination)
        events.append(("replace", Path(destination), None))
        return result

    def publish(*args, **kwargs):
        events.append(("publish", None, None))
        return original_publish(*args, **kwargs)

    monkeypatch.setattr(Path, "stat", destination_stat)
    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(shared, "immutable_bytes", publish)
    create_admission(context, handoff)
    publication = next(index for index, event in enumerate(events) if event[0] == "publish")
    last_replace = max(index for index, event in enumerate(events)
                       if event[0] == "replace" and event[1] in paths)
    barrier = events[last_replace + 1:publication]
    assert sum(kind == "inode" and mode & 0o222 == 0 for kind, _, mode in barrier) == (
        3 if separate_device else 1)
    required = {root.parent}
    for path in paths:
        parent = path.parent
        while parent != root.parent:
            required.add(parent)
            parent = parent.parent
    assert required <= {path for kind, path, _ in barrier if kind == "directory"}
    record_directory = root.parent / "metadata" / "evidence-admission" / root.name
    assert ("directory", record_directory) in {
        (kind, path) for kind, path, _ in events[publication + 1:]}


@pytest.mark.parametrize("failure", ["inode", "directory"])
def test_detached_durability_failure_prevents_admission_publication(
        aliased_publication, monkeypatch, failure):
    import os
    import stat
    from appsec_review.storage import admission

    root, context, handoff, paths = aliased_publication
    directory = root.parent / "metadata" / "evidence-admission" / root.name
    before = set(directory.iterdir())
    original_sync = os.fsync

    def sync(descriptor):
        mode = os.fstat(descriptor).st_mode
        if ((failure == "directory" and stat.S_ISDIR(mode))
                or (failure == "inode" and stat.S_ISREG(mode) and not mode & 0o222)):
            raise OSError("injected custody durability failure")
        return original_sync(descriptor)

    monkeypatch.setattr(admission.os, "fsync", sync)
    with pytest.raises(OSError, match="custody durability"):
        create_admission(context, handoff)
    assert set(directory.iterdir()) == before
    assert all(path.read_bytes() == b"evidence" for path in paths)
    assert not list(root.rglob(".admit-*"))


def test_non_detached_json_and_its_replacement_directory_are_durable_before_admission(
        aliased_publication, monkeypatch):
    import os
    import stat
    from appsec_review.storage import atomic_json, shared

    root, context, handoff, _ = aliased_publication
    terminal = root / "data/jobs/fixture/attempt/status.json"
    atomic_json(terminal, {"status": "xxxxxxxxx"})
    atomic_json(terminal, {"status": "SUCCEEDED"})
    handoff["artifacts"].append(shared.reference(root, terminal))
    expected_inode = terminal.stat().st_ino
    events = []
    original_sync, original_publish = os.fsync, shared.immutable_bytes

    def sync(descriptor):
        metadata = os.fstat(descriptor)
        events.append((Path(os.readlink(f"/proc/self/fd/{descriptor}")),
                       metadata.st_ino, stat.S_ISDIR(metadata.st_mode)))
        return original_sync(descriptor)

    def publish(*args, **kwargs):
        assert (terminal, expected_inode, False) in events
        assert any(path == terminal.parent and directory for path, _, directory in events)
        return original_publish(*args, **kwargs)

    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(shared, "immutable_bytes", publish)
    record = create_admission(context, handoff)
    assert record is not None
    assert terminal.stat().st_mode & 0o200


def test_legacy_admission_without_durable_custody_cannot_enable_bypass(tmp_path):
    import hashlib
    import hmac
    import json
    from appsec_review.storage import admission, canonical_json, shared
    from appsec_review.storage.validation import validation_scope

    root, _, _, handoff = admitted_fixture(tmp_path)
    reference = handoff["validation_record"]
    metadata = root.parent / "metadata"
    path = metadata / reference["path"]
    record = json.loads(path.read_bytes())
    record.pop("custody_durability")
    record.pop("authentication")
    record["authentication"] = hmac.new(
        admission._key(root, create=False), canonical_json(record), hashlib.sha256).hexdigest()
    path.write_bytes(canonical_json(record))
    handoff["validation_record"] = shared.reference(metadata, path)
    with validation_scope(root), pytest.raises(ValueError, match="crash-durable custody"):
        admission.consume_admission(root, handoff)


def test_persistent_admission_authenticates_in_a_fresh_process_with_inherited_affinity(tmp_path):
    import json
    import os
    import subprocess
    import sys
    root, _, ref, handoff = admitted_fixture(tmp_path)
    code = """
import json, os, sys
from pathlib import Path
from appsec_review.storage.shared import verify_handoff, verify_reference
from appsec_review.storage.validation import validation_scope
import appsec_review.storage.validation as validation
def forbidden(path):
    raise AssertionError("managed consumer rehashed an admitted payload")
validation.file_sha256 = forbidden
root, handoff, reference = Path(sys.argv[1]), json.loads(sys.argv[2]), json.loads(sys.argv[3])
if hasattr(os, "sched_getaffinity"):
    assert sorted(os.sched_getaffinity(0)) == json.loads(sys.argv[4])
with validation_scope(root):
    verify_handoff(root, handoff)
    verify_reference(root, reference)
"""
    affinity = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else []
    result = subprocess.run([sys.executable, "-c", code, str(root), json.dumps(handoff),
                             json.dumps(ref), json.dumps(affinity)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_rehashed_admission_record_still_requires_authentication(tmp_path):
    import json
    root, _, _, handoff = admitted_fixture(tmp_path)
    record = handoff["validation_record"]
    path = root.parent / "metadata" / record["path"]
    value = json.loads(path.read_bytes())
    value["producer"]["attempt_id"] = "forged"
    atomic_json(path, value)
    record["sha256"] = file_sha256(path)
    record["size_bytes"] = path.stat().st_size
    with pytest.raises(ValueError, match="authentication"):
        verify_handoff(root, handoff)


def test_admission_rejects_a_different_run_and_changed_operator_policy(tmp_path):
    import json
    import shutil
    root, _, _, handoff = admitted_fixture(tmp_path)
    other = tmp_path / "other-run"
    shutil.copytree(root, other)
    with pytest.raises(ValueError, match="escapes its run"):
        verify_handoff(other, handoff)
    configuration = root / "data" / "configuration"
    value = json.loads((configuration / "resolved.json").read_bytes())
    value["review_policy"]["project_id"] = "another-project"
    atomic_json(configuration / "resolved.json", value)
    atomic_json(configuration / "manifest.json", {
        "resolved_sha256": file_sha256(configuration / "resolved.json")})
    with pytest.raises(ValueError, match="mismatch"):
        verify_handoff(root, handoff)


def test_managed_custody_is_not_a_claim_of_repeated_payload_tamper_detection(tmp_path):
    root, _, ref, handoff = admitted_fixture(tmp_path)
    path = root / ref["path"]
    path.chmod(0o644)
    path.write_bytes(b"changed!")
    path.chmod(0o444)
    with validation_scope(root):
        verify_handoff(root, handoff)
        verify_reference(root, ref)
    del handoff["validation_record"]
    with pytest.raises(ValueError, match="integrity"):
        verify_handoff(root, handoff)


def test_publication_reuses_authenticated_custody_without_copying_upstream_payload(tmp_path, monkeypatch):
    import json
    import appsec_review.storage.admission as admission
    root, _, _, handoff = admitted_fixture(tmp_path)
    frozen = json.loads((root / "data" / "configuration" / "resolved.json").read_bytes())["review_policy"]
    policy = parse_review_policy({key: value for key, value in frozen.items()
                                  if key not in {"scope_version", "validation_version", "platform_payload_verification"}})
    context = SimpleNamespace(run_root=root, target_root=Path(policy.target_root),
                              review_policy=policy, source_fingerprint="target")
    def forbidden(*args):
        pytest.fail("authenticated upstream payload was detached again")
    with validation_scope(root):
        verify_handoff(root, handoff)
        monkeypatch.setattr(admission, "_detach_payload", forbidden)
        republished = {key: value for key, value in handoff.items() if key != "validation_record"}
        republished["attempt_id"] = "two"
        republished["validation_record"] = create_admission(context, republished)
    verify_handoff(root, republished)


def test_fresh_process_publication_restores_only_claimed_authenticated_upstreams(tmp_path):
    import json
    import os
    import subprocess
    import sys
    root, _, _, handoff = admitted_fixture(tmp_path, attempt_id="attempt_0001")
    path = root / handoff["resolving_paths"]["attempt"] / "handoff.json"
    atomic_json(path, handoff)
    code = """
import json, os, sys
from pathlib import Path
from types import SimpleNamespace
from appsec_review.config.assurance import parse_review_policy
from appsec_review.storage.shared import verify_handoff
from appsec_review.storage.validation import validation_scope
import appsec_review.storage.admission as admission
import appsec_review.storage.validation as validation
root, handoff, digest = Path(sys.argv[1]), json.loads(sys.argv[2]), sys.argv[3]
if hasattr(os, "sched_getaffinity"):
    assert sorted(os.sched_getaffinity(0)) == json.loads(sys.argv[4])
policy_value = json.loads((root / "data/configuration/resolved.json").read_bytes())["review_policy"]
policy = parse_review_policy({key: value for key, value in policy_value.items()
    if key not in {"scope_version", "validation_version", "platform_payload_verification"}})
context = SimpleNamespace(run_root=root, target_root=Path(policy.target_root),
                          review_policy=policy, source_fingerprint="target")
attempt = root / "data/jobs/consumer/attempts/attempt_0001"
attempt.mkdir(parents=True)
republished = {key: value for key, value in handoff.items() if key != "validation_record"}
republished.update(job_id="consumer", resolving_paths={"attempt": attempt.relative_to(root).as_posix()},
                   upstream_handoff_sha256={"fixture": digest})
def forbidden(*args):
    raise AssertionError("fresh publication rehashed or detached an admitted upstream payload")
validation.file_sha256 = forbidden
admission._detach_payload = forbidden
republished["validation_record"] = admission.create_admission(context, republished)
with validation_scope(root):
    verify_handoff(root, republished)
"""
    affinity = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else []
    result = subprocess.run([sys.executable, "-c", code, str(root), json.dumps(handoff),
                             file_sha256(path), json.dumps(affinity)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("invalid", ["missing_record", "wrong_target", "wrong_claim"])
def test_publication_upstream_claim_does_not_grant_unauthenticated_trust(tmp_path, invalid):
    import json
    from appsec_review.storage.admission import admit_upstreams
    root, _, ref, handoff = admitted_fixture(tmp_path, attempt_id="attempt_0001")
    frozen = json.loads((root / "data/configuration/resolved.json").read_bytes())["review_policy"]
    policy = parse_review_policy({key: value for key, value in frozen.items()
        if key not in {"scope_version", "validation_version", "platform_payload_verification"}})
    context = SimpleNamespace(run_root=root, target_root=Path(policy.target_root),
                              review_policy=policy, source_fingerprint="target")
    if invalid == "missing_record":
        del handoff["validation_record"]
        payload = root / ref["path"]
        payload.chmod(0o644)
        payload.write_bytes(b"changed!")
    elif invalid == "wrong_target":
        handoff["source_fingerprint"] = "other-target"
    path = root / handoff["resolving_paths"]["attempt"] / "handoff.json"
    atomic_json(path, handoff)
    claim = {"fixture": "0" * 64 if invalid == "wrong_claim" else file_sha256(path)}
    with validation_scope(root):
        if invalid == "missing_record":
            admit_upstreams(context, claim)
            with pytest.raises(ValueError, match="integrity"):
                verify_reference(root, ref)
        else:
            with pytest.raises(ValueError, match="different target|exactly one accepted handoff"):
                admit_upstreams(context, claim)
