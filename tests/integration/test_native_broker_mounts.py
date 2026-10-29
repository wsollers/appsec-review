"""Integration tier: real native broker bind-mount policy, driven as its granted non-root client.

Operator-run against a commissioned broker (deploy/dagster/native/README.md, "Integration and
acceptance tests"). Skipped, with the unmet precondition named, unless ``APPSEC_NATIVE_INTEGRATION=1``,
the published client contract and broker socket exist, this process runs as the contract's uid/gid
inside the contract's host cgroup, and the client modules equal the installed release copies.
Every case uses the public ``NativeClient`` under a removed-only resource lease and always removes
any execution it owns.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import uuid

import pytest

import appsec_review.container_runtime.native_client as native_client_module
from appsec_review.container_runtime.native_commands import parse_native_command
from appsec_review.runtime import resources
from tests.native_live_support import INTEGRATION_ENV, new_name, open_session, skip_reason


_SKIP = skip_reason(INTEGRATION_ENV)
pytestmark = pytest.mark.skipif(_SKIP is not None, reason=_SKIP or "")


@pytest.fixture(scope="module")
def session(tmp_path_factory):
    return open_session(tmp_path_factory.mktemp("native-events") / "native-events.jsonl")


@pytest.fixture
def scratch(session):
    created: list[Path] = []

    def make(prefix: str, suffix: str = "") -> Path:
        path = session.run_root / f"c4b-{prefix}-{uuid.uuid4().hex[:12]}{suffix}"
        created.append(path)
        return path

    yield make
    for path in reversed(created):
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)


def test_run_root_subdirectory_bind_mount_is_visible_on_host_and_removed(session, scratch):
    mounted = scratch("mount")
    mounted.mkdir(mode=0o700)
    name = new_name()
    argv = session.run_argv(name, "/bin/sh", ["-c", "printf plain > /scratch/plain.txt"], source=mounted)
    with session.reserved("scratch-mount"):
        try:
            code, out, err, timed = session.client.run(argv, 60)
        finally:
            session.remove_if_owned(name)
    assert code == 0 and not timed, (code, out, err)
    assert (mounted / "plain.txt").read_bytes() == b"plain"
    assert session.client.executions[name]["state"] == "REMOVED"


def test_mount_subpath_with_bind_option_separator_is_rejected_by_broker(session, scratch):
    legitimate = scratch("legit")
    legitimate.mkdir(mode=0o700)
    unsafe = scratch("comma", ",readonly=false")
    unsafe.mkdir(mode=0o700)
    name = new_name()
    argv = session.run_argv(name, "/bin/sh", ["-c", "printf plain > /scratch/plain.txt"], source=legitimate)
    payload = session.client._create(parse_native_command(argv))
    # The client's --mount parser already refuses ','; send the subpath to prove the broker does too.
    payload["mounts"] = [{**payload["mounts"][0], "relative_path": unsafe.name}]
    rejected = None
    with session.reserved("comma-subpath"):
        resources.track_container(name)
        try:
            try:
                created = session.client.request("execution.create", payload)
            except RuntimeError as error:
                rejected = error
            else:
                session.client.executions[name] = created
        finally:
            session.remove_if_owned(name)
            resources.container_stopped(name)
    # The broker refuses the policy before journaling an intent and closes without a reply.
    assert rejected is not None and "closed without a complete response" in str(rejected), rejected
    assert name not in session.client.executions
    assert not (unsafe / "plain.txt").exists() and not (legitimate / "plain.txt").exists()


def test_symlinked_mount_subpath_is_rejected_by_broker(session, scratch, monkeypatch):
    real = scratch("real")
    real.mkdir(mode=0o700)
    link = scratch("link")
    link.symlink_to(real.name)
    name = new_name()
    argv = session.run_argv(name, "/bin/sh", ["-c", "printf plain > /scratch/plain.txt"], source=link)
    payload = session.client._create(parse_native_command(argv))
    assert payload["mounts"][0]["relative_path"] == link.name
    responses: list[dict] = []
    replies: list[dict] = []
    parse = native_client_module._json

    def recording(data: bytes) -> dict:
        document = parse(data)
        if "result" in document:
            responses.append(document["result"])
        return document

    # Observe the broker's reply so a quarantined intent can still be removed with its token.
    monkeypatch.setattr(native_client_module, "_json", recording)
    rejected = None
    action = "symlink-subpath"
    with session.reserved(action) as lease_id:
        resources.track_container(name)
        try:
            try:
                created = session.client.request("execution.create", payload)
            except RuntimeError as error:
                rejected = error
                replies = [body for body in responses if body.get("execution_id") == payload["execution_id"]]
                if replies:
                    # Copy: client cleanup rewrites the stored record's state in place.
                    session.client.executions[name] = dict(replies[-1])
            else:
                session.client.executions[name] = created
        finally:
            session.remove_if_owned(name)
    assert rejected is not None and "quarantined" in str(rejected), rejected
    assert replies and replies[-1]["state"] == "UNKNOWN" and replies[-1]["container_id"] is None, replies
    assert session.client.executions[name]["state"] == "REMOVED"
    assert not (real / "plain.txt").exists()
    ledger = Path(session.contract.metadata_root) / "resource-admission" / "leases.json"
    entry = json.loads(ledger.read_text())["leases"][lease_id]
    assert entry["quarantine"] == "native_broker_outcome_unknown" and entry["containers"] == [], entry
    # Removal was confirmed by the broker above, so the retained lease is reconciled, not left behind.
    reclaimed = session.admission.reconcile(
        lambda container: False, confirmed_cleanup=lambda lease: True,
        lease_filter=lambda lease: lease.get("action") == "native-test." + action and lease["pid"] == os.getpid(),
        confirmed_removed=lambda container: container == name)
    assert lease_id in reclaimed
