from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from appsec_review.container_runtime import native_contracts
from appsec_review.container_runtime.native_contracts import client_contracts, contract_path, publish_client_contracts
from appsec_review.container_runtime.engine_broker import _installed_module_path
from tests.test_native_engine_broker import native  # noqa: F401
from tests.test_bounded_image_build_service import forbid_real_execution  # noqa: F401


def test_client_contract_is_derived_from_exact_operator_grant_and_broker(native):
    contract, = client_contracts(native.config)
    assert contract.binding == native.client.contract.binding
    assert contract.broker_pid == os.getpid()
    assert contract.resources == native.config.resources
    assert contract.mounts == native.client.contract.mounts
    assert contract.executables == {
        "python": "/usr/bin/python3", "python3": "/usr/bin/python3",
        "/usr/bin/python3": "/usr/bin/python3"}
    with pytest.raises(ValueError, match="operator-selected"):
        contract_path(native.config, 0)
    with pytest.raises(PermissionError, match="root broker"):
        publish_client_contracts(native.config)


def test_installed_bootstrap_is_permitted_only_as_the_exact_main_module():
    root, stdlib = Path("/operator/release/lib"), Path("/usr/lib/python3.12")
    assert _installed_module_path("__main__", root.parent / "root_entrypoint.py", root, stdlib)
    assert _installed_module_path("appsec_review", root / "appsec_review/__init__.py", root, stdlib)
    for name, path in [
        ("__main__", Path("/client/root_entrypoint.py")),
        ("other", root.parent / "root_entrypoint.py"),
        ("__main__", root.parent / "different.py"),
    ]:
        assert not _installed_module_path(name, path, root, stdlib)


def test_root_client_contract_publication_is_durable_and_refuses_policy_drift(native, tmp_path, monkeypatch):
    root = tmp_path / "public-contracts"
    root.mkdir(mode=0o711)
    config = replace(native.config, native_engine=replace(
        native.config.native_engine, client_contract_root=str(root)))
    original_stat, original_lstat = Path.stat, Path.lstat

    def root_owned(function):
        def inspect(path, *args, **kwargs):
            metadata = list(function(path, *args, **kwargs))
            metadata[4] = 0
            metadata[5] = 0
            if path != root and path in root.parents:
                metadata[0] |= 0o001
            return os.stat_result(metadata)
        return inspect

    monkeypatch.setattr(Path, "stat", root_owned(original_stat))
    monkeypatch.setattr(Path, "lstat", root_owned(original_lstat))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    syncs = []
    original_fsync = os.fsync

    def sync(descriptor):
        syncs.append(Path(os.readlink(f"/proc/self/fd/{descriptor}")))
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", sync)
    path, = publish_client_contracts(config)
    assert path == root / "grant-0.json"
    assert path.stat().st_mode & 0o777 == 0o444
    assert syncs[-1] == root
    document = json.loads(path.read_bytes())
    expected, = client_contracts(config)
    assert document["binding"] == expected.binding
    assert document["resources"] == expected.resources.view()
    assert publish_client_contracts(config) == (path,)
    changed = replace(config, native_engine=replace(config.native_engine, engine_generation="new-engine"))
    with pytest.raises(RuntimeError, match="drift"):
        publish_client_contracts(changed)
    assert json.loads(path.read_bytes()) == document
    assert set(root.iterdir()) == {path}


def test_client_contract_directory_must_not_be_target_owned(native):
    with pytest.raises(ValueError, match="worker custody"):
        replace(native.config.native_engine, client_contract_root=native.client.contract.target_root)


def test_platform_mount_cannot_expose_control_sockets_even_read_only(native):
    from appsec_review.config.native_engine import NativeMount

    mount = NativeMount("unsafe-platform", "/", "/platform", "platform")
    with pytest.raises(ValueError, match="control paths"):
        replace(native.config, native_engine=replace(
            native.config.native_engine, mounts=(*native.config.native_engine.mounts, mount)))
