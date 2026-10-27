import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


SPEC = importlib.util.spec_from_file_location(
    "native_root_entrypoint",
    Path(__file__).parents[1] / "deploy/dagster/native/root_entrypoint.py")
assert SPEC is not None and SPEC.loader is not None
entrypoint = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(entrypoint)


@pytest.fixture
def installed_release(tmp_path, monkeypatch):
    release = tmp_path / "release"
    package = release / "lib/appsec_review"
    (package / "container_runtime").mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "container_runtime/image_builder_service.py").write_text("")
    bootstrap = release / "root_entrypoint.py"
    bootstrap.write_text("# installed fixture, never executed")
    python = tmp_path / "python3"
    python.write_bytes(b"fixture")
    python.chmod(0o755)
    config = tmp_path / "service.toml"
    config.write_text("# operator fixture")
    config.chmod(0o600)
    original = Path.lstat

    def root_owned(path, *args, **kwargs):
        value = list(original(path, *args, **kwargs))
        value[4] = 0
        return os.stat_result(value)

    monkeypatch.setattr(Path, "lstat", root_owned)
    monkeypatch.setattr(os, "statvfs", lambda path: SimpleNamespace(f_flag=os.ST_RDONLY))
    return python, bootstrap, config


def test_root_launch_is_isolated_and_never_inherits_client_environment(installed_release, monkeypatch):
    python, bootstrap, config = installed_release
    monkeypatch.setenv("PYTHONPATH", "/client/editable")
    monkeypatch.setenv("PYTHONHOME", "/client/venv")
    monkeypatch.setenv("DOCKER_HOST", "unix:///client/socket")
    monkeypatch.setenv("CLIENT_SECRET", "must-not-be-inherited")
    specification = entrypoint.launch_spec(python, bootstrap, config)
    assert specification["argv"] == (
        str(python), "-I", "-S", str(bootstrap), "--config", str(config))
    assert specification["cwd"] == str(bootstrap.parent)
    assert specification["environment"] == entrypoint.ROOT_ENVIRONMENT
    assert not set(specification["environment"]) & {
        "PYTHONPATH", "PYTHONHOME", "DOCKER_HOST", "CLIENT_SECRET"}


@pytest.mark.parametrize("unsafe", ["entrypoint-mode", "config-mode", "writable-release", "symlink"])
def test_root_launch_rejects_unsafe_installed_inputs(installed_release, monkeypatch, unsafe):
    python, bootstrap, config = installed_release
    if unsafe == "entrypoint-mode":
        bootstrap.chmod(0o666)
    elif unsafe == "config-mode":
        config.chmod(0o644)
    elif unsafe == "writable-release":
        monkeypatch.setattr(os, "statvfs", lambda path: SimpleNamespace(f_flag=0))
    else:
        indirect = bootstrap.with_name("indirect.py")
        indirect.symlink_to(bootstrap)
        bootstrap = indirect
    with pytest.raises(PermissionError):
        entrypoint.launch_spec(python, bootstrap, config)


def test_root_launch_rejects_client_owned_code(installed_release, monkeypatch):
    python, bootstrap, config = installed_release
    original = Path.lstat

    def client_owned(path, *args, **kwargs):
        metadata = original(path, *args, **kwargs)
        if path == bootstrap:
            values = list(metadata)
            values[4] = 1000
            return os.stat_result(values)
        return metadata

    monkeypatch.setattr(Path, "lstat", client_owned)
    with pytest.raises(PermissionError, match="owned by a client"):
        entrypoint.launch_spec(python, bootstrap, config)


def test_root_entrypoint_refuses_nonisolated_startup_before_service_import(monkeypatch):
    monkeypatch.setattr(entrypoint.os, "geteuid", lambda: 0)
    monkeypatch.setattr(entrypoint.runpy, "run_module",
                        lambda *args, **kwargs: pytest.fail("unsafe startup imported the service"))
    with monkeypatch.context() as context:
        context.setattr(entrypoint.sys, "flags", SimpleNamespace(isolated=0, no_site=0))
        with pytest.raises(PermissionError, match="Python -I -S"):
            entrypoint.main(["--config", "/unused"])


@pytest.mark.parametrize("operation", ["reserve-lifetime", "reconcile-admission", "release-lifetime"])
def test_installed_root_lifecycle_preserves_isolated_launch_boundary(installed_release, operation):
    python, bootstrap, config = installed_release
    specification = entrypoint.launch_spec(python, bootstrap, config, operation=operation)
    assert specification["argv"] == (
        str(python), "-I", "-S", str(bootstrap), "--config", str(config), "--operation", operation)
    assert specification["environment"] == entrypoint.ROOT_ENVIRONMENT


def test_installed_root_lifecycle_is_not_an_arbitrary_command_entrypoint(installed_release):
    with pytest.raises(ValueError, match="unsupported"):
        entrypoint.launch_spec(*installed_release, operation="docker run --privileged")
