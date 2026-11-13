"""Real launch policy and timeout cleanup in every configured project-build profile."""

from __future__ import annotations

import json
import os
import subprocess

import pytest

from appsec_review.container_runtime import ProjectImageResolver

from .support import PROFILES, assert_declared_files, boundary_run, executor_for


@pytest.mark.parametrize("family", PROFILES)
def test_profile_enforces_mount_user_network_and_read_only_root(tmp_path, family, record_property):
    executor = executor_for(family)
    record_property("build_image_id", executor.profile.image_id)
    record_property("image_signature", "verified")
    run = boundary_run(tmp_path)
    resolver = ProjectImageResolver(
        metadata_root=run.workspace.parent / "image-metadata", target_root=run.workspace,
        run_root=run.root, timeout_seconds=30,
    )
    image, stdout, stderr = resolver.resolve({
        "image_profile": family, "source_dir": ".", "dependency_files": [],
        "system_packages": [], "environment": {}, "network_required": False,
    }, executor.profile)
    assert image.image_id == image.base_image_id == executor.profile.image_id
    assert not image.customized and image.cache_disposition == "NOT_APPLICABLE"
    assert stdout == stderr == b""
    assert not (run.workspace.parent / "image-metadata").exists()
    script = (
        "import errno,json,os,pathlib,sys\n"
        "try:\n"
        " pathlib.Path('/appsec-integration-forbidden').write_text('x')\n"
        "except OSError as error:\n"
        " assert error.errno == errno.EROFS, str(error)\n"
        "else:\n"
        " raise AssertionError('image root is writable')\n"
        "pathlib.Path('boundary-output').write_text(sys.argv[1])\n"
        "print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'cwd':os.getcwd(),"
        "'network':sorted(os.listdir('/sys/class/net')),'value':os.environ['BOUNDARY_VALUE']}))\n"
    )
    result = executor.execute(
        ("python3", "-c", script, "literal ; $value"),
        workspace=run.workspace, working_directory=".", environment={"BOUNDARY_VALUE": "not a shell"},
    )
    assert result.exit_code == 0 and not result.timed_out, result.stderr.decode(errors="replace")
    observed = json.loads(result.stdout)
    assert observed == {
        "uid": os.geteuid(), "gid": os.getegid(), "cwd": "/workspace",
        "network": ["lo"], "value": "not a shell",
    }
    assert observed["uid"] > 0 and observed["gid"] > 0
    assert (run.workspace / "boundary-output").read_text() == "literal ; $value"
    assert not (run.workspace.stat().st_mode & 0o022)
    assert_declared_files(run)


def test_timeout_closes_its_container_and_install_mounts(tmp_path):
    executor = executor_for("native", timeout=2)
    run = boundary_run(tmp_path)
    install = run.workspace.parent / "install"
    install.mkdir()
    leases = run.workspace.parent / "leases"
    executor.lease_directory = leases
    result = executor.execute(
        ("python3", "-c", "import time; time.sleep(60)"),
        workspace=run.workspace, working_directory=".", environment={}, install_dir=install,
    )
    assert result.timed_out and result.exit_code is None
    assert result.cleanup_complete
    lease_path, = leases.glob("*.json")
    lease = json.loads(lease_path.read_bytes())
    assert lease["container_closed"] is True and lease["mounts_closed"] is True
    inspected = subprocess.run(
        ["docker", "container", "inspect", lease["container"]],
        capture_output=True, text=True, check=False, timeout=10,
    )
    assert inspected.returncode == 1 and "no such" in inspected.stderr.lower(), inspected.stderr
    assert not (run.workspace.stat().st_mode & 0o022)
    assert not (install.stat().st_mode & 0o022)
    assert_declared_files(run)
