import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from appsec_review.signing.core import OpenSSL, key_id
from appsec_review.signing.modules import sign_modules
from appsec_review.signing.release_lib import sign_release_lib


REPOSITORY = Path(__file__).parents[1]
SIGNING_SOURCE = REPOSITORY / "src/appsec_review/signing"
SPEC = importlib.util.spec_from_file_location(
    "native_root_entrypoint",
    REPOSITORY / "deploy/dagster/native/root_entrypoint.py")
assert SPEC is not None and SPEC.loader is not None
entrypoint = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(entrypoint)


def _signing_layout(release: Path) -> None:
    signing = release / "signing"
    (signing / "trusted-keys").mkdir(parents=True)
    (signing / "bootstrap").mkdir()
    (signing / "python-modules.json").write_text("{}")
    (signing / "python-release-lib.json").write_text("{}")
    for name in entrypoint.SIGNING_BOOTSTRAP_FILES:
        shutil.copyfile(SIGNING_SOURCE / name, signing / "bootstrap" / name)


@pytest.fixture
def installed_release(tmp_path, monkeypatch):
    release = tmp_path / "release"
    package = release / "lib/appsec_review"
    (package / "container_runtime").mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "container_runtime/image_builder_service.py").write_text("")
    _signing_layout(release)
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


@pytest.mark.parametrize("operation", [
    "reserve-lifetime", "reconcile-admission", "release-lifetime", "finalize-commissioning",
])
def test_installed_root_lifecycle_preserves_isolated_launch_boundary(installed_release, operation):
    python, bootstrap, config = installed_release
    specification = entrypoint.launch_spec(python, bootstrap, config, operation=operation)
    assert specification["argv"] == (
        str(python), "-I", "-S", str(bootstrap), "--config", str(config), "--operation", operation)
    assert specification["environment"] == entrypoint.ROOT_ENVIRONMENT


def test_installed_root_lifecycle_is_not_an_arbitrary_command_entrypoint(installed_release):
    with pytest.raises(ValueError, match="unsupported"):
        entrypoint.launch_spec(*installed_release, operation="docker run --privileged")


@pytest.mark.parametrize("operation", [
    "reconcile-retired-admission", "release-prior-lifetime", "reconcile-prior-engine"])
def test_retired_recovery_separates_current_and_prior_private_configurations(installed_release, operation):
    python, bootstrap, config = installed_release
    prior = config.with_name("prior.toml")
    prior.write_text("# unchanged retired operator fixture")
    prior.chmod(0o600)
    spec = entrypoint.launch_spec(
        python, bootstrap, config, operation=operation, prior_configuration=prior)
    assert spec["argv"][-4:] == (
        "--operation", operation, "--prior-config", str(prior))
    prior.chmod(0o644)
    with pytest.raises(PermissionError, match="prior.*private"):
        entrypoint.launch_spec(
            python, bootstrap, config, operation=operation, prior_configuration=prior)


@pytest.mark.parametrize("operation", [
    "serve", "reconcile-admission", "reconcile-retired-admission", "release-prior-lifetime",
    "reconcile-prior-engine",
])
def test_prior_configuration_cannot_be_ignored_or_implicitly_assumed(installed_release, operation):
    python, bootstrap, config = installed_release
    with pytest.raises(ValueError, match="separate prior"):
        entrypoint.launch_spec(
            python, bootstrap, config, operation=operation,
            prior_configuration=None if operation in {
                "reconcile-retired-admission", "release-prior-lifetime",
                "reconcile-prior-engine"} else config)


@pytest.mark.parametrize("missing", [
    "signing/python-modules.json", "signing/python-release-lib.json", "signing/trusted-keys",
    "signing/bootstrap/bootstrap.py", "signing/bootstrap/core.py", "signing/bootstrap/modules.py",
    "signing/bootstrap/import_hook.py", "signing/bootstrap/release_lib.py",
])
def test_root_launch_requires_the_installed_module_signature_and_verifier(installed_release, missing):
    python, bootstrap, config = installed_release
    path = bootstrap.parent / missing
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()
    with pytest.raises(OSError):
        entrypoint.launch_spec(python, bootstrap, config)


@pytest.mark.parametrize("unsafe", ["writable-trust-anchor", "linked-verifier", "envelope-directory"])
def test_root_launch_rejects_unsafe_signing_inputs(installed_release, unsafe):
    python, bootstrap, config = installed_release
    signing = bootstrap.parent / "signing"
    if unsafe == "writable-trust-anchor":
        anchor = signing / "trusted-keys" / f"{'0' * 64}.pem"
        anchor.write_text("fixture")
        anchor.chmod(0o664)
    elif unsafe == "linked-verifier":
        core = signing / "bootstrap/core.py"
        core.rename(core.with_name("real_core.py"))
        core.symlink_to(core.with_name("real_core.py"))
    else:
        envelope = signing / "python-modules.json"
        envelope.unlink()
        envelope.mkdir()
    with pytest.raises(PermissionError):
        entrypoint.launch_spec(python, bootstrap, config)


SERVICE = """\
import json, sys
from pathlib import Path
Path(sys.argv[2]).with_suffix(".ran").write_text(json.dumps({
    "argv": sys.argv, "loader": type(__spec__.loader).__name__,
    "first_finder": type(sys.meta_path[0]).__name__, "path": sys.path,
    "verifier": sorted(name for name in sys.modules if name.startswith("appsec_review_signing_"))}))
"""

# Simulates root ownership, a read-only mount and euid 0; everything else is the real isolated startup.
ROOT_SIMULATION = """\
import importlib.util, os, sys, tempfile
from pathlib import Path
from types import SimpleNamespace
original = Path.lstat
def root_owned(path, *args, **kwargs):
    values = list(original(path, *args, **kwargs))
    values[4] = 0
    return os.stat_result(values)
Path.lstat = root_owned
os.statvfs = lambda path: SimpleNamespace(f_flag=os.ST_RDONLY)
os.geteuid = lambda: 0
sys.executable = os.path.realpath(sys.executable)
tempfile.tempdir = sys.argv[3]
spec = importlib.util.spec_from_file_location("root_entrypoint", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.main(["--config", sys.argv[2]])
"""


@pytest.fixture
def signed_release(tmp_path):
    if not os.path.isfile(str(entrypoint.OPENSSL)):
        pytest.skip("system OpenSSL is required")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    openssl = OpenSSL(str(entrypoint.OPENSSL), temp_dir=str(scratch))
    private_key = openssl.generate_private_key(tmp_path / "operator/private/modules.pem")
    release = tmp_path / "release"
    package = release / "lib/appsec_review"
    (package / "container_runtime").mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "container_runtime/image_builder_service.py").write_text(SERVICE)
    dependency = release / "lib/fakedep"
    dependency.mkdir()
    (dependency / "__init__.py").write_text("")
    (release / "lib/fakedep-1.0.dist-info").mkdir()
    (release / "lib/fakedep-1.0.dist-info/METADATA").write_text("Name: fakedep\n")
    _signing_layout(release)
    envelope = release / "signing/python-modules.json"
    envelope.unlink()
    sign_modules(openssl, private_key, package, envelope)
    library_envelope = release / "signing/python-release-lib.json"
    library_envelope.unlink()
    sign_release_lib(openssl, private_key, release / "lib", library_envelope)
    public_key_pem = openssl.public_key_pem(private_key)
    anchor = key_id(openssl.public_key_der(public_key_pem)).removeprefix("sha256:")
    (release / f"signing/trusted-keys/{anchor}.pem").write_bytes(public_key_pem)
    shutil.copyfile(REPOSITORY / "deploy/dagster/native/root_entrypoint.py", release / "root_entrypoint.py")
    config = tmp_path / "service.toml"
    config.write_text("# operator fixture")
    config.chmod(0o600)
    return release, config, scratch


def _run_root_entrypoint(release: Path, config: Path, scratch: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", ROOT_SIMULATION, str(release / "root_entrypoint.py"),
         str(config), str(scratch)],
        capture_output=True, text=True, timeout=120, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})


def test_root_entrypoint_runs_the_service_only_through_the_verified_import_hook(signed_release):
    release, config, scratch = signed_release
    result = _run_root_entrypoint(release, config, scratch)
    assert result.returncode == 0, result.stderr
    report = json.loads(config.with_suffix(".ran").read_text())
    assert report["argv"] == ["appsec-review-image-builder", "--config", str(config)]
    assert report["loader"] == "VerifiedSourceLoader"
    assert report["first_finder"] == "VerifiedFinder"
    assert report["path"][-1] == str(release / "lib")
    assert report["path"].count(str(release / "lib")) == 1
    assert report["verifier"] == [
        "appsec_review_signing_bootstrap", "appsec_review_signing_core", "appsec_review_signing_import_hook",
        "appsec_review_signing_modules"]
    assert not list((release / "lib").rglob("__pycache__"))


@pytest.mark.parametrize("tamper", ["service", "unlisted", "envelope", "trust-anchor", "dependency",
                                    "unlisted-dependency", "missing-dependency", "dependency-pycache",
                                    "library-envelope"])
def test_root_entrypoint_rejects_tampered_release_before_running_the_service(signed_release, tamper):
    release, config, scratch = signed_release
    package = release / "lib/appsec_review"
    if tamper == "service":
        service = package / "container_runtime/image_builder_service.py"
        service.write_text(SERVICE + "# changed\n")
    elif tamper == "unlisted":
        (package / "container_runtime/__init__.py").write_text("")
    elif tamper == "envelope":
        envelope = release / "signing/python-modules.json"
        signed = json.loads(envelope.read_text())
        signed["statement"]["subject"]["files"]["__init__.py"] = "sha256:" + "0" * 64
        envelope.write_text(json.dumps(signed))
    elif tamper == "dependency":
        (release / "lib/fakedep/__init__.py").write_text("import os\n")
    elif tamper == "unlisted-dependency":
        (release / "lib/evil.pth").write_text("import os\n")
    elif tamper == "missing-dependency":
        (release / "lib/fakedep-1.0.dist-info/METADATA").unlink()
    elif tamper == "dependency-pycache":
        (release / "lib/fakedep/__pycache__").mkdir()
    elif tamper == "library-envelope":
        (release / "signing/python-release-lib.json").write_text("{}")
    else:
        for anchor in (release / "signing/trusted-keys").iterdir():
            anchor.unlink()
    result = _run_root_entrypoint(release, config, scratch)
    assert result.returncode != 0
    assert "SignatureVerificationError" in result.stderr
    assert not config.with_suffix(".ran").exists()
