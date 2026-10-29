"""Native Windows host behavior, simulated on POSIX by replacing ``core.windows_host``."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

from appsec_review.config import signing as signing_config
from appsec_review.signing import cli as signing_cli
from appsec_review.signing import core, modules


GIT_OPENSSL = r"C:\Program Files\Git\mingw64\bin\openssl.exe"


@pytest.fixture
def windows(monkeypatch) -> None:
    monkeypatch.setattr(core, "windows_host", lambda: True)
    for name in ("ProgramW6432", "ProgramFiles"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ProgramData", r"C:\ProgramData")


@pytest.mark.parametrize("value, absolute", [
    (GIT_OPENSSL, True), (r"\\server\share\openssl.exe", True), ("C:/Tools/openssl.exe", True),
    ("/usr/bin/openssl", False), (r"\usr\bin\openssl", False), ("C:openssl.exe", False),
    ("openssl.exe", False), ("", False)])
def test_windows_absolute_paths_need_a_drive_or_unc_share(windows, value, absolute) -> None:
    assert core.is_absolute_path(value) is absolute


def test_posix_absolute_paths_are_unchanged() -> None:
    assert core.is_absolute_path("/usr/bin/openssl")
    assert not core.is_absolute_path("usr/bin/openssl")
    assert not core.is_absolute_path(GIT_OPENSSL)
    assert core.default_openssl() == "/usr/bin/openssl"


def test_windows_default_openssl_prefers_an_existing_program_files_git(windows, monkeypatch) -> None:
    assert core.default_openssl() == GIT_OPENSSL
    monkeypatch.setenv("ProgramFiles", r"D:\Apps")
    expected = r"D:\Apps\Git\mingw64\bin\openssl.exe"
    monkeypatch.setattr(core.os.path, "isfile", lambda path: path == expected)
    assert core.default_openssl() == expected


def test_windows_openssl_environment_keeps_only_system_variables_and_the_binary_directory() -> None:
    environ = {"SystemRoot": r"C:\Windows", "windir": r"C:\Windows", "TEMP": r"C:\Temp", "TMP": r"C:\Temp",
               "PATHEXT": ".EXE", "ComSpec": r"C:\Windows\system32\cmd.exe", "PATH": r"C:\evil",
               "OPENSSL_CONF": r"C:\evil.cnf", "OPENSSL_MODULES": r"C:\evil", "OPENSSL_ENGINES": r"C:\evil",
               "PYTHONPATH": r"C:\evil"}
    environment = core.windows_openssl_environment(GIT_OPENSSL, r"C:\Temp\x\openssl.cnf", environ)
    assert environment == {
        "SYSTEMROOT": r"C:\Windows", "WINDIR": r"C:\Windows", "TEMP": r"C:\Temp", "TMP": r"C:\Temp",
        "PATHEXT": ".EXE", "COMSPEC": r"C:\Windows\system32\cmd.exe",
        "PATH": r"C:\Program Files\Git\mingw64\bin;C:\Windows\System32",
        "OPENSSL_CONF": r"C:\Temp\x\openssl.cnf"}


def test_windows_openssl_runs_with_an_empty_private_config_file(windows, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(core, "windows_host", lambda: False)
    openssl = core.OpenSSL("/usr/bin/openssl", temp_dir=str(tmp_path))
    monkeypatch.setattr(core, "windows_host", lambda: True)
    seen = []
    real_run = subprocess.run

    def recording_run(command, **kwargs):
        config = Path(kwargs["env"]["OPENSSL_CONF"])
        seen.append((config, config.read_bytes(), kwargs["cwd"], kwargs["env"]["PATH"]))
        return real_run(command, **kwargs)

    monkeypatch.setattr(core.subprocess, "run", recording_run)
    assert openssl.self_test()
    assert seen
    for config, data, cwd, path in seen:
        assert data == b""
        assert cwd == str(config.parent) and config.parent.parent == tmp_path
        assert path.split(";")[0] == "/usr/bin"
        assert not config.parent.exists()


def test_posix_openssl_environment_is_unchanged(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(core.subprocess, "run",
                        lambda command, **kwargs: calls.append(kwargs) or subprocess.CompletedProcess(command, 0, b"", b""))
    core.OpenSSL("/usr/bin/openssl")._run(["version"])
    assert calls[0]["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "OPENSSL_CONF": "/dev/null"}
    assert calls[0]["cwd"] == "/"


def test_windows_rejects_a_drive_less_openssl(windows) -> None:
    with pytest.raises(core.SignatureVerificationError, match="absolute path"):
        core.OpenSSL("/usr/bin/openssl")


def test_reparse_points_count_as_links() -> None:
    regular = SimpleNamespace(st_mode=stat.S_IFREG | 0o644)
    junction = SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
    assert not core.is_link_or_reparse_point(regular)
    assert core.is_link_or_reparse_point(junction)
    assert core.is_link_or_reparse_point(SimpleNamespace(st_mode=stat.S_IFLNK | 0o777))


def test_reading_a_reparse_point_file_is_refused(monkeypatch, tmp_path) -> None:
    target = tmp_path / "envelope.json"
    target.write_bytes(b"{}")
    monkeypatch.setattr(core, "is_link_or_reparse_point", lambda info: True)
    with pytest.raises(core.SignatureVerificationError, match="symbolic link"):
        core.read_envelope(target)


def _tree(root: Path) -> Path:
    (root / "sub").mkdir(parents=True)
    (root / "__init__.py").write_bytes(b"")
    (root / "sub" / "mod.py").write_bytes(b"VALUE = 1\r\n")
    return root


def test_manifest_paths_are_posix_relative_on_every_host(windows, tmp_path) -> None:
    files = modules.build_manifest(_tree(tmp_path / "pkg"))["files"]
    assert sorted(files) == ["__init__.py", "sub/mod.py"]
    assert all("\\" not in relpath for relpath in files)


def test_windows_walk_rejects_a_junction_in_the_package(windows, monkeypatch, tmp_path) -> None:
    root = _tree(tmp_path / "pkg")
    junction = os.lstat(root / "sub")
    real = core.is_link_or_reparse_point
    monkeypatch.setattr(core, "is_link_or_reparse_point",
                        lambda info: info.st_ino == junction.st_ino or real(info))
    with pytest.raises(core.SignatureVerificationError, match="symbolic links"):
        modules.build_manifest(root)


def test_windows_signing_config_defaults_use_program_data_and_git_openssl(windows) -> None:
    config = signing_config.SigningConfig()
    assert str(config.openssl) == GIT_OPENSSL
    assert str(config.trusted_keys_dir) == r"C:\ProgramData\appsec-review\signing\trusted-keys"
    assert str(config.image_signatures_dir) == r"C:\ProgramData\appsec-review\signing\images"


def test_windows_maps_the_repository_posix_defaults_and_refuses_other_rooted_paths(windows, tmp_path) -> None:
    parsed = signing_config.parse_signing({"openssl": "/usr/bin/openssl", "image_enforcement": "required"}, tmp_path)
    assert str(parsed.openssl) == GIT_OPENSSL
    assert signing_config._host_path("/etc/appsec-review/signing/trusted-keys", "trusted_keys_dir") == \
        r"C:\ProgramData\appsec-review\signing\trusted-keys"
    assert signing_config._host_path("/var/lib/appsec-review/signing/images", "image_signatures_dir") == \
        r"C:\ProgramData\appsec-review\signing\images"
    assert str(signing_config.parse_signing({"openssl": r"D:\Tools\openssl.exe"}, tmp_path).openssl) == \
        r"D:\Tools\openssl.exe"
    for value in ("/opt/openssl/bin/openssl", r"D:\Tools\..\openssl.exe", "openssl.exe"):
        with pytest.raises(ValueError, match="absolute path"):
            signing_config.parse_signing({"openssl": value}, tmp_path)
    with pytest.raises(ValueError, match="drive"):
        signing_config.parse_signing({"trusted_keys_dir": "/srv/keys"}, tmp_path)


def test_posix_signing_config_is_unchanged(tmp_path) -> None:
    config = signing_config.SigningConfig()
    assert config.view() == {"openssl": "/usr/bin/openssl",
                             "trusted_keys_dir": "/etc/appsec-review/signing/trusted-keys",
                             "image_signatures_dir": "/var/lib/appsec-review/signing/images",
                             "image_enforcement": "required"}
    assert signing_config.parse_signing({"trusted_keys_dir": "/srv/keys"}, tmp_path).trusted_keys_dir == \
        Path("/srv/keys")


def test_windows_private_key_directory_skips_posix_modes_but_not_links(windows, monkeypatch, tmp_path) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o777)
    os.chmod(directory, 0o777)
    signing_cli._private_parent(directory / "operator.pem")
    monkeypatch.setattr(core, "is_link_or_reparse_point", lambda info: True)
    with pytest.raises(ValueError, match="real directory"):
        signing_cli._private_parent(directory / "operator.pem")


def test_posix_private_key_directory_still_requires_0700(tmp_path) -> None:
    directory = tmp_path / "private"
    directory.mkdir()
    os.chmod(directory, 0o777)
    with pytest.raises(ValueError, match="0700"):
        signing_cli._private_parent(directory / "operator.pem")


def test_bootstrap_openssl_defaults_to_the_host_default() -> None:
    from appsec_review.signing import bootstrap

    assert bootstrap._parser().parse_args(
        ["--envelope", "/e", "--package-root", "/r", "--trusted-keys", "/k", "--module", "m"]).openssl is None
    environ = {"APPSEC_REVIEW_MODULE_SIGNATURE": "relative.json", "APPSEC_REVIEW_MODULE_ROOT": "/r",
               "APPSEC_REVIEW_TRUSTED_KEYS_DIR": "/k"}
    with pytest.raises(Exception, match=r"absolute: APPSEC_REVIEW_MODULE_SIGNATURE$"):
        bootstrap.activate_from_environment(environ)
