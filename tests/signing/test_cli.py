"""Unit tests for the ``appsec-review signing`` command group (real OpenSSL, faked ``docker image inspect``)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

from appsec_review import cli
from appsec_review.config.signing import SigningConfig
from appsec_review.signing import cli as signing_cli
from appsec_review.signing.core import OpenSSL, key_id


OPENSSL_BINARY = "/usr/bin/openssl"
IMAGE_A = "sha256:" + "a1" * 32
IMAGE_B = "sha256:" + "b2" * 32
IMAGE_C = "sha256:" + "c3" * 32
IMAGE_D = "sha256:" + "d4" * 32

pytestmark = pytest.mark.skipif(not os.path.isfile(OPENSSL_BINARY), reason="system OpenSSL is required")


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def _main(capsys, *argv: str) -> tuple[int, dict]:
    code = cli.main(["signing", *argv])
    return code, json.loads(capsys.readouterr().out)


@pytest.fixture
def local_images(monkeypatch) -> dict[str, str]:
    images: dict[str, str] = {}

    def runner(command, **_kwargs):
        assert command[:5] == ["docker", "image", "inspect", "--format", "{{.Id}}"]
        reference = command[-1]
        image = images.get(reference) or (reference if reference in images.values() else None)
        if image is None:
            return subprocess.CompletedProcess(command, 1, b"", f"Error: No such image: {reference}".encode())
        return subprocess.CompletedProcess(command, 0, image.encode() + b"\n", b"")

    monkeypatch.setattr(signing_cli, "_inspect_runner", runner)
    return images


@pytest.fixture
def key(tmp_path) -> SimpleNamespace:
    openssl = OpenSSL(OPENSSL_BINARY)
    private_key = openssl.generate_private_key(tmp_path / "keys" / "private" / "operator.pem")
    public_key_pem = openssl.public_key_pem(private_key)
    identity = key_id(openssl.public_key_der(public_key_pem))
    trusted = tmp_path / "keys" / "trusted"
    trusted.mkdir()
    (trusted / f"{identity.removeprefix('sha256:')}.pem").write_bytes(public_key_pem)
    return SimpleNamespace(private=private_key, trusted=trusted, key_id=identity)


@pytest.fixture
def config(tmp_path, key, monkeypatch) -> SimpleNamespace:
    root = tmp_path / "repository"
    (root / "containers").mkdir(parents=True)
    loaded = SimpleNamespace(
        runtime=SimpleNamespace(repository_root=root),
        signing=SigningConfig(openssl=Path(OPENSSL_BINARY), trusted_keys_dir=key.trusted,
                              image_signatures_dir=tmp_path / "signatures"),
        resolved_json=b"{}")
    monkeypatch.setattr(cli, "load_config", lambda *_args, **_kwargs: loaded)
    return loaded


def test_keygen_writes_private_key_0600_in_0700_dir_and_installs_the_trusted_key(tmp_path, capsys) -> None:
    private_key = tmp_path / "home" / "private" / "operator.pem"
    trusted = tmp_path / "trusted-keys"
    code, report = _main(capsys, "keygen", "--openssl", OPENSSL_BINARY, "--private-key", str(private_key),
                         "--trusted-keys-dir", str(trusted))
    assert code == 0
    assert _mode(private_key) == 0o600 and _mode(private_key.parent) == 0o700
    openssl = OpenSSL(OPENSSL_BINARY)
    expected = key_id(openssl.public_key_der(openssl.public_key_pem(private_key)))
    assert report["key_id"] == expected
    installed = trusted / f"{expected.removeprefix('sha256:')}.pem"
    assert report["trusted_key"] == str(installed) and _mode(installed) == 0o644
    assert installed.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")
    assert "PRIVATE KEY" not in json.dumps(report)


def test_keygen_refuses_to_overwrite_an_existing_private_key(tmp_path, capsys) -> None:
    private_key = tmp_path / "private" / "operator.pem"
    assert _main(capsys, "keygen", "--openssl", OPENSSL_BINARY, "--private-key", str(private_key))[0] == 0
    before = private_key.read_bytes()
    code, report = _main(capsys, "keygen", "--openssl", OPENSSL_BINARY, "--private-key", str(private_key))
    assert code == 1 and "refusing to overwrite" in report["error"]
    assert private_key.read_bytes() == before


def test_keygen_refuses_a_group_accessible_key_directory(tmp_path, capsys) -> None:
    directory = tmp_path / "shared"
    directory.mkdir()
    os.chmod(directory, 0o750)
    code, report = _main(capsys, "keygen", "--openssl", OPENSSL_BINARY,
                         "--private-key", str(directory / "operator.pem"))
    assert code == 1 and "0700" in report["error"]
    assert not (directory / "operator.pem").exists()


def test_keygen_uses_the_configured_openssl_by_default(tmp_path, capsys, config) -> None:
    code, report = _main(capsys, "keygen", "--private-key", str(tmp_path / "private" / "operator.pem"))
    assert code == 0 and report["key_id"].startswith("sha256:")


def test_sign_image_then_verify_image_round_trip(tmp_path, capsys, key, config, local_images) -> None:
    local_images.update({"tool:1": IMAGE_A, "tool:2": IMAGE_B})
    code, report = _main(capsys, "sign-image", "tool:1", "--private-key", str(key.private))
    assert code == 0
    envelope = tmp_path / "signatures" / f"{IMAGE_A.removeprefix('sha256:')}.json"
    assert report["images"] == [{"reference": "tool:1", "image_id": IMAGE_A, "envelope": str(envelope),
                                 "error": None, "status": "signed"}]
    code, report = _main(capsys, "verify-image", "tool:1")
    assert code == 0 and report["images"][0]["status"] == "verified"

    code, report = _main(capsys, "verify-image", "tool:1", "tool:2")
    assert code == 1
    assert [row["status"] for row in report["images"]] == ["verified", "failed"]
    assert "no signature envelope" in report["images"][1]["error"]


def test_verify_image_fails_against_an_untrusted_key(tmp_path, capsys, key, config, local_images) -> None:
    local_images["tool:1"] = IMAGE_A
    assert _main(capsys, "sign-image", "tool:1", "--private-key", str(key.private))[0] == 0
    empty = tmp_path / "no-trusted-keys"
    empty.mkdir()
    code, report = _main(capsys, "verify-image", "tool:1", "--trusted-keys-dir", str(empty))
    assert code == 1 and "not valid" in report["images"][0]["error"]


def test_sign_image_reports_an_uninspectable_reference(tmp_path, capsys, key, config, local_images) -> None:
    code, report = _main(capsys, "sign-image", "absent:1", "--private-key", str(key.private),
                         "--signatures-dir", str(tmp_path / "other"))
    assert code == 1 and report["images"][0]["status"] == "failed"
    assert "No such image" in report["images"][0]["error"]
    assert not (tmp_path / "other").exists()


def test_sign_image_requires_references_or_all_pinned(capsys, key, config) -> None:
    code, report = _main(capsys, "sign-image", "--private-key", str(key.private))
    assert code == 1 and "--all-pinned" in report["error"]
    code, report = _main(capsys, "sign-image", "tool:1", "--all-pinned", "--private-key", str(key.private))
    assert code == 1


CATALOG = f'''[[images]]
id = "matched"
state = "enabled"
tag = "fixture/matched:1"
image_id = "{IMAGE_A}"

[[images]]
id = "moved"
state = "enabled"
tag = "fixture/moved:1"
image_id = "{IMAGE_B}"

[[images]]
id = "unpinned"
state = "enabled"
tag = "fixture/unpinned:1"

[[images]]
id = "disabled"
state = "disabled"
tag = "fixture/disabled:1"
image_id = "{IMAGE_D}"
'''

DOCUMENT = {"jobs": {
    "job_project_build": {"settings": {"profiles": {"native": {"tag": "fixture/matched:1", "image_id": IMAGE_A}}}},
    "job_codeql_analysis": {"settings": {
        "source_image_tag": "fixture/matched:1", "source_image_id": IMAGE_A,
        "preinstalled_runtimes": [{"source_image_id": IMAGE_A, "build_image_id": IMAGE_A,
                                   "runtime_image_id": IMAGE_C}]}},
    "job_dossier_publication": {"settings": {"image_tag": "fixture/latex:1", "image_id": IMAGE_C}},
    "job_disabled": {"settings": {"enabled": False, "tag": "fixture/disabled:1", "image_id": IMAGE_D}},
}}


def test_pinned_images_adds_id_only_and_image_tag_pins_of_enabled_jobs() -> None:
    import tomllib
    pins = signing_cli.pinned_images(tomllib.loads(CATALOG)["images"], DOCUMENT)
    by_source = {pin["source"]: (pin["tag"], pin["image_id"]) for pin in pins}
    runtimes = "jobs.job_codeql_analysis.settings.preinstalled_runtimes[0]"
    assert by_source == {
        "containers/catalog.toml images.matched.image_id": ("fixture/matched:1", IMAGE_A),
        "containers/catalog.toml images.moved.image_id": ("fixture/moved:1", IMAGE_B),
        "containers/catalog.toml images.unpinned.image_id": ("fixture/unpinned:1", None),
        "jobs.job_codeql_analysis.settings.source_image_id": ("fixture/matched:1", IMAGE_A),
        f"{runtimes}.source_image_id": (None, IMAGE_A),
        f"{runtimes}.build_image_id": (None, IMAGE_A),
        f"{runtimes}.runtime_image_id": (None, IMAGE_C),
        "jobs.job_dossier_publication.settings.image_id": ("fixture/latex:1", IMAGE_C),
        "jobs.job_project_build.settings.profiles.native.image_id": ("fixture/matched:1", IMAGE_A),
    }


def test_sign_all_pinned_signs_matching_pins_and_never_a_mismatched_image(
        tmp_path, capsys, key, config, local_images) -> None:
    (config.runtime.repository_root / "containers" / "catalog.toml").write_text(CATALOG, encoding="utf-8")
    config.resolved_json = json.dumps(DOCUMENT).encode()
    # fixture/moved:1 now resolves to IMAGE_D, not its pin IMAGE_B; the runtime pin IMAGE_C is inspected by ID.
    local_images.update({"fixture/matched:1": IMAGE_A, "fixture/moved:1": IMAGE_D,
                         "fixture/unpinned:1": IMAGE_B, "fixture/latex:1": IMAGE_C})
    code, report = _main(capsys, "sign-image", "--all-pinned", "--private-key", str(key.private))
    assert code == 1
    status = {row["source"]: row["status"] for row in report["images"]}
    assert status["containers/catalog.toml images.moved.image_id"] == "mismatched"
    assert status["containers/catalog.toml images.unpinned.image_id"] == "skipped_unpinned"
    assert {value for source, value in status.items() if "moved" not in source and "unpinned" not in source} \
        == {"signed"}
    signatures = tmp_path / "signatures"
    assert sorted(path.name for path in signatures.iterdir()) == sorted(
        f"{image.removeprefix('sha256:')}.json" for image in (IMAGE_A, IMAGE_C))

    local_images["fixture/moved:1"] = IMAGE_B
    code, report = _main(capsys, "sign-image", "--all-pinned", "--private-key", str(key.private))
    assert code == 0
    code, report = _main(capsys, "verify-image", "fixture/moved:1", "fixture/latex:1", IMAGE_A)
    assert code == 0, report


PACKAGE = {"__init__.py": b"VALUE = 1\n", "core.py": b"def answer():\n    return 42\n",
           "sub/__init__.py": b"", "sub/leaf.py": b"LEAF = 'leaf'\n"}


def _package(root: Path) -> Path:
    for relpath, data in PACKAGE.items():
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def test_sign_modules_then_verify_modules_round_trip_and_tamper(tmp_path, capsys, key, config) -> None:
    root = _package(tmp_path / "site" / "appsec_review")
    envelope = tmp_path / "out" / "python-modules.json"
    code, report = _main(capsys, "sign-modules", "--private-key", str(key.private), "--output", str(envelope),
                         "--package-root", str(root))
    assert code == 0 and report["files"] == len(PACKAGE) and report["key_ids"] == [key.key_id]
    verify = ("verify-modules", "--envelope", str(envelope), "--trusted-keys-dir", str(key.trusted),
              "--package-root", str(root))
    code, report = _main(capsys, *verify)
    assert code == 0 and report["status"] == "verified" and report["files"] == len(PACKAGE)

    (root / "sub" / "leaf.py").write_bytes(b"LEAF = 'tampered'\n")
    code, report = _main(capsys, *verify)
    assert code == 1 and report["status"] == "failed" and "does not match" in report["error"]


def test_verify_modules_rejects_an_unlisted_file_and_an_untrusted_key(tmp_path, capsys, key, config) -> None:
    root = _package(tmp_path / "appsec_review")
    envelope = tmp_path / "python-modules.json"
    assert _main(capsys, "sign-modules", "--private-key", str(key.private), "--output", str(envelope),
                 "--package-root", str(root))[0] == 0
    empty = tmp_path / "empty-trust"
    empty.mkdir()
    code, report = _main(capsys, "verify-modules", "--envelope", str(envelope), "--trusted-keys-dir", str(empty),
                         "--package-root", str(root))
    assert code == 1 and report["status"] == "failed"
    (root / "extra.py").write_bytes(b"EXTRA = 1\n")
    code, report = _main(capsys, "verify-modules", "--envelope", str(envelope), "--trusted-keys-dir",
                         str(key.trusted), "--package-root", str(root))
    assert code == 1 and "not in the signed manifest" in report["error"]


def test_sign_modules_refuses_an_envelope_inside_the_package(tmp_path, capsys, key, config) -> None:
    root = _package(tmp_path / "appsec_review")
    code, report = _main(capsys, "sign-modules", "--private-key", str(key.private),
                         "--output", str(root / "python-modules.json"), "--package-root", str(root))
    assert code == 1 and "outside the signed package tree" in report["error"]
    assert not (root / "python-modules.json").exists()


def test_sign_modules_defaults_to_the_installed_package(capsys, key, config, tmp_path) -> None:
    envelope = tmp_path / "installed.json"
    code, report = _main(capsys, "sign-modules", "--private-key", str(key.private), "--output", str(envelope))
    assert code == 0
    assert report["package_root"] == str(Path(signing_cli.__file__).resolve().parent.parent)
    assert "signing/cli.py" in json.loads(envelope.read_bytes())["statement"]["subject"]["files"]


def test_sign_release_lib_then_verify_release_lib_round_trip_and_tamper(tmp_path, capsys, key, config) -> None:
    library = tmp_path / "release" / "lib"
    _package(library / "appsec_review")
    (library / "dep").mkdir()
    (library / "dep" / "__init__.py").write_bytes(b"DEP = 1\n")
    (library / "dep.pth").write_bytes(b"dep\n")
    envelope = tmp_path / "release" / "signing" / "python-release-lib.json"
    code, report = _main(capsys, "sign-release-lib", "--private-key", str(key.private), "--output", str(envelope),
                         "--lib", str(library))
    assert code == 0 and report["files"] == 2 and report["key_ids"] == [key.key_id]
    verify = ("verify-release-lib", "--envelope", str(envelope), "--trusted-keys-dir", str(key.trusted),
              "--lib", str(library))
    code, report = _main(capsys, *verify)
    assert code == 0 and report["status"] == "verified" and report["files"] == 2

    (library / "dep" / "extra.py").write_bytes(b"EXTRA = 1\n")
    code, report = _main(capsys, *verify)
    assert code == 1 and report["status"] == "failed" and "not in the signed manifest" in report["error"]


def test_sign_release_lib_refuses_an_envelope_inside_the_library(tmp_path, capsys, key, config) -> None:
    library = tmp_path / "lib"
    library.mkdir()
    code, report = _main(capsys, "sign-release-lib", "--private-key", str(key.private),
                         "--output", str(library / "python-release-lib.json"), "--lib", str(library))
    assert code == 1 and "outside the signed release library" in report["error"]
    assert not (library / "python-release-lib.json").exists()


def test_export_bootstrap_copies_files_byte_identically(tmp_path, capsys) -> None:
    directory = tmp_path / "release" / "signing"
    code, report = _main(capsys, "export-bootstrap", str(directory))
    assert code == 0 and sorted(report["files"]) == sorted(signing_cli.BOOTSTRAP_FILES)
    assert "release_lib.py" in report["files"]
    source = Path(signing_cli.__file__).resolve().parent
    for name in signing_cli.BOOTSTRAP_FILES:
        assert (directory / name).read_bytes() == (source / name).read_bytes()
        assert _mode(directory / name) == 0o644
    assert sorted(path.name for path in directory.iterdir()) == sorted(signing_cli.BOOTSTRAP_FILES)
    # Re-exporting over regular files replaces them.
    (directory / "core.py").write_bytes(b"stale\n")
    assert _main(capsys, "export-bootstrap", str(directory))[0] == 0
    assert (directory / "core.py").read_bytes() == (source / "core.py").read_bytes()


def test_export_bootstrap_refuses_symbolic_link_targets(tmp_path, capsys) -> None:
    directory = tmp_path / "export"
    directory.mkdir()
    victim = tmp_path / "victim.py"
    victim.write_bytes(b"original\n")
    (directory / "modules.py").symlink_to(victim)
    code, report = _main(capsys, "export-bootstrap", str(directory))
    assert code == 1 and "symbolic link" in report["error"]
    assert victim.read_bytes() == b"original\n" and not (directory / "core.py").exists()

    linked = tmp_path / "linked"
    linked.symlink_to(tmp_path / "real", target_is_directory=True)
    (tmp_path / "real").mkdir()
    code, report = _main(capsys, "export-bootstrap", str(linked))
    assert code == 1 and "symbolic link" in report["error"]
    assert not any((tmp_path / "real").iterdir())
