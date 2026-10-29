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
from tests.signing._host import OPENSSL_BINARY, POSIX_ONLY, symlink

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
    if os.name != "nt":
        assert _mode(private_key) == 0o600 and _mode(private_key.parent) == 0o700
    openssl = OpenSSL(OPENSSL_BINARY)
    expected = key_id(openssl.public_key_der(openssl.public_key_pem(private_key)))
    assert report["key_id"] == expected
    installed = trusted / f"{expected.removeprefix('sha256:')}.pem"
    assert report["trusted_key"] == str(installed)
    if os.name != "nt":
        assert _mode(installed) == 0o644
    assert installed.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")
    assert "PRIVATE KEY" not in json.dumps(report)


def test_keygen_refuses_to_overwrite_an_existing_private_key(tmp_path, capsys) -> None:
    private_key = tmp_path / "private" / "operator.pem"
    assert _main(capsys, "keygen", "--openssl", OPENSSL_BINARY, "--private-key", str(private_key))[0] == 0
    before = private_key.read_bytes()
    code, report = _main(capsys, "keygen", "--openssl", OPENSSL_BINARY, "--private-key", str(private_key))
    assert code == 1 and "refusing to overwrite" in report["error"]
    assert private_key.read_bytes() == before


@POSIX_ONLY
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


CVE_SOURCE = "jobs.job_third_party_data_sync.steps.cve_bin_tool_db_build.settings.image_id"


def _cve_document(**settings: object) -> dict:
    step = {"settings": {"image": "fixture/cve-bin-tool:3.4", "tool_version": "3.4", **settings}}
    return {"jobs": {"job_third_party_data_sync": {"settings": {}, "steps": {"cve_bin_tool_db_build": step}}}}


def test_pinned_images_include_the_cve_bin_tool_step_only_when_pinned() -> None:
    assert signing_cli.pinned_images([], _cve_document()) == []
    assert signing_cli.pinned_images([], _cve_document(image_id=IMAGE_A)) == [
        {"source": CVE_SOURCE, "tag": "fixture/cve-bin-tool:3.4", "image_id": IMAGE_A}]
    disabled = _cve_document(image_id=IMAGE_A)
    disabled["jobs"]["job_third_party_data_sync"]["settings"]["enabled"] = False
    assert signing_cli.pinned_images([], disabled) == []


def test_sign_all_pinned_signs_the_pinned_cve_bin_tool_image_only_when_its_tag_matches(
        tmp_path, capsys, key, config, local_images) -> None:
    (config.runtime.repository_root / "containers" / "catalog.toml").write_text("", encoding="utf-8")
    config.resolved_json = json.dumps(_cve_document(image_id=IMAGE_A)).encode()
    local_images["fixture/cve-bin-tool:3.4"] = IMAGE_B
    code, report = _main(capsys, "sign-image", "--all-pinned", "--private-key", str(key.private))
    assert code == 1 and [(row["source"], row["status"]) for row in report["images"]] == [
        (CVE_SOURCE, "mismatched")]
    local_images["fixture/cve-bin-tool:3.4"] = IMAGE_A
    code, report = _main(capsys, "sign-image", "--all-pinned", "--private-key", str(key.private))
    assert code == 0 and [(row["source"], row["status"]) for row in report["images"]] == [
        (CVE_SOURCE, "signed")]
    assert [path.name for path in (tmp_path / "signatures").iterdir()] == [f"{IMAGE_A.removeprefix('sha256:')}.json"]


def _builder_service_config(path: Path, *, proxy: str | None = None, inputs: dict[str, str] | None = None,
                            worker: str = IMAGE_B) -> Path:
    lines = ["[image_builder_service]", 'endpoint = "/run/builder/builder.sock"',
             'state_root = "/var/lib/builder"', 'release_id = "builder-release"',
             f'worker_image_id = "{worker}"', 'worker_release_id = "buildkit-release"',
             'host_cgroup = "/sys/fs/cgroup/builder-host"',
             'worker_cgroup_parent = "/sys/fs/cgroup/builder-workers"',
             'docker_endpoint = "/run/docker.sock"', 'docker_binary = "/usr/bin/docker"',
             'skopeo_binary = "/usr/bin/skopeo"', 'docker_release_id = "docker-release"',
             'skopeo_release_id = "skopeo-release"']
    if proxy is not None:
        lines += [f'network_id = "{"1" * 64}"', f'proxy_container_id = "{"2" * 64}"',
                  f'proxy_image_id = "{proxy}"', 'proxy_release_id = "proxy-release"',
                  'proxy_url = "http://172.30.0.2:3128"', 'ip_release_id = "iproute2-release"']
    lines += ["[image_builder_service.admission]", 'metadata_root = "/srv/runs/metadata"',
              "uid = 1000", "gid = 1000", f'lease_id = "{"3" * 32}"',
              "[[image_builder_service.grants]]", "uid = 1000", 'tenant_id = "tenant"',
              'project_id = "project"', 'run_id = "run-one"', 'run_root = "/srv/runs/run-one"',
              'target_snapshot = "target-one"', f'namespace = "{"4" * 24}"',
              'client_context_root = "/srv/runs/metadata/bounded-image-contexts"',
              'service_context_root = "/srv/runs/metadata/bounded-image-contexts"']
    for alias, image_id in (inputs or {}).items():
        lines += ["[[image_builder_service.images]]", f'alias = "{alias}"', f'image_id = "{image_id}"',
                  f'release_id = "{alias.replace(":", "-")}"']
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_builder_service_image_pins_list_worker_proxy_and_declared_inputs(tmp_path) -> None:
    path = _builder_service_config(tmp_path / "service.toml", proxy=IMAGE_C,
                                   inputs={"base:release": IMAGE_D, "tools:release": IMAGE_A})
    assert signing_cli.builder_service_image_pins(path) == [
        {"source": source, "tag": None, "image_id": image_id, "config": str(path)}
        for source, image_id in (("builder-service:worker", IMAGE_B), ("builder-service:proxy", IMAGE_C),
                                 ("builder-service:input:base:release", IMAGE_D),
                                 ("builder-service:input:tools:release", IMAGE_A))]
    without_proxy = _builder_service_config(tmp_path / "plain.toml", inputs={"base:release": IMAGE_D})
    assert [pin["source"] for pin in signing_cli.builder_service_image_pins(without_proxy)] == [
        "builder-service:worker", "builder-service:input:base:release"]


def test_builder_service_linux_paths_are_judged_as_posix_on_a_windows_operator_host(tmp_path,
                                                                                   monkeypatch) -> None:
    from pathlib import PureWindowsPath
    from appsec_review.config import assurance, image_builder_service

    for module in (assurance, image_builder_service):
        monkeypatch.setattr(module, "Path", PureWindowsPath)
    path = _builder_service_config(tmp_path / "service.toml", inputs={"base:release": IMAGE_D})
    service = image_builder_service.load_image_builder_service(path)
    assert service.endpoint == "/run/builder/builder.sock"
    assert service.client_policy.endpoint == service.endpoint
    for endpoint in ("run/builder/builder.sock", r"C:\run\builder.sock"):
        with pytest.raises(ValueError, match="absolute operator-owned Unix socket"):
            assurance.ImageBuilderConfig(endpoint, "builder-release", "tenant")
    relative = path.read_text(encoding="utf-8").replace(
        'endpoint = "/run/builder/builder.sock"', 'endpoint = "run/builder/builder.sock"')
    path.write_text(relative, encoding="utf-8")
    with pytest.raises(ValueError, match="canonical absolute Linux path"):
        image_builder_service.load_image_builder_service(path)


def test_sign_all_pinned_signs_builder_service_images_and_dedups_ids(
        tmp_path, capsys, key, config, local_images) -> None:
    (config.runtime.repository_root / "containers" / "catalog.toml").write_text(
        f'[[images]]\nid = "shared"\nstate = "enabled"\ntag = "fixture/shared:1"\nimage_id = "{IMAGE_A}"\n',
        encoding="utf-8")
    service = _builder_service_config(tmp_path / "service.toml", proxy=IMAGE_C,
                                      inputs={"base:release": IMAGE_D, "shared:release": IMAGE_A})
    local_images.update({"fixture/shared:1": IMAGE_A, "worker": IMAGE_B, "proxy": IMAGE_C, "base": IMAGE_D})
    signed: list[str] = []
    real_sign = signing_cli.sign_image

    def counting_sign(openssl, private_key, image_id, directory):
        signed.append(image_id)
        return real_sign(openssl, private_key, image_id, directory)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(signing_cli, "sign_image", counting_sign)
        code, report = _main(capsys, "sign-image", "--all-pinned", "--private-key", str(key.private),
                             "--builder-service-config", str(service),
                             "--builder-service-config", str(service))
    assert code == 0, report
    rows = {row["source"]: row for row in report["images"]}
    assert set(rows) == {"containers/catalog.toml images.shared.image_id", "builder-service:worker",
                         "builder-service:proxy", "builder-service:input:base:release",
                         "builder-service:input:shared:release"}
    assert {row["status"] for row in rows.values()} == {"signed"}
    assert rows["builder-service:worker"]["config"] == str(service)
    assert rows["builder-service:worker"]["resolved_image_id"] == IMAGE_B
    assert sorted(signed) == sorted([IMAGE_A, IMAGE_B, IMAGE_C, IMAGE_D])
    code, report = _main(capsys, "verify-image", IMAGE_B, IMAGE_C, IMAGE_D, "fixture/shared:1")
    assert code == 0, report


def test_sign_all_pinned_refuses_a_missing_or_mismatched_builder_service_image(
        tmp_path, capsys, key, config, local_images) -> None:
    (config.runtime.repository_root / "containers" / "catalog.toml").write_text("", encoding="utf-8")
    service = _builder_service_config(tmp_path / "service.toml", proxy=IMAGE_C,
                                      inputs={"base:release": IMAGE_D})
    local_images.update({"worker": IMAGE_B, "base": IMAGE_D})
    real_runner = signing_cli._inspect_runner

    def runner(command, **kwargs):
        # The daemon reports another .Id for the pinned input ID, so the pin does not resolve exactly.
        if command[-1] == IMAGE_D:
            return subprocess.CompletedProcess(command, 0, IMAGE_A.encode() + b"\n", b"")
        return real_runner(command, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(signing_cli, "_inspect_runner", runner)
        code, report = _main(capsys, "sign-image", "--all-pinned", "--private-key", str(key.private),
                             "--builder-service-config", str(service))
    assert code == 1
    status = {row["source"]: row["status"] for row in report["images"]}
    assert status == {"builder-service:worker": "signed", "builder-service:proxy": "inspect_failed",
                      "builder-service:input:base:release": "mismatched"}
    assert [path.name for path in (tmp_path / "signatures").iterdir()] == [f"{IMAGE_B.removeprefix('sha256:')}.json"]


def test_builder_service_config_errors_are_clear_and_sign_nothing(tmp_path, capsys, key, config,
                                                                   local_images) -> None:
    (config.runtime.repository_root / "containers" / "catalog.toml").write_text(
        f'[[images]]\nid = "shared"\nstate = "enabled"\ntag = "fixture/shared:1"\nimage_id = "{IMAGE_A}"\n',
        encoding="utf-8")
    local_images["fixture/shared:1"] = IMAGE_A
    missing = tmp_path / "absent.toml"
    code, report = _main(capsys, "sign-image", "--all-pinned", "--private-key", str(key.private),
                         "--builder-service-config", str(missing))
    assert code == 1 and report == {"error": f"builder service configuration is not a file: {missing}"}
    invalid = tmp_path / "invalid.toml"
    invalid.write_text("[image_builder_service]\nunknown = true\n", encoding="utf-8")
    code, report = _main(capsys, "sign-image", "--all-pinned", "--private-key", str(key.private),
                         "--builder-service-config", str(invalid))
    assert code == 1 and report["error"].startswith(f"invalid builder service configuration {invalid}: ")
    code, report = _main(capsys, "sign-image", "tool:1", "--private-key", str(key.private),
                         "--builder-service-config", str(invalid))
    assert code == 1 and report["error"] == "--builder-service-config requires --all-pinned"
    assert not (tmp_path / "signatures").exists()


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
        if os.name != "nt":
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
    symlink(directory / "modules.py", victim)
    code, report = _main(capsys, "export-bootstrap", str(directory))
    assert code == 1 and "symbolic link" in report["error"]
    assert victim.read_bytes() == b"original\n" and not (directory / "core.py").exists()

    linked = tmp_path / "linked"
    symlink(linked, tmp_path / "real", target_is_directory=True)
    (tmp_path / "real").mkdir()
    code, report = _main(capsys, "export-bootstrap", str(linked))
    assert code == 1 and "symbolic link" in report["error"]
    assert not any((tmp_path / "real").iterdir())
