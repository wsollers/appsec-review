"""The Dagster deployment builds, signs and verifies its image on the host before Compose launches it."""

from __future__ import annotations

import json
from pathlib import Path
import re
import stat
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / "deploy" / "dagster"
sys.path.insert(0, str(DEPLOYMENT / "bin"))
import host  # noqa: E402
import image_signing  # noqa: E402
import lifecycle  # noqa: E402
import smoke  # noqa: E402

SIGNED = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "APPSEC_SIGNING_PYTHON": "/venv/bin/python",
               "APPSEC_SIGNING_PRIVATE_KEY": "/keys/operator.pem",
               "APPSEC_SIGNING_TRUSTED_KEYS_DIR": "/trust", "APPSEC_SIGNING_IMAGE_SIGNATURES_DIR": "/sigs",
               "APPSEC_SIGNING_OPENSSL": "/usr/bin/openssl"}
SIGNING_TARGETS = {"/etc/appsec-review/signing/trusted-keys", "/var/lib/appsec-review/signing/images"}


class FakeRunner:
    """Stands in for the signing CLI, docker build and docker compose; records every command."""

    def __init__(self, *, verified: str | None = SIGNED, verify_rc: int = 0, verify_stdout: str | None = None,
                 build_rc: int = 0) -> None:
        self.calls: list[tuple[list[str], dict]] = []
        self.verified, self.verify_rc, self.verify_stdout, self.build_rc = verified, verify_rc, verify_stdout, build_rc

    def __call__(self, command, **kwargs):
        self.calls.append((list(command), kwargs))
        if "signing" in command:
            step = command[command.index("signing") + 1]
            if step == "sign-modules":
                return self.reply({"envelope": command[command.index("--output") + 1], "files": 3}, 0)
            if step == "verify-modules":
                return self.reply({"status": "verified"}, 0)
            if step == "sign-image":
                return self.reply({"images": [{"status": "signed", "image_id": SIGNED}]}, 0)
            if step == "verify-image":
                if self.verify_stdout is not None:
                    return subprocess.CompletedProcess(command, self.verify_rc, self.verify_stdout, "")
                row = ({"status": "verified", "image_id": self.verified, "error": None} if self.verify_rc == 0
                       else {"status": "failed", "image_id": SIGNED, "error": "no signature envelope"})
                return self.reply({"images": [row]}, self.verify_rc)
        if command[:2] == ["docker", "build"]:
            return subprocess.CompletedProcess(command, self.build_rc, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    @staticmethod
    def reply(report: dict, rc: int) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess([], rc, json.dumps(report), "")

    def steps(self) -> list[str]:
        names = []
        for command, _ in self.calls:
            if "signing" in command:
                names.append(command[command.index("signing") + 1])
            else:
                names.append(" ".join(command[:2]))
        return names

    def compose_calls(self) -> list[tuple[list[str], dict]]:
        return [(command, kwargs) for command, kwargs in self.calls if command[:2] == ["docker", "compose"]]


@pytest.fixture
def env_file(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / ".env"
    path.write_text("APPSEC_COMPOSE_PROJECT=appsec-review-dagster-wsl\nAPPSEC_REVIEW_DAGSTER_IMAGE=" + OTHER
                    + "\nDAGSTER_POSTGRES_PASSWORD=secret\n", encoding="utf-8")
    monkeypatch.setattr(lifecycle, "environment_file", path)
    return path


def test_build_signs_modules_then_builds_signs_and_verifies_the_image(env_file: Path) -> None:
    runner = FakeRunner()
    assert lifecycle.run_action("build", "wsl", "dev", ENVIRONMENT, runner=runner) == lifecycle.OK
    assert runner.steps() == ["sign-modules", "verify-modules", "docker build", "sign-image", "verify-image"]
    commands = [command for command, _ in runner.calls]
    sign_modules = commands[0]
    assert sign_modules[:4] == ["/venv/bin/python", "-m", "appsec_review", "signing"]
    assert sign_modules[sign_modules.index("--output") + 1] == str(ROOT / "deploy/dagster/signing/python-modules.json")
    assert sign_modules[sign_modules.index("--package-root") + 1] == str(ROOT / "src/appsec_review")
    assert sign_modules[sign_modules.index("--private-key") + 1] == "/keys/operator.pem"
    assert commands[1][commands[1].index("--trusted-keys-dir") + 1] == "/trust"
    build = commands[2]
    assert build[build.index("--target") + 1] == "runtime"
    assert build[build.index("--tag") + 1] == "appsec-review-dagster:wsl"
    assert runner.calls[2][1]["env"]["DOCKER_BUILDKIT"] == "1"
    assert commands[3][commands[3].index("sign-image") + 1] == "appsec-review-dagster:wsl"
    assert commands[4][commands[4].index("verify-image") + 1] == SIGNED
    assert runner.calls[0][1]["env"]["PYTHONPATH"].split(":")[0] == str(ROOT / "src")
    assert runner.compose_calls() == []


def test_build_stops_when_the_image_build_fails(env_file: Path) -> None:
    runner = FakeRunner(build_rc=1)
    assert lifecycle.run_action("build", "wsl", "dev", ENVIRONMENT, runner=runner) == lifecycle.FAILED
    assert runner.steps() == ["sign-modules", "verify-modules", "docker build"]


@pytest.mark.parametrize(("platform", "profile", "target", "tag"), [
    ("wsl", "dev", "runtime", "appsec-review-dagster:wsl"),
    ("linux", "prod", "runtime", "appsec-review-dagster:linux"),
    ("windows", "dev", "runtime-windows", "appsec-review-dagster:windows"),
    ("windows", "copilot-prod", "runtime-copilot", "appsec-review-dagster:windows-copilot"),
    ("wsl", "copilot-dev", "runtime-copilot", "appsec-review-dagster:wsl-copilot"),
])
def test_each_profile_builds_its_signature_enforcing_final_stage(platform, profile, target, tag) -> None:
    assert host.image_target(platform, profile) == target
    assert host.image_tag(platform, profile) == tag


@pytest.mark.parametrize("runner", [
    FakeRunner(verify_rc=1),
    FakeRunner(verify_stdout="Traceback: not json", verify_rc=1),
    FakeRunner(verify_stdout=json.dumps({"images": [{"status": "verified", "image_id": "sha256:short"}]})),
    FakeRunner(verify_stdout=json.dumps({"images": []})),
], ids=["unsigned", "no-report", "malformed-id", "no-image"])
@pytest.mark.parametrize("action", ["start", "reload"])
def test_launch_refuses_an_unverified_image_without_running_compose(env_file: Path, runner, action) -> None:
    before = env_file.read_bytes()
    runner.calls.clear()
    assert lifecycle.run_action(action, "wsl", "dev", ENVIRONMENT, runner=runner) == lifecycle.REFUSED
    assert runner.steps() == ["verify-image"]
    assert runner.compose_calls() == []
    assert env_file.read_bytes() == before


def test_launch_refuses_a_tampered_image_whose_id_differs_from_the_requested_one(env_file: Path) -> None:
    runner = FakeRunner(verified=OTHER)
    environ = {**ENVIRONMENT, host.IMAGE_VARIABLE: SIGNED}
    assert lifecycle.run_action("start", "wsl", "dev", environ, runner=runner) == lifecycle.REFUSED
    assert runner.compose_calls() == []


def test_start_verifies_then_launches_exactly_the_verified_id(env_file: Path) -> None:
    runner = FakeRunner()
    assert lifecycle.run_action("start", "wsl", "dev", ENVIRONMENT, runner=runner) == lifecycle.OK
    assert runner.steps() == ["verify-image", "docker compose"]
    verify = runner.calls[0][0]
    assert verify[verify.index("verify-image") + 1] == "appsec-review-dagster:wsl"
    assert verify[verify.index("--signatures-dir") + 1] == "/sigs"
    assert verify[verify.index("--trusted-keys-dir") + 1] == "/trust"
    (command, kwargs), = runner.compose_calls()
    assert command[-3:] == ["up", "-d", "--wait"]
    assert command[command.index("-f", command.index("-f") + 1) + 1].endswith("compose.claude.yaml")
    assert kwargs["env"][host.IMAGE_VARIABLE] == SIGNED
    assert kwargs["env"]["APPSEC_SIGNING_TRUSTED_KEYS_DIR"] == "/trust"
    assert kwargs["env"]["APPSEC_SIGNING_IMAGE_SIGNATURES_DIR"] == "/sigs"
    lines = env_file.read_text(encoding="utf-8").splitlines()
    assert lines == ["APPSEC_COMPOSE_PROJECT=appsec-review-dagster-wsl", "DAGSTER_POSTGRES_PASSWORD=secret",
                     f"{host.IMAGE_VARIABLE}={SIGNED}"]
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600


def test_explicit_image_is_verified_by_id(env_file: Path) -> None:
    runner = FakeRunner()
    environ = {**ENVIRONMENT, host.IMAGE_VARIABLE: SIGNED}
    assert lifecycle.run_action("reload", "wsl", "copilot-dev", environ, runner=runner) == lifecycle.OK
    assert runner.calls[0][0][runner.calls[0][0].index("verify-image") + 1] == SIGNED
    (command, kwargs), = runner.compose_calls()
    assert command[-len(host.IMAGE_SERVICES):] == list(host.IMAGE_SERVICES) and "--force-recreate" in command
    assert command[command.index("-f", command.index("-f") + 1) + 1].endswith("compose.copilot.yaml")
    assert kwargs["env"][host.IMAGE_VARIABLE] == SIGNED


def test_non_launching_actions_never_verify_and_use_a_placeholder_only_without_a_record(env_file: Path) -> None:
    runner = FakeRunner()
    assert lifecycle.run_action("config", "wsl", "dev", ENVIRONMENT, runner=runner) == lifecycle.OK
    (_, kwargs), = runner.compose_calls()
    assert host.IMAGE_VARIABLE not in kwargs["env"]  # Compose reads the recorded ID from .env.
    env_file.write_text("APPSEC_COMPOSE_PROJECT=appsec-review-dagster-wsl\n", encoding="utf-8")
    for action in ("status", "logs", "stop"):
        runner = FakeRunner()
        assert lifecycle.run_action(action, "wsl", "dev", ENVIRONMENT, runner=runner) == lifecycle.OK
        assert runner.steps() == ["docker compose"]
        assert runner.compose_calls()[0][1]["env"][host.IMAGE_VARIABLE] == host.UNVERIFIED_IMAGE


def test_signing_settings_default_to_the_configured_host_directories() -> None:
    settings = image_signing.SigningSettings.load({})
    config = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    assert f'trusted_keys_dir = "{settings.trusted_keys_dir.as_posix()}"' in config
    assert f'image_signatures_dir = "{settings.image_signatures_dir.as_posix()}"' in config
    assert f'openssl = "{settings.openssl.as_posix()}"' in config
    assert settings.private_key.name == "operator.pem"


def _compose(name: str) -> dict:
    return yaml.safe_load((DEPLOYMENT / name).read_text(encoding="utf-8"))


def test_compose_launches_only_the_verified_image_with_read_only_signing_mounts() -> None:
    compose = _compose("compose.yaml")
    anchor = compose["x-dagster-service"]
    assert anchor["image"].startswith("${APPSEC_REVIEW_DAGSTER_IMAGE:?")
    assert anchor["pull_policy"] == "never"
    services = compose["services"]
    for name in ("code-location", "webserver", "daemon"):
        service = services[name]
        assert service["image"] == anchor["image"] and service["pull_policy"] == "never"
        assert "build" not in service
        mounts = {item["target"]: item for item in service["volumes"] if isinstance(item, dict)}
        assert set(mounts) == SIGNING_TARGETS
        for target, mount in mounts.items():
            assert mount["type"] == "bind" and mount["read_only"] is True
            assert mount["bind"]["create_host_path"] is False
            variable = ("APPSEC_SIGNING_TRUSTED_KEYS_DIR" if target.startswith("/etc")
                        else "APPSEC_SIGNING_IMAGE_SIGNATURES_DIR")
            assert mount["source"] == f"${{{variable}:-{target}}}"
    for overlay in ("compose.copilot.yaml", "compose.windows.yaml", "compose.claude.yaml"):
        for name, service in (_compose(overlay).get("services") or {}).items():
            assert "image" not in service and "build" not in service, (overlay, name)


COMPOSE_FILES = sorted(path.name for path in DEPLOYMENT.glob("compose*.yaml"))
REQUIRED_IMAGE = re.compile(r"\$\{APPSEC_REVIEW_DAGSTER_IMAGE:\?APPSEC_REVIEW_DAGSTER_IMAGE must be a "
                            r"host-verified sha256 image id; start through deploy/dagster/bin/ops\.py\}")


def _image_services(document: dict) -> dict[str, dict]:
    return {name: service for name, service in (document.get("services") or {}).items()
            if host.IMAGE_VARIABLE in str(service.get("image", ""))}


def test_every_dagster_image_reference_requires_the_verified_id_without_a_default() -> None:
    assert {"compose.yaml", "compose.windows.yaml", "compose.copilot.yaml", "compose.claude.yaml"} <= set(
        COMPOSE_FILES)
    for name in COMPOSE_FILES:
        text = (DEPLOYMENT / name).read_text(encoding="utf-8")
        references = re.findall(r"\$\{?" + host.IMAGE_VARIABLE + r"[^}\s]*\}?[^\n]*", text)
        assert all(REQUIRED_IMAGE.fullmatch(item) for item in references), (name, references)
        for service_name, service in _image_services(yaml.safe_load(text)).items():
            assert REQUIRED_IMAGE.fullmatch(service["image"]), (name, service_name)
            assert service.get("pull_policy") == "never" and "build" not in service, (name, service_name)
        if name != "compose.yaml":
            for service_name, service in (yaml.safe_load(text).get("services") or {}).items():
                assert not {"image", "build", "pull_policy"} & set(service), (name, service_name)


def test_image_services_constant_matches_the_compose_file() -> None:
    services = _image_services(_compose("compose.yaml"))
    assert set(host.IMAGE_SERVICES) == set(services) and len(host.IMAGE_SERVICES) == len(services)
    assert smoke.APPLICATION_SERVICES == host.IMAGE_SERVICES
    for overlay in COMPOSE_FILES:
        assert set(_compose(overlay).get("services") or {}) <= set(_compose("compose.yaml")["services"]), overlay


def test_env_example_provides_no_launchable_image() -> None:
    path = DEPLOYMENT / ".env.example"
    assert host.IMAGE_VARIABLE not in host.read_environment(path)
    active = [line for line in path.read_text(encoding="utf-8").splitlines()
              if host.IMAGE_VARIABLE in line and not line.lstrip().startswith("#")]
    assert active == []


def test_reload_verifies_then_recreates_every_image_service_but_not_postgres(env_file: Path) -> None:
    runner = FakeRunner()
    assert lifecycle.run_action("reload", "wsl", "dev", ENVIRONMENT, runner=runner) == lifecycle.OK
    assert runner.steps() == ["verify-image", "docker compose"]
    (command, kwargs), = runner.compose_calls()
    up = command.index("up")
    assert command[up:up + 5] == ["up", "-d", "--no-deps", "--force-recreate", "--wait"]
    assert set(command[up + 5:]) == set(_image_services(_compose("compose.yaml")))
    assert "postgres" not in command
    assert kwargs["env"][host.IMAGE_VARIABLE] == SIGNED


def test_smoke_config_check_requires_the_signed_image_contract() -> None:
    services = _compose("compose.yaml")["services"]
    resolved = {name: {**service, "image": SIGNED, "volumes": [
        item for item in service.get("volumes", []) if isinstance(item, dict)]}
        for name, service in services.items()}
    smoke.check_signed_image(resolved)
    resolved["daemon"] = {**resolved["daemon"], "image": OTHER}
    with pytest.raises(RuntimeError, match="share one verified image"):
        smoke.check_signed_image(resolved)
    resolved["daemon"] = {**resolved["daemon"], "image": SIGNED,
                          "volumes": [{**item, "read_only": False} for item in resolved["daemon"]["volumes"]]}
    with pytest.raises(RuntimeError, match="read-only"):
        smoke.check_signed_image(resolved)


def _stages(dockerfile: str) -> dict[str, str]:
    code = "\n".join(line for line in dockerfile.splitlines() if not line.lstrip().startswith("#"))
    stages = {}
    for block in code.split("\nFROM ")[1:]:
        header, _, body = block.partition("\n")
        stages[header.rsplit(" AS ", 1)[1]] = header + "\n" + body
    return stages


def test_dockerfile_enforces_signed_modules_only_in_the_final_stages() -> None:
    dockerfile = (DEPLOYMENT / "Dockerfile").read_text(encoding="utf-8")
    stages = _stages(dockerfile)
    base = stages["runtime-base"]
    assert "apt-get install -y --no-install-recommends docker-cli openssl \\\n" in base
    assert "/opt/appsec-review/signing-bootstrap/" in base
    for name in ("bootstrap.py", "core.py", "modules.py", "import_hook.py", "sitecustomize_shim.py"):
        assert f"src/appsec_review/signing/{name}" in base
    assert ("COPY --chown=0:0 --chmod=0644 src/appsec_review/signing/sitecustomize_shim.py "
            "/usr/local/lib/python3.12/sitecustomize.py\n") in base
    for line in ("APPSEC_REVIEW_SIGNING_BOOTSTRAP_DIR=/opt/appsec-review/signing-bootstrap",
                 "APPSEC_REVIEW_MODULE_ROOT=/usr/local/lib/python3.12/site-packages/appsec_review",
                 "APPSEC_REVIEW_TRUSTED_KEYS_DIR=/etc/appsec-review/signing/trusted-keys",
                 "APPSEC_REVIEW_OPENSSL=/usr/bin/openssl"):
        assert line in base
    assert "sys.modules['sitecustomize'].__file__ == '/usr/local/lib/python3.12/sitecustomize.py'" in base
    assert 'test "$status" = 78' in base
    assert base.index("pip install --no-cache-dir --no-build-isolation --no-deps .") < base.index("sitecustomize.py")
    assert "APPSEC_REVIEW_MODULE_SIGNATURE" not in base
    assert "    APPSEC_REVIEW_REQUIRE_SIGNED_MODULES=1\n" not in base
    for name in ("runtime-copilot-base", "runtime-windows-base", "test"):
        assert "APPSEC_REVIEW_REQUIRE_SIGNED_MODULES" not in stages[name]
        assert "python-modules.json" not in stages[name]
    for name, parent in (("runtime", "runtime-base"), ("runtime-copilot", "runtime-copilot-base"),
                         ("runtime-windows", "runtime-windows-base")):
        stage = stages[name]
        assert stage.startswith(f"{parent} AS {name}\n")
        assert ("COPY --chown=0:0 --chmod=0644 deploy/dagster/signing/python-modules.json "
                "/opt/appsec-review/signing/python-modules.json\n") in stage
        assert "APPSEC_REVIEW_MODULE_SIGNATURE=/opt/appsec-review/signing/python-modules.json" in stage
        assert "APPSEC_REVIEW_REQUIRE_SIGNED_MODULES=1\n" in stage
        assert "RUN " not in stage
    assert stages["test"].startswith("runtime-base AS test\n")


def test_module_envelope_is_ignored_but_reaches_the_build_context() -> None:
    assert "/deploy/dagster/signing/python-modules.json" in (ROOT / ".gitignore").read_text(encoding="utf-8")
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert not any(line.strip().startswith(("deploy/dagster/signing", "deploy/dagster/**")) for line in ignored)
    assert image_signing.MODULE_ENVELOPE.as_posix() == "deploy/dagster/signing/python-modules.json"


def test_signing_settings_default_to_host_paths(monkeypatch) -> None:
    for name in ("ProgramW6432", "ProgramFiles"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ProgramData", r"C:\ProgramData")
    posix = image_signing.SigningSettings.load({}, windows=False)
    assert (str(posix.openssl), str(posix.trusted_keys_dir), str(posix.image_signatures_dir)) == (
        "/usr/bin/openssl", "/etc/appsec-review/signing/trusted-keys", "/var/lib/appsec-review/signing/images")
    windows = image_signing.host_defaults(windows=True)
    assert windows == {"APPSEC_SIGNING_OPENSSL": r"C:\Program Files\Git\mingw64\bin\openssl.exe",
                       "APPSEC_SIGNING_TRUSTED_KEYS_DIR": r"C:\ProgramData\appsec-review\signing\trusted-keys",
                       "APPSEC_SIGNING_IMAGE_SIGNATURES_DIR": r"C:\ProgramData\appsec-review\signing\images"}
    overridden = image_signing.SigningSettings.load({"APPSEC_SIGNING_OPENSSL": r"D:\ssl\openssl.exe"}, windows=True)
    assert str(overridden.openssl) == r"D:\ssl\openssl.exe"
    assert overridden.compose_environment() == {
        "APPSEC_SIGNING_TRUSTED_KEYS_DIR": windows["APPSEC_SIGNING_TRUSTED_KEYS_DIR"],
        "APPSEC_SIGNING_IMAGE_SIGNATURES_DIR": windows["APPSEC_SIGNING_IMAGE_SIGNATURES_DIR"]}