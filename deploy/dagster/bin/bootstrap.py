"""Create or normalize the ignored environment for this host's Dagster stack."""

from pathlib import Path
import os
import secrets
import shutil
import tempfile

from host import actual_platform, project_name, validate_workspace


deployment = Path(__file__).resolve().parents[1]
repository = deployment.parents[1]
environment = deployment / ".env"
platform = actual_platform()
validate_workspace(repository, platform)

lines = environment.read_text(encoding="utf-8").splitlines() if environment.exists() else []
existing = {line.split("=", 1)[0]: line.split("=", 1)[1] for line in lines
            if "=" in line and not line.lstrip().startswith("#")}
values: dict[str, object] = {
    "DAGSTER_POSTGRES_PASSWORD": existing.get("DAGSTER_POSTGRES_PASSWORD") or secrets.token_hex(32),
    "APPSEC_DEPLOYMENT_PLATFORM": platform,
    "APPSEC_COMPOSE_PROJECT": project_name(platform),
}
host_keys = {"APPSEC_UID", "APPSEC_GID", "APPSEC_DOCKER_GID", "APPSEC_CLAUDE_BINARY",
             "APPSEC_CLAUDE_CONFIG_DIR", "APPSEC_CLAUDE_STATE_FILE"}
if platform != "windows":
    values.update(APPSEC_UID=os.getuid(), APPSEC_GID=os.getgid())
    socket = Path("/var/run/docker.sock")
    if socket.exists():
        values["APPSEC_DOCKER_GID"] = socket.stat().st_gid
    claude = shutil.which("claude")
    config_dir = Path.home() / ".claude"
    state_file = Path.home() / ".claude.json"
    if claude and config_dir.is_dir() and state_file.is_file():
        values.update(APPSEC_CLAUDE_BINARY=Path(claude).resolve(),
                      APPSEC_CLAUDE_CONFIG_DIR=config_dir.resolve(),
                      APPSEC_CLAUDE_STATE_FILE=state_file.resolve())

managed = set(values) | host_keys
preserved = [line for line in lines if line.split("=", 1)[0] not in managed]
contents = "\n".join(preserved + [f"{key}={value}" for key, value in values.items()]) + "\n"
with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=deployment,
                                 prefix=".env-", delete=False) as stream:
    temporary = Path(stream.name)
    stream.write(contents)
try:
    temporary.chmod(0o600)
    temporary.replace(environment)
finally:
    temporary.unlink(missing_ok=True)
print(f"Dagster {platform} deployment environment is ready at {environment}.")
