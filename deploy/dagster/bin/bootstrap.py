"""Create the ignored local Compose secret without overwriting an existing one."""

from pathlib import Path
import os
import secrets
import shutil


deployment = Path(__file__).resolve().parents[1]
environment = deployment / ".env"
try:
    with environment.open("x", encoding="utf-8") as stream:
        stream.write(f"DAGSTER_POSTGRES_PASSWORD={secrets.token_hex(32)}\n")
except FileExistsError:
    print(f"Preserved existing {environment}")
else:
    environment.chmod(0o600)
    print(f"Created {environment}")

if not environment.exists():
    raise SystemExit("could not create deployment environment")
if hasattr(os, "getuid"):
    text = environment.read_text(encoding="utf-8")
    keys = {line.partition("=")[0] for line in text.splitlines() if "=" in line}
    values: list[tuple[str, object]] = [
        ("APPSEC_UID", os.getuid()), ("APPSEC_GID", os.getgid()),
    ]
    claude = shutil.which("claude")
    config_dir = Path.home() / ".claude"
    state_file = Path.home() / ".claude.json"
    if claude and config_dir.is_dir() and state_file.is_file():
        values.extend((
            ("APPSEC_CLAUDE_BINARY", Path(claude).resolve()),
            ("APPSEC_CLAUDE_CONFIG_DIR", config_dir.resolve()),
            ("APPSEC_CLAUDE_STATE_FILE", state_file.resolve()),
        ))
    additions = [
        f"{key}={value}"
        for key, value in values
        if key not in keys
    ]
    if additions:
        with environment.open("a", encoding="utf-8") as stream:
            stream.write(("" if text.endswith("\n") else "\n") + "\n".join(additions) + "\n")
        print("Recorded native-Linux operator and available Claude CLI bind paths.")
print("Dagster deployment environment is ready.")
