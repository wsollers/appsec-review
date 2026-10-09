#!/usr/bin/python3
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading


root = Path(os.environ["APPSEC_CAPTURE_ROOT"])
tool = sys.argv[1]
argv = sys.argv[2:]
real = shutil.which(tool, path=os.environ["APPSEC_CAPTURE_REAL_PATH"])
if real is None:
    print(f"capture wrapper could not resolve {tool}", file=sys.stderr)
    raise SystemExit(127)

counter_path = root / "tool-call-counter"
counter_path.touch(exist_ok=True)
with counter_path.open("r+") as counter:
    fcntl.flock(counter, fcntl.LOCK_EX)
    text = counter.read().strip()
    ordinal = int(text or "0") + 1
    counter.seek(0)
    counter.truncate()
    counter.write(str(ordinal))
    counter.flush()
    fcntl.flock(counter, fcntl.LOCK_UN)

limit = int(os.environ["APPSEC_CAPTURE_CALL_LIMIT"])
if ordinal > limit:
    os.execv(real, [real, *argv])

call_root = root / "tool-calls" / f"{ordinal:08d}-{tool.replace('/', '_')}"
call_root.mkdir(parents=True)
stdout_path, stderr_path = call_root / "stdout", call_root / "stderr"
process = subprocess.Popen([real, *argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
sizes = {"stdout": 0, "stderr": 0}


def pump(source, destination: Path, target, name: str) -> None:
    with destination.open("wb") as stream:
        while chunk := source.read(65536):
            sizes[name] += len(chunk)
            target.buffer.write(chunk)
            target.buffer.flush()
            stream.write(chunk)


threads = (
    threading.Thread(target=pump, args=(process.stdout, stdout_path, sys.stdout, "stdout")),
    threading.Thread(target=pump, args=(process.stderr, stderr_path, sys.stderr, "stderr")),
)
for thread in threads:
    thread.start()
return_code = process.wait()
for thread in threads:
    thread.join()


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


redacted = set(json.loads((root / "envp-redact-names.json").read_text(encoding="utf-8")))
environment = ({key: ("<redacted>" if key in redacted else value)
                for key, value in sorted(os.environ.items())
                if not key.startswith("APPSEC_CAPTURE_")}
               if os.environ["APPSEC_CAPTURE_ENVP"] == "1" else {})
record = {
    "schema": "appsec-review/build-tool-call/1", "ordinal": ordinal, "tool": tool,
    "executable": real, "argv": [tool, *argv], "environment": environment,
    "environment_captured": os.environ["APPSEC_CAPTURE_ENVP"] == "1",
    "environment_redacted_names": sorted(key for key in environment if key in redacted),
    "exit_code": return_code,
    "stdout": {"uri": "stdout", "bytes": sizes["stdout"], "retained_bytes": stdout_path.stat().st_size,
               "truncated": False, "storage": "complete-file", "sha256": digest(stdout_path)},
    "stderr": {"uri": "stderr", "bytes": sizes["stderr"], "retained_bytes": stderr_path.stat().st_size,
               "truncated": False, "storage": "complete-file", "sha256": digest(stderr_path)},
}
(call_root / "record.json").write_text(
    json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
# The fixed container UID owns these files on a native Linux bind mount.  Permit the host
# orchestrator to copy and replace the completed subtree before scanning and retention; it will
# immediately recreate the subtree with run-owner-only permissions.
for path in (stdout_path, stderr_path, call_root / "record.json"):
    path.chmod(0o666)
call_root.chmod(0o777)
call_root.parent.chmod(0o777)
raise SystemExit(return_code)
