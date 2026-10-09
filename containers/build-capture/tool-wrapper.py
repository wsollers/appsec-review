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
stream_limit = int(os.environ["APPSEC_CAPTURE_STREAM_LIMIT"])
process = subprocess.Popen([real, *argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
sizes = {"stdout": 0, "stderr": 0}


def pump(source, destination: Path, target, name: str) -> None:
    retained = 0
    with destination.open("wb") as stream:
        while chunk := source.read(65536):
            sizes[name] += len(chunk)
            target.buffer.write(chunk)
            target.buffer.flush()
            if retained < stream_limit:
                selected = chunk[:stream_limit - retained]
                stream.write(selected)
                retained += len(selected)


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
    return hashlib.sha256(path.read_bytes()).hexdigest()


redacted = ("TOKEN", "SECRET", "PASSWORD", "PASSWD", "AUTH", "COOKIE", "PRIVATE", "KEY")
environment = {key: ("<redacted>" if any(part in key.upper() for part in redacted) else value)
               for key, value in sorted(os.environ.items())
               if not key.startswith("APPSEC_CAPTURE_")}
record = {
    "schema": "appsec-review/build-tool-call/1", "ordinal": ordinal, "tool": tool,
    "executable": real, "argv": [tool, *argv], "environment": environment,
    "exit_code": return_code,
    "stdout": {"uri": "stdout", "bytes": sizes["stdout"], "retained_bytes": stdout_path.stat().st_size,
               "truncated": sizes["stdout"] > stdout_path.stat().st_size, "sha256": digest(stdout_path)},
    "stderr": {"uri": "stderr", "bytes": sizes["stderr"], "retained_bytes": stderr_path.stat().st_size,
               "truncated": sizes["stderr"] > stderr_path.stat().st_size, "sha256": digest(stderr_path)},
}
(call_root / "record.json").write_text(
    json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
raise SystemExit(return_code)
