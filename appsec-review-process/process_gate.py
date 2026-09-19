"""Trusted process gate. POSIX EOF watchdog also cleans descendants on worker loss."""
import subprocess
import sys
import os
import signal
import threading

if os.read(0, 1) != b'1':
    raise SystemExit(125)
if os.name != 'nt':
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    def owner_watchdog():
        while os.read(0, 1):
            pass
        os.killpg(os.getpgrp(), signal.SIGKILL)
    threading.Thread(target=owner_watchdog, daemon=True).start()
try:
    raise SystemExit(subprocess.call(sys.argv[1:], stdin=subprocess.DEVNULL))
except OSError as exc:
    print(f'STARTUP_ERROR: {exc}', file=sys.stderr, flush=True)
    raise SystemExit(127)
