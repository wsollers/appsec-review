"""Create local Compose configuration once; never overwrite an existing instance password.

On a POSIX host it also records the operator's uid/gid (APPSEC_UID / APPSEC_GID) so the runtime
containers run as the operator instead of root. Without that, on native Linux, everything a
container creates under the bind-mounted runs/ is owned by root (the host-side launcher cannot
write beside it) and git refuses the operator-owned mounted target as "dubious ownership".
Docker Desktop and Windows have no os.getuid and need neither; the compose default stays root.
Existing lines are never changed: a value is appended only when its key is absent.

It also creates .host/ (ADR-0011: the host code location's DAGSTER_HOME, compute logs, artifacts)
as the operator. Otherwise `compose up` creates the compute-logs bind source as root first, and the
host code location can no longer write under .host/.
"""
import os
from pathlib import Path
import secrets

path = Path(__file__).resolve().parent / '.env'
try:
    with path.open('x', encoding='utf-8') as stream:
        stream.write('DAGSTER_POSTGRES_PASSWORD=' + secrets.token_hex(32) + '\n')
    print('Created ignored local Compose configuration.')
except FileExistsError:
    print('Existing local Compose configuration preserved.')

if hasattr(os, 'getuid'):
    text = path.read_text(encoding='utf-8')
    present = {line.split('=', 1)[0].strip() for line in text.splitlines() if '=' in line}
    wanted = {'APPSEC_UID': os.getuid(), 'APPSEC_GID': os.getgid()}
    missing = [f'{key}={value}\n' for key, value in wanted.items() if key not in present]
    if missing:
        with path.open('a', encoding='utf-8') as stream:
            stream.write(('' if text.endswith('\n') or not text else '\n') + ''.join(missing))
        print('Recorded the operator uid/gid for the runtime containers.')

for name in ('home', 'compute-logs', 'artifacts'):
    (path.parent / '.host' / name).mkdir(parents=True, exist_ok=True)
