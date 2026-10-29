"""Acceptance tier: the frozen ``tiny-build`` command compiles and runs under process-tree capture.

Operator-run against a commissioned v8 broker (deploy/dagster/native/README.md, "Integration and
acceptance tests"). Skipped, with the unmet precondition named, unless ``APPSEC_NATIVE_ACCEPTANCE=1``,
the integration preconditions hold and the build driver is staged in the granted run root. The
command is the literal allowlisted ``tiny-build``: build-driver.sh traces
``gcc -o /scratch/hello /scratch/hello.c && /scratch/hello > /scratch/hello.out`` with strace.
"""

from __future__ import annotations

import re

import pytest

from tests.native_live_support import (
    ACCEPTANCE_ENV, BUILD_DRIVER_PREFIX, CONTAINER_ENVIRONMENT, capture_staging_reason, new_name, open_session,
    skip_reason)


_SKIP = skip_reason(ACCEPTANCE_ENV) or capture_staging_reason()
pytestmark = pytest.mark.skipif(_SKIP is not None, reason=_SKIP or "")

TINY_BUILD = "gcc -o /scratch/hello /scratch/hello.c && /scratch/hello > /scratch/hello.out"
HELLO = '#include <stdio.h>\nint main(void) { puts("hello native"); return 0; }\n'
TOOLCHAIN = re.compile(r'execve\("[^"]*/(?:gcc(?:-[0-9]+)?|cc1|collect2|ld(?:\.bfd|\.gold)?|x86_64-linux-gnu-gcc(?:-[0-9]+)?)"')


@pytest.fixture(scope="module")
def session(tmp_path_factory):
    return open_session(tmp_path_factory.mktemp("native-events") / "native-events.jsonl")


def test_tiny_build_compiles_runs_and_captures_compiler_process_tree(session):
    run = session.run_root
    for stale in ("hello", "hello.out"):
        (run / stale).unlink(missing_ok=True)
    (run / "hello.c").write_text(HELLO)
    before = set((run / "capture").glob("trace*"))
    name = new_name()
    argv = session.run_argv(name, "/bin/sh", [*BUILD_DRIVER_PREFIX, "/bin/sh", "-c", TINY_BUILD],
                            source=run, environment=CONTAINER_ENVIRONMENT)
    with session.reserved("tiny-build"):
        try:
            code, out, err, timed = session.client.run(argv, 120)
        finally:
            session.remove_if_owned(name)
    assert code == 0 and not timed, (code, out, err)
    assert session.client.executions[name]["state"] == "REMOVED"
    assert (run / "hello.out").read_bytes() == b"hello native\n"
    traces = sorted(set((run / "capture").glob("trace*")) - before)
    assert traces, "process-tree capture produced no trace artifact"
    assert any(TOOLCHAIN.search(path.read_text(errors="replace")) for path in traces), traces
