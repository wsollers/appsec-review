"""Only the explicitly selected offline test files may be collected by the quality runner."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


def pytest_collection_finish(session: pytest.Session) -> None:
    expected = set(json.loads(os.environ["APPSEC_QUALITY_TEST_FILES"]))
    actual = {Path(str(item.path)).resolve().relative_to(session.config.rootpath.resolve()).as_posix()
              for item in session.items}
    if not session.items or actual != expected:
        raise pytest.UsageError(f"quality selector coverage mismatch: expected {sorted(expected)}, got {sorted(actual)}")


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        skipped = (reporter.stats.get("skipped", []) + reporter.stats.get("xfailed", [])
                   + reporter.stats.get("deselected", []))
        if skipped:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
            reporter.write_sep("!", "quality gate refuses skipped/xfail/deselected coverage")
