from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest

from appsec_review.acceptance.lanes import LaneWorkspace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy" / "dagster" / "bin"))
import ops_tests  # noqa: E402


def arguments(**overrides) -> argparse.Namespace:
    return argparse.Namespace(**{
        "suite": None, "extra": [], "acceptance": "quick", "workers": None,
        "deadline": None, "case_deadline": None, "parallel": False,
        "background": False, "strict": False, "dry_run": False, **overrides})


def owned_workspace(tmp_path: Path) -> LaneWorkspace:
    workspace = LaneWorkspace.create(ROOT, "runner-test")
    # Test-created case files are read-only inputs; every subprocess output remains invocation-owned.
    return workspace


def execute(tmp_path: Path, source: str, *, seconds: float = 20,
            prerequisites: tuple[str, ...] = ()) -> tuple[dict, LaneWorkspace]:
    path = tmp_path / "test_micro.py"
    path.write_text(source, encoding="utf-8")
    workspace = owned_workspace(tmp_path)
    outcome = ops_tests.supervised_pytest(
        sys.executable, [str(path)], workspace, "micro",
        deadline=time.monotonic() + seconds, prerequisites=prerequisites)
    return outcome, workspace


def test_owned_job_fixture_and_local_transport(acceptance_runs_dir: Path, acceptance_workspace) -> None:
    assert acceptance_runs_dir == acceptance_workspace.runs_dir
    assert acceptance_runs_dir.is_relative_to(acceptance_workspace.root)
    path = acceptance_runs_dir / "fixture.json"
    path.write_text('{"job":"fixture","production":false}\n', encoding="utf-8")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        with socket.create_connection(listener.getsockname(), timeout=1) as client:
            peer, _ = listener.accept()
            with peer:
                client.sendall(b"fixture")
                assert peer.recv(7) == b"fixture"
    assert json.loads(path.read_text(encoding="utf-8"))["production"] is False


def test_supervisor_reports_actual_resources_and_production_format(tmp_path: Path) -> None:
    outcome, workspace = execute(tmp_path, "def test_micro():\n    assert sum(range(100)) == 4950\n")
    assert outcome["outcome"] == "completed", outcome
    assert outcome["exit_code"] == 0
    assert outcome["cleanup"]["confirmed"]
    case = outcome["pytest"]["cases"][0]
    assert case["outcome"] == "passed" and case["duration_seconds"] > 0
    assert case["resources"]["cpu_user_seconds"] >= 0
    assert "io_unavailable_reason" in case["resources"]
    assert case["resources"]["peak_rss_bytes"] is None
    assert case["resources"]["peak_rss_unavailable_reason"]
    records, torn = workspace.pipeline.read()
    assert not torn
    assert all(record["schema"] == "appsec-review/telemetry-event/1" for record in records)
    assert all(record["trigger"] == "acceptance" for record in records)
    assert records[-1]["event_type"] == "OPERATION_COMPLETED"
    assert workspace.pipeline.path.is_relative_to(workspace.driver_root)


@pytest.mark.parametrize("source,expected", [
    ("def test_bad():\n    assert False\n", "failed"),
    ("import pytest\ndef test_skip():\n    pytest.skip('required unavailable')\n", "skipped"),
    ("import pytest\n@pytest.mark.xfail(reason='still required')\ndef test_xfail():\n    assert False\n", "xfail"),
    ("import pytest\n@pytest.mark.xfail(reason='unexpected pass')\ndef test_xpass():\n    pass\n", "xpass"),
    ("import pytest\n@pytest.fixture\ndef broken():\n    yield\n    assert False\n"
     "def test_teardown(broken):\n    pass\n", "failed"),
])
def test_required_failure_skip_xfail_xpass_and_teardown_are_rejected(
        tmp_path: Path, source: str, expected: str) -> None:
    outcome, _ = execute(tmp_path, source)
    assert outcome["exit_code"] != 0, outcome
    assert outcome["pytest"]["cases"][0]["outcome"] == expected
    assert outcome["cleanup"]["confirmed"]


@pytest.mark.parametrize("source", ["value = 1\n", "raise ValueError('collection failure')\n",
                                    "import pytest\npytest.skip('module unavailable', allow_module_level=True)\n"])
def test_empty_collection_errors_and_module_skips_are_rejected(tmp_path: Path, source: str) -> None:
    outcome, _ = execute(tmp_path, source)
    assert outcome["exit_code"] != 0, outcome
    assert outcome["cleanup"]["confirmed"]


def test_missing_prerequisites_fail_without_a_success_shaped_skip(tmp_path: Path) -> None:
    outcome, _ = execute(tmp_path, "def test_ok(): pass\n",
                         prerequisites=("python:appsec_nonexistent_required_dependency",))
    assert outcome["exit_code"] != 0
    assert outcome["pytest"]["prerequisites"] == [{
        "name": "python:appsec_nonexistent_required_dependency", "available": False,
        "reason": "ModuleNotFoundError"}]
    assert outcome["pytest"]["cases"] == []
    assert outcome["cleanup"]["confirmed"]


def test_real_hard_case_deadline_kills_only_owned_tree(tmp_path: Path) -> None:
    unrelated = subprocess.Popen([sys._base_executable, "-c", "import time; time.sleep(60)"],
                                  cwd=tmp_path, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        started = time.monotonic()
        outcome, workspace = execute(tmp_path,
            "import os, pathlib, subprocess, sys, time\n"
            "def test_hang():\n"
            "    root = pathlib.Path(os.environ['APPSEC_ACCEPTANCE_ROOT'])\n"
            "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
            "cwd=root, start_new_session=(os.name != 'nt'))\n"
            "    (root / 'child.pid').write_text(str(child.pid))\n"
            "    time.sleep(60)\n", seconds=6)
        assert time.monotonic() - started < 7
        assert outcome["outcome"] == "timeout", outcome
        assert outcome["cleanup"]["confirmed"], outcome
        assert outcome["cleanup"]["remaining_processes"] == 0
        assert outcome["cleanup"]["observed_processes"] >= 2
        assert (workspace.root / "child.pid").is_file(), outcome
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=3)


def test_completed_case_with_leaked_descendant_is_not_credited(tmp_path: Path) -> None:
    outcome, _ = execute(tmp_path,
        "import os, subprocess, sys\n"
        "def test_leak():\n"
        "    subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
        "cwd=os.environ['APPSEC_ACCEPTANCE_ROOT'])\n")
    assert outcome["outcome"] == "error"
    assert outcome["reason"] == "test_left_descendants_running"
    assert outcome["cleanup"]["confirmed"] and outcome["cleanup"]["observed_processes"] >= 2


def test_worker_death_keeps_owned_supervisor_alive_for_descendant_cleanup(tmp_path: Path) -> None:
    outcome, _ = execute(tmp_path,
        "import os, subprocess, sys\n"
        "def test_death():\n"
        "    subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
        "cwd=os.environ['APPSEC_ACCEPTANCE_ROOT'], start_new_session=(os.name != 'nt'))\n"
        "    os._exit(7)\n")
    assert outcome["exit_code"] == 7
    assert outcome["outcome"] == "error"
    assert outcome["cleanup"]["confirmed"] and outcome["cleanup"]["remaining_processes"] == 0
    assert outcome["pytest"]["cases"][0]["outcome"] == "interrupted"


def test_environment_removes_deployment_selection_and_credentials(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APPSEC_REVIEW_PROFILE", "prod")
    monkeypatch.setenv("APPSEC_NATIVE_CONFIG", "production.json")
    monkeypatch.setenv("APPSEC_PYTHON", "borrowed-python")
    monkeypatch.setenv("DAGSTER_HOME", "production-dagster")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "never-inherit")
    monkeypatch.setenv("PYTEST_ADDOPTS", "-n auto")
    workspace = owned_workspace(tmp_path)
    environment = ops_tests.acceptance_environment(workspace)
    for key in ("APPSEC_REVIEW_PROFILE", "APPSEC_NATIVE_CONFIG", "APPSEC_PYTHON",
                "ANTHROPIC_API_KEY", "PYTEST_ADDOPTS"):
        assert key not in environment
    assert Path(environment["DAGSTER_HOME"]).is_relative_to(workspace.root)
    assert Path(environment["APPSEC_ACCEPTANCE_RUNS_DIR"]) == workspace.runs_dir
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"


def test_hermetic_guard_refuses_external_writes_commands_and_connections(tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("unchanged", encoding="utf-8")
    outcome, _ = execute(tmp_path,
        "import pathlib, socket, subprocess, pytest\n"
        "def test_guard():\n"
        f"    with pytest.raises(PermissionError): pathlib.Path({str(sentinel)!r}).write_text('changed')\n"
        "    with pytest.raises(PermissionError): subprocess.run(['docker', 'info'])\n"
        "    with socket.socket() as connection:\n"
        "        with pytest.raises(PermissionError): connection.connect(('192.0.2.1', 12345))\n")
    assert outcome["exit_code"] == 0, outcome
    assert sentinel.read_text(encoding="utf-8") == "unchanged"


def test_suite_deadline_includes_collection_cases_and_cleanup(tmp_path: Path, monkeypatch) -> None:
    case_file = tmp_path / "test_suite.py"
    case_file.write_text("import time\ndef test_first(): time.sleep(60)\ndef test_second(): time.sleep(60)\n",
                         encoding="utf-8")
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({
        "profiles": {"quick": {"tier": "hermetic", "deadline_seconds": 9,
                                "case_deadline_seconds": 6, "obligations": ["bounded"]}},
        "obligations": [{"id": "bounded", "nodes": [case_file.relative_to(ROOT).as_posix()]}],
    }), encoding="utf-8")
    monkeypatch.setattr(ops_tests, "INVENTORY", inventory)
    monkeypatch.delenv("APPSEC_PYTHON", raising=False)
    before = set((ROOT / "test" / "tmp" / "acceptance").glob("*/quick/result.json"))
    started = time.monotonic()
    assert ops_tests.run_acceptance(arguments(), ROOT) == 1
    assert time.monotonic() - started < 10
    new = set((ROOT / "test" / "tmp" / "acceptance").glob("*/quick/result.json")) - before
    assert len(new) == 1
    result = json.loads(new.pop().read_text(encoding="utf-8"))
    assert result["failed_obligations"] == ["bounded"]
    assert result["executed_obligations"] == ["bounded"]
    assert result["cleanup"]["confirmed"]
    assert result["duration_seconds"] < result["budget"]["suite_seconds"]
    assert len(result["cases"]) == 2
    assert all(not case["passed"] for case in result["cases"])


@pytest.mark.parametrize("overrides", [
    {"parallel": True}, {"background": True}, {"suite": "fast"},
    {"extra": ["-k", "something"]}, {"deadline": 721}, {"case_deadline": 61}, {"workers": 3},
    {"case_deadline": 3},
])
def test_acceptance_rejects_unsafe_or_unbounded_options(overrides: dict) -> None:
    assert ops_tests.run_acceptance(arguments(**overrides), ROOT) == 2


def test_unconfirmed_cleanup_cannot_pass_even_with_successful_pytest(monkeypatch, capsys) -> None:
    monkeypatch.delenv("APPSEC_PYTHON", raising=False)
    inventory = json.loads((ROOT / ops_tests.INVENTORY).read_text(encoding="utf-8"))
    nodes = [node for item in inventory["obligations"]
             if item["id"] in inventory["profiles"]["quick"]["obligations"] for node in item["nodes"]]

    def fake_supervisor(python, arguments, workspace, key, **options):
        collecting = "--collect-only" in arguments
        return {"outcome": "completed", "exit_code": 0, "cleanup": {"confirmed": collecting},
                "pytest": {"collected": nodes if collecting else arguments, "prerequisites": [],
                           "cases": [] if collecting else [{"node": arguments[0], "outcome": "passed"}]}}

    monkeypatch.setattr(ops_tests, "supervised_pytest", fake_supervisor)
    assert ops_tests.run_acceptance(arguments(), ROOT) == 1
    path = Path(capsys.readouterr().out.split("result: ", 1)[1].strip())
    result = json.loads(path.read_text(encoding="utf-8"))
    assert "cleanup_unconfirmed" in result["failures"] and result["cleanup"]["confirmed"] is False
    assert result["failed_obligations"]


def test_deferred_profiles_fail_instead_of_claiming_optional_coverage(monkeypatch, capsys) -> None:
    monkeypatch.delenv("APPSEC_PYTHON", raising=False)
    assert ops_tests.run_acceptance(arguments(acceptance="provider"), ROOT) == 1
    path = Path(capsys.readouterr().out.split("result: ", 1)[1].strip())
    result = json.loads(path.read_text(encoding="utf-8"))
    assert result["passed"] is False
    assert "profile_not_implemented" in result["failures"]
    assert not result["cases"] and result["coverage_status"] == "incomplete"
    assert result["cleanup"]["confirmed"]
