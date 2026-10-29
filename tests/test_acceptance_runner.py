from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
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
            prerequisites: tuple[str, ...] = (), tested_commit: str | None = None) -> tuple[dict, LaneWorkspace]:
    path = tmp_path / "test_micro.py"
    path.write_text(source, encoding="utf-8")
    workspace = owned_workspace(tmp_path)
    outcome = ops_tests.supervised_pytest(
        sys.executable, [str(path)], workspace, "micro",
        deadline=time.monotonic() + seconds, prerequisites=prerequisites, tested_commit=tested_commit)
    return outcome, workspace


def test_supervisor_exports_its_exact_commit_without_a_child_git_process(tmp_path: Path) -> None:
    commit = "1" * 40
    outcome, _workspace = execute(tmp_path,
        "import os\n"
        "def test_identity():\n"
        "    assert os.environ['APPSEC_ACCEPTANCE_TESTED_COMMIT'] == '" + commit + "'\n",
        tested_commit=commit)
    assert outcome["exit_code"] == 0 and outcome["cleanup"]["confirmed"], outcome


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


@pytest.mark.parametrize("platform_name", ["linux", "windows"])
def test_selected_platform_prerequisite_is_required_before_collection(tmp_path: Path, platform_name: str) -> None:
    requirement = "platform:" + platform_name
    expected = sys.platform == "linux" if platform_name == "linux" else os.name == "nt"
    outcome, _ = execute(tmp_path, "def test_ok(): pass\n", prerequisites=(requirement,))
    assert outcome["pytest"]["prerequisites"] == [{"name": requirement, "available": expected}]
    assert (outcome["exit_code"] == 0) == expected
    assert bool(outcome["pytest"]["cases"]) == expected
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
        "import os, pathlib, socket, subprocess, sys, pytest\n"
        "def test_guard():\n"
        f"    with pytest.raises(PermissionError): pathlib.Path({str(sentinel)!r}).write_text('changed')\n"
        f"    with pytest.raises(PermissionError): os.open({str(sentinel)!r}, os.O_RDWR)\n"
        f"    descriptor = os.open({str(sentinel)!r}, os.O_RDONLY)\n"
        "    try:\n"
        "        with pytest.raises(PermissionError): open(descriptor, 'wb', closefd=False)\n"
        "        with pytest.raises(PermissionError): os.ftruncate(descriptor, 0)\n"
        "    finally: os.close(descriptor)\n"
        "    with pytest.raises(PermissionError): open(9999999, 'rb', closefd=False)\n"
        "    child = subprocess.Popen([sys.executable, '-c', "
        "\"import sys; v=sys.stdin.buffer.read(); sys.stdout.buffer.write(v.upper()); sys.stderr.write('pipe stderr')\"], "
        "cwd=os.environ['APPSEC_ACCEPTANCE_ROOT'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
        "    out, err = child.communicate(b'pipe input', timeout=5)\n"
        "    assert child.returncode == 0 and out == b'PIPE INPUT' and err == b'pipe stderr'\n"
        "    with pytest.raises(PermissionError): subprocess.run(['docker', 'info'])\n"
        "    with socket.socket() as connection:\n"
        "        with pytest.raises(PermissionError): connection.connect(('192.0.2.1', 12345))\n")
    assert outcome["exit_code"] == 0, outcome
    assert sentinel.read_text(encoding="utf-8") == "unchanged"


def test_guard_allows_only_pinned_static_taxonomy_reads_and_never_mutation(tmp_path: Path) -> None:
    outcome, _ = execute(tmp_path,
        "import json, os, pathlib, pytest\n"
        "def test_static_reference():\n"
        f"    repository = pathlib.Path({str(ROOT)!r})\n"
        "    pins = json.loads(os.environ['APPSEC_ACCEPTANCE_STATIC_INPUTS'])\n"
        "    assert len(pins) == 2\n"
        "    for relative in pins:\n"
        "        path = repository / relative\n"
        "        assert json.loads(path.read_text(encoding='utf-8'))\n"
        "        with pytest.raises(PermissionError): path.write_text('changed')\n"
        "        with pytest.raises(PermissionError): os.open(path, os.O_RDONLY | os.O_TRUNC)\n"
        "        with pytest.raises(PermissionError): path.unlink()\n"
        "    with pytest.raises(PermissionError):\n"
        "        (repository / 'data' / 'not-an-allowed-reference.json').read_bytes()\n")
    assert outcome["exit_code"] == 0 and outcome["cleanup"]["confirmed"], outcome
    assert set(outcome["static_input_identities"]) == {
        "data/reference/taxonomy/vocabulary.json", "data/reference/taxonomy/crosswalk.json"}


def test_guard_rejects_changed_static_reference_identity_before_running_tests(tmp_path: Path, monkeypatch) -> None:
    environment = ops_tests.acceptance_environment

    def wrong_pin(workspace):
        result = environment(workspace)
        result["APPSEC_ACCEPTANCE_STATIC_INPUTS"] = json.dumps({
            "data/reference/taxonomy/vocabulary.json": "0" * 64})
        return result

    monkeypatch.setattr(ops_tests, "acceptance_environment", wrong_pin)
    outcome, _ = execute(tmp_path, "def test_must_not_run():\n    assert False\n")
    assert outcome["exit_code"] != 0 and outcome["cleanup"]["confirmed"], outcome
    assert "acceptance static reference identity changed" in Path(outcome["log"]).read_text(
        encoding="utf-8")


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
    {"extra": ["-k", "something"]}, {"deadline": 721}, {"case_deadline": 121}, {"workers": 3},
    {"case_deadline": 3},
])
def test_acceptance_rejects_unsafe_or_unbounded_options(overrides: dict) -> None:
    assert ops_tests.run_acceptance(arguments(**overrides), ROOT) == 2


@pytest.mark.parametrize("failure", ["cleanup", "static-input"])
def test_cleanup_and_source_identity_must_hold_even_with_successful_pytest(monkeypatch, capsys, failure) -> None:
    monkeypatch.delenv("APPSEC_PYTHON", raising=False)
    inventory = json.loads((ROOT / ops_tests.INVENTORY).read_text(encoding="utf-8"))
    nodes = [node for item in inventory["obligations"]
             if item["id"] in inventory["profiles"]["quick"]["obligations"] for node in item["nodes"]]

    def fake_supervisor(python, arguments, workspace, key, **options):
        collecting = "--collect-only" in arguments
        pins = json.loads(ops_tests.acceptance_environment(workspace)["APPSEC_ACCEPTANCE_STATIC_INPUTS"])
        if failure == "static-input":
            pins["data/reference/taxonomy/vocabulary.json"] = "0" * 64
        return {"outcome": "completed", "exit_code": 0,
                "cleanup": {"confirmed": collecting or failure != "cleanup"},
                "static_input_identities": pins,
                "pytest": {"collected": nodes if collecting else arguments, "prerequisites": [],
                           "cases": [] if collecting else [{"node": arguments[0], "outcome": "passed"}]}}

    monkeypatch.setattr(ops_tests, "supervised_pytest", fake_supervisor)
    assert ops_tests.run_acceptance(arguments(), ROOT) == 1
    path = Path(capsys.readouterr().out.split("result: ", 1)[1].strip())
    result = json.loads(path.read_text(encoding="utf-8"))
    if failure == "cleanup":
        assert "cleanup_unconfirmed" in result["failures"] and result["cleanup"]["confirmed"] is False
    else:
        assert result["cleanup"]["confirmed"]
        executed = [case for case in result["cases"] if case["outcome"] != "blocked"]
        assert executed
        assert all(case["reason"] == "static_reference_changed_during_suite" for case in executed)
        for case in result["cases"]:
            if case["outcome"] == "blocked":
                assert case["dependency"] in result["failed_obligations"]
                assert case["reason"] == f"prerequisite_failed_or_incomplete:{case['dependency']}"
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


_STAGED_MICRO = '''
import os
from pathlib import Path
import pytest
from appsec_review.acceptance.staging import SeedInputs, stage_context
from appsec_review.acceptance.custody import materialize_seed, verify_seed

@pytest.mark.parametrize("variant", ["micro"])
def test_prepare(variant):
    context = stage_context()
    assert context.variant == variant and context.seed_root is None
    root = context.work_root
    for name in ("target", "runs/micro-run/data/configuration"):
        (root / name).mkdir(parents=True)
    for name in ("target/source.py", "appsec-review.toml", "overlay.toml",
                 "fixture-state.json", "runs/micro-run/data/configuration/frozen.json"):
        (root / name).write_bytes(b"immutable micro bytes")
    (root / "custody-input.json").write_text(__import__("json").dumps(SeedInputs(variant, (
        "target", "appsec-review.toml", "overlay.toml", "fixture-state.json",
        "runs/micro-run/data/configuration")).record()), encoding="utf-8")
    (root / "progress.txt").write_text("prepare", encoding="utf-8")

@pytest.mark.parametrize("variant", ["micro"])
def test_review(variant):
    context = stage_context()
    root = context.work_root
    assert (root / "progress.txt").read_text(encoding="utf-8") == "prepare"
    with pytest.raises(PermissionError):
        (root / "target/source.py").write_bytes(b"changed")
    with pytest.raises(PermissionError):
        (root / "target").rename(root / "relocated-target")
    with pytest.raises(PermissionError):
        (root / "custody-input.json").unlink()
    with pytest.raises(PermissionError):
        Path(os.environ["APPSEC_ACCEPTANCE_FROZEN_INPUTS"]).write_bytes(b"changed receipt")
    (root / "progress.txt").write_text("review", encoding="utf-8")

@pytest.mark.parametrize("variant", ["micro"])
def test_report(variant):
    context = stage_context()
    root = context.work_root
    assert (root / "progress.txt").read_text(encoding="utf-8") == "review"
    (root / "progress.txt").write_text("report", encoding="utf-8")
    (root / "runs/micro-run/evidence.txt").write_bytes(b"micro evidence, not an accepted artifact")

@pytest.mark.parametrize("vector", ["first", "second"])
def test_consume(vector):
    context = stage_context()
    manifest = verify_seed(context)
    root = context.work_root
    assert (root / "progress.txt").read_text(encoding="utf-8") == "report"
    assert manifest["tree"]["files"]["runs/micro-run/evidence.txt"]
    source = context.seed_root / "target/source.py"
    for path in (source, context.seed_root / "progress.txt", context.manifest_path):
        with pytest.raises(PermissionError):
            path.write_bytes(b"changed")
        with pytest.raises(PermissionError):
            os.open(path, os.O_RDONLY | os.O_TRUNC)
        with pytest.raises(PermissionError):
            path.chmod(0o600)
        with pytest.raises(PermissionError):
            path.unlink()
        with pytest.raises(PermissionError):
            path.rename(root / "stolen")
    descriptor = os.open(source, os.O_RDONLY)
    try:
        with pytest.raises(PermissionError):
            os.ftruncate(descriptor, 0)
    finally:
        os.close(descriptor)
    with pytest.raises(PermissionError):
        os.link(source, root / "shared")
    with pytest.raises(PermissionError):
        os.symlink(source, root / "redirect")
    with pytest.raises(PermissionError):
        (context.workspace_root / "not-this-consumer.txt").write_bytes(b"changed")
    with pytest.raises(PermissionError):
        (context.workspace_root / "stages/other").mkdir()
    with pytest.raises(PermissionError):
        root.with_name(root.name + ".custody.json").write_bytes(b"changed receipt")
    private = materialize_seed(context, root / ("vector-" + vector))
    path = private / "target/source.py"
    path.write_bytes(b"intentional private tamper")
    descriptor = os.open(path, os.O_RDWR)
    try:
        os.ftruncate(descriptor, 4)
    finally:
        os.close(descriptor)
    assert path.read_bytes() == b"inte"
    assert source.read_bytes() == b"immutable micro bytes"
'''


def staged_inventory(tmp_path: Path, monkeypatch, *, source: str = _STAGED_MICRO):
    path = tmp_path / "test_staged_micro.py"
    path.write_text(source, encoding="utf-8")
    relative = path.relative_to(ROOT).as_posix()
    entries = []
    predecessor = None
    for phase in ("prepare", "review", "report"):
        name = "micro-" + phase
        entries.append({
            "id": name, "nodes": [f"{relative}::test_{phase}[micro]"],
            "stage": {"kind": "producer", "variant": "micro",
                      "depends_on": [predecessor] if predecessor else [], "seals": phase == "report"}})
        predecessor = name
    entries.append({
        "id": "micro-consumer", "nodes": [f"{relative}::test_consume"],
        "stage": {"kind": "consumer", "variant": "micro", "depends_on": ["micro-report"]}})
    inventory = tmp_path / "micro-inventory.json"
    payload = {
        "profiles": {"quick": {"tier": "hermetic", "deadline_seconds": 100,
                                "case_deadline_seconds": 20,
                                "obligations": [entry["id"] for entry in entries]}},
        "obligations": entries,
    }
    inventory.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(ops_tests, "INVENTORY", inventory)
    monkeypatch.delenv("APPSEC_PYTHON", raising=False)
    return path, inventory, payload


def acceptance_result(capsys) -> dict:
    output = capsys.readouterr().out
    return json.loads(Path(output.split("result: ", 1)[1].strip()).read_bytes())


def test_real_stages_run_ordered_predecessors_and_isolated_parameterized_consumers(
        tmp_path: Path, monkeypatch, capsys) -> None:
    staged_inventory(tmp_path, monkeypatch)
    assert ops_tests.run_acceptance(arguments(workers=2), ROOT) == 0
    result = acceptance_result(capsys)
    assert len(result["cases"]) == 5
    assert result["budget"]["workers"] == 2 and result["cleanup"]["confirmed"]
    assert result["executed_obligations"] == result["selected_obligations"]
    assert not result["failed_obligations"] and not result["blocked_obligations"]
    cases = {case["obligation_id"]: case for case in result["cases"]}
    producer_roots = {case["stage"]["work_root"] for case in result["cases"]
                      if case["stage"]["kind"] == "producer"}
    assert len(producer_roots) == 1
    consumer_roots = {case["stage"]["work_root"] for case in result["cases"]
                      if case["stage"]["kind"] == "consumer"}
    assert len(consumer_roots) == 2 and consumer_roots.isdisjoint(producer_roots)
    for phase in ("prepare", "review", "report"):
        assert cases["micro-" + phase]["checkpoint"]["sha256"]
    assert cases["micro-report"]["seal"]["sha256"]
    assert "APPSEC_ACCEPTANCE_STAGE" not in result["collection"]["command"]
    assert all(case["duration_seconds"] <= case["budget_seconds"] for case in result["cases"])
    assert all(case["staging"] for case in result["cases"])
    assert "src/appsec_review/acceptance/custody.py" in result["source_identities"]


@pytest.mark.parametrize("failure", ["assertion", "leaked-descendant", "timeout", "seal-deadline"])
def test_real_failed_prerequisite_never_executes_or_seals_descendants(
        tmp_path: Path, monkeypatch, capsys, failure: str) -> None:
    if failure == "assertion":
        source = _STAGED_MICRO.replace(
            '(root / "progress.txt").write_text("review", encoding="utf-8")',
            "assert False, 'deliberate micro producer failure'")
    elif failure == "leaked-descendant":
        source = _STAGED_MICRO.replace(
            '(root / "progress.txt").write_text("report", encoding="utf-8")',
            "__import__('subprocess').Popen([__import__('sys').executable, '-c', "
            "'import time; time.sleep(60)'], cwd=root)")
    elif failure == "timeout":
        source = _STAGED_MICRO.replace(
            '(root / "progress.txt").write_text("report", encoding="utf-8")',
            "__import__('time').sleep(60)")
    else:
        from appsec_review.acceptance import custody

        source = _STAGED_MICRO
        seal = custody.seal_seed

        def late_seal(context, path):
            seal(context, path)
            raise custody.CustodyError("custody_deadline_exceeded")

        monkeypatch.setattr(custody, "seal_seed", late_seal)
    _path, inventory, payload = staged_inventory(tmp_path, monkeypatch, source=source)
    if failure == "timeout":
        payload["obligations"][2]["case_deadline_seconds"] = 8
        inventory.write_text(json.dumps(payload), encoding="utf-8")
    assert ops_tests.run_acceptance(arguments(workers=2), ROOT) == 1
    result = acceptance_result(capsys)
    failed = "micro-review" if failure == "assertion" else "micro-report"
    assert failed in result["failed_obligations"]
    blocked = [case for case in result["cases"] if case["outcome"] == "blocked"]
    assert blocked and all(case["pytest"] is None and not case["passed"] for case in blocked)
    assert all(case["dependency"] and "prerequisite_failed_or_incomplete" in case["reason"] for case in blocked)
    assert "micro-consumer" not in result["executed_obligations"]
    assert not (Path(result["artifacts_root"]) / "custody/micro/sealed.json").exists()
    assert result["cleanup"]["confirmed"]
    if failure == "seal-deadline":
        report = next(case for case in result["cases"] if case["obligation_id"] == "micro-report")
        assert report["pytest"]["cases"][0]["outcome"] == "passed" and not report["passed"]
        assert "deadline_exceeded" in report["reason"]


@pytest.mark.parametrize("change", ["source", "config", "target", "copy"])
def test_real_stage_source_configuration_and_target_drift_blocks_consumers(
        tmp_path: Path, monkeypatch, capsys, change: str) -> None:
    path, _inventory, _payload = staged_inventory(tmp_path, monkeypatch)
    original = ops_tests.supervised_pytest

    def drift(python, arguments, workspace, key, **options):
        context = options.get("stage")
        if context is not None and context.obligation_id == "micro-review":
            if change != "copy":
                changed = {"source": path, "config": context.work_root / "appsec-review.toml",
                           "target": context.work_root / "target/source.py"}[change]
                changed.write_bytes(changed.read_bytes() + b"\n# changed after predecessor capture\n")
        elif context is not None and context.obligation_id == "micro-consumer" and change == "copy":
            changed = context.work_root / "target/source.py"
            changed.write_bytes(changed.read_bytes() + b"\n# changed after materialization\n")
        return original(python, arguments, workspace, key, **options)

    monkeypatch.setattr(ops_tests, "supervised_pytest", drift)
    assert ops_tests.run_acceptance(arguments(), ROOT) == 1
    result = acceptance_result(capsys)
    if change == "copy":
        assert result["failed_obligations"] == ["micro-consumer"]
        assert not result["blocked_obligations"]
        assert all(case["passed"] for case in result["cases"][:3])
        assert all("copy_changed_before_execution" in case["reason"] for case in result["cases"][3:])
    else:
        assert "micro-review" in result["failed_obligations"]
        assert result["blocked_obligations"] == ["micro-report", "micro-consumer"]
        assert all(not case["passed"] for case in result["cases"][1:])
        assert not (Path(result["artifacts_root"]) / "custody/micro/sealed.json").exists()


@pytest.mark.parametrize("change", [
    "cycle", "missing-selection", "unknown", "incompatible", "branch", "nonliteral", "overlap",
])
def test_stage_graph_errors_fail_before_dispatch(tmp_path: Path, monkeypatch, change: str) -> None:
    _path, inventory, payload = staged_inventory(tmp_path, monkeypatch)
    entries = payload["obligations"]
    if change == "cycle":
        entries[0]["stage"]["depends_on"] = ["micro-review"]
    elif change == "missing-selection":
        payload["profiles"]["quick"]["obligations"].remove("micro-prepare")
    elif change == "unknown":
        entries[1]["stage"]["depends_on"] = ["unknown-prepare"]
    elif change == "incompatible":
        entries[1]["stage"]["variant"] = "other"
    elif change == "branch":
        entries[2]["stage"]["depends_on"] = ["micro-prepare"]
    elif change == "nonliteral":
        entries[0]["nodes"][0] = entries[0]["nodes"][0].replace("[micro]", "")
    else:
        entries[1]["nodes"] = entries[0]["nodes"]
    inventory.write_text(json.dumps(payload), encoding="utf-8")

    def forbidden(*args, **kwargs):
        pytest.fail("invalid graph dispatched a process")

    monkeypatch.setattr(ops_tests, "supervised_pytest", forbidden)
    assert ops_tests.run_acceptance(arguments(), ROOT) == 2


@pytest.mark.parametrize("workers,expected", [(None, 1), (2, 2)])
def test_real_worker_default_and_explicit_maximum(tmp_path: Path, monkeypatch, capsys, workers, expected) -> None:
    path, inventory, payload = staged_inventory(tmp_path, monkeypatch, source=(
        'import pytest\n@pytest.mark.parametrize("value", [1, 2])\n'
        'def test_worker(value):\n    assert value in (1, 2)\n'))
    payload["obligations"] = [{
        "id": "workers", "nodes": [path.relative_to(ROOT).as_posix() + "::test_worker"]}]
    payload["profiles"]["quick"]["obligations"] = ["workers"]
    inventory.write_text(json.dumps(payload), encoding="utf-8")
    original = ops_tests.supervised_pytest
    lock = threading.Lock()
    barrier = threading.Barrier(2) if expected == 2 else None
    active = maximum = 0

    def supervised(python, arguments, workspace, key, **options):
        nonlocal active, maximum
        if "--collect-only" in arguments:
            return original(python, arguments, workspace, key, **options)
        with lock:
            active += 1
            maximum = max(maximum, active)
        try:
            if barrier:
                barrier.wait(timeout=5)
            return original(python, arguments, workspace, key, **options)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(ops_tests, "supervised_pytest", supervised)
    assert ops_tests.run_acceptance(arguments(workers=workers), ROOT) == 0
    result = acceptance_result(capsys)
    assert result["budget"]["workers"] == maximum == expected
    assert len(result["cases"]) == 2 and result["cleanup"]["confirmed"]


def test_zero_execution_budget_does_not_open_a_gate_and_keeps_a_receipt(tmp_path: Path) -> None:
    workspace = owned_workspace(tmp_path)
    outcome = ops_tests.supervised_pytest(
        sys.executable, ["test_must_not_exist.py"], workspace, "no-execution",
        deadline=time.monotonic() + ops_tests._CLEANUP_SECONDS)
    assert outcome["outcome"] == "not_executed"
    assert outcome["reason"] == "deadline_has_no_execution_budget"
    assert outcome["cleanup"] == {"confirmed": True, "started": False}
    assert (workspace.root / "processes/no-execution/supervisor.json").is_file()
    assert not (workspace.root / "processes/no-execution/gate.json").exists()


@pytest.mark.parametrize("changed", [
    "tests/final_report_support.py", "docs/schemas/fixture.json", "pipeline/prompt-fragments/fixture.md",
])
def test_source_identities_include_transitive_fixture_helpers_and_dynamic_core(tmp_path: Path, changed: str) -> None:
    root = tmp_path / "source-manifest-fixture"
    sources = {
        "appsec-review.toml": "",
        "tests/conftest.py": "",
        "tests/acceptance_plugin.py": "",
        "deploy/dagster/bin/ops_tests.py": "",
        "src/appsec_review/acceptance/custody.py": "",
        "src/appsec_review/jobs/dynamic_handler.py": "",
        "docs/schemas/fixture.json": "{}\n",
        "pipeline/prompt-fragments/fixture.md": "fixture guidance\n",
        "tests/test_selected.py": "from tests.acceptance_review_stages import helper\n",
        "tests/acceptance_review_stages.py": "from tests.final_report_support import helper\n",
        "tests/final_report_support.py": "helper = 1\n",
        "tests/unrelated.py": "",
    }
    for relative, content in sources.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    identities = ops_tests._source_identities(root, ("tests/test_selected.py::test_case",), {}, staged=True)
    assert set(identities) == set(sources) - {"tests/unrelated.py"}
    path = root / changed
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="acceptance_source_changed:" + changed):
        ops_tests._verify_sources(root, identities)


def test_fresh_source_verification_stops_at_the_current_case_deadline(tmp_path: Path, monkeypatch) -> None:
    from appsec_review.acceptance import custody
    from appsec_review import storage

    identities = {}
    for name in ("first", "second"):
        path = tmp_path / name
        path.write_bytes(b"fresh bounded source")
        identities[name] = storage.file_sha256(path)
    original = storage.file_sha256
    inspected = []

    def expiring(path):
        digest = original(path)
        inspected.append(path)
        custody._DEADLINE.set(time.monotonic() - 1)
        return digest

    monkeypatch.setattr(storage, "file_sha256", expiring)
    with pytest.raises(custody.CustodyError, match="deadline_exceeded"):
        with custody.custody_deadline(time.monotonic() + 10):
            ops_tests._verify_sources(tmp_path.resolve(), identities)
    assert inspected == [tmp_path / "first"]


_PUBLICATION_PREPARE = '''
    import subprocess, sys
    from tests.test_acceptance_custody import publish_micro_outputs
    with pytest.raises(PermissionError):
        os.link(root / "target/source.py", root / "forbidden-input-alias")
    with pytest.raises(PermissionError):
        os.link(root / "runs/micro-run/data/configuration/frozen.json", root / "forbidden-config-alias")
    with pytest.raises(PermissionError):
        os.link(str(root) + "/target/../target/source.py", root / "noncanonical-alias")
    with pytest.raises(PermissionError):
        open(9999999, "wb", closefd=False)
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys; v=sys.stdin.buffer.read(); sys.stdout.buffer.write(v.upper()); sys.stderr.write('owned pipe')"],
        cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = child.communicate(b"stdio micro", timeout=5)
    assert child.returncode == 0 and out == b"STDIO MICRO" and err == b"owned pipe"
    publish_micro_outputs(root)
    if os.link in os.supports_dir_fd:
        directory = root / "runs/micro-run/data"
        (directory / "pipe-link-source").write_bytes(b"actual transient link")
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.link("pipe-link-source", "pipe-link-destination", src_dir_fd=descriptor, dst_dir_fd=descriptor)
            os.unlink("pipe-link-destination", dir_fd=descriptor)
        finally:
            os.close(descriptor)
        (directory / "pipe-link-source").unlink()
'''


@pytest.mark.parametrize("fail_detachment", [False, True])
def test_real_producer_publication_and_pipe_stdio_keep_strict_acceptance_custody(
        tmp_path: Path, monkeypatch, capsys, fail_detachment: bool) -> None:
    source = _STAGED_MICRO.replace(
        '    (root / "custody-input.json").write_text',
        _PUBLICATION_PREPARE + '\n    (root / "custody-input.json").write_text')
    source = source.replace(
        '    (root / "progress.txt").write_text("review", encoding="utf-8")',
        '    descriptor = os.open(root / "target/source.py", os.O_RDONLY)\n'
        '    try:\n'
        '        with pytest.raises(PermissionError): os.ftruncate(descriptor, 0)\n'
        '    finally: os.close(descriptor)\n'
        '    (root / "progress.txt").write_text("review", encoding="utf-8")')
    staged_inventory(tmp_path, monkeypatch, source=source)
    if fail_detachment:
        from appsec_review.acceptance import custody

        def cancelled(*args):
            raise custody.CustodyError("injected detachment cancellation")

        monkeypatch.setattr(custody, "_detach_publication_member", cancelled)
    code = ops_tests.run_acceptance(arguments(workers=2), ROOT)
    result = acceptance_result(capsys)
    assert result["cleanup"]["confirmed"]
    prepare = result["cases"][0]
    assert prepare["pytest"]["cases"][0]["outcome"] == "passed"
    receipt = json.loads(Path(prepare["producer_publication"]["path"]).read_bytes())
    if fail_detachment:
        assert code == 1 and not prepare["passed"] and receipt["outcome"] == "failed"
        assert result["blocked_obligations"] == ["micro-review", "micro-report", "micro-consumer"]
        assert not list((Path(result["artifacts_root"]) / "custody/micro").glob("*.checkpoint.json"))
        assert not (Path(result["artifacts_root"]) / "custody/micro/sealed.json").exists()
    else:
        assert code == 0 and prepare["passed"] and receipt["outcome"] == "detached"
        assert receipt["replaced_files"] == receipt["verified_copy_files"] == 4
        assert prepare["producer_publication"]["sha256"]
        assert any(item["operation"] == "producer_publication" for item in prepare["staging"])
        assert result["cases"][2]["seal"]["sha256"]
