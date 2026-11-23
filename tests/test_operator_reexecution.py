from types import SimpleNamespace
import hashlib

import pytest

from tests import operator_support  # noqa: F401
from dagster._core.execution.plan.outputs import StepOutputHandle
from reexecute_run import retained_outputs, selected_steps


def graph():
    return {
        "catalog__begin": set(),
        "catalog__finalize": {"catalog__begin"},
        "security_tagging__begin": {"catalog__finalize"},
        "security_tagging__collection__coverage_gaps": {"security_tagging__begin"},
        "security_tagging__finalize": {"security_tagging__collection__coverage_gaps"},
        "report__begin": {"security_tagging__finalize", "catalog__finalize"},
        "report__finalize": {"report__begin"},
        "unrelated__begin": set(),
        "unrelated__finalize": {"unrelated__begin"},
    }


def test_reexecution_starts_the_whole_failed_job_but_not_completed_upstream_jobs():
    assert selected_steps(graph(), "job_security_tagging") == [
        "report__begin", "report__finalize", "security_tagging__begin",
        "security_tagging__collection__coverage_gaps", "security_tagging__finalize",
    ]


@pytest.mark.parametrize("boundary", ["job_missing", "security_tagging", "job_security_tagging*"])
def test_invalid_restart_boundary_never_falls_back_to_the_whole_graph(boundary):
    with pytest.raises(ValueError, match="restart boundary"):
        selected_steps(graph(), boundary)


def test_unknown_parent_dependency_is_refused():
    dependencies = graph()
    dependencies["security_tagging__begin"].add("missing__finalize")
    with pytest.raises(ValueError, match="unknown dependencies"):
        selected_steps(dependencies, "job_security_tagging")


def retained_fixture(tmp_path):
    handle = StepOutputHandle("catalog__finalize", "result")
    snapshot = SimpleNamespace(steps=[
        SimpleNamespace(key="security_tagging__begin", inputs=[
            SimpleNamespace(dagster_type_key="PythonDict", upstream_output_handles=[handle])]),
    ])
    origin = SimpleNamespace(run_id="original", produced_outputs={handle}, parent_state=None)
    known = SimpleNamespace(parent_state=SimpleNamespace(
        run_id="intermediate", produced_outputs=set(), parent_state=origin))
    instance = SimpleNamespace(storage_directory=lambda: str(tmp_path))
    path = tmp_path / "original/catalog__finalize/result"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"original retained output")
    return instance, snapshot, known, path


def test_retained_output_is_hash_bound_to_its_actual_parent_chain(tmp_path):
    instance, snapshot, known, path = retained_fixture(tmp_path)
    values = retained_outputs(instance, snapshot, {"security_tagging__begin"}, known)
    assert values == [{
        "run_id": "original", "step_key": "catalog__finalize", "output_name": "result",
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size_bytes": path.stat().st_size,
    }]
    path.write_bytes(b"changed")
    assert retained_outputs(instance, snapshot, {"security_tagging__begin"}, known) != values


@pytest.mark.parametrize("damage", ["missing", "symlink", "uncommitted"])
def test_unavailable_parent_output_is_not_replaced_with_fabricated_inputs(tmp_path, damage):
    instance, snapshot, known, path = retained_fixture(tmp_path)
    if damage == "uncommitted":
        known.parent_state.parent_state.produced_outputs = set()
    else:
        path.unlink()
        if damage == "symlink":
            target = tmp_path / "outside"
            target.write_bytes(b"original retained output")
            path.symlink_to(target)
    with pytest.raises(ValueError, match="parent.*output"):
        retained_outputs(instance, snapshot, {"security_tagging__begin"}, known)
