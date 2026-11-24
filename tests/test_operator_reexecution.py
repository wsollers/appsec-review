from types import SimpleNamespace
import hashlib
import io
import pickle

import pytest

from tests import operator_support  # noqa: F401
from dagster._core.execution.plan.outputs import StepOutputHandle
from reexecute_run import ParentContextReader, retained_outputs, selected_steps


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


def test_multiple_failed_siblings_do_not_reexecute_their_successful_common_parent():
    dependencies = {
        "gate__begin": set(), "gate__finalize": {"gate__begin"},
        "report__begin": {"gate__finalize"}, "report__assemble": {"report__begin"},
        "report__finalize": {"report__assemble"},
        "openvex__begin": {"gate__finalize"}, "openvex__load": {"openvex__begin"},
        "openvex__finalize": {"openvex__load"},
    }
    assert selected_steps(dependencies, "job_report", additional_jobs=["job_openvex"]) == [
        "openvex__begin", "openvex__finalize", "openvex__load",
        "report__assemble", "report__begin", "report__finalize",
    ]
    for extra in (["job_missing"], ["job_report"], "job_openvex"):
        with pytest.raises(ValueError):
            selected_steps(dependencies, "job_report", additional_jobs=extra)


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


def test_parent_context_reader_accepts_data_but_never_loads_python_objects():
    value = {"run_id": "fixture", "completed_handoffs": {"job_source": "a" * 64}}
    assert ParentContextReader(io.BytesIO(pickle.dumps(value))).load() == value
    with pytest.raises(ValueError, match="primitive data"):
        ParentContextReader(io.BytesIO(pickle.dumps(SimpleNamespace(value=1)))).load()


def test_changed_source_admission_is_scoped_to_selected_jobs_not_retained_producers(tmp_path, monkeypatch):
    from appsec_review.runtime import GraphRunner
    from appsec_review.runtime.release import load_release
    from appsec_review.runtime.repair import current_binding
    from tests.release_support import write_release
    from tests.test_repair_admission import fixture
    from reexecute_run import scoped_source_repair

    config, jobs, _calls = fixture(tmp_path, ("job_source", "job_security_tagging", "job_report"))
    dependencies = {"job_source": (), "job_security_tagging": ("job_source",),
                    "job_report": ("job_security_tagging",)}
    outcome = GraphRunner(config, jobs, dependencies=dependencies).run(
        target_root=tmp_path, source_fingerprint="none")
    root = config.runtime.runs_dir / outcome["run_id"]
    binding = current_binding(root)
    (tmp_path / "release-src/job_security_tagging/job.py").write_text("VERSION = 2\n")
    write_release(tmp_path, tuple(dependencies))
    by_id = {job.job_id: job for job in jobs}
    monkeypatch.setattr("appsec_review.runtime.registry.builtin_registry", lambda: SimpleNamespace(
        job_ids=lambda: tuple(by_id), build=by_id.__getitem__))
    monkeypatch.setattr("appsec_review.orchestration.topology.wave1_dependencies", lambda _ids: dependencies)
    monkeypatch.setattr("appsec_review.runtime.launch.configured_target", lambda *_args: tmp_path)
    monkeypatch.setattr("appsec_review.jobs.cataloging.source_fingerprint", lambda _target: "none")
    plan, selected, _deps, _target = scoped_source_repair(
        config, root, ["security_tagging__begin", "report__begin"], load_release(tmp_path), binding)
    assert plan["admissible"], plan["refusals"]
    assert [job.job_id for job in selected] == ["job_security_tagging", "job_report"]
    assert {row["job_id"] for row in plan["decisions"]} == {"job_security_tagging", "job_report"}
    assert "job_source" not in plan["attempt_snapshots"]
