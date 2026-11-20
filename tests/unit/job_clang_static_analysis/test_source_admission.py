"""Clang's missing-source guard against the actual prepare/catalog/scope boundary."""
from dataclasses import replace

import pytest

from appsec_review.jobs import cpp_index_scopes as scopes
from appsec_review.jobs.job_clang_static_analysis import job
from appsec_review.jobs.job_cpp_compiled_analysis import job as cpp
from tests.unit.job_cpp_compiled_analysis.test_job_pipeline import _make_unit, _stage_language_build


@pytest.mark.parametrize("missing_before_prepare", [False, True], ids=["complete", "unmapped-source"])
def test_prepare_catalog_never_admits_a_command_without_its_source_mapping(monkeypatch, tmp_path, missing_before_prepare):
    unit = _make_unit(tmp_path, repository_root=tmp_path / "private-repository")
    _stage_language_build(unit.job.run_root, unit.job.target_root, unit.job.source_fingerprint)
    if missing_before_prepare:
        (unit.job.target_root / "app/helper.cpp").unlink()
    handlers = {item.unit_id: item.handler for item in cpp.build_job().units}
    unit._store["plan.accepted_cpp_plan"] = handlers["plan.accepted_cpp_plan"](unit)
    unit._store["prepare.projects"] = handlers["prepare.projects"](unit)
    catalogs = handlers["catalog.projects"](unit)
    # Replace only the accepted-handoff I/O boundary, using the real producer's serialized catalog.
    accepted = {"result": {"outputs": {"catalog.projects": catalogs}}}
    monkeypatch.setattr(scopes, "load_accepted_cpp", lambda _root: accepted)
    _, actual, unavailable = scopes.accepted_cpp_scopes(unit.job.run_root)
    if missing_before_prepare:
        assert catalogs["projects"]["proj-app"]["terminal_status"] == "INVALID_COMPILE_DATABASE"
        assert actual == []
        assert "not in the accepted case mapping" in unavailable["proj-app"]
    else:
        assert len(actual) == 1
        assert all(actual[0].accepted_file(row["file"]) for row in actual[0].container_compile_database())
        assert "proj-app" not in unavailable


def test_post_catalog_source_loss_and_corrupted_scope_fail_before_any_clang_execution(tmp_path):
    unit = _make_unit(tmp_path, repository_root=tmp_path / "private-repository")
    _stage_language_build(unit.job.run_root, unit.job.target_root, unit.job.source_fingerprint)
    handlers = {item.unit_id: item.handler for item in cpp.build_job().units}
    unit._store["plan.accepted_cpp_plan"] = handlers["plan.accepted_cpp_plan"](unit)
    unit._store["prepare.projects"] = handlers["prepare.projects"](unit)
    catalog = handlers["catalog.projects"](unit)["projects"]["proj-app"]
    scope = scopes._scope(unit.job.run_root, "proj-app", catalog)
    from .support import SETTINGS
    unit.job.config.settings = SETTINGS
    with pytest.raises(ValueError, match="did not resolve to accepted source"):
        job._analyze_scope(unit, replace(scope, _by_relative={}),
                           lambda _u: pytest.fail("unadmitted source reached an executor"))
    (scope.case_root / "source/helper.cpp").unlink()
    with pytest.raises(ValueError, match="materialized source changed"):
        scopes._scope(unit.job.run_root, "proj-app", catalog)
