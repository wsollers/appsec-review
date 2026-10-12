from appsec_review.jobs.component_ownership import resolve_ownership, resolve_root_ownership
from appsec_review.jobs.job_change_context_analysis.metrics import component_of
from appsec_review.jobs.job_review_prioritization.job import _component
from appsec_review.jobs.job_source_history_analysis.signals import _component_of
from appsec_review.jobs.job_source_history_analysis.signals import co_change
from appsec_review.jobs.job_target_analysis_plan.planning import _component_paths


def test_equal_root_components_use_manifest_and_ecosystem() -> None:
    components = (
        {"component_id": "go", "root": "service", "manifest": "service/go.mod", "ecosystem": "go"},
        {"component_id": "rust", "root": "service", "manifest": "service/Cargo.toml", "ecosystem": "rust"},
    )
    assert resolve_ownership("service/go.mod", components).component_ids == ("go",)
    assert resolve_ownership("service/main.rs", components).component_ids == ("rust",)
    assert resolve_ownership("service/config.json", components).status == "ambiguous"
    paths = _component_paths(tuple({"path": path} for path in
                                   ("service/go.mod", "service/main.rs", "service/config.json")), components)
    assert paths == {"go": ["service/go.mod"], "rust": ["service/main.rs"]}


def test_root_only_consumers_do_not_pick_an_id_for_a_tie() -> None:
    roots = [("service", "go"), ("service", "rust"), (".", "root")]
    for resolver in (resolve_root_ownership, component_of, _component, _component_of):
        assert resolver("service/config.json", roots) is None
        assert resolver("other/config.json", roots) == "root"
    partners = co_change([{"change_id": "a", "bulk": False, "files": [
        {"current_path": "service/a.txt"}, {"current_path": "service/b.txt"}]}], {},
        eligible={"service/a.txt", "service/b.txt"}, roots=roots, top_k=2, min_support=1)
    assert partners["service/a.txt"][0]["cross_component"] is None
