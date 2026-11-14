from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from scripts import documentation
from scripts.docs_support import BLOCK, frontmatter, links

ROOT = Path(__file__).resolve().parents[2]


def test_generated_views_match_regeneration(tmp_path: Path) -> None:
    paths = documentation.generate(ROOT, tmp_path)
    assert paths
    drift = [path for path in paths
             if not (ROOT / path).is_file()
             or (tmp_path / path).read_bytes() != (ROOT / path).read_bytes()]
    assert not drift, f"run scripts/generate-docs.sh: {drift}"


def test_every_configured_task_and_dataset_is_projected(doc_inventory) -> None:
    from appsec_review.runtime.registry import builtin_registry
    config, _ = documentation.recipe_config(ROOT)
    registry = builtin_registry()
    assert set(doc_inventory["jobs"]) == set(config.jobs) == set(registry.job_ids())
    for job_id, configured in config.jobs.items():
        row = doc_inventory["jobs"][job_id]
        assert set(row["steps"]) == set(configured.steps)
        for step_id, step in configured.steps.items():
            assert set(row["steps"][step_id]["tasks"]) == set(step.tasks)
        assert {item["output_kind"] for item in row["datasets"]} == {
            item.output_kind for item in registry.build(job_id).datasets}
        assert row["contract"] == registry.build(job_id).contract.document()


def test_host_environment_does_not_change_the_inventory(monkeypatch, doc_inventory) -> None:
    monkeypatch.setenv("APPSEC_REVIEW_PROFILE", "prod")
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG_OVERLAY", "/missing/production-overlay.toml")
    monkeypatch.setenv("APPSEC_REVIEW_HOST_PINS", "/missing/production-host-pins.toml")
    actual = documentation.build_inventory(ROOT)
    assert actual == doc_inventory
    assert "sha256:" + "0" * 64 not in json.dumps(actual)
    assert str(ROOT) not in json.dumps(actual)


def test_undeclared_bindings_are_gaps_not_empty_successes(doc_inventory) -> None:
    tasks = [task for job in doc_inventory["jobs"].values()
             for step in job["steps"].values() for task in step["tasks"].values()]
    unknown = [task for task in tasks if task["tool_binding"] == "not_declared"]
    assert unknown
    assert all(task["tool_gap"] == "T-147" and not task["tools"] for task in unknown)
    scan = doc_inventory["jobs"]["job_evidence_collection"]["steps"]["source_sast"]["tasks"]["semgrep_scan"]
    assert scan["tool_binding"] == "bound_adapter" and scan["tools"] == ["tool-semgrep"]
    internal = doc_inventory["jobs"]["job_ci_configuration_analysis"]["steps"]["ci_analysis"]["tasks"]["azure_schema_scan"]
    assert internal["internal_tools"] == ["ci-schema"] and internal["tools"] == []


def test_job_blocks_keep_verbatim_identifiers_and_provenance(doc_inventory) -> None:
    for job_id, job in doc_inventory["jobs"].items():
        text = (ROOT / job["page"]).read_text(encoding="utf-8")
        blocks = list(BLOCK.finditer(text))
        assert len(blocks) == 1 and blocks[0][1] == job_id
        body = blocks[0][0]
        assert body.splitlines()[1].startswith("<!-- generated from:")
        assert f'job["{job_id}"]' in body and "flowchart LR" in body
        for row in job["datasets"]:
            assert f'["{row["output_kind"]}"]' in body
            assert f'["{row["schema"]}"]' in body


def test_overview_is_first_and_never_a_generated_output(doc_inventory) -> None:
    outputs = documentation.render(ROOT, doc_inventory)
    assert "docs/overview.md" not in outputs
    assert "docs/assets/review-pipeline.svg" not in outputs
    _, body = frontmatter(outputs["docs/README.md"])
    assert links(body)[0] == "overview.md"
    assert "generated from:" in outputs[documentation.INVENTORY].splitlines()[0]


def test_drift_check_does_not_write(tmp_path: Path) -> None:
    paths = documentation.generate(ROOT, tmp_path, check=True)
    assert documentation.INVENTORY in paths
    assert not list(tmp_path.iterdir())


def test_adapter_reference_without_a_scan_is_not_a_launch() -> None:
    def normalize(context, selected=SimpleNamespace(tool_id="tool-semgrep")):
        return selected.tool_id
    row = documentation.task_binding(SimpleNamespace(unit_id="step.normalize", handler=normalize), ROOT)
    assert row["tools"] == [] and row["tool_gap"] == "T-147"
