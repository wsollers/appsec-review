from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from scripts import documentation
from scripts.docs_support import BLOCK, frontmatter, identifier_errors, links, with_frontmatter

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


def _identity_document(body: str) -> str:
    return with_frontmatter({
        "title": "Identity contract", "kind": "architecture", "subsystem": "runtime interchange",
        "status": "current", "last reconciled": "a" * 40,
    }, body)


def test_current_claim_identity_is_discovered_without_relabelling_the_ledger_schema() -> None:
    schemas, _ = documentation.source_identifiers(ROOT)
    inventory = {"identifiers": {"schemas": schemas}}
    assert identifier_errors(_identity_document("Identity `claim/3`; record `appsec-review/claim/1`."),
                             inventory) == []
    assert identifier_errors(_identity_document("Undeclared identity `claim/999`."), inventory)


def _source_identifiers(tmp_path: Path, monkeypatch, source: str) -> set[str]:
    path = "src/appsec_review/review/fixture.py"
    for relative in (path, "scripts/documentation.py", "scripts/docs_matrices.py",
                     "tests/acceptance_review_stages.py"):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source if relative == path else "", encoding="utf-8")
    monkeypatch.setattr(documentation.subprocess, "run",
                        lambda *args, **kwargs: SimpleNamespace(stdout=path + "\0"))
    return documentation.source_identifiers(tmp_path)[0]


def test_identity_discovery_follows_the_bound_version_not_a_literal_allowlist(tmp_path, monkeypatch) -> None:
    source = '''
from appsec_review.review.identity import make_id
FIXTURE_IDENTITY_VERSION = 7
raise AssertionError("source discovery must never execute inspected modules")
def identity():
    return make_id("claim", FIXTURE_IDENTITY_VERSION, {})
'''
    schemas = _source_identifiers(tmp_path, monkeypatch, source)
    assert "claim/7" in schemas and "claim/3" not in schemas
    schemas = _source_identifiers(tmp_path, monkeypatch, source.replace("VERSION = 7", "VERSION = 8"))
    assert "claim/8" in schemas and "claim/7" not in schemas


def test_identity_discovery_does_not_promote_prose_or_unbound_calls(tmp_path, monkeypatch) -> None:
    schemas = _source_identifiers(tmp_path, monkeypatch, '''
"""A discussion of `prose-only/9` is not a declaration."""
EXPLANATION = "A string mentioning string-only/9 does not declare it."
from another_library import make_id
VERSION = 9
def identity():
    return make_id("unrelated", VERSION, {})
''')
    inventory = {"identifiers": {"schemas": schemas}}
    for name in ("prose-only/9", "string-only/9", "unrelated/9"):
        assert name not in schemas
        assert identifier_errors(_identity_document(f"Undeclared `{name}`."), inventory)
    for source in (
        'VERSION = 9\ndef identity(make_id): return make_id("claim", VERSION, {})',
        'VERSION = 9\ndef identity(VERSION): return make_id("claim", VERSION, {})',
        'VERSION = True\ndef identity(): return make_id("claim", VERSION, {})',
        'VERSION = 9\ndef identity(): return make_id("unregistered_kind", VERSION, {})',
    ):
        schemas = _source_identifiers(
            tmp_path, monkeypatch, "from appsec_review.review.identity import make_id\n" + source)
        assert not schemas
