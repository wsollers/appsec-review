"""Contract tests for source-backed documentation intelligence-bucket joins."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re

import pytest

from appsec_review.tool_inputs import InputSupport
from scripts.docs_matrices import (
    build_matrices, cell, load_buckets, validate_buckets, validate_cell, validate_matrices,
)


ROOT = Path(__file__).resolve().parents[2]
TODO_IDS = {"T-147", "T-157"}
LANGUAGES = {".js": "JavaScript", ".py": "Python"}


@pytest.fixture
def matrix_input() -> tuple[dict, dict, dict]:
    dataset = {
        "output_kind": "source_records", "step": "analyze", "family": "source",
        "schema": "fixture/source/1", "sensitivity": "internal", "authority": "producer_evidence",
        "disposition": "indexed", "indexes": ["source"], "mcp_tools": ["search"],
        "query_route": "search", "store": "retrieval", "description": "Fixture source records.",
    }
    protected = {**dataset, "output_kind": "raw_records", "family": "execution_receipts",
                 "schema": "application/octet-stream", "sensitivity": "sensitive",
                 "authority": "operational", "disposition": "protected", "indexes": [],
                 "mcp_tools": ["query_dataset_inventory"], "query_route": "query_dataset_inventory"}
    inventory = {
        "images": {"tool-fixture": {"kind": "tool", "state": "enabled"},
                   "base-fixture": {"kind": "base", "state": "enabled"}},
        "jobs": {"job_fixture": {
            "enabled": True, "contract": {"target_access": "checkout"},
            "settings": {"languages": {"python": {"source_languages": ["Python"], "enabled": True}}},
            "steps": {"analyze": {"tasks": {"scan": {
                "id": "analyze.scan", "tools": ["tool-fixture"], "source": "src/fixture.py", "line": 1,
            }}}},
            "datasets": [dataset, protected],
        }},
        "mcp_tools": {"search": {}, "query_dataset_inventory": {}, "query_owasp_workbench": {},
                      "query_artifacts": {}},
        "guidance": {"roles": {
            "red_team_analyst": {"tools": ["search", "query_artifacts"]},
            "completeness_reviewer": {"tools": ["query_dataset_inventory"]},
        }},
    }
    taxonomy = {
        "schema": "appsec-review/intelligence-buckets/1",
        "buckets": {"source_snapshot": {"definition": "Accepted source identities."},
                    "review_products": {"definition": "Bounded review products."}},
        "tools": {"tool-fixture": "source_snapshot"},
        "datasets": {"source_records": "source_snapshot", "raw_records": "review_products"},
        "semantics": ["Primary-purpose grouping, never an evidence or permission claim."],
    }
    supports = {"tool-fixture": InputSupport("tool-fixture", "Python source", suffixes=frozenset({".py"}))}
    return inventory, taxonomy, supports


def build(inputs) -> dict:
    inventory, taxonomy, supports = inputs
    return build_matrices(inventory, taxonomy, TODO_IDS, supports=supports, languages=LANGUAGES)


def test_repository_bucket_map_covers_all_tools_and_datasets(doc_inventory) -> None:
    taxonomy = load_buckets(ROOT / "docs/intelligence-buckets.json")
    validate_buckets(taxonomy, doc_inventory)
    assert len(taxonomy["buckets"]) <= 12
    assert set(taxonomy["tools"]) == {
        name for name, image in doc_inventory["images"].items() if image["kind"] == "tool"}
    assert set(taxonomy["datasets"]) == {
        dataset["output_kind"] for job in doc_inventory["jobs"].values() for dataset in job["datasets"]}


def test_repository_matrices_keep_every_empty_cell_named(doc_inventory) -> None:
    taxonomy = load_buckets(ROOT / "docs/intelligence-buckets.json")
    todo_ids = set(re.findall(r"^### (T-\d{3}) ", (ROOT / "docs/TODO.md").read_text(), re.M))
    expected = build_matrices(doc_inventory, taxonomy, todo_ids)
    tools = json.loads((ROOT / "docs/generated/matrix-tool-bucket.json").read_text())
    available = json.loads((ROOT / "docs/generated/matrix-bucket-availability.json").read_text())
    assert tools["rows"] == expected["tools"]
    assert tools["non_tool_catalog_entries"] == expected["non_tool_catalog_entries"]
    assert available["datasets"] == expected["datasets"]
    assert available["buckets"] == expected["buckets"]
    assert available["language_rows"] == expected["language_rows"]
    assert available["languages"] == expected["languages"]


@pytest.mark.parametrize("kind", ["tools", "datasets"])
def test_missing_assignment_fails(matrix_input, kind) -> None:
    inventory, taxonomy, _ = matrix_input
    taxonomy[kind].pop(next(iter(taxonomy[kind])))
    with pytest.raises(ValueError, match="bucket coverage differs"):
        validate_buckets(taxonomy, inventory)


@pytest.mark.parametrize("kind", ["tools", "datasets"])
def test_multiple_or_unknown_bucket_assignment_fails(matrix_input, kind) -> None:
    inventory, taxonomy, _ = matrix_input
    name = next(iter(taxonomy[kind]))
    taxonomy[kind][name] = ["source_snapshot", "review_products"]
    with pytest.raises(ValueError, match="exactly one"):
        validate_buckets(taxonomy, inventory)
    taxonomy[kind][name] = "unknown"
    with pytest.raises(ValueError, match="exactly one"):
        validate_buckets(taxonomy, inventory)


def test_bucket_without_definition_fails(matrix_input) -> None:
    inventory, taxonomy, _ = matrix_input
    taxonomy["buckets"]["source_snapshot"] = {}
    with pytest.raises(ValueError, match="definition"):
        validate_buckets(taxonomy, inventory)


def test_thirteenth_bucket_fails(matrix_input) -> None:
    inventory, taxonomy, _ = matrix_input
    taxonomy["buckets"].update({f"extra_{index}": {"definition": "A bounded category."} for index in range(11)})
    with pytest.raises(ValueError, match="twelve"):
        validate_buckets(taxonomy, inventory)


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "buckets.json"
    path.write_text('{"tools":{"tool-fixture":"one","tool-fixture":"two"}}')
    with pytest.raises(ValueError, match="duplicate"):
        load_buckets(path)


@pytest.mark.parametrize("state", ["declared", "partial", "gap"])
def test_empty_cell_without_todo_gap_fails(state) -> None:
    value = {"state": state, "values": [], "basis": "Declared source boundary.", "gaps": []}
    with pytest.raises(ValueError):
        validate_cell(value, TODO_IDS, allow_na=False)


def test_invented_gap_id_fails() -> None:
    value = cell([], "No language declaration.", gaps=["T-999"])
    with pytest.raises(ValueError, match="unknown TODO"):
        validate_cell(value, TODO_IDS, allow_na=False)


def test_input_languages_are_not_inferred_beyond_suffix_declarations(matrix_input) -> None:
    _, _, supports = matrix_input
    supports["tool-fixture"] = InputSupport(
        "tool-fixture", "Mixed parser inputs", suffixes=frozenset({".py", ".unknown"}))
    value = build(matrix_input)["tools"][0]["input_languages"]
    assert value["values"] == ["Python"] and value["state"] == "partial"
    assert value["gaps"] == ["T-157"]


def test_arbitrary_input_is_not_universal_language_coverage(matrix_input) -> None:
    _, _, supports = matrix_input
    supports["tool-fixture"] = InputSupport("tool-fixture", "Any cataloged file", any_input=True)
    value = build(matrix_input)["tools"][0]["input_languages"]
    assert value["state"] == "not_applicable" and value["values"] == []


def test_absent_task_binding_remains_unknown(matrix_input) -> None:
    inventory, _, _ = matrix_input
    inventory["jobs"]["job_fixture"]["steps"]["analyze"]["tasks"]["scan"]["tools"] = []
    row = build(matrix_input)["tools"][0]
    assert row["jobs"]["state"] == row["tasks"]["state"] == "gap"
    assert row["gap"] == ["T-147"]


def test_protected_payload_exposes_only_metadata_eligibility(matrix_input) -> None:
    row = next(row for row in build(matrix_input)["datasets"] if row["dataset"] == "raw_records")
    assert row["stage"] == "protected" and row["access"] == "sanitized_metadata_only"
    assert row["retrieval_indexes"]["state"] == "not_applicable"
    assert row["review_roles"]["values"] == ["completeness_reviewer"]
    assert row["authority"] == "operational"


def test_role_eligibility_does_not_grant_an_incompatible_index(matrix_input) -> None:
    inventory, _, _ = matrix_input
    source = inventory["jobs"]["job_fixture"]["datasets"][0]
    source.update(mcp_tools=["query_artifacts"], query_route="query_artifacts")
    row = next(row for row in build(matrix_input)["datasets"] if row["dataset"] == "source_records")
    assert row["review_roles"]["values"] == []
    assert row["review_roles"]["gaps"] == ["T-157"]


def test_separate_owasp_store_is_not_granted_to_review_cells(matrix_input) -> None:
    inventory, _, _ = matrix_input
    source = inventory["jobs"]["job_fixture"]["datasets"][0]
    source.update(mcp_tools=["query_owasp_workbench"], query_route="query_owasp_workbench", store="owasp")
    row = next(row for row in build(matrix_input)["datasets"] if row["dataset"] == "source_records")
    assert row["review_roles"]["state"] == "not_applicable"


def test_disabled_job_and_enabled_image_remain_distinct(matrix_input) -> None:
    inventory, _, _ = matrix_input
    inventory["jobs"]["job_fixture"]["enabled"] = False
    result = build(matrix_input)
    assert result["tools"][0]["catalog_state"] == "enabled"
    assert result["tools"][0]["launch_bindings"][0]["job_enabled"] is False
    assert all(row["job_enabled"] is False for row in result["datasets"])


def test_language_grid_exposes_missing_and_unbound_coverage(matrix_input) -> None:
    result = build(matrix_input)
    assert len(result["language_rows"]) == 4
    python = next(row for row in result["language_rows"]
                  if row["bucket"] == "source_snapshot" and row["language"] == "Python")
    javascript = next(row for row in result["language_rows"]
                      if row["bucket"] == "source_snapshot" and row["language"] == "JavaScript")
    assert python["producers"]["values"] == ["job_fixture"]
    assert python["datasets"]["state"] == "partial" and python["gap"] == ["T-157"]
    assert javascript["producers"]["values"] == [] and javascript["gap"] == ["T-157"]


def test_shared_output_kind_does_not_lose_a_producer(matrix_input) -> None:
    inventory, taxonomy, _ = matrix_input
    inventory["jobs"]["job_second"] = deepcopy(inventory["jobs"]["job_fixture"])
    result = build(matrix_input)
    assert len(result["datasets"]) == 4
    result["datasets"].pop()
    with pytest.raises(ValueError, match="loses a producer"):
        validate_matrices(result, taxonomy, TODO_IDS, inventory, languages=LANGUAGES)


def test_unjustified_not_applicable_cannot_hide_a_missing_language(matrix_input) -> None:
    inventory, taxonomy, _ = matrix_input
    result = build(matrix_input)
    result["datasets"][0]["producer_languages"] = cell([], "No declaration.", not_applicable=True)
    with pytest.raises(ValueError, match="not justified"):
        validate_matrices(result, taxonomy, TODO_IDS, inventory, languages=LANGUAGES)


@pytest.mark.parametrize(("field", "value"), [
    ("authority", "producer_evidence"), ("stage", "indexed"),
], ids=["authority", "stage"])
def test_matrix_cannot_relabel_source_authority_or_stage(matrix_input, field, value) -> None:
    inventory, taxonomy, _ = matrix_input
    result = build(matrix_input)
    result["datasets"][0][field] = value
    with pytest.raises(ValueError, match="source contract"):
        validate_matrices(result, taxonomy, TODO_IDS, inventory, languages=LANGUAGES)


def test_missing_bucket_language_cell_fails(matrix_input) -> None:
    inventory, taxonomy, _ = matrix_input
    result = build(matrix_input)
    result["language_rows"].pop()
    with pytest.raises(ValueError, match="bucket/language"):
        validate_matrices(result, taxonomy, TODO_IDS, inventory, languages=LANGUAGES)


def test_missing_language_from_universe_fails(matrix_input) -> None:
    inventory, taxonomy, _ = matrix_input
    result = build(matrix_input)
    result["languages"].remove("JavaScript")
    result["language_rows"] = [row for row in result["language_rows"] if row["language"] != "JavaScript"]
    with pytest.raises(ValueError, match="universe"):
        validate_matrices(result, taxonomy, TODO_IDS, inventory, languages=LANGUAGES)


def test_emitted_markdown_is_a_seven_column_summary() -> None:
    for path in ("matrix-tool-bucket.md", "matrix-bucket-availability.md"):
        text = (ROOT / "docs/generated" / path).read_text()
        tables = [line for line in text.splitlines() if line.startswith("|")]
        assert tables
        assert all(len(re.split(r"(?<!\\)\|", line)) - 2 <= 7 for line in tables)
        assert re.search(r"\| Gap \|$", tables[0])
