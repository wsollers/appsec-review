from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

from appsec_review.development.test_selection import (
    KINDS, MAP_SCHEMA, SELECTION_SCHEMA, TestSelectionError, _registered_jobs, main, select_tests,
)


ROOT = Path(__file__).resolve().parents[1]


def _mapping(**selections):
    return {kind: selections.get(kind, []) for kind in KINDS}


def _write_map(root, jobs, *, common_contracts=None):
    (root / "tests" / "job-test-map.json").write_text(
        json.dumps({"schema": MAP_SCHEMA, "jobs": jobs, "common_contracts": common_contracts or {}}),
        encoding="utf-8")


def _write_source(root, relative, text="def test_ok(): pass\n"):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def checkout(tmp_path):
    _write_source(tmp_path, "src/appsec_review/runtime/registry.py",
                  "raise AssertionError('registry must not be imported')\n"
                  "def builtin_registry():\n"
                  "    registry.register('job_alpha', unavailable_factory)\n"
                  "    registry.register('job_beta', unavailable_factory)\n"
                  "    registry.register('job_unmapped', unavailable_factory)\n")
    _write_source(tmp_path, "tests/test_alpha.py",
                  "raise AssertionError('tests must not be imported')\n"
                  "def test_first(): pass\n"
                  "def test_second(): pass\n"
                  "class TestGroup:\n"
                  "    def test_case(self): pass\n")
    _write_source(tmp_path, "tests/test_beta.py")
    _write_map(tmp_path, {
        "job_alpha": _mapping(unit=["tests/test_alpha.py::test_second", "tests/test_alpha.py::test_first"]),
        "job_beta": _mapping(unit=["tests/test_beta.py", "tests/test_alpha.py::test_first"]),
    })
    return tmp_path


def test_ordered_exact_union_and_unique_scoped_argv(checkout):
    first = select_tests(checkout, ["job_beta", "job_alpha", "job_beta"])
    second = select_tests(checkout, iter(["job_alpha", "job_beta"]))
    assert first["schema"] == SELECTION_SCHEMA
    assert first["repository_root"] == str(checkout)
    assert first["jobs"] == ["job_alpha", "job_beta"]
    assert first["selectors"] == [
        "tests/test_alpha.py::test_first", "tests/test_alpha.py::test_second", "tests/test_beta.py",
    ]
    assert first["gaps"] == []
    assert first["handler_selectors"] == first["selectors"]
    assert first["common_contracts"] == []
    argv = first["pytest_argv"]
    assert argv[:3] == [sys.executable, "-m", "pytest"]
    assert re.fullmatch(r"--basetemp=test/tmp/job-selection-[0-9a-f]{32}", argv[3])
    assert argv[4:] == first["selectors"]
    assert argv[3] != second["pytest_argv"][3]
    assert {key: value for key, value in first.items() if key != "pytest_argv"} == {
        key: value for key, value in second.items() if key != "pytest_argv"
    }
    assert not (checkout / "test").exists()


def test_missing_mapping_and_empty_category_are_gaps_not_fallbacks(checkout):
    result = select_tests(checkout, ["job_unmapped", "job_alpha"])
    assert result["selectors"] == ["tests/test_alpha.py::test_first", "tests/test_alpha.py::test_second"]
    assert result["gaps"] == [{
        "job_id": "job_unmapped", "kind": "unit", "scope": "handler",
        "reason": "Registered job has no handler-specific test metadata.",
    }]
    empty = select_tests(checkout, ["job_alpha", "job_unmapped"], kind="integration")
    assert empty["selectors"] == []
    assert empty["pytest_argv"] is None
    assert empty["gaps"] == [
        {"job_id": "job_alpha", "kind": "integration", "scope": "handler",
         "reason": "No explicit handler-specific integration selectors mapped for this registered job."},
        {"job_id": "job_unmapped", "kind": "integration", "scope": "handler",
         "reason": "Registered job has no handler-specific test metadata."},
    ]


@pytest.mark.parametrize("kind", KINDS)
def test_categories_select_only_the_explicit_requested_kind(checkout, kind):
    selectors = {}
    for category in KINDS:
        relative = f"tests/{category}/test_selected.py"
        _write_source(checkout, relative)
        selectors[category] = [relative]
    _write_map(checkout, {"job_alpha": selectors})
    result = select_tests(checkout, ["job_alpha"], kind=kind)
    assert result["kind"] == kind
    assert result["selectors"] == selectors[kind]
    assert result["gaps"] == []


def test_class_method_and_parameterized_function_base_selectors_are_static(checkout):
    source = (
        "import pytest\n"
        "@pytest.mark.parametrize('value', unavailable_values())\n"
        "def test_parameterized(value): pass\n"
        "class TestCases:\n"
        "    def test_method(self): pass\n"
    )
    _write_source(checkout, "tests/test_cases.py", source)
    expected = ["tests/test_cases.py::TestCases::test_method", "tests/test_cases.py::test_parameterized"]
    _write_map(checkout, {"job_alpha": _mapping(unit=expected)})
    assert select_tests(checkout, ["job_alpha"])["selectors"] == expected


@pytest.mark.parametrize("jobs", [[], ["job_missing"], ["alpha"], ["job_alpha", "job_missing"],
                                  ["job_alpha", 1], "job_alpha", ["job_alpha;echo"]])
def test_unknown_or_malformed_job_ids_are_refused(checkout, jobs):
    with pytest.raises(TestSelectionError):
        select_tests(checkout, jobs)


def test_unknown_kind_is_refused(checkout):
    with pytest.raises(TestSelectionError, match="unknown test kind"):
        select_tests(checkout, ["job_alpha"], kind="all")


@pytest.mark.parametrize("selector", [
    "", "tests", "tests/test_alpha.py ", "tests/test_alpha.py\n--collect-only",
    "-k", "--collect-only", "/tests/test_alpha.py", "../tests/test_alpha.py",
    "tests/../tests/test_alpha.py", "tests//test_alpha.py", "./tests/test_alpha.py",
    "tests\\test_alpha.py", "tests/test_*.py", "tests/test_alpha.py::", "tests/test_alpha.py::test_missing",
    "tests/test_alpha.py::test_first[case]", "tests/test_alpha.py::TestGroup",
    "tests/test_alpha.py::test_first::extra", "tests/test_alpha.py::TestGroup::test_missing",
    "tests/test_alpha.py::TestGroup::test_case::extra", "tests/test_missing.py", 7, None,
])
def test_malformed_and_unknown_selectors_are_refused(checkout, selector):
    _write_map(checkout, {"job_alpha": _mapping(unit=[selector])})
    with pytest.raises(TestSelectionError):
        select_tests(checkout, ["job_alpha"])


@pytest.mark.parametrize("source", [
    "def helper(): pass\n",
    "def test_bad(:\n",
    "def test_duplicate(): pass\ndef test_duplicate(): pass\n",
])
def test_non_test_or_unparseable_or_shadowed_file_is_refused(checkout, source):
    _write_source(checkout, "tests/test_bad.py", source)
    _write_map(checkout, {"job_alpha": _mapping(unit=["tests/test_bad.py"])})
    with pytest.raises(TestSelectionError):
        select_tests(checkout, ["job_alpha"])


@pytest.mark.parametrize("relative", [
    "tests/integration/test_manual.py", "tests/acceptance/test_manual.py",
    "tests/live/test_manual.py", "tests/test_live_manual.py", "tests/test_manual_live.py",
    "tests/test_poc_live_compile.py",
])
def test_manual_paths_cannot_be_labelled_unit(checkout, relative):
    _write_source(checkout, relative)
    _write_map(checkout, {"job_alpha": _mapping(unit=[relative])})
    with pytest.raises(TestSelectionError, match="category mismatch"):
        select_tests(checkout, ["job_alpha"])


@pytest.mark.parametrize("source", [
    "import pytest\npytestmark = pytest.mark.integration\ndef test_ok(): pass\n",
    "import pytest\npytestmark: object = [pytest.mark.acceptance]\ndef test_ok(): pass\n",
    "import pytest\n@pytest.mark.live\ndef test_ok(): pass\n",
    "import pytest\n@pytest.mark.requires_target('local-only')\ndef test_ok(): pass\n",
    "import pytest\n@pytest.mark.acceptance\nclass TestManual:\n    def test_ok(self): pass\n",
])
def test_manual_markers_cannot_be_labelled_unit(checkout, source):
    _write_source(checkout, "tests/test_marked.py", source)
    _write_map(checkout, {"job_alpha": _mapping(unit=["tests/test_marked.py"])})
    with pytest.raises(TestSelectionError, match="category mismatch"):
        select_tests(checkout, ["job_alpha"])


def test_mixed_module_requires_exact_nodes_and_disjoint_categories(checkout):
    _write_source(checkout, "tests/test_mixed.py",
                  "import pytest\n"
                  "def test_fast(): pass\n"
                  "@pytest.mark.requires_target('authorized-target')\n"
                  "def test_target(): pass\n")
    _write_map(checkout, {"job_alpha": _mapping(
        unit=["tests/test_mixed.py::test_fast"], live=["tests/test_mixed.py::test_target"])})
    assert select_tests(checkout, ["job_alpha"])["selectors"] == ["tests/test_mixed.py::test_fast"]
    _write_map(checkout, {"job_alpha": _mapping(unit=["tests/test_mixed.py"])})
    with pytest.raises(TestSelectionError, match="category mismatch"):
        select_tests(checkout, ["job_alpha"])


@pytest.mark.parametrize("manual", ["tests/test_alpha.py::test_first", "tests/test_alpha.py"])
def test_file_and_node_cannot_overlap_across_categories(checkout, manual):
    _write_map(checkout, {
        "job_alpha": _mapping(unit=["tests/test_alpha.py"]),
        "job_beta": _mapping(acceptance=[manual]),
    })
    with pytest.raises(TestSelectionError, match="overlapping selector categories"):
        select_tests(checkout, ["job_alpha"])


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(schema="appsec-review/job-test-map/999"),
    lambda value: value.update(unexpected=True),
    lambda value: value.update(jobs=[]),
    lambda value: value.update(common_contracts=[]),
    lambda value: value.pop("common_contracts"),
    lambda value: value["jobs"].update(job_missing=_mapping()),
    lambda value: value["jobs"]["job_alpha"].update(unexpected=[]),
    lambda value: value["jobs"]["job_alpha"].pop("live"),
    lambda value: value["jobs"]["job_alpha"].update(unit="tests/test_alpha.py"),
    lambda value: value["jobs"]["job_alpha"].update(unit=["tests/test_alpha.py", "tests/test_alpha.py"]),
    lambda value: value["jobs"]["job_beta"].update(live=["tests/test_missing.py"]),
])
def test_entire_metadata_is_validated_even_for_unselected_jobs_or_kinds(checkout, mutation):
    path = checkout / "tests/job-test-map.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    mutation(document)
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(TestSelectionError):
        select_tests(checkout, ["job_alpha"])


@pytest.mark.parametrize("text", [
    "{", "null", "[]",
    '{"schema":"appsec-review/job-test-map/1","schema":"appsec-review/job-test-map/1","jobs":{}}',
    '{"schema":"appsec-review/job-test-map/1","jobs":{"job_alpha":{},"job_alpha":{}}}',
])
def test_invalid_json_or_duplicate_keys_are_refused(checkout, text):
    (checkout / "tests/job-test-map.json").write_text(text, encoding="utf-8")
    with pytest.raises(TestSelectionError):
        select_tests(checkout, ["job_alpha"])


@pytest.mark.parametrize("relative", ["tests/test_link.py", "tests/linked/test_link.py"])
def test_symlinked_test_files_and_parents_are_refused(checkout, relative):
    if relative == "tests/test_link.py":
        (checkout / relative).symlink_to(checkout / "tests/test_beta.py")
    else:
        directory = checkout / "real-tests"
        directory.mkdir()
        (directory / "test_link.py").write_text("def test_ok(): pass\n", encoding="utf-8")
        (checkout / "tests/linked").symlink_to(directory, target_is_directory=True)
    _write_map(checkout, {"job_alpha": _mapping(unit=[relative])})
    with pytest.raises(TestSelectionError, match="symlinked source"):
        select_tests(checkout, ["job_alpha"])


def test_symlinked_metadata_is_refused(checkout):
    path = checkout / "tests/job-test-map.json"
    original = checkout / "tests/map-original.json"
    path.rename(original)
    path.symlink_to(original)
    with pytest.raises(TestSelectionError, match="symlinked source"):
        select_tests(checkout, ["job_alpha"])


@pytest.mark.parametrize("relative", ["test", "test/tmp"])
@pytest.mark.parametrize("symlink", [False, True])
def test_scratch_parent_cannot_be_a_file_or_symlink(checkout, relative, symlink):
    path = checkout / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if symlink:
        path.symlink_to(checkout / "tests", target_is_directory=True)
    else:
        path.write_text("not a directory", encoding="utf-8")
    with pytest.raises(TestSelectionError, match="scratch parents"):
        select_tests(checkout, ["job_alpha"])


@pytest.mark.parametrize("body", [
    "def builtin_registry():\n    registry.register(dynamic_job, factory)\n",
    "def builtin_registry():\n    registry.register('job_alpha', factory)\n"
    "    registry.register('job_alpha', other_factory)\n",
    "def builtin_registry(): pass\n",
    "def renamed_registry(): pass\n",
])
def test_unresolvable_registry_is_refused_without_importing_it(checkout, body):
    _write_source(checkout, "src/appsec_review/runtime/registry.py", body)
    with pytest.raises(TestSelectionError):
        select_tests(checkout, ["job_alpha"])


def test_cli_outputs_json_and_never_runs_pytest_or_imports_tests(checkout, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("selection must not execute commands or pytest")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(pytest, "main", forbidden)
    monkeypatch.chdir(checkout)
    before = {path.relative_to(checkout) for path in checkout.rglob("*")}
    assert main(["--job", "job_beta", "--job", "job_alpha", "--kind", "unit"]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert captured.err == ""
    assert result["jobs"] == ["job_alpha", "job_beta"]
    assert result["selectors"] == [
        "tests/test_alpha.py::test_first", "tests/test_alpha.py::test_second", "tests/test_beta.py",
    ]
    assert {path.relative_to(checkout) for path in checkout.rglob("*")} == before


def test_cli_errors_and_gap_only_plan_are_distinct(checkout, capsys):
    assert main(["--repository-root", str(checkout), "--job", "job_missing"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unknown job" in json.loads(captured.err)["error"]
    assert main(["--repository-root", str(checkout), "--job", "job_unmapped"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["gaps"] and result["pytest_argv"] is None
    with pytest.raises(SystemExit) as error:
        main(["--job", "job_alpha", "--kind", "everything"])
    assert error.value.code == 2


def test_common_contract_is_exact_scoped_and_never_fills_handler_gap(checkout):
    _write_source(checkout, "tests/test_common.py",
                  "raise AssertionError('common tests must not be imported')\n"
                  "def test_contract(): pass\n")
    selector = "tests/test_common.py::test_contract"
    _write_map(checkout, {"job_alpha": _mapping(unit=["tests/test_alpha.py::test_first"])},
               common_contracts={"recovery": {
                   "jobs": ["job_unmapped", "job_alpha"], **_mapping(unit=[selector]),
               }})
    result = select_tests(checkout, ["job_unmapped", "job_alpha", "job_unmapped"])
    assert result["selectors"] == ["tests/test_alpha.py::test_first", selector]
    assert result["handler_selectors"] == ["tests/test_alpha.py::test_first"]
    assert result["common_contracts"] == [{
        "contract_id": "recovery", "jobs": ["job_alpha", "job_unmapped"], "selectors": [selector],
    }]
    assert result["gaps"] == [{
        "job_id": "job_unmapped", "kind": "unit", "scope": "handler",
        "reason": "Registered job has no handler-specific test metadata.",
    }]
    assert result["pytest_argv"][4:] == result["selectors"]
    only_common = select_tests(checkout, ["job_unmapped"])
    assert only_common["selectors"] == [selector] and only_common["handler_selectors"] == []
    assert only_common["gaps"] == result["gaps"]
    unrelated = select_tests(checkout, ["job_beta"])
    assert unrelated["selectors"] == unrelated["common_contracts"] == []
    assert unrelated["gaps"][0]["job_id"] == "job_beta"


@pytest.mark.parametrize("kind", ["integration", "acceptance"])
def test_common_manual_contracts_are_only_planned_for_the_requested_kind(checkout, kind):
    selector = f"tests/{kind}/test_repair.py"
    _write_source(checkout, selector,
                  "raise AssertionError('manual tests must not be imported')\ndef test_manual(): pass\n")
    _write_map(checkout, {"job_alpha": _mapping()}, common_contracts={
        "manual-repair": {"jobs": ["job_alpha"], **_mapping(**{kind: [selector]})},
    })
    result = select_tests(checkout, ["job_alpha"], kind=kind)
    assert result["selectors"] == [selector]
    assert result["handler_selectors"] == []
    assert result["common_contracts"] == [{
        "contract_id": "manual-repair", "jobs": ["job_alpha"], "selectors": [selector],
    }]
    assert result["gaps"][0]["scope"] == "handler"
    unit = select_tests(checkout, ["job_alpha"])
    assert unit["selectors"] == unit["common_contracts"] == []
    assert unit["pytest_argv"] is None


@pytest.mark.parametrize("mutation", [
    lambda contracts: contracts.update({"bad_id": contracts.pop("recovery")}),
    lambda contracts: contracts.update(recovery=[]),
    lambda contracts: contracts["recovery"].pop("jobs"),
    lambda contracts: contracts["recovery"].update(jobs=[]),
    lambda contracts: contracts["recovery"].update(jobs="job_beta"),
    lambda contracts: contracts["recovery"].update(jobs=["job_missing"]),
    lambda contracts: contracts["recovery"].update(jobs=["job_beta", "job_beta"]),
    lambda contracts: contracts["recovery"].update(jobs=[None]),
    lambda contracts: contracts["recovery"].update(unit=["tests/test_missing.py"]),
    lambda contracts: contracts["recovery"].update(unit=["tests/integration/test_manual.py"]),
    lambda contracts: contracts["recovery"].update(unit=["tests/test_common.py", "tests/test_common.py"]),
    lambda contracts: contracts["recovery"].update(unexpected=True),
])
def test_unselected_common_contracts_are_strictly_validated(checkout, mutation):
    _write_source(checkout, "tests/test_common.py")
    _write_source(checkout, "tests/integration/test_manual.py")
    contracts = {"recovery": {"jobs": ["job_beta"], **_mapping(unit=["tests/test_common.py"])}}
    mutation(contracts)
    _write_map(checkout, {"job_alpha": _mapping(unit=["tests/test_alpha.py"])}, common_contracts=contracts)
    with pytest.raises(TestSelectionError):
        select_tests(checkout, ["job_alpha"])


@pytest.mark.parametrize(("handler", "common"), [
    ("tests/test_alpha.py", "tests/test_alpha.py"),
    ("tests/test_alpha.py", "tests/test_alpha.py::test_first"),
    ("tests/test_alpha.py::test_first", "tests/test_alpha.py"),
])
def test_common_coverage_cannot_also_be_claimed_as_handler_coverage(checkout, handler, common):
    _write_map(checkout, {"job_alpha": _mapping(unit=[handler])}, common_contracts={
        "recovery": {"jobs": ["job_beta"], **_mapping(unit=[common])},
    })
    with pytest.raises(TestSelectionError, match="common/handler selector overlap"):
        select_tests(checkout, ["job_alpha"])


def test_shipped_metadata_covers_registered_jobs_and_resolves_every_category():
    document = json.loads((ROOT / "tests/job-test-map.json").read_text(encoding="utf-8"))
    registered = _registered_jobs(ROOT)
    assert set(document["jobs"]) == registered
    for kind in KINDS:
        result = select_tests(ROOT, sorted(registered), kind=kind)
        handler = sorted({selector for mapping in document["jobs"].values() for selector in mapping[kind]})
        common = [
            {"contract_id": contract_id, "jobs": sorted(mapping["jobs"]), "selectors": sorted(mapping[kind])}
            for contract_id, mapping in sorted(document["common_contracts"].items()) if mapping[kind]
        ]
        expected = sorted(set(handler).union(*(item["selectors"] for item in common)))
        assert result["handler_selectors"] == handler
        assert result["common_contracts"] == common
        assert result["selectors"] == expected
        assert {gap["job_id"] for gap in result["gaps"]} == {
            job_id for job_id, mapping in document["jobs"].items() if not mapping[kind]
        }
        assert result["pytest_argv"][4:] == expected
    document_gap = select_tests(ROOT, ["job_document_issue_analysis"])
    assert document_gap["handler_selectors"] == []
    assert document_gap["selectors"] == document["common_contracts"]["recovery-admission"]["unit"]
    assert document_gap["gaps"][0]["job_id"] == "job_document_issue_analysis"
    assert document_gap["gaps"][0]["scope"] == "handler"


def test_shipped_recovery_maps_preserve_narrow_fixture_scopes_and_manual_categories():
    document = json.loads((ROOT / "tests/job-test-map.json").read_text(encoding="utf-8"))
    common = document["common_contracts"]
    recovery_cases = [
        "test_active_workers_and_cleanup_uncertainty_refuse",
        "test_application_image_stages_declared_release_inputs",
        "test_compatible_shared_computation_survives_explicit_repair",
        "test_concurrent_or_stale_repair_claims_are_rejected",
        "test_config_schema_and_unknown_release_refuse_repair",
        "test_explicit_release_dependency_cannot_be_silently_missing",
        "test_failed_job_does_not_fall_back_to_older_accepted_attempt",
        "test_failed_publication_stage_never_reuses_partial_handoff",
        "test_missing_original_release_evidence_rejects_predecessor_reuse",
        "test_named_cache_cannot_hide_an_incompatible_producer_as_legacy",
        "test_publication_refuses_incompatible_receipt_even_when_lookup_is_bypassed",
        "test_repair_does_not_relabel_an_old_shared_computation_as_new_code",
        "test_shared_producer_change_invalidates_its_real_consumer_not_an_independent_job",
        "test_successful_portable_unit_is_admitted_into_fresh_attempt",
    ]
    assert common["recovery-admission"]["unit"] == [
        f"tests/test_repair_admission.py::{case}" for case in recovery_cases
    ]
    assert common["recovery-admission"]["integration"] == ["tests/integration/test_repair_workflow.py"]
    assert common["recovery-admission"]["acceptance"] == common["recovery-admission"]["live"] == []
    assert common["wave1-reuse"]["jobs"] == ["job_review_intake", "job_target_catalog"]
    assert common["wave1-reuse"]["unit"] == [
        "tests/test_wave1_resume.py::test_every_wave1_job_is_reused_without_handler_execution",
        "tests/test_wave1_resume.py::test_warm_graph_preserves_gap_completion_status",
    ]
    assert common["fixture-review-repair"]["jobs"] == [
        "job_document_issue_analysis", "job_final_report_publication", "job_review_intake",
    ]
    assert common["fixture-review-repair"]["acceptance"] == ["tests/acceptance/test_repair_fixture_review.py"]
    assert common["fixture-review-repair"]["unit"] == common["fixture-review-repair"]["integration"] == []
    for job_id in ("job_review_intake", "job_target_catalog", "job_document_issue_analysis"):
        selected = select_tests(ROOT, [job_id])
        contract_ids = [contract["contract_id"] for contract in selected["common_contracts"]]
        assert ("wave1-reuse" in contract_ids) is (job_id != "job_document_issue_analysis")
        assert not any("/integration/" in selector or "/acceptance/" in selector
                       for selector in selected["selectors"])
