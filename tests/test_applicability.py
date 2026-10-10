from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.applicability import (
    FACTS_SCHEMA, ApplicabilityAction, ProcessingDisposition, ProcessingFeature,
    ProjectProcessingFacts, ReasonCode, SourceArtifactIdentity, decision_from_mapping,
    evaluate_applicability, facts_from_build_unit, finalize_processing, source_only_facts,
)
from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units
from appsec_review.jobs.cataloging import inventory


ROOT = Path(__file__).parents[1]
TARGET = ROOT / "targets" / "appsec-multi-vuln"
MATRIX_PATH = TARGET / "support" / "project-matrix.json"
CONFIGURATION_SHA256 = "c" * 64


def _document(path: str, content: str) -> dict[str, object]:
    return {"path": path, "sha256": "a" * 64, "content": content}


def _unit(*, family: str = "node", system: str = "node",
          documents: list[dict[str, object]], gaps: list[str] | None = None,
          extra: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "build_unit_id": "build-unit-" + "1" * 20, "root": ".", "family": family,
        "build_system": system, "markers": [],
        "descriptor_package": {"documents": documents, "gaps": list(gaps or [])},
        **(extra or {}),
    }


def _facts(*, material: bool = True, artifacts: tuple[str, ...] = ("object",),
           capabilities: tuple[str, ...] = ("codeql-build",), complete: bool = True
           ) -> ProjectProcessingFacts:
    return ProjectProcessingFacts(
        FACTS_SCHEMA, "project-1", "cpp", "native", ".", "cmake", complete,
        ("compiled-descriptor:cmake",) if material else (),
        () if material else ("syntax-only:node--check",), artifacts, capabilities,
        (SourceArtifactIdentity("CMakeLists.txt", "a" * 64),),
    )


@pytest.mark.parametrize("feature,policy,expected_action,expected_disposition", [
    (ProcessingFeature.BUILD_CAPTURE, "required", ApplicabilityAction.RUN, None),
    (ProcessingFeature.BUILD_CAPTURE, "auto", ApplicabilityAction.RUN, None),
    (ProcessingFeature.BUILD_CAPTURE, "disabled", ApplicabilityAction.SKIP,
     ProcessingDisposition.SKIPPED_POLICY),
    (ProcessingFeature.COMPILER_ARTIFACTS, "required", ApplicabilityAction.RUN, None),
    (ProcessingFeature.COMPILER_ARTIFACTS, "auto", ApplicabilityAction.RUN, None),
    (ProcessingFeature.COMPILER_ARTIFACTS, "disabled", ApplicabilityAction.SKIP,
     ProcessingDisposition.SKIPPED_POLICY),
    (ProcessingFeature.CODEQL, "build", ApplicabilityAction.RUN, None),
    (ProcessingFeature.CODEQL, "source", ApplicabilityAction.GAP, ProcessingDisposition.GAP),
    (ProcessingFeature.CODEQL, "auto", ApplicabilityAction.RUN, None),
    (ProcessingFeature.CODEQL, "disabled", ApplicabilityAction.SKIP,
     ProcessingDisposition.SKIPPED_POLICY),
])
def test_policy_transitions(feature, policy, expected_action, expected_disposition) -> None:
    decision = evaluate_applicability(
        feature=feature, policy=policy, facts=_facts(),
        configuration_sha256=CONFIGURATION_SHA256)
    assert decision.action is expected_action
    assert decision.disposition is expected_disposition
    assert decision_from_mapping(decision.as_dict()) == decision


def test_confirmed_absence_is_skip_but_inventory_failure_is_gap() -> None:
    absent = evaluate_applicability(
        feature=ProcessingFeature.BUILD_CAPTURE, policy="auto",
        facts=_facts(material=False, artifacts=(), capabilities=("codeql-source",)),
        configuration_sha256=CONFIGURATION_SHA256)
    missing = evaluate_applicability(
        feature=ProcessingFeature.BUILD_CAPTURE, policy="auto",
        facts=_facts(material=False, artifacts=(), complete=False),
        configuration_sha256=CONFIGURATION_SHA256)
    assert (absent.disposition, absent.reason_code) == (
        ProcessingDisposition.SKIPPED_NA, ReasonCode.MATERIAL_BUILD_ABSENT)
    assert (missing.disposition, missing.reason_code) == (
        ProcessingDisposition.GAP, ReasonCode.INVENTORY_UNAVAILABLE)


@pytest.mark.parametrize("kwargs,reason", [
    ({"toolchain_available": False, "succeeded": False}, ReasonCode.TOOLCHAIN_UNAVAILABLE),
    ({"succeeded": False}, ReasonCode.PROCESSING_FAILED),
    ({"succeeded": True, "evidence_complete": False}, ReasonCode.EVIDENCE_INCOMPLETE),
    ({"succeeded": True, "artifacts_valid": False}, ReasonCode.ARTIFACT_VALIDATION_FAILED),
    ({"succeeded": True}, ReasonCode.PROCESSING_SUCCEEDED),
])
def test_final_processing_dispositions(kwargs, reason) -> None:
    planned = evaluate_applicability(
        feature=ProcessingFeature.COMPILER_ARTIFACTS, policy="required", facts=_facts(),
        configuration_sha256=CONFIGURATION_SHA256)
    terminal = finalize_processing(planned, **kwargs)
    assert terminal.reason_code is reason
    assert terminal.disposition is (
        ProcessingDisposition.SUCCEEDED if reason is ReasonCode.PROCESSING_SUCCEEDED
        else ProcessingDisposition.GAP)


@pytest.mark.parametrize("document,trigger", [
    (_document("package.json", '{"scripts":{"build":"tsc"}}'), "transpilation"),
    (_document("package.json", '{"scripts":{"build":"esbuild in.js --bundle"}}'), "bundler-build"),
    (_document("package.json", '{"scripts":{"postinstall":"node hook.js"}}'), "package-lifecycle-hook"),
    (_document("package.json", '{"scripts":{"build":"node-gyp rebuild"}}'), "native-extension"),
    (_document("setup.py", 'setup(ext_modules=[Extension("x", sources=["x.c"])])'), "native-extension"),
    (_document("composer.json", '{"scripts":{"build":"@php build.php"}}'), "package-lifecycle-hook"),
    (_document("config.m4", "PHP_NEW_EXTENSION([x], [x.c], [$ext_shared])"), "native-extension"),
    (_document("build.gradle.kts", 'id("com.android.application")'), "android-gradle-build"),
    (_document("build.sh", "clang --target=wasm32 -o build/a.wasm a.c"), "webassembly-compilation"),
    (_document("build.sh", "kotlinc src/Main.kt -d build/a.jar"), "compiler-invocation:kotlinc"),
])
def test_each_material_build_trigger_is_descriptor_backed(document, trigger) -> None:
    facts = facts_from_build_unit(_unit(documents=[document]))
    assert trigger in facts.material_build_facts
    assert facts.sources[0].path == document["path"]


@pytest.mark.parametrize("language,syntax", [
    ("python", "python-py_compile"), ("javascript", "node--check"), ("php", "php-lint"),
])
def test_syntax_only_controls_do_not_become_material_builds(language: str, syntax: str) -> None:
    facts = source_only_facts(
        project_id=f"plain-{language}", language=language, root=".",
        sources=({"path": f"main.{ {'python':'py','javascript':'js','php':'php'}[language]}",
                  "sha256": "a" * 64},), capabilities=("codeql-source",))
    assert not facts.material_build
    decision = evaluate_applicability(
        feature=ProcessingFeature.BUILD_CAPTURE, policy="auto", facts=facts,
        configuration_sha256=CONFIGURATION_SHA256)
    assert decision.disposition is ProcessingDisposition.SKIPPED_NA


def test_untrusted_wrapper_or_log_text_cannot_establish_applicability() -> None:
    facts = facts_from_build_unit(_unit(
        documents=[_document("package.json", '{"scripts":{"build":"node --check index.js"}}')],
        extra={"wrapper_log": "gcc main.c && webpack --mode production"}))
    assert not facts.material_build
    assert facts.syntax_only_facts == ("syntax-only:node--check",)


def test_unsupported_codeql_capability_is_gap() -> None:
    decision = evaluate_applicability(
        feature=ProcessingFeature.CODEQL, policy="build",
        facts=_facts(capabilities=("codeql-source",)),
        configuration_sha256=CONFIGURATION_SHA256)
    assert decision.disposition is ProcessingDisposition.GAP
    assert decision.reason_code is ReasonCode.CAPABILITY_UNSUPPORTED


def test_codeql_auto_selects_declared_source_capability() -> None:
    decision = evaluate_applicability(
        feature=ProcessingFeature.CODEQL, policy="auto",
        facts=_facts(material=False, artifacts=(), capabilities=("codeql-source",)),
        configuration_sha256=CONFIGURATION_SHA256)
    assert decision.action is ApplicabilityAction.RUN
    assert decision.selected_capability == "source"
    assert decision.reason_code is ReasonCode.CODEQL_SOURCE_SELECTED


def test_configuration_identity_and_fact_changes_invalidate_decision_hash() -> None:
    first = evaluate_applicability(
        feature=ProcessingFeature.BUILD_CAPTURE, policy="auto", facts=_facts(),
        configuration_sha256="1" * 64)
    config_changed = evaluate_applicability(
        feature=ProcessingFeature.BUILD_CAPTURE, policy="auto", facts=_facts(),
        configuration_sha256="2" * 64)
    facts_changed = evaluate_applicability(
        feature=ProcessingFeature.BUILD_CAPTURE, policy="auto",
        facts=replace(_facts(), material_build_facts=("transpilation",)),
        configuration_sha256="1" * 64)
    assert len({first.decision_sha256, config_changed.decision_sha256,
                facts_changed.decision_sha256}) == 3


@pytest.mark.parametrize("path", ["../escape", "/absolute", "a/../../escape"])
def test_source_identity_rejects_escaped_paths(path: str) -> None:
    with pytest.raises(ValueError, match="source artifact"):
        SourceArtifactIdentity(path, "a" * 64)


def _matrix() -> list[dict[str, object]]:
    value = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    assert set(value) == {"schema_version", "capture_policies", "projects"}
    assert value["schema_version"] == 1
    assert isinstance(value["projects"], list) and value["projects"]
    return value["projects"]


@pytest.mark.parametrize("row", _matrix(), ids=lambda row: row["path"])
def test_multivuln_matrix_applicability(row: dict[str, object]) -> None:
    root = (TARGET / str(row["path"])).resolve(strict=True)
    assert TARGET.resolve() in root.parents
    snapshot = inventory(root)
    assert not snapshot["gaps"]
    units = discover_build_units(snapshot["files"])
    bounded = [{**unit, "descriptor_package": descriptor_package(root, unit, snapshot["files"])}
               for unit in units]
    facts = [facts_from_build_unit(unit) for unit in bounded]
    expected = str(row["expected_applicability"])
    if expected == "not-applicable-syntax-only":
        source = snapshot["files"][0]
        selected = source_only_facts(
            project_id=str(row["path"]), language=str(row["language"]), root=".",
            sources=({"path": source["path"], "sha256": source["sha256"]},),
            capabilities=("codeql-source",) if row["language"] != "php" else ())
        assert not selected.material_build
    else:
        assert facts, f"no bounded build unit for {row['path']}"
        selected = next((item for item in facts if item.material_build), None)
        assert selected is not None, f"no material trigger for {row['path']}"
    decision = evaluate_applicability(
        feature=ProcessingFeature.BUILD_CAPTURE, policy=str(row["capture_policy"]),
        facts=selected, configuration_sha256=CONFIGURATION_SHA256)
    if row["capture_policy"] == "disabled":
        assert decision.disposition is ProcessingDisposition.SKIPPED_POLICY
    else:
        assert decision.action is ApplicabilityAction.RUN
    assert all((root / item.path).is_file() for item in selected.sources)
