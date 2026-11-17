"""D1/D9 (run 2026-11-16-0005): the OWASP workbench reads its target class from the tags index alone.

On that run the shared routing scan (tags, priority and graph shards under one cap of 240 rows) ended
inside a 675-row graph shard sorted before ``tags/facets``, so the derived ``target:cli`` row was never
read, the component had no class and 277 rows were ``cannot_determine`` for the false reason
"collation assigned no target tag". Tag discovery now has its own cap and a dropped target or facet
record is a gap; priority/graph rows are a second, separately capped context list.
"""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

from appsec_review.owasp_workbench import build_applicability, classify_components, load_catalogs, select_profiles
from appsec_review.owasp_workbench import evidence

ROOT = Path(__file__).resolve().parents[3]
GRAPH_SHARD = {"name": "graph", "shard_id": "graph-unit-call_site", "sha256": "4" * 64,
               "producer": {"job": "job_code_graph_index"}}
TAG_SHARD = {"name": "tags", "shard_id": "facets", "sha256": "5" * 64, "producer": {"job": "job_security_tagging"}}
CATALOG_FILES = {
    "ASVS": "asvs-5.0.0.json", "MASVS": "masvs-2.1.0.json", "MASTG": "mastg-2.0.0.json",
    "OWASP_API_TOP_10": "api-top10-2023.json", "OWASP_TOP_10": "top10-2025.json",
}


def graph_rows(count: int) -> list[dict]:
    return [{"identity": f"asr:call_site:{number:064d}", "kind": "call_site", "index": "graph",
             "shard_id": "graph-unit-call_site", "name": f"call{number}",
             "payload": {"component_id": "api", "result": {"sink_class": "exec"}}, "location": None}
            for number in range(count)]


def tag_row(tag: str, basis: str, *, subject: str = "component") -> dict:
    owner = ({"kind": "component", "component_id": "api", "logical_id": "component", "assignment_id": f"tag:{tag}"}
             if subject == "component" else
             {"kind": "source_file", "component_id": "api", "logical_id": "file-app", "path": "app.py",
              "assignment_id": f"tag:{tag}:file"})
    return {"identity": f"asr:tag_assignment:{subject}:{tag}", "kind": "tag_assignment", "index": "tags",
            "shard_id": "facets", "name": tag, "location": None,
            "payload": {"schema": "appsec-review/tag-assignment/1", "tag": tag, "namespace": tag.split(":")[0],
                        "basis": basis, "subject": owner}}


def discovered(accepted, settings, monkeypatch, rows, **changes):
    boundary = accepted({"app.py": "VALUE = 1\n"}, extra_rows=rows, extra_shards=(GRAPH_SHARD, TAG_SHARD))
    monkeypatch.setattr(evidence, "accept_manifest", lambda *args, **kwargs: boundary.scope)
    monkeypatch.setattr(evidence, "EvidenceResolver", lambda *args, **kwargs: boundary.resolver)
    return evidence.accepted_inputs(boundary.resolver.core, replace(settings, **changes),
                                    manifest_path=boundary.scope.manifest_path)


def fixture_sources() -> dict:
    from appsec_review.owasp_workbench.standards import digest
    result = {}
    for family, name in CATALOG_FILES.items():
        path = ROOT / "data" / "reference" / "owasp" / "fixtures" / name
        document = json.loads(path.read_text(encoding="utf-8"))
        result[family] = {"catalog_path": path.relative_to(ROOT).as_posix(), "catalog_sha256": digest(document),
                          "version": document["version"], **document["upstream"]}
    return result


def test_target_class_is_read_behind_a_graph_shard_larger_than_the_context_scan(accepted, settings, monkeypatch):
    rows = [*graph_rows(300), tag_row("target:cli", "derived"), tag_row("mechanism:cli", "declared"),
            tag_row("mechanism:cli", "declared", subject="source_file")]
    assert settings.max_evidence_per_component * 4 < 300, "the graph shard must exceed the context scan cap"
    result = discovered(accepted, settings, monkeypatch, rows)
    [component] = result["components"]
    assert {row["index"] for row in component["routing_context"]} == {"tags"}
    assert {row["index"] for row in component["graph_context"]} == {"graph"}
    assert len(component["graph_context"]) == settings.max_evidence_per_component
    assert component["tag_cloud"]["counts"] == {"mechanism:cli": 2, "target:cli": 1}
    assert result["gaps"] == [] and component["gaps"] == [] and component["tag_scan_complete"] is True
    assert any("routing index scan cap reached" in item for item in result["limitations"])
    assert component["source_support"]["supported_files"] == 1 and component["source_support"]["unsupported_files"] == 0
    assert set(component["source_support"]) == {"supported_files", "unsupported_files", "evidence_count", "recognisers",
                                                "languages"}
    assert component["source_support"]["languages"] == ["python"]
    [classification] = classify_components(result["components"], assessment_mode="assessment")
    assert classification["target_classes"] == ["target:cli"] and classification["confidence"] == "high"
    assert classification["facets"] == ["mechanism:cli"] and classification["gaps"] == []
    assert classification["graph_context"] == component["graph_context"]


def test_a_target_record_dropped_by_the_tag_cap_is_a_gap_and_the_class_is_reported_unread(
        accepted, settings, monkeypatch):
    rows = [tag_row("target:cli", "derived"), tag_row("mechanism:cli", "declared")]
    result = discovered(accepted, settings, monkeypatch, rows, max_evidence_per_component=1)
    [component] = result["components"]
    assert component["tag_records_omitted"] == 1
    assert [gap for gap in result["gaps"] if "tag record cap omitted 1 target class or facet records" in gap]
    assert component["gaps"] == [gap for gap in result["gaps"] if gap.startswith("api:")]
    [classification] = classify_components(result["components"], assessment_mode="assessment")
    assert classification["target_classes"] == [] and classification["target_class_unread"] is True
    assert any(gap.startswith("target class not read: routing cap omitted tag records") for gap in classification["gaps"])
    assert not any("collation assigned no target class" in gap for gap in classification["gaps"])
    catalogs = load_catalogs(ROOT, fixture_sources())
    rows = build_applicability(catalogs, [classification], select_profiles(catalogs, asvs_level=2, masvs_profile="L2"),
                               assessment_mode="assessment")
    assert rows and {row["outcome"] for row in rows} == {"cannot_determine"}
    assert all(row["reason"] == "component target class not read: routing cap omitted tag records" for row in rows)


def test_tag_scan_cap_is_a_gap_even_when_the_class_was_read(accepted, settings, monkeypatch):
    rows = [tag_row("target:cli", "derived"), tag_row("mechanism:cli", "declared"),
            tag_row("mechanism:cli", "declared", subject="source_file")]
    result = discovered(accepted, settings, monkeypatch, rows, max_tag_records=2)
    [component] = result["components"]
    assert component["tag_scan_complete"] is False
    assert any(gap.startswith("tag index scan cap reached") for gap in result["gaps"])
    assert any("tag index scan incomplete" in gap for gap in component["gaps"])
    [classification] = classify_components(result["components"], assessment_mode="assessment")
    assert classification["target_classes"] == ["target:cli"] and classification["target_class_unread"] is False
    assert any("tag index scan incomplete" in gap for gap in classification["gaps"])


def test_component_without_tags_keeps_the_unassigned_reason(accepted, settings, monkeypatch):
    result = discovered(accepted, settings, monkeypatch, graph_rows(3))
    [component] = result["components"]
    assert component["routing_context"] == [] and component["tag_cloud"]["counts"] == {}
    [classification] = classify_components(result["components"], assessment_mode="assessment")
    assert classification["target_class_unread"] is False
    assert classification["gaps"] == [
        "collation assigned no target class to this component; applicability cannot be determined"]
