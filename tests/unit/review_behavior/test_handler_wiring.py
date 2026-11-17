"""Real lane-assembly handlers, with only their separately tested step boundaries replaced."""
import json
from pathlib import Path
from types import SimpleNamespace
import tomllib

import pytest

from appsec_review.config.inference_review import parse_inference_review_settings
from appsec_review.jobs.job_inference_security_review import job
from appsec_review.review import hunt_plan
from appsec_review.review.lead_families import LeadCollection
from appsec_review.review.packages import Assembly

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize("lane", ["lead", "hunt"])
def test_real_assembly_handler_supplies_original_core_and_preserves_cutoff_sources(tmp_path, monkeypatch, lane):
    with (ROOT / "appsec-review.toml").open("rb") as stream:
        settings = parse_inference_review_settings(tomllib.load(stream)["jobs"]["job_inference_security_review"]["settings"])
    root = tmp_path / "run"
    unit_root = root / "data" / "unit"
    unit_root.mkdir(parents=True)
    scope, core = object(), object()
    collection = LeadCollection((), (), {}, None)
    observed, events = {}, []
    reference = SimpleNamespace(accepted_ids=(), gap=None, record=lambda: {})
    reference.with_fallback = lambda values: reference
    manifest = {"units": [{"unit_key": "unit", "position": 1, "hunted": False,
                           "source_ids": ["source"], "coverage_scope": "operation"}],
                "admission": [], "content_sha256": "a" * 64}

    def assemble(actual_scope, package_settings, **kwargs):
        assert actual_scope is scope and kwargs["collection"] is collection
        assert kwargs["behavior_core"] is core
        assert package_settings.max_operation_records == 2000
        observed["assembly"] = kwargs
        return Assembly((), manifest, ())

    def publish(assembly, directory, *, run_root):
        assert run_root == root and assembly.manifest == manifest
        directory.mkdir(parents=True)
        path = directory / "package-manifest.json"
        path.write_text(json.dumps(manifest))
        observed["publication"] = path
        return path

    def collect(actual_scope, assessments=None, *, filters=None):
        assert actual_scope is scope and assessments is None
        assert filters == settings.lead_filters
        observed["collect"] = filters
        return collection

    monkeypatch.setattr(job, "_scope", lambda _: scope)
    monkeypatch.setattr(job, "_settings", lambda _: settings)
    monkeypatch.setattr(job, "load_cwe_reference", lambda _: reference)
    monkeypatch.setattr(job, "RetrievalCore", lambda *a, **k: core)
    monkeypatch.setattr(job, "AcceptedSliceSources", lambda scope, *, core: "source-boundary")
    monkeypatch.setattr(job, "assemble_packages", assemble)
    monkeypatch.setattr(job, "publish_packages", publish)
    monkeypatch.setattr(job, "collect_leads", collect)
    # The handler reads two upstream artifacts: the triage document and the hunting campaign plan (T-5030).
    def read(_root, ref):
        if ref["name"] == "packages.plan_hunt_campaign":
            return hunt_plan.disabled_document(settings.hunting)
        return {"enabled": False}

    monkeypatch.setattr(job, "_read", read)
    monkeypatch.setattr(job, "_excluded", lambda _: set())
    monkeypatch.setattr(job, "_membership", lambda *a: {})
    monkeypatch.setattr(job, "_taxonomy", lambda _: (None, None))
    monkeypatch.setattr(job, "crosswalk_tags", lambda _: ())
    unit_id = f"packages.assemble_{lane}_packages"
    unit = SimpleNamespace(
        unit_id=unit_id, unit_root=unit_root,
        job=SimpleNamespace(run_root=root, run_id="run", events=SimpleNamespace(
            write=lambda name, **details: events.append((name, details)))),
        output=lambda name: {"artifact": {"name": name}, "manifest_path": "manifest.json", "manifest_sha256": "b" * 64})
    handler = next(item.handler for item in job.build_job(repository_root=ROOT).units if item.unit_id == unit_id)
    result = handler(unit)
    output = json.loads((root / result["artifact"]["path"]).read_bytes())
    # The lane document adds the campaign fields to every unit row (none under a disabled plan).
    assert output["units"] == [{**row, "hunt_area": None, "hunt_gap": None} for row in manifest["units"]]
    assert output["lane"] == lane and result["terminal_status"] == "SUCCEEDED"
    assert output["hunt_plan"]["status"] == "disabled" and output["hunt_plan"]["plan_id"] is None
    assert events == [("INFERENCE_REVIEW_PACKAGES_ASSEMBLED", {"lane": lane, "package_count": 0})]
    assert set(observed) == {"collect", "assembly", "publication"}
