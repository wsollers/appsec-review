import json
from contextlib import contextmanager
from pathlib import Path
from statistics import median
import sys
from time import perf_counter

import pytest

from appsec_review.observability import aggregate_run_metrics
from appsec_review.observability import spans
from appsec_review.retrieval import RetrievalCore
from appsec_review.review_packages import verify_review_packages
from tests.test_target_document_pipeline import _run


def _verified_membership(config, target, outcome, root):
    job = outcome["jobs"]["job_review_package_assembly"]
    claim = json.loads((Path(job["attempt_root"]) / "claim.json").read_text())
    output = job["result"]["outputs"]["publication.publish_packages"]
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"],
                         manifest_path=root / claim["input_manifest_path"],
                         manifest_sha256=claim["input_manifest_sha256"])
    directory = root / output["package_directory"]
    manifest = verify_review_packages(core, directory)
    membership, resolved_evidence = [], {}
    for item in manifest["packages"]:
        package = json.loads((directory / f"{item['package_id']}.json").read_text())
        # These bindings must differ across frozen runs; semantic content must not.
        for key in ("package_id", "run_id", "manifest_sha256", "input_fingerprint"):
            package.pop(key)
        for evidence in package["evidence"]:
            evidence.pop("shard_sha256")
            if evidence["resolution"] == "source_line":
                rows = core.find(identity=evidence["entity_id"])["results"]
                assert len(rows) == 1
                source, gap = core.read_source_lines(identity=rows[0]["identity"])
                assert gap is None and source["lines"]
                location = source["location"]
                expected_source = (target / location["path"]).resolve()
                assert expected_source.is_relative_to(target.resolve())
                expected_lines = expected_source.read_text(encoding="utf-8").splitlines()
                assert source["lines"] == expected_lines
                start, end = location["start_line"], location["end_line"]
                assert 1 <= start <= end
                key = (evidence["entity_id"], location["path"], start, end)
                resolved = {
                    "entity_id": evidence["entity_id"], "location": location,
                    "requested_range": [start, end], "lines": source["lines"][start - 1:end],
                }
                if key in resolved_evidence:
                    assert resolved_evidence[key] == resolved
                resolved_evidence[key] = resolved
        membership.append(package)
    rows = core.find(path="backend/orders.routes.ts", limit=1)["results"]
    source, gap = core.read_source_lines(identity=rows[0]["identity"])
    assert gap is None
    assert source["lines"] == (target / "backend/orders.routes.ts").read_text().splitlines()
    return {
        "counts": manifest["counts"], "coverage_gaps": manifest["coverage_gaps"],
        "packages": sorted(membership, key=lambda item: (item["kind"], item["scope"]["partition_key"])),
        "resolved_evidence": [resolved_evidence[key] for key in sorted(resolved_evidence)],
    }


@pytest.mark.parametrize("changed_other_source", (False, True))
def test_evidence_comparison_checks_every_resolved_source(tmp_path, monkeypatch, changed_other_source):
    comparison = sys.modules[__name__]

    target, packages = tmp_path / "target", tmp_path / "packages"
    (target / "backend").mkdir(parents=True)
    packages.mkdir()
    (target / "backend/orders.routes.ts").write_text("route();\n", encoding="utf-8")
    (target / "design.md").write_text("first\nsecond\nthird\n", encoding="utf-8")
    (tmp_path / "claim.json").write_text(json.dumps({
        "input_manifest_path": "unused.json", "input_manifest_sha256": "a" * 64,
    }))
    (packages / "fixture.json").write_text(json.dumps({
        "package_id": "fixture", "run_id": "fixture-run", "manifest_sha256": "a" * 64,
        "input_fingerprint": "b" * 64, "kind": "document_hunt",
        "scope": {"partition_key": "fixture"}, "evidence": [{
            "entity_id": "design", "resolution": "source_line", "shard_sha256": "c" * 64,
        }],
    }))

    class Core:
        def __init__(self, *args, **kwargs):
            pass

        def find(self, *, identity=None, **kwargs):
            return {"results": [{"identity": identity or "route"}]}

        def read_source_lines(self, *, identity):
            if identity == "design":
                return {"location": {"path": "design.md", "start_line": 2, "end_line": 2},
                        "lines": ["first", "WRONG" if changed_other_source else "second", "third"]}, None
            return {"location": {"path": "backend/orders.routes.ts", "start_line": 1, "end_line": 1},
                    "lines": ["route();"]}, None

    monkeypatch.setattr(comparison, "RetrievalCore", Core)
    monkeypatch.setattr(comparison, "verify_review_packages", lambda *_: {
        "packages": [{"package_id": "fixture"}], "counts": {"packages": 1}, "coverage_gaps": [],
    })
    from types import SimpleNamespace
    config = SimpleNamespace(runtime=SimpleNamespace(runs_dir=tmp_path))
    outcome = {"run_id": "fixture-run", "jobs": {"job_review_package_assembly": {
        "attempt_root": str(tmp_path), "result": {"outputs": {
            "publication.publish_packages": {"package_directory": "packages"},
        }},
    }}}
    if changed_other_source:
        with pytest.raises(AssertionError):
            _verified_membership(config, target, outcome, tmp_path)
    else:
        result = _verified_membership(config, target, outcome, tmp_path)
        assert result["resolved_evidence"] == [{
            "entity_id": "design", "location": {"path": "design.md", "start_line": 2, "end_line": 2},
            "requested_range": [2, 2], "lines": ["second"],
        }]


def test_three_repeat_strict_managed_package_equivalence_and_lifecycle_measurement(tmp_path):
    samples, expected = [], None
    for repetition in range(3):
        order = ("strict", "first_party_managed")
        if repetition % 2:
            order = tuple(reversed(order))
        for mode in order:
            directory = tmp_path / f"trial-{repetition}-{mode}"
            directory.mkdir()
            started = perf_counter()
            config, target, outcome, root = _run(
                directory, fts_disabled=True, implementation=True,
                assurance_mode=mode, include_packages=True)
            wall_ms = (perf_counter() - started) * 1000
            metrics = aggregate_run_metrics(root)
            sample = {
                "repetition": repetition, "mode": mode, "lifecycle_wall_ms": wall_ms,
                "work_counters": metrics["work_counters"], "resource_spans": metrics["resource_spans"],
                "configuration_sha256": config.resolved_sha256, "semantic_equivalence_verified": False,
            }
            samples.append(sample)
            (tmp_path / "samples.json").write_text(json.dumps(samples, indent=2))
            membership = _verified_membership(config, target, outcome, root)
            if expected is None:
                expected = membership
            assert membership == expected
            sample.update({
                "package_counts": membership["counts"], "coverage_gap_count": len(membership["coverage_gaps"]),
                "semantic_equivalence_verified": True,
            })
            (tmp_path / "samples.json").write_text(json.dumps(samples, indent=2))
    medians = {mode: median(sample["lifecycle_wall_ms"] for sample in samples if sample["mode"] == mode)
               for mode in ("strict", "first_party_managed")}
    reduction = 100 * (1 - medians["first_party_managed"] / medians["strict"])
    (tmp_path / "comparison.json").write_text(json.dumps({
        "schema": "appsec-review/fixture-performance-comparison/1",
        "workload": "intake-catalog-indexing-packages; equal semantic membership, evidence and gaps",
        "cache_state": "fresh run stores; host filesystem cache uncontrolled; FTS disabled",
        "repetitions_per_mode": 3, "samples": samples, "median_lifecycle_wall_ms": medians,
        "lifecycle_reduction_percent": reduction, "fixture_lifecycle_reduction_at_least_50_percent": reduction >= 50,
        "historical_lifecycle_overhead_gate": "not_established_by_a_strict_vs_managed_fixture",
        "fresh_codeql_nonregression_gate": "not_measured; no real CodeQL execution authorized",
    }, indent=2))


def test_three_repeat_operation_telemetry_overhead(tmp_path, monkeypatch):
    """Measure added operation instrumentation, retaining ordinary lifecycle logs."""
    @contextmanager
    def without_operation_measurement(*args, **kwargs):
        yield None

    samples, expected = [], None
    original = spans.operation_span
    for repetition in range(3):
        order = (True, False) if repetition % 2 == 0 else (False, True)
        for enabled in order:
            directory = tmp_path / f"trial-{repetition}-telemetry-{enabled}"
            directory.mkdir()
            with monkeypatch.context() as patch:
                if not enabled:
                    for name, module in tuple(sys.modules.items()):
                        if name.startswith("appsec_review.") and module is not None:
                            if getattr(module, "operation_span", None) is original:
                                patch.setattr(module, "operation_span", without_operation_measurement)
                started = perf_counter()
                config, target, outcome, root = _run(
                    directory, fts_disabled=True, implementation=True,
                    assurance_mode="strict", include_packages=True)
                wall_ms = (perf_counter() - started) * 1000
            metrics = aggregate_run_metrics(root)
            sample = {
                "repetition": repetition, "operation_telemetry_enabled": enabled,
                "lifecycle_wall_ms": wall_ms, "configuration_sha256": config.resolved_sha256,
                "semantic_equivalence_verified": False,
            }
            samples.append(sample)
            (tmp_path / "telemetry-samples.json").write_text(json.dumps(samples, indent=2))
            assert bool(metrics["resource_spans"]) is enabled
            membership = _verified_membership(config, target, outcome, root)
            if expected is None:
                expected = membership
            assert membership == expected
            sample.update({
                "package_counts": membership["counts"],
                "coverage_gap_count": len(membership["coverage_gaps"]),
                "semantic_equivalence_verified": True,
            })
            (tmp_path / "telemetry-samples.json").write_text(json.dumps(samples, indent=2))
    medians = {
        "enabled" if enabled else "disabled": median(
            sample["lifecycle_wall_ms"] for sample in samples
            if sample["operation_telemetry_enabled"] is enabled)
        for enabled in (True, False)
    }
    overhead = 100 * (medians["enabled"] / medians["disabled"] - 1)
    (tmp_path / "telemetry-comparison.json").write_text(json.dumps({
        "schema": "appsec-review/fixture-telemetry-comparison/1",
        "measurement_scope": "operation spans, their counters and resource sampling only",
        "retained_in_both": "ordinary lifecycle logs, evidence validation, publication and retrieval",
        "workload": "strict intake-catalog-indexing-packages; equal semantic membership, evidence and gaps",
        "cache_state": "fresh run stores; host filesystem cache uncontrolled; FTS disabled",
        "repetitions_per_condition": 3, "samples": samples,
        "median_lifecycle_wall_ms": medians, "operation_telemetry_overhead_percent": overhead,
        "fixture_telemetry_overhead_at_most_5_percent": overhead <= 5,
        "production_overhead_gate": "not_established_by_this_fixture",
    }, indent=2))
