from appsec_review.observability.findings.coverage_adapter import CoverageDocuments, reviewed_units


def test_operation_success_is_not_whole_file_coverage():
    docs = CoverageDocuments(
        catalog={"source": {"path": "api.py", "sha256": "a" * 64}},
        packages=[{"package_id": "op", "source_ids": ["source"], "coverage_scope": "operation"}],
        cells={"cell": [{"package_id": "op", "role": "hypothesis_hunter", "status": "succeeded"}]},
        units=[{"unit_key": "fallback", "hunted": False, "source_ids": ["source"]}])
    reviewed, unreviewed, gaps = reviewed_units(docs)
    assert reviewed == {} and unreviewed == {"api.py": "operation_only"}
    assert gaps == ["units_below_hunt_cutoff:1"]


def test_sources_below_hunt_cutoff_are_identified_without_a_package():
    docs = CoverageDocuments(
        catalog={"source": {"path": "api.py", "sha256": "a" * 64}},
        packages=[], cells={}, units=[{"hunted": False, "source_ids": ["source"]}])
    reviewed, unreviewed, _ = reviewed_units(docs)
    assert reviewed == {} and unreviewed == {"api.py": "below_hunt_cutoff"}


def test_completed_fallback_can_cover_file_also_containing_an_operation():
    docs = CoverageDocuments(
        catalog={"source": {"path": "api.py", "sha256": "a" * 64}},
        packages=[{"package_id": name, "source_ids": ["source"], "coverage_scope": kind}
                  for name, kind in (("op", "operation"), ("fallback", "files"))],
        cells={name: [{"package_id": name, "role": "hypothesis_hunter", "status": "succeeded"}]
               for name in ("op", "fallback")}, units=[])
    reviewed, unreviewed, gaps = reviewed_units(docs)
    assert reviewed == {"api.py": "a" * 64} and not unreviewed and not gaps
