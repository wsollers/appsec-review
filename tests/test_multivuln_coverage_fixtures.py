from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_test_coverage import bind_coverage_paths, parse_coverage


ROOT = Path(__file__).parents[1]
TARGET = ROOT / "targets" / "appsec-multi-vuln"


@pytest.mark.requires_target("appsec-multi-vuln")
def test_declared_multivuln_coverage_fixtures_parse_and_bind_to_their_projects() -> None:
    matrix = json.loads((TARGET / "support" / "project-matrix.json").read_text(encoding="utf-8"))
    catalog_hashes = {
        path.relative_to(TARGET).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in TARGET.rglob("*")
        if path.is_file()
    }
    checked_formats: set[str] = set()

    for project in matrix["projects"]:
        project_root = project["path"]
        for artifact in project["coverage_artifacts"]:
            report = TARGET / project_root / artifact["path"]
            document = parse_coverage(report.read_bytes(), artifact["format"])
            rows, gaps = bind_coverage_paths(
                document, catalog_hashes, build_root=project_root,
            )

            assert artifact["provenance"] == "fixture"
            assert not gaps
            assert [row["producer_path"] for row in rows] == artifact["source_paths"]
            assert all(row["binding"] == "exact" for row in rows)
            assert [row["path"] for row in rows] == [
                f"{project_root}/{path}" for path in artifact["source_paths"]
            ]
            checked_formats.add(artifact["format"])

    assert checked_formats == {"lcov", "cobertura", "jacoco", "llvm"}
