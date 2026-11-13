"""Manual local-index/publication integration; not selected by the unit tier."""
import json

import pytest

from appsec_review.retrieval.core import RetrievalCore
from appsec_review.review.models import IntegrityError
from appsec_review.review.package_view import ViewLimits, build_view
from appsec_review.review.packages import PackageSettings, assemble_packages, publish_packages, verify_package_manifest
from appsec_review.review.scope import accept_manifest
from tests.fixtures.inference_review.builder import build_accepted_index_set
from tests.review.test_packages_graph_context import attach_graph

pytestmark = pytest.mark.time_budget(120, reason="bounded local accepted-index and package publication integration")


def test_accepted_graph_operations_reach_hash_bound_packages_and_worker_views(tmp_path):
    fixture = build_accepted_index_set(tmp_path / "fixture")
    attach_graph(fixture)
    scope = accept_manifest(fixture.run_root)
    assembly = assemble_packages(scope, PackageSettings(hunt_max_units=100))
    path = publish_packages(assembly, fixture.run_root / "data/behavior-packages")
    manifest = verify_package_manifest(path)
    operations = [row for row in manifest["units"] if row["coverage_scope"] == "operation"]
    assert operations and all(row["source_ids"] for row in manifest["units"])
    assert manifest["audit"]["lane_a"]["status"] == manifest["audit"]["lane_b"]["status"] == "passed"
    core = RetrievalCore(fixture.runs_dir, fixture.run_id)
    packages = [item.document() for item in assembly.packages if item.document()["scope"].get("operation")]
    assert packages
    for package in packages:
        operation = package["scope"]["operation"]
        assert operation["authority"] == "routing_context"
        assert all(core.find(identity=identity, limit=1)["results"] for identity in operation["anchor_ids"])
        view = build_view(package, core, ViewLimits())
        assert view.document["source"]
        assert view.document["scope"]["operation"]["authority"] == "routing_context"
    assert all(not item["operation"] for item in manifest["units"] if item["coverage_scope"] == "files")


def test_operation_package_tampering_is_rejected(tmp_path):
    fixture = build_accepted_index_set(tmp_path / "fixture")
    attach_graph(fixture)
    assembly = assemble_packages(accept_manifest(fixture.run_root), PackageSettings(hunt_max_units=100))
    path = publish_packages(assembly, fixture.run_root / "data/behavior-packages")
    package = next(item for item in assembly.packages if item.document()["scope"].get("operation"))
    artifact = path.parent / "packages" / f"{package.package_id}.json"
    document = json.loads(artifact.read_bytes())
    document["scope"]["operation"]["authority"] = "confirmed"
    artifact.write_text(json.dumps(document))
    with pytest.raises(IntegrityError, match="bytes"):
        verify_package_manifest(path)
