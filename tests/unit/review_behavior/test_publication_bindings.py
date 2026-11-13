from pathlib import Path

import pytest

from appsec_review.jobs import accepted_review
from appsec_review.review.models import IntegrityError
from appsec_review.review.packages import verify_behavior_model
from appsec_review.storage import file_sha256


def bound_model(tmp_path):
    root = tmp_path / "run"
    root.mkdir()
    files = {}
    for name in ("handoff.json", "dfd.json", "threat-model.json", "evidence.json", "result.json"):
        path = root / name
        path.write_text("{}")
        files[name] = {"path": name, "sha256": file_sha256(path)}
    return root, {"run_id": "run", "behavior_model": {
        "handoff": files.pop("handoff.json"), "artifacts": files}}


def test_legacy_manifests_without_generated_context_need_no_new_inputs():
    assert verify_behavior_model({"run_id": "old"}, None) is None


def test_original_generated_bytes_are_reverified(tmp_path):
    root, document = bound_model(tmp_path)
    assert verify_behavior_model(document, root) is None
    (root / "dfd.json").write_text('{"changed":true}')
    with pytest.raises(IntegrityError, match="changed"):
        verify_behavior_model(document, root)


@pytest.mark.parametrize("root", [None, Path("foreign")], ids=["not-supplied", "foreign"])
def test_model_requires_explicit_matching_run_root(tmp_path, root):
    _, document = bound_model(tmp_path)
    with pytest.raises(IntegrityError, match="exact run_root"):
        verify_behavior_model(document, root)


def test_model_references_cannot_escape_the_run(tmp_path):
    root, document = bound_model(tmp_path)
    document["behavior_model"]["handoff"]["path"] = "../outside.json"
    with pytest.raises(IntegrityError, match="outside"):
        verify_behavior_model(document, root)


def test_model_artifacts_propagate_into_the_gate_certification_bindings(tmp_path, monkeypatch):
    root, document = bound_model(tmp_path)
    manifest = {**document, "content_sha256": "a" * 64}
    calls = []

    def verify(path, *, run_root):
        assert run_root == root
        calls.append(path)
        return manifest

    monkeypatch.setattr(accepted_review, "verify_package_manifest", verify)
    monkeypatch.setattr(accepted_review, "resolve_bound", lambda root, ref: root / ref["path"])
    monkeypatch.setattr(accepted_review, "read_bound_json", lambda root, ref: {
        "package_manifest": {"path": "manifest.json", "sha256": "b" * 64},
        "package_manifest_content_sha256": "a" * 64, "packages": []})
    outputs = {f"packages.assemble_{lane}_packages": {
        "artifact": {"path": lane + ".json", "sha256": "c" * 64}} for lane in ("lead", "hunt")}
    review = {"package_manifest_sha256": "a" * 64, "lead_package_manifest_sha256": "a" * 64}
    bindings = accepted_review._verify_package_manifests(root, outputs, review)
    assert len(calls) == 2
    assert {"handoff.json", "dfd.json", "threat-model.json", "evidence.json", "result.json"} <= {
        item["path"] for item in bindings}
