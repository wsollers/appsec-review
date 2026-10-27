import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import Bounds, inventory, source_fingerprint
from appsec_review.jobs.job_artifact_indexing import build_job as build_artifact_index, load_accepted_artifact_index
from appsec_review.jobs.job_artifact_security_analysis import (
    build_job as build_artifact_security, load_accepted_artifact_security_analysis,
)
from appsec_review.jobs.job_evidence_collection.job import load_target_catalog
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.inference import ModelResult
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner
from appsec_review.storage import file_sha256


ROOT = Path(__file__).parents[1]
WASM = b"\0asm\x01\0\0\0"


def test_binary_candidates_share_inventory_bounds_and_preserve_text_counts(tmp_path):
    (tmp_path / "a.bin").write_bytes(WASM)
    (tmp_path / "b.bin").write_bytes(WASM)
    (tmp_path / "c.txt").write_text("source")
    result = inventory(tmp_path, Bounds(max_files=2))
    assert result["files"] == [] and result["file_count"] == result["total_bytes"] == 0
    assert result["artifact_candidate_count"] == 2
    assert result["artifact_candidate_bytes"] == 2 * len(WASM)
    assert result["gaps"] == [{"path": "c.txt", "reason": "inventory_bound_reached"}]
    assert result["snapshot"]["file_count"] == 3


@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
def test_prebuilt_target_reaches_index_and_scanners_without_build_receipts(tmp_path, monkeypatch, mode):
    import appsec_review.jobs.cataloging as cataloging
    import appsec_review.runtime.scope as scope
    from appsec_review.container_runtime import BuildContainerExecutor, ContainerExecutor

    config_path = tmp_path / "appsec-review.toml"
    target = tmp_path / "target"
    target.mkdir()
    text = (ROOT / "appsec-review.toml").read_text()
    if mode == "first_party_managed":
        text = text.replace(
            '[review_policy]\nmode = "strict"\napproved_first_party_projects = []',
            '[review_policy]\nmode = "first_party_managed"\nproject_id = "fixture"\n'
            'approved_first_party_projects = ["fixture"]\ncustody = "application_private_v1"\n'
            f'target_root = {json.dumps(str(target))}')
    config_path.write_text(text)
    config = load_config(config_path)
    assert config.review_policy.mode.value == mode
    (target / "README.md").write_text("A prebuilt customer target.\n")
    paths = ("vendor/runtime.bin", "node_modules/bundled.wasm",
             "containers/tools/codeql/customer.wasm")
    for relative in paths:
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(WASM)
    executable = target / "customer"
    elf = bytearray(64)
    elf[:6] = b"\x7fELF\x02\x01"
    elf[16:18] = b"\x02\0"
    executable.write_bytes(elf)

    def forbidden(*args, **kwargs):
        pytest.fail("prebuilt target intake must not execute a build or real scanner")

    monkeypatch.setattr(ContainerExecutor, "execute", forbidden)
    monkeypatch.setattr(BuildContainerExecutor, "execute", forbidden)
    hash_guard = scope.require_hashable_evidence
    supplied_roots = tuple(ROOT / name for name in ("src", "containers", "rules", ".venv"))

    def no_platform_payload(path):
        assert not any(path.resolve().is_relative_to(root.resolve()) for root in supplied_roots)
        hash_guard(path)

    monkeypatch.setattr(scope, "require_hashable_evidence", no_platform_payload)
    digest = cataloging.sha256_file
    hashed = []

    def target_only(path):
        assert path.resolve().is_relative_to(target.resolve()), "supplied platform tree was hashed"
        hashed.append(path.relative_to(target).as_posix())
        return digest(path)

    monkeypatch.setattr(cataloging, "sha256_file", target_only)
    scans = []

    def scanner(capability, path, artifact, timeout, limit):
        assert artifact["artifact_origin"] == "target-intake"
        assert artifact["scope_role"] == "unknown" and artifact["delivery_status"] == "unknown"
        assert artifact["analysis_reason"] == "delivery-unknown-candidate-review"
        assert artifact["analysis_lane"] == "target"
        assert "build_unit_id" not in artifact and "image" not in artifact["producer"]
        assert file_sha256(path) == artifact["sha256"]
        scans.append((capability, artifact["target_relative_path"]))
        return {"stdout": b"{}", "stderr": b"", "exit_code": 0, "observation": {},
                "tool_identity": {"scanner": capability, "release": "fixture"}}

    def inference(request, *, timeout_seconds):
        assert not request.summary.get("build_units")
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [], "build_recipes": []})

    outcome = GraphRunner(config, [
        build_intake(), build_catalog(), build_plan(infer=inference),
        build_projects(executor_factory=forbidden,
                       image_resolver_factory=lambda unit: SimpleNamespace(resolve=forbidden)),
        build_language(executor_factory=forbidden), build_artifact_index(),
        build_artifact_security(scanner_runner=scanner),
    ]).run(target_root=target, source_fingerprint=source_fingerprint(target))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / outcome["run_id"]
    catalog = load_target_catalog(run_root)
    assert catalog.target_artifact_inventory_available
    assert all(item["analysis_reason"] == "delivery-unknown-candidate-review"
               for item in catalog.target_artifacts)
    assert {item["target_relative_path"] for item in catalog.target_artifacts} == {*paths, "customer"}
    assert len(catalog.files) == 1
    assert set(paths) <= set(hashed)
    assert load_accepted_language_build(run_root)["receipts"] == []
    indexed = load_accepted_artifact_index(run_root)
    assert indexed["artifact_count"] == 4 and len(indexed["target_artifacts"]) == 4
    assert indexed["target_catalog_handoff_sha256"] == catalog.handoff_sha256
    security = load_accepted_artifact_security_analysis(run_root)
    assert security["artifact_count"] == 4
    assert security["capabilities"]["wasm"]["observation_count"] == 3
    assert any(path == "customer" for _, path in scans)
    assert sum("delivery status is unknown" in gap for gap in indexed["gaps"]) == 4
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    results = core.search(query="customer", indexes=("artifacts",))
    assert results["results"]
    assert {"artifacts", "observations"} <= core.indexes.keys()
    prior_path = run_root / indexed["index_manifest"]["path"]
    prior = json.loads(prior_path.read_text())
    assert file_sha256(prior_path) == indexed["index_manifest"]["sha256"]
    inherited = [item for item in core.manifest["indexes"]
                 if (item["name"], item.get("shard_id")) != ("observations", "artifact-security")]
    assert inherited == prior["indexes"]
    for artifact in indexed["target_artifacts"]:
        found = core.find(identity=artifact["canonical_identity"], indexes=("artifacts",))
        assert len(found["results"]) == 1
        assert found["results"][0]["identity"] == artifact["canonical_identity"]


@pytest.mark.parametrize("mutation", ["same_size", "growth", "symlink"])
def test_intake_rejects_changed_target_before_object_publication(tmp_path, monkeypatch, mutation):
    from appsec_review.jobs.job_target_catalog import job as catalog_job
    from appsec_review.storage import shared

    target = tmp_path / "target"
    target.mkdir()
    path = target / "customer.wasm"
    path.write_bytes(WASM)
    snapshot = inventory(target)
    if mutation == "symlink":
        supplied = tmp_path / "supplied"
        supplied.write_bytes(WASM)
        path.unlink()
        path.symlink_to(supplied)
    else:
        path.write_bytes(b"\0changed" if mutation == "same_size" else WASM + b"x" * 64)
    monkeypatch.setattr(catalog_job, "inventory", lambda *args, **kwargs: snapshot)
    monkeypatch.setattr(shared, "put_bytes",
                        lambda *args: pytest.fail("changed target bytes reached publication"))
    unit = SimpleNamespace(
        unit_id="repository_discovery.partition_repository",
        job=SimpleNamespace(target_root=target, run_root=tmp_path / "run",
                            config=SimpleNamespace(exclusions=None)))
    partition = next(item for item in build_catalog().units if item.unit_id == unit.unit_id)
    with pytest.raises(ValueError, match="symlink" if mutation == "symlink" else "changed during bounded intake"):
        partition.handler(unit)


def test_target_artifact_scanner_mount_keeps_original_filename_without_copying_payload(tmp_path, monkeypatch):
    from appsec_review.container_runtime import ContainerExecutor
    from appsec_review.jobs.job_artifact_security_analysis.scanners import ContainerScannerRunner
    run_root = tmp_path / "run"
    path = run_root / "data/shared/objects" / ("a" * 64)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"PK\0customer-archive")
    raw = run_root / "raw"
    raw.mkdir()
    (raw / "stdout").write_bytes(b"{}")
    (raw / "stderr").write_bytes(b"")
    (raw / "receipt.json").write_text("{}")
    requests = []

    def execute(self, request):
        requests.append(request)
        return SimpleNamespace(stdout_path="raw/stdout", stderr_path="raw/stderr",
                               receipt_path="raw/receipt.json", timed_out=False, exit_code=0,
                               stdout_truncated=False, stderr_truncated=False)

    monkeypatch.setattr(ContainerExecutor, "execute", execute)
    runner = ContainerScannerRunner(ROOT, run_root, run_root / "scratch")
    monkeypatch.setattr(runner, "identity", lambda *args: {"scanner": "fixture"})
    runner("spotbugs", path, {"artifact_origin": "target-intake", "target_relative_path": "lib/customer.jar",
                            "canonical_identity": "target-artifact", "sha256": file_sha256(path)}, 30, 4096)
    [request] = requests
    [mount] = request.extra_mounts
    assert mount.source == path and mount.target == "/target/customer.jar" and mount.read_only
    assert "/target/customer.jar" in request.argv
    assert request.target_root != path.parent
    assert list(request.target_root.iterdir()) == [request.target_root / "customer.jar"]
    assert (request.target_root / "customer.jar").stat().st_size == 0


@pytest.mark.parametrize("corrupt", ["platform_role", "different_target", "outside_object_store"])
def test_invalid_target_artifact_provenance_is_rejected_before_payload_access(tmp_path, monkeypatch, corrupt):
    from appsec_review.config.assurance import SCOPE_VERSION, ScopeRole
    from appsec_review.jobs.job_artifact_indexing.job import ArtifactIndexIntegrityError, _target_artifacts
    from appsec_review.jobs.job_evidence_collection import job as evidence
    from appsec_review.storage import shared
    latest = tmp_path / "data/jobs/job_target_catalog/latest.json"
    latest.parent.mkdir(parents=True)
    latest.write_text("{}")
    raw = {"path": "data/shared/objects/" + "a" * 64, "sha256": "a" * 64, "size_bytes": 8,
           "schema": "appsec-review/target-artifact-intake/1",
           "kind": "wasm-module", "workspace_path": "module.wasm", "target_relative_path": "module.wasm",
           "artifact_origin": "target-intake", "scope_version": SCOPE_VERSION,
           "scope_role": ScopeRole.UNKNOWN.value, "source_fingerprint": "target",
           "delivery_status": "unknown", "mapping": "exact-target-path", "mapping_confidence": 1.0}
    if corrupt == "platform_role":
        raw["scope_role"] = ScopeRole.PLATFORM.value
    elif corrupt == "different_target":
        raw["source_fingerprint"] = "different"
    else:
        raw["path"] = "data/codeql/scopes/unit/export/pack/supplied"
    catalog = SimpleNamespace(source_fingerprint="target", handoff_sha256="b" * 64,
                              target_artifact_inventory_available=True, target_artifact_gaps=(),
                              target_artifacts=(raw,))
    monkeypatch.setattr(evidence, "load_target_catalog", lambda _: catalog)
    monkeypatch.setattr(shared, "verify_reference",
                        lambda *args: pytest.fail("invalid provenance reached payload verification"))
    unit = SimpleNamespace(job=SimpleNamespace(run_root=tmp_path, source_fingerprint="target"))
    with pytest.raises(ArtifactIndexIntegrityError, match="provenance"):
        _target_artifacts(unit)
