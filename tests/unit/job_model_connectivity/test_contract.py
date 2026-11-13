"""Pin the no-upstream contract and the exact run-owned input/output file identities."""

from __future__ import annotations

from dataclasses import asdict
from fnmatch import fnmatchcase
import hashlib
import json
from pathlib import Path

from appsec_review.jobs.job_model_connectivity.datasets import CONTRACT, CONSUMES, DATASETS
from appsec_review.jobs.job_model_connectivity.job import build_job
from appsec_review.runtime.contracts import DispatchClass, TargetAccess
from appsec_review.runtime.datasets import EvidenceAuthority

from .support import PUBLISH, RESOLVE, SCHEMA, VERIFY, context, handler, serving, write_configuration


ATTEMPTS = "data/jobs/job_model_connectivity/attempts/*"
ARTIFACTS = (
    ATTEMPTS + "/steps/connectivity/tasks/verify_models/model-connectivity.json",
    ATTEMPTS + "/steps/publication/tasks/publish_handoff/model-connectivity-handoff.json",
)


def test_contract_has_no_input_requirements_or_target_authority() -> None:
    assert CONTRACT.inputs == ()
    assert CONTRACT.schedule_after == ()
    assert CONTRACT.consumes == CONSUMES == ()
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.NONE
    assert CONTRACT.always_execute is True
    assert CONTRACT.propagate_handoff is False
    job = build_job()
    assert job.contract is CONTRACT and job.datasets is DATASETS
    assert job.consumes == ()


def test_dataset_pins_every_field_and_both_artifact_globs() -> None:
    assert [asdict(item) for item in DATASETS] == [{
        "output_kind": "model_connectivity",
        "step": "publication",
        "family": "configuration",
        "schema": "appsec-review/model-preflight/1",
        "sensitivity": "internal",
        "disposition": "artifact_only",
        "description": "Fresh provider and model connectivity evidence for one graph dispatch.",
        "indexes": (),
        "shard_prefixes": (),
        "shard_suffixes": (),
        "artifacts": ARTIFACTS,
        "query_route": "query_dataset_inventory (sanitized identity, hash, status and coverage only)",
        "reason": "live provider readiness metadata; no target security evidence",
        "required": False,
        "store": "retrieval",
        "authority": EvidenceAuthority.OPERATIONAL,
    }]
    assert not any(fnmatchcase(
        "data/jobs/job_review_intake/attempts/attempt_0001/steps/connectivity/tasks/"
        "verify_models/model-connectivity.json", pattern,
    ) for pattern in ARTIFACTS)


def test_resolve_reads_only_the_manifest_and_hash_pinned_resolved_configuration(
    tmp_path: Path, monkeypatch,
) -> None:
    unit = context(tmp_path, RESOLVE)
    write_configuration(unit.job.run_root, {"jobs": {
        "job_a": {"settings": {"model": {"provider": "p", "model": "m"}}},
    }})
    reads = []
    original_open = Path.open

    def record_open(path, *args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "r")
        if "r" in mode:
            reads.append(path.relative_to(unit.job.run_root).as_posix())
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", record_open)
    result = handler(RESOLVE)(unit)
    assert reads == [
        "data/configuration/manifest.json",
        "data/configuration/resolved.json",
        "data/configuration/resolved.json",
    ]
    assert result == {
        "required": [{
            "job_id": "job_a", "setting": "settings.model", "provider": "p", "model": "m", "enabled": True,
        }],
        "not_required": [], "model_count": 1, "not_required_count": 0,
    }
    assert sorted(path.relative_to(unit.job.run_root).as_posix()
                  for path in unit.job.run_root.rglob("*") if path.is_file()) == [
        "data/configuration/manifest.json", "data/configuration/resolved.json",
    ]


def test_each_published_file_matches_its_declared_glob_schema_and_content_hash(tmp_path: Path) -> None:
    calls = []
    resolved = {
        "required": [{"job_id": "job_a", "provider": "p", "model": "m"}],
        "not_required": [],
    }
    verify_unit = context(tmp_path, VERIFY, {RESOLVE: resolved})
    verified = handler(VERIFY, check_models=serving(calls))(verify_unit)
    publish_unit = context(tmp_path, PUBLISH, {VERIFY: verified})
    published = handler(PUBLISH)(publish_unit)
    run_root = verify_unit.job.run_root
    expected_paths = [
        pattern.replace("*", "attempt_0001") for pattern in ARTIFACTS
    ]
    assert sorted(path.relative_to(run_root).as_posix()
                  for path in run_root.rglob("*") if path.is_file()) == expected_paths
    for result, relative, pattern in zip((verified, published), expected_paths, ARTIFACTS, strict=True):
        identity = result["artifact"]
        data = (run_root / relative).read_bytes()
        document = json.loads(data)
        assert identity == {
            "path": relative, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data),
        }
        assert fnmatchcase(relative, pattern)
        assert document["schema"] == result["schema"] == DATASETS[0].schema == SCHEMA
    verify_document = json.loads((run_root / expected_paths[0]).read_bytes())
    assert verify_document == {
        "schema": SCHEMA, **resolved,
        "providers": {"p": {
            "provider": "p", "transport": True, "method": "probe", "error": None,
            "models": {"m": {"available": True, "detail": "fixture answered"}},
        }},
        "unavailable": [], "unavailable_not_required": [], "gaps": [],
    }
    assert json.loads((run_root / expected_paths[1]).read_bytes()) == {
        "schema": SCHEMA, "artifact": verified["artifact"],
        "providers": ["p"], "verified": ["p/m"], "not_required": [], "unavailable_not_required": [],
    }
    assert calls == [("p", ("m",), 37)]
