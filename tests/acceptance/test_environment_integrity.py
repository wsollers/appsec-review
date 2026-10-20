from __future__ import annotations

import hashlib
import json
from pathlib import Path

from appsec_review.acceptance.diff import Difference, classify_environment, failing
from appsec_review.acceptance.integrity import attempt_integrity

JOB = "job_target_catalog"
RUN = "2026-10-20-0001"


def _kinds(*pairs: tuple[str, str, str]) -> list[str]:
    differences = [Difference(JOB, kind, path, json.dumps(left), json.dumps(right))
                   for kind, path, (left, right) in ((kind, path, values) for kind, path, values in pairs)]
    return [item.kind for item in classify_environment(differences)]


def test_populated_paths_hashes_and_ids_are_environment_not_failures() -> None:
    kinds = _kinds(
        ("coverage", "outputs.fetch_config.path", ("<repo>/appsec-review.toml", "/opt/app/appsec-review.toml")),
        ("content", "a.json.digest", ("a" * 64, "b" * 64)),
        ("coverage", "outputs.x.run", ("<run-id>", "<uuid>")),
    )
    assert kinds == ["environment", "environment", "environment"]
    assert failing([Difference(JOB, kind, "p") for kind in kinds]) == []


def test_missing_empty_or_different_values_still_fail() -> None:
    kinds = _kinds(
        ("coverage", "outputs.x.path", ("<repo>/a.toml", None)),
        ("coverage", "outputs.x.path", ("<repo>/a.toml", "")),
        ("coverage", "outputs.x.count", (2, 3)),
        ("content", "a.json.status", ("SUCCEEDED", "PARTIAL")),
        ("coverage", "outputs.x.value", ("<repo>/a.toml", "a" * 64)),
    )
    assert kinds == ["coverage", "coverage", "coverage", "content", "coverage"]


def test_artifact_signatures_may_differ_only_in_their_digest() -> None:
    def signature(**fields) -> str:
        return json.dumps([json.dumps(fields, sort_keys=True)])

    same = Difference(JOB, "coverage", "artifacts[x.sqlite]", signature(kind="sqlite", rows={"files": 8}, sha256="a"),
                      signature(kind="sqlite", rows={"files": 8}, sha256="b"))
    fewer = Difference(JOB, "coverage", "artifacts[x.sqlite]", signature(kind="sqlite", rows={"files": 8}, sha256="a"),
                       signature(kind="sqlite", rows={"files": 7}, sha256="b"))
    assert [item.kind for item in classify_environment([same, fewer])] == ["environment", "coverage"]


def _write(path: Path, value: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(tmp_path: Path) -> tuple[Path, Path]:
    run_root = tmp_path / "runs" / RUN
    upstream = _write(run_root / "data/jobs/job_review_intake/attempts/attempt_0001/handoff.json", {"job_id": "x"})
    _write(run_root / "data/jobs/job_review_intake/latest.json", {"handoff_sha256": upstream})
    attempt = run_root / f"data/jobs/{JOB}/attempts/attempt_0001"
    artifact = attempt / "artifacts/catalog.json"
    digest = _write(artifact, {"files": 8})
    common = {"job_id": JOB, "attempt_id": "attempt_0001"}
    bound = {"job_review_intake": upstream}
    _write(attempt / "claim.json", {**common, "run_id": RUN, "target_root": "/opt/app/targets/relay",
                                    "source_fingerprint": "f", "input_identity": None, "upstream_handoffs": bound})
    _write(attempt / "status.json", {**common, "run_id": RUN, "status": "SUCCEEDED"})
    _write(attempt / "result.json", {"outputs": {"catalog.files": {"artifact": {
        "path": artifact.relative_to(run_root).as_posix(), "sha256": digest}}}})
    handoff = _write(attempt / "handoff.json", {
        **common, "status": "ACCEPTED", "completion_status": "SUCCEEDED", "source_fingerprint": "f",
        "input_identity": None, "upstream_handoff_sha256": bound,
        "artifacts": [{"path": artifact.relative_to(run_root).as_posix(), "sha256": digest,
                       "size_bytes": artifact.stat().st_size}],
        **{key: "x" for key in ("implementation_identity", "schema_identity", "validation_identity",
                                "resolved_config_sha256", "job_config_sha256")}})
    _write(run_root / f"data/jobs/{JOB}/latest.json", {
        "handoff_path": (attempt / "handoff.json").relative_to(run_root).as_posix(), "handoff_sha256": handoff})
    return run_root, attempt


def test_a_consistent_attempt_has_no_integrity_problems(tmp_path: Path) -> None:
    run_root, attempt = _run(tmp_path)
    assert attempt_integrity(JOB, run_root, RUN, attempt, "local") == []


def test_wrong_ids_changed_bytes_and_broken_upstream_links_are_reported(tmp_path: Path) -> None:
    run_root, attempt = _run(tmp_path)
    (attempt / "artifacts/catalog.json").write_text('{"files": 9}', encoding="utf-8")
    status = json.loads((attempt / "status.json").read_text(encoding="utf-8"))
    (attempt / "status.json").write_text(json.dumps({**status, "run_id": "2026-10-20-0009"}), encoding="utf-8")
    _write(run_root / "data/jobs/job_review_intake/latest.json", {"handoff_sha256": "0" * 64})

    paths = {item.path for item in attempt_integrity(JOB, run_root, RUN, attempt, "dagster")}
    assert {"dagster:status.run_id", "dagster:upstream.job_review_intake",
            "dagster:handoff.artifacts[0].sha256", "dagster:result.outputs.catalog.files.artifact.sha256"} <= paths


def _with_target_reference(attempt: Path, digest: str) -> None:
    result = json.loads((attempt / "result.json").read_text(encoding="utf-8"))
    result["outputs"]["catalog.source"] = {"file": {"path": "src/main.cpp", "sha256": digest}}
    (attempt / "result.json").write_text(json.dumps(result), encoding="utf-8")


def test_target_relative_references_resolve_in_the_target_checkout(tmp_path: Path) -> None:
    run_root, attempt = _run(tmp_path)
    source = tmp_path / "target" / "src" / "main.cpp"
    source.parent.mkdir(parents=True)
    source.write_text("int main() {}\n", encoding="utf-8")
    _with_target_reference(attempt, hashlib.sha256(source.read_bytes()).hexdigest())
    target = tmp_path / "target"

    assert attempt_integrity(JOB, run_root, RUN, attempt, "local", target) == []
    # Without a checkout to resolve against, the reference is not checked.
    assert attempt_integrity(JOB, run_root, RUN, attempt, "local") == []

    source.write_text("int main() { return 1; }\n", encoding="utf-8")
    changed = {item.path for item in attempt_integrity(JOB, run_root, RUN, attempt, "local", target)}
    assert "local:result.outputs.catalog.source.file.sha256" in changed
    source.unlink()
    missing = {item.path for item in attempt_integrity(JOB, run_root, RUN, attempt, "local", target)}
    assert "local:result.outputs.catalog.source.file.path" in missing
