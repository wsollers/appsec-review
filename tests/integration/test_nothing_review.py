"""End-to-end review of a target with nothing to find.

The review graph is the one ``appsec-review start`` runs: ``cli.GRAPH_JOB_IDS`` then
``cli.POST_INDEX_JOB_IDS``, filtered by each job's ``settings.enabled`` in ``appsec-review.toml``,
built from ``builtin_registry()`` and executed by ``GraphRunner`` and ``JobRunner``. The target is
a small benign repository created at test time: one Python module, one C file with a
``CMakeLists.txt``, and a README, committed with a fixed author and date.

Two substitutions keep the run deterministic and offline, and neither bypasses a job:

* Model transport. ``inference.PROVIDERS`` and ``inference.MODEL_CHECKS`` are replaced by a replay
  transport, so the real ``infer`` and ``check_models`` dispatch runs. The connectivity check reports
  every configured model available; the planning request is answered with the recipe a build
  engineer derives from ``CMakeLists.txt``. Any other request is refused and recorded, and the test
  fails if one arrives.
* Image-pin verification. ``job_image_pin_verification`` is disabled in this test's configuration
  copy (the documented switch that makes it transparent). Verifying every catalog image and pin is
  its own concern; the full tier instead skips, naming what is missing, when an image is absent.

Tiers:

* ``test_nothing_review_without_container_images`` runs everywhere. A ``docker`` stub that reports
  an unreachable daemon is put first on ``PATH``, so the run behaves the same on a host with images.
  A job that needs a container image fails with the runner's named precondition; the test records
  the image, removes the job and resumes the same run with ``GraphRunner`` (as ``appsec-review
  resume`` does). A job that then fails only because it needs a removed job's handoff is removed the
  same way. Any other failure fails the test.
* ``test_nothing_review_with_pinned_images`` runs the same graph with the real Docker daemon in one
  ``GraphRunner.run`` and requires every job to finish. It skips, naming what is missing, when the
  daemon or any enabled catalog tool image or build-profile image is unavailable.

A security observation on this benign target is a false positive in the rule that raised it: report
the rule; do not change the target to avoid it.

Run each tier with its own base directory:

    python -m pytest -p no:cacheprovider tests/integration/test_nothing_review.py \
        -k without_container_images --basetemp=test/tmp/nothing-review
    python -m pytest -p no:cacheprovider tests/integration/test_nothing_review.py \
        -k with_pinned_images --basetemp=test/tmp/nothing-review-full
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field, replace
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tomllib
from typing import Any

import pytest

from appsec_review import inference
from appsec_review.cli import GRAPH_JOB_IDS, POST_INDEX_JOB_IDS
from appsec_review.config import AppConfig, load_config
from appsec_review.container_runtime import load_catalog, profiles_from_settings
from appsec_review.inference import ModelResult
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_dependency_intelligence.inference import PROPOSAL_SCHEMA as DEPENDENCY_SCHEMA
from appsec_review.jobs.job_evidence_collection import plan_applicability
from appsec_review.jobs.job_review_intake.job import configured_models
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA as PLAN_SCHEMA
from appsec_review.observability import PipelineLog
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.retrieval.model import EntityKind
from appsec_review.retrieval.observations import classify
from appsec_review.runtime import GraphRunner, active_job_ids
from appsec_review.runtime.job import Job
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import canonical_json, file_sha256
from tests.test_blind_target_isolation import ANSWER_MARKER


ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="host git is required to create the target")

# Unit dispositions that are complete coverage or a positive "does not apply" decision.
CLEAN = {"SUCCEEDED", "NOT_APPLICABLE", "SKIPPED_NA", "SKIPPED_POLICY"}
# Observation classes that are review leads. Inventory and tool diagnostics are not findings.
NON_FINDING_CLASSES = {"inventory", "diagnostic"}
# Keys under which job outputs name missing coverage.
GAP_KEYS = ("gaps", "producer_gaps", "coverage_gaps", "gap", "reason")
IMAGE_PRECONDITION = re.compile(r"cataloged image is not locally available: (tool-[A-Za-z0-9_.-]+)")

TARGET_FILES = {
    "README.md": "# Greeter\n\nA small greeting library with a C helper that adds two numbers.\n",
    "greeter.py": (
        '"""Return friendly greetings."""\n\n\n'
        "def greet(name: str) -> str:\n"
        '    return f"Hello, {name}!"\n\n\n'
        'if __name__ == "__main__":\n'
        '    print(greet("world"))\n'
    ),
    "src/add.c": (
        "int add(int left, int right)\n{\n    return left + right;\n}\n\n"
        "int main(void)\n{\n    return add(2, 3) == 5 ? 0 : 1;\n}\n"
    ),
    "CMakeLists.txt": (
        "cmake_minimum_required(VERSION 3.16)\n"
        "project(greeter C)\n"
        "add_executable(add src/add.c)\n"
    ),
}
GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "Fixture Author", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "Fixture Author", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00",
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
}
DOCKER_STUB = (
    "#!/bin/sh\n"
    "echo 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
    "Is the docker daemon running?' >&2\n"
    "exit 1\n"
)


# ------------------------------------------------------------------------------------------ fixtures


def _target(base: Path) -> Path:
    target = base / "target"
    for relative, text in TARGET_FILES.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    environment = {**os.environ, **GIT_IDENTITY}
    for argv in (("git", "init", "-q", "-b", "main"), ("git", "add", "-A"),
                 ("git", "commit", "-q", "--no-gpg-sign", "-m", "Add greeter")):
        subprocess.run(argv, cwd=target, env=environment, check=True, capture_output=True)
    return target


def _config(base: Path) -> AppConfig:
    """The repository configuration with run state under ``base`` and the image-pin gate disabled."""
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    header = "[jobs.job_image_pin_verification.settings]\n"
    start = text.index(header) + len(header)
    end = text.index("\n[", start)
    section = text[start:end]
    assert section.count("enabled = true") == 1, "the image-pin verification dispatch switch moved"
    text = text[:start] + section.replace("enabled = true", "enabled = false") + text[end:]
    runs = (base / "runs").as_posix()
    for old, new in (('runs_dir = "runs"', f'runs_dir = "{runs}"'),
                     ('metadata_dir = "runs/metadata"', f'metadata_dir = "{runs}/metadata"'),
                     ('data_dir = "data"', f'data_dir = "{(ROOT / "data").as_posix()}"')):
        assert text.count(old) == 1, f"[runtime] no longer has {old}"
        text = text.replace(old, new)
    base.mkdir(parents=True, exist_ok=True)
    path = base / "appsec-review.toml"
    path.write_text(text, encoding="utf-8")
    config = load_config(path)
    # Repository-relative inputs (containers, rules, pipeline guidance) still resolve from the checkout.
    return replace(config, runtime=replace(config.runtime, repository_root=ROOT))


def _graph_job_ids(config: AppConfig) -> tuple[str, ...]:
    return active_job_ids(config, (*GRAPH_JOB_IDS, *POST_INDEX_JOB_IDS))


class ReplayModel:
    """Offline model transport: every configured model is available; planning gets a CMake recipe."""

    def __init__(self) -> None:
        self.requests: list[str] = []
        self.refused: list[str] = []

    def models(self, names, *, timeout_seconds: int) -> dict[str, Any]:
        return {"method": "test-replay", "listed": sorted(names),
                "models": {name: {"available": True, "detail": "test replay transport"} for name in names}}

    def send(self, request, *, timeout_seconds: int) -> ModelResult:
        self.requests.append(request.schema)
        if request.schema == PLAN_SCHEMA:
            return ModelResult({"schema": PLAN_SCHEMA, "component_proposals": [],
                                "build_recipes": [self._recipe(unit) for unit in request.summary["build_units"]
                                                  if unit["build_system"] == "cmake"]})
        if request.schema == DEPENDENCY_SCHEMA:
            candidate = request.summary["candidate"]
            return ModelResult({"schema": DEPENDENCY_SCHEMA, "candidate_id": candidate.get("candidate_id"),
                                "repository": None, "confidence": 0})
        self.refused.append(request.schema)
        raise RuntimeError(f"replay transport has no answer for {request.schema}")

    @staticmethod
    def _recipe(unit: Mapping[str, Any]) -> dict[str, Any]:
        root = str(unit["root"])
        build = "build" if root in {"", "."} else f"{root}/build"
        return {"schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": unit["family"], "source_dir": root or ".", "build_dir": build,
                "system_packages": [], "environment": {},
                "dependency_files": [item["path"] for item in unit["markers"]],
                "configure_commands": [["cmake", "-S", root or ".", "-B", build,
                                        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]],
                "build_commands": [["cmake", "--build", build]],
                "expected_outputs": [f"{build}/add"], "network_required": False,
                "reason": "CMakeLists.txt declares one C executable, add, from src/add.c"}


@dataclass
class Review:
    config: AppConfig
    target: Path
    run_id: str
    run_root: Path
    job_ids: tuple[str, ...]
    model: ReplayModel
    outcome: Mapping[str, Any]
    # job id -> the named reason the job could not run on this host
    gated: dict[str, str] = field(default_factory=dict)


def _failed_job(run_root: Path, jobs: list[Job]) -> tuple[Job, list[str]]:
    """The job whose newest attempt failed, with every failed task's (or the job's) error message."""
    for job in jobs:
        attempts = sorted((run_root / "data" / "jobs" / job.job_id / "attempts").glob("attempt_*"))
        if not attempts:
            continue
        status = json.loads((attempts[-1] / "status.json").read_text(encoding="utf-8"))
        if status["status"] != "FAILED":
            continue
        errors = [json.loads(path.read_text(encoding="utf-8"))["error"]["message"]
                  for path in sorted(attempts[-1].glob("steps/*/tasks/*/status.json"))
                  if json.loads(path.read_text(encoding="utf-8"))["status"] == "FAILED"]
        return job, errors or [status["error"]["message"]]
    raise AssertionError("the graph failed but no job attempt is FAILED")


def _run_review(base: Path, *, without_images: bool) -> Review:
    config = _config(base)
    target = _target(base)
    fingerprint = source_fingerprint(target)
    model = ReplayModel()
    job_ids = _graph_job_ids(config)
    registry = builtin_registry()
    jobs = [registry.build(job_id) for job_id in job_ids]
    gated: dict[str, str] = {}
    with pytest.MonkeyPatch.context() as patch:
        for provider in inference.PROVIDERS:
            patch.setitem(inference.PROVIDERS, provider, model.send)
        for provider in inference.MODEL_CHECKS:
            patch.setitem(inference.MODEL_CHECKS, provider, model.models)
        if without_images:
            stub = base / "no-docker"
            stub.mkdir()
            (stub / "docker").write_text(DOCKER_STUB, encoding="utf-8")
            (stub / "docker").chmod(0o755)
            patch.setenv("PATH", f"{stub}{os.pathsep}{os.environ.get('PATH', '')}")
        run_id: str | None = None
        while True:
            try:
                outcome = GraphRunner(config, jobs).run(target_root=target, source_fingerprint=fingerprint,
                                                        run_id=run_id)
                break
            except Exception as error:
                if not without_images:
                    raise
                if run_id is None:
                    run_id = sorted(path.name for path in config.runtime.runs_dir.iterdir()
                                    if path.name != "metadata")[-1]
                job, errors = _failed_job(config.runtime.runs_dir / run_id, jobs)
                images = sorted({match.group(1) for message in errors
                                 for match in [IMAGE_PRECONDITION.search(message)] if match})
                upstream = sorted(set(job.consumes) & set(gated))
                if images:
                    gated[job.job_id] = "container image unavailable: " + ", ".join(images)
                elif upstream and all(any(name in message for name in upstream) for message in errors):
                    gated[job.job_id] = "requires the handoff of " + ", ".join(upstream)
                else:
                    raise AssertionError(f"{job.job_id} failed for a reason other than a missing container "
                                         f"image: {errors}") from error
                jobs = [item for item in jobs if item.job_id != job.job_id]
    run_root = config.runtime.runs_dir / outcome["run_id"]
    return Review(config, target, outcome["run_id"], run_root, job_ids, model, outcome, gated)


@pytest.fixture(scope="module")
def no_images(tmp_path_factory) -> Iterator[Review]:
    yield _run_review(tmp_path_factory.mktemp("nothing"), without_images=True)


# ------------------------------------------------------------------------------------------ readers


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _accepted_handoff(run_root: Path, job_id: str) -> tuple[Mapping[str, Any], Path] | None:
    pointer = run_root / "data" / "jobs" / job_id / "latest.json"
    if not pointer.is_file():
        return None
    latest = _json(pointer)
    path = run_root / latest["handoff_path"]
    assert file_sha256(path) == latest["handoff_sha256"], f"{job_id}: handoff changed after acceptance"
    return _json(path), path


def _unit_outputs(run_root: Path, job_id: str) -> dict[str, Mapping[str, Any]]:
    accepted = _accepted_handoff(run_root, job_id)
    assert accepted is not None, job_id
    handoff, _ = accepted
    result = _json(run_root / handoff["resolving_paths"]["result"])
    return dict(result.get("outputs", {}))


def _manifest_shards(run_root: Path) -> list[tuple[Mapping[str, Any], Path]]:
    """Every shard reachable from the accepted manifest, verified, with its database path."""
    pointer = _json(run_root / "data" / "indices" / "accepted.json")
    document, _ = load_verified_manifest(run_root, run_root / pointer["manifest_path"], pointer["manifest_sha256"])
    shards: dict[tuple[str, str], tuple[Mapping[str, Any], Path]] = {}
    pending = [document]
    while pending:
        current = pending.pop()
        for item in current.get("indexes", ()):
            shards.setdefault((item["name"], item.get("shard_id", "default")), (item, run_root / item["relative_path"]))
        for upstream in current.get("upstream_manifests", ()):
            pending.append(_json(run_root / upstream["path"]))
    return list(shards.values())


def _findings(run_root: Path) -> list[dict[str, Any]]:
    """Security leads in the accepted index: tool observations outside inventory/diagnostics and
    finding packages."""
    values = []
    for item, path in _manifest_shards(run_root):
        with sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True) as database:
            rows = database.execute("SELECT identity, kind, payload_json FROM entities WHERE kind IN (?, ?)",
                                    (EntityKind.TOOL_OBSERVATION.value, EntityKind.FINDING_PACKAGE.value))
            for identity, kind, payload_json in rows:
                payload = json.loads(payload_json)
                if kind == EntityKind.TOOL_OBSERVATION.value and classify(payload) in NON_FINDING_CLASSES:
                    continue
                values.append({"shard": f"{item['name']}/{item.get('shard_id')}", "kind": kind,
                               "identity": identity, "class": classify(payload),
                               "tool": payload.get("tool_id"), "rule": payload.get("rule_id")})
    return values


# ------------------------------------------------------------------------------------------ assertions


def assert_target_is_benign(review: Review) -> None:
    for relative in TARGET_FILES:
        assert not ANSWER_MARKER.search(relative) and not ANSWER_MARKER.search(TARGET_FILES[relative]), relative


def assert_every_job_is_terminal(review: Review) -> None:
    """Every enabled graph job has an accepted handoff, or a named reason it could not run here."""
    assert set(review.job_ids) == set(_graph_job_ids(review.config))
    for job_id in review.job_ids:
        accepted = _accepted_handoff(review.run_root, job_id)
        if job_id in review.gated:
            assert accepted is None, f"{job_id} is both gated and accepted"
            continue
        assert accepted is not None, f"{job_id} has no accepted handoff"
        handoff, path = accepted
        assert handoff["status"] == "ACCEPTED" and handoff["job_id"] == job_id
        assert handoff["completion_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}, (job_id, handoff)
        assert handoff["resolved_config_sha256"] == review.config.resolved_sha256
        assert _json(path.parent / "status.json")["status"] == handoff["completion_status"]
        for artifact in handoff["artifacts"]:
            path = (review.run_root / artifact["path"]).resolve()
            assert review.run_root.resolve() in path.parents, (job_id, artifact)
            assert file_sha256(path) == artifact["sha256"], (job_id, artifact)
    decisions = {item["job_id"] for item in review.outcome["decisions"]}
    assert decisions == set(review.job_ids) - set(review.gated)


def _named_gaps(output: Mapping[str, Any]) -> list[str]:
    return [str(value) for key in GAP_KEYS for value in (
        output.get(key) if isinstance(output.get(key), list) else [output.get(key)]) if value]


def assert_dispositions_are_truthful(review: Review) -> None:
    """Coverage that is missing is a named gap and makes the job COMPLETED_WITH_GAPS, never SUCCEEDED."""
    for job_id in sorted(set(review.job_ids) - set(review.gated)):
        handoff, _ = _accepted_handoff(review.run_root, job_id)
        degraded: dict[str, str] = {}
        for unit, output in _unit_outputs(review.run_root, job_id).items():
            if not isinstance(output, Mapping):
                continue
            status = output.get("terminal_status")
            if status not in {None, *CLEAN}:
                assert _named_gaps(output), f"{job_id}.{unit} is {status} without a named gap"
                degraded[unit] = str(status)
            for decision in output.get("processing_decisions", ()):
                if decision.get("disposition") == "GAP":
                    assert decision.get("reason_code"), (job_id, unit, decision)
                    degraded[unit] = f"{decision.get('project_id')}: {decision['reason_code']}"
        if degraded:
            assert handoff["completion_status"] == "COMPLETED_WITH_GAPS", \
                f"{job_id} reports {handoff['completion_status']} with missing coverage: {degraded}"


def assert_scanner_coverage_is_recorded(review: Review) -> None:
    """Every evidence tool has a disposition; each one that did not run cleanly names why."""
    if "job_evidence_collection" in review.gated:
        return
    outputs = _unit_outputs(review.run_root, "job_evidence_collection")
    handoff = _json(review.run_root / outputs["evidence_publication.publish_handoff"]["artifact"]["path"])
    assert handoff["security_findings"] == []
    dispositions = {item["tool_id"]: item for item in handoff["dispositions"]}
    applicability = {item["tool_id"]: item for item in plan_applicability(review.run_root)}
    assert set(dispositions) == set(applicability)
    for tool_id, item in dispositions.items():
        planned = applicability[tool_id]
        if not planned["applicable"]:
            assert planned["reason"], tool_id
            assert item["terminal_status"] in {"NOT_APPLICABLE", "SKIPPED_NA", "SKIPPED_POLICY"}, item
        elif item["terminal_status"] == "SUCCEEDED":
            shard = ("observations", item["shard_id"])
            assert shard in {(entry["name"], entry["shard_id"]) for entry, _ in _manifest_shards(review.run_root)}, item
        else:
            assert item["gaps"], f"{tool_id} is {item['terminal_status']} without a named gap"


def assert_no_findings(review: Review) -> None:
    assert _findings(review.run_root) == []
    if "job_review_package_assembly" not in review.gated:
        outputs = _unit_outputs(review.run_root, "job_review_package_assembly")
        assert outputs, "review package assembly published no outputs"


def assert_configuration_and_guidance(review: Review) -> None:
    configuration = review.run_root / "data" / "configuration"
    manifest = _json(configuration / "manifest.json")
    assert manifest["resolved_sha256"] == review.config.resolved_sha256 == file_sha256(configuration / "resolved.json")
    assert manifest["source_sha256"] == file_sha256(configuration / "appsec-review.toml") == \
        file_sha256(review.config.source_path)
    frozen = tomllib.loads((configuration / "appsec-review.toml").read_text(encoding="utf-8"))
    assert {item["provider"] for item in configured_models(frozen)}, "no configured model was preflighted"
    # Every model call names a hash-pinned guidance bundle that exists under the run and hashes to its id.
    records, torn = PipelineLog(review.run_root).read()
    assert not torn
    used = {str(record["details"]["guidance_bundle_sha256"]) for record in records
            if record["event_type"] == "MODEL_CALL_STARTED"}
    assert used, "the planning model was never called"
    for bundle in sorted(used):
        root = review.run_root / "data" / "guidance" / bundle
        identity = _json(root / "model-identity.json")
        assert identity.pop("guidance_sha256") == bundle
        content = b"\0".join((root / name).read_bytes() for name in ("persona.md", "role.md", "task.md"))
        assert hashlib.sha256(content + b"\0" + canonical_json(identity)).hexdigest() == bundle
    assert review.model.refused == [], review.model.refused
    assert set(review.model.requests) <= {PLAN_SCHEMA, DEPENDENCY_SCHEMA}


def assert_integrity_audit_passes(review: Review) -> None:
    if "job_review_data_indexing" in review.gated:
        return
    reports = sorted(review.run_root.glob(
        "data/jobs/job_review_data_indexing/attempts/*/steps/audit/tasks/inventory/inventory.json"))
    audit = _json(reports[-1])["audit"]
    assert audit["status"] != "FAILED" and audit["violations"] == [], audit["violations"][:5]
    _manifest_shards(review.run_root)  # the accepted manifest and every shard verify


def _assert_all(review: Review) -> None:
    assert_target_is_benign(review)
    assert_every_job_is_terminal(review)
    assert_dispositions_are_truthful(review)
    assert_scanner_coverage_is_recorded(review)
    assert_no_findings(review)
    assert_configuration_and_guidance(review)
    assert_integrity_audit_passes(review)


# ------------------------------------------------------------------------------------------ tiers


def test_nothing_review_without_container_images(no_images: Review) -> None:
    review = no_images
    _assert_all(review)
    # Without a daemon every gated job names the image or the gated upstream it needed.
    assert review.gated, "no job needed a container image; the stub did not take effect"
    for job_id, reason in review.gated.items():
        assert reason.startswith(("container image unavailable: tool-", "requires the handoff of job_")), reason
    # The planning prefix never needs an image.
    for job_id in ("job_model_connectivity", "job_review_intake", "job_target_catalog", "job_target_analysis_plan"):
        if job_id in review.job_ids:
            assert job_id not in review.gated, review.gated
    plan = _unit_outputs(review.run_root, "job_target_analysis_plan")
    assert plan["plan_acceptance.publish_handoff"].get("terminal_status") in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    assert_failed_native_build_is_a_gap_downstream(review)


# Jobs that analyze a native build; a planned native unit whose build failed is a gap in each.
NATIVE_LANE_JOBS = ("job_language_build", "job_cpp_compiled_analysis", "job_clang_static_analysis",
                    "job_cpp_symbol_index")


def assert_failed_native_build_is_a_gap_downstream(review: Review) -> None:
    """Without images the CMake unit cannot be built; no native-lane job may then read as clean."""
    outputs = _unit_outputs(review.run_root, "job_project_build")
    document = _json(review.run_root / outputs["acceptance.publish_handoff"]["artifact"]["path"])
    failed = [item["build_unit_id"] for item in document["probe_receipts"]
              if item.get("family") == "native" and item.get("terminal_status") != "SUCCEEDED"]
    assert failed, "the CMake unit was expected to be planned and blocked without images"
    for job_id in NATIVE_LANE_JOBS:
        if job_id not in review.job_ids or job_id in review.gated:
            continue
        handoff, _ = _accepted_handoff(review.run_root, job_id)
        assert handoff["completion_status"] == "COMPLETED_WITH_GAPS", (job_id, handoff["completion_status"])
        gaps = [gap for output in handoff["outputs"].values() for gap in _named_gaps(output)]
        for build_unit_id in failed:
            assert any(build_unit_id in gap and "job_project_build" in gap for gap in gaps), (job_id, gaps)


def _missing_images(config: AppConfig) -> list[str]:
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=60, check=True)
    except (OSError, subprocess.SubprocessError):
        return ["the Docker daemon"]
    tags = {tool.tag for tool in load_catalog(ROOT).tools.values()}
    if "job_project_build" in config.jobs:
        tags |= {profile.tag for profile in profiles_from_settings(
            config.job("job_project_build").settings["profiles"]).values()}
    missing = []
    for tag in sorted(tags):
        inspected = subprocess.run(["docker", "image", "inspect", tag], capture_output=True, timeout=60)
        if inspected.returncode != 0:
            missing.append(tag)
    return missing


def test_nothing_review_with_pinned_images(tmp_path: Path) -> None:
    missing = _missing_images(_config(tmp_path / "probe"))
    if missing:
        pytest.skip("pinned container images are unavailable: " + ", ".join(missing))
    review = _run_review(tmp_path / "review", without_images=False)
    assert review.gated == {}
    _assert_all(review)
    # Every applicable scanner ran to completion and observed nothing.
    outputs = _unit_outputs(review.run_root, "job_evidence_collection")
    handoff = _json(review.run_root / outputs["evidence_publication.publish_handoff"]["artifact"]["path"])
    ran = [item for item in handoff["dispositions"] if item["terminal_status"] == "SUCCEEDED"]
    assert ran, "no scanner ran"
